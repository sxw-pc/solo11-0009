"""Lifecycle manager: retention scheduling, grace-period workflow, verifiable destruction.

State machine for one artifact::

    ACTIVE ──retention expires──> PENDING (destroy token issued)
                                  │  grace window, revocable
              revoke <───────────┤
                │                │ grace ends
                ▼                ▼
             REVOKED        GRACE_EXPIRED (virtual; row stays PENDING)
                │                │ destroy() with confirmation
                └─ new expiry    ▼
                              DESTROYED (evidence appended to audit chain)

    any erasure error ──> FAILED (row keeps its place; retry resumes it)

The audit log is append-only: every transition is a *new* chained entry,
never an update or deletion, and the chain is re-verified after each batch.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .clock import Clock
from .erase import EraseError, secure_erase
from .inventory import LifecycleInventory
from .retention import RetentionPolicy
from .types import ArtifactRecord, ArtifactStatus, ArtifactType
from ..audit import AuditLog
from ..config import Paths
from ..pipeline.checkpoint import CheckpointStore
from ..utils import MasklineError, atomic_write_text, canonical_json, file_sha256, sha256_text

# Run statuses that mean a run may still write or be resumed.
BLOCKING_RUN_STATUSES = ("running", "interrupted", "failed")


class LifecycleError(MasklineError):
    pass


@dataclass
class DestructionItem:
    artifact: ArtifactRecord
    state: str                       # ready_to_schedule | in_grace | grace_expired | blocked | destroyed
    blocked_reason: str | None = None
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, Any]:
        record = self.artifact
        return {
            "artifact_id": record.artifact_id,
            "artifact_type": record.artifact_type.value,
            "path": str(record.path),
            "run_id": record.run_id,
            "dataset_fingerprint": record.dataset_fingerprint,
            "status": record.status.value,
            "state": self.state,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "grace_ends_at": record.grace_ends_at,
            "retention_days": record.retention_days,
            "grace_days": record.grace_days,
            "blocked_reason": self.blocked_reason,
            "requires_confirmation": self.requires_confirmation,
            "destroy_token": record.destroy_token,
        }


@dataclass
class DestructionPlan:
    generated_at: str
    items: list[DestructionItem] = field(default_factory=list)

    @property
    def schedulable(self) -> list[DestructionItem]:
        return [item for item in self.items if item.state == "ready_to_schedule"]

    @property
    def in_grace(self) -> list[DestructionItem]:
        return [item for item in self.items if item.state == "in_grace"]

    @property
    def grace_expired(self) -> list[DestructionItem]:
        return [item for item in self.items if item.state == "grace_expired"]

    @property
    def blocked(self) -> list[DestructionItem]:
        return [item for item in self.items if item.state == "blocked"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "totals": {
                "ready_to_schedule": len(self.schedulable),
                "in_grace": len(self.in_grace),
                "grace_expired": len(self.grace_expired),
                "blocked": len(self.blocked),
            },
            "items": [item.to_dict() for item in self.items],
        }


@dataclass
class DestructionResult:
    destruction_id: str
    succeeded: list[dict[str, Any]] = field(default_factory=list)
    failed: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    audit_verified: bool = False
    certificate_path: Path | None = None

    @property
    def ok(self) -> bool:
        return not self.failed


class LifecycleManager:

    def __init__(
        self,
        paths: Paths,
        retention_policy: RetentionPolicy | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.paths = paths
        self.policy = retention_policy or RetentionPolicy.default()
        self.clock = clock or Clock()
        self.inventory = LifecycleInventory(paths.lifecycle_db)
        self.audit = AuditLog(paths.audit_path)

    def close(self) -> None:
        self.inventory.close()

    def __enter__(self) -> "LifecycleManager":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------- registration

    def register_run_artifacts(self, result: Any) -> list[ArtifactRecord]:
        """Register every artifact produced by one completed masking run."""
        now = self.clock.now()
        now_iso = now.isoformat(timespec="seconds")
        fingerprint = result.dataset_fingerprint
        run_id = result.run_id
        candidates: list[tuple[ArtifactType, Path, str | None]] = [
            (ArtifactType.OUTPUT, Path(result.output_path), result.output_hash),
            (ArtifactType.PSEUDOMAP, self.paths.pseudomap_db, None),
            (ArtifactType.CHECKPOINT, self.paths.checkpoint_db, None),
            (
                ArtifactType.MANIFEST,
                self.paths.manifest_dir / f"{fingerprint[:16]}.json",
                None,
            ),
            (ArtifactType.REPORT, self.paths.reports_dir / f"{run_id}.md", None),
            (ArtifactType.REPORT, self.paths.reports_dir / f"{run_id}.json", None),
        ]
        records: list[ArtifactRecord] = []
        for artifact_type, path, known_hash in candidates:
            if not path.exists():
                continue
            schedule = self.policy.schedule_for(artifact_type, fingerprint)
            content_hash = known_hash or file_sha256(path)
            record = ArtifactRecord(
                artifact_id=f"art-{secrets.token_hex(8)}",
                artifact_type=artifact_type,
                path=path,
                run_id=run_id,
                dataset_fingerprint=fingerprint,
                content_hash=content_hash,
                size_bytes=path.stat().st_size,
                created_at=now_iso,
                retention_days=schedule.retention_days,
                grace_days=schedule.grace_days,
                expires_at=self.clock.iso_after(schedule.retention_days),
                grace_ends_at=self.clock.iso_after(
                    schedule.retention_days + schedule.grace_days
                ),
                status=ArtifactStatus.ACTIVE,
                updated_at=now_iso,
            )
            records.append(self.inventory.upsert_artifact(record))
        return records

    # ------------------------------------------------------------- in-flight check

    def _blocking_runs(self) -> list[Any]:
        if not self.paths.checkpoint_db.exists():
            return []
        store = CheckpointStore(self.paths.checkpoint_db)
        try:
            return [
                run
                for run in store.list_runs(limit=10000)
                if run.status in BLOCKING_RUN_STATUSES
            ]
        finally:
            store.close()

    def _blocked_reason(
        self, artifact: ArtifactRecord, blocking_runs: list[Any]
    ) -> str | None:
        run_ids = {run.run_id for run in blocking_runs}
        dataset_runs = {
            run.run_id for run in blocking_runs
            if run.dataset_fingerprint == artifact.dataset_fingerprint
        }
        if artifact.artifact_type is ArtifactType.CHECKPOINT and run_ids:
            return (
                "checkpoint store holds in-flight/resumable runs: "
                + ", ".join(sorted(run_ids))
            )
        if artifact.artifact_type is ArtifactType.PSEUDOMAP and dataset_runs:
            return (
                "pseudonym mapping is still needed by in-flight/resumable runs: "
                + ", ".join(sorted(dataset_runs))
            )
        if artifact.run_id and artifact.run_id in run_ids:
            matching = next(run for run in blocking_runs if run.run_id == artifact.run_id)
            return f"run {artifact.run_id} is still {matching.status}"
        if artifact.dataset_fingerprint and dataset_runs:
            return (
                "dataset has in-flight/resumable runs: " + ", ".join(sorted(dataset_runs))
            )
        return None

    # ---------------------------------------------------------------- preview

    def preview(self) -> DestructionPlan:
        """Read-only preview: what is due, in grace, expired, or blocked."""
        now_iso = self.clock.now_iso()
        blocking_runs = self._blocking_runs()
        plan = DestructionPlan(generated_at=now_iso)
        for record in self.inventory.list_artifacts():
            if record.status in (ArtifactStatus.DESTROYED, ArtifactStatus.FAILED):
                state = record.status.value
                plan.items.append(
                    DestructionItem(
                        record, state,
                        requires_confirmation=record.is_pseudomap,
                    )
                )
                continue
            reason = self._blocked_reason(record, blocking_runs)
            if reason:
                plan.items.append(
                    DestructionItem(record, "blocked", blocked_reason=reason,
                                    requires_confirmation=record.is_pseudomap)
                )
                continue
            if record.status is ArtifactStatus.PENDING:
                state = "in_grace" if now_iso < record.grace_ends_at else "grace_expired"
            elif record.expires_at <= now_iso:
                state = "ready_to_schedule"
            else:
                state = "active"
            plan.items.append(
                DestructionItem(record, state,
                                requires_confirmation=record.is_pseudomap)
            )
        return plan

    # ------------------------------------------------------------- phase 1: schedule

    def schedule_due(self) -> DestructionPlan:
        """Move retention-expired artifacts into the revocable grace window."""
        now_iso = self.clock.now_iso()
        blocking_runs = self._blocking_runs()
        due = self.inventory.expired_active(now_iso)
        new_items: list[dict[str, Any]] = []
        grace_days_seen: set[int] = set()
        blocked: list[DestructionItem] = []
        destruction_id = self._new_destruction_id()
        for record in due:
            reason = self._blocked_reason(record, blocking_runs)
            if reason:
                blocked.append(
                    DestructionItem(record, "blocked", blocked_reason=reason,
                                    requires_confirmation=record.is_pseudomap)
                )
                continue
            token = f"dtk-{secrets.token_urlsafe(18)}"
            self.inventory.update_status(
                record.artifact_id, ArtifactStatus.PENDING, now_iso, destroy_token=token
            )
            updated = self.inventory.get(record.artifact_id)
            assert updated is not None
            grace_days_seen.add(updated.grace_days)
            new_items.append(
                {
                    "artifact_id": updated.artifact_id,
                    "artifact_type": updated.artifact_type.value,
                    "path": str(updated.path),
                    "content_hash": updated.content_hash,
                    "item_status": "pending",
                }
            )
        if new_items:
            self.inventory.create_destruction_batch(destruction_id, new_items)
            self.audit.append(
                {
                    "event": "lifecycle.scheduled",
                    "destruction_id": destruction_id,
                    "grace_days": sorted(grace_days_seen),
                    "items": [
                        {
                            "artifact_id": item["artifact_id"],
                            "artifact_type": item["artifact_type"],
                            "path": item["path"],
                            "requires_confirmation": item["artifact_type"]
                            == ArtifactType.PSEUDOMAP.value,
                        }
                        for item in new_items
                    ],
                }
            )
        return self.preview()

    # ------------------------------------------------------------- grace revocation

    def revoke(self, artifact_id: str) -> ArtifactRecord:
        """Cancel a pending destruction while still inside the grace window."""
        record = self.inventory.get(artifact_id)
        if record is None:
            raise LifecycleError(f"unknown artifact id: {artifact_id}")
        if record.status is not ArtifactStatus.PENDING:
            raise LifecycleError(
                f"artifact {artifact_id} is {record.status.value}; only pending "
                "destructions inside the grace window can be revoked"
            )
        now_iso = self.clock.now_iso()
        if now_iso >= record.grace_ends_at:
            raise LifecycleError(
                f"grace window for {artifact_id} ended at {record.grace_ends_at}; "
                "revocation is no longer possible"
            )
        new_expires = self.clock.iso_after(record.retention_days)
        new_grace_end = self.clock.iso_after(
            record.retention_days + record.grace_days
        )
        self.inventory.conn.execute(
            "UPDATE artifacts SET status = ?, destroy_token = NULL, "
            "expires_at = ?, grace_ends_at = ?, updated_at = ? WHERE artifact_id = ?",
            (ArtifactStatus.REVOKED.value, new_expires, new_grace_end,
             now_iso, artifact_id),
        )
        self.inventory.conn.commit()
        for batch in self.inventory.list_batches():
            batch_id = batch["destruction_id"]
            for item in self.inventory.get_batch(batch_id):
                if item["artifact_id"] == artifact_id and item["item_status"] in (
                    "pending", "failed"
                ):
                    self.inventory.update_destruction_item(
                        batch_id, artifact_id, "skipped", now_iso,
                        error="revoked during grace window; retention restarted",
                    )
        self.audit.append(
            {
                "event": "lifecycle.revoked",
                "artifact_id": artifact_id,
                "artifact_type": record.artifact_type.value,
                "path": str(record.path),
                "run_id": record.run_id,
                "dataset_fingerprint": record.dataset_fingerprint,
                "new_expires_at": new_expires,
                "new_grace_ends_at": new_grace_end,
            }
        )
        refreshed = self.inventory.get(artifact_id)
        assert refreshed is not None
        return refreshed

    # ------------------------------------------------------------- phase 2: destroy

    def destroy(
        self,
        destruction_id: str | None = None,
        *,
        confirmations: dict[str, str] | None = None,
    ) -> DestructionResult:
        """Erase all due items (or one batch), resuming anything left over.

        ``confirmations`` maps artifact id to the destroy token shown by the
        preview. Pseudonym-mapping artifacts require a matching token; the call
        refuses the whole batch if a due pseudomap lacks one.
        """
        confirmations = confirmations or {}
        now_iso = self.clock.now_iso()
        outstanding = self._select_outstanding(destruction_id)
        if not outstanding:
            raise LifecycleError("no outstanding destruction items")
        blocking_runs = self._blocking_runs()
        result = DestructionResult(destruction_id=destruction_id or "all-batches")
        certificate: dict[str, Any] | None = None
        for item in outstanding:
            outcome = self._destroy_one(item, confirmations, blocking_runs, now_iso)
            if outcome is None:
                continue
            kind, payload = outcome
            getattr(result, kind).append(payload)
        # A resumed multi-batch run may touch several batches; verify once at end.
        if result.succeeded or result.failed:
            verification = self.audit.verify()
            result.audit_verified = True
            certificate = self._write_certificate(result, verification.head_hash)
            result.certificate_path = certificate
        if result.failed:
            raise LifecycleError(
                f"{len(result.failed)} item(s) failed to erase; re-run destroy to "
                f"resume: " + ", ".join(item["artifact_id"] for item in result.failed)
            )
        return result

    def _select_outstanding(self, destruction_id: str | None) -> list[dict[str, Any]]:
        if destruction_id is None:
            return self.inventory.outstanding_items()
        items = self.inventory.get_batch(destruction_id)
        outstanding = [
            item for item in items if item["item_status"] in ("pending", "failed")
        ]
        if not outstanding:
            known = {row["destruction_id"] for row in self.inventory.list_batches()}
            if destruction_id not in known:
                raise LifecycleError(f"unknown destruction id: {destruction_id}")
        return outstanding

    def _destroy_one(
        self,
        item: dict[str, Any],
        confirmations: dict[str, str],
        blocking_runs: list[Any],
        now_iso: str,
    ) -> tuple[str, dict[str, Any]] | None:
        artifact_id = item["artifact_id"]
        record = self.inventory.get(artifact_id)
        if record is None:
            raise LifecycleError(f"inventory row missing for artifact {artifact_id}")
        if record.status is ArtifactStatus.REVOKED:
            self.inventory.update_destruction_item(
                item["destruction_id"], artifact_id, "skipped", now_iso,
                error="artifact was revoked during the grace window",
            )
            return "skipped", {"artifact_id": artifact_id, "path": item["path"],
                               "reason": "revoked"}
        if record.status not in (ArtifactStatus.PENDING, ArtifactStatus.FAILED):
            raise LifecycleError(
                f"artifact {artifact_id} is {record.status.value}, not pending"
            )
        if now_iso < record.grace_ends_at:
            raise LifecycleError(
                f"grace window for {artifact_id} ends at {record.grace_ends_at}; "
                "destruction is not permitted yet"
            )
        reason = self._blocked_reason(record, blocking_runs)
        if reason:
            raise LifecycleError(
                f"destruction refused for {artifact_id} ({record.artifact_type.value} "
                f"at {record.path}): {reason}"
            )
        if record.is_pseudomap:
            token = confirmations.get(artifact_id)
            if not token or not secrets.compare_digest(token, record.destroy_token or ""):
                raise LifecycleError(
                    f"pseudonym mapping {artifact_id} requires its destroy token; "
                    "re-run the preview to obtain it and pass the confirmation"
                )
        try:
            erase_outcomes = secure_erase(record.path)
        except EraseError as exc:
            self.inventory.update_destruction_item(
                item["destruction_id"], artifact_id, "failed", now_iso, error=str(exc)
            )
            # Keep the destroy token: a retry must still be able to confirm the
            # pseudonym mapping erasure without issuing a brand-new token.
            self.inventory.update_status(
                artifact_id, ArtifactStatus.FAILED, now_iso
            )
            self.audit.append(
                {
                    "event": "lifecycle.erasure_failed",
                    "destruction_id": item["destruction_id"],
                    "artifact_id": artifact_id,
                    "artifact_type": record.artifact_type.value,
                    "path": str(record.path),
                    "error": str(exc),
                }
            )
            return "failed", {"artifact_id": artifact_id, "path": str(record.path),
                              "error": str(exc)}
        evidence = self._build_evidence(item, record, erase_outcomes, now_iso)
        self.inventory.update_destruction_item(
            item["destruction_id"], artifact_id, "succeeded", now_iso,
            evidence_hash=evidence["evidence_hash"],
        )
        self.inventory.update_status(
            artifact_id, ArtifactStatus.DESTROYED, now_iso, clear_token=True
        )
        entry = self.audit.append({"event": "lifecycle.destroyed", **evidence})
        evidence["audit_seq"] = entry["seq"]
        evidence["audit_entry_hash"] = entry["entry_hash"]
        return "succeeded", evidence

    def _build_evidence(
        self,
        item: dict[str, Any],
        record: ArtifactRecord,
        erase_outcomes: list[Any],
        now_iso: str,
    ) -> dict[str, Any]:
        primary = next((o for o in erase_outcomes if o.path == record.path), None)
        sidecars = [
            {
                "path": str(outcome.path),
                "existed": outcome.existed,
                "size_bytes": outcome.size_bytes,
                "pre_hash": outcome.pre_hash,
                "post_hash": outcome.post_hash,
            }
            for outcome in erase_outcomes
            if outcome.path != record.path
        ]
        payload = {
            "destruction_id": item["destruction_id"],
            "artifact_id": record.artifact_id,
            "artifact_type": record.artifact_type.value,
            "path": str(record.path),
            "run_id": record.run_id,
            "dataset_fingerprint": record.dataset_fingerprint,
            "size_bytes": primary.size_bytes if primary else record.size_bytes,
            "existed": primary.existed if primary else False,
            "pre_hash": primary.pre_hash if primary else record.content_hash,
            "post_hash": primary.post_hash if primary else None,
            "sidecars": sidecars,
            "destroyed_at": now_iso,
            "actor": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        }
        payload["evidence_hash"] = sha256_text(canonical_json(payload))
        return payload
    def _write_certificate(
        self, result: DestructionResult, head_hash: str
    ) -> Path:
        self.paths.certificates_dir.mkdir(parents=True, exist_ok=True)
        certificate_path = self.paths.certificates_dir / "latest.json"
        body = {
            "generated_at": self.clock.now_iso(),
            "audit_head_hash": head_hash,
            "succeeded": result.succeeded,
            "failed": result.failed,
            "skipped": result.skipped,
        }
        atomic_write_text(
            certificate_path,
            canonical_json(body) + "\n",
            mode=0o600,
        )
        # Also keep one immutable certificate per destruction batch.
        if result.succeeded:
            first = result.succeeded[0]
            batch_path = self.paths.certificates_dir / f"{first['destruction_id']}.json"
            atomic_write_text(
                batch_path, canonical_json(body) + "\n", mode=0o600
            )
        return certificate_path

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _new_destruction_id() -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"dst-{stamp}-{secrets.token_hex(3)}"

    def list_artifacts(self) -> list[ArtifactRecord]:
        return self.inventory.list_artifacts()
