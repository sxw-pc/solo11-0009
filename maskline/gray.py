"""Isolated gray-release trials for versioned detector rules.

A gray trial never writes formal findings, checkpoints, pseudonym mappings,
reports or formal manifests.  It owns a dedicated ``data/gray/<trial_id>/``
directory containing only a temporary findings snapshot and trial metadata.
Successful trials are retained for seven days by default; any failure removes
the whole trial directory before the exception propagates.
"""

from __future__ import annotations

import json
import secrets
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import Paths
from .dataset_io import DatasetError
from .detectors.engine import detect_inventory
from .registry import inspect_dataset
from .resources import ResourceLimits, ResourceGovernor
from .rule_registry import RuleCatalog, resolve_actor
from .utils import MasklineError, atomic_write_text

GRAY_RETENTION_DAYS = 7


class GrayError(MasklineError):
    pass


@dataclass(frozen=True)
class GrayTrialRecord:
    trial_id: str
    rule_version: str
    dataset_path: str
    dataset_fingerprint: str
    actor: str
    status: str
    snapshot_path: str
    findings_count: int
    high_medium_count: int
    resource_limits: dict[str, Any]
    created_at: str
    completed_at: str | None
    expires_at: str

    def to_record(self) -> dict[str, Any]:
        return {
            "trial_id": self.trial_id,
            "rule_version": self.rule_version,
            "dataset_path": self.dataset_path,
            "dataset_fingerprint": self.dataset_fingerprint,
            "actor": self.actor,
            "status": self.status,
            "snapshot_path": self.snapshot_path,
            "findings_count": self.findings_count,
            "high_medium_count": self.high_medium_count,
            "resource_limits": self.resource_limits,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "expires_at": self.expires_at,
        }


@dataclass
class GrayTrialResult:
    trial_id: str
    rule_version: str
    dataset_path: Path
    dataset_fingerprint: str
    actor: str
    snapshot_path: Path
    findings: list[dict[str, Any]]
    resource_limits: dict[str, Any]
    created_at: str
    expires_at: str

    @property
    def findings_count(self) -> int:
        return len(self.findings)

    @property
    def high_medium_count(self) -> int:
        return sum(
            1
            for item in self.findings
            if item.get("confidence") in {"high", "medium"}
        )


class GrayTrialStore:
    """Persistent index of temporary gray snapshots and their expiry times."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS gray_trials (
                trial_id TEXT PRIMARY KEY,
                rule_version TEXT NOT NULL,
                dataset_path TEXT NOT NULL,
                dataset_fingerprint TEXT NOT NULL,
                actor TEXT NOT NULL,
                status TEXT NOT NULL,
                snapshot_path TEXT NOT NULL,
                findings_count INTEGER NOT NULL DEFAULT 0,
                high_medium_count INTEGER NOT NULL DEFAULT 0,
                resource_limits_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                completed_at TEXT,
                expires_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "GrayTrialStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def create(
        self,
        *,
        trial_id: str,
        rule_version: str,
        dataset_path: Path,
        dataset_fingerprint: str,
        actor: str,
        snapshot_path: Path,
        resource_limits: dict[str, Any],
        created_at: str,
        expires_at: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO gray_trials "
            "(trial_id, rule_version, dataset_path, dataset_fingerprint, actor, "
            "status, snapshot_path, findings_count, high_medium_count, "
            "resource_limits_json, created_at, completed_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, 'running', ?, 0, 0, ?, ?, NULL, ?)",
            (
                trial_id,
                rule_version,
                str(dataset_path),
                dataset_fingerprint,
                actor,
                str(snapshot_path),
                json.dumps(resource_limits, ensure_ascii=False, sort_keys=True),
                created_at,
                expires_at,
            ),
        )
        self.conn.commit()

    def finish(
        self,
        trial_id: str,
        *,
        findings_count: int,
        high_medium_count: int,
        status: str = "completed",
        completed_at: str | None = None,
    ) -> None:
        self.conn.execute(
            "UPDATE gray_trials SET status = ?, findings_count = ?, "
            "high_medium_count = ?, completed_at = ? WHERE trial_id = ?",
            (status, findings_count, high_medium_count, completed_at, trial_id),
        )
        self.conn.commit()

    def delete(self, trial_id: str) -> None:
        self.conn.execute(
            "DELETE FROM gray_trials WHERE trial_id = ?", (trial_id,)
        )
        self.conn.commit()

    def get(self, trial_id: str) -> GrayTrialRecord | None:
        row = self.conn.execute(
            "SELECT * FROM gray_trials WHERE trial_id = ?", (trial_id,)
        ).fetchone()
        return _record_from_row(row) if row else None

    def list(self) -> list[GrayTrialRecord]:
        rows = self.conn.execute(
            "SELECT * FROM gray_trials ORDER BY created_at, trial_id"
        ).fetchall()
        return [_record_from_row(row) for row in rows]

    def purge_expired(
        self, gray_dir: str | Path, now: datetime | None = None
    ) -> list[GrayTrialRecord]:
        now_dt = now or datetime.now(timezone.utc)
        cutoff = _iso(now_dt)
        rows = self.conn.execute(
            "SELECT * FROM gray_trials WHERE expires_at < ? ORDER BY created_at",
            (cutoff,),
        ).fetchall()
        removed: list[GrayTrialRecord] = []
        base = Path(gray_dir).expanduser().resolve()
        for row in rows:
            record = _record_from_row(row)
            snapshot = Path(record.snapshot_path)
            trial_dir = snapshot.parent
            try:
                resolved = trial_dir.expanduser().resolve()
                if resolved != base and resolved.is_relative_to(base):
                    shutil.rmtree(resolved, ignore_errors=True)
            except OSError:
                # A missing/moved directory must not block metadata cleanup.
                pass
            self.conn.execute(
                "DELETE FROM gray_trials WHERE trial_id = ?", (record.trial_id,)
            )
            removed.append(record)
        if removed:
            self.conn.commit()
        return removed


class GraySnapshot:
    """Temporary findings database scoped to one gray trial."""

    def __init__(self, path: str | Path, *, create: bool = True) -> None:
        self.path = Path(path)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif not self.path.exists():
            raise GrayError(f"gray snapshot not found: {self.path}")
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        if create:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    dataset_fingerprint TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    column_name TEXT NOT NULL,
                    sensitive_type TEXT,
                    confidence TEXT NOT NULL DEFAULT 'none',
                    score REAL NOT NULL DEFAULT 0,
                    hit_rate REAL NOT NULL DEFAULT 0,
                    validate_rate REAL NOT NULL DEFAULT 0,
                    sample_size INTEGER NOT NULL DEFAULT 0,
                    candidates_json TEXT NOT NULL DEFAULT '[]',
                    rule_version TEXT NOT NULL,
                    saved_at TEXT NOT NULL,
                    PRIMARY KEY (dataset_fingerprint, table_name, column_name)
                );
                """
            )
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "GraySnapshot":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def save_finding(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO findings "
            "(dataset_fingerprint, table_name, column_name, sensitive_type, "
            "confidence, score, hit_rate, validate_rate, sample_size, "
            "candidates_json, rule_version, saved_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(dataset_fingerprint, table_name, column_name) DO UPDATE SET "
            "sensitive_type=excluded.sensitive_type, "
            "confidence=excluded.confidence, score=excluded.score, "
            "hit_rate=excluded.hit_rate, validate_rate=excluded.validate_rate, "
            "sample_size=excluded.sample_size, "
            "candidates_json=excluded.candidates_json, "
            "rule_version=excluded.rule_version, saved_at=excluded.saved_at",
            (
                record["dataset_fingerprint"],
                record["table_name"],
                record["column_name"],
                record.get("sensitive_type"),
                record.get("confidence", "none"),
                float(record.get("score", 0.0)),
                float(record.get("hit_rate", 0.0)),
                float(record.get("validate_rate", 0.0)),
                int(record.get("sample_size", 0)),
                json.dumps(record.get("candidates", []), ensure_ascii=False),
                record.get("rule_version", ""),
                _iso(datetime.now(timezone.utc)),
            ),
        )
        self.conn.commit()

    def findings(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM findings ORDER BY table_name, column_name"
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["candidates"] = json.loads(item.pop("candidates_json"))
            result.append(item)
        return result


def purge_expired_trials(
    paths: Paths,
    *,
    audit_path: str | Path | None = None,
    now: datetime | None = None,
) -> list[GrayTrialRecord]:
    """Remove trial directories past their retention window (lazy cleanup)."""
    with GrayTrialStore(paths.gray_db) as store:
        removed = store.purge_expired(paths.gray_dir, now=now)
    if removed and audit_path is not None:
        AuditLog(audit_path).append(
            {
                "event": "gray_trial_expired",
                "actor": "system",
                "trial_ids": [record.trial_id for record in removed],
                "count": len(removed),
            }
        )
    return removed


def _new_trial_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"gray-{stamp}-{secrets.token_hex(3)}"


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def run_gray_trial(
    paths: Paths,
    rule_catalog: RuleCatalog | None = None,
    *,
    rule_version: str,
    dataset: str | Path,
    actor: str | None = None,
    sample_limit: int = 200,
    limits: ResourceLimits | None = None,
    retention_days: int = GRAY_RETENTION_DAYS,
    now: datetime | None = None,
    audit_path: str | Path | None = None,
) -> GrayTrialResult:
    """Run one rule version against one dataset inside an isolated snapshot."""
    if rule_catalog is None:
        with RuleCatalog(
            paths.rules_db, audit_path=paths.audit_path, create=True
        ) as catalog:
            return run_gray_trial(
                paths,
                catalog,
                rule_version=rule_version,
                dataset=dataset,
                actor=actor,
                sample_limit=sample_limit,
                limits=limits,
                retention_days=retention_days,
                now=now,
                audit_path=audit_path,
            )
    if not isinstance(sample_limit, int) or isinstance(sample_limit, bool) or sample_limit < 1:
        raise GrayError("sample_limit must be a positive integer")
    if (
        not isinstance(retention_days, int)
        or isinstance(retention_days, bool)
        or retention_days < 0
    ):
        raise GrayError("retention_days must be a non-negative integer")
    limits = limits or ResourceLimits()
    actor = resolve_actor(actor)
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    audit_path = audit_path if audit_path is not None else paths.audit_path

    dataset_path = Path(dataset).expanduser().resolve()
    if not dataset_path.is_file():
        raise DatasetError(f"dataset not found: {dataset_path}")

    # Validate/compile the rule version and permissions before creating any
    # temporary resources.  A syntax error here leaves nothing behind.
    record = rule_catalog.assert_can_trial(rule_version, dataset_path, actor)
    inventory = inspect_dataset(dataset_path)

    purge_expired_trials(paths, audit_path=audit_path, now=now_dt)

    trial_id = _new_trial_id()
    trial_dir = paths.gray_dir / trial_id
    snapshot_path = trial_dir / "findings.sqlite"
    created_at = _iso(now_dt)
    expires_at = _iso(now_dt + timedelta(days=retention_days))
    trial_dir.mkdir(parents=True, exist_ok=True)
    store = GrayTrialStore(paths.gray_db)
    snapshot: GraySnapshot | None = None
    try:
        snapshot = GraySnapshot(snapshot_path)
        with ResourceGovernor(limits) as applied:
            store.create(
                trial_id=trial_id,
                rule_version=rule_version,
                dataset_path=dataset_path,
                dataset_fingerprint=inventory.fingerprint,
                actor=actor,
                snapshot_path=snapshot_path,
                resource_limits=applied,
                created_at=created_at,
                expires_at=expires_at,
            )
            AuditLog(audit_path).append(
                {
                    "event": "gray_trial_started",
                    "trial_id": trial_id,
                    "rule_version": rule_version,
                    "rule_fingerprint": record.fingerprint,
                    "dataset_path": str(dataset_path),
                    "dataset_fingerprint": inventory.fingerprint,
                    "actor": actor,
                    "sample_limit": sample_limit,
                    "resource_limits": applied,
                    "expires_at": expires_at,
                }
            )
            findings = detect_inventory(
                inventory, sample_limit=sample_limit, rule_set=record.rule_set
            )
            for finding in findings:
                snapshot.save_finding(finding)
        snapshot.close()
        snapshot = None
        high_medium = sum(
            1
            for item in findings
            if item.get("confidence") in {"high", "medium"}
        )
        completed_at = _iso(datetime.now(timezone.utc))
        store.finish(
            trial_id,
            findings_count=len(findings),
            high_medium_count=high_medium,
            completed_at=completed_at,
        )
        metadata = {
            "trial_id": trial_id,
            "status": "completed",
            "rule_version": rule_version,
            "rule_fingerprint": record.fingerprint,
            "dataset_path": str(dataset_path),
            "dataset_fingerprint": inventory.fingerprint,
            "actor": actor,
            "created_at": created_at,
            "completed_at": completed_at,
            "expires_at": expires_at,
            "retention_days": retention_days,
            "sample_limit": sample_limit,
            "resource_limits": applied,
            "findings_count": len(findings),
            "high_medium_count": high_medium,
            "isolation": {
                "snapshot": str(snapshot_path),
                "formal_meta_db": False,
                "formal_checkpoint_db": False,
                "formal_pseudomap_db": False,
                "formal_reports": False,
            },
        }
        atomic_write_text(
            trial_dir / "trial.json",
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        )
        AuditLog(audit_path).append(
            {
                "event": "gray_trial_completed",
                "trial_id": trial_id,
                "rule_version": rule_version,
                "rule_fingerprint": record.fingerprint,
                "dataset_path": str(dataset_path),
                "dataset_fingerprint": inventory.fingerprint,
                "actor": actor,
                "findings_count": len(findings),
                "high_medium_count": high_medium,
                "snapshot_path": str(snapshot_path),
                "expires_at": expires_at,
            }
        )
        result = GrayTrialResult(
            trial_id=trial_id,
            rule_version=rule_version,
            dataset_path=dataset_path,
            dataset_fingerprint=inventory.fingerprint,
            actor=actor,
            snapshot_path=snapshot_path,
            findings=findings,
            resource_limits=applied,
            created_at=created_at,
            expires_at=expires_at,
        )
        return result
    except BaseException as exc:
        if snapshot is not None:
            try:
                snapshot.close()
            except Exception:
                pass
            snapshot = None
        shutil.rmtree(trial_dir, ignore_errors=True)
        try:
            store.delete(trial_id)
        except Exception:
            pass
        try:
            AuditLog(audit_path).append(
                {
                    "event": "gray_trial_failed",
                    "trial_id": trial_id,
                    "rule_version": rule_version,
                    "dataset_path": str(dataset_path),
                    "actor": actor,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "cleaned_up": True,
                }
            )
        except Exception:
            # Never hide the original failure behind an audit-write failure.
            pass
        if isinstance(exc, MasklineError):
            raise
        if not isinstance(exc, Exception):
            raise
        raise GrayError(f"gray trial failed: {exc}") from exc
    finally:
        if snapshot is not None:
            try:
                snapshot.close()
            except Exception:
                pass
        store.close()


def _record_from_row(row: sqlite3.Row) -> GrayTrialRecord:
    return GrayTrialRecord(
        trial_id=row["trial_id"],
        rule_version=row["rule_version"],
        dataset_path=row["dataset_path"],
        dataset_fingerprint=row["dataset_fingerprint"],
        actor=row["actor"],
        status=row["status"],
        snapshot_path=row["snapshot_path"],
        findings_count=int(row["findings_count"]),
        high_medium_count=int(row["high_medium_count"]),
        resource_limits=json.loads(row["resource_limits_json"] or "{}"),
        created_at=row["created_at"],
        completed_at=row["completed_at"],
        expires_at=row["expires_at"],
    )
