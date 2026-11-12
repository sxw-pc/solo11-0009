"""Application services: versioned jobs, batch classification, corrections, re-runs.

A classification job pins exact rule-pack version ids, so concurrent jobs over
different datasets never observe a half-published rule change and never
disagree about which version produced a label.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Sequence

from ..audit import AuditLog
from ..dataset_io import read_column_samples, read_headerless_column_samples
from ..detectors.engine import analyze_values, scan_inventory
from ..registry import Catalog
from .engine import ClassificationEngine, ColumnInput
from .models import Alert, FieldClassification, RulePack
from .rulepacks import builtin_rule_packs, load_rule_pack
from .store import ClassificationStore
from .tolerant import TolerantInventory, inspect_tolerant


class ClassificationServiceError(RuntimeError):
    pass


def _job_id() -> str:
    return "cls-" + uuid.uuid4().hex[:12]


class ClassificationService:

    def __init__(
        self,
        store: ClassificationStore,
        catalog: Catalog,
        audit: AuditLog | None = None,
        max_nesting_depth: int = 3,
        sample_limit: int = 200,
    ) -> None:
        self.store = store
        self.catalog = catalog
        self.audit = audit
        self.max_nesting_depth = max_nesting_depth
        self.sample_limit = sample_limit

    # ----- rule pack lifecycle -----------------------------------------------

    def ensure_builtin_packs(self) -> list[dict[str, Any]]:
        published = []
        for pack in builtin_rule_packs():
            version_id, created = self.store.publish_pack(pack)
            published.append(
                {
                    "pack_id": pack.pack_id,
                    "standard_code": pack.standard.code,
                    "version_id": version_id,
                    "created": created,
                    "builtin": True,
                    "fingerprint": pack.fingerprint,
                }
            )
            if created and self.audit:
                self.audit.append(
                    {
                        "event": "rule_pack_published",
                        "pack_id": pack.pack_id,
                        "standard_code": pack.standard.code,
                        "revision": pack.revision,
                        "rule_pack_fingerprint": pack.fingerprint,
                        "rule_pack_version_id": version_id,
                        "builtin": True,
                    }
                )
        return published

    def publish_custom_pack(self, path: str | Path) -> dict[str, Any]:
        pack = load_rule_pack(path, builtin=False)
        version_id, created = self.store.publish_pack(pack)
        if self.audit:
            self.audit.append(
                {
                    "event": "rule_pack_published",
                    "pack_id": pack.pack_id,
                    "standard_code": pack.standard.code,
                    "revision": pack.revision,
                    "rule_pack_fingerprint": pack.fingerprint,
                    "rule_pack_version_id": version_id,
                    "builtin": False,
                    "source_path": pack.source_path,
                    "created": created,
                }
            )
        return {
            "pack_id": pack.pack_id,
            "standard_code": pack.standard.code,
            "version_id": version_id,
            "created": created,
            "builtin": False,
            "fingerprint": pack.fingerprint,
        }

    def _load_snapshot(
        self, pack_version_ids: Sequence[int] | None
    ) -> tuple[list[RulePack], dict[str, int], list[int]]:
        if pack_version_ids is None:
            rows = self.store.active_versions()
            if not rows:
                raise ClassificationServiceError(
                    "no rule packs registered; run ensure_builtin_packs first"
                )
        else:
            rows = self.store.versions_for(list(pack_version_ids))
        packs: list[RulePack] = []
        version_ids: dict[str, int] = {}
        for row in rows:
            content = json.loads(row["content_json"])
            from .rulepacks import _parse_pack  # local import keeps public API small

            pack = _parse_pack(content, Path(row["source_path"]) if row["source_path"] else None,
                               builtin=bool(row["builtin"]))
            if pack.fingerprint != row["fingerprint"]:
                raise ClassificationServiceError(
                    f"stored content for version {row['version_id']} fails fingerprint check"
                )
            packs.append(pack)
            version_ids[pack.standard.code] = row["version_id"]
        ordered_ids = [row["version_id"] for row in rows]
        return packs, version_ids, ordered_ids

    # ----- findings ----------------------------------------------------------

    def _findings_map(self, fingerprint: str) -> dict[tuple[str, str], dict[str, Any]]:
        return {
            (item["table_name"], item["column_name"]): item
            for item in self.catalog.findings_for(fingerprint)
        }

    def _headerless_findings(
        self, tolerated: TolerantInventory
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Content-only detection for headerless CSV; nothing is written to the catalog."""
        inventory = tolerated.inventory
        findings: dict[tuple[str, str], dict[str, Any]] = {}
        for table in inventory.tables:
            for index, column in enumerate(table.columns):
                if tolerated.headerless:
                    samples = read_headerless_column_samples(
                        inventory.path, index, self.sample_limit
                    )
                else:
                    samples = read_column_samples(
                        inventory.path, inventory.kind, table.name,
                        column.name, self.sample_limit,
                    )
                result = analyze_values(
                    samples,
                    sample_limit=self.sample_limit,
                    table=table.name,
                    column=column.name,
                )
                record = result.to_record(inventory.fingerprint, table.name, column.name)
                findings[(table.name, column.name)] = record
        return findings

    # ----- classification ----------------------------------------------------

    def classify_dataset(
        self,
        path: str | Path,
        pack_version_ids: Sequence[int] | None = None,
    ) -> dict[str, Any]:
        tolerated = inspect_tolerant(path, max_nesting_depth=self.max_nesting_depth)
        inventory = tolerated.inventory
        packs, version_id_map, ordered_ids = self._load_snapshot(pack_version_ids)
        findings: dict[tuple[str, str], dict[str, Any]]
        if tolerated.headerless:
            findings = self._headerless_findings(tolerated)
        else:
            # Reuse the existing discovery + findings storage: register the
            # dataset, run the detectors, and persist findings into the catalog.
            self.catalog.register(inventory)
            scan_inventory(inventory, self.catalog, sample_limit=self.sample_limit)
            findings = self._findings_map(inventory.fingerprint)
        engine = ClassificationEngine(
            packs, version_id_map, max_nesting_depth=self.max_nesting_depth
        )
        all_alerts: list[Alert] = list(tolerated.alerts)
        results: list[FieldClassification] = []
        degraded_columns = {
            (alert.table, alert.column)
            for alert in tolerated.alerts
            if alert.code == "nested_depth"
        }
        for table in inventory.tables:
            for column in table.columns:
                finding = findings.get((table.name, column.name))
                item = ColumnInput(
                    table=table.name,
                    column=column.name,
                    sensitive_type=finding["sensitive_type"] if finding else None,
                    detection_confidence=finding["confidence"] if finding else "none",
                    candidates=tuple(finding.get("candidates", ())) if finding else (),
                    name_match_available=not tolerated.headerless,
                    degraded=(tolerated.headerless
                              or (table.name, column.name) in degraded_columns),
                )
                column_alerts = [
                    alert
                    for alert in tolerated.alerts
                    if alert.table == table.name and alert.column == column.name
                ]
                result = engine.classify_column(
                    inventory.fingerprint, item, degraded_alerts=column_alerts
                )
                results.append(result)
        results = engine.enforce_semantic_consistency(results)
        for result in results:
            all_alerts.extend(result.alerts)
            self.store.upsert_classification(result.to_dict())
        job_id = _job_id()
        self.store.record_job(
            job_id=job_id,
            dataset_fingerprint=inventory.fingerprint,
            dataset_path=str(inventory.path),
            pack_version_ids=ordered_ids,
            degraded=tolerated.degraded,
            alert_count=len(all_alerts),
            field_count=len(results),
        )
        if self.audit:
            self.audit.append(
                {
                    "event": "classification_job",
                    "job_id": job_id,
                    "dataset_path": str(inventory.path),
                    "dataset_fingerprint": inventory.fingerprint,
                    "rule_pack_version_ids": ordered_ids,
                    "field_count": len(results),
                    "alert_count": len(all_alerts),
                    "degraded": tolerated.degraded,
                }
            )
        return {
            "job_id": job_id,
            "inventory": inventory,
            "results": results,
            "alerts": all_alerts,
            "pack_version_ids": ordered_ids,
            "headerless": tolerated.headerless,
        }

    def classify_many(
        self,
        paths: Sequence[str | Path],
        pack_version_ids: Sequence[int] | None = None,
    ) -> list[dict[str, Any]]:
        """Pin one snapshot up front so every dataset in the batch uses identical versions."""
        _packs, _map, ordered_ids = self._load_snapshot(pack_version_ids)
        outcomes: list[dict[str, Any]] = []
        for path in paths:
            try:
                outcome = self.classify_dataset(path, pack_version_ids=ordered_ids)
            except Exception as exc:  # one bad dataset must not abort the batch
                outcome = {
                    "job_id": None,
                    "path": str(path),
                    "error": str(exc),
                    "alerts": [
                        Alert(
                            code="dataset_failed",
                            severity="warning",
                            message=f"数据集分级失败但流程继续：{exc}",
                            detail={"path": str(path)},
                        )
                    ],
                }
            outcomes.append(outcome)
        return outcomes

    # ----- manual correction -------------------------------------------------

    def correct_field(
        self,
        dataset_fingerprint: str,
        table: str,
        column: str,
        standard_code: str,
        level: str | None,
        category: str | None,
        controls: Sequence[str] | None,
        reason: str,
        operator: str,
        special_category: bool | None = None,
        cross_border: bool | None = None,
    ) -> dict[str, Any]:
        if not reason.strip() or not operator.strip():
            raise ClassificationServiceError("correction requires a non-empty reason and operator")
        current = self.store.get_classification(dataset_fingerprint, table, column)
        if current is None:
            raise ClassificationServiceError(
                f"no classification found for {table}.{column}"
            )
        index = next(
            (i for i, std in enumerate(current["standards"])
             if std["standard_code"] == standard_code),
            None,
        )
        if index is None:
            raise ClassificationServiceError(
                f"standard {standard_code!r} was not applied to {table}.{column}"
            )
        previous = current["standards"][index]
        # Validate a manual level against the level order of the pack that
        # produced the original label.
        pack_row = self.store.pack_version(previous["rule_pack_version_id"])
        if level is not None and pack_row is not None:
            pack_content = json.loads(pack_row["content_json"])
            if level not in pack_content["level_order"]:
                raise ClassificationServiceError(
                    f"level {level!r} is not in level_order "
                    f"{pack_content['level_order']} of standard {standard_code!r}"
                )
        corrected = dict(previous)
        if level is not None:
            corrected["level"] = level
        if category is not None:
            corrected["category"] = category
        if controls is not None:
            corrected["controls"] = list(controls)
        if special_category is not None:
            corrected["special_category"] = bool(special_category)
        if cross_border is not None:
            corrected["cross_border"] = bool(cross_border)
        corrected["match_basis"] = "manual"
        chain_entry = self.store.append_correction(
            dataset_fingerprint=dataset_fingerprint,
            table=table,
            column=column,
            standard_code=standard_code,
            previous=previous,
            corrected=corrected,
            reason=reason,
            operator=operator,
        )
        updated = self.store.update_standard_result(
            dataset_fingerprint, table, column, standard_code, corrected
        )
        if self.audit:
            self.audit.append(
                {
                    "event": "classification_correction",
                    "dataset_fingerprint": dataset_fingerprint,
                    "table_name": table,
                    "column_name": column,
                    "standard_code": standard_code,
                    "previous": previous,
                    "corrected": corrected,
                    "reason": reason,
                    "operator": operator,
                    "correction_id": chain_entry["correction_id"],
                    "correction_entry_hash": chain_entry["entry_hash"],
                }
            )
        return {
            "correction": chain_entry,
            "previous": previous,
            "corrected": corrected,
            "record": updated["record"],
        }

    # ----- fingerprint-driven re-classification ------------------------------

    def reclassify_changed(
        self, pack_version_ids: Sequence[int] | None = None
    ) -> dict[str, Any]:
        """Re-run datasets whose current fingerprint differs from the last classified one."""
        # Pin the snapshot once so a mid-batch pack publish cannot split versions.
        _packs, _map, ordered_ids = self._load_snapshot(pack_version_ids)
        states = self.store.conn.execute(
            "SELECT * FROM dataset_classification_state ORDER BY dataset_path"
        ).fetchall()
        re_run: list[dict[str, Any]] = []
        unchanged: list[dict[str, Any]] = []
        for row in states:
            path = row["dataset_path"]
            source = Path(path)
            if not source.exists():
                re_run.append(
                    {
                        "path": path,
                        "error": "dataset file no longer exists",
                        "previous_fingerprint": row["dataset_fingerprint"],
                    }
                )
                continue
            tolerated = inspect_tolerant(path, max_nesting_depth=self.max_nesting_depth)
            current_fp = tolerated.inventory.fingerprint
            if current_fp == row["dataset_fingerprint"]:
                unchanged.append({"path": path, "fingerprint": current_fp})
                continue
            outcome = self.classify_dataset(path, pack_version_ids=pack_version_ids)
            re_run.append(
                {
                    "path": path,
                    "previous_fingerprint": row["dataset_fingerprint"],
                    "current_fingerprint": current_fp,
                    "job_id": outcome["job_id"],
                    "alert_count": len(outcome["alerts"]),
                }
            )
            if self.audit:
                self.audit.append(
                    {
                        "event": "fingerprint_reclassification",
                        "dataset_path": path,
                        "previous_fingerprint": row["dataset_fingerprint"],
                        "current_fingerprint": current_fp,
                        "job_id": outcome["job_id"],
                    }
                )
        return {"reclassified": re_run, "unchanged": unchanged}

    # ----- read side ---------------------------------------------------------

    def get_results(self, dataset_fingerprint: str) -> list[dict[str, Any]]:
        return self.store.classifications_for(dataset_fingerprint)

    def verify_corrections(self) -> dict[str, Any]:
        return self.store.verify_correction_chain()
