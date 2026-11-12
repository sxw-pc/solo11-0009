"""High-level operations shared by the CLI and the one-command demo."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .audit import AuditLog, build_adjudication_entry, build_audit_entry
from .config import SecretStore
from .dataset_io import discover_datasets
from .detectors.engine import detect_inventory
from .overrides import (
    AppliedOverrides,
    OverrideSet,
    adjudicate_findings,
    dataset_missing_entries,
    load_default_overrides,
    load_overrides,
    resolve_operator,
)
from .policies import Policy
from .registry import Catalog, DatasetInventory, inspect_dataset
from .report import generate_report
from .utils import MasklineError


@dataclass
class ScanSummary:
    inventory: DatasetInventory
    newly_registered: bool
    findings: list[dict[str, Any]]
    adjudications: AppliedOverrides | None = None
    unmatched: list[Any] = field(default_factory=list)
    adjudication_ids: list[int] = field(default_factory=list)


def _policy_columns(policy: Policy | None, inventory: DatasetInventory) -> dict[str, dict[str, str]] | None:
    if policy is None:
        return None
    rule = policy.for_dataset(inventory.path)
    return {
        table_name: {name: detail.transformer for name, detail in table_policy.columns.items()}
        for table_name, table_policy in rule.tables.items()
    }


def _merged_findings(
    inventory: DatasetInventory,
    findings: list[dict[str, Any]],
    overrides: OverrideSet | None,
    policy: Policy | None,
) -> tuple[list[dict[str, Any]], AppliedOverrides | None]:
    records, applied = adjudicate_findings(
        inventory,
        findings,
        overrides,
        policy_columns=_policy_columns(policy, inventory),
    )
    return records, applied


def _persist_and_audit(
    paths: Any,
    catalog: Catalog,
    inventory: DatasetInventory,
    overrides: OverrideSet | None,
    applied: AppliedOverrides | None,
    *,
    emit_audit: bool = True,
) -> list[int]:
    """Write adjudication rows to the registry and one audit event per override."""
    if overrides is None or applied is None or not applied.applied:
        return []
    ids: list[int] = []
    for record in applied.applied:
        conflict = next(
            (
                item
                for item in applied.conflicts
                if item.table == record["table"] and item.column == record["column"]
            ),
            None,
        )
        row_id = catalog.record_adjudication(
            {
                "dataset_fingerprint": inventory.fingerprint,
                "dataset_path": str(inventory.path),
                "table_name": record["table"],
                "column_name": record["column"],
                "decision": record["decision"],
                "reason": record["reason"],
                "operator": overrides.operator,
                "override_fingerprint": overrides.fingerprint,
                "detected_type": record.get("detected_type"),
                "detected_confidence": record.get("detected_confidence"),
                "effective_type": record.get("effective_type"),
                "effective_confidence": record.get("effective_confidence"),
                "policy_conflict": (
                    {
                        "transformer": conflict.transformer,
                        "dataset": conflict.entry.dataset_pattern,
                    }
                    if conflict
                    else None
                ),
            }
        )
        ids.append(row_id)
    if emit_audit:
        AuditLog(paths.audit_path).append(
            build_adjudication_entry(
                dataset_path=inventory.path,
                dataset_fingerprint=inventory.fingerprint,
                overrides=overrides,
                applied=applied,
                registry_ids=ids,
            )
        )
    return ids


def scan_paths(
    targets: Iterable[str | Path],
    paths: Any,
    sample_limit: int = 200,
    overrides: OverrideSet | None = None,
    policy: Policy | None = None,
    use_default_overrides: bool = True,
    operator: str | None = None,
    audit_adjudications: bool = True,
) -> list[ScanSummary]:
    """Scan and register datasets, merging human adjudications into findings.

    When `overrides` is None and `use_default_overrides` is true, the workspace
    `overrides.yaml` is loaded if it exists. When `policy` is given its column
    transformers are used only to detect force_not_sensitive/policy conflicts.
    """
    files: list[Path] = []
    for target in targets:
        files.extend(discover_datasets(target))
    unique = sorted({path.resolve() for path in files}, key=lambda path: path.as_posix())
    if not unique:
        raise MasklineError("no supported dataset files found")
    if overrides is None and use_default_overrides:
        overrides = load_default_overrides(
            paths, operator=resolve_operator(operator)
        )
    summaries: list[ScanSummary] = []
    with Catalog(paths.meta_db) as catalog:
        for path in unique:
            inventory = inspect_dataset(path)
            newly = catalog.register(inventory)
            raw_findings = detect_inventory(inventory, sample_limit=sample_limit)
            findings, applied = _merged_findings(
                inventory, raw_findings, overrides, policy
            )
            for record in findings:
                catalog.save_finding(record)
            ids = _persist_and_audit(
                paths, catalog, inventory, overrides, applied,
                emit_audit=audit_adjudications,
            )
            summaries.append(
                ScanSummary(
                    inventory,
                    newly,
                    findings,
                    adjudications=applied,
                    unmatched=list(applied.unmatched) if applied else [],
                    adjudication_ids=ids,
                )
            )
    if overrides is not None:
        # Entries whose dataset matches nothing in this scan command: the
        # dataset (and possibly its columns) was renamed/removed. Attach each
        # such notice once, to the first dataset summary, so it is never silently
        # dropped and never duplicated per file.
        inventories = [summary.inventory for summary in summaries]
        missing = dataset_missing_entries(overrides, inventories)
        if missing and summaries:
            summaries[0].unmatched.extend(missing)
    return summaries


def findings_for(paths: Any, fingerprint: str) -> list[dict[str, Any]]:
    with Catalog(paths.meta_db) as catalog:
        return catalog.findings_for(fingerprint)


def adjudications_for(paths: Any, fingerprint: str) -> list[dict[str, Any]]:
    with Catalog(paths.meta_db) as catalog:
        return catalog.adjudications_for(fingerprint)


def needs_secret(policy: Policy, inventory: DatasetInventory) -> bool:
    rule = policy.validate_against(inventory)
    return any(
        column.transformer in {"hash", "pseudonym"}
        for table in rule.tables.values()
        for column in table.columns.values()
    )


def secrets_for(
    policy: Policy, inventory: DatasetInventory, auto_path: Path | None = None
) -> SecretStore | None:
    if not needs_secret(policy, inventory):
        return None
    from .config import resolve_secret_store
    return resolve_secret_store(auto_path)


def finalize_run(
    paths: Any,
    inventory: DatasetInventory,
    policy: Policy,
    result: Any,
    findings: list[dict[str, Any]],
    adjudications: AppliedOverrides | None = None,
) -> dict[str, Any]:
    report_paths = generate_report(
        paths, inventory, policy, result, findings, adjudications=adjudications
    )
    entry = build_audit_entry(
        result,
        result.transformer_map,
        extra=(
            {
                "operator": adjudications.operator,
                "override_file": adjudications.override_file,
                "override_fingerprint": adjudications.override_fingerprint,
                "adjudications": _adjudication_audit_payload(adjudications),
            }
            if adjudications
            else None
        ),
    )
    audit_entry = AuditLog(paths.audit_path).append(entry)
    return {"report": report_paths, "audit": audit_entry}


def _adjudication_audit_payload(adjudications: AppliedOverrides) -> dict[str, Any]:
    return {
        "applied": adjudications.applied,
        "conflicts": [
            {
                "dataset": conflict.entry.dataset_pattern,
                "table": conflict.table,
                "column": conflict.column,
                "decision": conflict.entry.decision,
                "transformer": conflict.transformer,
            }
            for conflict in adjudications.conflicts
        ],
        "unmatched": [item.to_dict() for item in adjudications.unmatched],
    }


def merge_run_findings(
    inventory: DatasetInventory,
    findings: list[dict[str, Any]],
    overrides: OverrideSet | None,
    policy: Policy | None = None,
) -> tuple[list[dict[str, Any]], AppliedOverrides | None]:
    """Apply overrides to already-detected findings for a run (no writes)."""
    return _merged_findings(inventory, findings, overrides, policy)
