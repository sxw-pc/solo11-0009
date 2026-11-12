"""High-level operations shared by the CLI and the one-command demo."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .audit import AuditLog, build_audit_entry
from .config import SecretStore
from .dataset_io import discover_datasets
from .detectors.engine import scan_inventory
from .drift import DriftIgnoreRules, DriftReport, compare_findings
from .policies import Policy
from .registry import Catalog, DatasetInventory, inspect_dataset
from .report import generate_report
from .utils import MasklineError


@dataclass
class ScanSummary:
    inventory: DatasetInventory
    newly_registered: bool
    findings: list[dict[str, Any]]
    drift: DriftReport | None = None


def _detect_and_record_drift(
    catalog: Catalog,
    paths: Any,
    inventory: DatasetInventory,
    findings: list[dict[str, Any]],
    ignore_rules: DriftIgnoreRules | None,
) -> DriftReport | None:
    """Compare a freshly registered version against its predecessor.

    The comparison runs on stored findings only. When a baseline with
    findings exists, the drift record is appended to the tamper-evident
    audit chain and indexed in the catalog, even when no drift was found
    (the entry attests that the version transition was checked).
    """
    baseline: dict[str, Any] | None = None
    for version in reversed(catalog.datasets_for_path(inventory.path)):
        if version["fingerprint"] != inventory.fingerprint:
            baseline = version
            break
    if baseline is None:
        return None
    baseline_findings = catalog.findings_for(baseline["fingerprint"])
    if not baseline_findings:
        return None
    report = compare_findings(
        baseline_findings,
        findings,
        dataset_path=str(inventory.path),
        baseline_fingerprint=baseline["fingerprint"],
        current_fingerprint=inventory.fingerprint,
        ignore_rules=ignore_rules,
    )
    record = report.to_record()
    entry = AuditLog(paths.audit_path).append({"kind": "dataset_drift", **record})
    report.audit_seq = entry["seq"]
    report.audit_entry_hash = entry["entry_hash"]
    catalog.save_drift_report(record, audit_seq=entry["seq"])
    return report


def scan_paths(
    targets: Iterable[str | Path],
    paths: Any,
    sample_limit: int = 200,
    ignore_rules: DriftIgnoreRules | None = None,
) -> list[ScanSummary]:
    files: list[Path] = []
    for target in targets:
        files.extend(discover_datasets(target))
    unique = sorted({path.resolve() for path in files}, key=lambda path: path.as_posix())
    if not unique:
        raise MasklineError("no supported dataset files found")
    summaries: list[ScanSummary] = []
    with Catalog(paths.meta_db) as catalog:
        for path in unique:
            inventory = inspect_dataset(path)
            newly = catalog.register(inventory)
            findings = scan_inventory(inventory, catalog, sample_limit=sample_limit)
            drift = None
            if newly:
                drift = _detect_and_record_drift(
                    catalog, paths, inventory, findings, ignore_rules
                )
            summaries.append(ScanSummary(inventory, newly, findings, drift))
    return summaries


def compare_dataset_versions(
    paths: Any,
    dataset_path: str | Path,
    ignore_rules: DriftIgnoreRules | None = None,
) -> DriftReport | None:
    """Read-only on-demand comparison of the two latest registered versions."""
    resolved = Path(dataset_path).expanduser().resolve()
    with Catalog(paths.meta_db) as catalog:
        versions = catalog.datasets_for_path(resolved)
        if len(versions) < 2:
            return None
        baseline, current = versions[-2], versions[-1]
        baseline_findings = catalog.findings_for(baseline["fingerprint"])
        current_findings = catalog.findings_for(current["fingerprint"])
    if not baseline_findings or not current_findings:
        return None
    return compare_findings(
        baseline_findings,
        current_findings,
        dataset_path=str(resolved),
        baseline_fingerprint=baseline["fingerprint"],
        current_fingerprint=current["fingerprint"],
        ignore_rules=ignore_rules,
    )


def findings_for(paths: Any, fingerprint: str) -> list[dict[str, Any]]:
    with Catalog(paths.meta_db) as catalog:
        return catalog.findings_for(fingerprint)


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
    drift: DriftReport | None = None,
) -> dict[str, Any]:
    report_paths = generate_report(paths, inventory, policy, result, findings, drift=drift)
    entry = build_audit_entry(result, result.transformer_map)
    if drift is not None and drift.audit_seq is not None:
        entry["drift_ref"] = {
            "audit_seq": drift.audit_seq,
            "entry_hash": drift.audit_entry_hash,
            "active_events": drift.summary()["active"],
        }
    audit_entry = AuditLog(paths.audit_path).append(entry)
    return {"report": report_paths, "audit": audit_entry}
