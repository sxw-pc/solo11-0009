"""High-level operations shared by the CLI and the one-command demo."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .audit import AuditLog, build_audit_entry
from .config import SecretStore
from .dataset_io import discover_datasets
from .detectors.engine import scan_inventory
from .policies import Policy
from .registry import Catalog, DatasetInventory, inspect_dataset
from .report import generate_report
from .utils import MasklineError


@dataclass
class ScanSummary:
    inventory: DatasetInventory
    newly_registered: bool
    findings: list[dict[str, Any]]


def scan_paths(
    targets: Iterable[str | Path], paths: Any, sample_limit: int = 200
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
            summaries.append(ScanSummary(inventory, newly, findings))
    return summaries


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
) -> dict[str, Any]:
    report_paths = generate_report(paths, inventory, policy, result, findings)
    entry = build_audit_entry(
        result,
        result.transformer_map,
        extra={"target_kind": getattr(result, "target_kind", "sqlite")},
    )
    audit_entry = AuditLog(paths.audit_path).append(entry)
    return {"report": report_paths, "audit": audit_entry}
