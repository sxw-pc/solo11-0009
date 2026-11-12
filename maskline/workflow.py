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
from .registry import Catalog, DatasetInventory, inspect_dataset, stable_dataset_id
from .report import generate_report
from .utils import MasklineError


@dataclass
class ScanSummary:
    inventory: DatasetInventory
    newly_registered: bool
    findings: list[dict[str, Any]]
    reused_tables: int = 0
    rescanned_tables: int = 0
    new_tables: int = 0
    reused_columns: int = 0
    scanned_columns: int = 0
    scan_id: str = ""
    force_full: bool = False


def scan_paths(
    targets: Iterable[str | Path],
    paths: Any,
    sample_limit: int = 200,
    force_full: bool = False,
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
            dataset_id = stable_dataset_id(inventory.path)
            was_known = catalog.dataset_state(dataset_id) is not None
            result = scan_inventory(
                inventory,
                catalog,
                sample_limit=sample_limit,
                force_full=force_full,
            )
            summaries.append(
                ScanSummary(
                    inventory=inventory,
                    newly_registered=not was_known,
                    findings=result.findings,
                    reused_tables=result.reused_tables,
                    rescanned_tables=result.rescanned_tables,
                    new_tables=result.new_tables,
                    reused_columns=result.reused_columns,
                    scanned_columns=result.scanned_columns,
                    scan_id=result.scan_id,
                    force_full=force_full,
                )
            )
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
    entry = build_audit_entry(result, result.transformer_map)
    audit_entry = AuditLog(paths.audit_path).append(entry)
    return {"report": report_paths, "audit": audit_entry}
