"""High-level operations shared by the CLI and the one-command demo."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .audit import AuditLog, build_audit_entry
from .config import SecretStore
from .dataset_io import discover_datasets
from .detectors.engine import detect_inventory
from .overrides import (
    OverrideApplication,
    OverrideSet,
    apply_overrides,
    build_override_audit_entry,
    now_utc,
    resolve_operator,
    unmatched_without_dataset,
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
    override_application: OverrideApplication | None = None


def scan_paths(
    targets: Iterable[str | Path],
    paths: Any,
    sample_limit: int = 200,
    overrides: OverrideSet | None = None,
) -> list[ScanSummary]:
    files: list[Path] = []
    for target in targets:
        files.extend(discover_datasets(target))
    unique = sorted({path.resolve() for path in files}, key=lambda path: path.as_posix())
    if not unique:
        raise MasklineError("no supported dataset files found")
    operator: str | None = None
    override_at: str | None = None
    audit: AuditLog | None = None
    if overrides is not None and overrides.entries:
        operator = resolve_operator()
        override_at = now_utc()
        audit = AuditLog(paths.audit_path)
    summaries: list[ScanSummary] = []
    inventories: list[DatasetInventory] = []
    with Catalog(paths.meta_db) as catalog:
        for path in unique:
            inventory = inspect_dataset(path)
            inventories.append(inventory)
            newly = catalog.register(inventory)
            findings = detect_inventory(inventory, sample_limit=sample_limit)
            application = apply_overrides(
                inventory,
                findings,
                overrides,
                operator=operator,
                at=override_at,
            )
            for record in application.findings:
                catalog.save_finding(record)
            summaries.append(
                ScanSummary(inventory, newly, application.findings, application)
            )
            if audit is not None:
                assert operator is not None and override_at is not None
                for item in application.applied:
                    audit.append(
                        build_override_audit_entry(
                            item, overrides, operator, override_at, matched=True
                        )
                    )
                for item in application.unmatched:
                    audit.append(
                        build_override_audit_entry(
                            item, overrides, operator, override_at, matched=False
                        )
                    )
    if overrides is not None and overrides.entries:
        unmatched = unmatched_without_dataset(overrides, inventories)
        if unmatched and summaries:
            summaries[0].override_application.unmatched.extend(unmatched)
        if audit is not None:
            assert operator is not None and override_at is not None
            for item in unmatched:
                audit.append(
                    build_override_audit_entry(
                        item, overrides, operator, override_at, matched=False
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
    override_application: OverrideApplication | None = None,
) -> dict[str, Any]:
    report_paths = generate_report(
        paths,
        inventory,
        policy,
        result,
        findings,
        override_application=override_application,
    )
    entry = build_audit_entry(result, result.transformer_map)
    audit_entry = AuditLog(paths.audit_path).append(entry)
    return {"report": report_paths, "audit": audit_entry}
