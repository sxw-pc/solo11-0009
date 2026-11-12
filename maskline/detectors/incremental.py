"""Incremental scan planning and execution.

A scan compares the freshly inspected inventory against the fingerprints stored
in the registry and decides, per table, whether detector evidence can be
reused or must be regenerated:

* ``reuse``            - structure, per-column content hashes and row count all
                         match; the stored findings are copied verbatim and the
                         detector never touches the table's data.
* ``rescan_columns``   - only structure-level or single-column changes; just
                         the added/changed columns are sampled and scored,
                         findings of untouched columns stay byte-identical.
* ``rescan_table``     - row count moved beyond the configured ratio, the
                         detector version or sample limit changed, or no
                         trustworthy baseline exists (first scan / migrated v1
                         registry without column hashes).

Every write for one dataset happens inside a single catalog transaction, so a
Ctrl-C rolls the whole dataset back and the next scan starts from the previous
committed state.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from ..dataset_io import read_column_samples
from ..registry import (
    DEFAULT_ROW_COUNT_CHANGE_RATIO,
    DETECTOR_VERSION,
    Catalog,
    ColumnInfo,
    DatasetInventory,
    TableInfo,
    stable_dataset_id,
)
from .engine import analyze_values

ACTION_REUSE = "reuse"
ACTION_RESCAN_COLUMNS = "rescan_columns"
ACTION_RESCAN_TABLE = "rescan_table"
ACTION_NEW_TABLE = "new_table"


@dataclass
class TablePlan:
    table: TableInfo
    action: str
    reason: str
    columns_to_scan: list[str] = field(default_factory=list)


@dataclass
class IncrementalResult:
    inventory: DatasetInventory
    dataset_id: str
    scan_id: str
    plans: list[TablePlan]
    findings: list[dict[str, Any]]
    reused_tables: int = 0
    rescanned_tables: int = 0
    new_tables: int = 0
    reused_columns: int = 0
    scanned_columns: int = 0

    @property
    def total_tables(self) -> int:
        return len(self.plans)


def _row_count_changed(old_count: int, new_count: int, ratio: float) -> bool:
    """Significant row-count change, relative to the previously seen size.

    A brand-new (previously empty) table is always considered significant.
    """
    if old_count <= 0:
        return new_count > 0
    return abs(new_count - old_count) / old_count > ratio


def plan_scan(
    inventory: DatasetInventory,
    catalog: Catalog,
    sample_limit: int = 200,
    row_count_ratio: float = DEFAULT_ROW_COUNT_CHANGE_RATIO,
    force_full: bool = False,
) -> list[TablePlan]:
    dataset_id = stable_dataset_id(inventory.path)
    state = catalog.dataset_state(dataset_id)
    previous = catalog.table_states(dataset_id) if state else {}
    plans: list[TablePlan] = []
    for table in inventory.tables:
        old = previous.get(table.name)
        if force_full:
            plans.append(
                TablePlan(table, ACTION_RESCAN_TABLE, "forced full scan",
                          [col.name for col in table.columns])
            )
            continue
        if old is None:
            plans.append(
                TablePlan(table, ACTION_NEW_TABLE, "no previous fingerprint",
                          [col.name for col in table.columns])
            )
            continue
        # Baseline produced by another detector generation / sampling budget:
        # its evidence is not comparable, rescore everything.
        if old["detector_version"] != DETECTOR_VERSION or old["sample_limit"] != sample_limit:
            plans.append(
                TablePlan(table, ACTION_RESCAN_TABLE,
                          f"detector/sample baseline changed "
                          f"({old['detector_version']}@{old['sample_limit']} -> "
                          f"{DETECTOR_VERSION}@{sample_limit})",
                          [col.name for col in table.columns])
            )
            continue
        if _row_count_changed(old["row_count"], table.row_count, row_count_ratio):
            plans.append(
                TablePlan(table, ACTION_RESCAN_TABLE,
                          f"row count changed significantly: "
                          f"{old['row_count']} -> {table.row_count}",
                          [col.name for col in table.columns])
            )
            continue
        if old["structure_fingerprint"] != table.structure_fingerprint:
            old_cols = {item["name"]: item for item in old["columns"]}
            to_scan = [
                col.name
                for col in table.columns
                if _column_needs_scan(col, old_cols.get(col.name))
            ]
            plans.append(
                TablePlan(table, ACTION_RESCAN_COLUMNS,
                          "structure changed; only added/changed columns rescored",
                          to_scan)
            )
            continue
        if old["content_fingerprint"] != table.content_fingerprint:
            # Same shape, different values: per-column hashes localize it.
            old_cols = {item["name"]: item for item in old["columns"]}
            to_scan = [
                col.name
                for col in table.columns
                if col.content_fingerprint
                != old_cols.get(col.name, {}).get("content_fingerprint", "")
            ]
            plans.append(
                TablePlan(table, ACTION_RESCAN_COLUMNS,
                          "content changed; only changed columns rescored",
                          to_scan or [col.name for col in table.columns])
            )
            continue
        plans.append(TablePlan(table, ACTION_REUSE, "fingerprints identical"))
    return plans


def _column_needs_scan(col: ColumnInfo, old_col: dict[str, Any] | None) -> bool:
    if old_col is None:
        return True  # newly added column
    if old_col.get("structure_fingerprint") != col.structure_fingerprint:
        return True  # type/nullability changed
    if (
        old_col.get("content_fingerprint")
        and old_col.get("content_fingerprint") != col.content_fingerprint
    ):
        return True  # values of an existing column changed too
    return False


def _score_column(
    inventory: DatasetInventory, table: TableInfo, column_name: str, sample_limit: int
) -> dict[str, Any]:
    samples = read_column_samples(
        inventory.path, inventory.kind, table.name, column_name, sample_limit
    )
    result = analyze_values(
        samples, sample_limit=sample_limit, table=table.name, column=column_name
    )
    return result.to_record("", table.name, column_name)


def run_incremental_scan(
    inventory: DatasetInventory,
    catalog: Catalog,
    sample_limit: int = 200,
    row_count_ratio: float = DEFAULT_ROW_COUNT_CHANGE_RATIO,
    force_full: bool = False,
) -> IncrementalResult:
    """Execute an incremental scan, persisting fingerprints and findings atomically."""
    dataset_id = stable_dataset_id(inventory.path)
    scan_id = f"scan-{uuid.uuid4().hex}"
    plans = plan_scan(
        inventory,
        catalog,
        sample_limit=sample_limit,
        row_count_ratio=row_count_ratio,
        force_full=force_full,
    )
    catalog.reap_stale_scans()
    # Score outside the write transaction: sampling reads can be slow and must
    # not hold the catalog write lock. Only persistence is transactional.
    scored: dict[tuple[str, str], dict[str, Any]] = {}
    for plan in plans:
        if plan.action == ACTION_REUSE:
            continue
        for column_name in plan.columns_to_scan:
            scored[(plan.table.name, column_name)] = _score_column(
                inventory, plan.table, column_name, sample_limit
            )
    with catalog.transaction():
        catalog.begin_scan_run(scan_id, dataset_id, inventory.path)
        catalog.upsert_dataset_record(inventory, dataset_id)
        for plan in plans:
            table = plan.table
            catalog.record_table_action(
                scan_id, dataset_id, table.name, plan.action, plan.reason,
                plan.columns_to_scan,
            )
            if plan.action == ACTION_REUSE:
                catalog.replace_table_fingerprint(
                    dataset_id, table, sample_limit, DETECTOR_VERSION
                )
                continue
            # A structure change may have removed columns: drop their findings.
            live_columns = {col.name for col in table.columns}
            stale = [
                name
                for name in _stored_column_names(catalog, dataset_id, table.name)
                if name not in live_columns
            ]
            catalog.delete_findings(dataset_id, table.name, stale)
            fresh = [
                scored[(table.name, name)] for name in plan.columns_to_scan
            ]
            catalog.save_findings_bulk(dataset_id, fresh)
            if plan.action == ACTION_RESCAN_TABLE:
                # Defensive: a full rescan replaces every column of the table,
                # so any finding without a live column must already be gone.
                assert not stale
            catalog.replace_table_fingerprint(
                dataset_id, table, sample_limit, DETECTOR_VERSION
            )
        catalog.finish_scan_run(scan_id)
    findings = catalog.findings_for_dataset(dataset_id)
    return _summarize(inventory, dataset_id, scan_id, plans, findings)


def _stored_column_names(catalog: Catalog, dataset_id: str, table: str) -> list[str]:
    rows = catalog.conn.execute(
        "SELECT column_name FROM findings_v2 WHERE dataset_id=? AND table_name=?",
        (dataset_id, table),
    ).fetchall()
    return [row[0] for row in rows]


def _summarize(
    inventory: DatasetInventory,
    dataset_id: str,
    scan_id: str,
    plans: list[TablePlan],
    findings: list[dict[str, Any]],
) -> IncrementalResult:
    reused_tables = sum(1 for plan in plans if plan.action == ACTION_REUSE)
    new_tables = sum(1 for plan in plans if plan.action == ACTION_NEW_TABLE)
    rescanned_tables = len(plans) - reused_tables - new_tables
    scanned_columns = sum(len(plan.columns_to_scan) for plan in plans if plan.action != ACTION_REUSE)
    reused_columns = sum(
        len(plan.table.columns) for plan in plans if plan.action == ACTION_REUSE
    ) + sum(
        len(plan.table.columns) - len(plan.columns_to_scan)
        for plan in plans
        if plan.action == ACTION_RESCAN_COLUMNS
    )
    return IncrementalResult(
        inventory=inventory,
        dataset_id=dataset_id,
        scan_id=scan_id,
        plans=plans,
        findings=findings,
        reused_tables=reused_tables,
        rescanned_tables=rescanned_tables,
        new_tables=new_tables,
        reused_columns=reused_columns,
        scanned_columns=scanned_columns,
    )
