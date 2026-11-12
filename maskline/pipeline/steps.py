"""Low-level batch, schema-copy, and row-transformation steps for the runner."""

from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..dataset_io import iter_csv_tuples, iter_table_rows, sqlite_schema_sql
from ..json_ import JsonRunState, transform_json_cell
from ..registry import DatasetInventory, TableInfo
from ..transformers import REGISTRY, TransformContext
from ..utils import quote_ident
from .errors import PipelineError


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"run-{stamp}-{secrets.token_hex(3)}"


def merge_counts(
    target: dict[str, dict[str, int]], source: dict[str, dict[str, int]]
) -> None:
    for name, values in source.items():
        slot = target.setdefault(name, {"seen": 0, "processed": 0, "changed": 0})
        for key in ("seen", "processed", "changed"):
            slot[key] = slot.get(key, 0) + int(values.get(key, 0))


def csv_batches(
    path: Path, after: int, size: int
) -> Iterator[list[tuple[int, tuple[str, ...]]]]:
    batch: list[tuple[int, tuple[str, ...]]] = []
    for index, row in enumerate(iter_csv_tuples(path), start=1):
        if index <= after:
            continue
        batch.append((index, row))
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def source_batches(
    inventory: DatasetInventory, table: TableInfo, after: int, size: int
) -> Iterator[list[tuple[int, tuple[Any, ...]]]]:
    if inventory.kind == "csv":
        yield from csv_batches(inventory.path, after, size)
        return
    cursor = after
    while True:
        _columns, batch = iter_table_rows(inventory.path, table.name, cursor, size)
        if not batch:
            return
        yield batch
        cursor = batch[-1][0]


def create_target(inventory: DatasetInventory, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(output) + suffix)
        if candidate.exists():
            candidate.unlink()
    conn = sqlite3.connect(output)
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
        if inventory.kind == "sqlite":
            schemas = sqlite_schema_sql(inventory.path)
            for table in inventory.tables:
                sql = schemas.get(table.name)
                if not sql:
                    raise PipelineError(f"cannot copy schema for table {table.name!r}")
                conn.execute(sql)
        else:
            for table in inventory.tables:
                definitions = ", ".join(
                    f"{quote_ident(column.name)} TEXT" for column in table.columns
                )
                conn.execute(f"CREATE TABLE {quote_ident(table.name)} ({definitions})")
        conn.commit()
    finally:
        conn.close()


def transform_row(
    row: tuple[Any, ...],
    table: TableInfo,
    table_policy: Any,
    context: TransformContext,
    table_counts: dict[str, dict[str, int]],
    json_state: JsonRunState | None = None,
    rowid: int | None = None,
) -> tuple[Any, ...]:
    if table_policy is None:
        return row
    output: list[Any] = []
    for column, value in zip(table.columns, row):
        policy = table_policy.columns.get(column.name)
        if policy is None:
            output.append(value)
            continue
        if policy.json_config is not None and json_state is not None:
            json_config = policy.json_config
            transformed, _outcome = transform_json_cell(
                value,
                json_config.path_rules,
                json_config.fallback_transformer,
                json_config.fallback_params,
                json_config.limits,
                context,
                json_state.for_column(column.name),
                rowid,
                table.name,
                column.name,
            )
            if policy.transformer:
                # Column-level transformer counts still describe whole-column scope.
                counts = table_counts.setdefault(
                    policy.transformer, {"seen": 0, "processed": 0, "changed": 0}
                )
                counts["seen"] += 1
                if value is not None and value != "":
                    counts["processed"] += 1
                if transformed != value:
                    counts["changed"] += 1
            output.append(transformed)
            continue
        counts = table_counts.setdefault(
            policy.transformer, {"seen": 0, "processed": 0, "changed": 0}
        )
        counts["seen"] += 1
        if value is not None and value != "":
            counts["processed"] += 1
        context.table = table.name
        context.column = column.name
        transformed = REGISTRY.get(policy.transformer).transform(value, policy.params, context)
        if transformed != value:
            counts["changed"] += 1
        output.append(transformed)
    return tuple(output)


def insert_batch(
    conn: sqlite3.Connection,
    table: TableInfo,
    rows: list[tuple[int, tuple[Any, ...]]],
) -> None:
    if not rows:
        return
    columns = [column.name for column in table.columns]
    placeholders = ", ".join("?" for _ in range(len(columns) + 1))
    column_sql = ", ".join(quote_ident(name) for name in columns)
    statement = (
        f"INSERT INTO {quote_ident(table.name)} (rowid, {column_sql}) "
        f"VALUES ({placeholders})"
    )
    low, high = rows[0][0], rows[-1][0]
    conn.execute(
        f"DELETE FROM {quote_ident(table.name)} WHERE rowid BETWEEN ? AND ?", (low, high)
    )
    conn.executemany(statement, [(rowid, *values) for rowid, values in rows])
