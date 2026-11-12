"""Low-level batch, schema-copy, and row-transformation steps for the runner."""

from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, TYPE_CHECKING

from ..dataset_io import iter_csv_tuples, iter_table_rows, sqlite_schema_sql
from ..registry import DatasetInventory, TableInfo
from ..transformers import REGISTRY, TransformContext
from ..utils import quote_ident
from .errors import PipelineError

if TYPE_CHECKING:
    from .checkpoint import CheckpointStore


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


def table_creation_sql(
    inventory: DatasetInventory,
    table: TableInfo,
    schemas: dict[str, str] | None = None,
) -> str:
    """CREATE TABLE statement for one target table, copied from the source."""
    if inventory.kind == "sqlite":
        if schemas is None:
            schemas = sqlite_schema_sql(inventory.path)
        sql = schemas.get(table.name)
        if not sql:
            raise PipelineError(f"cannot copy schema for table {table.name!r}")
        return sql
    definitions = ", ".join(
        f"{quote_ident(column.name)} TEXT" for column in table.columns
    )
    return f"CREATE TABLE {quote_ident(table.name)} ({definitions})"


def create_target(inventory: DatasetInventory, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    # Remove stale sidecars too, so a leftover journal from a crashed run
    # never has to be reconciled against the freshly created database.
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(str(output) + suffix)
        if candidate.exists():
            candidate.unlink()
    conn = sqlite3.connect(output)
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
        schemas = sqlite_schema_sql(inventory.path) if inventory.kind == "sqlite" else None
        for table in inventory.tables:
            conn.execute(table_creation_sql(inventory, table, schemas))
        conn.commit()
    finally:
        conn.close()


def reconcile_target_with_checkpoints(
    target: sqlite3.Connection,
    store: "CheckpointStore",
    run_id: str,
    inventory: DatasetInventory,
) -> None:
    """Bring a resumable target database back in line with its checkpoints.

    A crash can leave the target ahead of the checkpoint database (batch
    committed, checkpoint not yet saved) or — for artifacts of older
    versions — behind it. Afterwards every checkpointed table holds exactly
    the rows its checkpoint describes, so replaying the remaining batches
    reproduces a full uninterrupted run. Every operation here is
    idempotent: if the process dies mid-reconcile, the next resume simply
    reconciles again.
    """
    existing = {
        row[0]
        for row in target.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    for table in inventory.tables:
        quoted = quote_ident(table.name)
        if table.name not in existing:
            # The target lost a table (e.g. crash during schema creation of
            # an older version); recreate it and reprocess from scratch.
            target.execute(table_creation_sql(inventory, table))
            store.delete_checkpoint(run_id, table.name)
            continue
        checkpoint = store.get_checkpoint(run_id, table.name)
        if checkpoint is None:
            # Rows without a checkpoint are stragglers from a batch that
            # committed before its checkpoint was saved; drop them.
            target.execute(f"DELETE FROM {quoted}")
            continue
        target.execute(
            f"DELETE FROM {quoted} WHERE rowid > ?", (checkpoint.last_rowid,)
        )
        count = int(
            target.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
        )
        if count != checkpoint.rows_done:
            # The committed prefix diverges from the checkpoint; neither the
            # rows nor the stored counts can be trusted, so rebuild the
            # table from scratch on this resume.
            target.execute(f"DELETE FROM {quoted}")
            store.delete_checkpoint(run_id, table.name)
    target.commit()


def transform_row(
    row: tuple[Any, ...],
    table: TableInfo,
    table_policy: Any,
    context: TransformContext,
    table_counts: dict[str, dict[str, int]],
) -> tuple[Any, ...]:
    if table_policy is None:
        return row
    output: list[Any] = []
    for column, value in zip(table.columns, row):
        policy = table_policy.columns.get(column.name)
        if policy is None:
            output.append(value)
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
