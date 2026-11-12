"""Read-only, streaming access to datasets for evaluation.

Both source and product datasets are opened through the same interfaces:
SQLite files are always opened with ``mode=ro`` + ``query_only`` and CSV files
are only ever read. Nothing in the evaluation package opens a writable
handle against either dataset.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from ..dataset_io import (
    csv_table_name,
    dataset_kind,
    read_csv_header,
    sqlite_columns,
    sqlite_table_names,
)
from ..utils import MasklineError, quote_ident, sqlite_connect_readonly


class EvaluationError(MasklineError):
    pass


@dataclass(frozen=True)
class ColumnSchema:
    name: str
    declared_type: str


@dataclass(frozen=True)
class TableSchema:
    name: str
    columns: tuple[ColumnSchema, ...]

    def column_names(self) -> tuple[str, ...]:
        return tuple(column.name for column in self.columns)

    def index_of(self, column: str) -> int:
        names = self.column_names()
        try:
            return names.index(column)
        except ValueError as exc:
            raise EvaluationError(f"column {column!r} does not exist in table {self.name!r}") from exc


def schema_of(path: Path) -> dict[str, TableSchema]:
    """Read table/column metadata without scanning row content."""
    kind = dataset_kind(path)
    if kind == "sqlite":
        conn = sqlite_connect_readonly(path)
        try:
            result: dict[str, TableSchema] = {}
            for table in sqlite_table_names(conn):
                columns = sqlite_columns(conn, table)
                result[table] = TableSchema(
                    name=table,
                    columns=tuple(
                        ColumnSchema(item["name"], item["declared_type"]) for item in columns
                    ),
                )
            return result
        finally:
            conn.close()
    header = read_csv_header(path)
    table = TableSchema(
        name=csv_table_name(path),
        columns=tuple(ColumnSchema(name, "TEXT") for name in header),
    )
    return {table.name: table}


def row_count(path: Path, table: str) -> int:
    cache = _ROW_COUNT_CACHE.setdefault(path.resolve(), {})
    if table in cache:
        return cache[table]
    kind = dataset_kind(path)
    if kind == "sqlite":
        conn = sqlite_connect_readonly(path)
        try:
            count = int(
                conn.execute(f"SELECT COUNT(*) FROM {quote_ident(table)}").fetchone()[0]
            )
        finally:
            conn.close()
    else:
        count = 0
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for _ in csv.reader(handle):
                count += 1
        count = max(count - 1, 0)
    cache[table] = count
    return count


_ROW_COUNT_CACHE: dict[Path, dict[str, int]] = {}


def iter_rows(path: Path, table: str, columns: tuple[str, ...]) -> Iterator[tuple[Any, ...]]:
    """Yield the requested columns of every row, in storage order, as tuples.

    SQLite is paged through rowid windows; CSV is streamed line by line. Both
    paths hold at most one batch in memory.
    """
    kind = dataset_kind(path)
    if kind == "sqlite":
        yield from _iter_sqlite(path, table, columns)
    else:
        yield from _iter_csv(path, columns)


def _iter_sqlite(path: Path, table: str, columns: tuple[str, ...]) -> Iterator[tuple[Any, ...]]:
    # Keyset pagination over the full column ordering, not rowid windows:
    # rowid is not guaranteed unique (a WITHOUT ROWID table, or a table whose
    # rowid values collide), so "WHERE rowid > ?" can skip or duplicate rows.
    # Ordering by every selected column gives a deterministic total order for
    # streaming aggregation while remaining index-friendly on small column
    # sets.
    select = ", ".join(quote_ident(name) for name in columns)
    order = ", ".join(quote_ident(name) for name in columns)
    batch_size = 10_000
    conn = sqlite_connect_readonly(path)
    try:
        last_row: tuple[Any, ...] | None = None
        while True:
            if last_row is None:
                rows = conn.execute(
                    f"SELECT {select} FROM {quote_ident(table)} "
                    f"ORDER BY {order} LIMIT ?",
                    (batch_size,),
                ).fetchall()
            else:
                placeholders = ", ".join("?" for _ in columns)
                rows = conn.execute(
                    f"SELECT {select} FROM {quote_ident(table)} "
                    f"WHERE ({order}) > ({placeholders}) "
                    f"ORDER BY {order} LIMIT ?",
                    (*last_row, batch_size),
                ).fetchall()
            if not rows:
                return
            for row in rows:
                yield tuple(row)
            last_row = tuple(rows[-1])
    finally:
        conn.close()


def _iter_csv(path: Path, columns: tuple[str, ...]) -> Iterator[tuple[Any, ...]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        present = reader.fieldnames or ()
        missing = [name for name in columns if name not in present]
        if missing:
            raise EvaluationError(
                f"CSV {path.name} is missing columns: {', '.join(missing)}"
            )
        for row in reader:
            yield tuple(row.get(name, "") for name in columns)


def align_schemas(
    source: dict[str, TableSchema], product: dict[str, TableSchema]
) -> tuple[dict[str, TableSchema], list[str]]:
    """Match product tables/columns back onto the source schema.

    Returns the aligned schema (product tables keyed by source table name,
    restricted to columns present in both) and a list of human-readable
    structural warnings. Evaluation never fails on a mismatch: missing pieces
    are reported as total utility loss instead.
    """
    warnings: list[str] = []
    aligned: dict[str, TableSchema] = {}
    for table_name, source_table in source.items():
        product_table = product.get(table_name)
        if product_table is None:
            warnings.append(f"表 {table_name!r} 在脱敏产物中缺失，整表效用按归零处理")
            continue
        source_names = source_table.column_names()
        product_names = product_table.column_names()
        shared = [name for name in source_names if name in product_names]
        for name in source_names:
            if name not in product_names:
                warnings.append(
                    f"列 {table_name}.{name} 在脱敏产物中缺失，该列效用按归零处理"
                )
        extra = [name for name in product_names if name not in source_names]
        for name in extra:
            warnings.append(f"产物列 {table_name}.{name} 在源数据中不存在，已忽略")
        product_by_name = {column.name: column for column in product_table.columns}
        aligned[table_name] = TableSchema(
            name=table_name,
            columns=tuple(
                ColumnSchema(name, product_by_name[name].declared_type) for name in shared
            ),
        )
    for table_name in product:
        if table_name not in source:
            warnings.append(f"产物表 {table_name!r} 在源数据中不存在，已忽略")
    return aligned, warnings


def parse_number(value: Any) -> float | None:
    """Best-effort numeric parsing; non-numeric content yields None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def collect_text_samples(
    path: Path,
    schema_map: dict[str, TableSchema],
    cap: int = 5000,
    min_length: int = 4,
) -> list[str]:
    """Stream text cell values for the report redaction guard.

    Only non-numeric text at least ``min_length`` characters long is kept:
    these are the plaintext categories the report must never contain. Numeric
    samples are excluded deliberately, because reports legitimately contain
    aggregate numeric boundaries. The samples stay inside the evaluation
    process and are never serialized into a report.
    """
    samples: set[str] = set()
    for table in schema_map.values():
        columns = table.column_names()
        for row in iter_rows(path, table.name, columns):
            for value in row:
                if value is None or not isinstance(value, str):
                    continue
                text = value.strip()
                if len(text) < min_length or parse_number(text) is not None:
                    continue
                samples.add(text)
                if len(samples) >= cap:
                    return sorted(samples)
    return sorted(samples)
