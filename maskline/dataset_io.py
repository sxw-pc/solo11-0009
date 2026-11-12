"""Read-only access to the supported local dataset formats."""

from __future__ import annotations

import csv
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Iterator

from .utils import MasklineError, quote_ident, sqlite_connect_readonly

SQLITE_EXTENSIONS = {".sqlite", ".sqlite3", ".db"}
CSV_EXTENSIONS = {".csv"}


class DatasetError(MasklineError):
    pass


def is_supported(path: Path) -> bool:
    return path.suffix.lower() in SQLITE_EXTENSIONS | CSV_EXTENSIONS


def dataset_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in SQLITE_EXTENSIONS:
        return "sqlite"
    if suffix in CSV_EXTENSIONS:
        return "csv"
    raise DatasetError(f"unsupported dataset file: {path}")


def discover_datasets(target: str | Path) -> list[Path]:
    path = Path(target).expanduser().resolve()
    if path.is_file():
        if not is_supported(path):
            raise DatasetError(f"unsupported dataset file: {path}")
        return [path]
    if not path.is_dir():
        raise DatasetError(f"dataset path does not exist: {path}")
    files = [item for item in path.rglob("*") if item.is_file() and is_supported(item)]
    return sorted(files, key=lambda item: item.as_posix())


def sanitize_table_name(name: str) -> str:
    cleaned = re.sub(r"\W+", "_", name, flags=re.UNICODE).strip("_")
    if not cleaned:
        cleaned = "data"
    if cleaned[0].isdigit():
        cleaned = "t_" + cleaned
    return cleaned


def csv_table_name(path: Path) -> str:
    return sanitize_table_name(path.stem)


def sqlite_table_names(conn: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


def sqlite_columns(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    rows = conn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()
    return [
        {
            "name": row[1],
            "declared_type": row[2] or "TEXT",
            "nullable": not bool(row[3]),
        }
        for row in rows
    ]


def read_csv_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise DatasetError(f"CSV file has no header: {path}") from exc
    if not header or any(not name.strip() for name in header):
        raise DatasetError(f"CSV file has an empty column name: {path}")
    if len(set(header)) != len(header):
        raise DatasetError(f"CSV file has duplicate column names: {path}")
    return header


def iter_csv_dicts(path: Path) -> Iterator[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield {key: (value if value is not None else "") for key, value in row.items()}


def iter_csv_tuples(path: Path) -> Iterator[tuple[str, ...]]:
    header = read_csv_header(path)
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        next(reader)
        for row in reader:
            if len(row) < len(header):
                row = row + [""] * (len(header) - len(row))
            yield tuple(row[: len(header)])


def iter_table_rows(
    path: Path, table: str, after_rowid: int = 0, limit: int | None = None
) -> tuple[list[str], list[tuple[int, tuple[Any, ...]]]]:
    """Return (column names, [(rowid, values), ...]) ordered by rowid."""
    conn = sqlite_connect_readonly(path)
    try:
        columns = [item["name"] for item in sqlite_columns(conn, table)]
        select_cols = ", ".join(quote_ident(name) for name in columns)
        limit_sql = f" LIMIT {int(limit)}" if limit is not None else ""
        rows = conn.execute(
            f"SELECT rowid, {select_cols} FROM {quote_ident(table)} "
            f"WHERE rowid > ? ORDER BY rowid{limit_sql}",
            (after_rowid,),
        ).fetchall()
        return columns, [(int(row[0]), tuple(row[1:])) for row in rows]
    except sqlite3.Error as exc:
        raise DatasetError(f"cannot read table {table!r} from {path}: {exc}") from exc
    finally:
        conn.close()


def read_table_sample(
    path: Path, kind: str, table: str, limit: int
) -> tuple[list[str], list[tuple[Any, ...]]]:
    """Read up to ``limit`` rows from one table in a single pass.

    Returns (column names, rows). Used by the linkage profiler so a dataset is
    opened once per table instead of once per column.
    """
    if limit < 1:
        raise ValueError("sample limit must be positive")
    if kind == "sqlite":
        conn = sqlite_connect_readonly(path)
        try:
            columns = [item["name"] for item in sqlite_columns(conn, table)]
            select_cols = ", ".join(quote_ident(name) for name in columns)
            rows = conn.execute(
                f"SELECT {select_cols} FROM {quote_ident(table)} LIMIT ?",
                (limit,),
            ).fetchall()
            return columns, [tuple(row) for row in rows]
        except sqlite3.Error as exc:
            raise DatasetError(f"cannot sample table {table!r} from {path}: {exc}") from exc
        finally:
            conn.close()
    header = read_csv_header(path)
    rows: list[tuple[Any, ...]] = []
    for row in iter_csv_tuples(path):
        rows.append(tuple(row))
        if len(rows) >= limit:
            break
    return header, rows


def read_column_samples(
    path: Path, kind: str, table: str, column: str, limit: int
) -> list[Any]:
    if limit < 1:
        raise ValueError("sample limit must be positive")
    if kind == "sqlite":
        conn = sqlite_connect_readonly(path)
        try:
            rows = conn.execute(
                f"SELECT {quote_ident(column)} FROM {quote_ident(table)} "
                f"WHERE {quote_ident(column)} IS NOT NULL LIMIT ?",
                (limit,),
            ).fetchall()
            return [row[0] for row in rows]
        except sqlite3.Error as exc:
            raise DatasetError(f"cannot sample {table}.{column}: {exc}") from exc
        finally:
            conn.close()
    rows: list[Any] = []
    for row in iter_csv_dicts(path):
        value = row.get(column)
        if value is not None:
            rows.append(value)
        if len(rows) >= limit:
            break
    return rows


def sqlite_schema_sql(path: Path) -> dict[str, str]:
    conn = sqlite_connect_readonly(path)
    try:
        names = sqlite_table_names(conn)
        result: dict[str, str] = {}
        for name in names:
            row = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)
            ).fetchone()
            if row and row[0]:
                result[name] = row[0]
        return result
    finally:
        conn.close()


def iter_sqlite_rows_by_rowid(path: Path, table: str) -> Iterable[tuple[int, tuple[Any, ...]]]:
    after = 0
    while True:
        _columns, batch = iter_table_rows(path, table, after_rowid=after, limit=1000)
        if not batch:
            return
        for row in batch:
            yield row
        after = batch[-1][0]
