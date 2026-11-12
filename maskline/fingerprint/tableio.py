"""Format-tolerant table IO for fingerprint embedding and verification.

Supported containers: CSV (.csv), JSON Lines (.jsonl) and SQLite (.sqlite/.db,
single table). Verification additionally accepts column cropping and type
conversion: numeric text such as "12.30" or "1.23e1" parses back to the same
grid parity, and headers are matched by exact name with optional whitespace
normalisation.
"""

from __future__ import annotations

import csv
import json
import math
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..utils import MasklineError, atomic_write_text, quote_ident, sqlite_connect_readonly

CSV_SUFFIXES = {".csv", ".tsv", ".txt"}
JSONL_SUFFIXES = {".jsonl", ".ndjson"}
SQLITE_SUFFIXES = {".sqlite", ".sqlite3", ".db"}


class TableError(MasklineError):
    pass


@dataclass
class Table:
    header: list[str]
    rows: list[dict[str, Any]]
    source_format: str
    source_table: str | None = None

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def column_values(self, column: str) -> list[Any]:
        return [row.get(column) for row in self.rows]


def table_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in CSV_SUFFIXES:
        return "csv"
    if suffix in JSONL_SUFFIXES:
        return "jsonl"
    if suffix in SQLITE_SUFFIXES:
        return "sqlite"
    raise TableError(
        f"unsupported table format: {path} (supported: csv, tsv, jsonl, sqlite)"
    )


def _first_sqlite_table(path: Path) -> str:
    conn = sqlite_connect_readonly(path)
    try:
        names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        if not names:
            raise TableError(f"sqlite file contains no user table: {path}")
        if len(names) > 1:
            raise TableError(
                f"sqlite file {path} has multiple tables {names}; "
                "fingerprinting operates on one table per file"
            )
        return names[0]
    finally:
        conn.close()


def read_table(path: str | Path, table: str | None = None) -> Table:
    source = Path(path)
    if not source.exists():
        raise TableError(f"file not found: {source}")
    kind = table_kind(source)
    if kind == "csv":
        return _read_csv(source)
    if kind == "jsonl":
        return _read_jsonl(source)
    return _read_sqlite(source, table)


def _read_csv(source: Path) -> Table:
    delimiter = "\t" if source.suffix.lower() == ".tsv" else ","
    with source.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh, delimiter=delimiter)
        if reader.fieldnames is None:
            raise TableError(f"CSV file has no header: {source}")
        header = [name.strip() for name in reader.fieldnames]
        rows: list[dict[str, Any]] = []
        for raw in reader:
            rows.append({key.strip(): value for key, value in raw.items() if key is not None})
    return Table(header=header, rows=rows, source_format="csv")


def _read_jsonl(source: Path) -> Table:
    rows: list[dict[str, Any]] = []
    header: list[str] = []
    with source.open("r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TableError(f"invalid JSONL on line {line_number} of {source}: {exc}") from exc
            if not isinstance(item, dict):
                raise TableError(f"JSONL line {line_number} is not an object")
            row = {str(key): value for key, value in item.items()}
            for key in row:
                if key not in header:
                    header.append(key)
            rows.append(row)
    return Table(header=header, rows=rows, source_format="jsonl")


def _read_sqlite(source: Path, table: str | None) -> Table:
    table_name = table or _first_sqlite_table(source)
    conn = sqlite_connect_readonly(source)
    try:
        columns = [row[1] for row in conn.execute(f"PRAGMA table_info({quote_ident(table_name)})")]
        select_cols = ", ".join(quote_ident(name) for name in columns)
        raw_rows = conn.execute(
            f"SELECT {select_cols} FROM {quote_ident(table_name)}"
        ).fetchall()
    except sqlite3.Error as exc:
        raise TableError(f"cannot read table {table_name!r} from {source}: {exc}") from exc
    finally:
        conn.close()
    rows = [dict(zip(columns, tuple(values))) for values in raw_rows]
    return Table(header=list(columns), rows=rows, source_format="sqlite", source_table=table_name)


def write_table(path: str | Path, table: Table, output_format: str | None = None) -> None:
    target = Path(path)
    fmt = output_format or table_kind(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "csv":
        _write_csv(target, table)
    elif fmt == "jsonl":
        _write_jsonl(target, table)
    elif fmt == "sqlite":
        raise TableError(
            "sqlite output requires write_sqlite_table(); call the embedder instead"
        )
    else:
        raise TableError(f"unknown output format: {fmt}")


def _write_csv(target: Path, table: Table) -> None:
    def render(fh: Any) -> None:
        writer = csv.DictWriter(fh, fieldnames=table.header, lineterminator="\n",
                                extrasaction="ignore")
        writer.writeheader()
        for row in table.rows:
            writer.writerow({key: _render_cell(row.get(key)) for key in table.header})
    text_target = target.with_suffix("") if target.suffix == "" else target
    with _text_atomic(text_target) as fh:
        render(fh)


class _AtomicText:
    def __init__(self, target: Path) -> None:
        self.target = target
        self.fh: Any = None

    def __enter__(self) -> Any:
        import tempfile
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=self.target.parent,
            prefix=f".{self.target.name}.", delete=False,
        )
        self.fh = self.tmp.__enter__()
        return self.fh

    def __exit__(self, *exc: Any) -> None:
        self.tmp.__exit__(*exc)
        import os
        if exc[0] is None:
            os.replace(self.tmp.name, self.target)
        elif os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)


def _text_atomic(target: Path) -> _AtomicText:
    return _AtomicText(target)


def _render_cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, float):
        if math.isfinite(value):
            return repr(value)
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    return value


def _write_jsonl(target: Path, table: Table) -> None:
    lines = []
    for row in table.rows:
        payload = {key: row.get(key) for key in table.header if key in row}
        lines.append(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    atomic_write_text(target, "\n".join(lines) + ("\n" if lines else ""))


def write_sqlite_table(target: Path, table: Table, table_name: str = "delivery") -> None:
    import os
    import tempfile
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent, suffix=".sqlite")
    os.close(fd)
    try:
        conn = sqlite3.connect(tmp_name)
        try:
            cols_sql = ", ".join(f"{quote_ident(name)} TEXT" for name in table.header)
            conn.execute(f"CREATE TABLE {quote_ident(table_name)} ({cols_sql})")
            placeholders = ", ".join("?" for _ in table.header)
            conn.executemany(
                f"INSERT INTO {quote_ident(table_name)} VALUES ({placeholders})",
                [
                    tuple(
                        None if row.get(key) is None else str(_render_cell(row.get(key)))
                        for key in table.header
                    )
                    for row in table.rows
                ],
            )
            conn.commit()
        finally:
            conn.close()
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, target)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def parse_number(value: Any) -> float | None:
    """Parse a suspect cell into a float; return None for unparseable/empty."""
    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    text = str(value).strip().replace(",", "")
    if not text:
        return None
    # Tolerate currency symbols and percent suffixes after type conversion.
    text = text.lstrip("¥$€£+").rstrip("%").strip()
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def canonical_cell(value: Any) -> str:
    """Stable canonical form used for canary fingerprint matching."""
    number = parse_number(value) if not isinstance(value, (dict, list)) else None
    if number is not None and not isinstance(value, bool):
        if number.is_integer():
            return str(int(number))
        return repr(number)
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value).strip()
