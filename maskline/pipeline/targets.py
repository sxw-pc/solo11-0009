"""Pluggable output targets for the streaming runner.

A target owns the physical output of one run and exposes the small batch
interface the runner drives:

- ``create`` / ``open_for_resume``: lifecycle for new and resumed runs.
- ``prepare_table``: reconcile any half-written table output with the
  persisted checkpoint before the runner streams batches for that table.
  Returns the checkpoint the table should resume from (``None`` = start the
  table over); implementations may persist a reset checkpoint themselves.
- ``write_batch``: write one transformed batch and make it durable. This is
  the commit point the runner aligns with ``CheckpointStore.save_checkpoint``,
  so a batch is always either fully durable and checkpointed, or redone.
- ``finish_table``: the table is complete; make its output final.
- ``digest``: content hash of the completed output, stored in manifests,
  reports, and the audit chain.

Two targets exist:

``SqliteTarget``
    One independent SQLite database; batches land in idempotent
    delete-then-insert transactions (the historical behaviour).

``CsvTarget``
    One RFC 4180 CSV file per source table inside an output directory:
    source column order, UTF-8, header row, NULL as an empty field. Batches
    are appended to ``<table>.csv.part`` and journaled in
    ``<table>.csv.journal`` (``rows_done byte-offset`` per committed batch).
    The final ``<table>.csv`` only appears via atomic rename once the table
    is complete, so half-written output is always recognizable by the
    ``.part`` suffix and is truncated back to the checkpointed offset (or
    safely rebuilt) on resume.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Protocol

from ..dataset_io import sanitize_table_name
from ..registry import DatasetInventory, TableInfo
from ..utils import atomic_write_text, read_json, sqlite_content_digest
from .checkpoint import CheckpointStore, TableCheckpoint
from .errors import PipelineError
from .steps import create_target, insert_batch

TARGET_FORMATS = ("sqlite", "csv")

MARKER_NAME = ".maskline-target.json"
_MARKER = {"kind": "csv", "version": 1}


class OutputTarget(Protocol):
    kind: str
    path: Path

    def create(self) -> None:
        """Prepare a fresh output for a new run (refuse unsafe locations)."""
        ...

    def open_for_resume(self) -> None:
        """Validate the existing output of an interrupted run."""
        ...

    def prepare_table(
        self,
        table: TableInfo,
        checkpoint: TableCheckpoint | None,
        store: CheckpointStore,
        run_id: str,
    ) -> TableCheckpoint | None:
        """Reconcile partial table output with the checkpoint; return the
        checkpoint to resume this table from (None = rebuild the table)."""
        ...

    def write_batch(
        self, table: TableInfo, rows: list[tuple[int, tuple[Any, ...]]], rows_done: int
    ) -> None:
        """Durably write one batch; ``rows_done`` counts rows after it."""
        ...

    def finish_table(self, table: TableInfo) -> None:
        """Mark the table's output as complete."""
        ...

    def close(self) -> None:
        ...

    def digest(self) -> str:
        """Content hash of the completed output."""
        ...


class SqliteTarget:
    """The historical target: one independent SQLite database file."""

    kind = "sqlite"

    def __init__(self, inventory: DatasetInventory, output: Path) -> None:
        self.inventory = inventory
        self.path = Path(output)
        self.conn: sqlite3.Connection | None = None

    def create(self) -> None:
        if self.path == self.inventory.path.resolve():
            raise PipelineError("refusing to write the target over the source dataset")
        create_target(self.inventory, self.path)
        self._connect()

    def open_for_resume(self) -> None:
        if not self.path.exists():
            raise PipelineError(f"target database is missing: {self.path}")
        self._connect()

    def _connect(self) -> None:
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=DELETE")

    def prepare_table(
        self,
        table: TableInfo,
        checkpoint: TableCheckpoint | None,
        store: CheckpointStore,
        run_id: str,
    ) -> TableCheckpoint | None:
        return checkpoint

    def write_batch(
        self, table: TableInfo, rows: list[tuple[int, tuple[Any, ...]]], rows_done: int
    ) -> None:
        assert self.conn is not None
        with self.conn:
            insert_batch(self.conn, table, rows)

    def finish_table(self, table: TableInfo) -> None:
        return None

    def close(self) -> None:
        if self.conn is not None:
            self.conn.commit()
            self.conn.close()
            self.conn = None

    def digest(self) -> str:
        return sqlite_content_digest(self.path)


class _Utf8Sink:
    """Text sink for csv.writer that encodes straight into a binary file."""

    def __init__(self, binary_file: Any) -> None:
        self._file = binary_file

    def write(self, text: str) -> None:
        self._file.write(text.encode("utf-8"))


class _TableFile:
    """Append handles for one table's ``.part`` data file and its journal."""

    def __init__(self, data_path: Path, journal_path: Path) -> None:
        self.data = data_path.open("ab")
        self.writer = csv.writer(_Utf8Sink(self.data))
        self.journal = journal_path.open("a", encoding="utf-8", newline="")

    def offset(self) -> int:
        return self.data.tell()

    def flush(self) -> None:
        self.data.flush()
        os.fsync(self.data.fileno())

    def commit(self, rows_done: int) -> None:
        self.flush()
        self.journal.write(f"{rows_done} {self.offset()}\n")
        self.journal.flush()
        os.fsync(self.journal.fileno())

    def close(self) -> None:
        self.journal.close()
        self.data.close()


def _column_affinity(declared_type: str) -> str:
    """SQLite column affinity rules (same precedence as SQLite itself)."""
    text = (declared_type or "").upper()
    if "INT" in text:
        return "INTEGER"
    if any(token in text for token in ("CHAR", "CLOB", "TEXT")):
        return "TEXT"
    if "BLOB" in text or not text:
        return "BLOB"
    if any(token in text for token in ("REAL", "FLOA", "DOUB")):
        return "REAL"
    return "NUMERIC"


def _csv_value(value: Any, affinity: str) -> Any:
    """Render one value as CSV text.

    Numbers follow the source column's SQLite type affinity, so the CSV text
    matches what the SQLite target would store and read back (e.g. an
    integer rounded balance in a REAL column reads back as ``4288.0``).
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value
    if affinity == "REAL":
        return str(float(value))
    if affinity in ("INTEGER", "NUMERIC") and isinstance(value, float):
        if value.is_integer() and -(2**63) <= value < 2**63:
            return str(int(value))
        return str(value)
    return value


def _read_journal(journal_path: Path) -> dict[int, int] | None:
    """Parse a ``rows_done offset`` journal, dropping a torn trailing line.

    Returns None when the journal is unreadable or internally corrupt, so the
    caller falls back to scanning the data file.
    """
    try:
        raw = journal_path.read_bytes()
    except OSError:
        return None
    if not raw.endswith(b"\n"):
        # A kill can leave a partially written last line; only complete
        # lines are trustworthy, so truncate the tail away.
        last_newline = raw.rfind(b"\n")
        raw = raw[: last_newline + 1] if last_newline >= 0 else b""
        try:
            with journal_path.open("r+b") as fh:
                fh.truncate(len(raw))
        except OSError:
            return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    entries: dict[int, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 2:
            return None
        try:
            rows_done, offset = int(parts[0]), int(parts[1])
        except ValueError:
            return None
        if rows_done < 0 or offset < 0:
            return None
        entries[rows_done] = offset
    return entries


def _scan_committed_offset(part: Path, header: list[str], rows_done: int) -> int | None:
    """Byte offset just after data row ``rows_done``, found by streaming the
    partial file through the CSV parser (constant memory). Returns None when
    the file cannot supply that many complete rows."""
    offset = 0

    def lines() -> Any:
        nonlocal offset
        with part.open("rb") as fh:
            for raw in fh:
                offset += len(raw)
                yield raw.decode("utf-8")

    reader = csv.reader(lines())
    try:
        if next(reader, None) != header:
            return None
        count = 0
        while count < rows_done:
            if next(reader, None) is None:
                return None
            count += 1
    except (csv.Error, UnicodeDecodeError):
        return None
    return offset


class CsvTarget:
    """One RFC 4180 CSV file per source table inside an output directory."""

    kind = "csv"

    def __init__(self, inventory: DatasetInventory, output: Path) -> None:
        self.inventory = inventory
        self.path = Path(output)
        self._stems: dict[str, str] = {}
        self._affinities: dict[str, list[str]] = {}
        seen: dict[str, str] = {}
        for table in inventory.tables:
            stem = sanitize_table_name(table.name)
            if stem in seen:
                raise PipelineError(
                    f"tables {seen[stem]!r} and {table.name!r} would both "
                    f"write {stem}.csv; rename one of them"
                )
            seen[stem] = table.name
            self._stems[table.name] = stem
            self._affinities[table.name] = [
                _column_affinity(column.declared_type) for column in table.columns
            ]
        self._open: dict[str, _TableFile] = {}

    def _paths_for(self, table_name: str) -> tuple[Path, Path, Path]:
        final = self.path / f"{self._stems[table_name]}.csv"
        return final, Path(str(final) + ".part"), Path(str(final) + ".journal")

    @staticmethod
    def _header(table: TableInfo) -> list[str]:
        return [column.name for column in table.columns]

    # -- lifecycle ---------------------------------------------------------

    def create(self) -> None:
        if self.path.suffix.lower() == ".csv":
            raise PipelineError(
                f"CSV target output is a directory of per-table files, "
                f"not a single file: {self.path}"
            )
        source = self.inventory.path.resolve()
        for table in self.inventory.tables:
            final, _, _ = self._paths_for(table.name)
            if final.resolve() == source:
                raise PipelineError("refusing to write the target over the source dataset")
        marker = self.path / MARKER_NAME
        if self.path.exists():
            if not self.path.is_dir():
                raise PipelineError(f"CSV output path is not a directory: {self.path}")
            if any(self.path.iterdir()) and not marker.exists():
                raise PipelineError(
                    f"refusing to use non-empty directory without {MARKER_NAME}: "
                    f"{self.path}"
                )
            # A directory we previously marked is safe to reuse: drop outputs
            # and half-written files from earlier runs.
            for pattern in ("*.csv", "*.csv.part", "*.csv.journal"):
                for stale in self.path.glob(pattern):
                    stale.unlink()
        else:
            self.path.mkdir(parents=True)
        atomic_write_text(marker, json.dumps(_MARKER, sort_keys=True) + "\n")

    def open_for_resume(self) -> None:
        if not self.path.is_dir():
            raise PipelineError(f"target directory is missing: {self.path}")
        marker = read_json(self.path / MARKER_NAME)
        if not isinstance(marker, dict) or marker.get("kind") != "csv":
            raise PipelineError(f"not a maskline CSV output directory: {self.path}")

    # -- per-table reconciliation ------------------------------------------

    def prepare_table(
        self,
        table: TableInfo,
        checkpoint: TableCheckpoint | None,
        store: CheckpointStore,
        run_id: str,
    ) -> TableCheckpoint | None:
        final, part, journal = self._paths_for(table.name)
        rows_done = checkpoint.rows_done if checkpoint else 0
        if final.exists() and checkpoint is not None and rows_done >= table.row_count:
            # This table finished in a previous attempt; drop any strays.
            part.unlink(missing_ok=True)
            journal.unlink(missing_ok=True)
            return checkpoint
        if final.exists():
            # The checkpoint says the table never finished, so this file
            # cannot belong to a completed table of this run: rebuild it.
            final.unlink()
        if part.exists():
            offset = self._recover_offset(table, part, journal, rows_done)
            if offset is not None:
                with part.open("r+b") as fh:
                    fh.truncate(offset)
                self._open[table.name] = _TableFile(part, journal)
                return checkpoint
            # The partial file cannot be reconciled with the checkpoint
            # (e.g. it was removed or corrupted externally): rebuild it.
        if checkpoint is not None and (checkpoint.rows_done or checkpoint.last_rowid):
            store.save_checkpoint(run_id, table.name, 0, 0, {})
        self._create_fresh(table, part, journal)
        return None

    def _recover_offset(
        self, table: TableInfo, part: Path, journal: Path, rows_done: int
    ) -> int | None:
        size = part.stat().st_size
        if journal.exists():
            entries = _read_journal(journal)
            if entries is not None:
                offset = entries.get(rows_done)
                if offset is not None and 0 <= offset <= size:
                    return offset
        offset = _scan_committed_offset(part, self._header(table), rows_done)
        if offset is None:
            return None
        # The journal was missing or unusable: restart it from the recovered
        # point so later batches append to a trustworthy file.
        atomic_write_text(journal, f"{rows_done} {offset}\n")
        return offset

    def _create_fresh(self, table: TableInfo, part: Path, journal: Path) -> None:
        part.unlink(missing_ok=True)
        journal.unlink(missing_ok=True)
        handle = _TableFile(part, journal)
        handle.writer.writerow(self._header(table))
        handle.commit(0)
        self._open[table.name] = handle

    # -- batch interface -----------------------------------------------------

    def write_batch(
        self, table: TableInfo, rows: list[tuple[int, tuple[Any, ...]]], rows_done: int
    ) -> None:
        handle = self._open[table.name]
        affinities = self._affinities[table.name]
        for _rowid, values in rows:
            handle.writer.writerow(
                [_csv_value(value, affinity) for value, affinity in zip(values, affinities)]
            )
        handle.commit(rows_done)

    def finish_table(self, table: TableInfo) -> None:
        handle = self._open.pop(table.name, None)
        if handle is None:
            return
        final, part, journal = self._paths_for(table.name)
        handle.flush()
        handle.close()
        journal.unlink(missing_ok=True)
        os.replace(part, final)

    def close(self) -> None:
        for handle in self._open.values():
            handle.close()
        self._open.clear()

    def digest(self) -> str:
        digest = hashlib.sha256(b"maskline-csv-target-v1\x00")
        for table in self.inventory.tables:
            final, _, _ = self._paths_for(table.name)
            digest.update(b"\x00table\x00" + table.name.encode("utf-8") + b"\x00")
            with final.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(chunk)
        return digest.hexdigest()


def make_target(kind: str, inventory: DatasetInventory, output: Path) -> OutputTarget:
    if kind == "sqlite":
        return SqliteTarget(inventory, output)
    if kind == "csv":
        return CsvTarget(inventory, output)
    raise PipelineError(
        f"unknown target format {kind!r}; expected one of: {', '.join(TARGET_FORMATS)}"
    )


def target_for_resume(inventory: DatasetInventory, output: Path) -> OutputTarget:
    """Recover the target kind recorded for an interrupted run.

    CSV outputs are directories carrying a marker file; everything else is
    treated as a SQLite database, which keeps checkpoints written by older
    versions resumable.
    """
    output = Path(output)
    if output.is_dir() or (output / MARKER_NAME).exists():
        return CsvTarget(inventory, output)
    return SqliteTarget(inventory, output)
