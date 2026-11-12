"""Dataset inventory, content fingerprints, and the metadata catalog.

Fingerprint model (v2, see docs/incremental-scan.md for the full rationale):

* **structure fingerprint** is table-level: a canonical hash of every column
  descriptor (name, declared type, nullability). Any added, dropped, retyped
  or renamed column changes it.
* **content fingerprint** is column-level: one hash per column covering every
  normalized value of that column (NULLs included). They are produced in the
  same single streaming pass as the dataset-wide fingerprint, so incremental
  scans add no extra read of the source data. Per-column hashes let a scan
  pinpoint that one added/changed column instead of resampling a whole table.
* A table-level content hash is derived from the per-column hashes for cheap
  whole-table equality checks.

The v1 catalog (datasets/findings keyed by the whole-dataset fingerprint) is
still readable: opening such a registry migrates it to v2 automatically inside
a single transaction. A registry written by a *newer* maskline version is
refused with an explicit error instead of crashing.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .dataset_io import (
    DatasetError,
    csv_table_name,
    dataset_kind,
    iter_csv_tuples,
    iter_sqlite_rows_by_rowid,
    read_csv_header,
    sqlite_columns,
    sqlite_connect_readonly,
    sqlite_table_names,
)
from .utils import canonical_json, normalize_sqlite_value, quote_ident, sha256_text

SCHEMA_VERSION = 2
# Bump whenever detector scoring semantics change; cached findings produced by
# an older detector version are never reused blindly.
DETECTOR_VERSION = "detectors-v1"
# Default relative row-count change that forces a table rescan even when the
# per-column content hashes would otherwise suggest reuse.
DEFAULT_ROW_COUNT_CHANGE_RATIO = 0.5


class RegistryVersionError(DatasetError):
    """Raised when a registry DB comes from an unsupported (newer) version."""


V2_DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        schema_version INTEGER NOT NULL,
        migrated_from INTEGER,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dataset_records (
        dataset_id TEXT PRIMARY KEY,
        path TEXT NOT NULL,
        kind TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        row_count INTEGER NOT NULL,
        tables_json TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS table_fingerprints (
        dataset_id TEXT NOT NULL,
        table_name TEXT NOT NULL,
        row_count INTEGER NOT NULL,
        structure_fingerprint TEXT NOT NULL,
        content_fingerprint TEXT NOT NULL,
        columns_json TEXT NOT NULL,
        sample_limit INTEGER,
        detector_version TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (dataset_id, table_name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings_v2 (
        dataset_id TEXT NOT NULL,
        table_name TEXT NOT NULL,
        column_name TEXT NOT NULL,
        sensitive_type TEXT,
        confidence TEXT NOT NULL DEFAULT 'none',
        score REAL NOT NULL DEFAULT 0,
        hit_rate REAL NOT NULL DEFAULT 0,
        validate_rate REAL NOT NULL DEFAULT 0,
        sample_size INTEGER NOT NULL DEFAULT 0,
        candidates_json TEXT NOT NULL DEFAULT '[]',
        updated_at TEXT NOT NULL,
        PRIMARY KEY (dataset_id, table_name, column_name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_runs (
        scan_id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        dataset_path TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_table_actions (
        scan_id TEXT NOT NULL,
        dataset_id TEXT NOT NULL,
        table_name TEXT NOT NULL,
        action TEXT NOT NULL,
        reason TEXT NOT NULL,
        columns_json NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        PRIMARY KEY (scan_id, dataset_id, table_name)
    )
    """,
    # Legacy v1 tables are re-created with IF NOT EXISTS so both layouts can
    # coexist during and after migration.
    """
    CREATE TABLE IF NOT EXISTS datasets (
        fingerprint TEXT PRIMARY KEY,
        path TEXT NOT NULL,
        kind TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        row_count INTEGER NOT NULL,
        tables_json TEXT NOT NULL,
        registered_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        dataset_fingerprint TEXT NOT NULL,
        table_name TEXT NOT NULL,
        column_name TEXT NOT NULL,
        sensitive_type TEXT,
        confidence TEXT NOT NULL DEFAULT 'none',
        score REAL NOT NULL DEFAULT 0,
        hit_rate REAL NOT NULL DEFAULT 0,
        validate_rate REAL NOT NULL DEFAULT 0,
        sample_size INTEGER NOT NULL DEFAULT 0,
        candidates_json TEXT NOT NULL DEFAULT '[]',
        updated_at TEXT NOT NULL,
        PRIMARY KEY (dataset_fingerprint, table_name, column_name)
    )
    """,
)


@dataclass(frozen=True)
class ColumnInfo:
    name: str
    declared_type: str
    nullable: bool = True
    content_fingerprint: str = ""

    @property
    def descriptor(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "declared_type": self.declared_type,
            "nullable": self.nullable,
        }

    @property
    def structure_fingerprint(self) -> str:
        return sha256_text(
            "maskline-column-v2\x00" + canonical_json(self.descriptor)
        )


@dataclass(frozen=True)
class TableInfo:
    name: str
    columns: tuple[ColumnInfo, ...]
    row_count: int
    structure_fingerprint: str = ""
    content_fingerprint: str = ""

    def column(self, name: str) -> ColumnInfo | None:
        return next((item for item in self.columns if item.name == name), None)


@dataclass(frozen=True)
class DatasetInventory:
    path: Path
    kind: str
    fingerprint: str
    size_bytes: int
    tables: tuple[TableInfo, ...] = field(default_factory=tuple)
    @property
    def row_count(self) -> int:
        return sum(table.row_count for table in self.tables)

    def table(self, name: str) -> TableInfo | None:
        return next((table for table in self.tables if table.name == name), None)

    def to_record(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "fingerprint": self.fingerprint,
            "size_bytes": self.size_bytes,
            "row_count": self.row_count,
            "tables": [
                {
                    "name": table.name,
                    "row_count": table.row_count,
                    "structure_fingerprint": table.structure_fingerprint,
                    "content_fingerprint": table.content_fingerprint,
                    "columns": [
                        {
                            "name": col.name,
                            "declared_type": col.declared_type,
                            "nullable": col.nullable,
                            "content_fingerprint": col.content_fingerprint,
                        }
                        for col in table.columns
                    ],
                }
                for table in self.tables
            ],
        }


def _finish_table(
    name: str,
    column_metas: list[dict[str, Any]],
    column_hashers: dict[str, "hashlib._Hash"],
    count: int,
) -> TableInfo:
    columns: list[ColumnInfo] = []
    column_hashes: dict[str, str] = {}
    for meta in column_metas:
        digest = column_hashers[meta["name"]].hexdigest()
        column_hashes[meta["name"]] = digest
        columns.append(
            ColumnInfo(
                name=meta["name"],
                declared_type=meta["declared_type"],
                nullable=meta["nullable"],
                content_fingerprint=digest,
            )
        )
    structure = sha256_text(
        "maskline-table-structure-v2\x00"
        + canonical_json([col.descriptor for col in columns])
    )
    content = sha256_text(
        "maskline-table-content-v2\x00" + canonical_json(column_hashes)
    )
    return TableInfo(
        name=name,
        columns=tuple(columns),
        row_count=count,
        structure_fingerprint=structure,
        content_fingerprint=content,
    )


def _sqlite_fingerprint(path: Path) -> tuple[str, tuple[TableInfo, ...]]:
    conn = sqlite_connect_readonly(path)
    try:
        digest = hashlib.sha256(b"maskline-sqlite-v1\x00")
        tables: list[TableInfo] = []
        for table in sqlite_table_names(conn):
            columns_meta = sqlite_columns(conn, table)
            digest.update(table.encode("utf-8") + b"\x00")
            digest.update(canonical_json(columns_meta).encode("utf-8"))
            count = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM {quote_ident(table)}"
                ).fetchone()[0]
            )
            column_hashers = {
                item["name"]: hashlib.sha256(
                    b"maskline-column-content-v2\x00"
                    + item["name"].encode("utf-8")
                    + b"\x00"
                )
                for item in columns_meta
            }
            col_names = [item["name"] for item in columns_meta]
            for row in iter_sqlite_rows_by_rowid(path, table):
                normalized = [normalize_sqlite_value(value) for value in row[1]]
                digest.update(canonical_json(normalized).encode("utf-8") + b"\n")
                for name, value in zip(col_names, normalized):
                    column_hashers[name].update(
                        canonical_json(value).encode("utf-8") + b"\n"
                    )
            tables.append(
                _finish_table(table, columns_meta, column_hashers, count)
            )
        return digest.hexdigest(), tuple(tables)
    except sqlite3.Error as exc:
        raise DatasetError(f"cannot inspect SQLite dataset {path}: {exc}") from exc
    finally:
        conn.close()


def _csv_fingerprint(path: Path) -> tuple[str, tuple[TableInfo, ...]]:
    header = read_csv_header(path)
    digest = hashlib.sha256(b"maskline-csv-v1\x00")
    digest.update(canonical_json(header).encode("utf-8") + b"\n")
    column_metas = [
        {"name": name, "declared_type": "TEXT", "nullable": True}
        for name in header
    ]
    column_hashers = {
        name: hashlib.sha256(
            b"maskline-column-content-v2\x00" + name.encode("utf-8") + b"\x00"
        )
        for name in header
    }
    count = 0
    for row in iter_csv_tuples(path):
        digest.update(canonical_json(list(row)).encode("utf-8") + b"\n")
        for name, value in zip(header, row):
            column_hashers[name].update(
                canonical_json(value).encode("utf-8") + b"\n"
            )
        count += 1
    table = _finish_table(csv_table_name(path), column_metas, column_hashers, count)
    return digest.hexdigest(), (table,)


def inspect_dataset(path: str | Path) -> DatasetInventory:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise DatasetError(f"dataset not found: {source}")
    kind = dataset_kind(source)
    if kind == "sqlite":
        fingerprint, tables = _sqlite_fingerprint(source)
    else:
        fingerprint, tables = _csv_fingerprint(source)
    return DatasetInventory(
        path=source,
        kind=kind,
        fingerprint=fingerprint,
        size_bytes=source.stat().st_size,
        tables=tables,
    )


def stable_dataset_id(path: str | Path) -> str:
    """Stable identity of a dataset across content changes: its resolved path."""
    resolved = Path(path).expanduser().resolve()
    return sha256_text("maskline-dataset-id-v2\x00" + resolved.as_posix())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Catalog:
    """Metadata database: dataset registrations, fingerprints, and findings.

    On open, a brand-new database gets the v2 schema; a v1 database is migrated
    automatically; a database stamped with a newer schema version raises
    :class:`RegistryVersionError`.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Autocommit mode: every transaction boundary is explicit so that an
        # interrupted scan rolls back instead of leaving partial writes.
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self._ensure_schema()

    # ------------------------------------------------------------------ schema

    def _table_names(self) -> set[str]:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        return {row[0] for row in rows}

    def _ensure_schema(self) -> None:
        tables = self._table_names()
        if "schema_meta" in tables:
            row = self.conn.execute(
                "SELECT schema_version FROM schema_meta WHERE key='version'"
            ).fetchone()
            version = int(row[0]) if row else 0
            if version > SCHEMA_VERSION:
                raise RegistryVersionError(
                    f"registry {self.path} was written by a newer maskline "
                    f"(schema v{version}); this build supports up to "
                    f"v{SCHEMA_VERSION}. Upgrade maskline to read it."
                )
            self._create_v2_tables()
            return
        if "datasets" in tables:
            # Legacy v1 registry without a schema_meta table.
            self._migrate_v1()
            return
        self._create_v2_tables()
        self.conn.execute(
            "INSERT INTO schema_meta (key, schema_version, migrated_from, updated_at) "
            "VALUES ('version', ?, NULL, ?)",
            (SCHEMA_VERSION, _now()),
        )

    def _create_v2_tables(self) -> None:
        # Individual execute() calls (not executescript) so DDL participates in
        # the caller's transaction and rolls back on failure.
        for statement in V2_DDL_STATEMENTS:
            self.conn.execute(statement)

    def _migrate_v1(self) -> None:
        """Copy the legacy v1 data into v2 tables in one transaction.

        DDL and data movement share a single explicit transaction, so a
        failure rolls everything back and the upgrade can be retried. The
        legacy tables are only ever read, never dropped.
        """
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self._create_v2_tables()
            now = _now()
            legacy_rows = self.conn.execute("SELECT * FROM datasets").fetchall()
            for row in legacy_rows:
                tables = json.loads(row["tables_json"])
                dataset_id = stable_dataset_id(row["path"])
                self.conn.execute(
                    "INSERT OR IGNORE INTO dataset_records "
                    "(dataset_id, path, kind, fingerprint, size_bytes, row_count, "
                    "tables_json, registered_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        dataset_id,
                        row["path"],
                        row["kind"],
                        row["fingerprint"],
                        row["size_bytes"],
                        row["row_count"],
                        row["tables_json"],
                        row["registered_at"],
                        now,
                    ),
                )
                for table in tables:
                    columns = table.get("columns", [])
                    structure = sha256_text(
                        "maskline-table-structure-v2\x00"
                        + canonical_json(
                            [
                                {
                                    "name": col["name"],
                                    "declared_type": col["declared_type"],
                                    "nullable": col["nullable"],
                                }
                                for col in columns
                            ]
                        )
                    )
                    self.conn.execute(
                        "INSERT OR IGNORE INTO table_fingerprints "
                        "(dataset_id, table_name, row_count, structure_fingerprint, "
                        "content_fingerprint, columns_json, sample_limit, "
                        "detector_version, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                        (
                            dataset_id,
                            table["name"],
                            table["row_count"],
                            structure,
                            # No per-column hashes exist in v1: the empty marker
                            # forces a full rescan on the first v2 scan.
                            "",
                            json.dumps(columns, ensure_ascii=False),
                            now,
                        ),
                    )
                for finding in self.conn.execute(
                    "SELECT * FROM findings WHERE dataset_fingerprint = ?",
                    (row["fingerprint"],),
                ):
                    self.conn.execute(
                        "INSERT OR IGNORE INTO findings_v2 "
                        "(dataset_id, table_name, column_name, sensitive_type, "
                        "confidence, score, hit_rate, validate_rate, sample_size, "
                        "candidates_json, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            dataset_id,
                            finding["table_name"],
                            finding["column_name"],
                            finding["sensitive_type"],
                            finding["confidence"],
                            finding["score"],
                            finding["hit_rate"],
                            finding["validate_rate"],
                            finding["sample_size"],
                            finding["candidates_json"],
                            finding["updated_at"],
                        ),
                    )
            self.conn.execute(
                "INSERT INTO schema_meta (key, schema_version, migrated_from, updated_at) "
                "VALUES ('version', ?, 1, ?)",
                (SCHEMA_VERSION, now),
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    # ------------------------------------------------------------------ plumbing

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Catalog":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """One atomic unit: commit on success, roll back on any exception."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def reap_stale_scans(self) -> int:
        """Remove bookkeeping rows left by scans that died before committing.

        A scan's data writes are transactional, so a killed scan never leaves
        findings/fingerprints behind; only its run/action bookkeeping needs
        clearing. Returns the number of reaped scan ids.
        """
        rows = self.conn.execute(
            "SELECT scan_id FROM scan_runs WHERE status='running'"
        ).fetchall()
        for row in rows:
            self.conn.execute("DELETE FROM scan_table_actions WHERE scan_id=?", (row[0],))
            self.conn.execute("DELETE FROM scan_runs WHERE scan_id=?", (row[0],))
        return len(rows)

    # ------------------------------------------------------------- v1-compatible

    def register(self, inventory: DatasetInventory) -> bool:
        """Legacy whole-dataset registration; returns True when newly inserted."""
        now = _now()
        record = inventory.to_record()
        existing = self.conn.execute(
            "SELECT 1 FROM datasets WHERE fingerprint = ?", (inventory.fingerprint,)
        ).fetchone()
        if existing:
            return False
        self.conn.execute(
            "INSERT INTO datasets "
            "(fingerprint, path, kind, size_bytes, row_count, tables_json, registered_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                inventory.fingerprint,
                record["path"],
                record["kind"],
                record["size_bytes"],
                record["row_count"],
                json.dumps(record["tables"], ensure_ascii=False),
                now,
            ),
        )
        self.conn.commit()
        return True

    def list_datasets(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM dataset_records ORDER BY registered_at"
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["tables"] = json.loads(item.pop("tables_json"))
            result.append(item)
        return result

    def get_dataset(self, fingerprint: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM dataset_records WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["tables"] = json.loads(item.pop("tables_json"))
        return item

    def save_finding(self, record: dict[str, Any]) -> None:
        """Persist one finding (v2 dataset_id preferred)."""
        dataset_id = record.get("dataset_id")
        if not dataset_id:
            source = record.get("dataset_path")
            if not source:
                raise ValueError(
                    "finding record needs 'dataset_id' or 'dataset_path'"
                )
            dataset_id = stable_dataset_id(source)
        self._upsert_finding(dataset_id, record, _now())
        self.conn.commit()

    def findings_for(self, fingerprint: str) -> list[dict[str, Any]]:
        row = self.conn.execute(
            "SELECT dataset_id FROM dataset_records WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if not row:
            return []
        return self.findings_for_dataset(row[0])

    # ------------------------------------------------------------------ v2 API

    def dataset_state(self, dataset_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM dataset_records WHERE dataset_id = ?", (dataset_id,)
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["tables"] = json.loads(item.pop("tables_json"))
        return item

    def table_states(self, dataset_id: str) -> dict[str, dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM table_fingerprints WHERE dataset_id = ?", (dataset_id,)
        ).fetchall()
        return {
            row["table_name"]: {
                "row_count": row["row_count"],
                "structure_fingerprint": row["structure_fingerprint"],
                "content_fingerprint": row["content_fingerprint"],
                "columns": json.loads(row["columns_json"]),
                "sample_limit": row["sample_limit"],
                "detector_version": row["detector_version"],
            }
            for row in rows
        }

    def findings_for_dataset(self, dataset_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM findings_v2 WHERE dataset_id = ? "
            "ORDER BY table_name, column_name",
            (dataset_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["candidates"] = json.loads(item.pop("candidates_json"))
            result.append(item)
        return result

    def begin_scan_run(self, scan_id: str, dataset_id: str, dataset_path: str) -> None:
        self.conn.execute(
            "INSERT INTO scan_runs "
            "(scan_id, dataset_id, dataset_path, status, started_at, finished_at) "
            "VALUES (?, ?, ?, 'running', ?, NULL)",
            (scan_id, dataset_id, str(dataset_path), _now()),
        )

    def record_table_action(
        self,
        scan_id: str,
        dataset_id: str,
        table_name: str,
        action: str,
        reason: str,
        columns: list[str] | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO scan_table_actions "
            "(scan_id, dataset_id, table_name, action, reason, columns_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(scan_id, dataset_id, table_name) DO UPDATE SET "
            "action=excluded.action, reason=excluded.reason, "
            "columns_json=excluded.columns_json, created_at=excluded.created_at",
            (
                scan_id,
                dataset_id,
                table_name,
                action,
                reason,
                json.dumps(columns or [], ensure_ascii=False),
                _now(),
            ),
        )

    def finish_scan_run(self, scan_id: str, status: str = "completed") -> None:
        self.conn.execute(
            "UPDATE scan_runs SET status=?, finished_at=? WHERE scan_id=?",
            (status, _now(), scan_id),
        )

    def upsert_dataset_record(self, inventory: DatasetInventory, dataset_id: str) -> None:
        now = _now()
        record = inventory.to_record()
        self.conn.execute(
            """
            INSERT INTO dataset_records
                (dataset_id, path, kind, fingerprint, size_bytes, row_count,
                 tables_json, registered_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dataset_id) DO UPDATE SET
                path=excluded.path, kind=excluded.kind,
                fingerprint=excluded.fingerprint, size_bytes=excluded.size_bytes,
                row_count=excluded.row_count, tables_json=excluded.tables_json,
                updated_at=excluded.updated_at
            """,
            (
                dataset_id,
                record["path"],
                record["kind"],
                record["fingerprint"],
                record["size_bytes"],
                record["row_count"],
                json.dumps(record["tables"], ensure_ascii=False),
                now,
                now,
            ),
        )

    def replace_table_fingerprint(
        self,
        dataset_id: str,
        table: TableInfo,
        sample_limit: int,
        detector_version: str,
    ) -> None:
        now = _now()
        columns = [
            {
                "name": col.name,
                "declared_type": col.declared_type,
                "nullable": col.nullable,
                "structure_fingerprint": col.structure_fingerprint,
                "content_fingerprint": col.content_fingerprint,
            }
            for col in table.columns
        ]
        self.conn.execute(
            """
            INSERT INTO table_fingerprints
                (dataset_id, table_name, row_count, structure_fingerprint,
                 content_fingerprint, columns_json, sample_limit,
                 detector_version, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dataset_id, table_name) DO UPDATE SET
                row_count=excluded.row_count,
                structure_fingerprint=excluded.structure_fingerprint,
                content_fingerprint=excluded.content_fingerprint,
                columns_json=excluded.columns_json,
                sample_limit=excluded.sample_limit,
                detector_version=excluded.detector_version,
                updated_at=excluded.updated_at
            """,
            (
                dataset_id,
                table.name,
                table.row_count,
                table.structure_fingerprint,
                table.content_fingerprint,
                json.dumps(columns, ensure_ascii=False),
                sample_limit,
                detector_version,
                now,
            ),
        )

    def _upsert_finding(
        self, dataset_id: str, record: dict[str, Any], updated_at: str
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO findings_v2 (
                dataset_id, table_name, column_name, sensitive_type,
                confidence, score, hit_rate, validate_rate, sample_size,
                candidates_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dataset_id, table_name, column_name) DO UPDATE SET
                sensitive_type=excluded.sensitive_type,
                confidence=excluded.confidence,
                score=excluded.score,
                hit_rate=excluded.hit_rate,
                validate_rate=excluded.validate_rate,
                sample_size=excluded.sample_size,
                candidates_json=excluded.candidates_json,
                updated_at=excluded.updated_at
            """,
            (
                dataset_id,
                record["table_name"],
                record["column_name"],
                record.get("sensitive_type"),
                record.get("confidence", "none"),
                float(record.get("score", 0.0)),
                float(record.get("hit_rate", 0.0)),
                float(record.get("validate_rate", 0.0)),
                int(record.get("sample_size", 0)),
                json.dumps(record.get("candidates", []), ensure_ascii=False),
                updated_at,
            ),
        )

    def save_findings_bulk(
        self, dataset_id: str, records: list[dict[str, Any]]
    ) -> None:
        """Upsert many findings inside the caller's open transaction."""
        now = _now()
        for record in records:
            self._upsert_finding(dataset_id, record, now)

    def delete_findings(self, dataset_id: str, table_name: str, columns: list[str]) -> None:
        if not columns:
            return
        placeholders = ", ".join("?" for _ in columns)
        self.conn.execute(
            f"DELETE FROM findings_v2 WHERE dataset_id=? AND table_name=? "
            f"AND column_name IN ({placeholders})",
            (dataset_id, table_name, *columns),
        )

    def scan_actions(self, scan_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM scan_table_actions WHERE scan_id=? ORDER BY table_name",
            (scan_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["columns"] = json.loads(item.pop("columns_json"))
            result.append(item)
        return result
