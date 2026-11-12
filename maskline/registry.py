"""Dataset inventory, content fingerprints, and the metadata catalog."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
from .utils import canonical_json, normalize_sqlite_value, quote_ident


@dataclass(frozen=True)
class ColumnInfo:
    name: str
    declared_type: str
    nullable: bool = True


@dataclass(frozen=True)
class TableInfo:
    name: str
    columns: tuple[ColumnInfo, ...]
    row_count: int


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
                    "columns": [
                        {
                            "name": col.name,
                            "declared_type": col.declared_type,
                            "nullable": col.nullable,
                        }
                        for col in table.columns
                    ],
                }
                for table in self.tables
            ],
        }


def _sqlite_fingerprint(path: Path) -> tuple[str, tuple[TableInfo, ...]]:
    conn = sqlite_connect_readonly(path)
    try:
        digest = hashlib.sha256(b"maskline-sqlite-v1\x00")
        tables: list[TableInfo] = []
        for table in sqlite_table_names(conn):
            columns = sqlite_columns(conn, table)
            digest.update(table.encode("utf-8") + b"\x00")
            digest.update(canonical_json(columns).encode("utf-8"))
            count = int(conn.execute(f"SELECT COUNT(*) FROM {quote_ident(table)}").fetchone()[0])
            col_names = [item["name"] for item in columns]
            for row in iter_sqlite_rows_by_rowid(path, table):
                normalized = [normalize_sqlite_value(value) for value in row[1]]
                digest.update(canonical_json(normalized).encode("utf-8") + b"\n")
            tables.append(
                TableInfo(
                    name=table,
                    columns=tuple(
                        ColumnInfo(item["name"], item["declared_type"], item["nullable"])
                        for item in columns
                    ),
                    row_count=count,
                )
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
    count = 0
    for row in iter_csv_tuples(path):
        digest.update(canonical_json(list(row)).encode("utf-8") + b"\n")
        count += 1
    table = TableInfo(
        name=csv_table_name(path),
        columns=tuple(ColumnInfo(name, "TEXT", True) for name in header),
        row_count=count,
    )
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


class Catalog:
    """Metadata database: dataset registrations and detector findings."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS datasets (
                fingerprint TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                kind TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                row_count INTEGER NOT NULL,
                tables_json TEXT NOT NULL,
                registered_at TEXT NOT NULL
            );
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
            );
            CREATE TABLE IF NOT EXISTS drift_comparisons (
                dedupe_key TEXT PRIMARY KEY,
                dataset_path TEXT NOT NULL,
                baseline_fingerprint TEXT NOT NULL,
                current_fingerprint TEXT NOT NULL,
                baseline_registered_at TEXT,
                ignore_rules_fingerprint TEXT,
                ignore_rules_path TEXT,
                hit_rate_tolerance REAL NOT NULL DEFAULT 0.05,
                drifts_json TEXT NOT NULL DEFAULT '[]',
                ignored_drifts_json TEXT NOT NULL DEFAULT '[]',
                summary_json TEXT NOT NULL DEFAULT '{}',
                audit_seq INTEGER NOT NULL,
                audit_entry_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS config_pins (
                scope TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_datasets_path
                ON datasets(path, registered_at);
            CREATE INDEX IF NOT EXISTS idx_findings_fingerprint
                ON findings(dataset_fingerprint);
            CREATE INDEX IF NOT EXISTS idx_drift_comparisons_dataset
                ON drift_comparisons(dataset_path, created_at);
            """
        )
        self._ensure_findings_columns()
        self.conn.commit()

    def _ensure_findings_columns(self) -> None:
        """Add later-era columns without touching existing finding rows.

        Version 0.1 registries already contain every expected column. The
        guard keeps upgrade compatibility if an even older catalog is opened:
        existing rows are never rewritten or deleted.
        """
        expected = (
            ("sensitive_type", "TEXT"),
            ("confidence", "TEXT NOT NULL DEFAULT 'none'"),
            ("score", "REAL NOT NULL DEFAULT 0"),
            ("hit_rate", "REAL NOT NULL DEFAULT 0"),
            ("validate_rate", "REAL NOT NULL DEFAULT 0"),
            ("sample_size", "INTEGER NOT NULL DEFAULT 0"),
            ("candidates_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("updated_at", "TEXT NOT NULL DEFAULT ''"),
        )
        existing = {
            row[1]
            for row in self.conn.execute("PRAGMA table_info(findings)").fetchall()
        }
        for name, declaration in expected:
            if name not in existing:
                self.conn.execute(
                    f"ALTER TABLE findings ADD COLUMN {quote_ident(name)} {declaration}"
                )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Catalog":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def register(self, inventory: DatasetInventory) -> bool:
        """Insert a dataset once; return True only when it was newly registered."""
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
        rows = self.conn.execute("SELECT * FROM datasets ORDER BY registered_at").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["tables"] = json.loads(item.pop("tables_json"))
            result.append(item)
        return result

    def get_dataset(self, fingerprint: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM datasets WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["tables"] = json.loads(item.pop("tables_json"))
        return item

    def save_finding(self, record: dict[str, Any], *, commit: bool = True) -> None:
        self.conn.execute(
            """
            INSERT INTO findings (
                dataset_fingerprint, table_name, column_name, sensitive_type,
                confidence, score, hit_rate, validate_rate, sample_size,
                candidates_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dataset_fingerprint, table_name, column_name) DO UPDATE SET
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
                record["dataset_fingerprint"],
                record["table_name"],
                record["column_name"],
                record.get("sensitive_type"),
                record.get("confidence", "none"),
                float(record.get("score", 0.0)),
                float(record.get("hit_rate", 0.0)),
                float(record.get("validate_rate", 0.0)),
                int(record.get("sample_size", 0)),
                json.dumps(record.get("candidates", []), ensure_ascii=False),
                _now(),
            ),
        )
        self.conn.commit()

    def findings_for(self, fingerprint: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE dataset_fingerprint = ? "
            "ORDER BY table_name, column_name",
            (fingerprint,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["candidates"] = json.loads(item.pop("candidates_json"))
            result.append(item)
        return result

    # ------------------------------------------------------------------
    # Version lookup. A logical dataset is identified by its resolved path;
    # every distinct content fingerprint registered at that path is a version.
    # ------------------------------------------------------------------

    def dataset_versions(self, path: str | Path) -> list[dict[str, Any]]:
        resolved = str(Path(path).expanduser().resolve())
        rows = self.conn.execute(
            "SELECT rowid, fingerprint, path, kind, size_bytes, row_count, "
            "tables_json, registered_at FROM datasets "
            "WHERE path = ? ORDER BY registered_at DESC, rowid DESC",
            (resolved,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            if "tables_json" in item:
                item["tables"] = json.loads(item.pop("tables_json"))
            result.append(item)
        return result

    def latest_version(self, path: str | Path) -> dict[str, Any] | None:
        versions = self.dataset_versions(path)
        return versions[0] if versions else None

    def previous_version(
        self, path: str | Path, current_fingerprint: str | None = None
    ) -> dict[str, Any] | None:
        """Return the newest registered version other than the current one."""
        resolved = str(Path(path).expanduser().resolve())
        if current_fingerprint is None:
            row = self.conn.execute(
                "SELECT rowid, fingerprint, path, kind, size_bytes, row_count, "
                "tables_json, registered_at FROM datasets WHERE path = ? "
                "ORDER BY registered_at DESC, rowid DESC LIMIT 1",
                (resolved,),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT rowid, fingerprint, path, kind, size_bytes, row_count, "
                "tables_json, registered_at FROM datasets "
                "WHERE path = ? AND fingerprint != ? "
                "ORDER BY registered_at DESC, rowid DESC LIMIT 1",
                (resolved, current_fingerprint),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["tables"] = json.loads(item.pop("tables_json"))
        return item

    # ------------------------------------------------------------------
    # Drift comparison catalog. Rows mirror the append-only audit entry so
    # that audit verification can cross-check both representations.
    # ------------------------------------------------------------------

    def get_drift_comparison(self, dedupe_key: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM drift_comparisons WHERE dedupe_key = ?", (dedupe_key,)
        ).fetchone()
        return _drift_row_to_dict(row) if row else None

    def list_drift_comparisons(
        self, dataset_path: str | Path | None = None
    ) -> list[dict[str, Any]]:
        if dataset_path is None:
            rows = self.conn.execute(
                "SELECT * FROM drift_comparisons ORDER BY rowid DESC"
            ).fetchall()
        else:
            resolved = str(Path(dataset_path).expanduser().resolve())
            rows = self.conn.execute(
                "SELECT * FROM drift_comparisons WHERE dataset_path = ? "
                "ORDER BY rowid DESC",
                (resolved,),
            ).fetchall()
        return [_drift_row_to_dict(row) for row in rows]

    def save_drift_comparison(self, record: dict[str, Any]) -> dict[str, Any]:
        """Insert one comparison once; return the stored record.

        The deterministic dedupe key makes repeated scans of the same version
        pair idempotent, so the audit chain does not accumulate duplicates.
        """
        existing = self.get_drift_comparison(record["dedupe_key"])
        if existing:
            return existing
        self.conn.execute(
            "INSERT INTO drift_comparisons ("
            "dedupe_key, dataset_path, baseline_fingerprint, current_fingerprint, "
            "baseline_registered_at, ignore_rules_fingerprint, ignore_rules_path, "
            "hit_rate_tolerance, drifts_json, ignored_drifts_json, summary_json, "
            "audit_seq, audit_entry_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["dedupe_key"],
                record["dataset_path"],
                record["baseline_fingerprint"],
                record["current_fingerprint"],
                record.get("baseline_registered_at"),
                record.get("ignore_rules_fingerprint"),
                record.get("ignore_rules_path"),
                float(record.get("hit_rate_tolerance", 0.05)),
                json.dumps(record.get("drifts", []), ensure_ascii=False),
                json.dumps(record.get("ignored_drifts", []), ensure_ascii=False),
                json.dumps(record.get("summary", {}), ensure_ascii=False),
                int(record["audit_seq"]),
                record["audit_entry_hash"],
                record.get("created_at") or _now(),
            ),
        )
        self.conn.commit()
        stored = self.get_drift_comparison(record["dedupe_key"])
        assert stored is not None
        return stored

    def get_config_pin(self, scope: str) -> str | None:
        row = self.conn.execute(
            "SELECT fingerprint FROM config_pins WHERE scope = ?", (scope,)
        ).fetchone()
        return row[0] if row else None

    def set_config_pin(self, scope: str, fingerprint: str) -> None:
        self.conn.execute(
            "INSERT INTO config_pins (scope, fingerprint, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(scope) DO UPDATE SET "
            "fingerprint=excluded.fingerprint, updated_at=excluded.updated_at",
            (scope, fingerprint, _now()),
        )
        self.conn.commit()


def _drift_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["drifts"] = json.loads(item.pop("drifts_json"))
    item["ignored_drifts"] = json.loads(item.pop("ignored_drifts_json"))
    item["summary"] = json.loads(item.pop("summary_json"))
    return item


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
