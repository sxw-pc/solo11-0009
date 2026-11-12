"""Versioned SQLite storage for linkage scans, profiles, edges, and risks.

Every scan run records a new version; edges and risk findings are tagged with
the version so history is preserved. Column profiles and value fingerprints
are keyed by dataset content fingerprint, which lets unchanged datasets be
reused across scans without re-reading the source files (incremental update).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .model import Association, ColRef, ColumnProfile, RiskFinding, ScanWarning
from .profile import ProfiledColumn

SCHEMA_VERSION = "1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class LinkStore:
    """Metadata database for the linkage capability (data/linkgraph.sqlite)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        # Derived, rebuildable store: WAL avoids one fsync per commit. The
        # tamper-evident record of scans lives in the audit chain, not here.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_runs (
                scan_id TEXT PRIMARY KEY,
                version_no INTEGER NOT NULL,
                target TEXT NOT NULL,
                options_json TEXT NOT NULL,
                ignore_fingerprint TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                stats_json TEXT NOT NULL DEFAULT '{}',
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dataset_state (
                path TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                mtime_ns INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                profiled_scan TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS column_profiles (
                dataset_fingerprint TEXT NOT NULL,
                table_name TEXT NOT NULL,
                column_name TEXT NOT NULL,
                profile_json TEXT NOT NULL,
                PRIMARY KEY (dataset_fingerprint, table_name, column_name)
            );
            CREATE TABLE IF NOT EXISTS column_values (
                dataset_fingerprint TEXT NOT NULL,
                table_name TEXT NOT NULL,
                column_name TEXT NOT NULL,
                value_hash TEXT NOT NULL,
                PRIMARY KEY (dataset_fingerprint, table_name, column_name, value_hash)
            );
            CREATE TABLE IF NOT EXISTS edges (
                version_no INTEGER NOT NULL,
                left_key TEXT NOT NULL,
                right_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                score REAL NOT NULL,
                overlap INTEGER NOT NULL DEFAULT 0,
                containment REAL NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                left_json TEXT NOT NULL,
                right_json TEXT NOT NULL,
                PRIMARY KEY (version_no, left_key, right_key, kind)
            );
            CREATE TABLE IF NOT EXISTS risks (
                version_no INTEGER NOT NULL,
                risk_id TEXT NOT NULL,
                level TEXT NOT NULL,
                score REAL NOT NULL,
                summary TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                PRIMARY KEY (version_no, risk_id)
            );
            CREATE TABLE IF NOT EXISTS warnings (
                scan_id TEXT NOT NULL,
                path TEXT NOT NULL,
                stage TEXT NOT NULL,
                message TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "LinkStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- dataset state -----------------------------------------------------

    def dataset_states(self) -> dict[str, dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM dataset_state").fetchall()
        return {row["path"]: dict(row) for row in rows}

    def upsert_state(
        self,
        path: str,
        fingerprint: str,
        kind: str,
        size_bytes: int,
        mtime_ns: int,
        status: str,
        scan_id: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO dataset_state
                (path, fingerprint, kind, size_bytes, mtime_ns, status,
                 profiled_scan, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                fingerprint=excluded.fingerprint,
                kind=excluded.kind,
                size_bytes=excluded.size_bytes,
                mtime_ns=excluded.mtime_ns,
                status=excluded.status,
                profiled_scan=excluded.profiled_scan,
                updated_at=excluded.updated_at
            """,
            (path, fingerprint, kind, size_bytes, mtime_ns, status, scan_id, _now()),
        )
        self.conn.commit()

    def set_status(self, path: str, status: str) -> None:
        self.conn.execute(
            "UPDATE dataset_state SET status = ?, updated_at = ? WHERE path = ?",
            (status, _now(), path),
        )
        self.conn.commit()

    # -- column profiles ---------------------------------------------------

    def replace_profiles(self, fingerprint: str, profiled: Iterable[ProfiledColumn]) -> None:
        items = list(profiled)
        with self.conn:
            self.conn.execute(
                "DELETE FROM column_profiles WHERE dataset_fingerprint = ?", (fingerprint,)
            )
            self.conn.execute(
                "DELETE FROM column_values WHERE dataset_fingerprint = ?", (fingerprint,)
            )
            for item in items:
                profile = item.profile
                self.conn.execute(
                    "INSERT INTO column_profiles "
                    "(dataset_fingerprint, table_name, column_name, profile_json) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        fingerprint,
                        profile.ref.table,
                        profile.ref.column,
                        json.dumps(profile.to_record(), ensure_ascii=False),
                    ),
                )
                for value_hash in sorted(item.value_hashes):
                    self.conn.execute(
                        "INSERT OR IGNORE INTO column_values "
                        "(dataset_fingerprint, table_name, column_name, value_hash) "
                        "VALUES (?, ?, ?, ?)",
                        (fingerprint, profile.ref.table, profile.ref.column, value_hash),
                    )

    def load_profiles(
        self,
    ) -> tuple[dict[str, ColumnProfile], dict[str, frozenset[str]]]:
        """Load profiles of all active datasets, keyed by column key.

        Datasets with identical content share one fingerprint; the canonical
        path is the lexicographically smallest active path.
        """
        active = self.conn.execute(
            "SELECT fingerprint, MIN(path) AS path FROM dataset_state "
            "WHERE status = 'active' GROUP BY fingerprint"
        ).fetchall()
        profiles: dict[str, ColumnProfile] = {}
        values: dict[str, set[str]] = {}
        for row in active:
            fingerprint = row["fingerprint"]
            path = row["path"]
            for item in self.conn.execute(
                "SELECT * FROM column_profiles WHERE dataset_fingerprint = ? "
                "ORDER BY table_name, column_name",
                (fingerprint,),
            ):
                ref = ColRef(fingerprint, path, item["table_name"], item["column_name"])
                record = json.loads(item["profile_json"])
                profiles[ref.key] = ColumnProfile.from_record(ref, record)
            for item in self.conn.execute(
                "SELECT table_name, column_name, value_hash FROM column_values "
                "WHERE dataset_fingerprint = ?",
                (fingerprint,),
            ):
                key = f"{fingerprint}:{item['table_name']}:{item['column_name']}"
                values.setdefault(key, set()).add(item["value_hash"])
        return profiles, {key: frozenset(item) for key, item in values.items()}

    # -- scan runs, edges, risks, warnings ---------------------------------

    def next_version(self) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(version_no), 0) + 1 AS next FROM scan_runs"
        ).fetchone()
        return int(row["next"])

    def record_scan(
        self,
        scan_id: str,
        version_no: int,
        target: str,
        options: dict[str, Any],
        ignore_fingerprint: str,
        status: str,
        stats: dict[str, Any],
        started_at: str,
        finished_at: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO scan_runs
                (scan_id, version_no, target, options_json, ignore_fingerprint,
                 status, stats_json, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                version_no,
                target,
                json.dumps(options, ensure_ascii=False, sort_keys=True),
                ignore_fingerprint,
                status,
                json.dumps(stats, ensure_ascii=False, sort_keys=True),
                started_at,
                finished_at,
            ),
        )
        self.conn.commit()

    def record_edges(self, version_no: int, edges: Iterable[Association]) -> None:
        with self.conn:
            for edge in edges:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO edges
                        (version_no, left_key, right_key, kind, score, overlap,
                         containment, reason, left_json, right_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        version_no,
                        edge.left.key,
                        edge.right.key,
                        edge.kind,
                        edge.score,
                        edge.overlap,
                        edge.containment,
                        edge.reason,
                        json.dumps(edge.left.to_dict(), ensure_ascii=False),
                        json.dumps(edge.right.to_dict(), ensure_ascii=False),
                    ),
                )

    def record_risks(self, version_no: int, risks: Iterable[RiskFinding]) -> None:
        with self.conn:
            for risk in risks:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO risks
                        (version_no, risk_id, level, score, summary, detail_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        version_no,
                        risk.risk_id,
                        risk.level,
                        risk.score,
                        risk.summary,
                        json.dumps(risk.to_record(), ensure_ascii=False),
                    ),
                )

    def record_warnings(self, scan_id: str, warnings: Iterable[ScanWarning]) -> None:
        with self.conn:
            for warning in warnings:
                self.conn.execute(
                    "INSERT INTO warnings (scan_id, path, stage, message) "
                    "VALUES (?, ?, ?, ?)",
                    (scan_id, warning.path, warning.stage, warning.message),
                )

    # -- queries -------------------------------------------------------------

    def latest_scan(self) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM scan_runs ORDER BY version_no DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["options"] = json.loads(result.pop("options_json"))
        result["stats"] = json.loads(result.pop("stats_json"))
        return result

    def scan_history(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM scan_runs ORDER BY version_no DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["options"] = json.loads(item.pop("options_json"))
            item["stats"] = json.loads(item.pop("stats_json"))
            result.append(item)
        return result

    def edges_for(self, version_no: int) -> list[Association]:
        rows = self.conn.execute(
            "SELECT * FROM edges WHERE version_no = ? ORDER BY kind, score DESC",
            (version_no,),
        ).fetchall()
        return [
            Association.from_record(
                {
                    "left": json.loads(row["left_json"]),
                    "right": json.loads(row["right_json"]),
                    "kind": row["kind"],
                    "score": row["score"],
                    "overlap": row["overlap"],
                    "containment": row["containment"],
                    "reason": row["reason"],
                }
            )
            for row in rows
        ]

    def risks_for(self, version_no: int) -> list[RiskFinding]:
        rows = self.conn.execute(
            "SELECT detail_json FROM risks WHERE version_no = ? ORDER BY risk_id",
            (version_no,),
        ).fetchall()
        return [RiskFinding.from_record(json.loads(row["detail_json"])) for row in rows]

    def warnings_for(self, scan_id: str) -> list[ScanWarning]:
        rows = self.conn.execute(
            "SELECT * FROM warnings WHERE scan_id = ? ORDER BY path", (scan_id,)
        ).fetchall()
        return [
            ScanWarning(row["path"], row["stage"], row["message"]) for row in rows
        ]
