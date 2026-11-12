"""Persistent run metadata and per-batch rowid checkpoints.

Run statuses are deliberately explicit so that recovery can distinguish a
legitimate resumable interruption from the remains of an abnormal exit:

``running``      a process currently owns the run (verified through its lock)
``interrupted``  the user suspended it on purpose; resumable, never reclaimed
``failed``       an exception terminated it; resources are recoverable garbage
``completed``    the official masked output; never reclaimed
``cleaned``      dirty resources were reclaimed; the run is no longer resumable
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..utils import sqlite_connect_readonly

RUN_STATUSES = ("running", "interrupted", "failed", "completed", "cleaned")
PROTECTED_STATUSES = ("completed", "interrupted")

# Columns added after the first public release. Existing databases are migrated
# in place so that older workspaces keep working.
_RUN_EXTRA_COLUMNS = {
    "error_type": "TEXT",
    "error_message": "TEXT",
    "finished_at": "TEXT",
    "pid": "INTEGER",
    "host": "TEXT",
}


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    dataset_path: str
    dataset_fingerprint: str
    policy_path: str
    policy_fingerprint: str
    output_path: str
    status: str
    started_at: str
    updated_at: str
    error_type: str | None = None
    error_message: str | None = None
    finished_at: str | None = None
    pid: int | None = None
    host: str | None = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "RunRecord":
        keys = set(row.keys())
        values = {}
        for name in cls.__dataclass_fields__:
            if name in keys:
                values[name] = row[name]
        return cls(**values)


@dataclass(frozen=True)
class TableCheckpoint:
    run_id: str
    table_name: str
    last_rowid: int
    rows_done: int
    updated_at: str
    counts: dict[str, dict[str, int]] = field(default_factory=dict)


def load_run_snapshot(
    db_path: str | Path, *, read_only: bool = True
) -> tuple[list[RunRecord], list[TableCheckpoint]]:
    """Read runs and checkpoints without creating or migrating the database.

    Returns an empty snapshot when the database (or table) does not exist yet.
    """
    path = Path(db_path)
    if not path.is_file():
        return [], []
    conn = sqlite_connect_readonly(path) if read_only else sqlite3.connect(path)
    try:
        try:
            run_rows = conn.execute("SELECT * FROM runs").fetchall()
        except sqlite3.Error:
            run_rows = []
        try:
            checkpoint_rows = conn.execute("SELECT * FROM checkpoints").fetchall()
        except sqlite3.Error:
            checkpoint_rows = []
        return (
            [RunRecord.from_row(row) for row in run_rows],
            [_checkpoint_from_row(row) for row in checkpoint_rows],
        )
    finally:
        conn.close()


class CheckpointStore:

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        # Recovery and concurrent runs share this database. Wait rather than
        # failing with "database is locked" during a short overlapping write.
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                dataset_path TEXT NOT NULL,
                dataset_fingerprint TEXT NOT NULL,
                policy_path TEXT NOT NULL,
                policy_fingerprint TEXT NOT NULL,
                output_path TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                error_type TEXT,
                error_message TEXT,
                finished_at TEXT,
                pid INTEGER,
                host TEXT
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                run_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                last_rowid INTEGER NOT NULL,
                rows_done INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                counts_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (run_id, table_name)
            );
            """
        )
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        existing = {
            row[1] for row in self.conn.execute("PRAGMA table_info(runs)").fetchall()
        }
        for column, kind in _RUN_EXTRA_COLUMNS.items():
            if column not in existing:
                self.conn.execute(f"ALTER TABLE runs ADD COLUMN {column} {kind}")
        checkpoint_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(checkpoints)").fetchall()
        }
        if "counts_json" not in checkpoint_columns:
            self.conn.execute(
                "ALTER TABLE checkpoints ADD COLUMN counts_json TEXT NOT NULL DEFAULT '{}'"
            )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "CheckpointStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def create_run(self, record: RunRecord) -> None:
        self.conn.execute(
            """
            INSERT INTO runs (
                run_id, dataset_path, dataset_fingerprint, policy_path,
                policy_fingerprint, output_path, status, started_at, updated_at,
                error_type, error_message, finished_at, pid, host
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.run_id, record.dataset_path, record.dataset_fingerprint,
                record.policy_path, record.policy_fingerprint, record.output_path,
                record.status, record.started_at, record.updated_at,
                record.error_type, record.error_message, record.finished_at,
                record.pid, record.host,
            ),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> RunRecord | None:
        row = self.conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return RunRecord.from_row(row) if row else None

    def set_status(self, run_id: str, status: str) -> None:
        now = _now()
        finished = now if status in {"completed", "failed", "interrupted", "cleaned"} else None
        try:
            self.conn.execute(
                "UPDATE runs SET status = ?, updated_at = ?, finished_at = ? "
                "WHERE run_id = ?",
                (status, now, finished, run_id),
            )
            self.conn.commit()
        except sqlite3.Error:
            # A full disk or revoked permission can make this write fail. The
            # caller is already handling an abnormal exit, so never mask it.
            self.conn.rollback()

    def record_error(self, run_id: str, error_type: str, message: str) -> None:
        try:
            self.conn.execute(
                "UPDATE runs SET error_type = ?, error_message = ?, updated_at = ? "
                "WHERE run_id = ?",
                (error_type, message[:4000], _now(), run_id),
            )
            self.conn.commit()
        except sqlite3.Error:
            self.conn.rollback()

    def save_checkpoint(
        self,
        run_id: str,
        table_name: str,
        last_rowid: int,
        rows_done: int,
        counts: dict[str, dict[str, int]] | None = None,
    ) -> None:
        now = _now()
        payload = json.dumps(counts or {}, sort_keys=True)
        self.conn.execute(
            """
            INSERT INTO checkpoints
                (run_id, table_name, last_rowid, rows_done, updated_at, counts_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, table_name) DO UPDATE SET
                last_rowid=excluded.last_rowid,
                rows_done=excluded.rows_done,
                updated_at=excluded.updated_at,
                counts_json=excluded.counts_json
            """,
            (run_id, table_name, last_rowid, rows_done, now, payload),
        )
        self.conn.execute("UPDATE runs SET updated_at = ? WHERE run_id = ?", (now, run_id))
        self.conn.commit()

    def get_checkpoint(self, run_id: str, table_name: str) -> TableCheckpoint | None:
        row = self.conn.execute(
            "SELECT * FROM checkpoints WHERE run_id = ? AND table_name = ?",
            (run_id, table_name),
        ).fetchone()
        return _checkpoint_from_row(row) if row else None

    def list_checkpoints(self, run_id: str) -> list[TableCheckpoint]:
        rows = self.conn.execute(
            "SELECT * FROM checkpoints WHERE run_id = ? ORDER BY table_name", (run_id,)
        ).fetchall()
        return [_checkpoint_from_row(row) for row in rows]

    def list_runs(self, limit: int = 20) -> list[RunRecord]:
        rows = self.conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [RunRecord.from_row(row) for row in rows]

    def delete_checkpoints(self, run_id: str) -> int:
        cursor = self.conn.execute(
            "DELETE FROM checkpoints WHERE run_id = ?", (run_id,)
        )
        self.conn.commit()
        return int(cursor.rowcount or 0)

    def delete_checkpoint_run_ids(self, run_ids: set[str]) -> int:
        if not run_ids:
            return 0
        removed = 0
        for run_id in sorted(run_ids):
            cursor = self.conn.execute(
                "DELETE FROM checkpoints WHERE run_id = ?", (run_id,)
            )
            removed += int(cursor.rowcount or 0)
        self.conn.commit()
        return removed


def _checkpoint_from_row(row: sqlite3.Row) -> TableCheckpoint:
    payload = row["counts_json"] if "counts_json" in row.keys() else "{}"
    return TableCheckpoint(
        run_id=row["run_id"],
        table_name=row["table_name"],
        last_rowid=int(row["last_rowid"]),
        rows_done=int(row["rows_done"]),
        updated_at=row["updated_at"],
        counts=json.loads(payload or "{}"),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
