"""Persistent run metadata and per-batch rowid checkpoints."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


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
    owner_pid: int | None = None
    owner_host: str | None = None
    status_detail: str | None = None
    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "RunRecord":
        return cls(**{key: row[key] for key in row.keys()})


@dataclass(frozen=True)
class TableCheckpoint:
    run_id: str
    table_name: str
    last_rowid: int
    rows_done: int
    updated_at: str
    counts: dict[str, dict[str, int]] = field(default_factory=dict)


# Columns added after the initial schema; migrated idempotently at open time.
_RUN_EXTRA_COLUMNS = (
    ("owner_pid", "INTEGER"),
    ("owner_host", "TEXT"),
    ("status_detail", "TEXT"),
)


class CheckpointStore:

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
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
                updated_at TEXT NOT NULL
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
            row[1] for row in self.conn.execute("PRAGMA table_info(runs)")
        }
        for name, ddl in _RUN_EXTRA_COLUMNS:
            if name in existing:
                continue
            try:
                self.conn.execute(f"ALTER TABLE runs ADD COLUMN {name} {ddl}")
            except sqlite3.OperationalError:
                # Another process migrated concurrently; verify and move on.
                refreshed = {
                    row[1] for row in self.conn.execute("PRAGMA table_info(runs)")
                }
                if name not in refreshed:
                    raise

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
                owner_pid, owner_host, status_detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.run_id, record.dataset_path, record.dataset_fingerprint,
                record.policy_path, record.policy_fingerprint, record.output_path,
                record.status, record.started_at, record.updated_at,
                record.owner_pid, record.owner_host, record.status_detail,
            ),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> RunRecord | None:
        row = self.conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return RunRecord.from_row(row) if row else None

    def set_status(self, run_id: str, status: str, detail: str | None = None) -> None:
        self.conn.execute(
            "UPDATE runs SET status = ?, status_detail = ?, updated_at = ? WHERE run_id = ?",
            (status, detail, _now(), run_id),
        )
        self.conn.commit()

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

    def list_runs(self, limit: int | None = 20) -> list[RunRecord]:
        if limit is None:
            rows = self.conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC"
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [RunRecord.from_row(row) for row in rows]

    def delete_run(self, run_id: str) -> None:
        """Remove a run record and all of its checkpoints (idempotent)."""
        self.conn.execute("DELETE FROM checkpoints WHERE run_id = ?", (run_id,))
        self.conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        self.conn.commit()

    def output_references(self, output_path: str) -> list[str]:
        """Run ids whose recorded output path matches ``output_path``."""
        rows = self.conn.execute(
            "SELECT run_id FROM runs WHERE output_path = ?", (output_path,)
        ).fetchall()
        return [row[0] for row in rows]

    def dataset_references(self, dataset_path: str) -> int:
        """How many runs use ``dataset_path`` as their source dataset."""
        row = self.conn.execute(
            "SELECT COUNT(*) FROM runs WHERE dataset_path = ?", (dataset_path,)
        ).fetchone()
        return int(row[0])


def _checkpoint_from_row(row: sqlite3.Row) -> TableCheckpoint:
    return TableCheckpoint(
        run_id=row["run_id"],
        table_name=row["table_name"],
        last_rowid=int(row["last_rowid"]),
        rows_done=int(row["rows_done"]),
        updated_at=row["updated_at"],
        counts=json.loads(row["counts_json"] or "{}"),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
