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
    skipped_rows: int = 0
    skipped_rowids: tuple[int, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RunEvent:
    run_id: str
    seq: int
    event: str
    ts: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "seq": self.seq,
            "event": self.event,
            "ts": self.ts,
            "details": dict(self.details),
        }


class CheckpointStore:

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        existing = {
            row[0]
            for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"runs", "checkpoints", "run_events"}.issubset(existing):
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
                    skipped_rows INTEGER NOT NULL DEFAULT 0,
                    skipped_rowids_json TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY (run_id, table_name)
                );
                CREATE TABLE IF NOT EXISTS run_events (
                    run_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    event TEXT NOT NULL,
                    ts TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (run_id, seq)
                );
                """
            )
        # Migration for checkpoint databases written by earlier versions,
        # which predate per-table skip accounting.
        columns = {
            row[1]
            for row in self.conn.execute("PRAGMA table_info(checkpoints)")
        }
        if "skipped_rows" not in columns:
            self.conn.execute(
                "ALTER TABLE checkpoints ADD COLUMN skipped_rows INTEGER NOT NULL DEFAULT 0"
            )
        if "skipped_rowids_json" not in columns:
            self.conn.execute(
                "ALTER TABLE checkpoints ADD COLUMN "
                "skipped_rowids_json TEXT NOT NULL DEFAULT '[]'"
            )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "CheckpointStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def create_run(self, record: RunRecord) -> None:
        self.conn.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.run_id, record.dataset_path, record.dataset_fingerprint,
                record.policy_path, record.policy_fingerprint, record.output_path,
                record.status, record.started_at, record.updated_at,
            ),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> RunRecord | None:
        row = self.conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return RunRecord.from_row(row) if row else None

    def set_status(self, run_id: str, status: str) -> None:
        self.conn.execute(
            "UPDATE runs SET status = ?, updated_at = ? WHERE run_id = ?",
            (status, _now(), run_id),
        )
        self.conn.commit()

    def save_checkpoint(
        self,
        run_id: str,
        table_name: str,
        last_rowid: int,
        rows_done: int,
        counts: dict[str, dict[str, int]] | None = None,
        skipped_rows: int = 0,
        skipped_rowids: list[int] | tuple[int, ...] | None = None,
    ) -> None:
        now = _now()
        payload = json.dumps(counts or {}, sort_keys=True)
        rowid_payload = json.dumps(list(skipped_rowids or []))
        self.conn.execute(
            """
            INSERT INTO checkpoints
                (run_id, table_name, last_rowid, rows_done, updated_at,
                 counts_json, skipped_rows, skipped_rowids_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, table_name) DO UPDATE SET
                last_rowid=excluded.last_rowid,
                rows_done=excluded.rows_done,
                updated_at=excluded.updated_at,
                counts_json=excluded.counts_json,
                skipped_rows=excluded.skipped_rows,
                skipped_rowids_json=excluded.skipped_rowids_json
            """,
            (
                run_id, table_name, last_rowid, rows_done, now, payload,
                skipped_rows, rowid_payload,
            ),
        )
        self.conn.execute("UPDATE runs SET updated_at = ? WHERE run_id = ?", (now, run_id))
        self.conn.commit()

    def add_event(
        self,
        run_id: str,
        event: str,
        details: dict[str, Any] | None = None,
        ts: str | None = None,
    ) -> RunEvent:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS last_seq FROM run_events WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        record = RunEvent(
            run_id=run_id,
            seq=int(row["last_seq"]) + 1,
            event=event,
            ts=ts or _now(),
            details=dict(details or {}),
        )
        self.conn.execute(
            "INSERT INTO run_events (run_id, seq, event, ts, details_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                record.run_id,
                record.seq,
                record.event,
                record.ts,
                json.dumps(record.details, ensure_ascii=False, sort_keys=True),
            ),
        )
        self.conn.commit()
        return record

    def list_events(self, run_id: str) -> list[RunEvent]:
        rows = self.conn.execute(
            "SELECT * FROM run_events WHERE run_id = ? ORDER BY seq", (run_id,)
        ).fetchall()
        return [_event_from_row(row) for row in rows]

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


def _checkpoint_from_row(row: sqlite3.Row) -> TableCheckpoint:
    keys = row.keys()
    skipped_rows = int(row["skipped_rows"]) if "skipped_rows" in keys else 0
    if "skipped_rowids_json" in keys:
        skipped_rowids = tuple(
            int(value) for value in json.loads(row["skipped_rowids_json"] or "[]")
        )
    else:
        skipped_rowids = ()
    return TableCheckpoint(
        run_id=row["run_id"],
        table_name=row["table_name"],
        last_rowid=int(row["last_rowid"]),
        rows_done=int(row["rows_done"]),
        updated_at=row["updated_at"],
        counts=json.loads(row["counts_json"] or "{}"),
        skipped_rows=skipped_rows,
        skipped_rowids=skipped_rowids,
    )


def _event_from_row(row: sqlite3.Row) -> RunEvent:
    return RunEvent(
        run_id=row["run_id"],
        seq=int(row["seq"]),
        event=row["event"],
        ts=row["ts"],
        details=json.loads(row["details_json"] or "{}"),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
