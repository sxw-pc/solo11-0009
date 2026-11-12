"""Persistent governor state: job queue, quotas, samples, and runtime knobs.

Everything is kept in one local SQLite database inside the maskline workspace,
so a governor daemon that is itself killed can restart and reconstruct every
job purely from disk.  Wall-clock timestamps (``time.time``) are stored rather
than monotonic clocks because they must survive daemon restarts.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import GovernorStateError, JobControlError

# Lifecycle of one submitted task.  The set is deliberately small and every
# transition is driven through GovernorStore.transition so invalid jumps fail
# loudly instead of corrupting the queue.
JOB_STATES = (
    "queued",       # accepted, waiting for a concurrency slot (FIFO)
    "running",      # a worker process is executing a slice
    "throttled",    # running but being duty-cycle throttled for CPU overuse
    "paused",       # worker stopped at a checkpoint; waiting to resume
    "completed",    # terminal success
    "failed",       # terminal failure after retries are exhausted
    "cancelled",    # terminal, requested by an operator
)

ACTIVE_STATES = ("queued", "running", "throttled", "paused")
TERMINAL_STATES = ("completed", "failed", "cancelled")

_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "queued": frozenset({"running", "cancelled"}),
    "running": frozenset({"throttled", "paused", "completed", "failed", "cancelled"}),
    "throttled": frozenset({"running", "paused", "completed", "failed", "cancelled"}),
    "paused": frozenset({"running", "failed", "cancelled"}),
    "completed": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}


@dataclass(frozen=True)
class JobRecord:
    job_id: str
    name: str
    state: str
    argv: tuple[str, ...]
    cwd: str
    env_json: str
    cpu_max_percent: float
    memory_max_mb: int
    max_runtime_seconds: int
    quota_source: str
    run_id: str | None
    attempt: int
    max_resume_attempts: int
    created_at: float
    updated_at: float
    run_started_at: float | None
    runtime_seconds: float
    cpu_breaches: int
    memory_breaches: int
    runtime_breaches: int
    throttle_events: int
    pause_events: int
    resume_events: int
    last_cpu_percent: float
    last_rss_mb: float
    last_exit_code: int | None
    last_error: str | None
    not_before: float
    pid: int | None
    log_path: str | None
    resume_mode: str = "maskline"

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "JobRecord":
        return cls(
            job_id=row["job_id"],
            name=row["name"],
            state=row["state"],
            argv=tuple(json.loads(row["argv_json"])),
            cwd=row["cwd"],
            env_json=row["env_json"],
            cpu_max_percent=float(row["cpu_max_percent"]),
            memory_max_mb=int(row["memory_max_mb"]),
            max_runtime_seconds=int(row["max_runtime_seconds"]),
            quota_source=row["quota_source"],
            run_id=row["run_id"],
            attempt=int(row["attempt"]),
            max_resume_attempts=int(row["max_resume_attempts"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            run_started_at=row["run_started_at"],
            runtime_seconds=float(row["runtime_seconds"]),
            cpu_breaches=int(row["cpu_breaches"]),
            memory_breaches=int(row["memory_breaches"]),
            runtime_breaches=int(row["runtime_breaches"]),
            throttle_events=int(row["throttle_events"]),
            pause_events=int(row["pause_events"]),
            resume_events=int(row["resume_events"]),
            last_cpu_percent=float(row["last_cpu_percent"]),
            last_rss_mb=float(row["last_rss_mb"]),
            last_exit_code=row["last_exit_code"],
            last_error=row["last_error"],
            not_before=float(row["not_before"]),
            pid=row["pid"],
            log_path=row["log_path"],
            resume_mode=row["resume_mode"],
        )

    def quota(self) -> dict[str, Any]:
        return {
            "cpu_max_percent": self.cpu_max_percent,
            "memory_max_mb": self.memory_max_mb,
            "max_runtime_seconds": self.max_runtime_seconds,
        }


@dataclass(frozen=True)
class SampleRecord:
    job_id: str
    sampled_at: float
    cpu_percent: float
    rss_mb: float
    system_available_mb: float


class GovernorStore:
    """SQLite-backed queue and bookkeeping; safe to reopen after a crash."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after the first release, idempotently."""
        existing = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(jobs)")
        }
        if "resume_mode" not in existing:
            self.conn.execute(
                "ALTER TABLE jobs ADD COLUMN resume_mode TEXT "
                "NOT NULL DEFAULT 'maskline'"
            )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "GovernorStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ jobs
    def create_job(self, record: JobRecord) -> None:
        self.conn.execute(
            f"INSERT INTO jobs ({', '.join(_JOB_COLUMNS)}) VALUES "
            f"({', '.join('?' for _ in _JOB_COLUMNS)})",
            _job_values(record),
        )
        self.conn.commit()

    def get_job(self, job_id: str) -> JobRecord | None:
        row = self.conn.execute(
            "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        return JobRecord.from_row(row) if row else None

    def require_job(self, job_id: str) -> JobRecord:
        record = self.get_job(job_id)
        if record is None:
            raise JobControlError(f"unknown job id: {job_id}")
        return record

    def list_jobs(self, include_terminal: bool = True) -> list[JobRecord]:
        sql = "SELECT * FROM jobs"
        if not include_terminal:
            placeholders = ", ".join("?" for _ in TERMINAL_STATES)
            sql += f" WHERE state NOT IN ({placeholders})"
            rows = self.conn.execute(
                sql + " ORDER BY created_at ASC", TERMINAL_STATES
            ).fetchall()
        else:
            rows = self.conn.execute(
                sql + " ORDER BY created_at ASC"
            ).fetchall()
        return [JobRecord.from_row(row) for row in rows]

    def next_queued(self) -> JobRecord | None:
        row = self.conn.execute(
            "SELECT * FROM jobs WHERE state = 'queued' "
            "ORDER BY created_at ASC LIMIT 1"
        ).fetchone()
        return JobRecord.from_row(row) if row else None

    def resumable_paused(self, now: float | None = None) -> list[JobRecord]:
        moment = now if now is not None else time.time()
        rows = self.conn.execute(
            "SELECT * FROM jobs WHERE state = 'paused' AND not_before <= ? "
            "ORDER BY not_before ASC",
            (moment,),
        ).fetchall()
        return [JobRecord.from_row(row) for row in rows]

    def count_running_slots(self) -> int:
        """Jobs that currently occupy a concurrency slot (paused jobs hold it)."""
        rows = self.conn.execute(
            "SELECT COUNT(*) AS n FROM jobs WHERE state IN ('running', 'throttled', 'paused')"
        ).fetchone()
        return int(rows["n"])

    def transition(
        self, job_id: str, new_state: str, *, expected: str | None = None
    ) -> JobRecord:
        record = self.require_job(job_id)
        if expected is not None and record.state != expected:
            raise JobControlError(
                f"job {job_id} is {record.state}, expected {expected}"
            )
        if new_state not in _ALLOWED_TRANSITIONS[record.state]:
            raise JobControlError(
                f"illegal transition for job {job_id}: "
                f"{record.state} -> {new_state}"
            )
        self.conn.execute(
            "UPDATE jobs SET state = ?, updated_at = ? WHERE job_id = ?",
            (new_state, time.time(), job_id),
        )
        self.conn.commit()
        return self.require_job(job_id)

    def update_job(self, job_id: str, **fields: Any) -> JobRecord:
        if not fields:
            return self.require_job(job_id)
        unknown = sorted(set(fields) - set(_JOB_COLUMNS))
        if unknown:
            raise GovernorStateError(f"unknown job field(s): {', '.join(unknown)}")
        assignments = ", ".join(f"{key} = ?" for key in fields)
        self.conn.execute(
            f"UPDATE jobs SET {assignments}, updated_at = ? WHERE job_id = ?",
            (*fields.values(), time.time(), job_id),
        )
        self.conn.commit()
        return self.require_job(job_id)

    def increment(self, job_id: str, **counters: int) -> None:
        if not counters:
            return
        assignments = ", ".join(f"{key} = {key} + ?" for key in counters)
        values = [int(value) for value in counters.values()]
        self.conn.execute(
            f"UPDATE jobs SET {assignments}, updated_at = ? WHERE job_id = ?",
            (*values, time.time(), job_id),
        )
        self.conn.commit()

    # --------------------------------------------------------------- samples
    def add_sample(self, sample: SampleRecord, retain: int = 2000) -> None:
        self.conn.execute(
            "INSERT INTO resource_samples "
            "(job_id, sampled_at, cpu_percent, rss_mb, system_available_mb) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                sample.job_id, sample.sampled_at, sample.cpu_percent,
                sample.rss_mb, sample.system_available_mb,
            ),
        )
        self.conn.execute(
            "DELETE FROM resource_samples WHERE id NOT IN "
            "(SELECT id FROM resource_samples ORDER BY id DESC LIMIT ?)",
            (retain,),
        )
        self.conn.commit()

    def latest_sample(self, job_id: str) -> SampleRecord | None:
        row = self.conn.execute(
            "SELECT * FROM resource_samples WHERE job_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (job_id,),
        ).fetchone()
        return _sample_from_row(row) if row else None

    # ------------------------------------------------- runtime configuration
    def set_setting(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, "
            "updated_at=excluded.updated_at",
            (key, json.dumps(value, sort_keys=True), time.time()),
        )
        self.conn.commit()

    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute(
            "SELECT value_json FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return json.loads(row["value_json"]) if row else default

    def all_settings(self) -> dict[str, Any]:
        rows = self.conn.execute("SELECT key, value_json FROM settings").fetchall()
        return {row["key"]: json.loads(row["value_json"]) for row in rows}

    def reset_orphans_on_start(self) -> list[str]:
        """Mark jobs whose workers died with the daemon as paused/resumable."""
        rows = self.conn.execute(
            "SELECT job_id FROM jobs WHERE state IN ('running', 'throttled')"
        ).fetchall()
        orphan_ids = [row["job_id"] for row in rows]
        if orphan_ids:
            self.conn.execute(
                "UPDATE jobs SET state = 'paused', pid = NULL, "
                "not_before = ?, updated_at = ? "
                "WHERE state IN ('running', 'throttled')",
                (time.time(), time.time()),
            )
            self.conn.commit()
        return orphan_ids


_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    state TEXT NOT NULL,
    argv_json TEXT NOT NULL,
    cwd TEXT NOT NULL,
    env_json TEXT NOT NULL,
    cpu_max_percent REAL NOT NULL,
    memory_max_mb INTEGER NOT NULL,
    max_runtime_seconds INTEGER NOT NULL,
    quota_source TEXT NOT NULL,
    run_id TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    max_resume_attempts INTEGER NOT NULL DEFAULT 10,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    run_started_at REAL,
    runtime_seconds REAL NOT NULL DEFAULT 0,
    cpu_breaches INTEGER NOT NULL DEFAULT 0,
    memory_breaches INTEGER NOT NULL DEFAULT 0,
    runtime_breaches INTEGER NOT NULL DEFAULT 0,
    throttle_events INTEGER NOT NULL DEFAULT 0,
    pause_events INTEGER NOT NULL DEFAULT 1,
    resume_events INTEGER NOT NULL DEFAULT 0,
    last_cpu_percent REAL NOT NULL DEFAULT 0,
    last_rss_mb REAL NOT NULL DEFAULT 0,
    last_exit_code INTEGER,
    last_error TEXT,
    not_before REAL NOT NULL DEFAULT 0,
    pid INTEGER,
    log_path TEXT,
    resume_mode TEXT NOT NULL DEFAULT 'maskline'
);
CREATE TABLE IF NOT EXISTS resource_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    sampled_at REAL NOT NULL,
    cpu_percent REAL NOT NULL,
    rss_mb REAL NOT NULL,
    system_available_mb REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_job ON resource_samples(job_id, id);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""

_JOB_COLUMNS = (
    "job_id", "name", "state", "argv_json", "cwd", "env_json",
    "cpu_max_percent", "memory_max_mb", "max_runtime_seconds", "quota_source",
    "run_id", "attempt", "max_resume_attempts", "created_at", "updated_at",
    "run_started_at", "runtime_seconds", "cpu_breaches", "memory_breaches",
    "runtime_breaches", "throttle_events", "pause_events", "resume_events",
    "last_cpu_percent", "last_rss_mb", "last_exit_code", "last_error",
    "not_before", "pid", "log_path", "resume_mode",
)


def _job_values(record: JobRecord) -> list[Any]:
    payload = {
        "job_id": record.job_id,
        "name": record.name,
        "state": record.state,
        "argv_json": json.dumps(list(record.argv)),
        "cwd": record.cwd,
        "env_json": record.env_json,
        "cpu_max_percent": record.cpu_max_percent,
        "memory_max_mb": record.memory_max_mb,
        "max_runtime_seconds": record.max_runtime_seconds,
        "quota_source": record.quota_source,
        "run_id": record.run_id,
        "attempt": record.attempt,
        "max_resume_attempts": record.max_resume_attempts,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "run_started_at": record.run_started_at,
        "runtime_seconds": record.runtime_seconds,
        "cpu_breaches": record.cpu_breaches,
        "memory_breaches": record.memory_breaches,
        "runtime_breaches": record.runtime_breaches,
        "throttle_events": record.throttle_events,
        "pause_events": record.pause_events,
        "resume_events": record.resume_events,
        "last_cpu_percent": record.last_cpu_percent,
        "last_rss_mb": record.last_rss_mb,
        "last_exit_code": record.last_exit_code,
        "last_error": record.last_error,
        "not_before": record.not_before,
        "pid": record.pid,
        "log_path": record.log_path,
        "resume_mode": record.resume_mode,
    }
    return [payload[column] for column in _JOB_COLUMNS]


def _sample_from_row(row: sqlite3.Row) -> SampleRecord:
    return SampleRecord(
        job_id=row["job_id"],
        sampled_at=float(row["sampled_at"]),
        cpu_percent=float(row["cpu_percent"]),
        rss_mb=float(row["rss_mb"]),
        system_available_mb=float(row["system_available_mb"]),
    )
