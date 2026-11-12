"""Cross-process run locks keyed by target database and dataset fingerprint.

A lock row lives in ``checkpoints.sqlite`` and records the owning ``run_id``,
PID, host and heartbeat timestamp.  Acquisition is serialised with an
``BEGIN IMMEDIATE`` SQLite transaction so two processes on the same server can
never believe they own the same target at the same time.

Abandoned locks are reclaimed automatically: a lock whose heartbeat is older
than the configured timeout is stale, as is a lock whose owner PID is no longer
alive on this host.  ``resume`` adopts the lock left behind by the interrupted
run instead of creating a second lock.  Every *reclamation* is appended to the
audit hash chain.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..audit import AuditLog
from ..utils import canonical_json, sha256_text
from .errors import PipelineError

DEFAULT_LOCK_TIMEOUT_SECONDS = 60.0
DEFAULT_LOCK_HEARTBEAT_SECONDS = 10.0
LOCK_STATE_ACTIVE = "active"
LOCK_STATE_INTERRUPTED = "interrupted"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_locks (
    lock_key TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    dataset_fingerprint TEXT NOT NULL,
    target_path TEXT NOT NULL,
    pid INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    started_at TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active'
);
"""


class RunLockError(PipelineError):
    """Raised when another live run owns the requested target + dataset lock."""


@dataclass(frozen=True)
class LockRecord:
    lock_key: str
    run_id: str
    dataset_fingerprint: str
    target_path: str
    pid: int
    hostname: str
    started_at: str
    acquired_at: str
    heartbeat_at: str
    state: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "LockRecord":
        return cls(
            lock_key=row["lock_key"],
            run_id=row["run_id"],
            dataset_fingerprint=row["dataset_fingerprint"],
            target_path=row["target_path"],
            pid=int(row["pid"]),
            hostname=row["hostname"],
            started_at=row["started_at"],
            acquired_at=row["acquired_at"],
            heartbeat_at=row["heartbeat_at"],
            state=row["state"],
        )


@dataclass(frozen=True)
class LockAcquisition:
    holder: LockRecord
    reclaimed: LockRecord | None = None
    reclaim_reason: str | None = None
    inherited: bool = False


def lock_key(target_path: str | Path, dataset_fingerprint: str) -> str:
    """Stable key: one target database plus one dataset content fingerprint."""
    target = str(Path(target_path).expanduser().resolve())
    return sha256_text(
        canonical_json(
            {"target": target, "dataset_fingerprint": dataset_fingerprint}
        )
    )


def lock_timeout_seconds(value: float | None = None) -> float:
    if value is None:
        raw = os.environ.get("MASKLINE_LOCK_TIMEOUT")
        if raw is None:
            raw = os.environ.get("MASKLINE_LOCK_TIMEOUT_SECONDS")
        value = DEFAULT_LOCK_TIMEOUT_SECONDS if raw is None or not raw.strip() else _to_float(raw)
    timeout = float(value)
    if timeout <= 0:
        raise PipelineError("lock timeout must be positive")
    return timeout


def lock_heartbeat_seconds(value: float | None, timeout: float) -> float:
    if value is None:
        raw = os.environ.get("MASKLINE_LOCK_HEARTBEAT")
        if raw is None:
            raw = os.environ.get("MASKLINE_LOCK_HEARTBEAT_SECONDS")
        value = DEFAULT_LOCK_HEARTBEAT_SECONDS if raw is None or not raw.strip() else _to_float(raw)
    interval = float(value)
    if interval <= 0:
        raise PipelineError("lock heartbeat interval must be positive")
    # Always beat well inside the staleness window, even for tiny test timeouts.
    return max(0.2, min(interval, timeout / 3.0))


def _to_float(raw: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:
        raise PipelineError(f"invalid lock timing value: {raw!r}") from exc


def _hostname() -> str:
    return socket.gethostname() or "unknown-host"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds")


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # exists, but owned by another user
    except OSError:
        return False
    # A zombie has not been reaped yet; treat it as dead for lock purposes.
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        state = stat.rsplit(")", 1)[1].split()[0]
        if state == "Z":
            return False
    except (OSError, IndexError):
        pass
    return True


def _heartbeat_age_seconds(record: LockRecord, now: datetime) -> float:
    try:
        heartbeat = datetime.fromisoformat(record.heartbeat_at)
    except (TypeError, ValueError):
        return float("inf")
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    return (now - heartbeat).total_seconds()


def _stale_reason(
    record: LockRecord, now: datetime, timeout: float, hostname: str
) -> tuple[bool, str | None]:
    if record.state == LOCK_STATE_INTERRUPTED:
        return True, "previous_run_interrupted"
    if record.hostname == hostname and not _pid_is_alive(record.pid):
        return True, "process_not_alive"
    if _heartbeat_age_seconds(record, now) > timeout:
        return True, "heartbeat_timeout"
    return False, None


class RunLockStore:
    """SQLite-backed lock table; operations are individually transactional."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = 30000")
        self.conn.executescript(_SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def acquire(
        self,
        *,
        run_id: str,
        target_path: str | Path,
        dataset_fingerprint: str,
        inherit_run_id: str | None = None,
        started_at: str | None = None,
        timeout: float,
        pid: int | None = None,
        hostname: str | None = None,
    ) -> LockAcquisition:
        now = _now()
        now_iso = _iso(now)
        key = lock_key(target_path, dataset_fingerprint)
        owner_pid = os.getpid() if pid is None else int(pid)
        owner_host = _hostname() if hostname is None else hostname
        target = str(Path(target_path).expanduser().resolve())

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT * FROM run_locks WHERE lock_key = ?", (key,)
            ).fetchone()
            if row is None:
                holder = LockRecord(
                    lock_key=key,
                    run_id=run_id,
                    dataset_fingerprint=dataset_fingerprint,
                    target_path=target,
                    pid=owner_pid,
                    hostname=owner_host,
                    started_at=started_at or now_iso,
                    acquired_at=now_iso,
                    heartbeat_at=now_iso,
                    state=LOCK_STATE_ACTIVE,
                )
                self._insert(holder)
                self.conn.execute("COMMIT")
                return LockAcquisition(holder=holder)

            previous = LockRecord.from_row(row)
            same_run = inherit_run_id is not None and previous.run_id == inherit_run_id
            same_owner = previous.hostname == owner_host and previous.pid == owner_pid

            if same_run and (
                same_owner or previous.state == LOCK_STATE_INTERRUPTED
            ):
                # resume adopts the original run's lock instead of taking a new one
                holder = self._replace(
                    previous,
                    run_id=run_id,
                    dataset_fingerprint=dataset_fingerprint,
                    target_path=target,
                    pid=owner_pid,
                    hostname=owner_host,
                    started_at=previous.started_at,
                    now_iso=now_iso,
                )
                self.conn.execute("COMMIT")
                return LockAcquisition(holder=holder, inherited=True)

            stale, reason = _stale_reason(previous, now, timeout, owner_host)
            if not stale:
                self.conn.execute("ROLLBACK")
                if same_run:
                    raise RunLockError(
                        f"run {previous.run_id} is already being resumed by "
                        f"pid {previous.pid} on {previous.hostname} "
                        f"(started at {previous.started_at}); refusing to start"
                    )
                raise RunLockError(
                    f"target is locked by run {previous.run_id} started at "
                    f"{previous.started_at} (pid {previous.pid} on "
                    f"{previous.hostname}, last heartbeat {previous.heartbeat_at}); "
                    f"refusing to start"
                )

            holder = self._replace(
                previous,
                run_id=run_id,
                dataset_fingerprint=dataset_fingerprint,
                target_path=target,
                pid=owner_pid,
                hostname=owner_host,
                started_at=previous.started_at if same_run else (started_at or now_iso),
                now_iso=now_iso,
            )
            self.conn.execute("COMMIT")
            return LockAcquisition(
                holder=holder,
                reclaimed=previous,
                reclaim_reason=reason,
                inherited=same_run,
            )
        except BaseException:
            if self.conn.in_transaction:
                self.conn.execute("ROLLBACK")
            raise

    def _insert(self, holder: LockRecord) -> None:
        self.conn.execute(
            """
            INSERT INTO run_locks (
                lock_key, run_id, dataset_fingerprint, target_path, pid,
                hostname, started_at, acquired_at, heartbeat_at, state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                holder.lock_key, holder.run_id, holder.dataset_fingerprint,
                holder.target_path, holder.pid, holder.hostname,
                holder.started_at, holder.acquired_at, holder.heartbeat_at,
                holder.state,
            ),
        )

    def _replace(
        self,
        previous: LockRecord,
        *,
        run_id: str,
        dataset_fingerprint: str,
        target_path: str,
        pid: int,
        hostname: str,
        started_at: str,
        now_iso: str,
    ) -> LockRecord:
        holder = LockRecord(
            lock_key=previous.lock_key,
            run_id=run_id,
            dataset_fingerprint=dataset_fingerprint,
            target_path=target_path,
            pid=pid,
            hostname=hostname,
            started_at=started_at,
            acquired_at=now_iso,
            heartbeat_at=now_iso,
            state=LOCK_STATE_ACTIVE,
        )
        self.conn.execute(
            """
            UPDATE run_locks SET
                run_id = ?, dataset_fingerprint = ?, target_path = ?, pid = ?,
                hostname = ?, started_at = ?, acquired_at = ?, heartbeat_at = ?,
                state = ?
            WHERE lock_key = ?
            """,
            (
                holder.run_id, holder.dataset_fingerprint, holder.target_path,
                holder.pid, holder.hostname, holder.started_at,
                holder.acquired_at, holder.heartbeat_at, holder.state,
                holder.lock_key,
            ),
        )
        return holder


class RunLockHandle:
    """Owns the acquired lock for the lifetime of a run; refreshes its heartbeat."""

    def __init__(
        self, db_path: str | Path, acquisition: LockAcquisition, heartbeat_interval: float
    ) -> None:
        self.db_path = Path(db_path)
        self.acquisition = acquisition
        self.heartbeat_interval = heartbeat_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lost = False

    @property
    def holder(self) -> LockRecord:
        return self.acquisition.holder

    @property
    def lost(self) -> bool:
        return self._lost

    def start(self) -> "RunLockHandle":
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"maskline-lock-{self.holder.run_id}",
            daemon=True,
        )
        self._thread.start()
        return self

    def _heartbeat_loop(self) -> None:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.execute("PRAGMA busy_timeout = 30000")
        try:
            while not self._stop.wait(self.heartbeat_interval):
                holder = self.holder
                cursor = conn.execute(
                    """
                    UPDATE run_locks SET heartbeat_at = ?
                    WHERE lock_key = ? AND run_id = ? AND pid = ?
                      AND hostname = ? AND state = 'active'
                    """,
                    (
                        _iso(_now()), holder.lock_key, holder.run_id,
                        holder.pid, holder.hostname,
                    ),
                )
                if cursor.rowcount == 0:
                    # The lock was reclaimed by another process; never overwrite it.
                    self._lost = True
                    return
        finally:
            conn.close()

    def _stop_heartbeat(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def release(self) -> None:
        """Drop the lock (completed or failed runs)."""
        self._stop_heartbeat()
        holder = self.holder
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        try:
            conn.execute(
                """
                DELETE FROM run_locks
                WHERE lock_key = ? AND run_id = ? AND pid = ? AND hostname = ?
                """,
                (holder.lock_key, holder.run_id, holder.pid, holder.hostname),
            )
        finally:
            conn.close()

    def abandon_for_resume(self) -> None:
        """Keep the lock row, marked interrupted, so ``resume`` inherits it."""
        self._stop_heartbeat()
        holder = self.holder
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        try:
            conn.execute(
                """
                UPDATE run_locks SET state = ?, heartbeat_at = ?
                WHERE lock_key = ? AND run_id = ? AND pid = ? AND hostname = ?
                """,
                (
                    LOCK_STATE_INTERRUPTED, _iso(_now()), holder.lock_key,
                    holder.run_id, holder.pid, holder.hostname,
                ),
            )
        finally:
            conn.close()


def reclaim_audit_entry(acquisition: LockAcquisition, run_id: str) -> dict[str, object]:
    previous = acquisition.reclaimed
    assert previous is not None
    return {
        "event": "lock_reclaimed",
        "run_id": run_id,
        "lock_key": acquisition.holder.lock_key,
        "dataset_fingerprint": acquisition.holder.dataset_fingerprint,
        "target_path": acquisition.holder.target_path,
        "previous_run_id": previous.run_id,
        "previous_pid": previous.pid,
        "previous_hostname": previous.hostname,
        "previous_started_at": previous.started_at,
        "previous_heartbeat_at": previous.heartbeat_at,
        "reclaim_reason": acquisition.reclaim_reason,
        "rows_processed": 0,
    }


def acquire_run_lock(
    checkpoint_db: str | Path,
    audit_path: str | Path,
    *,
    run_id: str,
    target_path: str | Path,
    dataset_fingerprint: str,
    inherit_run_id: str | None = None,
    started_at: str | None = None,
    timeout: float | None = None,
    heartbeat: float | None = None,
    pid: int | None = None,
    hostname: str | None = None,
) -> RunLockHandle:
    """Acquire (or inherit / reclaim) a run lock and start its heartbeat."""
    timeout_value = lock_timeout_seconds(timeout)
    heartbeat_value = lock_heartbeat_seconds(heartbeat, timeout_value)
    store = RunLockStore(checkpoint_db)
    try:
        acquisition = store.acquire(
            run_id=run_id,
            target_path=target_path,
            dataset_fingerprint=dataset_fingerprint,
            inherit_run_id=inherit_run_id,
            started_at=started_at,
            timeout=timeout_value,
            pid=pid,
            hostname=hostname,
        )
    finally:
        store.close()

    handle = RunLockHandle(checkpoint_db, acquisition, heartbeat_value)
    if acquisition.reclaimed is not None:
        try:
            AuditLog(audit_path).append(reclaim_audit_entry(acquisition, run_id))
        except BaseException:
            # Do not keep a lock that could not be recorded in the audit chain.
            handle.release()
            raise
    handle.start()
    return handle
