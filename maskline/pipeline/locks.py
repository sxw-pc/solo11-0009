"""Cross-process advisory locks for runs and recovery.

Liveness is decided by an OS advisory lock, not by stale PID heuristics: the
kernel releases ``flock`` automatically when a process dies, including
``SIGKILL``. Recovery therefore only reclaims a run's resources after it can
prove that no process still owns that run's lock.
"""

from __future__ import annotations

import errno
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:  # Linux / macOS
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows fallback
    _fcntl = None
    try:
        import msvcrt as _msvcrt
    except ImportError:  # pragma: no cover
        _msvcrt = None

from .errors import PipelineError


class ResourceLocked(PipelineError):
    """Another live process already owns the requested resource."""


def _try_lock(fh) -> bool:
    if _fcntl is not None:
        try:
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise
    if _msvcrt is not None:  # pragma: no cover - Windows fallback
        try:
            _msvcrt.locking(fh.fileno(), _msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    return True


def _unlock(fh) -> None:
    if _fcntl is not None:
        try:
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)
        except OSError:
            pass
    elif _msvcrt is not None:  # pragma: no cover - Windows fallback
        try:
            _msvcrt.locking(fh.fileno(), _msvcrt.LK_UNLCK, 1)
        except OSError:
            pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def host_name() -> str:
    try:
        return os.uname().nodename
    except AttributeError:  # pragma: no cover - Windows
        return os.environ.get("COMPUTERNAME", "unknown-host")


@dataclass
class LockOwner:
    run_id: str
    pid: int
    host: str
    acquired_at: str
    purpose: str = "run"


def lock_path(locks_dir: Path, name: str) -> Path:
    return Path(locks_dir) / f"{name}.lock"


def read_lock_owner(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def is_lock_live(path: Path) -> bool:
    """True when a live process still holds the advisory lock at *path*."""
    path = Path(path)
    if not path.exists():
        return False
    try:
        fh = path.open("r+", encoding="utf-8")
    except OSError:
        # Cannot even open it: treat it as not live rather than risk deleting a
        # resource that may belong to another process.
        return False
    try:
        if _try_lock(fh):
            _unlock(fh)
            return False
        return True
    finally:
        fh.close()


class FileLock:
    """Exclusive advisory lock held for the lifetime of the object."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fh = None

    def acquire(self, *, timeout: float = 0.0) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            fh = self.path.open("a+", encoding="utf-8")
            if _try_lock(fh):
                self._fh = fh
                return True
            fh.close()
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def write_owner(self, owner: LockOwner) -> None:
        if self._fh is None:
            return
        self._fh.seek(0)
        self._fh.truncate()
        self._fh.write(json.dumps(owner.__dict__, sort_keys=True) + "\n")
        self._fh.flush()
        try:
            os.fsync(self._fh.fileno())
        except OSError:
            pass

    def release(self, *, remove: bool = True) -> None:
        if self._fh is not None:
            try:
                if remove:
                    # Unlink while still holding the lock; any recovery process
                    # that already opened the old inode still observes the lock.
                    try:
                        self.path.unlink()
                    except OSError:
                        pass
                _unlock(self._fh)
            finally:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None


class RunLock(FileLock):
    """Per-run lock proving that this process is the active owner of a run."""

    def __init__(self, locks_dir: str | Path, run_id: str) -> None:
        self.run_id = run_id
        super().__init__(lock_path(Path(locks_dir), f"run-{run_id}"))

    @classmethod
    def acquire_for(cls, locks_dir: str | Path, run_id: str) -> "RunLock":
        lock = cls(locks_dir, run_id)
        if not lock.acquire():
            raise ResourceLocked(
                f"run {run_id} is already owned by another live maskline process"
            )
        lock.write_owner(
            LockOwner(
                run_id=run_id,
                pid=os.getpid(),
                host=host_name(),
                acquired_at=_now(),
            )
        )
        return lock


class CleanupLock(FileLock):
    """Serialises recovery across processes; never blocks a live run."""

    def __init__(self, locks_dir: str | Path) -> None:
        super().__init__(lock_path(Path(locks_dir), "cleanup"))

    @classmethod
    def acquire_for(cls, locks_dir: str | Path, timeout: float = 10.0) -> "CleanupLock | None":
        lock = cls(locks_dir)
        if not lock.acquire(timeout=timeout):
            return None
        lock.write_owner(
            LockOwner(
                run_id="cleanup",
                pid=os.getpid(),
                host=host_name(),
                acquired_at=_now(),
                purpose="cleanup",
            )
        )
        return lock
