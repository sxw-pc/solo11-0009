"""Cross-process advisory locks for runs and cleanup.

A run holds an exclusive ``flock`` on ``<lock_dir>/<run_id>.lock`` for its
whole lifetime. The kernel releases the lock when the process dies — even on
SIGKILL — so "lock is free" is a reliable signal that the owner vanished
without updating its run record. That is what lets the cleanup module tell
abnormal-exit residue apart from runs that are merely active right now.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

from ..utils import MasklineError


class LockHeldError(MasklineError):
    """Raised when a run lock is already held by another (live) process."""


class RunLock:
    """Exclusive advisory lock bound to one run id (or a fixed sentinel name)."""

    def __init__(self, lock_dir: str | Path, name: str) -> None:
        self.lock_dir = Path(lock_dir)
        self.name = name
        self.path = self.lock_dir / f"{name}.lock"
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self, blocking: bool = False) -> bool:
        """Take the lock; returns False (or raises nothing) when contended."""
        if self._fd is not None:
            return True
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        try:
            fcntl.flock(fd, flags)
        except BlockingIOError:
            os.close(fd)
            return False
        self._fd = fd
        return True

    def acquire_or_raise(self) -> None:
        if not self.acquire():
            raise LockHeldError(
                f"run {self.name!r} is locked by another live process"
            )

    def unlink(self) -> None:
        """Remove the lock file. Only call while holding the lock."""
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> "RunLock":
        self.acquire_or_raise()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()
