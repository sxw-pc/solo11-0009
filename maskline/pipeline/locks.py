"""Cross-process mutual exclusion for pipeline runs."""

from __future__ import annotations

from pathlib import Path

from ..utils import FileLock
from .errors import PipelineError


class RunLock:
    """Per-workspace lock guaranteeing a single active run at a time.

    The lock lives on a small sidecar file next to the checkpoint database
    and is held for the whole run. A second process that tries to run or
    resume in the same workspace fails fast instead of writing to the same
    target database. The lock is released automatically when the holder
    exits — even on SIGKILL — so crashed runs never leave stale locks.
    """

    def __init__(self, checkpoint_db: str | Path) -> None:
        self.path = Path(str(checkpoint_db) + ".lock")
        self._lock = FileLock(self.path, blocking=False)

    def acquire(self) -> None:
        try:
            self._lock.acquire()
        except BlockingIOError as exc:
            raise PipelineError(
                "another maskline run is active in this workspace; "
                "wait for it to finish before starting or resuming a run"
            ) from exc

    def release(self) -> None:
        self._lock.release()

    def __enter__(self) -> "RunLock":
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()
