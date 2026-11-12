"""Subprocess worker lifecycle: spawn, graceful pause, and guaranteed cleanup.

Each masking task runs as its own process *group*.  The group boundary matters
because a task may spawn helper processes (for example a ``python`` launcher
plus SQLite helpers); on pause or abnormal termination the whole group is
signalled so no orphan keeps holding CPU or memory after the job is released.

Pause is always graceful: SIGTERM is delivered at a batch boundary-safe point
because the runner commits every batch and stores its rowid checkpoint before
the next batch starts.  A hard SIGKILL only follows if the process ignores the
graceful request, and even then resume relies on the last committed checkpoint,
which is exactly the crash-safety guarantee the pipeline already provides.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..pipeline.progress import PROGRESS_ENV, latest_run_id
from .errors import GovernorError

# CLI flags that are only valid on the initial ``run`` invocation and must be
# stripped when the governor reconstructs a ``resume`` invocation.
_RUN_ONLY_FLAGS = {"--dataset", "--policy", "--output", "--dry-run"}
_GRACE_PERIOD_SECONDS = 15.0


@dataclass
class WorkerHandle:
    pid: int
    process: subprocess.Popen[Any]
    log_path: Path
    event_path: Path
    started_at: float
    argv: tuple[str, ...]

    @property
    def run_id(self) -> str | None:
        return latest_run_id(self.event_path)


def _resume_argv(run_id: str, original_argv: tuple[str, ...]) -> tuple[str, ...]:
    """Rebuild an in-process ``maskline resume`` command from a run command.

    The resume invocation always runs through the same interpreter as the
    governor so it works regardless of how the original ``maskline`` launcher
    was spelled (console script, ``python -m maskline``, or an absolute path).
    """
    argv = list(original_argv)
    head = [sys.executable, "-m", "maskline"]
    workspace: str | None = None
    batch_size = "1000"
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--workspace" and index + 1 < len(argv):
            workspace = argv[index + 1]
            index += 2
            continue
        if token.startswith("--workspace="):
            workspace = token.split("=", 1)[1]
        if token == "--batch-size" and index + 1 < len(argv):
            batch_size = argv[index + 1]
            index += 2
            continue
        if token.startswith("--batch-size="):
            batch_size = token.split("=", 1)[1]
        index += 1
    rebuilt = [*head, "resume", "--run-id", run_id, "--batch-size", batch_size]
    if workspace is not None:
        rebuilt.extend(["--workspace", workspace])
    return tuple(rebuilt)


def _native_maskline_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Rewrite a native maskline launcher to use the current interpreter.

    A bare ``maskline`` console script may not be on PATH inside the
    daemon's (non-activated) environment, so always run through
    ``sys.executable -m maskline``.  Generic commands are returned untouched.
    """
    tokens = list(argv)
    if not tokens:
        return argv
    head = tokens[0]
    head_name = Path(head).name
    if head == "maskline":
        return (sys.executable, "-m", "maskline", *tokens[1:])
    if head_name in {"python", "python3"} and len(tokens) >= 2 and tokens[1] == "-m":
        # `python -m maskline ...` -> pin the concrete interpreter.
        return (sys.executable, "-m", *tokens[2:])
    if head_name == "python" or head_name == "python3":
        # `python /path/to/maskline/__main__.py ...` style invocation.
        return (sys.executable, *tokens[1:])
    return argv


def spawn_worker(
    job: Any,
    *,
    event_dir: Path,
    log_dir: Path,
) -> WorkerHandle:
    """Start one execution slice for a job.

    The first attempt uses the submitted command (normalized onto the current
    interpreter for native maskline tasks); later attempts resume the captured
    run_id so processing continues from its checkpoint.
    """
    event_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    event_path = event_dir / f"{job.job_id}.attempt-{job.attempt}.jsonl"
    log_path = log_dir / f"{job.job_id}.attempt-{job.attempt}.log"

    if job.attempt > 0 and job.run_id and getattr(job, "resume_mode", "maskline") == "maskline":
        argv = _resume_argv(job.run_id, job.argv)
    elif getattr(job, "resume_mode", "maskline") == "maskline":
        argv = _native_maskline_argv(tuple(job.argv))
    else:
        # Generic commands are replayed verbatim; the command itself is
        # expected to be idempotent or to resolve its own checkpoint state.
        argv = tuple(job.argv)

    import json
    env = dict(os.environ)
    saved_env = json.loads(job.env_json)
    env.update(saved_env)
    env[PROGRESS_ENV] = str(event_path)
    # Tell the (possibly generic) worker which execution slice it is, so
    # checkpoint-aware commands can resume instead of redoing finished work.
    env["MASKLINE_GOVERNOR_ATTEMPT"] = str(job.attempt)
    if job.attempt > 0:
        env["MASKLINE_GOVERNOR_RESUMED"] = "1"
    # Each worker gets an unbuffered stdout/stderr so logs stay useful when a
    # process is terminated mid-slice.
    env.setdefault("PYTHONUNBUFFERED", "1")

    log_handle = log_path.open("ab")
    try:
        process = subprocess.Popen(
            argv,
            cwd=job.cwd,
            env=env,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # own process group / session leader
            close_fds=True,
        )
    finally:
        # The child inherited the descriptor; the parent does not need it.
        log_handle.close()

    return WorkerHandle(
        pid=process.pid,
        process=process,
        log_path=log_path,
        event_path=event_path,
        started_at=time.monotonic(),
        argv=argv,
    )


def request_pause(handle: WorkerHandle, grace: float = _GRACE_PERIOD_SECONDS) -> bool:
    """Gracefully stop a worker at its next committed batch boundary.

    Returns ``True`` when the process exited within the grace period.  A worker
    that ignores SIGTERM is killed together with its whole process group so the
    quota slot is always reclaimed; the last checkpoint still guarantees a
    consistent resume.
    """
    process = handle.process
    if process.poll() is not None:
        return True
    try:
        group = os.getpgid(process.pid)
        os.killpg(group, signal.SIGTERM)
    except ProcessLookupError:
        return True
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return True
        time.sleep(0.1)
    force_kill(handle)
    return False


def force_kill(handle: WorkerHandle) -> None:
    """Release every resource the worker (and its children) may still hold."""
    process = handle.process
    if process.poll() is not None:
        return
    try:
        group = os.getpgid(process.pid)
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError as exc:  # pragma: no cover - environment dependent
        raise GovernorError(f"cannot kill worker {process.pid}: {exc}") from exc
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        process.kill()
        process.wait()


def throttle_pause(handle: WorkerHandle, duration: float) -> None:
    """Suspend the whole process group briefly to shave CPU duty cycle."""
    if handle.process.poll() is not None:
        return
    try:
        group = os.getpgid(handle.process.pid)
        os.killpg(group, signal.SIGSTOP)
    except ProcessLookupError:
        return
    end = time.monotonic() + max(0.0, duration)
    while time.monotonic() < end and handle.process.poll() is None:
        time.sleep(min(0.1, end - time.monotonic()))
    try:
        os.killpg(group, signal.SIGCONT)
    except ProcessLookupError:
        pass
