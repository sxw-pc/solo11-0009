"""Daemon lifecycle and the control-plane operations used by the CLI.

The daemon is a single local process guarded by a PID lock file.  Control
operations (submit / quota / ps / cancel) only touch the SQLite state database
and the audit chain, so they keep working for inspection even while the daemon
is briefly restarting; the scheduler reconciles any in-flight work on startup.
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import Paths
from .config import GovernorConfig, Quota, load_config
from .errors import GovernorError, JobControlError
from .resources import default_sampler
from .scheduler import Scheduler
from .state import GovernorStore, JobRecord
from .trail import (
    EVENT_CONFIG_RELOADED,
    EVENT_DAEMON_START,
    EVENT_DAEMON_STOP,
    EVENT_JOB_SUBMIT,
    EVENT_ORPHAN_RECOVERED,
    EVENT_QUOTA_UPDATED,
    GovernorAudit,
)


def new_job_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"job-{stamp}-{secrets.token_hex(3)}"


def _read_pid(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    # /proc is authoritative on Linux and avoids EPERM ambiguity from kill(2).
    proc_entry = Path("/proc") / str(pid)
    if proc_entry.exists():
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return False


class PidLock:
    """Exclusive single-daemon lock backed by an atomic PID file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.acquired = False

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existing = _read_pid(self.path)
        if existing is not None and _pid_alive(existing):
            raise GovernorError(
                f"governor daemon already running (pid {existing})"
            )
        # Stale lock: the previous daemon is gone, so reclaim the file.
        if existing is not None:
            self.path.unlink()
        fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
        self.acquired = True

    def release(self) -> None:
        if not self.acquired:
            return
        try:
            if _read_pid(self.path) == os.getpid():
                self.path.unlink()
        except OSError:
            pass
        self.acquired = False

    def __enter__(self) -> "PidLock":
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


@dataclass
class SubmitResult:
    job_id: str
    state: str
    quota: Quota
    quota_source: str


class Governor:
    """High-level facade combining config, state, audit, and scheduler."""

    def __init__(
        self,
        paths: Paths,
        config: GovernorConfig,
        *,
        sampler: Any = None,
        scheduler_clock: Any = None,
        scheduler_sleeper: Any = None,
    ) -> None:
        self.paths = paths
        self.config = config
        self.sampler = sampler or default_sampler()
        self.store = GovernorStore(paths.governor_db)
        self.audit = GovernorAudit(paths.audit_path)
        kwargs: dict[str, Any] = {}
        if scheduler_clock is not None:
            kwargs["clock"] = scheduler_clock
        if scheduler_sleeper is not None:
            kwargs["sleeper"] = scheduler_sleeper
        self.scheduler = Scheduler(
            self.store, config, paths, self.audit, self.sampler, **kwargs,
        )

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> "Governor":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --------------------------------------------------------------- submit
    def submit(
        self,
        argv: list[str],
        *,
        name: str | None = None,
        cwd: str | None = None,
        overrides: dict[str, Any] | None = None,
        extra_env: dict[str, str] | None = None,
        resume_mode: str | None = None,
    ) -> SubmitResult:
        if not argv:
            raise JobControlError("a job requires a non-empty command line")
        job_name = name or _derive_name(argv)
        quota = self.config.effective_quotas(job_name, overrides)
        quota_source = _quota_source(self.config, job_name, overrides)
        resolved_mode = resume_mode or _detect_resume_mode(argv)
        now = time.time()
        job_id = new_job_id()
        record = JobRecord(
            job_id=job_id,
            name=job_name,
            state="queued",
            argv=tuple(argv),
            cwd=cwd or os.getcwd(),
            env_json=json.dumps(extra_env or {}, sort_keys=True),
            cpu_max_percent=quota.cpu_max_percent,
            memory_max_mb=quota.memory_max_mb,
            max_runtime_seconds=quota.max_runtime_seconds,
            quota_source=quota_source,
            run_id=None,
            attempt=0,
            max_resume_attempts=self.config.max_resume_attempts,
            created_at=now,
            updated_at=now,
            run_started_at=None,
            runtime_seconds=0.0,
            cpu_breaches=0,
            memory_breaches=0,
            runtime_breaches=0,
            throttle_events=0,
            pause_events=0,
            resume_events=0,
            last_cpu_percent=0.0,
            last_rss_mb=0.0,
            last_exit_code=None,
            last_error=None,
            not_before=0.0,
            pid=None,
            log_path=None,
            resume_mode=resolved_mode,
        )
        self.store.create_job(record)
        self.audit.record(
            EVENT_JOB_SUBMIT,
            {
                "job_id": job_id,
                "job_name": job_name,
                "argv": list(argv),
                "cwd": record.cwd,
                "quota": quota.as_dict(),
                "quota_source": quota_source,
                "position": len(self.store.list_jobs(include_terminal=False)),
            },
        )
        return SubmitResult(job_id=job_id, state="queued", quota=quota,
                            quota_source=quota_source)

    # ------------------------------------------------------------ inspection
    def list_jobs(self, include_terminal: bool = True) -> list[JobRecord]:
        return self.store.list_jobs(include_terminal=include_terminal)

    def status_snapshot(self) -> dict[str, Any]:
        jobs = self.store.list_jobs()
        active = [job for job in jobs if job.state in
                  ("queued", "running", "throttled", "paused")]
        available_mb, total_mb = self.sampler.system_memory()
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "daemon_pid": _read_pid(self.paths.governor_pid_file),
            "config": self.config.as_dict(),
            "system": {
                "total_memory_mb": round(total_mb, 2),
                "available_memory_mb": round(available_mb, 2),
                "concurrency_in_use": self.store.count_running_slots(),
                "max_concurrency": self.config.max_concurrency,
            },
            "jobs": [_job_view(job) for job in jobs],
            "active_count": len(active),
            "queued_count": sum(1 for job in active if job.state == "queued"),
        }

    # --------------------------------------------------------------- control
    def cancel(self, job_id: str) -> JobRecord:
        return self.scheduler.cancel_job(job_id)

    def update_quota(
        self,
        job_name_or_id: str,
        changes: dict[str, Any],
        *,
        scope: str = "job",
    ) -> JobRecord | None:
        """Apply a quota change at runtime and append it to the audit trail."""
        if scope == "global":
            current = {
                "cpu_max_percent": self.config.defaults.cpu_max_percent,
                "memory_max_mb": self.config.defaults.memory_max_mb,
                "max_runtime_seconds": self.config.defaults.max_runtime_seconds,
            }
            current.update(changes)
            self.store.set_setting("default_quota", current)
            self.audit.record(
                EVENT_QUOTA_UPDATED,
                {"scope": "global", "changes": changes, "effective": current},
            )
            return None
        job = self._resolve_job(job_name_or_id)
        new_quota = job.quota()
        new_quota.update(changes)
        updated = self.store.update_job(
            job.job_id,
            cpu_max_percent=new_quota["cpu_max_percent"],
            memory_max_mb=int(new_quota["memory_max_mb"]),
            max_runtime_seconds=int(new_quota["max_runtime_seconds"]),
            quota_source="runtime_override",
        )
        self.audit.record(
            EVENT_QUOTA_UPDATED,
            {
                "scope": "job",
                "job_id": job.job_id,
                "job_name": job.name,
                "changes": changes,
                "effective": updated.quota(),
            },
        )
        return updated

    def effective_config(self) -> GovernorConfig:
        """Overlay settings-table runtime overrides on the file config."""
        override = self.store.get_setting("default_quota")
        if not override:
            return self.config
        return GovernorConfig(
            defaults=Quota(**{
                "cpu_max_percent": override.get(
                    "cpu_max_percent", self.config.defaults.cpu_max_percent),
                "memory_max_mb": int(override.get(
                    "memory_max_mb", self.config.defaults.memory_max_mb)),
                "max_runtime_seconds": int(override.get(
                    "max_runtime_seconds", self.config.defaults.max_runtime_seconds)),
            }),
            max_concurrency=self.config.max_concurrency,
            sample_interval_seconds=self.config.sample_interval_seconds,
            throttle_stop_seconds=self.config.throttle_stop_seconds,
            throttle_breach_limit=self.config.throttle_breach_limit,
            resume_cooldown_seconds=self.config.resume_cooldown_seconds,
            max_resume_attempts=self.config.max_resume_attempts,
            memory_recover_ratio=self.config.memory_recover_ratio,
            jobs=dict(self.config.jobs),
            source_path=self.config.source_path,
        )

    def reload_config(self, path: str | Path | None = None) -> GovernorConfig:
        config = load_config(path or self.config.source_path)
        self.config = config
        self.scheduler.config = config
        self.audit.record(
            EVENT_CONFIG_RELOADED,
            {"source": str(config.source_path), "config": config.as_dict()},
        )
        return config

    # ---------------------------------------------------------------- daemon
    def serve_forever(self) -> None:
        paths = self.paths
        paths.ensure_runtime_dirs()
        lock = PidLock(paths.governor_pid_file)
        lock.acquire()
        self._install_signal_handlers()
        try:
            orphans = self.store.reset_orphans_on_start()
            self.audit.record(
                EVENT_DAEMON_START,
                {
                    "pid": os.getpid(),
                    "config": self.config.as_dict(),
                    "orphans_recovered": orphans,
                },
            )
            for job_id in orphans:
                job = self.store.get_job(job_id)
                if job is not None:
                    self.audit.job_event(EVENT_ORPHAN_RECOVERED, job)
            self.scheduler.run_forever()
        finally:
            self.audit.record(
                EVENT_DAEMON_STOP,
                {"pid": os.getpid(), "reason": "signal or shutdown"},
            )
            lock.release()

    def _install_signal_handlers(self) -> None:
        def _handler(signum: int, _frame: object) -> None:
            self.scheduler.stop()
        for signame in ("SIGINT", "SIGTERM"):
            target = getattr(signal, signame, None)
            if target is not None:
                try:
                    signal.signal(target, _handler)
                except (ValueError, OSError):  # pragma: no cover - non-main thread
                    pass

    def _resolve_job(self, job_name_or_id: str) -> JobRecord:
        record = self.store.get_job(job_name_or_id)
        if record is not None:
            return record
        matches = [
            job for job in self.store.list_jobs() if job.name == job_name_or_id
        ]
        if not matches:
            raise JobControlError(f"no job named or identified by {job_name_or_id!r}")
        if len(matches) > 1:
            raise JobControlError(
                f"job name {job_name_or_id!r} is ambiguous; use a job id"
            )
        return matches[0]


def _derive_name(argv: list[str]) -> str:
    for index, token in enumerate(argv):
        if token == "--dataset" and index + 1 < len(argv):
            return Path(argv[index + 1]).stem
        if token.startswith("--dataset="):
            return Path(token.split("=", 1)[1]).stem
    return Path(argv[0]).stem if argv else "job"


def _detect_resume_mode(argv: list[str]) -> str:
    """Identify native maskline runs so resume can target their run id.

    Every accepted native spelling -- the console script, ``python -m
    maskline``, and an absolute interpreter path followed by ``-m maskline``
    -- is recognised; anything else (including arbitrary existing shell
    commands) is treated as a generic, verbatim-replay command.
    """
    normalized = list(argv)
    if normalized and Path(normalized[0]).name in {"python", "python3"}:
        if len(normalized) >= 2 and normalized[1] == "-m":
            normalized = ["maskline", *normalized[3:]]
    if not normalized:
        return "generic"
    if normalized[0] == "maskline":
        if len(normalized) >= 2 and normalized[1] in {"run", "resume"}:
            return "maskline"
        return "generic"
    # python /path/to/maskline/__main__.py run ...
    if normalized and normalized[0].endswith("__main__.py"):
        if len(normalized) >= 2 and normalized[1] in {"run", "resume"}:
            return "maskline"
    return "generic"


def _quota_source(
    config: GovernorConfig, job_name: str, overrides: dict[str, Any] | None
) -> str:
    if overrides:
        return "submit_override"
    if job_name in config.jobs:
        return "job_pin"
    return "global_default"


def _job_view(job: JobRecord) -> dict[str, Any]:
    view = {
        "job_id": job.job_id,
        "name": job.name,
        "state": job.state,
        "pid": job.pid,
        "attempt": job.attempt,
        "run_id": job.run_id,
        "argv": list(job.argv),
        "quota": job.quota(),
        "quota_source": job.quota_source,
        "runtime_seconds": round(job.runtime_seconds, 2),
        "last_cpu_percent": round(job.last_cpu_percent, 2),
        "last_rss_mb": round(job.last_rss_mb, 2),
        "cpu_breaches": job.cpu_breaches,
        "memory_breaches": job.memory_breaches,
        "runtime_breaches": job.runtime_breaches,
        "throttle_events": job.throttle_events,
        "pause_events": job.pause_events,
        "resume_events": job.resume_events,
        "not_before": job.not_before,
        "last_exit_code": job.last_exit_code,
        "last_error": job.last_error,
        "log_path": job.log_path,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }
    return view


def is_daemon_running(paths: Paths) -> bool:
    pid = _read_pid(paths.governor_pid_file)
    return pid is not None and _pid_alive(pid)


def read_status(paths: Paths, config: GovernorConfig) -> dict[str, Any]:
    """Read-only snapshot without starting a scheduler (used by ``ps``)."""
    with Governor(paths, config) as governor:
        return governor.status_snapshot()
