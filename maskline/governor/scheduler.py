"""Core quota enforcement and FIFO scheduling loop.

The scheduler is intentionally written as a plain class with injectable
sampler/clock/sleeper so the whole enforcement state machine can be exercised
deterministically in tests without spawning real processes or sleeping.

Enforcement model
-----------------
* **Queue / concurrency**: jobs start in ``queued`` and are admitted in FIFO
  order only while fewer than ``max_concurrency`` jobs occupy slots.  Overflow
  waits instead of erroring.  A paused job keeps its slot, so admission order
  is always the submission order.
* **CPU**: repeated samples above ``cpu_max_percent`` first trigger duty-cycle
  throttling (SIGSTOP/SIGCONT windows).  Continued breach escalates to a clean
  pause-and-checkpoint; the job resumes once the window cools down.
* **Memory**: RSS above ``memory_max_mb`` (or exhaustion of the available
  system memory) pauses the worker at the next batch boundary and waits until
  the machine has headroom again, then resumes automatically.
* **Runtime**: no single execution slice may run longer than
  ``max_runtime_seconds``.  At the limit the worker is paused with its
  checkpoint persisted and, after the cooldown, resumed with the same run id.
* **Crashes**: an unexpected exit releases the process group immediately and
  resumes from the last committed checkpoint up to ``max_resume_attempts``.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..config import Paths
from .config import GovernorConfig
from .resources import ProcessSample, ResourceSampler
from .state import GovernorStore, JobRecord, SampleRecord
from .trail import (
    EVENT_JOB_CANCELLED,
    EVENT_JOB_COMPLETED,
    EVENT_JOB_FAILED,
    EVENT_JOB_PAUSED,
    EVENT_JOB_RESUMED,
    EVENT_JOB_START,
    EVENT_JOB_THROTTLED,
    GovernorAudit,
)
from .worker import WorkerHandle, force_kill, request_pause, spawn_worker, throttle_pause


@dataclass
class _LiveState:
    """Bookkeeping that only matters while a worker is alive."""

    handle: WorkerHandle
    cpu_breach_streak: int = 0
    last_slice_monotonic: float = 0.0
    last_sample_wall: float = 0.0
    pipeline_started_monotonic: float | None = None
    throttled: bool = False


@dataclass
class TickOutcome:
    """Diagnostic summary returned by each scheduler tick (used in tests)."""

    started: list[str] = field(default_factory=list)
    resumed: list[str] = field(default_factory=list)
    throttled: list[str] = field(default_factory=list)
    paused: list[str] = field(default_factory=list)
    completed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)


class Scheduler:
    def __init__(
        self,
        store: GovernorStore,
        config: GovernorConfig,
        paths: Paths,
        audit: GovernorAudit,
        sampler: ResourceSampler,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.store = store
        self.config = config
        self.paths = paths
        self.audit = audit
        self.sampler = sampler
        self.clock = clock
        self.sleeper = sleeper
        self._workers: dict[str, _LiveState] = {}
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    # ------------------------------------------------------------- lifecycle
    def run_forever(self) -> None:
        """Drive ticks until :meth:`stop` is called (daemon entry point)."""
        while not self._stop.is_set():
            self.tick()
            self._stop.wait(self.config.sample_interval_seconds)

    def tick(self) -> TickOutcome:
        outcome = TickOutcome()
        self._reap_finished(outcome)
        self._resume_paused(outcome)
        self._admit_queued(outcome)
        self._enforce_active(outcome)
        return outcome

    # ------------------------------------------------------------- admission
    def _admit_queued(self, outcome: TickOutcome) -> None:
        while self.store.count_running_slots() < self.config.max_concurrency:
            job = self.store.next_queued()
            if job is None:
                return
            self._start_slice(job, outcome, is_resume=False)

    def _resume_paused(self, outcome: TickOutcome) -> None:
        # A paused job already holds its concurrency slot, so resuming it does
        # not change the slot count and must not be blocked by the admission
        # gate -- otherwise a single paused job at max_concurrency could never
        # restart.  New jobs are admitted separately afterwards in FIFO order.
        for job in self.store.resumable_paused(time.time()):
            if job.attempt >= job.max_resume_attempts:
                self._fail_job(
                    job,
                    outcome,
                    f"resume attempt limit exhausted ({job.max_resume_attempts})",
                )
                continue
            self._start_slice(job, outcome, is_resume=True)

    def _start_slice(self, job: JobRecord, outcome: TickOutcome, *, is_resume: bool) -> None:
        handle = spawn_worker(
            job,
            event_dir=self.paths.governor_event_dir,
            log_dir=self.paths.governor_log_dir,
        )
        attempt = job.attempt + 1 if is_resume else max(1, job.attempt + 1)
        now_mono = self.clock()
        self._workers[job.job_id] = _LiveState(
            handle=handle,
            last_slice_monotonic=now_mono,
            last_sample_wall=time.time(),
        )
        updates = {
            "state": "running",
            "pid": handle.pid,
            "attempt": attempt,
            "run_started_at": time.time(),
            "log_path": str(handle.log_path),
        }
        run_id = handle.run_id
        if run_id:
            updates["run_id"] = run_id
        updated = self.store.update_job(job.job_id, **updates)
        if is_resume:
            self.store.increment(job.job_id, resume_events=1)
            outcome.resumed.append(job.job_id)
            self.audit.job_event(
                EVENT_JOB_RESUMED, updated,
                reason="cooldown elapsed", pid=handle.pid, argv=list(handle.argv),
            )
        else:
            outcome.started.append(job.job_id)
            self.audit.job_event(
                EVENT_JOB_START, updated,
                reason="slot available", pid=handle.pid, argv=list(handle.argv),
            )

    # ---------------------------------------------------------- enforcement
    def _enforce_active(self, outcome: TickOutcome) -> None:
        for job_id in list(self._workers):
            live = self._workers.get(job_id)
            if live is None:
                continue
            job = self.store.get_job(job_id)
            if job is None or job.state not in ("running", "throttled"):
                continue
            sample = self.sampler.sample(live.handle.pid)
            if not sample.alive:
                # Reaped on the next tick; do not act on a stale sample.
                continue
            self._record_sample(job, sample)
            now_wall = time.time()
            elapsed = max(0.0, now_wall - live.last_sample_wall)
            live.last_sample_wall = now_wall
            # The runtime quota governs pipeline execution, not process
            # startup.  Only start the slice clock once the worker has
            # announced its run id (i.e. execute_run created its run record),
            # so warm-up work (interpreter load, scan, detection) cannot burn
            # the quota before a resumable checkpoint exists.
            run_id_now = live.handle.run_id
            if run_id_now is not None and live.pipeline_started_monotonic is None:
                live.pipeline_started_monotonic = self.clock()
            if live.pipeline_started_monotonic is None:
                runtime_slice = 0.0
            else:
                runtime_slice = self.clock() - live.pipeline_started_monotonic
            self.store.update_job(
                job_id,
                last_cpu_percent=sample.cpu_percent,
                last_rss_mb=sample.rss_mb,
                runtime_seconds=job.runtime_seconds + elapsed,
            )
            # Memory takes priority: an oversized worker must stop promptly.
            if self._memory_breached(job, sample):
                self._pause_job(
                    job, live, outcome,
                    reason=(
                        f"rss {sample.rss_mb:.1f}MB exceeds "
                        f"{job.memory_max_mb}MB or system memory exhausted"
                    ),
                    memory=True,
                )
                continue
            if (
                live.pipeline_started_monotonic is not None
                and runtime_slice >= job.max_runtime_seconds
            ):
                self._pause_job(
                    job, live, outcome,
                    reason=(
                        f"slice runtime {runtime_slice:.1f}s reached "
                        f"max_runtime_seconds={job.max_runtime_seconds}"
                    ),
                    runtime=True,
                )
                continue
            self._enforce_cpu(job, live, sample, outcome)

    def _memory_breached(self, job: JobRecord, sample: ProcessSample) -> bool:
        if sample.rss_mb >= job.memory_max_mb:
            return True
        # System-wide guard: pause when the free memory ratio drops below the
        # configured recovery threshold so ordinary desktop work keeps headroom.
        total = sample.system_total_mb
        if total == float("inf") or total <= 0:
            return False
        available_ratio = sample.system_available_mb / total
        return available_ratio < (1.0 - self.config.memory_recover_ratio)

    def _enforce_cpu(
        self,
        job: JobRecord,
        live: _LiveState,
        sample: ProcessSample,
        outcome: TickOutcome,
    ) -> None:
        if sample.cpu_percent <= job.cpu_max_percent:
            live.cpu_breach_streak = 0
            if live.throttled:
                live.throttled = False
                self.store.transition(job.job_id, "running", expected="throttled")
            return
        live.cpu_breach_streak += 1
        self.store.increment(job.job_id, cpu_breaches=1)
        if live.cpu_breach_streak < self.config.throttle_breach_limit:
            return
        # Stage 1: duty-cycle throttle inside the same slice.
        if not live.throttled:
            live.throttled = True
            self.store.transition(job.job_id, "throttled", expected="running")
            self.store.increment(job.job_id, throttle_events=1)
            outcome.throttled.append(job.job_id)
        overshoot = sample.cpu_percent / max(job.cpu_max_percent, 1e-9)
        stop_for = min(
            max(self.config.throttle_stop_seconds * overshoot, 0.05),
            self.config.sample_interval_seconds,
        )
        throttle_pause(live.handle, stop_for)
        self.audit.job_event(
            EVENT_JOB_THROTTLED,
            self.store.require_job(job.job_id),
            cpu_percent=round(sample.cpu_percent, 2),
            cpu_quota=job.cpu_max_percent,
            stop_seconds=round(stop_for, 3),
            streak=live.cpu_breach_streak,
        )
        # Stage 2: sustained breach despite throttling -> checkpoint pause.
        if live.cpu_breach_streak >= self.config.throttle_breach_limit * 2:
            self._pause_job(
                job, live, outcome,
                reason=(
                    f"sustained CPU {sample.cpu_percent:.1f}% above "
                    f"{job.cpu_max_percent}% after throttling"
                ),
            )

    def _pause_job(
        self,
        job: JobRecord,
        live: _LiveState,
        outcome: TickOutcome,
        *,
        reason: str,
        memory: bool = False,
        runtime: bool = False,
    ) -> None:
        graceful = request_pause(live.handle)
        self._workers.pop(job.job_id, None)
        counters = {"pause_events": 1}
        if memory:
            counters["memory_breaches"] = 1
        if runtime:
            counters["runtime_breaches"] = 1
        run_id = live.handle.run_id or job.run_id
        cooldown = self.config.resume_cooldown_seconds
        updated = self.store.update_job(
            job.job_id,
            state="paused",
            pid=None,
            run_id=run_id,
            not_before=time.time() + cooldown,
            last_exit_code=live.handle.process.returncode,
        )
        self.store.increment(job.job_id, **counters)
        outcome.paused.append(job.job_id)
        self.audit.job_event(
            EVENT_JOB_PAUSED,
            self.store.require_job(job.job_id),
            reason=reason,
            graceful=graceful,
            resume_after_seconds=cooldown,
            run_id=run_id,
        )
        del updated

    # ---------------------------------------------------------------- reaping
    def _reap_finished(self, outcome: TickOutcome) -> None:
        for job_id, live in list(self._workers.items()):
            returncode = live.handle.process.poll()
            if returncode is None:
                continue
            job = self.store.get_job(job_id)
            self._workers.pop(job_id, None)
            if job is None:
                continue
            run_id = live.handle.run_id or job.run_id
            if returncode == 0:
                self._complete_job(job, live, run_id, outcome)
            else:
                self._handle_failure(job, live, returncode, run_id, outcome)

    def _complete_job(
        self,
        job: JobRecord,
        live: _LiveState,
        run_id: str | None,
        outcome: TickOutcome,
    ) -> None:
        updated = self.store.update_job(
            job.job_id, state="completed", pid=None, run_id=run_id,
            last_exit_code=0, last_error=None,
        )
        outcome.completed.append(job.job_id)
        self.audit.job_event(
            EVENT_JOB_COMPLETED, updated,
            run_id=run_id, pid=live.handle.pid,
            log_path=str(live.handle.log_path),
        )

    def _handle_failure(
        self,
        job: JobRecord,
        live: _LiveState,
        returncode: int,
        run_id: str | None,
        outcome: TickOutcome,
    ) -> None:
        # Make sure nothing from the dead group survives.
        force_kill(live.handle)
        next_attempt = job.attempt + 1
        error_tail = _tail_of(live.handle.log_path)
        if run_id and next_attempt <= job.max_resume_attempts:
            updated = self.store.update_job(
                job.job_id,
                state="paused",
                pid=None,
                run_id=run_id,
                attempt=job.attempt,
                last_exit_code=returncode,
                last_error=error_tail,
                not_before=time.time() + self.config.resume_cooldown_seconds,
            )
            outcome.paused.append(job.job_id)
            self.audit.job_event(
                EVENT_JOB_PAUSED,
                updated,
                reason=f"worker exited with code {returncode}; checkpoint resume scheduled",
                graceful=False,
                resume_after_seconds=self.config.resume_cooldown_seconds,
                run_id=run_id,
                log_tail=error_tail,
            )
            return
        self._fail_job(
            job, outcome,
            f"worker exited with code {returncode} and resume is not possible",
            log_tail=error_tail, run_id=run_id,
        )

    def _fail_job(
        self,
        job: JobRecord,
        outcome: TickOutcome,
        message: str,
        *,
        log_tail: str | None = None,
        run_id: str | None = None,
    ) -> None:
        live = self._workers.pop(job.job_id, None)
        if live is not None:
            force_kill(live.handle)
        updated = self.store.update_job(
            job.job_id, state="failed", pid=None, run_id=run_id or job.run_id,
            last_error=message,
        )
        outcome.failed.append(job.job_id)
        self.audit.job_event(
            EVENT_JOB_FAILED, updated, reason=message,
            log_tail=log_tail, resources_released=True,
        )

    # ----------------------------------------------------------------- cancel
    def cancel_job(self, job_id: str) -> JobRecord:
        self.store.require_job(job_id)  # raises if the job id is unknown
        live = self._workers.get(job_id)
        if live is not None:
            request_pause(live.handle)
            force_kill(live.handle)
            self._workers.pop(job_id, None)
        updated = self.store.update_job(
            job_id, state="cancelled", pid=None,
            not_before=float("inf"),
        )
        self.audit.job_event(
            EVENT_JOB_CANCELLED, updated,
            reason="operator cancel", resources_released=True,
        )
        return updated

    # ----------------------------------------------------------------- helpers
    def _record_sample(self, job: JobRecord, sample: ProcessSample) -> None:
        self.store.add_sample(
            SampleRecord(
                job_id=job.job_id,
                sampled_at=time.time(),
                cpu_percent=sample.cpu_percent,
                rss_mb=sample.rss_mb,
                system_available_mb=sample.system_available_mb,
            )
        )

    def active_workers(self) -> dict[str, _LiveState]:
        return dict(self._workers)


def _tail_of(path: Path, max_bytes: int = 2000) -> str:
    try:
        data = path.read_bytes()[-max_bytes:]
        return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""
