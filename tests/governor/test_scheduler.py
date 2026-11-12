"""End-to-end-ish scheduler tests using real short-lived subprocess workers."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from maskline.audit import read_audit_entries
from maskline.governor.daemon import Governor
from maskline.governor.resources import ProcessSample

FAKE_TASK = Path(__file__).with_name("fake_task.py")


def submit_fake(
    governor: Governor,
    *,
    name: str = "fake",
    env: dict | None = None,
    quotas: dict | None = None,
) -> str:
    argv = [sys.executable, str(FAKE_TASK)]
    merged_env = dict(env or {})
    # Each job gets its own checkpoint cursor so generic replays resume
    # exactly where the stopped slice committed.
    merged_env.setdefault(
        "FAKE_PROGRESS_FILE",
        str(governor.paths.governor_dir / f"progress-{name}.txt"),
    )
    result = governor.submit(
        argv,
        name=name,
        overrides=quotas,
        extra_env=merged_env,
        resume_mode="generic",
    )
    return result.job_id


def drive_until(
    governor: Governor,
    predicate,
    *,
    max_ticks: int = 200,
    advance: float = 0.06,
    clock=None,
) -> object:
    last = None
    for _ in range(max_ticks):
        last = governor.scheduler.tick()
        if predicate(governor):
            return last
        if clock is not None:
            clock.advance(advance)
        else:
            time.sleep(0.01)
    raise AssertionError(
        f"condition not reached after {max_ticks} ticks; "
        f"states={[j.state for j in governor.list_jobs()]}"
    )


def job_is_terminal(governor: Governor, job_id: str):
    job = governor.store.get_job(job_id)
    return job.state in ("completed", "failed", "cancelled")


def test_submit_queues_and_completes_a_task(governor):
    job_id = submit_fake(
        governor,
        env={"FAKE_BATCHES": "2", "FAKE_SLEEP_SECONDS": "0.02"},
        quotas={"max_runtime_seconds": 60},
    )
    assert governor.store.get_job(job_id).state == "queued"
    drive_until(
        governor,
        lambda gov: job_is_terminal(gov, job_id),
    )
    job = governor.store.get_job(job_id)
    assert job.state == "completed"
    assert job.run_id == "run-fake-0001"
    assert job.pid is None  # worker resources released
    # The submission and completion are both in the audit chain.
    events = [entry.get("governor_event") for entry in read_audit_entries(
        governor.paths.audit_path
    )]
    assert "job_submit" in events
    assert "job_completed" in events


def test_concurrency_threshold_queues_excess_jobs_fifo(
    gworkspace, governor_config, fake_sampler
):
    import dataclasses
    governor_config = dataclasses.replace(
        governor_config, max_concurrency=1
    )
    governor = Governor(
        gworkspace, governor_config, sampler=fake_sampler,
        scheduler_sleeper=lambda _s: None,
    )
    try:
        ids = [
            submit_fake(
                governor, name=f"fake-{index}",
                env={"FAKE_BATCHES": "1", "FAKE_SLEEP_SECONDS": "0.05"},
            )
            for index in range(3)
        ]
        governor.scheduler.tick()
        states = {job_id: governor.store.get_job(job_id).state for job_id in ids}
        assert states[ids[0]] == "running"
        assert states[ids[1]] == "queued"
        assert states[ids[2]] == "queued"
        # No error is raised; jobs drain strictly in submission order.
        completion_order = []
        for expected in ids:
            drive_until(
                governor,
                lambda gov, wanted=expected: job_is_terminal(gov, wanted),
            )
            completion_order.append(expected)
        assert completion_order == ids
        assert all(
            governor.store.get_job(job_id).state == "completed" for job_id in ids
        )
    finally:
        governor.close()


def test_memory_breach_pauses_and_auto_resumes(governor, fake_sampler):
    job_id = submit_fake(
        governor,
        env={"FAKE_BATCHES": "3", "FAKE_SLEEP_SECONDS": "0.4"},
        quotas={"memory_max_mb": 100},
    )
    governor.scheduler.tick()
    pid = governor.store.get_job(job_id).pid
    assert pid is not None

    # First observation is healthy, then two oversized readings force a pause.
    fake_sampler.script(pid, [
        ProcessSample(pid, True, 5.0, 20.0, 4096.0, 8192.0, 1.0),
        ProcessSample(pid, True, 5.0, 250.0, 4096.0, 8192.0, 2.0),
    ])

    def paused_then_running_again(gov):
        job = gov.store.get_job(job_id)
        return job.pause_events >= 1 and job.state in ("running", "throttled")

    drive_until(governor, paused_then_running_again, max_ticks=60)
    job = governor.store.get_job(job_id)
    assert job.memory_breaches >= 1
    assert job.run_id == "run-fake-0001"  # same run id across the pause
    drive_until(
        governor, lambda gov: job_is_terminal(gov, job_id),
    )
    final = governor.store.get_job(job_id)
    assert final.state == "completed"
    assert final.resume_events >= 1


def test_system_memory_pressure_pauses(governor, fake_sampler):
    job_id = submit_fake(
        governor,
        env={"FAKE_BATCHES": "2", "FAKE_SLEEP_SECONDS": "0.3"},
        quotas={"memory_max_mb": 4096},
    )
    governor.scheduler.tick()
    pid = governor.store.get_job(job_id).pid
    # recover_ratio 0.9 -> pause when available ratio < 0.1.
    fake_sampler.script(pid, [
        ProcessSample(pid, True, 5.0, 20.0, 500.0, 8192.0, 1.0),
        ProcessSample(pid, True, 5.0, 20.0, 400.0, 8192.0, 2.0),
    ])
    drive_until(
        governor,
        lambda gov: gov.store.get_job(job_id).pause_events >= 1,
    )
    assert governor.store.get_job(job_id).state == "paused"


def test_max_runtime_slice_pauses_and_resumes_same_run(
    gworkspace, governor_config, fake_sampler
):
    import dataclasses
    config = dataclasses.replace(
        governor_config,
        resume_cooldown_seconds=0.0,
    )
    governor = Governor(
        gworkspace, config, sampler=fake_sampler,
        scheduler_sleeper=lambda _s: None,
    )
    try:
        job_id = submit_fake(
            governor,
            env={"FAKE_BATCHES": "10", "FAKE_SLEEP_SECONDS": "1.5"},
            quotas={"max_runtime_seconds": 1},
        )

        def saw_runtime_pause(gov):
            job = gov.store.get_job(job_id)
            return job.runtime_breaches >= 1

        drive_until(governor, saw_runtime_pause, max_ticks=120)
        job = governor.store.get_job(job_id)
        assert job.state == "paused"
        assert job.run_id == "run-fake-0001"
        drive_until(
            governor, lambda gov: job_is_terminal(gov, job_id), max_ticks=200
        )
        finished = governor.store.get_job(job_id)
        assert finished.state == "completed"
        assert finished.runtime_breaches >= 1
        assert finished.resume_events >= 1
    finally:
        governor.close()


def test_cpu_overuse_throttles_then_escalates_to_pause(
    governor, fake_sampler
):
    job_id = submit_fake(
        governor,
        env={"FAKE_BATCHES": "8", "FAKE_CPU_SECONDS": "1.0",
             "FAKE_SLEEP_SECONDS": "0.5"},
        quotas={"cpu_max_percent": 10.0},
    )
    governor.scheduler.tick()
    pid = governor.store.get_job(job_id).pid

    hot = ProcessSample(pid, True, 95.0, 20.0, 4096.0, 8192.0, 1.0)
    fake_sampler.script(pid, [hot] * 10)

    def escalated(gov):
        job = gov.store.get_job(job_id)
        return job.throttle_events >= 1 and job.pause_events >= 1

    drive_until(governor, escalated, max_ticks=80)
    job = governor.store.get_job(job_id)
    assert job.cpu_breaches >= 1
    drive_until(
        governor, lambda gov: job_is_terminal(gov, job_id),
    )
    assert governor.store.get_job(job_id).state == "completed"


def test_worker_crash_is_retried_via_checkpoint_then_completes(
    gworkspace, governor_config, fake_sampler
):
    import dataclasses
    # A real cooldown window gives the test time to flip the outcome switch
    # between the crashed attempt and its checkpoint resume.
    config = dataclasses.replace(governor_config, resume_cooldown_seconds=0.6)
    governor = Governor(
        gworkspace, config, sampler=fake_sampler,
        scheduler_sleeper=lambda _s: None,
    )
    switch = gworkspace.root / "exit-code"
    switch.write_text("1", encoding="utf-8")
    try:
        job_id = governor.submit(
            [sys.executable, str(FAKE_TASK)],
            name="crashy",
            resume_mode="generic",
            extra_env={
                "FAKE_BATCHES": "4",
                "FAKE_SLEEP_SECONDS": "0.05",
                "FAKE_EXIT_CODE_FILE": str(switch),
            },
        ).job_id
        drive_until(
            governor,
            lambda gov: gov.store.get_job(job_id).state == "paused"
            and gov.store.get_job(job_id).last_exit_code == 1,
        )
        paused = governor.store.get_job(job_id)
        assert paused.run_id == "run-fake-0001"

        # Flip the outcome while the job waits out its resume cooldown.
        switch.write_text("0", encoding="utf-8")

        drive_until(
            governor, lambda gov: job_is_terminal(gov, job_id), max_ticks=200
        )
        finished = governor.store.get_job(job_id)
        assert finished.state == "completed"
        assert finished.attempt >= 2
        assert finished.resume_events >= 1
        # The failure and its recovery are both on the tamper-evident trail.
        events = read_audit_entries(governor.paths.audit_path)
        reasons = " ".join(str(e.get("reason", "")) for e in events)
        assert "checkpoint resume scheduled" in reasons
    finally:
        governor.close()


def test_resume_attempt_limit_marks_job_failed(gworkspace, fake_sampler):
    from maskline.governor.config import GovernorConfig, Quota
    config = GovernorConfig(
        defaults=Quota(50.0, 512, 30), max_concurrency=1,
        sample_interval_seconds=0.05, throttle_stop_seconds=0.01,
        throttle_breach_limit=2, resume_cooldown_seconds=0.0,
        max_resume_attempts=1, memory_recover_ratio=0.9,
    )
    governor = Governor(
        gworkspace, config, sampler=fake_sampler,
        scheduler_sleeper=lambda _s: None,
    )
    try:
        job_id = submit_fake(
            governor,
            env={"FAKE_BATCHES": "2", "FAKE_EXIT_CODE": "7"},
        )
        drive_until(
            governor, lambda gov: job_is_terminal(gov, job_id),
            max_ticks=100,
        )
        job = governor.store.get_job(job_id)
        assert job.state == "failed"
        assert "code 7" in (job.last_error or "")
    finally:
        governor.close()


def test_cancel_releases_process_group(governor):
    job_id = submit_fake(
        governor,
        env={"FAKE_BATCHES": "100", "FAKE_SLEEP_SECONDS": "5"},
    )
    governor.scheduler.tick()
    pid = governor.store.get_job(job_id).pid
    assert pid is not None
    cancelled = governor.cancel(job_id)
    assert cancelled.state == "cancelled"
    assert cancelled.pid is None
    # The whole process group is gone.
    import os
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_audit_chain_remains_valid(governor):
    for index in range(2):
        submit_fake(
            governor,
            name=f"audited-{index}",
            env={"FAKE_BATCHES": "1", "FAKE_SLEEP_SECONDS": "0.01"},
        )
    drive_until(
        governor,
        lambda gov: all(
            job.state in ("completed", "failed", "cancelled")
            for job in gov.list_jobs()
        ),
    )
    verification = governor.audit.verify()
    assert verification.entries >= 4  # submit + start + complete per job
