import time

import pytest

from maskline.governor.errors import JobControlError
from maskline.governor.state import (
    GovernorStore,
    JobRecord,
    SampleRecord,
    TERMINAL_STATES,
)


def make_job(job_id: str, state: str = "queued", created_at: float | None = None) -> JobRecord:
    now = created_at if created_at is not None else time.time()
    return JobRecord(
        job_id=job_id, name=f"name-{job_id}", state=state,
        argv=("maskline", "run", "--dataset", "x.sqlite"),
        cwd="/tmp", env_json="{}",
        cpu_max_percent=50.0, memory_max_mb=256, max_runtime_seconds=60,
        quota_source="global_default", run_id=None, attempt=0,
        max_resume_attempts=5, created_at=now, updated_at=now,
        run_started_at=None, runtime_seconds=0.0,
        cpu_breaches=0, memory_breaches=0, runtime_breaches=0,
        throttle_events=0, pause_events=0, resume_events=0,
        last_cpu_percent=0.0, last_rss_mb=0.0, last_exit_code=None,
        last_error=None, not_before=0.0, pid=None, log_path=None,
    )


def test_fifo_queue_ordering(store: GovernorStore):
    store.create_job(make_job("j1", created_at=1.0))
    store.create_job(make_job("j2", created_at=2.0))
    store.create_job(make_job("j3", created_at=3.0))
    assert store.next_queued().job_id == "j1"
    store.transition("j1", "running")
    assert store.next_queued().job_id == "j2"


def test_overflow_waits_in_queue_instead_of_erroring(store: GovernorStore):
    for index in range(5):
        store.create_job(make_job(f"j{index}", created_at=float(index)))
    store.transition("j0", "running")
    store.update_job("j1", state="paused", pid=None)
    assert store.count_running_slots() == 2  # paused jobs still hold a slot
    queued = store.list_jobs(include_terminal=False)
    assert [job.job_id for job in queued if job.state == "queued"] == [
        "j2", "j3", "j4"
    ]


def test_illegal_transitions_are_rejected(store: GovernorStore):
    store.create_job(make_job("j1"))
    with pytest.raises(JobControlError, match="illegal transition"):
        store.transition("j1", "completed")  # queued cannot jump to completed
    store.transition("j1", "running")
    store.transition("j1", "paused")
    store.transition("j1", "running")
    store.transition("j1", "completed")
    with pytest.raises(JobControlError, match="illegal transition"):
        store.transition("j1", "running")


def test_expected_state_guard(store: GovernorStore):
    store.create_job(make_job("j1"))
    with pytest.raises(JobControlError, match="expected running"):
        store.transition("j1", "cancelled", expected="running")


def test_resumable_paused_respects_not_before(store: GovernorStore):
    job = make_job("j1", state="paused", created_at=1.0)
    store.create_job(job)
    store.update_job("j1", not_before=100.0)
    assert store.resumable_paused(now=50.0) == []
    ready = store.resumable_paused(now=100.0)
    assert [item.job_id for item in ready] == ["j1"]


def test_counters_and_samples(store: GovernorStore):
    store.create_job(make_job("j1"))
    store.increment("j1", cpu_breaches=2, throttle_events=1)
    job = store.get_job("j1")
    assert job.cpu_breaches == 2
    assert job.throttle_events == 1
    for index in range(5):
        store.add_sample(
            SampleRecord("j1", float(index), cpu_percent=10.0 + index,
                         rss_mb=5.0, system_available_mb=100.0)
        )
    latest = store.latest_sample("j1")
    assert latest.cpu_percent == 14.0
    assert store.get_setting("missing", "default") == "default"
    store.set_setting("default_quota", {"memory_max_mb": 999})
    assert store.get_setting("default_quota")["memory_max_mb"] == 999


def test_orphan_recovery_marks_live_jobs_paused(store: GovernorStore):
    first = make_job("j1", state="running")
    second = make_job("j2", state="throttled")
    queued = make_job("j3", state="queued")
    store.create_job(first)
    store.create_job(second)
    store.create_job(queued)
    orphan_ids = store.reset_orphans_on_start()
    assert set(orphan_ids) == {"j1", "j2"}
    assert store.get_job("j1").state == "paused"
    assert store.get_job("j2").state == "paused"
    assert store.get_job("j3").state == "queued"


def test_unknown_job_raises(store: GovernorStore):
    with pytest.raises(JobControlError, match="unknown job"):
        store.require_job("nope")


def test_state_reopens_from_disk(gworkspace):
    path = gworkspace.governor_db
    store = GovernorStore(path)
    store.create_job(make_job("persisted"))
    store.set_setting("k", {"v": 1})
    store.close()
    reopened = GovernorStore(path)
    try:
        assert reopened.require_job("persisted").state == "queued"
        assert reopened.get_setting("k") == {"v": 1}
    finally:
        reopened.close()


def test_terminal_states_excluded_when_requested(store: GovernorStore):
    store.create_job(make_job("active"))
    done = make_job("done", state="completed")
    store.create_job(done)
    active = store.list_jobs(include_terminal=False)
    assert {job.job_id for job in active} == {"active"}
    assert TERMINAL_STATES == ("completed", "failed", "cancelled")
