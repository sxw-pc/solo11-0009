import json

import pytest

from maskline.audit import read_audit_entries
from maskline.governor.cli import main as governor_cli
from maskline.governor.daemon import PidLock, is_daemon_running
from maskline.governor.errors import GovernorError, JobControlError


def test_pid_lock_rejects_second_daemon(gworkspace):
    lock = PidLock(gworkspace.governor_pid_file)
    lock.acquire()
    try:
        with pytest.raises(GovernorError, match="already running"):
            PidLock(gworkspace.governor_pid_file).acquire()
        assert is_daemon_running(gworkspace)
    finally:
        lock.release()
    assert not is_daemon_running(gworkspace)


def test_stale_pid_lock_is_reclaimed(gworkspace):
    gworkspace.governor_pid_file.write_text("999999", encoding="utf-8")
    lock = PidLock(gworkspace.governor_pid_file)
    lock.acquire()
    lock.release()
    assert not gworkspace.governor_pid_file.exists()


def test_submit_records_quota_source_and_audits(governor):
    result = governor.submit(
        ["maskline", "run", "--dataset", "customers.sqlite", "--policy", "p.yaml"],
        name="heavy",
        overrides={"memory_max_mb": 2048},
    )
    assert result.quota_source == "submit_override"
    assert result.quota.memory_max_mb == 2048
    events = read_audit_entries(governor.paths.audit_path)
    submit_events = [e for e in events if e.get("governor_event") == "job_submit"]
    assert len(submit_events) == 1
    assert submit_events[0]["quota"]["memory_max_mb"] == 2048


def test_runtime_job_quota_update_is_audited(governor):
    governor.submit(["maskline", "run", "--dataset", "a.sqlite"], name="a")
    updated = governor.update_quota("a", {"cpu_max_percent": 12.5})
    assert updated.cpu_max_percent == 12.5
    assert updated.quota_source == "runtime_override"
    events = read_audit_entries(governor.paths.audit_path)
    quota_events = [e for e in events if e.get("governor_event") == "quota_updated"]
    assert quota_events and quota_events[-1]["changes"] == {"cpu_max_percent": 12.5}


def test_global_quota_update_persists_and_reloads(governor):
    governor.update_quota("<global>", {"memory_max_mb": 888}, scope="global")
    reloaded = governor.effective_config()
    assert reloaded.defaults.memory_max_mb == 888
    # Unchanged fields keep their previous values.
    assert reloaded.defaults.cpu_max_percent == governor.config.defaults.cpu_max_percent
    events = read_audit_entries(governor.paths.audit_path)
    assert any(e.get("governor_event") == "quota_updated" and e["scope"] == "global"
               for e in events)


def test_status_snapshot_shape(governor):
    governor.submit(["maskline", "run", "--dataset", "a.sqlite"], name="a")
    snapshot = governor.status_snapshot()
    assert snapshot["system"]["max_concurrency"] == 2
    assert snapshot["active_count"] == 1
    assert snapshot["queued_count"] == 1
    job_view = snapshot["jobs"][0]
    assert {"quota", "state", "quota_source", "last_cpu_percent", "last_rss_mb"} <= set(
        job_view
    )


def test_cancel_unknown_job_raises(governor):
    with pytest.raises(JobControlError, match="unknown job id"):
        governor.cancel("does-not-exist")


def test_config_reload_is_audited(governor, tmp_path):
    config_path = tmp_path / "gov.yaml"
    config_path.write_text(
        "defaults: {cpu_max_percent: 33, memory_max_mb: 128, "
        "max_runtime_seconds: 45}\nmax_concurrency: 4\n",
        encoding="utf-8",
    )
    reloaded = governor.reload_config(config_path)
    assert reloaded.max_concurrency == 4
    events = read_audit_entries(governor.paths.audit_path)
    assert any(e.get("governor_event") == "config_reloaded" for e in events)


# ---------------------------------------------------------------------- CLI
def _cli(base_flags, action, *rest):
    return governor_cli([action, *base_flags, *rest])


def test_cli_submit_ps_quota_and_cancel(gworkspace, tmp_path):
    config_path = tmp_path / "gov.yaml"
    config_path.write_text(
        "defaults: {cpu_max_percent: 50, memory_max_mb: 256, "
        "max_runtime_seconds: 60}\nmax_concurrency: 2\n",
        encoding="utf-8",
    )
    flags = ["--config", str(config_path), "--workspace", str(gworkspace.root)]

    rc = _cli(
        flags, "submit", "--name", "cli-job",
        "--quota", "memory_max_mb=512",
        "--", "maskline", "run", "--dataset", "demo.sqlite",
    )
    assert rc == 0

    snapshot = cli_json(governor_cli, ["ps", *flags, "--json"])
    assert snapshot["jobs"][0]["name"] == "cli-job"
    assert snapshot["jobs"][0]["quota"]["memory_max_mb"] == 512

    job_id = snapshot["jobs"][0]["job_id"]
    assert _cli(flags, "quota", "--job", job_id, "--set", "cpu_max_percent=22") == 0
    assert _cli(flags, "cancel", job_id) == 0
    cancelled = cli_json(governor_cli, ["ps", *flags, "--json"])
    assert cancelled["jobs"][0]["state"] == "cancelled"


def test_cli_rejects_empty_submit(gworkspace):
    rc = governor_cli(["submit", "--workspace", str(gworkspace.root)])
    assert rc == 2


def test_cli_global_quota_and_config_queries(gworkspace, tmp_path):
    config_path = tmp_path / "gov.yaml"
    config_path.write_text(
        "defaults: {cpu_max_percent: 50, memory_max_mb: 256, "
        "max_runtime_seconds: 60}\n",
        encoding="utf-8",
    )
    flags = ["--config", str(config_path), "--workspace", str(gworkspace.root)]
    assert governor_cli(["quota", *flags, "--global",
                         "--set", "max_runtime_seconds=120"]) == 0
    output = cli_json(governor_cli, ["quota", *flags, "--json"])
    assert output["defaults"]["max_runtime_seconds"] == 120


def cli_json(_entrypoint, argv):
    import contextlib
    import io
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = governor_cli(argv)
    assert rc == 0
    return json.loads(buffer.getvalue())
