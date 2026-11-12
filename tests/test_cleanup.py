from __future__ import annotations

import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

from maskline.config import Paths
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.cleanup import CleanupOptions, cleanup_dirty_resources
from maskline.pipeline.locks import lock_path
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.pseudomap import PseudoMap
from maskline.utils import sqlite_content_digest

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "policies" / "example.yaml"
CHILD = REPO / "tests" / "helpers_abnormal.py"


class _AbruptExit(BaseException):
    """Simulates an asynchronous process death that bypasses ``except Exception``."""


def _strict_options(**overrides) -> CleanupOptions:
    values = {"lock_grace_seconds": 0.0, "temp_grace_seconds": 0.0}
    values.update(overrides)
    return CleanupOptions(**values)


def _baseline(ws: Paths, inventory, policy, secret) -> object:
    return execute_run(
        inventory,
        policy,
        ws,
        secrets_store=secret,
        output_path=ws.out_dir / "official.sqlite",
        batch_size=2,
        cleanup_on_start=False,
    )


def _run_for_output(ws: Paths, output: str | Path):
    output_path = Path(output).expanduser().resolve()
    with CheckpointStore(ws.checkpoint_db) as store:
        for record in store.list_runs(limit=100):
            if Path(record.output_path).expanduser().resolve() == output_path:
                return record
    raise AssertionError(f"no run recorded for output {output_path}")


def _failed_run(ws, inventory, policy, secret, exc, output_name="dirty.sqlite"):
    import maskline.pipeline.runner as runner

    original = runner.insert_batch
    calls = {"count": 0}

    def flaky(conn, table, rows):
        calls["count"] += 1
        original(conn, table, rows)
        if calls["count"] >= 2:
            raise exc

    output = ws.out_dir / output_name
    with mock.patch.object(runner, "insert_batch", flaky):
        with pytest.raises(type(exc)):
            runner.execute_run(
                inventory,
                policy,
                ws,
                secrets_store=secret,
                batch_size=2,
                output_path=output,
                cleanup_on_start=False,
            )
    return _run_for_output(ws, output)


def _crashed_run(ws, inventory, policy, secret, output_name="dirty.sqlite"):
    original = CheckpointStore.save_checkpoint

    def abrupt(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise _AbruptExit()

    output = ws.out_dir / output_name
    with mock.patch.object(CheckpointStore, "save_checkpoint", abrupt):
        with pytest.raises(_AbruptExit):
            execute_run(
                inventory,
                policy,
                ws,
                secrets_store=secret,
                batch_size=2,
                output_path=output,
                cleanup_on_start=False,
            )
    return _run_for_output(ws, output)


def _assert_dirty_reclaimed(ws: Paths, run_id: str, report) -> None:
    assert run_id in report.cleaned_run_ids, report.to_dict()
    with CheckpointStore(ws.checkpoint_db) as store:
        record = store.get_run(run_id)
        assert record is not None and record.status == "cleaned"
        assert store.list_checkpoints(run_id) == []
    assert not Path(record.output_path).exists()
    if ws.pseudomap_db.exists():
        with PseudoMap(ws.pseudomap_db) as mapping:
            assert mapping.usage_count(run_id) == 0


def _start_child(
    ws: Paths,
    inventory,
    policy,
    secret,
    output: Path,
    mode: str,
    sentinel: Path,
) -> subprocess.Popen:
    command = [
        sys.executable, str(CHILD),
        "--workspace", str(ws.root),
        "--dataset", str(inventory.path),
        "--policy", str(policy.source_path),
        "--secret", str(secret.source),
        "--output", str(output),
        "--mode", mode,
        "--sentinel", str(sentinel),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO)
    return subprocess.Popen(
        command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )


def _wait_sentinel(proc: subprocess.Popen, sentinel: Path, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if sentinel.exists():
            return
        if proc.poll() is not None:
            output = proc.stdout.read() if proc.stdout else ""
            pytest.fail(f"child exited before sentinel (code={proc.returncode}):\n{output}")
        time.sleep(0.02)
    pytest.fail("timed out waiting for child sentinel")


def _sigkill_run(ws, inventory, policy, secret, tmp_path) -> str:
    output = ws.out_dir / "dirty.sqlite"
    sentinel = tmp_path / "kill.sentinel"
    proc = _start_child(ws, inventory, policy, secret, output, "kill", sentinel)
    _wait_sentinel(proc, sentinel)
    os.kill(proc.pid, signal.SIGKILL)
    proc.wait(timeout=30)
    assert proc.returncode == -signal.SIGKILL
    return _run_for_output(ws, output).run_id


# ---------------------------------------------------------------------------
# The ten abnormal-exit scenarios
# ---------------------------------------------------------------------------

def _scenario_runtime_error(ws, inventory, policy, secret, tmp_path):
    run_id = _failed_run(ws, inventory, policy, secret, RuntimeError("boom"))

    def check(report):
        _assert_dirty_reclaimed(ws, run_id, report)

    return check


def _scenario_disk_full(ws, inventory, policy, secret, tmp_path):
    run_id = _failed_run(
        ws, inventory, policy, secret, sqlite3.OperationalError("database or disk is full")
    )

    def check(report):
        _assert_dirty_reclaimed(ws, run_id, report)
        scene = (ws.cleanup_dir / "last-failure.json")
        assert scene.exists()

    return check


def _scenario_permission_denied(ws, inventory, policy, secret, tmp_path):
    run_id = _failed_run(
        ws, inventory, policy, secret, PermissionError("target directory is read-only")
    )

    def check(report):
        _assert_dirty_reclaimed(ws, run_id, report)

    return check


def _scenario_crashed_dead_lock(ws, inventory, policy, secret, tmp_path):
    run_id = _crashed_run(ws, inventory, policy, secret)
    with CheckpointStore(ws.checkpoint_db) as store:
        record = store.get_run(run_id)
        assert record.status == "running"
        assert len(store.list_checkpoints(run_id)) > 0
    assert not lock_path(ws.locks_dir, f"run-{run_id}").exists()

    def check(report):
        _assert_dirty_reclaimed(ws, run_id, report)

    return check


def _scenario_sigkill(ws, inventory, policy, secret, tmp_path):
    run_id = _sigkill_run(ws, inventory, policy, secret, tmp_path)
    with CheckpointStore(ws.checkpoint_db) as store:
        record = store.get_run(run_id)
        assert record.status == "running"
        assert len(store.list_checkpoints(run_id)) > 0
    assert lock_path(ws.locks_dir, f"run-{run_id}").exists()

    def check(report):
        _assert_dirty_reclaimed(ws, run_id, report)
        assert any("run-" in path for path in report.removed_stale_locks)
        assert not lock_path(ws.locks_dir, f"run-{run_id}").exists()

    return check


def _scenario_target_journal(ws, inventory, policy, secret, tmp_path):
    run_id = _failed_run(ws, inventory, policy, secret, RuntimeError("killed mid-transaction"))
    record = _run_for_output(ws, ws.out_dir / "dirty.sqlite")
    journal = Path(record.output_path + "-journal")
    journal.write_bytes(b"leftover rollback journal")

    def check(report):
        _assert_dirty_reclaimed(ws, run_id, report)
        assert str(journal) in report.removed_sidecars
        assert not journal.exists()

    return check


def _scenario_orphan_checkpoint(ws, inventory, policy, secret, tmp_path):
    ghost = "run-orphan-checkpoint"
    with CheckpointStore(ws.checkpoint_db) as store:
        store.save_checkpoint(ghost, "customers", 5, 5)
        assert len(store.list_checkpoints(ghost)) == 1

    def check(report):
        assert ghost in report.removed_orphan_checkpoint_runs
        with CheckpointStore(ws.checkpoint_db) as store:
            assert store.list_checkpoints(ghost) == []

    return check


def _scenario_orphan_corrupt_output(ws, inventory, policy, secret, tmp_path):
    orphan = ws.out_dir / "orphan.partial.sqlite"
    orphan.write_bytes(b"not a sqlite database")

    def check(report):
        assert str(orphan) in report.removed_orphan_outputs
        assert not orphan.exists()

    return check


def _scenario_stale_lock(ws, inventory, policy, secret, tmp_path):
    ws.ensure_runtime_dirs()
    stale = lock_path(ws.locks_dir, "run-deadbeef")
    stale.write_text('{"run_id": "run-deadbeef", "pid": 999999}\n', encoding="utf-8")
    old = time.time() - 3600
    os.utime(stale, (old, old))

    def check(report):
        assert str(stale) in report.removed_stale_locks
        assert not stale.exists()

    return check


def _scenario_temp_file(ws, inventory, policy, secret, tmp_path):
    ws.ensure_runtime_dirs()
    leftover = ws.manifest_dir / ".official.json.abandoned"
    leftover.write_text("partial manifest", encoding="utf-8")
    old = time.time() - 3600
    os.utime(leftover, (old, old))

    def check(report):
        assert str(leftover) in report.removed_temp_files
        assert not leftover.exists()

    return check


SCENARIOS = [
    ("generic_failure", _scenario_runtime_error),
    ("disk_full", _scenario_disk_full),
    ("permission_denied", _scenario_permission_denied),
    ("crashed_dead_lock", _scenario_crashed_dead_lock),
    ("sigkill", _scenario_sigkill),
    ("target_journal", _scenario_target_journal),
    ("orphan_checkpoint", _scenario_orphan_checkpoint),
    ("orphan_corrupt_output", _scenario_orphan_corrupt_output),
    ("stale_lock", _scenario_stale_lock),
    ("temp_file", _scenario_temp_file),
]


def test_ten_abnormal_exit_scenarios_are_identified_without_overreach(
    tmp_path, inventories, secret_store
):
    """All ten abnormal-exit shapes are reclaimed exactly, 10/10."""
    policy = load_policy(EXAMPLE)
    inventory = inventories["sqlite"]
    source_hash = sqlite_content_digest(inventory.path)
    verified = 0
    for name, scenario in SCENARIOS:
        ws = Paths.for_workspace(tmp_path / name)
        official = _baseline(ws, inventory, policy, secret_store)
        check = scenario(ws, inventory, policy, secret_store, tmp_path / f"{name}-sentinel")
        report = cleanup_dirty_resources(ws, _strict_options())
        check(report)
        # Official artifact and source dataset are never touched.
        assert Path(official.output_path).exists()
        assert sqlite_content_digest(official.output_path) == official.output_hash
        assert sqlite_content_digest(inventory.path) == source_hash
        assert not report.errors, (name, report.errors)
        verified += 1
    assert verified == 10


def test_cleanup_is_idempotent(tmp_path, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    ws = Paths.for_workspace(tmp_path / "ws")
    _failed_run(ws, inventories["sqlite"], policy, secret_store, RuntimeError("boom"))
    first = cleanup_dirty_resources(ws, _strict_options())
    assert first.cleaned_run_ids
    second = cleanup_dirty_resources(ws, _strict_options())
    third = cleanup_dirty_resources(ws, _strict_options())
    assert second.removed_count == 0
    assert third.removed_count == 0
    assert second.errors == [] and third.errors == []
    # The run row and failure scene survive as debugging evidence.
    with CheckpointStore(ws.checkpoint_db) as store:
        record = store.get_run(first.cleaned_run_ids[0])
        assert record.status == "cleaned"
    assert (ws.cleanup_dir / "last-failure.json").exists()


def test_cleanup_dry_run_deletes_nothing(tmp_path, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    ws = Paths.for_workspace(tmp_path / "ws")
    run_id = _failed_run(
        ws, inventories["sqlite"], policy, secret_store, RuntimeError("boom")
    ).run_id
    report = cleanup_dirty_resources(ws, _strict_options(dry_run=True))
    assert report.dry_run
    assert run_id in report.removed_checkpoints or report.removed_targets
    assert Path((ws.out_dir / "dirty.sqlite")).exists()
    with CheckpointStore(ws.checkpoint_db) as store:
        assert store.get_run(run_id).status == "failed"
    # A following real pass still reclaims the same resources.
    real = cleanup_dirty_resources(ws, _strict_options())
    assert run_id in real.cleaned_run_ids


def test_interrupted_run_is_preserved_and_resume_matches_baseline(
    tmp_path, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    baseline_ws = Paths.for_workspace(tmp_path / "baseline")
    baseline = execute_run(
        inventories["sqlite"], policy, baseline_ws,
        secrets_store=secret_store, batch_size=2, cleanup_on_start=False,
    )

    ws = Paths.for_workspace(tmp_path / "interrupted")
    from maskline.pipeline.errors import PipelineInterrupted

    with pytest.raises(PipelineInterrupted) as info:
        execute_run(
            inventories["sqlite"], policy, ws,
            secrets_store=secret_store, batch_size=2,
            interrupt_after_batches=1, cleanup_on_start=False,
        )
    run_id = info.value.run_id
    report = cleanup_dirty_resources(ws, _strict_options())
    assert report.cleaned_run_ids == []
    assert report.preserved_run_ids[run_id].startswith("interrupted")
    with CheckpointStore(ws.checkpoint_db) as store:
        assert store.get_run(run_id).status == "interrupted"
        assert store.get_checkpoint(run_id, "customers").rows_done == 2
    assert Path((ws.out_dir / "demo.masked.sqlite")).exists()
    if ws.pseudomap_db.exists():
        with PseudoMap(ws.pseudomap_db) as mapping:
            assert mapping.usage_count(run_id) > 0

    resumed = execute_run(
        inventories["sqlite"], policy, ws,
        secrets_store=secret_store, batch_size=3,
        resume_run_id=run_id, cleanup_on_start=True,
    )
    assert resumed.output_hash == baseline.output_hash
    assert resumed.transform_counts == baseline.transform_counts
    assert sqlite_content_digest(resumed.output_path) == baseline.output_hash


def test_mapping_rows_shared_with_completed_run_survive(
    tmp_path, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    ws = Paths.for_workspace(tmp_path / "ws")
    completed = execute_run(
        inventories["sqlite"], policy, ws,
        secrets_store=secret_store, output_path=ws.out_dir / "official.sqlite",
        batch_size=2, cleanup_on_start=False,
    )
    with PseudoMap(ws.pseudomap_db) as mapping:
        completed_usage = mapping.usage_count(completed.run_id)
        completed_tokens = mapping.count()
    assert completed_usage > 0

    # Same dataset: its tokens are shared with the completed run.
    shared_run = _failed_run(
        ws, inventories["sqlite"], policy, secret_store, RuntimeError("boom"),
        output_name="shared.sqlite",
    )
    # A different dataset: its tokens belong only to the aborted run.
    dirty_only_run = _failed_run(
        ws, inventories["csv"], policy, secret_store, RuntimeError("boom"),
        output_name="dirty-only.sqlite",
    )
    with PseudoMap(ws.pseudomap_db) as mapping:
        dirty_only_usage = mapping.usage_count(dirty_only_run.run_id)
    assert dirty_only_usage > 0

    report = cleanup_dirty_resources(ws, _strict_options())
    assert shared_run.run_id in report.cleaned_run_ids
    assert dirty_only_run.run_id in report.cleaned_run_ids
    with PseudoMap(ws.pseudomap_db) as mapping:
        assert mapping.usage_count(completed.run_id) == completed_usage
        assert mapping.usage_count(shared_run.run_id) == 0
        assert mapping.usage_count(dirty_only_run.run_id) == 0
        # Completed tokens plus shared tokens survive; dirty-only tokens are gone.
        assert mapping.count() == completed_tokens
    assert report.removed_mapping_tokens > 0
    assert report.removed_mapping_usage > 0
    assert Path(completed.output_path).exists()


def test_low_disk_mode_reclaims_oldest_dirty_resources_first(
    tmp_path, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    ws = Paths.for_workspace(tmp_path / "ws")
    older = _failed_run(
        ws, inventories["sqlite"], policy, secret_store, RuntimeError("old"),
        output_name="older.sqlite",
    )
    newer = _failed_run(
        ws, inventories["csv"], policy, secret_store, RuntimeError("new"),
        output_name="newer.sqlite",
    )
    with CheckpointStore(ws.checkpoint_db) as store:
        store.conn.execute(
            "UPDATE runs SET started_at = ? WHERE run_id = ?",
            ("2020-01-01T00:00:00+00:00", older.run_id),
        )
        store.conn.execute(
            "UPDATE runs SET started_at = ? WHERE run_id = ?",
            ("2025-01-01T00:00:00+00:00", newer.run_id),
        )
        store.conn.commit()

    free = __import__("shutil").disk_usage(ws.root).free
    report = cleanup_dirty_resources(
        ws, _strict_options(min_free_bytes=free + 1)
    )
    assert report.low_disk
    assert report.frozen_for_disk_space
    assert report.cleaned_run_ids == [older.run_id]
    assert Path((ws.out_dir / "older.sqlite")).exists() is False
    assert Path((ws.out_dir / "newer.sqlite")).exists() is True
    with CheckpointStore(ws.checkpoint_db) as store:
        assert store.get_run(newer.run_id).status == "failed"
    # Without pressure the rest is reclaimed in a later pass.
    second = cleanup_dirty_resources(ws, _strict_options())
    assert newer.run_id in second.cleaned_run_ids


def test_cleanup_makes_no_network_calls(tmp_path, inventories, secret_store, monkeypatch):
    policy = load_policy(EXAMPLE)
    ws = Paths.for_workspace(tmp_path / "ws")

    class _NoNetwork:
        def __init__(self, *args, **kwargs):
            raise AssertionError("network access attempted during cleanup")

    monkeypatch.setattr("socket.socket", _NoNetwork)
    monkeypatch.setattr("socket.create_connection", _NoNetwork)
    monkeypatch.setattr("socket.getaddrinfo", _NoNetwork)

    _failed_run(ws, inventories["sqlite"], policy, secret_store, RuntimeError("boom"))
    report = cleanup_dirty_resources(ws, _strict_options())
    assert report.cleaned_run_ids
    assert not report.errors
