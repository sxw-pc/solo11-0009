"""Dirty-resource identification and cleanup after abnormal exits.

Covers ten simulated abnormal-exit scenarios, cross-process lock conflicts,
concurrent cleaners, idempotency, disk-pressure ordering, and the guarantee
that legitimate breakpoints, finished products and source datasets survive.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import shutil
import socket
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from maskline.config import Paths
from maskline.fixturegen import generate_fixture
from maskline.pipeline.checkpoint import CheckpointStore, RunRecord
from maskline.pipeline.cleanup import clean_workspace
from maskline.pipeline.errors import PipelineError, PipelineInterrupted
from maskline.pipeline.locks import RunLock
from maskline.pipeline.runner import execute_run
from maskline.pipeline.steps import new_run_id
from maskline.policies import load_policy
from maskline.pseudomap import PseudoMap
from maskline.registry import inspect_dataset
from maskline.utils import file_sha256, sqlite_content_digest

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def table_rows(path, table):
    conn = sqlite3.connect(path)
    try:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
        select = ", ".join(f'"{name}"' for name in columns)
        return conn.execute(
            f'SELECT rowid, {select} FROM "{table}" ORDER BY rowid'
        ).fetchall()
    finally:
        conn.close()


def make_workspace(tmp_path, name="ws"):
    paths = Paths.for_workspace(tmp_path / name)
    paths.ensure_runtime_dirs()
    return paths


def run_completed(paths, inventory, policy, secret_store, output_name):
    return execute_run(
        inventory, policy, paths, secrets_store=secret_store,
        batch_size=2, output_path=paths.out_dir / output_name,
    )


def run_interrupted(paths, inventory, policy, secret_store, output_name):
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventory, policy, paths, secrets_store=secret_store,
            batch_size=2, interrupt_after_batches=1,
            output_path=paths.out_dir / output_name,
        )
    return excinfo.value.run_id


def make_dirty_run(
    paths,
    inventory,
    policy,
    *,
    status="running",
    output_name=None,
    with_output=True,
    output_bytes=b"half-written-target" * 64,
    sidecars=(),
    checkpoints=True,
    mapping_tokens=(),
    shared_tokens=(),
    output_dir=None,
    age_days=0,
):
    """Fabricate the residue a crashed/killed run would leave behind."""
    run_id = new_run_id()
    directory = output_dir or paths.out_dir
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / (output_name or f"dirty-{run_id}.sqlite")
    store = CheckpointStore(paths.checkpoint_db)
    now = datetime.now(timezone.utc)
    if age_days:
        now = now - timedelta(days=age_days)
    stamp = now.isoformat(timespec="seconds")
    store.create_run(
        RunRecord(
            run_id, str(inventory.path), inventory.fingerprint,
            str(policy.source_path), policy.fingerprint, str(output.resolve()),
            status, stamp, stamp, owner_pid=os.getpid(), owner_host="test-host",
        )
    )
    if checkpoints:
        store.save_checkpoint(
            run_id, "customers", 2, 2,
            {"mask": {"seen": 2, "processed": 2, "changed": 2}},
        )
    store.close()
    if with_output:
        output.write_bytes(output_bytes)
        for suffix in sidecars:
            Path(str(output) + suffix).write_bytes(b"sidecar" * 32)
    if mapping_tokens or shared_tokens:
        with PseudoMap(paths.pseudomap_db, create=True) as mapping:
            for token in mapping_tokens:
                mapping.put(token, f"plain:{token}", run_id=run_id)
            for token, plaintext in shared_tokens:
                mapping.put(token, plaintext, run_id=run_id)
            mapping.commit()
    return run_id, output


def read_run(paths, run_id):
    with CheckpointStore(paths.checkpoint_db) as store:
        return store.get_run(run_id)


def mapping_count(paths):
    with PseudoMap(paths.pseudomap_db) as mapping:
        return mapping.count()


def mapping_tokens(paths):
    with PseudoMap(paths.pseudomap_db) as mapping:
        return {token for token, _ in mapping.iter_entries(limit=10000)}


def load_scene(paths, run_id):
    scene_path = paths.cleanup_dir / f"{run_id}.json"
    assert scene_path.exists(), f"missing failure scene: {scene_path}"
    return json.loads(scene_path.read_text(encoding="utf-8"))


@pytest.fixture
def ctx(tmp_path, inventories, secret_store, monkeypatch):
    """A workspace with one completed and one interrupted legitimate run."""
    paths = make_workspace(tmp_path)
    policy = load_policy(EXAMPLE)
    inventory = inventories["sqlite"]
    completed = run_completed(paths, inventory, policy, secret_store, "completed.sqlite")
    interrupted_id = run_interrupted(paths, inventory, policy, secret_store, "interrupted.sqlite")
    return SimpleNamespace(
        tmp_path=tmp_path,
        paths=paths,
        policy=policy,
        inventory=inventory,
        secret_store=secret_store,
        monkeypatch=monkeypatch,
        completed=completed,
        interrupted_id=interrupted_id,
        completed_digest=sqlite_content_digest(completed.output_path),
        source_sha=file_sha256(inventory.path),
        mapping_count=mapping_count(paths),
        tokens=mapping_tokens(paths),
    )


def assert_untouched(ctx, report):
    """Legitimate breakpoints, finished products and sources are intact."""
    assert ctx.completed.run_id in report.completed_run_ids
    assert ctx.interrupted_id in report.interrupted_run_ids
    assert ctx.completed.run_id not in report.cleaned_run_ids
    assert ctx.interrupted_id not in report.cleaned_run_ids
    # finished product untouched
    assert sqlite_content_digest(ctx.completed.output_path) == ctx.completed_digest
    # source dataset untouched
    assert file_sha256(ctx.inventory.path) == ctx.source_sha
    # interrupted run record, checkpoints and partial output untouched
    record = read_run(ctx.paths, ctx.interrupted_id)
    assert record is not None and record.status == "interrupted"
    with CheckpointStore(ctx.paths.checkpoint_db) as store:
        checkpoint = store.get_checkpoint(ctx.interrupted_id, "customers")
    assert checkpoint is not None and checkpoint.rows_done == 2
    assert (ctx.paths.out_dir / "interrupted.sqlite").exists()


def assert_interrupt_still_resumes(ctx):
    resumed = execute_run(
        ctx.inventory, ctx.policy, ctx.paths, secrets_store=ctx.secret_store,
        batch_size=3, resume_run_id=ctx.interrupted_id,
    )
    assert resumed.row_count == ctx.completed.row_count
    assert resumed.output_hash == ctx.completed.output_hash
    assert table_rows(resumed.output_path, "customers") == table_rows(
        ctx.completed.output_path, "customers"
    )


# ---------------------------------------------------------------------------
# lock primitives
# ---------------------------------------------------------------------------

class TestRunLock:
    def test_exclusive_and_released(self, tmp_path):
        first = RunLock(tmp_path, "run-a")
        second = RunLock(tmp_path, "run-a")
        assert first.acquire()
        assert not second.acquire()
        first.release()
        assert second.acquire()
        second.release()

    def test_unlink_while_held(self, tmp_path):
        lock = RunLock(tmp_path, "run-b")
        lock.acquire()
        lock.unlink()
        assert not lock.path.exists()
        lock.release()
        # a fresh lock on the same name works afterwards
        again = RunLock(tmp_path, "run-b")
        assert again.acquire()
        again.release()


# ---------------------------------------------------------------------------
# ten abnormal-exit scenarios
# ---------------------------------------------------------------------------

def _scenario_sigkill_stale_running(ctx):
    run_id, output = make_dirty_run(
        ctx.paths, ctx.inventory, ctx.policy, status="running",
        mapping_tokens=("psn_dead_1", "psn_dead_2", "psn_dead_3"),
    )
    ctx.dirty_run_id = run_id
    ctx.dirty_output = output

    def verify(report):
        assert run_id in report.cleaned_run_ids
        assert read_run(ctx.paths, run_id) is None
        with CheckpointStore(ctx.paths.checkpoint_db) as store:
            assert store.list_checkpoints(run_id) == []
        assert not output.exists()
        assert mapping_count(ctx.paths) == ctx.mapping_count
        scene = load_scene(ctx.paths, run_id)
        assert scene["reason"] == "stale-running"
        assert scene["run"]["status"] == "running"
        assert scene["checkpoints"] and scene["checkpoints"][0]["rows_done"] == 2
        assert scene["output"]["existed"] is True
    return verify


def _scenario_wal_sidecars(ctx):
    run_id, output = make_dirty_run(
        ctx.paths, ctx.inventory, ctx.policy, status="running",
        sidecars=("-wal", "-shm"),
    )
    ctx.dirty_run_id = run_id

    def verify(report):
        assert run_id in report.cleaned_run_ids
        assert not output.exists()
        assert not Path(str(output) + "-wal").exists()
        assert not Path(str(output) + "-shm").exists()
        assert load_scene(ctx.paths, run_id)["reason"] == "stale-running"
    return verify


def _scenario_record_only_crash(ctx):
    # Died after the run record but before the target file existed.
    run_id, output = make_dirty_run(
        ctx.paths, ctx.inventory, ctx.policy, status="running",
        with_output=False, checkpoints=False,
    )
    ctx.dirty_run_id = run_id

    def verify(report):
        assert run_id in report.cleaned_run_ids
        assert read_run(ctx.paths, run_id) is None
        scene = load_scene(ctx.paths, run_id)
        assert scene["output"]["existed"] is False
        assert scene["checkpoints"] == []
    return verify


def _scenario_disk_full_failed(ctx):
    import maskline.pipeline.runner as runner

    real_insert = runner.insert_batch
    state = {"fail": True}

    def flaky_insert(*args, **kwargs):
        if state["fail"]:
            raise sqlite3.OperationalError("database or disk is full")
        return real_insert(*args, **kwargs)

    ctx.monkeypatch.setattr(runner, "insert_batch", flaky_insert)
    with pytest.raises(sqlite3.OperationalError):
        execute_run(
            ctx.inventory, ctx.policy, ctx.paths,
            secrets_store=ctx.secret_store, batch_size=2,
            output_path=ctx.paths.out_dir / "diskfull.sqlite",
        )
    state["fail"] = False  # let the later legitimate resume proceed
    failed = [
        run for run in _all_runs(ctx.paths) if run.status == "failed"
    ]
    assert len(failed) == 1
    ctx.dirty_run_id = failed[0].run_id
    ctx.dirty_output = ctx.paths.out_dir / "diskfull.sqlite"

    def verify(report):
        assert ctx.dirty_run_id in report.cleaned_run_ids
        assert read_run(ctx.paths, ctx.dirty_run_id) is None
        assert not ctx.dirty_output.exists()
        scene = load_scene(ctx.paths, ctx.dirty_run_id)
        assert scene["reason"] == "failed-run"
        assert "disk is full" in (scene["run"]["status_detail"] or "")
    return verify


def _scenario_permission_failed(ctx):
    import maskline.pipeline.runner as runner

    real_create = runner.create_target
    state = {"fail": True}

    def flaky_create(*args, **kwargs):
        if state["fail"]:
            raise PermissionError("permission denied: read-only filesystem")
        return real_create(*args, **kwargs)

    ctx.monkeypatch.setattr(runner, "create_target", flaky_create)
    with pytest.raises(PermissionError):
        execute_run(
            ctx.inventory, ctx.policy, ctx.paths,
            secrets_store=ctx.secret_store, batch_size=2,
            output_path=ctx.paths.out_dir / "denied.sqlite",
        )
    state["fail"] = False
    failed = [run for run in _all_runs(ctx.paths) if run.status == "failed"]
    assert len(failed) == 1
    ctx.dirty_run_id = failed[0].run_id

    def verify(report):
        assert ctx.dirty_run_id in report.cleaned_run_ids
        assert read_run(ctx.paths, ctx.dirty_run_id) is None
        scene = load_scene(ctx.paths, ctx.dirty_run_id)
        assert scene["reason"] == "failed-run"
        assert "permission denied" in (scene["run"]["status_detail"] or "")
    return verify


def _scenario_transform_crash_failed(ctx):
    import maskline.pipeline.runner as runner

    real_transform = runner.transform_row
    state = {"fail": True, "calls": 0}

    def flaky_transform(*args, **kwargs):
        state["calls"] += 1
        if state["fail"] and state["calls"] > 3:
            raise RuntimeError("simulated transformer crash")
        return real_transform(*args, **kwargs)

    ctx.monkeypatch.setattr(runner, "transform_row", flaky_transform)
    with pytest.raises(RuntimeError, match="simulated transformer crash"):
        execute_run(
            ctx.inventory, ctx.policy, ctx.paths,
            secrets_store=ctx.secret_store, batch_size=2,
            output_path=ctx.paths.out_dir / "crashed.sqlite",
        )
    state["fail"] = False
    failed = [run for run in _all_runs(ctx.paths) if run.status == "failed"]
    assert len(failed) == 1
    ctx.dirty_run_id = failed[0].run_id
    ctx.dirty_output = ctx.paths.out_dir / "crashed.sqlite"

    def verify(report):
        assert ctx.dirty_run_id in report.cleaned_run_ids
        assert not ctx.dirty_output.exists()
        scene = load_scene(ctx.paths, ctx.dirty_run_id)
        assert "simulated transformer crash" in (scene["run"]["status_detail"] or "")
    return verify


def _scenario_orphan_output_no_record(ctx):
    # Crash between target creation and run-record insert (legacy versions):
    # an untracked half-written output with no run record at all.
    orphan = ctx.paths.out_dir / "ghost.masked.sqlite"
    orphan.write_bytes(b"orphaned" * 128)
    Path(str(orphan) + "-wal").write_bytes(b"wal" * 64)
    ctx.dirty_run_id = None

    def verify(report):
        assert str(orphan) in report.orphan_files_removed
        assert not orphan.exists()
        assert not Path(str(orphan) + "-wal").exists()
        # tracked outputs were not mistaken for orphans
        assert (ctx.paths.out_dir / "completed.sqlite").exists()
        assert (ctx.paths.out_dir / "interrupted.sqlite").exists()
    return verify


def _scenario_shared_mapping_tokens(ctx):
    # A dirty run that re-used tokens owned by the completed run plus some
    # of its own: shared entries must survive, exclusive ones must go.
    shared = sorted(ctx.tokens)[:2]
    shared_pairs = []
    with PseudoMap(ctx.paths.pseudomap_db) as mapping:
        for token in shared:
            shared_pairs.append((token, mapping.reveal(token)))
    run_id, _output = make_dirty_run(
        ctx.paths, ctx.inventory, ctx.policy, status="failed",
        mapping_tokens=("psn_exclusive_1", "psn_exclusive_2"),
        shared_tokens=shared_pairs,
    )
    ctx.dirty_run_id = run_id
    assert mapping_count(ctx.paths) == ctx.mapping_count + 2

    def verify(report):
        assert run_id in report.cleaned_run_ids
        remaining = mapping_tokens(ctx.paths)
        assert "psn_exclusive_1" not in remaining
        assert "psn_exclusive_2" not in remaining
        for token in shared:
            assert token in remaining  # still needed by the completed run
        assert mapping_count(ctx.paths) == ctx.mapping_count
        with PseudoMap(ctx.paths.pseudomap_db) as mapping:
            assert mapping.count_refs(run_id) == 0
    return verify


def _scenario_killed_during_resume(ctx):
    # A legitimate interrupted run whose resume died right after flipping
    # the status back to "running": the whole run is now dirty residue.
    doomed_id = run_interrupted(
        ctx.paths, ctx.inventory, ctx.policy, ctx.secret_store, "doomed.sqlite"
    )
    with CheckpointStore(ctx.paths.checkpoint_db) as store:
        store.set_status(doomed_id, "running")  # what a live resume sets first
    ctx.dirty_run_id = doomed_id

    def verify(report):
        assert doomed_id in report.cleaned_run_ids
        assert read_run(ctx.paths, doomed_id) is None
        assert not (ctx.paths.out_dir / "doomed.sqlite").exists()
        scene = load_scene(ctx.paths, doomed_id)
        assert scene["reason"] == "stale-running"
        # resuming the cleaned run now fails cleanly instead of reading dirt
        with pytest.raises(PipelineError, match="unknown run id"):
            execute_run(
                ctx.inventory, ctx.policy, ctx.paths,
                secrets_store=ctx.secret_store, resume_run_id=doomed_id,
            )
    return verify


def _scenario_custom_output_outside_outdir(ctx):
    outside = ctx.tmp_path / "elsewhere"
    run_id, output = make_dirty_run(
        ctx.paths, ctx.inventory, ctx.policy, status="failed",
        output_dir=outside, output_name="custom.sqlite",
    )
    ctx.dirty_run_id = run_id
    # plus a stale lock file whose run vanished without a trace
    ghost_lock = ctx.paths.lock_dir / "run-ghost.lock"
    ghost_lock.write_text("")

    def verify(report):
        assert run_id in report.cleaned_run_ids
        assert not output.exists()
        assert not ghost_lock.exists()
        assert str(ghost_lock) in report.orphan_files_removed
        scene = load_scene(ctx.paths, run_id)
        assert scene["run"]["output_path"] == str(output.resolve())
    return verify


SCENARIOS = [
    ("sigkill-stale-running", _scenario_sigkill_stale_running),
    ("wal-sidecars", _scenario_wal_sidecars),
    ("record-only-crash", _scenario_record_only_crash),
    ("disk-full-failed", _scenario_disk_full_failed),
    ("permission-failed", _scenario_permission_failed),
    ("transform-crash-failed", _scenario_transform_crash_failed),
    ("orphan-output-no-record", _scenario_orphan_output_no_record),
    ("shared-mapping-tokens", _scenario_shared_mapping_tokens),
    ("killed-during-resume", _scenario_killed_during_resume),
    ("custom-output-outside-outdir", _scenario_custom_output_outside_outdir),
]


def _all_runs(paths):
    with CheckpointStore(paths.checkpoint_db) as store:
        return store.list_runs(limit=None)


@pytest.mark.parametrize("name,scenario", SCENARIOS, ids=[name for name, _ in SCENARIOS])
def test_abnormal_exit_scenario(ctx, name, scenario):
    verify = scenario(ctx)
    report = clean_workspace(ctx.paths)
    verify(report)
    assert_untouched(ctx, report)
    assert_interrupt_still_resumes(ctx)


def test_scenario_count_is_ten():
    assert len(SCENARIOS) == 10


# ---------------------------------------------------------------------------
# real SIGKILL against a live child process
# ---------------------------------------------------------------------------

def _child_mask_run(workspace, dataset, policy_path, secret_file):
    os.environ["MASKLINE_SECRET_FILE"] = secret_file
    from maskline.config import Paths, SecretStore
    from maskline.pipeline.runner import execute_run
    from maskline.policies import load_policy
    from maskline.registry import inspect_dataset

    paths = Paths.for_workspace(workspace)
    policy = load_policy(policy_path)
    inventory = inspect_dataset(dataset)
    execute_run(
        inventory, policy, paths,
        secrets_store=SecretStore.from_file(secret_file), batch_size=1,
    )


def _read_runs_raw(checkpoint_db):
    conn = sqlite3.connect(f"file:{checkpoint_db}?mode=ro", uri=True)
    try:
        return conn.execute("SELECT run_id, status FROM runs").fetchall()
    finally:
        conn.close()


def _read_checkpoint_count(checkpoint_db):
    conn = sqlite3.connect(f"file:{checkpoint_db}?mode=ro", uri=True)
    try:
        return conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
    finally:
        conn.close()


def test_sigkill_mid_run_leaves_cleanable_residue(tmp_path, secret_store):
    big = generate_fixture(tmp_path / "bigraw", seed=11, customers=200, orders=20, leads=2)
    paths = make_workspace(tmp_path)
    policy = load_policy(EXAMPLE)
    ctx = mp.get_context("fork")
    child = ctx.Process(
        target=_child_mask_run,
        args=(str(paths.root), str(big["sqlite"]), str(EXAMPLE),
              os.environ["MASKLINE_SECRET_FILE"]),
    )
    child.daemon = True  # never block the test run if the kernel wedges
    child.start()
    run_id = None
    deadline = time.time() + 30
    while time.time() < deadline:
        if paths.checkpoint_db.exists():
            try:
                runs = _read_runs_raw(paths.checkpoint_db)
                checkpoints = _read_checkpoint_count(paths.checkpoint_db)
            except sqlite3.OperationalError:
                runs, checkpoints = [], 0
            running = [rid for rid, status in runs if status == "running"]
            if running and checkpoints >= 1:
                run_id = running[0]
                break
        time.sleep(0.05)
    assert run_id, "child never reached a checkpointed running state"
    child.kill()  # SIGKILL: no finally blocks, no status update
    child.join(timeout=30)
    assert not child.is_alive(), "child ignored SIGKILL"
    assert child.exitcode == -9

    record = read_run(paths, run_id)
    assert record is not None and record.status == "running"  # stale
    output = Path(record.output_path)
    assert output.exists()  # half-written target left behind
    assert mapping_count(paths) > 0  # committed mapping entries left behind

    report = clean_workspace(paths)
    assert report.cleaned_run_ids == [run_id]
    assert read_run(paths, run_id) is None
    assert not output.exists()
    assert mapping_count(paths) == 0
    scene = load_scene(paths, run_id)
    assert scene["reason"] == "stale-running"
    assert scene["run"]["owner_pid"] == child.pid

    # the workspace is healthy again: a fresh run completes cleanly
    inventory = inspect_dataset(big["sqlite"])
    result = execute_run(
        inventory, policy, paths,
        secrets_store=secret_store, batch_size=500,
    )
    assert result.row_count == inventory.row_count


# ---------------------------------------------------------------------------
# cross-process lock conflicts
# ---------------------------------------------------------------------------

def _lock_holder_process(lock_dir, name, acquired, release):
    lock = RunLock(lock_dir, name)
    lock.acquire()
    acquired.set()
    release.wait(30)
    lock.release()


def test_cleaner_respects_lock_held_by_other_process(tmp_path, inventories, secret_store):
    paths = make_workspace(tmp_path)
    policy = load_policy(EXAMPLE)
    inventory = inventories["sqlite"]
    # one run whose lock is held by a live "worker" process
    active_id, active_output = make_dirty_run(
        paths, inventory, policy, status="running"
    )
    # one genuinely abandoned run
    stale_id, stale_output = make_dirty_run(
        paths, inventory, policy, status="running"
    )
    ctx = mp.get_context("fork")
    acquired, release = ctx.Event(), ctx.Event()
    holder = ctx.Process(
        target=_lock_holder_process,
        args=(str(paths.lock_dir), active_id, acquired, release),
    )
    holder.start()
    assert acquired.wait(30)
    try:
        report = clean_workspace(paths)
    finally:
        release.set()
        holder.join()
    assert stale_id in report.cleaned_run_ids
    assert active_id in report.active_run_ids
    assert active_id not in report.cleaned_run_ids
    assert active_output.exists()  # the live process's resources survive
    assert not stale_output.exists()
    assert read_run(paths, active_id) is not None


def test_concurrent_mixed_workload_no_false_deletes(tmp_path, inventories, secret_store):
    """8 tasks (2 completed, 2 interrupted, 2 active, 2 dirty) + 3 cleaners."""
    paths = make_workspace(tmp_path)
    policy = load_policy(EXAMPLE)
    inventory = inventories["sqlite"]
    source_sha = file_sha256(inventory.path)

    completed = [
        run_completed(paths, inventory, policy, secret_store, f"c{i}.sqlite")
        for i in range(2)
    ]
    completed_digests = {
        r.run_id: sqlite_content_digest(r.output_path) for r in completed
    }
    interrupted_ids = [
        run_interrupted(paths, inventory, policy, secret_store, f"i{i}.sqlite")
        for i in range(2)
    ]

    stop = threading.Event()
    active_ids = [new_run_id(), new_run_id()]
    active_outputs = [paths.out_dir / f"active{i}.sqlite" for i in range(2)]
    worker_errors = []

    def worker(run_id, output):
        try:
            lock = RunLock(paths.lock_dir, run_id)
            lock.acquire()
            # lock first, then the record: exactly what the real runner does
            store = CheckpointStore(paths.checkpoint_db)
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            store.create_run(
                RunRecord(
                    run_id, str(inventory.path), inventory.fingerprint,
                    str(policy.source_path), policy.fingerprint,
                    str(output.resolve()), "running", now, now,
                )
            )
            store.close()
            output.write_bytes(b"live-partial" * 64)
            while not stop.is_set():
                time.sleep(0.01)
            lock.release()
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            worker_errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(rid, out))
        for rid, out in zip(active_ids, active_outputs)
    ]
    for thread in threads:
        thread.start()
    deadline = time.time() + 30
    while time.time() < deadline:
        if len([r for r in _all_runs(paths) if r.run_id in active_ids]) == 2:
            break
        time.sleep(0.05)
    else:  # pragma: no cover
        raise AssertionError("workers never registered")

    dirty_ids = [
        make_dirty_run(paths, inventory, policy, status="running")[0],
        make_dirty_run(paths, inventory, policy, status="failed")[0],
    ]

    reports, cleaner_errors = [], []

    def cleaner():
        try:
            reports.append(clean_workspace(paths))
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            cleaner_errors.append(exc)

    cleaners = [threading.Thread(target=cleaner) for _ in range(3)]
    for thread in cleaners:
        thread.start()
    for thread in cleaners:
        thread.join()
    stop.set()
    for thread in threads:
        thread.join()

    assert not cleaner_errors and not worker_errors
    cleaned = sorted(rid for report in reports for rid in report.cleaned_run_ids)
    assert cleaned == sorted(dirty_ids)  # each dirty run cleaned exactly once
    for report in reports:
        assert set(active_ids) <= set(report.active_run_ids)
        assert set(interrupted_ids) <= set(report.interrupted_run_ids)
        assert {r.run_id for r in completed} <= set(report.completed_run_ids)
    # active runs completely untouched
    for run_id, output in zip(active_ids, active_outputs):
        assert output.exists()
        record = read_run(paths, run_id)
        assert record is not None and record.status == "running"
    # interrupted and completed runs completely untouched
    for run_id in interrupted_ids:
        assert read_run(paths, run_id).status == "interrupted"
    for run in completed:
        assert sqlite_content_digest(run.output_path) == completed_digests[run.run_id]
    assert file_sha256(inventory.path) == source_sha
    # dirty runs fully reclaimed, with failure scenes preserved
    for run_id in dirty_ids:
        assert read_run(paths, run_id) is None
        assert load_scene(paths, run_id)["run_id"] == run_id
    # and a legitimate breakpoint still resumes to the correct result
    resumed = execute_run(
        inventory, policy, paths, secrets_store=secret_store,
        batch_size=3, resume_run_id=interrupted_ids[0],
    )
    assert resumed.output_hash == completed[0].output_hash


# ---------------------------------------------------------------------------
# idempotency, dry-run, disk pressure, no-network, resume equivalence
# ---------------------------------------------------------------------------

def test_clean_is_idempotent(ctx):
    run_id, output = make_dirty_run(
        ctx.paths, ctx.inventory, ctx.policy, status="failed",
        mapping_tokens=("psn_junk",),
    )
    first = clean_workspace(ctx.paths)
    assert run_id in first.cleaned_run_ids
    scene_path = ctx.paths.cleanup_dir / f"{run_id}.json"
    assert scene_path.exists()
    second = clean_workspace(ctx.paths)
    assert second.cleaned == []
    assert second.orphan_files_removed == []
    assert scene_path.exists()  # failure scene survives repeated cleaning
    third = clean_workspace(ctx.paths, dry_run=True)
    assert third.cleaned == []
    assert_untouched(ctx, second)


def test_dry_run_changes_nothing(ctx):
    run_id, output = make_dirty_run(
        ctx.paths, ctx.inventory, ctx.policy, status="failed",
        mapping_tokens=("psn_junk",),
    )
    before = mapping_count(ctx.paths)
    report = clean_workspace(ctx.paths, dry_run=True)
    assert run_id in report.cleaned_run_ids  # reported as a candidate...
    item = report.cleaned[0]
    assert item.freed_bytes == output.stat().st_size  # ...with an estimate
    assert item.mapping_entries_removed == 1
    assert read_run(ctx.paths, run_id) is not None  # ...but nothing removed
    assert output.exists()
    assert mapping_count(ctx.paths) == before
    assert not (ctx.paths.cleanup_dir / f"{run_id}.json").exists()
    real = clean_workspace(ctx.paths)
    assert run_id in real.cleaned_run_ids
    assert not output.exists()


def test_disk_pressure_cleans_oldest_first(tmp_path, inventories, secret_store):
    paths = make_workspace(tmp_path)
    policy = load_policy(EXAMPLE)
    inventory = inventories["sqlite"]
    sizes = [1 << 20, 1 << 20, 1 << 20]
    run_ids = []
    for index, size in enumerate(sizes):
        run_id, _output = make_dirty_run(
            paths, inventory, policy, status="failed",
            output_bytes=b"x" * size, age_days=10 - index,  # oldest first
        )
        run_ids.append(run_id)
    free_before = shutil.disk_usage(paths.out_dir).free
    # Ask for roughly one oldest file's worth of space: only it should go.
    target = free_before + sizes[0] - (512 << 10)
    report = clean_workspace(paths, min_free_bytes=target)
    assert report.cleaned_run_ids == [run_ids[0]]
    assert read_run(paths, run_ids[0]) is None
    assert read_run(paths, run_ids[1]) is not None
    assert read_run(paths, run_ids[2]) is not None
    # with no pressure target everything dirty is reclaimed
    rest = clean_workspace(paths)
    assert sorted(rest.cleaned_run_ids) == sorted(run_ids[1:])


def test_no_network_requests(ctx, monkeypatch):
    def boom(*args, **kwargs):  # pragma: no cover - fails the test if hit
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    run_id, _output = make_dirty_run(
        ctx.paths, ctx.inventory, ctx.policy, status="failed",
        mapping_tokens=("psn_junk",),
    )
    report = clean_workspace(ctx.paths)
    assert run_id in report.cleaned_run_ids
    assert_interrupt_still_resumes(ctx)


def test_resume_after_clean_matches_resume_without_clean(tmp_path, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    inventory = inventories["sqlite"]
    outcomes = {}
    for name in ("cleaned", "uncleaned"):
        paths = make_workspace(tmp_path, name)
        run_id = run_interrupted(paths, inventory, policy, secret_store, "out.sqlite")
        if name == "cleaned":
            make_dirty_run(
                paths, inventory, policy, status="failed",
                mapping_tokens=("psn_junk",),
            )
            report = clean_workspace(paths)
            assert len(report.cleaned_run_ids) == 1
            assert run_id in report.interrupted_run_ids
        outcomes[name] = execute_run(
            inventory, policy, paths, secrets_store=secret_store,
            batch_size=3, resume_run_id=run_id,
        )
    cleaned, uncleaned = outcomes["cleaned"], outcomes["uncleaned"]
    assert cleaned.output_hash == uncleaned.output_hash
    assert cleaned.transform_counts == uncleaned.transform_counts
    assert cleaned.row_count == uncleaned.row_count
    for table in ("customers", "orders"):
        assert table_rows(cleaned.output_path, table) == table_rows(
            uncleaned.output_path, table
        )


def test_failed_resume_attempt_keeps_legitimate_breakpoint(tmp_path, inventories, secret_store, make_policy):
    # A resume that fails validation must not demote the interrupted run to
    # "failed" (which cleanup would then reclaim as dirty residue).
    paths = make_workspace(tmp_path)
    inventory = inventories["sqlite"]
    policy = load_policy(EXAMPLE)
    run_id = run_interrupted(paths, inventory, policy, secret_store, "out.sqlite")
    other = make_policy(
        """
        version: 1
        name: incompatible
        datasets:
          - path: "demo.sqlite"
            tables:
              customers:
                columns:
                  phone:
                    transformer: mask
        """
    )
    with pytest.raises(PipelineError, match="policy changed"):
        execute_run(
            inventory, other, paths, secrets_store=secret_store,
            resume_run_id=run_id,
        )
    record = read_run(paths, run_id)
    assert record.status == "interrupted"
    report = clean_workspace(paths)
    assert report.cleaned == []
    assert run_id in report.interrupted_run_ids


def test_cli_clean_smoke(tmp_path, inventories, secret_store, capsys):
    from maskline.__main__ import main

    paths = make_workspace(tmp_path)
    policy = load_policy(EXAMPLE)
    inventory = inventories["sqlite"]
    run_id, _output = make_dirty_run(paths, inventory, policy, status="failed")
    assert main(["clean", "--workspace", str(paths.root), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would-clean" in out and run_id in out
    assert main(["clean", "--workspace", str(paths.root)]) == 0
    out = capsys.readouterr().out
    assert "cleaned" in out and run_id in out
    assert read_run(paths, run_id) is None
