import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from maskline.audit import read_audit_entries, verify_audit
from maskline.config import Paths, create_demo_secret
from maskline.fixturegen import generate_fixture
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineError, PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.registry import inspect_dataset
from maskline.utils import sqlite_content_digest
from maskline.workflow import finalize_run

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"

def table_rows(path, table):
    conn = sqlite3.connect(path)
    try:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
        select = ", ".join(f'"{name}"' for name in columns)
        return conn.execute(f'SELECT rowid, {select} FROM "{table}" ORDER BY rowid').fetchall()
    finally:
        conn.close()

def run_baseline(tmp_path, inventories, secret_store, batch_size=2):
    """One uninterrupted run in its own workspace, used as the reference."""
    paths = Paths.for_workspace(tmp_path / "baseline")
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, paths,
        secrets_store=secret_store, batch_size=batch_size,
    )
    return result, paths

def interrupt_run(paths, inventory, secret_store, batch_size=2, after=1):
    policy = load_policy(EXAMPLE)
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventory, policy, paths, secrets_store=secret_store,
            batch_size=batch_size, interrupt_after_batches=after,
        )
    return excinfo.value.run_id

def resume_run(paths, inventory, secret_store, run_id, batch_size=3):
    policy = load_policy(EXAMPLE)
    return execute_run(
        inventory, policy, paths, secrets_store=secret_store,
        batch_size=batch_size, resume_run_id=run_id,
    )

def assert_same_output(resumed, resumed_paths, baseline, baseline_paths):
    """Final state after resume must equal one uninterrupted run exactly."""
    assert resumed.output_hash == baseline.output_hash
    assert resumed.row_count == baseline.row_count
    assert resumed.transform_counts == baseline.transform_counts
    assert sqlite_content_digest(resumed_paths.pseudomap_db) == sqlite_content_digest(
        baseline_paths.pseudomap_db
    )

def test_interrupted_run_resumes_to_identical_output(
    tmp_path, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    baseline = execute_run(
        inventories["sqlite"], policy, baseline_paths,
        secrets_store=secret_store, batch_size=2,
    )
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, interrupted_paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    run_id = excinfo.value.run_id
    with CheckpointStore(interrupted_paths.checkpoint_db) as store:
        assert store.get_run(run_id).status == "interrupted"
        assert store.get_checkpoint(run_id, "customers").rows_done == 2
    resumed = execute_run(
        inventories["sqlite"], policy, interrupted_paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    with CheckpointStore(interrupted_paths.checkpoint_db) as store:
        assert store.get_run(run_id).status == "completed"
    assert resumed.run_id == run_id
    assert resumed.row_count == baseline.row_count
    assert resumed.output_hash == baseline.output_hash
    assert sqlite_content_digest(resumed.output_path) == baseline.output_hash
    assert resumed.transform_counts == baseline.transform_counts
    for table in ("customers", "orders"):
        assert table_rows(resumed.output_path, table) == table_rows(baseline.output_path, table)
    assert table_rows(resumed.output_path, "customers") != table_rows(
        inventories["sqlite"].path, "customers"
    )

def test_completed_run_cannot_be_resumed_again(tmp_path, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    paths = Paths.for_workspace(tmp_path / "workspace")
    result = execute_run(
        inventories["sqlite"], policy, paths, secrets_store=secret_store
    )
    with pytest.raises(PipelineError, match="already completed"):
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, resume_run_id=result.run_id,
        )

def test_repeated_interrupt_resume_always_matches_baseline(
    tmp_path, inventories, secret_store
):
    """The interrupt-simulation case, repeated with varying interrupt points
    and resume batch sizes: final output must always equal the full run."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    for iteration in range(10):
        paths = Paths.for_workspace(tmp_path / f"case-{iteration}")
        run_id = interrupt_run(
            paths, inventories["sqlite"], secret_store,
            batch_size=2, after=iteration % 8 + 1,
        )
        resumed = resume_run(
            paths, inventories["sqlite"], secret_store, run_id,
            batch_size=iteration % 3 + 1,
        )
        assert_same_output(resumed, paths, baseline, baseline_paths)
        with CheckpointStore(paths.checkpoint_db) as store:
            assert store.get_run(run_id).status == "completed"
            checkpoints = {
                cp.table_name: cp for cp in store.list_checkpoints(run_id)
            }
        assert checkpoints["customers"].rows_done == 6
        assert checkpoints["orders"].rows_done == 9

def test_crash_window_target_ahead_of_checkpoint(
    tmp_path, inventories, secret_store
):
    """Crash after the target commit but before the checkpoint commit:
    the target holds batches the checkpoint does not know about."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    # Reference checkpoint state after exactly one batch.
    reference = Paths.for_workspace(tmp_path / "reference")
    ref_run_id = interrupt_run(
        reference, inventories["sqlite"], secret_store, batch_size=2, after=1
    )
    # Main run gets two batches further than its checkpoint will say.
    paths = Paths.for_workspace(tmp_path / "crashed")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=3)
    # Simulate the crash: rewind the checkpoint to the one-batch state while
    # the target keeps all three committed batches.
    with CheckpointStore(reference.checkpoint_db) as ref_store:
        old = ref_store.get_checkpoint(ref_run_id, "customers")
    with CheckpointStore(paths.checkpoint_db) as store:
        store.save_checkpoint(run_id, "customers", old.last_rowid, old.rows_done, old.counts)
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=5)
    assert_same_output(resumed, paths, baseline, baseline_paths)

def test_crash_window_checkpoint_ahead_of_target(
    tmp_path, inventories, secret_store
):
    """Artifacts of an older version: the checkpoint records batches that
    never made it into the target database."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    paths = Paths.for_workspace(tmp_path / "crashed")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=2)
    output = paths.out_dir / "demo.masked.sqlite"
    conn = sqlite3.connect(output)
    try:
        conn.execute("DELETE FROM customers WHERE rowid > 2")
        conn.commit()
    finally:
        conn.close()
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=4)
    assert_same_output(resumed, paths, baseline, baseline_paths)

def test_straggler_rows_without_checkpoint_are_dropped(
    tmp_path, inventories, secret_store
):
    """Crash before the first checkpoint of a table: committed target rows
    exist with no checkpoint at all."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    paths = Paths.for_workspace(tmp_path / "crashed")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    with CheckpointStore(paths.checkpoint_db) as store:
        store.delete_checkpoint(run_id, "customers")
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=2)
    assert_same_output(resumed, paths, baseline, baseline_paths)

def test_duplicate_rows_from_old_version_are_dropped(
    tmp_path, inventories, secret_store
):
    """An old-version target already contains a duplicate of a source row
    under a new rowid; resume must not keep it."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    paths = Paths.for_workspace(tmp_path / "crashed")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    output = paths.out_dir / "demo.masked.sqlite"
    conn = sqlite3.connect(output)
    try:
        row = conn.execute("SELECT * FROM customers WHERE rowid = 1").fetchone()
        columns = [r[1] for r in conn.execute('PRAGMA table_info("customers")')]
        # A foreign row far beyond the checkpointed prefix, duplicating the
        # content of source row 1 under a new rowid/primary key.
        values = tuple(
            999 if column == "customer_id" else value
            for column, value in zip(columns, row)
        )
        placeholders = ", ".join("?" for _ in columns)
        conn.execute(
            f"INSERT INTO customers (rowid, {', '.join(columns)}) "
            f"VALUES (999, {placeholders})",
            values,
        )
        conn.commit()
    finally:
        conn.close()
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=2)
    assert_same_output(resumed, paths, baseline, baseline_paths)
    assert table_rows(resumed.output_path, "customers") == table_rows(
        baseline.output_path, "customers"
    )

def test_concurrent_resume_has_a_single_winner(
    tmp_path, inventories, secret_store
):
    """Two processes resuming the same run: exactly one proceeds, the other
    exits immediately with a clean error and writes nothing."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    paths = Paths.for_workspace(tmp_path / "shared")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    results, errors = [], []
    barrier = threading.Barrier(2)

    def worker():
        try:
            barrier.wait(timeout=10)
            results.append(
                resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=2)
            )
        except PipelineError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert len(results) == 1
    assert len(errors) == 1
    assert "another maskline run is active" in str(errors[0])
    assert_same_output(results[0], paths, baseline, baseline_paths)
    # A later, non-concurrent resume of the completed run is rejected.
    with pytest.raises(PipelineError, match="already completed"):
        resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=2)

def test_old_checkpoint_file_is_migrated_and_resumed(
    tmp_path, inventories, secret_store
):
    """Checkpoint files written before the secret_fingerprint column
    existed must stay usable."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    paths = Paths.for_workspace(tmp_path / "old")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    db = paths.checkpoint_db
    conn = sqlite3.connect(db)
    try:
        run_row = conn.execute(
            "SELECT run_id, dataset_path, dataset_fingerprint, policy_path,"
            " policy_fingerprint, output_path, status, started_at, updated_at"
            " FROM runs"
        ).fetchone()
        checkpoint_rows = conn.execute(
            "SELECT run_id, table_name, last_rowid, rows_done, updated_at, counts_json"
            " FROM checkpoints"
        ).fetchall()
    finally:
        conn.close()
    db.unlink()
    # Rebuild the file with the previous generation's schema (no
    # secret_fingerprint column on runs).
    conn = sqlite3.connect(db)
    try:
        conn.executescript(
            """
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                dataset_path TEXT NOT NULL,
                dataset_fingerprint TEXT NOT NULL,
                policy_path TEXT NOT NULL,
                policy_fingerprint TEXT NOT NULL,
                output_path TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE checkpoints (
                run_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                last_rowid INTEGER NOT NULL,
                rows_done INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                counts_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (run_id, table_name)
            );
            """
        )
        conn.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", run_row)
        conn.executemany("INSERT INTO checkpoints VALUES (?, ?, ?, ?, ?, ?)", checkpoint_rows)
        conn.commit()
    finally:
        conn.close()
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=3)
    assert_same_output(resumed, paths, baseline, baseline_paths)

def test_resume_rejects_a_changed_secret(tmp_path, inventories, secret_store):
    paths = Paths.for_workspace(tmp_path / "ws")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    other_secret = create_demo_secret(tmp_path / "other-secret.txt")
    with pytest.raises(PipelineError, match="secret store differs"):
        resume_run(paths, inventories["sqlite"], other_secret, run_id, batch_size=2)

def test_finalize_run_writes_exactly_one_audit_entry(
    tmp_path, inventories, secret_store
):
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    policy = load_policy(EXAMPLE)
    finalize_run(baseline_paths, inventories["sqlite"], policy, baseline, [])
    finalize_run(baseline_paths, inventories["sqlite"], policy, baseline, [])
    entries = read_audit_entries(baseline_paths.audit_path)
    assert len([entry for entry in entries if entry["run_id"] == baseline.run_id]) == 1
    verification = verify_audit(baseline_paths.audit_path)
    assert verification.entries == len(entries)

def test_audit_entry_matches_full_run_after_resume(
    tmp_path, inventories, secret_store
):
    """The resumed run's audit record carries the same content a single
    uninterrupted run in the same workspace would have produced, and each
    run contributes exactly one entry to the chain."""
    policy = load_policy(EXAMPLE)
    paths = Paths.for_workspace(tmp_path / "ws")
    full = execute_run(
        inventories["sqlite"], policy, paths, secrets_store=secret_store, batch_size=2
    )
    finalize_run(paths, inventories["sqlite"], policy, full, [])
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=3)
    finalize_run(paths, inventories["sqlite"], policy, resumed, [])
    entries = read_audit_entries(paths.audit_path)
    assert len(entries) == 2
    volatile = {"run_id", "ts", "elapsed_seconds", "seq", "prev_hash", "entry_hash"}
    stable = [
        {key: value for key, value in entry.items() if key not in volatile}
        for entry in entries
    ]
    assert stable[0] == stable[1]
    verify_audit(paths.audit_path)

def test_csv_dataset_resumes_to_identical_output(tmp_path, inventories, secret_store):
    paths = Paths.for_workspace(tmp_path / "csv")
    policy = load_policy(EXAMPLE)
    baseline_result = execute_run(
        inventories["csv"], policy, Paths.for_workspace(tmp_path / "csv-base"),
        secrets_store=secret_store, batch_size=1,
    )
    run_id = interrupt_run(paths, inventories["csv"], secret_store, batch_size=1, after=1)
    resumed = resume_run(paths, inventories["csv"], secret_store, run_id, batch_size=2)
    assert resumed.output_hash == baseline_result.output_hash
    assert resumed.transform_counts == baseline_result.transform_counts

def test_no_sidecar_residue_after_run_and_resume(
    tmp_path, inventories, secret_store
):
    """Connections are released: no journal/wal/shm files remain behind."""
    paths = Paths.for_workspace(tmp_path / "ws")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=2)
    leftovers = [
        path
        for path in (paths.root).rglob("*")
        if path.suffix in {"-journal", "-wal", "-shm"}
        or path.name.endswith(("-journal", "-wal", "-shm"))
    ]
    assert leftovers == []

def test_stale_journal_does_not_corrupt_recreated_target(tmp_path):
    """A hot journal left next to a deleted target must not be rolled back
    into the freshly created database."""
    from maskline.pipeline.steps import create_target
    from maskline.registry import inspect_dataset
    from maskline.fixturegen import generate_fixture

    fixture = generate_fixture(tmp_path / "raw", seed=11, customers=3, orders=3, leads=1)
    inventory = inspect_dataset(fixture["sqlite"])
    output = tmp_path / "out" / "demo.masked.sqlite"
    output.parent.mkdir(parents=True)
    # Build a stale hot journal that belongs to a different, deleted file.
    stale = tmp_path / "stale.sqlite"
    conn = sqlite3.connect(stale)
    conn.execute("CREATE TABLE junk (value TEXT)")
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO junk VALUES ('x')")
    journal = Path(str(output) + "-journal")
    # Move the live journal next to the future target path.
    live_journal = Path(str(stale) + "-journal")
    assert live_journal.exists()
    live_journal.rename(journal)
    conn.close()
    stale.unlink()
    create_target(inventory, output)
    conn = sqlite3.connect(output)
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert names == {"customers", "orders"}
    finally:
        conn.close()

def test_hard_kill_mid_run_then_resume_matches_full_run(tmp_path, secret_store):
    """A real SIGKILL mid-run: resume still reproduces the uninterrupted
    output, the pseudomap, and the transform counts."""
    fixtures = generate_fixture(tmp_path / "raw", seed=5, customers=120, orders=180, leads=5)
    inventory = inspect_dataset(fixtures["sqlite"])
    policy = load_policy(EXAMPLE)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    baseline = execute_run(
        inventory, policy, baseline_paths, secrets_store=secret_store, batch_size=5
    )
    crashed_paths = Paths.for_workspace(tmp_path / "crashed")
    repo_root = Path(__file__).resolve().parents[1]
    # The child reports every committed batch on stdout, so the parent can
    # kill it mid-run without ever touching the checkpoint database (reading
    # it concurrently would starve the child's write transactions).
    child = (
        "from maskline.config import Paths, SecretStore\n"
        "from maskline.policies import load_policy\n"
        "from maskline.registry import inspect_dataset\n"
        "from maskline.pipeline.runner import execute_run\n"
        "from maskline.pipeline.checkpoint import CheckpointStore\n"
        "_orig = CheckpointStore.save_checkpoint\n"
        "def _wrapped(self, *args, **kwargs):\n"
        "    _orig(self, *args, **kwargs)\n"
        "    print('BATCH-COMMITTED', flush=True)\n"
        "CheckpointStore.save_checkpoint = _wrapped\n"
        f"inv = inspect_dataset({str(fixtures['sqlite'])!r})\n"
        f"pol = load_policy({str(EXAMPLE)!r})\n"
        "sec = SecretStore.from_env()\n"
        f"execute_run(inv, pol, Paths.for_workspace({str(crashed_paths.root)!r}),"
        " secrets_store=sec, batch_size=5)\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.Popen(
        [sys.executable, "-c", child], cwd=repo_root, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        # Wait for the third committed batch, then kill the process.
        import select

        deadline = time.monotonic() + 300
        batches = 0
        while batches < 3:
            if time.monotonic() > deadline:
                pytest.fail("child never reached mid-run checkpoints")
            ready, _, _ = select.select([proc.stdout], [], [], 5)
            if not ready:
                if proc.poll() is not None:
                    pytest.fail(f"child exited early: {proc.stdout.read()}")
                continue
            line = proc.stdout.readline()
            if line.strip() == "BATCH-COMMITTED":
                batches += 1
        proc.kill()
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    with CheckpointStore(crashed_paths.checkpoint_db) as store:
        runs = store.list_runs()
        assert len(runs) == 1
        run_id = runs[0].run_id
        assert runs[0].status == "running"  # killed before any status update
    resumed = execute_run(
        inventory, policy, crashed_paths, secrets_store=secret_store,
        batch_size=7, resume_run_id=run_id,
    )
    assert resumed.output_hash == baseline.output_hash
    assert resumed.row_count == baseline.row_count
    assert resumed.transform_counts == baseline.transform_counts
    assert sqlite_content_digest(crashed_paths.pseudomap_db) == sqlite_content_digest(
        baseline_paths.pseudomap_db
    )

def test_corrupt_target_is_rebuilt_on_resume(tmp_path, inventories, secret_store):
    """A target file that no longer opens as SQLite is rebuilt from scratch."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    paths = Paths.for_workspace(tmp_path / "crashed")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    output = paths.out_dir / "demo.masked.sqlite"
    output.write_bytes(b"definitely not a sqlite database" * 200)
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=2)
    assert_same_output(resumed, paths, baseline, baseline_paths)

def test_missing_table_in_target_is_recreated(tmp_path, inventories, secret_store):
    """A target that lost a whole table (torn schema creation in an older
    version) is repaired by the resume reconcile."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    paths = Paths.for_workspace(tmp_path / "crashed")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    output = paths.out_dir / "demo.masked.sqlite"
    conn = sqlite3.connect(output)
    try:
        conn.execute("DROP TABLE orders")
        conn.commit()
    finally:
        conn.close()
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=2)
    assert_same_output(resumed, paths, baseline, baseline_paths)

def test_missing_pseudomap_forces_regeneration(tmp_path, inventories, secret_store):
    """If the mapping database vanishes between interrupt and resume, the
    committed batches' pseudonyms are unrecoverable; resume rebuilds the
    target and regenerates the complete mapping deterministically."""
    baseline, baseline_paths = run_baseline(tmp_path, inventories, secret_store)
    paths = Paths.for_workspace(tmp_path / "crashed")
    run_id = interrupt_run(paths, inventories["sqlite"], secret_store, batch_size=2, after=1)
    paths.pseudomap_db.unlink()
    resumed = resume_run(paths, inventories["sqlite"], secret_store, run_id, batch_size=2)
    assert_same_output(resumed, paths, baseline, baseline_paths)
