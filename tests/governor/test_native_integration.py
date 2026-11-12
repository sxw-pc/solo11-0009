"""End-to-end governance over a REAL maskline masking task.

These tests prove the central safety property of the governor: pausing a
native ``maskline run`` at a quota boundary and resuming it through
``maskline resume --run-id`` produces byte-identical output to an uninterrupted
run, with no duplicate rows and no lost rows.  They exercise the real pipeline
(checkpoints, target DB, pseudomap, audit chain) rather than the fake worker.
"""

from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

from maskline.config import Paths, SecretStore
from maskline.fixturegen import generate_fixture
from maskline.governor.config import GovernorConfig, Quota
from maskline.governor.daemon import Governor
from maskline.governor.resources import ProcResourceSampler
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.registry import inspect_dataset
from maskline.utils import sqlite_content_digest

POLICY = Path(__file__).resolve().parents[2] / "policies" / "example.yaml"


def _table_row_counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {table: conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                for table in tables}
    finally:
        conn.close()


def _drive(governor: Governor, job_id: str, *, max_seconds: float = 60.0) -> None:
    deadline = time.monotonic() + max_seconds
    while time.monotonic() < deadline:
        governor.scheduler.tick()
        job = governor.store.get_job(job_id)
        if job.state in ("completed", "failed", "cancelled"):
            return
        time.sleep(0.05)
    raise AssertionError("job did not finish in time")


def test_native_run_pause_resume_matches_uninterrupted_output(
    tmp_path, secret_file
):
    # A dataset large enough that a short runtime slice cannot finish it in
    # one go, forcing at least one pause + resume cycle.
    raw = tmp_path / "raw"
    fixtures = generate_fixture(raw, seed=3, customers=400, orders=800, leads=100)
    dataset = fixtures["sqlite"]
    policy = load_policy(POLICY)

    # --- Baseline: an ordinary, uninterrupted masking run ----------------
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    baseline = execute_run(
        inspect_dataset(dataset),
        policy,
        baseline_paths,
        secrets_store=SecretStore.from_file(secret_file),
        batch_size=50,
    )
    baseline_counts = _table_row_counts(baseline.output_path)

    # --- Governed run with a deliberately tiny runtime slice -------------
    gov_paths = Paths.for_workspace(tmp_path / "governed")
    gov_paths.ensure_runtime_dirs()
    config = GovernorConfig(
        # The slice quota starts only after the pipeline announces its run
        # id, so warm-up (interpreter load, scan, detection) is excluded.
        # A generous slice lets each attempt do substantial checkpointed work
        # before pausing even on slow CI machines.
        defaults=Quota(cpu_max_percent=100.0, memory_max_mb=4096,
                       max_runtime_seconds=4),
        max_concurrency=1,
        sample_interval_seconds=0.2,
        throttle_stop_seconds=0.05,
        throttle_breach_limit=3,
        resume_cooldown_seconds=0.1,
        max_resume_attempts=30,
        memory_recover_ratio=0.95,
    )
    output = gov_paths.out_dir / "governed.masked.sqlite"
    argv = [
        sys.executable, "-m", "maskline", "run",
        "--dataset", str(dataset),
        "--policy", str(POLICY),
        "--output", str(output),
        "--batch-size", "200",
        "--workspace", str(gov_paths.root),
    ]
    governor = Governor(
        gov_paths, config, sampler=ProcResourceSampler(),
        scheduler_sleeper=lambda _s: None,
    )
    try:
        job_id = governor.submit(
            argv,
            name="native-pause-resume",
            extra_env={"MASKLINE_SECRET_FILE": str(secret_file)},
        ).job_id
        _drive(governor, job_id)
        job = governor.store.get_job(job_id)
        assert job.state == "completed", f"job ended {job.state}: {job.last_error}"
        # The slice boundary must actually have been exercised.
        assert job.runtime_breaches >= 1
        assert job.resume_events >= 1
    finally:
        governor.close()

    # --- Consistency: identical content, no duplicate / missing rows ------
    assert output.exists()
    assert sqlite_content_digest(output) == baseline.output_hash
    assert _table_row_counts(output) == baseline_counts

    # The pipeline's own checkpoint store shows one run, fully completed.
    with CheckpointStore(gov_paths.checkpoint_db) as store:
        run_ids = [row.run_id for row in store.list_runs(limit=10)]
        assert len(run_ids) == 1
        assert store.get_run(run_ids[0]).status == "completed"
