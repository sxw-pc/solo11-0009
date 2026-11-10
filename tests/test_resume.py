import sqlite3
from pathlib import Path

import pytest

from maskline.config import Paths
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineError, PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.utils import sqlite_content_digest

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"

def table_rows(path, table):
    conn = sqlite3.connect(path)
    try:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
        select = ", ".join(f'"{name}"' for name in columns)
        return conn.execute(f'SELECT rowid, {select} FROM "{table}" ORDER BY rowid').fetchall()
    finally:
        conn.close()

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
