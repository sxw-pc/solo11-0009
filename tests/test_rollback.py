"""Audit-failure rollback and long-run chain stability, end to end."""

import errno
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from maskline import audit as audit_module
from maskline.audit import AuditError, verify_audit
from maskline.config import Paths
from maskline.fixturegen import generate_fixture
from maskline.pipeline import runner as runner_module
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.registry import inspect_dataset
from maskline.utils import sqlite_content_digest
from maskline.workflow import finalize_run, scan_paths

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
ROOT = Path(__file__).resolve().parents[1]


def _only_run_status(paths):
    with CheckpointStore(paths.checkpoint_db) as store:
        runs = store.list_runs(limit=5)
        assert len(runs) == 1
        return runs[0].status


def test_audit_write_failure_rolls_back_the_whole_run(
    workspace, inventories, secret_store, monkeypatch
):
    policy = load_policy(EXAMPLE)
    source = inventories["sqlite"].path
    source_hash = sqlite_content_digest(source)
    output = workspace.out_dir / "demo.masked.sqlite"

    def no_space(fd):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(audit_module.os, "fsync", no_space)
    with pytest.raises(AuditError):
        execute_run(
            inventories["sqlite"], policy, workspace, secrets_store=secret_store
        )
    monkeypatch.undo()

    # the task rolled back: no target database, no manifest, no report,
    # no audit entry, and the source database is byte-identical
    assert not output.exists()
    assert not list(workspace.manifest_dir.glob("*.json"))
    assert not list(workspace.reports_dir.glob("*"))
    assert sqlite_content_digest(source) == source_hash
    assert _only_run_status(workspace) == "failed"
    assert (
        not workspace.audit_path.exists()
        or workspace.audit_path.stat().st_size == 0
    )

    # disk recovered: the pipeline runs again and the chain starts cleanly
    result = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store
    )
    finalize_run(workspace, inventories["sqlite"], policy, result, [])
    verification = verify_audit(workspace.audit_path)
    assert verification.entries == 1
    assert result.audit_entry["seq"] == 1
    assert output.exists()


def test_head_anchor_write_failure_rolls_back_the_run(
    workspace, inventories, secret_store, monkeypatch
):
    policy = load_policy(EXAMPLE)
    output = workspace.out_dir / "demo.masked.sqlite"

    def no_space(target, text, mode=None):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(audit_module, "atomic_write_text", no_space)
    with pytest.raises(AuditError, match="head anchor"):
        execute_run(
            inventories["sqlite"], policy, workspace, secrets_store=secret_store
        )
    monkeypatch.undo()

    assert not output.exists()
    assert _only_run_status(workspace) == "failed"
    # the failed append was rolled back too: no unanchored entry is left
    assert (
        not workspace.audit_path.exists()
        or workspace.audit_path.stat().st_size == 0
    )

    result = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store
    )
    finalize_run(workspace, inventories["sqlite"], policy, result, [])
    assert verify_audit(workspace.audit_path).entries == 1


def test_partial_output_is_removed_when_a_run_fails(
    workspace, inventories, secret_store, monkeypatch
):
    policy = load_policy(EXAMPLE)
    output = workspace.out_dir / "demo.masked.sqlite"

    def no_space(*args, **kwargs):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(runner_module, "insert_batch", no_space)
    with pytest.raises(OSError):
        execute_run(
            inventories["sqlite"], policy, workspace, secrets_store=secret_store
        )
    assert not output.exists()
    assert _only_run_status(workspace) == "failed"
    # the failed run left no audit entry behind
    assert not workspace.audit_path.exists()


def test_twenty_consecutive_pipeline_runs_keep_the_chain_intact(
    workspace, fixture_files, secret_store
):
    policy = load_policy(EXAMPLE)
    summaries = scan_paths([fixture_files["csv"]], workspace)
    inventory = summaries[0].inventory
    findings = summaries[0].findings
    for expected in range(1, 21):
        result = execute_run(
            inventory, policy, workspace, secrets_store=secret_store
        )
        finalize_run(workspace, inventory, policy, result, findings)
        verification = verify_audit(workspace.audit_path)
        assert verification.entries == expected
        assert result.audit_entry["seq"] == expected
    entries = [
        line for line in workspace.audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(entries) == 20


def test_sigkill_mid_run_leaves_chain_intact_and_resumable(tmp_path, secret_store):
    """A process dying mid-run must not break the audit chain, and the
    killed run must resume to the same output as an uninterrupted one."""
    fixture = generate_fixture(
        tmp_path / "raw", seed=11, customers=40, orders=80, leads=10
    )
    killed = Paths.for_workspace(tmp_path / "killed")
    suicide_script = f"""
import os, sys
sys.path.insert(0, {str(ROOT)!r})
from maskline.config import Paths
from maskline.policies import load_policy
from maskline.registry import inspect_dataset
from maskline.pipeline import runner
_calls = {{"n": 0}}
_real_insert = runner.insert_batch
def _suicide(*args, **kwargs):
    _calls["n"] += 1
    if _calls["n"] >= 3:
        os._exit(1)  # hard death: no cleanup, no status update
    return _real_insert(*args, **kwargs)
runner.insert_batch = _suicide
from maskline.config import SecretStore
paths = Paths.for_workspace({str(killed.root)!r})
inventory = inspect_dataset({str(fixture["sqlite"])!r})
policy = load_policy({str(EXAMPLE)!r})
runner.execute_run(inventory, policy, paths, batch_size=5,
                   secrets_store=SecretStore.from_env())
"""
    proc = subprocess.run(
        [sys.executable, "-c", suicide_script],
        env={**os.environ, "MASKLINE_SECRET_FILE": os.environ["MASKLINE_SECRET_FILE"]},
        capture_output=True,
    )
    assert proc.returncode == 1

    # the crash happened before the commit point: no audit entry, but any
    # pre-existing chain is untouched; the run is still marked "running"
    with CheckpointStore(killed.checkpoint_db) as store:
        runs = store.list_runs(limit=1)
        assert len(runs) == 1 and runs[0].status == "running"
        run_id = runs[0].run_id
    assert not killed.audit_path.exists()

    # the killed run resumes and completes with its audit entry appended
    policy = load_policy(EXAMPLE)
    inventory = inspect_dataset(fixture["sqlite"])
    resumed = execute_run(
        inventory, policy, killed,
        secrets_store=secret_store, batch_size=5, resume_run_id=run_id,
    )
    assert resumed.audit_entry["seq"] == 1
    verification = verify_audit(killed.audit_path)
    assert verification.entries == 1

    # and it matches an uninterrupted baseline run
    baseline = Paths.for_workspace(tmp_path / "baseline")
    clean = execute_run(inventory, policy, baseline, secrets_store=secret_store, batch_size=5)
    assert resumed.output_hash == clean.output_hash
    assert verify_audit(baseline.audit_path).entries == 1
