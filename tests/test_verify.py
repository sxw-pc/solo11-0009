from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from maskline.__main__ import main
from maskline.audit import AuditLog, read_audit_entries
from maskline.config import Paths
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.manifest import manifest_path
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.utils import file_sha256
from maskline.verify import VerifyError, verify_run
from maskline.workflow import finalize_run

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _completed_run(workspace, inventory, secret_store, batch_size=2, policy=None):
    policy = policy or load_policy(EXAMPLE)
    result = execute_run(
        inventory, policy, workspace, secrets_store=secret_store, batch_size=batch_size
    )
    finalize_run(workspace, inventory, policy, result, [])
    return result


def _execute(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def _cli(workspace, run_id):
    return main(["verify", "--workspace", str(workspace.root), "--run-id", run_id])


def test_verify_ok_after_clean_run(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert report.ok and not report.degraded
    assert report.tables_checked == 2
    assert report.batches_checked > 0
    assert report.rows_checked == 15
    assert report.audit_appended


def test_verify_cli_ok(workspace, inventories, secret_store, capsys):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    assert _cli(workspace, result.run_id) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK")
    assert "degraded=False" in out


def test_verify_detects_single_row_tamper(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    _execute(
        result.output_path,
        "UPDATE customers SET email = 'tampered@example.com' WHERE rowid = 3",
    )
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    tamper = [
        m for m in report.mismatches
        if m.scope == "target" and m.table == "customers" and m.batch is not None
    ]
    assert tamper, "expected a batch-level checksum mismatch for customers"
    assert tamper[0].batch == 1  # batch_size=2 -> rowid 3 lives in the second batch
    assert "checksum" in tamper[0].message
    assert _cli(workspace, result.run_id) == 1


def test_verify_detects_row_delete(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    _execute(result.output_path, "DELETE FROM customers WHERE rowid = 3")
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    assert any(
        m.table == "customers" and "row count" in m.message for m in report.mismatches
    )


def test_verify_detects_extra_row_outside_batches(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    _execute(
        result.output_path,
        "INSERT INTO customers (customer_id, full_name, phone, email, id_card, "
        "bank_card, address, birth_date, age, balance, status, notes) "
        "SELECT 999, full_name, phone, email, id_card, bank_card, address, "
        "birth_date, age, balance, status, notes FROM customers WHERE customer_id = 1",
    )
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    assert any(
        m.table == "customers" and "outside the recorded batches" in m.message
        for m in report.mismatches
    )


def test_verify_detects_pseudomap_deletion(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    _execute(
        workspace.pseudomap_db,
        "DELETE FROM pseudonym_map WHERE token IN "
        "(SELECT token FROM pseudonym_map LIMIT 2)",
    )
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    assert any(
        m.scope == "pseudomap" and "lost" in m.message for m in report.mismatches
    )
    assert _cli(workspace, result.run_id) == 1


def test_verify_detects_pseudomap_substitution(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    _execute(
        workspace.pseudomap_db,
        "UPDATE pseudonym_map SET plaintext = 'attacker@example.com' "
        "WHERE token = (SELECT token FROM pseudonym_map LIMIT 1)",
    )
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    assert any(
        m.scope == "pseudomap" and "digest" in m.message for m in report.mismatches
    )


def test_verify_degraded_without_secret(workspace, inventories, secret_store, monkeypatch, capsys):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    monkeypatch.delenv("MASKLINE_SECRET_FILE")
    report = verify_run(workspace, result.run_id, secrets_store=None)
    assert report.ok and report.degraded and report.degraded_reason
    assert _cli(workspace, result.run_id) == 0
    captured = capsys.readouterr()
    assert "OK (degraded)" in captured.out
    assert "WARNING" in captured.err
    entries = read_audit_entries(workspace.audit_path)
    assert entries[-1]["event"] == "verify"
    assert entries[-1]["result"] == "ok_degraded"
    assert entries[-1]["degraded"] is True


def test_verify_appends_audit_event(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    before = len(read_audit_entries(workspace.audit_path))
    verify_run(workspace, result.run_id, secrets_store=secret_store)
    entries = read_audit_entries(workspace.audit_path)
    assert len(entries) == before + 1
    assert entries[-1]["event"] == "verify"
    assert entries[-1]["run_id"] == result.run_id
    assert entries[-1]["result"] == "ok"
    # The chain, including the new verify event, still verifies.
    AuditLog(workspace.audit_path).verify()


def test_verify_failure_is_also_audited(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    _execute(result.output_path, "DELETE FROM orders WHERE rowid = 1")
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    entries = read_audit_entries(workspace.audit_path)
    assert entries[-1]["event"] == "verify"
    assert entries[-1]["result"] == "failed"
    assert entries[-1]["mismatch_count"] == len(report.mismatches)


def test_verify_unknown_run_id(workspace, inventories, secret_store, capsys):
    _completed_run(workspace, inventories["sqlite"], secret_store)
    with pytest.raises(VerifyError, match="unknown run id"):
        verify_run(workspace, "run-20990101-000000-ffffff", secrets_store=secret_store)
    assert _cli(workspace, "run-20990101-000000-ffffff") == 2


def test_verify_rejects_unfinished_run(tmp_path, inventories, secret_store):
    paths = Paths.for_workspace(tmp_path / "ws")
    policy = load_policy(EXAMPLE)
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    with pytest.raises(VerifyError, match="only completed runs"):
        verify_run(paths, excinfo.value.run_id, secrets_store=secret_store)


def test_verify_resumed_run(tmp_path, inventories, secret_store):
    paths = Paths.for_workspace(tmp_path / "ws")
    policy = load_policy(EXAMPLE)
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    run_id = excinfo.value.run_id
    resumed = execute_run(
        inventories["sqlite"], policy, paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    finalize_run(paths, inventories["sqlite"], policy, resumed, [])
    report = verify_run(paths, run_id, secrets_store=secret_store)
    assert report.ok
    assert report.rows_checked == 15


def test_verify_unkeyed_run_needs_no_secret(workspace, inventories, make_policy):
    policy = make_policy(
        """
        version: 1
        name: no-secret
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  phone:
                    transformer: mask
                    params: {keep_prefix: 2, keep_suffix: 2}
        """
    )
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=None)
    assert result.checksum_mode == "sha256"
    finalize_run(workspace, inventories["sqlite"], policy, result, [])
    report = verify_run(workspace, result.run_id, secrets_store=None)
    assert report.ok and not report.degraded


def test_verify_csv_run(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["csv"], secret_store)
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert report.ok
    assert report.rows_checked == 3


def test_verify_manifest_superseded_by_later_run(workspace, inventories, secret_store, capsys):
    first = _completed_run(workspace, inventories["sqlite"], secret_store)
    _completed_run(workspace, inventories["sqlite"], secret_store)
    with pytest.raises(VerifyError, match="latest run"):
        verify_run(workspace, first.run_id, secrets_store=secret_store)
    assert _cli(workspace, first.run_id) == 2


def test_verify_detects_audit_tamper(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    lines = workspace.audit_path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"rows_processed":15', '"rows_processed":14', 1)
    workspace.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    assert any(m.scope == "audit" for m in report.mismatches)
    assert not report.audit_appended  # cannot append to a broken chain


def test_verify_is_read_only_on_databases(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    before = {
        path: file_sha256(path)
        for path in sorted(workspace.root.rglob("*"))
        if path.is_file()
    }
    verify_run(workspace, result.run_id, secrets_store=secret_store)
    after = {
        path: file_sha256(path)
        for path in sorted(workspace.root.rglob("*"))
        if path.is_file()
    }
    assert set(after) == set(before), "verify must not create or delete files"
    changed = {path for path in before if before[path] != after[path]}
    assert {path.name for path in changed} <= {"audit.jsonl", "audit.jsonl.head"}
    assert result.output_path not in changed
    assert workspace.pseudomap_db not in changed
    assert workspace.checkpoint_db not in changed


def test_verify_missing_target_database(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    result.output_path.unlink()
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    assert any(
        m.scope == "target" and "missing" in m.message for m in report.mismatches
    )


def test_verify_missing_manifest(workspace, inventories, secret_store):
    result = _completed_run(workspace, inventories["sqlite"], secret_store)
    manifest_path(workspace.manifest_dir, result.dataset_fingerprint).unlink()
    report = verify_run(workspace, result.run_id, secrets_store=secret_store)
    assert not report.ok
    assert any(m.scope == "manifest" for m in report.mismatches)
