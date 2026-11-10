import json

import pytest

from maskline.audit import (
    AuditError,
    AuditIntegrityError,
    AuditLog,
    head_path,
    read_audit_entries,
    verify_audit,
)

def append_three(log_path):
    log = AuditLog(log_path)
    for index in range(3):
        log.append(
            {
                "run_id": f"run-{index}",
                "rows_processed": index + 1,
                "output_hash": str(index) * 64,
            }
        )
    return log

def test_append_builds_chain_and_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    entries = read_audit_entries(path)
    assert [entry["seq"] for entry in entries] == [1, 2, 3]
    assert entries[0]["prev_hash"] == "0" * 64
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    verification = verify_audit(path)
    assert verification.entries == 3
    assert verification.head_hash == entries[-1]["entry_hash"]
    assert json.loads(head_path(path).read_text())["count"] == 3

def test_tampering_middle_entry_is_located(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["rows_processed"] = 999
    lines[1] = json.dumps(second, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError) as excinfo:
        verify_audit(path)
    assert excinfo.value.line == 2
    assert "hash" in str(excinfo.value)

def test_truncation_is_detected_by_head_anchor(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="head anchor"):
        verify_audit(path)

def test_append_refuses_tampered_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = append_three(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"rows_processed":1', '"rows_processed":7')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        log.append({"run_id": "new"})

def test_missing_or_empty_log_errors(tmp_path):
    with pytest.raises(AuditError):
        verify_audit(tmp_path / "missing.jsonl")
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    with pytest.raises(AuditError, match="empty"):
        verify_audit(path)
