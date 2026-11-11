import errno
import json
import os

import pytest

from maskline import audit as audit_module
from maskline.audit import (
    AuditError,
    AuditIntegrityError,
    AuditLog,
    head_path,
    read_audit_entries,
    verify_audit,
)
from maskline.utils import canonical_json, sha256_text

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

def _rewrite_line(path, index, mutate):
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[index])
    mutate(entry)
    lines[index] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def test_tampering_first_entry_is_located(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    _rewrite_line(path, 0, lambda entry: entry.update(run_id="forged"))
    with pytest.raises(AuditIntegrityError) as excinfo:
        verify_audit(path)
    assert excinfo.value.line == 1
    assert "hash" in str(excinfo.value)

def test_tampering_last_entry_is_located(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    _rewrite_line(path, 2, lambda entry: entry.update(rows_processed=12345))
    with pytest.raises(AuditIntegrityError) as excinfo:
        verify_audit(path)
    assert excinfo.value.line == 3
    assert "hash" in str(excinfo.value)

def test_deleting_first_entry_is_located(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError) as excinfo:
        verify_audit(path)
    assert excinfo.value.line == 1
    assert "seq" in str(excinfo.value)

def test_deleting_middle_entry_is_located(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError) as excinfo:
        verify_audit(path)
    assert excinfo.value.line == 2
    assert "seq" in str(excinfo.value)

def test_deleting_multiple_tail_entries_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="head anchor"):
        verify_audit(path)

def test_head_anchor_tampering_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    head_path(path).write_text(
        json.dumps({"count": 3, "last_hash": "0" * 64}) + "\n", encoding="utf-8"
    )
    with pytest.raises(AuditIntegrityError, match="head anchor"):
        verify_audit(path)

def test_recomputed_chain_without_anchor_update_is_detected(tmp_path):
    # An attacker who rewrites history must recompute every subsequent hash;
    # the head anchor still gives the forgery away.
    path = tmp_path / "audit.jsonl"
    append_three(path)
    entries = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    entries[0]["rows_processed"] = 777
    previous = "0" * 64
    forged = []
    for index, entry in enumerate(entries, start=1):
        entry.pop("entry_hash", None)
        entry["seq"] = index
        entry["prev_hash"] = previous
        entry["entry_hash"] = sha256_text(canonical_json(entry))
        previous = entry["entry_hash"]
        forged.append(canonical_json(entry))
    path.write_text("\n".join(forged) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="head anchor"):
        verify_audit(path)

def test_verify_flags_unterminated_final_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    data = path.read_bytes()
    assert data.endswith(b"\n")
    path.write_bytes(data[:-1])
    with pytest.raises(AuditIntegrityError, match="newline-terminated"):
        verify_audit(path)

def test_append_failure_leaves_log_and_anchor_untouched(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    log = append_three(path)
    log_before = path.read_bytes()
    head_before = head_path(path).read_bytes()

    def no_space(fd):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(audit_module.os, "fsync", no_space)
    with pytest.raises(AuditError, match="cannot append"):
        log.append({"run_id": "run-blocked"})
    monkeypatch.undo()
    assert path.read_bytes() == log_before
    assert head_path(path).read_bytes() == head_before
    # disk recovered: appending works again and the chain stays intact
    log.append({"run_id": "run-4"})
    assert verify_audit(path).entries == 4

def test_head_write_failure_rolls_back_the_entry(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    log = append_three(path)
    log_before = path.read_bytes()

    def no_space(target, text, mode=None):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(audit_module, "atomic_write_text", no_space)
    with pytest.raises(AuditError, match="head anchor"):
        log.append({"run_id": "run-blocked"})
    monkeypatch.undo()
    assert path.read_bytes() == log_before
    log.append({"run_id": "run-4"})
    assert verify_audit(path).entries == 4

def test_append_reanchors_after_crash_between_entry_and_head(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    log = append_three(path)

    def crash(count, last_hash):
        raise SystemExit(1)

    monkeypatch.setattr(AuditLog, "_write_head", lambda self, c, h: crash(c, h))
    with pytest.raises(SystemExit):
        log.append({"run_id": "run-crashed"})
    monkeypatch.undo()
    # the entry is durable but the anchor still points at entry 3
    with pytest.raises(AuditIntegrityError, match="head anchor"):
        verify_audit(path)
    with pytest.warns(RuntimeWarning, match="head anchor"):
        stored = AuditLog(path).append({"run_id": "run-5"})
    assert stored["seq"] == 5
    assert verify_audit(path).entries == 5

def test_append_truncates_corrupt_tail_from_interrupted_write(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"run_id": "partial", "seq": 4, "prev_')
    with pytest.raises(AuditIntegrityError):
        verify_audit(path)
    with pytest.warns(RuntimeWarning, match="corrupt tail"):
        stored = AuditLog(path).append({"run_id": "run-4"})
    assert stored["seq"] == 4
    assert verify_audit(path).entries == 4

def test_append_refuses_corrupt_middle_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1][:40]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        AuditLog(path).append({"run_id": "run-x"})
    assert path.read_text(encoding="utf-8").splitlines()[1] == lines[1]

def test_append_refuses_when_head_anchor_is_missing(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    head_path(path).unlink()
    with pytest.raises(AuditIntegrityError, match="head anchor"):
        AuditLog(path).append({"run_id": "run-x"})
    with pytest.raises(AuditIntegrityError, match="head anchor"):
        verify_audit(path)

def test_append_refuses_after_log_truncation(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_three(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="head anchor"):
        AuditLog(path).append({"run_id": "run-x"})

def test_entries_in_the_original_format_still_verify(tmp_path):
    # Reproduce the v0.1.0 writer byte-for-byte: same canonical JSON, same
    # hash chain, same anchor file. New code must accept old logs as-is.
    path = tmp_path / "audit.jsonl"
    previous = "0" * 64
    lines = []
    for index in range(3):
        body = {
            "run_id": f"legacy-{index}",
            "rows_processed": index + 1,
            "ts": "2024-05-13T08:00:00+00:00",
            "seq": index + 1,
            "prev_hash": previous,
        }
        body["entry_hash"] = sha256_text(canonical_json(body))
        previous = body["entry_hash"]
        lines.append(canonical_json(body))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    head_path(path).write_text(
        json.dumps({"count": 3, "last_hash": previous}, sort_keys=True,
                   separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    verification = verify_audit(path)
    assert verification.entries == 3
    stored = AuditLog(path).append({"run_id": "new-after-upgrade"})
    assert stored["seq"] == 4
    assert stored["prev_hash"] == previous
    assert verify_audit(path).entries == 4
