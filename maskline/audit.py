"""Append-only JSONL audit log with a tamper-evident hash chain."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .utils import MasklineError, atomic_write_text, canonical_json, sha256_text

GENESIS_HASH = "0" * 64


class AuditError(MasklineError):
    pass


class AuditIntegrityError(AuditError):

    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"audit chain invalid at line {line}: {message}")
        self.line = line


@dataclass(frozen=True)
class AuditVerification:
    entries: int
    head_hash: str


def head_path(log_path: Path) -> Path:
    return log_path.with_name(log_path.name + ".head")


class AuditLog:

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, entry: dict[str, Any]) -> dict[str, Any]:
        previous_hash = GENESIS_HASH
        sequence = 1
        if self.path.exists() and self.path.stat().st_size > 0:
            verification = self.verify()
            entries = read_audit_entries(self.path)
            previous_hash = verification.head_hash
            sequence = len(entries) + 1
        body = dict(entry)
        body.pop("entry_hash", None)
        body.pop("prev_hash", None)
        body.setdefault("ts", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        body["seq"] = sequence
        body["prev_hash"] = previous_hash
        entry_hash = sha256_text(canonical_json(body))
        stored = dict(body)
        stored["entry_hash"] = entry_hash
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(canonical_json(stored) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._write_head(sequence, entry_hash)
        return stored

    def verify(self) -> AuditVerification:
        return verify_audit(self.path)

    def _write_head(self, count: int, last_hash: str) -> None:
        payload = {"count": count, "last_hash": last_hash}
        atomic_write_text(
            head_path(self.path),
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            mode=0o600,
        )


def read_audit_entries(path: str | Path) -> list[dict[str, Any]]:
    log_path = Path(path)
    if not log_path.exists():
        return []
    entries: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            if not line.strip():
                raise AuditIntegrityError(line_number, "blank line in audit log")
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditIntegrityError(line_number, f"invalid JSON: {exc.msg}") from exc
            if not isinstance(item, dict):
                raise AuditIntegrityError(line_number, "entry is not a JSON object")
            entries.append(item)
    return entries


def verify_audit(path: str | Path) -> AuditVerification:
    log_path = Path(path)
    if not log_path.exists():
        raise AuditError(f"audit log not found: {log_path}")
    entries = read_audit_entries(log_path)
    previous = GENESIS_HASH
    for line_number, entry in enumerate(entries, start=1):
        if entry.get("seq") != line_number:
            raise AuditIntegrityError(
                line_number, f"expected seq {line_number}, found {entry.get('seq')!r}"
            )
        if entry.get("prev_hash") != previous:
            raise AuditIntegrityError(line_number, "previous hash does not match")
        claimed = entry.get("entry_hash")
        if not isinstance(claimed, str) or len(claimed) != 64:
            raise AuditIntegrityError(line_number, "missing or malformed entry_hash")
        payload = {key: value for key, value in entry.items() if key != "entry_hash"}
        expected = sha256_text(canonical_json(payload))
        if claimed != expected:
            raise AuditIntegrityError(line_number, "entry hash does not match content")
        previous = claimed
    if not entries:
        raise AuditError("audit log is empty")
    anchor = head_path(log_path)
    if not anchor.exists():
        raise AuditIntegrityError(
            len(entries), "head anchor is missing; cannot rule out truncation"
        )
    try:
        head = json.loads(anchor.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditIntegrityError(len(entries), "head anchor is unreadable") from exc
    if head.get("count") != len(entries) or head.get("last_hash") != previous:
        raise AuditIntegrityError(
            len(entries), "head anchor does not match the final chained entry"
        )
    return AuditVerification(entries=len(entries), head_hash=previous)


def build_audit_entry(
    result: Any,
    rule_columns: dict[str, dict[str, str]],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Turn a RunResult plus applied columns into one audit record."""
    entry: dict[str, Any] = {
        "run_id": result.run_id,
        "dataset_path": str(result.dataset_path),
        "dataset_fingerprint": result.dataset_fingerprint,
        "policy_name": result.policy_name,
        "policy_fingerprint": result.policy_fingerprint,
        "columns": rule_columns,
        "rows_processed": result.row_count,
        "transform_counts": result.transform_counts,
        "output_path": str(result.output_path) if result.output_path else None,
        "output_hash": result.output_hash,
        "elapsed_seconds": round(result.elapsed_seconds, 6),
    }
    if extra:
        entry.update(extra)
    return entry
