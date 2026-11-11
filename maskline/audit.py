"""Append-only JSONL audit log with a tamper-evident hash chain.

Storage format (unchanged since v0.1.0): one canonical-JSON object per line,
each entry carrying ``seq``, ``prev_hash`` and ``entry_hash``; a sibling
``.head`` anchor file records ``{"count": N, "last_hash": H}`` so that tail
truncation cannot go unnoticed.

Failure handling:

- Appends are all-or-nothing. A failed write/fsync rolls the log back to its
  previous size, and if the head anchor cannot be persisted the just-written
  entry is rolled back too, so a full disk never leaves the chain broken.
- ``verify_audit`` is strict: any modified, deleted or reordered entry, a
  corrupt or unterminated final line, and any head-anchor mismatch is
  reported with its line number.
- ``append`` repairs *crash artifacts only* before chaining a new entry: a
  corrupt or unterminated final line (interrupted write) is truncated, and a
  head anchor that is a strict prefix of an otherwise fully valid chain
  (crash between the entry fsync and the anchor rewrite) is re-anchored
  forward. Anything that looks like tampering — damage in the middle of the
  log, a missing anchor, or an anchor proving the log was truncated — still
  refuses to append.
"""

from __future__ import annotations

import json
import os
import warnings
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
            try:
                verification = verify_audit(self.path)
            except AuditIntegrityError as exc:
                verification = self._recover(exc)
            previous_hash = verification.head_hash
            sequence = verification.entries + 1
        body = dict(entry)
        body.pop("entry_hash", None)
        body.pop("prev_hash", None)
        body.setdefault("ts", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        body["seq"] = sequence
        body["prev_hash"] = previous_hash
        entry_hash = sha256_text(canonical_json(body))
        stored = dict(body)
        stored["entry_hash"] = entry_hash
        offset = self._append_line(canonical_json(stored) + "\n")
        try:
            self._write_head(sequence, entry_hash)
        except OSError as exc:
            # The entry must not outlive its anchor: roll the line back so the
            # log returns to the exact state the current head vouches for.
            self._rollback_line(offset)
            raise AuditError(
                f"cannot update the audit head anchor {head_path(self.path)}: {exc}"
            ) from exc
        return stored

    def verify(self) -> AuditVerification:
        return verify_audit(self.path)

    def _append_line(self, text: str) -> int:
        """Append one line all-or-nothing; return the offset it started at."""
        data = text.encode("utf-8")
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        offset: int | None = None
        try:
            offset = os.lseek(fd, 0, os.SEEK_END)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write while appending the audit entry")
                view = view[written:]
            os.fsync(fd)
        except BaseException as exc:
            if offset is not None:
                self._rollback_line(offset)
            if isinstance(exc, OSError):
                raise AuditError(
                    f"cannot append to audit log {self.path}: {exc}"
                ) from exc
            raise
        finally:
            os.close(fd)
        return offset

    def _rollback_line(self, offset: int) -> None:
        """Best-effort truncation back to ``offset`` after a failed append."""
        try:
            _truncate_file(self.path, offset)
        except OSError as exc:
            # The chain stays consistent: the stale tail is either still
            # covered by the current head or repaired by the next append.
            warnings.warn(
                f"could not roll back the failed audit append in {self.path}: "
                f"{exc}; the next append will repair the log",
                RuntimeWarning,
                stacklevel=2,
            )

    def _write_head(self, count: int, last_hash: str) -> None:
        payload = {"count": count, "last_hash": last_hash}
        atomic_write_text(
            head_path(self.path),
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
            mode=0o600,
        )

    def _recover(self, error: AuditIntegrityError) -> AuditVerification:
        """Repair crash artifacts; re-raise ``error`` for anything else.

        Only two states are recoverable, because only they can be produced by
        an interrupted write rather than by tampering: a corrupt/unterminated
        final line, and a head anchor that lags behind a fully valid chain
        while exactly matching one of its prefixes. Nothing is mutated until
        every check has passed.
        """
        raw = self.path.read_bytes()
        lines = raw.split(b"\n")
        terminated = raw.endswith(b"\n")
        if terminated:
            lines = lines[:-1]  # drop the empty segment after the final newline
        entries: list[dict[str, Any]] = []
        corrupt_index: int | None = None
        for index, line in enumerate(lines):
            item: Any = None
            if line.strip():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    item = None
            if not isinstance(item, dict):
                corrupt_index = index
                break
            entries.append(item)
        truncated = False
        if corrupt_index is not None:
            if corrupt_index != len(lines) - 1:
                raise error  # damage beyond the final line: tampering
            truncated = True
        elif not terminated:
            # The final line parsed but lacks its newline terminator.
            entries = entries[:-1]
            truncated = True
        if truncated and not entries:
            raise error  # never recover by emptying the log
        try:
            verification = _verify_entries(entries)
        except AuditIntegrityError:
            raise error from None  # chain damage is tampering, not a crash
        count = verification.entries
        final_hash = verification.head_hash
        head = _read_head(head_path(self.path))
        reanchor = False
        if head is None:
            raise error  # cannot rule out truncation without the anchor
        head_count = head.get("count")
        head_hash = head.get("last_hash")
        if (
            not isinstance(head_count, int)
            or isinstance(head_count, bool)
            or not isinstance(head_hash, str)
        ):
            raise error
        if head_count == count and head_hash == final_hash:
            pass  # already consistent; only the tail needed truncation
        elif head_count > count:
            raise error  # the anchor proves entries were deleted
        elif head_count < 1 or entries[head_count - 1].get("entry_hash") != head_hash:
            raise error  # the anchor matches no prefix of the chain
        else:
            reanchor = True  # crash between the entry fsync and the anchor write
        if truncated:
            new_size = sum(len(line) + 1 for line in lines[:count])
            try:
                _truncate_file(self.path, new_size)
            except OSError as exc:
                raise AuditError(
                    f"cannot remove the corrupt tail of {self.path}: {exc}"
                ) from exc
            warnings.warn(
                f"audit log {self.path}: removed corrupt tail at line "
                f"{count + 1} left by an interrupted write",
                RuntimeWarning,
                stacklevel=3,
            )
        if reanchor:
            try:
                self._write_head(count, final_hash)
            except OSError as exc:
                raise AuditError(
                    f"cannot re-anchor the audit head at {head_path(self.path)}: {exc}"
                ) from exc
            warnings.warn(
                f"audit log {self.path}: head anchor re-written for {count} "
                f"entries after an interrupted write",
                RuntimeWarning,
                stacklevel=3,
            )
        return verification


def _truncate_file(path: Path, size: int) -> None:
    fd = os.open(path, os.O_WRONLY)
    try:
        os.ftruncate(fd, size)
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_head(anchor: Path) -> dict[str, Any] | None:
    try:
        head = json.loads(anchor.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return head if isinstance(head, dict) else None


def _verify_entries(entries: list[dict[str, Any]]) -> AuditVerification:
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
    return AuditVerification(entries=len(entries), head_hash=previous)


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
    if not entries:
        raise AuditError("audit log is empty")
    verification = _verify_entries(entries)
    with log_path.open("rb") as fh:
        fh.seek(-1, os.SEEK_END)
        if fh.read(1) != b"\n":
            raise AuditIntegrityError(
                len(entries),
                "final line is not newline-terminated; possible partial write "
                "from an interrupted process",
            )
    anchor = head_path(log_path)
    if not anchor.exists():
        raise AuditIntegrityError(
            len(entries), "head anchor is missing; cannot rule out truncation"
        )
    head = _read_head(anchor)
    if head is None:
        raise AuditIntegrityError(len(entries), "head anchor is unreadable")
    if head.get("count") != len(entries) or head.get("last_hash") != verification.head_hash:
        raise AuditIntegrityError(
            len(entries), "head anchor does not match the final chained entry"
        )
    return verification


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
