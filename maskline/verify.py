"""Post-delivery integrity verification for completed runs.

``verify`` re-reads the target database and the pseudonym mapping database
strictly read-only (SQLite ``mode=ro`` + ``PRAGMA query_only``), streams each
table batch by batch, recomputes the per-batch row counts and checksums
recorded in the run manifest, cross-checks the pseudonym mapping count against
the run's completion event in the audit chain, and appends its own outcome as
a new audit event. It never writes to the target, mapping, or checkpoint
databases and never creates temporary files.

Exit-code contract (enforced by the CLI): 0 = all performed checks passed
(possibly degraded), 1 = at least one inconsistency was detected,
2 = verification could not be performed (unknown run, run not completed,
superseded or pre-checksum manifest, invalid secret file, ...).

Degraded mode: when the run's checksums are keyed (``hmac-sha256``) but no
secret file is available, content checksums cannot be recomputed. Following
the documented trade-off, verification then degrades to row counts, schema
structure, evidence consistency, and the mapping count check, and the result
is prominently marked degraded instead of failing outright. In degraded mode,
in-place value edits that preserve row counts are NOT detectable.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditLog, AuditError, read_audit_entries
from .config import Paths, SecretStore
from .integrity import (
    CHECKSUM_HMAC,
    CHECKSUM_PLAIN,
    StreamChecksum,
    batch_checksum_header,
    derive_verify_key,
    pseudomap_checksum_header,
)
from .pipeline.manifest import manifest_path
from .utils import MasklineError, quote_ident, read_json, sqlite_connect_readonly


class VerifyError(MasklineError):
    """Operational problems that prevent verification from running (exit 2)."""


@dataclass
class VerifyMismatch:
    scope: str  # target | pseudomap | audit | manifest | metadata
    message: str
    table: str | None = None
    batch: int | None = None

    def describe(self) -> str:
        location = ""
        if self.table is not None:
            location += f' table="{self.table}"'
            if self.batch is not None:
                location += f" batch={self.batch}"
        return f"[{self.scope}]{location} {self.message}"


@dataclass
class VerifyReport:
    run_id: str
    degraded: bool = False
    degraded_reason: str | None = None
    checks: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    mismatches: list[VerifyMismatch] = field(default_factory=list)
    tables_checked: int = 0
    batches_checked: int = 0
    rows_checked: int = 0
    audit_appended: bool = False
    audit_seq: int | None = None

    @property
    def ok(self) -> bool:
        return not self.mismatches

    @property
    def result_label(self) -> str:
        if self.mismatches:
            return "failed"
        return "ok_degraded" if self.degraded else "ok"


def verify_run(
    paths: Paths, run_id: str, secrets_store: SecretStore | None = None
) -> VerifyReport:
    """Verify one completed run; never mutates the target or mapping databases."""
    record = _load_run_record(paths, run_id)
    if record["status"] != "completed":
        raise VerifyError(
            f"run {run_id} has status {record['status']!r}; "
            "only completed runs can be verified"
        )
    report = VerifyReport(run_id=run_id)
    manifest = _load_manifest(paths, record, report)
    entries, chain_ok = _check_audit_chain(paths, report)
    event = _find_completion_event(entries, run_id, report) if entries else None
    if manifest is not None:
        mode = manifest.get("checksum_mode", "")
        if mode not in (CHECKSUM_HMAC, CHECKSUM_PLAIN):
            raise VerifyError(f"unknown checksum_mode in manifest: {mode!r}")
        verify_key: bytes | None = None
        if mode == CHECKSUM_HMAC:
            if secrets_store is None:
                report.degraded = True
                report.degraded_reason = (
                    "secret file not provided; batch content checksums and the "
                    "mapping content digest were NOT recomputed"
                )
            else:
                verify_key = derive_verify_key(secrets_store.get("hmac_salt"))
        _check_metadata(report, record, manifest, event)
        _verify_target(report, run_id, manifest, verify_key)
        _verify_pseudomap(report, paths, manifest, event, entries, verify_key)
    _append_audit_event(paths, report, chain_ok)
    return report


def _load_run_record(paths: Paths, run_id: str) -> dict[str, Any]:
    if not paths.checkpoint_db.exists():
        raise VerifyError(
            f"no checkpoint database at {paths.checkpoint_db}; no runs recorded here"
        )
    try:
        conn = sqlite_connect_readonly(paths.checkpoint_db)
    except sqlite3.Error as exc:
        raise VerifyError(f"cannot open checkpoint database read-only: {exc}") from exc
    try:
        row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise VerifyError(f"unknown run id: {run_id}")
    return dict(row)


def _load_manifest(
    paths: Paths, record: dict[str, Any], report: VerifyReport
) -> dict[str, Any] | None:
    path = manifest_path(paths.manifest_dir, record["dataset_fingerprint"])
    if not path.exists():
        report.mismatches.append(
            VerifyMismatch("manifest", f"run manifest missing: {path}")
        )
        return None
    manifest = read_json(path)
    if not isinstance(manifest, dict):
        raise VerifyError(f"run manifest is not a JSON object: {path}")
    if manifest.get("run_id") != report.run_id:
        raise VerifyError(
            f"the manifest for this dataset belongs to later run "
            f"{manifest.get('run_id')}; run {report.run_id} can no longer be "
            "verified (manifests track the latest run per dataset)"
        )
    if "tables" not in manifest or "checksum_mode" not in manifest:
        raise VerifyError(
            "manifest predates batch checksums; re-run the pipeline to produce "
            "verifiable evidence"
        )
    report.checks.append("manifest")
    return manifest


def _check_audit_chain(
    paths: Paths, report: VerifyReport
) -> tuple[list[dict[str, Any]], bool]:
    if not paths.audit_path.exists():
        report.mismatches.append(
            VerifyMismatch("audit", f"audit log missing: {paths.audit_path}")
        )
        return [], False
    try:
        entries = read_audit_entries(paths.audit_path)
    except AuditError as exc:
        report.mismatches.append(
            VerifyMismatch("audit", f"audit log unreadable: {exc}")
        )
        return [], False
    try:
        AuditLog(paths.audit_path).verify()
    except AuditError as exc:
        report.mismatches.append(VerifyMismatch("audit", f"audit chain invalid: {exc}"))
        return entries, False
    report.checks.append("audit-chain")
    return entries, True


def _is_completion_event(entry: dict[str, Any], run_id: str | None = None) -> bool:
    if run_id is not None and entry.get("run_id") != run_id:
        return False
    if entry.get("event") == "run_completed":
        return True
    # Entries written before the event field existed.
    return "event" not in entry and "output_hash" in entry


def _find_completion_event(
    entries: list[dict[str, Any]], run_id: str, report: VerifyReport
) -> dict[str, Any] | None:
    matches = [entry for entry in entries if _is_completion_event(entry, run_id)]
    if not matches:
        report.mismatches.append(
            VerifyMismatch(
                "audit", f"no completion event for run {run_id} in the audit chain"
            )
        )
        return None
    report.checks.append("audit-event")
    return matches[-1]


def _check_metadata(
    report: VerifyReport,
    record: dict[str, Any],
    manifest: dict[str, Any],
    event: dict[str, Any] | None,
) -> None:
    if str(record["output_path"]) != str(manifest.get("output")):
        report.mismatches.append(
            VerifyMismatch(
                "metadata",
                f"output path desync: checkpoints={record['output_path']!r} "
                f"manifest={manifest.get('output')!r}",
            )
        )
    if record["dataset_fingerprint"] != manifest.get("dataset_fingerprint"):
        report.mismatches.append(
            VerifyMismatch("metadata", "dataset fingerprint desync between "
                           "checkpoints and manifest")
        )
    if event is not None:
        pairs = [
            ("output_hash", manifest.get("output_hash"), event.get("output_hash")),
            ("row_count", manifest.get("row_count"), event.get("rows_processed")),
            ("pseudomap_count", manifest.get("pseudomap_count"),
             event.get("pseudomap_count")),
            ("pseudomap_digest", manifest.get("pseudomap_digest"),
             event.get("pseudomap_digest")),
        ]
        for name, manifest_value, event_value in pairs:
            if (
                manifest_value is not None
                and event_value is not None
                and manifest_value != event_value
            ):
                report.mismatches.append(
                    VerifyMismatch(
                        "metadata",
                        f"{name} desync: manifest={manifest_value!r} "
                        f"audit={event_value!r}",
                    )
                )
    report.checks.append("metadata")


def _verify_target(
    report: VerifyReport,
    run_id: str,
    manifest: dict[str, Any],
    verify_key: bytes | None,
) -> None:
    output = Path(manifest["output"])
    if not output.exists():
        report.mismatches.append(
            VerifyMismatch("target", f"target database missing: {output}")
        )
        return
    mode = manifest["checksum_mode"]
    try:
        conn = sqlite_connect_readonly(output)
    except sqlite3.Error as exc:
        report.mismatches.append(
            VerifyMismatch("target", f"cannot open target database read-only: {exc}")
        )
        return
    try:
        actual_tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
        expected = manifest["tables"]
        for name in sorted(set(expected) - actual_tables):
            report.mismatches.append(
                VerifyMismatch(
                    "target", "table missing from target database", table=name
                )
            )
        for name in sorted(actual_tables - set(expected)):
            report.mismatches.append(
                VerifyMismatch(
                    "target", "unexpected table in target database", table=name
                )
            )
        for name in sorted(set(expected) & actual_tables):
            _verify_table(report, conn, run_id, name, expected[name], mode, verify_key)
        report.checks.append("target")
    finally:
        conn.close()


def _verify_table(
    report: VerifyReport,
    conn: sqlite3.Connection,
    run_id: str,
    table_name: str,
    spec: dict[str, Any],
    mode: str,
    verify_key: bytes | None,
) -> None:
    expected_columns = list(spec.get("columns") or [])
    actual_columns = [
        row[1] for row in conn.execute(f"PRAGMA table_info({quote_ident(table_name)})")
    ]
    if actual_columns != expected_columns:
        report.mismatches.append(
            VerifyMismatch(
                "target",
                f"schema mismatch: expected columns {expected_columns}, "
                f"found {actual_columns}",
                table=table_name,
            )
        )
        return
    batches = list(spec.get("batches") or [])
    can_recompute = mode != CHECKSUM_HMAC or verify_key is not None
    select_cols = ", ".join(quote_ident(name) for name in expected_columns)
    for record in batches:
        hasher = (
            StreamChecksum(
                mode, verify_key,
                batch_checksum_header(run_id, table_name, int(record["batch"])),
            )
            if can_recompute
            else None
        )
        count = 0
        cursor = conn.execute(
            f"SELECT rowid, {select_cols} FROM {quote_ident(table_name)} "
            "WHERE rowid >= ? AND rowid <= ? ORDER BY rowid",
            (int(record["first_rowid"]), int(record["last_rowid"])),
        )
        for row in cursor:
            count += 1
            if hasher is not None:
                hasher.add_values(list(row))
        report.rows_checked += count
        report.batches_checked += 1
        if count != int(record["rows"]):
            report.mismatches.append(
                VerifyMismatch(
                    "target",
                    f"row count mismatch (expected {record['rows']}, found {count})",
                    table=table_name,
                    batch=int(record["batch"]),
                )
            )
        elif hasher is not None:
            actual = hasher.hexdigest()
            if actual != record["checksum"]:
                report.mismatches.append(
                    VerifyMismatch(
                        "target",
                        f"checksum mismatch (expected {record['checksum'][:16]}..., "
                        f"recomputed {actual[:16]}...)",
                        table=table_name,
                        batch=int(record["batch"]),
                    )
                )
    report.tables_checked += 1
    # Tiling: nothing may exist outside the recorded batch ranges either.
    total = int(
        conn.execute(f"SELECT COUNT(*) FROM {quote_ident(table_name)}").fetchone()[0]
    )
    expected_total = int(spec.get("rows") or 0)
    recorded_total = sum(int(record["rows"]) for record in batches)
    if recorded_total != expected_total:
        report.mismatches.append(
            VerifyMismatch(
                "manifest",
                f"manifest is internally inconsistent: rows={expected_total} but "
                f"batches sum to {recorded_total}",
                table=table_name,
            )
        )
    if total != expected_total:
        report.mismatches.append(
            VerifyMismatch(
                "target",
                f"table contains {total} rows, expected {expected_total} "
                "(rows were added or removed outside the recorded batches)",
                table=table_name,
            )
        )
    if batches:
        min_rowid, max_rowid = conn.execute(
            f"SELECT MIN(rowid), MAX(rowid) FROM {quote_ident(table_name)}"
        ).fetchone()
        first = int(batches[0]["first_rowid"])
        last = int(batches[-1]["last_rowid"])
        if min_rowid != first or max_rowid != last:
            report.mismatches.append(
                VerifyMismatch(
                    "target",
                    f"rowid bounds [{min_rowid}, {max_rowid}] exceed the recorded "
                    f"batch range [{first}, {last}]",
                    table=table_name,
                )
            )


def _verify_pseudomap(
    report: VerifyReport,
    paths: Paths,
    manifest: dict[str, Any],
    event: dict[str, Any] | None,
    entries: list[dict[str, Any]],
    verify_key: bytes | None,
) -> None:
    expected_count = manifest.get("pseudomap_count")
    expected_digest = manifest.get("pseudomap_digest")
    if event is not None:
        if event.get("pseudomap_count") is not None:
            expected_count = event["pseudomap_count"]
        if event.get("pseudomap_digest") is not None:
            expected_digest = event["pseudomap_digest"]
    if expected_count is None:
        report.notes.append(
            "pseudonym mapping count was not recorded for this run; "
            "mapping check skipped"
        )
        return
    db_path = paths.pseudomap_db
    if not db_path.exists():
        if expected_count:
            report.mismatches.append(
                VerifyMismatch(
                    "pseudomap",
                    f"pseudonym mapping database missing: {db_path} "
                    f"(run recorded {expected_count} mappings)",
                )
            )
        else:
            report.notes.append(
                "pseudonym mapping database not present; run recorded 0 mappings"
            )
        return
    mode = manifest["checksum_mode"]
    try:
        conn = sqlite_connect_readonly(db_path)
        try:
            actual_count = int(
                conn.execute("SELECT COUNT(*) FROM pseudonym_map").fetchone()[0]
            )
            actual_digest: str | None = None
            if (
                expected_digest is not None
                and actual_count == expected_count
                and (mode != CHECKSUM_HMAC or verify_key is not None)
            ):
                hasher = StreamChecksum(mode, verify_key, pseudomap_checksum_header())
                for row in conn.execute(
                    "SELECT token, plaintext FROM pseudonym_map ORDER BY token"
                ):
                    hasher.add_values([row[0], row[1]])
                actual_digest = hasher.hexdigest()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        report.mismatches.append(
            VerifyMismatch("pseudomap", f"cannot read mapping database: {exc}")
        )
        return
    report.checks.append("pseudomap")
    if actual_count < expected_count:
        report.mismatches.append(
            VerifyMismatch(
                "pseudomap",
                f"mapping record count {actual_count} is below the "
                f"{expected_count} recorded at run completion "
                f"({expected_count - actual_count} mapping record(s) lost)",
            )
        )
        return
    if actual_count > expected_count:
        recorded = [
            entry["pseudomap_count"]
            for entry in entries
            if _is_completion_event(entry) and entry.get("pseudomap_count") is not None
        ]
        if recorded and actual_count == max(recorded):
            report.notes.append(
                f"mapping count grew from {expected_count} to {actual_count} "
                "through later recorded runs"
            )
        else:
            report.mismatches.append(
                VerifyMismatch(
                    "pseudomap",
                    f"mapping record count {actual_count} exceeds the "
                    f"{expected_count} recorded for this run and no run in the "
                    "audit chain accounts for the growth",
                )
            )
        return
    # Counts match: also compare the content digest when it can be recomputed.
    if expected_digest is None:
        report.notes.append(
            "mapping content digest not recorded for this run; count check only"
        )
    elif actual_digest is None:
        report.notes.append(
            "mapping content digest not recomputed (secret unavailable); "
            "count check only"
        )
    elif actual_digest != expected_digest:
        report.mismatches.append(
            VerifyMismatch(
                "pseudomap",
                "mapping content digest mismatch (records were altered or "
                "replaced without changing the count)",
            )
        )


def _append_audit_event(paths: Paths, report: VerifyReport, chain_ok: bool) -> None:
    if not chain_ok:
        report.notes.append("verify event not appended: audit chain is not intact")
        return
    entry = {
        "event": "verify",
        "run_id": report.run_id,
        "result": report.result_label,
        "degraded": report.degraded,
        "checks": sorted(set(report.checks)),
        "mismatch_count": len(report.mismatches),
        "mismatches": [mismatch.describe() for mismatch in report.mismatches],
        "tables_checked": report.tables_checked,
        "batches_checked": report.batches_checked,
        "rows_checked": report.rows_checked,
    }
    try:
        stored = AuditLog(paths.audit_path).append(entry)
    except AuditError as exc:
        report.notes.append(f"verify event could not be appended: {exc}")
        return
    report.audit_appended = True
    report.audit_seq = stored.get("seq")
