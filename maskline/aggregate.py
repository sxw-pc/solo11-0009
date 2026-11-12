"""Cross-run aggregate reports for one source dataset.

This module deliberately sits beside :mod:`maskline.report`.  Single-run report
generation is left untouched; aggregation reads the existing registry, run
checkpoints, per-run report snapshots, and audit chain without ever opening a
data source for writing.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .audit import (
    AuditError,
    AuditIntegrityError,
    AuditLog,
    head_path,
    read_audit_entries,
    verify_audit,
)
from .config import Paths
from .pipeline.checkpoint import read_checkpoint_records, read_run_records
from .registry import (
    DatasetInventory,
    inspect_dataset,
    read_dataset_record,
    read_findings_snapshot,
)
from .utils import MasklineError, atomic_write_text, canonical_json

DEFAULT_DETAIL_LIMIT = 50
AGGREGATE_EVENT = "aggregate_report"
FINGERPRINT_RE = re.compile(r"[0-9a-fA-F]{64}")
CONFIDENCE_KEYS = ("high", "medium", "low", "none")
CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低", "none": "无"}
TRANSFORMER_LABELS = {
    "mask": "遮蔽",
    "hash": "HMAC 哈希",
    "generalize": "泛化",
    "pseudonym": "假名化",
    "nullify": "置空",
    "round": "取整",
}


@dataclass
class AggregateReportResult:
    """Paths and outcome of one aggregate report generation."""

    markdown_path: Path
    json_path: Path
    dataset_fingerprint: str
    aggregate_id: str
    history_runs: int
    included_runs: tuple[str, ...]
    excluded_runs: tuple[str, ...]
    details_folded: bool
    audit_entry: dict[str, Any] | None
    audit_append_status: str


class AggregateError(MasklineError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_fingerprint(value: str) -> bool:
    return bool(FINGERPRINT_RE.fullmatch(value.strip()))


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _first(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if text != "" else '""'


# ---------------------------------------------------------------------------
# Read-only source discovery
# ---------------------------------------------------------------------------


def _resolve_dataset(
    paths: Paths, target: str | Path
) -> tuple[str, str | None, dict[str, Any] | None, DatasetInventory | None]:
    """Return (fingerprint, dataset path, registry record, inventory)."""
    raw = str(target).strip()
    if _is_fingerprint(raw):
        fingerprint = raw.lower()
        record = read_dataset_record(paths.meta_db, fingerprint)
        if record:
            return fingerprint, record.get("path"), record, None
        runs = read_run_records(paths.checkpoint_db, fingerprint)
        if runs:
            return fingerprint, runs[-1].get("dataset_path"), None, None
        # Last resort: an audit-only history may outlive the metadata databases.
        try:
            entries = read_audit_entries(paths.audit_path)
        except AuditError:
            entries = []
        matching = [
            entry
            for entry in entries
            if entry.get("dataset_fingerprint") == fingerprint
            and entry.get("event") != AGGREGATE_EVENT
        ]
        if matching:
            return fingerprint, matching[-1].get("dataset_path"), None, None
        raise AggregateError(f"no registered dataset or run history for fingerprint {fingerprint}")

    inventory = inspect_dataset(target)
    record = read_dataset_record(paths.meta_db, inventory.fingerprint)
    return inventory.fingerprint, str(inventory.path), record, inventory


def _audit_status(paths: Paths) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = paths.audit_path
    anchor = head_path(path)
    status: dict[str, Any] = {
        "path": str(path),
        "present": path.is_file(),
        "valid": False,
        "entries": 0,
        "head_hash": None,
        "error": None,
        "error_type": None,
        "error_line": None,
        "anchor": {
            "path": str(anchor),
            "present": anchor.is_file(),
            "readable": False,
            "count": None,
            "last_hash": None,
            "matches_chain": False,
        },
    }
    if anchor.is_file():
        try:
            payload = json.loads(anchor.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                status["anchor"]["readable"] = True
                status["anchor"]["count"] = payload.get("count")
                status["anchor"]["last_hash"] = payload.get("last_hash")
        except (OSError, json.JSONDecodeError):
            pass
    if not status["present"]:
        status["error"] = f"audit log not found: {path}"
        status["error_type"] = "missing"
        return status, []

    verification = None
    try:
        verification = verify_audit(path)
    except AuditIntegrityError as exc:
        status["error"] = str(exc)
        status["error_type"] = "integrity"
        status["error_line"] = exc.line
    except AuditError as exc:
        status["error"] = str(exc)
        status["error_type"] = "audit"
    except OSError as exc:
        status["error"] = str(exc)
        status["error_type"] = "io"

    try:
        entries = read_audit_entries(path)
    except AuditError as exc:
        entries = []
        if not status["error"]:
            status["error"] = str(exc)
            status["error_type"] = "parse"

    if verification is not None:
        status["valid"] = True
        status["entries"] = verification.entries
        status["head_hash"] = verification.head_hash
        status["anchor"]["matches_chain"] = True
    elif entries:
        # The chain may be invalid while individual lines are still readable.
        status["entries"] = len(entries)
    return status, entries


# ---------------------------------------------------------------------------
# Per-run assembly
# ---------------------------------------------------------------------------


def _load_report_snapshot(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, "missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"invalid: {exc}"
    if not isinstance(payload, dict):
        return None, "invalid: report root is not an object"
    return payload, None


def _merge_counts(
    target: dict[str, dict[str, int]], source: dict[str, dict[str, int]]
) -> None:
    for name, values in source.items():
        slot = target.setdefault(name, {"seen": 0, "processed": 0, "changed": 0})
        for key in ("seen", "processed", "changed"):
            try:
                slot[key] = slot.get(key, 0) + int(values.get(key, 0))
            except (TypeError, ValueError):
                slot[key] = slot.get(key, 0)


def _checkpoint_fallback(paths: Paths, run_id: str) -> tuple[int | None, dict[str, dict[str, int]]]:
    records = read_checkpoint_records(paths.checkpoint_db, run_id)
    if not records:
        return None, {}
    counts: dict[str, dict[str, int]] = {}
    rows = 0
    for record in records:
        try:
            rows += int(record.get("rows_done") or 0)
        except (TypeError, ValueError):
            pass
        _merge_counts(counts, _as_dict(record.get("counts")))
    return rows, counts


def _policy_from_applied(applied_policy: Any) -> tuple[dict[str, Any] | None, bool]:
    """Normalize a single-run ``applied_policy`` block into table/column maps."""
    applied = _as_dict(applied_policy)
    tables = _as_dict(applied.get("tables"))
    if not tables:
        return None, False
    result: dict[str, Any] = {}
    complete = True
    for table_name, table_block in tables.items():
        columns = _as_dict(_as_dict(table_block).get("columns"))
        if not columns:
            continue
        result[table_name] = {}
        for column_name, detail in columns.items():
            detail = _as_dict(detail)
            if "params" not in detail:
                complete = False
            result[table_name][column_name] = {
                "transformer": detail.get("transformer"),
                "params": detail.get("params", {}),
            }
    return (result or None), complete


def _policy_from_audit_entry(entry: dict[str, Any] | None) -> tuple[dict[str, Any] | None, bool]:
    """Reconstruct the transformer map from an audit entry (params unavailable)."""
    columns = _as_dict(_as_dict(entry).get("columns"))
    if not columns:
        return None, False
    result: dict[str, Any] = {}
    for table_name, table_columns in columns.items():
        table_map = _as_dict(table_columns)
        if not table_map:
            continue
        result[table_name] = {
            str(column_name): {"transformer": transformer, "params": {}}
            for column_name, transformer in table_map.items()
        }
    return (result or None), False


def _applied_policy_block(policy_map: dict[str, Any] | None) -> dict[str, Any] | None:
    if policy_map is None:
        return None
    return {
        "path": None,
        "tables": {
            table_name: {
                "columns": {
                    column_name: {
                        "transformer": detail.get("transformer"),
                        "params": dict(detail.get("params") or {}),
                    }
                    for column_name, detail in columns.items()
                }
            }
            for table_name, columns in policy_map.items()
        },
    }


def _findings_map(findings: Iterable[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = (str(finding.get("table_name")), str(finding.get("column_name")))
        result[key] = finding
    return result


def _finding_counts(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {key: 0 for key in CONFIDENCE_KEYS}
    for finding in findings:
        confidence = str(finding.get("confidence") or "none")
        counts[confidence] = counts.get(confidence, 0) + 1
    return counts


def _compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "table_name": finding.get("table_name"),
        "column_name": finding.get("column_name"),
        "sensitive_type": finding.get("sensitive_type"),
        "confidence": finding.get("confidence"),
        "score": finding.get("score"),
        "hit_rate": finding.get("hit_rate"),
        "validate_rate": finding.get("validate_rate"),
        "sample_size": finding.get("sample_size"),
    }


def _build_run_entry(
    paths: Paths,
    fingerprint: str,
    dataset_path: str | None,
    run_id: str,
    record: dict[str, Any] | None,
    audit_entry: dict[str, Any] | None,
    duplicate_audit_entries: int,
    audit_chain_valid: bool,
) -> dict[str, Any]:
    report_path = paths.reports_dir / f"{run_id}.json"
    markdown_report_path = paths.reports_dir / f"{run_id}.md"
    report, report_error = _load_report_snapshot(report_path)
    report_block = _as_dict(_as_dict(report).get("run"))

    status = str(record.get("status")) if record and record.get("status") else (
        "completed" if audit_entry else "unknown"
    )
    status_source = "run_record" if record else ("audit_entry" if audit_entry else "unknown")

    output_path = _first(
        _as_dict(audit_entry).get("output_path"),
        _as_dict(record).get("output_path"),
        report_block.get("output"),
    )
    output_hash = _first(
        _as_dict(audit_entry).get("output_hash"),
        report_block.get("output_hash"),
    )
    output_present = bool(output_path) and Path(str(output_path)).is_file()

    rows_processed = _first(
        _as_dict(audit_entry).get("rows_processed"),
        report_block.get("rows_processed"),
    )
    elapsed_seconds = _first(
        _as_dict(audit_entry).get("elapsed_seconds"),
        report_block.get("elapsed_seconds"),
    )
    if rows_processed is None or not _as_dict(audit_entry).get("transform_counts"):
        checkpoint_rows, checkpoint_counts = _checkpoint_fallback(paths, run_id)
        if rows_processed is None:
            rows_processed = checkpoint_rows
        if not _as_dict(audit_entry).get("transform_counts") and not _as_dict(report).get("transform_counts"):
            transform_counts = checkpoint_counts
        else:
            transform_counts = _first(
                _as_dict(report).get("transform_counts"),
                _as_dict(audit_entry).get("transform_counts"),
            ) or {}
    else:
        transform_counts = _first(
            _as_dict(report).get("transform_counts"),
            _as_dict(audit_entry).get("transform_counts"),
        ) or {}

    policy_name = _first(
        _as_dict(audit_entry).get("policy_name"),
        _as_dict(record).get("policy_name") if record else None,
        report_block.get("policy_name"),
    )
    policy_fingerprint = _first(
        _as_dict(audit_entry).get("policy_fingerprint"),
        _as_dict(record).get("policy_fingerprint") if record else None,
        report_block.get("policy_fingerprint"),
    )
    policy_path = _as_dict(record).get("policy_path")
    policy_map, params_complete = _policy_from_applied(_as_dict(report).get("applied_policy"))
    if policy_map is None:
        policy_map, params_complete = _policy_from_audit_entry(audit_entry)
    applied_policy = _applied_policy_block(policy_map)
    policy_changed_value = report_block.get("policy_changed")

    started_at = _first(
        _as_dict(record).get("started_at"),
        _as_dict(audit_entry).get("ts"),
        _as_dict(report).get("generated_at"),
    )
    completed_at = _first(
        _as_dict(record).get("updated_at"),
        _as_dict(audit_entry).get("ts"),
        _as_dict(report).get("generated_at"),
    )

    findings = [item for item in _as_list(_as_dict(report).get("findings")) if isinstance(item, dict)]
    findings_available = report is not None and isinstance(_as_dict(report).get("findings"), list)
    warnings = [item for item in _as_list(_as_dict(report).get("warnings")) if isinstance(item, dict)]

    audit_present = audit_entry is not None
    checks = {
        "run_record_present": record is not None,
        "status_completed": status == "completed",
        "audit_entry_present": audit_present,
        "audit_chain_valid": bool(audit_chain_valid),
        "output_present": output_present,
        "report_snapshot_present": report is not None,
    }
    reasons: list[str] = []
    if not checks["status_completed"]:
        reasons.append(f"status_not_completed:{status}")
    if not checks["audit_entry_present"]:
        reasons.append("audit_entry_missing")
    if not checks["audit_chain_valid"]:
        reasons.append("audit_chain_invalid")
    if output_path is None:
        reasons.append("output_unknown")
    elif not output_present:
        reasons.append("output_missing")
    passed = all(
        checks[key]
        for key in ("status_completed", "audit_entry_present", "audit_chain_valid", "output_present")
    )
    warning_codes: list[str] = []
    if not checks["run_record_present"]:
        warning_codes.append("run_record_missing")
    if not checks["report_snapshot_present"]:
        warning_codes.append("report_snapshot_missing")
    if duplicate_audit_entries:
        warning_codes.append(f"duplicate_audit_entries:{duplicate_audit_entries}")

    run_block = {
        "run_id": run_id,
        "dataset": dataset_path,
        "dataset_fingerprint": fingerprint,
        "policy_name": policy_name,
        "policy_fingerprint": policy_fingerprint,
        "policy_path": policy_path,
        "policy_changed": policy_changed_value,
        "output": output_path,
        "output_hash": output_hash,
        "rows_processed": rows_processed,
        "elapsed_seconds": elapsed_seconds,
        "started_at": started_at,
        "completed_at": completed_at,
        "status": status,
        "status_source": status_source,
    }
    artifacts = {
        "output": {
            "path": output_path,
            "present": output_present,
            "hash": output_hash,
        },
        "reports": {
            "json": {
                "path": str(report_path),
                "present": report is not None,
                "error": report_error,
            },
            "markdown": {
                "path": str(markdown_report_path),
                "present": markdown_report_path.is_file(),
            },
        },
    }
    audit_view = {
        "entry_seq": _as_dict(audit_entry).get("seq") if audit_entry else None,
        "entry_hash": _as_dict(audit_entry).get("entry_hash") if audit_entry else None,
        "verified": bool(audit_present and audit_chain_valid),
        "chain_valid": bool(audit_chain_valid),
    }
    return {
        "run": run_block,
        "status": status,
        "validation": {
            "passed": passed,
            "checks": checks,
            "reasons": reasons,
            "warnings": warning_codes,
        },
        "artifacts": artifacts,
        "audit": audit_view,
        "applied_policy": applied_policy,
        "policy_params_complete": params_complete,
        "transform_counts": _as_dict(transform_counts),
        "findings": findings,
        "findings_available": findings_available,
        "findings_count": len(findings),
        "confidence_counts": _finding_counts(findings),
        "warnings": warnings,
        "changes": {"policy": None, "findings": None},
    }


# ---------------------------------------------------------------------------
# Differences between successive runs
# ---------------------------------------------------------------------------


def _sort_key(entry: dict[str, Any]) -> tuple[str, str]:
    run = _as_dict(entry.get("run"))
    started = run.get("started_at")
    return (str(started) if started is not None else "\uffff", str(run.get("run_id")))


def _changed_fields(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    fields = ("sensitive_type", "confidence", "score", "hit_rate", "validate_rate")
    delta: dict[str, Any] = {}
    for field in fields:
        left = before.get(field)
        right = after.get(field)
        if left != right:
            delta[field] = {"from": left, "to": right}
    return delta


def _findings_diff(
    previous: dict[tuple[str, str], dict[str, Any]] | None,
    previous_run_id: str | None,
    current: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    if previous is None:
        return {
            "available": True,
            "baseline": True,
            "compared_to_run_id": None,
            "added": [],
            "removed": [],
            "changed": [],
            "current_count": len(current),
        }
    added_keys = sorted(set(current) - set(previous))
    removed_keys = sorted(set(previous) - set(current))
    changed = []
    for key in sorted(set(current) & set(previous)):
        delta = _changed_fields(previous[key], current[key])
        if not delta:
            continue
        changed.append(
            {
                "table_name": key[0],
                "column_name": key[1],
                "from": _compact_finding(previous[key]),
                "to": _compact_finding(current[key]),
                "delta": delta,
            }
        )
    return {
        "available": True,
        "baseline": False,
        "compared_to_run_id": previous_run_id,
        "added": [_compact_finding(current[key]) for key in added_keys],
        "removed": [_compact_finding(previous[key]) for key in removed_keys],
        "changed": changed,
        "current_count": len(current),
    }


def _params_equal(left: Any, right: Any) -> bool:
    return canonical_json(left) == canonical_json(right)


def _policy_diff(
    previous: tuple[dict[str, Any], bool] | None,
    previous_run: dict[str, Any] | None,
    current: dict[str, Any],
    current_complete: bool,
    current_run: dict[str, Any],
) -> dict[str, Any]:
    current_flat = {
        (table, column): detail
        for table, columns in current.items()
        for column, detail in columns.items()
    }
    fingerprint_changed = bool(
        previous_run
        and previous_run.get("policy_fingerprint") is not None
        and current_run.get("policy_fingerprint") is not None
        and previous_run.get("policy_fingerprint") != current_run.get("policy_fingerprint")
    )
    name_changed = bool(
        previous_run
        and previous_run.get("policy_name") is not None
        and current_run.get("policy_name") is not None
        and previous_run.get("policy_name") != current_run.get("policy_name")
    )
    if previous is None:
        return {
            "available": True,
            "baseline": True,
            "compared_to_run_id": None,
            "policy_fingerprint_changed": False,
            "policy_name_changed": False,
            "params_complete": current_complete,
            "added_tables": sorted(current),
            "removed_tables": [],
            "added_columns": [
                {"table": table, "column": column, **_compact_policy_detail(detail)}
                for (table, column), detail in sorted(current_flat.items())
            ],
            "removed_columns": [],
            "changed_columns": [],
        }

    previous_map, previous_complete = previous
    previous_flat = {
        (table, column): detail
        for table, columns in previous_map.items()
        for column, detail in columns.items()
    }
    added = sorted(set(current_flat) - set(previous_flat))
    removed = sorted(set(previous_flat) - set(current_flat))
    changed = []
    params_complete = bool(previous_complete and current_complete)
    for key in sorted(set(current_flat) & set(previous_flat)):
        before = previous_flat[key]
        after = current_flat[key]
        transformer_changed = before.get("transformer") != after.get("transformer")
        params_changed = (
            params_complete and not _params_equal(before.get("params"), after.get("params"))
        )
        if not transformer_changed and not params_changed:
            continue
        changed.append(
            {
                "table": key[0],
                "column": key[1],
                "from": _compact_policy_detail(before),
                "to": _compact_policy_detail(after),
                "transformer_changed": transformer_changed,
                "params_changed": params_changed,
            }
        )
    return {
        "available": True,
        "baseline": False,
        "compared_to_run_id": previous_run.get("run_id") if previous_run else None,
        "policy_fingerprint_changed": fingerprint_changed,
        "policy_name_changed": name_changed,
        "params_complete": params_complete,
        "added_tables": sorted(set(current) - set(previous_map)),
        "removed_tables": sorted(set(previous_map) - set(current)),
        "added_columns": [
            {"table": table, "column": column, **_compact_policy_detail(current_flat[(table, column)])}
            for table, column in added
        ],
        "removed_columns": [
            {"table": table, "column": column, **_compact_policy_detail(previous_flat[(table, column)])}
            for table, column in removed
        ],
        "changed_columns": changed,
    }


def _compact_policy_detail(detail: dict[str, Any]) -> dict[str, Any]:
    return {
        "transformer": detail.get("transformer"),
        "params": dict(detail.get("params") or {}),
    }


def _compute_changes(entries: list[dict[str, Any]]) -> None:
    previous_findings: dict[tuple[str, str], dict[str, Any]] | None = None
    previous_findings_run_id: str | None = None
    previous_policy: tuple[dict[str, Any], bool] | None = None
    previous_policy_run: dict[str, Any] | None = None

    for entry in entries:
        run = _as_dict(entry.get("run"))
        findings_changes: dict[str, Any]
        if not entry.get("findings_available"):
            findings_changes = {"available": False, "reason": "report_snapshot_unavailable"}
        else:
            current_findings = _findings_map(_as_list(entry.get("findings")))
            findings_changes = _findings_diff(
                previous_findings, previous_findings_run_id, current_findings
            )
            previous_findings = current_findings
            previous_findings_run_id = run.get("run_id")

        policy_changes: dict[str, Any]
        if entry.get("applied_policy") is None:
            policy_changes = {"available": False, "reason": "policy_snapshot_unavailable"}
        else:
            current_policy, _ = _policy_from_applied(entry.get("applied_policy"))
            current_complete = bool(entry.get("policy_params_complete"))
            if current_policy is None:
                policy_changes = {"available": False, "reason": "policy_snapshot_unavailable"}
            else:
                policy_changes = _policy_diff(
                    previous_policy,
                    previous_policy_run,
                    current_policy,
                    current_complete,
                    run,
                )
                previous_policy = (current_policy, current_complete)
                previous_policy_run = run

        entry["changes"] = {"policy": policy_changes, "findings": findings_changes}
        if run.get("policy_changed") is None:
            run["policy_changed"] = bool(
                policy_changes.get("policy_fingerprint_changed")
                or policy_changes.get("added_columns")
                or policy_changes.get("removed_columns")
                or policy_changes.get("changed_columns")
            )
        entry["changes_summary"] = {
            "policy_available": bool(policy_changes.get("available")),
            "policy_changed": bool(run.get("policy_changed")),
            "params_complete": bool(policy_changes.get("params_complete")),
            "policy_added_columns": len(_as_list(policy_changes.get("added_columns"))),
            "policy_removed_columns": len(_as_list(policy_changes.get("removed_columns"))),
            "policy_changed_columns": len(_as_list(policy_changes.get("changed_columns"))),
            "findings_available": bool(findings_changes.get("available")),
            "findings_added": len(_as_list(findings_changes.get("added"))),
            "findings_removed": len(_as_list(findings_changes.get("removed"))),
            "findings_changed": len(_as_list(findings_changes.get("changed"))),
        }


# ---------------------------------------------------------------------------
# Views, trends, and rendering
# ---------------------------------------------------------------------------


def _summary_view(entry: dict[str, Any]) -> dict[str, Any]:
    run = _as_dict(entry.get("run"))
    return {
        "run": run,
        "status": entry.get("status"),
        "included": bool(_as_dict(entry.get("validation")).get("passed")),
        "validation": {
            "passed": bool(_as_dict(entry.get("validation")).get("passed")),
            "reasons": list(_as_dict(entry.get("validation")).get("reasons") or []),
            "warnings": list(_as_dict(entry.get("validation")).get("warnings") or []),
        },
        "findings_available": bool(entry.get("findings_available")),
        "findings_count": entry.get("findings_count"),
        "confidence_counts": entry.get("confidence_counts"),
        "artifacts": entry.get("artifacts"),
        "audit": entry.get("audit"),
        "changes_summary": entry.get("changes_summary"),
    }


def _compact_run_view(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "run": entry.get("run"),
        "status": entry.get("status"),
        "validation": entry.get("validation"),
        "artifacts": entry.get("artifacts"),
        "audit": entry.get("audit"),
        "findings_available": entry.get("findings_available"),
        "findings_count": entry.get("findings_count"),
        "confidence_counts": entry.get("confidence_counts"),
        "changes_summary": entry.get("changes_summary"),
    }


def _anomaly_view(entry: dict[str, Any]) -> dict[str, Any]:
    view = _summary_view(entry)
    view["reasons"] = list(_as_dict(entry.get("validation")).get("reasons") or [])
    return view


def _trend_view(
    history: list[dict[str, Any]],
    included: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
) -> dict[str, Any]:
    first_with_findings = next(
        (entry for entry in included if entry.get("findings_available")), None
    )
    last_with_findings = next(
        (entry for entry in reversed(included) if entry.get("findings_available")), None
    )
    first_counts = (
        _as_dict(first_with_findings.get("confidence_counts")) if first_with_findings else None
    )
    last_counts = (
        _as_dict(last_with_findings.get("confidence_counts")) if last_with_findings else None
    )
    delta: dict[str, int] | None = None
    if first_counts is not None and last_counts is not None:
        delta = {
            key: int(last_counts.get(key, 0)) - int(first_counts.get(key, 0))
            for key in CONFIDENCE_KEYS
        }
    policy_change_runs = [
        entry.get("run", {}).get("run_id")
        for entry in included
        if _as_dict(entry.get("changes_summary")).get("policy_changed")
    ]
    per_run = []
    for entry in included:
        run = _as_dict(entry.get("run"))
        changes = _as_dict(entry.get("changes_summary"))
        per_run.append(
            {
                "run_id": run.get("run_id"),
                "started_at": run.get("started_at"),
                "rows_processed": run.get("rows_processed"),
                "policy_fingerprint": run.get("policy_fingerprint"),
                "policy_changed": bool(changes.get("policy_changed")),
                "findings_available": bool(entry.get("findings_available")),
                "findings_total": entry.get("findings_count"),
                "confidence_counts": entry.get("confidence_counts"),
                "findings_added": changes.get("findings_added"),
                "findings_removed": changes.get("findings_removed"),
                "findings_changed": changes.get("findings_changed"),
            }
        )
    return {
        "history_runs": len(history),
        "runs_included": len(included),
        "runs_excluded": len(anomalies),
        "first_run_id": _as_dict(history[0].get("run")).get("run_id") if history else None,
        "last_run_id": _as_dict(history[-1].get("run")).get("run_id") if history else None,
        "policy_change_runs": policy_change_runs,
        "policy_change_count": len(policy_change_runs),
        "findings_first": first_counts,
        "findings_last": last_counts,
        "findings_delta": delta,
        "per_run": per_run,
    }


def _render_run_detail(entry: dict[str, Any], level: int = 3) -> list[str]:
    run = _as_dict(entry.get("run"))
    validation = _as_dict(entry.get("validation"))
    artifacts = _as_dict(entry.get("artifacts"))
    output = _as_dict(artifacts.get("output"))
    reports = _as_dict(artifacts.get("reports"))
    json_report = _as_dict(reports.get("json"))
    changes = _as_dict(entry.get("changes"))
    policy_changes = _as_dict(changes.get("policy"))
    findings_changes = _as_dict(changes.get("findings"))
    heading = "#" * level

    lines = [
        f"{heading} {run.get('run_id')}",
        "",
        f"- 状态：{_cell(entry.get('status'))}",
        f"- 纳入汇总：{'是' if validation.get('passed') else '否'}",
        f"- 策略：`{_cell(run.get('policy_name'))}` (`{_cell(run.get('policy_fingerprint'))}`)",
        f"- 策略变更：{'是' if run.get('policy_changed') else '否'}",
        f"- 行数：{_cell(run.get('rows_processed'))}",
        f"- 开始时间：{_cell(run.get('started_at'))}",
        f"- 输出：`{_cell(output.get('path'))}`（{'存在' if output.get('present') else '缺失'}）",
        f"- 输出哈希：`{_cell(output.get('hash'))}`",
        f"- 报告快照：`{_cell(json_report.get('path'))}`（{'存在' if json_report.get('present') else '缺失'}）",
        f"- 审计条目：seq={_cell(_as_dict(entry.get('audit')).get('entry_seq'))}，"
        f"校验={'通过' if _as_dict(entry.get('audit')).get('verified') else '未通过'}",
    ]
    if validation.get("reasons"):
        lines.append(f"- 异常原因：{', '.join(str(item) for item in validation['reasons'])}")
    if validation.get("warnings"):
        lines.append(f"- 警告：{', '.join(str(item) for item in validation['warnings'])}")
    lines.extend(["", f"{heading}# 策略调整差异", ""])
    if not policy_changes.get("available"):
        lines.append("策略快照不可用，无法计算差异。")
    elif policy_changes.get("baseline"):
        lines.append(
            f"基线运行：已配置 {len(_as_list(policy_changes.get('added_columns')))} 个字段。"
        )
    else:
        if policy_changes.get("policy_fingerprint_changed"):
            lines.append(
                f"- 策略指纹变化：`{_cell(policy_changes.get('compared_to_run_id'))}` 之后的新指纹"
                f" `{_cell(run.get('policy_fingerprint'))}`"
            )
        if policy_changes.get("policy_name_changed"):
            lines.append("- 策略名称发生变化。")
        for item in _as_list(policy_changes.get("added_columns")):
            item = _as_dict(item)
            lines.append(
                f"- 新增：`{_cell(item.get('table'))}.{_cell(item.get('column'))}` "
                f"-> `{_cell(item.get('transformer'))}`"
            )
        for item in _as_list(policy_changes.get("removed_columns")):
            item = _as_dict(item)
            lines.append(
                f"- 移除：`{_cell(item.get('table'))}.{_cell(item.get('column'))}`"
            )
        for item in _as_list(policy_changes.get("changed_columns")):
            item = _as_dict(item)
            before = _as_dict(item.get("from"))
            after = _as_dict(item.get("to"))
            text = (
                f"- 调整：`{_cell(item.get('table'))}.{_cell(item.get('column'))}` "
                f"`{_cell(before.get('transformer'))}` -> `{_cell(after.get('transformer'))}`"
            )
            if item.get("params_changed"):
                text += f"，参数 `{_cell(before.get('params'))}` -> `{_cell(after.get('params'))}`"
            lines.append(text)
        if not (
            policy_changes.get("policy_fingerprint_changed")
            or policy_changes.get("policy_name_changed")
            or _as_list(policy_changes.get("added_columns"))
            or _as_list(policy_changes.get("removed_columns"))
            or _as_list(policy_changes.get("changed_columns"))
        ):
            lines.append("无策略调整。")
        if not policy_changes.get("params_complete"):
            lines.append("> 部分运行缺少报告快照，参数级差异不完整。")

    lines.extend(["", f"{heading}# 敏感发现变化", ""])
    if not findings_changes.get("available"):
        lines.append("报告快照不可用，无法计算敏感发现变化。")
    elif findings_changes.get("baseline"):
        lines.append(
            f"基线运行：{_cell(findings_changes.get('current_count'))} 条发现（"
            f"高 {_cell(_as_dict(entry.get('confidence_counts')).get('high'))} / "
            f"中 {_cell(_as_dict(entry.get('confidence_counts')).get('medium'))} / "
            f"低 {_cell(_as_dict(entry.get('confidence_counts')).get('low'))}）。"
        )
    else:
        for item in _as_list(findings_changes.get("added")):
            item = _as_dict(item)
            lines.append(
                f"- 新增：`{_cell(item.get('table_name'))}.{_cell(item.get('column_name'))}` "
                f"-> {_cell(item.get('sensitive_type'))}（{_cell(item.get('confidence'))}）"
            )
        for item in _as_list(findings_changes.get("removed")):
            item = _as_dict(item)
            lines.append(
                f"- 消失：`{_cell(item.get('table_name'))}.{_cell(item.get('column_name'))}` "
                f"（原 {_cell(item.get('sensitive_type'))}）"
            )
        for item in _as_list(findings_changes.get("changed")):
            item = _as_dict(item)
            before = _as_dict(item.get("from"))
            after = _as_dict(item.get("to"))
            lines.append(
                f"- 漂移：`{_cell(item.get('table_name'))}.{_cell(item.get('column_name'))}` "
                f"{_cell(before.get('sensitive_type'))}/{_cell(before.get('confidence'))} -> "
                f"{_cell(after.get('sensitive_type'))}/{_cell(after.get('confidence'))}"
            )
        if not (
            _as_list(findings_changes.get("added"))
            or _as_list(findings_changes.get("removed"))
            or _as_list(findings_changes.get("changed"))
        ):
            lines.append("无敏感发现变化。")

    findings = _as_list(entry.get("findings"))
    if findings:
        lines.extend(
            [
                "",
                f"{heading}# 发现条目",
                "",
                "| 表 | 列 | 建议类型 | 置信度 | 得分 | 命中率 | 校验通过率 |",
                "|---|---|---|---|---:|---:|---:|",
            ]
        )
        for finding in findings:
            finding = _as_dict(finding)
            lines.append(
                f"| {_cell(finding.get('table_name'))} | {_cell(finding.get('column_name'))} | "
                f"{_cell(finding.get('sensitive_type'))} | "
                f"{CONFIDENCE_LABELS.get(str(finding.get('confidence')), finding.get('confidence'))} | "
                f"{_cell(finding.get('score'))} | {_cell(finding.get('hit_rate'))} | "
                f"{_cell(finding.get('validate_rate'))} |"
            )
    return lines


def _render_markdown(report: dict[str, Any]) -> str:
    aggregate = _as_dict(report.get("aggregate"))
    dataset = _as_dict(report.get("dataset"))
    audit = _as_dict(report.get("audit"))
    trend = _as_dict(report.get("trend"))
    anomalies = _as_list(report.get("anomalies"))
    history = _as_list(report.get("history"))
    runs = _as_list(report.get("runs"))
    audit_append = _as_dict(report.get("audit_append"))
    folded = bool(aggregate.get("details_folded"))
    detail_runs = _as_list(_as_dict(report.get("appendix")).get("runs")) if folded else runs

    lines = [
        "# maskline 汇总报告",
        "",
        f"- 汇总 ID：`{_cell(aggregate.get('aggregate_id'))}`",
        f"- 数据集：`{_cell(dataset.get('path'))}`",
        f"- 数据集指纹：`{_cell(dataset.get('fingerprint'))}`",
        f"- 数据集类型：{_cell(dataset.get('kind'))}",
        f"- 历史运行数：{_cell(aggregate.get('history_runs'))}"
        f"（纳入 {_cell(aggregate.get('runs_included'))}"
        f"，异常排除 {_cell(aggregate.get('runs_excluded'))}）",
        f"- 明细阈值：{_cell(aggregate.get('detail_limit'))} 轮",
        f"- 明细折叠：{'是' if aggregate.get('details_folded') else '否'}",
        f"- 报告生成时间：{_cell(report.get('generated_at'))}",
        "",
        "## 审计链状态",
        "",
        f"- 审计日志：`{_cell(audit.get('path'))}`（{'存在' if audit.get('present') else '缺失'}）",
        f"- 链校验：{'通过' if audit.get('valid') else '未通过'}",
        f"- 条目数：{_cell(audit.get('entries'))}",
        f"- 头哈希：`{_cell(audit.get('head_hash'))}`",
        f"- 锚点：`{_cell(_as_dict(audit.get('anchor')).get('path'))}`"
        f"（{'存在' if _as_dict(audit.get('anchor')).get('present') else '缺失'}"
        f"，{'匹配' if _as_dict(audit.get('anchor')).get('matches_chain') else '不匹配'}）",
    ]
    if audit.get("error"):
        lines.append(f"- 错误：{_cell(audit.get('error'))}")
    if anomalies:
        lines.append("- 提示：审计链异常会使相关运行无法通过校验，默认不纳入汇总。")

    lines.extend(
        [
            "",
            "## 核心变化趋势",
            "",
            f"- 纳入运行的策略变更轮次：{_cell(trend.get('policy_change_count'))}",
        ]
    )
    first = _as_dict(trend.get("findings_first"))
    last = _as_dict(trend.get("findings_last"))
    delta = _as_dict(trend.get("findings_delta"))
    if first and last:
        lines.append(
            f"- 发现总数：首轮 {sum(int(first.get(key, 0)) for key in CONFIDENCE_KEYS)}"
            f" -> 末轮 {sum(int(last.get(key, 0)) for key in CONFIDENCE_KEYS)}"
            f"（Δ {sum(int(delta.get(key, 0)) for key in CONFIDENCE_KEYS) if delta else 0}）"
        )
        lines.append(
            "- 置信度分布（首轮/末轮）："
            f"高 {first.get('high', 0)}/{last.get('high', 0)}，"
            f"中 {first.get('medium', 0)}/{last.get('medium', 0)}，"
            f"低 {first.get('low', 0)}/{last.get('low', 0)}"
        )
    else:
        lines.append("- 发现趋势：历史报告快照不足，无法计算首末轮变化。")

    lines.extend(
        [
            "",
            "## 运行概览",
            "",
            "| run_id | 开始时间 | 状态 | 纳入 | 审计 | 行数 | 发现(高/中/低) | 策略变更 |",
            "|---|---|---|---|---|---:|---|---|",
        ]
    )
    for item in history:
        item = _as_dict(item)
        run = _as_dict(item.get("run"))
        counts = _as_dict(item.get("confidence_counts"))
        findings_text = "—" if not item.get("findings_available") else (
            f"{counts.get('high', 0)}/{counts.get('medium', 0)}/{counts.get('low', 0)}"
        )
        audit_view = _as_dict(item.get("audit"))
        if audit_view.get("verified"):
            audit_text = "通过"
        elif audit_view.get("entry_seq") is None:
            audit_text = "缺失"
        else:
            audit_text = "未验证"
        lines.append(
            f"| `{_cell(run.get('run_id'))}` | {_cell(run.get('started_at'))} | "
            f"{_cell(item.get('status'))} | {'是' if item.get('included') else '否'} | "
            f"{audit_text} | {_cell(run.get('rows_processed'))} | {findings_text} | "
            f"{'是' if _as_dict(item.get('changes_summary')).get('policy_changed') else '否'} |"
        )

    lines.extend(["", "## 异常运行（未纳入汇总）", ""])
    if anomalies:
        lines.extend(
            [
                "| run_id | 状态 | 原因 | 输出产物 | 审计 |",
                "|---|---|---|---|---|",
            ]
        )
        for item in anomalies:
            item = _as_dict(item)
            run = _as_dict(item.get("run"))
            output = _as_dict(_as_dict(item.get("artifacts")).get("output"))
            reasons = ", ".join(str(reason) for reason in _as_list(item.get("reasons")))
            audit_text = "通过" if _as_dict(item.get("audit")).get("verified") else "未通过"
            lines.append(
                f"| `{_cell(run.get('run_id'))}` | {_cell(item.get('status'))} | "
                f"{_cell(reasons)} | {'存在' if output.get('present') else '缺失'} | "
                f"{audit_text} |"
            )
        lines.append("")
        lines.append("> 异常条目已单独标注，报告生成未中断；修复后可重新生成以获得完整汇总。")
    else:
        lines.append("无。所有历史运行均通过默认状态校验。")

    if folded:
        lines.extend(
            [
                "",
                "## 逐轮明细",
                "",
                f"历史运行 {aggregate.get('history_runs')} 轮，超过阈值 "
                f"{aggregate.get('detail_limit')} 轮；逐轮明细已折叠到附录。",
                "",
            ]
        )
        lines.append("## 附录：逐轮明细")
    else:
        lines.extend(["", "## 逐轮明细", ""])

    for entry in detail_runs:
        lines.extend(_render_run_detail(_as_dict(entry)))
        lines.append("")

    lines.extend(["", "## 汇总审计追加", ""])
    append_status = audit_append.get("status")
    if append_status == "appended":
        lines.append(
            f"- 状态：已追加到现有审计链（seq={_cell(audit_append.get('seq'))}，"
            f"entry_hash=`{_cell(audit_append.get('entry_hash'))}`）"
        )
    elif append_status == "skipped":
        lines.append(f"- 状态：已跳过（{_cell(audit_append.get('reason'))}）")
    elif append_status == "failed":
        lines.append(f"- 状态：追加失败（{_cell(audit_append.get('error'))}）")
    else:
        lines.append(f"- 状态：{_cell(append_status)}")
    lines.append("")
    return "\n".join(lines)


def _write_outputs(paths: Paths, fingerprint: str, report: dict[str, Any]) -> tuple[Path, Path]:
    paths.reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = paths.reports_dir / f"aggregate-{fingerprint[:16]}.json"
    markdown_path = paths.reports_dir / f"aggregate-{fingerprint[:16]}.md"
    atomic_write_text(
        markdown_path,
        _render_markdown(report),
    )
    atomic_write_text(
        json_path,
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
    )
    return markdown_path, json_path


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _aggregate_id(fingerprint: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"agg-{fingerprint[:16]}-{stamp}"


def generate_aggregate_report(
    paths: Paths,
    target: str | Path,
    *,
    detail_limit: int = DEFAULT_DETAIL_LIMIT,
    include_anomalies: bool = False,
) -> AggregateReportResult:
    """Build an MD/JSON report spanning every historical run of one dataset.

    ``target`` is either a dataset path or a 64-character content fingerprint.
    Only runs that pass status, audit-chain, and output-artifact checks are
    included by default; anomalous runs are listed separately and never abort
    generation.
    """
    if detail_limit < 1:
        raise AggregateError("detail_limit must be positive")

    fingerprint, dataset_path, record, inventory = _resolve_dataset(paths, target)
    audit_status, audit_entries = _audit_status(paths)
    audit_chain_valid = bool(audit_status.get("valid"))

    run_records = read_run_records(paths.checkpoint_db, fingerprint)
    records_by_id = {
        str(item.get("run_id")): item
        for item in run_records
        if item.get("run_id") is not None
    }
    audit_by_run: dict[str, dict[str, Any]] = {}
    duplicate_audit_entries: dict[str, int] = {}
    for entry in audit_entries:
        if entry.get("event") == AGGREGATE_EVENT:
            continue
        if entry.get("dataset_fingerprint") != fingerprint:
            continue
        run_id = entry.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            continue
        existing = audit_by_run.get(run_id)
        if existing is not None:
            duplicate_audit_entries[run_id] = duplicate_audit_entries.get(run_id, 1) + 1
            try:
                existing_seq = int(existing.get("seq") or 0)
            except (TypeError, ValueError):
                existing_seq = 0
            try:
                new_seq = int(entry.get("seq") or 0)
            except (TypeError, ValueError):
                new_seq = 0
            if new_seq >= existing_seq:
                audit_by_run[run_id] = entry
        else:
            audit_by_run[run_id] = entry

    run_ids = sorted(set(records_by_id) | set(audit_by_run))
    entries: list[dict[str, Any]] = []
    for run_id in run_ids:
        entries.append(
            _build_run_entry(
                paths,
                fingerprint,
                dataset_path,
                run_id,
                records_by_id.get(run_id),
                audit_by_run.get(run_id),
                duplicate_audit_entries.get(run_id, 0),
                audit_chain_valid,
            )
        )
    entries.sort(key=_sort_key)
    _compute_changes(entries)

    included = [
        entry
        for entry in entries
        if _as_dict(entry.get("validation")).get("passed") or include_anomalies
    ]
    anomalies_entries = [
        entry for entry in entries if not _as_dict(entry.get("validation")).get("passed")
    ]
    excluded_ids = tuple(
        str(_as_dict(entry.get("run")).get("run_id"))
        for entry in anomalies_entries
        if not include_anomalies
    )
    included_ids = tuple(
        str(_as_dict(entry.get("run")).get("run_id")) for entry in included
    )

    details_folded = len(entries) > detail_limit
    history_views = [_summary_view(entry) for entry in entries]
    anomaly_views = [_anomaly_view(entry) for entry in anomalies_entries]

    registry_findings = read_findings_snapshot(paths.meta_db, fingerprint)
    manifest_path = paths.manifest_dir / f"{fingerprint[:16]}.json"
    dataset_block = {
        "path": dataset_path,
        "fingerprint": fingerprint,
        "kind": _first(
            _as_dict(record).get("kind"),
            inventory.kind if inventory else None,
        ),
        "size_bytes": _as_dict(record).get("size_bytes"),
        "row_count": _as_dict(record).get("row_count"),
        "tables": _as_dict(record).get("tables"),
        "registered_at": _as_dict(record).get("registered_at"),
        "source_present": bool(dataset_path) and Path(str(dataset_path)).is_file(),
        "manifest": {
            "path": str(manifest_path),
            "present": manifest_path.is_file(),
        },
        "latest_registry_findings": registry_findings,
    }

    aggregate_id = _aggregate_id(fingerprint)
    can_append = bool(audit_status.get("present") and audit_status.get("valid"))
    if can_append:
        initial_append: dict[str, Any] = {"status": "pending"}
    elif not audit_status.get("present"):
        initial_append = {
            "status": "skipped",
            "reason": "audit log is missing; no existing chain to append to",
        }
    else:
        initial_append = {
            "status": "skipped",
            "reason": f"audit chain is not valid: {audit_status.get('error')}",
        }

    report = {
        "aggregate": {
            "aggregate_id": aggregate_id,
            "schema_version": 1,
            "history_runs": len(entries),
            "runs_included": len(included),
            "runs_excluded": len(excluded_ids),
            "anomalies": len(anomalies_entries),
            "detail_limit": detail_limit,
            "details_folded": details_folded,
            "generated_at": _now(),
        },
        "dataset": dataset_block,
        "audit": audit_status,
        "trend": _trend_view(entries, included, anomalies_entries),
        "history": history_views,
        "runs": [_compact_run_view(entry) for entry in included] if details_folded else included,
        "anomalies": anomaly_views,
        # Folded reports keep the full per-run detail in the appendix so JSON
        # consumers still have access to every finding and policy change, while
        # the main `runs` list stays compact.
        "appendix": {"runs": included} if details_folded else None,
        "audit_append": initial_append,
        "generated_at": _now(),
    }

    markdown_path, json_path = _write_outputs(paths, fingerprint, report)

    audit_entry: dict[str, Any] | None = None
    if can_append:
        try:
            entry_body = {
                "event": AGGREGATE_EVENT,
                "run_id": aggregate_id,
                "aggregate_id": aggregate_id,
                "dataset_path": dataset_path,
                "dataset_fingerprint": fingerprint,
                "runs_considered": len(entries),
                "runs_included": len(included),
                "runs_excluded": len(excluded_ids),
                "anomalies": len(anomalies_entries),
                "included_run_ids": list(included_ids),
                "excluded_run_ids": list(excluded_ids),
                "details_folded": details_folded,
                "reports": {
                    "markdown": str(markdown_path),
                    "json": str(json_path),
                },
                "audit_status_before": {
                    "valid": True,
                    "entries": audit_status.get("entries"),
                    "head_hash": audit_status.get("head_hash"),
                },
                "generated_at": report["generated_at"],
            }
            audit_entry = AuditLog(paths.audit_path).append(entry_body)
            report["audit_append"] = {
                "status": "appended",
                "seq": audit_entry.get("seq"),
                "entry_hash": audit_entry.get("entry_hash"),
            }
        except (AuditError, OSError) as exc:
            report["audit_append"] = {"status": "failed", "error": str(exc)}
        # Rewrite after the append outcome is known so the report itself records
        # whether traceability was achieved.
        _write_outputs(paths, fingerprint, report)

    return AggregateReportResult(
        markdown_path=markdown_path,
        json_path=json_path,
        dataset_fingerprint=fingerprint,
        aggregate_id=aggregate_id,
        history_runs=len(entries),
        included_runs=included_ids,
        excluded_runs=excluded_ids,
        details_folded=details_folded,
        audit_entry=audit_entry,
        audit_append_status=str(_as_dict(report.get("audit_append")).get("status")),
    )
