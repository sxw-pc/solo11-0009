"""Cross-version discovery comparison and sensitive drift detection.

The comparison is deliberately registry-only: it consumes the findings and
schema snapshots that were already persisted by an earlier scan. It never
opens the source dataset, so it works entirely offline and its cost scales
with the number of columns, not with dataset size.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .audit import AuditIntegrityError, AuditLog, read_audit_entries
from .config import Paths
from .registry import Catalog, DatasetInventory
from .utils import MasklineError, canonical_json, sha256_text, sqlite_connect_readonly

DRIFT_TYPES = (
    "column_added",
    "column_removed",
    "type_changed",
    "level_changed",
)
DRIFT_TYPE_ORDER = {name: index for index, name in enumerate(DRIFT_TYPES)}
DRIFT_TYPE_LABELS = {
    "column_added": "新增敏感字段",
    "column_removed": "删除敏感字段",
    "type_changed": "敏感类型变更",
    "level_changed": "敏感等级调整",
}
SEVERITY_LABELS = {"high": "高", "medium": "中", "low": "低"}
CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
SENSITIVE_CONFIDENCE = {"high", "medium"}
HIT_RATE_TOLERANCE = 0.05
IGNORE_RULES_VERSION = 1


class DriftError(MasklineError):
    pass


# ----------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class IgnoreRule:
    table: str
    column: str
    drift_types: tuple[str, ...]
    reason: str = ""

    def matches(self, table: str, column: str, drift_type: str) -> bool:
        return (
            _pattern_matches(self.table, table)
            and _pattern_matches(self.column, column)
            and drift_type in self.drift_types
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "column": self.column,
            "drift_types": list(self.drift_types),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class IgnoreRules:
    name: str
    description: str
    entries: tuple[IgnoreRule, ...]
    fingerprint: str
    source_path: Path


@dataclass(frozen=True)
class DriftItem:
    drift_type: str
    table: str
    column: str
    severity: str
    baseline: dict[str, Any] | None
    current: dict[str, Any] | None
    hit_rate_delta: float | None = None
    ignore_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "drift_type": self.drift_type,
            "type_label": DRIFT_TYPE_LABELS[self.drift_type],
            "table": self.table,
            "column": self.column,
            "severity": self.severity,
            "baseline": dict(self.baseline) if self.baseline is not None else None,
            "current": dict(self.current) if self.current is not None else None,
        }
        if self.hit_rate_delta is not None:
            payload["hit_rate_delta"] = round(self.hit_rate_delta, 6)
        if self.ignore_reason:
            payload["ignore_reason"] = self.ignore_reason
        return payload


@dataclass(frozen=True)
class DriftComparison:
    dataset_path: str
    baseline_fingerprint: str
    current_fingerprint: str
    baseline_registered_at: str | None
    hit_rate_tolerance: float
    ignore_rules_fingerprint: str | None
    ignore_rules_path: str | None
    drifts: tuple[DriftItem, ...] = ()
    ignored_drifts: tuple[DriftItem, ...] = ()

    @property
    def detected(self) -> bool:
        return bool(self.drifts)

    @property
    def dedupe_key(self) -> str:
        return sha256_text(
            canonical_json(
                {
                    "baseline": self.baseline_fingerprint,
                    "current": self.current_fingerprint,
                    "ignore_rules": self.ignore_rules_fingerprint or "",
                    "tolerance": round(self.hit_rate_tolerance, 6),
                }
            )
        )

    def summary(self) -> dict[str, int]:
        counts = {name: 0 for name in DRIFT_TYPES}
        for item in self.drifts:
            counts[item.drift_type] = counts.get(item.drift_type, 0) + 1
        counts["ignored"] = len(self.ignored_drifts)
        counts["total"] = len(self.drifts)
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_path": self.dataset_path,
            "baseline_fingerprint": self.baseline_fingerprint,
            "current_fingerprint": self.current_fingerprint,
            "baseline_registered_at": self.baseline_registered_at,
            "hit_rate_tolerance": round(self.hit_rate_tolerance, 6),
            "ignore_rules_fingerprint": self.ignore_rules_fingerprint,
            "ignore_rules_path": self.ignore_rules_path,
            "drifts": [item.to_dict() for item in self.drifts],
            "ignored_drifts": [item.to_dict() for item in self.ignored_drifts],
            "summary": self.summary(),
        }


@dataclass(frozen=True)
class DriftRecord:
    """A comparison tied to the exact append-only audit entry that stores it."""

    comparison: DriftComparison
    audit_entry: dict[str, Any]

    def to_report_dict(self) -> dict[str, Any]:
        payload = self.comparison.to_dict()
        payload["audit_seq"] = int(self.audit_entry["seq"])
        payload["audit_entry_hash"] = self.audit_entry["entry_hash"]
        # Use the stored audit payload directly so the report and the audit
        # chain are byte-for-byte equivalent in their drift content.
        payload["drifts"] = self.audit_entry.get("drifts", payload["drifts"])
        payload["ignored_drifts"] = self.audit_entry.get(
            "ignored_drifts", payload["ignored_drifts"]
        )
        payload["summary"] = self.audit_entry.get("summary", payload["summary"])
        return payload


# ----------------------------------------------------------------------
# Ignore rules loading with fingerprint verification
# ----------------------------------------------------------------------


def _pattern_matches(pattern: str, value: str) -> bool:
    return pattern == "*" or fnmatch.fnmatchcase(value, pattern)


def _expect_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DriftError(f"{where} must be a mapping")
    return value


def _parse_ignore_rule(raw: Any, where: str) -> IgnoreRule:
    config = _expect_mapping(raw, where)
    unknown = set(config) - {"table", "column", "drift_types", "reason"}
    if unknown:
        raise DriftError(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
    table = config.get("table")
    column = config.get("column")
    if not isinstance(table, str) or not table:
        raise DriftError(f"{where}: table must be a non-empty string")
    if not isinstance(column, str) or not column:
        raise DriftError(f"{where}: column must be a non-empty string")
    raw_types = config.get("drift_types", list(DRIFT_TYPES))
    if not isinstance(raw_types, list) or not raw_types:
        raise DriftError(f"{where}: drift_types must be a non-empty list")
    drift_types: list[str] = []
    for item in raw_types:
        if not isinstance(item, str) or item not in DRIFT_TYPES:
            raise DriftError(
                f"{where}: unknown drift type {item!r}; expected one of "
                + ", ".join(DRIFT_TYPES)
            )
        if item in drift_types:
            raise DriftError(f"{where}: duplicate drift type {item!r}")
        drift_types.append(item)
    reason = config.get("reason", "")
    if not isinstance(reason, str):
        raise DriftError(f"{where}: reason must be a string")
    return IgnoreRule(
        table=table,
        column=column,
        drift_types=tuple(sorted(drift_types, key=lambda name: DRIFT_TYPE_ORDER[name])),
        reason=reason,
    )


def load_ignore_rules(
    path: str | Path, *, expected_fingerprint: str | None = None
) -> IgnoreRules:
    """Load and strictly validate drift ignore rules.

    The normalized content fingerprint is stable across formatting changes and
    can be pinned in the registry. A mismatch with ``expected_fingerprint``
    means the rules file was edited outside an approved flow.
    """
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise DriftError(f"drift ignore rules file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DriftError(f"cannot load drift ignore rules {source}: {exc}") from exc
    root = _expect_mapping(data, "ignore rules root")
    unknown = set(root) - {"version", "name", "description", "ignore"}
    if unknown:
        raise DriftError(f"ignore rules root has unknown keys: {', '.join(sorted(unknown))}")
    version = root.get("version")
    if version != IGNORE_RULES_VERSION or isinstance(version, bool):
        raise DriftError(f"ignore rules version must be the integer {IGNORE_RULES_VERSION}")
    name = root.get("name")
    if not isinstance(name, str) or not name.strip():
        raise DriftError("ignore rules name must be a non-empty string")
    description = root.get("description", "")
    if not isinstance(description, str):
        raise DriftError("ignore rules description must be a string")
    raw_entries = root.get("ignore", [])
    if not isinstance(raw_entries, list):
        raise DriftError("ignore rules 'ignore' must be a list")
    entries: list[IgnoreRule] = []
    seen: set[tuple[str, str, tuple[str, ...], str]] = set()
    for index, raw in enumerate(raw_entries):
        rule = _parse_ignore_rule(raw, f"ignore[{index}]")
        identity = (rule.table, rule.column, rule.drift_types, rule.reason)
        if identity in seen:
            raise DriftError(f"ignore[{index}] duplicates an earlier rule")
        seen.add(identity)
        entries.append(rule)
    entries.sort(key=lambda rule: (rule.table, rule.column, rule.drift_types, rule.reason))
    normalized = {
        "version": IGNORE_RULES_VERSION,
        "name": name,
        "description": description,
        "ignore": [rule.to_dict() for rule in entries],
    }
    fingerprint = sha256_text(canonical_json(normalized))
    if expected_fingerprint is not None and fingerprint != expected_fingerprint:
        raise DriftError(
            "drift ignore rules fingerprint mismatch: file may have been modified "
            f"without approval (expected {expected_fingerprint}, got {fingerprint})"
        )
    return IgnoreRules(
        name=name,
        description=description,
        entries=tuple(entries),
        fingerprint=fingerprint,
        source_path=source,
    )


def ensure_ignore_rules_pin(
    catalog: Catalog, rules: IgnoreRules, *, repin: bool = False
) -> None:
    """Pin the ignore-rules fingerprint and fail closed on unapproved edits."""
    scope = "drift_ignore_rules:" + str(rules.source_path)
    pinned = catalog.get_config_pin(scope)
    if pinned is None:
        catalog.set_config_pin(scope, rules.fingerprint)
        return
    if pinned == rules.fingerprint:
        return
    if not repin:
        raise DriftError(
            "drift ignore rules were modified after being pinned; "
            f"pinned={pinned}, current={rules.fingerprint}. "
            "Review the change, then re-pin explicitly with --repin-ignore-rules."
        )
    catalog.set_config_pin(scope, rules.fingerprint)


def apply_ignore_rules(
    drifts: Iterable[DriftItem], rules: IgnoreRules | None
) -> tuple[tuple[DriftItem, ...], tuple[DriftItem, ...]]:
    if rules is None:
        return tuple(drifts), ()
    active: list[DriftItem] = []
    ignored: list[DriftItem] = []
    for item in drifts:
        reason = next(
            (
                rule.reason or "ignored by drift ignore rules"
                for rule in rules.entries
                if rule.matches(item.table, item.column, item.drift_type)
            ),
            None,
        )
        if reason is None:
            active.append(item)
        else:
            ignored.append(replace(item, ignore_reason=reason))
    return tuple(active), tuple(ignored)


# ----------------------------------------------------------------------
# Comparison
# ----------------------------------------------------------------------


def _finding_view(finding: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if finding is None:
        return None
    return {
        "sensitive_type": finding.get("sensitive_type"),
        "confidence": finding.get("confidence") or "none",
        "score": round(float(finding.get("score") or 0.0), 4),
        "hit_rate": round(float(finding.get("hit_rate") or 0.0), 4),
        "validate_rate": round(float(finding.get("validate_rate") or 0.0), 4),
        "sample_size": int(finding.get("sample_size") or 0),
    }


def _is_sensitive(view: Mapping[str, Any] | None) -> bool:
    return bool(
        view
        and view.get("sensitive_type")
        and view.get("confidence") in SENSITIVE_CONFIDENCE
    )


def _column_set(
    schema: Mapping[str, Any] | None, findings: Sequence[Mapping[str, Any]]
) -> set[tuple[str, str]]:
    columns: set[tuple[str, str]] = set()
    if schema:
        for table in schema.get("tables", []):
            table_name = table.get("name")
            for column in table.get("columns", []):
                column_name = column.get("name")
                if table_name is not None and column_name is not None:
                    columns.add((str(table_name), str(column_name)))
    for finding in findings:
        columns.add((str(finding["table_name"]), str(finding["column_name"])))
    return columns


def _within_tolerance(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    tolerance: float,
) -> bool:
    return (
        abs(float(current.get("hit_rate") or 0.0) - float(baseline.get("hit_rate") or 0.0))
        <= tolerance
        and abs(
            float(current.get("validate_rate") or 0.0)
            - float(baseline.get("validate_rate") or 0.0)
        )
        <= tolerance
    )


def compare_versions(
    baseline_schema: Mapping[str, Any] | None,
    baseline_findings: Sequence[Mapping[str, Any]],
    current_schema: Mapping[str, Any] | None,
    current_findings: Sequence[Mapping[str, Any]],
    *,
    tolerance: float = HIT_RATE_TOLERANCE,
) -> tuple[DriftItem, ...]:
    """Diff two persisted discovery versions and classify real drift.

    Sampling noise is suppressed when both hit rate and validation rate move
    by no more than ``tolerance``. A genuine type change is still reported:
    replacing an entire phone column with e-mails keeps hit rate at 1.0 but
    must not be mistaken for sampling noise.
    """
    if tolerance < 0:
        raise DriftError("hit rate tolerance must be non-negative")
    baseline_map = {
        (str(item["table_name"]), str(item["column_name"])): item
        for item in baseline_findings
    }
    current_map = {
        (str(item["table_name"]), str(item["column_name"])): item
        for item in current_findings
    }
    baseline_columns = _column_set(baseline_schema, baseline_findings)
    current_columns = _column_set(current_schema, current_findings)
    items: list[DriftItem] = []

    for table, column in sorted(current_columns - baseline_columns):
        finding = current_map.get((table, column))
        if finding is None:
            continue
        current = _finding_view(finding)
        if not _is_sensitive(current):
            continue
        items.append(
            DriftItem(
                drift_type="column_added",
                table=table,
                column=column,
                severity="high" if current["confidence"] == "high" else "medium",
                baseline=None,
                current=current,
            )
        )

    for table, column in sorted(baseline_columns - current_columns):
        finding = baseline_map.get((table, column))
        if finding is None:
            continue
        baseline = _finding_view(finding)
        if not _is_sensitive(baseline):
            continue
        items.append(
            DriftItem(
                drift_type="column_removed",
                table=table,
                column=column,
                severity="medium",
                baseline=baseline,
                current=None,
            )
        )

    for table, column in sorted(baseline_columns & current_columns):
        baseline_finding = baseline_map.get((table, column))
        current_finding = current_map.get((table, column))
        if baseline_finding is None or current_finding is None:
            continue
        baseline = _finding_view(baseline_finding)
        current = _finding_view(current_finding)
        assert baseline is not None and current is not None
        baseline_type = baseline.get("sensitive_type")
        current_type = current.get("sensitive_type")
        delta = float(current["hit_rate"]) - float(baseline["hit_rate"])

        if baseline_type != current_type:
            # A flip between "not sensitive" and sensitive can be caused by a
            # sample hovering around the detection threshold. Suppress it when
            # both hit and validation rates stayed within tolerance. A change
            # between two real sensitive types is always reported.
            if (
                (baseline_type is None or current_type is None)
                and _within_tolerance(baseline, current, tolerance)
            ):
                continue
            items.append(
                DriftItem(
                    drift_type="type_changed",
                    table=table,
                    column=column,
                    severity="high",
                    baseline=baseline,
                    current=current,
                    hit_rate_delta=delta,
                )
            )
            continue

        if baseline_type is None:
            continue

        baseline_confidence = baseline.get("confidence", "none")
        current_confidence = current.get("confidence", "none")
        if baseline_confidence == current_confidence:
            continue
        if _within_tolerance(baseline, current, tolerance):
            continue
        severity = (
            "high"
            if CONFIDENCE_RANK.get(current_confidence, 0)
            > CONFIDENCE_RANK.get(baseline_confidence, 0)
            else "medium"
        )
        items.append(
            DriftItem(
                drift_type="level_changed",
                table=table,
                column=column,
                severity=severity,
                baseline=baseline,
                current=current,
                hit_rate_delta=delta,
            )
        )

    items.sort(
        key=lambda item: (
            item.table,
            item.column,
            DRIFT_TYPE_ORDER[item.drift_type],
        )
    )
    return tuple(items)


def evaluate_version_drift(
    catalog: Catalog,
    dataset_path: str | Path,
    current_fingerprint: str,
    *,
    baseline_fingerprint: str | None = None,
    current_inventory: DatasetInventory | None = None,
    current_findings: Sequence[Mapping[str, Any]] | None = None,
    ignore_rules: IgnoreRules | None = None,
    tolerance: float = HIT_RATE_TOLERANCE,
) -> DriftComparison | None:
    """Compare the current fingerprint with a baseline version.

    By default the newest earlier version registered at the same path is used.
    An explicit ``baseline_fingerprint`` can select any other version. Returns
    ``None`` when no earlier version exists.
    """
    resolved = str(Path(dataset_path).expanduser().resolve())
    if baseline_fingerprint is not None:
        if baseline_fingerprint == current_fingerprint:
            raise DriftError("baseline and current fingerprints must differ")
        baseline = catalog.get_dataset(baseline_fingerprint)
        if baseline is None:
            raise DriftError(f"baseline dataset fingerprint is not registered: {baseline_fingerprint}")
        baseline.setdefault("registered_at", None)
    else:
        baseline = catalog.previous_version(resolved, current_fingerprint)
    if baseline is None:
        return None
    if current_inventory is not None:
        current_schema: Mapping[str, Any] | None = current_inventory.to_record()
    else:
        current_schema = catalog.get_dataset(current_fingerprint)
    if current_schema is None:
        raise DriftError(f"current dataset fingerprint is not registered: {current_fingerprint}")
    if current_findings is None:
        current_findings = catalog.findings_for(current_fingerprint)
    baseline_schema = catalog.get_dataset(baseline["fingerprint"]) or baseline
    baseline_findings = catalog.findings_for(baseline["fingerprint"])
    raw = compare_versions(
        baseline_schema,
        baseline_findings,
        current_schema,
        current_findings,
        tolerance=tolerance,
    )
    active, ignored = apply_ignore_rules(raw, ignore_rules)
    return DriftComparison(
        dataset_path=resolved,
        baseline_fingerprint=baseline["fingerprint"],
        current_fingerprint=current_fingerprint,
        baseline_registered_at=baseline.get("registered_at"),
        hit_rate_tolerance=tolerance,
        ignore_rules_fingerprint=ignore_rules.fingerprint if ignore_rules else None,
        ignore_rules_path=str(ignore_rules.source_path) if ignore_rules else None,
        drifts=active,
        ignored_drifts=ignored,
    )


# ----------------------------------------------------------------------
# Audit-chain integration
# ----------------------------------------------------------------------


def record_drift_comparison(
    paths: Paths, catalog: Catalog, comparison: DriftComparison
) -> DriftRecord:
    """Append the comparison to the audit chain and mirror it in the catalog."""
    existing = catalog.get_drift_comparison(comparison.dedupe_key)
    if existing:
        entries = read_audit_entries(paths.audit_path)
        entry = next(
            (item for item in entries if item.get("seq") == existing.get("audit_seq")),
            None,
        )
        if entry is not None and entry.get("entry_hash") == existing.get("audit_entry_hash"):
            return DriftRecord(comparison, entry)

    payload = comparison.to_dict()
    payload["kind"] = "drift_comparison"
    payload["dedupe_key"] = comparison.dedupe_key
    stored = AuditLog(paths.audit_path).append(payload)
    catalog.save_drift_comparison(
        {
            "dedupe_key": comparison.dedupe_key,
            "dataset_path": comparison.dataset_path,
            "baseline_fingerprint": comparison.baseline_fingerprint,
            "current_fingerprint": comparison.current_fingerprint,
            "baseline_registered_at": comparison.baseline_registered_at,
            "ignore_rules_fingerprint": comparison.ignore_rules_fingerprint,
            "ignore_rules_path": comparison.ignore_rules_path,
            "hit_rate_tolerance": comparison.hit_rate_tolerance,
            "drifts": stored.get("drifts", []),
            "ignored_drifts": stored.get("ignored_drifts", []),
            "summary": stored.get("summary", {}),
            "audit_seq": stored["seq"],
            "audit_entry_hash": stored["entry_hash"],
            "created_at": stored.get("ts"),
        }
    )
    return DriftRecord(comparison, stored)


def verify_registry_drift_records(paths: Paths) -> int:
    """Cross-check catalog drift mirrors against their audit-chain entries.

    Raises :class:`AuditIntegrityError` when a stored drift row was modified
    independently of the append-only log. Returns the number of rows checked.
    """
    meta_path = Path(paths.meta_db)
    if not meta_path.exists():
        return 0
    conn = sqlite_connect_readonly(meta_path)
    try:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "drift_comparisons" not in tables:
            return 0
        rows = [dict(row) for row in conn.execute(
            "SELECT * FROM drift_comparisons ORDER BY rowid"
        ).fetchall()]
    finally:
        conn.close()
    if not rows:
        return 0
    entries = {
        int(entry.get("seq", -1)): entry
        for entry in read_audit_entries(paths.audit_path)
    }
    for row in rows:
        seq = int(row["audit_seq"])
        entry = entries.get(seq)
        if entry is None:
            raise AuditIntegrityError(
                seq, "catalog drift record points to a missing audit entry"
            )
        if entry.get("kind") != "drift_comparison":
            raise AuditIntegrityError(seq, "audit entry is not a drift comparison")
        if entry.get("entry_hash") != row["audit_entry_hash"]:
            raise AuditIntegrityError(
                seq, "catalog drift record audit hash does not match"
            )
        checks = (
            ("drifts_json", "drifts", "drift payload"),
            ("ignored_drifts_json", "ignored_drifts", "ignored drift payload"),
            ("summary_json", "summary", "drift summary"),
        )
        for column, audit_key, label in checks:
            if json.loads(row[column]) != entry.get(audit_key):
                raise AuditIntegrityError(
                    seq, f"catalog {label} differs from the audit entry"
                )
        scalar_checks = (
            ("dataset_path", "dataset_path"),
            ("baseline_fingerprint", "baseline_fingerprint"),
            ("current_fingerprint", "current_fingerprint"),
            ("ignore_rules_fingerprint", "ignore_rules_fingerprint"),
        )
        for column, audit_key in scalar_checks:
            if row[column] != entry.get(audit_key):
                raise AuditIntegrityError(
                    seq, f"catalog {column} differs from the audit entry"
                )
    return len(rows)
