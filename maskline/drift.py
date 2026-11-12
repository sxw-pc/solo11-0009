"""Cross-version drift detection over stored discovery findings.

Compares the findings of two registered versions of one dataset (same path,
different content fingerprints) and reports three core drift classes:

- ``field_added`` / ``field_removed``: columns present in only one version
- ``type_changed``: the winning sensitive type of a column changed
- ``level_changed``: same sensitive type, different confidence level

Everything here operates on registry metadata only: no dataset content is
read, and nothing leaves the machine. Sampling noise is absorbed by a hit /
validate rate tolerance (default 5%): classification flips whose underlying
rates moved within the tolerance never raise an event.

User-supplied ignore rules are loaded from a YAML file that is validated and
fingerprinted exactly like a policy file; the fingerprint is embedded in
every drift record so later modification of the rules is detectable. Ignored
events are never deleted — they are recorded as suppressed, together with
the rule that matched them.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .utils import MasklineError, canonical_json

DRIFT_TYPES = ("field_added", "field_removed", "type_changed", "level_changed")
DEFAULT_HIT_TOLERANCE = 0.05
LEVEL_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


class DriftRulesError(MasklineError):
    pass


# ---------------------------------------------------------------------------
# Ignore rules (fingerprinted like policy files)


@dataclass(frozen=True)
class DriftIgnoreRule:
    table: str
    column: str
    drift_types: tuple[str, ...] = ()
    reason: str = ""

    def matches(self, event: "DriftEvent") -> bool:
        if self.table != "*" and self.table != event.table:
            return False
        if self.column != "*" and self.column != event.column:
            return False
        if self.drift_types and event.drift_type not in self.drift_types:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "column": self.column,
            "drift_types": list(self.drift_types),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DriftIgnoreRules:
    name: str
    rules: tuple[DriftIgnoreRule, ...]
    fingerprint: str
    source_path: Path

    def match(self, event: "DriftEvent") -> tuple[int, DriftIgnoreRule] | None:
        for index, rule in enumerate(self.rules):
            if rule.matches(event):
                return index, rule
        return None


def _expect_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DriftRulesError(f"{where} must be a mapping")
    return value


def _parse_rule(raw: Any, where: str) -> DriftIgnoreRule:
    config = _expect_mapping(raw, where)
    unknown = set(config) - {"table", "column", "drift_types", "reason"}
    if unknown:
        raise DriftRulesError(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
    table = config.get("table")
    column = config.get("column")
    if not isinstance(table, str) or not table.strip():
        raise DriftRulesError(f"{where}: table must be a non-empty string")
    if not isinstance(column, str) or not column.strip():
        raise DriftRulesError(f"{where}: column must be a non-empty string")
    raw_types = config.get("drift_types", [])
    if not isinstance(raw_types, list):
        raise DriftRulesError(f"{where}: drift_types must be a list")
    drift_types: list[str] = []
    for item in raw_types:
        if item not in DRIFT_TYPES:
            raise DriftRulesError(
                f"{where}: unknown drift type {item!r}; "
                f"expected one of {', '.join(DRIFT_TYPES)}"
            )
        if item in drift_types:
            raise DriftRulesError(f"{where}: duplicate drift type {item!r}")
        drift_types.append(item)
    reason = config.get("reason", "")
    if not isinstance(reason, str):
        raise DriftRulesError(f"{where}: reason must be a string")
    return DriftIgnoreRule(table, column, tuple(drift_types), reason)


def load_ignore_rules(path: str | Path) -> DriftIgnoreRules:
    """Load and fingerprint a drift-ignore rules file (same model as policies)."""
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise DriftRulesError(f"ignore rules file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DriftRulesError(f"cannot load ignore rules {source}: {exc}") from exc
    root = _expect_mapping(data, "ignore rules root")
    unknown = set(root) - {"version", "name", "rules"}
    if unknown:
        raise DriftRulesError(
            f"ignore rules root has unknown keys: {', '.join(sorted(unknown))}"
        )
    version = root.get("version")
    if version != 1 or isinstance(version, bool):
        raise DriftRulesError("ignore rules version must be the integer 1")
    name = root.get("name", "")
    if not isinstance(name, str):
        raise DriftRulesError("ignore rules name must be a string")
    raw_rules = root.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise DriftRulesError("ignore rules must contain a non-empty 'rules' list")
    rules = tuple(
        _parse_rule(raw_rule, f"rules[{index}]")
        for index, raw_rule in enumerate(raw_rules)
    )
    normalized = {
        "version": 1,
        "name": name,
        "rules": [rule.to_dict() for rule in rules],
    }
    fingerprint = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return DriftIgnoreRules(
        name=name,
        rules=rules,
        fingerprint=fingerprint,
        source_path=source,
    )


# ---------------------------------------------------------------------------
# Drift events and reports


@dataclass(frozen=True)
class DriftEvent:
    drift_type: str
    table: str
    column: str
    severity: str
    old: dict[str, Any] | None
    new: dict[str, Any] | None

    def to_record(self) -> dict[str, Any]:
        return {
            "drift_type": self.drift_type,
            "table": self.table,
            "column": self.column,
            "severity": self.severity,
            "old": self.old,
            "new": self.new,
        }


@dataclass(frozen=True)
class SuppressedEvent:
    event: DriftEvent
    rule: DriftIgnoreRule
    rule_index: int

    def to_record(self) -> dict[str, Any]:
        return {
            "event": self.event.to_record(),
            "rule": self.rule.to_dict(),
            "rule_index": self.rule_index,
        }


@dataclass
class DriftReport:
    """Outcome of one cross-version comparison (metadata only)."""

    dataset_path: str
    baseline_fingerprint: str
    current_fingerprint: str
    ignore_fingerprint: str | None
    events: list[DriftEvent] = field(default_factory=list)
    suppressed: list[SuppressedEvent] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    audit_seq: int | None = None
    audit_entry_hash: str | None = None

    def summary(self) -> dict[str, int]:
        counts = {drift_type: 0 for drift_type in DRIFT_TYPES}
        for event in self.events:
            counts[event.drift_type] += 1
        counts["active"] = len(self.events)
        counts["suppressed"] = len(self.suppressed)
        return counts

    def to_record(self) -> dict[str, Any]:
        """Canonical record shared verbatim by the audit chain and reports."""
        return {
            "dataset_path": self.dataset_path,
            "baseline_fingerprint": self.baseline_fingerprint,
            "current_fingerprint": self.current_fingerprint,
            "ignore_fingerprint": self.ignore_fingerprint,
            "events": [event.to_record() for event in self.events],
            "suppressed": [item.to_record() for item in self.suppressed],
            "summary": self.summary(),
            "elapsed_seconds": round(self.elapsed_seconds, 6),
        }


# ---------------------------------------------------------------------------
# Comparison engine


def _brief(finding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sensitive_type": finding.get("sensitive_type"),
        "confidence": finding.get("confidence", "none"),
        "hit_rate": round(float(finding.get("hit_rate", 0.0)), 6),
        "validate_rate": round(float(finding.get("validate_rate", 0.0)), 6),
        "score": round(float(finding.get("score", 0.0)), 6),
    }


def _candidate_stats(finding: Mapping[str, Any], sensitive_type: str) -> tuple[float, float]:
    """Hit/validate rate of one sensitive type within a finding (0 if absent)."""
    if finding.get("sensitive_type") == sensitive_type:
        return (
            float(finding.get("hit_rate", 0.0)),
            float(finding.get("validate_rate", 0.0)),
        )
    for candidate in finding.get("candidates") or []:
        if candidate.get("sensitive_type") == sensitive_type:
            return (
                float(candidate.get("hit_rate", 0.0)),
                float(candidate.get("validate_rate", 0.0)),
            )
    return 0.0, 0.0


def _within_tolerance(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    sensitive_types: tuple[str, ...],
    tolerance: float,
) -> bool:
    """True when every involved type's rates moved within the sampling tolerance.

    A small epsilon keeps exactly-at-boundary deltas (e.g. 0.80 vs 0.75,
    whose float difference is 0.050000000000000044) inside "within 5%".
    """
    limit = tolerance + 1e-9
    for sensitive_type in sensitive_types:
        old_hit, old_validate = _candidate_stats(old, sensitive_type)
        new_hit, new_validate = _candidate_stats(new, sensitive_type)
        if abs(old_hit - new_hit) > limit:
            return False
        if abs(old_validate - new_validate) > limit:
            return False
    return True


def _added_severity(finding: Mapping[str, Any]) -> str:
    confidence = finding.get("confidence", "none")
    if confidence in {"high", "medium"}:
        return "high"
    if confidence == "low":
        return "medium"
    return "low"


def _removed_severity(finding: Mapping[str, Any]) -> str:
    return "medium" if finding.get("confidence", "none") in {"high", "medium"} else "low"


def _type_severity(new_type: str | None) -> str:
    return "medium" if new_type is None else "high"


def _level_severity(old: Mapping[str, Any], new: Mapping[str, Any]) -> str:
    old_rank = LEVEL_RANK.get(old.get("confidence", "none"), 0)
    new_rank = LEVEL_RANK.get(new.get("confidence", "none"), 0)
    if new_rank > old_rank:
        return "high" if new.get("confidence") == "high" else "medium"
    return "low"


def _compare_column(
    table: str,
    column: str,
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    tolerance: float,
) -> DriftEvent | None:
    old_type = old.get("sensitive_type")
    new_type = new.get("sensitive_type")
    if old_type == new_type:
        if old_type is None or old.get("confidence") == new.get("confidence"):
            return None
        if _within_tolerance(old, new, (old_type,), tolerance):
            return None
        return DriftEvent(
            "level_changed", table, column, _level_severity(old, new),
            _brief(old), _brief(new),
        )
    involved = tuple(item for item in (old_type, new_type) if item)
    if involved and _within_tolerance(old, new, involved, tolerance):
        return None
    return DriftEvent(
        "type_changed", table, column, _type_severity(new_type),
        _brief(old), _brief(new),
    )


def compare_findings(
    baseline: list[dict[str, Any]],
    current: list[dict[str, Any]],
    *,
    dataset_path: str,
    baseline_fingerprint: str,
    current_fingerprint: str,
    ignore_rules: DriftIgnoreRules | None = None,
    hit_tolerance: float = DEFAULT_HIT_TOLERANCE,
) -> DriftReport:
    """Compare two versions' finding rows; pure metadata, fully offline."""
    started = time.perf_counter()
    base_map = {(item["table_name"], item["column_name"]): item for item in baseline}
    curr_map = {(item["table_name"], item["column_name"]): item for item in current}
    events: list[DriftEvent] = []
    for key in sorted(curr_map.keys() - base_map.keys()):
        finding = curr_map[key]
        events.append(
            DriftEvent(
                "field_added", key[0], key[1], _added_severity(finding),
                None, _brief(finding),
            )
        )
    for key in sorted(base_map.keys() - curr_map.keys()):
        finding = base_map[key]
        events.append(
            DriftEvent(
                "field_removed", key[0], key[1], _removed_severity(finding),
                _brief(finding), None,
            )
        )
    for key in sorted(base_map.keys() & curr_map.keys()):
        event = _compare_column(
            key[0], key[1], base_map[key], curr_map[key], hit_tolerance
        )
        if event is not None:
            events.append(event)
    events.sort(key=lambda event: (event.table, event.column, event.drift_type))
    active: list[DriftEvent] = []
    suppressed: list[SuppressedEvent] = []
    for event in events:
        matched = ignore_rules.match(event) if ignore_rules else None
        if matched is None:
            active.append(event)
        else:
            index, rule = matched
            suppressed.append(SuppressedEvent(event, rule, index))
    elapsed = time.perf_counter() - started
    return DriftReport(
        dataset_path=dataset_path,
        baseline_fingerprint=baseline_fingerprint,
        current_fingerprint=current_fingerprint,
        ignore_fingerprint=ignore_rules.fingerprint if ignore_rules else None,
        events=active,
        suppressed=suppressed,
        elapsed_seconds=elapsed,
    )
