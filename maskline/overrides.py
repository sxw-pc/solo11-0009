"""Human adjudications layered on top of detector findings.

An override file lets a reviewer state, per dataset/table/column, either
`force_sensitive` (treat as sensitive even if detectors say otherwise) or
`force_not_sensitive` (confirmed non-sensitive; stop reporting it). Every
entry requires a reason and is deliberately data-switched: overrides change
discovery conclusions and reporting, never the execution policy.

Safety asymmetry: `force_not_sensitive` can only remove a column from the
finding conclusion. If the masking policy still configures a transformer for
that column, the override does *not* disable it -- the run keeps masking and
a conflict warning is emitted. Masking more than necessary is acceptable;
masking less is not.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from .utils import MasklineError, canonical_json, path_matches

DECISION_SENSITIVE = "force_sensitive"
DECISION_NOT_SENSITIVE = "force_not_sensitive"
DECISIONS = (DECISION_SENSITIVE, DECISION_NOT_SENSITIVE)

OVERRIDE_FILENAME = "overrides.yaml"
OPERATOR_ENV = "MASKLINE_OPERATOR"
DEFAULT_ADJUDICATED_TYPE = "manual_adjudication"


class OverrideError(MasklineError):
    pass


@dataclass(frozen=True)
class OverrideEntry:
    dataset_pattern: str
    table: str
    column: str
    decision: str
    reason: str

    @property
    def is_sensitive(self) -> bool:
        return self.decision == DECISION_SENSITIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset_pattern,
            "table": self.table,
            "column": self.column,
            "decision": self.decision,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class OverrideSet:
    entries: tuple[OverrideEntry, ...]
    fingerprint: str
    source_path: Path
    operator: str


@dataclass
class UnmatchedOverride:
    entry: OverrideEntry
    reason: str
    # "dataset": the rule's dataset could not be matched to a scanned dataset;
    # "table": the dataset matched but has no such table;
    # "column": the table matched but has no such column.
    kind: str

    def to_dict(self) -> dict[str, Any]:
        payload = self.entry.to_dict()
        payload.update({"kind": self.kind, "reason_unmatched": self.reason})
        return payload


@dataclass
class Conflict:
    entry: OverrideEntry
    table: str
    column: str
    transformer: str


@dataclass
class AppliedOverrides:
    """All adjudication effects for one dataset scan or run."""
    dataset: Path
    operator: str = ""
    override_file: str = ""
    override_fingerprint: str = ""
    # True when a masking policy was supplied, i.e. conflicts could be detected.
    policy_checked: bool = False
    matched: list[OverrideEntry] = field(default_factory=list)
    applied: list[dict[str, Any]] = field(default_factory=list)
    unmatched: list[UnmatchedOverride] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)


def _expect_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OverrideError(f"{where} must be a mapping")
    return value


def _parse_entry(index: int, raw: Any) -> OverrideEntry:
    where = f"overrides[{index}]"
    rule = _expect_mapping(raw, where)
    unknown = set(rule) - {"dataset", "table", "column", "decision", "reason"}
    if unknown:
        raise OverrideError(f"{where} has unknown keys: {', '.join(sorted(unknown))}")
    values: dict[str, str] = {}
    for key in ("dataset", "table", "column", "decision", "reason"):
        value = rule.get(key)
        if not isinstance(value, str) or not value.strip():
            raise OverrideError(f"{where}.{key} must be a non-empty string")
        values[key] = value.strip()
    if values["decision"] not in DECISIONS:
        raise OverrideError(
            f"{where}.decision must be one of: {', '.join(DECISIONS)}"
        )
    return OverrideEntry(
        dataset_pattern=values["dataset"],
        table=values["table"],
        column=values["column"],
        decision=values["decision"],
        reason=values["reason"],
    )


def _overlapping_patterns(first: str, second: str) -> bool:
    """Best-effort check that two dataset patterns could match one path."""
    if first == second:
        return True
    if "*" in first or "*" in second:
        return fnmatch.fnmatchcase(first, second) or fnmatch.fnmatchcase(second, first)
    first_name = first.replace("\\", "/").rsplit("/", 1)[-1]
    second_name = second.replace("\\", "/").rsplit("/", 1)[-1]
    return first_name == second_name


def _parse_overrides(data: Any, source_path: Path, operator: str) -> OverrideSet:
    root = _expect_mapping(data, "override root")
    unknown = set(root) - {"version", "description", "overrides"}
    if unknown:
        raise OverrideError(
            "override root has unknown keys: " + ", ".join(sorted(unknown))
        )
    version = root.get("version")
    if version != 1 or isinstance(version, bool):
        raise OverrideError("override version must be the integer 1")
    description = root.get("description", "")
    if not isinstance(description, str):
        raise OverrideError("override description must be a string")
    raw_entries = root.get("overrides", [])
    if not isinstance(raw_entries, list):
        raise OverrideError("overrides must be a list")
    entries: list[OverrideEntry] = []
    for index, raw in enumerate(raw_entries):
        entries.append(_parse_entry(index, raw))
    # Duplicates are an error, not last-wins: the file is human-authored and a
    # repeated key almost always means a copy/paste mistake or a merge artifact.
    seen: dict[tuple[str, str, str], OverrideEntry] = {}
    for entry in entries:
        key = (entry.dataset_pattern, entry.table, entry.column)
        other = seen.get(key)
        if other is not None:
            raise OverrideError(
                "duplicate override for "
                f"dataset={key[0]!r} table={key[1]!r} column={key[2]!r} "
                f"(decisions {other.decision!r} and {entry.decision!r}); "
                "remove one entry -- duplicates are rejected, not resolved"
            )
        seen[key] = entry
    # Overlapping dataset patterns that both target the same table/column would
    # make matching order-dependent even without literal duplicates.
    for left_index, left in enumerate(entries):
        for right in entries[left_index + 1:]:
            if left.table != right.table or left.column != right.column:
                continue
            if _overlapping_patterns(left.dataset_pattern, right.dataset_pattern):
                raise OverrideError(
                    "ambiguous overrides for "
                    f"table={left.table!r} column={left.column!r}: dataset patterns "
                    f"{left.dataset_pattern!r} and {right.dataset_pattern!r} may "
                    "match the same dataset; make them unambiguous"
                )
    normalized = {
        "version": version,
        "description": description,
        "overrides": [entry.to_dict() for entry in entries],
    }
    fingerprint = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return OverrideSet(
        entries=tuple(entries),
        fingerprint=fingerprint,
        source_path=source_path,
        operator=operator,
    )


def load_overrides(path: str | Path, operator: str | None = None) -> OverrideSet:
    """Load and strictly validate an override file.

    An override file is only valid when the operator is known, because every
    applied adjudication is recorded in the audit log with that operator. An
    empty file (no entries) does not need one.
    """
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise OverrideError(f"override file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise OverrideError(f"cannot load overrides {source}: {exc}") from exc
    if data is None:
        data = {}
    root = _expect_mapping(data, "override root")
    raw_entries = root.get("overrides", [])
    has_entries = bool(raw_entries) if isinstance(raw_entries, list) else True
    if operator is not None:
        operator = operator.strip()
    if has_entries and not operator:
        raise OverrideError(
            f"{OPERATOR_ENV} must be set to a non-empty operator identity "
            f"when using overrides ({source})"
        )
    return _parse_overrides(data, source, operator or "")


def load_default_overrides(
    paths: Any, operator: str | None = None
) -> OverrideSet | None:
    """Load `<workspace>/overrides.yaml` if present, else None."""
    path = Path(paths.root) / OVERRIDE_FILENAME
    if not path.is_file():
        return None
    return load_overrides(path, operator=operator)


def resolve_operator(value: str | None = None) -> str | None:
    """Return the configured operator identity, or None when unset."""
    if value is None:
        value = os.environ.get(OPERATOR_ENV)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _rename_hint(table: Any, column: str) -> str | None:
    """Best-effort suggestion when an adjudicated column no longer exists.

    Deliberately conservative: only a single other column with the same
    normalized name (case/punctuation-insensitive) is suggested. Anything else
    would be guessing, and a wrong hint on a sensitive column is worse than no
    hint.
    """
    normalized = "".join(ch for ch in column.lower() if ch.isalnum())
    candidates = [
        existing.name
        for existing in table.columns
        if "".join(ch for ch in existing.name.lower() if ch.isalnum()) == normalized
    ]
    if len(candidates) == 1 and candidates[0] != column:
        return candidates[0]
    return None


def _apply_decision(
    finding: dict[str, Any], entry: OverrideEntry
) -> dict[str, Any]:
    detected_type = finding.get("detected_type", finding.get("sensitive_type"))
    detected_confidence = finding.get("detected_confidence", finding["confidence"])
    merged = dict(finding)
    merged["detected_type"] = detected_type
    merged["detected_confidence"] = detected_confidence
    if entry.is_sensitive:
        merged["sensitive_type"] = detected_type or DEFAULT_ADJUDICATED_TYPE
        merged["confidence"] = "high"
        merged["forced"] = True
    else:
        merged["sensitive_type"] = None
        merged["confidence"] = "none"
        merged["suppressed"] = True
    merged["override"] = {
        "decision": entry.decision,
        "reason": entry.reason,
        "dataset": entry.dataset_pattern,
        "table": entry.table,
        "column": entry.column,
    }
    merged["effective_confidence"] = merged["confidence"]
    return merged


def adjudicate_findings(
    inventory: DatasetInventory,
    findings: Iterable[dict[str, Any]],
    overrides: OverrideSet | None,
    *,
    policy_columns: Mapping[str, Mapping[str, str]] | None = None,
) -> tuple[list[dict[str, Any]], AppliedOverrides]:
    """Merge overrides into detector findings for one dataset.

    `policy_columns` maps table -> column -> transformer for the dataset's
    masking policy (None when no policy is involved, e.g. a plain `scan`). It is
    used only to detect the force_not_sensitive/policy conflict; the findings
    themselves are never altered for execution.
    """
    report = AppliedOverrides(
        dataset=inventory.path, policy_checked=policy_columns is not None
    )
    records = [dict(finding) for finding in findings]
    if overrides is not None:
        report.operator = overrides.operator
        report.override_file = str(overrides.source_path)
        report.override_fingerprint = overrides.fingerprint
        for entry in overrides.entries:
            if not path_matches(entry.dataset_pattern, inventory.path):
                continue
            report.matched.append(entry)
            table = inventory.table(entry.table)
            if table is None:
                report.unmatched.append(
                    UnmatchedOverride(entry, f"table {entry.table!r} not found", "table")
                )
                continue
            column_info = table.column(entry.column)
            if column_info is None:
                hint = _rename_hint(table, entry.column)
                available = ", ".join(
                    existing.name for existing in table.columns[:12]
                )
                if len(table.columns) > 12:
                    available += ", ..."
                reason = f"column {entry.table}.{entry.column!r} not found"
                if hint:
                    reason += f"; possible rename of {hint!r}"
                reason += f" (table now has: {available})"
                report.unmatched.append(
                    UnmatchedOverride(entry, reason, "column")
                )
                continue
            target = None
            for finding in records:
                if (
                    finding["table_name"] == entry.table
                    and finding["column_name"] == entry.column
                ):
                    target = finding
                    break
            if target is None:
                # Should not happen when the dataset was scanned; treat like a
                # missing column rather than silently dropping the adjudication.
                report.unmatched.append(
                    UnmatchedOverride(entry, "no finding for column", "column")
                )
                continue
            merged = _apply_decision(target, entry)
            target.clear()
            target.update(merged)
            if not entry.is_sensitive:
                transformer = (
                    policy_columns.get(entry.table, {}).get(entry.column)
                    if policy_columns is not None
                    else None
                )
                if transformer is not None:
                    report.conflicts.append(
                        Conflict(entry, entry.table, entry.column, transformer)
                    )
            report.applied.append(
                {
                    **entry.to_dict(),
                    "detected_type": merged.get("detected_type"),
                    "detected_confidence": merged.get("detected_confidence"),
                    "effective_type": merged.get("sensitive_type"),
                    "effective_confidence": merged.get("confidence"),
                }
            )
    return records, report


def dataset_missing_entries(
    overrides: OverrideSet | None,
    all_inventories: Iterable[DatasetInventory],
) -> list[UnmatchedOverride]:
    """Entries that match no dataset scored by this scan command.

    This is the rename/removal signal: the override names something that used
    to exist (possibly under the same dataset path) but no longer resolves.
    Callers attach each item to one summary so the console/report lists it once.
    """
    if overrides is None:
        return []
    inventories = list(all_inventories)
    unmatched = []
    for entry in overrides.entries:
        if any(path_matches(entry.dataset_pattern, item.path) for item in inventories):
            continue
        unmatched.append(
            UnmatchedOverride(
                entry,
                "no scanned dataset matches this override's dataset pattern; "
                "the dataset may have been renamed or removed",
                "dataset",
            )
        )
    return unmatched
