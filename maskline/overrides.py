"""Manual adjudication overrides for detector findings.

Overrides are a separate, strictly validated YAML file.  They never alter the
masking policy: a ``force_not_sensitive`` verdict only changes discovery output.
When such a verdict contradicts a configured policy column, execution still
masks the column (fail safe: over-mask rather than under-mask) and the run
report emits a warning.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from .policies import path_matches
from .registry import DatasetInventory
from .utils import MasklineError, canonical_json


class OverrideError(MasklineError):
    pass


FORCE_SENSITIVE = "force_sensitive"
FORCE_NOT_SENSITIVE = "force_not_sensitive"
VERDICTS = {FORCE_SENSITIVE, FORCE_NOT_SENSITIVE}
MANUAL_SENSITIVE_TYPE = "manual"
OPERATOR_ENV = "MASKLINE_OPERATOR"
OPERATOR_FALLBACKS = ("USER", "USERNAME", "LOGNAME")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_operator() -> str:
    """Resolve the human operator recorded in registry rows and audit entries.

    ``MASKLINE_OPERATOR`` is the documented source.  Common login environment
    variables are accepted as a deterministic fallback; if none is present the
    operation fails rather than writing an anonymous adjudication.
    """
    explicit = os.environ.get(OPERATOR_ENV)
    if explicit and explicit.strip():
        return explicit.strip()
    for name in OPERATOR_FALLBACKS:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    raise OverrideError(
        f"{OPERATOR_ENV} is not set; set it to the person applying overrides "
        "(or provide USER in the environment)"
    )


@dataclass(frozen=True)
class OverrideEntry:
    dataset_pattern: str
    table: str
    column: str
    verdict: str
    reason: str
    index: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset_pattern,
            "table": self.table,
            "column": self.column,
            "verdict": self.verdict,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class OverrideSet:
    entries: tuple[OverrideEntry, ...]
    source_path: Path
    fingerprint: str
    description: str = ""

    def matching_entries(self, inventory: DatasetInventory) -> list[OverrideEntry]:
        return [
            entry
            for entry in self.entries
            if path_matches(entry.dataset_pattern, inventory.path)
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "description": self.description,
            "source": str(self.source_path),
            "fingerprint": self.fingerprint,
            "overrides": [entry.to_dict() for entry in self.entries],
        }


@dataclass(frozen=True)
class AppliedOverride:
    entry: OverrideEntry
    dataset_path: Path
    dataset_fingerprint: str
    detected_sensitive_type: str | None
    detected_confidence: str
    detected_score: float
    operator: str
    at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset": str(self.dataset_path),
            "dataset_fingerprint": self.dataset_fingerprint,
            "table": self.entry.table,
            "column": self.entry.column,
            "verdict": self.entry.verdict,
            "reason": self.entry.reason,
            "operator": self.operator,
            "at": self.at,
            "detected": {
                "sensitive_type": self.detected_sensitive_type,
                "confidence": self.detected_confidence,
                "score": self.detected_score,
            },
        }


@dataclass(frozen=True)
class UnmatchedOverride:
    entry: OverrideEntry
    dataset_path: Path | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_pattern": self.entry.dataset_pattern,
            "dataset": str(self.dataset_path) if self.dataset_path else None,
            "table": self.entry.table,
            "column": self.entry.column,
            "verdict": self.entry.verdict,
            "reason": self.reason,
        }


@dataclass
class OverrideApplication:
    findings: list[dict[str, Any]]
    applied: list[AppliedOverride] = field(default_factory=list)
    unmatched: list[UnmatchedOverride] = field(default_factory=list)
    source_path: Path | None = None
    fingerprint: str | None = None

    def applied_map(self) -> dict[tuple[str, str], AppliedOverride]:
        return {
            (item.entry.table, item.entry.column): item for item in self.applied
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source_path) if self.source_path else None,
            "fingerprint": self.fingerprint,
            "applied": [item.to_dict() for item in self.applied],
            "unmatched": [item.to_dict() for item in self.unmatched],
        }


def empty_application(findings: list[dict[str, Any]]) -> OverrideApplication:
    return OverrideApplication(findings=list(findings))


def _expect_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OverrideError(f"{where} must be a mapping")
    return value


def _expect_text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OverrideError(f"{where} must be a non-empty string")
    return value.strip()


def _parse_override_file(data: Any, source_path: Path) -> OverrideSet:
    root = _expect_mapping(data, "overrides root")
    unknown = set(root) - {"version", "description", "overrides"}
    if unknown:
        raise OverrideError(
            "overrides root has unknown keys: " + ", ".join(sorted(unknown))
        )
    version = root.get("version")
    if version != 1 or isinstance(version, bool):
        raise OverrideError("overrides version must be the integer 1")
    description = root.get("description", "")
    if not isinstance(description, str):
        raise OverrideError("overrides description must be a string")
    raw_entries = root.get("overrides")
    if not isinstance(raw_entries, list):
        raise OverrideError("overrides entries must be a list")

    entries: list[OverrideEntry] = []
    seen: dict[tuple[str, str, str], int] = {}
    for index, raw in enumerate(raw_entries, start=1):
        where = f"overrides[{index}]"
        item = _expect_mapping(raw, where)
        allowed = {"dataset", "table", "column", "verdict", "reason"}
        unknown_keys = set(item) - allowed
        missing = allowed - set(item)
        if unknown_keys:
            raise OverrideError(
                f"{where} has unknown keys: {', '.join(sorted(unknown_keys))}"
            )
        if missing:
            raise OverrideError(
                f"{where} is missing required keys: {', '.join(sorted(missing))}"
            )
        dataset = _expect_text(item["dataset"], f"{where}.dataset")
        table = _expect_text(item["table"], f"{where}.table")
        column = _expect_text(item["column"], f"{where}.column")
        verdict = _expect_text(item["verdict"], f"{where}.verdict")
        if verdict not in VERDICTS:
            raise OverrideError(
                f"{where}.verdict must be one of: {', '.join(sorted(VERDICTS))}"
            )
        reason = _expect_text(item["reason"], f"{where}.reason")
        key = (dataset, table, column)
        if key in seen:
            raise OverrideError(
                f"duplicate override for dataset {dataset!r} table {table!r} "
                f"column {column!r} (entries {seen[key]} and {index}); "
                "remove duplicates so verdict precedence is unambiguous"
            )
        seen[key] = index
        entries.append(
            OverrideEntry(
                dataset_pattern=dataset,
                table=table,
                column=column,
                verdict=verdict,
                reason=reason,
                index=index,
            )
        )

    normalized = {
        "version": version,
        "description": description,
        "overrides": [entry.to_dict() for entry in entries],
    }
    fingerprint = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return OverrideSet(
        entries=tuple(entries),
        source_path=source_path,
        fingerprint=fingerprint,
        description=description,
    )


def load_overrides(path: str | Path) -> OverrideSet:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise OverrideError(f"overrides file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise OverrideError(f"cannot load overrides {source}: {exc}") from exc
    return _parse_override_file(data, source)


def _apply_to_finding(
    record: dict[str, Any],
    entry: OverrideEntry,
    operator: str,
    at: str,
) -> dict[str, Any]:
    effective = dict(record)
    detected_type = record.get("sensitive_type")
    effective["detected_sensitive_type"] = detected_type
    effective["detected_confidence"] = record.get("confidence", "none")
    effective["detected_score"] = float(record.get("score", 0.0))
    effective["override_verdict"] = entry.verdict
    effective["override_reason"] = entry.reason
    effective["override_operator"] = operator
    effective["override_at"] = at
    if entry.verdict == FORCE_SENSITIVE:
        effective["sensitive_type"] = detected_type or MANUAL_SENSITIVE_TYPE
        effective["confidence"] = "high"
    else:
        effective["sensitive_type"] = None
        effective["confidence"] = "none"
    return effective


def apply_overrides(
    inventory: DatasetInventory,
    findings: list[dict[str, Any]],
    override_set: OverrideSet | None,
    *,
    operator: str | None,
    at: str | None,
) -> OverrideApplication:
    """Merge manual verdicts into detector findings without touching policy."""
    if override_set is None or not override_set.entries:
        return empty_application(findings)
    if operator is None or at is None:
        raise OverrideError("operator and timestamp are required to apply overrides")

    by_key = {
        (finding["table_name"], finding["column_name"]): finding
        for finding in findings
    }
    applied: list[AppliedOverride] = []
    unmatched: list[UnmatchedOverride] = []
    claimed: dict[tuple[str, str], OverrideEntry] = {}
    updated: list[dict[str, Any]] = list(findings)

    for entry in override_set.matching_entries(inventory):
        table = inventory.table(entry.table)
        if table is None:
            unmatched.append(
                UnmatchedOverride(
                    entry,
                    inventory.path,
                    f"table {entry.table!r} not found in dataset "
                    "(possibly renamed or removed)",
                )
            )
            continue
        if entry.column not in {column.name for column in table.columns}:
            unmatched.append(
                UnmatchedOverride(
                    entry,
                    inventory.path,
                    f"column {entry.table}.{entry.column} not found in dataset "
                    "(possibly renamed or removed)",
                )
            )
            continue
        key = (entry.table, entry.column)
        previous = claimed.get(key)
        if previous is not None:
            raise OverrideError(
                f"multiple overrides match {entry.table}.{entry.column} in "
                f"{inventory.path.name}: entries {previous.index} and {entry.index} "
                "match the same column; make dataset patterns unambiguous"
            )
        claimed[key] = entry
        record = by_key.get(key)
        if record is None:
            raise OverrideError(
                f"internal error: no finding generated for {entry.table}.{entry.column}"
            )
        detected_type = record.get("sensitive_type")
        detected_confidence = record.get("confidence", "none")
        detected_score = float(record.get("score", 0.0))
        effective = _apply_to_finding(record, entry, operator, at)
        index = next(
            i
            for i, item in enumerate(updated)
            if (item["table_name"], item["column_name"]) == key
        )
        updated[index] = effective
        applied.append(
            AppliedOverride(
                entry=entry,
                dataset_path=inventory.path,
                dataset_fingerprint=inventory.fingerprint,
                detected_sensitive_type=detected_type,
                detected_confidence=detected_confidence,
                detected_score=detected_score,
                operator=operator,
                at=at,
            )
        )

    return OverrideApplication(
        findings=updated,
        applied=applied,
        unmatched=unmatched,
        source_path=override_set.source_path,
        fingerprint=override_set.fingerprint,
    )


def unmatched_without_dataset(
    override_set: OverrideSet | None,
    inventories: list[DatasetInventory],
) -> list[UnmatchedOverride]:
    """Entries whose dataset pattern matches none of the datasets in this scan."""
    if override_set is None:
        return []
    matched_indexes = {
        entry.index
        for inventory in inventories
        for entry in override_set.matching_entries(inventory)
    }
    return [
        UnmatchedOverride(
            entry,
            None,
            "no dataset in this scan matches the dataset path pattern",
        )
        for entry in override_set.entries
        if entry.index not in matched_indexes
    ]


def build_override_audit_entry(
    item: AppliedOverride | UnmatchedOverride,
    override_set: OverrideSet,
    operator: str,
    at: str,
    *,
    matched: bool,
) -> dict[str, Any]:
    entry = item.entry
    payload: dict[str, Any] = {
        "event": "override_adjudication",
        "ts": at,
        "operator": operator,
        "overrides_path": str(override_set.source_path),
        "overrides_fingerprint": override_set.fingerprint,
        "dataset_pattern": entry.dataset_pattern,
        "table_name": entry.table,
        "column_name": entry.column,
        "verdict": entry.verdict,
        "reason": entry.reason,
        "matched": matched,
        "dataset_path": str(item.dataset_path) if item.dataset_path else None,
        "dataset_fingerprint": (
            item.dataset_fingerprint
            if isinstance(item, AppliedOverride)
            else None
        ),
    }
    if not matched:
        payload["unmatched_reason"] = item.reason
    return payload
