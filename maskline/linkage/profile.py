"""Column profiling: detector scores plus value-set fingerprints for key columns.

Profiling reuses the existing single-dataset detectors (``analyze_values``) so
linkage scores stay compatible with the standalone scan, and adds the column
level value-set fingerprints used for cross-dataset equality matching. Only
unique-identifier-like columns get a stored value fingerprint, which keeps the
linkage store small and avoids tracking values of clearly non-joinable fields.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..dataset_io import read_table_sample
from ..detectors.base import CONFIDENCE_LOW, clean_text_values
from ..detectors.engine import analyze_values
from ..registry import DatasetInventory
from ..utils import sha256_text
from .ignore import EMPTY_RULES, IgnoreRules
from .model import ColRef, ColumnProfile

IDENTIFIER_TYPES = frozenset({"id_card", "mobile_phone", "email", "bank_card", "credit_code"})

MAX_TRACKED_VALUES = 5000
MIN_KEY_DISTINCT = 10
MIN_FK_DISTINCT_RATIO = 0.05
UNIQUE_DISTINCT_RATIO = 0.9
ID_SHAPE_RATIO = 0.9

_KEY_NAME_RE = re.compile(
    r"(?:^|[_\-\s])(?:id|no|num|number|code|sn|uuid|guid|key)(?:[_\-\s\d]|$)"
    r"|编号|标识|卡号|账号|账户|工号|单号|证件号|客户号|会员号|订单号",
    re.IGNORECASE,
)
_ID_VALUE_RE = re.compile(r"^[0-9]+$|^[A-Za-z0-9][A-Za-z0-9_\-]{3,63}$")
_DATE_LIKE_RE = re.compile(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}")


def normalize_value(value: str) -> str:
    """Canonical form used for cross-dataset equality comparison."""
    return value.strip().lower()


def value_fingerprint(value: str) -> str:
    return sha256_text(normalize_value(value))


def _key_reasons(
    sensitive_type: str | None,
    detector_score: float,
    column_name: str,
    distinct_count: int,
    distinct_ratio: float,
    texts: list[str],
) -> tuple[str, ...]:
    """Decide whether a column can act as a cross-dataset join key."""
    reasons: list[str] = []
    if sensitive_type in IDENTIFIER_TYPES and detector_score >= CONFIDENCE_LOW:
        reasons.append(f"identifier-type:{sensitive_type}")
    if (
        distinct_count >= MIN_KEY_DISTINCT
        and distinct_ratio >= MIN_FK_DISTINCT_RATIO
        and _KEY_NAME_RE.search(column_name)
    ):
        reasons.append("key-like-name")
    if distinct_count >= MIN_KEY_DISTINCT and distinct_ratio >= UNIQUE_DISTINCT_RATIO and texts:
        shaped = sum(
            1
            for value in texts
            if _ID_VALUE_RE.match(value) and not _DATE_LIKE_RE.match(value)
        )
        if shaped / len(texts) >= ID_SHAPE_RATIO:
            reasons.append("unique-id-shape")
    return tuple(reasons)


@dataclass(frozen=True)
class ProfiledColumn:
    profile: ColumnProfile
    value_hashes: frozenset[str]


def profile_inventory(
    inventory: DatasetInventory,
    sample_limit: int = 500,
    ignore_rules: IgnoreRules = EMPTY_RULES,
) -> list[ProfiledColumn]:
    """Sample every table once and derive one profile per column."""
    results: list[ProfiledColumn] = []
    for table in inventory.tables:
        column_names, rows = read_table_sample(
            inventory.path, inventory.kind, table.name, sample_limit
        )
        declared = {column.name: column.declared_type for column in table.columns}
        for index, name in enumerate(column_names):
            raw_values = [row[index] for row in rows if index < len(row)]
            texts = clean_text_values(raw_values)
            detection = analyze_values(
                texts, sample_limit=sample_limit, table=table.name, column=name
            )
            normalized = [normalize_value(value) for value in texts]
            distinct = set(normalized)
            ratio = len(distinct) / len(normalized) if normalized else 0.0
            ignored = ignore_rules.column_ignored(inventory.path, table.name, name)
            reasons: tuple[str, ...] = ()
            if not ignored:
                reasons = _key_reasons(
                    detection.sensitive_type,
                    detection.score,
                    name,
                    len(distinct),
                    ratio,
                    texts,
                )
            value_hashes: frozenset[str] = frozenset()
            truncated = False
            if reasons:
                capped = sorted(distinct)[:MAX_TRACKED_VALUES]
                truncated = len(distinct) > MAX_TRACKED_VALUES
                value_hashes = frozenset(sha256_text(value) for value in capped)
            results.append(
                ProfiledColumn(
                    profile=ColumnProfile(
                        ref=ColRef(
                            inventory.fingerprint, str(inventory.path), table.name, name
                        ),
                        declared_type=declared.get(name, ""),
                        sample_size=len(texts),
                        distinct_count=len(distinct),
                        distinct_ratio=round(ratio, 4),
                        sensitive_type=detection.sensitive_type,
                        confidence=detection.confidence,
                        score=round(detection.score, 4),
                        hit_rate=round(detection.hit_rate, 4),
                        validate_rate=round(detection.validate_rate, 4),
                        key_candidate=bool(reasons),
                        ignored=ignored,
                        key_reasons=reasons,
                        value_truncated=truncated,
                    ),
                    value_hashes=value_hashes,
                )
            )
    return results
