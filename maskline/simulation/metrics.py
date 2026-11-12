"""Quantitative impact metrics for simulated masking.

Four metric families are produced:

1. **Coverage** – share of non-empty values actually changed by the transformer,
   measured over the full streamed dataset (not just the sample).
2. **Distribution shift** – PSI and Jensen-Shannon divergence of value
   distributions plus null-rate and cardinality changes, measured on the sample.
3. **Linkage retention** – how much of the cross-table value overlap survives,
   estimated with multiset intersections on sampled key columns.
4. **Business KPI deviation** – sum / mean / min / max drift for numeric
   columns, accumulated over the full streamed dataset.

All functions are pure: the runner supplies raw counters and sample rows, and
these functions return JSON-serializable dictionaries.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable

# Distribution smoothing: zero-frequency buckets are replaced by this floor so
# that PSI stays finite while still penalizing buckets that disappear.
PSI_EPSILON = 1e-4
NUMERIC_DETECTION_RATIO = 0.8


def _is_empty(value: Any) -> bool:
    return value is None or value == ""


def _category_key(value: Any) -> str:
    return "∅" if _is_empty(value) else str(value)


# --------------------------------------------------------------------------
# Coverage (full-stream counters)
# --------------------------------------------------------------------------

@dataclass
class CoverageAccumulator:
    total: int = 0
    non_empty: int = 0
    empty: int = 0
    changed: int = 0
    unchanged: int = 0

    def observe(self, before: Any, after: Any) -> None:
        self.total += 1
        if _is_empty(before):
            self.empty += 1
            return
        self.non_empty += 1
        if after != before:
            self.changed += 1
        else:
            self.unchanged += 1

    def to_metric(self) -> dict[str, Any]:
        rate = self.changed / self.non_empty if self.non_empty else 0.0
        return {
            "total_values": self.total,
            "non_empty_values": self.non_empty,
            "empty_values": self.empty,
            "changed_values": self.changed,
            "unchanged_non_empty_values": self.unchanged,
            "coverage_rate": round(rate, 6),
        }


# --------------------------------------------------------------------------
# Distribution shift (sample-based)
# --------------------------------------------------------------------------

def _frequency(rows: Iterable[Any]) -> Counter:
    counter: Counter = Counter()
    for value in rows:
        counter[_category_key(value)] += 1
    return counter


def psi(before: Counter, after: Counter) -> float:
    """Population Stability Index with epsilon smoothing for empty buckets."""
    total_before = sum(before.values())
    total_after = sum(after.values())
    if not total_before or not total_after:
        return 0.0
    keys = set(before) | set(after)
    score = 0.0
    for key in keys:
        p_before = max(before.get(key, 0) / total_before, PSI_EPSILON)
        p_after = max(after.get(key, 0) / total_after, PSI_EPSILON)
        score += (p_after - p_before) * math.log(p_after / p_before)
    return round(score, 6)


def jensen_shannon_divergence(before: Counter, after: Counter) -> float:
    total_before = sum(before.values())
    total_after = sum(after.values())
    if not total_before or not total_after:
        return 0.0
    keys = set(before) | set(after)
    p = {key: before.get(key, 0) / total_before for key in keys}
    q = {key: after.get(key, 0) / total_after for key in keys}
    divergence = 0.0
    for key in keys:
        mixture = (p[key] + q[key]) / 2
        if p[key] > 0:
            divergence += 0.5 * p[key] * math.log(p[key] / mixture)
        if q[key] > 0:
            divergence += 0.5 * q[key] * math.log(q[key] / mixture)
    return round(divergence, 6)


def _top_categories(counter: Counter, limit: int = 5) -> list[dict[str, Any]]:
    total = sum(counter.values())
    return [
        {"value": key, "count": count, "share": round(count / total, 6) if total else 0.0}
        for key, count in counter.most_common(limit)
    ]


def distribution_metric(before_values: list[Any], after_values: list[Any]) -> dict[str, Any]:
    before = _frequency(before_values)
    after = _frequency(after_values)
    sample_size = len(before_values)
    null_before = sum(1 for value in before_values if _is_empty(value))
    null_after = sum(1 for value in after_values if _is_empty(value))
    distinct_before = len({key for key in before if key != "∅"})
    distinct_after = len({key for key in after if key != "∅"})
    return {
        "sample_size": sample_size,
        "psi": psi(before, after),
        "js_divergence": jensen_shannon_divergence(before, after),
        "null_rate_before": round(null_before / sample_size, 6) if sample_size else 0.0,
        "null_rate_after": round(null_after / sample_size, 6) if sample_size else 0.0,
        "distinct_before": distinct_before,
        "distinct_after": distinct_after,
        "distinct_retention": (
            round(distinct_after / distinct_before, 6) if distinct_before else 0.0
        ),
        "top_before": _top_categories(before),
        "top_after": _top_categories(after),
    }


# --------------------------------------------------------------------------
# Numeric business KPI drift (full-stream accumulators)
# --------------------------------------------------------------------------

def parse_number(value: Any) -> Decimal | None:
    if _is_empty(value) or isinstance(value, bool):
        return None
    try:
        number = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        return None
    return number if number.is_finite() else None


@dataclass
class NumericAccumulator:
    seen: int = 0
    non_empty: int = 0
    numeric: int = 0
    null_like: int = 0
    total: Decimal = field(default_factory=lambda: Decimal("0"))
    minimum: Decimal | None = None
    maximum: Decimal | None = None

    def observe(self, value: Any) -> None:
        self.seen += 1
        if _is_empty(value):
            self.null_like += 1
            return
        self.non_empty += 1
        number = parse_number(value)
        if number is None:
            return
        self.numeric += 1
        self.total += number
        self.minimum = number if self.minimum is None else min(self.minimum, number)
        self.maximum = number if self.maximum is None else max(self.maximum, number)

    @property
    def is_numeric_column(self) -> bool:
        if self.non_empty == 0:
            return False
        return self.numeric / self.non_empty >= NUMERIC_DETECTION_RATIO

    def snapshot(self) -> dict[str, Any]:
        return {
            "numeric": self.numeric,
            "non_empty": self.non_empty,
            "null_like": self.null_like,
            "sum": float(self.total),
            "mean": float(self.total / self.numeric) if self.numeric else None,
            "min": float(self.minimum) if self.minimum is not None else None,
            "max": float(self.maximum) if self.maximum is not None else None,
        }


def _deviation(after: float | None, before: float | None) -> float | None:
    if before is None or before == 0:
        if after is None or after == 0:
            return 0.0
        return 1.0
    if after is None:
        return 1.0
    return round(abs(after - before) / abs(before), 6)


def kpi_metric(before: NumericAccumulator, after: NumericAccumulator) -> dict[str, Any]:
    before_snap = before.snapshot()
    after_snap = after.snapshot()
    return {
        "numeric_before": before.is_numeric_column,
        "numeric_after": after.is_numeric_column,
        "sum_before": before_snap["sum"],
        "sum_after": after_snap["sum"],
        "sum_deviation_rate": _deviation(after_snap["sum"], before_snap["sum"]),
        "mean_before": before_snap["mean"],
        "mean_after": after_snap["mean"],
        "mean_deviation_rate": _deviation(after_snap["mean"], before_snap["mean"]),
        "min_before": before_snap["min"],
        "min_after": after_snap["min"],
        "max_before": before_snap["max"],
        "max_after": after_snap["max"],
        "null_rate_before": round(before.null_like / before.seen, 6) if before.seen else 0.0,
        "null_rate_after": round(after.null_like / after.seen, 6) if after.seen else 0.0,
        "numeric_value_count_before": before.numeric,
        "numeric_value_count_after": after.numeric,
    }


# --------------------------------------------------------------------------
# Cross-table linkage retention (sample-based, multiset overlap)
# --------------------------------------------------------------------------

def multiset_overlap(left: Iterable[Any], right: Iterable[Any]) -> int:
    """Count of joinable row pairs proportional to shared multiset multiplicity."""
    return sum((Counter(left) & Counter(right)).values())


def linkage_metric(
    left_before: list[Any],
    right_before: list[Any],
    left_after: list[Any],
    right_after: list[Any],
) -> dict[str, Any]:
    overlap_before = multiset_overlap(left_before, right_before)
    overlap_after = multiset_overlap(left_after, right_after)
    distinct_left_before = len(set(left_before))
    distinct_left_after = len(set(left_after))
    distinct_right_before = len(set(right_before))
    distinct_right_after = len(set(right_after))
    retention = round(overlap_after / overlap_before, 6) if overlap_before else 0.0
    return {
        "sample_size_left": len(left_before),
        "sample_size_right": len(right_before),
        "overlap_before": overlap_before,
        "overlap_after": overlap_after,
        "retention_rate": retention,
        "fully_broken": overlap_before > 0 and overlap_after == 0,
        "cardinality_retention_left": (
            round(distinct_left_after / distinct_left_before, 6)
            if distinct_left_before else 0.0
        ),
        "cardinality_retention_right": (
            round(distinct_right_after / distinct_right_before, 6)
            if distinct_right_before else 0.0
        ),
    }
