"""Read-only utility and re-identification risk evaluation of masked products.

Opens the source dataset and the masked product side by side (both read-only)
and produces a quantitative report: per-column cardinality / null-rate drift,
categorical and numeric distribution drift, foreign-key join preservation, and
equivalence-class statistics for user-specified quasi-identifier sets.

Hard rules enforced in this module:

- no raw values in the report: distributions appear only as buckets or
  rank-anonymized profiles with shares; sparse buckets merge into "其他".
- the pseudonym mapping store is never opened (evaluation cannot and must not
  reverse pseudonyms); passing it as input is rejected defensively.
- aggregation is streaming: SQLite inputs are aggregated inside the SQLite
  engine (which spills to disk), CSV inputs via bounded-memory accumulators.
  Python-side memory does not grow with row count.
"""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

from .dataset_io import dataset_kind, iter_csv_tuples
from .registry import DatasetInventory, TableInfo, inspect_dataset
from .utils import (
    MasklineError,
    canonical_json,
    normalize_sqlite_value,
    quote_ident,
    sqlite_connect_readonly,
)


class EvaluationError(MasklineError):
    """User-facing evaluation failure."""


NUMERIC_TYPE_MARKERS = ("INT", "REAL", "FLOA", "DOUB", "NUM", "DEC")
OTHER_LABEL = "其他（小样本合并）"
CONSTANT_LABEL = "（常量，取值已隐藏）"
NUMERIC_TEXT_RE = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")

UTILITY_RULES = {
    "preserved": "基数比 ≥ 0.5，空值率变化 ≤ 0.2，分布差异 TVD ≤ 0.5",
    "degraded": "上述任一条件不满足（列仍非空）",
    "lost": "产物列缺失，或源列有值而产物列整体为空",
    "empty": "源列与产物列均为空",
}

# ---------------------------------------------------------------------------
# Parameters and spec parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QiSet:
    table: str
    columns: tuple[str, ...]


@dataclass(frozen=True)
class JoinSpec:
    child_table: str
    child_column: str
    parent_table: str
    parent_column: str
    origin: str = "cli"


@dataclass(frozen=True)
class EvalParams:
    numeric_buckets: int = 10
    min_bucket_size: int = 5
    categorical_max_distinct: int = 50
    distinct_cap: int = 500_000
    display_max_buckets: int = 15
    qi_sets: tuple[QiSet, ...] = ()
    joins: tuple[JoinSpec, ...] = ()

    def validate(self) -> None:
        if self.numeric_buckets < 1:
            raise EvaluationError("numeric bucket count must be >= 1")
        if self.min_bucket_size < 1:
            raise EvaluationError("min bucket size must be >= 1")
        if self.categorical_max_distinct < 1:
            raise EvaluationError("categorical max distinct must be >= 1")
        if self.distinct_cap < 1000:
            raise EvaluationError("distinct cap must be >= 1000")

    def to_dict(self) -> dict[str, Any]:
        return {
            "numeric_buckets": self.numeric_buckets,
            "min_bucket_size": self.min_bucket_size,
            "categorical_max_distinct": self.categorical_max_distinct,
            "distinct_cap": self.distinct_cap,
            "display_max_buckets": self.display_max_buckets,
            "qi_sets": [
                {"table": qi.table, "columns": list(qi.columns)} for qi in self.qi_sets
            ],
            "joins": [
                {
                    "child_table": join.child_table,
                    "child_column": join.child_column,
                    "parent_table": join.parent_table,
                    "parent_column": join.parent_column,
                    "origin": join.origin,
                }
                for join in self.joins
            ],
        }


def parse_qi_spec(text: str) -> QiSet:
    """Parse "table:col1,col2" into a QiSet."""
    table, sep, columns_text = text.partition(":")
    if not sep or not table.strip():
        raise EvaluationError(
            f"invalid --qi spec {text!r}; expected TABLE:COLUMN[,COLUMN...]"
        )
    columns: list[str] = []
    for part in columns_text.split(","):
        name = part.strip()
        if name and name not in columns:
            columns.append(name)
    if not columns:
        raise EvaluationError(f"invalid --qi spec {text!r}; no columns given")
    return QiSet(table=table.strip(), columns=tuple(columns))


def parse_join_spec(text: str) -> JoinSpec:
    """Parse "child_table.child_col=parent_table.parent_col" into a JoinSpec."""
    left, sep, right = text.partition("=")
    if not sep:
        raise EvaluationError(
            f"invalid --join spec {text!r}; expected CHILD_TABLE.COL=PARENT_TABLE.COL"
        )
    child_table, dot_left, child_column = left.strip().rpartition(".")
    parent_table, dot_right, parent_column = right.strip().rpartition(".")
    if not dot_left or not dot_right or not all(
        (child_table, child_column, parent_table, parent_column)
    ):
        raise EvaluationError(
            f"invalid --join spec {text!r}; expected CHILD_TABLE.COL=PARENT_TABLE.COL"
        )
    return JoinSpec(child_table, child_column, parent_table, parent_column)


def new_evaluation_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"eval-{stamp}-{secrets.token_hex(3)}"


# ---------------------------------------------------------------------------
# Bounded-memory streaming primitives
# ---------------------------------------------------------------------------


class HyperLogLog:
    """Distinct-count estimator with 2**precision one-byte registers."""

    def __init__(self, precision: int = 14) -> None:
        if not 4 <= precision <= 18:
            raise ValueError("precision must be in [4, 18]")
        self.precision = precision
        self.m = 1 << precision
        self.registers = bytearray(self.m)

    def add(self, value: Any) -> None:
        payload = canonical_json(normalize_sqlite_value(value)).encode("utf-8")
        digest = int.from_bytes(hashlib.blake2b(payload, digest_size=8).digest(), "big")
        index = digest >> (64 - self.precision)
        remaining = digest & ((1 << (64 - self.precision)) - 1)
        span = 64 - self.precision
        rank = span - remaining.bit_length() + 1 if remaining else span + 1
        if rank > self.registers[index]:
            self.registers[index] = rank

    def estimate(self) -> float:
        indicator = sum(2.0 ** -register for register in self.registers)
        raw = 0.7213 / (1 + 1.079 / self.m) * self.m * self.m / indicator
        zeros = self.registers.count(0)
        if raw <= 2.5 * self.m and zeros:
            return self.m * math.log(self.m / zeros)
        return raw


class DistinctCounter:
    """Exact distinct count up to `cap` uniques, then HLL estimate.

    Memory stays bounded either way: the exact set is dropped once it exceeds
    the cap, and the HLL sketch is a constant 16 KiB.
    """

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self._exact: set[str] | None = set()
        self._hll = HyperLogLog()

    @staticmethod
    def _encode(value: Any) -> str:
        return canonical_json(normalize_sqlite_value(value))

    def add(self, value: Any) -> None:
        encoded = self._encode(value)
        self._hll.add(value)
        if self._exact is not None:
            self._exact.add(encoded)
            if len(self._exact) > self.cap:
                self._exact = None

    def result(self) -> tuple[int, str]:
        if self._exact is not None:
            return len(self._exact), "exact"
        return int(round(self._hll.estimate())), "hll_estimate"


# ---------------------------------------------------------------------------
# Shared statistics helpers
# ---------------------------------------------------------------------------


def _share(part: int, total: int) -> float | None:
    if total <= 0:
        return None
    return round(part / total, 6)


def _profile_tvd(source_counts: Sequence[int], product_counts: Sequence[int]) -> float | None:
    """TVD between rank-aligned frequency profiles (label-independent)."""
    source_total = sum(source_counts)
    product_total = sum(product_counts)
    if source_total == 0 and product_total == 0:
        return None
    if source_total == 0 or product_total == 0:
        return 1.0
    length = max(len(source_counts), len(product_counts))
    tvd = 0.0
    for index in range(length):
        s = source_counts[index] / source_total if index < len(source_counts) else 0.0
        p = product_counts[index] / product_total if index < len(product_counts) else 0.0
        tvd += abs(s - p)
    return round(0.5 * tvd, 6)


def _bucket_tvd(source_counts: Sequence[int], product_counts: Sequence[int]) -> float | None:
    source_total = sum(source_counts)
    product_total = sum(product_counts)
    if source_total == 0 and product_total == 0:
        return None
    if source_total == 0 or product_total == 0:
        return 1.0
    tvd = 0.0
    for s, p in zip(source_counts, product_counts):
        tvd += abs(s / source_total - p / product_total)
    return round(0.5 * tvd, 6)


def _nice_bounds(low: float, high: float, significant: int = 4) -> tuple[float, float]:
    """Widen [low, high] outward to round numbers so edges match no raw value."""
    if low == high:
        return low, high
    step = 10.0 ** (math.floor(math.log10(high - low)) - (significant - 1))
    return math.floor(low / step) * step, math.ceil(high / step) * step


def _bucket_index(value: float, low: float, width: float, count: int) -> int:
    index = int((value - low) / width)
    return min(max(index, 0), count - 1)


def _format_edge(value: float) -> str:
    return f"{value:.6g}"


# ---------------------------------------------------------------------------
# SQLite-side aggregation (engine spills to disk; Python memory stays flat)
# ---------------------------------------------------------------------------


@dataclass
class _SideStats:
    rows: int = 0
    empty: int = 0
    distinct: int = 0
    distinct_method: str = "exact"
    numeric_min: float | None = None
    numeric_max: float | None = None
    numeric_excluded: int = 0  # non-empty values unusable as numbers
    categories: list[int] | None = None  # counts, descending


def _is_numeric_declared(declared_type: str) -> bool:
    upper = declared_type.upper()
    return any(marker in upper for marker in NUMERIC_TYPE_MARKERS)


def _sqlite_table_stats(
    conn: sqlite3.Connection, table: TableInfo
) -> dict[str, _SideStats]:
    """One streaming pass per table: row count, nulls, distinct, numeric range."""
    numeric_columns = [
        column.name for column in table.columns if _is_numeric_declared(column.declared_type)
    ]
    selects = ["COUNT(*)"]
    for column in table.columns:
        ident = quote_ident(column.name)
        selects.append(f"SUM({ident} IS NULL)")
        selects.append(f"COUNT(DISTINCT {ident})")
    for name in numeric_columns:
        ident = quote_ident(name)
        selects.append(
            f"MIN(CASE WHEN typeof({ident}) IN ('integer','real') THEN {ident} END)"
        )
        selects.append(
            f"MAX(CASE WHEN typeof({ident}) IN ('integer','real') THEN {ident} END)"
        )
        selects.append(
            f"SUM(CASE WHEN {ident} IS NOT NULL "
            f"AND typeof({ident}) NOT IN ('integer','real') THEN 1 ELSE 0 END)"
        )
    sql = f"SELECT {', '.join(selects)} FROM {quote_ident(table.name)}"
    row = conn.execute(sql).fetchone()
    values = tuple(row)
    result: dict[str, _SideStats] = {}
    rows = int(values[0])
    offset = 1
    for column in table.columns:
        stats = _SideStats(rows=rows)
        stats.empty = int(values[offset] or 0)
        stats.distinct = int(values[offset + 1] or 0)
        offset += 2
        result[column.name] = stats
    for name in numeric_columns:
        stats = result[name]
        if values[offset] is not None:
            stats.numeric_min = float(values[offset])
        if values[offset + 1] is not None:
            stats.numeric_max = float(values[offset + 1])
        stats.numeric_excluded = int(values[offset + 2] or 0)
        offset += 3
    return result


def _sqlite_category_counts(
    conn: sqlite3.Connection, table: str, column: str
) -> list[int]:
    ident = quote_ident(column)
    cursor = conn.execute(
        f"SELECT COUNT(*) FROM {quote_ident(table)} WHERE {ident} IS NOT NULL "
        f"GROUP BY {ident} ORDER BY 1 DESC"
    )
    return [int(record[0]) for record in cursor]


def _sqlite_numeric_buckets(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    low: float,
    width: float,
    bucket_count: int,
) -> list[int]:
    ident = quote_ident(column)
    counts = [0] * bucket_count
    if width <= 0:
        total = conn.execute(
            f"SELECT COUNT(*) FROM {quote_ident(table)} WHERE {ident} IS NOT NULL "
            f"AND typeof({ident}) IN ('integer','real')"
        ).fetchone()[0]
        counts[0] = int(total)
        return counts
    cursor = conn.execute(
        f"SELECT MIN(MAX(CAST(({ident} - ?) / ? AS INTEGER), 0), ?) AS bucket, COUNT(*) "
        f"FROM {quote_ident(table)} "
        f"WHERE {ident} IS NOT NULL AND typeof({ident}) IN ('integer','real') "
        f"GROUP BY bucket",
        (low, width, bucket_count - 1),
    )
    for bucket, count in cursor:
        counts[int(bucket)] = int(count)
    return counts


# ---------------------------------------------------------------------------
# CSV-source streaming accumulators (bounded memory)
# ---------------------------------------------------------------------------


class _CsvColumnAccumulator:
    __slots__ = (
        "empty",
        "distinct",
        "categories",
        "category_cap",
        "numeric_ok",
        "numeric_count",
        "numeric_min",
        "numeric_max",
    )

    def __init__(self, distinct_cap: int, category_cap: int) -> None:
        self.empty = 0
        self.distinct = DistinctCounter(distinct_cap)
        self.categories: dict[str, int] | None = {}
        self.category_cap = category_cap
        self.numeric_ok = True
        self.numeric_count = 0
        self.numeric_min: float | None = None
        self.numeric_max: float | None = None

    def add(self, value: Any) -> None:
        if value is None or value == "":
            self.empty += 1
            return
        self.distinct.add(value)
        if self.categories is not None:
            key = value if isinstance(value, str) else str(value)
            self.categories[key] = self.categories.get(key, 0) + 1
            if len(self.categories) > self.category_cap:
                self.categories = None  # high-cardinality: stop tracking, stay bounded
        text = str(value).strip()
        if NUMERIC_TEXT_RE.match(text):
            number = float(text)
            self.numeric_count += 1
            self.numeric_min = number if self.numeric_min is None else min(self.numeric_min, number)
            self.numeric_max = number if self.numeric_max is None else max(self.numeric_max, number)
        else:
            self.numeric_ok = False


def _iter_sqlite_values(path: Path, table: str, columns: Sequence[str]) -> Iterator[tuple[Any, ...]]:
    """Stream one table's rows through a single read-only connection."""
    conn = sqlite_connect_readonly(path)
    try:
        select = ", ".join(quote_ident(name) for name in columns)
        cursor = conn.execute(f"SELECT {select} FROM {quote_ident(table)}")
        for record in cursor:
            yield tuple(record)
    finally:
        conn.close()


def _csv_accumulate(
    rows: Iterator[tuple[Any, ...]],
    column_names: Sequence[str],
    params: EvalParams,
) -> tuple[int, dict[str, _CsvColumnAccumulator]]:
    accumulators = {
        name: _CsvColumnAccumulator(params.distinct_cap, params.categorical_max_distinct)
        for name in column_names
    }
    row_count = 0
    for record in rows:
        row_count += 1
        for index, name in enumerate(column_names):
            accumulators[name].add(record[index] if index < len(record) else None)
    return row_count, accumulators


def _csv_numeric_buckets(
    rows: Iterator[tuple[Any, ...]],
    column_index: int,
    low: float,
    width: float,
    bucket_count: int,
) -> tuple[list[int], int]:
    """Second streaming pass: bucket counts plus non-numeric exclusion count."""
    counts = [0] * bucket_count
    excluded = 0
    for record in rows:
        value = record[column_index] if column_index < len(record) else None
        if value is None or value == "":
            continue
        text = str(value).strip()
        if not NUMERIC_TEXT_RE.match(text):
            excluded += 1
            continue
        number = float(text)
        if width <= 0:
            counts[0] += 1
        else:
            counts[_bucket_index(number, low, width, bucket_count)] += 1
    return counts, excluded


# ---------------------------------------------------------------------------
# Column classification and metric assembly
# ---------------------------------------------------------------------------


def _classify_sqlite_column(declared_type: str, distinct: int, params: EvalParams) -> str:
    if _is_numeric_declared(declared_type):
        return "numeric"
    if distinct <= params.categorical_max_distinct:
        return "categorical"
    return "text"


def _classify_csv_column(acc: _CsvColumnAccumulator, distinct: int, params: EvalParams) -> str:
    if distinct == 0:
        return "categorical"
    if acc.numeric_ok and acc.numeric_count > 0 and distinct > params.categorical_max_distinct:
        return "numeric"
    if distinct <= params.categorical_max_distinct and acc.categories is not None:
        return "categorical"
    return "text"


def _build_numeric_section(
    source_stats: _SideStats,
    product_stats: _SideStats,
    source_counts: list[int],
    product_counts: list[int],
    low: float,
    width: float,
    bucket_count: int,
    min_bucket_size: int,
) -> dict[str, Any]:
    source_total = sum(source_counts)
    product_total = sum(product_counts)
    buckets = []
    other = {"source_count": 0, "product_count": 0, "merged_buckets": 0}
    empty_buckets = 0
    for index in range(bucket_count):
        s_count = source_counts[index]
        p_count = product_counts[index]
        if s_count == 0 and p_count == 0:
            empty_buckets += 1
            continue
        if s_count < min_bucket_size or p_count < min_bucket_size:
            other["source_count"] += s_count
            other["product_count"] += p_count
            other["merged_buckets"] += 1
            continue
        if width <= 0:
            label = CONSTANT_LABEL
        else:
            lower = low + index * width
            upper = low + (index + 1) * width
            bracket = "]" if index == bucket_count - 1 else ")"
            label = f"[{_format_edge(lower)}, {_format_edge(upper)}{bracket}"
        buckets.append(
            {
                "label": label,
                "source_count": s_count,
                "product_count": p_count,
                "source_share": _share(s_count, source_total),
                "product_share": _share(p_count, product_total),
            }
        )
    section: dict[str, Any] = {
        "bucket_count": bucket_count,
        "bucket_width": round(width, 6) if width > 0 else 0,
        "buckets": buckets,
        "other": (
            {
                **other,
                "source_share": _share(other["source_count"], source_total),
                "product_share": _share(other["product_count"], product_total),
            }
            if other["merged_buckets"]
            else None
        ),
        "empty_buckets_omitted": empty_buckets,
        "tvd": _bucket_tvd(source_counts, product_counts),
        "source_numeric_values": source_total,
        "product_numeric_values": product_total,
        "product_non_numeric_excluded": product_stats.numeric_excluded,
    }
    return section


def _build_categorical_section(
    source_counts: list[int],
    product_counts: list[int],
    min_bucket_size: int,
    display_max: int,
) -> dict[str, Any]:
    source_total = sum(source_counts)
    product_total = sum(product_counts)
    profile = []
    other = {"source_count": 0, "product_count": 0, "merged_ranks": 0}
    length = max(len(source_counts), len(product_counts))
    for index in range(length):
        s_count = source_counts[index] if index < len(source_counts) else 0
        p_count = product_counts[index] if index < len(product_counts) else 0
        keep = (
            index < display_max
            and s_count >= min_bucket_size
            and p_count >= min_bucket_size
        )
        if not keep:
            other["source_count"] += s_count
            other["product_count"] += p_count
            other["merged_ranks"] += 1
            continue
        profile.append(
            {
                "rank": index + 1,
                "source_count": s_count,
                "product_count": p_count,
                "source_share": _share(s_count, source_total),
                "product_share": _share(p_count, product_total),
            }
        )
    return {
        "note": "按各自频次排名对齐，不输出原始类别名；排名不对应同一取值",
        "profile": profile,
        "other": (
            {
                **other,
                "source_share": _share(other["source_count"], source_total),
                "product_share": _share(other["product_count"], product_total),
            }
            if other["merged_ranks"]
            else None
        ),
        "tvd": _profile_tvd(source_counts, product_counts),
    }


def _column_status(
    source_stats: _SideStats,
    product_stats: _SideStats,
    cardinality_ratio: float | None,
    null_delta: float | None,
    tvd: float | None,
    missing_in_product: bool,
) -> tuple[str, list[str]]:
    flags: list[str] = []
    source_non_empty = source_stats.rows - source_stats.empty
    product_non_empty = product_stats.rows - product_stats.empty
    if missing_in_product:
        return "lost", ["product_column_missing"]
    if source_non_empty == 0 and product_non_empty == 0:
        return "empty", ["both_sides_empty"]
    if source_non_empty > 0 and product_non_empty == 0:
        return "lost", ["product_all_null"]
    if source_non_empty == 0 and product_non_empty > 0:
        flags.append("unexpected_product_values")
        return "degraded", flags
    if cardinality_ratio is not None and cardinality_ratio < 0.5:
        flags.append("cardinality_reduced")
    if null_delta is not None and null_delta > 0.2:
        flags.append("null_rate_increased")
    if tvd is not None and tvd > 0.5:
        flags.append("distribution_shifted")
    return ("degraded" if flags else "preserved"), flags


# ---------------------------------------------------------------------------
# Join preservation and quasi-identifier risk
# ---------------------------------------------------------------------------


def _readonly_uri(path: Path) -> str:
    return "file:" + urllib.parse.quote(path.resolve().as_posix(), safe="/:") + "?mode=ro"


def _join_side_metrics(conn: sqlite3.Connection, alias: str, join: JoinSpec) -> dict[str, Any]:
    child = f"{alias}.{quote_ident(join.child_table)}"
    parent = f"{alias}.{quote_ident(join.parent_table)}"
    child_col = quote_ident(join.child_column)
    parent_col = quote_ident(join.parent_column)
    rows = conn.execute(f"SELECT COUNT(*) FROM {child}").fetchone()[0]
    non_null = conn.execute(
        f"SELECT COUNT(*) FROM {child} WHERE {child_col} IS NOT NULL"
    ).fetchone()[0]
    orphans = conn.execute(
        f"SELECT COUNT(*) FROM {child} AS c WHERE c.{child_col} IS NOT NULL "
        f"AND NOT EXISTS (SELECT 1 FROM {parent} AS p WHERE p.{parent_col} = c.{child_col})"
    ).fetchone()[0]
    rate = None
    if non_null:
        rate = round((non_null - orphans) / non_null, 6)
    return {
        "rows": int(rows),
        "non_null_fk": int(non_null),
        "orphan_rows": int(orphans),
        "preservation_rate": rate,
    }


def _join_metrics(source_path: Path, product_path: Path, joins: Sequence[JoinSpec]) -> list[dict[str, Any]]:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("ATTACH DATABASE ? AS src", (_readonly_uri(source_path),))
        conn.execute("ATTACH DATABASE ? AS prod", (_readonly_uri(product_path),))
        results = []
        for join in joins:
            results.append(
                {
                    "child_table": join.child_table,
                    "child_column": join.child_column,
                    "parent_table": join.parent_table,
                    "parent_column": join.parent_column,
                    "origin": join.origin,
                    "source": _join_side_metrics(conn, "src", join),
                    "product": _join_side_metrics(conn, "prod", join),
                }
            )
        return results
    finally:
        conn.close()


def _qi_metrics(
    conn: sqlite3.Connection, table: str, columns: Sequence[str]
) -> dict[str, Any]:
    group_cols = ", ".join(quote_ident(name) for name in columns)
    cursor = conn.execute(
        f"SELECT COUNT(*) FROM {quote_ident(table)} GROUP BY {group_cols}"
    )
    rows = 0
    classes = 0
    min_class_size: int | None = None
    unique_rows = 0
    histogram: dict[int, int] = {}
    overflow: dict[str, int] | None = None
    for record in cursor:
        size = int(record[0])
        classes += 1
        rows += size
        min_class_size = size if min_class_size is None else min(min_class_size, size)
        if size == 1:
            unique_rows += 1
        if overflow is not None:
            overflow["classes"] += 1
            overflow["rows"] += size
            continue
        histogram[size] = histogram.get(size, 0) + 1
        if len(histogram) > 4096:
            # pathological spread of class sizes: keep the smallest sizes and
            # collapse the rest so the histogram itself stays bounded
            keep = set(sorted(histogram)[:1024])
            overflow = {"gte": max(keep) + 1, "classes": 0, "rows": 0}
            for key in list(histogram):
                if key not in keep:
                    count = histogram.pop(key)
                    overflow["classes"] += count
                    overflow["rows"] += key * count
    entries = [
        {"size": size, "classes": count, "rows": size * count}
        for size, count in sorted(histogram.items())
    ]
    if overflow is not None:
        entries.append(
            {
                "size_gte": overflow["gte"],
                "classes": overflow["classes"],
                "rows": overflow["rows"],
            }
        )
    return {
        "table": table,
        "columns": list(columns),
        "rows": rows,
        "classes": classes,
        "min_class_size": min_class_size,
        "unique_rows": unique_rows,
        "uniqueness_ratio": _share(unique_rows, rows),
        "size_histogram": entries,
    }


# ---------------------------------------------------------------------------
# Foreign-key discovery and validation
# ---------------------------------------------------------------------------


def _declared_foreign_keys(
    conn: sqlite3.Connection, inventory: DatasetInventory
) -> list[JoinSpec]:
    specs: list[JoinSpec] = []
    pk_cache: dict[str, str | None] = {}

    def single_pk(table: str) -> str | None:
        if table not in pk_cache:
            rows = conn.execute(
                f"PRAGMA table_info({quote_ident(table)})"
            ).fetchall()
            pks = [row[1] for row in rows if row[5]]
            pk_cache[table] = pks[0] if len(pks) == 1 else None
        return pk_cache[table]

    for table in inventory.tables:
        cursor = conn.execute(
            f"PRAGMA foreign_key_list({quote_ident(table.name)})"
        )
        for record in cursor:
            parent_table, from_col, to_col = record[2], record[3], record[4]
            if to_col is None:
                to_col = single_pk(parent_table)
            if to_col is None:
                continue
            specs.append(
                JoinSpec(table.name, from_col, parent_table, to_col, origin="schema_fk")
            )
    return specs


def _validate_qi_sets(product: DatasetInventory, qi_sets: Sequence[QiSet]) -> None:
    for qi in qi_sets:
        table = product.table(qi.table)
        if table is None:
            raise EvaluationError(
                f"--qi table {qi.table!r} not found in the product database"
            )
        available = {column.name for column in table.columns}
        missing = [name for name in qi.columns if name not in available]
        if missing:
            raise EvaluationError(
                f"--qi columns not found in product table {qi.table!r}: "
                + ", ".join(missing)
            )


def _validate_joins(
    source: DatasetInventory, product: DatasetInventory, joins: Sequence[JoinSpec]
) -> None:
    if not joins:
        return
    if source.kind != "sqlite":
        raise EvaluationError(
            "join preservation metrics require a SQLite source dataset "
            "(CSV sources hold a single table)"
        )
    for join in joins:
        for inventory, label in ((source, "source"), (product, "product")):
            for table_name, column in (
                (join.child_table, join.child_column),
                (join.parent_table, join.parent_column),
            ):
                table = inventory.table(table_name)
                if table is None:
                    raise EvaluationError(
                        f"--join table {table_name!r} not found in the {label} dataset"
                    )
                if column not in {col.name for col in table.columns}:
                    raise EvaluationError(
                        f"--join column {table_name}.{column} not found in the {label} dataset"
                    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _table_column_metrics_sqlite(
    source_conn: sqlite3.Connection,
    product_conn: sqlite3.Connection,
    source_table: TableInfo,
    product_table: TableInfo,
    params: EvalParams,
    warnings: list[str],
) -> list[dict[str, Any]]:
    source_stats = _sqlite_table_stats(source_conn, source_table)
    product_stats = _sqlite_table_stats(product_conn, product_table)
    product_columns = {column.name for column in product_table.columns}
    entries = []
    for column in source_table.columns:
        name = column.name
        s_stats = source_stats[name]
        missing = name not in product_columns
        p_stats = (
            product_stats[name]
            if not missing
            else _SideStats(rows=product_table.row_count)
        )
        kind = _classify_sqlite_column(column.declared_type, s_stats.distinct, params)
        if kind == "categorical" and p_stats.distinct > params.categorical_max_distinct:
            kind = "text"  # product side exploded beyond the cap; stay bounded
        entry = _assemble_column_entry(
            table=source_table.name,
            name=name,
            declared_type=column.declared_type,
            kind=kind,
            source_stats=s_stats,
            product_stats=p_stats,
            missing_in_product=missing,
            params=params,
            warnings=warnings,
        )
        if missing:
            entries.append(entry)
            continue
        if kind == "categorical":
            s_counts = _sqlite_category_counts(source_conn, source_table.name, name)
            p_counts = _sqlite_category_counts(product_conn, source_table.name, name)
            entry["categorical"] = _build_categorical_section(
                s_counts, p_counts, params.min_bucket_size, params.display_max_buckets
            )
            entry["categorical"]["distinct_source"] = s_stats.distinct
            entry["categorical"]["distinct_product"] = p_stats.distinct
            _refresh_status_for_tvd(entry, entry["categorical"]["tvd"])
        elif kind == "numeric":
            _attach_numeric_section(
                entry, s_stats, p_stats, params, warnings,
                bucket_fn=lambda conn_side, low, width, count: _sqlite_numeric_buckets(
                    source_conn if conn_side == "source" else product_conn,
                    source_table.name, name, low, width, count,
                ),
            )
        entries.append(entry)
    return entries


def _attach_numeric_section(
    entry: dict[str, Any],
    s_stats: _SideStats,
    p_stats: _SideStats,
    params: EvalParams,
    warnings: list[str],
    bucket_fn: Any,
) -> None:
    lows = [v for v in (s_stats.numeric_min, p_stats.numeric_min) if v is not None]
    highs = [v for v in (s_stats.numeric_max, p_stats.numeric_max) if v is not None]
    if not lows or not highs:
        entry["numeric"] = None
        return
    low, high = _nice_bounds(min(lows), max(highs))
    width = (high - low) / params.numeric_buckets if high > low else 0.0
    s_counts = bucket_fn("source", low, width, params.numeric_buckets)
    p_counts = bucket_fn("product", low, width, params.numeric_buckets)
    entry["numeric"] = _build_numeric_section(
        s_stats, p_stats, s_counts, p_counts, low, width,
        params.numeric_buckets, params.min_bucket_size,
    )
    if p_stats.numeric_excluded:
        warnings.append(
            f"列 {entry['table']}.{entry['column']} 产物侧有 "
            f"{p_stats.numeric_excluded} 个非数值取值，已排除在分桶之外"
        )
    _refresh_status_for_tvd(entry, entry["numeric"]["tvd"])


def _refresh_status_for_tvd(entry: dict[str, Any], tvd: float | None) -> None:
    if tvd is not None and tvd > 0.5 and "distribution_shifted" not in entry["flags"]:
        entry["flags"].append("distribution_shifted")
        if entry["utility_status"] == "preserved":
            entry["utility_status"] = "degraded"


def _assemble_column_entry(
    table: str,
    name: str,
    declared_type: str,
    kind: str,
    source_stats: _SideStats,
    product_stats: _SideStats,
    missing_in_product: bool,
    params: EvalParams,
    warnings: list[str],
) -> dict[str, Any]:
    source_non_empty = source_stats.rows - source_stats.empty
    product_non_empty = product_stats.rows - product_stats.empty
    cardinality_ratio = None
    if source_stats.distinct > 0:
        cardinality_ratio = round(product_stats.distinct / source_stats.distinct, 6)
    source_null_rate = _share(source_stats.empty, source_stats.rows)
    product_null_rate = _share(product_stats.empty, product_stats.rows)
    null_delta = None
    if source_null_rate is not None and product_null_rate is not None:
        null_delta = round(product_null_rate - source_null_rate, 6)
    status, flags = _column_status(
        source_stats, product_stats, cardinality_ratio, null_delta, None, missing_in_product
    )
    if source_stats.distinct_method == "hll_estimate" or product_stats.distinct_method == "hll_estimate":
        flags.append("cardinality_estimated")
        warnings.append(
            f"列 {table}.{name} 的基数为 HLL 估计值（精确去重超过上限 {params.distinct_cap}）"
        )
    if kind == "text":
        flags.append("distribution_skipped_high_cardinality")
    if product_non_empty == 0 < source_non_empty and not missing_in_product:
        warnings.append(f"列 {table}.{name} 在产物中整体为空，效用归零")
    return {
        "table": table,
        "column": name,
        "declared_type": declared_type,
        "kind": kind,
        "non_empty": {"source": source_non_empty, "product": product_non_empty},
        "null_rate": {
            "source": source_null_rate,
            "product": product_null_rate,
            "delta": null_delta,
        },
        "cardinality": {
            "source": source_stats.distinct,
            "product": product_stats.distinct,
            "ratio": cardinality_ratio,
            "method": (
                "hll_estimate"
                if "hll_estimate" in (source_stats.distinct_method, product_stats.distinct_method)
                else "exact"
            ),
        },
        "categorical": None,
        "numeric": None,
        "utility_status": status,
        "flags": flags,
    }


def _table_column_metrics_csv(
    source_path: Path,
    product_path: Path,
    source_table: TableInfo,
    product_table: TableInfo,
    params: EvalParams,
    warnings: list[str],
) -> list[dict[str, Any]]:
    column_names = [column.name for column in source_table.columns]
    source_rows, source_acc = _csv_accumulate(
        iter_csv_tuples(source_path), column_names, params
    )
    product_column_names = [column.name for column in product_table.columns]
    product_rows, product_acc = _csv_accumulate(
        _iter_sqlite_values(product_path, source_table.name, product_column_names),
        product_column_names,
        params,
    )
    product_columns = set(product_column_names)
    entries = []
    for column in source_table.columns:
        name = column.name
        s_acc = source_acc[name]
        missing = name not in product_columns
        s_stats = _SideStats(rows=source_rows)
        s_stats.empty = s_acc.empty
        s_stats.distinct, s_stats.distinct_method = s_acc.distinct.result()
        s_stats.numeric_min = s_acc.numeric_min
        s_stats.numeric_max = s_acc.numeric_max
        if missing:
            p_stats = _SideStats(rows=product_rows)
            kind = "categorical" if s_stats.distinct <= params.categorical_max_distinct else "text"
        else:
            p_acc = product_acc[name]
            p_stats = _SideStats(rows=product_rows)
            p_stats.empty = p_acc.empty
            p_stats.distinct, p_stats.distinct_method = p_acc.distinct.result()
            p_stats.numeric_min = p_acc.numeric_min
            p_stats.numeric_max = p_acc.numeric_max
            kind = _classify_csv_column(s_acc, s_stats.distinct, params)
        entry = _assemble_column_entry(
            source_table.name, name, column.declared_type, kind,
            s_stats, p_stats, missing, params, warnings,
        )
        if missing:
            entries.append(entry)
            continue
        if kind == "categorical":
            p_acc_final = product_acc[name]
            if s_acc.categories is None or p_acc_final.categories is None:
                entry["kind"] = "text"
                entry["flags"].append("distribution_skipped_high_cardinality")
                entries.append(entry)
                continue
            s_counts = sorted(s_acc.categories.values(), reverse=True)
            p_counts = sorted(p_acc_final.categories.values(), reverse=True)
            entry["categorical"] = _build_categorical_section(
                s_counts, p_counts, params.min_bucket_size, params.display_max_buckets
            )
            entry["categorical"]["distinct_source"] = s_stats.distinct
            entry["categorical"]["distinct_product"] = p_stats.distinct
            _refresh_status_for_tvd(entry, entry["categorical"]["tvd"])
        elif kind == "numeric":
            column_index = column_names.index(name)

            def bucket_fn(side: str, low: float, width: float, count: int) -> list[int]:
                if side == "source":
                    rows: Iterator[tuple[Any, ...]] = iter_csv_tuples(source_path)
                    index = column_index
                else:
                    rows = _iter_sqlite_values(product_path, source_table.name, [name])
                    index = 0
                counts, excluded = _csv_numeric_buckets(rows, index, low, width, count)
                if side == "product":
                    p_stats.numeric_excluded = excluded
                return counts

            _attach_numeric_section(entry, s_stats, p_stats, params, warnings, bucket_fn)
        entries.append(entry)
    return entries


def evaluate(
    source_path: str | Path,
    product_path: str | Path,
    params: EvalParams,
    paths: Any,
) -> dict[str, Any]:
    """Evaluate a masked product against its source. Both opened read-only."""
    started = time.monotonic()
    params.validate()
    source = Path(source_path).expanduser().resolve()
    product = Path(product_path).expanduser().resolve()
    if source == product:
        raise EvaluationError("source and product must be different files")
    pseudomap = Path(paths.pseudomap_db).resolve()
    if source == pseudomap or product == pseudomap:
        raise EvaluationError(
            "refusing to evaluate the pseudonym mapping store; "
            "evaluation never reverses pseudonyms"
        )
    if not source.is_file():
        raise EvaluationError(f"source dataset not found: {source}")
    if not product.is_file():
        raise EvaluationError(f"product database not found: {product}")
    if dataset_kind(product) != "sqlite":
        raise EvaluationError("the masked product must be a SQLite database")

    source_inventory = inspect_dataset(source)
    product_inventory = inspect_dataset(product)
    _validate_qi_sets(product_inventory, params.qi_sets)

    joins = list(params.joins)
    if source_inventory.kind == "sqlite":
        declared_conn = sqlite_connect_readonly(source)
        try:
            declared = _declared_foreign_keys(declared_conn, source_inventory)
        finally:
            declared_conn.close()
        seen = {(j.child_table, j.child_column, j.parent_table, j.parent_column) for j in joins}
        for spec in declared:
            key = (spec.child_table, spec.child_column, spec.parent_table, spec.parent_column)
            if key not in seen:
                joins.append(spec)
                seen.add(key)
    _validate_joins(source_inventory, product_inventory, joins)

    warnings: list[str] = []
    product_tables = {table.name: table for table in product_inventory.tables}
    source_conn = (
        sqlite_connect_readonly(source) if source_inventory.kind == "sqlite" else None
    )
    product_conn = sqlite_connect_readonly(product)
    table_entries: list[dict[str, Any]] = []
    try:
        for source_table in source_inventory.tables:
            product_table = product_tables.get(source_table.name)
            if product_table is None:
                warnings.append(
                    f"表 {source_table.name} 在产物中缺失，相关列效用记为归零"
                )
                table_entries.append(
                    {
                        "table": source_table.name,
                        "status": "missing_in_product",
                        "rows": {"source": source_table.row_count, "product": 0},
                        "columns": [
                            {
                                "table": source_table.name,
                                "column": column.name,
                                "declared_type": column.declared_type,
                                "kind": "unknown",
                                "non_empty": {"source": None, "product": 0},
                                "null_rate": {"source": None, "product": None, "delta": None},
                                "cardinality": {
                                    "source": None,
                                    "product": 0,
                                    "ratio": None,
                                    "method": "exact",
                                },
                                "categorical": None,
                                "numeric": None,
                                "utility_status": "lost",
                                "flags": ["product_table_missing"],
                            }
                            for column in source_table.columns
                        ],
                    }
                )
                continue
            if source_table.row_count != product_table.row_count:
                warnings.append(
                    f"表 {source_table.name} 行数不一致：源 {source_table.row_count} / "
                    f"产物 {product_table.row_count}"
                )
            extra_columns = [
                column.name
                for column in product_table.columns
                if column.name not in {c.name for c in source_table.columns}
            ]
            for extra in extra_columns:
                warnings.append(f"产物列 {source_table.name}.{extra} 在源数据集中不存在")
            if source_inventory.kind == "sqlite":
                columns = _table_column_metrics_sqlite(
                    source_conn, product_conn, source_table, product_table, params, warnings
                )
            else:
                columns = _table_column_metrics_csv(
                    source, product, source_table, product_table, params, warnings
                )
            table_entries.append(
                {
                    "table": source_table.name,
                    "status": "ok",
                    "rows": {
                        "source": source_table.row_count,
                        "product": product_table.row_count,
                    },
                    "columns": columns,
                }
            )
    finally:
        if source_conn is not None:
            source_conn.close()
        product_conn.close()

    for extra_table in sorted(set(product_tables) - {t.name for t in source_inventory.tables}):
        warnings.append(f"产物表 {extra_table} 在源数据集中不存在，未纳入评估")

    join_results = _join_metrics(source, product, joins) if joins else []

    risk_results = []
    if params.qi_sets:
        qi_conn = sqlite_connect_readonly(product)
        try:
            for qi in params.qi_sets:
                risk_results.append(_qi_metrics(qi_conn, qi.table, qi.columns))
        finally:
            qi_conn.close()

    status_counts = {"preserved": 0, "degraded": 0, "lost": 0, "empty": 0}
    column_total = 0
    for table_entry in table_entries:
        for column_entry in table_entry["columns"]:
            column_total += 1
            status_counts[column_entry["utility_status"]] = (
                status_counts.get(column_entry["utility_status"], 0) + 1
            )

    evaluation_id = new_evaluation_id()
    return {
        "evaluation_id": evaluation_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "source": {
            "path": str(source),
            "kind": source_inventory.kind,
            "fingerprint": source_inventory.fingerprint,
            "rows": source_inventory.row_count,
        },
        "product": {
            "path": str(product),
            "kind": product_inventory.kind,
            "fingerprint": product_inventory.fingerprint,
            "rows": product_inventory.row_count,
        },
        "parameters": params.to_dict(),
        "utility_rules": UTILITY_RULES,
        "summary": {
            "tables": len(table_entries),
            "columns": column_total,
            "status_counts": status_counts,
            "join_checks": len(join_results),
            "qi_sets": len(risk_results),
            "warnings": len(warnings),
        },
        "tables": table_entries,
        "joins": join_results,
        "risks": risk_results,
        "warnings": warnings,
        "privacy_note": (
            "本报告不包含任何原始取值：类别分布按频次排名匿名展示，数值分布仅给出"
            "外扩取整后的分桶边界与占比；样本量低于阈值的桶已合并为“其他”。"
            "评估全程以只读方式打开源数据集与产物，未访问假名映射库。"
        ),
    }
