"""Streaming utility/risk evaluation engine.

The engine opens the source dataset and the masked product read-only and
never imports the pseudonym mapping library. All aggregates are either
fixed-size sketches (HyperLogLog, Misra-Gries, Bloom filter) or externally
spilled exact counters, so peak memory does not grow with row count.

Report payloads contain bucket ordinals, counts and proportions only. Raw
cell values and even value fingerprints are never emitted: categorical
buckets are paired internally by hash but rendered by ordinal, and QI
fingerprints are discarded once counted.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..utils import MasklineError, file_sha256
from . import access
from .access import ColumnSchema, TableSchema, parse_number
from .sketches import (
    BloomFilter,
    ExternalHashCounter,
    HyperLogLog,
    MisraGries,
    NumericRangeTracker,
    fingerprint_key,
    hash_value,
)

OTHER_LABEL = "其他"
NUMERIC_HINTS = ("INT", "REAL", "FLOA", "DOUB", "NUMERIC", "DECIMAL")
DEFAULT_BUCKETS = 10
DEFAULT_MIN_BUCKET = 5
DEFAULT_TOP_K = 64
DEFAULT_HLL_PRECISION = 14
DEFAULT_MG_CAPACITY = 4096


class EvaluationInputError(MasklineError):
    pass


@dataclass(frozen=True)
class QISpec:
    table: str
    columns: tuple[str, ...]

    @property
    def label(self) -> str:
        return f"{self.table}:" + ",".join(self.columns)


@dataclass(frozen=True)
class JoinSpec:
    parent_table: str
    parent_column: str
    child_table: str
    child_column: str

    @property
    def label(self) -> str:
        return f"{self.parent_table}.{self.parent_column}={self.child_table}.{self.child_column}"


@dataclass
class _ColumnAgg:
    schema: ColumnSchema
    hll: HyperLogLog
    mg: MisraGries
    range_tracker: NumericRangeTracker
    nulls: int = 0
    total: int = 0
    parsed_numeric: int = 0
    is_numeric: bool = False
    edges: list[float] | None = None
    bucket_counts: list[int] | None = None
    out_of_range: int = 0

    @property
    def non_null(self) -> int:
        return self.total - self.nulls


@dataclass
class _JoinAgg:
    spec: JoinSpec
    parent_bloom: BloomFilter
    child_total: int = 0
    child_nulls: int = 0
    child_matched: int = 0


@dataclass(frozen=True)
class EvaluationConfig:
    bucket_count: int = DEFAULT_BUCKETS
    min_bucket: int = DEFAULT_MIN_BUCKET
    top_k: int = DEFAULT_TOP_K
    hll_precision: int = DEFAULT_HLL_PRECISION
    mg_capacity: int = DEFAULT_MG_CAPACITY
    spill_dir: Path | None = None
    max_memory_keys: int = 200_000
    spill_partitions: int = 256


@dataclass
class TableEvaluation:
    table: str
    source_rows: int
    product_rows: int
    columns: list[dict[str, Any]] = field(default_factory=list)
    structural_note: str | None = None


@dataclass
class EvaluationResult:
    evaluation_id: str
    source_path: Path
    product_path: Path
    source_hash: str
    product_hash: str
    config: dict[str, Any]
    tables: list[TableEvaluation]
    joins: list[dict[str, Any]]
    quasi_identifiers: list[dict[str, Any]]
    warnings: list[str]
    generated_at: str
    spill_bytes: int


def _is_null(value: Any) -> bool:
    return value is None or value == ""


def _declared_numeric(declared_type: str) -> bool:
    upper = declared_type.upper()
    return any(hint in upper for hint in NUMERIC_HINTS)


def _ratio(numerator: int, denominator: int) -> float:
    if not denominator:
        return 0.0
    return round(numerator / denominator, 6)


def _round_edge(value: float) -> float:
    return round(float(value), 6)


def _new_column_agg(schema: ColumnSchema, config: EvaluationConfig) -> _ColumnAgg:
    return _ColumnAgg(
        schema=schema,
        hll=HyperLogLog(precision=config.hll_precision),
        mg=MisraGries(capacity=config.mg_capacity),
        range_tracker=NumericRangeTracker(bucket_count=config.bucket_count),
    )


def _bucket_index(edges: list[float], value: float, bucket_count: int) -> int:
    if value <= edges[0]:
        return 0
    if value >= edges[-1]:
        return bucket_count - 1
    lo, hi = 0, bucket_count - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if value < edges[mid + 1]:
            hi = mid
        else:
            lo = mid + 1
    return lo


class Evaluator:

    def __init__(
        self,
        source_path: Path,
        product_path: Path,
        qi_specs: list[QISpec],
        join_specs: list[JoinSpec],
        config: EvaluationConfig,
    ) -> None:
        self.source_path = source_path
        self.product_path = product_path
        self.qi_specs = qi_specs
        self.join_specs = join_specs
        self.config = config
        self.warnings: list[str] = []
        self._salt = secrets.token_hex(16)
        self._spill_bytes = 0

    # ------------------------------------------------------------------
    # Join bookkeeping: one _JoinAgg per spec, shared by the two sides
    # ------------------------------------------------------------------

    def _build_join_aggs(
        self, path: Path, schema_map: dict[str, TableSchema]
    ) -> dict[str, _JoinAgg]:
        aggs: dict[str, _JoinAgg] = {}
        for spec in self.join_specs:
            parent = schema_map.get(spec.parent_table)
            child = schema_map.get(spec.child_table)
            if parent is None or child is None:
                continue
            if spec.parent_column not in parent.column_names():
                continue
            if spec.child_column not in child.column_names():
                continue
            expected = max(access.row_count(path, spec.parent_table), 1)
            aggs[spec.label] = _JoinAgg(spec=spec, parent_bloom=BloomFilter(expected))
        return aggs

    def _join_aggs_for_table(
        self, aggs: dict[str, _JoinAgg], table_name: str
    ) -> list[_JoinAgg]:
        return [
            agg
            for agg in aggs.values()
            if table_name in (agg.spec.parent_table, agg.spec.child_table)
        ]

    def _table_order(self, schema_map: dict[str, TableSchema]) -> list[str]:
        """Parents before children so Bloom filters are populated in time."""
        names = list(schema_map)
        pending = set(names)
        ordered: list[str] = []
        edges = {
            spec.child_table: spec.parent_table
            for spec in self.join_specs
            if spec.child_table in pending and spec.parent_table in pending
        }
        while pending:
            ready = sorted(name for name in pending if edges.get(name) not in pending)
            if not ready:  # cycle or self-reference: keep the remaining order
                ready = sorted(pending)
            for name in ready:
                ordered.append(name)
                pending.remove(name)
        return ordered

    # ------------------------------------------------------------------
    # Pass 1: cardinality, nulls, heavy hitters, numeric range, join blooms
    # ------------------------------------------------------------------

    def _pass_one(
        self,
        dataset_path: Path,
        table: TableSchema,
        aggs: dict[str, _ColumnAgg],
        join_aggs: list[_JoinAgg],
    ) -> int:
        columns = table.column_names()
        rows = 0
        for row in access.iter_rows(dataset_path, table.name, columns):
            rows += 1
            for idx, value in enumerate(row):
                agg = aggs[columns[idx]]
                agg.total += 1
                if _is_null(value):
                    agg.nulls += 1
                    continue
                agg.hll.add(value)
                agg.mg.add(hash_value(value))
                number = parse_number(value)
                if number is not None:
                    agg.parsed_numeric += 1
                    agg.range_tracker.observe(number)
                else:
                    agg.range_tracker.observe(None)
            for join_agg in join_aggs:
                spec = join_agg.spec
                if table.name == spec.parent_table:
                    value = row[columns.index(spec.parent_column)]
                    if not _is_null(value):
                        join_agg.parent_bloom.add(value)
                else:
                    value = row[columns.index(spec.child_column)]
                    join_agg.child_total += 1
                    if _is_null(value):
                        join_agg.child_nulls += 1
                    elif join_agg.parent_bloom.might_contain(value):
                        join_agg.child_matched += 1
        return rows

    # ------------------------------------------------------------------
    # Pass 2: numeric bucket accumulation on shared source-derived edges
    # ------------------------------------------------------------------

    def _pass_two_numeric(
        self,
        dataset_path: Path,
        table_name: str,
        numeric_columns: tuple[str, ...],
        aggs: dict[str, _ColumnAgg],
        edges_by_column: dict[str, list[float]],
        track_out_of_range: bool,
    ) -> None:
        for row in access.iter_rows(dataset_path, table_name, numeric_columns):
            for slot, name in enumerate(numeric_columns):
                value = row[slot]
                if _is_null(value):
                    continue
                number = parse_number(value)
                if number is None:
                    continue
                agg = aggs[name]
                assert agg.edges is not None and agg.bucket_counts is not None
                edges = agg.edges
                if number < edges[0] or number > edges[-1]:
                    if track_out_of_range:
                        agg.out_of_range += 1
                    number = min(max(number, edges[0]), edges[-1])
                agg.bucket_counts[_bucket_index(edges, number, self.config.bucket_count)] += 1

    # ------------------------------------------------------------------
    # QI equivalence classes via external hash aggregation (product only)
    # ------------------------------------------------------------------

    def _evaluate_qi(self, product_schema: dict[str, TableSchema]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        by_table: dict[str, list[QISpec]] = {}
        for spec in self.qi_specs:
            by_table.setdefault(spec.table, []).append(spec)
        for table_name, specs in by_table.items():
            table = product_schema.get(table_name)
            if table is None:
                for spec in specs:
                    results.append(self._missing_qi(spec, "产物中缺失该表"))
                continue
            counters: dict[str, ExternalHashCounter] = {}
            spill_subdirs: list[Path] = []
            valid_specs: list[QISpec] = []
            for spec in specs:
                missing = [c for c in spec.columns if c not in table.column_names()]
                if missing:
                    results.append(
                        self._missing_qi(spec, f"产物中缺失列: {', '.join(missing)}")
                    )
                    continue
                # Each counter gets its own subdirectory: counters for
                # different QI groups sharing one spill directory would
                # otherwise overwrite each other's partition files.
                if self.config.spill_dir is not None:
                    spill_dir = Path(self.config.spill_dir) / f"qi-{len(counters):04d}"
                    spill_subdirs.append(spill_dir)
                else:
                    spill_dir = None
                counters[spec.label] = ExternalHashCounter(
                    max_keys=self.config.max_memory_keys,
                    partitions=self.config.spill_partitions,
                    spill_dir=spill_dir,
                )
                valid_specs.append(spec)
            if not valid_specs:
                continue
            column_set = tuple(
                sorted({col for spec in valid_specs for col in spec.columns})
            )
            positions = {
                spec.label: [column_set.index(col) for col in spec.columns]
                for spec in valid_specs
            }
            null_rows = {spec.label: 0 for spec in valid_specs}
            total_rows = 0
            try:
                for row in access.iter_rows(self.product_path, table_name, column_set):
                    total_rows += 1
                    for spec in valid_specs:
                        values = tuple(row[pos] for pos in positions[spec.label])
                        if any(_is_null(value) for value in values):
                            null_rows[spec.label] += 1
                            continue
                        counters[spec.label].add(
                            fingerprint_key(values, salt=self._salt)
                        )
                for spec in valid_specs:
                    counter = counters[spec.label]
                    self._spill_bytes += self._spill_footprint(counter)
                    results.append(
                        self._summarize_qi(spec, counter, total_rows, null_rows[spec.label])
                    )
            finally:
                for counter in counters.values():
                    counter.cleanup()
                for subdir in spill_subdirs:
                    try:
                        subdir.rmdir()
                    except OSError:
                        pass
        return results

    def _missing_qi(self, spec: QISpec, reason: str) -> dict[str, Any]:
        return {
            "table": spec.table,
            "columns": list(spec.columns),
            "status": "unavailable",
            "reason": reason,
        }

    def _summarize_qi(
        self, spec: QISpec, counter: ExternalHashCounter, total_rows: int, null_rows: int
    ) -> dict[str, Any]:
        evaluated_rows = total_rows - null_rows
        class_count = 0
        singleton_classes = 0
        min_size: int | None = None
        max_size = 0
        size_histogram: dict[int, int] = {}
        for _fingerprint, size in counter.iter_counts():
            class_count += 1
            if size == 1:
                singleton_classes += 1
            min_size = size if min_size is None else min(min_size, size)
            max_size = max(max_size, size)
            size_histogram[size] = size_histogram.get(size, 0) + 1
        thresholds = (2, 3, 5, 10)
        below_threshold = {
            str(k): sum(num for size, num in size_histogram.items() if size < k)
            for k in thresholds
        }
        unique_ratio = (singleton_classes / evaluated_rows) if evaluated_rows else 0.0
        return {
            "table": spec.table,
            "columns": list(spec.columns),
            "status": "ok",
            "rows_total": total_rows,
            "rows_with_null_components": null_rows,
            "rows_evaluated": evaluated_rows,
            "equivalence_class_count": class_count,
            "min_class_size": min_size,
            "max_class_size": max_size,
            "singleton_class_count": singleton_classes,
            "unique_ratio": round(unique_ratio, 6),
            "classes_below_size": below_threshold,
            "class_size_distribution": self._qi_size_buckets(size_histogram),
            "external_spill_used": counter.spilled,
        }

    def _qi_size_buckets(self, size_histogram: dict[int, int]) -> list[dict[str, Any]]:
        """Collapse the class-size histogram into bounded ordinal buckets."""
        ordered = sorted(size_histogram.items())
        total = sum(size_histogram.values())
        if not ordered:
            return []
        buckets: list[dict[str, Any]] = []
        small_classes = 0
        for size, num_classes in ordered:
            if num_classes < self.config.min_bucket:
                small_classes += num_classes
                continue
            buckets.append(
                {
                    "class_size": size,
                    "class_count": num_classes,
                    "share": round(num_classes / total, 6),
                }
            )
        if small_classes:
            buckets.append(
                {
                    "class_size": OTHER_LABEL,
                    "class_count": small_classes,
                    "share": round(small_classes / total, 6),
                }
            )
        return buckets

    def _spill_footprint(self, counter: ExternalHashCounter) -> int:
        if not counter.spilled or counter._spill_paths is None:
            return 0
        return sum(
            path.stat().st_size for path in counter._spill_paths if path.exists()
        )

    # ------------------------------------------------------------------
    # Column metric assembly
    # ------------------------------------------------------------------

    def _classify_numeric(self, source_agg: _ColumnAgg) -> bool:
        # Only columns whose source schema declares a numeric type are
        # histogrammed numerically. Numeric-looking TEXT (phone numbers, bank
        # card numbers, IDs) stays categorical, so the report never exposes
        # the value range of an identifier.
        return _declared_numeric(source_agg.schema.declared_type) and (
            source_agg.parsed_numeric > 0
        )

    def _column_metrics(
        self,
        source_agg: _ColumnAgg,
        product_agg: _ColumnAgg,
    ) -> dict[str, Any]:
        metrics: dict[str, Any] = {
            "column": source_agg.schema.name,
            "source_rows": source_agg.total,
            "product_rows": product_agg.total,
            "cardinality": {
                "source_distinct_estimate": source_agg.hll.estimate(),
                "product_distinct_estimate": product_agg.hll.estimate(),
            },
            "null_rate": {
                "source": _ratio(source_agg.nulls, source_agg.total),
                "product": _ratio(product_agg.nulls, product_agg.total),
            },
            "utility_status": "ok",
        }
        card = metrics["cardinality"]
        card["delta"] = card["product_distinct_estimate"] - card["source_distinct_estimate"]
        card["retention_ratio"] = _ratio(
            card["product_distinct_estimate"], max(card["source_distinct_estimate"], 1)
        )
        metrics["null_rate"]["delta"] = round(
            metrics["null_rate"]["product"] - metrics["null_rate"]["source"], 6
        )
        if source_agg.non_null > 0 and product_agg.non_null == 0:
            metrics["utility_status"] = "zero"
            metrics["utility_note"] = "产物中该列全部为空值，列效用归零"
            return metrics
        if product_agg.non_null == 0:
            metrics["utility_status"] = "empty"
            return metrics
        if source_agg.is_numeric:
            metrics["numeric_distribution"] = self._numeric_distribution(
                source_agg, product_agg
            )
        else:
            metrics["categorical_distribution"] = self._categorical_distribution(
                source_agg, product_agg
            )
        return metrics

    def _categorical_distribution(
        self, source_agg: _ColumnAgg, product_agg: _ColumnAgg
    ) -> dict[str, Any]:
        src_items = dict(source_agg.mg.items())
        prd_items = dict(product_agg.mg.items())
        threshold = self.config.min_bucket
        # Values below the reporting threshold on both sides collapse into
        # "other"; values surviving on either side remain matched by ordinal.
        matched = sorted(
            (
                key
                for key in src_items
                if key in prd_items
                and (src_items[key] >= threshold or prd_items[key] >= threshold)
            ),
            key=lambda key: (-src_items[key], key),
        )[: self.config.top_k]
        matched_set = set(matched)
        src_other = source_agg.non_null - sum(src_items[key] for key in matched_set)
        prd_other = product_agg.non_null - sum(prd_items.get(key, 0) for key in matched_set)
        buckets: list[dict[str, Any]] = []
        for ordinal, key in enumerate(matched, start=1):
            buckets.append(
                {
                    "bucket": f"桶{ordinal}",
                    "source_count": src_items[key],
                    "product_count": prd_items[key],
                    "source_share": _ratio(src_items[key], source_agg.non_null),
                    "product_share": _ratio(prd_items[key], product_agg.non_null),
                }
            )
        buckets.append(
            {
                "bucket": OTHER_LABEL,
                "source_count": src_other,
                "product_count": prd_other,
                "source_share": _ratio(src_other, source_agg.non_null),
                "product_share": _ratio(prd_other, product_agg.non_null),
            }
        )
        tvd = 0.5 * sum(
            abs(bucket["source_share"] - bucket["product_share"]) for bucket in buckets
        )
        return {
            "buckets": buckets,
            "tvd": round(tvd, 6),
            "heavy_hitter_capacity": self.config.mg_capacity,
            "source_sketch_exact": source_agg.mg.exact,
            "product_sketch_exact": product_agg.mg.exact,
        }

    def _numeric_distribution(
        self, source_agg: _ColumnAgg, product_agg: _ColumnAgg
    ) -> dict[str, Any]:
        assert source_agg.edges is not None and source_agg.bucket_counts is not None
        assert product_agg.bucket_counts is not None
        edges = source_agg.edges
        src_counts = source_agg.bucket_counts
        prd_counts = product_agg.bucket_counts
        threshold = self.config.min_bucket
        merged_src = 0
        merged_prd = 0
        kept: list[int] = []
        for idx in range(self.config.bucket_count):
            if src_counts[idx] < threshold and prd_counts[idx] < threshold:
                merged_src += src_counts[idx]
                merged_prd += prd_counts[idx]
            else:
                kept.append(idx)
        buckets: list[dict[str, Any]] = []
        for ordinal, idx in enumerate(kept, start=1):
            buckets.append(
                {
                    "bucket": f"桶{ordinal}",
                    "range": {
                        "lower": _round_edge(edges[idx]),
                        "upper": _round_edge(edges[idx + 1]),
                    },
                    "source_count": src_counts[idx],
                    "product_count": prd_counts[idx],
                    "source_share": _ratio(src_counts[idx], source_agg.non_null),
                    "product_share": _ratio(prd_counts[idx], product_agg.non_null),
                }
            )
        if merged_src or merged_prd:
            buckets.append(
                {
                    "bucket": OTHER_LABEL,
                    "range": None,
                    "source_count": merged_src,
                    "product_count": merged_prd,
                    "source_share": _ratio(merged_src, source_agg.non_null),
                    "product_share": _ratio(merged_prd, product_agg.non_null),
                }
            )
        tvd = 0.5 * sum(
            abs(bucket["source_share"] - bucket["product_share"]) for bucket in buckets
        )
        return {
            "bucket_edges": [_round_edge(edge) for edge in edges],
            "buckets": buckets,
            "tvd": round(tvd, 6),
            "product_out_of_range_values": product_agg.out_of_range,
        }

    # ------------------------------------------------------------------
    # Join retention
    # ------------------------------------------------------------------

    def _join_side(self, agg: _JoinAgg) -> dict[str, Any]:
        denominator = agg.child_total - agg.child_nulls
        return {
            "child_rows": agg.child_total,
            "child_null_keys": agg.child_nulls,
            "child_rows_evaluated": denominator,
            "matched_rows": agg.child_matched,
            "retention_ratio": _ratio(agg.child_matched, denominator),
            "bloom_filter": {
                "byte_size": agg.parent_bloom.byte_size,
                "hash_count": agg.parent_bloom.hash_count,
                "configured_false_positive_rate": agg.parent_bloom.false_positive_rate,
            },
        }

    def _join_metrics(
        self,
        source_aggs: dict[str, _JoinAgg],
        product_aggs: dict[str, _JoinAgg],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for spec in self.join_specs:
            product_agg = product_aggs.get(spec.label)
            if product_agg is None:
                results.append(
                    {
                        "relationship": spec.label,
                        "status": "unavailable",
                        "reason": "产物中缺失参与连接的表或列",
                    }
                )
                continue
            entry: dict[str, Any] = {
                "relationship": spec.label,
                "status": "ok",
                "product": self._join_side(product_agg),
            }
            source_agg = source_aggs.get(spec.label)
            if source_agg is not None:
                entry["source"] = self._join_side(source_agg)
                entry["retention_ratio_change"] = round(
                    entry["product"]["retention_ratio"]
                    - entry["source"]["retention_ratio"],
                    6,
                )
            results.append(entry)
        return results

    # ------------------------------------------------------------------

    def _project_table(self, table: TableSchema, names: tuple[str, ...]) -> TableSchema:
        keep = set(names)
        return TableSchema(
            name=table.name,
            columns=tuple(col for col in table.columns if col.name in keep),
        )

    def _validate_specs(self, source_schema: dict[str, TableSchema]) -> None:
        for spec in self.qi_specs:
            table = source_schema.get(spec.table)
            if table is None:
                raise EvaluationInputError(f"准标识符引用了不存在的表: {spec.table}")
            unknown = [c for c in spec.columns if c not in table.column_names()]
            if unknown:
                raise EvaluationInputError(
                    f"准标识符 {spec.label} 引用了不存在的列: {', '.join(unknown)}"
                )
            if not spec.columns:
                raise EvaluationInputError(f"准标识符 {spec.table} 至少需要一列")
        for spec in self.join_specs:
            for table_name, column in (
                (spec.parent_table, spec.parent_column),
                (spec.child_table, spec.child_column),
            ):
                table = source_schema.get(table_name)
                if table is None:
                    raise EvaluationInputError(f"连接关系引用了不存在的表: {table_name}")
                if column not in table.column_names():
                    raise EvaluationInputError(
                        f"连接关系 {spec.label} 引用了不存在的列: {table_name}.{column}"
                    )

    def run(self) -> EvaluationResult:
        source_schema = access.schema_of(self.source_path)
        product_schema = access.schema_of(self.product_path)
        aligned, structural_warnings = access.align_schemas(source_schema, product_schema)
        self.warnings.extend(structural_warnings)
        self._validate_specs(source_schema)

        source_join_aggs = self._build_join_aggs(self.source_path, source_schema)
        product_join_aggs = self._build_join_aggs(self.product_path, aligned)

        table_results: list[TableEvaluation] = []
        for table_name in self._table_order(source_schema):
            source_table = source_schema[table_name]
            product_table = aligned.get(table_name)
            if product_table is None:
                table_results.append(
                    TableEvaluation(
                        table=table_name,
                        source_rows=access.row_count(self.source_path, table_name),
                        product_rows=0,
                        structural_note="产物中缺失该表，整表效用归零",
                    )
                )
                continue
            shared = product_table.column_names()
            projected_source = self._project_table(source_table, shared)
            source_schema_by_name = {col.name: col for col in projected_source.columns}
            source_aggs = {
                col.name: _new_column_agg(source_schema_by_name[col.name], self.config)
                for col in product_table.columns
            }
            product_aggs = {
                col.name: _new_column_agg(col, self.config) for col in product_table.columns
            }
            source_rows = self._pass_one(
                self.source_path,
                projected_source,
                source_aggs,
                self._join_aggs_for_table(source_join_aggs, table_name),
            )
            product_rows = self._pass_one(
                self.product_path,
                product_table,
                product_aggs,
                self._join_aggs_for_table(product_join_aggs, table_name),
            )
            edges_by_column: dict[str, list[float]] = {}
            for name, source_agg in source_aggs.items():
                is_numeric = self._classify_numeric(source_agg)
                source_agg.is_numeric = is_numeric
                product_aggs[name].is_numeric = is_numeric
                if is_numeric and source_agg.range_tracker.minimum is not None:
                    edges = source_agg.range_tracker.finalize_edges()
                    source_agg.edges = edges
                    source_agg.bucket_counts = [0] * self.config.bucket_count
                    product_aggs[name].edges = edges
                    product_aggs[name].bucket_counts = [0] * self.config.bucket_count
                    edges_by_column[name] = edges
            if edges_by_column:
                numeric_columns = tuple(edges_by_column)
                self._pass_two_numeric(
                    self.source_path,
                    table_name,
                    numeric_columns,
                    source_aggs,
                    edges_by_column,
                    track_out_of_range=False,
                )
                self._pass_two_numeric(
                    self.product_path,
                    table_name,
                    numeric_columns,
                    product_aggs,
                    edges_by_column,
                    track_out_of_range=True,
                )
            column_metrics = [
                self._column_metrics(source_aggs[col.name], product_aggs[col.name])
                for col in product_table.columns
            ]
            table_results.append(
                TableEvaluation(
                    table=table_name,
                    source_rows=source_rows,
                    product_rows=product_rows,
                    columns=column_metrics,
                )
            )

        join_metrics = self._join_metrics(source_join_aggs, product_join_aggs)
        qi_metrics = self._evaluate_qi(aligned)
        zeroed = [
            f"{table.table}.{column['column']}"
            for table in table_results
            for column in table.columns
            if column.get("utility_status") == "zero"
        ]
        if zeroed:
            self.warnings.append("以下列在产物中效用归零: " + ", ".join(zeroed))

        evaluation_id = (
            "eval-"
            + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            + "-"
            + secrets.token_hex(3)
        )
        return EvaluationResult(
            evaluation_id=evaluation_id,
            source_path=self.source_path,
            product_path=self.product_path,
            source_hash=file_sha256(self.source_path),
            product_hash=file_sha256(self.product_path),
            config={
                "bucket_count": self.config.bucket_count,
                "min_bucket": self.config.min_bucket,
                "top_k": self.config.top_k,
                "hll_precision": self.config.hll_precision,
                "misra_gries_capacity": self.config.mg_capacity,
                "max_memory_keys": self.config.max_memory_keys,
                "spill_partitions": self.config.spill_partitions,
                "qi_specs": [spec.label for spec in self.qi_specs],
                "join_specs": [spec.label for spec in self.join_specs],
            },
            tables=table_results,
            joins=join_metrics,
            quasi_identifiers=qi_metrics,
            warnings=self.warnings,
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            spill_bytes=self._spill_bytes,
        )
