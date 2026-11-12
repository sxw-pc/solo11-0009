"""Orchestrate one policy impact simulation without formal masking artifacts.

The runner composes the three existing capabilities:

* :mod:`maskline.policies` parses and strictly validates the declarative policy
  (identical grammar and parameter checks as the formal pipeline);
* :mod:`maskline.transformers` and the pipeline row transformer apply the rules
  to sampled rows, backed by an isolated temporary pseudonym database;
* :mod:`maskline.dataset_io` / :mod:`maskline.simulation.sampling` stream rows
  from the read-only source under a memory bound.

Source files are opened read-only, every transient artifact lives inside the
:class:`SimulationWorkspace` temp directory, and no file is ever created in the
formal output directory.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import Paths, SecretStore
from ..policies import Policy, TablePolicy, load_policy
from ..pseudomap import PseudoMap
from ..registry import DatasetInventory, TableInfo, inspect_dataset
from ..transformers import REGISTRY, TransformContext
from .errors import SimulationError
from .metrics import (
    CoverageAccumulator,
    NumericAccumulator,
    distribution_metric,
    kpi_metric,
    linkage_metric,
)
from .sampling import SamplingConfig, TableSample, iter_all_rows, sample_table
from .workspace import SimulationWorkspace, default_temp_root, sweep_stale_workspaces

EMPTY_SAMPLE_WARNING = "sampled data is empty: table has no rows"


@dataclass
class StreamCoverage:
    """Full-stream value counts collected in the single source pass."""

    total: int = 0
    non_empty: int = 0
    empty: int = 0

    def observe(self, value: Any) -> None:
        self.total += 1
        if value is None or value == "":
            self.empty += 1
        else:
            self.non_empty += 1


@dataclass
class SimulationResult:
    simulation_id: str
    status: str
    document: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    temp_dir: Path | None = None
    elapsed_seconds: float = 0.0


@dataclass(frozen=True)
class LinkageSpec:
    left_table: str
    left_column: str
    right_table: str
    right_column: str

    @classmethod
    def parse(cls, text: str) -> "LinkageSpec":
        parts = [part.strip() for part in text.split("=")]
        if len(parts) != 2 or not all(parts):
            raise SimulationError(
                f"invalid linkage pair {text!r}; expected 'table.column=table.column'"
            )
        left = parts[0].split(".")
        right = parts[1].split(".")
        if len(left) != 2 or len(right) != 2 or not all(left + right):
            raise SimulationError(
                f"invalid linkage pair {text!r}; expected 'table.column=table.column'"
            )
        return cls(left[0], left[1], right[0], right[1])

    def key(self) -> tuple[str, str, str, str]:
        return (self.left_table, self.left_column, self.right_table, self.right_column)


def _masked_columns(table_policy: TablePolicy | None) -> set[str]:
    return set(table_policy.columns) if table_policy else set()


def _column_index(table: TableInfo) -> dict[str, int]:
    return {column.name: position for position, column in enumerate(table.columns)}


def _sample_values(
    rows: list[tuple[int, tuple[Any, ...]]], position: int
) -> list[Any]:
    return [
        values[position] if position < len(values) else None
        for _rowid, values in rows
    ]


def _transform_sample(
    table: TableInfo,
    table_policy: TablePolicy | None,
    sample: TableSample,
    context: TransformContext,
) -> tuple[list[tuple[int, tuple[Any, ...]]], dict[str, dict[str, int]]]:
    transform_counts: dict[str, dict[str, int]] = {}
    transformed: list[tuple[int, tuple[Any, ...]]] = []
    context.table = table.name
    for rowid, values in sample.rows:
        new_values: list[Any] = []
        for position, column in enumerate(table.columns):
            value = values[position] if position < len(values) else None
            column_policy = (
                table_policy.columns.get(column.name) if table_policy else None
            )
            if column_policy is None:
                new_values.append(value)
                continue
            context.column = column.name
            slot = transform_counts.setdefault(
                column_policy.transformer,
                {"seen": 0, "processed": 0, "changed": 0},
            )
            slot["seen"] += 1
            if value is not None and value != "":
                slot["processed"] += 1
            result = REGISTRY.get(column_policy.transformer).transform(
                value, column_policy.params, context
            )
            if result != value:
                slot["changed"] += 1
            new_values.append(result)
        transformed.append((rowid, tuple(new_values)))
    return transformed, transform_counts


def _full_stream_coverage(
    stream: StreamCoverage, sample: CoverageAccumulator
) -> dict[str, Any]:
    """Coverage over the full streamed table.

    The streaming pass counts every non-empty value; the changed ratio is taken
    from the before/after sample (which includes deterministic edge rows) and
    applied to the full non-empty count.
    """
    if sample.non_empty == 0:
        changed_rate = 0.0
    else:
        changed_rate = sample.changed / sample.non_empty
    estimated_changed = round(stream.non_empty * changed_rate)
    rate = estimated_changed / stream.non_empty if stream.non_empty else 0.0
    return {
        "total_values": stream.total,
        "non_empty_values": stream.non_empty,
        "empty_values": stream.empty,
        "changed_values_estimated": estimated_changed,
        "changed_values_sampled": sample.changed,
        "coverage_rate": round(rate, 6),
        "estimated": sample.non_empty < stream.non_empty,
    }


def _simulate_table(
    inventory: DatasetInventory,
    table: TableInfo,
    table_policy: TablePolicy | None,
    config: SamplingConfig,
    seed_text: str,
    context: TransformContext,
    kpi_columns: set[str],
    linkage_columns: set[str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, int]]]:
    masked = _masked_columns(table_policy)
    # Linkage/KPI columns must retain sampled values even when unmasked, so that
    # cross-table overlap and unmasked baseline statistics stay available.
    sampled_columns = masked | linkage_columns
    stream_coverage: dict[str, StreamCoverage] = {
        name: StreamCoverage() for name in masked
    }
    numeric_before: dict[str, NumericAccumulator] = {
        name: NumericAccumulator() for name in masked | kpi_columns
    }
    index = _column_index(table)

    def observe(_rowid: int, values: tuple[Any, ...]) -> None:
        for name in masked:
            stream_coverage[name].observe(values[index[name]])
        for name in masked | kpi_columns:
            numeric_before[name].observe(values[index[name]])

    sample = sample_table(
        inventory, table, sampled_columns, config, seed_text, observer=observe
    )
    transformed_rows, transform_counts = _transform_sample(
        table, table_policy, sample, context
    )

    warnings: list[dict[str, str]] = []
    if sample.is_empty:
        warnings.append({"table": table.name, "message": EMPTY_SAMPLE_WARNING})

    numeric_after: dict[str, NumericAccumulator] = {
        name: NumericAccumulator() for name in masked | kpi_columns
    }
    # Numeric KPI statistics are computed over the full streamed dataset, not
    # just the sample: the streaming observer already tallied "before" values
    # for every row, so transformed values must cover the same population.
    context.table = table.name
    index_map = _column_index(table)
    for batch in iter_all_rows(inventory, table, config):
        for _rowid, values in batch:
            for name in masked | kpi_columns:
                column_policy = (
                    table_policy.columns.get(name) if table_policy else None
                )
                value = values[index_map[name]] if index_map[name] < len(values) else None
                if column_policy is not None:
                    context.column = name
                    value = REGISTRY.get(column_policy.transformer).transform(
                        value, column_policy.params, context
                    )
                numeric_after[name].observe(value)

    column_documents: list[dict[str, Any]] = []
    for column in table.columns:
        name = column.name
        if name not in masked and name not in kpi_columns and name not in linkage_columns:
            continue
        column_policy = table_policy.columns.get(name) if table_policy else None
        before_values = _sample_values(sample.rows, index[name])
        after_values = _sample_values(transformed_rows, index[name])
        document: dict[str, Any] = {
            "column_name": name,
            "declared_type": column.declared_type,
            "transformer": column_policy.transformer if column_policy else None,
            "transformer_params": dict(column_policy.params) if column_policy else None,
            "sample_size": len(before_values),
        }
        if name in masked:
            pair_coverage = CoverageAccumulator()
            for before, after in zip(before_values, after_values):
                pair_coverage.observe(before, after)
            document["coverage"] = _full_stream_coverage(
                stream_coverage[name], pair_coverage
            )
            document["distribution_shift"] = distribution_metric(
                before_values, after_values
            )
        elif name in linkage_columns:
            # Unmasked join key: still report distribution drift for completeness.
            document["distribution_shift"] = distribution_metric(
                before_values, after_values
            )
        # KPI drift is meaningful only while the source column stays numeric.
        if (
            name in numeric_before
            and numeric_before[name].is_numeric_column
            and (name in kpi_columns or numeric_after[name].is_numeric_column)
        ):
            document["kpi"] = kpi_metric(numeric_before[name], numeric_after[name])
        column_documents.append(document)

    table_document = {
        "table_name": table.name,
        "row_count": table.row_count,
        "sampled_rows": len(sample.rows),
        "mode": sample.mode,
        "edge_rowids": {
            str(rowid): reasons for rowid, reasons in sample.edge_rowids.items()
        },
        "columns": column_documents,
        "warnings": warnings,
    }
    samples = {
        "before": {name: _sample_values(sample.rows, index[name])
                   for name in sampled_columns},
        "after": {name: _sample_values(transformed_rows, index[name])
                  for name in sampled_columns},
    }
    return table_document, samples, transform_counts


def _validate_linkages(
    specs: list[LinkageSpec], inventory: DatasetInventory
) -> list[LinkageSpec]:
    tables = {table.name: table for table in inventory.tables}
    validated: list[LinkageSpec] = []
    seen: set[tuple[str, str, str, str]] = set()
    for spec in specs:
        for table_name, column_name in (
            (spec.left_table, spec.left_column),
            (spec.right_table, spec.right_column),
        ):
            table = tables.get(table_name)
            if table is None:
                raise SimulationError(
                    f"linkage pair refers to unknown table {table_name!r}"
                )
            if column_name not in {column.name for column in table.columns}:
                raise SimulationError(
                    f"linkage pair refers to unknown column {table_name}.{column_name}"
                )
        if spec.key() in seen:
            raise SimulationError(f"duplicate linkage pair: {spec.key()}")
        seen.add(spec.key())
        validated.append(spec)
    return validated


def _resolve_kpi_columns(
    kpi_columns: set[str], inventory: DatasetInventory
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {table.name: set() for table in inventory.tables}
    for reference in kpi_columns:
        if "." not in reference:
            raise SimulationError(
                f"invalid KPI column {reference!r}; expected 'table.column'"
            )
        table_name, column_name = reference.split(".", 1)
        table = next((item for item in inventory.tables if item.name == table_name), None)
        if table is None:
            raise SimulationError(f"KPI column refers to unknown table {table_name!r}")
        if column_name not in {column.name for column in table.columns}:
            raise SimulationError(
                f"KPI column refers to unknown column {table_name}.{column_name}"
            )
        result[table_name].add(column_name)
    return result


def run_simulation(
    dataset_path: str | Path,
    policy_path: str | Path,
    paths: Paths,
    *,
    sample_size: int = 10_000,
    batch_size: int = 1000,
    file_size_threshold: int = 100 * 1024 * 1024,
    linkage_pairs: list[str] | None = None,
    kpi_columns: list[str] | None = None,
    secrets_store: SecretStore | None = None,
    temp_root: Path | None = None,
    save_result: bool = True,
    detect: bool = True,
) -> SimulationResult:
    """Execute one isolated simulation and return the structured result."""
    from .store import SimulationStore
    from ..detectors.engine import detect_inventory

    started = time.monotonic()
    config = SamplingConfig(
        sample_size=sample_size,
        file_size_threshold=file_size_threshold,
        batch_size=batch_size,
    )
    warnings: list[str] = []
    root = temp_root or default_temp_root(paths)
    sweep_stale_workspaces(paths, root)

    try:
        policy = load_policy(policy_path)
    except Exception as exc:
        raise SimulationError(f"policy validation failed: {exc}") from exc

    try:
        inventory = inspect_dataset(dataset_path)
    except Exception as exc:
        raise SimulationError(f"cannot inspect dataset: {exc}") from exc

    try:
        rule = policy.validate_against(inventory)
    except Exception as exc:
        raise SimulationError(f"policy validation failed: {exc}") from exc

    needs_secret = any(
        detail.transformer in {"hash", "pseudonym"}
        for table_policy in rule.tables.values()
        for detail in table_policy.columns.values()
    )
    if needs_secret and secrets_store is None:
        raise SimulationError(
            "policy uses hash/pseudonym transformers; supply MASKLINE_SECRET_FILE "
            "or a secret store before running the simulation"
        )

    specs = _validate_linkages(
        [LinkageSpec.parse(text) for text in (linkage_pairs or [])], inventory
    )
    kpi_by_table = _resolve_kpi_columns(set(kpi_columns or []), inventory)
    linkage_by_table: dict[str, set[str]] = {
        table.name: set() for table in inventory.tables
    }
    for spec in specs:
        linkage_by_table[spec.left_table].add(spec.left_column)
        linkage_by_table[spec.right_table].add(spec.right_column)

    workspace = SimulationWorkspace.create(paths, root)
    mapping: PseudoMap | None = None
    store = SimulationStore(paths=paths) if save_result else None
    findings: list[dict[str, Any]] = []
    try:
        if detect:
            findings = detect_inventory(inventory, sample_limit=min(sample_size, 1000))
        if needs_secret:
            mapping = PseudoMap(workspace.pseudomap_db, create=True)
        context = TransformContext(
            secrets=secrets_store, pseudomap=mapping, write_mapping=mapping is not None
        )
        seed_text = (
            f"{inventory.fingerprint}|{policy.fingerprint}|{workspace.simulation_id}"
        )

        table_documents: list[dict[str, Any]] = []
        table_samples: dict[str, dict[str, Any]] = {}
        merged_transform_counts: dict[str, dict[str, int]] = {}
        for table in inventory.tables:
            table_policy = rule.tables.get(table.name)
            document, samples, transform_counts = _simulate_table(
                inventory, table, table_policy, config, seed_text,
                context, kpi_by_table.get(table.name, set()),
                linkage_by_table.get(table.name, set()),
            )
            for name, counts in transform_counts.items():
                slot = merged_transform_counts.setdefault(
                    name, {"seen": 0, "processed": 0, "changed": 0}
                )
                for key in ("seen", "processed", "changed"):
                    slot[key] += counts[key]
            table_samples[table.name] = samples
            table_documents.append(document)
            for warning in document["warnings"]:
                warnings.append(f"{warning['table']}: {warning['message']}")

        linkage_documents = _build_linkages(specs, table_samples)
        elapsed = time.monotonic() - started
        document = _build_document(
            workspace, inventory, policy, config, table_documents,
            linkage_documents, findings, warnings, elapsed,
            merged_transform_counts,
        )
        if store is not None:
            store.save(document)
        return SimulationResult(
            simulation_id=workspace.simulation_id,
            status=document["status"],
            document=document,
            warnings=warnings,
            temp_dir=workspace.temp_dir,
            elapsed_seconds=elapsed,
        )
    finally:
        if mapping is not None:
            mapping.close()
        workspace.cleanup()


def _build_linkages(
    specs: list[LinkageSpec], table_samples: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for spec in specs:
        left = table_samples[spec.left_table]
        right = table_samples[spec.right_table]
        documents.append(
            {
                "columns": list(spec.key()),
                **linkage_metric(
                    left["before"].get(spec.left_column, []),
                    right["before"].get(spec.right_column, []),
                    left["after"].get(spec.left_column, []),
                    right["after"].get(spec.right_column, []),
                ),
            }
        )
    return documents


def _summarize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary = []
    for finding in findings:
        if finding.get("confidence") in {"high", "medium"}:
            summary.append(
                {
                    "table_name": finding["table_name"],
                    "column_name": finding["column_name"],
                    "sensitive_type": finding.get("sensitive_type"),
                    "confidence": finding["confidence"],
                }
            )
    return summary


def _build_document(
    workspace: SimulationWorkspace,
    inventory: DatasetInventory,
    policy: Policy,
    config: SamplingConfig,
    tables: list[dict[str, Any]],
    linkages: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    warnings: list[str],
    elapsed: float,
    transform_counts: dict[str, dict[str, int]],
) -> dict[str, Any]:
    streaming_tables = [
        table["table_name"] for table in tables if table["mode"] == "streaming"
    ]
    return {
        "simulation_id": workspace.simulation_id,
        "kind": "policy_impact_simulation",
        "status": "completed_with_warnings" if warnings else "completed",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elapsed_seconds": round(elapsed, 6),
        "dataset": {
            "path": str(inventory.path),
            "fingerprint": inventory.fingerprint,
            "kind": inventory.kind,
            "size_bytes": inventory.size_bytes,
            "row_count": inventory.row_count,
        },
        "policy": {
            "name": policy.name,
            "version": policy.version,
            "fingerprint": policy.fingerprint,
            "source_path": str(policy.source_path),
        },
        "sample": {
            "requested_sample_size": config.sample_size,
            "batch_size": config.batch_size,
            "file_size_threshold": config.file_size_threshold,
            "streaming_tables": streaming_tables,
        },
        "rows_processed": sum(table["row_count"] for table in tables),
        "transform_counts": transform_counts,
        "tables": tables,
        "linkages": linkages,
        "findings_summary": _summarize_findings(findings),
        "warnings": warnings,
        "temp_resources": {
            "temp_dir": str(workspace.temp_dir),
            "cleaned_up": True,
        },
    }
