"""High-level evaluation workflow: parse specs, run, report, audit.

The evaluation action is recorded in the same append-only hash-chained audit
log as masking runs. The audit entry contains fingerprints and aggregate
counts only — never row values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..config import Paths
from ..utils import MasklineError
from . import access
from .engine import (
    EvaluationConfig,
    EvaluationInputError,
    Evaluator,
    JoinSpec,
    QISpec,
)
from .report import write_reports


class SpecParseError(MasklineError):
    pass


def parse_qi(expression: str) -> QISpec:
    if ":" not in expression:
        raise SpecParseError(
            f"invalid quasi-identifier {expression!r}; expected TABLE:COL[,COL...]"
        )
    table, raw_columns = expression.split(":", 1)
    table = table.strip()
    columns = tuple(part.strip() for part in raw_columns.split(",") if part.strip())
    if not table or not columns:
        raise SpecParseError(
            f"invalid quasi-identifier {expression!r}; table and columns must be non-empty"
        )
    return QISpec(table=table, columns=columns)


def parse_join(expression: str) -> JoinSpec:
    if "=" not in expression:
        raise SpecParseError(
            f"invalid join {expression!r}; expected PARENT_TABLE.PARENT_COL=CHILD_TABLE.CHILD_COL"
        )
    left, right = expression.split("=", 1)
    parent_parts = [part.strip() for part in left.split(".")]
    child_parts = [part.strip() for part in right.split(".")]
    if len(parent_parts) != 2 or len(child_parts) != 2 or not all(
        parent_parts + child_parts
    ):
        raise SpecParseError(
            f"invalid join {expression!r}; expected PARENT_TABLE.PARENT_COL=CHILD_TABLE.CHILD_COL"
        )
    return JoinSpec(
        parent_table=parent_parts[0],
        parent_column=parent_parts[1],
        child_table=child_parts[0],
        child_column=child_parts[1],
    )


def run_evaluation(
    *,
    paths: Paths,
    source: str | Path,
    product: str | Path,
    qi_expressions: list[str],
    join_expressions: list[str],
    bucket_count: int,
    min_bucket: int,
    top_k: int,
    spill_dir: str | None,
    max_memory_keys: int,
) -> dict[str, Any]:
    source_path = Path(source).expanduser().resolve()
    product_path = Path(product).expanduser().resolve()
    if not source_path.is_file():
        raise EvaluationInputError(f"source dataset not found: {source_path}")
    if not product_path.is_file():
        raise EvaluationInputError(f"product dataset not found: {product_path}")
    if source_path == product_path:
        raise EvaluationInputError("source and product must be different files")
    if bucket_count < 1 or min_bucket < 1 or top_k < 1 or max_memory_keys < 1:
        raise EvaluationInputError("bucket/min-bucket/top-k/max-memory-keys must be positive")

    qi_specs = [parse_qi(expression) for expression in qi_expressions]
    join_specs = [parse_join(expression) for expression in join_expressions]
    config = EvaluationConfig(
        bucket_count=bucket_count,
        min_bucket=min_bucket,
        top_k=top_k,
        spill_dir=Path(spill_dir).expanduser().resolve() if spill_dir else None,
        max_memory_keys=max_memory_keys,
    )
    paths.ensure_runtime_dirs()

    evaluator = Evaluator(source_path, product_path, qi_specs, join_specs, config)
    result = evaluator.run()

    # Redaction guard: sample raw text from both datasets and prove none of it
    # appears in the serialized report before anything is written to disk.
    source_schema = access.schema_of(source_path)
    product_schema = access.schema_of(product_path)
    forbidden = access.collect_text_samples(source_path, source_schema)
    forbidden.extend(access.collect_text_samples(product_path, product_schema))
    report_paths = write_reports(result, paths.reports_dir, forbidden_values=forbidden)

    audit_entry = AuditLog(paths.audit_path).append(_audit_entry(result, report_paths))
    payload = _as_payload(result)
    payload["json"] = report_paths["json"]
    payload["markdown"] = report_paths["markdown"]
    payload["json_hash"] = report_paths["json_hash"]
    payload["audit_seq"] = audit_entry["seq"]
    return payload


def _as_payload(result: Any) -> dict[str, Any]:
    from dataclasses import asdict

    payload = asdict(result)
    payload["source_path"] = str(result.source_path)
    payload["product_path"] = str(result.product_path)
    payload["warnings"] = list(result.warnings)
    return payload


def _audit_entry(result: Any, report_paths: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": "evaluation",
        "evaluation_id": result.evaluation_id,
        "source_path": str(result.source_path),
        "source_hash": result.source_hash,
        "product_path": str(result.product_path),
        "product_hash": result.product_hash,
        "qi_specs": result.config["qi_specs"],
        "join_specs": result.config["join_specs"],
        "table_row_counts": {
            table.table: {
                "source_rows": table.source_rows,
                "product_rows": table.product_rows,
            }
            for table in result.tables
        },
        "zero_utility_columns": [
            f"{table.table}.{column['column']}"
            for table in result.tables
            for column in table.columns
            if column.get("utility_status") == "zero"
        ],
        "spill_bytes": result.spill_bytes,
        "report_json": str(report_paths["json"]),
        "report_markdown": str(report_paths["markdown"]),
        "report_json_hash": report_paths["json_hash"],
    }
