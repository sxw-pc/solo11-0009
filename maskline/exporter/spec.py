"""Declarative export specs: load, validate, and fingerprint subset selections.

An export spec selects a subset of an existing masked product along three
dimensions: row filters (``where``), column pruning (``columns`` /
``exclude_columns``), and sampling ratio (``sample``). The spec fingerprint
covers the selection rules only -- source and output paths identify one
execution, not the reusable rule set.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from ..utils import MasklineError, canonical_json
from .errors import ExportError
from .filtering import FilterSyntaxError, compile_filter

FORMATS = ("sqlite", "csv")


@dataclass(frozen=True)
class TableSelection:
    table: str
    columns: tuple[str, ...] | None = None          # keep-list; None = keep all
    exclude_columns: tuple[str, ...] | None = None  # drop-list
    where: str | None = None
    sample: float | None = None                     # ratio in (0, 1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "columns": list(self.columns) if self.columns is not None else None,
            "exclude_columns": (
                list(self.exclude_columns) if self.exclude_columns is not None else None
            ),
            "where": self.where,
            "sample": self.sample,
        }


@dataclass(frozen=True)
class ExportSpec:
    name: str
    source: Path
    output: Path | None
    format: str
    sample_seed: str | int | None
    tables: tuple[TableSelection, ...] | None  # None = every table, unfiltered
    fingerprint: str
    source_path: Path | None = field(default=None, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Normalized selection rules used for the fingerprint."""
        return {
            "version": 1,
            "name": self.name,
            "format": self.format,
            "sample_seed": self.sample_seed,
            "tables": (
                {selection.table: selection.to_dict() for selection in self.tables}
                if self.tables is not None
                else None
            ),
        }


def _expect_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExportError("EXPORT_SPEC_INVALID", f"{where} must be a mapping")
    return value


def _column_list(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ExportError("EXPORT_SPEC_INVALID", f"{where} must be a non-empty list")
    columns: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ExportError(
                "EXPORT_SPEC_INVALID", f"{where} entries must be non-empty strings"
            )
        columns.append(item)
    if len(set(columns)) != len(columns):
        raise ExportError("EXPORT_SPEC_INVALID", f"{where} contains duplicates")
    return tuple(columns)


def _parse_table(table: str, raw: Any) -> TableSelection:
    where = f"tables.{table}"
    config = _expect_mapping(raw, where)
    unknown = set(config) - {"columns", "exclude_columns", "where", "sample"}
    if unknown:
        raise ExportError(
            "EXPORT_SPEC_INVALID", f"{where} has unknown keys: {', '.join(sorted(unknown))}"
        )
    columns = config.get("columns")
    exclude = config.get("exclude_columns")
    if columns is not None and exclude is not None:
        raise ExportError(
            "EXPORT_SPEC_INVALID",
            f"{where}: 'columns' and 'exclude_columns' are mutually exclusive",
        )
    keep = _column_list(columns, f"{where}.columns") if columns is not None else None
    drop = (
        _column_list(exclude, f"{where}.exclude_columns") if exclude is not None else None
    )
    condition = config.get("where")
    if condition is not None:
        if not isinstance(condition, str) or not condition.strip():
            raise ExportError(
                "EXPORT_SPEC_INVALID", f"{where}.where must be a non-empty string"
            )
        try:
            compile_filter(condition)
        except FilterSyntaxError as exc:
            raise ExportError(
                "EXPORT_FILTER_INVALID", f"{where}.where: {exc}"
            ) from exc
    sample = config.get("sample")
    if sample is not None:
        if isinstance(sample, bool) or not isinstance(sample, (int, float)):
            raise ExportError(
                "EXPORT_SPEC_INVALID", f"{where}.sample must be a number in (0, 1]"
            )
        if not 0 < float(sample) <= 1:
            raise ExportError(
                "EXPORT_SPEC_INVALID", f"{where}.sample must be in (0, 1]"
            )
        sample = float(sample)
    return TableSelection(table, keep, drop, condition, sample)


def _parse_spec(data: Any, source_path: Path | None) -> ExportSpec:
    root = _expect_mapping(data, "export spec root")
    unknown = set(root) - {"version", "name", "source", "output", "format", "sample_seed", "tables"}
    if unknown:
        raise ExportError(
            "EXPORT_SPEC_INVALID",
            f"export spec has unknown keys: {', '.join(sorted(unknown))}",
        )
    if root.get("version") != 1 or isinstance(root.get("version"), bool):
        raise ExportError("EXPORT_SPEC_INVALID", "export spec version must be the integer 1")
    name = root.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ExportError("EXPORT_SPEC_INVALID", "export spec name must be a non-empty string")
    source = root.get("source")
    if not isinstance(source, str) or not source.strip():
        raise ExportError("EXPORT_SPEC_INVALID", "export spec source must be a non-empty string")
    output = root.get("output")
    if output is not None and (not isinstance(output, str) or not output.strip()):
        raise ExportError("EXPORT_SPEC_INVALID", "export spec output must be a non-empty string")
    fmt = root.get("format", "sqlite")
    if fmt not in FORMATS:
        raise ExportError(
            "EXPORT_SPEC_INVALID",
            f"export spec format must be one of: {', '.join(FORMATS)}",
        )
    seed = root.get("sample_seed")
    if seed is not None:
        if isinstance(seed, bool) or not isinstance(seed, (int, str)):
            raise ExportError(
                "EXPORT_SPEC_INVALID", "export spec sample_seed must be a string or integer"
            )
        if isinstance(seed, str) and not seed.strip():
            raise ExportError(
                "EXPORT_SPEC_INVALID", "export spec sample_seed must not be empty"
            )
    raw_tables = root.get("tables")
    tables: tuple[TableSelection, ...] | None = None
    if raw_tables is not None:
        table_map = _expect_mapping(raw_tables, "tables")
        if not table_map:
            raise ExportError("EXPORT_SPEC_INVALID", "tables must not be empty")
        selections: list[TableSelection] = []
        for table_name, raw_table in table_map.items():
            if not isinstance(table_name, str) or not table_name:
                raise ExportError("EXPORT_SPEC_INVALID", "table names must be non-empty strings")
            selections.append(_parse_table(table_name, raw_table))
        tables = tuple(selections)
    normalized = {
        "version": 1,
        "name": name,
        "format": fmt,
        "sample_seed": seed,
        "tables": (
            {selection.table: selection.to_dict() for selection in tables}
            if tables is not None
            else None
        ),
    }
    fingerprint = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return ExportSpec(
        name=name,
        source=Path(source).expanduser(),
        output=Path(output).expanduser() if output else None,
        format=fmt,
        sample_seed=seed,
        tables=tables,
        fingerprint=fingerprint,
        source_path=source_path,
    )


def load_export_spec(path: str | Path) -> ExportSpec:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise ExportError("EXPORT_SPEC_INVALID", f"export spec file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ExportError("EXPORT_SPEC_INVALID", f"cannot load export spec {source}: {exc}") from exc
    return _parse_spec(data, source)


def spec_from_options(
    *,
    source: str,
    name: str | None = None,
    tables: list[str] | None = None,
    where: str | None = None,
    columns: str | None = None,
    exclude_columns: str | None = None,
    sample: float | None = None,
    sample_seed: str | None = None,
    fmt: str | None = None,
    output: str | None = None,
) -> ExportSpec:
    """Build a spec from CLI flags; per-table flags require exactly one table."""
    per_table = any(
        item is not None for item in (where, columns, exclude_columns, sample)
    )
    if per_table and (not tables or len(tables) != 1):
        raise ExportError(
            "EXPORT_SPEC_INVALID",
            "--where/--columns/--exclude-columns/--sample require exactly one --table",
        )
    data: dict[str, Any] = {
        "version": 1,
        "name": name or f"export-{Path(source).stem}",
        "source": source,
    }
    if output:
        data["output"] = output
    if fmt:
        data["format"] = fmt
    if sample_seed is not None:
        data["sample_seed"] = sample_seed
    if tables:
        table_config: dict[str, Any] = {}
        if columns:
            table_config["columns"] = [item.strip() for item in columns.split(",")]
        if exclude_columns:
            table_config["exclude_columns"] = [
                item.strip() for item in exclude_columns.split(",")
            ]
        if where:
            table_config["where"] = where
        if sample is not None:
            table_config["sample"] = sample
        data["tables"] = {tables[0]: table_config} if table_config else {
            table: {} for table in tables
        }
    return _parse_spec(data, None)
