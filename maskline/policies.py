"""Load, validate, match, and fingerprint declarative YAML masking policies."""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .registry import DatasetInventory
from .transformers import REGISTRY, TransformError
from .utils import MasklineError, canonical_json


class PolicyError(MasklineError):
    pass


@dataclass(frozen=True)
class ColumnPolicy:
    transformer: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"transformer": self.transformer, "params": dict(self.params)}


@dataclass(frozen=True)
class TablePolicy:
    name: str
    columns: dict[str, ColumnPolicy]

    def to_dict(self) -> dict[str, Any]:
        return {
            "columns": {name: policy.to_dict() for name, policy in self.columns.items()}
        }


@dataclass(frozen=True)
class DatasetRule:
    path_pattern: str
    tables: dict[str, TablePolicy]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path_pattern,
            "tables": {name: table.to_dict() for name, table in self.tables.items()},
        }


@dataclass(frozen=True)
class Policy:
    name: str
    version: int
    datasets: tuple[DatasetRule, ...]
    fingerprint: str
    source_path: Path
    description: str = ""

    def matching_rule(self, dataset_path: Path) -> DatasetRule | None:
        resolved = dataset_path.expanduser().resolve()
        matches = [rule for rule in self.datasets if _path_matches(rule.path_pattern, resolved)]
        if len(matches) > 1:
            raise PolicyError(
                f"multiple dataset rules match {resolved}; make path patterns unambiguous"
            )
        return matches[0] if matches else None

    def for_dataset(self, dataset_path: Path) -> DatasetRule:
        rule = self.matching_rule(dataset_path)
        if rule is None:
            raise PolicyError(
                f"no dataset rule in policy {self.source_path.name!r} matches "
                f"dataset {dataset_path}"
            )
        return rule

    def validate_against(self, inventory: DatasetInventory) -> DatasetRule:
        rule = self.for_dataset(inventory.path)
        for table_name, table_policy in rule.tables.items():
            table = inventory.table(table_name)
            if table is None:
                raise PolicyError(
                    f"policy refers to unknown table {table_name!r} "
                    f"in {inventory.path.name}"
                )
            known_columns = {column.name for column in table.columns}
            for column_name in table_policy.columns:
                if column_name not in known_columns:
                    raise PolicyError(
                        f"policy refers to unknown column {table_name}.{column_name} "
                        f"in {inventory.path.name}"
                    )
        return rule

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "fingerprint": self.fingerprint,
            "datasets": [rule.to_dict() for rule in self.datasets],
        }


def _path_matches(pattern: str, path: Path) -> bool:
    if not pattern or not pattern.strip():
        return False
    normalized = pattern.replace("\\", "/")
    variants = {
        path.name,
        path.as_posix(),
        str(path),
    }
    return any(
        fnmatch.fnmatchcase(candidate, normalized)
        or fnmatch.fnmatchcase(candidate.replace("\\", "/"), normalized)
        or fnmatch.fnmatchcase(candidate, f"*{normalized}")
        for candidate in variants
    )


def _expect_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{where} must be a mapping")
    return value


def _parse_column(name: str | int, raw: Any, where: str) -> tuple[str, ColumnPolicy]:
    if not isinstance(name, str) or not name:
        raise PolicyError(f"{where}: column names must be non-empty strings")
    if isinstance(raw, str):
        transformer, params = raw, {}
    else:
        config = _expect_mapping(raw, where)
        unknown = set(config) - {"transformer", "params"}
        if unknown:
            raise PolicyError(f"{where}: unknown keys: {', '.join(sorted(unknown))}")
        if "transformer" not in config:
            raise PolicyError(f"{where}: missing required key 'transformer'")
        transformer = config["transformer"]
        params = config.get("params", {})
        if not isinstance(transformer, str) or not transformer:
            raise PolicyError(f"{where}: transformer must be a non-empty string")
        params = _expect_mapping(params, f"{where}.params")
    try:
        resolved = REGISTRY.validate_params(transformer, params)
    except TransformError as exc:
        raise PolicyError(f"{where}: {exc}") from exc
    return name, ColumnPolicy(transformer, resolved)


def _parse_policy(data: Any, source_path: Path) -> Policy:
    root = _expect_mapping(data, "policy root")
    unknown = set(root) - {"version", "name", "description", "datasets"}
    if unknown:
        raise PolicyError(f"policy root has unknown keys: {', '.join(sorted(unknown))}")
    version = root.get("version")
    if version != 1 or isinstance(version, bool):
        raise PolicyError("policy version must be the integer 1")
    name = root.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PolicyError("policy name must be a non-empty string")
    description = root.get("description", "")
    if not isinstance(description, str):
        raise PolicyError("policy description must be a string")
    raw_datasets = root.get("datasets")
    if not isinstance(raw_datasets, list) or not raw_datasets:
        raise PolicyError("policy datasets must be a non-empty list")
    patterns: set[str] = set()
    datasets: list[DatasetRule] = []
    for index, raw_rule in enumerate(raw_datasets):
        rule = _expect_mapping(raw_rule, f"datasets[{index}]")
        allowed = set(rule) - {"path", "tables"}
        if allowed:
            raise PolicyError(
                f"datasets[{index}] has unknown keys: {', '.join(sorted(allowed))}"
            )
        pattern = rule.get("path")
        if not isinstance(pattern, str) or not pattern.strip():
            raise PolicyError(f"datasets[{index}].path must be a non-empty string")
        if pattern in patterns:
            raise PolicyError(f"duplicate dataset path rule: {pattern}")
        patterns.add(pattern)
        raw_tables = _expect_mapping(rule.get("tables"), f"datasets[{index}].tables")
        tables: dict[str, TablePolicy] = {}
        for table_name, raw_table in raw_tables.items():
            if not isinstance(table_name, str) or not table_name:
                raise PolicyError(f"datasets[{index}].tables has an invalid table name")
            table_map = _expect_mapping(
                raw_table, f"datasets[{index}].tables.{table_name}"
            )
            if set(table_map) != {"columns"}:
                raise PolicyError(
                    f"datasets[{index}].tables.{table_name} must contain only 'columns'"
                )
            raw_columns = _expect_mapping(
                table_map["columns"],
                f"datasets[{index}].tables.{table_name}.columns",
            )
            if not raw_columns:
                raise PolicyError(f"table {table_name!r} has no column policies")
            columns: dict[str, ColumnPolicy] = {}
            for column_name, raw_column in raw_columns.items():
                key, column_policy = _parse_column(
                    column_name,
                    raw_column,
                    f"dataset {pattern!r} table {table_name!r} column {column_name!r}",
                )
                columns[key] = column_policy
            tables[table_name] = TablePolicy(table_name, columns)
        datasets.append(DatasetRule(pattern, tables))
    normalized = {
        "version": version,
        "name": name,
        "description": description,
        "datasets": [rule.to_dict() for rule in datasets],
    }
    fingerprint = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return Policy(
        name=name,
        version=version,
        datasets=tuple(datasets),
        fingerprint=fingerprint,
        source_path=source_path,
        description=description,
    )


def load_policy(path: str | Path) -> Policy:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise PolicyError(f"policy file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"cannot load policy {source}: {exc}") from exc
    return _parse_policy(data, source)
