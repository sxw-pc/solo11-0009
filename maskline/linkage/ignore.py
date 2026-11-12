"""User-configured ignore rules for linkage scans (YAML).

Ignore rules let users exclude known non-association fields, whole datasets,
specific column pairs, or whole sensitive types from linkage matching and risk
scoring, which keeps false positives out of the association graph.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from ..utils import MasklineError, canonical_json, sha256_text
from .model import ColRef


class IgnoreRuleError(MasklineError):
    pass


ColumnPattern = tuple[str, str, str]  # (path glob, table glob, column glob)


def _split_column_pattern(pattern: str) -> ColumnPattern:
    if ":" not in pattern:
        raise IgnoreRuleError(
            "column ignore pattern must be '<path-glob>:<table>.<column>': "
            f"{pattern!r}"
        )
    path_glob, _, column_part = pattern.rpartition(":")
    if "." not in column_part:
        raise IgnoreRuleError(
            "column ignore pattern must end with '<table>.<column>': " f"{pattern!r}"
        )
    table_glob, _, column_glob = column_part.rpartition(".")
    if not path_glob or not table_glob or not column_glob:
        raise IgnoreRuleError(f"column ignore pattern has an empty part: {pattern!r}")
    return path_glob, table_glob, column_glob


def _path_variants(path: str | Path) -> set[str]:
    resolved = Path(path)
    return {resolved.name, resolved.as_posix(), str(resolved)}


def _path_glob_matches(pattern: str, path: str | Path) -> bool:
    return any(
        fnmatch.fnmatchcase(candidate, pattern)
        or fnmatch.fnmatchcase(candidate, f"*{pattern}")
        for candidate in _path_variants(path)
    )


def _column_pattern_matches(pattern: ColumnPattern, path: str | Path, table: str, column: str) -> bool:
    path_glob, table_glob, column_glob = pattern
    return (
        _path_glob_matches(path_glob, path)
        and fnmatch.fnmatchcase(table, table_glob)
        and fnmatch.fnmatchcase(column, column_glob)
    )


@dataclass(frozen=True)
class IgnoreRules:
    dataset_patterns: tuple[str, ...] = ()
    column_patterns: tuple[ColumnPattern, ...] = ()
    pair_patterns: tuple[tuple[ColumnPattern, ColumnPattern], ...] = ()
    sensitive_types: frozenset[str] = frozenset()
    fingerprint: str = ""

    def dataset_ignored(self, path: str | Path) -> bool:
        return any(_path_glob_matches(pattern, path) for pattern in self.dataset_patterns)

    def column_ignored(self, path: str | Path, table: str, column: str) -> bool:
        return any(
            _column_pattern_matches(pattern, path, table, column)
            for pattern in self.column_patterns
        )

    def pair_ignored(self, ref_a: ColRef, ref_b: ColRef) -> bool:
        for pattern_a, pattern_b in self.pair_patterns:
            forward = _column_pattern_matches(
                pattern_a, ref_a.dataset_path, ref_a.table, ref_a.column
            ) and _column_pattern_matches(
                pattern_b, ref_b.dataset_path, ref_b.table, ref_b.column
            )
            backward = _column_pattern_matches(
                pattern_a, ref_b.dataset_path, ref_b.table, ref_b.column
            ) and _column_pattern_matches(
                pattern_b, ref_a.dataset_path, ref_a.table, ref_a.column
            )
            if forward or backward:
                return True
        return False

    def type_ignored(self, sensitive_type: str) -> bool:
        return sensitive_type in self.sensitive_types


EMPTY_RULES = IgnoreRules()


def _expect_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IgnoreRuleError(f"{where} must be a mapping")
    return value


def _string_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise IgnoreRuleError(f"{where} must be a list of non-empty strings")
    return list(value)


def load_ignore_rules(path: str | Path) -> IgnoreRules:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise IgnoreRuleError(f"ignore rules file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise IgnoreRuleError(f"cannot load ignore rules {source}: {exc}") from exc
    root = _expect_mapping(data, "ignore rules root")
    unknown = set(root) - {"version", "ignore"}
    if unknown:
        raise IgnoreRuleError(
            "ignore rules root has unknown keys: " + ", ".join(sorted(unknown))
        )
    version = root.get("version")
    if version != 1 or isinstance(version, bool):
        raise IgnoreRuleError("ignore rules version must be the integer 1")
    ignore = _expect_mapping(root.get("ignore"), "ignore")
    unknown = set(ignore) - {"datasets", "columns", "pairs", "sensitive_types"}
    if unknown:
        raise IgnoreRuleError("ignore has unknown keys: " + ", ".join(sorted(unknown)))
    datasets = _string_list(ignore.get("datasets"), "ignore.datasets")
    columns = _string_list(ignore.get("columns"), "ignore.columns")
    types = _string_list(ignore.get("sensitive_types"), "ignore.sensitive_types")
    raw_pairs = ignore.get("pairs", [])
    if not isinstance(raw_pairs, list):
        raise IgnoreRuleError("ignore.pairs must be a list of column pattern pairs")
    pairs: list[tuple[str, str]] = []
    for index, item in enumerate(raw_pairs):
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or any(not isinstance(part, str) or not part for part in item)
        ):
            raise IgnoreRuleError(
                f"ignore.pairs[{index}] must be a pair of column pattern strings"
            )
        pairs.append((item[0], item[1]))
    parsed_columns = tuple(_split_column_pattern(pattern) for pattern in columns)
    parsed_pairs = tuple(
        (_split_column_pattern(pattern_a), _split_column_pattern(pattern_b))
        for pattern_a, pattern_b in pairs
    )
    normalized = {
        "version": 1,
        "ignore": {
            "datasets": datasets,
            "columns": columns,
            "pairs": [list(pair) for pair in pairs],
            "sensitive_types": sorted(types),
        },
    }
    return IgnoreRules(
        dataset_patterns=tuple(datasets),
        column_patterns=parsed_columns,
        pair_patterns=parsed_pairs,
        sensitive_types=frozenset(types),
        fingerprint=sha256_text(canonical_json(normalized)),
    )
