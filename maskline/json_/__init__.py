"""JSON-column support: recursive discovery, path policies, leaf masking."""

from __future__ import annotations

from .engine import (
    NOT_JSON,
    TOO_DEEP,
    TOO_LARGE,
    WARNING_REASONS,
    JsonColumnState,
    JsonOutcome,
    JsonRunState,
    PathRule,
    build_path_rules,
    discover_json_paths,
    generalized_path,
    iter_leaves,
    probe_json_column,
    transform_json_cell,
)
from .limits import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    HARD_MAX_BYTES,
    HARD_MAX_DEPTH,
    JsonLimitError,
    JsonLimits,
    raw_depth,
    safe_loads,
)
from .paths import JsonPath, JsonPathError, canonical_path, parse_path, render_path

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_DEPTH",
    "HARD_MAX_BYTES",
    "HARD_MAX_DEPTH",
    "NOT_JSON",
    "TOO_DEEP",
    "TOO_LARGE",
    "WARNING_REASONS",
    "JsonColumnState",
    "JsonLimitError",
    "JsonLimits",
    "JsonOutcome",
    "JsonPath",
    "JsonPathError",
    "JsonRunState",
    "PathRule",
    "build_path_rules",
    "canonical_path",
    "discover_json_paths",
    "generalized_path",
    "iter_leaves",
    "parse_path",
    "probe_json_column",
    "raw_depth",
    "render_path",
    "safe_loads",
    "transform_json_cell",
]
