"""Recursive JSON discovery and leaf-level transformation.

The module never aborts a batch because of one bad cell. Every cell falls into
one of these outcomes (see :class:`JsonOutcome`):

* ``ok``            : parsed and processed (possibly without any path hit);
* ``not_json``      : text that does not parse;
* ``too_large``     : raw size over the configured cap;
* ``too_deep``      : nesting depth over the configured cap;
* ``empty``         : NULL / empty string, passed through untouched.

Anything other than ``ok``/``empty`` is a warning. When the column declares a
``fallback`` transformer, the whole raw string is transformed with it; the
untransformed raw value is preserved otherwise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..detectors.base import clean_text_values
from ..transformers import REGISTRY, TransformContext
from ..transformers.base import TransformError, resolve_params
from .limits import JsonLimitError, JsonLimits, safe_loads
from .paths import (
    INDEX,
    KEY,
    WILDCARD,
    JsonPath,
    JsonPathError,
    Segment,
    iter_matches,
    parse_path,
    render_path,
)

# A column enters JSON discovery mode only when at least this fraction of its
# non-empty sampled cells parse to a JSON container (object/array).
JSON_PROBE_RATIO = 0.6
# How many offending rowids per (column, reason) are retained for the report.
WARNING_SAMPLE_CAP = 10

NOT_JSON = "not_json"
TOO_LARGE = "too_large"
TOO_DEEP = "too_deep"

WARNING_REASONS = (NOT_JSON, TOO_LARGE, TOO_DEEP)


@dataclass(frozen=True)
class JsonOutcome:
    status: str
    warning: str | None = None


@dataclass
class JsonColumnState:
    """Per-column accumulator carried through the run and its checkpoints."""

    cells: int = 0
    json_ok: int = 0
    empty: int = 0
    warnings: dict[str, int] = field(default_factory=dict)
    warning_samples: dict[str, list[int]] = field(default_factory=dict)
    # generalized path -> transformer name -> counts
    path_stats: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)

    def record_warning(self, reason: str, rowid: int | None) -> None:
        self.warnings[reason] = self.warnings.get(reason, 0) + 1
        if rowid is not None:
            samples = self.warning_samples.setdefault(reason, [])
            if len(samples) < WARNING_SAMPLE_CAP:
                samples.append(rowid)

    def record_path(
        self, path: str, transformer: str, seen: int, processed: int, changed: int
    ) -> None:
        slot = self.path_stats.setdefault(
            path,
            {transformer: {"seen": 0, "processed": 0, "changed": 0}},
        )
        counts = slot.setdefault(
            transformer, {"seen": 0, "processed": 0, "changed": 0}
        )
        counts["seen"] += seen
        counts["processed"] += processed
        counts["changed"] += changed

    def to_dict(self) -> dict[str, Any]:
        return {
            "cells": self.cells,
            "json_ok": self.json_ok,
            "empty": self.empty,
            "warnings": dict(sorted(self.warnings.items())),
            "warning_samples": {
                key: list(values) for key, values in sorted(self.warning_samples.items())
            },
            "path_stats": {
                path: {
                    transformer: dict(counts)
                    for transformer, counts in sorted(entries.items())
                }
                for path, entries in sorted(self.path_stats.items())
            },
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "JsonColumnState":
        state = cls()
        state.cells = int(payload.get("cells", 0))
        state.json_ok = int(payload.get("json_ok", 0))
        state.empty = int(payload.get("empty", 0))
        state.warnings = dict(payload.get("warnings", {}))
        state.warning_samples = {
            key: list(values) for key, values in payload.get("warning_samples", {}).items()
        }
        state.path_stats = {
            path: {
                transformer: dict(counts)
                for transformer, counts in entries.items()
            }
            for path, entries in payload.get("path_stats", {}).items()
        }
        return state


@dataclass
class JsonRunState:
    """All JSON columns in one run, serialized wholesale into checkpoints."""

    columns: dict[str, JsonColumnState] = field(default_factory=dict)

    def for_column(self, column: str) -> JsonColumnState:
        return self.columns.setdefault(column, JsonColumnState())

    def to_dict(self) -> dict[str, Any]:
        return {
            "columns": {
                name: state.to_dict() for name, state in sorted(self.columns.items())
            }
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any] | None) -> "JsonRunState":
        run = cls()
        if not payload:
            return run
        for name, raw in payload.get("columns", {}).items():
            run.columns[name] = JsonColumnState.from_dict(raw)
        return run


def is_container_document(document: Any) -> bool:
    return isinstance(document, (dict, list))


def probe_json_column(values: list[Any], limits: JsonLimits) -> bool:
    """Decide whether a sampled column behaves like a JSON container column."""
    non_empty = [value for value in clean_text_values(values)]
    if not non_empty:
        return False
    containers = 0
    for value in non_empty:
        try:
            document = safe_loads(str(value), limits)
        except (ValueError, JsonLimitError):
            continue
        if is_container_document(document):
            containers += 1
    return containers / len(non_empty) >= JSON_PROBE_RATIO


def _is_leaf(value: Any) -> bool:
    return not isinstance(value, (dict, list))


def iter_leaves(
    document: Any, prefix: tuple[Segment, ...] = ()
) -> list[tuple[tuple[Segment, ...], Any]]:
    """Enumerate leaf locations in deterministic document order.

    Array indices are kept concrete; the discovery layer generalizes them with
    :func:`generalize_tokens` so every element of one array shares a path.
    """
    if _is_leaf(document):
        return [(prefix, document)]
    found: list[tuple[tuple[Segment, ...], Any]] = []
    if isinstance(document, dict):
        for key, value in document.items():
            found.extend(iter_leaves(value, prefix + (Segment(KEY, key),)))
        return found
    for index, value in enumerate(document):
        found.extend(iter_leaves(value, prefix + (Segment(INDEX, index),)))
    return found


def generalize_tokens(tokens: tuple[Segment, ...]) -> tuple[Segment, ...]:
    """Replace concrete array indices with wildcards for grouped findings."""
    return tuple(
        Segment(WILDCARD) if segment.kind == INDEX else segment for segment in tokens
    )


def generalized_path(tokens: tuple[Segment, ...]) -> str:
    return render_path(generalize_tokens(tokens))


def discover_json_paths(
    values: list[Any],
    limits: JsonLimits,
    sample_limit: int = 200,
    table: str = "",
    column: str = "",
) -> list[dict[str, Any]]:
    """Score every generalized JSON path using the existing scalar detectors."""
    buckets: dict[str, list[Any]] = {}
    scanned = 0
    for value in clean_text_values(values)[:sample_limit]:
        try:
            document = safe_loads(str(value), limits)
        except (ValueError, JsonLimitError):
            continue
        if not is_container_document(document):
            continue
        scanned += 1
        for tokens, leaf in iter_leaves(document):
            if leaf is None:
                continue
            buckets.setdefault(generalized_path(tokens), []).append(leaf)
    findings: list[dict[str, Any]] = []
    # Imported lazily to avoid a package-import cycle (detectors -> json_).
    from ..detectors.engine import analyze_values

    for path in sorted(buckets):
        result = analyze_values(
            buckets[path], sample_limit=len(buckets[path]), table=table, column=column
        )
        if result.sensitive_type is None:
            continue
        record = result.to_record("", table, column)
        record["json_path"] = path
        findings.append(record)
    return findings


@dataclass(frozen=True)
class PathRule:
    """One parsed ``json.paths`` entry from the policy."""

    path: JsonPath
    canonical: str
    transformer: str
    params: dict[str, Any]


def transform_json_cell(
    value: Any,
    path_rules: tuple[PathRule, ...],
    fallback_transformer: str | None,
    fallback_params: dict[str, Any],
    limits: JsonLimits,
    context: TransformContext,
    state: JsonColumnState,
    rowid: int | None,
    table: str,
    column: str,
) -> tuple[Any, JsonOutcome]:
    """Transform one JSON cell, returning the new storage value and an outcome."""
    state.cells += 1
    if value is None or value == "":
        state.empty += 1
        return value, JsonOutcome("empty")

    text = str(value)
    try:
        document = safe_loads(text, limits)
    except JsonLimitError as exc:
        state.record_warning(exc.reason, rowid)
        return _apply_fallback(
            value, fallback_transformer, fallback_params, context, table, column
        ), JsonOutcome("warning", exc.reason)
    except ValueError:
        state.record_warning(NOT_JSON, rowid)
        return _apply_fallback(
            value, fallback_transformer, fallback_params, context, table, column
        ), JsonOutcome("warning", NOT_JSON)

    state.json_ok += 1
    if not path_rules:
        # Parsed JSON but the policy only declares a fallback: keep it intact.
        return value, JsonOutcome("ok")

    changed_any = False
    for rule in path_rules:
        seen = processed = changed = 0
        for tokens, leaf in iter_matches(document, rule.path.segments):
            if not _is_leaf(leaf):
                continue
            seen += 1
            if leaf is not None and leaf != "":
                processed += 1
            context.table = table
            context.column = column
            transformed = REGISTRY.get(rule.transformer).transform(
                leaf, rule.params, context
            )
            if transformed != leaf:
                changed += 1
                changed_any = True
            _assign(document, tokens, transformed)
        if seen:
            state.record_path(rule.canonical, rule.transformer, seen, processed, changed)

    if not changed_any:
        # Re-serializing would only reshuffle whitespace; preserve the raw text.
        return value, JsonOutcome("ok")
    return _dumps(document), JsonOutcome("ok")


def _apply_fallback(
    value: Any,
    transformer: str | None,
    params: dict[str, Any],
    context: TransformContext,
    table: str,
    column: str,
) -> Any:
    if transformer is None:
        return value
    context.table = table
    context.column = column
    return REGISTRY.get(transformer).transform(value, params, context)


def _assign(document: Any, tokens: tuple[Segment, ...], new_value: Any) -> None:
    current = document
    for segment in tokens[:-1]:
        if segment.kind == KEY:
            current = current[segment.value]
        else:  # INDEX (wildcards are always expanded before assignment)
            current = current[segment.value]
    last = tokens[-1]
    if last.kind == KEY:
        current[last.value] = new_value
    else:
        current[last.value] = new_value


def _dumps(document: Any) -> str:
    # Fixed separators and no ASCII escaping make reruns byte-identical;
    # dict insertion order preserves the original key order.
    return json.dumps(document, ensure_ascii=False, separators=(",", ":"))


def build_path_rules(
    raw_paths: Mapping[str, Any], where: str
) -> tuple[PathRule, ...]:
    """Validate and parse the ``json.paths`` mapping at policy load time."""
    rules: list[PathRule] = []
    seen: set[str] = set()
    for raw_path, raw_config in raw_paths.items():
        try:
            parsed = parse_path(raw_path)
        except JsonPathError as exc:
            raise ValueError(f"{where}: {exc}") from exc
        canonical = parsed.render()
        if canonical in seen:
            raise ValueError(
                f"{where}: duplicate JSON path {canonical!r} "
                f"(from {raw_path!r}) after normalization"
            )
        seen.add(canonical)
        if not parsed.segments:
            raise ValueError(
                f"{where}: path '$' targets the whole document; "
                "configure the column-level transformer instead"
            )
        if isinstance(raw_config, str):
            transformer = raw_config
            try:
                params = REGISTRY.validate_params(transformer, {})
            except TransformError as exc:
                raise ValueError(f"{where} path {canonical}: {exc}") from exc
        elif isinstance(raw_config, Mapping):
            unknown = set(raw_config) - {"transformer", "params"}
            if unknown:
                raise ValueError(
                    f"{where} path {canonical}: unknown keys: "
                    + ", ".join(sorted(unknown))
                )
            transformer = raw_config.get("transformer")
            if not isinstance(transformer, str) or not transformer:
                raise ValueError(
                    f"{where} path {canonical}: transformer must be a non-empty string"
                )
            raw_params = raw_config.get("params", {})
            if not isinstance(raw_params, Mapping):
                raise ValueError(f"{where} path {canonical}: params must be a mapping")
            try:
                params = resolve_params(
                    REGISTRY.get(transformer).param_specs, raw_params
                )
            except TransformError as exc:
                raise ValueError(f"{where} path {canonical}: {exc}") from exc
        else:
            raise ValueError(
                f"{where} path {canonical}: expected a transformer name or mapping"
            )
        rules.append(PathRule(parsed, canonical, transformer, params))
    rules.sort(key=lambda rule: rule.canonical)
    return tuple(rules)
