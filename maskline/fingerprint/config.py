"""Declarative fingerprint configuration for one logical dataset.

The same config is reused across every delivery of the same dataset; only the
per-delivery key material differs. Protected columns (pseudonyms, direct
identifiers and any join keys whose values must stay byte-stable) are listed
explicitly and the embedder refuses to mark them -- watermarking must never
break the global pseudonym mapping.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from ..utils import MasklineError, canonical_json, sha256_text


class FingerprintConfigError(MasklineError):
    pass


@dataclass(frozen=True)
class NumericColumn:
    name: str
    # Quantization quantum q. The marked cell moves at most q, and the carried
    # bit is round(value / q) mod 2. None means auto-derive from the data at
    # embedding time (the resolved value is then frozen into the manifest).
    quantum: float | None = None
    # Fraction of non-null cells selected for marking in this column.
    mark_rate: float = 0.5
    integer: bool = False


@dataclass(frozen=True)
class FingerprintConfig:
    dataset_name: str
    key_column: str
    # Columns whose values must never be altered (pseudonym ids, direct
    # identifiers retained as tokens, join keys).
    protected_columns: tuple[str, ...] = ()
    # Columns usable as fallback row anchors when the primary key column is
    # cropped from a leak. Must be a subset of protected columns. Defaults to
    # the protected columns; the key column is always the primary anchor.
    anchor_columns: tuple[str, ...] | None = None
    numeric_columns: tuple[NumericColumn, ...] = ()
    # Free-text / categorical columns eligible for canary row generation.
    canary_columns: tuple[str, ...] = ()
    canary_count: int = 8
    canary_rate: float = 0.0
    embed_row_order: bool = True
    # Reject a run unless at least this many rows exist (minimal statistical
    # power for the numeric channel).
    min_rows: int = 50

    @property
    def fingerprint(self) -> str:
        return sha256_text(canonical_json(to_config_dict(self)))

    def effective_anchor_columns(self) -> tuple[str, ...]:
        """Anchor candidates in preference order: key column first, then extras."""
        extras = self.anchor_columns
        if extras is None:
            extras = tuple(c for c in self.protected_columns if c != self.key_column)
        ordered = [self.key_column]
        for column in extras:
            if column not in ordered:
                ordered.append(column)
        return tuple(ordered)

    def numeric(self, column: str) -> NumericColumn | None:
        for item in self.numeric_columns:
            if item.name == column:
                return item
        return None

    def validate(self, header: list[str]) -> None:
        names = set(header)
        if self.key_column not in names:
            raise FingerprintConfigError(
                f"key column {self.key_column!r} not found in dataset header {sorted(names)}"
            )
        if self.key_column in self.protected_columns:
            pass  # key column is protected implicitly
        protected = set(self.protected_columns) | {self.key_column}
        seen: set[str] = set()
        for column in self.numeric_columns:
            if column.name not in names:
                raise FingerprintConfigError(
                    f"numeric column {column.name!r} not found in dataset header"
                )
            if column.name in protected:
                raise FingerprintConfigError(
                    f"refusing to watermark protected column {column.name!r}"
                )
            if not 0.0 < column.mark_rate <= 1.0:
                raise FingerprintConfigError(
                    f"mark_rate for {column.name!r} must be in (0, 1]"
                )
            if column.quantum is not None and column.quantum <= 0:
                raise FingerprintConfigError(
                    f"quantum for {column.name!r} must be positive"
                )
            if column.name in seen:
                raise FingerprintConfigError(f"duplicate numeric column {column.name!r}")
            seen.add(column.name)
        for column in self.canary_columns:
            if column not in names:
                raise FingerprintConfigError(
                    f"canary column {column!r} not found in dataset header"
                )
        for column in self.anchor_columns or ():
            if column not in names:
                raise FingerprintConfigError(
                    f"anchor column {column!r} not found in dataset header"
                )
            if column not in protected:
                raise FingerprintConfigError(
                    f"anchor column {column!r} must also be a protected column "
                    "(anchors must stay byte-stable)"
                )
        if not 0 <= self.canary_rate < 1:
            raise FingerprintConfigError("canary_rate must be in [0, 1)")
        if self.canary_count < 0:
            raise FingerprintConfigError("canary_count must be >= 0")


def to_config_dict(config: FingerprintConfig) -> dict[str, Any]:
    data = asdict(config)
    data["protected_columns"] = list(config.protected_columns)
    data["numeric_columns"] = [asdict(item) for item in config.numeric_columns]
    data["canary_columns"] = list(config.canary_columns)
    return data


def _coerce_numeric(raw: dict[str, Any]) -> NumericColumn:
    try:
        name = str(raw["name"])
    except (KeyError, TypeError) as exc:
        raise FingerprintConfigError("each numeric column needs a 'name'") from exc
    quantum = raw.get("quantum")
    if quantum is not None:
        if not isinstance(quantum, (int, float)) or isinstance(quantum, bool):
            raise FingerprintConfigError(f"quantum for {name!r} must be a number")
        quantum = float(quantum)
    mark_rate = float(raw.get("mark_rate", 0.5))
    integer = bool(raw.get("integer", False))
    return NumericColumn(name=name, quantum=quantum, mark_rate=mark_rate, integer=integer)


def load_fingerprint_config(path: str | Path) -> FingerprintConfig:
    source = Path(path)
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise FingerprintConfigError(f"cannot read fingerprint config {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise FingerprintConfigError("fingerprint config must be a YAML mapping")
    try:
        dataset_name = str(raw["dataset_name"])
        key_column = str(raw["key_column"])
    except KeyError as exc:
        raise FingerprintConfigError(f"missing required field: {exc.args[0]}") from exc
    protected = tuple(str(item) for item in raw.get("protected_columns", ()))
    numeric_raw = raw.get("numeric_columns", ())
    if not isinstance(numeric_raw, (list, tuple)):
        raise FingerprintConfigError("numeric_columns must be a list")
    numeric = tuple(_coerce_numeric(dict(item)) for item in numeric_raw)
    canary_columns = tuple(str(item) for item in raw.get("canary_columns", ()))
    anchor_raw = raw.get("anchor_columns")
    anchor_columns = (
        tuple(str(item) for item in anchor_raw) if anchor_raw is not None else None
    )
    return FingerprintConfig(
        dataset_name=dataset_name,
        key_column=key_column,
        protected_columns=protected,
        anchor_columns=anchor_columns,
        numeric_columns=numeric,
        canary_columns=canary_columns,
        canary_count=int(raw.get("canary_count", 8)),
        canary_rate=float(raw.get("canary_rate", 0.0)),
        embed_row_order=bool(raw.get("embed_row_order", True)),
        min_rows=int(raw.get("min_rows", 50)),
    )


def dump_fingerprint_config(config: FingerprintConfig) -> str:
    return yaml.safe_dump(to_config_dict(config), sort_keys=True, allow_unicode=True)
