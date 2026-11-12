"""Embed a per-delivery fingerprint into a masked table.

The embedder is deliberately conservative:

* protected columns (pseudonyms, identifiers, the row key) are never modified --
  global pseudonym consistency cannot be affected by watermarking;
* a numeric cell moves at most one quantum q, and only a configured fraction of
  cells are selected, so column means, ranges and analytic results move within
  a documented, auditable bound;
* canary rows are generated from keyed HMAC streams and mimic the shapes of
  real values (token prefix, numeric range, categorical pool);
* every parameter needed for later verification is returned in a sealed
  manifest; the master key and the original sensitive data are not needed then.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..utils import file_sha256
from .config import FingerprintConfig
from .crypto import (
    DOMAIN_CANARY_KEY,
    DOMAIN_CANARY_PICK,
    DOMAIN_CANARY_VALUE,
    DOMAIN_CELL_BIT,
    DOMAIN_ORDER_BIT,
    anchor_digest,
    cell_fingerprint,
    derive_subkey,
    hmac_bit,
    hmac_token,
    hmac_uniform,
    row_seed,
    stable_key,
)
from .manifest import (
    CanarySpec,
    DeliveryManifest,
    NumericSpec,
    utc_now,
)
from .tableio import Table, canonical_cell, parse_number, read_table, write_table, write_sqlite_table


class EmbedError(RuntimeError):
    pass


@dataclass
class EmbedResult:
    manifest: DeliveryManifest
    output_path: Path
    rows_in: int
    rows_out: int
    canary_rows: int
    skipped_null_keys: int
    channel_summary: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Numeric channel
# --------------------------------------------------------------------------- #

def auto_quantum(values: list[float], integer: bool) -> float:
    """Pick a quantum near 1% of the observed spread, on a tidy grid."""
    observed = [v for v in values if v is not None and math.isfinite(v)]
    if not observed:
        return 1.0 if integer else 0.01
    if integer:
        spread = max(observed) - min(observed)
        if spread <= 10:
            return 1.0
        magnitude = 10 ** math.floor(math.log10(spread / 100.0)) if spread > 100 else 1.0
        magnitude = max(1.0, magnitude)
        return float(magnitude)
    spread = max(observed) - min(observed)
    if spread <= 0:
        return 0.01
    target = spread / 100.0
    exponent = math.floor(math.log10(target))
    base = 10 ** exponent
    factor = min((1.0, 2.0, 5.0, 10.0), key=lambda f: abs(target - f * base))
    return factor * base


def grid_parity(value: float, quantum: float) -> int:
    return int(round(value / quantum)) & 1


def mark_numeric_value(value: float, quantum: float, target_bit: int,
                       integer: bool) -> tuple[float, float]:
    """Move value to the nearest grid multiple whose parity equals target_bit."""
    current = int(round(value / quantum))
    if current & 1 == target_bit:
        # Only move when needed; leaving unselected cells untouched keeps the
        # perturbation budget entirely on cells that carry a bit.
        return value, 0.0
    candidate_up = (current + 1) * quantum
    candidate_down = (current - 1) * quantum
    if abs(candidate_up - value) <= abs(value - candidate_down):
        chosen = candidate_up
    else:
        chosen = candidate_down
    if integer:
        chosen = float(round(chosen))
    delta = abs(chosen - value)
    return chosen, delta


# --------------------------------------------------------------------------- #
# Canary generation
# --------------------------------------------------------------------------- #

def _looks_like_pseudonym_column(config: FingerprintConfig, column: str,
                                 sample: list[Any]) -> bool:
    if column == config.key_column or column in config.protected_columns:
        return True
    return any(isinstance(v, str) and v.startswith("psn_") for v in sample[:50])


def generate_canary_rows(
    config: FingerprintConfig,
    table: Table,
    subkey: bytes,
    count: int,
) -> list[tuple[dict[str, Any], CanarySpec]]:
    if count <= 0:
        return []
    pools: dict[str, list[str]] = {}
    numeric_ranges: dict[str, tuple[float, float, float, bool]] = {}
    for column in table.header:
        values = [row.get(column) for row in table.rows]
        present = [v for v in values if v not in (None, "")]
        if column in {spec.name for spec in config.numeric_columns}:
            parsed = [parse_number(v) for v in present]
            parsed = [v for v in parsed if v is not None]
            if parsed:
                spec = config.numeric(column)
                numeric_ranges[column] = (
                    min(parsed), max(parsed),
                    spec.quantum if spec and spec.quantum else auto_quantum(parsed, bool(spec and spec.integer)),
                    bool(spec and spec.integer),
                )
        else:
            pool = list(dict.fromkeys(canonical_cell(v) for v in present))
            if pool:
                pools[column] = pool

    canaries: list[tuple[dict[str, Any], CanarySpec]] = []
    numeric_column_names = {spec.name for spec in config.numeric_columns}
    for index in range(count):
        row: dict[str, Any] = {}
        fingerprints: dict[str, str] = {}
        numeric_sentinels: dict[str, float] = {}
        # Row key: a token indistinguishable in shape from a real pseudonym.
        key_token = "psn_" + hmac_token(subkey, DOMAIN_CANARY_KEY,
                                        [config.dataset_name, "canary", index], length=20)
        row[config.key_column] = key_token
        fingerprints[config.key_column] = cell_fingerprint(
            subkey, config.key_column, canonical_cell(key_token)
        )
        for column in table.header:
            if column == config.key_column:
                continue
            if column in numeric_ranges:
                low, high, quantum, is_int = numeric_ranges[column]
                # Sentinels live OUTSIDE the observed real range (one to a few
                # grid steps beyond the maximum), so a genuine data row
                # essentially never reproduces one, while the value stays
                # within a plausible order of magnitude and preserves a valid
                # numeric type.
                steps = 1 + hmac_uniform(
                    subkey, DOMAIN_CANARY_VALUE,
                    [config.dataset_name, "canary", index, column], 4,
                )
                jitter = hmac_uniform(
                    subkey, DOMAIN_CANARY_VALUE,
                    [config.dataset_name, "canary", index, column, "jitter"],
                    max(1, int(round(quantum * 100))),
                ) / 100.0
                if is_int:
                    number = float(round(high + steps * quantum + jitter))
                else:
                    number = high + steps * quantum + jitter
                row[column] = int(number) if is_int else round(number, 10)
                if column in numeric_column_names:
                    numeric_sentinels[column] = float(row[column])
            elif _looks_like_pseudonym_column(
                config, column, [r.get(column) for r in table.rows]
            ):
                # Fresh keyed token, shape-identical to a real pseudonym but
                # never colliding with a real anchor value.
                row[column] = "psn_" + hmac_token(
                    subkey, DOMAIN_CANARY_KEY,
                    [config.dataset_name, "canary", index, column], length=20,
                )
            elif column in pools:
                pool = pools[column]
                pick = hmac_uniform(
                    subkey, DOMAIN_CANARY_PICK,
                    [config.dataset_name, "canary", index, column], len(pool),
                )
                row[column] = pool[pick]
            else:
                row[column] = ""
            fingerprints[column] = cell_fingerprint(
                subkey, column, canonical_cell(row[column])
            )
        row_fp = cell_fingerprint(subkey, "__row__",
                                  "|".join(fingerprints[col] for col in table.header))
        canaries.append((row, CanarySpec(
            key_token=key_token,
            cell_fingerprints=fingerprints,
            row_fingerprint=row_fp,
            numeric_sentinels=numeric_sentinels,
        )))
    return canaries


# --------------------------------------------------------------------------- #
# Order channel
# --------------------------------------------------------------------------- #

def apply_order_marks(rows: list[dict[str, Any]], key_column: str, subkey: bytes,
                      dataset_name: str, seeds: dict[str, str]) -> int:
    """Reorder rows so key-sorted adjacent pairs follow HMAC-derived directions.

    Returns the number of encoded pairs. The transformation is a stable sort on
    an HMAC rank per row, which simultaneously hides the original order and
    embeds O(n) order bits; verification recomputes the same ranks from the
    per-row seeds (which remain recoverable through fallback anchor columns).
    """
    def rank(row: dict[str, Any]) -> int:
        key_text = stable_key(row.get(key_column))
        return hmac_uniform(
            subkey, DOMAIN_ORDER_BIT,
            [dataset_name, "rank", seeds[key_text]],
            1 << 53,
        )

    rows.sort(key=rank)
    return max(0, len(rows) - 1)


# --------------------------------------------------------------------------- #
# Top-level embedding
# --------------------------------------------------------------------------- #

def embed_delivery(
    config: FingerprintConfig,
    input_path: str | Path,
    output_path: str | Path,
    delivery_id: str,
    master_key: str,
    *,
    table: str | None = None,
    output_format: str | None = None,
    notes: str = "",
    canary_count_override: int | None = None,
) -> EmbedResult:
    source_table = read_table(input_path, table=table)
    config.validate(source_table.header)
    if source_table.row_count < config.min_rows:
        raise EmbedError(
            f"dataset has {source_table.row_count} rows but fingerprint config "
            f"requires at least {config.min_rows}"
        )

    subkey = derive_subkey(master_key, delivery_id)
    protected = set(config.protected_columns) | {config.key_column}

    # ---- per-row seeds (stable row identity, indirection enables anchors) -- #
    seeds: dict[str, str] = {}
    skipped_null_keys = 0
    for row in source_table.rows:
        key = row.get(config.key_column)
        if key in (None, ""):
            skipped_null_keys += 1
            continue
        key_text = stable_key(key)
        seeds[key_text] = row_seed(subkey, delivery_id, config.dataset_name, key_text)

    # ---- fallback anchor index (unique protected columns only) ------------- #
    anchor_columns = list(config.effective_anchor_columns())
    anchor_index: dict[str, list[dict[str, Any]]] = {}
    usable_anchors = [config.key_column]
    for column in anchor_columns:
        if column == config.key_column:
            continue
        groups: dict[str, str] = {}
        duplicated: set[str] = set()
        for row in source_table.rows:
            value = row.get(column)
            if value in (None, ""):
                continue
            canonical = canonical_cell(value)
            key_text = stable_key(row.get(config.key_column))
            if canonical in duplicated:
                continue
            if canonical in groups:
                # An anchor must be entity-unique; shared values (e.g. a
                # low-cardinality advisor id) make the binomial test ambiguous.
                duplicated.add(canonical)
                groups.pop(canonical, None)
                continue
            groups[canonical] = seeds[key_text]
        entries = [
            {"digest": anchor_digest(subkey, column, canonical), "seed": seed}
            for canonical, seed in groups.items()
        ]
        anchor_index[column] = entries
        usable_anchors.append(column)

    # ---- numeric channel -------------------------------------------------- #
    numeric_specs: list[NumericSpec] = []
    for spec in config.numeric_columns:
        column = spec.name
        raw_values = [parse_number(row.get(column)) for row in source_table.rows]
        quantum = spec.quantum or auto_quantum(
            [v for v in raw_values if v is not None], spec.integer
        )
        marked = 0
        deltas: list[float] = []
        selection_modulus = max(2, round(1.0 / spec.mark_rate))
        for row, parsed in zip(source_table.rows, raw_values):
            key = row.get(config.key_column)
            if key in (None, "") or parsed is None:
                continue
            key_text = stable_key(key)
            seed = seeds[key_text]
            # Deterministic sparse selection: rate 1/modulus of rows.
            if hmac_uniform(subkey, DOMAIN_CELL_BIT,
                            [delivery_id, column, "select", seed],
                            selection_modulus) != 0:
                continue
            target = hmac_bit(subkey, DOMAIN_CELL_BIT,
                              [delivery_id, column, "bit", seed])
            new_value, delta = mark_numeric_value(parsed, quantum, target, spec.integer)
            row[column] = int(new_value) if spec.integer else new_value
            marked += 1
            if delta:
                deltas.append(delta)
        numeric_specs.append(NumericSpec(
            column=column,
            quantum=quantum,
            mark_rate=spec.mark_rate,
            integer=spec.integer,
            marked_cells=marked,
            mean_abs_delta=round(sum(deltas) / len(deltas), 12) if deltas else 0.0,
            max_abs_delta=round(max(deltas), 12) if deltas else 0.0,
        ))

    # ---- canary channel --------------------------------------------------- #
    canary_target = config.canary_count if canary_count_override is None else canary_count_override
    canary_pairs = generate_canary_rows(config, source_table, subkey, canary_target)
    for canary_row, _spec in canary_pairs:
        source_table.rows.append(canary_row)
        canary_key = stable_key(canary_row[config.key_column])
        seeds[canary_key] = row_seed(
            subkey, delivery_id, config.dataset_name, canary_key
        )

    # ---- order channel ---------------------------------------------------- #
    order_pairs = 0
    if config.embed_row_order:
        order_pairs = apply_order_marks(
            source_table.rows, config.key_column, subkey,
            config.dataset_name, seeds,
        )

    # ---- write output ----------------------------------------------------- #
    out = Path(output_path)
    fmt = output_format or out.suffix.lstrip(".").lower()
    if fmt == "sqlite":
        write_sqlite_table(out, source_table, table_name=config.dataset_name)
    else:
        write_table(out, source_table, output_format=fmt)
    delivery_hash = file_sha256(out)

    manifest = DeliveryManifest(
        delivery_id=delivery_id,
        dataset_name=config.dataset_name,
        config_fingerprint=config.fingerprint,
        created_at=utc_now(),
        source_delivery_hash=delivery_hash,
        source_row_count=len(source_table.rows),
        key_column=config.key_column,
        protected_columns=sorted(protected),
        numeric_specs=numeric_specs,
        canary_specs=[spec for _row, spec in canary_pairs],
        order_pairs=order_pairs,
        output_format=fmt,
        notes=notes,
        anchor_columns=usable_anchors,
        anchor_index=anchor_index,
    ).seal()

    expected_marks = sum(spec.marked_cells for spec in numeric_specs)
    return EmbedResult(
        manifest=manifest,
        output_path=out,
        rows_in=source_table.row_count - len(canary_pairs),
        rows_out=len(source_table.rows),
        canary_rows=len(canary_pairs),
        skipped_null_keys=skipped_null_keys,
        channel_summary={
            "numeric_marked_cells": expected_marks,
            "numeric_columns": len(numeric_specs),
            "order_pairs": order_pairs,
            "canary_rows": len(canary_pairs),
        },
    )
