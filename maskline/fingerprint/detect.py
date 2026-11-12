"""Offline attribution of a suspect file against archived delivery manifests.

The verifier never opens the original sensitive dataset or the pseudonym
mapping store. Given a suspect table, the local master key and a set of sealed
delivery manifests, it re-derives each delivery's sub-key and re-evaluates the
three channels independently:

* numeric: exact one-sided binomial test on surviving marked cells;
* canary: reproduction of keyed cell fingerprints (rows and columns cropped
  simply reduce the number of comparisons);
* order:   adjacent-rank concordance, which collapses harmlessly to chance if
  the rows were shuffled or re-exported in another order.

Every delivery is scored independently, so a file assembled from several
deliveries produces several significant matches with estimated mixture
fractions instead of a single forced answer. Clean, never-delivered data fails
all three gates and is explicitly reported as no_match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .crypto import (
    DOMAIN_CELL_BIT,
    DOMAIN_ORDER_BIT,
    anchor_digest,
    cell_fingerprint,
    derive_subkey,
    hmac_bit,
    hmac_uniform,
    row_seed,
    stable_key,
)
from .manifest import DeliveryManifest
from .stats import (
    BAND_NO_MATCH,
    MIN_NUMERIC_TRIALS,
    ConfidenceVerdict,
    band_from_p,
    binomial_tail,
    canary_p_value,
    fisher_combine,
    order_p_value,
    wilson_interval,
)
from .tableio import Table, canonical_cell, parse_number, read_table


class AttributionError(RuntimeError):
    pass


# Family-wise gating: with K archived deliveries a clean file must not produce
# even a "possible" match. Per-delivery numeric evidence must clear 0.01/K
# (Bonferroni), keeping the family-wise false-positive rate below 1%; the
# stronger bands use thresholds orders of magnitude below that in practice.
GATE_POSSIBLE_P = 1e-2
# Order evidence can only corroborate; it never triggers a verdict alone.
ORDER_CORROBORATION_P = 1e-2
MIN_ORDER_PAIRS = 20


@dataclass
class NumericChannelResult:
    trials: int = 0
    matches: int = 0
    mismatches: int = 0
    per_column: dict[str, dict[str, int]] = field(default_factory=dict)
    p_value: float = 1.0
    fraction_estimate: float = 0.0
    fraction_ci: tuple[float, float] = (0.0, 0.0)

    @property
    def match_rate(self) -> float:
        return self.matches / self.trials if self.trials else 0.0


@dataclass
class CanaryChannelResult:
    surviving_canaries: int = 0
    row_hits: int = 0
    cell_comparisons: int = 0
    cell_hits: int = 0
    matched_columns: list[str] = field(default_factory=list)
    p_value: float = 1.0


@dataclass
class OrderChannelResult:
    pairs: int = 0
    agreements: int = 0
    p_value: float = 1.0
    usable: bool = False


@dataclass
class ChannelResult:
    numeric: NumericChannelResult
    canary: CanaryChannelResult
    order: OrderChannelResult


@dataclass
class MatchResult:
    delivery_id: str
    verdict: ConfidenceVerdict
    channels: ChannelResult
    combined_p_value: float
    mixture_fraction: float
    mixture_ci: tuple[float, float]
    unresolved_rows: int = 0
    is_primary: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "band": self.verdict.band,
            "confidence_score": self.verdict.score,
            "p_value": self.combined_p_value,
            "rationale": self.verdict.rationale,
            "is_primary_component": self.is_primary,
            "estimated_mixture_fraction": self.mixture_fraction,
            "mixture_fraction_ci": list(self.mixture_ci),
            "unresolved_rows": self.unresolved_rows,
            "numeric": {
                "trials": self.channels.numeric.trials,
                "matches": self.channels.numeric.matches,
                "mismatches": self.channels.numeric.mismatches,
                "match_rate": round(self.channels.numeric.match_rate, 4),
                "p_value": self.channels.numeric.p_value,
                "per_column": self.channels.numeric.per_column,
            },
            "canary": {
                "surviving_canaries": self.channels.canary.surviving_canaries,
                "row_hits": self.channels.canary.row_hits,
                "cell_comparisons": self.channels.canary.cell_comparisons,
                "cell_hits": self.channels.canary.cell_hits,
                "matched_columns": self.channels.canary.matched_columns,
                "p_value": self.channels.canary.p_value,
            },
            "order": {
                "pairs": self.channels.order.pairs,
                "agreements": self.channels.order.agreements,
                "usable": self.channels.order.usable,
                "p_value": self.channels.order.p_value,
            },
        }


@dataclass
class AttributionReport:
    suspect_path: str
    suspect_rows: int
    header: list[str]
    manifest_count: int
    matches: list[MatchResult]
    primary_delivery_id: str | None
    overall_verdict: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "suspect_path": self.suspect_path,
            "suspect_rows": self.suspect_rows,
            "header": self.header,
            "manifests_checked": self.manifest_count,
            "overall_verdict": self.overall_verdict,
            "primary_delivery_id": self.primary_delivery_id,
            "rationale": self.rationale,
            "deliveries": [match.to_dict() for match in self.matches],
        }


# --------------------------------------------------------------------------- #
# Seed resolution: primary key column, then archived fallback anchors
# --------------------------------------------------------------------------- #

class SeedResolver:
    """Maps each suspect row to its delivery row seed.

    Preferred path: recompute the seed from the primary key column when it
    survives. Fallback: look the row up in the archived anchor index built on
    another protected (byte-stable) column. Rows that cannot be resolved are
    skipped -- they simply do not contribute evidence, never false evidence.
    """

    def __init__(self, table: Table, manifest: DeliveryManifest, subkey: bytes):
        self.table = table
        self.manifest = manifest
        self.subkey = subkey
        self.key_present = manifest.key_column in table.header
        self.anchor_maps: dict[str, dict[str, str]] = {}
        self.used_anchor: str | None = None
        if not self.key_present:
            for column in manifest.anchor_columns:
                if column == manifest.key_column or column not in table.header:
                    continue
                entries = manifest.anchor_index.get(column)
                if not entries:
                    continue
                self.anchor_maps[column] = {
                    entry["digest"]: entry["seed"] for entry in entries
                }
            # Prefer the anchor with the highest coverage on the suspect data.
            best_column, best_count = None, -1
            for column, mapping in self.anchor_maps.items():
                count = sum(
                    1 for row in table.rows
                    if anchor_digest(subkey, column,
                                     canonical_cell(row.get(column))) in mapping
                )
                if count > best_count:
                    best_column, best_count = column, count
            self.used_anchor = best_column
        # Resolve every row exactly once up front, so the unresolved count is a
        # property of the table/manifest pair, not of how many channels ran.
        self._seeds: list[str | None] = [self._resolve(row) for row in table.rows]
        self.unresolved = sum(1 for seed in self._seeds if seed is None)

    def _resolve(self, row: dict[str, Any]) -> str | None:
        if self.key_present:
            key = row.get(self.manifest.key_column)
            if key in (None, ""):
                return None
            key_text = stable_key(key)
            return row_seed(
                self.subkey, self.manifest.delivery_id,
                self.manifest.dataset_name, key_text,
            )
        if self.used_anchor is None:
            return None
        value = row.get(self.used_anchor)
        if value in (None, ""):
            return None
        digest = anchor_digest(self.subkey, self.used_anchor, canonical_cell(value))
        return self.anchor_maps[self.used_anchor].get(digest)

    @property
    def mode(self) -> str:
        if self.key_present:
            return "key"
        return f"anchor:{self.used_anchor}" if self.used_anchor else "none"

    def seed_at(self, index: int) -> str | None:
        """Seed for the row at ``index`` in the suspect table (any channel)."""
        return self._seeds[index]

    def seed_for(self, row: dict[str, Any]) -> str | None:
        # Linear fallback for callers that iterate rows directly; prefer
        # seed_at(index) inside the channel evaluators.
        return self._resolve(row)


# --------------------------------------------------------------------------- #
# Channel evaluation
# --------------------------------------------------------------------------- #

def _evaluate_numeric(table: Table, manifest: DeliveryManifest,
                      subkey: bytes, resolver: SeedResolver) -> NumericChannelResult:
    result = NumericChannelResult()
    header_set = set(table.header)
    for spec in manifest.numeric_specs:
        if spec.column not in header_set:
            continue
        selection_modulus = max(2, round(1.0 / spec.mark_rate))
        col_trials = col_matches = col_mismatches = 0
        for index, row in enumerate(table.rows):
            seed = resolver.seed_at(index)
            if seed is None:
                continue
            parsed = parse_number(row.get(spec.column))
            if parsed is None:
                continue
            if hmac_uniform(subkey, DOMAIN_CELL_BIT,
                            [manifest.delivery_id, spec.column, "select", seed],
                            selection_modulus) != 0:
                continue
            target = hmac_bit(subkey, DOMAIN_CELL_BIT,
                              [manifest.delivery_id, spec.column, "bit", seed])
            observed = int(round(parsed / spec.quantum)) & 1
            col_trials += 1
            if observed == target:
                col_matches += 1
            else:
                col_mismatches += 1
        result.per_column[spec.column] = {
            "trials": col_trials,
            "matches": col_matches,
            "mismatches": col_mismatches,
        }
        result.trials += col_trials
        result.matches += col_matches
        result.mismatches += col_mismatches
    result.p_value = binomial_tail(result.matches, result.trials)
    result.fraction_estimate = result.match_rate
    result.fraction_ci = wilson_interval(result.matches, result.trials)
    return result


def _evaluate_canary(table: Table, manifest: DeliveryManifest,
                     subkey: bytes) -> CanaryChannelResult:
    result = CanaryChannelResult()
    if not manifest.canary_specs:
        return result
    header_set = set(table.header)
    key_column = manifest.key_column

    if key_column in header_set:
        # Primary mode: identify canary rows by their key token, then verify
        # every surviving cell against its keyed fingerprint.
        by_token = {spec.key_token: spec for spec in manifest.canary_specs}
        matched_columns: set[str] = set()
        for row in table.rows:
            key = row.get(key_column)
            if key in (None, ""):
                continue
            spec = by_token.get(str(key))
            if spec is None:
                continue
            result.surviving_canaries += 1
            row_hit = False
            for column, expected_fp in spec.cell_fingerprints.items():
                if column not in header_set or column not in row:
                    continue
                result.cell_comparisons += 1
                actual_fp = cell_fingerprint(subkey, column, canonical_cell(row.get(column)))
                if actual_fp == expected_fp:
                    result.cell_hits += 1
                    row_hit = True
                    matched_columns.add(column)
            if row_hit:
                result.row_hits += 1
        result.matched_columns = sorted(matched_columns)
        result.p_value = canary_p_value(result.row_hits, max(1, result.surviving_canaries))
        return result

    # Fallback mode (key column cropped): no row-level identity survives. The
    # only trustworthy canary evidence left is the NUMERIC sentinels -- their
    # value space is large, so a keyed fingerprint collision on two or more
    # numeric columns in the same row is astronomically unlikely. Low-
    # cardinality categorical values are deliberately ignored here: real rows
    # legitimately share them, which would otherwise create false hits.
    numeric_fingerprints_by_column: dict[str, set[str]] = {}
    numeric_sentinel_count = 0
    for spec in manifest.canary_specs:
        for column, value in spec.numeric_sentinels.items():
            if column in header_set:
                numeric_fingerprints_by_column.setdefault(column, set()).add(
                    cell_fingerprint(subkey, column, canonical_cell(value))
                )
                numeric_sentinel_count += 1
    if len(numeric_fingerprints_by_column) < 3:
        # Need a joint signature on at least three numeric columns.
        result.surviving_canaries = len(manifest.canary_specs)
        result.p_value = 1.0
        return result
    row_hits = 0
    cell_hits = 0
    matched_columns: set[str] = set()
    for row in table.rows:
        row_matches = 0
        for column, expected_fps in numeric_fingerprints_by_column.items():
            actual_fp = cell_fingerprint(
                subkey, column, canonical_cell(row.get(column))
            )
            result.cell_comparisons += 1
            if actual_fp in expected_fps:
                cell_hits += 1
                row_matches += 1
                matched_columns.add(column)
        # A joint hit requires sentinels on >=3 numeric columns in one row.
        # Coarse integer columns (e.g. age) have a small grid on their own; the
        # triple-joint requirement makes accidental reproduction negligible.
        if row_matches >= 3:
            row_hits += 1
    result.cell_hits = cell_hits
    result.surviving_canaries = len(manifest.canary_specs)
    result.row_hits = row_hits
    result.matched_columns = sorted(matched_columns)
    # Per-sentinel chance collision: numeric cells span a large grid, bounded
    # conservatively at 1e-9; the joint requirement dominates the tail.
    result.p_value = canary_p_value(row_hits, max(1, table.row_count),
                                    alphabet_guard=1e-9)
    return result


def _evaluate_order(table: Table, manifest: DeliveryManifest,
                    subkey: bytes, resolver: SeedResolver) -> OrderChannelResult:
    result = OrderChannelResult()
    if manifest.order_pairs < MIN_ORDER_PAIRS:
        return result
    ranked: list[tuple[int, str]] = []
    for index, row in enumerate(table.rows):
        seed = resolver.seed_at(index)
        if seed is None:
            continue
        rank = hmac_uniform(
            subkey, DOMAIN_ORDER_BIT,
            [manifest.dataset_name, "rank", seed], 1 << 53,
        )
        ranked.append((rank, seed))
    if len(ranked) < MIN_ORDER_PAIRS + 1:
        return result
    agreements = 0
    pairs = 0
    for (rank_a, _), (rank_b, _) in zip(ranked, ranked[1:]):
        pairs += 1
        if rank_b > rank_a:
            agreements += 1
    result.pairs = pairs
    result.agreements = agreements
    result.usable = pairs >= MIN_ORDER_PAIRS
    result.p_value = order_p_value(agreements, pairs) if result.usable else 1.0
    return result


# --------------------------------------------------------------------------- #
# Attribution
# --------------------------------------------------------------------------- #

def _score_one(table: Table, manifest: DeliveryManifest, master_key: str,
               family_size: int) -> MatchResult:
    subkey = derive_subkey(master_key, manifest.delivery_id)
    resolver = SeedResolver(table, manifest, subkey)
    numeric = _evaluate_numeric(table, manifest, subkey, resolver)
    canary = _evaluate_canary(table, manifest, subkey)
    order = _evaluate_order(table, manifest, subkey, resolver)
    channels = ChannelResult(numeric=numeric, canary=canary, order=order)

    # Bonferroni-adjusted gate: the chance of ANY of K clean deliveries looking
    # like even a weak ("possible") match stays below GATE_POSSIBLE_P.
    family_gate = GATE_POSSIBLE_P / max(1, family_size)
    evidence_p: list[float] = []
    if numeric.trials >= MIN_NUMERIC_TRIALS and numeric.p_value <= family_gate:
        evidence_p.append(numeric.p_value)
    if canary.row_hits > 0:
        evidence_p.append(canary.p_value)
    if order.usable and order.p_value <= ORDER_CORROBORATION_P:
        evidence_p.append(order.p_value)

    combined = fisher_combine(evidence_p) if evidence_p else 1.0
    verdict = band_from_p(combined, numeric.trials, canary.row_hits)
    # Hard family-wise gate: nothing above no_match without numeric or canary
    # evidence clearing the adjusted gate, regardless of order alone.
    if not evidence_p or (
        numeric.p_value > family_gate and canary.row_hits == 0
    ):
        verdict = ConfidenceVerdict(
            BAND_NO_MATCH, 0.0, combined,
            f"no channel cleared the family-wise gate (p<={family_gate:.1e}); "
            "treated as no match"
        )

    # Mixture fraction: rows from THIS delivery match with probability ~1,
    # foreign/clean rows match with probability 1/2 by chance. If f is the true
    # share of this delivery's rows, the observed match rate is f + (1-f)/2,
    # so f = 2*rate - 1. The Wilson interval transforms the same way.
    if numeric.trials:
        rate = numeric.fraction_estimate
        low_rate, high_rate = numeric.fraction_ci
        fraction = max(0.0, min(1.0, 2.0 * rate - 1.0))
        ci = (max(0.0, min(1.0, 2.0 * low_rate - 1.0)),
              max(0.0, min(1.0, 2.0 * high_rate - 1.0)))
    elif table.row_count:
        fraction = canary.surviving_canaries / table.row_count
        ci = (fraction, fraction)
    else:
        fraction, ci = 0.0, (0.0, 0.0)

    return MatchResult(
        delivery_id=manifest.delivery_id,
        verdict=verdict,
        channels=channels,
        combined_p_value=combined,
        mixture_fraction=round(fraction, 4),
        mixture_ci=(round(ci[0], 4), round(ci[1], 4)),
        unresolved_rows=resolver.unresolved,
    )


def detect_attribution(
    suspect_path: str | Path,
    manifests: list[DeliveryManifest],
    master_key: str,
    *,
    table: str | None = None,
) -> AttributionReport:
    if not manifests:
        raise AttributionError("at least one delivery manifest is required")
    suspect = read_table(suspect_path, table=table)
    matches = [_score_one(suspect, manifest, master_key, len(manifests))
               for manifest in manifests]

    significant = [
        match for match in matches
        if match.verdict.band != BAND_NO_MATCH
    ]
    significant.sort(key=lambda m: (m.combined_p_value, -m.mixture_fraction))
    if significant:
        significant[0].is_primary = True
        primary = significant[0]
        primary_delivery = primary.delivery_id
        if len(significant) == 1:
            overall = primary.verdict.band
            rationale = (
                f"single source detected: {primary_delivery} "
                f"(band={primary.verdict.band}, p={primary.combined_p_value:.2e}, "
                f"estimated share={primary.mixture_fraction:.0%})"
            )
        else:
            overall = "mixed"
            others = ", ".join(
                f"{m.delivery_id}={m.mixture_fraction:.0%} ({m.verdict.band})"
                for m in significant[1:]
            )
            rationale = (
                f"mixed file: primary component {primary_delivery} "
                f"({primary.verdict.band}, share={primary.mixture_fraction:.0%}); "
                f"additional sources: {others}"
            )
    else:
        primary_delivery = None
        overall = BAND_NO_MATCH
        best = min(matches, key=lambda m: m.combined_p_value)
        rationale = (
            "no delivery cleared the attribution gate "
            f"(best candidate {best.delivery_id} p={best.combined_p_value:.2e}); "
            "the file is consistent with clean, never-delivered data"
        )

    # Keep the full per-delivery list, strongest first, no_match entries after.
    matches.sort(key=lambda m: (m.verdict.band == BAND_NO_MATCH, m.combined_p_value))
    return AttributionReport(
        suspect_path=str(suspect_path),
        suspect_rows=suspect.row_count,
        header=list(suspect.header),
        manifest_count=len(manifests),
        matches=matches,
        primary_delivery_id=primary_delivery,
        overall_verdict=overall,
        rationale=rationale,
    )
