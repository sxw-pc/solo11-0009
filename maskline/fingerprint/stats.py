"""Statistical primitives for attribution decisions.

The numeric watermark channel reduces to a one-sided binomial sign test: under
the null hypothesis "the suspect data does not carry this delivery's mark",
each surviving marked cell has a 50% chance of matching the expected bit. We
compute the exact binomial tail (regularised incomplete beta) rather than a
normal approximation, so the test stays valid on small surviving samples, and
combine independent channels with Fisher's method.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# Confidence bands used in the final verdict. The numeric p-value is the
# primary gate; canary and order channels can only corroborate, never trigger a
# match on their own below the "substantial" numeric threshold.
BAND_NO_MATCH = "no_match"
BAND_POSSIBLE = "possible"
BAND_LIKELY = "likely"
BAND_VERY_LIKELY = "very_likely"
BAND_CONFIRMED = "confirmed"

# Gates. p = 1e-3 over ~25 independent matches is roughly the "likely" onset;
# canary hits are individually far stronger (see canary_p_value).
LIKELY_P = 1e-3
VERY_LIKELY_P = 1e-6
CONFIRMED_P = 1e-9
POSSIBLE_P = 5e-2

# Minimum surviving marked cells before the numeric channel counts as evidence.
MIN_NUMERIC_TRIALS = 8
# A verdict of anything above "possible" requires at least this many trials,
# so a handful of coincidental matches can never drive a strong attribution.
MIN_STRONG_TRIALS = 20


def _betacf(a: float, b: float, x: float) -> float:
    """Lentz's continued fraction for the incomplete beta (Numerical Recipes)."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < 1e-30:
        d = 1e-30
    d = 1.0 / d
    h = d
    for m in range(1, 201):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-12:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def binomial_tail(successes: int, trials: int) -> float:
    """One-sided exact p-value: P(X >= successes) under X ~ Binomial(trials, 1/2)."""
    if trials <= 0:
        return 1.0
    successes = max(0, min(successes, trials))
    if successes == 0:
        return 1.0
    # P(X >= k) = I_{1/2}(k, n-k+1)
    return betainc(successes, trials - successes + 1, 0.5)


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for the embedded-fraction estimate."""
    if trials == 0:
        return (0.0, 0.0)
    phat = successes / trials
    denom = 1 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denom
    margin = (z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def canary_p_value(hits: int, candidates: int, alphabet_guard: float = 1e-6) -> float:
    """Conservative per-delivery p-value for canary evidence.

    A canary hit means a suspect row reproduces a keyed cell fingerprint that an
    unmarked dataset could only produce by chance. Treating each surviving canary
    cell comparison as an independent Bernoulli with probability no larger than
    ``alphabet_guard`` (the canonical-value space is large for the numeric/key
    columns that dominate canaries, and we cap conservatively at 1e-6) gives a
    binomial tail, summed in log space to avoid underflow.
    """
    if hits <= 0 or candidates <= 0:
        return 1.0
    log_p = math.log(alphabet_guard)
    log_q = math.log1p(-alphabet_guard)
    terms = []
    for k in range(hits, candidates + 1):
        log_coef = (math.lgamma(candidates + 1)
                    - math.lgamma(k + 1) - math.lgamma(candidates - k + 1))
        terms.append(log_coef + k * log_p + (candidates - k) * log_q)
    # log-sum-exp over the tail terms.
    peak = max(terms)
    return min(1.0, math.exp(peak + math.log(sum(math.exp(t - peak) for t in terms))))


def order_p_value(agreements: int, pairs: int) -> float:
    if pairs < 4:
        return 1.0
    return binomial_tail(agreements, pairs)


def fisher_combine(p_values: list[float]) -> float:
    """Fisher's method for combining independent p-values (chi-square, 2k dof).

    Computed entirely in log space so that several very small p-values combine
    to a small but representable result instead of underflowing to zero.
    """
    valid = [min(max(p, 1e-300), 1.0) for p in p_values if p < 1.0]
    if not valid:
        return 1.0
    k = len(valid)
    half = -sum(math.log(p) for p in valid)  # = chi2 statistic / 2
    # chi-square survival with 2k dof:
    # Q = exp(-half) * sum_{j=0}^{k-1} half^j / j!
    log_terms = []
    log_half = math.log(half)
    for j in range(k):
        log_terms.append(j * log_half - math.lgamma(j + 1))
    peak = max(log_terms)
    log_sum = peak + math.log(sum(math.exp(t - peak) for t in log_terms))
    log_survival = -half + log_sum
    return min(1.0, math.exp(min(0.0, log_survival)))


@dataclass(frozen=True)
class ConfidenceVerdict:
    band: str
    score: float  # 0..100, monotone in -log10 combined p
    p_value: float
    rationale: str


def band_from_p(p_value: float, numeric_trials: int, canary_hits: int) -> ConfidenceVerdict:
    """Map combined evidence onto a calibrated, conservative band."""
    strength = -math.log10(max(p_value, 1e-300))
    score = round(min(100.0, 100.0 * (1.0 - math.exp(-strength / 6.0))), 1)

    if numeric_trials < MIN_NUMERIC_TRIALS and canary_hits == 0:
        return ConfidenceVerdict(
            BAND_NO_MATCH, 0.0, p_value,
            "insufficient surviving marked cells; no evidence either way"
        )
    if p_value > POSSIBLE_P:
        return ConfidenceVerdict(
            BAND_NO_MATCH, score, p_value,
            "match rate statistically indistinguishable from random (p>=0.05)"
        )
    if numeric_trials < MIN_STRONG_TRIALS and canary_hits == 0:
        return ConfidenceVerdict(
            BAND_POSSIBLE, score, p_value,
            "weak signal but too few surviving cells for a strong attribution"
        )
    if canary_hits >= 2 and p_value <= VERY_LIKELY_P:
        return ConfidenceVerdict(
            BAND_CONFIRMED, score, p_value,
            f"statistical mark plus {canary_hits} canary rows reproduced"
        )
    if p_value <= CONFIRMED_P:
        return ConfidenceVerdict(BAND_CONFIRMED, score, p_value,
                                 "overwhelming statistical agreement across marked cells")
    if p_value <= VERY_LIKELY_P:
        return ConfidenceVerdict(BAND_VERY_LIKELY, score, p_value,
                                 "strong agreement well beyond chance")
    if p_value <= LIKELY_P:
        return ConfidenceVerdict(BAND_LIKELY, score, p_value,
                                 "agreement significant at the 0.001 level")
    return ConfidenceVerdict(BAND_POSSIBLE, score, p_value,
                             "agreement above chance but limited strength")
