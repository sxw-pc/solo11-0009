"""Unit tests for statistical calibration and table parsing tolerance."""

from __future__ import annotations

import math

import pytest

from maskline.fingerprint.stats import (
    band_from_p,
    binomial_tail,
    canary_p_value,
    fisher_combine,
    wilson_interval,
)
from maskline.fingerprint.tableio import canonical_cell, parse_number


def test_binomial_tail_known_values():
    assert binomial_tail(0, 10) == 1.0
    assert binomial_tail(11, 10) == pytest.approx(1 / 2**10)
    assert binomial_tail(8, 10) == pytest.approx(56 / 1024)
    assert binomial_tail(1, 1) == pytest.approx(0.5)


def test_binomial_tail_monotone():
    base = binomial_tail(12, 20)
    stronger = binomial_tail(15, 20)
    weaker = binomial_tail(10, 20)
    assert stronger < base < weaker


def test_wilson_interval_covers_half():
    low, high = wilson_interval(50, 100)
    assert low < 0.5 < high
    assert 0.0 <= low <= high <= 1.0


def test_canary_p_value_is_tiny_for_hits():
    assert canary_p_value(0, 10) == 1.0
    assert canary_p_value(2, 10) < 1e-9
    assert canary_p_value(1, 1) == pytest.approx(1e-6)


def test_fisher_combine_strengthens_with_independent_evidence():
    combined = fisher_combine([1e-3, 1e-3])
    assert combined < 1e-3
    assert fisher_combine([]) == 1.0


def test_band_requires_minimum_trials():
    verdict = band_from_p(1e-12, numeric_trials=5, canary_hits=0)
    assert verdict.band == "no_match"
    strong = band_from_p(1e-12, numeric_trials=60, canary_hits=0)
    assert strong.band in {"likely", "very_likely", "confirmed"}
    clean = band_from_p(0.5, numeric_trials=200, canary_hits=0)
    assert clean.band == "no_match"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("12.30", 12.3),
        ("1.23e1", 12.3),
        ("¥1,234.5", 1234.5),
        ("12%", 12.0),
        ("", None),
        (None, None),
        ("not-a-number", None),
        (42, 42.0),
        (True, 1.0),
    ],
)
def test_parse_number_tolerance(raw, expected):
    result = parse_number(raw)
    if expected is None:
        assert result is None
    else:
        assert math.isclose(result, expected)


def test_canonical_cell_stable_across_text_types():
    assert canonical_cell("12.0") == canonical_cell(12)
    assert canonical_cell(12.0) == "12"
    assert canonical_cell(None) == ""
    assert canonical_cell("  hello ") == "hello"
