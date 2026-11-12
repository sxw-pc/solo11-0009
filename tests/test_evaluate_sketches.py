"""Tests for bounded-memory streaming aggregation primitives."""

from __future__ import annotations

import pytest

from maskline.evaluate.sketches import (
    BloomFilter,
    ExternalHashCounter,
    HyperLogLog,
    MisraGries,
    NumericRangeTracker,
    fingerprint_key,
    hash_value,
)


def test_hyperloglog_estimates_within_tolerance():
    hll = HyperLogLog(precision=14)
    exact = 50_000
    for value in range(exact):
        hll.add(value)
    estimate = hll.estimate()
    assert abs(estimate - exact) / exact < 0.02


def test_hyperloglog_dedupes_repeated_values():
    hll = HyperLogLog(precision=12)
    for _ in range(10_000):
        hll.add("only-one-value")
    assert hll.estimate() == 1


def test_misra_gries_is_exact_below_capacity_and_bounded_above():
    mg = MisraGries(capacity=100)
    for value in range(60):
        for _ in range(10):
            mg.add(value)
    assert mg.exact is True
    assert sum(mg.counts.values()) == 600
    # Once capacity is exceeded, memory stays at/below capacity and counts are
    # lower bounds.
    mg2 = MisraGries(capacity=32)
    for value in range(10_000):
        mg2.add(value)
    assert len(mg2.counts) <= 32
    assert mg2.exact is False
    assert mg2.error >= 1


def test_numeric_tracker_buckets_cover_all_values():
    tracker = NumericRangeTracker(bucket_count=5)
    values = [float(v) for v in range(100)]
    for value in values:
        tracker.observe(value)
    edges = tracker.finalize_edges()
    assert len(edges) == 6
    tracker.buckets = [0] * 5
    for value in values:
        tracker.add_bucket(value)
    assert sum(tracker.buckets) == 100


def test_bloom_filter_membership_no_false_negatives():
    bloom = BloomFilter(expected_items=1000, false_positive_rate=0.01)
    members = {f"member-{i}" for i in range(1000)}
    for member in members:
        bloom.add(member)
    for member in members:
        assert bloom.might_contain(member)  # never a false negative
    # Empirical false-positive rate stays near the configured target.
    false_positives = sum(
        bloom.might_contain(f"absent-{i}") for i in range(10_000)
    )
    assert false_positives / 10_000 < 0.03


def test_external_counter_exact_without_spill(tmp_path):
    counter = ExternalHashCounter(max_keys=1000, spill_dir=tmp_path / "a")
    for value in range(500):
        counter.add(fingerprint_key([value], salt="s"))
    counts = dict(counter.iter_counts())
    assert len(counts) == 500
    assert counter.spilled is False
    counter.cleanup()


def test_external_counter_exact_with_spill_and_repeated_keys(tmp_path):
    # Tiny buffer forces repeated flush cycles; repeated keys must merge, not
    # duplicate, and distinct classes must be reported exactly.
    counter = ExternalHashCounter(
        max_keys=50, partitions=16, spill_dir=tmp_path / "spill"
    )
    distinct = 300
    repeats = 20
    for _ in range(repeats):
        for value in range(distinct):
            counter.add(fingerprint_key([value], salt="s"))
    counts = dict(counter.iter_counts())
    assert len(counts) == distinct
    assert sum(counts.values()) == distinct * repeats
    assert all(count == repeats for count in counts.values())
    assert counter.spilled is True
    counter.cleanup()
    # Spill artifacts are removed after cleanup.
    assert not any((tmp_path / "spill").iterdir())


def test_external_counter_handles_rowid_style_adjacent_keys(tmp_path):
    # Regression: 120k adjacent keys through a small buffer must not lose any
    # class (the earlier rowid-window row-loss bug surfaced exactly like this).
    counter = ExternalHashCounter(
        max_keys=5000, partitions=256, spill_dir=tmp_path / "big"
    )
    rows = [(f"q1-{i}", f"q2-{i % 50_000}") for i in range(120_000)]
    for pair in rows:
        counter.add(fingerprint_key(pair, salt="s"))
    counts = list(counter.iter_counts())
    assert len(counts) == 120_000
    assert sum(size for _, size in counts) == 120_000
    counter.cleanup()


def test_fingerprint_is_salted_and_fixed_width():
    fp_a = fingerprint_key(("x", "y"), salt="salt-one")
    fp_b = fingerprint_key(("x", "y"), salt="salt-two")
    assert len(fp_a) == 16 and len(fp_b) == 16
    assert fp_a != fp_b  # salt changes the fingerprint
    # Deterministic for the same salt.
    assert fingerprint_key(("x", "y"), salt="salt-one") == fp_a


def test_hash_value_stable_across_calls():
    assert hash_value("abc") == hash_value("abc")
    assert hash_value("abc") != hash_value("abd")
    assert hash_value(None) != hash_value("None")


def test_external_counter_rejects_wrong_key_size(tmp_path):
    counter = ExternalHashCounter(key_size=16, spill_dir=tmp_path / "x")
    with pytest.raises(ValueError):
        counter.add(b"too-short")
    counter.cleanup()
