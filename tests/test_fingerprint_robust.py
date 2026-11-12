"""Robustness tests: filtering, cropping, type conversion, mixing, clean data."""

from __future__ import annotations

import csv
import random

from maskline.fingerprint.detect import detect_attribution
from maskline.fingerprint.embed import embed_delivery
from maskline.fingerprint.keystore import FingerprintPaths
from maskline.fingerprint.manifest import load_manifests, write_manifest
from maskline.fingerprint.stats import BAND_NO_MATCH
from maskline.fingerprint.tableio import read_table, write_table, Table


DELIVERY_IDS = ("vendor-A", "vendor-B", "vendor-C")


def _embed_three(tmp_path, synthetic_table, config, master_key, *, fmt="csv"):
    paths = FingerprintPaths.for_workspace(tmp_path / "ws")
    paths.ensure()
    outputs = {}
    for delivery_id in DELIVERY_IDS:
        out = tmp_path / f"{delivery_id}.{fmt}"
        result = embed_delivery(
            config, synthetic_table["csv"], out,
            delivery_id=delivery_id, master_key=master_key,
            output_format=None if fmt != "csv" else "csv",
        )
        write_manifest(result.manifest, paths.manifest_dir)
        outputs[delivery_id] = out
    manifests = load_manifests(paths.manifest_dir)
    return paths, outputs, manifests


def _filter_rows(table: Table, keep_fraction: float, seed: int) -> Table:
    rng = random.Random(seed)
    keep = int(len(table.rows) * keep_fraction)
    rows = rng.sample(table.rows, keep)
    return Table(header=list(table.header), rows=rows, source_format=table.source_format)


def _crop_columns(table: Table, columns: list[str]) -> Table:
    kept = [name for name in table.header if name not in columns]
    rows = [{key: row[key] for key in kept} for row in table.rows]
    return Table(header=kept, rows=rows, source_format=table.source_format)


def test_untampered_delivery_is_attributed(tmp_path, synthetic_table,
                                           fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    report = detect_attribution(outputs["vendor-B"], manifests, master_key)
    assert report.primary_delivery_id == "vendor-B"
    primary = next(m for m in report.matches if m.delivery_id == "vendor-B")
    assert primary.verdict.band != BAND_NO_MATCH
    assert primary.channels.numeric.match_rate > 0.95


def test_thirty_percent_row_deletion_still_attributed(tmp_path, synthetic_table,
                                                      fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    table = read_table(outputs["vendor-A"])
    thinned = _filter_rows(table, keep_fraction=0.68, seed=42)
    leak = tmp_path / "leak-thinned.csv"
    write_table(leak, thinned)
    report = detect_attribution(leak, manifests, master_key)
    assert report.primary_delivery_id == "vendor-A"
    primary = next(m for m in report.matches if m.delivery_id == "vendor-A")
    assert primary.verdict.band in {"likely", "very_likely", "confirmed"}
    assert primary.combined_p_value < 1e-6


def test_column_cropping_and_type_conversion(tmp_path, synthetic_table,
                                             fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    table = read_table(outputs["vendor-C"])
    cropped = _crop_columns(table, ["advisor_id", "tier", "channel", "visit_count"])
    # Convert every remaining numeric to formatted strings (simulate Excel export).
    for row in cropped.rows:
        for column in ("age", "annual_income_k", "credit_score", "monthly_spend"):
            if column in row and row[column] not in (None, ""):
                row[column] = f"¥{float(row[column]):,.4f}"
    leak = tmp_path / "leak-cropped.jsonl"
    write_table(leak, cropped, output_format="jsonl")
    report = detect_attribution(leak, manifests, master_key)
    assert report.primary_delivery_id == "vendor-C"
    primary = next(m for m in report.matches if m.delivery_id == "vendor-C")
    assert primary.verdict.band in {"likely", "very_likely", "confirmed"}


def test_mixed_leak_from_three_deliveries_points_to_primary(tmp_path, synthetic_table,
                                                             fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    rng = random.Random(7)
    # Vendor A supplies 55%, B 30%, C 15%; then drop 35% of rows overall and
    # crop one numeric column plus a categorical column.
    parts = [(0.55, "vendor-A"), (0.30, "vendor-B"), (0.15, "vendor-C")]
    mixed: list[dict] = []
    for fraction, delivery_id in parts:
        table = read_table(outputs[delivery_id])
        take = int(len(table.rows) * fraction)
        mixed.extend(rng.sample(table.rows, take))
    rng.shuffle(mixed)
    mixed = rng.sample(mixed, int(len(mixed) * 0.65))
    header = [name for name in read_table(outputs["vendor-A"]).header
              if name not in ("visit_count", "channel")]
    mixed = [{key: row.get(key) for key in header} for row in mixed]
    leak = tmp_path / "leak-mixed.csv"
    with leak.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header, lineterminator="\n")
        writer.writeheader()
        writer.writerows(mixed)
    report = detect_attribution(leak, manifests, master_key)
    assert report.overall_verdict == "mixed"
    assert report.primary_delivery_id == "vendor-A"
    by_id = {match.delivery_id: match for match in report.matches}
    # All three components are independently detected; A dominates by share.
    for delivery_id in DELIVERY_IDS:
        assert by_id[delivery_id].verdict.band != BAND_NO_MATCH
    assert by_id["vendor-A"].mixture_fraction >= by_id["vendor-B"].mixture_fraction
    assert by_id["vendor-B"].mixture_fraction >= by_id["vendor-C"].mixture_fraction


def test_clean_never_delivered_data_reports_no_match(tmp_path, synthetic_table,
                                                     fingerprint_config, master_key):
    _paths, _outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    # Independent synthetic table with the same schema but untouched values.
    clean = read_table(synthetic_table["csv"])
    rng = random.Random(99)
    rng.shuffle(clean.rows)
    # Perturb values slightly with an unrelated scheme so grid parity is random
    # relative to every delivery's embedded bits.
    for row in clean.rows:
        row["credit_score"] = round(float(row["credit_score"]) + rng.uniform(-3, 3), 3)
        row["monthly_spend"] = round(float(row["monthly_spend"]) * rng.uniform(0.9, 1.1), 3)
    clean_path = tmp_path / "clean.csv"
    write_table(clean_path, clean)
    report = detect_attribution(clean_path, manifests, master_key)
    assert report.overall_verdict == BAND_NO_MATCH
    assert report.primary_delivery_id is None
    assert all(match.verdict.band == BAND_NO_MATCH for match in report.matches)


def test_format_conversion_roundtrip_jsonl_and_sqlite(tmp_path, synthetic_table,
                                                      fingerprint_config, master_key):
    paths = FingerprintPaths.for_workspace(tmp_path / "ws")
    paths.ensure()
    sqlite_out = tmp_path / "vendor-A.sqlite"
    result = embed_delivery(
        fingerprint_config, synthetic_table["csv"], sqlite_out,
        delivery_id="vendor-A", master_key=master_key, output_format="sqlite",
    )
    write_manifest(result.manifest, paths.manifest_dir)
    manifests = load_manifests(paths.manifest_dir)
    # Re-export the sqlite delivery as JSONL, then verify.
    table = read_table(sqlite_out)
    jsonl = tmp_path / "vendor-A.jsonl"
    write_table(jsonl, table, output_format="jsonl")
    report = detect_attribution(jsonl, manifests, master_key)
    assert report.primary_delivery_id == "vendor-A"


def test_canary_rows_survive_column_crops(tmp_path, synthetic_table,
                                          fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    table = read_table(outputs["vendor-B"])
    cropped = _crop_columns(table, ["advisor_id", "city", "tier", "channel"])
    leak = tmp_path / "canary-only.csv"
    write_table(leak, cropped)
    report = detect_attribution(leak, manifests, master_key)
    match_b = next(m for m in report.matches if m.delivery_id == "vendor-B")
    assert match_b.channels.canary.row_hits >= 1
    assert match_b.verdict.band != BAND_NO_MATCH


def test_row_shuffle_destroys_order_but_not_primary_channel(tmp_path, synthetic_table,
                                                            fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    table = read_table(outputs["vendor-A"])
    rng = random.Random(11)
    rng.shuffle(table.rows)
    leak = tmp_path / "shuffled.csv"
    write_table(leak, table)
    report = detect_attribution(leak, manifests, master_key)
    assert report.primary_delivery_id == "vendor-A"
    primary = next(m for m in report.matches if m.delivery_id == "vendor-A")
    # Order channel must not falsely claim agreement after shuffling.
    assert primary.channels.order.agreements / max(1, primary.channels.order.pairs) < 0.7
    assert primary.verdict.band != BAND_NO_MATCH


def test_false_positive_rate_on_many_clean_tables(tmp_path, synthetic_table,
                                                   fingerprint_config, master_key):
    # Five archived deliveries enlarge the multiple-testing surface; then throw
    # many independently re-randomised clean tables at the verifier.
    paths = FingerprintPaths.for_workspace(tmp_path / "ws")
    paths.ensure()
    for index in range(5):
        out = tmp_path / f"vendor-{index}.csv"
        result = embed_delivery(
            fingerprint_config, synthetic_table["csv"], out,
            delivery_id=f"vendor-{index}", master_key=master_key,
        )
        write_manifest(result.manifest, paths.manifest_dir)
    manifests = load_manifests(paths.manifest_dir)

    base = read_table(synthetic_table["csv"])
    false_alarms = 0
    for trial in range(25):
        rng = random.Random(1000 + trial)
        clean_rows = [dict(row) for row in base.rows]
        rng.shuffle(clean_rows)
        for row in clean_rows:
            row["credit_score"] = round(float(row["credit_score"]) + rng.uniform(-4, 4), 3)
            row["monthly_spend"] = round(
                float(row["monthly_spend"]) * rng.uniform(0.85, 1.15), 3
            )
            row["age"] = int(row["age"]) + rng.choice((-1, 0, 0, 1))
        clean_path = tmp_path / f"clean-{trial}.csv"
        write_table(clean_path, Table(header=list(base.header), rows=clean_rows,
                                      source_format="csv"))
        report = detect_attribution(clean_path, manifests, master_key)
        if report.overall_verdict != BAND_NO_MATCH:
            false_alarms += 1
    # Bonferroni keeps the observed family-wise false-positive count at zero
    # across the Monte Carlo run.
    assert false_alarms == 0


def test_wrong_master_key_cannot_attribute(tmp_path, synthetic_table,
                                           fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    report = detect_attribution(
        outputs["vendor-A"], manifests,
        master_key="a-totally-different-key-held-by-someone-else-0000",
    )
    assert report.overall_verdict == BAND_NO_MATCH
    assert all(match.verdict.band == BAND_NO_MATCH for match in report.matches)


def test_key_column_cropped_falls_back_to_anchor(tmp_path, synthetic_table,
                                                 fingerprint_config, master_key):
    # The strongest column-cropping attack: the primary key column is gone, so
    # row identity must be recovered through the archived fallback anchor.
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    manifest_a = next(m for m in manifests if m.delivery_id == "vendor-A")
    assert "account_id" in manifest_a.anchor_columns
    assert manifest_a.anchor_index.get("account_id")

    table = read_table(outputs["vendor-A"])
    # Drop the key column AND a low-cardinality protected column; keep the
    # unique anchor. Then delete 30% of rows and drop one numeric column too.
    thinned = _filter_rows(table, keep_fraction=0.7, seed=3)
    cropped = _crop_columns(thinned, ["customer_id", "advisor_id", "visit_count"])
    leak = tmp_path / "keyless.csv"
    write_table(leak, cropped)

    report = detect_attribution(leak, manifests, master_key)
    assert report.primary_delivery_id == "vendor-A"
    primary = next(m for m in report.matches if m.delivery_id == "vendor-A")
    assert primary.verdict.band in {"likely", "very_likely", "confirmed"}
    # Only canary rows remain unresolved: their anchor tokens are deliberately
    # absent from the real-row anchor index.
    expected_canaries = len(manifest_a.canary_specs)
    assert primary.unresolved_rows <= expected_canaries
    # Other deliveries must not be falsely accused via the same anchor path.
    for match in report.matches:
        if match.delivery_id != "vendor-A":
            assert match.verdict.band == BAND_NO_MATCH


def test_key_column_cropped_mixed_file_keeps_primary(tmp_path, synthetic_table,
                                                      fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    rng = random.Random(123)
    parts = [(0.6, "vendor-A"), (0.25, "vendor-B"), (0.15, "vendor-C")]
    mixed: list[dict] = []
    for fraction, delivery_id in parts:
        table = read_table(outputs[delivery_id])
        mixed.extend(rng.sample(table.rows, int(len(table.rows) * fraction)))
    rng.shuffle(mixed)
    mixed = rng.sample(mixed, int(len(mixed) * 0.7))
    header = [name for name in read_table(outputs["vendor-A"]).header
              if name not in ("customer_id", "advisor_id", "channel")]
    mixed = [{key: row.get(key) for key in header} for row in mixed]
    leak = tmp_path / "keyless-mixed.csv"
    with leak.open("w", encoding="utf-8", newline="") as fh:
        import csv as _csv
        writer = _csv.DictWriter(fh, fieldnames=header, lineterminator="\n")
        writer.writeheader()
        writer.writerows(mixed)
    report = detect_attribution(leak, manifests, master_key)
    assert report.primary_delivery_id == "vendor-A"
    primary = next(m for m in report.matches if m.delivery_id == "vendor-A")
    assert primary.verdict.band != BAND_NO_MATCH


def test_anchor_index_stores_no_plaintext(tmp_path, synthetic_table,
                                          fingerprint_config, master_key):
    _paths, outputs, manifests = _embed_three(
        tmp_path, synthetic_table, fingerprint_config, master_key
    )
    from maskline.fingerprint.manifest import write_manifest
    from maskline.fingerprint.keystore import FingerprintPaths
    paths = FingerprintPaths.for_workspace(tmp_path / "ws2")
    paths.ensure()
    target = write_manifest(
        next(m for m in manifests if m.delivery_id == "vendor-A"),
        paths.manifest_dir,
    )
    blob = target.read_text(encoding="utf-8")
    # Real anchor values (pseudonym tokens) must never appear in the manifest.
    tokens = {row["account_id"] for row in synthetic_table["rows"][:25]}
    assert not any(token in blob for token in tokens)
    assert master_key not in blob
