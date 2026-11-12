"""Core fingerprint guarantees: protection, perturbation bounds, sealed records."""

from __future__ import annotations

import json

import pytest

from maskline.fingerprint.config import FingerprintConfigError
from maskline.fingerprint.crypto import derive_subkey
from maskline.fingerprint.embed import embed_delivery
from maskline.fingerprint.keystore import FingerprintPaths, record_delivery_audit
from maskline.fingerprint.manifest import load_manifest, write_manifest
from maskline.fingerprint.tableio import read_table

from fp_fixtures import DATASET_NAME


def test_protected_columns_never_change(tmp_path, synthetic_table, fingerprint_config, master_key):
    before = read_table(synthetic_table["csv"])
    out = tmp_path / "delivery-a.csv"
    result = embed_delivery(
        fingerprint_config, synthetic_table["csv"], out,
        delivery_id="vendor-A", master_key=master_key,
    )
    after = read_table(out)
    protected = set(fingerprint_config.protected_columns) | {
        fingerprint_config.key_column,
    }
    before_by_key = {row["customer_id"]: row for row in before.rows}
    changed_cells = []
    for row in after.rows:
        original = before_by_key.get(row["customer_id"])
        if original is None:
            continue  # canary row
        for column in protected:
            if str(row[column]) != str(original[column]):
                changed_cells.append((row["customer_id"], column))
    assert changed_cells == []
    assert result.skipped_null_keys == 0


def test_pseudonym_mapping_stays_global_and_consistent(tmp_path, synthetic_table,
                                                       fingerprint_config, master_key):
    # Same key value must appear identically across two independent deliveries.
    outputs = []
    for delivery_id in ("vendor-A", "vendor-B"):
        out = tmp_path / f"{delivery_id}.csv"
        embed_delivery(
            fingerprint_config, synthetic_table["csv"], out,
            delivery_id=delivery_id, master_key=master_key,
        )
        outputs.append(read_table(out))
    a, b = outputs
    mapping_a = {row["customer_id"]: row["advisor_id"] for row in a.rows}
    mapping_b = {row["customer_id"]: row["advisor_id"] for row in b.rows}
    shared = set(mapping_a) & set(mapping_b)
    assert len(shared) > 500
    assert all(mapping_a[key] == mapping_b[key] for key in shared)
    # No duplicate pseudonyms were introduced.
    ids_a = [row["customer_id"] for row in a.rows]
    assert len(ids_a) == len(set(ids_a))


def test_numeric_perturbation_within_quantum_and_analytics_bounded(
    tmp_path, synthetic_table, fingerprint_config, master_key
):
    before = read_table(synthetic_table["csv"])
    out = tmp_path / "delivery-a.csv"
    result = embed_delivery(
        fingerprint_config, synthetic_table["csv"], out,
        delivery_id="vendor-A", master_key=master_key,
    )
    after = read_table(out)
    manifest = result.manifest
    by_key = {row["customer_id"]: row for row in before.rows}
    for spec in manifest.numeric_specs:
        deltas = []
        for row in after.rows:
            original = by_key.get(row["customer_id"])
            if original is None:
                continue
            deltas.append(abs(float(row[spec.column]) - float(original[spec.column])))
        assert max(deltas) <= spec.quantum + 1e-9
        # Mean shift over the whole column is far below one quantum.
        mean_shift = sum(deltas) / len(deltas)
        assert mean_shift <= spec.quantum * (spec.mark_rate + 0.05)
        if spec.integer:
            assert all(
                isinstance(row[spec.column], int)
                or float(row[spec.column]).is_integer()
                for row in after.rows
            )


def test_manifest_is_sealed_and_contains_no_plaintext_secrets(
    tmp_path, synthetic_table, fingerprint_config, master_key
):
    out = tmp_path / "delivery-a.csv"
    result = embed_delivery(
        fingerprint_config, synthetic_table["csv"], out,
        delivery_id="vendor-A", master_key=master_key,
    )
    paths = FingerprintPaths.for_workspace(tmp_path / "ws")
    paths.ensure()
    target = write_manifest(result.manifest, paths.manifest_dir)
    loaded = load_manifest(target)
    assert loaded.manifest_hash == result.manifest.manifest_hash
    raw = json.loads(target.read_text(encoding="utf-8"))
    blob = json.dumps(raw, ensure_ascii=False)
    # The master key and any original numeric value must not appear.
    assert master_key not in blob
    original = read_table(synthetic_table["csv"])
    sample_values = {str(original.rows[0][col]) for col in
                     ("credit_score", "monthly_spend", "annual_income_k")}
    assert not any(value in blob for value in sample_values)


def test_tampered_manifest_is_rejected(tmp_path, synthetic_table,
                                       fingerprint_config, master_key):
    out = tmp_path / "delivery-a.csv"
    result = embed_delivery(
        fingerprint_config, synthetic_table["csv"], out,
        delivery_id="vendor-A", master_key=master_key,
    )
    paths = FingerprintPaths.for_workspace(tmp_path / "ws")
    paths.ensure()
    target = write_manifest(result.manifest, paths.manifest_dir)
    raw = json.loads(target.read_text(encoding="utf-8"))
    raw["notes"] = "tampered"
    target.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(Exception):
        load_manifest(target)


def test_per_delivery_subkeys_are_independent(master_key):
    key_a = derive_subkey(master_key, "vendor-A")
    key_b = derive_subkey(master_key, "vendor-B")
    key_a_again = derive_subkey(master_key, "vendor-A")
    assert key_a != key_b
    assert key_a == key_a_again
    assert len(key_a) == 32


def test_refuses_to_mark_protected_column(tmp_path, synthetic_table, master_key):
    from maskline.fingerprint.config import FingerprintConfig, NumericColumn
    bad = FingerprintConfig(
        dataset_name=DATASET_NAME,
        key_column="customer_id",
        protected_columns=("advisor_id",),
        numeric_columns=(NumericColumn(name="advisor_id", quantum=1.0),),
    )
    with pytest.raises(FingerprintConfigError):
        embed_delivery(
            bad, synthetic_table["csv"], tmp_path / "x.csv",
            delivery_id="v", master_key=master_key,
        )


def test_audit_entry_pins_manifest(tmp_path, synthetic_table,
                                   fingerprint_config, master_key):
    paths = FingerprintPaths.for_workspace(tmp_path / "ws")
    paths.ensure()
    out = tmp_path / "delivery-a.csv"
    result = embed_delivery(
        fingerprint_config, synthetic_table["csv"], out,
        delivery_id="vendor-A", master_key=master_key,
    )
    write_manifest(result.manifest, paths.manifest_dir)
    entry = record_delivery_audit(paths, result.manifest, out, recipient="外包商甲")
    assert entry["manifest_hash"] == result.manifest.manifest_hash
    assert entry["recipient"] == "外包商甲"
    rows = __import__(
        "maskline.fingerprint.keystore", fromlist=["reconcile_manifests_with_audit"]
    ).reconcile_manifests_with_audit(paths)
    assert rows and all(row["reconciled"] for row in rows)
