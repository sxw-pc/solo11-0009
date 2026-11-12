"""Cross-version drift detection, audit coupling, and upgrade compatibility."""

from __future__ import annotations

import json
import random
import sqlite3
import time
from pathlib import Path

import pytest

from maskline.audit import AuditIntegrityError, AuditLog, read_audit_entries, verify_audit
from maskline.config import Paths
from maskline.drift import (
    DriftError,
    apply_ignore_rules,
    compare_versions,
    ensure_ignore_rules_pin,
    evaluate_version_drift,
    load_ignore_rules,
    record_drift_comparison,
    verify_registry_drift_records,
)
from maskline.fixturegen import generate_fixture, synthetic_phone
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.registry import Catalog
from maskline.workflow import finalize_run, scan_paths

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _finding(
    column: str,
    sensitive_type: str | None,
    confidence: str,
    hit_rate: float,
    validate_rate: float = 1.0,
    table: str = "t",
) -> dict:
    return {
        "table_name": table,
        "column_name": column,
        "sensitive_type": sensitive_type,
        "confidence": confidence,
        "score": hit_rate * validate_rate,
        "hit_rate": hit_rate,
        "validate_rate": validate_rate,
        "sample_size": 200,
    }


def _schema(*pairs: tuple[str, str], table: str = "t") -> dict:
    return {
        "tables": [
            {
                "name": table,
                "row_count": 0,
                "columns": [
                    {"name": column, "declared_type": dtype, "nullable": True}
                    for column, dtype in pairs
                ],
            }
        ]
    }


def _drift_for(workspace: Paths, sqlite_path: Path) -> object:
    return scan_paths([sqlite_path], workspace)[0].drift


def test_old_registry_is_upgraded_without_touching_history(tmp_path):
    meta = tmp_path / "meta.sqlite"
    conn = sqlite3.connect(meta)
    # Exactly the 0.1 registry schema: no drift tables yet.
    conn.executescript(
        """
        CREATE TABLE datasets (
            fingerprint TEXT PRIMARY KEY, path TEXT NOT NULL, kind TEXT NOT NULL,
            size_bytes INTEGER NOT NULL, row_count INTEGER NOT NULL,
            tables_json TEXT NOT NULL, registered_at TEXT NOT NULL
        );
        CREATE TABLE findings (
            dataset_fingerprint TEXT NOT NULL, table_name TEXT NOT NULL,
            column_name TEXT NOT NULL, sensitive_type TEXT,
            confidence TEXT NOT NULL DEFAULT 'none', score REAL NOT NULL DEFAULT 0,
            hit_rate REAL NOT NULL DEFAULT 0, validate_rate REAL NOT NULL DEFAULT 0,
            sample_size INTEGER NOT NULL DEFAULT 0,
            candidates_json TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL,
            PRIMARY KEY (dataset_fingerprint, table_name, column_name)
        );
        """
    )
    conn.execute(
        "INSERT INTO datasets VALUES (?,?,?,?,?,?,?)",
        (
            "old-fingerprint",
            "/historical/dataset.sqlite",
            "sqlite",
            10,
            5,
            json.dumps(_schema(("phone", "TEXT")), ensure_ascii=False),
            "2024-01-01T00:00:00+00:00",
        ),
    )
    conn.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            "old-fingerprint",
            "t",
            "phone",
            "mobile_phone",
            "high",
            1.0,
            1.0,
            1.0,
            5,
            "[]",
            "2024-01-01T00:00:00+00:00",
        ),
    )
    conn.commit()
    conn.close()

    before = sqlite3.connect(meta)
    before_row = before.execute("SELECT * FROM findings").fetchall()
    before.close()

    with Catalog(meta) as catalog:
        assert catalog.findings_for("old-fingerprint")[0]["sensitive_type"] == "mobile_phone"
        assert catalog.get_dataset("old-fingerprint")["row_count"] == 5
        assert [item["fingerprint"] for item in catalog.dataset_versions(
            "/historical/dataset.sqlite"
        )] == ["old-fingerprint"]
        tables = {
            row[0]
            for row in catalog.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"drift_comparisons", "config_pins"} <= tables

    after = sqlite3.connect(meta)
    assert after.execute("SELECT * FROM findings").fetchall() == before_row
    after.close()


def test_column_addition_and_removal_are_classified_without_false_positives(
    workspace: Paths,
):
    fixtures = generate_fixture(
        workspace.raw_dir, seed=7, customers=8, orders=9, leads=3
    )
    source = fixtures["sqlite"]
    assert _drift_for(workspace, source) is None

    conn = sqlite3.connect(source)
    conn.execute("ALTER TABLE customers ADD COLUMN emergency_phone TEXT")
    rng = random.Random(11)
    conn.executemany(
        "UPDATE customers SET emergency_phone = ? WHERE customer_id = ?",
        [(synthetic_phone(rng), index) for index in range(1, 9)],
    )
    conn.execute("ALTER TABLE customers DROP COLUMN email")  # was a sensitive column
    conn.execute("ALTER TABLE customers ADD COLUMN loyalty_tier TEXT DEFAULT 'gold'")
    conn.commit()
    conn.close()

    drift = _drift_for(workspace, source)
    assert drift is not None
    found = {(item.drift_type, item.column) for item in drift.drifts}
    assert found == {
        ("column_added", "emergency_phone"),
        ("column_removed", "email"),
    }
    # A newly added non-sensitive column must not raise an alarm.
    assert "loyalty_tier" not in {item.column for item in drift.drifts}
    assert drift.summary()["total"] == 2


def test_sensitive_type_change_is_detected_even_with_identical_hit_rate(
    workspace: Paths,
):
    fixtures = generate_fixture(
        workspace.raw_dir, seed=7, customers=8, orders=9, leads=3
    )
    source = fixtures["sqlite"]
    assert _drift_for(workspace, source) is None

    conn = sqlite3.connect(source)
    conn.execute(
        "UPDATE customers SET phone = 'user' || customer_id || '@example.invalid'"
    )
    conn.commit()
    conn.close()

    drift = _drift_for(workspace, source)
    assert drift is not None
    assert [(item.drift_type, item.column) for item in drift.drifts] == [
        ("type_changed", "phone")
    ]
    item = drift.drifts[0]
    assert item.baseline["sensitive_type"] == "mobile_phone"
    assert item.current["sensitive_type"] == "email"
    assert item.baseline["hit_rate"] == item.current["hit_rate"] == 1.0
    assert item.hit_rate_delta == 0.0


def test_sampling_fluctuation_within_five_percent_is_not_alarmed():
    baseline = [_finding("phone", "mobile_phone", "high", 0.82)]
    current = [_finding("phone", "mobile_phone", "medium", 0.79)]
    assert compare_versions(_schema(("phone", "TEXT")), baseline,
                            _schema(("phone", "TEXT")), current) == ()

    # A real confidence drop with more than 5% movement is reported.
    current_real = [_finding("phone", "mobile_phone", "medium", 0.66)]
    items = compare_versions(
        _schema(("phone", "TEXT")), baseline, _schema(("phone", "TEXT")), current_real
    )
    assert [(item.drift_type, item.column) for item in items] == [
        ("level_changed", "phone")
    ]

    # Crossing the detection threshold with only sampling noise is suppressed.
    near_threshold_before = [_finding("phone", None, "none", 0.18)]
    near_threshold_after = [_finding("phone", "mobile_phone", "low", 0.21)]
    assert compare_versions(
        _schema(("phone", "TEXT")),
        near_threshold_before,
        _schema(("phone", "TEXT")),
        near_threshold_after,
    ) == ()


def test_ignore_rules_are_strict_ordered_and_fingerprinted(tmp_path):
    first = tmp_path / "ignore-a.yaml"
    first.write_text(
        """
version: 1
name: accepted
ignore:
  - table: t
    column: phone
    drift_types: [level_changed]
    reason: known sampling noise
""".lstrip(),
        encoding="utf-8",
    )
    reordered = tmp_path / "ignore-b.yaml"
    reordered.write_text(
        """
version: 1
name: accepted
ignore:
  - reason: known sampling noise
    drift_types: [level_changed]
    column: phone
    table: t
""".lstrip(),
        encoding="utf-8",
    )
    rules = load_ignore_rules(first)
    assert load_ignore_rules(reordered).fingerprint == rules.fingerprint

    altered = tmp_path / "ignore-c.yaml"
    altered.write_text(
        first.read_text(encoding="utf-8").replace(
            "known sampling noise", "edited without approval"
        ),
        encoding="utf-8",
    )
    with pytest.raises(DriftError, match="fingerprint mismatch"):
        load_ignore_rules(altered, expected_fingerprint=rules.fingerprint)

    baseline = [_finding("phone", "mobile_phone", "high", 0.9)]
    current = [_finding("phone", "mobile_phone", "medium", 0.6)]
    items = compare_versions(_schema(("phone", "TEXT")), baseline,
                             _schema(("phone", "TEXT")), current)
    active, ignored = apply_ignore_rules(items, rules)
    assert active == ()
    assert len(ignored) == 1
    assert ignored[0].ignore_reason == "known sampling noise"

    with Catalog(tmp_path / "meta.sqlite") as catalog:
        ensure_ignore_rules_pin(catalog, rules)
        # Editing the *same* rules file after pinning must fail closed.
        first.write_text(
            first.read_text(encoding="utf-8").replace(
                "known sampling noise", "edited without approval"
            ),
            encoding="utf-8",
        )
        with pytest.raises(DriftError, match="modified after being pinned"):
            ensure_ignore_rules_pin(catalog, load_ignore_rules(first))
        ensure_ignore_rules_pin(catalog, load_ignore_rules(first), repin=True)


def test_report_drift_section_matches_audit_entry(
    workspace: Paths, fixture_files, secret_store
):
    source = fixture_files["sqlite"]
    policy = load_policy(EXAMPLE)
    assert _drift_for(workspace, source) is None

    conn = sqlite3.connect(source)
    conn.execute(
        "UPDATE customers SET phone = 'user' || customer_id || '@example.invalid'"
    )
    conn.commit()
    conn.close()

    summary = scan_paths([source], workspace)[0]
    assert summary.drift is not None
    result = execute_run(
        summary.inventory, policy, workspace, secrets_store=secret_store
    )
    artifacts = finalize_run(
        workspace,
        summary.inventory,
        policy,
        result,
        summary.findings,
        drift_comparison=summary.drift,
    )
    report = json.loads(artifacts["report"]["json"].read_text(encoding="utf-8"))
    entries = read_audit_entries(workspace.audit_path)
    drift_entry = next(entry for entry in entries if entry.get("kind") == "drift_comparison")

    assert report["drift"]["audit_seq"] == drift_entry["seq"]
    assert report["drift"]["audit_entry_hash"] == drift_entry["entry_hash"]
    assert report["drift"]["drifts"] == drift_entry["drifts"]
    assert report["drift"]["ignored_drifts"] == drift_entry["ignored_drifts"]
    assert report["drift"]["summary"] == drift_entry["summary"]
    assert "跨版本漂移检测" in artifacts["report"]["markdown"].read_text(encoding="utf-8")
    assert verify_registry_drift_records(workspace) == 1
    AuditLog(workspace.audit_path).verify()


def test_tampering_either_audit_or_catalog_drift_record_is_detected(tmp_path):
    paths = Paths.for_workspace(tmp_path / "workspace")
    paths.ensure_runtime_dirs()
    fixtures = generate_fixture(paths.raw_dir, seed=7, customers=6, orders=9, leads=3)
    source = fixtures["sqlite"]
    scan_paths([source], paths)

    conn = sqlite3.connect(source)
    conn.execute(
        "UPDATE customers SET phone = 'user' || customer_id || '@example.invalid'"
    )
    conn.commit()
    conn.close()
    drift = scan_paths([source], paths)[0].drift
    with Catalog(paths.meta_db) as catalog:
        record = record_drift_comparison(paths, catalog, drift)
    assert AuditLog(paths.audit_path).verify().entries == 1

    # Tampering the catalog mirror is caught by the audit cross-check.
    conn = sqlite3.connect(paths.meta_db)
    conn.execute(
        "UPDATE drift_comparisons SET drifts_json = ? WHERE audit_seq = ?",
        ('[{"drift_type": "forged"}]', record.audit_entry["seq"]),
    )
    conn.commit()
    conn.close()
    with pytest.raises(AuditIntegrityError, match="differs from the audit entry"):
        verify_registry_drift_records(paths)

    # Tampering the append-only entry itself is caught by the hash chain.
    lines = paths.audit_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["summary"]["total"] = 100
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    paths.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="hash does not match"):
        verify_audit(paths.audit_path)


def test_comparison_reads_only_registry_not_dataset_content(
    tmp_path, monkeypatch
):
    paths = Paths.for_workspace(tmp_path / "workspace")
    paths.ensure_runtime_dirs()
    source = tmp_path / "dataset.sqlite"
    conn = sqlite3.connect(source)
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, phone TEXT)")
    conn.execute("INSERT INTO t (phone) VALUES ('13800000000')")
    conn.commit()
    conn.close()
    inventory = None

    with Catalog(paths.meta_db) as catalog:
        # Seed two versions directly; no dataset scan is needed for comparison.
        for fingerprint, columns, sensitive_type, hit in (
            ("v1", (("id", "INTEGER"), ("phone", "TEXT")), "mobile_phone", 0.9),
            ("v2", (("id", "INTEGER"), ("phone", "TEXT")), "email", 0.9),
        ):
            catalog.conn.execute(
                "INSERT INTO datasets VALUES (?,?,?,?,?,?,?)",
                (
                    fingerprint,
                    str(source.resolve()),
                    "sqlite",
                    source.stat().st_size,
                    1,
                    json.dumps(_schema(*columns)["tables"], ensure_ascii=False),
                    "2024-01-01T00:00:00+00:00",
                ),
            )
            catalog.conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    fingerprint,
                    "t",
                    "phone",
                    sensitive_type,
                    "high",
                    hit,
                    hit,
                    1.0,
                    1,
                    "[]",
                    "2024-01-01T00:00:00+00:00",
                ),
            )
        catalog.conn.commit()

        import maskline.dataset_io as dataset_io

        def forbidden(*_args, **_kwargs):
            raise AssertionError("comparison must not read dataset content")

        monkeypatch.setattr(dataset_io, "read_column_samples", forbidden)
        monkeypatch.setattr(dataset_io, "iter_table_rows", forbidden)
        comparison = evaluate_version_drift(catalog, source, "v2")
        assert comparison is not None
        assert [item.column for item in comparison.drifts] == ["phone"]


def test_full_comparison_is_far_below_15_percent_of_scan_time(tmp_path):
    paths = Paths.for_workspace(tmp_path / "workspace")
    paths.ensure_runtime_dirs()
    source = tmp_path / "large.sqlite"
    rows = 60_000
    conn = sqlite3.connect(source)
    conn.execute(
        "CREATE TABLE big (id INTEGER PRIMARY KEY, phone TEXT, email TEXT, "
        "name TEXT, amount REAL, note TEXT)"
    )
    conn.executemany(
        "INSERT INTO big VALUES (?,?,?,?,?,?)",
        (
            (
                index,
                "138%08d" % index,
                "user%d@example.invalid" % index,
                "张" + str(index),
                index % 1000,
                "note",
            )
            for index in range(1, rows + 1)
        ),
    )
    conn.commit()
    conn.close()

    started = time.perf_counter()
    scan_paths([source], paths)
    scan_seconds = time.perf_counter() - started

    conn = sqlite3.connect(source)
    conn.execute("ALTER TABLE big ADD COLUMN emergency_phone TEXT")
    conn.executemany(
        "UPDATE big SET emergency_phone = ? WHERE id = ?",
        (("139%08d" % index, index) for index in range(1, rows + 1)),
    )
    conn.commit()
    conn.close()
    summary = scan_paths([source], paths)[0]
    assert summary.drift is not None

    with Catalog(paths.meta_db) as catalog:
        started = time.perf_counter()
        # Full comparison over every persisted column for both versions.
        evaluate_version_drift(catalog, source, summary.inventory.fingerprint)
        compare_seconds = time.perf_counter() - started

    assert scan_seconds > 0
    assert compare_seconds <= 0.15 * scan_seconds
