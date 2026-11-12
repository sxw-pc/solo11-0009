"""Incremental scan: fingerprint reuse, column-level changes, migration, crash safety."""

from __future__ import annotations

import json
import sqlite3

import pytest

from maskline.detectors import incremental
from maskline.detectors.engine import scan_inventory
from maskline.registry import (
    DETECTOR_VERSION,
    Catalog,
    RegistryVersionError,
    inspect_dataset,
    stable_dataset_id,
)


# --------------------------------------------------------------------- helpers


def _open_rw(path):
    return sqlite3.connect(path)


def _baseline_scan(workspace, dataset_path, sample_limit=200):
    inventory = inspect_dataset(dataset_path)
    with Catalog(workspace.meta_db) as catalog:
        result = scan_inventory(inventory, catalog, sample_limit=sample_limit)
        findings = catalog.findings_for(inventory.fingerprint)
    return inventory, result, findings


def _rescan(workspace, dataset_path):
    inventory = inspect_dataset(dataset_path)
    with Catalog(workspace.meta_db) as catalog:
        result = scan_inventory(inventory, catalog)
        findings = catalog.findings_for(inventory.fingerprint)
        plans = {p.table.name: p for p in result.plans}
    return inventory, result, findings, plans


# ------------------------------------------------------------- unchanged reuse


def test_unchanged_dataset_reuses_every_table_byte_for_byte(workspace, fixture_files):
    inventory, first, first_findings = _baseline_scan(workspace, fixture_files["sqlite"])
    assert first.scanned_columns > 0
    assert first.reused_tables == 0

    _inv, second, second_findings, plans = _rescan(workspace, fixture_files["sqlite"])

    assert second.reused_tables == first.total_tables
    assert second.scanned_columns == 0
    assert second.reused_columns == sum(len(t.columns) for t in inventory.tables)
    # Findings of untouched tables must be byte-identical, updated_at included.
    assert second_findings == first_findings
    assert {p.action for p in second.plans} == {incremental.ACTION_REUSE}


def test_unchanged_scan_does_not_sample_data(workspace, fixture_files, monkeypatch):
    _baseline_scan(workspace, fixture_files["sqlite"])
    calls = []

    def boom(*args, **kwargs):  # pragma: no cover - must never be called
        calls.append(args)
        raise AssertionError("unchanged tables must not be resampled")

    monkeypatch.setattr(incremental, "read_column_samples", boom)
    _inv, result, _f, _plans = _rescan(workspace, fixture_files["sqlite"])
    assert calls == []
    assert result.scanned_columns == 0


def test_repeated_rescan_is_stable(workspace, fixture_files):
    _baseline_scan(workspace, fixture_files["sqlite"])
    previous = None
    for _ in range(3):
        _inv, _result, findings, _plans = _rescan(workspace, fixture_files["sqlite"])
        if previous is not None:
            assert findings == previous
        previous = findings


# ------------------------------------------------------------- added column


def test_added_column_is_detected_and_scanned_alone(workspace, fixture_files):
    inventory, _first, first_findings = _baseline_scan(
        workspace, fixture_files["sqlite"]
    )
    customers_before = {
        f["column_name"]: f
        for f in first_findings
        if f["table_name"] == "customers"
    }

    conn = _open_rw(fixture_files["sqlite"])
    try:
        conn.execute("ALTER TABLE customers ADD COLUMN extra_email TEXT")
        conn.execute(
            "UPDATE customers SET extra_email = 'added@example.invalid' "
            "WHERE rowid <= 3"
        )
        conn.commit()
    finally:
        conn.close()

    _inv, result, findings, plans = _rescan(workspace, fixture_files["sqlite"])
    customers_plan = plans["customers"]
    assert customers_plan.action == incremental.ACTION_RESCAN_COLUMNS
    assert customers_plan.columns_to_scan == ["extra_email"]
    # The other table is untouched.
    assert plans["orders"].action == incremental.ACTION_REUSE

    after = {(f["table_name"], f["column_name"]): f for f in findings}
    new_finding = after[("customers", "extra_email")]
    assert new_finding["sensitive_type"] == "email"
    # Existing columns: records reused verbatim.
    for name, old in customers_before.items():
        assert after[("customers", name)] == old


def test_added_column_keeps_all_other_findings_byte_identical(workspace, fixture_files):
    _inv, _first, first_findings = _baseline_scan(workspace, fixture_files["sqlite"])
    conn = _open_rw(fixture_files["sqlite"])
    try:
        conn.execute("ALTER TABLE orders ADD COLUMN note TEXT")
        conn.commit()
    finally:
        conn.close()

    _inv2, _result, second_findings, _plans = _rescan(
        workspace, fixture_files["sqlite"]
    )
    first_map = {(f["table_name"], f["column_name"]): f for f in first_findings}
    second_map = {(f["table_name"], f["column_name"]): f for f in second_findings}
    for key, old in first_map.items():
        assert second_map[key] == old
    assert ("orders", "note") in second_map


# ------------------------------------------------------------- dropped column


def test_dropped_column_removes_its_finding(workspace, fixture_files):
    _baseline_scan(workspace, fixture_files["sqlite"])
    conn = _open_rw(fixture_files["sqlite"])
    try:
        conn.execute("ALTER TABLE customers DROP COLUMN notes")
        conn.commit()
    finally:
        conn.close()

    _inv, result, findings, plans = _rescan(workspace, fixture_files["sqlite"])
    plan = plans["customers"]
    assert plan.action == incremental.ACTION_RESCAN_COLUMNS
    names = {f["column_name"] for f in findings if f["table_name"] == "customers"}
    assert "notes" not in names
    assert "phone" in names
    # orders table fully reused.
    assert plans["orders"].action == incremental.ACTION_REUSE


# ------------------------------------------------------------- row count change


def test_doubled_rows_triggers_table_rescan(workspace, fixture_files):
    inventory, first, first_findings = _baseline_scan(
        workspace, fixture_files["sqlite"]
    )
    conn = _open_rw(fixture_files["sqlite"])
    try:
        cols = [r[1] for r in conn.execute('PRAGMA table_info("orders")')]
        select = ", ".join(f'"{c}"' for c in cols)
        rows = conn.execute(f"SELECT {select} FROM orders").fetchall()
        # Offset the primary key so the copies do not violate uniqueness.
        id_idx = cols.index("order_id")
        copies = [
            tuple(1_000_000 + value if i == id_idx else value for i, value in enumerate(row))
            for row in rows
        ]
        placeholders = ", ".join("?" for _ in cols)
        conn.executemany(
            f'INSERT INTO orders ({select}) VALUES ({placeholders})', copies
        )
        conn.commit()
    finally:
        conn.close()

    _inv, result, findings, plans = _rescan(workspace, fixture_files["sqlite"])
    orders_plan = plans["orders"]
    assert orders_plan.action == incremental.ACTION_RESCAN_TABLE
    assert "row count changed significantly" in orders_plan.reason
    assert orders_plan.columns_to_scan == [c.name for c in inventory.table("orders").columns]
    assert plans["customers"].action == incremental.ACTION_REUSE
    # customers findings still byte-identical.
    first_customers = [f for f in first_findings if f["table_name"] == "customers"]
    second_customers = [f for f in findings if f["table_name"] == "customers"]
    assert first_customers == second_customers


def test_small_row_change_below_threshold_is_column_localized(workspace, fixture_files):
    _baseline_scan(workspace, fixture_files["sqlite"])
    conn = _open_rw(fixture_files["sqlite"])
    try:
        # 9 -> 10 rows: an 11% change, below the default 50% threshold.
        conn.execute(
            "INSERT INTO orders VALUES (999, 1, 'ORD-99999', 1.0, "
            "'192.0.2.9', '13800000000', '2024-06-01 00:00:00', 'new')"
        )
        conn.commit()
    finally:
        conn.close()

    _inv, result, _findings, plans = _rescan(workspace, fixture_files["sqlite"])
    plan = plans["orders"]
    assert plan.action == incremental.ACTION_RESCAN_COLUMNS
    # Every column's content hash moved (one appended row each), but no full rescan.
    assert set(plan.columns_to_scan) == {
        c.name for c in _inv.table("orders").columns
    }


# ------------------------------------------------------------- value-only change


def test_value_change_with_same_shape_localizes_to_column(workspace, fixture_files):
    _baseline_scan(workspace, fixture_files["sqlite"])
    conn = _open_rw(fixture_files["sqlite"])
    try:
        conn.execute("UPDATE customers SET status = 'vip' WHERE rowid = 1")
        conn.commit()
    finally:
        conn.close()

    _inv, result, _findings, plans = _rescan(workspace, fixture_files["sqlite"])
    plan = plans["customers"]
    assert plan.action == incremental.ACTION_RESCAN_COLUMNS
    assert plan.columns_to_scan == ["status"]
    assert plans["orders"].action == incremental.ACTION_REUSE


# ------------------------------------------------------------- force full scan


def test_force_full_rescans_everything(workspace, fixture_files):
    _baseline_scan(workspace, fixture_files["sqlite"])
    inventory = inspect_dataset(fixture_files["sqlite"])
    with Catalog(workspace.meta_db) as catalog:
        result = scan_inventory(inventory, catalog, force_full=True)
    assert result.reused_tables == 0
    assert result.scanned_columns == sum(len(t.columns) for t in inventory.tables)
    assert all(p.action == incremental.ACTION_RESCAN_TABLE for p in result.plans)


# ------------------------------------------------------------- sample limit / detector version


def test_changed_sample_limit_invalidates_cache(workspace, fixture_files):
    _baseline_scan(workspace, fixture_files["sqlite"], sample_limit=200)
    inventory = inspect_dataset(fixture_files["sqlite"])
    with Catalog(workspace.meta_db) as catalog:
        result = scan_inventory(inventory, catalog, sample_limit=50)
    assert all(p.action == incremental.ACTION_RESCAN_TABLE for p in result.plans)
    # And a rerun at the new limit reuses.
    with Catalog(workspace.meta_db) as catalog:
        again = scan_inventory(inventory, catalog, sample_limit=50)
    assert again.reused_tables == again.total_tables


# ------------------------------------------------------------- Ctrl-C safety


def test_interrupted_scan_leaves_no_partial_state(workspace, fixture_files, monkeypatch):
    _baseline_scan(workspace, fixture_files["sqlite"])
    baseline_findings = None
    with Catalog(workspace.meta_db) as catalog:
        baseline_findings = catalog.findings_for_dataset(
            stable_dataset_id(fixture_files["sqlite"])
        )
        baseline_tables = catalog.table_states(
            stable_dataset_id(fixture_files["sqlite"])
        )

    # Modify the dataset, then kill the scan mid-way through scoring.
    conn = _open_rw(fixture_files["sqlite"])
    try:
        conn.execute("ALTER TABLE customers ADD COLUMN extra_phone TEXT")
        conn.execute(
            "UPDATE customers SET extra_phone='13900000001' WHERE rowid <= 2"
        )
        conn.commit()
    finally:
        conn.close()

    real_score = incremental._score_column
    calls = {"n": 0}

    def flaky(inventory, table, column_name, sample_limit):
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyboardInterrupt
        return real_score(inventory, table, column_name, sample_limit)

    monkeypatch.setattr(incremental, "_score_column", flaky)
    inventory = inspect_dataset(fixture_files["sqlite"])
    with Catalog(workspace.meta_db) as catalog:
        with pytest.raises(KeyboardInterrupt):
            scan_inventory(inventory, catalog)

    # The transaction rolled back: no running scan, no partial fingerprints.
    with Catalog(workspace.meta_db) as catalog:
        assert catalog.reap_stale_scans() == 0
        running = catalog.conn.execute(
            "SELECT COUNT(*) FROM scan_runs WHERE status='running'"
        ).fetchone()[0]
        assert running == 0
        dataset_id = stable_dataset_id(fixture_files["sqlite"])
        assert catalog.table_states(dataset_id) == baseline_tables
        assert catalog.findings_for_dataset(dataset_id) == baseline_findings

    # Next scan works normally and applies the pending change.
    monkeypatch.undo()
    _inv, result, findings, plans = _rescan(workspace, fixture_files["sqlite"])
    plan = plans["customers"]
    assert plan.action == incremental.ACTION_RESCAN_COLUMNS
    assert plan.columns_to_scan == ["extra_phone"]


# ------------------------------------------------------------- v1 migration


def _build_v1_registry(db_path, dataset_path):
    """Reproduce the pre-upgrade registry layout by hand."""
    inventory = inspect_dataset(dataset_path)
    record = inventory.to_record()
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE datasets (
                fingerprint TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                kind TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                row_count INTEGER NOT NULL,
                tables_json TEXT NOT NULL,
                registered_at TEXT NOT NULL
            );
            CREATE TABLE findings (
                dataset_fingerprint TEXT NOT NULL,
                table_name TEXT NOT NULL,
                column_name TEXT NOT NULL,
                sensitive_type TEXT,
                confidence TEXT NOT NULL DEFAULT 'none',
                score REAL NOT NULL DEFAULT 0,
                hit_rate REAL NOT NULL DEFAULT 0,
                validate_rate REAL NOT NULL DEFAULT 0,
                sample_size INTEGER NOT NULL DEFAULT 0,
                candidates_json TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT NOT NULL,
                PRIMARY KEY (dataset_fingerprint, table_name, column_name)
            );
            """
        )
        conn.execute(
            "INSERT INTO datasets VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                inventory.fingerprint,
                record["path"],
                record["kind"],
                record["size_bytes"],
                record["row_count"],
                json.dumps(record["tables"], ensure_ascii=False),
                "2026-01-01T00:00:00+00:00",
            ),
        )
        conn.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                inventory.fingerprint,
                "customers",
                "phone",
                "mobile_phone",
                "high",
                1.0,
                1.0,
                1.0,
                6,
                json.dumps([{"sensitive_type": "mobile_phone"}], ensure_ascii=False),
                "2026-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return inventory


def test_v1_registry_migrates_without_crashing(workspace, fixture_files):
    db = workspace.meta_db
    inventory = _build_v1_registry(db, fixture_files["sqlite"])

    with Catalog(db) as catalog:  # migration happens on open
        meta = catalog.conn.execute(
            "SELECT schema_version, migrated_from FROM schema_meta"
        ).fetchone()
        assert tuple(meta) == (2, 1)
        dataset_id = stable_dataset_id(inventory.path)
        state = catalog.dataset_state(dataset_id)
        assert state is not None
        # Migrated findings survive the upgrade.
        findings = catalog.findings_for_dataset(dataset_id)
        assert len(findings) == 1
        assert findings[0]["column_name"] == "phone"
        assert findings[0]["confidence"] == "high"
        # v1 tables are retained untouched.
        legacy = catalog.conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]
        assert legacy == 1
        # The migrated table has no v2 content hashes: first scan is a full
        # rescan rather than trusting incomplete fingerprints.
        tables = catalog.table_states(dataset_id)
        assert tables["customers"]["content_fingerprint"] == ""
        assert tables["customers"]["detector_version"] is None

        result = scan_inventory(inventory, catalog)
        assert all(p.action == incremental.ACTION_RESCAN_TABLE for p in result.plans)
        full_findings = catalog.findings_for_dataset(dataset_id)
        assert len(full_findings) == 20

    # Second scan on the migrated DB is fully incremental.
    with Catalog(db) as catalog:
        again = scan_inventory(inspect_dataset(inventory.path), catalog)
        assert again.reused_tables == again.total_tables


def test_newer_schema_version_is_rejected_clearly(workspace, fixture_files):
    db = workspace.meta_db
    _build_v1_registry(db, fixture_files["sqlite"])
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, schema_version INTEGER, "
            "migrated_from INTEGER, updated_at TEXT)"
        )
        conn.execute(
            "INSERT INTO schema_meta VALUES ('version', 99, NULL, '2026-01-01')"
        )
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(RegistryVersionError, match="newer maskline"):
        Catalog(db)


def test_migration_failure_keeps_v1_data_intact(workspace, fixture_files, monkeypatch):
    db = workspace.meta_db
    inventory = _build_v1_registry(db, fixture_files["sqlite"])

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("simulated migration failure")

    # Fail inside the data-copy transaction (DDL itself has already run).
    import maskline.registry as registry_module

    monkeypatch.setattr(registry_module, "stable_dataset_id", fail)
    with pytest.raises(sqlite3.OperationalError):
        Catalog(db)

    # The whole migration (DDL included) rolled back: only v1 tables remain and
    # their data is untouched. Opening again retries the migration successfully.
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        names = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "schema_meta" not in names
        assert "dataset_records" not in names
    finally:
        conn.close()
    monkeypatch.undo()
    with Catalog(db) as catalog:
        assert catalog.dataset_state(stable_dataset_id(inventory.path)) is not None


# ------------------------------------------------------------- new dataset / tables


def test_new_table_in_known_dataset_is_scanned(workspace, fixture_files):
    _baseline_scan(workspace, fixture_files["sqlite"])
    conn = _open_rw(fixture_files["sqlite"])
    try:
        conn.execute(
            "CREATE TABLE extras (id INTEGER PRIMARY KEY, contact_email TEXT)"
        )
        conn.executemany(
            "INSERT INTO extras VALUES (?, ?)",
            [(1, "a@example.invalid"), (2, "b@example.invalid")],
        )
        conn.commit()
    finally:
        conn.close()

    _inv, result, findings, plans = _rescan(workspace, fixture_files["sqlite"])
    assert plans["extras"].action == incremental.ACTION_NEW_TABLE
    assert result.new_tables == 1
    assert plans["customers"].action == incremental.ACTION_REUSE
    extras = [f for f in findings if f["table_name"] == "extras"]
    assert {f["column_name"] for f in extras} == {"id", "contact_email"}
    assert next(
        f for f in extras if f["column_name"] == "contact_email"
    )["sensitive_type"] == "email"


def test_csv_dataset_is_incremental_too(workspace, fixture_files):
    inventory, first, first_findings = _baseline_scan(workspace, fixture_files["csv"])
    assert first.total_tables == 1
    _inv, second, second_findings, plans = _rescan(workspace, fixture_files["csv"])
    assert second.reused_tables == 1
    assert second_findings == first_findings
    table_name = inventory.tables[0].name
    assert plans[table_name].action == incremental.ACTION_REUSE
