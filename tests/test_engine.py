import pytest

from maskline.dataset_io import read_column_samples
from maskline.detectors.engine import analyze_column, analyze_values, detect_inventory
from maskline.detectors.engine import scan_inventory
from maskline.registry import Catalog

def _values(inventory, table, column):
    return read_column_samples(inventory.path, inventory.kind, table, column, 200)

@pytest.mark.parametrize(
    "table,column,expected",
    [
        ("customers", "full_name", "person_name"),
        ("customers", "phone", "mobile_phone"),
        ("customers", "email", "email"),
        ("customers", "id_card", "id_card"),
        ("customers", "bank_card", "bank_card"),
        ("customers", "address", "address"),
        ("orders", "ip_address", "ipv4"),
        ("orders", "contact_phone", "mobile_phone"),
    ],
)

def test_known_sensitive_columns_are_detected(inventories, table, column, expected):
    result = analyze_column(
        _values(inventories["sqlite"], table, column), table=table, column=column
    )
    assert result.sensitive_type == expected
    assert result.confidence in {"high", "medium"}
    assert result.score == pytest.approx(1.0)

def test_csv_credit_code_is_detected(inventories):
    values = _values(inventories["csv"], "leads", "company_code")
    result = analyze_column(values, table="leads", column="company_code")
    assert result.sensitive_type == "credit_code"
    assert result.validate_rate == 1.0

@pytest.mark.parametrize(
    "table,column",
    [
        ("customers", "customer_id"),
        ("customers", "age"),
        ("customers", "status"),
        ("customers", "notes"),
        ("orders", "order_id"),
        ("orders", "amount"),
        ("orders", "status"),
    ],
)

def test_non_sensitive_columns_do_not_false_positive(inventories, table, column):
    result = analyze_column(_values(inventories["sqlite"], table, column))
    assert result.sensitive_type is None
    assert result.confidence == "none"

def test_csv_identifier_and_stage_are_not_flagged(inventories):
    assert analyze_column(_values(inventories["csv"], "leads", "lead_id")).sensitive_type is None
    assert analyze_column(_values(inventories["csv"], "leads", "stage")).sensitive_type is None

def test_score_is_hit_rate_times_validation_rate():
    result = analyze_values(["13800000000", "not-a-phone", "13900000000", "x"])
    assert result.sensitive_type == "mobile_phone"
    assert result.hit_rate == 0.5
    assert result.validate_rate == 1.0
    assert result.score == 0.5
    assert result.confidence == "medium"

def test_failed_checksum_lowers_confidence():
    result = analyze_values(["4111111111111112"] * 6 + ["4111111111111111"] * 4)
    assert result.sensitive_type == "bank_card"
    assert result.validate_rate == pytest.approx(0.4)
    assert result.confidence in {"low", "medium"}

def test_empty_and_invalid_values_are_safe():
    assert analyze_values([]).confidence == "none"
    assert analyze_values([None, "", "  "]).sample_size == 0
    assert analyze_column([None, 123, b"bytes"]).confidence == "none"

def test_scan_persists_findings_and_registration_is_idempotent(workspace, inventories):
    inventory = inventories["sqlite"]
    with Catalog(workspace.meta_db) as catalog:
        assert catalog.register(inventory) is True
        assert catalog.register(inventory) is False
        findings = scan_inventory(inventory, catalog)
        stored = catalog.findings_for(inventory.fingerprint)
        assert len(stored) == len(findings)
        # One column-level row per column, plus extra rows for JSON paths.
        column_level = [item for item in stored if not item.get("json_path")]
        assert len(column_level) == sum(len(table.columns) for table in inventory.tables)
        assert {item["column_name"] for item in stored} >= {"phone", "id_card"}
        assert any(item.get("json_path") for item in stored)
        assert len(catalog.list_datasets()) == 1

def test_detect_inventory_is_pure(workspace, inventories):
    inventory = inventories["sqlite"]
    findings = detect_inventory(inventory)
    column_level = [item for item in findings if not item.get("json_path")]
    assert len(column_level) == sum(
        len(table.columns) for table in inventory.tables
    )
    assert any(item.get("json_path") for item in findings)
    with Catalog(workspace.meta_db) as catalog:
        assert catalog.findings_for(inventories["sqlite"].fingerprint) == []
