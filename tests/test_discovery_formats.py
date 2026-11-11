"""Regression tests for format-tolerant discovery and legacy registries."""

from __future__ import annotations

import csv
import hashlib
import json
import random
import sqlite3
from datetime import date
from pathlib import Path

import pytest

from maskline.dataset_io import detect_csv_encoding
from maskline.detectors.engine import analyze_values, detect_inventory, scan_inventory
from maskline.fixturegen import synthetic_id_card
from maskline.registry import Catalog, inspect_dataset

PHONE_FORMATS = [
    "13800138000",
    "138 0013 8000",
    "138-0013-8000",
    "+86 138 0013 8000",
    "+8613800138000",
    "8613800138000",
    "0086 138 0013 8000",
    "0086-138-0013-8000",
    "(+86) 138-0013-8000",
    "＋８６　１３８－００１３－８０００",
    "联系电话：+86 138 0013 8000",
    "手机号：138 0013 8000",
]


@pytest.mark.parametrize("phone", PHONE_FORMATS)
def test_phone_presentation_formats_are_detected(phone):
    result = analyze_values([phone])
    assert result.sensitive_type == "mobile_phone"
    assert result.confidence in {"high", "medium"}
    assert result.score == pytest.approx(1.0)


def test_mixed_phone_formats_have_no_misses():
    result = analyze_values(PHONE_FORMATS)
    assert result.sensitive_type == "mobile_phone"
    assert result.hit_rate == 1.0


def test_address_with_numeric_door_numbers_is_not_an_id_card():
    values = [
        "北京市朝阳区建国路88号院3号楼2单元1801室",
        "上海市浦东新区世纪大道100号2101室",
        "广东省深圳市南山区科技园路18号A栋501室",
        # A numeric run embedded in address text must not be mined as an ID.
        "北京市朝阳区建国路88号院110101199001011234室",
    ]
    result = analyze_values(values)
    assert result.sensitive_type == "address"
    assert all(item.sensitive_type != "id_card" for item in result.candidates)


def test_pure_id_cards_are_still_detected():
    rng = random.Random(7)
    value = synthetic_id_card(rng, date(1990, 1, 1))
    result = analyze_values([value] * 10)
    assert result.sensitive_type == "id_card"
    assert result.score == pytest.approx(1.0)


def _write_csv(path: Path, rows: list[list[str]], encoding: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding=encoding, newline="") as handle:
        csv.writer(handle).writerows(rows)


def test_gbk_and_utf8_bom_csv_scan_the_same(tmp_path):
    rows = [
        ["id", "name", "mobile", "address"],
        ["1", "张三", "+86 138 0013 8000", "北京市朝阳区建国路88号院3号楼1801室"],
        ["2", "李四", "138-0013-8001", "上海市浦东新区世纪大道100号2101室"],
        ["3", "王五", "13800138002", "广东省深圳市南山区科技园路18号A栋501室"],
    ]
    paths = {
        "utf8": tmp_path / "utf8" / "data.csv",
        "gbk": tmp_path / "gbk" / "data.csv",
        "bom": tmp_path / "bom" / "data.csv",
    }
    _write_csv(paths["utf8"], rows, "utf-8")
    _write_csv(paths["gbk"], rows, "gbk")
    _write_csv(paths["bom"], rows, "utf-8-sig")

    findings = {}
    fingerprints = set()
    for name, path in paths.items():
        inventory = inspect_dataset(path)
        fingerprints.add(inventory.fingerprint)
        findings[name] = [
            (item["column_name"], item["sensitive_type"], item["score"])
            for item in detect_inventory(inventory)
        ]
    assert fingerprints == {inspect_dataset(paths["utf8"]).fingerprint}
    assert findings["gbk"] == findings["utf8"] == findings["bom"]
    assert detect_csv_encoding(paths["gbk"]) in {"gbk", "gb18030"}


def test_repeated_scans_produce_identical_finding_records(tmp_path):
    rows = [
        ["id", "mobile", "address"],
        ["1", "138 0013 8000", "北京市朝阳区建国路88号"],
        ["2", "+86 138-0013-8001", "上海市浦东新区世纪大道100号"],
    ]
    path = tmp_path / "data.csv"
    _write_csv(path, rows, "gbk")
    inventory = inspect_dataset(path)
    catalog_path = tmp_path / "meta.sqlite"
    with Catalog(catalog_path) as catalog:
        catalog.register(inventory)
        first = scan_inventory(inventory, catalog)
        stored_first = catalog.findings_for(inventory.fingerprint)
        second = scan_inventory(inventory, catalog)
        stored_second = catalog.findings_for(inventory.fingerprint)
    canonical = lambda value: hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert canonical(first) == canonical(second)
    assert canonical(stored_first) == canonical(stored_second)


def test_legacy_registry_is_migrated_and_remains_scannable(tmp_path):
    meta = tmp_path / "meta.sqlite"
    conn = sqlite3.connect(meta)
    conn.executescript(
        """
        CREATE TABLE datasets (
            fingerprint TEXT PRIMARY KEY,
            path TEXT,
            kind TEXT,
            size_bytes INTEGER,
            row_count INTEGER
        );
        CREATE TABLE findings (
            dataset_fingerprint TEXT,
            table_name TEXT,
            column_name TEXT,
            sensitive_type TEXT,
            confidence TEXT NOT NULL,
            score REAL
        );
        INSERT INTO datasets VALUES ('legacy', 'old/data.csv', 'csv', 10, 1);
        INSERT INTO findings VALUES ('legacy', 't', 'c', 'mobile_phone', 'high', 1.0);
        """
    )
    conn.commit()
    conn.close()

    with Catalog(meta) as catalog:
        assert catalog.get_dataset("legacy") is not None
        assert catalog.findings_for("legacy")[0]["sensitive_type"] == "mobile_phone"

    rows = [
        ["id", "mobile", "address"],
        ["1", "+86 138 0013 8000", "北京市朝阳区建国路88号"],
    ]
    path = tmp_path / "data.csv"
    _write_csv(path, rows, "gbk")
    inventory = inspect_dataset(path)
    with Catalog(meta) as catalog:
        assert catalog.register(inventory) is True
        scan_inventory(inventory, catalog)
        stored = catalog.findings_for(inventory.fingerprint)
    assert {item["column_name"] for item in stored} == {"id", "mobile", "address"}
    assert {item["sensitive_type"] for item in stored} == {
        None,
        "mobile_phone",
        "address",
    }
