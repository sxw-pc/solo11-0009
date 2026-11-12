from __future__ import annotations

import csv

from maskline.classification.tolerant import (
    inspect_tolerant,
    is_deep_column,
    leaf_token,
)


def _write(path, rows):
    with path.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerows(rows)


def test_headered_csv_is_not_mistaken_for_headerless(tmp_path):
    path = tmp_path / "headed.csv"
    _write(
        path,
        [
            ["full_name", "phone", "id_card"],
            ["王安宁", "13800138000", "999999197001010017"],
            ["李溪晨", "13900139000", "999999198512311238"],
        ],
    )
    tolerated = inspect_tolerant(path)
    assert tolerated.headerless is False
    assert tolerated.alerts == []
    assert [col.name for col in tolerated.inventory.tables[0].columns] == [
        "full_name",
        "phone",
        "id_card",
    ]


def test_headerless_csv_gets_synthetic_columns_and_alert(tmp_path):
    path = tmp_path / "no_header.csv"
    _write(
        path,
        [
            ["王安宁", "13800138000", "999999197001010017"],
            ["李溪晨", "13900139000", "999999198512311238"],
        ],
    )
    tolerated = inspect_tolerant(path)
    assert tolerated.headerless is True
    assert tolerated.alerts and tolerated.alerts[0].code == "headerless_file"
    assert [col.name for col in tolerated.inventory.tables[0].columns] == [
        "col_001",
        "col_002",
        "col_003",
    ]


def test_deep_nesting_helpers():
    assert is_deep_column("a.b.c.d")
    assert not is_deep_column("a.b.c")
    assert leaf_token("payload.user.contact.mobile") == "mobile"
    assert leaf_token("payload[0].name") == "name"
    assert leaf_token("plain") == "plain"


def test_deeply_nested_sqlite_column_is_flagged(tmp_path):
    import sqlite3

    db = tmp_path / "nested.sqlite"
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE t ("a.b.c.d" TEXT, plain TEXT)')
    conn.executemany("INSERT INTO t VALUES (?, ?)", [("x", "y"), ("p", "q")])
    conn.commit()
    conn.close()
    tolerated = inspect_tolerant(db, max_nesting_depth=3)
    codes = {alert.code for alert in tolerated.alerts}
    assert codes == {"nested_depth"}
    alert = tolerated.alerts[0]
    assert alert.table == "t" and alert.column == "a.b.c.d"
