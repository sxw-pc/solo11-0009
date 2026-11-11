import sqlite3
import secrets
import threading

import pytest

from maskline.pseudomap import PseudoMap, PseudoMapError, PseudonymCollision
from maskline.transformers.pseudonym import pseudonym_token

TEST_KEY = secrets.token_urlsafe(32)

def test_put_get_reveal_and_persistence(tmp_path):
    path = tmp_path / "map.sqlite"
    token = pseudonym_token("张伟", TEST_KEY)
    with PseudoMap(path, create=True) as mapping:
        mapping.put(token, "张伟")
        mapping.put(token, "张伟")
        assert mapping.get(token) == "张伟"
        assert mapping.count() == 1
    with PseudoMap(path) as mapping:
        assert mapping.reveal(token) == "张伟"
        assert mapping.get("missing") is None
        assert list(mapping.iter_entries()) == [(token, "张伟")]

def test_collision_is_rejected(tmp_path):
    token = pseudonym_token("张伟", TEST_KEY)
    with PseudoMap(tmp_path / "map.sqlite", create=True) as mapping:
        mapping.put(token, "张伟")
        with pytest.raises(PseudonymCollision):
            mapping.put(token, "李娜")
        # The rejected write must not replace the original entry.
        assert mapping.reveal(token) == "张伟"
        assert mapping.count() == 1

def test_missing_mapping_file_and_token_errors(tmp_path):
    with pytest.raises(PseudoMapError, match="not found"):
        PseudoMap(tmp_path / "missing.sqlite")
    with PseudoMap(tmp_path / "map.sqlite", create=True) as mapping:
        with pytest.raises(PseudoMapError, match="token not found"):
            mapping.reveal("psn_missing")

def test_concurrent_writers_do_not_conflict_or_duplicate(tmp_path):
    path = tmp_path / "map.sqlite"
    PseudoMap(path, create=True).close()
    token = pseudonym_token("张伟", TEST_KEY)
    errors = []
    start = threading.Barrier(6)

    def worker():
        try:
            start.wait()
            with PseudoMap(path) as mapping:
                for _ in range(50):
                    mapping.put(token, "张伟")
        except Exception as exc:  # pragma: no cover - assertion helper
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    with PseudoMap(path) as mapping:
        assert mapping.count() == 1
        assert mapping.reveal(token) == "张伟"

def test_legacy_mapping_database_remains_compatible(tmp_path):
    path = tmp_path / "legacy.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE pseudonym_map ("
        "token TEXT PRIMARY KEY, plaintext TEXT NOT NULL, created_at TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO pseudonym_map (token, plaintext, created_at) VALUES (?, ?, ?)",
        ("psn_legacy", "历史值", "2020-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()
    with PseudoMap(path) as mapping:
        assert mapping.reveal("psn_legacy") == "历史值"
        mapping.put("psn_new", "新值")
        mapping.put("psn_new", "新值")
        assert mapping.count() == 2
        summary = mapping.summary()
        assert summary["inserted"] == 1
        assert summary["reused"] == 1
    with PseudoMap(path) as mapping:
        assert mapping.reveal("psn_legacy") == "历史值"
        assert mapping.reveal("psn_new") == "新值"

def test_legacy_mapping_without_created_at_is_upgraded_additively(tmp_path):
    path = tmp_path / "legacy-no-time.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE pseudonym_map (token TEXT PRIMARY KEY, plaintext TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO pseudonym_map (token, plaintext) VALUES (?, ?)",
        ("psn_legacy", "历史值"),
    )
    conn.commit()
    conn.close()
    with PseudoMap(path) as mapping:
        assert mapping.reveal("psn_legacy") == "历史值"
        mapping.put("psn_new", "新值")
        assert mapping.count() == 2

