import secrets
import sqlite3

import pytest

from maskline.config import DEFAULT_KID, PseudonymKey, SecretStore
from maskline.pseudomap import PseudoMap, PseudoMapError, PseudonymCollision
from maskline.transformers.pseudonym import pseudonym_token

TEST_KEY = secrets.token_urlsafe(32)


def _store(mapping: dict[str, str], current: str, tmp_path) -> SecretStore:
    keys = {
        kid: PseudonymKey(kid=kid, value=value, current=(kid == current))
        for kid, value in mapping.items()
    }
    return SecretStore(
        {"hmac_salt": secrets.token_urlsafe(32)},
        tmp_path / "memory-secret",
        pseudonym_keys=keys,
    )


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


def test_missing_mapping_file_and_token_errors(tmp_path):
    with pytest.raises(PseudoMapError, match="not found"):
        PseudoMap(tmp_path / "missing.sqlite")
    with PseudoMap(tmp_path / "map.sqlite", create=True) as mapping:
        with pytest.raises(PseudoMapError, match="token not found"):
            mapping.reveal("psn_missing")


def test_same_plaintext_under_two_kids_coexists_and_reveals_independently(tmp_path):
    key_a = secrets.token_urlsafe(32)
    key_b = secrets.token_urlsafe(32)
    store = _store({"k-a": key_a, "k-b": key_b}, "k-b", tmp_path)
    path = tmp_path / "map.sqlite"
    token_a = pseudonym_token("张伟", key_a)
    token_b = pseudonym_token("张伟", key_b)
    assert token_a != token_b
    with PseudoMap(path, create=True, current_kid="k-a") as mapping:
        assert mapping.put(token_a, "张伟", kid="k-a") == "k-a"
    # Reopen after rotation: new writes use the new current kid.
    with PseudoMap(path, current_kid="k-b") as mapping:
        mapping.put(token_b, "张伟")  # defaults to current kid k-b
        assert mapping.count() == 2
        assert set(mapping.kids_in_use()) == {"k-a", "k-b"}
        # Each row reveals via the key matching its own recorded kid.
        assert mapping.reveal(token_a, store) == "张伟"
        assert mapping.reveal(token_b, store) == "张伟"
        assert mapping.kid_for(token_a) == "k-a"
        assert mapping.kid_for(token_b) == "k-b"
        records = {(kid, token): pt for kid, token, pt in mapping.iter_records()}
        assert records[("k-a", token_a)] == "张伟"
        assert records[("k-b", token_b)] == "张伟"


def test_reveal_detects_wrong_key_for_recorded_kid(tmp_path):
    key_a = secrets.token_urlsafe(32)
    key_b = secrets.token_urlsafe(32)
    store = _store({"k-a": key_a, "k-b": key_b}, "k-a", tmp_path)
    token_a = pseudonym_token("张伟", key_a)
    with PseudoMap(tmp_path / "map.sqlite", create=True, current_kid="k-a") as mapping:
        mapping.put(token_a, "张伟", kid="k-a")
        with pytest.raises(PseudoMapError, match="does not verify against pseudonym key 'k-a'"):
            # A store whose k-a material does not match the row must be rejected.
            wrong = _store({"k-a": key_b}, "k-a", tmp_path)
            mapping.reveal(token_a, wrong)
        # The real store still verifies.
        assert mapping.reveal(token_a, store) == "张伟"


def test_missing_kid_in_store_blocks_reveal_with_a_clear_error(tmp_path):
    key_a = secrets.token_urlsafe(32)
    token = pseudonym_token("张伟", key_a)
    with PseudoMap(tmp_path / "map.sqlite", create=True, current_kid="k-a") as mapping:
        mapping.put(token, "张伟", kid="k-a")
    store = _store({"k-other": secrets.token_urlsafe(32)}, "k-other", tmp_path)
    with PseudoMap(tmp_path / "map.sqlite") as mapping:
        with pytest.raises(Exception, match="no pseudonym key with kid 'k-a'"):
            mapping.reveal(token, store)


def test_legacy_database_without_kid_opens_and_migrates_silently(tmp_path):
    path = tmp_path / "legacy.sqlite"
    legacy_key = secrets.token_urlsafe(32)
    token = pseudonym_token("李娜", legacy_key)
    # Build a database exactly as the pre-rotation version would have.
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE pseudonym_map (token TEXT PRIMARY KEY, plaintext TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO pseudonym_map (token, plaintext, created_at) VALUES (?, ?, ?)",
        (token, "李娜", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()
    # The new version must open it without raising and treat rows as default kid.
    with PseudoMap(path) as mapping:
        assert mapping.kids_in_use() == (DEFAULT_KID,)
        assert mapping.reveal(token) == "李娜"
        assert mapping.kid_for(token) == DEFAULT_KID
        assert mapping.count() == 1
    # A migrated, reopened DB accepts new-kid rows alongside legacy ones.
    new_key = secrets.token_urlsafe(32)
    store = _store({DEFAULT_KID: legacy_key, "k-new": new_key}, "k-new", tmp_path)
    new_token = pseudonym_token("李娜", new_key)
    with PseudoMap(path, current_kid="k-new") as mapping:
        mapping.put(new_token, "李娜")
        assert mapping.count() == 2
        assert mapping.reveal(token, store) == "李娜"
        assert mapping.reveal(new_token, store) == "李娜"
        assert set(mapping.kids_in_use()) == {DEFAULT_KID, "k-new"}


def test_legacy_flat_secret_reveals_migrated_legacy_rows(tmp_path):
    # End-to-end flavour: legacy secret file + legacy DB, new code opens both.
    secret_path = tmp_path / "legacy-secret.yaml"
    legacy_key = secrets.token_urlsafe(32)
    secret_path.write_text(
        f'hmac_salt: "{secrets.token_urlsafe(32)}"\npseudonym_key: "{legacy_key}"\n',
        encoding="utf-8",
    )
    store = SecretStore.from_file(secret_path)
    token = pseudonym_token("王芳", legacy_key)
    path = tmp_path / "map.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE pseudonym_map (token TEXT PRIMARY KEY, plaintext TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO pseudonym_map (token, plaintext, created_at) VALUES (?, ?, ?)",
        (token, "王芳", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()
    with PseudoMap(path) as mapping:
        assert mapping.reveal(token, store) == "王芳"
