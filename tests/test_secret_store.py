"""Multi-key secret store: versioned kids, rotation, and strict validation."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from maskline.config import (
    DEFAULT_KID,
    ConfigError,
    SecretStore,
    create_demo_secret,
    rotate_pseudonym_key,
)

LONG = "0123456789abcdef"  # exactly 16 chars, passes MIN_LENGTH


def write_secret(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "secret.yaml"
    path.write_text(textwrap_dedent(text), encoding="utf-8")
    return path


def textwrap_dedent(text: str) -> str:
    import textwrap

    return textwrap.dedent(text).lstrip()


VERSIONED = """
hmac_salt: "{salt}"
keys:
  - kid: "k1"
    value: "{v1}"
    current: true
  - kid: "k2"
    value: "{v2}"
    current: false
"""


def test_versioned_file_loads_all_kids_and_marks_current(tmp_path):
    path = write_secret(
        tmp_path,
        VERSIONED.format(salt=LONG, v1="a" * 32, v2="b" * 32),
    )
    store = SecretStore.from_file(path)
    assert store.kids() == ("k1", "k2")
    assert store.current_kid() == "k1"
    assert store.current_pseudonym_key().value == "a" * 32
    assert store.key_for("k2").value == "b" * 32
    # Backwards-compatible scalar access resolves to the current key.
    assert store.get("pseudonym_key") == "a" * 32
    assert store.get("hmac_salt") == LONG


def test_legacy_flat_file_is_exposed_under_default_kid(tmp_path):
    path = write_secret(
        tmp_path,
        f"""
        hmac_salt: "{LONG}"
        pseudonym_key: "{'c' * 32}"
        """,
    )
    store = SecretStore.from_file(path)
    assert store.kids() == (DEFAULT_KID,)
    assert store.current_kid() == DEFAULT_KID
    assert store.key_for(DEFAULT_KID).value == "c" * 32
    assert store.get("pseudonym_key") == "c" * 32


def test_missing_current_marker_errors_and_names_the_file(tmp_path):
    path = write_secret(
        tmp_path,
        f"""
        hmac_salt: "{LONG}"
        keys:
          - kid: "k1"
            value: "{'a' * 32}"
            current: false
        """,
    )
    with pytest.raises(ConfigError, match="marks no current pseudonym key") as exc:
        SecretStore.from_file(path)
    assert str(path) in str(exc.value)


def test_multiple_current_markers_list_the_offending_kids(tmp_path):
    path = write_secret(
        tmp_path,
        f"""
        hmac_salt: "{LONG}"
        keys:
          - kid: "k1"
            value: "{'a' * 32}"
            current: true
          - kid: "k2"
            value: "{'b' * 32}"
            current: true
        """,
    )
    with pytest.raises(ConfigError, match="multiple current pseudonym keys") as exc:
        SecretStore.from_file(path)
    message = str(exc.value)
    assert "k1" in message and "k2" in message


def test_duplicate_kid_is_rejected_with_the_kid_named(tmp_path):
    path = write_secret(
        tmp_path,
        f"""
        hmac_salt: "{LONG}"
        keys:
          - kid: "k1"
            value: "{'a' * 32}"
            current: true
          - kid: "k1"
            value: "{'b' * 32}"
            current: false
        """,
    )
    with pytest.raises(ConfigError, match="duplicate kid 'k1'"):
        SecretStore.from_file(path)


def test_missing_kid_and_bad_value_shape_are_rejected(tmp_path):
    bad_shape = write_secret(
        tmp_path,
        f"""
        hmac_salt: "{LONG}"
        keys:
          - value: "{'a' * 32}"
            current: true
        """,
    )
    with pytest.raises(ConfigError, match="missing a non-empty string 'kid'"):
        SecretStore.from_file(bad_shape)
    missing_value = write_secret(
        tmp_path,
        """
        hmac_salt: "0123456789abcdef"
        keys:
          - kid: "k1"
            current: true
        """,
    )
    with pytest.raises(ConfigError, match="kid 'k1' is missing a string 'value'"):
        SecretStore.from_file(missing_value)


def test_empty_keys_list_and_short_material_are_rejected(tmp_path):
    empty = write_secret(
        tmp_path,
        f"""
        hmac_salt: "{LONG}"
        keys: []
        """,
    )
    with pytest.raises(ConfigError, match="non-empty list"):
        SecretStore.from_file(empty)
    short = write_secret(
        tmp_path,
        """
        hmac_salt: "0123456789abcdef"
        keys:
          - kid: "k1"
            value: "short"
            current: true
        """,
    )
    with pytest.raises(ConfigError, match="too short"):
        SecretStore.from_file(short)


def test_placeholder_material_is_rejected(tmp_path):
    path = write_secret(
        tmp_path,
        """
        hmac_salt: "0123456789abcdef"
        keys:
          - kid: "k1"
            value: "REPLACE_ME_WITH_RANDOM_BYTES"
            current: true
        """,
    )
    with pytest.raises(ConfigError, match="placeholder"):
        SecretStore.from_file(path)


def test_reveal_with_unknown_kid_errors_clearly(tmp_path):
    path = write_secret(
        tmp_path,
        VERSIONED.format(salt=LONG, v1="a" * 32, v2="b" * 32),
    )
    store = SecretStore.from_file(path)
    with pytest.raises(ConfigError, match="no pseudonym key with kid 'gone'"):
        store.key_for("gone")


def test_rotate_pseudonym_key_preserves_old_material_and_moves_current(tmp_path):
    path = tmp_path / "secret.yaml"
    store = create_demo_secret(path, kid="k1")
    old_value = store.key_for("k1").value
    rotated = rotate_pseudonym_key(path, "k2")
    assert rotated.current_kid() == "k2"
    assert set(rotated.kids()) == {"k1", "k2"}
    # Old key material must survive rotation so historical mappings reveal.
    assert rotated.key_for("k1").value == old_value
    assert rotated.key_for("k2").value != old_value
    # A second process reopening the file sees exactly the same configuration.
    reopened = SecretStore.from_file(path)
    assert reopened.current_kid() == "k2"
    assert reopened.key_for("k1").value == old_value


def test_rotate_rejects_a_kid_that_already_exists(tmp_path):
    path = tmp_path / "secret.yaml"
    create_demo_secret(path, kid="k1")
    with pytest.raises(ConfigError, match="that kid already exists"):
        rotate_pseudonym_key(path, "k1")


def test_boolean_looking_kid_is_treated_as_a_string(tmp_path):
    # Unquoted on/off/yes/no are YAML 1.1 booleans; a kid must stay a string.
    path = write_secret(
        tmp_path,
        f"""
        hmac_salt: "{LONG}"
        keys:
          - kid: on
            value: "{'a' * 32}"
            current: true
        """,
    )
    with pytest.raises(ConfigError, match="missing a non-empty string 'kid'"):
        SecretStore.from_file(path)


def test_demo_secret_is_written_in_versioned_format(tmp_path):
    path = tmp_path / "demo-secret.txt"
    store = create_demo_secret(path)
    assert store.current_kid() == DEFAULT_KID
    text = path.read_text(encoding="utf-8")
    assert "keys:" in text and "current: true" in text
    # The file itself must not expose a bare pseudonym_key scalar anymore.
    assert "pseudonym_key:" not in text
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_in_memory_constructor_keeps_backwards_compatible_usage():
    store = SecretStore(
        {"hmac_salt": LONG, "pseudonym_key": "z" * 32}, Path("memory-secret")
    )
    assert store.current_kid() == DEFAULT_KID
    assert store.get("pseudonym_key") == "z" * 32
    assert secrets.compare_digest(store.current_pseudonym_key().value, "z" * 32)
