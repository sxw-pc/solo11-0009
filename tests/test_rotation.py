"""End-to-end key rotation: two runs, two kids, both revealable, clean audit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maskline.audit import read_audit_entries
from maskline.config import (
    DEFAULT_KID,
    SecretStore,
    create_demo_secret,
    rotate_pseudonym_key,
)
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.pseudomap import PseudoMap
from maskline.transformers.pseudonym import pseudonym_token
from maskline.workflow import finalize_run

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _names_from_output(output_path: Path) -> list[str]:
    import sqlite3

    conn = sqlite3.connect(output_path)
    try:
        return [row[0] for row in conn.execute(
            "SELECT full_name FROM customers ORDER BY customer_id"
        )]
    finally:
        conn.close()


def test_rotation_two_runs_coexist_and_both_reveal(workspace, inventories):
    policy = load_policy(EXAMPLE)
    secret_path = workspace.root / "secret.yaml"
    first_store = create_demo_secret(secret_path, kid="2026-q1")
    first_key = first_store.key_for("2026-q1").value

    # Round 1: mappings created under the first kid.
    first = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=first_store
    )
    assert first.pseudonym_kid == "2026-q1"
    first_tokens = _names_from_output(first.output_path)
    assert all(token.startswith("psn_") for token in first_tokens)

    # Rotate: new current kid, old key retained in the same file.
    rotated_store = rotate_pseudonym_key(secret_path, "2026-q2")
    assert rotated_store.current_kid() == "2026-q2"
    assert rotated_store.key_for("2026-q1").value == first_key

    # Round 2 against a fresh target, using the rotated store.
    second = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=rotated_store
    )
    assert second.pseudonym_kid == "2026-q2"
    second_tokens = _names_from_output(second.output_path)

    # Same people, different tokens per key generation.
    assert first_tokens != second_tokens
    with PseudoMap(workspace.pseudomap_db) as mapping:
        assert set(mapping.kids_in_use()) == {"2026-q1", "2026-q2"}
        # Both rounds reveal through the kid recorded on each row.
        for token in first_tokens:
            assert mapping.reveal(token, rotated_store)
            assert mapping.kid_for(token) == "2026-q1"
        for token in second_tokens:
            assert mapping.reveal(token, rotated_store)
            assert mapping.kid_for(token) == "2026-q2"
        # The two tokens for one plaintext are both present and distinct.
        plaintext = mapping.reveal(first_tokens[0], rotated_store)
        assert pseudonym_token(plaintext, first_key) == first_tokens[0]
        assert pseudonym_token(
            plaintext, rotated_store.key_for("2026-q2").value
        ) == second_tokens[0]


def test_audit_chain_carries_kid_but_never_key_material(workspace, inventories):
    policy = load_policy(EXAMPLE)
    secret_path = workspace.root / "secret.yaml"
    store = create_demo_secret(secret_path, kid="2026-q1")
    result_one = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=store
    )
    finalize_run(workspace, inventories["sqlite"], policy, result_one, [])
    rotate_pseudonym_key(secret_path, "2026-q2")
    rotated = SecretStore.from_file(secret_path)
    result_two = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=rotated
    )
    finalize_run(workspace, inventories["sqlite"], policy, result_two, [])

    entries = read_audit_entries(workspace.audit_path)
    assert len(entries) == 2
    assert [entry["pseudonym_kid"] for entry in entries] == ["2026-q1", "2026-q2"]

    raw_log = workspace.audit_path.read_text(encoding="utf-8")
    # No key material, no legacy scalar name anywhere in the chain.
    for kid in rotated.kids():
        assert rotated.key_for(kid).value not in raw_log
    assert rotated.get("hmac_salt") not in raw_log
    assert "pseudonym_key" not in raw_log
    # Kids themselves are allowed and useful for auditing.
    assert "2026-q1" in raw_log and "2026-q2" in raw_log
    # Every entry remains structurally a self-consistent chain record.
    for entry in entries:
        assert set(entry) >= {"seq", "prev_hash", "entry_hash", "pseudonym_kid"}


def test_new_version_opens_unmigrated_legacy_database_for_runs(
    workspace, inventories, tmp_path
):
    # Simulate a mapping DB produced by the old, kid-less release.
    import sqlite3

    from maskline.transformers.pseudonym import pseudonym_token

    legacy_key = "legacy-" + "x" * 40
    legacy_db = workspace.pseudomap_db
    legacy_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(legacy_db)
    conn.execute(
        "CREATE TABLE pseudonym_map (token TEXT PRIMARY KEY, plaintext TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    token = pseudonym_token("张伟", legacy_key)
    conn.execute(
        "INSERT INTO pseudonym_map (token, plaintext, created_at) VALUES (?, ?, ?)",
        (token, "张伟", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()

    # A legacy flat secret file whose pseudonym_key matches the old rows.
    secret_path = tmp_path / "legacy-secret.yaml"
    secret_path.write_text(
        f'hmac_salt: "{"s" * 40}"\npseudonym_key: "{legacy_key}"\n',
        encoding="utf-8",
    )
    store = SecretStore.from_file(secret_path)
    assert store.current_kid() == DEFAULT_KID

    # A normal run opens the legacy DB, migrates it, and adds current-kid rows.
    policy = load_policy(EXAMPLE)
    execute_run(inventories["sqlite"], policy, workspace, secrets_store=store)
    with PseudoMap(legacy_db) as mapping:
        # The pre-existing row is untouched and still reveals.
        assert mapping.reveal(token, store) == "张伟"
        assert mapping.kid_for(token) == DEFAULT_KID
        assert DEFAULT_KID in mapping.kids_in_use()
