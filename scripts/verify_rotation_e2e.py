#!/usr/bin/env python3
"""Manual end-to-end verification of the multi-kid rotation model.

Scenarios:
  1. Round 1 mappings under kid 2026-q1; rotate to 2026-q2; round 2 mappings.
  2. Tokens from both rounds reveal correctly via their recorded kids.
  3. A kid-less legacy mapping DB and legacy flat secret file open directly.
  4. The audit chain contains kids but no key material.
  5. Malformed secret files (no current marker / duplicate kid) fail loudly.
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

from maskline.audit import AuditLog, read_audit_entries
from maskline.config import (
    DEFAULT_KID,
    ConfigError,
    SecretStore,
    create_demo_secret,
    rotate_pseudonym_key,
)
from maskline.fixturegen import generate_fixture
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.pseudomap import PseudoMap
from maskline.registry import inspect_dataset
from maskline.transformers.pseudonym import pseudonym_token
from maskline.workflow import finalize_run, scan_paths
from maskline.config import Paths

POLICY = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def names_in_output(output_path: Path) -> list[str]:
    conn = sqlite3.connect(output_path)
    try:
        return [r[0] for r in conn.execute(
            "SELECT full_name FROM customers ORDER BY customer_id"
        )]
    finally:
        conn.close()


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="maskline-rotation-e2e-"))
    paths = Paths.for_workspace(root / "workspace")
    paths.ensure_runtime_dirs()
    fixtures = generate_fixture(paths.raw_dir, seed=7, customers=6, orders=9, leads=3)
    inventory = inspect_dataset(fixtures["sqlite"])
    policy = load_policy(POLICY)

    # ---- Round 1 under kid 2026-q1 --------------------------------------
    secret_path = root / "secret.yaml"
    store1 = create_demo_secret(secret_path, kid="2026-q1")
    summaries = scan_paths([fixtures["sqlite"]], paths)
    run1 = execute_run(inventory, policy, paths, secrets_store=store1)
    finalize_run(paths, summaries[0].inventory, policy, run1, summaries[0].findings)
    tokens1 = names_in_output(run1.output_path)
    print(f"[round 1] kid={run1.pseudonym_kid} tokens={len(tokens1)}")

    # ---- Rotate ----------------------------------------------------------
    store2 = rotate_pseudonym_key(secret_path, "2026-q2")
    print(f"[rotate ] current={store2.current_kid()} retained={store2.kids()}")

    # ---- Round 2 under kid 2026-q2 --------------------------------------
    run2 = execute_run(inventory, policy, paths, secrets_store=store2)
    finalize_run(paths, summaries[0].inventory, policy, run2, summaries[0].findings)
    tokens2 = names_in_output(run2.output_path)
    print(f"[round 2] kid={run2.pseudonym_kid} tokens={len(tokens2)}")

    assert run1.pseudonym_kid == "2026-q1" and run2.pseudonym_kid == "2026-q2"
    assert tokens1 != tokens2, "rotation must change new tokens"

    # ---- Reveal both rounds with the rotated (multi-key) store ----------
    with PseudoMap(paths.pseudomap_db) as mapping:
        assert set(mapping.kids_in_use()) == {"2026-q1", "2026-q2"}
        for t1, t2 in zip(tokens1, tokens2):
            p1 = mapping.reveal(t1, store2)
            p2 = mapping.reveal(t2, store2)
            assert p1 == p2, "same person across rounds must reveal to the same plaintext"
            assert mapping.kid_for(t1) == "2026-q1"
            assert mapping.kid_for(t2) == "2026-q2"
            assert pseudonym_token(p1, store2.key_for("2026-q1").value) == t1
            assert pseudonym_token(p2, store2.key_for("2026-q2").value) == t2
    print("[reveal ] all round-1 and round-2 tokens verify against their own kid")

    # ---- Audit chain: kids present, zero key material -------------------
    AuditLog(paths.audit_path).verify()
    entries = read_audit_entries(paths.audit_path)
    assert [e["pseudonym_kid"] for e in entries] == ["2026-q1", "2026-q2"]
    raw = paths.audit_path.read_text(encoding="utf-8")
    for kid in store2.kids():
        assert store2.key_for(kid).value not in raw, "key material leaked into audit log"
    assert store2.get("hmac_salt") not in raw
    assert "pseudonym_key" not in raw
    print(f"[audit  ] chain verifies; {len(entries)} entries; only kids, no key material")

    # ---- Legacy unmigrated DB + legacy flat secret open directly --------
    legacy_root = Path(tempfile.mkdtemp(prefix="maskline-legacy-e2e-"))
    legacy_paths = Paths.for_workspace(legacy_root / "workspace")
    legacy_paths.ensure_runtime_dirs()
    legacy_fixtures = generate_fixture(
        legacy_paths.raw_dir, seed=11, customers=4, orders=4, leads=2
    )
    legacy_key = "legacy-" + "z" * 40
    legacy_db = legacy_paths.pseudomap_db
    conn = sqlite3.connect(legacy_db)
    conn.execute(
        "CREATE TABLE pseudonym_map (token TEXT PRIMARY KEY, plaintext TEXT NOT NULL, "
        "created_at TEXT NOT NULL)"
    )
    legacy_token = pseudonym_token("张伟", legacy_key)
    conn.execute(
        "INSERT INTO pseudonym_map (token, plaintext, created_at) VALUES (?, ?, ?)",
        (legacy_token, "张伟", "2026-01-01T00:00:00+00:00"),
    )
    conn.commit()
    conn.close()
    legacy_secret = legacy_root / "legacy-secret.yaml"
    legacy_secret.write_text(
        f'hmac_salt: "{"s" * 40}"\npseudonym_key: "{legacy_key}"\n', encoding="utf-8"
    )
    legacy_store = SecretStore.from_file(legacy_secret)
    assert legacy_store.current_kid() == DEFAULT_KID
    legacy_inventory = inspect_dataset(legacy_fixtures["sqlite"])
    legacy_summaries = scan_paths([legacy_fixtures["sqlite"]], legacy_paths)
    legacy_run = execute_run(
        legacy_inventory, policy, legacy_paths, secrets_store=legacy_store
    )
    finalize_run(
        legacy_paths, legacy_summaries[0].inventory, policy, legacy_run,
        legacy_summaries[0].findings,
    )
    with PseudoMap(legacy_db) as mapping:
        assert mapping.reveal(legacy_token, legacy_store) == "张伟"
        assert mapping.kid_for(legacy_token) == DEFAULT_KID
        new_tokens = names_in_output(legacy_run.output_path)
        for token in new_tokens:
            mapping.reveal(token, legacy_store)  # stored rows verify with default kid
    print("[legacy ] kid-less DB migrated on open; old row and new rows both reveal")

    # ---- Malformed secret files fail with explicit, located errors ------
    def bad_secret(text: str) -> None:
        p = root / "bad.yaml"
        p.write_text(text, encoding="utf-8")
        try:
            SecretStore.from_file(p)
        except ConfigError as exc:
            print(f"[config ] rejected as expected: {exc}")
            return
        raise AssertionError("malformed secret was silently accepted")

    bad_secret(
        f'hmac_salt: "{"s" * 40}"\n'
        'keys:\n  - kid: "k1"\n    value: "' + "a" * 40 + '"\n    current: false\n'
    )
    bad_secret(
        f'hmac_salt: "{"s" * 40}"\n'
        'keys:\n'
        '  - kid: "k1"\n    value: "' + "a" * 40 + '"\n    current: true\n'
        '  - kid: "k1"\n    value: "' + "b" * 40 + '"\n    current: false\n'
    )
    print("ALL E2E CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
