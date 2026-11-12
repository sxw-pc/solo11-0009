"""Secret-file fingerprinting: identity, hard rejection and legacy fallback.

Covers the compliance requirement that every run records which key it used,
that resume/reveal refuse a mismatched key with an audit trail, and that
artifacts produced before fingerprinting keep working with a warning.
"""

from __future__ import annotations

import json
import sqlite3
import warnings
from pathlib import Path

import pytest

from maskline.__main__ import main
from maskline.audit import read_audit_entries
from maskline.config import (
    SECRET_FINGERPRINT_PREFIX,
    ConfigError,
    SecretFingerprintMismatch,
    SecretStore,
    secret_fingerprint,
    verify_secret_fingerprint,
)
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.pseudomap import PseudoMap

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _write_secret(path: Path, salt: str = "salt-value-0123456789",
                  key: str = "key-value-0123456789") -> SecretStore:
    path.write_text(
        f'hmac_salt: "{salt}"\npseudonym_key: "{key}"\n', encoding="utf-8"
    )
    return SecretStore.from_file(path)


# --------------------------------------------------------------------------- #
# Fingerprint algorithm properties
# --------------------------------------------------------------------------- #

def test_fingerprint_is_stable_and_irreversible():
    # Hardcoded value pins the algorithm: it must not drift across versions.
    expected = (
        "sha256:v1:74ee0be04ee302f7e47547426882fd9f"
        "25c3ef46e2c23fbd35f77592926ad349"
    )
    assert secret_fingerprint({"hmac_salt": "a" * 20,
                               "pseudonym_key": "b" * 20}) == expected
    assert expected.startswith(SECRET_FINGERPRINT_PREFIX) and len(expected) == 10 + 64


def test_fingerprint_ignores_file_formatting_but_changes_with_content(
    tmp_path,
):
    plain = tmp_path / "plain.txt"
    quoted = tmp_path / "quoted.txt"
    reordered = tmp_path / "reordered.txt"
    different = tmp_path / "different.txt"
    plain.write_text(
        "hmac_salt: abcdefghijklmnop\npseudonym_key: qrstuvwxyz012345\n",
        encoding="utf-8",
    )
    quoted.write_text(
        '# a comment\n"pseudonym_key": "qrstuvwxyz012345"\n'
        '"hmac_salt": "abcdefghijklmnop"\n',
        encoding="utf-8",
    )
    reordered.write_text(
        "pseudonym_key: qrstuvwxyz012345\nhmac_salt: abcdefghijklmnop\n",
        encoding="utf-8",
    )
    different.write_text(
        "hmac_salt: abcdefghijklmnop\npseudonym_key: WRONG-VALUE-01234\n",
        encoding="utf-8",
    )
    fp_plain = SecretStore.from_file(plain).fingerprint
    assert SecretStore.from_file(quoted).fingerprint == fp_plain
    assert SecretStore.from_file(reordered).fingerprint == fp_plain
    assert SecretStore.from_file(different).fingerprint != fp_plain
    # The fingerprint must not disclose any secret material.
    assert "abcdefghijklmnop" not in fp_plain
    assert "qrstuvwxyz012345" not in fp_plain


def test_verify_outcomes_and_constant_time_equality():
    fp = secret_fingerprint({"k": "x" * 20})
    other = secret_fingerprint({"k": "y" * 20})
    assert verify_secret_fingerprint(fp, fp, operation="t") == "match"
    with pytest.warns(UserWarning, match="no secret fingerprint"):
        assert verify_secret_fingerprint(fp, None, operation="t") == "legacy"
    with pytest.raises(SecretFingerprintMismatch) as excinfo:
        verify_secret_fingerprint(fp, other, operation="resume")
    message = str(excinfo.value)
    assert "resume" in message
    # Neither digest value may appear in the user-facing error.
    assert fp not in message and other not in message
    assert "x" * 20 not in message


# --------------------------------------------------------------------------- #
# Fingerprint recorded in run artifacts
# --------------------------------------------------------------------------- #

def test_run_records_fingerprint_in_manifest_audit_and_pseudomap(
    tmp_path, inventories, monkeypatch,
):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    store = _write_secret(tmp_path / "secret.txt")
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(tmp_path / "secret.txt"))
    policy = load_policy(EXAMPLE)

    result = execute_run(
        inventories["sqlite"], policy, paths, secrets_store=store
    )
    assert result.secret_fingerprint == store.fingerprint

    manifest_path = (
        paths.manifest_dir / f"{inventories['sqlite'].fingerprint[:16]}.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["secret_fingerprint"] == store.fingerprint

    with CheckpointStore(paths.checkpoint_db) as checkpoints:
        record = checkpoints.get_run(result.run_id)
    assert record.secret_fingerprint == store.fingerprint

    with PseudoMap(paths.pseudomap_db) as mapping:
        assert mapping.secret_fingerprint == store.fingerprint

    # finalize_run is what appends the run event to the audit log.
    from maskline.audit import AuditLog, build_audit_entry

    AuditLog(paths.audit_path).append(build_audit_entry(result, result.transformer_map))
    audit = read_audit_entries(paths.audit_path)
    assert len(audit) == 1
    assert audit[-1]["secret_fingerprint"] == store.fingerprint


def test_rerun_with_same_key_is_unchanged_and_warns_free(
    tmp_path, inventories,
):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    store = _write_secret(tmp_path / "secret.txt")
    policy = load_policy(EXAMPLE)
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        first = execute_run(
            inventories["sqlite"], policy, paths, secrets_store=store
        )
        second = execute_run(
            inventories["sqlite"], policy, paths, secrets_store=store
        )
    assert first.output_hash == second.output_hash
    assert second.secret_fingerprint == store.fingerprint


# --------------------------------------------------------------------------- #
# Resume path: wrong key rejected, correct key works
# --------------------------------------------------------------------------- #

def _interrupted_run(inventories, policy, paths, store, tmp_path):
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=store, batch_size=2, interrupt_after_batches=1,
        )
    return excinfo.value.run_id


def test_resume_with_wrong_key_is_rejected_and_run_state_untouched(
    tmp_path, inventories,
):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    correct = _write_secret(tmp_path / "correct.txt", salt="s" * 20, key="k" * 20)
    policy = load_policy(EXAMPLE)
    run_id = _interrupted_run(inventories, policy, paths, correct, tmp_path)

    wrong = _write_secret(
        tmp_path / "wrong.txt", salt="s" * 20, key="Z" * 20
    )
    with pytest.raises(SecretFingerprintMismatch, match="resume"):
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=wrong, batch_size=3, resume_run_id=run_id,
        )
    with CheckpointStore(paths.checkpoint_db) as checkpoints:
        # Refusal must not flip the run to "failed".
        assert checkpoints.get_run(run_id).status == "interrupted"
        assert checkpoints.get_run(run_id).secret_fingerprint == correct.fingerprint

    # The correct key resumes the run to completion.
    resumed = execute_run(
        inventories["sqlite"], policy, paths,
        secrets_store=correct, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.run_id == run_id
    with CheckpointStore(paths.checkpoint_db) as checkpoints:
        assert checkpoints.get_run(run_id).status == "completed"


def test_fresh_run_against_known_dataset_rejects_wrong_key(tmp_path, inventories):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    correct = _write_secret(tmp_path / "correct.txt", salt="s" * 20, key="k" * 20)
    policy = load_policy(EXAMPLE)
    execute_run(inventories["sqlite"], policy, paths, secrets_store=correct)

    wrong = _write_secret(tmp_path / "wrong.txt", salt="s" * 20, key="Z" * 20)
    with pytest.raises(SecretFingerprintMismatch, match="'run'"):
        execute_run(inventories["sqlite"], policy, paths, secrets_store=wrong)


# --------------------------------------------------------------------------- #
# Reveal path: wrong key rejected with audit record
# --------------------------------------------------------------------------- #

def test_reveal_refuses_wrong_key_and_audits_rejection(
    tmp_path, inventories, monkeypatch,
):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    correct_path = tmp_path / "correct.txt"
    correct = _write_secret(correct_path, salt="s" * 20, key="k" * 20)
    policy = load_policy(EXAMPLE)
    execute_run(inventories["sqlite"], policy, paths, secrets_store=correct)
    with PseudoMap(paths.pseudomap_db) as mapping:
        token, plaintext = next(mapping.iter_entries(limit=1))

    wrong_path = tmp_path / "wrong.txt"
    _write_secret(wrong_path, salt="s" * 20, key="Z" * 20)
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(wrong_path))
    rc = main([
        "reveal", "--workspace", str(paths.root), "--token", token,
    ])
    assert rc == 2

    entries = read_audit_entries(paths.audit_path)
    rejections = [e for e in entries if e.get("event") == "operation_rejected"]
    assert len(rejections) == 1
    rejection = rejections[0]
    assert rejection["operation"] == "reveal"
    assert rejection["token"] == token
    assert rejection["presented_secret_fingerprint"].startswith(
        SECRET_FINGERPRINT_PREFIX
    )
    # The recorded (correct) fingerprint must not appear in a rejection entry.
    assert correct.fingerprint not in json.dumps(rejection)
    assert "k" * 20 not in json.dumps(rejection)

    # Correct key: reveal succeeds and the chain still verifies.
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(correct_path))
    assert main([
        "reveal", "--workspace", str(paths.root), "--token", token,
    ]) == 0
    paths_audit = paths.audit_path
    from maskline.audit import verify_audit

    verification = verify_audit(paths_audit)
    assert verification.entries == len(entries)


def test_cli_resume_wrong_key_records_rejection(
    tmp_path, inventories, monkeypatch,
):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    correct_path = tmp_path / "correct.txt"
    correct = _write_secret(correct_path, salt="s" * 20, key="k" * 20)
    policy = load_policy(EXAMPLE)
    run_id = _interrupted_run(inventories, policy, paths, correct, tmp_path)

    wrong_path = tmp_path / "wrong.txt"
    _write_secret(wrong_path, salt="s" * 20, key="Z" * 20)
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(wrong_path))
    rc = main([
        "resume", "--workspace", str(paths.root),
        "--run-id", run_id, "--batch-size", "3",
    ])
    assert rc == 2
    entries = read_audit_entries(paths.audit_path)
    rejection = [e for e in entries if e.get("event") == "operation_rejected"]
    assert len(rejection) == 1 and rejection[0]["operation"] == "resume"
    assert rejection[0]["run_id"] == run_id
    assert correct.fingerprint not in json.dumps(rejection[0])

    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(correct_path))
    assert main([
        "resume", "--workspace", str(paths.root),
        "--run-id", run_id, "--batch-size", "3",
    ]) == 0
    from maskline.audit import verify_audit

    verify_audit(paths.audit_path)
    assert result_still_completes(paths, run_id)


def result_still_completes(paths, run_id):
    with CheckpointStore(paths.checkpoint_db) as checkpoints:
        return checkpoints.get_run(run_id).status == "completed"


# --------------------------------------------------------------------------- #
# Backward compatibility: legacy artifacts have no fingerprint field
# --------------------------------------------------------------------------- #

def test_legacy_manifest_without_fingerprint_warns_and_runs(
    tmp_path, inventories,
):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    store = _write_secret(tmp_path / "secret.txt")
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, paths, secrets_store=store
    )
    manifest_path = paths.manifest_dir / (
        f"{inventories['sqlite'].fingerprint[:16]}.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["secret_fingerprint"]
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.warns(UserWarning, match="no secret fingerprint"):
        again = execute_run(
            inventories["sqlite"], policy, paths, secrets_store=store
        )
    # The new run backfills the fingerprint.
    backfilled = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert backfilled["secret_fingerprint"] == store.fingerprint
    assert again.output_hash == result.output_hash


def test_legacy_pseudomap_without_meta_allows_reveal_with_warning(
    tmp_path, monkeypatch,
):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    paths.pseudomap_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(paths.pseudomap_db)
    conn.execute(
        "CREATE TABLE pseudonym_map (token TEXT PRIMARY KEY, "
        "plaintext TEXT NOT NULL, created_at TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO pseudonym_map VALUES "
        "('psn_legacy', 'secret-value', '2026-01-01T00:00:00+00:00')"
    )
    conn.commit()
    conn.close()

    with PseudoMap(paths.pseudomap_db) as mapping:
        assert mapping.secret_fingerprint is None

    secret_path = tmp_path / "secret.txt"
    _write_secret(secret_path)
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(secret_path))
    with pytest.warns(UserWarning, match="no secret fingerprint"):
        rc = main([
            "reveal", "--workspace", str(paths.root),
            "--token", "psn_legacy",
        ])
    assert rc == 0


def test_legacy_checkpoint_db_resume_warns_then_allows(tmp_path, inventories):
    from maskline.config import Paths

    paths = Paths.for_workspace(tmp_path / "workspace")
    store = _write_secret(tmp_path / "secret.txt")
    policy = load_policy(EXAMPLE)
    run_id = _interrupted_run(inventories, policy, paths, store, tmp_path)

    # Simulate a pre-fingerprint checkpoint database.
    with sqlite3.connect(paths.checkpoint_db) as conn:
        conn.execute(
            "UPDATE runs SET secret_fingerprint = NULL WHERE run_id = ?",
            (run_id,),
        )
        conn.commit()

    with CheckpointStore(paths.checkpoint_db) as checkpoints:
        assert checkpoints.get_run(run_id).secret_fingerprint is None

    with pytest.warns(UserWarning, match="no secret fingerprint"):
        resumed = execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=store, batch_size=3, resume_run_id=run_id,
        )
    assert resumed.run_id == run_id


def test_dry_run_does_not_require_or_persist_fingerprint_artifacts(
    tmp_path, inventories,
):
    from maskline.config import Paths

    dry_root = tmp_path / "dry"
    paths = Paths.for_workspace(dry_root)
    store = _write_secret(tmp_path / "secret.txt")
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, paths, secrets_store=store, dry_run=True
    )
    assert result.dry_run and result.secret_fingerprint == store.fingerprint
    assert not dry_root.exists()


def test_mismatch_error_never_contains_key_material(tmp_path):
    secret = _write_secret(tmp_path / "s.txt", salt="salty-salty-1234",
                           key="super-secret-key-99")
    other = secret_fingerprint({"hmac_salt": "salty-salty-1234",
                                "pseudonym_key": "totally-other-key!"})
    with pytest.raises(SecretFingerprintMismatch) as excinfo:
        verify_secret_fingerprint(
            secret.fingerprint, other, operation="reveal"
        )
    message = str(excinfo.value)
    assert "salty-salty-1234" not in message
    assert "super-secret-key-99" not in message
    assert "totally-other-key!" not in message
    assert secret.fingerprint not in message and other not in message


def test_pseudomap_rejects_opening_with_a_different_key(tmp_path):
    from maskline.pseudomap import PseudoMapError

    db = tmp_path / "map.sqlite"
    fp_a = secret_fingerprint({"hmac_salt": "a" * 20, "pseudonym_key": "k" * 20})
    fp_b = secret_fingerprint({"hmac_salt": "a" * 20, "pseudonym_key": "Z" * 20})
    with PseudoMap(db, create=True, secret_fingerprint=fp_a):
        pass
    # Read-only opens (no fingerprint presented) stay possible for reveal.
    with PseudoMap(db) as mapping:
        assert mapping.secret_fingerprint == fp_a
    with pytest.raises(PseudoMapError, match="different secret file"):
        PseudoMap(db, create=True, secret_fingerprint=fp_b)
    # A legacy database without a meta row is simply backfilled.
    legacy = tmp_path / "legacy.sqlite"
    conn = sqlite3.connect(legacy)
    conn.execute(
        "CREATE TABLE pseudonym_map (token TEXT PRIMARY KEY, "
        "plaintext TEXT NOT NULL, created_at TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()
    with PseudoMap(legacy, create=True, secret_fingerprint=fp_a) as mapping:
        assert mapping.secret_fingerprint == fp_a


def test_placeholder_secret_still_rejected_before_fingerprinting(tmp_path):
    path = tmp_path / "bad.txt"
    path.write_text(
        'hmac_salt: "REPLACE-ME-123456"\npseudonym_key: "key-value-0123456789"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="placeholder"):
        SecretStore.from_file(path)
