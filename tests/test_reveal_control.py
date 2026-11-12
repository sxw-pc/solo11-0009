"""End-to-end and attack-scenario tests for the controlled reveal workflow.

The happy path exercises the full two-person flow:

    masking run -> keyring init -> operator key + reviewer key
    -> signed request -> signed authorization -> controlled reveal -> audit

Every remaining test simulates one concrete abuse and asserts it is rejected
*and* recorded in the audit chain.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from maskline.audit import read_audit_entries, verify_audit
from maskline.config import Paths, SecretStore, create_demo_secret
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.registry import inspect_dataset
from maskline.reveal import crypto, service
from maskline.reveal.clock import Clock
from maskline.reveal.errors import (
    AuthorizationError,
    ClockRollbackError,
    KeyringError,
    ReplayError,
    RevealControlError,
    ScopeError,
)
from maskline.reveal.executor import secure_delete
from maskline.reveal.keyring import Keyring
from maskline.reveal.records import (
    Scope,
    build_authorization_message,
    load_request,
    sign_authorization,
    sign_request,
    write_authorization,
    write_request,
)
from maskline.reveal.validator import (
    AUDIT_EVENT_DENIED,
    AuthorizationValidator,
)
from maskline.__main__ import main as cli_main

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
UTC = timezone.utc


class FakeClock:
    """Mutable UTC time source for deterministic expiry/rollback tests."""

    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **delta) -> None:
        self.current += timedelta(**delta)


@pytest.fixture
def masked_workspace(tmp_path, monkeypatch):
    """A workspace that has completed a masking run, with pseudonyms to reveal."""
    paths = Paths.for_workspace(tmp_path / "workspace")
    paths.ensure_runtime_dirs()
    secret_path = tmp_path / "secret.txt"
    create_demo_secret(secret_path)
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(secret_path))
    # Reuse the shared fixture generator.
    from maskline.fixturegen import generate_fixture

    fixtures = generate_fixture(tmp_path / "raw", seed=7, customers=6, orders=9, leads=3)
    policy = load_policy(EXAMPLE)
    inventory = inspect_dataset(fixtures["sqlite"])
    result = execute_run(
        inventory, policy, paths, batch_size=5,
        secrets_store=SecretStore.from_file(secret_path),
    )
    return {
        "paths": paths,
        "masked": result.output_path,
        "inventory": inspect_dataset(result.output_path),
        "run_id": result.run_id,
        "raw": fixtures["sqlite"],
        "table": "customers",
        "column": "full_name",
    }


@pytest.fixture
def started(masked_workspace):
    """Keyring plus distinct operator/reviewer identities and a fake clock."""
    paths = masked_workspace["paths"]
    base = datetime(2026, 11, 12, 9, 0, 0, tzinfo=UTC)
    clock_source = FakeClock(base)
    service.keygen_init(paths, now_iso=base.isoformat(timespec="seconds"))
    operator = service.keygen_generate(
        paths, "alice-operator", "operator", now_iso=base.isoformat(timespec="seconds")
    )
    reviewer = service.keygen_generate(
        paths, "bob-reviewer", "reviewer", now_iso=base.isoformat(timespec="seconds")
    )
    return {
        **masked_workspace,
        "clock": clock_source,
        "operator": operator,
        "reviewer": reviewer,
        "base": base,
    }


def _scope(ctx, **overrides) -> Scope:
    scope = Scope(
        run_id=ctx["run_id"],
        dataset_fingerprint=ctx["inventory"].fingerprint,
        table=ctx["table"],
        columns=(ctx["column"],),
    )
    if overrides:
        data = scope.to_message()
        data.update(overrides)
        scope = Scope.from_message(data)
    return scope


def _make_request(ctx, tmp_path, *, reason="incident response IR-42"):
    paths = ctx["paths"]
    req_path = tmp_path / "request.json"
    service.create_request(
        paths,
        operator_kid=ctx["operator"]["kid"],
        scope=_scope(ctx),
        reason=reason,
        out_path=req_path,
        now_iso=ctx["base"].isoformat(timespec="seconds"),
    )
    return req_path


def _make_authorization(ctx, tmp_path, request_path, *, max_rows=100, ttl_minutes=60):
    paths = ctx["paths"]
    expires = ctx["base"] + timedelta(minutes=ttl_minutes)
    auth_path = tmp_path / "authorization.json"
    service.create_authorization(
        paths,
        reviewer_kid=ctx["reviewer"]["kid"],
        request_path=request_path,
        expires_at=expires.isoformat(timespec="seconds"),
        max_rows=max_rows,
        out_path=auth_path,
        now_iso=ctx["base"].isoformat(timespec="seconds"),
    )
    return auth_path


def _audit_events(paths) -> list[dict]:
    return read_audit_entries(paths.audit_path)


def _denials(paths) -> list[dict]:
    return [entry for entry in _audit_events(paths) if entry.get("event") == AUDIT_EVENT_DENIED]


# ===================================================================== happy path
def test_happy_path_two_person_reveal_round_trips(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    output = tmp_path / "revealed.sqlite"

    result = service.execute_reveal(
        paths,
        request_path=request_path,
        authorization_path=auth_path,
        dataset_path=ctx["masked"],
        output_path=output,
        time_provider=ctx["clock"],
    )

    assert result.rows_revealed == 6
    assert output.exists()
    # The revealed column now holds original names, not psn_ tokens.
    with sqlite3.connect(output) as conn:
        names = [row[0] for row in conn.execute(
            "SELECT full_name FROM customers ORDER BY customer_id"
        )]
    assert names and all(not name.startswith("psn_") for name in names)
    # Unauthorized columns stay masked.
    with sqlite3.connect(output) as conn:
        phones = [row[0] for row in conn.execute("SELECT phone FROM customers")]
    assert all("*" in phone for phone in phones)

    events = {entry["event"] for entry in _audit_events(paths)}
    assert {
        "reveal-request-created",
        "reveal-authorized",
        "reveal-claimed",
        "reveal-completed",
    }.issubset(events)
    verify_audit(paths.audit_path)
    completion = next(e for e in _audit_events(paths) if e["event"] == "reveal-completed")
    assert completion["rows_revealed"] == 6
    assert completion["rows_authorized"] == 100
    # Every reveal audit entry carries an audit MAC under the keyring audit key.
    for entry in _audit_events(paths):
        if entry.get("event", "").startswith("reveal-"):
            assert "audit_mac" in entry


def test_key_files_are_0600_and_manifest_holds_no_secret(started):
    paths = started["paths"]
    keyring = Keyring(paths.keyring_dir)
    for identity in keyring.list_identities():
        key_file = keyring.dir / f"{identity.kid}.key"
        assert key_file.stat().st_mode & 0o777 == 0o600
        manifest_text = keyring.manifest_path.read_text(encoding="utf-8")
        raw = json.loads((keyring.dir / f"{identity.kid}.key").read_text())
        # Secret key material never appears in the public manifest.
        assert raw["key"] not in manifest_text
    assert keyring.dir.stat().st_mode & 0o777 == 0o700


# ============================================================ expiry (start + mid)
def test_authorization_expired_before_execution_is_denied(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path, ttl_minutes=30)
    # Jump past expiry before executing.
    ctx["clock"].advance(minutes=31)
    with pytest.raises(AuthorizationError, match="expired"):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )
    denial = _denials(paths)[-1]
    assert denial["reason"] == "authorization-expired"
    assert not (tmp_path / "out.sqlite").exists()
    verify_audit(paths.audit_path)


def test_authorization_expiring_mid_execution_aborts_and_erases(started, tmp_path, monkeypatch):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    # Build an authorization that expires one second after the base time.
    request = load_request(request_path)
    near_expiry = (ctx["base"] + timedelta(seconds=1)).isoformat(timespec="seconds")
    keyring, audit, clock = service.build_components(paths, time_provider=ctx["clock"])
    _id, reviewer_material = keyring.load_signing_key(
        ctx["reviewer"]["kid"], require_role="reviewer"
    )
    message = build_authorization_message(
        request=request,
        reviewer_kid=ctx["reviewer"]["kid"],
        expires_at=near_expiry,
        max_rows=100,
        now_iso=ctx["base"].isoformat(timespec="seconds"),
    )
    tight_path = tmp_path / "tight-auth.json"
    write_authorization(tight_path, sign_authorization(message, reviewer_material))

    # Make the clock cross expiry after the first row is processed.
    original_now = Clock.now

    def flipping_now(self) -> datetime:
        # After the first expiry check (validator uses clock.advance/now),
        # move time beyond expiry so the per-row guard trips.
        flipping_now.calls += 1
        if flipping_now.calls >= 2:
            return ctx["base"] + timedelta(seconds=5)
        return ctx["base"]

    flipping_now.calls = 0
    monkeypatch.setattr(Clock, "now", flipping_now)

    output = tmp_path / "partial.sqlite"
    with pytest.raises(AuthorizationError, match="expired during execution"):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=tight_path,
            dataset_path=ctx["masked"],
            output_path=output,
            time_provider=ctx["clock"],
        )
    # No plaintext output remains.
    assert not output.exists()
    assert not list(tmp_path.glob(".reveal.*"))
    abort = next(
        e for e in _audit_events(paths) if e["event"] == "reveal-aborted"
    )
    assert abort["reason"] == "authorization-expired"
    verify_audit(paths.audit_path)


# =============================================================== signature tamper
def test_tampered_authorization_tag_is_denied(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    document = json.loads(auth_path.read_text(encoding="utf-8"))
    document["authorization"]["tag"] = "0" * 64
    auth_path.write_text(json.dumps(document, sort_keys=True))

    with pytest.raises(AuthorizationError, match="tag does not verify"):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )
    assert _denials(paths)[-1]["reason"] == "authorization-signature-invalid"


def test_tampered_request_body_breaks_chain(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    # Change the reason after the reviewer signed.
    document = json.loads(request_path.read_text(encoding="utf-8"))
    document["message"]["reason"] = "tampered reason"
    request_path.write_text(json.dumps(document, sort_keys=True))

    with pytest.raises(AuthorizationError):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )
    # Either the request tag fails or the request_hash no longer matches.
    assert _denials(paths)[-1]["reason"] in {
        "request-signature-invalid",
        "request-hash-mismatch",
    }


def test_tampered_max_rows_in_authorization_is_denied(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path, max_rows=2)
    document = json.loads(auth_path.read_text(encoding="utf-8"))
    # Bump the cap without a valid signature.
    document["message"]["max_rows"] = 100
    auth_path.write_text(json.dumps(document, sort_keys=True))
    with pytest.raises(AuthorizationError, match="tag does not verify"):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )


def test_replaced_key_file_is_detected(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    keyring = Keyring(paths.keyring_dir)
    # Overwrite a key file's secret while keeping the JSON shape.
    key_file = keyring.dir / f"{ctx['operator']['kid']}.key"
    envelope = json.loads(key_file.read_text(encoding="utf-8"))
    envelope["key"] = crypto.encode_key(crypto.new_secret())
    key_file.write_text(json.dumps(envelope, sort_keys=True))
    with pytest.raises(KeyringError, match="integrity MAC"):
        service.create_request(
            paths,
            operator_kid=ctx["operator"]["kid"],
            scope=_scope(ctx),
            reason="x",
            out_path=tmp_path / "r.json",
        )


# ================================================================ scope / row cap
def test_scope_widening_to_unauthorized_column_is_denied(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    # Request only full_name; execution must not be able to pull id_card too.
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    # The executor derives scope from the request, so to attempt widening we
    # forge a second request object on disk referencing an extra column but
    # reusing the same authorization.
    widened = Scope.from_message(
        {
            **_scope(ctx).to_message(),
            "columns": ["full_name", "id_card"],
        }
    )
    rogue_path = tmp_path / "rogue-request.json"
    _id, operator_material = Keyring(paths.keyring_dir).load_signing_key(
        ctx["operator"]["kid"], require_role="operator"
    )
    from maskline.reveal.records import build_request_message

    rogue_msg = build_request_message(
        scope=widened,
        reason="attempt to widen",
        operator_kid=ctx["operator"]["kid"],
        now_iso=ctx["base"].isoformat(timespec="seconds"),
    )
    write_request(rogue_path, sign_request(rogue_msg, operator_material))

    with pytest.raises(AuthorizationError, match="request id|request_hash"):
        service.execute_reveal(
            paths,
            request_path=rogue_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )
    assert _denials(paths)[-1]["reason"] in {
        "request-mismatch",
        "request-hash-mismatch",
    }


def test_row_limit_smaller_than_dataset_is_denied_and_audited(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path, max_rows=3)
    with pytest.raises(AuthorizationError, match="exceeds the authorized limit"):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )
    abort = next(e for e in _audit_events(paths) if e["event"] == "reveal-aborted")
    assert abort["reason"] == "row-limit-exceeded"
    # The claim means the authorization is now spent even though no data flowed.
    with pytest.raises(ReplayError):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out2.sqlite",
            time_provider=ctx["clock"],
        )


def test_authorization_bound_to_other_batch_is_denied(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    # Scope carries a foreign run id / fingerprint.
    foreign = _scope(
        ctx,
        run_id="run_foreign_batch",
        dataset_fingerprint="a" * 64,
    )
    request_path = tmp_path / "request.json"
    service.create_request(
        paths,
        operator_kid=ctx["operator"]["kid"],
        scope=foreign,
        reason="cross-batch attempt",
        out_path=request_path,
        now_iso=ctx["base"].isoformat(timespec="seconds"),
    )
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    with pytest.raises(ScopeError, match="different batch"):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )


# ===================================================================== replay
def test_same_authorization_cannot_be_reused(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    common = dict(
        request_path=request_path,
        authorization_path=auth_path,
        dataset_path=ctx["masked"],
        time_provider=ctx["clock"],
    )
    first = service.execute_reveal(
        paths, **common, output_path=tmp_path / "first.sqlite"
    )
    assert first.rows_revealed == 6
    with pytest.raises(ReplayError, match="already consumed"):
        service.execute_reveal(
            paths, **common, output_path=tmp_path / "second.sqlite"
        )
    # Second output was never created and the chain still verifies.
    assert not (tmp_path / "second.sqlite").exists()
    verify_audit(paths.audit_path)


# ============================================================ role / key mixing
def test_operator_key_cannot_sign_authorization(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    request = load_request(request_path)
    # A second operator identity: same role as the requester, distinct person,
    # so separation-of-duties cannot be the reason for rejection.
    second_operator = service.keygen_generate(
        paths, "carol-operator", "operator",
        now_iso=ctx["base"].isoformat(timespec="seconds"),
    )
    keyring = Keyring(paths.keyring_dir)
    _id, operator_material = keyring.load_signing_key(
        second_operator["kid"], require_role="operator"
    )
    message = build_authorization_message(
        request=request,
        reviewer_kid=second_operator["kid"],  # operator masquerading as reviewer
        expires_at=(ctx["base"] + timedelta(hours=1)).isoformat(timespec="seconds"),
        max_rows=100,
        now_iso=ctx["base"].isoformat(timespec="seconds"),
    )
    bad_auth = tmp_path / "bad-auth.json"
    write_authorization(bad_auth, sign_authorization(message, operator_material))
    with pytest.raises(AuthorizationError):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=bad_auth,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )
    assert _denials(paths)[-1]["reason"] == "role-mismatch"


def test_reviewer_key_cannot_sign_request(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    with pytest.raises(KeyringError, match="role"):
        service.create_request(
            paths,
            operator_kid=ctx["reviewer"]["kid"],
            scope=_scope(ctx),
            reason="reviewer acting as operator",
            out_path=tmp_path / "r.json",
        )


def test_self_authorization_is_blocked_at_signing(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    request = load_request(request_path)
    # A single key has one role, so the service blocks role misuse first.
    with pytest.raises(KeyringError, match="role"):
        service.create_authorization(
            paths,
            reviewer_kid=ctx["operator"]["kid"],  # same person as operator
            request_path=request_path,
            expires_at=(ctx["base"] + timedelta(hours=1)).isoformat(timespec="seconds"),
            max_rows=100,
            out_path=tmp_path / "auth.json",
        )

    # Defense in depth: a hand-crafted authorization whose reviewer_kid equals
    # the operator kid is rejected on separation-of-duties before any signature
    # verification, regardless of the tag it carries.
    message = build_authorization_message(
        request=request,
        reviewer_kid=ctx["operator"]["kid"],  # collide with the operator identity
        expires_at=(ctx["base"] + timedelta(hours=1)).isoformat(timespec="seconds"),
        max_rows=100,
        now_iso=ctx["base"].isoformat(timespec="seconds"),
    )
    forged = tmp_path / "forged-auth.json"
    write_authorization(forged, sign_authorization(message, b"\x00" * 32))
    with pytest.raises(AuthorizationError, match="different identities"):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=forged,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )
    assert _denials(paths)[-1]["reason"] == "separation-of-duties"


# ============================================================== clock rollback
def test_clock_rollback_is_detected(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    # One successful run advances the monotonic anchor.
    service.execute_reveal(
        paths,
        request_path=request_path,
        authorization_path=auth_path,
        dataset_path=ctx["masked"],
        output_path=tmp_path / "first.sqlite",
        time_provider=ctx["clock"],
    )
    # Roll the wall clock backwards.
    ctx["clock"].current = ctx["base"] - timedelta(hours=2)
    request_two = _make_request(ctx, tmp_path / "req2")
    auth_two = _make_authorization(ctx, tmp_path, request_two)
    with pytest.raises(ClockRollbackError):
        service.execute_reveal(
            paths,
            request_path=request_two,
            authorization_path=auth_two,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "rolled.sqlite",
            time_provider=ctx["clock"],
        )


def test_tampered_clock_anchor_is_detected(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    service.execute_reveal(
        paths,
        request_path=request_path,
        authorization_path=auth_path,
        dataset_path=ctx["masked"],
        output_path=tmp_path / "first.sqlite",
        time_provider=ctx["clock"],
    )
    anchor = paths.clock_anchor_path
    payload = json.loads(anchor.read_text())
    payload["last_seen"] = "2000-01-01T00:00:00+00:00"
    anchor.write_text(json.dumps(payload, sort_keys=True))
    request_two = _make_request(ctx, tmp_path / "req2")
    auth_two = _make_authorization(ctx, tmp_path, request_two)
    with pytest.raises(ClockRollbackError, match="anchor MAC"):
        service.execute_reveal(
            paths,
            request_path=request_two,
            authorization_path=auth_two,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "x.sqlite",
            time_provider=ctx["clock"],
        )


# ================================================================ key rotation
def test_rotated_key_cannot_sign_but_history_verifies(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    # A valid authorization exists signed by the active reviewer.
    service.keygen_rotate(paths, ctx["reviewer"]["kid"])
    # Rotated reviewer can no longer issue new authorizations.
    with pytest.raises(KeyringError, match="active"):
        service.create_authorization(
            paths,
            reviewer_kid=ctx["reviewer"]["kid"],
            request_path=request_path,
            expires_at=(ctx["base"] + timedelta(hours=2)).isoformat(timespec="seconds"),
            max_rows=100,
            out_path=tmp_path / "new-auth.json",
        )
    # ...but the previously signed authorization still validates and executes.
    result = service.execute_reveal(
        paths,
        request_path=request_path,
        authorization_path=auth_path,
        dataset_path=ctx["masked"],
        output_path=tmp_path / "out.sqlite",
        time_provider=ctx["clock"],
    )
    assert result.rows_revealed == 6


def test_revoked_key_rejects_even_historical_signatures(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    service.keygen_revoke(paths, ctx["reviewer"]["kid"])
    with pytest.raises(AuthorizationError):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=tmp_path / "out.sqlite",
            time_provider=ctx["clock"],
        )
    assert _denials(paths)[-1]["reason"] == "key-revoked"


# ================================================================ misc hardening
def test_secure_delete_removes_file(started, tmp_path):
    target = tmp_path / "sensitive.tmp"
    target.write_text("plaintext", encoding="utf-8")
    secure_delete(target)
    assert not target.exists()


def test_refusing_to_overwrite_existing_output(started, tmp_path):
    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    output = tmp_path / "exists.sqlite"
    output.write_text("x")
    with pytest.raises(ScopeError, match="overwrite"):
        service.execute_reveal(
            paths,
            request_path=request_path,
            authorization_path=auth_path,
            dataset_path=ctx["masked"],
            output_path=output,
            time_provider=ctx["clock"],
        )


def test_csv_reveal_round_trip(masked_workspace, tmp_path, monkeypatch):
    ctx = masked_workspace
    paths = ctx["paths"]
    from maskline.fixturegen import generate_fixture

    fixtures = generate_fixture(tmp_path / "raw2", seed=11, customers=4, orders=4, leads=3)
    policy = load_policy(EXAMPLE)
    csv_inventory = inspect_dataset(fixtures["csv"])
    result = execute_run(
        csv_inventory, policy, paths,
        secrets_store=SecretStore.from_env(),
    )
    masked_csv = result.output_path
    # CSV inputs are emitted as sqlite; verify a CSV-native path via a fresh
    # CSV-scoped request using the actual output (sqlite) fingerprint.
    base = datetime(2026, 11, 12, 9, 0, 0, tzinfo=UTC)
    source_clock = FakeClock(base)
    service.keygen_init(paths, now_iso=base.isoformat(timespec="seconds"))
    operator = service.keygen_generate(paths, "op2", "operator")
    reviewer = service.keygen_generate(paths, "rv2", "reviewer")
    out_inventory = inspect_dataset(masked_csv)
    scope = Scope(
        run_id=result.run_id,
        dataset_fingerprint=out_inventory.fingerprint,
        table="leads",
        columns=("contact_name",),
    )
    req = tmp_path / "creq.json"
    service.create_request(
        paths, operator_kid=operator["kid"], scope=scope, reason="csv case",
        out_path=req, now_iso=base.isoformat(timespec="seconds"),
    )
    auth = tmp_path / "cauth.json"
    service.create_authorization(
        paths, reviewer_kid=reviewer["kid"], request_path=req,
        expires_at=(base + timedelta(hours=1)).isoformat(timespec="seconds"),
        max_rows=100, out_path=auth, now_iso=base.isoformat(timespec="seconds"),
    )
    revealed = service.execute_reveal(
        paths, request_path=req, authorization_path=auth,
        dataset_path=masked_csv, output_path=tmp_path / "revealed-leads.sqlite",
        time_provider=source_clock,
    )
    assert revealed.rows_revealed == 3


# ============================================================== command line
def test_full_cli_two_person_flow(masked_workspace, tmp_path, capsys):
    ctx = masked_workspace
    paths = ctx["paths"]
    ws = str(paths.root)

    def w(*parts: str) -> list[str]:
        # --workspace is defined on each subparser, so it follows the command.
        return [parts[0], "--workspace", ws, *parts[1:]]

    expiry = (datetime.now(tz=UTC) + timedelta(hours=1)).isoformat(timespec="seconds")

    assert cli_main(w("keygen", "init")) == 0
    assert cli_main(w("keygen", "new", "--name", "alice", "--role", "operator")) == 0
    assert cli_main(w("keygen", "new", "--name", "bob", "--role", "reviewer")) == 0
    capsys.readouterr()  # discard setup output
    assert cli_main(w("keygen", "list")) == 0
    listing = capsys.readouterr().out
    operator_kid = next(line.split()[0].split("=")[1] for line in listing.splitlines() if "alice" in line)
    reviewer_kid = next(line.split()[0].split("=")[1] for line in listing.splitlines() if "bob" in line)

    request_path = tmp_path / "cli-req.json"
    assert cli_main(w(
        "reveal-request", "--operator-kid", operator_kid,
        "--run-id", ctx["run_id"], "--dataset", str(ctx["masked"]),
        "--table", ctx["table"], "--column", ctx["column"],
        "--reason", "CLI flow", "--out", str(request_path),
    )) == 0

    auth_path = tmp_path / "cli-auth.json"
    assert cli_main(w(
        "authorize", "--reviewer-kid", reviewer_kid,
        "--request", str(request_path), "--expires-at", expiry,
        "--max-rows", "100", "--out", str(auth_path),
    )) == 0

    output = tmp_path / "cli-plain.sqlite"
    assert cli_main(w(
        "reveal", "--request", str(request_path),
        "--authorization", str(auth_path),
        "--dataset", str(ctx["masked"]), "--out", str(output),
    )) == 0
    assert output.exists()
    assert cli_main(w("audit", "--verify")) == 0


# ============================================================== audit MAC loop
def test_audit_mac_verifies_and_detects_tampering(started, tmp_path):
    from maskline.reveal.keyring import Keyring
    from maskline.reveal.validator import verify_reveal_audit_macs

    ctx = started
    paths = ctx["paths"]
    request_path = _make_request(ctx, tmp_path)
    auth_path = _make_authorization(ctx, tmp_path, request_path)
    service.execute_reveal(
        paths,
        request_path=request_path,
        authorization_path=auth_path,
        dataset_path=ctx["masked"],
        output_path=tmp_path / "out.sqlite",
        time_provider=ctx["clock"],
    )
    keyring = Keyring(paths.keyring_dir)
    entries = read_audit_entries(paths.audit_path)
    verified = verify_reveal_audit_macs(keyring, entries)
    assert verified >= 4  # key events, request, authorization, claim, completion

    # Forge a reveal entry by altering a field without recomputing the MAC.
    tampered = [dict(entry) for entry in entries]
    for entry in tampered:
        if entry.get("event") == "reveal-completed":
            entry["rows_revealed"] = 999999
            break
    with pytest.raises(AuthorizationError, match="audit MAC mismatch"):
        verify_reveal_audit_macs(keyring, tampered)
