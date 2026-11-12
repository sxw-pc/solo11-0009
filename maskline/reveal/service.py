"""High-level service functions wiring the keyring, records, validator and
executor together. These are the single entry points used by the CLI and the
tests, so that policy (who may sign what, what gets audited) lives in one
place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..config import Paths
from ..pseudomap import PseudoMap
from .clock import Clock
from .errors import RevealControlError
from .keyring import Keyring
from .records import (
    Scope,
    build_authorization_message,
    build_request_message,
    load_authorization,
    load_request,
    sign_authorization,
    sign_request,
    write_authorization,
    write_request,
)
from .executor import RevealExecutor
from .validator import AuthorizationValidator


def build_components(paths: Paths, *, time_provider=None) -> tuple[Keyring, AuditLog, Clock]:
    keyring = Keyring(paths.keyring_dir)
    if not keyring.exists():
        raise RevealControlError(
            f"keyring not initialized at {paths.keyring_dir}; run 'maskline keygen init'"
        )
    audit = AuditLog(paths.audit_path)
    if time_provider is None:
        time_provider = _default_provider()
    clock = Clock(
        anchor_path=paths.clock_anchor_path,
        mac_key=keyring.audit_mac_key,
        time_provider=time_provider,
    )
    return keyring, audit, clock


def _default_provider():
    from .clock import default_time_provider

    return default_time_provider


# --------------------------------------------------------------------- keyring
def keygen_init(paths: Paths, now_iso: str | None = None) -> Keyring:
    from .clock import utc_now_iso

    keyring = Keyring(paths.keyring_dir)
    paths.ensure_runtime_dirs()
    keyring.initialize(now_iso or utc_now_iso())
    return keyring


def keygen_generate(
    paths: Paths, name: str, role: str, now_iso: str | None = None
) -> dict[str, Any]:
    from .clock import utc_now_iso

    keyring, audit, _clock = build_components(paths)
    identity = keyring.generate(name, role, now_iso or utc_now_iso())
    validator = AuthorizationValidator(keyring, audit, _clock)
    validator.log_key_event("generated", identity.to_record())
    return identity.to_record()


def keygen_rotate(paths: Paths, kid: str, now_iso: str | None = None) -> dict[str, Any]:
    from .clock import utc_now_iso

    keyring, audit, clock = build_components(paths)
    identity = keyring.rotate(kid, now_iso or utc_now_iso())
    AuthorizationValidator(keyring, audit, clock).log_key_event(
        "rotated", identity.to_record()
    )
    return identity.to_record()


def keygen_revoke(paths: Paths, kid: str, now_iso: str | None = None) -> dict[str, Any]:
    from .clock import utc_now_iso

    keyring, audit, clock = build_components(paths)
    identity = keyring.revoke(kid, now_iso or utc_now_iso())
    AuthorizationValidator(keyring, audit, clock).log_key_event(
        "revoked", identity.to_record()
    )
    return identity.to_record()


def list_identities(paths: Paths) -> list[dict[str, Any]]:
    keyring, _audit, _clock = build_components(paths)
    return [item.to_record() for item in keyring.list_identities()]


# --------------------------------------------------------------------- request
def create_request(
    paths: Paths,
    *,
    operator_kid: str,
    scope: Scope,
    reason: str,
    out_path: str | Path,
    now_iso: str | None = None,
) -> Path:
    keyring, audit, clock = build_components(paths)
    _identity, material = keyring.load_signing_key(operator_kid, require_role="operator")
    message = build_request_message(
        scope=scope, reason=reason, operator_kid=operator_kid, now_iso=now_iso
    )
    document = sign_request(message, material)
    target = write_request(Path(out_path), document)
    AuthorizationValidator(keyring, audit, clock).log_request_created(
        str(target), document
    )
    return target


# --------------------------------------------------------------- authorization
def create_authorization(
    paths: Paths,
    *,
    reviewer_kid: str,
    request_path: str | Path,
    expires_at: str,
    max_rows: int,
    out_path: str | Path,
    now_iso: str | None = None,
) -> Path:
    keyring, audit, clock = build_components(paths)
    _identity, material = keyring.load_signing_key(reviewer_kid, require_role="reviewer")
    request = load_request(request_path)
    # Separation of duties is enforced at signing time as well, not only at
    # execution, so a reviewer cannot authorize their own request.
    if request["message"]["operator_kid"] == reviewer_kid:
        raise RevealControlError(
            "reviewer must be a different identity from the request operator",
            reason="separation-of-duties",
        )
    message = build_authorization_message(
        request=request,
        reviewer_kid=reviewer_kid,
        expires_at=expires_at,
        max_rows=max_rows,
        now_iso=now_iso,
    )
    document = sign_authorization(message, material)
    target = write_authorization(Path(out_path), document)
    AuthorizationValidator(keyring, audit, clock).log_authorization_created(
        str(target), document
    )
    return target


# ---------------------------------------------------------------------- execute
def execute_reveal(
    paths: Paths,
    *,
    request_path: str | Path,
    authorization_path: str | Path,
    dataset_path: str | Path,
    output_path: str | Path,
    time_provider=None,
):
    keyring, audit, clock = build_components(paths, time_provider=time_provider)
    with PseudoMap(paths.pseudomap_db) as mapping:
        executor = RevealExecutor(
            keyring,
            audit,
            clock,
            mapping,
            manifest_dir=paths.manifest_dir,
        )
        return executor.execute(
            request_path=request_path,
            authorization_path=authorization_path,
            dataset_path=dataset_path,
            output_path=output_path,
        )


def describe_request(path: str | Path) -> dict[str, Any]:
    return load_request(path)["message"]


def describe_authorization(path: str | Path) -> dict[str, Any]:
    return load_authorization(path)["message"]


def verify_audit(paths: Paths) -> dict[str, int]:
    """Verify the hash chain and, if a keyring exists, the reveal entry MACs."""
    from ..audit import read_audit_entries, verify_audit as verify_chain
    from .validator import verify_reveal_audit_macs

    chain = verify_chain(paths.audit_path)
    mac_entries = 0
    keyring = Keyring(paths.keyring_dir)
    if keyring.exists():
        mac_entries = verify_reveal_audit_macs(keyring, read_audit_entries(paths.audit_path))
    return {"entries": chain.entries, "reveal_mac_verified": mac_entries}
