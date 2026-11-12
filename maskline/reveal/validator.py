"""Authorization chain validation and replay protection.

The validator is the single gate in front of any plaintext production. It
re-derives every check from the request and authorization bytes and the
keyring -- it never trusts caller-supplied conclusions. Every failure raises a
:class:`RevealControlError` *and* appends a rejection record to the audit log,
so a denied attempt leaves the same forensic trail as an accepted one.

Replay protection is implemented entirely through the audit chain: an
authorization is considered consumed the moment an execution claims it, and
any later execution referencing the same ``authorization_id`` is rejected.
Because every append first verifies the whole hash chain, the consumption
marker cannot be silently removed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..audit import AuditLog
from . import crypto
from .clock import Clock, parse_iso8601
from .errors import (
    AuthorizationError,
    ClockRollbackError,
    ReplayError,
    RevealControlError,
    ScopeError,
)
from .keyring import ROLE_OPERATOR, ROLE_REVIEWER, Keyring
from .records import (
    AUTHORIZATION_RECORD_TYPE,
    REQUEST_RECORD_TYPE,
    Scope,
    authorization_scope,
    load_authorization,
    load_request,
    request_scope,
)

AUDIT_EVENT_REQUEST = "reveal-request-created"
AUDIT_EVENT_AUTHORIZED = "reveal-authorized"
AUDIT_EVENT_CLAIMED = "reveal-claimed"
AUDIT_EVENT_COMPLETED = "reveal-completed"
AUDIT_EVENT_ABORTED = "reveal-aborted"
AUDIT_EVENT_DENIED = "reveal-denied"
AUDIT_EVENT_KEY = "reveal-key-event"

# Audit entries whose presence consumes an authorization.
CONSUMING_EVENTS = (AUDIT_EVENT_CLAIMED, AUDIT_EVENT_COMPLETED, AUDIT_EVENT_ABORTED)


class AuthorizationValidator:
    def __init__(
        self,
        keyring: Keyring,
        audit: AuditLog,
        clock: Clock,
    ) -> None:
        self.keyring = keyring
        self.audit = audit
        self.clock = clock

    # ------------------------------------------------------------- audit helper
    def _audit(self, event: str, **fields: Any) -> dict[str, Any]:
        body: dict[str, Any] = {"event": event, **fields}
        mac_key = self.keyring.audit_mac_key
        body["audit_mac"] = crypto.tag(crypto.DOMAIN_AUDIT, mac_key, body)
        return self.audit.append(body)

    def log_key_event(self, action: str, identity: dict[str, Any]) -> dict[str, Any]:
        return self._audit(
            AUDIT_EVENT_KEY,
            action=action,
            kid=identity["kid"],
            name=identity["name"],
            role=identity["role"],
            state=identity["state"],
            version=identity["version"],
        )

    def log_request_created(self, request_path: str, document: dict[str, Any]) -> dict[str, Any]:
        message = document["message"]
        return self._audit(
            AUDIT_EVENT_REQUEST,
            request_path=request_path,
            request_id=message["request_id"],
            operator_kid=message["operator_kid"],
            scope=message["scope"],
            reason=message["reason"],
        )

    def log_authorization_created(
        self, authorization_path: str, document: dict[str, Any]
    ) -> dict[str, Any]:
        message = document["message"]
        return self._audit(
            AUDIT_EVENT_AUTHORIZED,
            authorization_path=authorization_path,
            authorization_id=message["authorization_id"],
            request_id=message["request_id"],
            reviewer_kid=message["reviewer_kid"],
            expires_at=message["expires_at"],
            max_rows=message["max_rows"],
            scope=message["scope"],
        )

    def _deny(self, code: str, message: str, **context: Any) -> None:
        self._audit(AUDIT_EVENT_DENIED, reason=code, detail=message, **context)
        raise AuthorizationError(message, reason=code)

    def record_denial(self, code: str, detail: str, **context: Any) -> dict[str, Any]:
        """Append a reveal-denied entry without raising (caller raises its own error)."""
        return self._audit(AUDIT_EVENT_DENIED, reason=code, detail=detail, **context)

    # ------------------------------------------------------------------ scanning
    def _audit_entries(self) -> list[dict[str, Any]]:
        from ..audit import read_audit_entries

        if not self.audit.path.exists():
            return []
        return read_audit_entries(self.audit.path)

    def _is_consumed(self, authorization_id: str) -> dict[str, Any] | None:
        return next(
            (
                entry
                for entry in self._audit_entries()
                if entry.get("event") in CONSUMING_EVENTS
                and entry.get("authorization_id") == authorization_id
            ),
            None,
        )

    # ------------------------------------------------------------- full gateway
    def validate(
        self,
        request_path: str,
        authorization_path: str,
        *,
        requested_scope: Scope,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Validate the full chain and return a vetted execution context.

        On success the authorization is atomically claimed (a ``reveal-claimed``
        audit entry is appended) so a second invocation cannot reuse it.
        """
        request = load_request(request_path)
        authorization = load_authorization(authorization_path)
        req_message = request["message"]
        auth_message = authorization["message"]
        context: dict[str, Any] = {
            "request_path": str(request_path),
            "authorization_path": str(authorization_path),
            "request_id": req_message.get("request_id"),
            "authorization_id": auth_message.get("authorization_id"),
        }

        def fail(code: str, detail: str) -> None:
            self._deny(code, detail, **context)

        # 0. Clock guard: a rolled-back clock invalidates every expiry claim.
        try:
            current = now or self.clock.advance()
        except ClockRollbackError as exc:
            self._audit(AUDIT_EVENT_DENIED, reason=exc.reason, detail=str(exc), **context)
            raise

        # 1. Structural / type checks.
        if req_message.get("type") != REQUEST_RECORD_TYPE:
            fail("bad-request-type", "request document has the wrong record type")
        if auth_message.get("type") != AUTHORIZATION_RECORD_TYPE:
            fail(
                "bad-authorization-type",
                "authorization document has the wrong record type",
            )

        # 2. Operator signature on the request (role enforced by the keyring).
        operator_kid = req_message.get("operator_kid")
        signature = request.get("signature") or {}
        if signature.get("kid") != operator_kid:
            fail("request-signer-mismatch", "request signature kid does not match operator_kid")
        try:
            _operator, operator_material = self.keyring.load_verification_key(
                operator_kid, require_role=ROLE_OPERATOR
            )
        except RevealControlError as exc:
            fail(exc.reason, f"operator key unusable: {exc}")
        if not crypto.verify_tag(
            crypto.DOMAIN_REQUEST, operator_material, req_message, signature.get("tag")
        ):
            fail("request-signature-invalid", "request HMAC tag does not verify")

        # 3. Authorization binding: it must reference this exact request.
        if auth_message.get("request_id") != req_message.get("request_id"):
            fail("request-mismatch", "authorization is bound to a different request id")
        expected_request_hash = crypto.digest_hex(crypto.DOMAIN_REQUEST, req_message)
        if auth_message.get("request_hash") != expected_request_hash:
            fail(
                "request-hash-mismatch",
                "authorization request_hash does not match the supplied request content",
            )

        # 4. Reviewer signature and two-person separation.
        reviewer_kid = auth_message.get("reviewer_kid")
        auth_tag = (authorization.get("authorization") or {}).get("tag")
        if (authorization.get("authorization") or {}).get("kid") != reviewer_kid:
            fail("auth-signer-mismatch", "authorization tag kid does not match reviewer_kid")
        if reviewer_kid == operator_kid:
            fail(
                "separation-of-duties",
                "reviewer and operator must be different identities; same kid used",
            )
        try:
            _reviewer, reviewer_material = self.keyring.load_verification_key(
                reviewer_kid, require_role=ROLE_REVIEWER
            )
        except RevealControlError as exc:
            fail(exc.reason, f"reviewer key unusable: {exc}")
        if not crypto.verify_tag(
            crypto.DOMAIN_AUTHORIZATION, reviewer_material, auth_message, auth_tag
        ):
            fail("authorization-signature-invalid", "authorization HMAC tag does not verify")

        # 5. Expiry, evaluated against the guarded clock.
        try:
            expires_at = parse_iso8601(auth_message["expires_at"])
        except (KeyError, ValueError) as exc:
            fail("bad-expiry", f"authorization expiry is malformed: {exc}")
        if current >= expires_at:
            fail(
                "authorization-expired",
                f"authorization expired at {expires_at.isoformat()}; current time "
                f"{current.isoformat(timespec='seconds')}",
            )

        # 6. Scope: the requested execution slice must fit inside both the
        #    request scope and the authorized scope (they are normally equal,
        #    but containment is checked explicitly on both sides).
        try:
            req_scope = request_scope(request)
            auth_scope = authorization_scope(authorization)
        except ScopeError as exc:
            fail("malformed-scope", str(exc))
        if not auth_scope.contains(req_scope):
            fail(
                "scope-mismatch",
                "authorization scope is narrower than the request scope",
            )
        if not req_scope.contains(requested_scope) or not auth_scope.contains(requested_scope):
            fail(
                "scope-mismatch",
                "execution scope falls outside the request/authorization scope",
            )

        # 7. Row limit.
        max_rows = auth_message.get("max_rows")
        if not isinstance(max_rows, int) or max_rows <= 0:
            fail("bad-row-limit", "authorization max_rows must be a positive integer")

        # 8. Replay: one authorization may be consumed at most once.
        prior = self._is_consumed(auth_message["authorization_id"])
        if prior is not None:
            self._audit(
                AUDIT_EVENT_DENIED,
                reason="authorization-replay",
                detail=(
                    f"authorization {auth_message['authorization_id']} was already "
                    f"consumed by audit seq {prior.get('seq')} event {prior.get('event')}"
                ),
                **context,
            )
            raise ReplayError(
                f"authorization {auth_message['authorization_id']} was already consumed "
                f"by audit seq {prior.get('seq')} event {prior.get('event')}",
                reason="authorization-replay",
            )

        # 9. Atomic claim before any plaintext is produced.
        claim = self._audit(
            AUDIT_EVENT_CLAIMED,
            **context,
            operator_kid=operator_kid,
            reviewer_kid=reviewer_kid,
            expires_at=auth_message["expires_at"],
            max_rows=max_rows,
            scope=requested_scope.to_message(),
            executed_at=current.isoformat(timespec="seconds"),
        )
        return {
            "claim_seq": claim["seq"],
            "authorization_id": auth_message["authorization_id"],
            "request_id": req_message["request_id"],
            "operator_kid": operator_kid,
            "reviewer_kid": reviewer_kid,
            "expires_at": expires_at,
            "max_rows": max_rows,
            "scope": requested_scope,
            "request": request,
            "authorization": authorization,
        }

    # -------------------------------------------------------------- terminal log
    def log_completion(self, vetted: dict[str, Any], rows_revealed: int, output_path: str) -> dict[str, Any]:
        return self._audit(
            AUDIT_EVENT_COMPLETED,
            authorization_id=vetted["authorization_id"],
            request_id=vetted["request_id"],
            operator_kid=vetted["operator_kid"],
            reviewer_kid=vetted["reviewer_kid"],
            scope=vetted["scope"].to_message(),
            rows_authorized=vetted["max_rows"],
            rows_revealed=rows_revealed,
            output_path=output_path,
        )

    def log_abort(self, vetted: dict[str, Any], rows_revealed: int, reason: str, detail: str) -> dict[str, Any]:
        return self._audit(
            AUDIT_EVENT_ABORTED,
            authorization_id=vetted["authorization_id"],
            request_id=vetted["request_id"],
            operator_kid=vetted["operator_kid"],
            reviewer_kid=vetted["reviewer_kid"],
            scope=vetted["scope"].to_message(),
            rows_revealed_before_abort=rows_revealed,
            reason=reason,
            detail=detail,
        )


def verify_reveal_audit_macs(keyring: Keyring, entries: list[dict[str, Any]]) -> int:
    """Recompute the audit MAC of every controlled-reveal audit entry.

    The hash chain already proves append-only ordering and detects content
    edits; this additional check proves that each reveal entry was produced by
    someone holding the keyring's audit key. Returns the number of entries
    verified and raises :class:`AuthorizationError` on the first bad MAC.
    Entries without an ``audit_mac`` (ordinary masking runs) are skipped.
    """
    mac_key = keyring.audit_mac_key
    # Envelope fields are added by AuditLog.append *after* the MAC is computed,
    # so they must be excluded when recomputing. Their integrity is separately
    # guaranteed by the audit hash chain; the MAC authenticates business content.
    envelope_fields = {"audit_mac", "ts", "seq", "prev_hash", "entry_hash"}
    verified = 0
    for entry in entries:
        provided = entry.get("audit_mac")
        if provided is None:
            continue
        body = {key: value for key, value in entry.items() if key not in envelope_fields}
        if not crypto.verify_tag(crypto.DOMAIN_AUDIT, mac_key, body, provided):
            raise AuthorizationError(
                f"audit MAC mismatch at seq {entry.get('seq')}; a reveal entry was "
                "forged or altered without the keyring audit key",
                reason="audit-mac-invalid",
            )
        verified += 1
    return verified
