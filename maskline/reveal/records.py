"""Reveal request and authorization record formats.

Both artifacts are single JSON documents with two top-level members:

* ``message``  -- the canonical, signed content (all business fields live here);
* ``signature`` / ``authorization`` -- a tagged object whose ``tag`` is the
  HMAC over the *canonical JSON of the message* under the signer's key.

Signing the message rather than the whole document means signature
verification is independent of on-disk key order or whitespace, and any change
to a business field changes the canonical bytes and breaks the tag.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..utils import atomic_write_text
from . import crypto
from .clock import parse_iso8601, utc_now_iso
from .errors import ScopeError

REQUEST_VERSION = 1
AUTHORIZATION_VERSION = 1
REQUEST_RECORD_TYPE = "reveal-request"
AUTHORIZATION_RECORD_TYPE = "reveal-authorization"


def new_request_id() -> str:
    return "req_" + secrets.token_hex(16)


def new_authorization_id() -> str:
    return "auth_" + secrets.token_hex(16)


@dataclass(frozen=True)
class Scope:
    """The exact slice of data a request is allowed to touch."""

    run_id: str
    dataset_fingerprint: str
    table: str
    columns: tuple[str, ...]

    def to_message(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "dataset_fingerprint": self.dataset_fingerprint,
            "table": self.table,
            "columns": sorted(self.columns),
        }

    @classmethod
    def from_message(cls, message: dict[str, Any]) -> "Scope":
        try:
            columns = message["columns"]
            return cls(
                run_id=str(message["run_id"]),
                dataset_fingerprint=str(message["dataset_fingerprint"]),
                table=str(message["table"]),
                columns=tuple(columns),
            )
        except (KeyError, TypeError) as exc:
            raise ScopeError(f"malformed scope: missing {exc}") from exc

    def contains(self, other: "Scope") -> bool:
        """True when ``other`` fits inside this (authorized) scope."""
        return (
            self.run_id == other.run_id
            and self.dataset_fingerprint == other.dataset_fingerprint
            and self.table == other.table
            and set(other.columns).issubset(set(self.columns))
        )


def _load_document(path: Path, expected_type: str) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"{expected_type} file not found: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScopeError(f"{expected_type} file is invalid JSON: {exc.msg}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("message"), dict):
        raise ScopeError(f"{expected_type} file has no message object")
    if document["message"].get("type") != expected_type:
        raise ScopeError(
            f"expected type {expected_type!r}, got {document['message'].get('type')!r}"
        )
    return document


def _write_document(path: Path, document: dict[str, Any]) -> None:
    atomic_write_text(
        Path(path),
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        mode=0o600,
    )


# --------------------------------------------------------------------- requests
def build_request_message(
    *,
    scope: Scope,
    reason: str,
    operator_kid: str,
    now_iso: str | None = None,
) -> dict[str, Any]:
    reason = (reason or "").strip()
    if not reason:
        raise ScopeError("a reveal request must state a reason")
    if len(reason) > 1000:
        raise ScopeError("reason is too long (1000 characters maximum)")
    return {
        "type": REQUEST_RECORD_TYPE,
        "version": REQUEST_VERSION,
        "request_id": new_request_id(),
        "created_at": now_iso or utc_now_iso(),
        "operator_kid": operator_kid,
        "reason": reason,
        "scope": scope.to_message(),
    }


def sign_request(message: dict[str, Any], operator_material: bytes) -> dict[str, Any]:
    document = {
        "message": message,
        "signature": {
            "alg": crypto.ALGORITHM,
            "kid": message["operator_kid"],
            "tag": crypto.tag(crypto.DOMAIN_REQUEST, operator_material, message),
        },
    }
    return document


def write_request(path: Path, document: dict[str, Any]) -> Path:
    _write_document(path, document)
    return Path(path)


def load_request(path: Path) -> dict[str, Any]:
    return _load_document(Path(path), REQUEST_RECORD_TYPE)


def request_scope(document: dict[str, Any]) -> Scope:
    return Scope.from_message(document["message"]["scope"])


# ---------------------------------------------------------------- authorizations
def build_authorization_message(
    *,
    request: dict[str, Any],
    reviewer_kid: str,
    expires_at: str,
    max_rows: int,
    now_iso: str | None = None,
) -> dict[str, Any]:
    request_message = request["message"]
    if isinstance(max_rows, bool):
        raise ScopeError("max_rows must be a positive integer, not a boolean")
    max_rows = int(max_rows)
    if max_rows <= 0:
        raise ScopeError("max_rows must be a positive integer")
    expiry = parse_iso8601(expires_at)
    created = parse_iso8601(now_iso) if now_iso else parse_iso8601(utc_now_iso())
    if expiry <= created:
        raise ScopeError("expires_at must be later than the authorization time")
    return {
        "type": AUTHORIZATION_RECORD_TYPE,
        "version": AUTHORIZATION_VERSION,
        "authorization_id": new_authorization_id(),
        "created_at": (now_iso or created.isoformat(timespec="seconds")),
        "reviewer_kid": reviewer_kid,
        "expires_at": expiry.isoformat(timespec="seconds"),
        "max_rows": max_rows,
        "request_id": request_message["request_id"],
        "request_hash": crypto.digest_hex(
            crypto.DOMAIN_REQUEST, request_message
        ),
        "scope": request_message["scope"],
    }


def sign_authorization(message: dict[str, Any], reviewer_material: bytes) -> dict[str, Any]:
    return {
        "message": message,
        "authorization": {
            "alg": crypto.ALGORITHM,
            "kid": message["reviewer_kid"],
            "tag": crypto.tag(crypto.DOMAIN_AUTHORIZATION, reviewer_material, message),
        },
    }


def write_authorization(path: Path, document: dict[str, Any]) -> Path:
    _write_document(path, document)
    return Path(path)


def load_authorization(path: Path) -> dict[str, Any]:
    return _load_document(Path(path), AUTHORIZATION_RECORD_TYPE)


def authorization_scope(document: dict[str, Any]) -> Scope:
    return Scope.from_message(document["message"]["scope"])
