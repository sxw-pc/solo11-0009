"""Cryptographic primitives for the controlled reveal workflow.

Only standard-library primitives are used (``hashlib`` and ``hmac``). The
design is *symmetric*: each identity owns a random HMAC key, and verification
requires access to the same key via the local, permission-protected keyring.
This is an explicit, documented trade-off of an offline, dependency-free
system -- see ``docs/controlled-reveal.md`` and ``docs/threat-model.md``.

Two construction details matter:

* **Domain separation.** A tag is always computed over a fixed ASCII domain
  prefix followed by the canonical JSON of a message. A request signature can
  therefore never be replayed as an authorization tag or as an audit MAC,
  even if the byte payload happens to collide.
* **Canonical serialization.** Messages are hashed with
  :func:`maskline.utils.canonical_json` (sorted keys, no whitespace), so the
  tag is independent of dict ordering and the on-disk JSON layout.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping

from ..utils import canonical_json

ALGORITHM = "HMAC-SHA256"
KEY_BYTES = 32  # 256-bit random keys
FINGERPRINT_BYTES = 16  # first 128 bits of the public fingerprint

# Domain prefixes. They are fixed, distinct ASCII strings; changing any of
# them invalidates every artifact produced under the old value, which is the
# intended behavior for a protocol version.
DOMAIN_REQUEST = b"maskline-reveal-request/v1\x00"
DOMAIN_AUTHORIZATION = b"maskline-reveal-authorization/v1\x00"
DOMAIN_KEYRING = b"maskline-keyring-entry/v1\x00"
DOMAIN_AUDIT = b"maskline-audit-mac/v1\x00"
DOMAIN_CLOCK = b"maskline-monotonic-clock/v1\x00"


def new_secret() -> bytes:
    """Generate a fresh 256-bit HMAC key using the OS CSPRNG."""
    import secrets

    return secrets.token_bytes(KEY_BYTES)


def encode_key(material: bytes) -> str:
    import base64

    return base64.b64encode(material).decode("ascii")


def decode_key(encoded: str) -> bytes:
    import base64

    try:
        material = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, AttributeError) as exc:
        raise ValueError("key material is not valid base64") from exc
    if len(material) != KEY_BYTES:
        raise ValueError(f"expected a {KEY_BYTES}-byte key, got {len(material)}")
    return material


def key_fingerprint(material: bytes) -> str:
    """Public, non-secret identifier for a key (used as ``kid``)."""
    return hashlib.sha256(b"maskline-key-fingerprint/v1\x00" + material).hexdigest()[
        : FINGERPRINT_BYTES * 2
    ]


def _message_bytes(message: Any) -> bytes:
    if not isinstance(message, Mapping):
        raise TypeError("signed message must be a JSON object")
    return canonical_json(message).encode("utf-8")


def tag(domain: bytes, material: bytes, message: Mapping[str, Any]) -> str:
    """Return a hex HMAC-SHA256 tag over ``domain || canonical(message)``."""
    return hmac.new(
        material, domain + _message_bytes(message), hashlib.sha256
    ).hexdigest()


def verify_tag(
    domain: bytes, material: bytes, message: Mapping[str, Any], provided: str
) -> bool:
    """Constant-time verification of a hex HMAC tag."""
    if not isinstance(provided, str):
        return False
    try:
        expected = tag(domain, material, message)
    except TypeError:
        return False
    return hmac.compare_digest(expected, provided)


def digest_hex(domain: bytes, message: Mapping[str, Any]) -> str:
    """Keyless domain-separated SHA-256 over a message."""
    return hashlib.sha256(domain + _message_bytes(message)).hexdigest()
