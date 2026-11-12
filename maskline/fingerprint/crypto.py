"""Keyed cryptographic primitives for delivery fingerprints.

All marking decisions are HMAC-SHA256 based. The master key never leaves the
local machine; every delivery gets an independently derived sub-key, so one
delivery's parameters cannot be derived from another's, and no parameter stored
in a manifest is sufficient to recover the master key (HMAC is a PRF, and the
manifest stores only its outputs / hashes of its outputs).
"""

from __future__ import annotations

import hashlib
import hmac
import math
from typing import Any, Iterable

from ..utils import canonical_json

# Domain-separation labels. Reusing a label across contexts would mix unrelated
# bit streams; keep them unique and stable (changing them invalidates manifests).
DOMAIN_SUBKEY = b"maskline-fp/v1/subkey"
DOMAIN_CELL_BIT = b"maskline-fp/v1/cell-bit"
DOMAIN_CANARY_PICK = b"maskline-fp/v1/canary-pick"
DOMAIN_CANARY_VALUE = b"maskline-fp/v1/canary-value"
DOMAIN_ORDER_BIT = b"maskline-fp/v1/order-bit"
DOMAIN_CANARY_KEY = b"maskline-fp/v1/canary-key"
DOMAIN_CELL_FP = b"maskline-fp/v1/cell-fingerprint"
DOMAIN_ROW_SEED = b"maskline-fp/v1/row-seed"
DOMAIN_ANCHOR = b"maskline-fp/v1/anchor"


def row_seed(subkey: bytes, delivery_id: str, dataset_name: str, key_text: str) -> str:
    """Stable per-row secret seed; all cell/order marks derive from it.

    Using an indirection lets verification recover the seed through a fallback
    anchor column (see anchor_digest) when the primary key column is cropped.
    """
    message = canonical_json([delivery_id, dataset_name, key_text]).encode("utf-8")
    return _hmac(subkey, DOMAIN_ROW_SEED, message).hex()


def anchor_digest(subkey: bytes, column: str, canonical_value: str) -> str:
    """Keyed digest of a fallback anchor cell, stored in the manifest index."""
    message = canonical_json([column, canonical_value]).encode("utf-8")
    return _hmac(subkey, DOMAIN_ANCHOR, message).hex()


def derive_subkey(master_key: str | bytes, delivery_id: str) -> bytes:
    """Derive the per-delivery secret from the local master key."""
    if isinstance(master_key, str):
        master_key = master_key.encode("utf-8")
    return hmac.new(master_key, DOMAIN_SUBKEY + delivery_id.encode("utf-8"),
                    hashlib.sha256).digest()


def _hmac(subkey: bytes, domain: bytes, message: bytes) -> bytes:
    return hmac.new(subkey, domain + b"|" + message, hashlib.sha256).digest()


def hmac_bit(subkey: bytes, domain: bytes, parts: Iterable[Any]) -> int:
    """Deterministic pseudorandom bit for a structured message."""
    message = canonical_json(list(parts)).encode("utf-8")
    return _hmac(subkey, domain, message)[0] & 1


def hmac_uniform(subkey: bytes, domain: bytes, parts: Iterable[Any], modulus: int) -> int:
    """Deterministic pseudorandom integer in [0, modulus) with rejection bias removed."""
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    message = canonical_json(list(parts)).encode("utf-8")
    digest = _hmac(subkey, domain, message)
    # 64-bit value; rejection sampling against the largest multiple of modulus.
    value = int.from_bytes(digest[:8], "big")
    limit = (1 << 64) - ((1 << 64) % modulus)
    while value >= limit:
        digest = hashlib.sha256(digest).digest()
        value = int.from_bytes(digest[:8], "big")
    return value % modulus


def hmac_token(subkey: bytes, domain: bytes, parts: Iterable[Any], length: int = 16) -> str:
    """Deterministic hex token (used for canary row keys)."""
    message = canonical_json(list(parts)).encode("utf-8")
    digest = _hmac(subkey, domain, message)
    # Expand deterministically if a longer token is requested.
    while len(digest) < length:
        digest += hashlib.sha256(digest).digest()
    return digest[:length].hex()


def cell_fingerprint(subkey: bytes, column: str, canonical_value: str) -> str:
    """Keyed fingerprint of a canary cell value. The value itself is not stored."""
    message = canonical_json([column, canonical_value]).encode("utf-8")
    return _hmac(subkey, DOMAIN_CELL_FP, message).hex()


def stable_key(value: Any) -> str:
    """Canonical string form of a row key, robust to int/float formatting drift."""
    if isinstance(value, bool):
        return "b:" + ("1" if value else "0")
    if isinstance(value, int):
        return f"i:{value}"
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return f"i:{int(value)}"
        return f"f:{value!r}"
    if value is None:
        return "n:"
    return "s:" + str(value)
