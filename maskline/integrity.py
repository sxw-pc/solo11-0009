"""Streaming, optionally keyed checksums for run evidence and verification.

Per-batch checksums are computed over the rows as stored in the target
database (read back after insert), so `verify` can recompute them later from
the target database alone. In keyed mode the checksums are HMAC-SHA256 with a
purpose-specific key derived from the deployment ``hmac_salt``; without the
secret file they can neither be recomputed nor forged, which is exactly what
the verify command's degraded mode accounts for.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .utils import canonical_json, normalize_sqlite_value

CHECKSUM_HMAC = "hmac-sha256"
CHECKSUM_PLAIN = "sha256"
CHECKSUM_MODES = (CHECKSUM_HMAC, CHECKSUM_PLAIN)

_KEY_PURPOSE = b"maskline/verify-batch-checksum/v1"
_STREAM_PREFIX = b"maskline-checksum/v1\n"


def derive_verify_key(hmac_salt: str) -> bytes:
    """Derive the purpose-specific checksum key from the deployment salt.

    The raw ``hmac_salt`` is never used directly for evidence checksums, so
    batch checksums cannot be confused with `hash` transformer outputs.
    """
    return hmac.new(hmac_salt.encode("utf-8"), _KEY_PURPOSE, hashlib.sha256).digest()


class StreamChecksum:
    """Incremental checksum over a canonical header plus row values.

    Rows are fed one at a time, so neither the runner nor the verifier ever
    needs to hold more than one row of a batch in memory for hashing.
    """

    def __init__(self, mode: str, key: bytes | None, header: dict[str, Any]) -> None:
        if mode == CHECKSUM_HMAC:
            if key is None:
                raise ValueError("hmac-sha256 checksums require a key")
            self._ctx: Any = hmac.new(key, digestmod=hashlib.sha256)
        elif mode == CHECKSUM_PLAIN:
            self._ctx = hashlib.sha256()
        else:
            raise ValueError(f"unknown checksum mode: {mode!r}")
        self._ctx.update(_STREAM_PREFIX)
        self._ctx.update(canonical_json(header).encode("utf-8"))
        self._ctx.update(b"\n")

    def add_values(self, values: list[Any] | tuple[Any, ...]) -> None:
        payload = canonical_json([normalize_sqlite_value(value) for value in values])
        self._ctx.update(payload.encode("utf-8"))
        self._ctx.update(b"\n")

    def hexdigest(self) -> str:
        return self._ctx.hexdigest()


def batch_checksum_header(run_id: str, table: str, batch: int) -> dict[str, Any]:
    return {"kind": "batch", "run_id": run_id, "table": table, "batch": batch}


def pseudomap_checksum_header() -> dict[str, Any]:
    return {"kind": "pseudonym_map"}
