"""Monotonic wall-clock guard against clock rollback.

Authorization expiry is checked against the current wall clock, so an
operator who can set the machine clock backwards could otherwise resurrect an
expired authorization. We cannot prevent clock changes, but we can detect a
backwards jump that crosses the last-observed instant and refuse to run.

State is a small anchor file written atomically after every successful guard
check. The anchor is authenticated with an HMAC key held in the keyring's
audit slot so that an attacker cannot simply edit the recorded timestamp.

A :class:`Clock` is intentionally injectable: tests pass a fake clock to
simulate expiry without sleeping.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..utils import atomic_write_text
from . import crypto
from .errors import ClockRollbackError

CLOCK_ANCHOR_VERSION = 1


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_iso8601(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, requiring an explicit timezone."""
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp {value!r} has no timezone offset; UTC is required")
    return parsed


def default_time_provider() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Clock:
    """Time source plus a persisted, MAC-protected monotonic anchor."""

    anchor_path: Path
    mac_key: bytes
    time_provider: Callable[[], datetime] = default_time_provider
    max_skew_seconds: int = 0

    def now(self) -> datetime:
        return self.time_provider().astimezone(timezone.utc)

    def now_iso(self) -> str:
        return self.now().isoformat(timespec="seconds")

    def _read_anchor(self) -> dict[str, str] | None:
        if not self.anchor_path.exists():
            return None
        try:
            payload = json.loads(self.anchor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ClockRollbackError(
                f"clock anchor is unreadable: {exc}", reason="clock-anchor-tampered"
            ) from exc
        body = {k: v for k, v in payload.items() if k != "mac"}
        mac = payload.get("mac")
        if not crypto.verify_tag(crypto.DOMAIN_CLOCK, self.mac_key, body, mac):
            raise ClockRollbackError(
                "clock anchor MAC does not verify; the anchor was tampered with",
                reason="clock-anchor-tampered",
            )
        return body

    def check_monotonic(self) -> datetime:
        """Return now, rejecting if the clock moved backwards since last run."""
        now = self.now()
        anchor = self._read_anchor()
        if anchor is not None:
            try:
                last_seen = parse_iso8601(anchor["last_seen"])
            except (KeyError, ValueError) as exc:
                raise ClockRollbackError(
                    "clock anchor is malformed", reason="clock-anchor-tampered"
                ) from exc
            # A small backwards tolerance is allowed only when explicitly
            # configured; by default any backwards move is rejected.
            if now < last_seen and (last_seen - now).total_seconds() > self.max_skew_seconds:
                raise ClockRollbackError(
                    f"system clock {now.isoformat()} is earlier than the last observed "
                    f"time {last_seen.isoformat()}; refusing to evaluate authorizations",
                    reason="clock-rollback",
                )
        return now

    def advance(self) -> datetime:
        """Verify monotonicity and persist the new high-water mark."""
        now = self.check_monotonic()
        body = {
            "version": CLOCK_ANCHOR_VERSION,
            "last_seen": now.isoformat(timespec="seconds"),
        }
        record = dict(body)
        record["mac"] = crypto.tag(crypto.DOMAIN_CLOCK, self.mac_key, body)
        atomic_write_text(
            self.anchor_path,
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            mode=0o600,
        )
        try:
            os.chmod(self.anchor_path, 0o600)
        except OSError:
            pass
        return now
