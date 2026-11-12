"""Injectable UTC clock so retention/grace transitions are testable without sleeping."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Callable


class Clock:
    """Wall-clock UTC by default; tests pin or advance a fixed instant."""

    def __init__(self, fixed: datetime | None = None) -> None:
        self._fixed = fixed

    @classmethod
    def pinned(cls, when: datetime) -> "Clock":
        if when.tzinfo is None:
            raise ValueError("pinned clock requires a timezone-aware datetime")
        return cls(fixed=when)

    @classmethod
    def from_env(cls) -> "Clock":
        """Build a clock, honoring MASKLINE_NOW (ISO-8601) when set.

        The variable exists so CLI/integration tests can drive retention
        transitions deterministically. It is not documented for production use.
        """
        override = os.environ.get("MASKLINE_NOW")
        if override:
            parsed = datetime.fromisoformat(override)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return cls(fixed=parsed)
        return cls()

    def now(self) -> datetime:
        return self._fixed if self._fixed is not None else datetime.now(timezone.utc)

    def now_iso(self) -> str:
        return self.now().isoformat(timespec="seconds")

    def advance(self, delta: timedelta) -> None:
        if self._fixed is None:
            self._fixed = datetime.now(timezone.utc)
        self._fixed = self._fixed + delta

    def iso_after(self, days: int) -> str:
        return (self.now() + timedelta(days=days)).isoformat(timespec="seconds")

    def override(self, when: datetime) -> None:
        self._fixed = when


def default_clock_factory() -> Callable[[], Clock]:
    return Clock
