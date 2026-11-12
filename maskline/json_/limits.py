"""Hard resource limits and fail-closed JSON parsing for untrusted cells.

Two guards run *before* ``json.loads`` so that a hostile document cannot reach
the recursive parser:

1. byte-size cap on the raw cell text;
2. a single linear scan that tracks bracket nesting depth (strings, escapes and
   structural whitespace cannot confuse it).

Both limits are configurable per column through the policy but clamped to hard
ceilings, so a policy cannot disable the protection outright.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_BYTES = 1 << 20  # 1 MiB per document
HARD_MAX_DEPTH = 256
HARD_MAX_BYTES = 16 << 20  # 16 MiB

# Reason codes shared with the processing engine (kept as plain strings to
# avoid an import cycle back into json_.engine).
REASON_TOO_LARGE = "too_large"
REASON_TOO_DEEP = "too_deep"


class JsonLimitError(ValueError):
    """Raised when a document exceeds the configured depth or size cap."""

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class JsonLimits:
    max_depth: int = DEFAULT_MAX_DEPTH
    max_bytes: int = DEFAULT_MAX_BYTES

    @classmethod
    def from_policy(
        cls,
        max_depth: int | None = None,
        max_bytes: int | None = None,
    ) -> "JsonLimits":
        depth = DEFAULT_MAX_DEPTH if max_depth is None else int(max_depth)
        size = DEFAULT_MAX_BYTES if max_bytes is None else int(max_bytes)
        if depth < 1 or depth > HARD_MAX_DEPTH:
            raise ValueError(
                f"json.max_depth must be between 1 and {HARD_MAX_DEPTH}"
            )
        if size < 1 or size > HARD_MAX_BYTES:
            raise ValueError(
                f"json.max_bytes must be between 1 and {HARD_MAX_BYTES}"
            )
        return cls(max_depth=depth, max_bytes=size)


def raw_depth(text: str) -> int:
    """Return the maximum bracket nesting depth of a JSON text.

    Only ``{`` and ``[`` open levels; characters inside strings (including
    escaped quotes) are ignored. Malformed text still gets a depth estimate,
    which is sufficient as a pre-parse guard.
    """
    depth = 0
    peak = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > peak:
                peak = depth
        elif char in "}]":
            depth = max(0, depth - 1)
    return peak


def safe_loads(text: str, limits: JsonLimits) -> Any:
    """Parse JSON text, rejecting oversize or over-deep documents first."""
    raw = text.strip()
    encoded_size = len(raw.encode("utf-8"))
    if encoded_size > limits.max_bytes:
        raise JsonLimitError(
            f"JSON document is {encoded_size} bytes, "
            f"exceeds limit of {limits.max_bytes} bytes",
            reason=REASON_TOO_LARGE,
        )
    depth = raw_depth(raw)
    if depth > limits.max_depth:
        raise JsonLimitError(
            f"JSON nesting depth is {depth}, exceeds limit of {limits.max_depth}",
            reason=REASON_TOO_DEEP,
        )
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"invalid JSON document: {exc}") from exc
