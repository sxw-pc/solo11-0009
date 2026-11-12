"""JSON path grammar: parsing, canonical rendering, and structural matching.

A path is a small, unambiguous JSONPath-style subset:

* ``$``              : document root (the whole document, including a scalar)
* ``$.foo``          : object key
* ``$["foo.bar"]``   : object key whose name is not a bare identifier
* ``$.items[*].phone``: every element of the ``items`` array, then key ``phone``
* ``$.items[0].phone``: one concrete array element

Only ``[*]`` is a wildcard. Recursive descent (``..``), filters, and slices
are deliberately unsupported: every rule must name a concrete structural
location so that findings and policy entries stay auditable. Paths are parsed
once at policy load time and re-rendered canonically, so equivalent spellings
(``$["a"].b`` and ``$.a.b``) collapse to one identity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

# A bare key may contain letters (incl. CJK), digits, underscore and hyphen,
# but must start with a letter or underscore. Anything else needs brackets.
_BARE_KEY_RE = re.compile(r"[^\W\d][\w-]*", re.UNICODE)
_SIMPLE_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")

# Segment tags
KEY = "key"
INDEX = "index"
WILDCARD = "wildcard"


class JsonPathError(ValueError):
    """Raised when a policy path does not conform to the path grammar."""


@dataclass(frozen=True)
class Segment:
    kind: str
    value: Any = None


@dataclass(frozen=True)
class JsonPath:
    """Parsed JSON path. ``segments == ()`` represents the root ``$``."""

    segments: tuple[Segment, ...]

    def render(self) -> str:
        return render_path(self.segments)

    def __str__(self) -> str:
        return self.render()


def _parse_quoted_key(text: str, pos: int) -> tuple[str, int]:
    # Consume the opening quote; only double-quoted bracket keys are allowed.
    assert text[pos] == '"'
    pos += 1
    chars: list[str] = []
    while pos < len(text):
        char = text[pos]
        if char == '"':
            if not chars:
                raise JsonPathError(f"empty quoted key in path {text!r}")
            return "".join(chars), pos + 1
        if char == "\\":
            if pos + 1 >= len(text):
                raise JsonPathError(f"dangling escape in path {text!r}")
            escaped = text[pos + 1]
            if escaped not in {'"', "\\"}:
                raise JsonPathError(
                    f"unsupported escape \\{escaped} in path {text!r}; "
                    "only \\\" and \\\\ are allowed"
                )
            chars.append(escaped)
            pos += 2
            continue
        chars.append(char)
        pos += 1
    raise JsonPathError(f"unterminated quoted key in path {text!r}")


def _parse_bracket(text: str, pos: int) -> tuple[Segment, int]:
    # text[pos] == "["
    pos += 1
    if pos >= len(text):
        raise JsonPathError(f"unterminated bracket in path {text!r}")
    if text[pos] == "*":
        pos += 1
        if pos >= len(text) or text[pos] != "]":
            raise JsonPathError(
                f"array wildcard must be written [*] in path {text!r}"
            )
        return Segment(WILDCARD), pos + 1
    if text[pos] == '"':
        key, pos = _parse_quoted_key(text, pos)
        if pos >= len(text) or text[pos] != "]":
            raise JsonPathError(f"missing closing bracket in path {text!r}")
        return Segment(KEY, key), pos + 1
    digits = ""
    while pos < len(text) and text[pos].isdigit():
        digits += text[pos]
        pos += 1
    if not digits or pos >= len(text) or text[pos] != "]":
        raise JsonPathError(
            f"bracket must contain [*], [0] or [\"key\"] in path {text!r}"
        )
    if len(digits) > 1 and digits[0] == "0":
        raise JsonPathError(
            f"array index must not have leading zeros in path {text!r}"
        )
    return Segment(INDEX, int(digits)), pos + 1


def parse_path(text: str) -> JsonPath:
    """Parse a path string into a normalized :class:`JsonPath`."""
    if not isinstance(text, str) or not text:
        raise JsonPathError("JSON path must be a non-empty string starting with '$'")
    if text[0] != "$":
        raise JsonPathError(f"JSON path must start with '$': {text!r}")
    pos = 1
    segments: list[Segment] = []
    length = len(text)
    while pos < length:
        char = text[pos]
        if char == ".":
            pos += 1
            if pos >= length:
                raise JsonPathError(f"trailing dot in path {text!r}")
            if text[pos] == ".":
                raise JsonPathError(
                    f"recursive descent '..' is not supported in path {text!r}"
                )
            if text[pos] == "*":
                raise JsonPathError(
                    f"bare wildcard '*' is not supported; use [*] in path {text!r}"
                )
            match = _BARE_KEY_RE.match(text, pos)
            if not match or match.start() != pos:
                raise JsonPathError(
                    f"invalid key after '.' in path {text!r}; "
                    "use [\"key\"] for non-identifier names"
                )
            segments.append(Segment(KEY, match.group(0)))
            pos = match.end()
            continue
        if char == "[":
            segment, pos = _parse_bracket(text, pos)
            segments.append(segment)
            continue
        raise JsonPathError(
            f"unexpected character {char!r} at position {pos} in path {text!r}"
        )
    return JsonPath(tuple(segments))


def render_key(key: str) -> str:
    if _SIMPLE_KEY_RE.fullmatch(key):
        return "." + key
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'["{escaped}"]'


def render_path(segments: tuple[Segment, ...] | list[Segment]) -> str:
    out = ["$"]
    for segment in segments:
        if segment.kind == KEY:
            out.append(render_key(segment.value))
        elif segment.kind == INDEX:
            out.append(f"[{segment.value}]")
        elif segment.kind == WILDCARD:
            out.append("[*]")
        else:  # pragma: no cover - defensive, grammar is closed
            raise JsonPathError(f"unknown path segment kind: {segment.kind}")
    return "".join(out)


def canonical_path(text: str) -> str:
    """Parse and re-render so equivalent spellings share one identity."""
    return parse_path(text).render()


def iter_matches(
    document: Any, segments: tuple[Segment, ...]
) -> Iterator[tuple[tuple[Any, ...], Any]]:
    """Yield ``(concrete_tokens, value)`` for every location the path reaches.

    ``concrete_tokens`` is the same segment tuple but with every wildcard
    expanded to a concrete ``INDEX`` segment, identifying the exact leaf.
    A wildcard over a non-array matches nothing (it never silently treats an
    object as indexable).
    """
    states: list[tuple[tuple[Segment, ...], Any]] = [((), document)]
    for segment in segments:
        next_states: list[tuple[tuple[Segment, ...], Any]] = []
        for tokens, current in states:
            if segment.kind == KEY:
                if isinstance(current, dict) and segment.value in current:
                    next_states.append(
                        (tokens + (Segment(KEY, segment.value),), current[segment.value])
                    )
            elif segment.kind == INDEX:
                if isinstance(current, list) and 0 <= segment.value < len(current):
                    next_states.append(
                        (tokens + (Segment(INDEX, segment.value),), current[segment.value])
                    )
            else:  # WILDCARD
                if isinstance(current, list):
                    for index, item in enumerate(current):
                        next_states.append(
                            (tokens + (Segment(INDEX, index),), item)
                        )
        states = next_states
        if not states:
            return
    yield from states


def path_matches(tokens: tuple[Segment, ...], pattern: tuple[Segment, ...]) -> bool:
    """True when a concrete discovery path matches a (possibly wildcard) rule."""
    if len(tokens) != len(pattern):
        return False
    for token, segment in zip(tokens, pattern):
        if segment.kind == WILDCARD:
            if token.kind != INDEX:
                return False
            continue
        if token.kind != segment.kind or token.value != segment.value:
            return False
    return True
