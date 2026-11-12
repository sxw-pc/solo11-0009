"""Regex detector family for common structured sensitive values.

Detectors are intentionally declarative enough to be snapshotted into a versioned
rule set: every regex detector records its pattern, flags, named validator and
optional value-level constraints.  The built-in detector tuple must remain
behaviourally identical to previous releases when compiled from a rule snapshot.
"""

from __future__ import annotations

import re
from typing import Callable, Mapping, Pattern, Sequence

from .base import Candidate, score_candidate
from .checksums import credit_code_valid, id_card_valid, ipv4_valid, luhn_valid

MOBILE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,24}(?![\w.-])"
)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
ID_CARD_RE = re.compile(r"(?<!\d)[1-9]\d{16}[\dXx](?![\dXx])")
BANK_CARD_RE = re.compile(r"(?<!\d)\d{16,19}(?!\d)")
CREDIT_CODE_RE = re.compile(
    r"(?<![0-9A-Za-z])[0-9A-HJ-NPQRTUWXYa-hj-npqrtuwxy]{18}(?![0-9A-Za-z])"
)

# Named validators are part of the versioned rule format.  Rule packs refer to
# these names instead of embedding Python callables.
VALIDATORS: Mapping[str, Callable[[str], bool] | None] = {
    "none": None,
    "id_card": id_card_valid,
    "luhn": luhn_valid,
    "ipv4": ipv4_valid,
    "credit_code": credit_code_valid,
}

_FLAG_TO_TEXT = {
    re.IGNORECASE: "i",
    re.MULTILINE: "m",
    re.DOTALL: "s",
    re.VERBOSE: "x",
}
_TEXT_TO_FLAG = {value: key for key, value in _FLAG_TO_TEXT.items()}


def flags_to_text(flags: int) -> str:
    """Return the rule-pack flag string, ignoring implicit ``re.UNICODE``."""
    return "".join(
        letter for flag, letter in _FLAG_TO_TEXT.items() if flags & flag
    )


def flags_from_text(text: str | int | None) -> int:
    if text is None or text == "":
        return 0
    if isinstance(text, int) and not isinstance(text, bool):
        return text
    if not isinstance(text, str):
        raise ValueError("regex flags must be a string such as 'i', 'm', 's' or 'x'")
    flags = 0
    for char in text:
        try:
            flags |= _TEXT_TO_FLAG[char]
        except KeyError as exc:
            raise ValueError(
                f"unsupported regex flag {char!r}; use i, m, s or x"
            ) from exc
    return flags


class RegexDetector:
    """Find a regex in each cell, then score the hit and validator pass rates."""

    def __init__(
        self,
        sensitive_type: str,
        pattern: Pattern[str] | str,
        validator: Callable[[str], bool] | None = None,
        *,
        validator_name: str = "none",
        require_fullmatch: bool = False,
        value_pattern: Pattern[str] | str | None = None,
        flags: int = 0,
        min_length: int = 0,
        max_length: int | None = None,
    ) -> None:
        if isinstance(pattern, str):
            pattern = re.compile(pattern, flags)
        self.sensitive_type = sensitive_type
        self.pattern = pattern
        self.validator_name = validator_name
        self.require_fullmatch = require_fullmatch
        self.min_length = min_length
        self.max_length = max_length
        self.value_pattern = (
            re.compile(value_pattern, flags)
            if isinstance(value_pattern, str)
            else value_pattern
        )
        named_validator = VALIDATORS.get(validator_name)
        if validator is None and validator_name != "none" and named_validator is None:
            raise ValueError(f"unknown detector validator: {validator_name!r}")
        base_validator = validator if validator is not None else named_validator
        checks: list[Callable[[str], bool]] = []
        if base_validator is not None:
            checks.append(base_validator)
        if require_fullmatch:
            compiled = self.pattern
            checks.append(lambda value: bool(compiled.fullmatch(value)))
        if self.value_pattern is not None:
            value_matcher = self.value_pattern
            checks.append(lambda value: bool(value_matcher.fullmatch(value)))
        if min_length > 0:
            checks.append(lambda value: len(value) >= min_length)
        if max_length is not None:
            checks.append(lambda value: len(value) <= max_length)
        if checks:
            self.validator = lambda value: all(check(value) for check in checks)
        else:
            self.validator = None

    def evaluate(self, values: Sequence[str]) -> Candidate | None:
        matches: list[str] = []
        for value in values:
            match = self.pattern.search(value)
            if match:
                matches.append(match.group(0))
        return score_candidate(self.sensitive_type, len(values), matches, self.validator)


DETECTORS = (
    RegexDetector("mobile_phone", MOBILE_RE),
    # Emails must cover the whole cell; other detectors score the substring.
    RegexDetector("email", EMAIL_RE, require_fullmatch=True),
    RegexDetector("ipv4", IPV4_RE, validator_name="ipv4"),
    RegexDetector("id_card", ID_CARD_RE, validator_name="id_card"),
    RegexDetector("bank_card", BANK_CARD_RE, validator_name="luhn"),
    RegexDetector("credit_code", CREDIT_CODE_RE, validator_name="credit_code"),
)
