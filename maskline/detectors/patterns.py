"""Regex detector family for common structured sensitive values."""

from __future__ import annotations

import re
from typing import Callable, Pattern, Sequence

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


def _fullmatch(pattern: Pattern[str], validator: Callable[[str], bool]) -> Callable[[str], bool]:
    return lambda value: bool(pattern.fullmatch(value)) and validator(value)


class RegexDetector:
    """Find a regex in each cell, then score the hit and validator pass rates."""

    def __init__(
        self,
        sensitive_type: str,
        pattern: Pattern[str],
        validator: Callable[[str], bool] | None = None,
    ) -> None:
        self.sensitive_type = sensitive_type
        self.pattern = pattern
        self.validator = validator

    def evaluate(self, values: Sequence[str]) -> Candidate | None:
        matches: list[str] = []
        for value in values:
            match = self.pattern.search(value)
            if match:
                matches.append(match.group(0))
        return score_candidate(self.sensitive_type, len(values), matches, self.validator)


DETECTORS = (
    RegexDetector("mobile_phone", MOBILE_RE),
    RegexDetector("email", EMAIL_RE, _fullmatch(EMAIL_RE, lambda _v: True)),
    RegexDetector("ipv4", IPV4_RE, ipv4_valid),
    RegexDetector("id_card", ID_CARD_RE, id_card_valid),
    RegexDetector("bank_card", BANK_CARD_RE, luhn_valid),
    RegexDetector("credit_code", CREDIT_CODE_RE, credit_code_valid),
)
