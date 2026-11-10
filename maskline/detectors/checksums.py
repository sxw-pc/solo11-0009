"""Checksum algorithms used to validate Chinese identity documents and cards.

These functions validate format only. They intentionally do not look up real
holders, issuing regions, or bank issuers.
"""

from __future__ import annotations

import re
from datetime import date

ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
ID_CHECK_CODES = "10X98765432"
CREDIT_CHARSET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
CREDIT_WEIGHTS = (
    1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28
)


def digits_only(value: str) -> str:
    return re.sub(r"[\s-]", "", value)


def luhn_valid(value: str) -> bool:
    """Validate a 16-19 digit bank card number with the Luhn algorithm."""
    digits = digits_only(value)
    if not re.fullmatch(r"\d{16,19}", digits):
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def luhn_check_digit(prefix: str) -> str:
    """Return the check digit for a card prefix (used by fixture generation)."""
    if not prefix.isdigit():
        raise ValueError("card prefix must contain digits only")
    total = 0
    for index, char in enumerate(reversed(prefix)):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((10 - total % 10) % 10)


def id_card_valid(value: str) -> bool:
    """Validate an 18-character resident ID according to GB 11643."""
    text = value.strip().upper()
    if not re.fullmatch(r"[1-9]\d{16}[\dX]", text):
        return False
    try:
        birth = date(int(text[6:10]), int(text[10:12]), int(text[12:14]))
    except ValueError:
        return False
    if birth > date.today():
        return False
    total = sum(int(char) * weight for char, weight in zip(text[:17], ID_WEIGHTS))
    return ID_CHECK_CODES[total % 11] == text[17]


def id_card_check_digit(first17: str) -> str:
    if not re.fullmatch(r"[1-9]\d{16}", first17):
        raise ValueError("resident ID prefix must be 17 numeric characters")
    total = sum(int(char) * weight for char, weight in zip(first17, ID_WEIGHTS))
    return ID_CHECK_CODES[total % 11]


def credit_code_valid(value: str) -> bool:
    """Validate an 18-character unified social credit code (GB 32100)."""
    text = value.strip().upper()
    if not re.fullmatch(r"[0-9A-HJ-NPQRTUWXY]{18}", text):
        return False
    total = 0
    for char, weight in zip(text[:17], CREDIT_WEIGHTS):
        total += CREDIT_CHARSET.index(char) * weight
    expected = CREDIT_CHARSET[(31 - total % 31) % 31]
    return expected == text[17]


def credit_code_check_digit(first17: str) -> str:
    text = first17.strip().upper()
    if not re.fullmatch(r"[0-9A-HJ-NPQRTUWXY]{17}", text):
        raise ValueError("credit code prefix has characters outside GB 32100")
    total = sum(CREDIT_CHARSET.index(char) * weight for char, weight in zip(text, CREDIT_WEIGHTS))
    return CREDIT_CHARSET[(31 - total % 31) % 31]


def ipv4_valid(value: str) -> bool:
    parts = value.strip().split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
