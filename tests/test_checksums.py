import pytest

from maskline.detectors.checksums import (
    credit_code_check_digit,
    credit_code_valid,
    id_card_check_digit,
    id_card_valid,
    ipv4_valid,
    luhn_check_digit,
    luhn_valid,
)

VALID_IDS = [
    "999999197001010017",
    "999999198512311238",
    "999999200002294562",
]
INVALID_IDS = [
    "999999197001010010",  # checksum mismatch
    "999999197002300017",  # impossible date
    "99999919700101001",   # too short
]
VALID_CREDITS = [
    "91999999MA0ABC001C",
    "91999999MA0ABC002F",
    "91999999MA0ABC003J",
]
VALID_CARDS = ["4111111111111111", "5500005555555559", "6011000990139424"]

@pytest.mark.parametrize("value", VALID_IDS)
def test_valid_resident_ids(value):
    assert id_card_valid(value)
    assert id_card_check_digit(value[:17]) == value[-1]

@pytest.mark.parametrize("value", INVALID_IDS)
def test_invalid_resident_ids(value):
    assert not id_card_valid(value)

def test_future_birth_date_is_rejected():
    assert not id_card_valid("999999299901010010")

@pytest.mark.parametrize("value", VALID_CREDITS)
def test_valid_credit_codes(value):
    assert credit_code_valid(value)
    assert credit_code_check_digit(value[:17]) == value[-1]

@pytest.mark.parametrize(
    "value",
    [
        "91999999MA0ABC001Z",
        "91999999MA0ABC001O",
        "91999999MA0ABC001",
    ],
)

def test_invalid_credit_codes(value):
    assert not credit_code_valid(value)

@pytest.mark.parametrize("value", VALID_CARDS)
def test_valid_bank_cards(value):
    assert luhn_valid(value)

@pytest.mark.parametrize(
    "value", ["4111111111111112", "1234567890123456", "4111 1111 1111 1112"]
)

def test_invalid_bank_cards(value):
    assert not luhn_valid(value)

def test_luhn_allows_documented_separators():
    assert luhn_valid("4111 1111-1111 1111")
    assert luhn_check_digit("411111111111111") == "1"

def test_ipv4_validator():
    assert ipv4_valid("192.0.2.1")
    assert not ipv4_valid("192.0.2.256")
    assert not ipv4_valid("192.0.2")
    assert not ipv4_valid("a.b.c.d")

def test_check_digit_helpers_reject_bad_prefixes():
    with pytest.raises(ValueError):
        id_card_check_digit("abc")
    with pytest.raises(ValueError):
        credit_code_check_digit("TOO-SHORT")
    with pytest.raises(ValueError):
        luhn_check_digit("12X4")
