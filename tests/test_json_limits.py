"""Pre-parse resource guards: size cap, depth cap, and fail-closed parsing."""

from __future__ import annotations

import pytest

from maskline.json_ import (
    HARD_MAX_BYTES,
    HARD_MAX_DEPTH,
    JsonLimitError,
    JsonLimits,
    raw_depth,
    safe_loads,
)


def test_raw_depth_ignores_strings_and_escapes():
    assert raw_depth("[]") == 1
    assert raw_depth('{"a": {"b": [1, 2]}}') == 3
    assert raw_depth('{"a": "[[[[[[[["}') == 1
    assert raw_depth('{"a": "he said \\"[[[\\" "}') == 1
    assert raw_depth("[" * 40 + "1" + "]" * 40) == 40


def test_safe_loads_parses_normal_documents():
    limits = JsonLimits(max_depth=32, max_bytes=4096)
    assert safe_loads('  {"a": 1}  ', limits) == {"a": 1}
    assert safe_loads("[1, 2, 3]", limits) == [1, 2, 3]


def test_oversize_document_is_rejected_before_parse():
    limits = JsonLimits(max_depth=32, max_bytes=128)
    payload = '"' + "x" * 200 + '"'
    with pytest.raises(JsonLimitError, match="bytes"):
        safe_loads(payload, limits)


def test_too_deep_document_is_rejected_before_parse():
    limits = JsonLimits(max_depth=8, max_bytes=4096)
    deep = "[" * 12 + "1" + "]" * 12
    with pytest.raises(JsonLimitError, match="depth"):
        safe_loads(deep, limits)


def test_malformed_json_raises_value_error():
    limits = JsonLimits()
    with pytest.raises(ValueError):
        safe_loads("{not json", limits)


def test_policy_overrides_are_clamped_to_hard_caps():
    assert JsonLimits.from_policy(16, 256) == JsonLimits(16, 256)
    with pytest.raises(ValueError):
        JsonLimits.from_policy(0, 256)
    with pytest.raises(ValueError):
        JsonLimits.from_policy(HARD_MAX_DEPTH + 1, 256)
    with pytest.raises(ValueError):
        JsonLimits.from_policy(16, HARD_MAX_BYTES + 1)


def test_multibyte_text_is_measured_in_utf8_bytes():
    limits = JsonLimits(max_bytes=8)
    # Each CJK character is 3 bytes; three of them exceed the cap.
    with pytest.raises(JsonLimitError, match="bytes"):
        safe_loads('"中文文字"', limits)
