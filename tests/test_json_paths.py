"""JSON path grammar: parsing, canonicalization, and wildcard matching."""

from __future__ import annotations

import pytest

from maskline.json_ import JsonPathError, canonical_path, parse_path
from maskline.json_.paths import WILDCARD, iter_matches, path_matches


@pytest.mark.parametrize(
    "raw,canonical",
    [
        ("$.a", "$.a"),
        ("$.a.b", "$.a.b"),
        ('$["a"].b', "$.a.b"),
        ('$.a["b"]', "$.a.b"),
        ("$.items[*].phone", "$.items[*].phone"),
        ("$.items[0].phone", "$.items[0].phone"),
        ("$.a[0][1]", "$.a[0][1]"),
        ('$["a.b"]', '$["a.b"]'),
        ('$["中文键"]', '$["中文键"]'),
        ('$["a\\"b"]', '$["a\\"b"]'),
        ("$", "$"),
    ],
)
def test_valid_paths_canonicalize(raw, canonical):
    assert canonical_path(raw) == canonical


def test_equivalent_spellings_share_identity():
    assert parse_path('$["items"][*]["phone"]').render() == "$.items[*].phone"
    assert canonical_path('$["a"].b') == canonical_path("$.a.b")


@pytest.mark.parametrize(
    "raw",
    [
        "a.b",          # missing root
        "$..a",         # recursive descent
        "$.*",          # bare wildcard
        "$.a[]",        # empty brackets
        "$.a[*",        # unterminated
        "$[**]",        # not the wildcard token
        '$[ "x" ]',     # spaces are not part of the grammar
        "$[01]",        # leading zero index
        "$.a.",         # trailing dot
        "$[",           # unterminated bracket
        '$["unclosed',  # unterminated quote
        "$[?(@.x)]",    # filters unsupported
        "$.a[*]..b",    # recursive descent after wildcard
    ],
)
def test_invalid_paths_are_rejected(raw):
    with pytest.raises(JsonPathError):
        parse_path(raw)


def test_wildcard_matches_every_array_element():
    doc = {"items": [{"phone": "1"}, {"phone": "2"}, {"other": "3"}]}
    matches = list(iter_matches(doc, parse_path("$.items[*].phone").segments))
    assert [value for _tokens, value in matches] == ["1", "2"]
    for tokens, value in matches:
        assert all(segment.kind != WILDCARD for segment in tokens)


def test_wildcard_over_object_matches_nothing():
    doc = {"items": {"phone": "1"}}
    assert list(iter_matches(doc, parse_path("$.items[*].phone").segments)) == []


def test_concrete_index_is_selective():
    doc = {"items": [{"phone": "1"}, {"phone": "2"}]}
    matches = list(iter_matches(doc, parse_path("$.items[1].phone").segments))
    assert [value for _tokens, value in matches] == ["2"]


def test_path_matches_semantics():
    pattern = parse_path("$.items[*].phone").segments
    assert path_matches(parse_path("$.items[3].phone").segments, pattern)
    assert not path_matches(parse_path("$.items[3].email").segments, pattern)
    assert not path_matches(parse_path("$.items.phone").segments, pattern)
    exact = parse_path("$.items[0].phone").segments
    assert path_matches(exact, exact)
    assert not path_matches(parse_path("$.items[1].phone").segments, exact)


def test_missing_key_and_index_do_not_error():
    assert list(iter_matches({"a": 1}, parse_path("$.b.c").segments)) == []
    assert list(iter_matches({"a": [1]}, parse_path("$.a[5]").segments)) == []
