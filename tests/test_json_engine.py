"""Discovery, leaf transformation, dirty-cell degradation, and determinism."""

from __future__ import annotations

import json

from maskline.json_ import (
    NOT_JSON,
    TOO_DEEP,
    TOO_LARGE,
    JsonLimits,
    JsonRunState,
    build_path_rules,
    discover_json_paths,
    probe_json_column,
    transform_json_cell,
)
from maskline.transformers import REGISTRY, TransformContext


LIMITS = JsonLimits(max_depth=32, max_bytes=4096)


def _doc(payload):
    return json.dumps(payload, ensure_ascii=False)


def test_discovery_generalizes_array_indices_into_one_path():
    values = [
        _doc({"items": [{"phone": "13800000000"}, {"phone": "13900000000"}]}),
        _doc({"items": [{"phone": "13700000000"}], "meta": {"id": 7}}),
    ]
    findings = discover_json_paths(
        values, LIMITS, sample_limit=200, table="orders", column="ext"
    )
    by_path = {item["json_path"]: item for item in findings}
    assert "$.items[*].phone" in by_path
    phone = by_path["$.items[*].phone"]
    assert phone["sensitive_type"] == "mobile_phone"
    assert phone["table_name"] == "orders" and phone["column_name"] == "ext"
    # All three phone leaves group under the wildcard path.
    assert phone["sample_size"] == 3 and phone["hit_rate"] == 1.0


def test_discovery_keeps_distinct_object_paths_apart():
    values = [
        _doc({"profile": {"phone": "13800000000"}, "backup": {"phone": "13900000000"}})
    ]
    findings = discover_json_paths(values, LIMITS)
    paths = {item["json_path"] for item in findings}
    assert "$.profile.phone" in paths and "$.backup.phone" in paths


def test_discovery_ignores_dirty_and_oversized_cells():
    values = [
        _doc({"phone": "13800000000"}),
        "not json at all",
        '"' + "x" * 5000 + '"',
    ]
    findings = discover_json_paths(values, LIMITS)
    assert [item["json_path"] for item in findings] == ["$.phone"]


def test_probe_requires_a_majority_of_container_documents():
    assert probe_json_column([_doc({"a": 1}), _doc({"b": 2}), "x"], LIMITS)
    assert not probe_json_column([_doc({"a": 1}), "x", "y", "z"], LIMITS)
    # Bare JSON scalars do not make a JSON column.
    assert not probe_json_column(["1", "2", "3"], LIMITS)
    assert not probe_json_column([], LIMITS)


def test_transform_replaces_only_matched_leaves_and_keeps_order():
    raw = _doc(
        {
            "profile": {"name": "张三", "id_card": "110101199003071234"},
            "items": [
                {"sku": "A", "phone": "13800000000"},
                {"sku": "B", "phone": "13900000000"},
            ],
            "tags": ["vip", "tier-1"],
        }
    )
    rules = build_path_rules(
        {
            "$.items[*].phone": {
                "transformer": "mask",
                "params": {"keep_prefix": 3, "keep_suffix": 4},
            },
            "$.profile.id_card": "nullify",
        },
        "test",
    )
    state = JsonRunState()
    out, outcome = transform_json_cell(
        raw, rules, None, {}, LIMITS, TransformContext(),
        state.for_column("ext"), 1, "orders", "ext",
    )
    assert outcome.status == "ok"
    parsed = json.loads(out)
    assert parsed["items"][0]["phone"] == "138****0000"
    assert parsed["items"][1]["phone"] == "139****0000"
    assert parsed["items"][0]["sku"] == "A"
    assert parsed["profile"]["name"] == "张三"
    assert parsed["profile"]["id_card"] is None
    assert parsed["tags"] == ["vip", "tier-1"]
    # Key order at every level is preserved.
    assert list(json.loads(raw).keys()) == list(parsed.keys())
    stats = state.to_dict()["columns"]["ext"]["path_stats"]
    assert stats["$.items[*].phone"]["mask"] == {
        "seen": 2, "processed": 2, "changed": 2,
    }
    assert stats["$.profile.id_card"]["nullify"]["seen"] == 1


def test_unmatched_document_is_returned_byte_identical():
    raw = _doc({"nothing": "relevant"})
    rules = build_path_rules({"$.other.value": "nullify"}, "test")
    out, outcome = transform_json_cell(
        raw, rules, None, {}, LIMITS, TransformContext(),
        JsonRunState().for_column("c"), 1, "t", "c",
    )
    assert out == raw and outcome.status == "ok"


def test_dirty_cell_without_fallback_is_kept_and_warned():
    rules = build_path_rules({"$.a": "nullify"}, "test")
    state = JsonRunState()
    out, outcome = transform_json_cell(
        "garbage{", rules, None, {}, LIMITS, TransformContext(),
        state.for_column("c"), 42, "t", "c",
    )
    assert out == "garbage{"
    assert outcome.status == "warning" and outcome.warning == NOT_JSON
    column = state.to_dict()["columns"]["c"]
    assert column["warnings"] == {NOT_JSON: 1}
    assert column["warning_samples"] == {NOT_JSON: [42]}
    assert column["json_ok"] == 0


def test_dirty_cell_with_fallback_is_transformed_as_whole_string():
    rules = build_path_rules({"$.a": "nullify"}, "test")
    params = REGISTRY.validate_params("mask", {"keep_prefix": 1, "keep_suffix": 0})
    state = JsonRunState()
    out, outcome = transform_json_cell(
        "dirty", rules, "mask", params, LIMITS, TransformContext(),
        state.for_column("c"), 7, "t", "c",
    )
    assert out == "d****" and outcome.warning == NOT_JSON


def test_size_and_depth_breaches_are_classified_distinctly():
    rules = build_path_rules({"$.a": "nullify"}, "test")
    state = JsonRunState()
    column_state = state.for_column("c")
    oversize = '"' + "x" * (LIMITS.max_bytes + 10) + '"'
    _out, outcome = transform_json_cell(
        oversize, rules, None, {}, LIMITS, TransformContext(),
        column_state, 1, "t", "c",
    )
    assert outcome.warning == TOO_LARGE
    deep = "[" * (LIMITS.max_depth + 5) + "1" + "]" * (LIMITS.max_depth + 5)
    _out, outcome = transform_json_cell(
        deep, rules, None, {}, LIMITS, TransformContext(),
        column_state, 2, "t", "c",
    )
    assert outcome.warning == TOO_DEEP
    assert column_state.warnings == {TOO_LARGE: 1, TOO_DEEP: 1}


def test_empty_and_null_cells_pass_through():
    rules = build_path_rules({"$.a": "nullify"}, "test")
    state = JsonRunState().for_column("c")
    for empty in (None, ""):
        out, outcome = transform_json_cell(
            empty, rules, None, {}, LIMITS, TransformContext(),
            state, 1, "t", "c",
        )
        assert out == empty and outcome.status == "empty"
    assert state.empty == 2 and state.warnings == {}


def test_repeated_runs_produce_byte_identical_output():
    raw = _doc({"items": [{"phone": "13800000000"}], "b": [1, 2], "a": {"x": 1}})
    rules = build_path_rules(
        {"$.items[*].phone": {
            "transformer": "mask", "params": {"keep_prefix": 3, "keep_suffix": 4}}},
        "test",
    )
    first, _ = transform_json_cell(
        raw, rules, None, {}, LIMITS, TransformContext(),
        JsonRunState().for_column("c"), 1, "t", "c",
    )
    second, _ = transform_json_cell(
        raw, rules, None, {}, LIMITS, TransformContext(),
        JsonRunState().for_column("c"), 1, "t", "c",
    )
    assert first == second
    # Re-applying to an already masked document is stable.
    third, _ = transform_json_cell(
        first, rules, None, {}, LIMITS, TransformContext(),
        JsonRunState().for_column("c"), 1, "t", "c",
    )
    assert third == first


def test_warning_samples_are_capped():
    rules = build_path_rules({"$.a": "nullify"}, "test")
    state = JsonRunState().for_column("c")
    for rowid in range(1, 25):
        transform_json_cell(
            "bad-json", rules, None, {}, LIMITS, TransformContext(),
            state, rowid, "t", "c",
        )
    assert state.warnings[NOT_JSON] == 24
    assert len(state.warning_samples[NOT_JSON]) == 10


def test_shorthand_transformer_gets_default_params():
    rules = build_path_rules({"$.n": "round"}, "test")
    assert rules[0].transformer == "round"
    assert rules[0].params == {"decimals": 0}


def test_run_state_round_trips_through_json():
    rules = build_path_rules({"$.a": "nullify"}, "test")
    state = JsonRunState()
    transform_json_cell(
        _doc({"a": "x"}), rules, None, {}, LIMITS, TransformContext(),
        state.for_column("c"), 1, "t", "c",
    )
    transform_json_cell(
        "bad", rules, None, {}, LIMITS, TransformContext(),
        state.for_column("c"), 2, "t", "c",
    )
    payload = state.to_dict()
    restored = JsonRunState.from_dict(payload)
    assert restored.to_dict() == payload
