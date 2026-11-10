from pathlib import Path
import secrets

import pytest

from maskline.config import SecretStore
from maskline.pseudomap import PseudoMap
from maskline.transformers import REGISTRY, TransformContext, TransformError
from maskline.transformers.pseudonym import pseudonym_token

def run(name, value, params=None, context=None):
    return REGISTRY.transform(name, value, params or {}, context or TransformContext())

def test_all_builtins_are_registered():
    assert set(REGISTRY.names()) == {
        "mask", "hash", "generalize", "pseudonym", "nullify", "round"
    }

def test_mask_keeps_edges_and_is_deterministic():
    context = TransformContext()
    first = run("mask", "12345678901", {"keep_prefix": 3, "keep_suffix": 4}, context)
    assert first == "123****8901"
    assert first == run("mask", "12345678901", {"keep_prefix": 3, "keep_suffix": 4})
    assert run("mask", "abc", {"keep_prefix": 2, "keep_suffix": 2}) == "***"
    assert run("mask", None) is None
    assert run("mask", "") == ""

def test_hash_is_keyed_deterministic_and_null_safe(secret_store):
    context = TransformContext(secrets=secret_store)
    first = run("hash", "12345678901", {}, context)
    second = run("hash", "12345678901", {}, context)
    assert first == second and len(first) == 64
    assert first != run("hash", "12345678902", {}, context)
    assert run("hash", None, {}, context) is None
    assert run("hash", "", {}, context) == ""
    other = SecretStore(
        {"hmac_salt": secrets.token_urlsafe(32), "pseudonym_key": secrets.token_urlsafe(32)}, Path("memory-secret")
    )
    assert first != run("hash", "12345678901", {}, TransformContext(secrets=other))
    with pytest.raises(TransformError):
        run("hash", "x", {}, TransformContext())

@pytest.mark.parametrize(
    "mode,value,params,expected",
    [
        ("date", "2024-02-29", {}, "2024-02"),
        ("date", "2024-02-29", {"level": "quarter"}, "2024-Q1"),
        ("date", "2024/12/31", {"level": "year"}, "2024"),
        ("age", "42", {"width": 10}, "40-49"),
        ("age", "42", {"width": 1}, "42-42"),
        ("amount", "1234.56", {"width": 100}, "1200-1299"),
        ("address", "浙江省杭州市西湖区示例路1号", {}, "杭州市"),
        ("address", "北京市朝阳区示例路1号", {}, "北京市"),
        ("address", "不知名地点", {}, "其他地区"),
    ],
)

def test_generalize_modes(mode, value, params, expected):
    extra = dict(params)
    extra["mode"] = mode
    assert run("generalize", value, extra) == expected

def test_generalize_is_safe_for_bad_values():
    for mode in ("date", "age", "amount"):
        assert run("generalize", "not-valid", {"mode": mode}) == "not-valid"
        assert run("generalize", None, {"mode": mode}) is None
        assert run("generalize", "", {"mode": mode}) == ""
    assert run("generalize", "-1", {"mode": "age"}) == "-1"

def test_round_and_nullify(secret_store):
    assert run("round", "2.5", {"decimals": 0}) == 3
    assert run("round", 12.345, {"decimals": 2}) == 12.35
    assert run("round", "not-a-number") == "not-a-number"
    assert run("round", None) is None
    assert run("round", "") == ""
    assert run("nullify", "secret") is None
    assert run("nullify", None) is None

def test_pseudonym_is_reversible_and_consistent_across_runs(tmp_path, secret_store):
    map_path = tmp_path / "map.sqlite"
    with PseudoMap(map_path, create=True) as mapping:
        context = TransformContext(secrets=secret_store, pseudomap=mapping)
        token = run("pseudonym", "张伟", {}, context)
        assert token == pseudonym_token("张伟", secret_store.get("pseudonym_key"))
        assert mapping.reveal(token) == "张伟"
    with PseudoMap(map_path) as reopened:
        context = TransformContext(secrets=secret_store, pseudomap=reopened)
        assert run("pseudonym", "张伟", {}, context) == token
        assert run("pseudonym", "李娜", {}, context) != token
        assert reopened.count() == 2

def test_pseudonym_null_safe_and_validation_flags(secret_store, tmp_path):
    with PseudoMap(tmp_path / "map.sqlite", create=True) as mapping:
        context = TransformContext(secrets=secret_store, pseudomap=mapping)
        assert run("pseudonym", None, {}, context) is None
        assert run("pseudonym", "", {}, context) == ""
    with pytest.raises(TransformError):
        run("pseudonym", "张伟", {}, TransformContext(secrets=secret_store))
    dry = run("pseudonym", "张伟", {}, TransformContext(secrets=secret_store, write_mapping=False))
    assert dry.startswith("psn_")

@pytest.mark.parametrize(
    "name,params",
    [
        ("mask", {"unknown": 1}),
        ("hash", {"salt_ref": 3}),
        ("generalize", {}),
        ("generalize", {"mode": "invalid"}),
        ("round", {"decimals": "2"}),
    ],
)

def test_parameter_validation(name, params):
    with pytest.raises(TransformError):
        REGISTRY.validate_params(name, params)

def test_unknown_transformer_has_clear_error():
    with pytest.raises(TransformError, match="unknown transformer"):
        run("does-not-exist", "x")
