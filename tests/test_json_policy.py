"""Policy loading and strict validation for JSON column declarations."""

from __future__ import annotations

import pytest

from maskline.policies import PolicyError, load_policy


VALID_BASE = """
version: 1
name: json-policy
datasets:
  - path: "demo.sqlite"
    tables:
      profiles:
        columns:
          payload:
            json:
              paths:
                "$.items[*].phone":
                  transformer: mask
                  params: {keep_prefix: 3, keep_suffix: 4}
                "$.profile.id_card":
                  transformer: nullify
              fallback:
                transformer: nullify
"""


def test_json_paths_are_parsed_and_canonicalized(make_policy):
    policy = make_policy(
        VALID_BASE.replace('"$.items[*].phone"', '"$[\\"items\\"][*][\\"phone\\"]"')
    )
    config = policy.datasets[0].tables["profiles"].columns["payload"].json_config
    assert config is not None
    canonicals = [rule.canonical for rule in config.path_rules]
    assert "$.items[*].phone" in canonicals
    assert config.fallback_transformer == "nullify"
    assert config.limits.max_depth == 32 and config.limits.max_bytes == 1 << 20


def test_json_only_column_needs_no_column_transformer(make_policy):
    policy = make_policy(VALID_BASE)
    detail = policy.datasets[0].tables["profiles"].columns["payload"]
    assert detail.transformer == "" and detail.json_config is not None
    assert detail.requires_secret() is False
    # Fingerprint includes the path rules, so it stays stable across reloads.
    assert policy.fingerprint == load_policy(policy.source_path).fingerprint


def test_secret_requirement_recurses_into_path_rules(make_policy):
    policy = make_policy(
        VALID_BASE.replace("transformer: nullify", "transformer: hash", 1)
    )
    detail = policy.datasets[0].tables["profiles"].columns["payload"]
    assert detail.requires_secret() is True
    policy2 = make_policy(
        VALID_BASE.replace(
            "fallback:\n                transformer: nullify",
            "fallback:\n                transformer: pseudonym",
        )
    )
    assert policy2.datasets[0].tables["profiles"].columns["payload"].requires_secret()


def test_custom_limits_are_validated(make_policy):
    policy = make_policy(
        VALID_BASE.replace(
            "paths:", "max_depth: 16\n              max_bytes: 2048\n              paths:"
        )
    )
    limits = policy.datasets[0].tables["profiles"].columns["payload"].json_config.limits
    assert limits.max_depth == 16 and limits.max_bytes == 2048


@pytest.mark.parametrize(
    "block,message",
    [
        ('              paths:\n                "$..phone": {transformer: nullify}',
         "recursive descent"),
        ("              paths: {}", "non-empty mapping"),
        ("              paths: []", "non-empty mapping"),
        ("              max_depth: 0\n              paths: {'$.a': {transformer: nullify}}",
         "between 1 and"),
        ("              max_depth: 'x'\n              paths: {'$.a': {transformer: nullify}}",
         "integer"),
        ("              unknown_key: 1\n              paths: {'$.a': {transformer: nullify}}",
         "unknown keys"),
        ("              paths: {'$.a': {transformer: nope}}", "unknown transformer"),
        ("              paths: {'$.a': {transformer: nullify}}\n"
         "              fallback: {transformer: nope}", "unknown transformer"),
        ("              paths:\n"
         "                '$.a':\n"
         "                  transformer: mask\n"
         "                  params: {bad: 1}",
         "unknown transformer parameter"),
    ],
)
def test_invalid_json_config_fails_at_load(make_policy, block, message):
    text = (
        "version: 1\nname: json-policy\ndatasets:\n"
        "  - path: 'demo.sqlite'\n    tables:\n"
        "      profiles:\n        columns:\n"
        "          payload:\n            json:\n" + block + "\n"
    )
    with pytest.raises(PolicyError, match=message):
        make_policy(text)


def test_duplicate_paths_after_normalization_are_rejected(make_policy):
    text = (
        "version: 1\nname: json-policy\ndatasets:\n"
        "  - path: 'demo.sqlite'\n    tables:\n"
        "      profiles:\n        columns:\n"
        "          payload:\n            json:\n"
        "              paths:\n"
        '                "$[\\"items\\"][*][\\"phone\\"]":\n'
        "                  transformer: nullify\n"
        '                "$.items[*].phone":\n'
        "                  transformer: mask\n"
    )
    with pytest.raises(PolicyError, match="duplicate JSON path"):
        make_policy(text)


def test_column_transformer_and_json_paths_can_coexist(make_policy):
    text = VALID_BASE.replace(
        "          payload:\n            json:",
        "          payload:\n            transformer: nullify\n            json:",
    )
    policy = make_policy(text)
    detail = policy.datasets[0].tables["profiles"].columns["payload"]
    assert detail.transformer == "nullify" and detail.json_config is not None
