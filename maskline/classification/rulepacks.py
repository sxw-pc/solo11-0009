"""Strict YAML rule-pack loading, validation, fingerprinting, and built-in discovery.

Everything is local: built-in packs ship inside the package and custom packs are
read from the local filesystem. No network access is ever performed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import yaml

from ..utils import canonical_json, sha256_text
from .models import (
    AliasGroup,
    ClassificationRule,
    RuleLabels,
    RuleMatch,
    RulePack,
    RulePackError,
    StandardInfo,
)

PACK_DOCUMENT_VERSION = 1
BUILTIN_PACK_DIR = Path(__file__).resolve().parent / "rule_packs"


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RulePackError(f"{where} must be a mapping")
    return value


def _non_empty_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RulePackError(f"{where} must be a non-empty string")
    return value


def _str_list(value: Any, where: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RulePackError(f"{where} must be a list of strings")
    if not allow_empty and not value:
        raise RulePackError(f"{where} must not be empty")
    return list(value)


def _parse_rule(raw: Any, index: int, levels: set[str]) -> ClassificationRule:
    where = f"rules[{index}]"
    rule = _mapping(raw, where)
    unknown = set(rule) - {"id", "priority", "match", "labels", "special_category", "cross_border_flag"}
    if unknown:
        raise RulePackError(f"{where} has unknown keys: {', '.join(sorted(unknown))}")
    rule_id = _non_empty_str(rule.get("id"), f"{where}.id")
    priority = rule.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool) or priority < 0:
        raise RulePackError(f"{where}.priority must be a non-negative integer")
    special = rule.get("special_category", False)
    cross_border = rule.get("cross_border_flag", False)
    if not isinstance(special, bool) or not isinstance(cross_border, bool):
        raise RulePackError(f"{where} boolean flags must be true/false")
    match = _mapping(rule.get("match"), f"{where}.match")
    if set(match) != {"sensitive_types", "name_patterns"}:
        raise RulePackError(f"{where}.match must contain only sensitive_types and name_patterns")
    sensitive_types = _str_list(match.get("sensitive_types"), f"{where}.match.sensitive_types")
    name_patterns = _str_list(match.get("name_patterns"), f"{where}.match.name_patterns")
    if not sensitive_types and not name_patterns:
        raise RulePackError(f"{where}.match must define at least one sensitive type or name pattern")
    labels = _mapping(rule.get("labels"), f"{where}.labels")
    if set(labels) != {"level", "category", "controls"}:
        raise RulePackError(f"{where}.labels must contain only level, category, controls")
    level = _non_empty_str(labels.get("level"), f"{where}.labels.level")
    if level not in levels:
        raise RulePackError(f"{where}.labels.level {level!r} is not in level_order")
    category = _non_empty_str(labels.get("category"), f"{where}.labels.category")
    controls = _str_list(labels.get("controls"), f"{where}.labels.controls", allow_empty=False)
    return ClassificationRule(
        rule_id=rule_id,
        priority=priority,
        match=RuleMatch(tuple(sensitive_types), tuple(name_patterns)),
        labels=RuleLabels(level=level, category=category, controls=tuple(controls)),
        special_category=special,
        cross_border_flag=cross_border,
    )


def _parse_pack(data: Any, source_path: Path | None, builtin: bool) -> RulePack:
    root = _mapping(data, "rule pack root")
    allowed = {
        "version", "pack_id", "revision", "standard", "level_order", "level_names",
        "defaults", "controls_catalog", "cross_border_name_patterns", "aliases", "rules",
    }
    unknown = set(root) - allowed
    if unknown:
        raise RulePackError(f"rule pack root has unknown keys: {', '.join(sorted(unknown))}")
    version = root.get("version")
    if version != PACK_DOCUMENT_VERSION or isinstance(version, bool):
        raise RulePackError("rule pack version must be the integer 1")
    pack_id = _non_empty_str(root.get("pack_id"), "pack_id")
    revision = root.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise RulePackError("revision must be a positive integer")
    standard_raw = _mapping(root.get("standard"), "standard")
    if set(standard_raw) != {"code", "name", "version", "description"}:
        raise RulePackError("standard must contain code, name, version, description")
    standard = StandardInfo(
        code=_non_empty_str(standard_raw["code"], "standard.code"),
        name=_non_empty_str(standard_raw["name"], "standard.name"),
        version=_non_empty_str(standard_raw["version"], "standard.version"),
        description=standard_raw.get("description", "")
        if isinstance(standard_raw.get("description", ""), str)
        else _non_empty_str(None, "standard.description"),
    )
    level_order = _str_list(root.get("level_order"), "level_order", allow_empty=False)
    if len(set(level_order)) != len(level_order):
        raise RulePackError("level_order contains duplicates")
    levels = set(level_order)
    names_raw = _mapping(root.get("level_names", {}), "level_names")
    level_names: dict[str, str] = {}
    for key, value in names_raw.items():
        if key not in levels:
            raise RulePackError(f"level_names key {key!r} is not in level_order")
        level_names[key] = _non_empty_str(value, f"level_names.{key}")
    defaults = _mapping(root.get("defaults"), "defaults")
    if set(defaults) != {"fallback_level", "fallback_category", "fallback_controls"}:
        raise RulePackError("defaults must contain fallback_level/category/controls")
    fallback_level = _non_empty_str(defaults["fallback_level"], "defaults.fallback_level")
    if fallback_level not in levels:
        raise RulePackError("defaults.fallback_level is not in level_order")
    fallback_category = _non_empty_str(defaults["fallback_category"], "defaults.fallback_category")
    fallback_controls = tuple(
        _str_list(defaults["fallback_controls"], "defaults.fallback_controls", allow_empty=False)
    )
    catalog_raw = _mapping(root.get("controls_catalog", {}), "controls_catalog")
    controls_catalog = {
        _non_empty_str(key, "controls_catalog key"): _non_empty_str(value, f"controls_catalog.{key}")
        for key, value in catalog_raw.items()
    }
    declared_controls = set(controls_catalog)
    if not declared_controls:
        raise RulePackError("controls_catalog must declare at least one control")
    missing_default = [item for item in fallback_controls if item not in declared_controls]
    if missing_default:
        raise RulePackError(f"fallback controls not in controls_catalog: {', '.join(missing_default)}")
    cross_border_patterns = tuple(
        _str_list(root.get("cross_border_name_patterns", []), "cross_border_name_patterns")
    )
    aliases_raw = root.get("aliases", [])
    if not isinstance(aliases_raw, list):
        raise RulePackError("aliases must be a list")
    aliases: list[AliasGroup] = []
    seen_alias_names: dict[str, str] = {}
    for index, raw_group in enumerate(aliases_raw):
        group = _mapping(raw_group, f"aliases[{index}]")
        if set(group) != {"canonical", "names"}:
            raise RulePackError(f"aliases[{index}] must contain only canonical and names")
        canonical = _non_empty_str(group["canonical"], f"aliases[{index}].canonical")
        names = _str_list(group["names"], f"aliases[{index}].names", allow_empty=False)
        for name in names:
            owner = seen_alias_names.get(name)
            if owner is not None and owner != canonical:
                raise RulePackError(
                    f"alias {name!r} maps to both {owner!r} and {canonical!r}"
                )
            seen_alias_names[name] = canonical
        aliases.append(AliasGroup(canonical=canonical, names=tuple(names)))
    rules_raw = root.get("rules")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise RulePackError("rules must be a non-empty list")
    rules: list[ClassificationRule] = []
    rule_ids: set[str] = set()
    for index, raw_rule in enumerate(rules_raw):
        rule = _parse_rule(raw_rule, index, levels)
        if rule.rule_id in rule_ids:
            raise RulePackError(f"duplicate rule id: {rule.rule_id}")
        rule_ids.add(rule.rule_id)
        unknown_controls = [item for item in rule.labels.controls if item not in declared_controls]
        if unknown_controls:
            raise RulePackError(
                f"rule {rule.rule_id} uses controls not in controls_catalog: "
                f"{', '.join(unknown_controls)}"
            )
        rules.append(rule)
    pack = RulePack(
        pack_id=pack_id,
        revision=revision,
        standard=standard,
        level_order=tuple(level_order),
        level_names=level_names,
        fallback_level=fallback_level,
        fallback_category=fallback_category,
        fallback_controls=fallback_controls,
        controls_catalog=controls_catalog,
        cross_border_name_patterns=cross_border_patterns,
        aliases=tuple(aliases),
        rules=tuple(rules),
        fingerprint="",
        source_path=str(source_path) if source_path else None,
        builtin=builtin,
    )
    fingerprint = sha256_text(canonical_json(pack.to_dict()))
    return RulePack(
        pack_id=pack.pack_id,
        revision=pack.revision,
        standard=pack.standard,
        level_order=pack.level_order,
        level_names=pack.level_names,
        fallback_level=pack.fallback_level,
        fallback_category=pack.fallback_category,
        fallback_controls=pack.fallback_controls,
        controls_catalog=pack.controls_catalog,
        cross_border_name_patterns=pack.cross_border_name_patterns,
        aliases=pack.aliases,
        rules=pack.rules,
        fingerprint=fingerprint,
        source_path=pack.source_path,
        builtin=pack.builtin,
    )


def load_rule_pack(path: str | Path, *, builtin: bool = False) -> RulePack:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise RulePackError(f"rule pack file not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RulePackError(f"cannot load rule pack {source}: {exc}") from exc
    return _parse_pack(data, source, builtin)


def builtin_rule_packs() -> list[RulePack]:
    """Load the three packs bundled with the package, ordered by standard code."""
    packs = [
        load_rule_pack(path, builtin=True)
        for path in sorted(BUILTIN_PACK_DIR.glob("*.yaml"))
    ]
    codes = [pack.standard.code for pack in packs]
    if len(set(codes)) != len(codes):
        raise RulePackError("built-in rule packs must have distinct standard codes")
    return packs
