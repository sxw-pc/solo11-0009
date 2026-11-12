"""Dataclasses for compliance rule packs, rules, and classification outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class RulePackError(ValueError):
    """Raised when a rule pack document fails strict validation."""


@dataclass(frozen=True)
class RuleMatch:
    sensitive_types: tuple[str, ...]
    name_patterns: tuple[str, ...]


@dataclass(frozen=True)
class RuleLabels:
    level: str
    category: str
    controls: tuple[str, ...]


@dataclass(frozen=True)
class ClassificationRule:
    rule_id: str
    priority: int
    match: RuleMatch
    labels: RuleLabels
    special_category: bool = False
    cross_border_flag: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "priority": self.priority,
            "match": {
                "sensitive_types": list(self.match.sensitive_types),
                "name_patterns": list(self.match.name_patterns),
            },
            "labels": {
                "level": self.labels.level,
                "category": self.labels.category,
                "controls": list(self.labels.controls),
            },
            "special_category": self.special_category,
            "cross_border_flag": self.cross_border_flag,
        }


@dataclass(frozen=True)
class AliasGroup:
    canonical: str
    names: tuple[str, ...]


@dataclass(frozen=True)
class StandardInfo:
    code: str
    name: str
    version: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "name": self.name,
            "version": self.version,
            "description": self.description,
        }


@dataclass(frozen=True)
class RulePack:
    pack_id: str
    revision: int
    standard: StandardInfo
    level_order: tuple[str, ...]
    level_names: dict[str, str]
    fallback_level: str
    fallback_category: str
    fallback_controls: tuple[str, ...]
    controls_catalog: dict[str, str]
    cross_border_name_patterns: tuple[str, ...]
    aliases: tuple[AliasGroup, ...]
    rules: tuple[ClassificationRule, ...]
    fingerprint: str
    source_path: str | None = None
    builtin: bool = False

    def level_rank(self, level: str) -> int:
        try:
            return self.level_order.index(level)
        except ValueError:
            return -1

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "pack_id": self.pack_id,
            "revision": self.revision,
            "standard": self.standard.to_dict(),
            "level_order": list(self.level_order),
            "level_names": dict(self.level_names),
            "defaults": {
                "fallback_level": self.fallback_level,
                "fallback_category": self.fallback_category,
                "fallback_controls": list(self.fallback_controls),
            },
            "controls_catalog": dict(self.controls_catalog),
            "cross_border_name_patterns": list(self.cross_border_name_patterns),
            "aliases": [
                {"canonical": group.canonical, "names": list(group.names)}
                for group in self.aliases
            ],
            "rules": [rule.to_dict() for rule in self.rules],
        }


@dataclass(frozen=True)
class Alert:
    code: str
    severity: str  # warning | info
    message: str
    table: str | None = None
    column: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }
        if self.table is not None:
            payload["table"] = self.table
        if self.column is not None:
            payload["column"] = self.column
        if self.detail:
            payload["detail"] = self.detail
        return payload


@dataclass(frozen=True)
class StandardClassification:
    standard_code: str
    standard_name: str
    level: str | None
    level_label: str | None
    category: str | None
    controls: tuple[str, ...]
    special_category: bool
    cross_border: bool
    matched_rule_id: str | None
    match_basis: str  # sensitive_type | name | fallback | manual
    rule_pack_id: str
    rule_pack_fingerprint: str
    rule_pack_version_id: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard_code": self.standard_code,
            "standard_name": self.standard_name,
            "level": self.level,
            "level_label": self.level_label,
            "category": self.category,
            "controls": list(self.controls),
            "special_category": self.special_category,
            "cross_border": self.cross_border,
            "matched_rule_id": self.matched_rule_id,
            "match_basis": self.match_basis,
            "rule_pack_id": self.rule_pack_id,
            "rule_pack_fingerprint": self.rule_pack_fingerprint,
            "rule_pack_version_id": self.rule_pack_version_id,
        }


@dataclass
class FieldClassification:
    dataset_fingerprint: str
    table_name: str
    column_name: str
    semantic_key: str | None
    sensitive_type: str | None
    detection_confidence: str
    degraded: bool
    standards: list[StandardClassification]
    source: str  # auto | manual
    alerts: list[Alert] = field(default_factory=list)

    def identity(self) -> tuple[str, str, str]:
        return self.dataset_fingerprint, self.table_name, self.column_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_fingerprint": self.dataset_fingerprint,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "semantic_key": self.semantic_key,
            "sensitive_type": self.sensitive_type,
            "detection_confidence": self.detection_confidence,
            "degraded": self.degraded,
            "source": self.source,
            "standards": [item.to_dict() for item in self.standards],
            "alerts": [alert.to_dict() for alert in self.alerts],
        }
