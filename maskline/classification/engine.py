"""Rule matching engine: findings + column semantics -> compliance labels.

The engine never raises on ambiguous input. Rule conflicts, weak evidence, and
semantic drift are returned as structured :class:`Alert` objects so a batch job
finishes every column and every dataset while still flagging every case that
needs human review.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from ..utils import canonical_json
from .models import (
    Alert,
    ClassificationRule,
    FieldClassification,
    RulePack,
    StandardClassification,
)
from .semantic import SemanticResolver
from .tolerant import is_deep_column, leaf_token


@dataclass
class ColumnInput:
    table: str
    column: str
    sensitive_type: str | None
    detection_confidence: str
    candidates: tuple[str, ...] = ()
    name_match_available: bool = True
    degraded: bool = False

    @property
    def match_name(self) -> str:
        # Deeply nested paths match on their leaf token; the full path still
        # appears in outputs and alerts.
        if is_deep_column(self.column):
            return leaf_token(self.column)
        return self.column


@dataclass
class _RawMatch:
    rule: ClassificationRule
    basis: str  # sensitive_type | name
    score: int


@dataclass
class _PackOutcome:
    classification: StandardClassification
    alerts: list[Alert] = field(default_factory=list)


def _name_hits(patterns: tuple[str, ...], name: str) -> bool:
    lowered = name.lower()
    return any(fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in patterns)


def _match_pack(pack: RulePack, item: ColumnInput, version_id: int) -> _PackOutcome:
    alerts: list[Alert] = []
    matches: list[_RawMatch] = []
    for rule in pack.rules:
        type_hit = bool(
            item.sensitive_type and item.sensitive_type in rule.match.sensitive_types
        )
        name_hit = bool(
            item.name_match_available and _name_hits(rule.match.name_patterns, item.match_name)
        )
        if type_hit:
            # Content evidence outranks a mere name hit within the same rule.
            matches.append(_RawMatch(rule, "sensitive_type", rule.priority * 10 + 2))
        elif name_hit:
            matches.append(_RawMatch(rule, "name", rule.priority * 10 + 1))
    cross_border = False
    if item.name_match_available and _name_hits(pack.cross_border_name_patterns, item.match_name):
        cross_border = True
        alerts.append(
            Alert(
                code="cross_border_name_hit",
                severity="info",
                message=(
                    f"字段 {item.table}.{item.column} 命中 {pack.standard.code} "
                    "跨境传输名称模式，已标记跨境传输相关管控要求。"
                ),
                table=item.table,
                column=item.column,
            )
        )
    if not matches:
        if item.sensitive_type:
            alerts.append(
                Alert(
                    code="rule_unmapped_sensitive",
                    severity="warning",
                    message=(
                        f"字段 {item.table}.{item.column} 被识别为 "
                        f"{item.sensitive_type}，但 {pack.standard.code} 规则包无精确规则，"
                        "已按兜底等级分级，请人工确认。"
                    ),
                    table=item.table,
                    column=item.column,
                    detail={"sensitive_type": item.sensitive_type},
                )
            )
        classification = StandardClassification(
            standard_code=pack.standard.code,
            standard_name=pack.standard.name,
            level=pack.fallback_level if item.sensitive_type else None,
            level_label=pack.level_names.get(pack.fallback_level)
            if item.sensitive_type
            else None,
            category=pack.fallback_category if item.sensitive_type else None,
            controls=pack.fallback_controls if item.sensitive_type else (),
            special_category=False,
            cross_border=cross_border,
            matched_rule_id=None,
            match_basis="fallback" if item.sensitive_type else "unclassified",
            rule_pack_id=pack.pack_id,
            rule_pack_fingerprint=pack.fingerprint,
            rule_pack_version_id=version_id,
        )
        return _PackOutcome(classification, alerts)
    matches.sort(key=lambda match: (-match.score, match.rule.rule_id))
    best = matches[0]
    tied = [match for match in matches if match.score == best.score]
    if len(tied) > 1:
        alerts.append(
            Alert(
                code="rule_conflict",
                severity="warning",
                message=(
                    f"字段 {item.table}.{item.column} 在 {pack.standard.code} 下命中 "
                    f"{len(tied)} 条同分规则 {[m.rule.rule_id for m in tied]}，"
                    f"按规则 ID 字典序确定性选取 {best.rule.rule_id}，请人工复核。"
                ),
                table=item.table,
                column=item.column,
                detail={"rule_ids": [match.rule.rule_id for match in tied]},
            )
        )
    rule = best.rule
    if best.basis == "name" and item.detection_confidence in {"none", "low"}:
        alerts.append(
            Alert(
                code="weak_evidence_match",
                severity="warning",
                message=(
                    f"字段 {item.table}.{item.column} 仅按名称模式命中规则 "
                    f"{rule.rule_id}，内容识别置信度为 {item.detection_confidence}，"
                    "分级依据较弱，请人工复核。"
                ),
                table=item.table,
                column=item.column,
                detail={"rule_id": rule.rule_id, "confidence": item.detection_confidence},
            )
        )
    classification = StandardClassification(
        standard_code=pack.standard.code,
        standard_name=pack.standard.name,
        level=rule.labels.level,
        level_label=pack.level_names.get(rule.labels.level),
        category=rule.labels.category,
        controls=rule.labels.controls,
        special_category=rule.special_category,
        cross_border=cross_border or rule.cross_border_flag,
        matched_rule_id=rule.rule_id,
        match_basis=best.basis,
        rule_pack_id=pack.pack_id,
        rule_pack_fingerprint=pack.fingerprint,
        rule_pack_version_id=version_id,
    )
    return _PackOutcome(classification, alerts)


class ClassificationEngine:

    def __init__(
        self,
        packs: list[RulePack],
        version_ids: dict[str, int],
        max_nesting_depth: int = 3,
    ) -> None:
        if not packs:
            raise ValueError("at least one rule pack is required")
        self.packs = packs
        self.version_ids = version_ids
        self.max_nesting_depth = max_nesting_depth
        self.resolver = SemanticResolver.build(packs)

    def classify_column(
        self,
        dataset_fingerprint: str,
        item: ColumnInput,
        degraded_alerts: list[Alert] | None = None,
    ) -> FieldClassification:
        alerts: list[Alert] = list(degraded_alerts or [])
        semantic_key, semantic_alerts = self.resolver.resolve(item.column, item.degraded)
        alerts.extend(semantic_alerts)
        outcomes: list[tuple[str, _PackOutcome]] = []
        for pack in self.packs:
            version_id = self.version_ids[pack.standard.code]
            outcome = _match_pack(pack, item, version_id)
            alerts.extend(outcome.alerts)
            outcomes.append((pack.standard.code, outcome))
        result = FieldClassification(
            dataset_fingerprint=dataset_fingerprint,
            table_name=item.table,
            column_name=item.column,
            semantic_key=semantic_key,
            sensitive_type=item.sensitive_type,
            detection_confidence=item.detection_confidence,
            degraded=item.degraded,
            standards=[outcome.classification for _code, outcome in outcomes],
            source="auto",
            alerts=alerts,
        )
        return result

    def enforce_semantic_consistency(
        self, results: list[FieldClassification]
    ) -> list[FieldClassification]:
        """Force one label per semantic key; highest protection level wins.

        Labels are aligned per standard independently. Any divergence that had to
        be reconciled produces a ``semantic_drift`` alert on every affected column.
        """
        groups: dict[str, list[FieldClassification]] = {}
        for result in results:
            if result.semantic_key:
                groups.setdefault(result.semantic_key, []).append(result)
        for semantic_key, members in groups.items():
            if len(members) < 2:
                continue
            for pack in self.packs:
                code = pack.standard.code
                per_member = {
                    id(member): next(
                        std for std in member.standards if std.standard_code == code
                    )
                    for member in members
                }
                signatures = {
                    canonical_json(std.to_dict()) for std in per_member.values()
                }
                if len(signatures) <= 1:
                    continue
                winner_std = max(
                    per_member.values(),
                    key=lambda std: (pack.level_rank(std.level or ""), std.matched_rule_id or ""),
                )
                for member in members:
                    current = per_member[id(member)]
                    if current is winner_std:
                        continue
                    index = next(
                        i
                        for i, std in enumerate(member.standards)
                        if std.standard_code == code
                    )
                    member.standards[index] = winner_std
                    member.alerts.append(
                        Alert(
                            code="semantic_drift",
                            severity="warning",
                            message=(
                                f"语义键 {semantic_key!r} 下的异名字段 "
                                f"{member.table_name}.{member.column_name} 与同语义字段分级不一致，"
                                f"已统一为最高保护等级 {winner_std.level} "
                                f"(规则 {winner_std.matched_rule_id})。"
                            ),
                            table=member.table_name,
                            column=member.column_name,
                            detail={
                                "semantic_key": semantic_key,
                                "standard": code,
                                "unified_rule_id": winner_std.matched_rule_id,
                                "unified_level": winner_std.level,
                            },
                        )
                    )
        return results
