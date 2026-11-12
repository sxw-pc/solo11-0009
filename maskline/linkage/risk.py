"""Combination risk scoring, aligned with the existing detector score rules.

The per-column sensitive scores come from the existing detectors (0..1), and
the base level reuses the same confidence thresholds (0.8 / 0.5 / 0.2). The
combination score merges the types reachable through one join cluster with a
noisy-or over per-type weights; combination rules then escalate the level for
known high-impact identity/finance combinations, up to ``critical``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from ..detectors.base import CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM
from .graph import LinkCluster, LinkGraph
from .model import LEVEL_ORDER, RiskFinding

TYPE_WEIGHTS = {
    "id_card": 1.0,
    "bank_card": 0.9,
    "mobile_phone": 0.8,
    "credit_code": 0.7,
    "address": 0.7,
    "person_name": 0.6,
    "email": 0.5,
    "ipv4": 0.3,
}
DEFAULT_TYPE_WEIGHT = 0.3


@dataclass(frozen=True)
class ComboRule:
    types: frozenset[str]
    min_level: str
    label: str
    advice: str

    def to_record(self) -> dict[str, Any]:
        return {
            "types": sorted(self.types),
            "min_level": self.min_level,
            "label": self.label,
            "advice": self.advice,
        }


COMBO_RULES: tuple[ComboRule, ...] = (
    ComboRule(
        frozenset({"person_name", "id_card"}),
        "critical",
        "实名身份核验组合",
        "姓名与身份证号关联后可完整冒用自然人身份，两者必须强脱敏并审批关联查询",
    ),
    ComboRule(
        frozenset({"person_name", "bank_card"}),
        "critical",
        "资金账户实名组合",
        "姓名与银行卡关联后可直接定位资金账户，必须假名化/哈希后方可使用",
    ),
    ComboRule(
        frozenset({"id_card", "bank_card"}),
        "critical",
        "金融账户控制组合",
        "身份证号与银行卡关联后可用于账户找回与盗刷，必须按最高等级管控",
    ),
    ComboRule(
        frozenset({"bank_card", "mobile_phone"}),
        "high",
        "账户触达组合",
        "银行卡与手机号关联后可重置支付凭证，出域前必须脱敏",
    ),
    ComboRule(
        frozenset({"person_name", "mobile_phone"}),
        "high",
        "联系触达组合",
        "姓名与手机号关联后可直接触达自然人，建议遮蔽或假名化",
    ),
    ComboRule(
        frozenset({"person_name", "address"}),
        "high",
        "居住地址画像组合",
        "姓名与住址关联后可定位自然人住所，建议泛化地址",
    ),
    ComboRule(
        frozenset({"mobile_phone", "address"}),
        "medium",
        "行踪联络组合",
        "手机号与住址关联后可刻画行踪，建议泛化或遮蔽",
    ),
    ComboRule(
        frozenset({"person_name", "email"}),
        "medium",
        "通讯身份组合",
        "姓名与邮箱关联后可定向触达，建议评估使用场景后脱敏",
    ),
    ComboRule(
        frozenset({"person_name", "credit_code"}),
        "medium",
        "企业自然人关联组合",
        "姓名与统一社会信用代码关联后暴露自然人与企业关系，建议评估后脱敏",
    ),
)

LEVEL_RECOMMENDATIONS = {
    "critical": "极高风险：关联后可还原完整敏感身份或账户，组合内敏感字段必须假名化/哈希，"
    "关联键建议假名化以切断跨库关联，访问需审批并留痕",
    "high": "高风险：关联后形成敏感组合，出域前必须完成遮蔽/哈希/假名化脱敏",
    "medium": "中风险：建议对组合内字段泛化或遮蔽，限制批量导出与关联查询",
    "low": "低风险：关注并定期复核，按需脱敏",
}


def _base_level(score: float) -> str:
    """Map a combined score to a level using the detector confidence steps."""
    if score >= CONFIDENCE_HIGH:
        return "high"
    if score >= CONFIDENCE_MEDIUM:
        return "medium"
    if score >= CONFIDENCE_LOW:
        return "low"
    return "none"


def _combine_scores(type_scores: dict[str, float]) -> float:
    survival = 1.0
    for sensitive_type, score in type_scores.items():
        weight = TYPE_WEIGHTS.get(sensitive_type, DEFAULT_TYPE_WEIGHT)
        survival *= 1.0 - weight * score
    return round(1.0 - survival, 4)


def _cluster_finding(cluster: LinkCluster, type_ignored: frozenset[str]) -> RiskFinding | None:
    type_scores = cluster.sensitive_type_scores(type_ignored)
    if not type_scores:
        return None
    score = _combine_scores(type_scores)
    level = _base_level(score)
    matched = [rule for rule in COMBO_RULES if rule.types <= set(type_scores)]
    for rule in matched:
        if LEVEL_ORDER[rule.min_level] > LEVEL_ORDER[level]:
            level = rule.min_level
    if len(type_scores) >= 2 and LEVEL_ORDER[level] < LEVEL_ORDER["medium"]:
        level = "medium"
    if level == "none":
        return None
    datasets = cluster.datasets
    endpoint_keys = {
        endpoint
        for edge in cluster.edges
        for endpoint in (edge.left.key, edge.right.key)
    }
    join_keys = tuple(sorted(column.ref.label for column in cluster.join_key_columns))
    columns = tuple(
        {
            "ref": column.ref.label,
            "path": column.ref.dataset_path,
            "table": column.ref.table,
            "column": column.ref.column,
            "sensitive_type": column.sensitive_type,
            "confidence": column.confidence,
            "score": column.score,
            "join_key": column.ref.key in endpoint_keys,
        }
        for column in cluster.columns
    )
    summary = (
        f"跨 {len(datasets)} 个数据集经 {len(join_keys)} 个关联键形成敏感组合："
        + "、".join(sorted(type_scores))
    )
    return RiskFinding(
        risk_id="",
        level=level,
        score=score,
        summary=summary,
        recommendation=LEVEL_RECOMMENDATIONS[level],
        datasets=datasets,
        columns=columns,
        join_keys=join_keys,
        sensitive_types=dict(sorted(type_scores.items())),
        combo_rules=tuple(rule.to_record() for rule in matched),
    )


def evaluate_risks(
    graph: LinkGraph, version_no: int, type_ignored: frozenset[str] = frozenset()
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for cluster in graph.clusters:
        finding = _cluster_finding(cluster, type_ignored)
        if finding is not None:
            findings.append(finding)
    findings.sort(
        key=lambda item: (-LEVEL_ORDER[item.level], -item.score, item.datasets)
    )
    return [
        replace(finding, risk_id=f"R-{version_no}-{index:02d}")
        for index, finding in enumerate(findings, start=1)
    ]
