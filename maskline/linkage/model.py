"""Shared data model for cross-dataset linkage risk identification."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RISK_LEVELS = ("none", "low", "medium", "high", "critical")
LEVEL_ORDER = {name: index for index, name in enumerate(RISK_LEVELS)}
LEVEL_LABELS = {"none": "无", "low": "低", "medium": "中", "high": "高", "critical": "极高"}


@dataclass(frozen=True)
class ColRef:
    """Stable reference to one column of one registered dataset."""

    dataset_fingerprint: str
    dataset_path: str
    table: str
    column: str

    @property
    def key(self) -> str:
        return f"{self.dataset_fingerprint}:{self.table}:{self.column}"

    @property
    def label(self) -> str:
        return f"{Path(self.dataset_path).name}:{self.table}.{self.column}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_fingerprint": self.dataset_fingerprint,
            "dataset_path": self.dataset_path,
            "table": self.table,
            "column": self.column,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ColRef":
        return cls(
            dataset_fingerprint=data["dataset_fingerprint"],
            dataset_path=data["dataset_path"],
            table=data["table"],
            column=data["column"],
        )


@dataclass(frozen=True)
class ColumnProfile:
    """Per-column statistics, detector score, and key-candidate flags."""

    ref: ColRef
    declared_type: str
    sample_size: int
    distinct_count: int
    distinct_ratio: float
    sensitive_type: str | None
    confidence: str
    score: float
    hit_rate: float
    validate_rate: float
    key_candidate: bool
    ignored: bool = False
    key_reasons: tuple[str, ...] = ()
    value_truncated: bool = False

    def to_record(self) -> dict[str, Any]:
        return {
            "declared_type": self.declared_type,
            "sample_size": self.sample_size,
            "distinct_count": self.distinct_count,
            "distinct_ratio": self.distinct_ratio,
            "sensitive_type": self.sensitive_type,
            "confidence": self.confidence,
            "score": self.score,
            "hit_rate": self.hit_rate,
            "validate_rate": self.validate_rate,
            "key_candidate": self.key_candidate,
            "ignored": self.ignored,
            "key_reasons": list(self.key_reasons),
            "value_truncated": self.value_truncated,
        }

    @classmethod
    def from_record(cls, ref: ColRef, record: dict[str, Any]) -> "ColumnProfile":
        return cls(
            ref=ref,
            declared_type=record.get("declared_type", ""),
            sample_size=int(record.get("sample_size", 0)),
            distinct_count=int(record.get("distinct_count", 0)),
            distinct_ratio=float(record.get("distinct_ratio", 0.0)),
            sensitive_type=record.get("sensitive_type"),
            confidence=record.get("confidence", "none"),
            score=float(record.get("score", 0.0)),
            hit_rate=float(record.get("hit_rate", 0.0)),
            validate_rate=float(record.get("validate_rate", 0.0)),
            key_candidate=bool(record.get("key_candidate", False)),
            ignored=bool(record.get("ignored", False)),
            key_reasons=tuple(record.get("key_reasons", ())),
            value_truncated=bool(record.get("value_truncated", False)),
        )


@dataclass(frozen=True)
class Association:
    """One directed-less edge between two columns of different datasets."""

    left: ColRef
    right: ColRef
    kind: str  # "equals" | "semantic"
    score: float
    overlap: int = 0
    containment: float = 0.0
    reason: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
            "kind": self.kind,
            "score": self.score,
            "overlap": self.overlap,
            "containment": self.containment,
            "reason": self.reason,
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "Association":
        return cls(
            left=ColRef.from_dict(record["left"]),
            right=ColRef.from_dict(record["right"]),
            kind=record["kind"],
            score=float(record["score"]),
            overlap=int(record.get("overlap", 0)),
            containment=float(record.get("containment", 0.0)),
            reason=record.get("reason", ""),
        )


@dataclass(frozen=True)
class ScanWarning:
    """A skipped file: the scan continues and the warning is recorded."""

    path: str
    stage: str
    message: str

    def to_record(self) -> dict[str, Any]:
        return {"path": self.path, "stage": self.stage, "message": self.message}


@dataclass(frozen=True)
class RiskFinding:
    """One sensitive combination reachable through cross-dataset joins."""

    risk_id: str
    level: str
    score: float
    summary: str
    recommendation: str
    datasets: tuple[str, ...]
    columns: tuple[dict[str, Any], ...]
    join_keys: tuple[str, ...]
    sensitive_types: dict[str, float]
    combo_rules: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def to_record(self) -> dict[str, Any]:
        return {
            "risk_id": self.risk_id,
            "level": self.level,
            "level_label": LEVEL_LABELS.get(self.level, self.level),
            "score": self.score,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "datasets": list(self.datasets),
            "columns": list(self.columns),
            "join_keys": list(self.join_keys),
            "sensitive_types": dict(self.sensitive_types),
            "combo_rules": list(self.combo_rules),
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "RiskFinding":
        return cls(
            risk_id=record["risk_id"],
            level=record["level"],
            score=float(record["score"]),
            summary=record.get("summary", ""),
            recommendation=record.get("recommendation", ""),
            datasets=tuple(record.get("datasets", ())),
            columns=tuple(record.get("columns", ())),
            join_keys=tuple(record.get("join_keys", ())),
            sensitive_types=dict(record.get("sensitive_types", {})),
            combo_rules=tuple(record.get("combo_rules", ())),
        )
