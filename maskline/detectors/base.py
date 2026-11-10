"""Detector protocol, candidates, and deterministic sampling helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol, Sequence

CONFIDENCE_HIGH = 0.80
CONFIDENCE_MEDIUM = 0.50
CONFIDENCE_LOW = 0.20


def confidence_for(score: float) -> str:
    if score >= CONFIDENCE_HIGH:
        return "high"
    if score >= CONFIDENCE_MEDIUM:
        return "medium"
    if score >= CONFIDENCE_LOW:
        return "low"
    return "none"


@dataclass(frozen=True)
class Candidate:
    sensitive_type: str
    score: float
    hit_rate: float
    validate_rate: float
    sample_size: int
    matched_count: int
    matches: tuple[str, ...] = field(default=(), repr=False, compare=False)
    @property
    def confidence(self) -> str:
        return confidence_for(self.score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sensitive_type": self.sensitive_type,
            "score": round(self.score, 4),
            "hit_rate": round(self.hit_rate, 4),
            "validate_rate": round(self.validate_rate, 4),
            "sample_size": self.sample_size,
            "matched_count": self.matched_count,
            "confidence": self.confidence,
        }


class Detector(Protocol):
    sensitive_type: str

    def evaluate(self, values: Sequence[str]) -> Candidate | None:
        ...


def clean_text_values(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            result.append(text)
    return result


def text_sample(values: Iterable[Any], limit: int) -> list[str]:
    """Deterministic prefix sample used for every detector in one column."""
    return clean_text_values(values)[:limit]


def score_candidate(
    sensitive_type: str,
    sample_size: int,
    matches: list[str],
    validator: Callable[[str], bool] | None = None,
) -> Candidate | None:
    if sample_size == 0 or not matches:
        return None
    valid = matches
    if validator is not None:
        valid = [match for match in matches if validator(match)]
    hit_rate = len(matches) / sample_size
    validation_rate = len(valid) / len(matches) if matches else 0.0
    score = hit_rate * validation_rate
    if score <= 0:
        return None
    return Candidate(
        sensitive_type=sensitive_type,
        score=score,
        hit_rate=hit_rate,
        validate_rate=validation_rate,
        sample_size=sample_size,
        matched_count=len(matches),
        matches=tuple(matches),
    )
