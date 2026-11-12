"""Detection scoring, suppression of overlapping formats, and dataset scans."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..dataset_io import read_column_samples
from ..registry import Catalog, DatasetInventory
from .base import CONFIDENCE_LOW, Candidate, clean_text_values
from .checksums import id_card_valid
from .lexicon import LEXICON_DETECTORS
from .patterns import DETECTORS

PRIORITY = {
    "id_card": 0,
    "credit_code": 1,
    "bank_card": 2,
    "mobile_phone": 3,
    "email": 4,
    "ipv4": 5,
    "person_name": 6,
    "address": 7,
}


def detector_version() -> str:
    """Fingerprint of the detector package source.

    Any change to detector logic (patterns, lexicons, checksums, scoring)
    changes this version, so a registered dataset can be flagged for re-scan.
    """
    digest = hashlib.sha256(b"maskline-detectors-v1\x00")
    package = Path(__file__).resolve().parent
    try:
        for source in sorted(package.glob("*.py")):
            digest.update(source.name.encode("utf-8") + b"\x00")
            digest.update(source.read_bytes())
    except OSError:
        return "unknown"
    return digest.hexdigest()[:16]


@dataclass(frozen=True)
class DetectionResult:
    table: str
    column: str
    sample_size: int
    sensitive_type: str | None
    confidence: str
    score: float
    hit_rate: float
    validate_rate: float
    candidates: tuple[Candidate, ...] = field(default_factory=tuple)

    def to_record(self, dataset_fingerprint: str, table: str, column: str) -> dict[str, Any]:
        return {
            "dataset_fingerprint": dataset_fingerprint,
            "table_name": table,
            "column_name": column,
            "sensitive_type": self.sensitive_type,
            "confidence": self.confidence,
            "score": self.score,
            "hit_rate": self.hit_rate,
            "validate_rate": self.validate_rate,
            "sample_size": self.sample_size,
            "candidates": [item.to_dict() for item in self.candidates],
        }


def _suppress_overlaps(candidates: list[Candidate]) -> list[Candidate]:
    by_type = {item.sensitive_type: item for item in candidates}
    id_candidate = by_type.get("id_card")
    if not id_candidate or id_candidate.score < CONFIDENCE_LOW:
        return candidates
    adjusted: list[Candidate] = []
    for candidate in candidates:
        if candidate.sensitive_type in {"bank_card", "credit_code"}:
            id_like = sum(1 for match in candidate.matches if id_card_valid(match))
            ratio = id_like / len(candidate.matches) if candidate.matches else 0.0
            if ratio > 0:
                candidate = Candidate(
                    sensitive_type=candidate.sensitive_type,
                    score=candidate.score * (1.0 - ratio),
                    hit_rate=candidate.hit_rate,
                    validate_rate=candidate.validate_rate,
                    sample_size=candidate.sample_size,
                    matched_count=candidate.matched_count,
                    matches=candidate.matches,
                )
        if candidate.score > 0:
            adjusted.append(candidate)
    return adjusted


def analyze_values(
    values: Iterable[Any], sample_limit: int = 200, table: str = "", column: str = ""
) -> DetectionResult:
    sample = clean_text_values(values)[:sample_limit]
    if not sample:
        return DetectionResult(table, column, 0, None, "none", 0.0, 0.0, 0.0)
    candidates: list[Candidate] = []
    for detector in (*DETECTORS, *LEXICON_DETECTORS):
        candidate = detector.evaluate(sample)
        if candidate is not None and candidate.score > 0:
            candidates.append(candidate)
    candidates = _suppress_overlaps(candidates)
    candidates.sort(key=lambda item: (-item.score, PRIORITY.get(item.sensitive_type, 99)))
    best = candidates[0] if candidates else None
    if best is None or best.score < CONFIDENCE_LOW:
        return DetectionResult(
            table=table,
            column=column,
            sample_size=len(sample),
            sensitive_type=None,
            confidence="none",
            score=best.score if best else 0.0,
            hit_rate=best.hit_rate if best else 0.0,
            validate_rate=best.validate_rate if best else 0.0,
            candidates=tuple(candidates),
        )
    return DetectionResult(
        table=table,
        column=column,
        sample_size=len(sample),
        sensitive_type=best.sensitive_type,
        confidence=best.confidence,
        score=best.score,
        hit_rate=best.hit_rate,
        validate_rate=best.validate_rate,
        candidates=tuple(candidates),
    )


def analyze_column(
    values: Iterable[Any], sample_limit: int = 200, table: str = "", column: str = ""
) -> DetectionResult:
    return analyze_values(values, sample_limit=sample_limit, table=table, column=column)


def detect_inventory(
    inventory: DatasetInventory, sample_limit: int = 200
) -> list[dict[str, Any]]:
    """Score every column without writing anything (used by dry-run and scans)."""
    findings: list[dict[str, Any]] = []
    for table in inventory.tables:
        for column in table.columns:
            samples = read_column_samples(
                inventory.path, inventory.kind, table.name, column.name, sample_limit
            )
            result = analyze_values(
                samples, sample_limit=sample_limit, table=table.name, column=column.name
            )
            findings.append(
                result.to_record(inventory.fingerprint, table.name, column.name)
            )
    return findings


def scan_inventory(
    inventory: DatasetInventory, catalog: Catalog, sample_limit: int = 200
) -> list[dict[str, Any]]:
    """Sample every column, score it, persist findings, and return the rows."""
    findings = detect_inventory(inventory, sample_limit=sample_limit)
    for record in findings:
        catalog.save_finding(record)
    return findings
