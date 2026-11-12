"""Retention defaults per artifact type and per-dataset overrides.

Each produced artifact kind gets a default retention window in days. A policy
file may shorten or extend the window either globally (per type) or for one
dataset fingerprint. Pseudonym mapping defaults to the shortest window because
it is equivalent to a plaintext key.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .types import ArtifactType
from ..utils import MasklineError


class RetentionPolicyError(MasklineError):
    pass


# Pseudonym mapping is the plaintext key: keep it for the shortest window.
# Reports and manifests describe the run and live a bit longer; checkpoints
# are only useful while a run may be resumed, so they expire first.
DEFAULT_RETENTION_DAYS: dict[ArtifactType, int] = {
    ArtifactType.PSEUDOMAP: 30,
    ArtifactType.OUTPUT: 90,
    ArtifactType.CHECKPOINT: 14,
    ArtifactType.REPORT: 180,
    ArtifactType.MANIFEST: 180,
}

DEFAULT_GRACE_DAYS = 7


def _parse_days(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RetentionPolicyError(f"{label} must be an integer number of days")
    if value < 0:
        raise RetentionPolicyError(f"{label} must be >= 0 days")
    return value


@dataclass(frozen=True)
class RetentionSchedule:
    """Effective retention and grace windows resolved for one artifact."""

    retention_days: int
    grace_days: int


class RetentionPolicy:
    """Layered retention configuration: built-in defaults < policy file < dataset override."""

    def __init__(
        self,
        retention_days: dict[ArtifactType, int] | None = None,
        grace_days: int = DEFAULT_GRACE_DAYS,
        dataset_overrides: dict[str, dict[ArtifactType, int]] | None = None,
        dataset_grace_overrides: dict[str, int] | None = None,
    ) -> None:
        self._retention: dict[ArtifactType, int] = dict(DEFAULT_RETENTION_DAYS)
        if retention_days:
            for artifact_type, days in retention_days.items():
                self._retention[ArtifactType(artifact_type)] = _parse_days(
                    days, f"retention for {artifact_type}"
                )
        self.grace_days = _parse_days(grace_days, "grace period")
        self._dataset_overrides: dict[str, dict[ArtifactType, int]] = {}
        for fingerprint, mapping in (dataset_overrides or {}).items():
            if not isinstance(fingerprint, str) or not fingerprint:
                raise RetentionPolicyError("dataset override keys must be fingerprint strings")
            resolved = {
                ArtifactType(artifact_type): _parse_days(
                    days, f"retention override for {fingerprint}/{artifact_type}"
                )
                for artifact_type, days in mapping.items()
            }
            self._dataset_overrides[fingerprint] = resolved
        self._dataset_grace: dict[str, int] = {
            fingerprint: _parse_days(days, f"grace override for {fingerprint}")
            for fingerprint, days in (dataset_grace_overrides or {}).items()
        }

    @classmethod
    def from_file(cls, path: str | Path) -> "RetentionPolicy":
        policy_path = Path(path)
        if not policy_path.is_file():
            raise RetentionPolicyError(f"retention policy file not found: {policy_path}")
        try:
            raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise RetentionPolicyError(f"cannot parse retention policy {policy_path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise RetentionPolicyError("retention policy must be a YAML mapping")
        known_types = {item.value for item in ArtifactType}
        retention_days: dict[ArtifactType, int] = {}
        defaults = raw.get("retention_days", {})
        if defaults is None:
            defaults = {}
        if not isinstance(defaults, dict):
            raise RetentionPolicyError("retention_days must be a mapping of artifact type to days")
        for name, days in defaults.items():
            if name not in known_types:
                raise RetentionPolicyError(
                    f"unknown artifact type {name!r}; valid types: {', '.join(sorted(known_types))}"
                )
            retention_days[ArtifactType(name)] = days
        grace_days = raw.get("grace_days", DEFAULT_GRACE_DAYS)
        overrides: dict[str, dict[ArtifactType, int]] = {}
        grace_overrides: dict[str, int] = {}
        datasets = raw.get("datasets", {})
        if datasets is None:
            datasets = {}
        if not isinstance(datasets, dict):
            raise RetentionPolicyError("datasets must be a mapping of fingerprint to overrides")
        for fingerprint, body in datasets.items():
            if not isinstance(body, dict):
                raise RetentionPolicyError(f"dataset override {fingerprint!r} must be a mapping")
            mapping = body.get("retention_days", {})
            if mapping is None:
                mapping = {}
            if not isinstance(mapping, dict):
                raise RetentionPolicyError(
                    f"retention_days under dataset {fingerprint!r} must be a mapping"
                )
            unknown = sorted(set(mapping) - known_types)
            if unknown:
                raise RetentionPolicyError(
                    f"unknown artifact type(s) {', '.join(unknown)!r} for dataset {fingerprint!r}"
                )
            overrides[str(fingerprint)] = {ArtifactType(name): days for name, days in mapping.items()}
            if "grace_days" in body:
                grace_overrides[str(fingerprint)] = body["grace_days"]
        return cls(
            retention_days=retention_days,
            grace_days=grace_days,
            dataset_overrides=overrides,
            dataset_grace_overrides=grace_overrides,
        )

    @classmethod
    def default(cls) -> "RetentionPolicy":
        return cls()

    def schedule_for(
        self, artifact_type: ArtifactType, dataset_fingerprint: str | None = None
    ) -> RetentionSchedule:
        retention_days = self._retention[ArtifactType(artifact_type)]
        grace_days = self.grace_days
        if dataset_fingerprint:
            override = self._dataset_overrides.get(dataset_fingerprint)
            if override and artifact_type in override:
                retention_days = override[artifact_type]
            grace_days = self._dataset_grace.get(dataset_fingerprint, grace_days)
        return RetentionSchedule(retention_days=retention_days, grace_days=grace_days)

    def describe(self) -> dict[str, Any]:
        return {
            "defaults": {
                artifact_type.value: days for artifact_type, days in self._retention.items()
            },
            "grace_days": self.grace_days,
            "datasets": {
                fingerprint: {
                    "retention_days": {
                        artifact_type.value: days for artifact_type, days in mapping.items()
                    },
                    **(
                        {"grace_days": self._dataset_grace[fingerprint]}
                        if fingerprint in self._dataset_grace
                        else {}
                    ),
                }
                for fingerprint, mapping in self._dataset_overrides.items()
            },
        }
