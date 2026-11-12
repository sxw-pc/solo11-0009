"""Shared enums and data classes for the lifecycle package."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path


class ArtifactType(str, enum.Enum):
    """The five kinds of produced artifacts under retention control.

    The audit log itself is intentionally excluded: it is append-only and is
    the place where destruction events are recorded, so destroying it would
    erase the evidence of destruction.
    """

    PSEUDOMAP = "pseudomap"
    OUTPUT = "output"
    CHECKPOINT = "checkpoint"
    REPORT = "report"
    MANIFEST = "manifest"


class ArtifactStatus(str, enum.Enum):
    ACTIVE = "active"
    PENDING = "pending"          # retention expired, inside grace period, revocable
    GRACE_EXPIRED = "grace_expired"
    DESTROYED = "destroyed"
    FAILED = "failed"            # last destruction attempt failed; retry will resume
    REVOKED = "revoked"          # grace-period revocation happened; retention restarts


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_id: str
    artifact_type: ArtifactType
    path: Path
    run_id: str | None
    dataset_fingerprint: str | None
    content_hash: str | None
    size_bytes: int | None
    created_at: str
    retention_days: int
    grace_days: int
    expires_at: str
    grace_ends_at: str
    status: ArtifactStatus
    destroy_token: str | None = None
    updated_at: str | None = None

    @property
    def is_pseudomap(self) -> bool:
        return self.artifact_type is ArtifactType.PSEUDOMAP
