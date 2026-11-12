"""Governance operation trail built on the existing tamper-evident AuditLog.

Every quota change and scheduling decision is appended to the same hash-chained
``audit.jsonl`` as normal masking runs, with a distinct ``governor_event``
field so verifiers can tell governance actions apart from data-plane events
without a second logging subsystem.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..audit import AuditLog
from .state import JobRecord

# Stable vocabulary for the governance trail.
EVENT_DAEMON_START = "daemon_start"
EVENT_DAEMON_STOP = "daemon_stop"
EVENT_JOB_SUBMIT = "job_submit"
EVENT_JOB_START = "job_start"
EVENT_JOB_THROTTLED = "job_throttled"
EVENT_JOB_PAUSED = "job_paused"
EVENT_JOB_RESUMED = "job_resumed"
EVENT_JOB_COMPLETED = "job_completed"
EVENT_JOB_FAILED = "job_failed"
EVENT_JOB_CANCELLED = "job_cancelled"
EVENT_QUOTA_UPDATED = "quota_updated"
EVENT_CONFIG_RELOADED = "config_reloaded"
EVENT_ORPHAN_RECOVERED = "orphan_recovered"


class GovernorAudit:
    """Thin, typed wrapper around the shared append-only AuditLog."""

    def __init__(self, audit_path: str | Path) -> None:
        self._log = AuditLog(audit_path)

    def record(self, event: str, details: dict[str, Any]) -> dict[str, Any]:
        entry = {"governor_event": event}
        entry.update(details)
        return self._log.append(entry)

    def job_event(self, event: str, job: JobRecord, **extra: Any) -> dict[str, Any]:
        details = {
            "job_id": job.job_id,
            "job_name": job.name,
            "state": job.state,
            "quota": job.quota(),
            "quota_source": job.quota_source,
            "attempt": job.attempt,
            "runtime_seconds": round(job.runtime_seconds, 3),
        }
        details.update(extra)
        return self.record(event, details)

    def verify(self) -> Any:
        return self._log.verify()
