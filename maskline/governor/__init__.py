"""Offline resource quota governance for masking tasks.

The governor integrates the three existing capabilities:

* streaming, batch-committed pipeline execution with rowid checkpoints,
* the SQLite run/checkpoint state store,
* the tamper-evident append-only audit chain.

It adds FIFO queueing, per-task CPU/memory/runtime quotas, automatic
throttle/pause/resume enforcement, and a real-time status view -- all running
locally without any external scheduler or third-party service.
"""

from __future__ import annotations

from .config import BUILTIN_DEFAULTS, GovernorConfig, Quota, load_config
from .daemon import Governor, PidLock, is_daemon_running, read_status
from .errors import GovernorError, JobControlError, QuotaConfigError
from .state import GovernorStore, JobRecord, JOB_STATES

__all__ = [
    "BUILTIN_DEFAULTS",
    "Governor",
    "GovernorConfig",
    "GovernorError",
    "GovernorStore",
    "JobControlError",
    "JobRecord",
    "JOB_STATES",
    "PidLock",
    "Quota",
    "QuotaConfigError",
    "is_daemon_running",
    "load_config",
    "read_status",
]
