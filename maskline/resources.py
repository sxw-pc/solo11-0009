"""Best-effort per-trial CPU and memory limits.

A gray trial runs in the same Python process as the CLI, but its resource
consumption is still bounded so an in-flight formal task is not starved:

* CPU affinity is narrowed to at most ``cpu_cores`` allowed CPUs (POSIX).
* ``RLIMIT_AS`` (address space) is capped at ``memory_mb`` (POSIX).

Limits are restored when the context exits.  On platforms that do not support
one of the mechanisms the corresponding flag is reported as ``False`` rather
than failing the trial; the workspace and snapshot isolation remains intact.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .utils import MasklineError


class ResourceLimitError(MasklineError):
    pass


@dataclass(frozen=True)
class ResourceLimits:
    cpu_cores: int = 2
    memory_mb: int = 512

    def __post_init__(self) -> None:
        if (
            not isinstance(self.cpu_cores, int)
            or isinstance(self.cpu_cores, bool)
            or self.cpu_cores < 1
        ):
            raise ResourceLimitError("cpu_cores must be a positive integer")
        if (
            not isinstance(self.memory_mb, int)
            or isinstance(self.memory_mb, bool)
            or self.memory_mb < 1
        ):
            raise ResourceLimitError("memory_mb must be a positive integer")


class ResourceGovernor:
    """Apply and restore per-process CPU affinity and address-space limits."""

    def __init__(self, limits: ResourceLimits) -> None:
        self.limits = limits
        self._original_affinity: set[int] | None = None
        self._affinity_changed = False
        self._original_rlimit: tuple[int, int] | None = None
        self._memory_changed = False
        self._applied: dict[str, Any] = {}

    def __enter__(self) -> dict[str, Any]:
        notes: list[str] = []
        applied: dict[str, Any] = {
            "cpu_cores": self.limits.cpu_cores,
            "memory_mb": self.limits.memory_mb,
            "cpu_enforced": False,
            "memory_enforced": False,
            "effective_cpu_cores": None,
            "effective_memory_bytes": None,
            "notes": notes,
        }
        self._applied = applied

        if hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"):
            try:
                current = set(os.sched_getaffinity(0))
                chosen = set(sorted(current)[: self.limits.cpu_cores])
                self._original_affinity = current
                if chosen and chosen != current:
                    os.sched_setaffinity(0, chosen)
                    self._affinity_changed = True
                applied["effective_cpu_cores"] = len(chosen)
                applied["cpu_enforced"] = True
            except (AttributeError, OSError, ValueError) as exc:
                notes.append(f"cpu affinity limit not applied: {exc}")
        else:
            notes.append("cpu affinity limit is not supported on this platform")

        try:
            import resource
        except ImportError:
            notes.append("memory limit is not supported on this platform")
            return applied

        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            desired = self.limits.memory_mb * 1024 * 1024
            if soft != resource.RLIM_INFINITY:
                # Never relax a limit that was already stricter.
                desired = min(desired, soft)
            if hard != resource.RLIM_INFINITY:
                desired = min(desired, hard)
            self._original_rlimit = (soft, hard)
            if soft == resource.RLIM_INFINITY or desired < soft:
                resource.setrlimit(resource.RLIMIT_AS, (desired, hard))
                self._memory_changed = True
                applied["effective_memory_bytes"] = desired
            else:
                applied["effective_memory_bytes"] = soft
            applied["memory_enforced"] = True
        except (OSError, ValueError) as exc:
            notes.append(f"memory limit not applied: {exc}")
        return applied

    def __exit__(self, *_exc: object) -> None:
        if self._affinity_changed and self._original_affinity is not None:
            try:
                os.sched_setaffinity(0, self._original_affinity)
            except (AttributeError, OSError, ValueError) as exc:
                self._applied.setdefault("notes", []).append(
                    f"cpu affinity restore failed: {exc}"
                )
            self._affinity_changed = False
        if self._memory_changed and self._original_rlimit is not None:
            try:
                import resource

                resource.setrlimit(resource.RLIMIT_AS, self._original_rlimit)
            except (ImportError, OSError, ValueError) as exc:
                self._applied.setdefault("notes", []).append(
                    f"memory limit restore failed: {exc}"
                )
            self._memory_changed = False
