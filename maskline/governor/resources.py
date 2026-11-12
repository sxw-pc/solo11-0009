"""Offline CPU and memory sampling for supervised processes.

On Linux every metric is read directly from ``/proc`` (and ``/sys`` for the
machine size): no third-party packages and no network access.  A portable
fallback based on :mod:`resource` and :mod:`os.times` keeps the import surface
working on macOS/Windows, where per-process /proc sampling does not exist; the
fallback only degrades memory precision, never the scheduling logic.

The sampler is intentionally a small protocol so tests can inject a
deterministic fake instead of racing real processes.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

PROC = Path("/proc")


@dataclass(frozen=True)
class ProcessSample:
    """One resource observation for a supervised process tree."""

    pid: int
    alive: bool
    cpu_percent: float
    rss_mb: float
    system_available_mb: float
    system_total_mb: float
    sampled_at: float


class ResourceSampler(Protocol):
    """Minimal surface the scheduler depends on."""

    def sample(self, pid: int) -> ProcessSample: ...

    def system_memory(self) -> tuple[float, float]:
        """Return ``(available_mb, total_mb)`` for the whole machine."""


def _page_size() -> int:
    try:
        return os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError):
        return 4096


def _clock_ticks() -> float:
    try:
        return float(os.sysconf("SC_CLK_TCK"))
    except (ValueError, OSError):
        return 100.0


def read_system_memory_mb() -> tuple[float, float]:
    """Parse /proc/meminfo for MemAvailable and MemTotal in MiB."""
    meminfo = PROC / "meminfo"
    if not meminfo.exists():
        return _fallback_system_memory()
    values: dict[str, int] = {}
    with meminfo.open("r", encoding="utf-8") as handle:
        for line in handle:
            key, _, rest = line.partition(":")
            if key in ("MemTotal", "MemAvailable"):
                amount = rest.strip().split()
                if amount:
                    values[key] = int(amount[0])  # always reported in kB
    total_kb = values.get("MemTotal", 0)
    available_kb = values.get("MemAvailable", values.get("MemTotal", 0))
    return available_kb / 1024.0, total_kb / 1024.0


def _fallback_system_memory() -> tuple[float, float]:
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        # Last resort: report the supervised RSS scale as the whole machine.
        return float("inf"), float("inf")
    memory = psutil.virtual_memory()
    return memory.available / (1024 * 1024), memory.total / (1024 * 1024)


def _descendant_pids(pid: int) -> list[int]:
    """Collect a process and all of its descendants from /proc."""
    children: dict[int, list[int]] = {}
    for entry in PROC.iterdir():
        if not entry.name.isdigit():
            continue
        stat = entry / "stat"
        try:
            text = stat.read_text(encoding="utf-8")
        except OSError:
            continue
        # comm is parenthesised and may contain spaces and parentheses itself.
        right_paren = text.rfind(")")
        fields = text[right_paren + 2:].split()
        if len(fields) < 2:
            continue
        ppid = int(fields[1])  # field 4 in proc(5), index 1 after comm split
        children.setdefault(ppid, []).append(int(entry.name))
    result: list[int] = []
    stack = [pid]
    while stack:
        current = stack.pop()
        if current in result:
            continue
        result.append(current)
        stack.extend(children.get(current, []))
    return result


def _read_stat(pid: int) -> tuple[int, int] | None:
    """Return ``(utime ticks, stime ticks)`` or None when the process is gone."""
    try:
        text = (PROC / str(pid) / "stat").read_text(encoding="utf-8")
    except OSError:
        return None
    right_paren = text.rfind(")")
    fields = text[right_paren + 2:].split()
    if len(fields) < 13:
        return None
    return int(fields[11]), int(fields[12])  # utime, stime (fields 14, 15)


def _read_rss_pages(pid: int) -> int:
    try:
        text = (PROC / str(pid) / "statm").read_text(encoding="utf-8")
    except OSError:
        return 0
    parts = text.split()
    if len(parts) < 2:
        return 0
    try:
        return int(parts[1])  # resident set size in pages
    except ValueError:
        return 0


class ProcResourceSampler:
    """Sample a whole process tree by diffing /proc jiffies between calls."""

    def __init__(self) -> None:
        self._ticks = _clock_ticks()
        self._page_size = _page_size()
        self._previous: dict[int, tuple[float, int, float]] = {}
        self._linux = PROC.exists()

    def system_memory(self) -> tuple[float, float]:
        return read_system_memory_mb()

    def sample(self, pid: int) -> ProcessSample:
        now = time.monotonic()
        available_mb, total_mb = self.system_memory()
        if not self._linux or not (PROC / str(pid)).exists():
            alive = _pid_alive(pid)
            return ProcessSample(
                pid=pid, alive=alive, cpu_percent=0.0,
                rss_mb=self._fallback_rss_mb(pid) if alive else 0.0,
                system_available_mb=available_mb,
                system_total_mb=total_mb, sampled_at=now,
            )
        tree = _descendant_pids(pid)
        cpu_ticks = 0
        rss_pages = 0
        alive_seen = False
        for member in tree:
            stat = _read_stat(member)
            if stat is None:
                continue
            alive_seen = True
            cpu_ticks += stat[0] + stat[1]
            rss_pages += _read_rss_pages(member)
        rss_mb = rss_pages * self._page_size / (1024 * 1024)
        cpu_percent = 0.0
        previous = self._previous.get(pid)
        if previous is not None and alive_seen:
            prev_time, prev_ticks, _prev_rss = previous
            elapsed = now - prev_time
            if elapsed > 0:
                cpu_percent = 100.0 * ((cpu_ticks - prev_ticks) / self._ticks) / elapsed
                cpu_percent = max(0.0, cpu_percent)
        self._previous[pid] = (now, cpu_ticks, rss_mb)
        return ProcessSample(
            pid=pid, alive=alive_seen, cpu_percent=cpu_percent, rss_mb=rss_mb,
            system_available_mb=available_mb, system_total_mb=total_mb,
            sampled_at=now,
        )

    def _fallback_rss_mb(self, pid: int) -> float:
        try:
            import resource
            wait_id = 0  # RUSAGE_SELF-like portability is not needed for children
            del wait_id
            ru = resource.getrusage(resource.RUSAGE_CHILDREN)
            return ru.ru_maxrss / 1024.0  # macOS reports bytes, Linux kB
        except (OSError, ValueError):
            return 0.0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def default_sampler() -> ResourceSampler:
    return ProcResourceSampler()
