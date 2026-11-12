"""Concurrent, incremental, fault-tolerant linkage scan orchestration.

The scanner never modifies source datasets. It bounds concurrency with a
worker pool plus a file-handle budget so scanning many small files cannot
exhaust the process file descriptor limit, skips and records unreadable files
instead of aborting, and reuses cached column profiles for datasets whose
content fingerprint is unchanged (incremental, no full rescan).
"""

from __future__ import annotations

import csv
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..config import Paths
from ..dataset_io import DatasetError, discover_datasets
from ..registry import Catalog, DatasetInventory, inspect_dataset
from ..utils import MasklineError
from .graph import LinkGraph, build_graph
from .ignore import EMPTY_RULES, IgnoreRules
from .matching import match_equality, match_semantic
from .model import RiskFinding, ScanWarning
from .profile import ProfiledColumn, profile_inventory
from .report import write_linkage_reports
from .risk import evaluate_risks
from .store import LinkStore
from .suggest import write_suggested_policy

try:
    import resource
except ImportError:  # pragma: no cover - non-POSIX platforms
    resource = None  # type: ignore[assignment]

# File-level problems that skip one dataset without aborting the whole scan.
SKIP_EXCEPTIONS = (DatasetError, OSError, UnicodeError, csv.Error, sqlite3.Error)
AUDIT_SKIP_DETAIL_CAP = 20


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FileBudget:
    """Semaphore bounding how many dataset files may be open at once."""

    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self._semaphore = threading.BoundedSemaphore(self.limit)

    def __enter__(self) -> "FileBudget":
        self._semaphore.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._semaphore.release()


def default_file_budget() -> int:
    """Conservative default derived from the process file descriptor limit."""
    if resource is None:
        return 8
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):
        return 8
    infinity = getattr(resource, "RLIM_INFINITY", -1)
    if soft <= 0 or soft == infinity:
        return 32
    return max(4, min(32, soft // 8))


@dataclass(frozen=True)
class LinkScanOptions:
    sample_limit: int = 500
    workers: int = 4
    max_open_files: int | None = None
    min_containment: float = 0.6
    min_overlap: int = 3
    full_rescan: bool = False
    export_policy: bool = False

    def budget(self) -> int:
        return self.max_open_files or default_file_budget()

    def to_record(self) -> dict[str, Any]:
        return {
            "sample_limit": self.sample_limit,
            "workers": self.workers,
            "max_open_files": self.budget(),
            "min_containment": self.min_containment,
            "min_overlap": self.min_overlap,
            "full_rescan": self.full_rescan,
            "export_policy": self.export_policy,
        }


@dataclass
class LinkScanOutcome:
    scan_id: str
    version_no: int
    stats: dict[str, Any]
    warnings: list[ScanWarning]
    graph: LinkGraph
    risks: list[RiskFinding]
    reports: dict[str, Path]


@dataclass(frozen=True)
class _FilePlan:
    path: Path
    action: str  # "profile" | "reuse" | "reactivate" | "missing"
    reason: str = ""


def _profile_task(
    path: Path, sample_limit: int, budget: FileBudget, ignore_rules: IgnoreRules
) -> tuple[DatasetInventory, list[ProfiledColumn], int, int]:
    """Inspect and profile one dataset while holding a file-handle permit."""
    with budget:
        inventory = inspect_dataset(path)
        profiled = profile_inventory(inventory, sample_limit, ignore_rules)
        stat = path.stat()
    return inventory, profiled, stat.st_size, stat.st_mtime_ns


def _plan_scans(
    discovered: list[Path],
    states: dict[str, dict[str, Any]],
    full_rescan: bool,
) -> tuple[list[_FilePlan], list[str]]:
    plans: list[_FilePlan] = []
    seen: set[str] = set()
    for path in discovered:
        key = str(path)
        seen.add(key)
        state = states.get(key)
        try:
            stat = path.stat()
        except OSError as exc:
            plans.append(_FilePlan(path, "missing", str(exc)))
            continue
        if state is None or full_rescan or state["status"] == "error":
            plans.append(_FilePlan(path, "profile", "new-or-changed"))
        elif state["status"] in {"removed", "ignored"}:
            if state["size_bytes"] == stat.st_size and state["mtime_ns"] == stat.st_mtime_ns:
                plans.append(_FilePlan(path, "reactivate"))
            else:
                plans.append(_FilePlan(path, "profile", "modified"))
        elif state["size_bytes"] != stat.st_size or state["mtime_ns"] != stat.st_mtime_ns:
            plans.append(_FilePlan(path, "profile", "modified"))
        else:
            plans.append(_FilePlan(path, "reuse"))
    removed = [
        key
        for key, state in states.items()
        if state["status"] == "active" and key not in seen
    ]
    return plans, removed


def _finding_record(inventory: DatasetInventory, item: ProfiledColumn) -> dict[str, Any]:
    profile = item.profile
    return {
        "dataset_fingerprint": inventory.fingerprint,
        "table_name": profile.ref.table,
        "column_name": profile.ref.column,
        "sensitive_type": profile.sensitive_type,
        "confidence": profile.confidence,
        "score": profile.score,
        "hit_rate": profile.hit_rate,
        "validate_rate": profile.validate_rate,
        "sample_size": profile.sample_size,
        "candidates": [],
    }


def _profile_files(
    paths: Paths,
    store: LinkStore,
    plans: list[_FilePlan],
    states: dict[str, dict[str, Any]],
    options: LinkScanOptions,
    ignore_rules: IgnoreRules,
    scan_id: str,
    warnings: list[ScanWarning],
    stats: dict[str, Any],
) -> None:
    budget = FileBudget(options.budget())
    workers = max(1, min(options.workers, options.budget(), len(plans)))
    catalog = Catalog(paths.meta_db)
    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="linkscan") as pool:
            futures = {
                pool.submit(
                    _profile_task, plan.path, options.sample_limit, budget, ignore_rules
                ): plan
                for plan in plans
            }
            for future in as_completed(futures):
                plan = futures[future]
                key = str(plan.path)
                try:
                    inventory, profiled, size_bytes, mtime_ns = future.result()
                except SKIP_EXCEPTIONS as exc:
                    warnings.append(ScanWarning(key, "profile", str(exc)))
                    store.set_status(key, "error")
                    continue
                state = states.get(key)
                if (
                    state is not None
                    and state["fingerprint"] == inventory.fingerprint
                    and not options.full_rescan
                ):
                    store.upsert_state(
                        key,
                        inventory.fingerprint,
                        inventory.kind,
                        size_bytes,
                        mtime_ns,
                        "active",
                        scan_id,
                    )
                    stats["files_reused"] += 1
                    continue
                store.replace_profiles(inventory.fingerprint, profiled)
                store.upsert_state(
                    key,
                    inventory.fingerprint,
                    inventory.kind,
                    size_bytes,
                    mtime_ns,
                    "active",
                    scan_id,
                )
                catalog.register(inventory)
                catalog.save_findings(
                    _finding_record(inventory, item) for item in profiled
                )
                stats["files_profiled"] += 1
    finally:
        catalog.close()


def _execute_scan(
    paths: Paths,
    store: LinkStore,
    audit: AuditLog,
    scan_id: str,
    started_at: str,
    target: str | Path,
    options: LinkScanOptions,
    ignore_rules: IgnoreRules,
) -> LinkScanOutcome:
    discovered_all = discover_datasets(target)
    discovered: list[Path] = []
    ignored_paths: list[Path] = []
    for path in discovered_all:
        if ignore_rules.dataset_ignored(path):
            ignored_paths.append(path)
        else:
            discovered.append(path)
    states = store.dataset_states()
    if not discovered and not any(
        state["status"] == "active" for state in states.values()
    ):
        raise MasklineError("no supported dataset files found")
    for path in ignored_paths:
        state = states.get(str(path))
        if state is not None and state["status"] == "active":
            store.set_status(str(path), "ignored")
    plans, removed = _plan_scans(discovered, states, options.full_rescan)
    for key in removed:
        store.set_status(key, "removed")
    stats: dict[str, Any] = {
        "files_seen": len(discovered),
        "files_profiled": 0,
        "files_reused": 0,
        "files_skipped": 0,
        "files_removed": len(removed),
        "files_ignored": len(ignored_paths),
    }
    warnings: list[ScanWarning] = []
    to_profile: list[_FilePlan] = []
    for plan in plans:
        if plan.action == "profile":
            to_profile.append(plan)
        elif plan.action == "reuse":
            stats["files_reused"] += 1
        elif plan.action == "reactivate":
            store.set_status(str(plan.path), "active")
            stats["files_reused"] += 1
        else:
            warnings.append(ScanWarning(str(plan.path), "stat", plan.reason))
            state = states.get(str(plan.path))
            if state is not None and state["status"] == "active":
                # Vanished mid-scan: drop its stale profiles from the graph.
                store.set_status(str(plan.path), "removed")
                stats["files_removed"] += 1
    if to_profile:
        _profile_files(
            paths, store, to_profile, states, options, ignore_rules, scan_id, warnings, stats
        )
    stats["files_skipped"] = len(warnings)

    profiles, values = store.load_profiles()
    equals = match_equality(
        profiles,
        values,
        min_containment=options.min_containment,
        min_overlap=options.min_overlap,
        pair_ignored=ignore_rules.pair_ignored,
    )
    semantics = match_semantic(profiles, equals, type_ignored=ignore_rules.type_ignored)
    graph = build_graph(profiles, equals, semantics)
    version_no = store.next_version()
    risks = evaluate_risks(graph, version_no, type_ignored=ignore_rules.sensitive_types)
    finished_at = _now()
    store.record_edges(version_no, (*equals, *semantics))
    store.record_risks(version_no, risks)
    store.record_warnings(scan_id, warnings)
    store.record_scan(
        scan_id,
        version_no,
        str(target),
        options.to_record(),
        ignore_rules.fingerprint,
        "completed",
        stats,
        started_at,
        finished_at,
    )
    for warning in warnings[:AUDIT_SKIP_DETAIL_CAP]:
        audit.append(
            {
                "event": "linkscan_file_skipped",
                "scan_id": scan_id,
                "path": warning.path,
                "stage": warning.stage,
                "message": warning.message,
            }
        )
    if len(warnings) > AUDIT_SKIP_DETAIL_CAP:
        audit.append(
            {
                "event": "linkscan_file_skipped_summary",
                "scan_id": scan_id,
                "additional_skips": len(warnings) - AUDIT_SKIP_DETAIL_CAP,
            }
        )
    level_counts: dict[str, int] = {}
    for risk in risks:
        level_counts[risk.level] = level_counts.get(risk.level, 0) + 1
    audit.append(
        {
            "event": "linkscan_completed",
            "scan_id": scan_id,
            "version_no": version_no,
            "stats": stats,
            "equals_edges": len(equals),
            "semantic_edges": len(semantics),
            "clusters": len(graph.clusters),
            "risks": len(risks),
            "risk_levels": level_counts,
        }
    )
    reports = write_linkage_reports(
        paths, version_no, scan_id, str(target), profiles, graph, risks, warnings, stats
    )
    if options.export_policy and risks:
        policy_path = write_suggested_policy(paths, version_no, risks)
        audit.append(
            {
                "event": "linkscan_policy_exported",
                "scan_id": scan_id,
                "path": str(policy_path),
                "risks": len(risks),
            }
        )
        reports["policy"] = policy_path
    return LinkScanOutcome(
        scan_id=scan_id,
        version_no=version_no,
        stats=stats,
        warnings=warnings,
        graph=graph,
        risks=risks,
        reports=reports,
    )


def run_linkscan(
    paths: Paths,
    target: str | Path,
    options: LinkScanOptions | None = None,
    ignore_rules: IgnoreRules = EMPTY_RULES,
) -> LinkScanOutcome:
    """Scan datasets under ``target`` and refresh the versioned linkage graph."""
    options = options or LinkScanOptions()
    paths.ensure_runtime_dirs()
    scan_id = f"link-{uuid.uuid4().hex[:12]}"
    started_at = _now()
    audit = AuditLog(paths.audit_path)
    store = LinkStore(paths.linkgraph_db)
    try:
        audit.append(
            {
                "event": "linkscan_started",
                "scan_id": scan_id,
                "target": str(target),
                "options": options.to_record(),
                "ignore_fingerprint": ignore_rules.fingerprint,
            }
        )
        try:
            return _execute_scan(
                paths, store, audit, scan_id, started_at, target, options, ignore_rules
            )
        except Exception as exc:
            audit.append(
                {"event": "linkscan_failed", "scan_id": scan_id, "error": str(exc)}
            )
            raise
    finally:
        store.close()
