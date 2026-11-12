"""Dirty-resource identification and cleanup after abnormal exits.

An abnormal exit (SIGKILL, disk full, permission errors, ...) can leave
behind half-written target databases, orphaned pseudonym mapping entries and
stale run/checkpoint records. This module reclaims those resources while
guaranteeing:

* legitimate breakpoints (status ``interrupted``) and completed runs are
  never touched — only ``failed`` runs and stale ``running`` runs whose
  cross-process lock is no longer held are considered dirty;
* resources of runs that are active right now (lock held by a live process)
  are never touched, even under disk pressure;
* source datasets and finished masking products are never touched;
* cleaning is idempotent and serialized across processes, and the most
  recent failure's scene metadata is preserved for troubleshooting.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..config import Paths
from ..pseudomap import PseudoMap
from ..utils import atomic_write_text, read_json
from .checkpoint import CheckpointStore, RunRecord
from .locks import RunLock

STATUS_COMPLETED = "completed"
STATUS_INTERRUPTED = "interrupted"
STATUS_FAILED = "failed"
STATUS_RUNNING = "running"

REASON_STALE_RUNNING = "stale-running"
REASON_FAILED = "failed-run"
REASON_ABANDONED = "abandoned-run"

_CLEANUP_LOCK_NAME = "_cleanup"
_SQLITE_SIDECARS = ("", "-wal", "-shm", "-journal")


@dataclass
class CleanedResource:
    run_id: str
    reason: str
    freed_bytes: int
    mapping_entries_removed: int
    scene_path: str | None
    actions: list[str] = field(default_factory=list)


@dataclass
class CleanReport:
    dry_run: bool
    cleaned: list[CleanedResource] = field(default_factory=list)
    active_run_ids: list[str] = field(default_factory=list)
    interrupted_run_ids: list[str] = field(default_factory=list)
    completed_run_ids: list[str] = field(default_factory=list)
    orphan_files_removed: list[str] = field(default_factory=list)
    orphan_bytes_freed: int = 0

    @property
    def total_freed_bytes(self) -> int:
        return self.orphan_bytes_freed + sum(item.freed_bytes for item in self.cleaned)

    @property
    def cleaned_run_ids(self) -> list[str]:
        return [item.run_id for item in self.cleaned]


def clean_workspace(
    paths: Paths,
    *,
    min_age_seconds: float = 0.0,
    min_free_bytes: int | None = None,
    dry_run: bool = False,
) -> CleanReport:
    """Reclaim dirty resources in ``paths``.

    With ``min_free_bytes=None`` every dirty run is cleaned. Otherwise dirty
    runs (and then orphan files) are cleaned oldest-first only until the free
    space on the output volume reaches ``min_free_bytes``. ``dry_run``
    reports what would happen without writing or deleting anything.
    """
    report = CleanReport(dry_run=dry_run)
    gate = RunLock(paths.lock_dir, _CLEANUP_LOCK_NAME)
    gate.acquire(blocking=True)
    try:
        _clean_locked(paths, report, min_age_seconds, min_free_bytes)
    finally:
        gate.release()
    return report


def _clean_locked(
    paths: Paths,
    report: CleanReport,
    min_age_seconds: float,
    min_free_bytes: int | None,
) -> None:
    now = datetime.now(timezone.utc)
    protected = _manifest_outputs(paths)
    store: CheckpointStore | None = None
    if paths.checkpoint_db.exists():
        store = CheckpointStore(paths.checkpoint_db)
    try:
        records = store.list_runs(limit=None) if store is not None else []
        referenced_outputs = {record.output_path for record in records}
        candidates: list[tuple[RunRecord, str, RunLock]] = []
        for record in records:
            if record.status == STATUS_COMPLETED:
                report.completed_run_ids.append(record.run_id)
                continue
            if record.status == STATUS_INTERRUPTED:
                report.interrupted_run_ids.append(record.run_id)
                continue
            if _record_age_seconds(record, now) < min_age_seconds:
                # Grace period: too fresh to prove abandonment.
                report.active_run_ids.append(record.run_id)
                continue
            lock = RunLock(paths.lock_dir, record.run_id)
            if not lock.acquire():
                # A live process holds this run: it is active, not residue.
                report.active_run_ids.append(record.run_id)
                continue
            candidates.append((record, _reason_for(record), lock))
        # Oldest residue first so disk-pressure cleaning frees the stalest junk.
        candidates.sort(key=lambda item: (item[0].updated_at, item[0].run_id))
        try:
            for record, reason, lock in candidates:
                if _space_satisfied(paths, min_free_bytes, report):
                    break
                try:
                    _clean_run(paths, store, record, reason, protected, report)
                finally:
                    lock.release()
        finally:
            for _record, _reason, lock in candidates:
                lock.release()
        _sweep_orphans(
            paths, store, referenced_outputs, protected,
            {record.run_id for record in records}, report,
            min_age_seconds, min_free_bytes, now,
        )
    finally:
        if store is not None:
            store.close()


def _clean_run(
    paths: Paths,
    store: CheckpointStore | None,
    record: RunRecord,
    reason: str,
    protected_outputs: set[str],
    report: CleanReport,
) -> None:
    """Clean one dirty run. The caller holds the run's lock."""
    if store is not None:
        current = store.get_run(record.run_id)
        if current is None or current.status in (STATUS_COMPLETED, STATUS_INTERRUPTED):
            return  # revalidated: someone finished or legitimately suspended it
        record = current
    actions: list[str] = []
    prefix = "would-" if report.dry_run else ""
    scene_path = paths.cleanup_dir / f"{record.run_id}.json"
    checkpoints = store.list_checkpoints(record.run_id) if store is not None else []
    output = Path(record.output_path)
    output_size = _path_size(output)
    refs = 0
    if paths.pseudomap_db.exists():
        with PseudoMap(paths.pseudomap_db) as mapping:
            refs = mapping.count_refs(record.run_id)
    scene = {
        "run_id": record.run_id,
        "reason": reason,
        "cleaned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dry_run": report.dry_run,
        "run": dataclasses.asdict(record),
        "checkpoints": [dataclasses.asdict(cp) for cp in checkpoints],
        "output": {
            "path": str(output),
            "existed": output.exists(),
            "size_bytes": output_size,
        },
        "pseudomap_refs": refs,
    }
    freed = 0
    removed_entries = 0
    actions.append(f"{prefix}write-scene:{scene_path}")
    if not report.dry_run:
        # Preserve the failure scene *before* deleting anything.
        atomic_write_text(scene_path, json.dumps(scene, ensure_ascii=False, indent=2) + "\n")
    if refs and paths.pseudomap_db.exists():
        actions.append(f"{prefix}remove-mapping-entries run={record.run_id} refs={refs}")
        if report.dry_run:
            with PseudoMap(paths.pseudomap_db) as mapping:
                removed_entries = mapping.count_removable_entries(record.run_id)
        else:
            with PseudoMap(paths.pseudomap_db) as mapping:
                removed_entries = mapping.remove_run_entries(record.run_id)
    actions.append(f"{prefix}delete-run-record:{record.run_id}")
    if not report.dry_run and store is not None:
        store.delete_run(record.run_id)
    freed += _delete_output(
        paths, store, record, output, protected_outputs, actions, report
    )
    actions.append(f"{prefix}remove-lock-file:{record.run_id}")
    if not report.dry_run:
        RunLock(paths.lock_dir, record.run_id).unlink()
    report.cleaned.append(
        CleanedResource(
            run_id=record.run_id,
            reason=reason,
            freed_bytes=freed,
            mapping_entries_removed=removed_entries,
            scene_path=str(scene_path),
            actions=actions,
        )
    )


def _delete_output(
    paths: Paths,
    store: CheckpointStore | None,
    record: RunRecord,
    output: Path,
    protected_outputs: set[str],
    actions: list[str],
    report: CleanReport,
) -> int:
    """Delete a dirty run's half-written target; never a source or a product."""
    prefix = "would-" if report.dry_run else ""
    try:
        resolved = str(output.resolve())
    except OSError:
        resolved = str(output)
    if resolved == str(Path(record.dataset_path).resolve()):
        actions.append("keep-output:equals-source-dataset")
        return 0
    if store is not None and store.dataset_references(resolved):
        actions.append("keep-output:referenced-as-source-dataset")
        return 0
    if store is not None:
        refs = [
            run_id for run_id in store.output_references(resolved)
            if run_id != record.run_id
        ]
        if refs:
            actions.append("keep-output:referenced-by-another-run")
            return 0
    if resolved in protected_outputs:
        actions.append("keep-output:referenced-by-manifest")
        return 0
    freed = 0
    for suffix in _SQLITE_SIDECARS:
        candidate = Path(str(output) + suffix)
        try:
            size = candidate.stat().st_size
        except OSError:
            continue  # already gone: idempotent
        actions.append(f"{prefix}delete-file:{candidate}")
        if not report.dry_run:
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
        freed += size
    return freed


def _sweep_orphans(
    paths: Paths,
    store: CheckpointStore | None,
    referenced_outputs: set[str],
    protected_outputs: set[str],
    known_run_ids: set[str],
    report: CleanReport,
    min_age_seconds: float,
    min_free_bytes: int | None,
    now: datetime,
) -> None:
    """Remove unreferenced ``*.masked.sqlite`` files and stale lock files."""
    out_dir = paths.out_dir
    if out_dir.is_dir():
        orphans = []
        for candidate in sorted(out_dir.glob("*.masked.sqlite")):
            key = str(candidate.resolve())
            if key in referenced_outputs or key in protected_outputs:
                continue
            if store is not None and store.dataset_references(key):
                continue
            try:
                age = now.timestamp() - candidate.stat().st_mtime
            except OSError:
                continue
            if age < min_age_seconds:
                continue
            orphans.append(candidate)
        # Oldest first under disk pressure.
        orphans.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0.0)
        for orphan in orphans:
            if _space_satisfied(paths, min_free_bytes, report):
                break
            for suffix in _SQLITE_SIDECARS:
                sidecar = Path(str(orphan) + suffix)
                try:
                    size = sidecar.stat().st_size
                except OSError:
                    continue
                if not report.dry_run:
                    try:
                        sidecar.unlink()
                    except FileNotFoundError:
                        continue
                report.orphan_bytes_freed += size
                if suffix == "":
                    report.orphan_files_removed.append(str(orphan))
    lock_dir = paths.lock_dir
    if lock_dir.is_dir():
        for lock_file in sorted(lock_dir.glob("*.lock")):
            name = lock_file.stem
            if name == _CLEANUP_LOCK_NAME or name in known_run_ids:
                continue
            lock = RunLock(lock_dir, name)
            if not lock.acquire():
                continue  # held by a live process
            try:
                if not report.dry_run:
                    lock.unlink()
                report.orphan_files_removed.append(str(lock_file))
            finally:
                lock.release()


def _space_satisfied(
    paths: Paths, min_free_bytes: int | None, report: CleanReport
) -> bool:
    if min_free_bytes is None:
        return False
    if report.dry_run:
        estimated = _free_bytes(paths) + report.total_freed_bytes
        return estimated >= min_free_bytes
    return _free_bytes(paths) >= min_free_bytes


def _free_bytes(paths: Paths) -> int:
    anchor = paths.out_dir if paths.out_dir.exists() else paths.root
    return shutil.disk_usage(anchor).free


def _reason_for(record: RunRecord) -> str:
    if record.status == STATUS_RUNNING:
        return REASON_STALE_RUNNING
    if record.status == STATUS_FAILED:
        return REASON_FAILED
    return f"{REASON_ABANDONED}:{record.status}"


def _record_age_seconds(record: RunRecord, now: datetime) -> float:
    try:
        updated = datetime.fromisoformat(record.updated_at)
    except ValueError:
        return float("inf")
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    return (now - updated).total_seconds()


def _path_size(path: Path) -> int:
    total = 0
    for suffix in _SQLITE_SIDECARS:
        try:
            total += Path(str(path) + suffix).stat().st_size
        except OSError:
            pass
    return total


def _manifest_outputs(paths: Paths) -> set[str]:
    """Outputs recorded in completion manifests: finished products, keep out."""
    protected: set[str] = set()
    manifest_dir = paths.manifest_dir
    if not manifest_dir.is_dir():
        return protected
    for manifest in manifest_dir.glob("*.json"):
        data = read_json(manifest, default=None)
        if not isinstance(data, dict):
            continue
        output = data.get("output")
        if isinstance(output, str) and output:
            protected.add(str(Path(output).resolve()))
    return protected
