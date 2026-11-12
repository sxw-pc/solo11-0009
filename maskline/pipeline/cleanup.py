"""Recovery of resources left behind by abnormal pipeline exits.

Design rules, in order of precedence:

1. A live ``flock`` owner (verified through :mod:`maskline.pipeline.locks`) is
   never touched, regardless of its database status.
2. ``completed`` outputs and every output recorded in a manifest are official
   artifacts and are never deleted; source datasets are never deleted either.
3. ``interrupted`` runs are legitimate, resumable suspensions. Their target,
   checkpoints and mapping usage are kept intact.
4. Only ``failed`` runs and ``running`` runs whose lock owner is dead are
   reclaimed. The run row survives as an audit trail and the most recent
   failure scene is written to ``data/cleanup/last-failure.json``.
5. Every operation tolerates missing files and repeated execution.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Paths
from ..dataset_io import SQLITE_EXTENSIONS
from ..pseudomap import PseudoMap
from ..utils import MasklineError, atomic_write_text, read_json, sqlite_connect_readonly
from .checkpoint import CheckpointStore, RunRecord, TableCheckpoint, load_run_snapshot
from .locks import CleanupLock, is_lock_live, lock_path, read_lock_owner

SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")
RUNTIME_DB_NAMES = {"meta.sqlite", "checkpoints.sqlite", "pseudomap.sqlite", "demo-secret.txt"}


class CleanupError(MasklineError):
    pass


@dataclass
class CleanupOptions:
    dry_run: bool = False
    # Reclaim oldest dirty resources first and stop once this much free space is
    # available. 0 disables low-disk prioritisation (all dirt is reclaimed).
    min_free_bytes: int = 0
    # Locks younger than this are presumed to belong to a process that is still
    # starting up. Tests may set this to 0.
    lock_grace_seconds: float = 1.0
    # Atomic-write temp files younger than this may belong to a live writer.
    temp_grace_seconds: float = 60.0
    # Run ids that must be preserved even if their status looks abnormal.
    protect_run_ids: set[str] = field(default_factory=set)
    preserve_pseudomap_sidecars_while_runs_live: bool = True
    include_orphans: bool = True
    cleanup_lock_timeout: float = 10.0


@dataclass
class CleanupReport:
    ran: bool = False
    locked: bool = False
    dry_run: bool = False
    low_disk: bool = False
    frozen_for_disk_space: bool = False
    free_bytes_before: int = 0
    free_bytes_after: int = 0
    reclaimed_bytes: int = 0
    removed_targets: list[str] = field(default_factory=list)
    removed_sidecars: list[str] = field(default_factory=list)
    removed_temp_files: list[str] = field(default_factory=list)
    removed_stale_locks: list[str] = field(default_factory=list)
    removed_orphan_outputs: list[str] = field(default_factory=list)
    removed_orphan_checkpoint_runs: list[str] = field(default_factory=list)
    removed_checkpoints: dict[str, int] = field(default_factory=dict)
    cleaned_run_ids: list[str] = field(default_factory=list)
    preserved_run_ids: dict[str, str] = field(default_factory=dict)
    skipped_active_run_ids: list[str] = field(default_factory=list)
    removed_mapping_usage: int = 0
    removed_mapping_tokens: int = 0
    errors: list[dict[str, str]] = field(default_factory=list)
    failure_scene_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            key: (sorted(value) if isinstance(value, list) else value)
            for key, value in self.__dict__.items()
        }

    @property
    def removed_count(self) -> int:
        return (
            len(self.removed_targets)
            + len(self.removed_sidecars)
            + len(self.removed_temp_files)
            + len(self.removed_stale_locks)
            + len(self.removed_orphan_outputs)
            + len(self.removed_orphan_checkpoint_runs)
            + len(self.cleaned_run_ids)
        )


@dataclass
class _DirtyRun:
    record: RunRecord
    reason: str
    checkpoints: list[TableCheckpoint]
    mapping_usage: int
    target_exists: bool
    target_size: int
    sidecars: list[Path]
    target_integrity: str


def cleanup_dirty_resources(
    paths: Paths, options: CleanupOptions | None = None
) -> CleanupReport:
    """Identify and reclaim abnormal-exit remnants. Safe to call repeatedly."""
    options = options or CleanupOptions()
    report = CleanupReport(dry_run=options.dry_run)
    try:
        usage = shutil.disk_usage(paths.root)
        report.free_bytes_before = int(usage.free)
    except OSError:
        report.free_bytes_before = 0

    if options.dry_run:
        _run_cleanup(paths, options, report)
        return report

    paths.ensure_runtime_dirs()
    lock = CleanupLock.acquire_for(paths.locks_dir, timeout=options.cleanup_lock_timeout)
    if lock is None:
        report.locked = True
        report.free_bytes_after = report.free_bytes_before
        return report
    try:
        report.ran = True
        _run_cleanup(paths, options, report)
    finally:
        lock.release()
    try:
        report.free_bytes_after = int(shutil.disk_usage(paths.root).free)
    except OSError:
        report.free_bytes_after = report.free_bytes_before
    return report


def _run_cleanup(paths: Paths, options: CleanupOptions, report: CleanupReport) -> None:
    runs, checkpoints = load_run_snapshot(paths.checkpoint_db)
    checkpoint_by_run: dict[str, list[TableCheckpoint]] = {}
    for checkpoint in checkpoints:
        checkpoint_by_run.setdefault(checkpoint.run_id, []).append(checkpoint)

    protected_paths, protected_reasons = _protected_paths(paths, runs)
    live_run_ids = {
        run.run_id for run in runs if is_lock_live(lock_path(paths.locks_dir, f"run-{run.run_id}"))
    }

    dirty_runs: list[_DirtyRun] = []
    for run in runs:
        if run.run_id in options.protect_run_ids:
            report.preserved_run_ids[run.run_id] = "explicitly protected"
            continue
        if run.status == "completed":
            report.preserved_run_ids[run.run_id] = "completed artifact"
            continue
        if run.status == "interrupted":
            report.preserved_run_ids[run.run_id] = "interrupted run (resumable)"
            continue
        if run.status in {"cleaned", "abandoned"}:
            continue
        live = run.run_id in live_run_ids
        if live:
            report.skipped_active_run_ids.append(run.run_id)
            report.preserved_run_ids[run.run_id] = "active owner"
            continue
        if run.status == "failed":
            reason = "failed run"
        elif run.status == "running":
            reason = "crashed run (dead lock owner)"
        else:
            report.preserved_run_ids[run.run_id] = f"unknown status: {run.status}"
            continue
        dirty_runs.append(
            _inspect_dirty_run(
                paths,
                run,
                reason,
                checkpoint_by_run.get(run.run_id, []),
                protected_paths,
            )
        )
        report.preserved_run_ids.pop(run.run_id, None)

    report.low_disk = bool(options.min_free_bytes) and (
        report.free_bytes_before < options.min_free_bytes
    )

    # Oldest first: under disk pressure the oldest dirt is reclaimed first and
    # we stop as soon as enough space is available, leaving newer/active work
    # untouched.
    dirty_runs.sort(key=lambda item: (item.record.started_at, item.record.run_id))

    dirty_run_ids: set[str] = set()
    mapping_reclaim_ids: set[str] = set()
    # Preserve the newest abnormal scene even when low-disk mode only reaches
    # older resources during this pass.
    if dirty_runs:
        newest = max(dirty_runs, key=lambda item: (item.record.updated_at, item.record.run_id))
        _write_failure_scene(paths, newest, options, report)
    for item in dirty_runs:
        if report.low_disk and _free_bytes(paths.root) >= options.min_free_bytes:
            report.frozen_for_disk_space = True
            break
        if not _reclaim_run(paths, item, options, protected_paths, report):
            report.preserved_run_ids[item.record.run_id] = "protected artifact collision"
            continue
        dirty_run_ids.add(item.record.run_id)
        mapping_reclaim_ids.add(item.record.run_id)

    # Checkpoints belonging to runs that no longer exist cannot be resumed.
    known_run_ids = {run.run_id for run in runs}
    orphan_checkpoint_ids = set(checkpoint_by_run) - known_run_ids
    orphan_checkpoint_ids -= options.protect_run_ids
    if orphan_checkpoint_ids:
        if options.dry_run:
            report.removed_orphan_checkpoint_runs = sorted(orphan_checkpoint_ids)
        else:
            with CheckpointStore(paths.checkpoint_db) as store:
                # row counts for the report; deletion itself is idempotent
                for run_id in sorted(orphan_checkpoint_ids):
                    count = len(checkpoint_by_run.get(run_id, []))
                    report.removed_checkpoints[run_id] = count
                store.delete_checkpoint_run_ids(orphan_checkpoint_ids)
            report.removed_orphan_checkpoint_runs = sorted(orphan_checkpoint_ids)

    if options.include_orphans:
        _reclaim_orphan_outputs(paths, runs, protected_paths, options, report)

    _reclaim_temp_files(paths, options, report)
    _reclaim_stale_locks(paths, options, report, {run.run_id for run in runs})

    if mapping_reclaim_ids:
        _reclaim_mapping(paths, mapping_reclaim_ids, options, report)

    _reclaim_runtime_sidecars(paths, runs, options, report)

    if not options.dry_run and dirty_run_ids:
        for run_id in sorted(dirty_run_ids):
            report.cleaned_run_ids.append(run_id)


def _protected_paths(
    paths: Paths, runs: list[RunRecord]
) -> tuple[set[Path], dict[str, str]]:
    protected: set[Path] = set()
    reasons: dict[str, str] = {}
    for run in runs:
        protected.update(_resolved_variants(Path(run.dataset_path)))
        reasons[str(Path(run.dataset_path))] = "source dataset"
    for run in runs:
        if run.status == "completed":
            for path in _resolved_variants(Path(run.output_path)):
                protected.add(path)
                reasons[str(path)] = "completed output"
    if paths.manifest_dir.is_dir():
        for manifest in sorted(paths.manifest_dir.glob("*.json")):
            data = read_json(manifest, default=None)
            if isinstance(data, dict) and data.get("output"):
                for path in _resolved_variants(Path(str(data["output"]))):
                    protected.add(path)
                    reasons[str(path)] = "manifest output"
    for name in RUNTIME_DB_NAMES:
        for path in _resolved_variants(paths.data_dir / name):
            protected.add(path)
            reasons[str(path)] = "runtime database"
    for attr in ("audit_path", "meta_db", "checkpoint_db", "pseudomap_db"):
        for path in _resolved_variants(getattr(paths, attr)):
            protected.add(path)
            reasons[str(path)] = "runtime artifact"
    return protected, reasons


def _resolved_variants(path: Path) -> set[Path]:
    result = {path}
    try:
        result.add(path.expanduser().resolve())
    except OSError:
        result.add(path.expanduser().absolute())
    return result


def _is_protected(path: Path, protected: set[Path]) -> bool:
    return bool(_resolved_variants(path) & protected)


def _sidecars(path: Path) -> list[Path]:
    return [Path(str(path) + suffix) for suffix in SIDECAR_SUFFIXES if Path(str(path) + suffix).exists()]


def _sqlite_integrity(path: Path) -> str:
    if not path.is_file():
        return "absent"
    if path.stat().st_size == 0:
        return "empty"
    try:
        conn = sqlite_connect_readonly(path)
    except Exception as exc:  # sqlite3.Error / OSError
        return f"unreadable: {type(exc).__name__}"
    try:
        try:
            result = conn.execute("PRAGMA integrity_check").fetchone()
        except Exception as exc:
            return f"unreadable: {type(exc).__name__}"
        return "ok" if result and str(result[0]).lower() == "ok" else "corrupt"
    finally:
        conn.close()


def _mapping_usage_count(paths: Paths, run_id: str) -> int:
    path = paths.pseudomap_db
    if not path.is_file():
        return 0
    try:
        conn = sqlite_connect_readonly(path)
    except Exception:
        return 0
    try:
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM pseudonym_usage WHERE run_id = ?", (run_id,)
            ).fetchone()
        except Exception:
            return 0
        return int(row[0]) if row else 0
    finally:
        conn.close()


def _inspect_dirty_run(
    paths: Paths,
    run: RunRecord,
    reason: str,
    checkpoints: list[TableCheckpoint],
    protected_paths: set[Path],
) -> _DirtyRun:
    target = Path(run.output_path)
    exists = target.is_file() and not target.is_symlink()
    size = target.stat().st_size if exists else 0
    return _DirtyRun(
        record=run,
        reason=reason,
        checkpoints=checkpoints,
        mapping_usage=_mapping_usage_count(paths, run.run_id),
        target_exists=exists,
        target_size=size,
        sidecars=_sidecars(target),
        target_integrity=_sqlite_integrity(target),
    )


def _free_bytes(path: Path) -> int:
    try:
        return int(shutil.disk_usage(path).free)
    except OSError:
        return 0


def _write_failure_scene(
    paths: Paths, item: _DirtyRun, options: CleanupOptions, report: CleanupReport
) -> None:
    if options.dry_run:
        return
    scene = {
        "captured_at": _now(),
        "workspace": str(paths.root),
        "reason": item.reason,
        "run_id": item.record.run_id,
        "status": item.record.status,
        "dataset_path": item.record.dataset_path,
        "dataset_fingerprint": item.record.dataset_fingerprint,
        "policy_path": item.record.policy_path,
        "policy_fingerprint": item.record.policy_fingerprint,
        "output_path": item.record.output_path,
        "started_at": item.record.started_at,
        "updated_at": item.record.updated_at,
        "finished_at": item.record.finished_at,
        "error_type": item.record.error_type,
        "error_message": item.record.error_message,
        "pid": item.record.pid,
        "host": item.record.host,
        "lock": read_lock_owner(lock_path(paths.locks_dir, f"run-{item.record.run_id}")),
        "resources": {
            "target_exists": item.target_exists,
            "target_bytes": item.target_size,
            "target_integrity": item.target_integrity,
            "sidecars": [str(path) for path in item.sidecars],
            "mapping_usage_entries": item.mapping_usage,
            "checkpoints": [
                {
                    "table_name": checkpoint.table_name,
                    "last_rowid": checkpoint.last_rowid,
                    "rows_done": checkpoint.rows_done,
                    "updated_at": checkpoint.updated_at,
                }
                for checkpoint in item.checkpoints
            ],
        },
    }
    target = paths.cleanup_dir / "last-failure.json"
    try:
        atomic_write_text(target, json.dumps(scene, ensure_ascii=False, indent=2) + "\n")
        report.failure_scene_path = str(target)
    except OSError as exc:
        report.errors.append({"path": str(target), "error": f"{type(exc).__name__}: {exc}"})


def _remove_file(path: Path, options: CleanupOptions, report: CleanupReport) -> int:
    """Delete one regular file; returns freed bytes. Never raises."""
    if not path.exists():
        return 0
    if path.is_symlink() or not path.is_file():
        report.errors.append({"path": str(path), "error": "refusing to delete a non-regular file"})
        return 0
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if options.dry_run:
        return size
    try:
        path.unlink()
        report.reclaimed_bytes += size
        return size
    except FileNotFoundError:
        return 0
    except OSError as exc:
        report.errors.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})
        return 0


def _reclaim_run(
    paths: Paths,
    item: _DirtyRun,
    options: CleanupOptions,
    protected_paths: set[Path],
    report: CleanupReport,
) -> bool:
    run_id = item.record.run_id
    target = Path(item.record.output_path)

    if target.exists() and _is_protected(target, protected_paths):
        report.errors.append(
            {"path": str(target), "error": "target collides with a protected artifact"}
        )
        return False

    if target.is_file() and not target.is_symlink():
        if options.dry_run:
            report.removed_targets.append(str(target))
            report.reclaimed_bytes += item.target_size
        else:
            _remove_file(target, options, report)
            if not target.exists():
                report.removed_targets.append(str(target))
            else:
                report.errors.append(
                    {"path": str(target), "error": "target could not be removed"}
                )
                return False

    for sidecar in item.sidecars:
        if options.dry_run:
            report.removed_sidecars.append(str(sidecar))
        else:
            _remove_file(sidecar, options, report)
            if not sidecar.exists():
                report.removed_sidecars.append(str(sidecar))

    if not options.dry_run:
        try:
            with CheckpointStore(paths.checkpoint_db) as store:
                removed = store.delete_checkpoints(run_id)
                if removed:
                    report.removed_checkpoints[run_id] = removed
                store.set_status(run_id, "cleaned")
        except OSError as exc:
            report.errors.append(
                {"path": str(paths.checkpoint_db), "error": f"{type(exc).__name__}: {exc}"}
            )
            return False
    elif item.checkpoints:
        report.removed_checkpoints[run_id] = len(item.checkpoints)
    return True


def _reclaim_orphan_outputs(
    paths: Paths,
    runs: list[RunRecord],
    protected_paths: set[Path],
    options: CleanupOptions,
    report: CleanupReport,
) -> None:
    referenced = {Path(run.output_path) for run in runs}
    out_dir = paths.out_dir
    if not out_dir.is_dir():
        return
    for candidate in sorted(out_dir.iterdir()):
        if not candidate.is_file() or candidate.suffix.lower() not in SQLITE_EXTENSIONS:
            continue
        if candidate.is_symlink() or candidate.name.startswith("."):
            continue
        if candidate in referenced or _is_protected(candidate, protected_paths):
            continue
        sidecars = _sidecars(candidate)
        integrity = _sqlite_integrity(candidate)
        # Conservative orphan rule: only obviously incomplete databases are
        # reclaimed. A valid, unreferenced database might be an official
        # artifact whose metadata was lost, so it is kept.
        if not (
            candidate.stat().st_size == 0
            or integrity.startswith("unreadable")
            or integrity == "corrupt"
            or sidecars
        ):
            continue
        if options.dry_run:
            report.removed_orphan_outputs.append(str(candidate))
            report.reclaimed_bytes += candidate.stat().st_size
        else:
            _remove_file(candidate, options, report)
            if not candidate.exists():
                report.removed_orphan_outputs.append(str(candidate))
        for sidecar in sidecars:
            if options.dry_run:
                report.removed_sidecars.append(str(sidecar))
            else:
                _remove_file(sidecar, options, report)
                if not sidecar.exists():
                    report.removed_sidecars.append(str(sidecar))


def _reclaim_temp_files(
    paths: Paths, options: CleanupOptions, report: CleanupReport
) -> None:
    if options.temp_grace_seconds < 0:
        return
    now = time.time()
    directories = [paths.manifest_dir, paths.cleanup_dir]
    for directory in directories:
        if not directory.is_dir():
            continue
        for candidate in sorted(directory.iterdir()):
            if candidate.is_symlink() or not candidate.is_file():
                continue
            # atomic_write_text uses mkstemp(prefix=".{name}.", dir=...)
            if not candidate.name.startswith("."):
                continue
            try:
                age = now - candidate.stat().st_mtime
            except OSError:
                continue
            if age < options.temp_grace_seconds:
                continue
            if options.dry_run:
                report.removed_temp_files.append(str(candidate))
            else:
                _remove_file(candidate, options, report)
                if not candidate.exists():
                    report.removed_temp_files.append(str(candidate))


def _reclaim_stale_locks(
    paths: Paths,
    options: CleanupOptions,
    report: CleanupReport,
    known_run_ids: set[str],
) -> None:
    locks_dir = paths.locks_dir
    if not locks_dir.is_dir():
        return
    now = time.time()
    for candidate in sorted(locks_dir.glob("*.lock")):
        if candidate.name == "cleanup.lock":
            continue  # held by this process (or another live cleanup)
        if is_lock_live(candidate):
            continue
        try:
            age = now - candidate.stat().st_mtime
        except OSError:
            age = 0.0
        if age < options.lock_grace_seconds:
            continue
        if options.dry_run:
            report.removed_stale_locks.append(str(candidate))
            continue
        _remove_file(candidate, options, report)
        if not candidate.exists():
            report.removed_stale_locks.append(str(candidate))


def _reclaim_mapping(
    paths: Paths,
    dirty_run_ids: set[str],
    options: CleanupOptions,
    report: CleanupReport,
) -> None:
    if not paths.pseudomap_db.is_file():
        return
    try:
        if options.dry_run:
            conn = sqlite_connect_readonly(paths.pseudomap_db)
            try:
                for run_id in sorted(dirty_run_ids):
                    try:
                        row = conn.execute(
                            "SELECT COUNT(*) FROM pseudonym_usage WHERE run_id = ?",
                            (run_id,),
                        ).fetchone()
                        report.removed_mapping_usage += int(row[0]) if row else 0
                    except Exception:
                        pass
                try:
                    usage_rows = conn.execute(
                        "SELECT token, run_id FROM pseudonym_usage"
                    ).fetchall()
                    owners: dict[str, set[str]] = {}
                    for row in usage_rows:
                        owners.setdefault(row[0], set()).add(row[1])
                    report.removed_mapping_tokens = sum(
                        1 for ids in owners.values()
                        if ids and ids <= dirty_run_ids
                    )
                except Exception:
                    pass
            finally:
                conn.close()
            return
        with PseudoMap(paths.pseudomap_db, create=True) as mapping:
            usage_removed, tokens_removed = mapping.reclaim(dirty_run_ids)
        report.removed_mapping_usage += usage_removed
        report.removed_mapping_tokens += tokens_removed
    except Exception as exc:
        report.errors.append(
            {"path": str(paths.pseudomap_db), "error": f"{type(exc).__name__}: {exc}"}
        )


def _reclaim_runtime_sidecars(
    paths: Paths,
    runs: list[RunRecord],
    options: CleanupOptions,
    report: CleanupReport,
) -> None:
    """Remove journal fragments of runtime DBs only when no *other* run is live.

    WAL/SHM files are never touched here: removing a WAL that contains
    committed-but-not-checkpointed frames would corrupt a database. A
    ``-journal`` file, by contrast, only belongs to an uncommitted transaction
    that SQLite would roll back anyway.
    """
    any_live = any(
        is_lock_live(lock_path(paths.locks_dir, f"run-{run.run_id}"))
        for run in runs
        if run.run_id not in options.protect_run_ids
    )
    if any_live and options.preserve_pseudomap_sidecars_while_runs_live:
        return
    for db in (paths.pseudomap_db, paths.checkpoint_db):
        for sidecar in _sidecars(db):
            if sidecar.suffix != "-journal":
                continue
            if options.dry_run:
                report.removed_sidecars.append(str(sidecar))
                continue
            _remove_file(sidecar, options, report)
            if not sidecar.exists():
                report.removed_sidecars.append(str(sidecar))


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")
