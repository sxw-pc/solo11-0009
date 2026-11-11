"""Batch-oriented, resumable execution into an independent target database."""

from __future__ import annotations

import copy
import sqlite3
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..audit import AuditLog, build_audit_entry
from ..config import Paths, SecretStore
from ..policies import DatasetRule, Policy
from ..pseudomap import PseudoMap
from ..registry import DatasetInventory, TableInfo
from ..transformers import TransformContext
from ..utils import sqlite_content_digest
from .checkpoint import CheckpointStore, RunRecord, TableCheckpoint
from .errors import PipelineError, PipelineInterrupted
from .manifest import write_manifest
from .steps import (
    create_target,
    insert_batch,
    merge_counts,
    new_run_id,
    source_batches,
    transform_row,
)


@dataclass
class RunResult:
    run_id: str
    dataset_path: Path
    dataset_fingerprint: str
    policy_name: str
    policy_fingerprint: str
    output_path: Path | None
    output_hash: str | None
    row_count: int
    elapsed_seconds: float
    transform_counts: dict[str, dict[str, int]]
    transformer_map: dict[str, dict[str, str]]
    table_rows: dict[str, int] = field(default_factory=dict)
    policy_changed: bool = False
    dry_run: bool = False
    audit_entry: dict[str, Any] | None = None


def _transformer_map(rule: DatasetRule) -> dict[str, dict[str, str]]:
    return {
        table_name: {name: col.transformer for name, col in table_policy.columns.items()}
        for table_name, table_policy in rule.tables.items()
    }


def _requires_secret(rule: DatasetRule) -> bool:
    return any(
        detail.transformer in {"pseudonym", "hash"}
        for table_policy in rule.tables.values()
        for detail in table_policy.columns.values()
    )


def _prepare_target(
    inventory: DatasetInventory,
    policy: Policy,
    paths: Paths,
    store: CheckpointStore,
    run_id: str,
    resume_run_id: str | None,
    output_path: str | Path | None,
) -> Path:
    if resume_run_id:
        record = store.get_run(run_id)
        if record is None:
            raise PipelineError(f"unknown run id: {run_id}")
        if record.status == "completed":
            raise PipelineError(f"run {run_id} is already completed")
        if record.dataset_fingerprint != inventory.fingerprint:
            raise PipelineError("dataset content changed since the interrupted run")
        if record.policy_fingerprint != policy.fingerprint:
            raise PipelineError("policy changed since the interrupted run")
        output = Path(record.output_path)
        if not output.exists():
            raise PipelineError(f"target database is missing: {output}")
        store.set_status(run_id, "running")
        return output
    output = Path(output_path) if output_path else (
        paths.out_dir / f"{inventory.path.stem}.masked.sqlite"
    )
    output = output.expanduser().resolve()
    if output == inventory.path.resolve():
        raise PipelineError("refusing to write the target over the source dataset")
    try:
        create_target(inventory, output)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        store.create_run(
            RunRecord(
                run_id, str(inventory.path), inventory.fingerprint, str(policy.source_path),
                policy.fingerprint, str(output), "running", now, now,
            )
        )
    except Exception:
        # Never leave a deliverable-looking target behind for a run that
        # could not even be registered (e.g. the disk is full).
        _discard_output(output)
        raise
    return output


def _process_table(
    inventory: DatasetInventory,
    table: TableInfo,
    table_policy: Any,
    checkpoint: TableCheckpoint | None,
    target: sqlite3.Connection | None,
    store: CheckpointStore | None,
    context: TransformContext,
    mapping: PseudoMap | None,
    run_id: str,
    batch_size: int,
    batch_counter: list[int],
    interrupt_after_batches: int | None,
) -> tuple[int, int, dict[str, dict[str, int]]]:
    after = checkpoint.last_rowid if checkpoint else 0
    rows_done = checkpoint.rows_done if checkpoint else 0
    table_counts = copy.deepcopy(checkpoint.counts) if checkpoint else {}
    for batch in source_batches(inventory, table, after, batch_size):
        transformed = [
            (rowid, transform_row(values, table, table_policy, context, table_counts))
            for rowid, values in batch
        ]
        if target is not None:
            with target:
                insert_batch(target, table, transformed)
        if mapping is not None:
            mapping.commit()
        rows_done += len(transformed)
        after = transformed[-1][0]
        batch_counter[0] += 1
        if store is not None:
            store.save_checkpoint(run_id, table.name, after, rows_done, table_counts)
        if interrupt_after_batches is not None and batch_counter[0] >= interrupt_after_batches:
            raise PipelineInterrupted(run_id)
    if store is not None and checkpoint is None:
        store.save_checkpoint(run_id, table.name, after, rows_done, table_counts)
    return after, rows_done, table_counts


def _discard_output(output: Path) -> None:
    """Best-effort removal of a failed run's target database.

    A run that fails must not leave a deliverable-looking database behind:
    without its audit entry the output is dirty data, so it is rolled back.
    """
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(str(output) + suffix)
        try:
            candidate.unlink(missing_ok=True)
        except OSError as exc:
            warnings.warn(
                f"could not remove {candidate} while rolling back a failed "
                f"run: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )


def execute_run(
    inventory: DatasetInventory,
    policy: Policy,
    paths: Paths,
    *,
    secrets_store: SecretStore | None = None,
    batch_size: int = 1000,
    dry_run: bool = False,
    resume_run_id: str | None = None,
    output_path: str | Path | None = None,
    interrupt_after_batches: int | None = None,
) -> RunResult:
    if batch_size < 1:
        raise PipelineError("batch_size must be positive")
    rule = policy.validate_against(inventory)
    if dry_run and resume_run_id:
        raise PipelineError("dry-run cannot be combined with resume")
    started = time.monotonic()
    run_id = resume_run_id or new_run_id()
    store: CheckpointStore | None = None
    target: sqlite3.Connection | None = None
    mapping: PseudoMap | None = None
    output: Path | None = None
    try:
        if not dry_run:
            paths.ensure_runtime_dirs()
            store = CheckpointStore(paths.checkpoint_db)
            output = _prepare_target(
                inventory, policy, paths, store, run_id, resume_run_id, output_path
            )
            if _requires_secret(rule):
                if secrets_store is None:
                    raise PipelineError("this policy requires MASKLINE_SECRET_FILE")
                mapping = PseudoMap(paths.pseudomap_db, create=True)
            target = sqlite3.connect(output)
            target.execute("PRAGMA journal_mode=DELETE")
            context = TransformContext(
                secrets=secrets_store, pseudomap=mapping, write_mapping=True
            )
        else:
            output = None
            context = TransformContext(
                secrets=secrets_store, pseudomap=None, write_mapping=False
            )
        transformer_map = _transformer_map(rule)
        dry_counts: dict[str, dict[str, int]] = {}
        batch_counter = [0]
        for table in inventory.tables:
            checkpoint = store.get_checkpoint(run_id, table.name) if store else None
            _after, _rows, table_counts = _process_table(
                inventory, table, rule.tables.get(table.name), checkpoint, target,
                store, context, mapping, run_id, batch_size, batch_counter,
                interrupt_after_batches,
            )
            if dry_run:
                merge_counts(dry_counts, table_counts)
        if target is not None:
            target.commit()
            target.close()
            target = None
        if dry_run:
            for table_policy in rule.tables.values():
                for detail in table_policy.columns.values():
                    dry_counts.setdefault(
                        detail.transformer,
                        {"seen": 0, "processed": 0, "changed": 0},
                    )
            return RunResult(
                run_id=run_id, dataset_path=inventory.path,
                dataset_fingerprint=inventory.fingerprint, policy_name=policy.name,
                policy_fingerprint=policy.fingerprint, output_path=None,
                output_hash=None, row_count=inventory.row_count,
                elapsed_seconds=time.monotonic() - started,
                transform_counts=dry_counts, transformer_map=transformer_map,
                table_rows={table.name: table.row_count for table in inventory.tables},
                policy_changed=False, dry_run=True,
            )
        assert store is not None and output is not None
        output_hash = sqlite_content_digest(output)
        final_counts: dict[str, dict[str, int]] = {}
        table_rows: dict[str, int] = {}
        for checkpoint in store.list_checkpoints(run_id):
            table_rows[checkpoint.table_name] = checkpoint.rows_done
            merge_counts(final_counts, checkpoint.counts)
        row_count = sum(table_rows.values())
        result = RunResult(
            run_id=run_id, dataset_path=inventory.path,
            dataset_fingerprint=inventory.fingerprint, policy_name=policy.name,
            policy_fingerprint=policy.fingerprint, output_path=output,
            output_hash=output_hash, row_count=row_count,
            elapsed_seconds=time.monotonic() - started,
            transform_counts=final_counts, transformer_map=transformer_map,
            table_rows=table_rows, policy_changed=False, dry_run=False,
        )
        # The audit entry is the commit point of the run. If it cannot be
        # written (e.g. the disk is full), the exception path below marks the
        # run failed and discards the target database, so a completed run
        # never exists without its audit record.
        result.audit_entry = AuditLog(paths.audit_path).append(
            build_audit_entry(result, transformer_map)
        )
        store.set_status(run_id, "completed")
        _manifest, changed = write_manifest(
            paths.manifest_dir, inventory, policy, run_id, output, output_hash,
            row_count, transformer_map, final_counts,
        )
        result.policy_changed = changed
        return result
    except PipelineInterrupted:
        if store is not None:
            store.set_status(run_id, "interrupted")
        raise
    except Exception:
        if store is not None:
            try:
                store.set_status(run_id, "failed")
            except Exception:
                pass
        if output is not None:
            _discard_output(output)
        raise
    finally:
        if target is not None:
            target.close()
        if mapping is not None:
            mapping.close()
        if store is not None:
            store.close()
