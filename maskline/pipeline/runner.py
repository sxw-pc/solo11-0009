"""Batch-oriented, resumable execution into an independent target database."""

from __future__ import annotations

import copy
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import Paths, SecretStore
from ..policies import DatasetRule, Policy
from ..pseudomap import PseudoMap
from ..registry import DatasetInventory, TableInfo
from ..transformers import TransformContext, TransformError
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

# Keep only a bounded sample of skip reasons in memory and in the run record;
# the authoritative total lives in the per-table checkpoints.
SKIP_SAMPLE_LIMIT = 20


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
    skipped_rows: int = 0
    pseudomap_entries: int = 0
    resumed: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)
    skip_samples: list[dict[str, Any]] = field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
) -> bool:
    """Create or re-open the target database; record the start/resume event."""
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
        prior_events = store.list_events(run_id)
        store.set_status(run_id, "running")
        checkpoints = store.list_checkpoints(run_id)
        store.add_event(
            run_id,
            "run_resumed",
            {
                "prior_events": len(prior_events),
                "tables": {
                    cp.table_name: {
                        "rows_done": cp.rows_done,
                        "skipped_rows": cp.skipped_rows,
                    }
                    for cp in checkpoints
                },
            },
        )
        return True
    output = Path(output_path) if output_path else (
        paths.out_dir / f"{inventory.path.stem}.masked.sqlite"
    )
    output = output.expanduser().resolve()
    if output == inventory.path.resolve():
        raise PipelineError("refusing to write the target over the source dataset")
    create_target(inventory, output)
    now = _now()
    store.create_run(
        RunRecord(
            run_id, str(inventory.path), inventory.fingerprint, str(policy.source_path),
            policy.fingerprint, str(output), "running", now, now,
        )
    )
    store.add_event(
        run_id,
        "run_started",
        {
            "dataset_fingerprint": inventory.fingerprint,
            "policy_fingerprint": policy.fingerprint,
            "output": str(output),
        },
        ts=now,
    )
    return False


def _row_arity_ok(table: TableInfo, values: tuple[Any, ...]) -> bool:
    return len(values) == len(table.columns)


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
    skip_samples: list[dict[str, Any]],
) -> tuple[int, int, int, dict[str, dict[str, int]]]:
    after = checkpoint.last_rowid if checkpoint else 0
    rows_done = checkpoint.rows_done if checkpoint else 0
    skipped_total = checkpoint.skipped_rows if checkpoint else 0
    # Rowids already counted as skips in earlier attempts of this run; without
    # this set a resume would re-scan trailing malformed rows and count them
    # again, inflating the skip total.
    skipped_rowids: list[int] = list(checkpoint.skipped_rowids) if checkpoint else []
    skipped_set = set(skipped_rowids)
    table_counts = copy.deepcopy(checkpoint.counts) if checkpoint else {}
    expected_arity = len(table.columns)

    def _record_skip(rowid: int, sample: dict[str, Any]) -> None:
        nonlocal skipped_total
        if rowid in skipped_set:
            return
        skipped_set.add(rowid)
        skipped_rowids.append(rowid)
        skipped_total += 1
        if len(skip_samples) < SKIP_SAMPLE_LIMIT:
            skip_samples.append(sample)
        if store is not None:
            store.save_checkpoint(
                run_id, table.name, rowid, rows_done, table_counts,
                skipped_total, skipped_rowids,
            )

    for batch in source_batches(inventory, table, after, batch_size):
        transformed: list[tuple[int, tuple[Any, ...]]] = []
        for rowid, values in batch:
            if not _row_arity_ok(table, values):
                _record_skip(
                    rowid,
                    {
                        "table": table.name,
                        "rowid": rowid,
                        "reason": "row_arity_mismatch",
                        "expected_columns": expected_arity,
                        "actual_columns": len(values),
                    },
                )
                continue
            try:
                output_values = transform_row(
                    values, table, table_policy, context, table_counts
                )
            except TransformError as exc:
                _record_skip(
                    rowid,
                    {
                        "table": table.name,
                        "rowid": rowid,
                        "reason": "transform_error",
                        "column": context.column,
                        "error": str(exc),
                    },
                )
                continue
            transformed.append((rowid, output_values))
        if target is not None and transformed:
            with target:
                insert_batch(target, table, transformed)
        if mapping is not None:
            mapping.commit()
        if transformed:
            rows_done += len(transformed)
            after = transformed[-1][0]
        elif batch:
            # Whole batch was skipped: still advance the rowid cursor so a
            # resume never re-scans the same malformed rows.
            after = batch[-1][0]
        batch_counter[0] += 1
        if store is not None:
            store.save_checkpoint(
                run_id, table.name, after, rows_done, table_counts,
                skipped_total, skipped_rowids,
            )
        if interrupt_after_batches is not None and batch_counter[0] >= interrupt_after_batches:
            raise PipelineInterrupted(run_id)
    if store is not None and checkpoint is None:
        store.save_checkpoint(
            run_id, table.name, after, rows_done, table_counts,
            skipped_total, skipped_rowids,
        )
    return after, rows_done, skipped_total, table_counts


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
    resumed = False
    skip_samples: list[dict[str, Any]] = []
    try:
        if not dry_run:
            paths.ensure_runtime_dirs()
            store = CheckpointStore(paths.checkpoint_db)
            resumed = _prepare_target(
                inventory, policy, paths, store, run_id, resume_run_id, output_path
            )
            if _requires_secret(rule):
                if secrets_store is None:
                    raise PipelineError("this policy requires MASKLINE_SECRET_FILE")
                mapping = PseudoMap(paths.pseudomap_db, create=True)
            output = Path(store.get_run(run_id).output_path)
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
        dry_skipped = 0
        for table in inventory.tables:
            checkpoint = store.get_checkpoint(run_id, table.name) if store else None
            _after, _rows, table_skipped, table_counts = _process_table(
                inventory, table, rule.tables.get(table.name), checkpoint, target,
                store, context, mapping, run_id, batch_size, batch_counter,
                interrupt_after_batches, skip_samples,
            )
            if dry_run:
                merge_counts(dry_counts, table_counts)
                dry_skipped += table_skipped
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
                output_hash=None, row_count=inventory.row_count - dry_skipped,
                elapsed_seconds=time.monotonic() - started,
                transform_counts=dry_counts, transformer_map=transformer_map,
                table_rows={table.name: table.row_count for table in inventory.tables},
                policy_changed=False, dry_run=True,
                skipped_rows=dry_skipped, pseudomap_entries=0, resumed=False,
                events=[], skip_samples=skip_samples,
            )
        assert store is not None and output is not None
        store.set_status(run_id, "completed")
        output_hash = sqlite_content_digest(output)
        final_counts: dict[str, dict[str, int]] = {}
        table_rows: dict[str, int] = {}
        skipped_rows = 0
        for checkpoint in store.list_checkpoints(run_id):
            table_rows[checkpoint.table_name] = checkpoint.rows_done
            skipped_rows += checkpoint.skipped_rows
            merge_counts(final_counts, checkpoint.counts)
        row_count = sum(table_rows.values())
        pseudomap_entries = mapping.count() if mapping is not None else 0
        _manifest, changed = write_manifest(
            paths.manifest_dir, inventory, policy, run_id, output, output_hash,
            row_count, transformer_map, final_counts,
        )
        store.add_event(
            run_id,
            "run_completed",
            {
                "rows_processed": row_count,
                "skipped_rows": skipped_rows,
                "pseudomap_entries": pseudomap_entries,
                "output_hash": output_hash,
                "skip_samples": skip_samples,
            },
        )
        events = [event.to_dict() for event in store.list_events(run_id)]
        return RunResult(
            run_id=run_id, dataset_path=inventory.path,
            dataset_fingerprint=inventory.fingerprint, policy_name=policy.name,
            policy_fingerprint=policy.fingerprint, output_path=output,
            output_hash=output_hash, row_count=row_count,
            elapsed_seconds=time.monotonic() - started,
            transform_counts=final_counts, transformer_map=transformer_map,
            table_rows=table_rows, policy_changed=changed, dry_run=False,
            skipped_rows=skipped_rows, pseudomap_entries=pseudomap_entries,
            resumed=resumed, events=events, skip_samples=skip_samples,
        )
    except PipelineInterrupted:
        if store is not None:
            store.set_status(run_id, "interrupted")
            checkpoints = store.list_checkpoints(run_id)
            store.add_event(
                run_id,
                "run_interrupted",
                {
                    "batches_processed": batch_counter[0],
                    "tables": {
                        cp.table_name: {
                            "rows_done": cp.rows_done,
                            "skipped_rows": cp.skipped_rows,
                        }
                        for cp in checkpoints
                    },
                },
            )
        raise
    except Exception as exc:
        if store is not None:
            store.set_status(run_id, "failed")
            store.add_event(run_id, "run_failed", {"error": str(exc)})
        raise
    finally:
        if target is not None:
            target.close()
        if mapping is not None:
            mapping.close()
        if store is not None:
            store.close()
