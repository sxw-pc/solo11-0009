"""Batch-oriented, resumable execution into a pluggable output target."""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import Paths, SecretStore
from ..policies import DatasetRule, Policy
from ..pseudomap import PseudoMap
from ..registry import DatasetInventory, TableInfo
from ..transformers import TransformContext
from .checkpoint import CheckpointStore, RunRecord, TableCheckpoint
from .errors import PipelineError, PipelineInterrupted
from .manifest import write_manifest
from .steps import merge_counts, new_run_id, source_batches, transform_row
from .targets import OutputTarget, make_target, target_for_resume


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
    target_kind: str = "sqlite"


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


def _default_output(paths: Paths, inventory: DatasetInventory, target_format: str) -> Path:
    if target_format == "csv":
        return paths.out_dir / f"{inventory.path.stem}.masked"
    return paths.out_dir / f"{inventory.path.stem}.masked.sqlite"


def _prepare_target(
    inventory: DatasetInventory,
    policy: Policy,
    paths: Paths,
    store: CheckpointStore,
    run_id: str,
    resume_run_id: str | None,
    output_path: str | Path | None,
    target_format: str,
) -> tuple[OutputTarget, Path]:
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
        target = target_for_resume(inventory, output)
        target.open_for_resume()
        store.set_status(run_id, "running")
        return target, output
    output = Path(output_path) if output_path else _default_output(
        paths, inventory, target_format
    )
    output = output.expanduser().resolve()
    target = make_target(target_format, inventory, output)
    target.create()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store.create_run(
        RunRecord(
            run_id, str(inventory.path), inventory.fingerprint, str(policy.source_path),
            policy.fingerprint, str(output), "running", now, now,
        )
    )
    return target, output


def _process_table(
    inventory: DatasetInventory,
    table: TableInfo,
    table_policy: Any,
    checkpoint: TableCheckpoint | None,
    target: OutputTarget | None,
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
            target.write_batch(table, transformed, rows_done + len(transformed))
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
    if target is not None:
        target.finish_table(table)
    return after, rows_done, table_counts


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
    target_format: str = "sqlite",
    interrupt_after_batches: int | None = None,
) -> RunResult:
    """Run the masking pipeline.

    ``target_format`` selects the output target for new runs ("sqlite" or
    "csv"); it is ignored when resuming, where the target kind recorded by
    the interrupted run is recovered from its output path.
    """
    if batch_size < 1:
        raise PipelineError("batch_size must be positive")
    rule = policy.validate_against(inventory)
    if dry_run and resume_run_id:
        raise PipelineError("dry-run cannot be combined with resume")
    started = time.monotonic()
    run_id = resume_run_id or new_run_id()
    store: CheckpointStore | None = None
    target: OutputTarget | None = None
    mapping: PseudoMap | None = None
    try:
        if not dry_run:
            paths.ensure_runtime_dirs()
            store = CheckpointStore(paths.checkpoint_db)
            target, output = _prepare_target(
                inventory, policy, paths, store, run_id, resume_run_id,
                output_path, target_format,
            )
            if _requires_secret(rule):
                if secrets_store is None:
                    raise PipelineError("this policy requires MASKLINE_SECRET_FILE")
                mapping = PseudoMap(paths.pseudomap_db, create=True)
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
            if target is not None:
                assert store is not None
                checkpoint = target.prepare_table(table, checkpoint, store, run_id)
            _after, _rows, table_counts = _process_table(
                inventory, table, rule.tables.get(table.name), checkpoint, target,
                store, context, mapping, run_id, batch_size, batch_counter,
                interrupt_after_batches,
            )
            if dry_run:
                merge_counts(dry_counts, table_counts)
        if target is not None:
            target.close()
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
                policy_changed=False, dry_run=True, target_kind=target_format,
            )
        assert store is not None and output is not None and target is not None
        store.set_status(run_id, "completed")
        output_hash = target.digest()
        final_counts: dict[str, dict[str, int]] = {}
        table_rows: dict[str, int] = {}
        for checkpoint in store.list_checkpoints(run_id):
            table_rows[checkpoint.table_name] = checkpoint.rows_done
            merge_counts(final_counts, checkpoint.counts)
        row_count = sum(table_rows.values())
        _manifest, changed = write_manifest(
            paths.manifest_dir, inventory, policy, run_id, output, output_hash,
            row_count, transformer_map, final_counts, target_kind=target.kind,
        )
        return RunResult(
            run_id=run_id, dataset_path=inventory.path,
            dataset_fingerprint=inventory.fingerprint, policy_name=policy.name,
            policy_fingerprint=policy.fingerprint, output_path=output,
            output_hash=output_hash, row_count=row_count,
            elapsed_seconds=time.monotonic() - started,
            transform_counts=final_counts, transformer_map=transformer_map,
            table_rows=table_rows, policy_changed=changed, dry_run=False,
            target_kind=target.kind,
        )
    except PipelineInterrupted:
        if store is not None:
            store.set_status(run_id, "interrupted")
        raise
    except Exception:
        if store is not None:
            store.set_status(run_id, "failed")
        raise
    finally:
        if target is not None:
            target.close()
        if mapping is not None:
            mapping.close()
        if store is not None:
            store.close()
