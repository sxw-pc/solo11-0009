"""Shared helpers for lifecycle tests: pinned-time runs and custom retention."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from maskline.config import Paths
from maskline.lifecycle.clock import Clock
from maskline.lifecycle.manager import LifecycleManager
from maskline.lifecycle.retention import RetentionPolicy
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"

EPOCH = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def pinned_clock(days_after_epoch: int = 0) -> Clock:
    return Clock.pinned(EPOCH + timedelta(days=days_after_epoch))


def custom_policy(retention: dict[str, int], grace_days: int = 7,
                  overrides: dict | None = None) -> RetentionPolicy:
    return RetentionPolicy(
        retention_days=retention,
        grace_days=grace_days,
        dataset_overrides=overrides or {},
    )


def run_and_register(workspace: Paths, inventory, secret_store, clock: Clock,
                     policy: RetentionPolicy, batch_size: int = 2):
    masking_policy = load_policy(EXAMPLE)
    result = execute_run(
        inventory, masking_policy, workspace,
        secrets_store=secret_store, batch_size=batch_size,
    )
    # finalize_run writes the report, appends the run audit entry and registers
    # the produced artifacts under the (possibly shortened) retention policy.
    from maskline.workflow import finalize_run
    finalize_run(workspace, inventory, masking_policy, result,
                 findings=[], retention_policy=policy, clock=clock)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        records = manager.list_artifacts()
    return result, records


def advance(clock: Clock, days: int) -> Clock:
    clock.advance(timedelta(days=days))
    return clock
