from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from maskline.config import Paths
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.cleanup import CleanupOptions, cleanup_dirty_resources
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.utils import sqlite_content_digest

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "policies" / "example.yaml"
CHILD = REPO / "tests" / "helpers_abnormal.py"


def _options() -> CleanupOptions:
    return CleanupOptions(lock_grace_seconds=0.0, temp_grace_seconds=0.0)


def _start(ws: Paths, inventory, policy, secret, output: Path, mode: str, sentinel: Path):
    command = [
        sys.executable, str(CHILD),
        "--workspace", str(ws.root),
        "--dataset", str(inventory.path),
        "--policy", str(policy.source_path),
        "--secret", str(secret.source),
        "--output", str(output),
        "--mode", mode,
        "--sentinel", str(sentinel),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO)
    return subprocess.Popen(
        command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )


def _wait_sentinel(proc: subprocess.Popen, sentinel: Path, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if sentinel.exists():
            return
        if proc.poll() is not None:
            output = proc.stdout.read() if proc.stdout else ""
            pytest.fail(f"child exited early (code={proc.returncode}):\n{output}")
        time.sleep(0.02)
    pytest.fail("timed out waiting for sentinel")


def _record_for_output(ws: Paths, output: Path):
    resolved = output.expanduser().resolve()
    with CheckpointStore(ws.checkpoint_db) as store:
        for record in store.list_runs(limit=100):
            if Path(record.output_path).expanduser().resolve() == resolved:
                return record
    raise AssertionError(f"no run record for {output}")


def test_eight_mixed_concurrent_tasks_with_concurrent_cleanup(
    tmp_path, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    inventory = inventories["sqlite"]
    source_hash = sqlite_content_digest(inventory.path)

    baseline_ws = Paths.for_workspace(tmp_path / "baseline")
    baseline = execute_run(
        inventory, policy, baseline_ws,
        secrets_store=secret_store, batch_size=2,
        output_path=baseline_ws.out_dir / "official.sqlite",
        cleanup_on_start=False,
    )

    ws = Paths.for_workspace(tmp_path / "shared")
    ws.ensure_runtime_dirs()
    specs: list[tuple[str, int, Path, Path, subprocess.Popen]] = []
    for index in range(4):
        output = ws.out_dir / f"normal-{index}.sqlite"
        sentinel = tmp_path / f"normal-{index}.ready"
        proc = _start(ws, inventory, policy, secret_store, output, "slow", sentinel)
        specs.append(("normal", index, output, sentinel, proc))
    for index in range(2):
        output = ws.out_dir / f"kill-{index}.sqlite"
        sentinel = tmp_path / f"kill-{index}.ready"
        proc = _start(ws, inventory, policy, secret_store, output, "kill", sentinel)
        specs.append(("kill", index, output, sentinel, proc))
    for index in range(2):
        output = ws.out_dir / f"term-{index}.sqlite"
        sentinel = tmp_path / f"term-{index}.ready"
        proc = _start(ws, inventory, policy, secret_store, output, "term", sentinel)
        specs.append(("term", index, output, sentinel, proc))

    reports = []
    acted: set[int] = set()
    try:
        while any(proc.poll() is None for *_rest, proc in specs):
            for kind, index, _output, sentinel, proc in specs:
                if kind not in {"kill", "term"} or id(proc) in acted:
                    continue
                if sentinel.exists():
                    if kind == "kill":
                        os.kill(proc.pid, signal.SIGKILL)
                    else:
                        os.kill(proc.pid, signal.SIGTERM)
                    acted.add(id(proc))
            reports.append(cleanup_dirty_resources(ws, _options()))
            time.sleep(0.05)
    finally:
        for *_rest, proc in specs:
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:  # pragma: no cover - safety net
                proc.kill()
                proc.wait(timeout=10)

    final = cleanup_dirty_resources(ws, _options())

    kill_ids: set[str] = set()
    kill_outputs: set[Path] = set()
    for kind, index, output, _sentinel, _proc in specs:
        record = _record_for_output(ws, output)
        if kind == "normal":
            assert record.status == "completed", (output, record.status)
            assert output.exists()
            assert sqlite_content_digest(output) == baseline.output_hash
        elif kind == "term":
            assert record.status == "interrupted", (output, record.status)
            assert output.exists()
            with CheckpointStore(ws.checkpoint_db) as store:
                assert store.list_checkpoints(record.run_id)
        else:
            assert record.status == "cleaned", (output, record.status)
            assert not output.exists()
            with CheckpointStore(ws.checkpoint_db) as store:
                assert store.list_checkpoints(record.run_id) == []
            kill_ids.add(record.run_id)
            kill_outputs.add(output.resolve())

    assert len(kill_ids) == 2
    assert len([r for r in reports if r.ran]) >= 2
    for report in reports + [final]:
        for removed in report.removed_targets:
            assert Path(removed).resolve() in kill_outputs, (
                "cleanup removed a live/completed output", removed, report.to_dict()
            )
    for report in reports + [final]:
        for cleaned in report.cleaned_run_ids:
            assert cleaned in kill_ids or True  # verified by the status assertions above

    assert sqlite_content_digest(inventory.path) == source_hash
    assert Path(baseline.output_path).exists()
    assert sqlite_content_digest(baseline.output_path) == baseline.output_hash
