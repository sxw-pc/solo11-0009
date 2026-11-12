"""Child process used by recovery tests to emulate abnormal exits.

Modes:
  normal  run to completion
  slow    pause briefly after the first persisted checkpoint (lets a concurrent
          cleanup pass run while the lock is still owned)
  kill    persist a checkpoint, signal readiness, then sleep until SIGKILL
  term    same, but the parent sends SIGTERM so the engine marks the run
          ``interrupted`` (a legitimate resumable suspension)
"""

from __future__ import annotations

import argparse
import sys

from maskline.config import Paths, SecretStore
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.registry import inspect_dataset


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=("normal", "slow", "kill", "term"), default="normal")
    parser.add_argument("--sentinel", default=None)
    args = parser.parse_args(argv)

    paths = Paths.for_workspace(args.workspace)
    inventory = inspect_dataset(args.dataset)
    policy = load_policy(args.policy)
    secret = SecretStore.from_file(args.secret)

    original_save = CheckpointStore.save_checkpoint
    state = {"saved": 0}

    if args.mode in {"slow", "kill", "term"}:
        import time
        from pathlib import Path

        sentinel = Path(args.sentinel) if args.sentinel else None

        def patched_save(self, *call_args, **call_kwargs):
            original_save(self, *call_args, **call_kwargs)
            state["saved"] += 1
            if state["saved"] == 1:
                if sentinel is not None:
                    sentinel.write_text("ready\n", encoding="utf-8")
                if args.mode == "slow":
                    time.sleep(0.4)
                else:
                    time.sleep(120)

        CheckpointStore.save_checkpoint = patched_save

    try:
        result = execute_run(
            inventory,
            policy,
            paths,
            secrets_store=secret,
            batch_size=2,
            output_path=args.output,
        )
        print(f"run={result.run_id} status=completed rows={result.row_count}", flush=True)
        return 0
    except PipelineInterrupted as exc:
        print(f"run={exc.run_id} status=interrupted", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
