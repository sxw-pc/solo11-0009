#!/usr/bin/env python3
"""Benchmark audit-log append throughput for the installed maskline.

Usage:
    python scripts/bench_audit.py [--entries 200] [--repeats 3]

Compare the appends/second reported here across versions; the hardened
append path must stay within 10% of the v0.1.0 implementation.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from maskline.audit import AuditLog  # noqa: E402


def bench(entries: int, directory: Path) -> float:
    log = AuditLog(directory / "audit.jsonl")
    started = time.perf_counter()
    for index in range(entries):
        log.append(
            {
                "run_id": f"bench-{index}",
                "rows_processed": index,
                "output_hash": "ab" * 32,
            }
        )
    return time.perf_counter() - started


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=int, default=200)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    samples = []
    for attempt in range(args.repeats):
        with tempfile.TemporaryDirectory() as tmp:
            elapsed = bench(args.entries, Path(tmp) / f"run{attempt}")
        samples.append(args.entries / elapsed)
        print(f"run {attempt + 1}: {args.entries} appends in {elapsed:.3f}s "
              f"({samples[-1]:.1f} appends/s)")
    best = max(samples)
    print(f"best: {best:.1f} appends/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
