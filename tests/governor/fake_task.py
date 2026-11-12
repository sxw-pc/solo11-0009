"""Deterministic fake masking task used by governor tests.

Behaviour is driven by environment variables so the governor can exercise every
enforcement branch without a real dataset:

* FAKE_CPU_SECONDS    -- busy loop duration (CPU pressure)
* FAKE_ALLOC_MB       -- RSS footprint to allocate and touch
* FAKE_SLEEP_SECONDS  -- idle wall time per batch (long slice coverage)
* FAKE_EXIT_CODE      -- exit status to simulate a crash
* FAKE_EXIT_CODE_FILE -- file whose contents override FAKE_EXIT_CODE at start,
                         letting a test flip the outcome between retries
* FAKE_BATCHES        -- number of "batch" checkpoint units to process
* FAKE_PROGRESS_FILE  -- where the committed batch cursor is persisted
* FAKE_RUN_ID         -- run id advertised through the progress event file

The script honours SIGTERM by flushing its checkpoint and exiting 0, mirroring
the batch-boundary safety of the real runner.  On a governor-driven replay it
reopens the progress file and continues after the last committed batch, which
is the generic-command analogue of the pipeline's rowid checkpoint resume: no
batch is processed twice and none is lost.
"""

from __future__ import annotations

import os
import signal
import sys
import time

from maskline.pipeline.progress import emit_event


def main() -> int:
    stopping = {"flag": False}

    def _term(_signum, _frame):
        stopping["flag"] = True

    signal.signal(signal.SIGTERM, _term)

    run_id = os.environ.get("FAKE_RUN_ID", "run-fake-0001")
    is_resume = "resume" in sys.argv or os.environ.get(
        "MASKLINE_GOVERNOR_RESUMED"
    ) == "1"
    attempt = int(os.environ.get("MASKLINE_GOVERNOR_ATTEMPT", "0"))
    batches = int(os.environ.get("FAKE_BATCHES", "4"))
    cpu_seconds = float(os.environ.get("FAKE_CPU_SECONDS", "0"))
    sleep_seconds = float(os.environ.get("FAKE_SLEEP_SECONDS", "0"))
    alloc_mb = int(os.environ.get("FAKE_ALLOC_MB", "0"))
    exit_code = int(os.environ.get("FAKE_EXIT_CODE", "0"))

    code_file = os.environ.get("FAKE_EXIT_CODE_FILE")
    if code_file and os.path.exists(code_file):
        try:
            exit_code = int(open(code_file, encoding="utf-8").read().strip() or "0")
        except ValueError:
            exit_code = 0

    progress_file = os.environ.get("FAKE_PROGRESS_FILE")
    start_batch = 0
    if progress_file and os.path.exists(progress_file):
        try:
            start_batch = int(open(progress_file, encoding="utf-8").read().strip() or "0")
        except ValueError:
            start_batch = 0

    emit_event(
        "run_started",
        {"run_id": run_id, "resume": is_resume, "dry_run": False,
         "attempt": attempt, "start_batch": start_batch},
    )

    blob = bytearray(alloc_mb * 1024 * 1024)
    for index in range(0, len(blob), 4096):
        blob[index] = index % 256  # touch pages so RSS really grows

    deadline = time.monotonic() + cpu_seconds
    batch = start_batch
    while batch < batches:
        if stopping["flag"]:
            emit_event("run_interrupted", {"run_id": run_id, "batch": batch})
            return 0
        if cpu_seconds and time.monotonic() < deadline:
            end = min(time.monotonic() + 0.05, deadline)
            value = 0
            while time.monotonic() < end:
                value = (value * 1103515245 + 12345) & 0x7FFFFFFF
        else:
            time.sleep(min(0.02, sleep_seconds or 0.02))
        batch += 1
        if progress_file:
            with open(progress_file, "w", encoding="utf-8") as handle:
                handle.write(str(batch))
                handle.flush()
                os.fsync(handle.fileno())
        emit_event("checkpoint", {"run_id": run_id, "batch": batch})

    if exit_code != 0:
        emit_event("run_failed", {"run_id": run_id, "error": "simulated"})
        print("simulated failure", file=sys.stderr)
        return exit_code
    emit_event("run_completed", {"run_id": run_id, "row_count": batches})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
