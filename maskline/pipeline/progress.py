"""Best-effort progress event sink for supervised pipeline runs.

When the environment variable ``MASKLINE_PROGRESS_FILE`` points at a writable
file, the runner appends one JSON object per lifecycle event.  The governor
relies on these events to learn a freshly created ``run_id`` without parsing
console output, which is what makes pause/resume fully automatic.

The sink is optional and deliberately failure-tolerant: a broken sink must
never change the behaviour of an ordinary masking task.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

PROGRESS_ENV = "MASKLINE_PROGRESS_FILE"


def progress_path() -> str | None:
    return os.environ.get(PROGRESS_ENV)


def emit_event(kind: str, payload: dict[str, Any] | None = None) -> None:
    """Append one event line; swallow every error to stay transparent."""
    path = progress_path()
    if not path:
        return
    event = {"kind": kind, "ts": time.time()}
    if payload:
        event.update(payload)
    try:
        with open(path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        return


def read_events(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Read back every event line, ignoring trailing partial writes."""
    events: list[dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    events.append(event)
    except OSError:
        return events
    return events


def latest_run_id(path: str | os.PathLike[str]) -> str | None:
    run_id: str | None = None
    for event in read_events(path):
        candidate = event.get("run_id")
        if isinstance(candidate, str) and candidate:
            run_id = candidate
    return run_id
