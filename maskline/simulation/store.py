"""Persistent storage and version comparison for simulation results.

Results are kept in a dedicated ``simulations.sqlite`` database physically
separate from the formal run checkpoints, pseudonym maps and output directory.
The full result document is stored as canonical JSON so it remains
self-describing, while indexed columns support fast lookup by dataset and
policy. A busy timeout plus WAL mode lets several simulation processes record
their results concurrently without clashing with formal masking runs.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..config import Paths
from ..utils import canonical_json
from .errors import SimulationError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS simulations (
    simulation_id TEXT PRIMARY KEY,
    dataset_path TEXT NOT NULL,
    dataset_fingerprint TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    policy_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    sample_size INTEGER NOT NULL,
    rows_processed INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    document_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_simulations_dataset
    ON simulations(dataset_fingerprint, created_at);
"""


class SimulationStore:

    def __init__(self, path: str | Path | None = None, paths: Paths | None = None) -> None:
        if path is None:
            if paths is None:
                raise SimulationError("either path or paths is required")
            paths.data_dir.mkdir(parents=True, exist_ok=True)
            path = paths.data_dir / "simulations.sqlite"
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._enable_wal_once()

    def _enable_wal_once(self) -> None:
        """Persist WAL mode on first creation only.

        The journal mode is stored in the database header, so later connections
        inherit it. Switching the mode needs exclusive access and is not fully
        guarded by busy_timeout, hence the bounded retry here instead of running
        the pragma on every concurrent connection.
        """
        for attempt in range(5):
            conn = sqlite3.connect(self.path, timeout=30.0)
            try:
                conn.execute("PRAGMA busy_timeout=30000")
                mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                if str(mode).lower() == "wal":
                    return
            except sqlite3.OperationalError:
                if attempt == 4:
                    # Another connection likely already holds the database; the
                    # persisted mode will be visible on the next attempt/process.
                    return
                time.sleep(0.05 * (attempt + 1))
            finally:
                conn.close()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=30000")
            conn.executescript(_SCHEMA)
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save(self, document: dict[str, Any]) -> None:
        required = (
            "simulation_id", "dataset", "policy", "status", "sample", "created_at",
        )
        missing = [key for key in required if key not in document]
        if missing:
            raise SimulationError(
                "simulation document is missing required keys: " + ", ".join(missing)
            )
        dataset = document["dataset"]
        policy = document["policy"]
        sample = document["sample"]
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO simulations (
                    simulation_id, dataset_path, dataset_fingerprint, policy_name,
                    policy_fingerprint, status, sample_size, rows_processed,
                    created_at, document_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    document["simulation_id"],
                    dataset["path"],
                    dataset["fingerprint"],
                    policy["name"],
                    policy["fingerprint"],
                    document["status"],
                    int(sample.get("requested_sample_size", 0)),
                    int(document.get("rows_processed", 0)),
                    document["created_at"],
                    canonical_json(document),
                ),
            )

    def get(self, simulation_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT document_json FROM simulations WHERE simulation_id = ?",
                (simulation_id,),
            ).fetchone()
        return json.loads(row["document_json"]) if row else None

    def list_for_dataset(self, dataset_fingerprint: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT simulation_id, policy_name, policy_fingerprint, status,
                       created_at, rows_processed
                FROM simulations
                WHERE dataset_fingerprint = ?
                ORDER BY created_at DESC, simulation_id DESC
                """,
                (dataset_fingerprint,),
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_for_dataset(
        self, dataset_fingerprint: str, *, exclude: str | None = None
    ) -> dict[str, Any] | None:
        with self._connect() as conn:
            if exclude:
                row = conn.execute(
                    """
                    SELECT document_json FROM simulations
                    WHERE dataset_fingerprint = ? AND simulation_id != ?
                      AND status = 'completed'
                    ORDER BY created_at DESC, simulation_id DESC LIMIT 1
                    """,
                    (dataset_fingerprint, exclude),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    SELECT document_json FROM simulations
                    WHERE dataset_fingerprint = ? AND status = 'completed'
                    ORDER BY created_at DESC, simulation_id DESC LIMIT 1
                    """,
                    (dataset_fingerprint,),
                ).fetchone()
        return json.loads(row["document_json"]) if row else None


# --------------------------------------------------------------------------
# Version comparison
# --------------------------------------------------------------------------

def _delta(current: Any, previous: Any, *, percent: bool = False) -> dict[str, Any]:
    if current is None or previous is None:
        return {"current": current, "previous": previous, "delta": None}
    change = current - previous
    return {
        "current": current,
        "previous": previous,
        "delta": round(change, 6),
        "delta_percent": round(change * 100, 4) if percent else None,
    }


def _index_metrics(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for table in document.get("tables", []):
        for column in table.get("columns", []):
            result[(table["table_name"], column["column_name"])] = column
    return result


def compare_simulations(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    """Diff two simulation documents for the same dataset across policy versions."""
    current_cols = _index_metrics(current)
    previous_cols = _index_metrics(previous)
    columns: list[dict[str, Any]] = []
    for key in sorted(set(current_cols) | set(previous_cols)):
        current_col = current_cols.get(key)
        previous_col = previous_cols.get(key)
        entry: dict[str, Any] = {"table_name": key[0], "column_name": key[1]}
        if current_col is None:
            entry["change"] = "removed_from_policy"
            columns.append(entry)
            continue
        if previous_col is None:
            entry["change"] = "newly_covered"
            entry["metrics"] = current_col
            columns.append(entry)
            continue
        entry["change"] = "modified" if (
            current_col.get("transformer") != previous_col.get("transformer")
            or current_col.get("transformer_params") != previous_col.get("transformer_params")
        ) else "unchanged"
        coverage = current_col.get("coverage") or {}
        previous_coverage = previous_col.get("coverage") or {}
        shift = current_col.get("distribution_shift") or {}
        previous_shift = previous_col.get("distribution_shift") or {}
        entry["coverage_rate"] = _delta(
            coverage.get("coverage_rate"), previous_coverage.get("coverage_rate")
        )
        entry["psi"] = _delta(shift.get("psi"), previous_shift.get("psi"))
        entry["js_divergence"] = _delta(
            shift.get("js_divergence"), previous_shift.get("js_divergence")
        )
        kpi = current_col.get("kpi")
        previous_kpi = previous_col.get("kpi")
        if kpi and previous_kpi:
            entry["sum_deviation_rate"] = _delta(
                kpi.get("sum_deviation_rate"), previous_kpi.get("sum_deviation_rate")
            )
            entry["mean_deviation_rate"] = _delta(
                kpi.get("mean_deviation_rate"), previous_kpi.get("mean_deviation_rate")
            )
        columns.append(entry)

    linkages: list[dict[str, Any]] = []
    current_links = {tuple(item["columns"]): item for item in current.get("linkages", [])}
    previous_links = {tuple(item["columns"]): item for item in previous.get("linkages", [])}
    for key in sorted(set(current_links) | set(previous_links)):
        item = current_links.get(key)
        old = previous_links.get(key)
        linkages.append(
            {
                "left_table": key[0],
                "left_column": key[1],
                "right_table": key[2],
                "right_column": key[3],
                "retention_rate": _delta(
                    item["retention_rate"] if item else None,
                    old["retention_rate"] if old else None,
                ),
                "fully_broken": bool(item and item.get("fully_broken")),
            }
        )

    return {
        "comparison_generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "current": {
            "simulation_id": current["simulation_id"],
            "policy_fingerprint": current["policy"]["fingerprint"],
            "created_at": current["created_at"],
        },
        "previous": {
            "simulation_id": previous["simulation_id"],
            "policy_fingerprint": previous["policy"]["fingerprint"],
            "created_at": previous["created_at"],
        },
        "same_dataset": (
            current["dataset"]["fingerprint"] == previous["dataset"]["fingerprint"]
        ),
        "columns": columns,
        "linkages": linkages,
        "summary": {
            "newly_covered": sum(1 for item in columns if item["change"] == "newly_covered"),
            "removed_from_policy": sum(
                1 for item in columns if item["change"] == "removed_from_policy"
            ),
            "modified": sum(1 for item in columns if item["change"] == "modified"),
            "fully_broken_linkages": sum(1 for item in linkages if item["fully_broken"]),
        },
    }
