"""Audit-chain integration for simulation operations.

Simulation entries are appended to the same tamper-evident JSONL audit log as
formal masking runs. They share the hash-chain machinery of
:mod:`maskline.audit` and are distinguished by ``event_type`` so verifiers and
consumers can tell the two apart. Both successful and failed simulations are
recorded: rule-validation failures, unreadable sources and empty samples must
leave a trace just like successful evaluations.
"""

from __future__ import annotations

from typing import Any

EVENT_TYPE = "policy_impact_simulation"


def build_simulation_audit_entry(
    *,
    simulation_id: str,
    document: dict[str, Any] | None,
    status: str,
    dataset_path: str | None = None,
    dataset_fingerprint: str | None = None,
    policy_name: str | None = None,
    policy_fingerprint: str | None = None,
    policy_path: str | None = None,
    rows_processed: int = 0,
    elapsed_seconds: float = 0.0,
    error: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one audit record for a simulation attempt (success or failure)."""
    if document is not None:
        dataset = document.get("dataset", {})
        policy = document.get("policy", {})
        entry: dict[str, Any] = {
            "event_type": EVENT_TYPE,
            "run_id": simulation_id,
            "simulation_id": simulation_id,
            "dataset_path": dataset.get("path"),
            "dataset_fingerprint": dataset.get("fingerprint"),
            "policy_name": policy.get("name"),
            "policy_fingerprint": policy.get("fingerprint"),
            "policy_path": policy.get("source_path"),
            "status": document.get("status", status),
            "rows_processed": document.get("rows_processed", rows_processed),
            "sample": document.get("sample"),
            "warnings": document.get("warnings", []),
            "linkage_pairs": [item.get("columns") for item in document.get("linkages", [])],
            "elapsed_seconds": round(
                document.get("elapsed_seconds", elapsed_seconds), 6
            ),
            # Simulations never produce formal masking artifacts.
            "output_path": None,
            "output_hash": None,
        }
    else:
        entry = {
            "event_type": EVENT_TYPE,
            "run_id": simulation_id,
            "simulation_id": simulation_id,
            "dataset_path": dataset_path,
            "dataset_fingerprint": dataset_fingerprint,
            "policy_name": policy_name,
            "policy_fingerprint": policy_fingerprint,
            "policy_path": policy_path,
            "status": status,
            "rows_processed": rows_processed,
            "warnings": [],
            "elapsed_seconds": round(elapsed_seconds, 6),
            "output_path": None,
            "output_hash": None,
        }
    if error:
        entry["error"] = error
    if extra:
        entry.update(extra)
    return entry
