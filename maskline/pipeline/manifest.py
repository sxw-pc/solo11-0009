"""Per-dataset run manifests, including policy version changes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..policies import Policy
from ..registry import DatasetInventory
from ..utils import atomic_write_text, read_json


def manifest_path(manifest_dir: Path, dataset_fingerprint: str) -> Path:
    return manifest_dir / f"{dataset_fingerprint[:16]}.json"


def previous_manifest(manifest_dir: Path, dataset_fingerprint: str) -> dict[str, Any] | None:
    return read_json(manifest_path(manifest_dir, dataset_fingerprint))


def policy_changed(
    manifest_dir: Path, dataset_fingerprint: str, policy_fingerprint: str
) -> bool:
    previous = previous_manifest(manifest_dir, dataset_fingerprint)
    if not previous:
        return False
    return previous.get("policy_fingerprint") != policy_fingerprint


def write_manifest(
    manifest_dir: Path,
    inventory: DatasetInventory,
    policy: Policy,
    run_id: str,
    output_path: Path,
    output_hash: str,
    row_count: int,
    transformer_map: dict[str, dict[str, str]],
    transform_counts: dict[str, dict[str, int]],
    checksum_mode: str = "",
    pseudomap_count: int | None = None,
    pseudomap_digest: str | None = None,
    tables_detail: dict[str, dict[str, Any]] | None = None,
) -> tuple[Path, bool]:
    previous = previous_manifest(manifest_dir, inventory.fingerprint)
    changed = bool(
        previous and previous.get("policy_fingerprint") != policy.fingerprint
    )
    data = {
        "run_id": run_id,
        "dataset": str(inventory.path),
        "dataset_fingerprint": inventory.fingerprint,
        "policy_name": policy.name,
        "policy_path": str(policy.source_path),
        "policy_fingerprint": policy.fingerprint,
        "policy_changed": changed,
        "previous_policy_fingerprint": (previous or {}).get("policy_fingerprint"),
        "output": str(output_path),
        "output_hash": output_hash,
        "row_count": row_count,
        "transformers": transformer_map,
        "transform_counts": transform_counts,
        "checksum_mode": checksum_mode,
        "pseudomap_count": pseudomap_count,
        "pseudomap_digest": pseudomap_digest,
        "tables": tables_detail or {},
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    target = manifest_path(manifest_dir, inventory.fingerprint)
    atomic_write_text(target, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    return target, changed
