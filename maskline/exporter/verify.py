"""Verify an exported subset against its provenance manifest.

This reuses the exact integrity primitives that protect masked products
(``sqlite_content_digest`` for SQLite subsets, ``file_sha256`` for CSV
subsets), so a subset never needs a format-specific verifier.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..utils import file_sha256, sqlite_content_digest
from .errors import ExportError


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ExportError(
            "EXPORT_VERIFY_FAILED", f"export manifest not found: {path}"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExportError(
            "EXPORT_VERIFY_FAILED", f"cannot read export manifest {path}: {exc}"
        ) from exc
    if not isinstance(data, dict) or data.get("kind") != "maskline.export":
        raise ExportError(
            "EXPORT_VERIFY_FAILED", f"not a maskline export manifest: {path}"
        )
    return data


def verify_subset(manifest_path: str | Path) -> dict[str, Any]:
    """Recompute the subset integrity identifier and compare it with the record."""
    path = Path(manifest_path).expanduser().resolve()
    manifest = _load_manifest(path)
    subset = manifest.get("subset") or {}
    integrity = (subset.get("integrity") or {}).get("value")
    fmt = subset.get("format")
    if not integrity or fmt not in {"sqlite", "csv"}:
        raise ExportError(
            "EXPORT_VERIFY_FAILED", f"export manifest {path} has no usable integrity record"
        )
    candidates = []
    recorded = subset.get("path")
    if recorded:
        candidates.append(Path(recorded))
    if subset.get("file"):
        candidates.append(path.parent / subset["file"])
    subset_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if subset_path is None:
        raise ExportError(
            "EXPORT_VERIFY_FAILED",
            f"subset file not found (tried: "
            + ", ".join(str(candidate) for candidate in candidates) + ")",
        )
    actual = (
        sqlite_content_digest(subset_path)
        if fmt == "sqlite"
        else file_sha256(subset_path)
    )
    if actual != integrity:
        raise ExportError(
            "EXPORT_VERIFY_FAILED",
            f"subset {subset_path} failed integrity check: expected {integrity}, "
            f"computed {actual}",
        )
    return {
        "export_id": manifest.get("export_id"),
        "subset": subset_path,
        "format": fmt,
        "integrity": actual,
        "row_count": subset.get("row_count"),
        "ok": True,
    }
