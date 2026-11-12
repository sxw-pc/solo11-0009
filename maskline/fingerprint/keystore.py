"""Local master-key custody and audit-log integration for fingerprints.

The fingerprint master key is independent of the masking pipeline's secret
store: the watermarking authority need not be the same person who holds the
pseudonym mapping key. The key file is created with 0600 permissions and its
path is supplied through MASKLINE_FP_KEY or an explicit CLI argument.

Every embedding appends one entry to the *same* append-only hash-chained audit
log used by the masking pipeline, pinning the sealed manifest hash, so a
delivery can be reconciled both ways: audit entry -> manifest -> delivery file.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from ..audit import AuditLog, read_audit_entries
from ..utils import MasklineError, atomic_write_text
from .manifest import DeliveryManifest


class FingerprintKeyError(MasklineError):
    pass


FP_KEY_ENV = "MASKLINE_FP_KEY"
DEFAULT_KEY_NAME = "fingerprint-master.key"
MANIFEST_DIR_NAME = "manifests"
BUNDLE_DIR_NAME = "verification-bundles"


@dataclass(frozen=True)
class FingerprintPaths:
    root: Path

    @classmethod
    def for_workspace(cls, workspace: str | Path | None = None) -> "FingerprintPaths":
        base = Path(workspace) if workspace else Path(
            os.environ.get("MASKLINE_HOME", Path.cwd())
        )
        return cls(base.expanduser().resolve())

    @property
    def fp_dir(self) -> Path:
        return self.root / "fingerprints"

    @property
    def key_path(self) -> Path:
        return self.fp_dir / DEFAULT_KEY_NAME

    @property
    def manifest_dir(self) -> Path:
        return self.fp_dir / MANIFEST_DIR_NAME

    @property
    def bundle_dir(self) -> Path:
        return self.fp_dir / BUNDLE_DIR_NAME

    @property
    def audit_path(self) -> Path:
        return self.root / "audit" / "audit.jsonl"

    def ensure(self) -> None:
        self.fp_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)


def generate_master_key(path: str | Path) -> Path:
    target = Path(path)
    if target.exists():
        raise FingerprintKeyError(
            f"fingerprint key already exists at {target}; refusing to overwrite"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(target, secrets.token_urlsafe(48) + "\n", mode=0o600)
    return target


def resolve_master_key(explicit: str | Path | None = None,
                       workspace_default: str | Path | None = None) -> tuple[str, Path]:
    if explicit is not None:
        path = Path(explicit).expanduser()
    else:
        env = os.environ.get(FP_KEY_ENV)
        if env:
            path = Path(env).expanduser()
        elif workspace_default is not None:
            path = Path(workspace_default)
        else:
            raise FingerprintKeyError(
                f"fingerprint master key not found; pass --key or set {FP_KEY_ENV} "
                "(generate one with 'maskline fp-keygen')"
            )
    if not path.is_file():
        raise FingerprintKeyError(f"fingerprint key file not found: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if len(value) < 32:
        raise FingerprintKeyError("fingerprint master key is too short; regenerate it")
    return value, path


def record_delivery_audit(paths: FingerprintPaths, manifest: DeliveryManifest,
                          output_path: Path, recipient: str | None) -> dict:
    entry = {
        "event": "fingerprint_delivery",
        "delivery_id": manifest.delivery_id,
        "dataset_name": manifest.dataset_name,
        "recipient": recipient,
        "manifest_hash": manifest.manifest_hash,
        "output_hash": manifest.source_delivery_hash,
        "output_path": str(output_path),
        "row_count": manifest.source_row_count,
        "numeric_marked_cells": sum(spec.marked_cells for spec in manifest.numeric_specs),
        "canary_rows": len(manifest.canary_specs),
        "order_pairs": manifest.order_pairs,
        "config_fingerprint": manifest.config_fingerprint,
    }
    return AuditLog(paths.audit_path).append(entry)


def reconcile_manifests_with_audit(paths: FingerprintPaths) -> list[dict]:
    """Cross-check every manifest against the hash-chained audit log.

    Returns one reconciliation row per fingerprint_delivery audit entry.
    Raises if the audit chain is broken or a pinned manifest hash is missing.
    """
    AuditLog(paths.audit_path).verify()
    entries = [
        entry for entry in read_audit_entries(paths.audit_path)
        if entry.get("event") == "fingerprint_delivery"
    ]
    manifest_hashes = {
        path.stem: _safe_manifest_hash(path)
        for path in paths.manifest_dir.glob("*.json")
    }
    rows: list[dict] = []
    for entry in entries:
        delivery_id = entry["delivery_id"]
        on_disk = manifest_hashes.get(delivery_id)
        rows.append({
            "seq": entry["seq"],
            "delivery_id": delivery_id,
            "audit_manifest_hash": entry["manifest_hash"],
            "disk_manifest_hash": on_disk,
            "reconciled": on_disk == entry["manifest_hash"],
            "output_hash": entry.get("output_hash"),
        })
    return rows


def _safe_manifest_hash(path: Path) -> str | None:
    from .manifest import load_manifest
    try:
        return load_manifest(path).manifest_hash
    except MasklineError:
        return None
