"""Delivery manifests: the archived, offline-verifiable fingerprint record.

A manifest stores everything needed to verify a leak against one delivery, and
nothing that can reconstruct the master key or the original sensitive values:

* the per-delivery HMAC outputs are derived from a sub-key never written here;
* canary rows appear only as keyed cell fingerprints, never as plaintext;
* numeric parameters store column names, quanta and mark rates, not row values;
* the original dataset and pseudonym mapping store are never referenced for
  verification -- only the marked delivery itself is hashed.

Manifests are content-hashed so audit entries can pin them, and an index file
supports tamper-evident listing alongside the existing append-only audit chain.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..utils import MasklineError, atomic_write_text, canonical_json, sha256_text

MANIFEST_VERSION = 1


class ManifestError(MasklineError):
    pass


@dataclass(frozen=True)
class NumericSpec:
    column: str
    quantum: float
    mark_rate: float
    integer: bool
    # Number of cells actually marked in this column during embedding.
    marked_cells: int
    # Mean absolute perturbation actually applied, for analytic-impact review.
    mean_abs_delta: float
    max_abs_delta: float


@dataclass(frozen=True)
class CanarySpec:
    # Keyed token used as the row-key value of the canary row.
    key_token: str
    # column -> keyed fingerprint of the canonical generated value.
    cell_fingerprints: dict[str, str]
    row_fingerprint: str
    # Numeric sentinels used when the key column is cropped: column -> value.
    # Their keyed fingerprints live in cell_fingerprints; numeric values are
    # stored here only because the manifest already records numeric parameters
    # and the values themselves are synthetic (never derived from real rows).
    numeric_sentinels: dict[str, float] = field(default_factory=dict)


@dataclass
class DeliveryManifest:
    delivery_id: str
    dataset_name: str
    config_fingerprint: str
    created_at: str
    source_delivery_hash: str
    source_row_count: int
    key_column: str
    protected_columns: list[str]
    numeric_specs: list[NumericSpec]
    canary_specs: list[CanarySpec]
    order_pairs: int
    output_format: str
    notes: str = ""
    # Anchor columns in preference order (key column first).
    anchor_columns: list[str] = field(default_factory=list)
    # Fallback anchor index, only for non-key anchors:
    # column -> [{digest: keyed digest of the anchor value, seeds: [row seeds]}]
    anchor_index: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Filled in when the manifest is written.
    manifest_hash: str = ""
    version: int = MANIFEST_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data

    def content_hash(self) -> str:
        payload = self.to_dict()
        payload.pop("manifest_hash", None)
        return sha256_text(canonical_json(payload))

    def seal(self) -> "DeliveryManifest":
        self.manifest_hash = self.content_hash()
        return self


def manifest_filename(delivery_id: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in delivery_id)
    return f"{safe}.json"


def write_manifest(manifest: DeliveryManifest, directory: str | Path) -> Path:
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest.seal()
    target = out_dir / manifest_filename(manifest.delivery_id)
    atomic_write_text(
        target,
        json.dumps(manifest.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        mode=0o600,
    )
    return target


def load_manifest(path: str | Path) -> DeliveryManifest:
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {source}: {exc}") from exc
    return manifest_from_dict(raw, source)


def manifest_from_dict(raw: dict[str, Any], source: Path | None = None) -> DeliveryManifest:
    required = {
        "delivery_id", "dataset_name", "config_fingerprint", "created_at",
        "source_delivery_hash", "source_row_count", "key_column",
        "protected_columns", "numeric_specs", "canary_specs", "order_pairs",
        "output_format",
    }
    missing = required - set(raw)
    if missing:
        where = f" {source}" if source else ""
        raise ManifestError(f"manifest{where} missing fields: {sorted(missing)}")
    numeric = [
        NumericSpec(
            column=item["column"],
            quantum=float(item["quantum"]),
            mark_rate=float(item["mark_rate"]),
            integer=bool(item["integer"]),
            marked_cells=int(item["marked_cells"]),
            mean_abs_delta=float(item["mean_abs_delta"]),
            max_abs_delta=float(item["max_abs_delta"]),
        )
        for item in raw["numeric_specs"]
    ]
    canaries = [
        CanarySpec(
            key_token=item["key_token"],
            cell_fingerprints=dict(item["cell_fingerprints"]),
            row_fingerprint=item["row_fingerprint"],
            numeric_sentinels={
                str(col): float(val) for col, val in item.get("numeric_sentinels", {}).items()
            },
        )
        for item in raw["canary_specs"]
    ]
    manifest = DeliveryManifest(
        delivery_id=str(raw["delivery_id"]),
        dataset_name=str(raw["dataset_name"]),
        config_fingerprint=str(raw["config_fingerprint"]),
        created_at=str(raw["created_at"]),
        source_delivery_hash=str(raw["source_delivery_hash"]),
        source_row_count=int(raw["source_row_count"]),
        key_column=str(raw["key_column"]),
        protected_columns=[str(item) for item in raw["protected_columns"]],
        numeric_specs=numeric,
        canary_specs=canaries,
        order_pairs=int(raw["order_pairs"]),
        output_format=str(raw["output_format"]),
        notes=str(raw.get("notes", "")),
        anchor_columns=[str(item) for item in raw.get("anchor_columns", [])],
        anchor_index={
            str(column): [dict(entry) for entry in entries]
            for column, entries in raw.get("anchor_index", {}).items()
        },
        manifest_hash=str(raw.get("manifest_hash", "")),
        version=int(raw.get("version", MANIFEST_VERSION)),
    )
    if manifest.manifest_hash and manifest.content_hash() != manifest.manifest_hash:
        raise ManifestError(
            f"manifest {source or manifest.delivery_id}: content hash mismatch; "
            "the archived record has been altered"
        )
    return manifest


def load_manifests(directory: str | Path) -> list[DeliveryManifest]:
    base = Path(directory)
    if not base.exists():
        raise ManifestError(f"manifest directory not found: {base}")
    manifests = [load_manifest(path) for path in sorted(base.glob("*.json"))]
    if not manifests:
        raise ManifestError(f"no manifests found under {base}")
    return manifests


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
