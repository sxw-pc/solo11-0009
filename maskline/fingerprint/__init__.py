"""Delivery fingerprinting (data watermarking) for masked datasets.

Three independent, offline-verifiable marking channels are embedded into every
delivery:

1. numeric perturbation  -- parity of a quantization grid carries HMAC-derived
   bits on non-protected numeric columns (the primary, statistics-based channel);
2. canary rows           -- synthetic, semantically plausible rows whose cell
   values are stored only as HMAC fingerprints in the delivery manifest;
3. row-order encoding    -- relative order of key-sorted adjacent row pairs.

Verification needs only the suspect file, the delivery manifests and the local
master key. The original sensitive dataset and the pseudonym mapping store are
never read during verification.
"""

from .config import (
    FingerprintConfig,
    FingerprintConfigError,
    NumericColumn,
    load_fingerprint_config,
)
from .manifest import (
    DeliveryManifest,
    ManifestError,
    load_manifest,
    load_manifests,
)
from .embed import EmbedResult, embed_delivery
from .detect import (
    AttributionReport,
    ChannelResult,
    MatchResult,
    detect_attribution,
)

__all__ = [
    "FingerprintConfig",
    "FingerprintConfigError",
    "NumericColumn",
    "load_fingerprint_config",
    "DeliveryManifest",
    "ManifestError",
    "load_manifest",
    "load_manifests",
    "EmbedResult",
    "embed_delivery",
    "AttributionReport",
    "ChannelResult",
    "MatchResult",
    "detect_attribution",
]
