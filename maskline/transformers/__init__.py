"""Built-in transformer registry."""

from __future__ import annotations

from .base import (
    ParamSpec,
    TransformContext,
    TransformError,
    TransformerRegistry,
    resolve_params,
)
from .generalize import GeneralizeTransformer
from .hashing import HashingTransformer
from .mask import MaskTransformer
from .nullify import NullifyTransformer, RoundTransformer
from .pseudonym import PseudonymTransformer

REGISTRY = TransformerRegistry()
for _transformer in (
    MaskTransformer(),
    HashingTransformer(),
    GeneralizeTransformer(),
    PseudonymTransformer(),
    NullifyTransformer(),
    RoundTransformer(),
):
    REGISTRY.register(_transformer)

__all__ = [
    "ParamSpec",
    "REGISTRY",
    "TransformContext",
    "TransformError",
    "TransformerRegistry",
    "resolve_params",
]
