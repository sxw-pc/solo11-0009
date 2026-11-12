"""Built-in transformer registry and the public transformer extension API.

Importing this package imports every built-in transformer module, and each
module registers itself on the shared ``REGISTRY`` via ``@register_transformer``.

Adding a custom transformer does not require editing this package: create one
module that calls :func:`register_transformer` (or ``REGISTRY.register``) and
load it with :func:`load_plugins` (CLI ``--plugin`` /
``MASKLINE_PLUGIN_PATH``). Policy validation and dispatch then pick it up
automatically.
"""

from __future__ import annotations

# Import order is not significant: each module self-registers, and duplicate
# names would raise at import time instead of overwriting each other.
from . import (  # noqa: F401
    generalize as _generalize,
    hashing as _hashing,
    mask as _mask,
    nullify as _nullify,
    pseudonym as _pseudonym,
)
from .base import (
    REGISTRY,
    ParamSpec,
    TransformContext,
    TransformError,
    Transformer,
    TransformerRegistry,
    implementation_id,
    load_plugins,
    register_transformer,
    resolve_params,
)
from .generalize import GeneralizeTransformer
from .hashing import HashingTransformer
from .mask import MaskTransformer
from .nullify import NullifyTransformer, RoundTransformer
from .pseudonym import PseudonymTransformer, pseudonym_token

__all__ = [
    "REGISTRY",
    "GeneralizeTransformer",
    "HashingTransformer",
    "MaskTransformer",
    "NullifyTransformer",
    "ParamSpec",
    "PseudonymTransformer",
    "RoundTransformer",
    "TransformContext",
    "TransformError",
    "Transformer",
    "TransformerRegistry",
    "implementation_id",
    "load_plugins",
    "pseudonym_token",
    "register_transformer",
    "resolve_params",
]
