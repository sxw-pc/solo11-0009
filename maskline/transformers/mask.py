"""Keep a prefix/suffix and replace the middle with a mask character."""

from __future__ import annotations

from typing import Any, Mapping

from .base import ParamSpec, TransformContext


class MaskTransformer:
    name = "mask"
    param_specs = (
        ParamSpec("keep_prefix", "int", default=0, minimum=0),
        ParamSpec("keep_suffix", "int", default=0, minimum=0),
        ParamSpec("mask_char", "char", default="*"),
    )

    def transform(
        self, value: Any, params: Mapping[str, Any], context: TransformContext
    ) -> Any:
        if value is None or value == "":
            return value
        text = str(value)
        prefix = params["keep_prefix"]
        suffix = params["keep_suffix"]
        char = params["mask_char"]
        if prefix + suffix >= len(text):
            return char * len(text)
        kept_suffix = text[-suffix:] if suffix else ""
        return text[:prefix] + char * (len(text) - prefix - suffix) + kept_suffix
