"""Tiny custom transformer used by the registry/plugin tests.

One file, one registration: nothing in the maskline package references it.
Tests load it through the public ``load_plugins`` entry point.
"""

from __future__ import annotations

from typing import Any, Mapping

from maskline.transformers import ParamSpec, TransformContext, register_transformer


@register_transformer
class UpperCaseTransformer:
    name = "upper_case"
    label = "大写化"
    version = 1
    param_specs = (ParamSpec("suffix", "str", default=""),)

    def transform(
        self, value: Any, params: Mapping[str, Any], context: TransformContext
    ) -> Any:
        if value is None or value == "":
            return value
        return str(value).upper() + params["suffix"]
