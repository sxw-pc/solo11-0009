"""Nullification and numeric rounding transformers."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Mapping

from .base import ParamSpec, TransformContext


class NullifyTransformer:
    name = "nullify"
    param_specs = ()

    def transform(
        self, value: Any, params: Mapping[str, Any], context: TransformContext
    ) -> Any:
        return None


class RoundTransformer:
    name = "round"
    param_specs = (ParamSpec("decimals", "int", default=0, minimum=0),)

    def transform(
        self, value: Any, params: Mapping[str, Any], context: TransformContext
    ) -> Any:
        if value is None or value == "":
            return value
        decimals = params["decimals"]
        if decimals < 0:
            raise ValueError("decimals must be >= 0")
        try:
            number = Decimal(str(value).strip())
        except (InvalidOperation, ValueError):
            return value
        if not number.is_finite():
            return value
        quantum = Decimal(1).scaleb(-decimals)
        rounded = number.quantize(quantum, rounding=ROUND_HALF_UP)
        if decimals == 0:
            return int(rounded)
        return float(rounded)
