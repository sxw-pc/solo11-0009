"""Deterministic reversible pseudonyms backed by an external mapping database."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping

from .base import TransformContext, TransformError


def pseudonym_token(value: str, key: str) -> str:
    digest = hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return "psn_" + digest[:40]


class PseudonymTransformer:
    name = "pseudonym"
    param_specs = ()

    def transform(
        self, value: Any, params: Mapping[str, Any], context: TransformContext
    ) -> Any:
        if value is None or value == "":
            return value
        if context.secrets is None:
            raise TransformError("pseudonym transformer requires a secret store")
        key = context.secrets.get("pseudonym_key")
        token = pseudonym_token(str(value), key)
        if context.pseudomap is None:
            if context.write_mapping:
                raise TransformError("pseudonym transformer requires a mapping store")
            return token
        if context.write_mapping:
            context.pseudomap.put(token, str(value))
        return token
