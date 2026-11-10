"""Keyed HMAC-SHA256 hashing with a named secret from SecretStore."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Mapping

from .base import ParamSpec, TransformContext, TransformError


class HashingTransformer:
    name = "hash"
    param_specs = (ParamSpec("salt_ref", "str", default="hmac_salt"),)

    def transform(
        self, value: Any, params: Mapping[str, Any], context: TransformContext
    ) -> Any:
        if value is None or value == "":
            return value
        if context.secrets is None:
            raise TransformError("hash transformer requires a secret store")
        key = context.secrets.get(params["salt_ref"]).encode("utf-8")
        message = str(value).encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()
