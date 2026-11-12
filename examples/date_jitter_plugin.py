"""Example custom transformer: format-preserving date perturbation.

This file is the *entire* integration. It is not imported by the maskline
package; to use it, point the CLI at the file (or its directory):

    maskline run --dataset data.sqlite --policy policy.yaml \\
        --plugin examples/date_jitter_plugin.py

or export::

    MASKLINE_PLUGIN_PATH=examples/date_jitter_plugin.py

Once loaded, policies can reference ``transformer: date_jitter`` exactly like
a built-in. Registration happens through the same registry the built-ins use,
so load-time parameter validation, dispatch, and resume identity checks all
apply automatically.

Semantics: a date is shifted by a deterministic, keyed number of days within
``[-max_days, max_days]``. The same input always perturbs to the same output
(transformers must be deterministic), every supported input format is
preserved byte-for-byte in shape, and unparseable / empty values pass through
unchanged.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Any, Mapping

from maskline.transformers import ParamSpec, TransformContext, register_transformer

# Output template per strptime format, so a "2024/02/29 10:00:00" input stays
# a "YYYY/MM/DD HH:MM:SS" string instead of being normalized to another shape.
_FORMATS: tuple[tuple[str, str], ...] = (
    ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"),
    ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"),
    ("%Y-%m-%d", "%Y-%m-%d"),
    ("%Y/%m/%d", "%Y/%m/%d"),
    ("%Y-%m", "%Y-%m"),
)


@register_transformer
class DateJitterTransformer:
    name = "date_jitter"
    label = "日期扰动"
    version = 1
    param_specs = (
        ParamSpec("max_days", "int", default=7, minimum=1),
        ParamSpec("jitter_key", "str", default="maskline-date-jitter"),
    )

    def transform(
        self, value: Any, params: Mapping[str, Any], context: TransformContext
    ) -> Any:
        if value is None or value == "":
            return value
        text = str(value).strip()
        parsed = None
        template = None
        for parse_fmt, out_fmt in _FORMATS:
            try:
                parsed = datetime.strptime(text, parse_fmt)
                template = out_fmt
                break
            except ValueError:
                continue
        if parsed is None:
            # Unrecognised values pass through untouched, like built-ins.
            return value
        offset = self._offset(text, params)
        return (parsed + timedelta(days=offset)).strftime(template)

    @staticmethod
    def _offset(value: str, params: Mapping[str, Any]) -> int:
        max_days = int(params["max_days"])
        digest = hashlib.sha256(
            f"{params['jitter_key']}\x00{value}".encode("utf-8")
        ).digest()
        # Deterministic integer in [0, 2*max_days], recentered to [-max_days, max_days].
        span = 2 * max_days + 1
        return int.from_bytes(digest[:8], "big") % span - max_days
