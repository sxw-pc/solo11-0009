"""Generalizers for dates, ages, monetary amounts, and addresses."""

from __future__ import annotations

import re
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from .base import ParamSpec, TransformContext, TransformError

DATE_FORMATS = ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m")
PROVINCE_RE = re.compile(r"^.{2,10}?(?:省|自治区|特别行政区)")
CITY_RE = re.compile(r"^([一-龥]{2,10}?(?:市|自治州|地区|盟))")


def _parse_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def _decimal_text(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    return "0" if text in {"-0", ""} else text


class GeneralizeTransformer:
    name = "generalize"
    param_specs = (
        ParamSpec("mode", "str", required=True, choices=("date", "age", "amount", "address")),
        ParamSpec("level", "str", default="month", choices=("month", "quarter", "year")),
        ParamSpec("width", "int", default=100, minimum=1),
        ParamSpec("unknown_label", "str", default="其他地区"),
    )

    def transform(
        self, value: Any, params: Mapping[str, Any], context: TransformContext
    ) -> Any:
        if value is None or value == "":
            return value
        mode = params["mode"]
        if mode == "date":
            return self._date(value, params["level"])
        if mode == "age":
            return self._age(value, params["width"])
        if mode == "amount":
            return self._amount(value, params["width"])
        if mode == "address":
            return self._address(value, params["unknown_label"])
        raise TransformError(f"unsupported generalize mode: {mode!r}")

    def _date(self, value: Any, level: str) -> Any:
        parsed = _parse_date(value)
        if parsed is None:
            return value
        if level == "year":
            return f"{parsed.year:04d}"
        if level == "quarter":
            return f"{parsed.year:04d}-Q{(parsed.month - 1) // 3 + 1}"
        return f"{parsed.year:04d}-{parsed.month:02d}"

    def _age(self, value: Any, width: int) -> Any:
        if width <= 0:
            raise ValueError("age width must be positive")
        try:
            age = int(str(value).strip())
        except (TypeError, ValueError):
            return value
        if age < 0:
            return value
        lower = (age // width) * width
        return f"{lower}-{lower + width - 1}"

    def _amount(self, value: Any, width: int) -> Any:
        if width <= 0:
            raise ValueError("amount width must be positive")
        try:
            amount = Decimal(str(value).strip())
            bucket = Decimal(width)
        except (InvalidOperation, ValueError):
            return value
        if not amount.is_finite():
            return value
        lower = (amount // bucket) * bucket
        upper = lower + bucket
        return f"{_decimal_text(lower)}-{_decimal_text(upper - Decimal(1))}"

    def _address(self, value: Any, unknown_label: str) -> Any:
        text = str(value).strip()
        remainder = PROVINCE_RE.sub("", text, count=1)
        city = CITY_RE.match(remainder) or CITY_RE.match(text)
        if city:
            return city.group(1)
        return unknown_label
