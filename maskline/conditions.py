"""Row-level ``when`` conditions for column policies.

Conditions are strictly declarative: a column reference, one operator from a
fixed whitelist, and an optional literal value. They are parsed into
:class:`Condition` objects and evaluated by fixed dispatch — policy files can
never inject or execute code.

Evaluation semantics:

- conditions always read the row's *original* (pre-transform) values, so the
  result never depends on the order in which columns are transformed;
- a ``NULL`` operand makes every comparison operator not match (the row keeps
  its original value); the ``is_null`` operator exists precisely to match
  ``NULL``/empty values;
- ``gt``/``lt`` compare numerically; values that cannot be coerced to numbers
  never match;
- ``eq``/``ne`` compare numerically when both sides look numeric (so CSV
  string cells match numeric YAML literals), otherwise as strings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .utils import MasklineError

OPERATORS = ("eq", "ne", "gt", "lt", "contains", "is_null")

OPERATOR_LABELS = {
    "eq": "等于",
    "ne": "不等于",
    "gt": "大于",
    "lt": "小于",
    "contains": "包含",
    "is_null": "为空",
}

_VALUE_OPERATORS = ("eq", "ne", "gt", "lt", "contains")


class ConditionError(MasklineError):
    pass


@dataclass(frozen=True)
class Condition:
    column: str
    op: str
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"column": self.column, "op": self.op}
        if self.op != "is_null":
            data["value"] = self.value
        return data

    def describe(self) -> str:
        label = OPERATOR_LABELS.get(self.op, self.op)
        if self.op == "is_null":
            return f"{self.column} {label}"
        rendered = json.dumps(self.value, ensure_ascii=False)
        return f"{self.column} {label} {rendered}"

    def matches(self, original_row: Mapping[str, Any]) -> bool:
        """Evaluate against pre-transform values keyed by column name."""
        if self.column not in original_row:
            # validate_against rejects unknown columns before a run; this is a
            # defensive fallback so a bad row mapping fails closed (no match).
            return False
        return evaluate(self.op, original_row[self.column], self.value)


def evaluate(op: str, cell: Any, value: Any = None) -> bool:
    if op == "is_null":
        return cell is None or cell == ""
    if cell is None:
        return False
    handler = _DISPATCH.get(op)
    if handler is None:
        raise ConditionError(
            f"unknown condition operator {op!r}; valid operators: "
            + ", ".join(OPERATORS)
        )
    return handler(cell, value)


def parse_condition(raw: Any, where: str) -> Condition:
    if not isinstance(raw, Mapping):
        raise ConditionError(f"{where}: 'when' must be a mapping")
    unknown = set(raw) - {"column", "op", "value"}
    if unknown:
        raise ConditionError(
            f"{where}: 'when' has unknown keys: {', '.join(sorted(unknown))}"
        )
    column = raw.get("column")
    if not isinstance(column, str) or not column:
        raise ConditionError(f"{where}: 'when.column' must be a non-empty string")
    op = raw.get("op")
    if op not in OPERATORS:
        raise ConditionError(
            f"{where}: unknown condition operator {op!r}; valid operators: "
            + ", ".join(OPERATORS)
        )
    if op == "is_null":
        if "value" in raw:
            raise ConditionError(
                f"{where}: operator 'is_null' does not take a 'value'"
            )
        return Condition(column, op)
    if "value" not in raw:
        raise ConditionError(f"{where}: operator {op!r} requires a 'value'")
    value = raw["value"]
    if value is None:
        raise ConditionError(
            f"{where}: operator {op!r} cannot compare against null; "
            "use operator 'is_null' to match NULL values"
        )
    if op in ("gt", "lt"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConditionError(
                f"{where}: operator {op!r} requires a numeric 'value'"
            )
    elif op == "contains":
        if not isinstance(value, str) or not value:
            raise ConditionError(
                f"{where}: operator 'contains' requires a non-empty string 'value'"
            )
    elif not isinstance(value, (str, int, float, bool)):
        raise ConditionError(
            f"{where}: operator {op!r} requires a scalar 'value' "
            "(string, number, or boolean)"
        )
    return Condition(column, op, value)


def _to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if text:
            try:
                return float(text)
            except ValueError:
                return None
    return None


def _eq(cell: Any, value: Any) -> bool:
    if isinstance(cell, str) and isinstance(value, str):
        return cell == value
    cell_num = _to_number(cell)
    value_num = _to_number(value)
    if cell_num is not None and value_num is not None:
        return cell_num == value_num
    return str(cell) == str(value)


def _ne(cell: Any, value: Any) -> bool:
    return not _eq(cell, value)


def _gt(cell: Any, value: Any) -> bool:
    cell_num = _to_number(cell)
    value_num = _to_number(value)
    if cell_num is None or value_num is None:
        return False
    return cell_num > value_num


def _lt(cell: Any, value: Any) -> bool:
    cell_num = _to_number(cell)
    value_num = _to_number(value)
    if cell_num is None or value_num is None:
        return False
    return cell_num < value_num


def _contains(cell: Any, value: Any) -> bool:
    text = cell if isinstance(cell, str) else str(cell)
    return value in text


_DISPATCH = {
    "eq": _eq,
    "ne": _ne,
    "gt": _gt,
    "lt": _lt,
    "contains": _contains,
}
