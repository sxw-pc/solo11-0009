"""Safe row-filter expressions for subset exports.

Grammar (keywords AND/OR/IN/CONTAINS/NULL are case-insensitive)::

    or_expr    := and_expr (OR and_expr)*
    and_expr   := factor (AND factor)*
    factor     := "(" or_expr ")" | comparison
    comparison := column (OP value | IN "(" value [, ...] ")" | CONTAINS string)
    OP         := "=" | "!=" | "<" | "<=" | ">" | ">="
    value      := number | 'string' | NULL
    column     := bare identifier | "double-quoted identifier"

Filters are parsed into an AST and evaluated per row in Python; nothing is
ever interpolated into SQL, so filter text cannot inject into the source
database. Evaluation rules:

- ``col = NULL`` matches rows where the value is NULL; ``col != NULL``
  matches non-NULL values. Any other operator against NULL never matches.
- Rows whose value is NULL never match comparisons against non-NULL literals
  (SQL three-valued logic).
- Numeric literal: the row value is coerced with ``float()``; values that
  cannot be parsed as numbers never match any operator (including ``!=``).
  This keeps filters meaningful on CSV-origin tables where every column is
  stored as TEXT.
- String literal: comparison happens on the string form of the row value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

from ..utils import MasklineError


class FilterSyntaxError(MasklineError):
    pass


_KEYWORDS = {"AND", "OR", "IN", "CONTAINS", "NULL"}
_BARE_IDENT = re.compile(r"\w+", re.UNICODE)
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


@dataclass(frozen=True)
class _Token:
    kind: str  # IDENT QIDENT STRING NUMBER OP LPAREN RPAREN COMMA KEYWORD EOF
    text: str
    value: Any = None


def _tokenize(text: str) -> Iterator[_Token]:
    pos = 0
    length = len(text)
    while pos < length:
        char = text[pos]
        if char.isspace():
            pos += 1
            continue
        if char == "(":
            yield _Token("LPAREN", char)
            pos += 1
            continue
        if char == ")":
            yield _Token("RPAREN", char)
            pos += 1
            continue
        if char == ",":
            yield _Token("COMMA", char)
            pos += 1
            continue
        if char in "=!<>":
            if text.startswith("!=", pos) or text.startswith("<=", pos) or text.startswith(">=", pos):
                yield _Token("OP", text[pos : pos + 2])
                pos += 2
                continue
            if char in "=<>":
                yield _Token("OP", char)
                pos += 1
                continue
            raise FilterSyntaxError(f"unexpected character {char!r} at position {pos}")
        if char == "'":
            end = pos + 1
            parts: list[str] = []
            while True:
                if end >= length:
                    raise FilterSyntaxError("unterminated string literal")
                if text[end] == "'":
                    if end + 1 < length and text[end + 1] == "'":
                        parts.append("'")
                        end += 2
                        continue
                    break
                parts.append(text[end])
                end += 1
            yield _Token("STRING", text[pos : end + 1], "".join(parts))
            pos = end + 1
            continue
        if char == '"':
            end = pos + 1
            parts = []
            while True:
                if end >= length:
                    raise FilterSyntaxError("unterminated quoted identifier")
                if text[end] == '"':
                    if end + 1 < length and text[end + 1] == '"':
                        parts.append('"')
                        end += 2
                        continue
                    break
                parts.append(text[end])
                end += 1
            yield _Token("QIDENT", text[pos : end + 1], "".join(parts))
            pos = end + 1
            continue
        number = _NUMBER.match(text, pos)
        if number:
            raw = number.group(0)
            value = float(raw) if "." in raw else int(raw)
            yield _Token("NUMBER", raw, value)
            pos = number.end()
            continue
        ident = _BARE_IDENT.match(text, pos)
        if ident:
            raw = ident.group(0)
            if raw.upper() in _KEYWORDS:
                yield _Token("KEYWORD", raw.upper())
            else:
                yield _Token("IDENT", raw, raw)
            pos = ident.end()
            continue
        raise FilterSyntaxError(f"unexpected character {char!r} at position {pos}")
    yield _Token("EOF", "")


# AST nodes are tuples:
#   ("and", (node, ...)) | ("or", (node, ...))
#   ("cmp", column, op, literal) | ("in", column, (literal, ...))
#   ("contains", column, str)


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> _Token:
        return self.tokens[self.pos]

    def advance(self) -> _Token:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def expect(self, kind: str, text: str | None = None) -> _Token:
        token = self.peek()
        if token.kind != kind or (text is not None and token.text != text):
            wanted = text or kind
            raise FilterSyntaxError(
                f"expected {wanted}, found {token.text!r}" if token.text else f"expected {wanted}"
            )
        return self.advance()

    def parse(self) -> Any:
        node = self.parse_or()
        if self.peek().kind != "EOF":
            raise FilterSyntaxError(f"unexpected trailing input: {self.peek().text!r}")
        return node

    def parse_or(self) -> Any:
        nodes = [self.parse_and()]
        while self.peek().kind == "KEYWORD" and self.peek().text == "OR":
            self.advance()
            nodes.append(self.parse_and())
        return nodes[0] if len(nodes) == 1 else ("or", tuple(nodes))

    def parse_and(self) -> Any:
        nodes = [self.parse_factor()]
        while self.peek().kind == "KEYWORD" and self.peek().text == "AND":
            self.advance()
            nodes.append(self.parse_factor())
        return nodes[0] if len(nodes) == 1 else ("and", tuple(nodes))

    def parse_factor(self) -> Any:
        token = self.peek()
        if token.kind == "LPAREN":
            self.advance()
            node = self.parse_or()
            self.expect("RPAREN")
            return node
        return self.parse_comparison()

    def parse_column(self) -> str:
        token = self.peek()
        if token.kind in {"IDENT", "QIDENT"}:
            self.advance()
            return token.value
        raise FilterSyntaxError(f"expected a column name, found {token.text!r}")

    def parse_value(self) -> Any:
        token = self.peek()
        if token.kind == "NUMBER":
            self.advance()
            return token.value
        if token.kind == "STRING":
            self.advance()
            return token.value
        if token.kind == "KEYWORD" and token.text == "NULL":
            self.advance()
            return None
        raise FilterSyntaxError(f"expected a value, found {token.text!r}")

    def parse_comparison(self) -> Any:
        column = self.parse_column()
        token = self.peek()
        if token.kind == "OP":
            self.advance()
            return ("cmp", column, token.text, self.parse_value())
        if token.kind == "KEYWORD" and token.text == "IN":
            self.advance()
            self.expect("LPAREN")
            values = [self.parse_value()]
            while self.peek().kind == "COMMA":
                self.advance()
                values.append(self.parse_value())
            self.expect("RPAREN")
            return ("in", column, tuple(values))
        if token.kind == "KEYWORD" and token.text == "CONTAINS":
            self.advance()
            value = self.parse_value()
            if not isinstance(value, str):
                raise FilterSyntaxError("CONTAINS expects a string literal")
            return ("contains", column, value)
        raise FilterSyntaxError(f"expected an operator, found {token.text!r}")


def _to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _eval_cmp(op: str, row_value: Any, literal: Any) -> bool:
    if literal is None:  # NULL literal
        if op == "=":
            return row_value is None
        if op == "!=":
            return row_value is not None
        return False
    if row_value is None:
        return False
    if isinstance(literal, (int, float)) and not isinstance(literal, bool):
        left = _to_number(row_value)
        if left is None:
            return False
        right: Any = float(literal)
    else:
        left = row_value if isinstance(row_value, str) else str(row_value)
        right = literal
    if op == "=":
        return left == right
    if op == "!=":
        return left != right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    raise FilterSyntaxError(f"unsupported operator {op!r}")


def _evaluate(node: Any, row: dict[str, Any]) -> bool:
    kind = node[0]
    if kind == "and":
        return all(_evaluate(child, row) for child in node[1])
    if kind == "or":
        return any(_evaluate(child, row) for child in node[1])
    if kind == "cmp":
        _tag, column, op, literal = node
        return _eval_cmp(op, row.get(column), literal)
    if kind == "in":
        _tag, column, literals = node
        return any(_eval_cmp("=", row.get(column), literal) for literal in literals)
    if kind == "contains":
        _tag, column, needle = node
        value = row.get(column)
        if value is None:
            return False
        text = value if isinstance(value, str) else str(value)
        return needle in text
    raise FilterSyntaxError(f"unsupported filter node {kind!r}")


def _columns_of(node: Any, found: set[str]) -> None:
    kind = node[0]
    if kind in {"and", "or"}:
        for child in node[1]:
            _columns_of(child, found)
    else:
        found.add(node[1])


class RowFilter:
    """A compiled filter expression ready for per-row evaluation."""

    def __init__(self, source: str, ast: Any) -> None:
        self.source = source
        self._ast = ast
        columns: set[str] = set()
        _columns_of(ast, columns)
        self.columns = frozenset(columns)

    def matches(self, row: dict[str, Any]) -> bool:
        return _evaluate(self._ast, row)

    def __repr__(self) -> str:
        return f"RowFilter({self.source!r})"


def compile_filter(text: str) -> RowFilter:
    if not isinstance(text, str) or not text.strip():
        raise FilterSyntaxError("filter expression must be a non-empty string")
    parser = _Parser(list(_tokenize(text)))
    return RowFilter(text, parser.parse())
