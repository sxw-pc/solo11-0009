"""Transformer protocol, parameter validation, and the transformer registry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, TYPE_CHECKING

from ..utils import MasklineError

if TYPE_CHECKING:
    from ..config import SecretStore
    from ..pseudomap import PseudoMap


class TransformError(MasklineError):
    pass


@dataclass
class TransformContext:
    secrets: "SecretStore | None" = None
    pseudomap: "PseudoMap | None" = None
    table: str = ""
    column: str = ""
    write_mapping: bool = True
    run_id: str = ""
    @property
    def dry_run(self) -> bool:
        return not self.write_mapping


@dataclass(frozen=True)
class ParamSpec:
    name: str
    kind: str = "str"
    required: bool = False
    default: Any = None
    choices: tuple[Any, ...] = ()
    minimum: int | None = None


class Transformer(Protocol):
    name: str
    param_specs: tuple[ParamSpec, ...]

    def transform(self, value: Any, params: Mapping[str, Any], context: TransformContext) -> Any:
        ...


def resolve_params(specs: tuple[ParamSpec, ...], params: Mapping[str, Any] | None) -> dict[str, Any]:
    if params is None:
        params = {}
    if not isinstance(params, Mapping):
        raise TransformError("transformer params must be a mapping")
    allowed = {spec.name: spec for spec in specs}
    unknown = sorted(set(params) - set(allowed))
    if unknown:
        raise TransformError("unknown transformer parameter(s): " + ", ".join(unknown))
    resolved: dict[str, Any] = {}
    for spec in specs:
        if spec.name in params:
            value = params[spec.name]
        elif spec.required:
            raise TransformError(f"missing required parameter {spec.name!r}")
        else:
            value = spec.default
        if value is not None:
            value = _check_type(spec, value)
        if spec.minimum is not None and value is not None and value < spec.minimum:
            raise TransformError(
                f"parameter {spec.name!r} must be >= {spec.minimum}"
            )
        if spec.choices and value not in spec.choices:
            raise TransformError(
                f"parameter {spec.name!r} must be one of: "
                + ", ".join(repr(choice) for choice in spec.choices)
            )
        resolved[spec.name] = value
    return resolved


def _check_type(spec: ParamSpec, value: Any) -> Any:
    if spec.kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise TransformError(f"parameter {spec.name!r} must be an integer")
        return value
    if spec.kind == "float":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TransformError(f"parameter {spec.name!r} must be a number")
        return value
    if spec.kind == "str":
        if not isinstance(value, str):
            raise TransformError(f"parameter {spec.name!r} must be a string")
        return value
    if spec.kind == "char":
        if not isinstance(value, str) or len(value) != 1:
            raise TransformError(f"parameter {spec.name!r} must be one character")
        return value
    if spec.kind == "bool":
        if not isinstance(value, bool):
            raise TransformError(f"parameter {spec.name!r} must be a boolean")
        return value
    raise TransformError(f"internal error: unsupported parameter kind {spec.kind!r}")


class TransformerRegistry:

    def __init__(self) -> None:
        self._items: dict[str, Transformer] = {}

    def register(self, transformer: Transformer) -> None:
        if transformer.name in self._items:
            raise TransformError(f"transformer {transformer.name!r} already registered")
        self._items[transformer.name] = transformer

    def get(self, name: str) -> Transformer:
        try:
            return self._items[name]
        except KeyError as exc:
            raise TransformError(
                f"unknown transformer {name!r}; available: " + ", ".join(self.names())
            ) from exc

    def names(self) -> list[str]:
        return sorted(self._items)

    def validate_params(self, name: str, params: Mapping[str, Any] | None) -> dict[str, Any]:
        return resolve_params(self.get(name).param_specs, params)

    def transform(
        self,
        name: str,
        value: Any,
        params: Mapping[str, Any] | None,
        context: TransformContext | None = None,
    ) -> Any:
        transformer = self.get(name)
        resolved = resolve_params(transformer.param_specs, params)
        return transformer.transform(value, resolved, context or TransformContext())
