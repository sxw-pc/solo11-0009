"""Transformer protocol, parameter validation, and the transformer registry.

A transformer is any object that declares:

* ``name``        -- the identifier used inside policy YAML;
* ``param_specs`` -- ordered parameter schema used for load-time validation;
* ``transform``   -- the pure, deterministic implementation;
* optional metadata: ``label``, ``version``, ``requires_secret``,
  ``requires_pseudomap``.

Third-party code registers a transformer exactly once via
``register_transformer`` (or ``REGISTRY.register``). Registering the same
name twice raises instead of silently replacing the implementation, so a
resume run can never pick up a different implementation behind the same
identifier.

Each registered transformer gets a stable ``implementation_id`` derived from
its source and schema. Run checkpoints and manifests record those ids; a
resume is refused when an id changed or the transformer no longer exists.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, TYPE_CHECKING, runtime_checkable

from ..utils import MasklineError, canonical_json

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

    def to_record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "required": self.required,
            "default": self.default,
            "choices": tuple(self.choices),
            "minimum": self.minimum,
        }


@runtime_checkable
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


def _source_digest(transformer: Any) -> str | None:
    """Hash the transformer's own source file, when it is readable."""
    try:
        source_file = inspect.getsourcefile(type(transformer))
    except (TypeError, OSError):
        source_file = None
    if not source_file:
        return None
    path = Path(source_file)
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()


def implementation_id(transformer: Any) -> str:
    """Stable identity of a transformer implementation.

    Covers the name, declared schema version, parameter schema, and the
    source file defining the class. Any code or schema change changes this
    id, which makes a resume against an older checkpoint fail loudly.
    """
    payload: dict[str, Any] = {
        "name": transformer.name,
        "version": getattr(transformer, "version", 1),
        "module": type(transformer).__module__,
        "qualname": type(transformer).__qualname__,
        "params": [spec.to_record() for spec in transformer.param_specs],
        "source_sha256": _source_digest(transformer),
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class TransformerRegistry:

    def __init__(self) -> None:
        self._items: dict[str, Transformer] = {}
        self._ids: dict[str, str] = {}

    def register(self, transformer: Any) -> Any:
        """Register a transformer instance, or a transformer class.

        A class is instantiated with no arguments so that the decorator
        ``@register_transformer`` can be applied directly to class
        definitions. The same name may only be registered once; a second
        registration raises instead of replacing the existing entry.

        The original object is returned unchanged (a class stays a class), so
        decorated module attributes remain normal, importable classes.
        """
        original = transformer
        candidate = transformer() if inspect.isclass(transformer) else transformer
        if not isinstance(candidate, Transformer):
            raise TransformError(
                "transformer must expose 'name', 'param_specs' and a "
                "transform(value, params, context) method"
            )
        if not candidate.name or not isinstance(candidate.name, str):
            raise TransformError("a transformer must declare a non-empty string 'name'")
        if candidate.name in self._items:
            raise TransformError(
                f"transformer {candidate.name!r} already registered by "
                f"{type(self._items[candidate.name]).__module__}."
                f"{type(self._items[candidate.name]).__qualname__}; "
                "duplicate registration is not allowed"
            )
        self._items[candidate.name] = candidate
        self._ids[candidate.name] = implementation_id(candidate)
        return original

    def get(self, name: str) -> Transformer:
        try:
            return self._items[name]
        except KeyError as exc:
            raise TransformError(
                f"unknown transformer {name!r}; available: " + ", ".join(self.names())
            ) from exc

    def has(self, name: str) -> bool:
        return name in self._items

    def names(self) -> list[str]:
        return sorted(self._items)

    def label(self, name: str) -> str:
        transformer = self.get(name)
        return getattr(transformer, "label", None) or name

    def requires_secret(self, name: str) -> bool:
        return bool(getattr(self.get(name), "requires_secret", False))

    def requires_pseudomap(self, name: str) -> bool:
        return bool(getattr(self.get(name), "requires_pseudomap", False))

    def implementation_id(self, name: str) -> str:
        self.get(name)
        return self._ids[name]

    def identities(self) -> dict[str, str]:
        return dict(sorted(self._ids.items()))

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


# Process-wide registry. Built-ins register themselves into this instance;
# external plugins do the same through register_transformer/load_plugins.
REGISTRY = TransformerRegistry()


def register_transformer(transformer: Transformer) -> Transformer:
    """Register a transformer instance on the process-wide registry."""
    return REGISTRY.register(transformer)


# Maps a resolved plugin file path to the sys.modules name of its most recent
# execution, so repeat loads are idempotent without stale-module surprises.
_PLUGIN_MODULES: dict[str, str] = {}


def _module_name_for(path: Path) -> str:
    return (
        "maskline_plugin_"
        + hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:16]
    )


def _provided_names(module: Any) -> list[str]:
    """Transformer names a plugin module would register."""
    names: list[str] = []
    for attribute in vars(module).values():
        # Only concrete classes defined in the plugin module itself; ignore
        # imported symbols, instances, and anything that is not instantiable.
        if not inspect.isclass(attribute) or attribute.__module__ != module.__name__:
            continue
        try:
            candidate = attribute()
        except Exception:
            continue
        if isinstance(candidate, Transformer) and isinstance(
            getattr(candidate, "name", None), str
        ):
            names.append(candidate.name)
    return names


def _load_module_from_path(path: Path) -> Any:
    resolved = path.resolve()
    cache_key = str(resolved)
    cached_name = _PLUGIN_MODULES.get(cache_key)
    cached = sys.modules.get(cached_name) if cached_name else None
    if cached is not None and all(
        name in REGISTRY._items for name in _provided_names(cached)
    ):
        # Already loaded and every transformer it provides is still
        # registered: importing again must be an idempotent no-op.
        return cached
    # Either first import, or a previous registration was removed (e.g. by a
    # test). Re-execute under a unique module name so the decorators run
    # again; a genuine same-name/different-implementation collision still
    # raises from the registry instead of overwriting anything.
    base_name = _module_name_for(resolved)
    module_name = base_name
    counter = 1
    while module_name in sys.modules:
        module_name = f"{base_name}_{counter}"
        counter += 1
    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise TransformError(f"cannot load transformer plugin {resolved}: not an importable module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    _PLUGIN_MODULES[cache_key] = module_name
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # plugin errors must surface as TransformError
        sys.modules.pop(module_name, None)
        _PLUGIN_MODULES.pop(cache_key, None)
        raise TransformError(f"cannot load transformer plugin {resolved}: {exc}") from exc
    return module


def load_plugins(paths: str | Path | list[str | Path] | tuple[str | Path, ...] | None) -> list[str]:
    """Import transformer plugin files so their registrations take effect.

    Each path may be a ``.py`` file or a directory; directories are scanned
    non-recursively for ``*.py`` files (excluding ``__init__``). Loading is
    idempotent: already-imported plugin modules are skipped, and duplicate
    registrations raise rather than overwrite. Returns the registered
    transformer names contributed by the loaded plugin modules.
    """
    if paths is None:
        return []
    if isinstance(paths, (str, Path)):
        candidates = [Path(paths)]
    else:
        candidates = [Path(item) for item in paths]
    files: list[Path] = []
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved.is_dir():
            files.extend(
                sorted(
                    item
                    for item in resolved.glob("*.py")
                    if item.is_file() and item.name != "__init__.py"
                )
            )
        elif resolved.is_file():
            files.append(resolved)
        else:
            raise TransformError(f"transformer plugin path does not exist: {resolved}")
    contributed: list[str] = []
    for file_path in files:
        before = set(REGISTRY.names())
        _load_module_from_path(file_path.resolve())
        contributed.extend(sorted(set(REGISTRY.names()) - before))
    return contributed
