"""Versioned detector rule packs.

Existing built-in detectors remain the default rule set.  A rule pack describes
an overlay (new detectors, adjusted regexes, lexicons or validators) on top of a
base version.  At creation time the fully resolved detector snapshot is stored,
so historical versions do not silently change when Python source rules change.

Rule pack format (``version: 1``)::

    version: 1
    rule_version: "mobile-v2"
    name: "mobile rule adjustment"
    description: "..."
    base: "builtin-v1"
    created_by: "alice"
    detectors:
      mobile_phone:
        pattern: "(?<!\\d)1[3-9]\\d{9}(?!\\d)"
      ipv4:
        disabled: true
      new_badge:
        kind: regex
        pattern: "(?<!\\d)BADGE-\\d{6}(?!\\d)"
        validator: none
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .detectors.lexicon import (
    LEXICON_DETECTORS,
    SURNAMES,
    AddressDetector,
    PersonNameDetector,
)
from .detectors.patterns import (
    DETECTORS,
    VALIDATORS,
    RegexDetector,
    flags_from_text,
    flags_to_text,
)
from .utils import MasklineError, canonical_json

BUILTIN_VERSION = "builtin-v1"
ACTIVE_VERSION_ALIAS = "active"
SYSTEM_ACTOR = "system"
RESERVED_VERSION_TAGS = {BUILTIN_VERSION, ACTIVE_VERSION_ALIAS}
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_DETECTOR_KINDS = {"regex", "person_name", "address"}
_REGEX_KEYS = {
    "kind",
    "disabled",
    "pattern",
    "flags",
    "validator",
    "require_fullmatch",
    "value_pattern",
    "min_length",
    "max_length",
}
_NAME_KEYS = {"kind", "disabled", "pattern", "flags", "surnames"}
_ADDRESS_KEYS = {"kind", "disabled", "pattern", "flags", "min_length"}
_ALL_OVERLAY_KEYS = _REGEX_KEYS | _NAME_KEYS | _ADDRESS_KEYS


class RuleError(MasklineError):
    pass


class RulePermissionError(RuleError):
    pass


def is_valid_version_tag(tag: Any) -> bool:
    return isinstance(tag, str) and bool(_VERSION_RE.fullmatch(tag))


@dataclass(frozen=True)
class RuleSet:
    version: str
    detectors: tuple[Any, ...]
    spec: dict[str, Any]
    fingerprint: str
    base_version: str = ""

    def detector_types(self) -> tuple[str, ...]:
        return tuple(detector.sensitive_type for detector in self.detectors)

    def summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "fingerprint": self.fingerprint,
            "base_version": self.base_version,
            "detectors": [detector.sensitive_type for detector in self.detectors],
            "spec": self.spec,
        }


@dataclass(frozen=True)
class RulePack:
    rule_version: str
    name: str
    description: str
    base: str
    created_by: str | None
    detectors: Mapping[str, Any]
    source_path: Path
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def fingerprint_spec(spec: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(spec).encode("utf-8")).hexdigest()


def _kind_of(detector: Any) -> str:
    if isinstance(detector, RegexDetector):
        return "regex"
    if isinstance(detector, PersonNameDetector):
        return "person_name"
    if isinstance(detector, AddressDetector):
        return "address"
    raise RuleError(f"unsupported detector type: {type(detector).__name__}")


def _detector_to_spec(detector: Any) -> dict[str, Any]:
    kind = _kind_of(detector)
    if kind == "regex":
        spec: dict[str, Any] = {
            "sensitive_type": detector.sensitive_type,
            "kind": "regex",
            "pattern": detector.pattern.pattern,
            "flags": flags_to_text(detector.pattern.flags),
            "validator": detector.validator_name,
            "require_fullmatch": bool(detector.require_fullmatch),
            "value_pattern": (
                detector.value_pattern.pattern
                if detector.value_pattern is not None
                else None
            ),
            "min_length": int(detector.min_length),
            "max_length": detector.max_length,
        }
        return spec
    if kind == "person_name":
        return {
            "sensitive_type": detector.sensitive_type,
            "kind": "person_name",
            "pattern": detector.pattern.pattern,
            "flags": flags_to_text(detector.pattern.flags),
            "surnames": sorted(detector.surnames),
        }
    return {
        "sensitive_type": detector.sensitive_type,
        "kind": "address",
        "pattern": detector.pattern.pattern,
        "flags": flags_to_text(detector.pattern.flags),
        "min_length": int(detector.min_length),
    }


def detectors_to_spec(detectors: Sequence[Any]) -> dict[str, Any]:
    return {"detectors": [_detector_to_spec(detector) for detector in detectors]}


@lru_cache(maxsize=1)
def builtin_rule_spec() -> dict[str, Any]:
    return detectors_to_spec((*DETECTORS, *LEXICON_DETECTORS))


@lru_cache(maxsize=1)
def builtin_rule_set() -> RuleSet:
    detectors = tuple(DETECTORS) + tuple(LEXICON_DETECTORS)
    spec = detectors_to_spec(detectors)
    return RuleSet(
        version=BUILTIN_VERSION,
        detectors=detectors,
        spec=spec,
        fingerprint=fingerprint_spec(spec),
        base_version="",
    )


def _allowed_keys(kind: str) -> set[str]:
    if kind == "regex":
        return _REGEX_KEYS
    if kind == "person_name":
        return _NAME_KEYS
    if kind == "address":
        return _ADDRESS_KEYS
    raise RuleError(f"unknown detector kind: {kind!r}")


def _normalize_surnames(value: Any, where: str) -> list[str]:
    if isinstance(value, str):
        items: list[Any] = list(value)
    elif isinstance(value, list):
        items = value
    else:
        raise RuleError(f"{where}.surnames must be a string or list of strings")
    normalized: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item:
            raise RuleError(f"{where}.surnames must contain non-empty strings")
        normalized.append(item)
    if not normalized:
        raise RuleError(f"{where}.surnames must not be empty")
    return normalized


def _validate_kind_value(value: Any, where: str) -> str:
    if not isinstance(value, str) or value not in _DETECTOR_KINDS:
        raise RuleError(
            f"{where}.kind must be one of: {', '.join(sorted(_DETECTOR_KINDS))}"
        )
    return value


def validate_detector_spec(spec: Mapping[str, Any], where: str) -> None:
    if not isinstance(spec, Mapping):
        raise RuleError(f"{where} must be a mapping")
    sensitive_type = spec.get("sensitive_type")
    if not isinstance(sensitive_type, str) or not re.fullmatch(
        r"[a-z][a-z0-9_]*", sensitive_type
    ):
        raise RuleError(
            f"{where}.sensitive_type must be lowercase letters, digits or underscores"
        )
    kind = _validate_kind_value(spec.get("kind"), where)
    unknown = set(spec) - _allowed_keys(kind) - {"sensitive_type"}
    if unknown:
        raise RuleError(f"{where} has unknown keys: {', '.join(sorted(unknown))}")
    pattern = spec.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise RuleError(f"{where}.pattern must be a non-empty string")
    try:
        re.compile(pattern, flags_from_text(spec.get("flags", "")))
    except ValueError as exc:
        raise RuleError(f"{where}.flags: {exc}") from exc
    except re.error as exc:
        raise RuleError(f"{where}.pattern is not a valid regex: {exc}") from exc
    if kind == "regex":
        validator = spec.get("validator", "none")
        if not isinstance(validator, str) or validator not in VALIDATORS:
            raise RuleError(
                f"{where}.validator must be one of: "
                f"{', '.join(sorted(VALIDATORS))}"
            )
        if not isinstance(spec.get("require_fullmatch", False), bool):
            raise RuleError(f"{where}.require_fullmatch must be a boolean")
        value_pattern = spec.get("value_pattern")
        if value_pattern is not None:
            if not isinstance(value_pattern, str) or not value_pattern:
                raise RuleError(f"{where}.value_pattern must be a non-empty string")
            try:
                re.compile(value_pattern, flags_from_text(spec.get("flags", "")))
            except re.error as exc:
                raise RuleError(
                    f"{where}.value_pattern is not a valid regex: {exc}"
                ) from exc
        _validate_lengths(spec, where)
    elif kind == "person_name":
        _normalize_surnames(spec.get("surnames"), where)
    elif kind == "address":
        min_length = spec.get("min_length", 4)
        if not isinstance(min_length, int) or isinstance(min_length, bool) or min_length < 0:
            raise RuleError(f"{where}.min_length must be a non-negative integer")
        for key in ("surnames",):
            if key in spec:
                raise RuleError(f"{where}.{key} is not valid for address detectors")


def _validate_lengths(spec: Mapping[str, Any], where: str) -> None:
    for key in ("min_length", "max_length"):
        value = spec.get(key)
        if value is None and key == "max_length":
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise RuleError(f"{where}.{key} must be a non-negative integer")
    minimum = spec.get("min_length", 0)
    maximum = spec.get("max_length")
    if maximum is not None and maximum < minimum:
        raise RuleError(f"{where}.max_length must be >= min_length")


def compile_detector(spec: Mapping[str, Any], where: str = "detector") -> Any:
    validate_detector_spec(spec, where)
    sensitive_type = str(spec["sensitive_type"])
    kind = str(spec["kind"])
    flags = flags_from_text(spec.get("flags", ""))
    pattern = spec["pattern"]
    try:
        if kind == "regex":
            return RegexDetector(
                sensitive_type,
                pattern,
                validator_name=str(spec.get("validator", "none")),
                require_fullmatch=bool(spec.get("require_fullmatch", False)),
                value_pattern=spec.get("value_pattern"),
                flags=flags,
                min_length=int(spec.get("min_length", 0)),
                max_length=spec.get("max_length"),
            )
        if kind == "person_name":
            return PersonNameDetector(
                pattern,
                _normalize_surnames(spec.get("surnames"), where),
                flags=flags,
            )
        if kind == "address":
            return AddressDetector(
                pattern,
                min_length=int(spec.get("min_length", 4)),
                flags=flags,
            )
    except (re.error, ValueError) as exc:
        raise RuleError(f"{where}: cannot compile detector: {exc}") from exc
    raise RuleError(f"{where}: unknown detector kind {kind!r}")


def compile_rule_set(
    spec: Mapping[str, Any], version: str, base_version: str = ""
) -> RuleSet:
    if not isinstance(spec, Mapping) or not isinstance(spec.get("detectors"), list):
        raise RuleError("rule set spec must contain a detectors list")
    detectors: list[Any] = []
    seen: set[str] = set()
    for index, raw in enumerate(spec["detectors"]):
        detector = compile_detector(raw, where=f"detectors[{index}]")
        if detector.sensitive_type in seen:
            raise RuleError(
                f"duplicate detector sensitive_type: {detector.sensitive_type}"
            )
        seen.add(detector.sensitive_type)
        detectors.append(detector)
    normalized = {"detectors": [_detector_to_spec(item) for item in detectors]}
    return RuleSet(
        version=version,
        detectors=tuple(detectors),
        spec=normalized,
        fingerprint=fingerprint_spec(normalized),
        base_version=base_version,
    )


def _base_detector_config(detector: Any | None, sensitive_type: str) -> dict[str, Any]:
    if detector is None:
        return {"sensitive_type": sensitive_type}
    return dict(_detector_to_spec(detector))


def apply_overlay(
    base_detectors: Sequence[Any], overlay: Mapping[str, Any]
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Apply a rule pack overlay and return compiled detectors plus full spec."""
    if not isinstance(overlay, Mapping):
        raise RuleError("rule pack detectors must be a mapping")
    result: list[Any] = list(base_detectors)
    positions = {detector.sensitive_type: index for index, detector in enumerate(result)}
    for sensitive_type, raw_config in overlay.items():
        where = f"detectors.{sensitive_type}"
        if not isinstance(sensitive_type, str) or not re.fullmatch(
            r"[a-z][a-z0-9_]*", sensitive_type
        ):
            raise RuleError(
                f"{where}: sensitive_type must be lowercase letters, digits or underscores"
            )
        if not isinstance(raw_config, Mapping):
            raise RuleError(f"{where} must be a mapping")
        unknown_top = set(raw_config) - _ALL_OVERLAY_KEYS
        # Union of all possible keys is validated after the kind is known.
        if unknown_top:
            raise RuleError(
                f"{where} has unknown keys: {', '.join(sorted(unknown_top))}"
            )
        existing = result[positions[sensitive_type]] if sensitive_type in positions else None
        disabled = raw_config.get("disabled", False)
        if not isinstance(disabled, bool):
            raise RuleError(f"{where}.disabled must be a boolean")
        if disabled:
            extra = set(raw_config) - {"disabled", "kind"}
            if extra:
                raise RuleError(
                    f"{where}: a disabled detector must not define "
                    f"{', '.join(sorted(extra))}"
                )
            if existing is None:
                raise RuleError(f"{where}: cannot disable an unknown detector")
            del result[positions[sensitive_type]]
            positions = {
                detector.sensitive_type: index
                for index, detector in enumerate(result)
            }
            continue
        base_config = _base_detector_config(existing, sensitive_type)
        kind = raw_config.get("kind", base_config.get("kind"))
        if existing is not None and raw_config.get("kind") not in (None, base_config.get("kind")):
            raise RuleError(
                f"{where}: cannot change detector kind from "
                f"{base_config.get('kind')!r} to {raw_config.get('kind')!r}"
            )
        kind = _validate_kind_value(kind, where)
        allowed = _allowed_keys(kind)
        unknown = set(raw_config) - allowed
        if unknown:
            raise RuleError(f"{where} has unknown keys: {', '.join(sorted(unknown))}")
        merged = base_config
        merged["kind"] = kind
        for key, value in raw_config.items():
            if key in {"kind", "disabled"}:
                continue
            merged[key] = value
        if kind == "regex":
            merged.setdefault("validator", "none")
            merged.setdefault("require_fullmatch", False)
            merged.setdefault("value_pattern", None)
            merged.setdefault("min_length", 0)
            merged.setdefault("max_length", None)
            merged.setdefault("flags", "")
        elif kind == "person_name":
            merged.setdefault("surnames", sorted(SURNAMES))
            merged.setdefault("flags", "")
        elif kind == "address":
            merged.setdefault("min_length", 4)
            merged.setdefault("flags", "")
        detector = compile_detector(merged, where=where)
        if existing is None:
            positions[sensitive_type] = len(result)
            result.append(detector)
        else:
            result[positions[sensitive_type]] = detector
    spec = detectors_to_spec(result)
    # Compile the fully resolved snapshot once more so the returned detectors
    # and the persisted spec are guaranteed to describe the same rule set.
    resolved = compile_rule_set(spec, version="<overlay>")
    return resolved.detectors, resolved.spec


def load_rule_pack(path: str | Path) -> RulePack:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise RuleError(f"rule pack file not found: {source}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"cannot load rule pack {source}: {exc}") from exc
    if not isinstance(raw, Mapping):
        raise RuleError("rule pack root must be a mapping")
    unknown = set(raw) - {
        "version",
        "rule_version",
        "name",
        "description",
        "base",
        "created_by",
        "detectors",
    }
    if unknown:
        raise RuleError(
            f"rule pack has unknown keys: {', '.join(sorted(unknown))}"
        )
    version = raw.get("version")
    if version != 1 or isinstance(version, bool):
        raise RuleError("rule pack version must be the integer 1")
    rule_version = raw.get("rule_version")
    if not is_valid_version_tag(rule_version):
        raise RuleError(
            "rule_version must be a non-empty tag of letters, digits, '.', '-' or '_'"
        )
    if rule_version in RESERVED_VERSION_TAGS:
        raise RuleError(f"rule_version {rule_version!r} is reserved")
    name = raw.get("name", rule_version)
    if not isinstance(name, str) or not name.strip():
        raise RuleError("rule pack name must be a non-empty string")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise RuleError("rule pack description must be a string")
    base = raw.get("base", BUILTIN_VERSION)
    if not isinstance(base, str) or not base.strip():
        raise RuleError("rule pack base must be a non-empty version tag")
    created_by = raw.get("created_by")
    if created_by is not None and (
        not isinstance(created_by, str) or not created_by.strip()
    ):
        raise RuleError("rule pack created_by must be a non-empty string")
    detectors = raw.get("detectors", {})
    if not isinstance(detectors, Mapping):
        raise RuleError("rule pack detectors must be a mapping")
    return RulePack(
        rule_version=rule_version,
        name=name,
        description=description,
        base=base,
        created_by=created_by,
        detectors=detectors,
        source_path=source,
        raw=dict(raw),
    )
