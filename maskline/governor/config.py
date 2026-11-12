"""Quota configuration: global defaults plus per-task overrides.

A governor config file is plain YAML and the only runtime dependency beyond
the rest of maskline is PyYAML.  Every quota field is optional at every level;
the resolution order for one task is

    built-in defaults  <  global ``defaults`` block  <  per-task ``jobs`` block
                          <  explicit CLI submit-time overrides

so the same file can govern a whole fleet while still pinning one heavy task.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import QuotaConfigError

# Built-in fallbacks used when neither the config nor an override supplies a
# value.  They are deliberately permissive so an unconfigured governor still
# behaves usefully on a small office workstation.
BUILTIN_DEFAULTS: dict[str, Any] = {
    "cpu_max_percent": 80.0,
    "memory_max_mb": 1024,
    "max_runtime_seconds": 3600,
    "max_concurrency": 2,
    "sample_interval_seconds": 2.0,
    "throttle_stop_seconds": 0.2,
    "throttle_breach_limit": 3,
    "resume_cooldown_seconds": 5.0,
    "max_resume_attempts": 10,
    "memory_recover_ratio": 0.9,
}

_QUOTA_FIELDS = ("cpu_max_percent", "memory_max_mb", "max_runtime_seconds")
_TUNABLE_FIELDS = (
    "max_concurrency",
    "sample_interval_seconds",
    "throttle_stop_seconds",
    "throttle_breach_limit",
    "resume_cooldown_seconds",
    "max_resume_attempts",
    "memory_recover_ratio",
)
_ALL_FIELDS = _QUOTA_FIELDS + _TUNABLE_FIELDS


@dataclass(frozen=True)
class Quota:
    """The three per-task resource quotas required by the governance spec."""

    cpu_max_percent: float
    memory_max_mb: int
    max_runtime_seconds: int

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class GovernorConfig:
    """Full governor configuration: defaults, tunables, and named job pins."""

    defaults: Quota
    max_concurrency: int
    sample_interval_seconds: float
    throttle_stop_seconds: float
    throttle_breach_limit: int
    resume_cooldown_seconds: float
    max_resume_attempts: int
    memory_recover_ratio: float
    jobs: dict[str, Quota] = field(default_factory=dict)
    source_path: Path | None = None

    def effective_quotas(
        self, job_name: str, overrides: dict[str, Any] | None = None
    ) -> Quota:
        """Resolve the quota that applies to one task at submit time."""
        merged = {
            "cpu_max_percent": self.defaults.cpu_max_percent,
            "memory_max_mb": self.defaults.memory_max_mb,
            "max_runtime_seconds": self.defaults.max_runtime_seconds,
        }
        pinned = self.jobs.get(job_name)
        if pinned is not None:
            merged.update(pinned.as_dict())
        if overrides:
            for key in _QUOTA_FIELDS:
                if key in overrides and overrides[key] is not None:
                    merged[key] = overrides[key]
        return Quota(**merged)

    def as_dict(self) -> dict[str, Any]:
        data = {
            "defaults": self.defaults.as_dict(),
            "max_concurrency": self.max_concurrency,
            "sample_interval_seconds": self.sample_interval_seconds,
            "throttle_stop_seconds": self.throttle_stop_seconds,
            "throttle_breach_limit": self.throttle_breach_limit,
            "resume_cooldown_seconds": self.resume_cooldown_seconds,
            "max_resume_attempts": self.max_resume_attempts,
            "memory_recover_ratio": self.memory_recover_ratio,
            "jobs": {name: quota.as_dict() for name, quota in sorted(self.jobs.items())},
        }
        if self.source_path is not None:
            data["source_path"] = str(self.source_path)
        return data


def _coerce_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise QuotaConfigError(f"{field_name} must be a number, got {value!r}")
    return float(value)


def _validate_quota_mapping(raw: dict[str, Any], label: str) -> dict[str, Any]:
    unknown = sorted(set(raw) - set(_QUOTA_FIELDS))
    if unknown:
        raise QuotaConfigError(
            f"unknown quota field(s) for {label}: {', '.join(unknown)}"
        )
    cleaned: dict[str, Any] = {}
    if "cpu_max_percent" in raw:
        cpu = _coerce_number(raw["cpu_max_percent"], "cpu_max_percent")
        if not 0 < cpu <= 100:
            raise QuotaConfigError("cpu_max_percent must be within (0, 100]")
        cleaned["cpu_max_percent"] = cpu
    if "memory_max_mb" in raw:
        memory = _coerce_number(raw["memory_max_mb"], "memory_max_mb")
        if memory <= 0:
            raise QuotaConfigError("memory_max_mb must be positive")
        cleaned["memory_max_mb"] = int(memory)
    if "max_runtime_seconds" in raw:
        runtime = _coerce_number(raw["max_runtime_seconds"], "max_runtime_seconds")
        if runtime <= 0:
            raise QuotaConfigError("max_runtime_seconds must be positive")
        cleaned["max_runtime_seconds"] = int(runtime)
    return cleaned


def _validate_tunables(raw: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(raw) - set(_ALL_FIELDS))
    if unknown:
        raise QuotaConfigError(f"unknown config field(s): {', '.join(unknown)}")
    cleaned = dict(raw)
    positive_int = ("max_concurrency", "throttle_breach_limit", "max_resume_attempts")
    positive_float = (
        "sample_interval_seconds",
        "throttle_stop_seconds",
        "resume_cooldown_seconds",
    )
    for name in positive_int:
        if name in cleaned:
            value = _coerce_number(cleaned[name], name)
            if value < 1:
                raise QuotaConfigError(f"{name} must be >= 1")
            cleaned[name] = int(value)
    for name in positive_float:
        if name in cleaned:
            value = _coerce_number(cleaned[name], name)
            if value <= 0:
                raise QuotaConfigError(f"{name} must be positive")
            cleaned[name] = value
    if "memory_recover_ratio" in cleaned:
        ratio = _coerce_number(cleaned["memory_recover_ratio"], "memory_recover_ratio")
        if not 0 < ratio <= 1:
            raise QuotaConfigError("memory_recover_ratio must be within (0, 1]")
        cleaned["memory_recover_ratio"] = ratio
    return cleaned


def load_config(path: str | Path | None) -> GovernorConfig:
    """Load and validate a YAML governor config, filling built-in defaults."""
    raw: dict[str, Any] = {}
    source: Path | None = None
    if path is not None:
        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise QuotaConfigError(f"governor config not found: {source}")
        try:
            loaded = yaml.safe_load(source.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise QuotaConfigError(f"invalid YAML in {source}: {exc}") from exc
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise QuotaConfigError("governor config must be a YAML mapping")
        raw = loaded

    defaults_raw = dict(BUILTIN_DEFAULTS)
    defaults_block = raw.get("defaults", {})
    if defaults_block is None:
        defaults_block = {}
    if not isinstance(defaults_block, dict):
        raise QuotaConfigError("defaults must be a mapping")
    defaults_raw.update(_validate_quota_mapping(defaults_block, "defaults"))

    tunables = {
        key: value
        for key, value in raw.items()
        if key not in ("defaults", "jobs")
    }
    tunables = _validate_tunables(tunables)
    for key in _TUNABLE_FIELDS:
        defaults_raw[key] = tunables.get(key, BUILTIN_DEFAULTS[key])

    jobs_raw = raw.get("jobs", {}) or {}
    if not isinstance(jobs_raw, dict):
        raise QuotaConfigError("jobs must be a mapping of job name to quota")
    pinned: dict[str, Quota] = {}
    for job_name, job_raw in jobs_raw.items():
        if not isinstance(job_name, str) or not job_name:
            raise QuotaConfigError("job names must be non-empty strings")
        if not isinstance(job_raw, dict):
            raise QuotaConfigError(f"jobs.{job_name} must be a mapping")
        merged = dict(defaults_raw)
        merged.update(_validate_quota_mapping(job_raw, f"jobs.{job_name}"))
        pinned[job_name] = Quota(
            cpu_max_percent=merged["cpu_max_percent"],
            memory_max_mb=merged["memory_max_mb"],
            max_runtime_seconds=merged["max_runtime_seconds"],
        )

    return GovernorConfig(
        defaults=Quota(
            cpu_max_percent=defaults_raw["cpu_max_percent"],
            memory_max_mb=defaults_raw["memory_max_mb"],
            max_runtime_seconds=defaults_raw["max_runtime_seconds"],
        ),
        max_concurrency=defaults_raw["max_concurrency"],
        sample_interval_seconds=defaults_raw["sample_interval_seconds"],
        throttle_stop_seconds=defaults_raw["throttle_stop_seconds"],
        throttle_breach_limit=defaults_raw["throttle_breach_limit"],
        resume_cooldown_seconds=defaults_raw["resume_cooldown_seconds"],
        max_resume_attempts=defaults_raw["max_resume_attempts"],
        memory_recover_ratio=defaults_raw["memory_recover_ratio"],
        jobs=pinned,
        source_path=source,
    )


def parse_overrides(items: list[str] | None) -> dict[str, Any]:
    """Parse ``key=value`` submit-time quota overrides from the CLI."""
    overrides: dict[str, Any] = {}
    for item in items or []:
        if "=" not in item:
            raise QuotaConfigError(
                f"quota override must be key=value, got {item!r}"
            )
        key, raw_value = item.split("=", 1)
        key = key.strip()
        if key not in _QUOTA_FIELDS:
            raise QuotaConfigError(
                f"unknown quota override {key!r}; valid fields: "
                + ", ".join(_QUOTA_FIELDS)
            )
        try:
            value: Any = float(raw_value)
        except ValueError as exc:
            raise QuotaConfigError(
                f"quota override {key} must be numeric, got {raw_value!r}"
            ) from exc
        overrides.update(_validate_quota_mapping({key: value}, f"override {key}"))
    return overrides
