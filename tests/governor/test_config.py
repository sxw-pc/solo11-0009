import pytest

from maskline.governor.config import (
    BUILTIN_DEFAULTS,
    load_config,
    parse_overrides,
)
from maskline.governor.errors import QuotaConfigError


def test_builtin_defaults_when_file_omitted():
    config = load_config(None)
    assert config.defaults.cpu_max_percent == BUILTIN_DEFAULTS["cpu_max_percent"]
    assert config.defaults.memory_max_mb == BUILTIN_DEFAULTS["memory_max_mb"]
    assert config.max_concurrency == BUILTIN_DEFAULTS["max_concurrency"]
    assert config.jobs == {}


def test_global_defaults_and_per_job_pins(tmp_path):
    path = tmp_path / "gov.yaml"
    path.write_text(
        """
defaults:
  cpu_max_percent: 55
  memory_max_mb: 700
  max_runtime_seconds: 900
max_concurrency: 3
jobs:
  heavy-extract:
    memory_max_mb: 4096
    cpu_max_percent: 90
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.defaults.memory_max_mb == 700
    assert config.max_concurrency == 3
    pinned = config.effective_quotas("heavy-extract")
    assert pinned.memory_max_mb == 4096
    assert pinned.cpu_max_percent == 90.0
    # Unpinned field inherits the global default.
    assert pinned.max_runtime_seconds == 900
    plain = config.effective_quotas("other-task")
    assert plain.memory_max_mb == 700


def test_submit_overrides_beat_job_pins(tmp_path):
    path = tmp_path / "gov.yaml"
    path.write_text(
        """
defaults: {cpu_max_percent: 10, memory_max_mb: 100, max_runtime_seconds: 60}
jobs:
  named: {memory_max_mb: 200}
""",
        encoding="utf-8",
    )
    config = load_config(path)
    quota = config.effective_quotas(
        "named", {"memory_max_mb": 999, "cpu_max_percent": 75.5}
    )
    assert quota.memory_max_mb == 999
    assert quota.cpu_max_percent == 75.5
    assert quota.max_runtime_seconds == 60


@pytest.mark.parametrize(
    "text, match",
    [
        ("defaults: {cpu_max_percent: 0}", "cpu_max_percent"),
        ("defaults: {cpu_max_percent: 120}", "cpu_max_percent"),
        ("defaults: {memory_max_mb: 0}", "memory_max_mb"),
        ("defaults: {max_runtime_seconds: -5}", "max_runtime_seconds"),
        ("max_concurrency: 0", "max_concurrency"),
        ("defaults: {unknown_field: 1}", "unknown quota"),
        ("bogus_top_level: 1", "unknown config"),
        ("jobs: {x: {cpu_max_percent: 'fast'}}", "number"),
    ],
)
def test_invalid_config_rejected(tmp_path, text, match):
    path = tmp_path / "bad.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(QuotaConfigError, match=match):
        load_config(path)


def test_missing_file_and_bad_yaml(tmp_path):
    with pytest.raises(QuotaConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("defaults: [", encoding="utf-8")
    with pytest.raises(QuotaConfigError, match="invalid YAML"):
        load_config(bad)


def test_parse_overrides():
    overrides = parse_overrides(
        ["cpu_max_percent=33.5", "memory_max_mb=256", "max_runtime_seconds=120"]
    )
    assert overrides == {
        "cpu_max_percent": 33.5,
        "memory_max_mb": 256,
        "max_runtime_seconds": 120,
    }
    with pytest.raises(QuotaConfigError, match="key=value"):
        parse_overrides(["nodelimiter"])
    with pytest.raises(QuotaConfigError, match="unknown quota override"):
        parse_overrides(["disk_gb=10"])
    with pytest.raises(QuotaConfigError, match="numeric"):
        parse_overrides(["memory_max_mb=big"])
