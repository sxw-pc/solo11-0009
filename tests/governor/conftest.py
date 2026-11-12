"""Shared fixtures and fakes for governor tests."""

from __future__ import annotations

import pytest

from maskline.config import Paths, create_demo_secret
from maskline.fixturegen import generate_fixture
from maskline.governor.config import GovernorConfig, Quota
from maskline.governor.daemon import Governor
from maskline.governor.resources import ProcessSample
from maskline.governor.state import GovernorStore
from maskline.governor.trail import GovernorAudit


@pytest.fixture
def gworkspace(tmp_path):
    paths = Paths.for_workspace(tmp_path / "gov")
    paths.ensure_runtime_dirs()
    return paths


@pytest.fixture
def secret_file(tmp_path, monkeypatch):
    path = tmp_path / "secret.txt"
    create_demo_secret(path)
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(path))
    return path


@pytest.fixture
def fixture_dataset(tmp_path):
    files = generate_fixture(tmp_path / "raw", seed=11, customers=20, orders=30, leads=5)
    return files


@pytest.fixture
def governor_config():
    return GovernorConfig(
        defaults=Quota(
            cpu_max_percent=40.0, memory_max_mb=512, max_runtime_seconds=30
        ),
        max_concurrency=2,
        sample_interval_seconds=0.05,
        throttle_stop_seconds=0.02,
        throttle_breach_limit=2,
        resume_cooldown_seconds=0.0,
        max_resume_attempts=5,
        memory_recover_ratio=0.9,
    )


class FakeSampler:
    """Deterministic sampler driven by per-pid scripted sample queues."""

    def __init__(self):
        self._scripts: dict[int, list[ProcessSample]] = {}
        self._default: dict[int, ProcessSample] = {}

    def script(self, pid: int, samples: list[ProcessSample]) -> None:
        self._scripts[pid] = list(samples)

    def set_default(self, pid: int, sample: ProcessSample) -> None:
        self._default[pid] = sample

    def sample(self, pid: int) -> ProcessSample:
        queue = self._scripts.get(pid)
        if queue:
            return queue.pop(0)
        return self._default.get(
            pid,
            ProcessSample(
                pid=pid, alive=True, cpu_percent=1.0, rss_mb=10.0,
                system_available_mb=4096.0, system_total_mb=8192.0,
                sampled_at=0.0,
            ),
        )

    def system_memory(self):
        return 4096.0, 8192.0


class ManualClock:
    def __init__(self, start: float = 1000.0):
        self.value = start

    def monotonic(self) -> float:
        return self.value

    def wall(self) -> float:
        return self.value * 10.0

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def fake_sampler():
    return FakeSampler()


@pytest.fixture
def manual_clock():
    return ManualClock()


@pytest.fixture
def governor(gworkspace, governor_config, fake_sampler):
    # Real monotonic/wall clocks are required because workers are genuine
    # subprocesses; determinism comes from the scripted FakeSampler instead.
    gov = Governor(
        gworkspace,
        governor_config,
        sampler=fake_sampler,
        scheduler_sleeper=lambda _seconds: None,
    )
    yield gov
    gov.close()


@pytest.fixture
def store(gworkspace):
    db = GovernorStore(gworkspace.governor_db)
    yield db
    db.close()


@pytest.fixture
def audit(gworkspace):
    return GovernorAudit(gworkspace.audit_path)
