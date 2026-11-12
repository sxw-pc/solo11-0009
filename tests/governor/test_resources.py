"""Tests for the offline /proc resource sampler."""

from __future__ import annotations

import os

from maskline.governor.resources import (
    ProcResourceSampler,
    _descendant_pids,
    read_system_memory_mb,
)


def test_system_memory_reports_sane_values():
    available, total = read_system_memory_mb()
    if total == float("inf"):
        return  # non-Linux fallback; nothing more to assert
    assert total > 0
    assert 0 <= available <= total


def test_sample_of_current_process_is_alive_and_nonnegative():
    sampler = ProcResourceSampler()
    first = sampler.sample(os.getpid())
    assert first.alive is True
    assert first.cpu_percent == 0.0  # no prior baseline yet
    assert first.rss_mb >= 0.0
    # A second reading establishes a jiffy-delta CPU figure.
    second = sampler.sample(os.getpid())
    assert second.alive is True
    assert second.cpu_percent >= 0.0
    assert second.rss_mb > 0.0


def test_sample_of_dead_pid_is_not_alive():
    sampler = ProcResourceSampler()
    # Pid 1 is always present in a Linux container; use an implausibly high
    # pid instead, which cannot have been recycled in the test window.
    dead_pid = 2_000_000
    sample = sampler.sample(dead_pid)
    assert sample.alive is False
    assert sample.cpu_percent == 0.0
    assert sample.rss_mb == 0.0


def test_descendant_collection_includes_self():
    pids = _descendant_pids(os.getpid())
    assert os.getpid() in pids
