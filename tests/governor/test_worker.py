"""Tests for worker command construction and process-group cleanup."""

from __future__ import annotations

import sys

from maskline.governor.worker import _native_maskline_argv, _resume_argv


def test_native_console_script_pinned_to_interpreter():
    argv = _native_maskline_argv(("maskline", "run", "--dataset", "x.sqlite"))
    assert argv[:3] == (sys.executable, "-m", "maskline")
    assert argv[3:] == ("run", "--dataset", "x.sqlite")


def test_python_m_invocation_pinned_to_interpreter():
    argv = _native_maskline_argv(
        ("/usr/bin/python3", "-m", "maskline", "run", "--dataset", "x")
    )
    assert argv == (sys.executable, "-m", "maskline", "run", "--dataset", "x")


def test_generic_command_left_untouched():
    original = ("/opt/tools/etl.sh", "--flag", "value")
    assert _native_maskline_argv(original) == original


def test_resume_argv_carries_workspace_and_batch_size():
    rebuilt = _resume_argv(
        "run-abc",
        (
            sys.executable, "-m", "maskline", "run",
            "--dataset", "x.sqlite",
            "--batch-size", "250",
            "--workspace", "/data/ws",
        ),
    )
    assert rebuilt[:4] == (sys.executable, "-m", "maskline", "resume")
    assert "--run-id" in rebuilt and "run-abc" in rebuilt
    joined = " ".join(rebuilt)
    assert "--workspace /data/ws" in joined
    # run-only flags must not leak into the resume invocation.
    assert "--dataset" not in rebuilt
    assert "250" in rebuilt
