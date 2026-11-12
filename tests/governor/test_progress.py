"""Tests for the runner progress event sink."""

from __future__ import annotations

from maskline.pipeline.progress import (
    PROGRESS_ENV,
    emit_event,
    latest_run_id,
    read_events,
)


def test_emit_is_noop_without_env(monkeypatch):
    monkeypatch.delenv(PROGRESS_ENV, raising=False)
    emit_event("run_started", {"run_id": "x"})  # must not raise


def test_events_are_appended_and_read_back(tmp_path, monkeypatch):
    path = tmp_path / "progress.jsonl"
    monkeypatch.setenv(PROGRESS_ENV, str(path))
    emit_event("run_started", {"run_id": "run-1"})
    emit_event("checkpoint", {"run_id": "run-1", "batch": 2})
    emit_event("run_completed", {"run_id": "run-1"})

    events = read_events(path)
    assert [event["kind"] for event in events] == [
        "run_started", "checkpoint", "run_completed"
    ]
    assert latest_run_id(path) == "run-1"


def test_latest_run_id_tracks_most_recent(tmp_path, monkeypatch):
    path = tmp_path / "progress.jsonl"
    monkeypatch.setenv(PROGRESS_ENV, str(path))
    emit_event("run_started", {"run_id": "run-old"})
    emit_event("run_started", {"run_id": "run-new"})
    assert latest_run_id(path) == "run-new"


def test_read_events_ignores_blank_and_garbage(tmp_path):
    path = tmp_path / "progress.jsonl"
    path.write_text(
        '{"kind": "run_started", "run_id": "r1"}\n\nnot-json\n',
        encoding="utf-8",
    )
    events = read_events(path)
    assert len(events) == 1
    assert events[0]["run_id"] == "r1"


def test_read_missing_file_returns_empty(tmp_path):
    assert read_events(tmp_path / "nope.jsonl") == []
    assert latest_run_id(tmp_path / "nope.jsonl") is None
