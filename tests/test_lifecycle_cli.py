"""CLI-level tests for the lifecycle subcommands."""

from __future__ import annotations

import json

import pytest

from maskline.__main__ import main
from maskline.audit import verify_audit
from maskline.lifecycle.manager import LifecycleManager
from maskline.lifecycle.types import ArtifactType
from maskline.pseudomap import PseudoMapError

from lifecycle_helpers import advance, custom_policy, pinned_clock, run_and_register


def _write_retention_policy(path, body):
    path.write_text(body, encoding="utf-8")
    return path


def test_cli_preview_list_schedule_revoke_destroy_flow(
    workspace, inventories, secret_store, capsys, monkeypatch
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 5, "output": 90, "checkpoint": 5, "report": 90, "manifest": 90},
        grace_days=2,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    monkeypatch.chdir(workspace.root)

    assert main(["lifecycle", "list", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert {item["type"] for item in listed} == set(t.value for t in ArtifactType)

    advance(clock, 6)
    monkeypatch.setenv("MASKLINE_NOW", clock.now_iso())
    # Schedule through the CLI itself so the process clock matches the data.
    assert main(["lifecycle", "schedule", "--json"]) == 0
    scheduled = json.loads(capsys.readouterr().out)
    checkpoint = next(
        item for item in scheduled["items"]
        if item["artifact_type"] == "checkpoint" and item["state"] == "in_grace"
    )
    assert main(["lifecycle", "revoke", "--artifact-id", checkpoint["artifact_id"]]) == 0
    out = capsys.readouterr().out
    assert "已撤销" in out
    verify_audit(workspace.audit_path)


def test_cli_preview_json_shape(workspace, inventories, secret_store, capsys, monkeypatch):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 1, "output": 1, "checkpoint": 1, "report": 1, "manifest": 1}
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    advance(clock, 2)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        manager.schedule_due()
    monkeypatch.chdir(workspace.root)
    monkeypatch.setenv("MASKLINE_NOW", clock.now_iso())
    assert main(["lifecycle", "preview", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "totals" in payload and "items" in payload
    assert payload["totals"]["in_grace"] >= 1


def test_cli_destroy_refuses_pseudomap_without_token(
    workspace, inventories, secret_store, capsys, monkeypatch
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 2, "output": 90, "checkpoint": 90, "report": 90, "manifest": 90},
        grace_days=1,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    advance(clock, 2)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        manager.schedule_due()
        pseudomap = next(
            r for r in manager.list_artifacts()
            if r.artifact_type is ArtifactType.PSEUDOMAP
        )
        token = pseudomap.destroy_token
    advance(clock, 2)
    monkeypatch.chdir(workspace.root)
    monkeypatch.setenv("MASKLINE_NOW", clock.now_iso())
    # Missing token -> exit code 2, mapping intact.
    assert main(["lifecycle", "destroy"]) == 2
    assert "destroy token" in capsys.readouterr().out
    assert workspace.pseudomap_db.exists()
    # Correct token -> exit 0, mapping gone.
    assert main(
        ["lifecycle", "destroy", "--token", f"{pseudomap.artifact_id}={token}"]
    ) == 0
    out = capsys.readouterr().out
    assert "审计链校验=通过" in out
    assert not workspace.pseudomap_db.exists()
    with pytest.raises(PseudoMapError):
        __import__("maskline.pseudomap", fromlist=["PseudoMap"]).PseudoMap(
            workspace.pseudomap_db
        )


def test_cli_batches_reports_progress(workspace, inventories, secret_store, capsys, monkeypatch):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 1, "output": 1, "checkpoint": 1, "report": 1, "manifest": 1}
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    advance(clock, 2)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        manager.schedule_due()
    monkeypatch.chdir(workspace.root)
    monkeypatch.setenv("MASKLINE_NOW", clock.now_iso())
    assert main(["lifecycle", "batches"]) == 0
    out = capsys.readouterr().out
    assert "dst-" in out and "待处理=" in out
