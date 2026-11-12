"""End-to-end acceptance for JSON columns: discovery, masking, reports, resume.

The fixture ``profiles`` table deliberately mixes five well-formed nested
documents with one unparseable cell, one oversize document, and one over-deep
document. A healthy run must finish the whole batch, mask only matched leaves,
degrade dirty cells through the fallback with warnings, and stay byte-stable
across reruns.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from maskline.config import Paths
from maskline.detectors.engine import detect_inventory
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.utils import sqlite_content_digest

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def test_json_paths_are_discovered_and_persisted(workspace, inventories):
    from maskline.registry import Catalog

    inventory = inventories["sqlite"]
    findings = detect_inventory(inventory)
    json_findings = [item for item in findings if item.get("json_path")]
    paths = {item["json_path"] for item in json_findings}
    assert "$.items[*].phone" in paths
    assert "$.profile.id_card" in paths
    assert "$.profile.address" in paths
    phones = next(item for item in json_findings if item["json_path"] == "$.items[*].phone")
    assert phones["sensitive_type"] == "mobile_phone"
    assert phones["confidence"] in {"high", "medium"}
    # Legacy column-level rows still exist alongside path rows.
    assert any(not item.get("json_path") and item["column_name"] == "payload" for item in findings)
    with Catalog(workspace.meta_db) as catalog:
        catalog.register(inventory)
        for record in findings:
            catalog.save_finding(record)
        stored = catalog.findings_for(inventory.fingerprint)
        assert len(stored) == len(findings)
        assert {item["json_path"] for item in stored if item.get("json_path")} == paths


def test_full_run_masks_leaves_and_preserves_structure(
    workspace, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, workspace,
        secrets_store=secret_store, batch_size=3,
    )
    source = inventories["sqlite"].path
    with connect(result.output_path) as conn:
        rows = conn.execute(
            "SELECT profile_id, payload, status FROM profiles ORDER BY profile_id"
        ).fetchall()
    with connect(source) as conn:
        source_rows = conn.execute(
            "SELECT profile_id, payload, status FROM profiles ORDER BY profile_id"
        ).fetchall()
    assert len(rows) == 8  # batch completed despite three bad cells

    for row, original in zip(rows[:5], source_rows[:5]):
        before = json.loads(original["payload"])
        after = json.loads(row["payload"])
        # Structure and key order survive.
        assert list(after.keys()) == list(before.keys())
        assert list(after["profile"].keys()) == list(before["profile"].keys())
        assert len(after["items"]) == len(before["items"])
        # Matched leaves are transformed.
        for before_item, after_item in zip(before["items"], after["items"]):
            assert after_item["phone"].startswith(before_item["phone"][:3])
            assert after_item["phone"] != before_item["phone"]
            assert after_item["sku"] == before_item["sku"]  # unmatched leaf intact
            assert after_item["remark"] == before_item["remark"]
        assert after["profile"]["id_card"] != before["profile"]["id_card"]
        assert after["profile"]["address"] != before["profile"]["address"]
        assert after["profile"]["real_name"] != before["profile"]["real_name"]
        # Non-sensitive branches are byte-identical.
        assert after["tags"] == before["tags"]
        assert after["score"] == before["score"]

    # Dirty cells were nullified by the fallback, batch still completed.
    dirty = {row["profile_id"]: (row["status"], row["payload"]) for row in rows[5:]}
    assert sorted(dirty) == [6, 7, 8]
    assert {status for status, _payload in dirty.values()} == {
        "broken", "oversized", "too_deep",
    }
    assert all(payload is None for _status, payload in dirty.values())

    state = result.json_state["columns"]["payload"]
    assert state["cells"] == 8 and state["json_ok"] == 5 and state["empty"] == 0
    assert state["warnings"] == {"not_json": 1, "too_large": 1, "too_deep": 1}
    assert state["warning_samples"]["not_json"] == [6]
    assert state["warning_samples"]["too_large"] == [7]
    assert state["warning_samples"]["too_deep"] == [8]
    path_stats = state["path_stats"]
    assert path_stats["$.items[*].phone"]["mask"]["seen"] >= 5
    assert path_stats["$.profile.id_card"]["mask"]["changed"] == 5


def test_rerun_is_byte_identical(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    first = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store)
    second = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store)
    assert first.output_hash == second.output_hash
    assert sqlite_content_digest(first.output_path) == sqlite_content_digest(second.output_path)
    assert first.json_state == second.json_state


def test_report_and_audit_capture_path_stats_and_warnings(
    workspace, inventories, secret_store
):
    from maskline.workflow import finalize_run

    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store
    )
    findings = detect_inventory(inventories["sqlite"])
    finalize_run(workspace, inventories["sqlite"], policy, result, findings)
    artifacts = {
        "markdown": workspace.reports_dir / f"{result.run_id}.md",
        "json": workspace.reports_dir / f"{result.run_id}.json",
    }
    markdown = artifacts["markdown"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json"].read_text(encoding="utf-8"))

    assert "JSON 路径处理统计" in markdown
    assert "JSON 降级警告" in markdown
    assert "$.items[*].phone" in markdown
    assert "not_json" not in markdown  # human-readable labels, not raw codes
    assert "JSON 解析失败" in markdown
    assert payload["json_state"]["columns"]["payload"]["warnings"] == {
        "not_json": 1, "too_large": 1, "too_deep": 1,
    }
    path_rows = [
        item for item in payload["findings"] if item.get("json_path")
    ]
    assert any(item["json_path"] == "$.items[*].phone" for item in path_rows)

    from maskline.audit import AuditLog, read_audit_entries
    entry = read_audit_entries(workspace.audit_path)[-1]
    assert "json_state" in entry
    assert AuditLog(workspace.audit_path).verify().entries >= 1


def test_resume_after_interruption_keeps_json_state_consistent(
    tmp_path, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    baseline = execute_run(
        inventories["sqlite"], policy, baseline_paths,
        secrets_store=secret_store, batch_size=2,
    )
    with pytest.raises(PipelineInterrupted):
        execute_run(
            inventories["sqlite"], policy, interrupted_paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    run_id = [
        name for name in {row.run_id for row in CheckpointStore(
            interrupted_paths.checkpoint_db
        ).list_runs()}
    ][0]
    with CheckpointStore(interrupted_paths.checkpoint_db) as store:
        checkpoint = store.list_checkpoints(run_id)[0]
        assert checkpoint.json_state  # JSON state persisted per checkpoint
    resumed = execute_run(
        inventories["sqlite"], policy, interrupted_paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.output_hash == baseline.output_hash
    assert resumed.json_state == baseline.json_state


def test_csv_json_column_is_handled(tmp_path, secret_store):
    import csv as csv_module

    csv_path = tmp_path / "events.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv_module.writer(fh)
        writer.writerow(["event_id", "detail"])
        writer.writerow([1, json.dumps({"user": {"phone": "13800000000"}}, ensure_ascii=False)])
        writer.writerow([2, "broken-json-cell"])
    from maskline.registry import inspect_dataset
    inventory = inspect_dataset(csv_path)
    policy_text = """
version: 1
name: csv-json
datasets:
  - path: "events.csv"
    tables:
      events:
        columns:
          detail:
            json:
              paths:
                "$.user.phone":
                  transformer: mask
                  params: {keep_prefix: 3, keep_suffix: 4}
              fallback:
                transformer: nullify
"""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
    paths = Paths.for_workspace(tmp_path / "ws")
    result = execute_run(
        inventory, load_policy(policy_path), paths, secrets_store=secret_store
    )
    with connect(result.output_path) as conn:
        rows = conn.execute("SELECT event_id, detail FROM events ORDER BY event_id").fetchall()
    assert json.loads(rows[0]["detail"])["user"]["phone"] == "138****0000"
    assert rows[1]["detail"] is None
    warnings = result.json_state["columns"]["detail"]["warnings"]
    assert warnings == {"not_json": 1}


def test_legacy_findings_without_json_path_still_display(workspace, inventories):
    # Simulate an old catalog row written before json_path existed.
    from maskline.registry import Catalog

    inventory = inventories["sqlite"]
    with Catalog(workspace.meta_db) as catalog:
        catalog.register(inventory)
        catalog.save_finding({
            "dataset_fingerprint": inventory.fingerprint,
            "table_name": "customers",
            "column_name": "phone",
            "sensitive_type": "mobile_phone",
            "confidence": "high",
            "score": 1.0,
            "hit_rate": 1.0,
            "validate_rate": 1.0,
            "sample_size": 6,
            "candidates": [],
        })
        stored = catalog.findings_for(inventory.fingerprint)
    legacy = [item for item in stored if item["column_name"] == "phone"]
    assert len(legacy) == 1 and legacy[0]["json_path"] == ""
