import gc
import json
import os
from pathlib import Path

import pytest

from maskline.__main__ import main
from maskline.audit import verify_audit
from maskline.config import Paths
from maskline.detectors.engine import detect_inventory
from maskline.pipeline.checkpoint import CheckpointStore, RunRecord
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.registry import inspect_dataset
from maskline.summary import generate_summary
from maskline.utils import MasklineError, file_sha256
from maskline.workflow import finalize_run, scan_paths

POLICY_A = """
version: 1
name: round-a
datasets:
  - path: demo.sqlite
    tables:
      customers:
        columns:
          phone:
            transformer: mask
            params: {keep_prefix: 3, keep_suffix: 4}
"""

POLICY_B = """
version: 1
name: round-b
datasets:
  - path: demo.sqlite
    tables:
      customers:
        columns:
          phone:
            transformer: mask
            params: {keep_prefix: 2, keep_suffix: 2}
          email:
            transformer: hash
          notes:
            transformer: nullify
"""


def _run_and_finalize(paths, inventory, policy, secret_store=None):
    result = execute_run(
        inventory, policy, paths, secrets_store=secret_store, batch_size=2
    )
    finalize_run(paths, inventory, policy, result, detect_inventory(inventory))
    return result


def _fabricate_runs(paths, inventory, count):
    store = CheckpointStore(paths.checkpoint_db)
    try:
        for index in range(count):
            moment = f"2026-01-01T00:{index // 60:02d}:{index % 60:02d}+00:00"
            store.create_run(
                RunRecord(
                    run_id=f"run-fake-{index:03d}",
                    dataset_path=str(inventory.path),
                    dataset_fingerprint=inventory.fingerprint,
                    policy_path="policy.yaml",
                    policy_fingerprint="p" * 64,
                    output_path=str(paths.out_dir / f"fake-{index}.sqlite"),
                    status="completed",
                    started_at=moment,
                    updated_at=moment,
                )
            )
    finally:
        store.close()


def test_summary_aggregates_runs_and_appends_audit(
    workspace, fixture_files, inventories, make_policy, secret_store
):
    scan_paths([fixture_files["sqlite"]], workspace)
    inventory = inventories["sqlite"]
    policy_a = make_policy(POLICY_A)
    first = _run_and_finalize(workspace, inventory, policy_a)
    policy_b = make_policy(POLICY_B)
    second = _run_and_finalize(workspace, inventory, policy_b, secret_store)

    result = generate_summary(workspace, fingerprint=inventory.fingerprint)
    md_path, json_path = result["markdown"], result["json"]
    assert md_path.exists() and json_path.exists()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    overview = payload["summary"]
    assert overview["dataset_fingerprint"] == inventory.fingerprint
    assert overview["runs_total"] == 2
    assert overview["runs_included"] == 2
    assert overview["runs_excluded"] == 0
    assert overview["details_collapsed"] is False
    assert overview["generated_at"]

    # run entries reuse the single-run report field names
    runs = {run["run_id"]: run for run in payload["runs"]}
    assert set(runs) == {first.run_id, second.run_id}
    first_run = runs[first.run_id]
    for key in (
        "dataset", "dataset_fingerprint", "policy_name", "policy_fingerprint",
        "output", "output_hash", "rows_processed", "transform_counts",
        "applied_policy", "findings",
    ):
        assert key in first_run
    assert first_run["output_hash"] == first.output_hash
    assert first_run["rows_processed"] == first.row_count
    assert first_run["included"] is True
    assert first_run["audit"]["anchored"] is True
    assert first_run["policy_changed"] is False
    assert runs[second.run_id]["policy_changed"] is True

    # policy diff between the two rounds
    assert len(payload["policy_changes"]) == 1
    change = payload["policy_changes"][0]
    assert change["from_run_id"] == first.run_id
    assert change["to_run_id"] == second.run_id
    assert change["detail_level"] == "full"
    added = {(c["table_name"], c["column_name"]) for c in change["added_columns"]}
    assert ("customers", "email") in added
    assert ("customers", "notes") in added
    changed = {(c["table_name"], c["column_name"]) for c in change["changed_columns"]}
    assert ("customers", "phone") in changed

    # findings drift between rounds (same data -> no added/removed)
    assert len(payload["findings_drift"]) == 1
    drift = payload["findings_drift"][0]
    assert drift["unavailable"] is False
    assert drift["added"] == [] and drift["removed"] == []

    # trends and the registry's current findings
    assert [t["run_id"] for t in payload["trends"]] == [first.run_id, second.run_id]
    assert payload["trends"][0]["findings_high_medium"] is not None
    assert payload["current_findings"]

    markdown = md_path.read_text(encoding="utf-8")
    for section in ("汇总报告", "核心变化趋势", "策略调整差异", "敏感发现漂移", "审计锚点状态"):
        assert section in markdown
    assert first.run_id in markdown and second.run_id in markdown
    assert "## 每轮明细" in markdown and "## 附录" not in markdown

    # the summary itself is anchored in the audit chain
    assert result["audit"] is not None
    entry = result["audit"]
    assert entry["event"] == "summary_report"
    assert entry["dataset_fingerprint"] == inventory.fingerprint
    assert entry["report_json_hash"] == file_sha256(json_path)
    assert entry["report_markdown_hash"] == file_sha256(md_path)
    assert verify_audit(workspace.audit_path).entries == 3  # two runs + summary

    # single-run reports still generate exactly as before afterwards
    third = _run_and_finalize(workspace, inventory, policy_a)
    assert (workspace.reports_dir / f"{third.run_id}.json").exists()
    follow = generate_summary(workspace, fingerprint=inventory.fingerprint)
    assert follow["payload"]["summary"]["runs_total"] == 3


def test_summary_accepts_dataset_path_or_fingerprint(
    workspace, fixture_files, inventories, make_policy
):
    scan_paths([fixture_files["sqlite"]], workspace)
    inventory = inventories["sqlite"]
    _run_and_finalize(workspace, inventory, make_policy(POLICY_A))
    by_path = generate_summary(workspace, dataset_path=fixture_files["sqlite"])
    by_fp = generate_summary(workspace, fingerprint=inventory.fingerprint)
    assert by_path["payload"]["summary"]["runs_total"] == 1
    assert by_fp["payload"]["summary"]["runs_total"] == 1
    assert (
        by_path["payload"]["summary"]["dataset_fingerprint"]
        == by_fp["payload"]["summary"]["dataset_fingerprint"]
        == inventory.fingerprint
    )
    with pytest.raises(MasklineError, match="no runs recorded"):
        generate_summary(workspace, fingerprint="0" * 64)
    with pytest.raises(MasklineError, match="exactly one"):
        generate_summary(workspace)
    with pytest.raises(MasklineError, match="exactly one"):
        generate_summary(
            workspace,
            fingerprint=inventory.fingerprint,
            dataset_path=fixture_files["sqlite"],
        )


def test_summary_requires_recorded_runs(workspace, fixture_files, inventories):
    scan_paths([fixture_files["sqlite"]], workspace)
    with pytest.raises(MasklineError, match="no runs recorded"):
        generate_summary(workspace, fingerprint=inventories["sqlite"].fingerprint)


def test_summary_annotates_cleaned_artifacts(
    workspace, fixture_files, inventories, make_policy, secret_store
):
    scan_paths([fixture_files["sqlite"]], workspace)
    inventory = inventories["sqlite"]
    first = _run_and_finalize(workspace, inventory, make_policy(POLICY_A))
    second = _run_and_finalize(workspace, inventory, make_policy(POLICY_B), secret_store)
    # operators clean up part of the artifacts by hand
    Path(first.output_path).unlink()
    (workspace.reports_dir / f"{second.run_id}.json").unlink()

    result = generate_summary(workspace, fingerprint=inventory.fingerprint)
    payload = result["payload"]
    # cleaned artifacts do not exclude otherwise valid runs
    assert payload["summary"]["runs_included"] == 2
    runs = {run["run_id"]: run for run in payload["runs"]}
    assert runs[first.run_id]["artifacts"]["output_exists"] is False
    assert any(a["kind"] == "output_missing" for a in runs[first.run_id]["anomalies"])
    assert runs[second.run_id]["artifacts"]["report_exists"] is False
    assert runs[second.run_id]["findings"] is None
    assert any(a["kind"] == "report_missing" for a in runs[second.run_id]["anomalies"])
    kinds = {a["kind"] for a in payload["anomalies"]}
    assert {"output_missing", "report_missing"} <= kinds
    # drift is marked unavailable instead of crashing
    assert payload["findings_drift"][0]["unavailable"] is True
    # policy diff degrades to transformer level via the audit columns
    assert payload["policy_changes"][0]["detail_level"] == "transformer"
    # the summary is still generated and anchored
    assert result["audit"] is not None
    assert verify_audit(workspace.audit_path).entries == 3
    markdown = result["markdown"].read_text(encoding="utf-8")
    assert "异常条目" in markdown
    assert "脱敏产物已清理" in markdown
    assert "单轮报告已清理" in markdown


def test_summary_survives_broken_audit_chain(
    workspace, fixture_files, inventories, make_policy
):
    scan_paths([fixture_files["sqlite"]], workspace)
    inventory = inventories["sqlite"]
    run = _run_and_finalize(workspace, inventory, make_policy(POLICY_A))
    # tamper with the first chain entry
    lines = workspace.audit_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["rows_processed"] = 999
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    workspace.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    before = workspace.audit_path.read_text(encoding="utf-8")

    result = generate_summary(workspace, fingerprint=inventory.fingerprint)
    payload = result["payload"]
    assert payload["audit_chain"]["status"] == "invalid"
    assert payload["audit_chain"]["error"]
    assert any(a["kind"] == "audit_chain_invalid" for a in payload["anomalies"])
    # generation is not interrupted; the run stays included but unverifiable
    assert payload["summary"]["runs_included"] == 1
    assert payload["runs"][0]["run_id"] == run.run_id
    assert payload["runs"][0]["audit"]["anchored"] is None
    # the broken chain is left untouched and the append is skipped
    assert result["audit"] is None
    assert result["audit_error"]
    assert workspace.audit_path.read_text(encoding="utf-8") == before
    markdown = result["markdown"].read_text(encoding="utf-8")
    assert "审计链校验失败" in markdown


def test_summary_marks_unfinished_runs_and_tracks_resume(
    workspace, fixture_files, inventories, make_policy
):
    scan_paths([fixture_files["sqlite"]], workspace)
    inventory = inventories["sqlite"]
    policy = make_policy(POLICY_A)
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(inventory, policy, workspace, batch_size=2, interrupt_after_batches=1)
    run_id = excinfo.value.run_id

    first = generate_summary(workspace, fingerprint=inventory.fingerprint)
    payload = first["payload"]
    assert payload["summary"]["runs_total"] == 1
    assert payload["summary"]["runs_included"] == 0
    assert payload["summary"]["runs_excluded"] == 1
    assert payload["runs"][0]["status"] == "interrupted"
    assert payload["runs"][0]["included"] is False
    assert any(a["kind"] == "run_not_completed" for a in payload["anomalies"])

    # --include-invalid folds the interrupted run into the trends
    relaxed = generate_summary(
        workspace, fingerprint=inventory.fingerprint, include_invalid=True
    )
    assert relaxed["payload"]["summary"]["runs_included"] == 1
    assert relaxed["payload"]["trends"][0]["run_id"] == run_id

    # resume to completion: the same run id becomes a completed, included round
    resumed = execute_run(inventory, policy, workspace, batch_size=3, resume_run_id=run_id)
    finalize_run(workspace, inventory, policy, resumed, detect_inventory(inventory))
    done = generate_summary(workspace, fingerprint=inventory.fingerprint)
    overview = done["payload"]["summary"]
    assert overview["runs_total"] == 1
    assert overview["runs_included"] == 1
    assert overview["runs_excluded"] == 0
    assert done["payload"]["runs"][0]["status"] == "completed"
    assert done["payload"]["runs"][0]["included"] is True
    assert done["payload"]["runs"][0]["audit"]["anchored"] is True


def test_summary_collapses_details_beyond_fifty_runs(workspace, inventories):
    _fabricate_runs(workspace, inventories["sqlite"], 51)
    result = generate_summary(workspace, fingerprint=inventories["sqlite"].fingerprint)
    payload = result["payload"]
    assert payload["summary"]["runs_total"] == 51
    assert payload["summary"]["details_collapsed"] is True
    markdown = result["markdown"].read_text(encoding="utf-8")
    assert "核心变化趋势" in markdown
    main_body, _, appendix = markdown.partition("## 附录：每轮明细")
    assert appendix, "collapsed summary must move details into an appendix"
    # per-run detail blocks live in the appendix, not the main body
    assert "- 状态：completed（已纳入汇总）" not in main_body
    assert appendix.count("- 状态：completed（已纳入汇总）") == 51


def test_summary_collapse_threshold_is_configurable(
    workspace, fixture_files, inventories, make_policy
):
    scan_paths([fixture_files["sqlite"]], workspace)
    inventory = inventories["sqlite"]
    policy = make_policy(POLICY_A)
    _run_and_finalize(workspace, inventory, policy)
    _run_and_finalize(workspace, inventory, policy)
    collapsed = generate_summary(
        workspace, fingerprint=inventory.fingerprint, collapse_threshold=1
    )
    assert collapsed["payload"]["summary"]["details_collapsed"] is True
    assert "## 附录：每轮明细" in collapsed["markdown"].read_text(encoding="utf-8")
    normal = generate_summary(workspace, fingerprint=inventory.fingerprint)
    assert normal["payload"]["summary"]["details_collapsed"] is False
    assert "## 每轮明细" in normal["markdown"].read_text(encoding="utf-8")


def test_findings_drift_detects_added_removed_and_confidence_changes():
    from maskline.summary import _findings_drift

    def finding(table, column, sensitive_type, confidence):
        return {
            "table_name": table,
            "column_name": column,
            "sensitive_type": sensitive_type,
            "confidence": confidence,
            "score": 0.9,
        }

    before = [
        finding("t", "a", "email", "high"),
        finding("t", "b", "mobile_phone", "medium"),
        finding("t", "c", None, "none"),
    ]
    after = [
        finding("t", "b", "mobile_phone", "high"),
        finding("t", "d", "id_card", "high"),
    ]
    runs = [
        {"run_id": "r1", "findings": before},
        {"run_id": "r2", "findings": after},
    ]
    drift = _findings_drift(runs)
    assert len(drift) == 1
    entry = drift[0]
    assert [(f["table_name"], f["column_name"]) for f in entry["added"]] == [("t", "d")]
    assert [(f["table_name"], f["column_name"]) for f in entry["removed"]] == [("t", "a")]
    assert entry["confidence_changed"] == [
        {
            "table_name": "t",
            "column_name": "b",
            "from": {"sensitive_type": "mobile_phone", "confidence": "medium"},
            "to": {"sensitive_type": "mobile_phone", "confidence": "high"},
        }
    ]


def test_summary_compatible_with_demo_flow(tmp_path, secret_store):
    from maskline.demo import run_demo

    demo = run_demo(workspace=tmp_path / "demo")
    paths = Paths.for_workspace(tmp_path / "demo")
    sqlite_inventory = inspect_dataset(paths.raw_dir / "demo.sqlite")
    result = generate_summary(paths, fingerprint=sqlite_inventory.fingerprint)
    payload = result["payload"]
    assert payload["summary"]["runs_total"] == 1
    assert payload["summary"]["runs_included"] == 1
    assert payload["audit_chain"]["status"] == "ok"
    # the demo's own reports and audit chain remain intact
    for report in demo.reports:
        assert report.exists()
    assert verify_audit(paths.audit_path).entries == demo.audit_entries + 1
    # the csv dataset summarises independently
    csv_inventory = inspect_dataset(paths.raw_dir / "leads.csv")
    csv_summary = generate_summary(paths, fingerprint=csv_inventory.fingerprint)
    assert csv_summary["payload"]["summary"]["runs_total"] == 1
    assert verify_audit(paths.audit_path).entries == demo.audit_entries + 2


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="requires /proc")
def test_summary_does_not_leak_file_handles(
    workspace, fixture_files, inventories, make_policy
):
    scan_paths([fixture_files["sqlite"]], workspace)
    inventory = inventories["sqlite"]
    _run_and_finalize(workspace, inventory, make_policy(POLICY_A))
    generate_summary(workspace, fingerprint=inventory.fingerprint)  # warm-up
    gc.collect()
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(5):
        generate_summary(workspace, fingerprint=inventory.fingerprint)
    gc.collect()
    assert len(os.listdir("/proc/self/fd")) <= before


def test_summary_cli(workspace, fixture_files, inventories, make_policy, capsys):
    scan_paths([fixture_files["sqlite"]], workspace)
    inventory = inventories["sqlite"]
    _run_and_finalize(workspace, inventory, make_policy(POLICY_A))
    rc = main(
        ["summary", "--workspace", str(workspace.root),
         "--fingerprint", inventory.fingerprint]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "summary=" in out and "audit_seq=" in out
    rc = main(
        ["summary", "--workspace", str(workspace.root),
         "--dataset", str(fixture_files["sqlite"])]
    )
    assert rc == 0
    rc = main(["summary", "--workspace", str(workspace.root), "--fingerprint", "0" * 64])
    assert rc == 2
