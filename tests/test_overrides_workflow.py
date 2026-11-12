import json
import sqlite3

import pytest

from maskline.audit import AuditLog, read_audit_entries, verify_audit
from maskline.overrides import OverrideError
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.registry import Catalog, inspect_dataset
from maskline.report import generate_report
from maskline.workflow import adjudications_for, scan_paths

OPERATOR = "sec-reviewer"


def write_overrides(paths, text, name="overrides.yaml"):
    import textwrap

    target = paths.root / name
    target.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return target


def scalar(path, sql, params=()):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


def test_scan_merges_overrides_and_persists_effective_findings(
    workspace, fixture_files, monkeypatch
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: id_card
            decision: force_not_sensitive
            reason: 测试构造的误报列，人工确认不是身份证
          - dataset: demo.sqlite
            table: customers
            column: customer_id
            decision: force_sensitive
            reason: 内部工号，检测器漏报，必须按敏感字段处理
        """,
    )
    summaries = scan_paths([fixture_files["sqlite"]], workspace)
    assert len(summaries) == 1
    summary = summaries[0]
    finding_map = {(f["table_name"], f["column_name"]): f for f in summary.findings}

    suppressed = finding_map[("customers", "id_card")]
    assert suppressed["confidence"] == "none"
    assert suppressed["sensitive_type"] is None
    assert suppressed["detected_confidence"] == "high"
    assert suppressed["override"]["decision"] == "force_not_sensitive"
    assert "误报列" in suppressed["override"]["reason"]

    forced = finding_map[("customers", "customer_id")]
    assert forced["confidence"] == "high"
    assert forced["sensitive_type"]
    assert forced["detected_confidence"] == "none"
    assert forced["override"]["decision"] == "force_sensitive"

    with Catalog(workspace.meta_db) as catalog:
        stored = {
            (f["table_name"], f["column_name"]): f
            for f in catalog.findings_for(summary.inventory.fingerprint)
        }
    assert stored[("customers", "id_card")]["confidence"] == "none"
    assert stored[("customers", "id_card")]["detected_confidence"] == "high"
    assert stored[("customers", "id_card")]["override_decision"] == "force_not_sensitive"
    assert stored[("customers", "customer_id")]["confidence"] == "high"
    assert stored[("customers", "customer_id")]["override_decision"] == "force_sensitive"

    records = adjudications_for(workspace, summary.inventory.fingerprint)
    assert {record["column_name"] for record in records} == {"id_card", "customer_id"}
    assert all(record["operator"] == OPERATOR for record in records)


def test_scan_appends_one_adjudication_audit_event_per_scan(
    workspace, fixture_files, monkeypatch
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_not_sensitive
            reason: 已确认客服热线
        """,
    )
    summaries = scan_paths([fixture_files["sqlite"]], workspace)
    entries = read_audit_entries(workspace.audit_path)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["event"] == "adjudication"
    assert entry["operator"] == OPERATOR
    assert entry["dataset_fingerprint"] == summaries[0].inventory.fingerprint
    assert entry["applied"][0]["column"] == "phone"
    assert entry["registry_ids"] == summaries[0].adjudication_ids
    assert "ts" in entry
    verification = verify_audit(workspace.audit_path)
    assert verification.entries == 1


def test_unmatched_adjudication_is_reported_when_column_is_removed(
    workspace, fixture_files, monkeypatch
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_not_sensitive
            reason: r
        """,
    )
    scan_paths([fixture_files["sqlite"]], workspace)

    conn = sqlite3.connect(fixture_files["sqlite"])
    conn.execute("ALTER TABLE customers RENAME COLUMN phone TO phone_legacy")
    conn.commit()
    conn.close()

    summaries = scan_paths([fixture_files["sqlite"]], workspace)
    summary = summaries[0]
    unmatched = [item for item in summary.unmatched if item.kind == "column"]
    assert len(unmatched) == 1
    assert unmatched[0].entry.column == "phone"
    assert "not found" in unmatched[0].reason
    assert summary.adjudications.applied == []


def test_unmatched_adjudication_is_reported_when_dataset_is_gone(
    workspace, fixture_files, monkeypatch, tmp_path
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: other.sqlite
            table: people
            column: ssn
            decision: force_sensitive
            reason: r
        """,
    )
    summaries = scan_paths([fixture_files["sqlite"]], workspace)
    unmatched = summaries[0].unmatched
    assert any(item.kind == "dataset" for item in unmatched)
    assert any("renamed or removed" in item.reason for item in unmatched)


def test_scan_without_operator_or_file_behaves_as_before(workspace, fixture_files, monkeypatch):
    monkeypatch.delenv("MASKLINE_OPERATOR", raising=False)
    summaries = scan_paths([fixture_files["sqlite"]], workspace)
    finding_map = {
        (f["table_name"], f["column_name"]): f for f in summaries[0].findings
    }
    assert finding_map[("customers", "phone")]["confidence"] == "high"
    assert "override" not in finding_map[("customers", "phone")]
    with Catalog(workspace.meta_db) as catalog:
        assert catalog.adjudications_for(summaries[0].inventory.fingerprint) == []


def test_overrides_without_operator_fail_loudly(workspace, fixture_files, monkeypatch):
    monkeypatch.delenv("MASKLINE_OPERATOR", raising=False)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_not_sensitive
            reason: r
        """,
    )
    with pytest.raises(OverrideError, match="MASKLINE_OPERATOR"):
        scan_paths([fixture_files["sqlite"]], workspace)


def test_force_not_sensitive_still_masks_when_policy_configures_it(
    workspace, fixture_files, inventories, secret_store, monkeypatch
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_not_sensitive
            reason: 已确认客服热线，但策略尚未同步
        """,
    )
    import textwrap

    policy_path = workspace.root / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            name: conflict-test
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone:
                        transformer: mask
                        params: {keep_prefix: 3, keep_suffix: 4}
            """
        ).lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)
    summaries = scan_paths(
        [fixture_files["sqlite"]], workspace, policy=policy
    )
    summary = summaries[0]
    assert len(summary.adjudications.conflicts) == 1
    conflict = summary.adjudications.conflicts[0]
    assert (conflict.table, conflict.column, conflict.transformer) == (
        "customers",
        "phone",
        "mask",
    )
    findings = summary.findings
    result = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store
    )
    # Execution layer still masks: every value differs from the source.
    source_conn = sqlite3.connect(fixture_files["sqlite"])
    out_conn = sqlite3.connect(result.output_path)
    try:
        source = source_conn.execute("SELECT phone FROM customers ORDER BY 1").fetchall()
        masked = out_conn.execute("SELECT phone FROM customers ORDER BY 1").fetchall()
    finally:
        source_conn.close()
        out_conn.close()
    assert all(before[0] != after[0] for before, after in zip(source, masked))
    assert all("****" in after[0] for after in masked)

    artifacts = generate_report(
        workspace, inventories["sqlite"], policy, result, findings,
        adjudications=summary.adjudications,
    )
    markdown = artifacts["markdown"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json"].read_text(encoding="utf-8"))
    assert "人工裁定冲突" in markdown
    assert "仍执行脱敏" in markdown
    assert payload["adjudications"]["conflicts"][0]["execution"] == "masked"
    assert payload["adjudications"]["conflicts"][0]["transformer"] == "mask"


def test_report_marks_adjudicated_columns_with_reason(
    workspace, fixture_files, inventories, secret_store, monkeypatch
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: id_card
            decision: force_not_sensitive
            reason: 人工确认该列不是身份证
          - dataset: demo.sqlite
            table: customers
            column: customer_id
            decision: force_sensitive
            reason: 内部工号
        """,
    )
    import textwrap

    policy_path = workspace.root / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            name: report-test
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone:
                        transformer: mask
                        params: {keep_prefix: 3, keep_suffix: 4}
            """
        ).lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)
    summary = scan_paths([fixture_files["sqlite"]], workspace, policy=policy)[0]
    result = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store
    )
    artifacts = generate_report(
        workspace, inventories["sqlite"], policy, result, summary.findings,
        adjudications=summary.adjudications,
    )
    markdown = artifacts["markdown"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json"].read_text(encoding="utf-8"))
    assert "强制非敏感：人工确认该列不是身份证" in markdown
    assert "强制敏感：内部工号" in markdown
    assert OPERATOR in markdown
    finding_map = {
        (f["table_name"], f["column_name"]): f for f in payload["findings"]
    }
    assert finding_map[("customers", "id_card")]["override"]["reason"] == "人工确认该列不是身份证"
    assert finding_map[("customers", "customer_id")]["effective_confidence"] == "high"


def test_registry_keeps_adjudication_history(workspace, fixture_files, monkeypatch):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_not_sensitive
            reason: first decision
        """,
    )
    first = scan_paths([fixture_files["sqlite"]], workspace)[0]
    fingerprint = first.inventory.fingerprint
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_sensitive
            reason: reversed decision
        """,
    )
    scan_paths([fixture_files["sqlite"]], workspace)
    records = adjudications_for(workspace, fingerprint)
    assert [record["decision"] for record in records] == [
        "force_not_sensitive",
        "force_sensitive",
    ]
    assert all(record["operator"] == OPERATOR for record in records)


def test_run_audit_entry_carries_operator_and_adjudications(
    workspace, fixture_files, inventories, secret_store, monkeypatch
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    from maskline.workflow import finalize_run

    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: id_card
            decision: force_not_sensitive
            reason: 误报列
        """,
    )
    import textwrap

    policy_path = workspace.root / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: 1
            name: audit-adjudication-test
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone:
                        transformer: mask
                        params: {keep_prefix: 3, keep_suffix: 4}
            """
        ).lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)
    summary = scan_paths(
        [fixture_files["sqlite"]], workspace, policy=policy, audit_adjudications=False
    )[0]
    result = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store
    )
    finalize_run(
        workspace, inventories["sqlite"], policy, result, summary.findings,
        adjudications=summary.adjudications,
    )
    entries = read_audit_entries(workspace.audit_path)
    assert len(entries) == 1, "run scans must not emit a duplicate adjudication event"
    entry = entries[0]
    assert entry["operator"] == OPERATOR
    assert entry["adjudications"]["applied"][0]["column"] == "id_card"
    assert entry["adjudications"]["applied"][0]["reason"] == "误报列"
    verify_audit(workspace.audit_path)


def test_malformed_override_file_fails_scan(workspace, fixture_files, monkeypatch):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_not_sensitive
        """,
    )
    with pytest.raises(OverrideError, match="reason"):
        scan_paths([fixture_files["sqlite"]], workspace)


def test_no_overrides_flag_bypasses_broken_workspace_file(
    workspace, fixture_files, monkeypatch
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(workspace, "version: 1\noverrides:\n  - bad: true\n")
    summaries = scan_paths(
        [fixture_files["sqlite"]], workspace, use_default_overrides=False
    )
    applied = summaries[0].adjudications
    assert applied is not None and applied.applied == [] and applied.matched == []


def test_override_decision_applies_to_correct_dataset_in_directory_scan(
    workspace, fixture_files, monkeypatch
):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    write_overrides(
        workspace,
        """
        version: 1
        overrides:
          - dataset: leads.csv
            table: leads
            column: mobile
            decision: force_not_sensitive
            reason: 人工确认为公开号码
        """,
    )
    summaries = scan_paths(
        [fixture_files["sqlite"], fixture_files["csv"]], workspace
    )
    by_name = {summary.inventory.path.name: summary for summary in summaries}
    csv_findings = {
        (f["table_name"], f["column_name"]): f
        for f in by_name["leads.csv"].findings
    }
    sqlite_findings = {
        (f["table_name"], f["column_name"]): f
        for f in by_name["demo.sqlite"].findings
    }
    assert csv_findings[("leads", "mobile")]["confidence"] == "none"
    assert sqlite_findings[("customers", "phone")]["confidence"] == "high"
    assert by_name["demo.sqlite"].adjudications.applied == []
