import json
import os
import sqlite3
from pathlib import Path

import pytest

from maskline.__main__ import main
from maskline.audit import read_audit_entries, verify_audit

OPERATOR = "security-ops-test"

POLICY_TEXT = """\
version: 1
name: cli-overrides-test
datasets:
  - path: demo.sqlite
    tables:
      customers:
        columns:
          phone:
            transformer: mask
            params: {keep_prefix: 3, keep_suffix: 4}
"""

OVERRIDES_TEXT = """\
version: 1
overrides:
  - dataset: demo.sqlite
    table: customers
    column: address
    decision: force_not_sensitive
    reason: 人工确认只是城市级地址，不是可识别个人信息
  - dataset: demo.sqlite
    table: customers
    column: customer_id
    decision: force_sensitive
    reason: 内部工号，检测器漏报，必须按敏感字段处理
"""


def setup_workspace(paths, fixture_files, monkeypatch):
    monkeypatch.setenv("MASKLINE_OPERATOR", OPERATOR)
    (paths.root / "policy.yaml").write_text(POLICY_TEXT, encoding="utf-8")
    (paths.root / "overrides.yaml").write_text(OVERRIDES_TEXT, encoding="utf-8")
    return paths.root


def test_scan_cli_surfaces_adjudications_conflicts_and_unmatched(
    workspace, fixture_files, monkeypatch, capsys
):
    root = setup_workspace(workspace, fixture_files, monkeypatch)
    code = main(["scan", str(fixture_files["sqlite"]), "--workspace", str(root)])
    out = capsys.readouterr().out
    assert code == 0
    assert "customers.customer_id -> manual_adjudication" in out
    assert "force_sensitive" in out
    assert "内部工号" in out
    assert "customers.address -> non-sensitive" in out
    assert "force_not_sensitive" in out
    assert "人工确认只是城市级地址" in out

    # Plain scan has no policy, so it only notes that conflicts were not checked.
    assert "! conflict:" not in out
    assert "conflicts are not evaluated" in out

    # Rename the adjudicated column: the next scan must say so.
    conn = sqlite3.connect(fixture_files["sqlite"])
    conn.execute("ALTER TABLE customers RENAME COLUMN address TO address_legacy")
    conn.commit()
    conn.close()
    code = main(["scan", str(fixture_files["sqlite"]), "--workspace", str(root)])
    out = capsys.readouterr().out
    assert code == 0
    assert "unmatched adjudication" in out
    assert "customers.address" in out
    assert "not found" in out


def test_scan_cli_rejects_overrides_without_operator(
    workspace, fixture_files, monkeypatch, capsys
):
    monkeypatch.delenv("MASKLINE_OPERATOR", raising=False)
    root = setup_workspace(workspace, fixture_files, monkeypatch)
    # setup_workspace sets the env var; clear it afterwards for this test.
    monkeypatch.delenv("MASKLINE_OPERATOR", raising=False)
    code = main(["scan", str(fixture_files["sqlite"]), "--workspace", str(root)])
    err = capsys.readouterr().err
    assert code == 2
    assert "MASKLINE_OPERATOR" in err
    assert "written" not in err


def test_run_cli_flags_conflict_but_still_masks_and_audits(
    workspace, fixture_files, monkeypatch, capsys
):
    root = setup_workspace(workspace, fixture_files, monkeypatch)
    # Make the adjudicated non-sensitive column one the policy transforms.
    (root / "policy.yaml").write_text(
        POLICY_TEXT.replace(
            "params: {keep_prefix: 3, keep_suffix: 4}",
            "params: {keep_prefix: 3, keep_suffix: 4}\n          address:\n"
            "            transformer: generalize\n            params: {mode: address}",
        ),
        encoding="utf-8",
    )
    secret = root / "data" / "secret.txt"
    from maskline.config import create_demo_secret

    create_demo_secret(secret)
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(secret))
    code = main(
        [
            "run",
            "--dataset", str(fixture_files["sqlite"]),
            "--policy", str(root / "policy.yaml"),
            "--workspace", str(root),
            "--output", str(root / "data/out/customers.test.sqlite"),
            "--batch-size", "2",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "conflict: customers.address" in out
    assert "masking is kept" in out
    assert "audit_seq=" in out

    result_path = root / "data/out/customers.test.sqlite"
    source = sqlite3.connect(fixture_files["sqlite"])
    target = sqlite3.connect(result_path)
    try:
        before = source.execute(
            "SELECT address FROM customers ORDER BY customer_id"
        ).fetchall()
        after = target.execute(
            "SELECT address FROM customers ORDER BY customer_id"
        ).fetchall()
    finally:
        source.close()
        target.close()
    assert all(row[0] != row[1] for row in zip(before, after))

    entries = read_audit_entries(workspace.audit_path)
    assert len(entries) == 1
    assert entries[0]["operator"] == OPERATOR
    assert entries[0]["adjudications"]["applied"]
    assert entries[0]["adjudications"]["conflicts"][0]["transformer"] == "generalize"
    verify_audit(workspace.audit_path)

    report_md = next((root / "reports").glob("*.md"))
    report_json = next((root / "reports").glob("*.json"))
    markdown = report_md.read_text(encoding="utf-8")
    payload = json.loads(report_json.read_text(encoding="utf-8"))
    assert "人工裁定冲突" in markdown
    assert "强制非敏感：人工确认只是城市级地址" in markdown
    assert "强制敏感：内部工号" in markdown
    assert payload["adjudications"]["conflicts"][0]["execution"] == "masked"


def test_run_cli_no_overrides_ignores_workspace_file(
    workspace, fixture_files, monkeypatch, capsys
):
    root = setup_workspace(workspace, fixture_files, monkeypatch)
    monkeypatch.delenv("MASKLINE_OPERATOR", raising=False)
    code = main(
        [
            "scan", str(fixture_files["sqlite"]), "--workspace", str(root), "--no-overrides",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "customers.address -> address" in out
    assert "force_not_sensitive" not in out


def test_scan_cli_detects_dataset_rename(
    workspace, fixture_files, monkeypatch, capsys, tmp_path
):
    root = setup_workspace(workspace, fixture_files, monkeypatch)
    new_dir = tmp_path / "renamed-dir"
    new_dir.mkdir()
    fixture_files["sqlite"].rename(new_dir / "renamed.sqlite")
    old = os.getcwd()
    os.chdir(new_dir)
    try:
        code = main(["scan", ".", "--workspace", str(root)])
        out = capsys.readouterr().out
    finally:
        os.chdir(old)
    assert code == 0
    assert "unmatched adjudication" in out
    assert "renamed or removed" in out
