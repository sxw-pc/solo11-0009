import json
import sqlite3

from maskline.detectors.engine import detect_inventory
from maskline.pipeline.runner import execute_run
from maskline.report import generate_report

def test_report_contains_findings_samples_and_unconfigured_warning(
    workspace, fixture_files, inventories, make_policy
):
    policy = make_policy(
        """
        version: 1
        name: partial
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  phone:
                    transformer: mask
                    params: {keep_prefix: 3, keep_suffix: 4}
        """
    )
    result = execute_run(inventories["sqlite"], policy, workspace, batch_size=2)
    findings = detect_inventory(inventories["sqlite"])
    artifacts = generate_report(workspace, inventories["sqlite"], policy, result, findings)
    assert artifacts["markdown"].exists() and artifacts["json"].exists()
    markdown = artifacts["markdown"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json"].read_text(encoding="utf-8"))
    assert "未配置策略告警" in markdown
    assert "字段发现" in markdown and "抽样前后对比" in markdown
    warning_columns = {item["column_name"] for item in payload["warnings"]}
    assert {"full_name", "id_card", "bank_card"} <= warning_columns
    source = sqlite3.connect(fixture_files["sqlite"])
    try:
        phone, id_card = source.execute(
            "SELECT phone, id_card FROM customers ORDER BY customer_id LIMIT 1"
        ).fetchone()
    finally:
        source.close()
    assert phone not in markdown
    assert id_card not in markdown
    assert len(payload["samples"]["customers"]) == 5
    assert payload["samples"]["customers"][0]["before"]["phone"] == "[源值已隐藏]"
    assert payload["samples"]["customers"][0]["after"]["phone"].startswith(phone[:3])
    assert payload["run"]["output_hash"] == result.output_hash
