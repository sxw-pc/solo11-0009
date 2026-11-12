"""End-to-end tests for the read-only evaluation engine and reports."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from maskline.evaluate import (
    EvaluationConfig,
    Evaluator,
    JoinSpec,
    QISpec,
)
from maskline.evaluate.access import schema_of
from maskline.evaluate.report import (
    ReportSafetyError,
    assert_no_plaintext,
    write_reports,
)
from maskline.evaluate.workflow import parse_join, parse_qi, run_evaluation
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.utils import sqlite_content_digest

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _run_evaluation(source, product, workspace, qi=None, joins=None, **kwargs):
    config = EvaluationConfig(**kwargs)
    evaluator = Evaluator(
        Path(source),
        Path(product),
        qi or [],
        joins or [],
        config,
    )
    return evaluator.run()


def test_evaluation_covers_cardinality_null_and_distribution_metrics(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    report = _run_evaluation(
        fixture_files["sqlite"], result.output_path, workspace,
        qi=[QISpec("customers", ("birth_date", "address"))],
        joins=[JoinSpec("customers", "customer_id", "orders", "customer_id")],
    )
    customers = next(table for table in report.tables if table.table == "customers")
    by_name = {column["column"]: column for column in customers.columns}
    # Cardinality and null-rate metrics exist for every shared column.
    for column in customers.columns:
        assert "cardinality" in column and "null_rate" in column
        assert 0.0 <= column["null_rate"]["product"] <= 1.0
    # Categorical column carries a TVD distribution with bucket shares.
    status = by_name["status"]
    dist = status["categorical_distribution"]
    assert 0.0 <= dist["tvd"] <= 1.0
    assert all("source_share" in bucket and "product_share" in bucket for bucket in dist["buckets"])
    # Numeric declared column is histogrammed; phone (TEXT digits) stays categorical.
    assert "numeric_distribution" in by_name["balance"]
    assert "categorical_distribution" in by_name["phone"]


def test_fully_nullified_column_is_flagged_zero_utility(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    nulled = workspace.root / "nulled.sqlite"
    import shutil
    shutil.copy(result.output_path, nulled)
    conn = sqlite3.connect(nulled)
    conn.execute("UPDATE customers SET balance = NULL")
    conn.commit()
    conn.close()
    report = _run_evaluation(fixture_files["sqlite"], nulled, workspace)
    balance = next(
        column
        for table in report.tables if table.table == "customers"
        for column in table.columns if column["column"] == "balance"
    )
    assert balance["utility_status"] == "zero"
    assert balance["null_rate"]["product"] == 1.0
    assert "归零" in balance["utility_note"]
    assert any("balance" in warning for warning in report.warnings)


def test_nullified_column_does_not_crash_and_missing_column_warns(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    dropped = workspace.root / "dropped.sqlite"
    import shutil
    shutil.copy(result.output_path, dropped)
    conn = sqlite3.connect(dropped)
    conn.execute("ALTER TABLE customers RENAME TO c_old")
    conn.execute("CREATE TABLE customers AS SELECT customer_id, status FROM c_old")
    conn.execute("DROP TABLE c_old")
    conn.commit()
    conn.close()
    report = _run_evaluation(fixture_files["sqlite"], dropped, workspace)
    # Evaluation completes and emits structural warnings rather than raising.
    assert any("phone" in warning for warning in report.warnings)
    customers = next(table for table in report.tables if table.table == "customers")
    assert {column["column"] for column in customers.columns} == {"customer_id", "status"}


def test_join_retention_measured_with_bloom_filter(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    join = JoinSpec("customers", "customer_id", "orders", "customer_id")
    report = _run_evaluation(
        fixture_files["sqlite"], result.output_path, workspace, joins=[join]
    )
    entry = report.joins[0]
    assert entry["status"] == "ok"
    # Keys are untouched by the example policy, so retention must be perfect.
    assert entry["product"]["retention_ratio"] == 1.0
    assert entry["product"]["child_rows_evaluated"] == entry["product"]["matched_rows"]
    assert entry["product"]["bloom_filter"]["byte_size"] > 0


def test_join_retention_detects_broken_relationship(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    broken = workspace.root / "broken.sqlite"
    import shutil
    shutil.copy(result.output_path, broken)
    conn = sqlite3.connect(broken)
    # Wipe half of the parent keys so child rows can no longer join.
    conn.execute("UPDATE customers SET customer_id = customer_id + 1000 WHERE customer_id <= 3")
    conn.commit()
    conn.close()
    join = JoinSpec("customers", "customer_id", "orders", "customer_id")
    report = _run_evaluation(fixture_files["sqlite"], broken, workspace, joins=[join])
    assert report.joins[0]["product"]["retention_ratio"] < 1.0


def test_qi_equivalence_classes_match_exact_sql(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    qi = QISpec("customers", ("birth_date", "address"))
    report = _run_evaluation(
        fixture_files["sqlite"], result.output_path, workspace, qi=[qi]
    )
    entry = report.quasi_identifiers[0]
    assert entry["status"] == "ok"
    truth = sqlite3.connect(result.output_path)
    try:
        exact_classes = truth.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM customers GROUP BY birth_date, address)"
        ).fetchone()[0]
        exact_singletons = truth.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM customers "
            "GROUP BY birth_date, address HAVING COUNT(*) = 1)"
        ).fetchone()[0]
    finally:
        truth.close()
    assert entry["equivalence_class_count"] == exact_classes
    assert entry["singleton_class_count"] == exact_singletons
    assert entry["min_class_size"] >= 1
    assert 0.0 <= entry["unique_ratio"] <= 1.0


def test_qi_external_spill_stays_exact(tmp_path):
    # Large distinct QI with a deliberately tiny in-memory cap forces spill;
    # results must remain exact against SQL GROUP BY.
    source = tmp_path / "src.sqlite"
    product = tmp_path / "prd.sqlite"
    for path, distinct in ((source, 40_000), (product, 40_000)):
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b TEXT)")
        conn.executemany(
            "INSERT INTO t VALUES (?,?,?)",
            [(i, f"a{i}", f"b{i % 7_000}") for i in range(distinct)],
        )
        conn.commit()
        conn.close()
    report = _run_evaluation(
        source, product, type("P", (), {"root": tmp_path})(),
        qi=[QISpec("t", ("a", "b"))],
        max_memory_keys=2000,
        spill_dir=tmp_path / "spill",
    )
    entry = report.quasi_identifiers[0]
    assert entry["external_spill_used"] is True
    assert entry["equivalence_class_count"] == 40_000
    assert entry["singleton_class_count"] == 40_000
    # No spill files remain after the run.
    assert not any((tmp_path / "spill").rglob("*.bin"))


def test_reports_contain_no_plaintext_and_match_across_formats(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    report = _run_evaluation(
        fixture_files["sqlite"], result.output_path, workspace,
        qi=[QISpec("customers", ("status",))],
    )
    forbidden = []
    source_conn = sqlite3.connect(fixture_files["sqlite"])
    try:
        for value, in source_conn.execute("SELECT full_name FROM customers"):
            forbidden.append(value)
    finally:
        source_conn.close()
    paths = write_reports(report, workspace.reports_dir, forbidden_values=forbidden)
    json_text = paths["json"].read_text(encoding="utf-8")
    md_text = paths["markdown"].read_text(encoding="utf-8")
    for value in forbidden:
        assert value not in json_text
        assert value not in md_text
    payload = json.loads(json_text)
    # The same numbers appear in both formats.
    customers = next(table for table in payload["tables"] if table["table"] == "customers")
    for column in customers["columns"]:
        assert str(column["cardinality"]["product_distinct_estimate"]) in md_text


def test_redaction_guard_fails_closed_on_leak():
    with pytest.raises(ReportSafetyError):
        assert_no_plaintext({"leak": "机密明文ABC"}, ["机密明文ABC"])


def test_workflow_writes_audit_entry_and_both_reports(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    payload = run_evaluation(
        paths=workspace,
        source=fixture_files["sqlite"],
        product=result.output_path,
        qi_expressions=["customers:status"],
        join_expressions=["customers.customer_id=orders.customer_id"],
        bucket_count=10,
        min_bucket=5,
        top_k=64,
        spill_dir=None,
        max_memory_keys=200_000,
    )
    assert Path(payload["json"]).exists() and Path(payload["markdown"]).exists()
    assert payload["audit_seq"] >= 1
    # The audit chain still verifies after the evaluation entry is appended.
    from maskline.audit import AuditLog, read_audit_entries
    verification = AuditLog(workspace.audit_path).verify()
    assert verification.entries == payload["audit_seq"]
    entries = read_audit_entries(workspace.audit_path)
    eval_entry = entries[-1]
    assert eval_entry["event"] == "evaluation"
    assert eval_entry["source_hash"] and eval_entry["product_hash"]


def test_spec_parsing_rejects_malformed_expressions():
    qi = parse_qi("customers:status,age")
    assert qi.table == "customers" and qi.columns == ("status", "age")
    join = parse_join("customers.customer_id=orders.customer_id")
    assert join.parent_table == "customers" and join.child_column == "customer_id"
    with pytest.raises(Exception):
        parse_qi("no-colon")
    with pytest.raises(Exception):
        parse_join("bad-format")


def test_unknown_qi_column_raises_input_error(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    with pytest.raises(Exception):
        _run_evaluation(
            fixture_files["sqlite"], result.output_path, workspace,
            qi=[QISpec("customers", ("nonexistent",))],
        )


def test_source_dataset_opened_read_only_and_unchanged(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=4)
    before = sqlite_content_digest(fixture_files["sqlite"])
    _run_evaluation(fixture_files["sqlite"], result.output_path, workspace)
    after = sqlite_content_digest(fixture_files["sqlite"])
    assert before == after


def test_csv_source_evaluates_against_sqlite_product(
    workspace, fixture_files, inventories, secret_store
):
    policy = load_policy(EXAMPLE)
    result = execute_run(inventories["csv"], policy, workspace, secrets_store=secret_store, batch_size=4)
    report = _run_evaluation(
        fixture_files["csv"], result.output_path, workspace,
        qi=[QISpec("leads", ("address", "stage"))],
    )
    leads = next(table for table in report.tables if table.table == "leads")
    assert leads.source_rows == leads.product_rows
    assert report.quasi_identifiers[0]["status"] == "ok"
    assert schema_of(fixture_files["csv"])  # schema read works on CSV
