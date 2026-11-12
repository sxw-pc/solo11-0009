import json
import sqlite3

import pytest

from maskline.conditions import Condition, ConditionError, evaluate, parse_condition
from maskline.detectors.engine import detect_inventory
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import PolicyError
from maskline.config import Paths
from maskline.registry import inspect_dataset
from maskline.report import generate_report


def make_orders_db(path):
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE orders ("
            "order_id INTEGER PRIMARY KEY, tier TEXT, amount REAL, "
            "phone TEXT, notes TEXT)"
        )
        conn.executemany(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?)",
            [
                (1, "VIP", 1500000.0, "13800000001", "vip big"),
                (2, "normal", 2000000.0, "13800000002", "big"),
                (3, "normal", 500.0, "13800000003", "small"),
                (4, "normal", None, "13800000004", "null amount"),
                (5, None, 3000000.0, "13800000005", "null tier"),
                # 1000000.4 rounds to 1000000; the condition must still see
                # the original value and match (> 1000000).
                (6, "normal", 1000000.4, "13800000006", "rounding"),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return path


@pytest.fixture
def orders_inventory(tmp_path):
    return inspect_dataset(make_orders_db(tmp_path / "orders.sqlite"))


@pytest.fixture
def conditional_policy(make_policy):
    return make_policy(
        """
        version: 1
        name: conditional
        datasets:
          - path: orders.sqlite
            tables:
              orders:
                columns:
                  phone:
                    transformer: mask
                    params: {keep_prefix: 3, keep_suffix: 4}
                    when: {column: tier, op: ne, value: VIP}
                  notes:
                    transformer: nullify
                    when: {column: amount, op: gt, value: 1000000}
                  amount:
                    transformer: round
                    params: {decimals: 0}
        """
    )


def target_rows(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT order_id, tier, amount, phone, notes FROM orders ORDER BY order_id"
        ).fetchall()
    finally:
        conn.close()


# --- operator semantics -------------------------------------------------

def test_eq_and_ne_compare_numbers_and_strings():
    assert evaluate("eq", "active", "active") is True
    assert evaluate("eq", "active", "VIP") is False
    assert evaluate("ne", "active", "VIP") is True
    assert evaluate("eq", 5, 5.0) is True
    # CSV cells are strings; numeric YAML literals still match them.
    assert evaluate("eq", "100", 100) is True
    assert evaluate("ne", "100", 100) is False
    # Both-string comparisons stay literal (no numeric coercion surprises).
    assert evaluate("eq", "007", "7") is False
    assert evaluate("eq", "007", "007") is True


def test_gt_and_lt_are_numeric_and_fail_closed():
    assert evaluate("gt", 2000000.0, 1000000) is True
    assert evaluate("gt", "2000000", 1000000) is True
    assert evaluate("lt", "500", 1000000) is True
    assert evaluate("gt", 500, 1000000) is False
    assert evaluate("gt", "not-a-number", 1000000) is False
    assert evaluate("lt", None, 1000000) is False


def test_contains_matches_substrings():
    assert evaluate("contains", "ORD-00042", "ORD-") is True
    assert evaluate("contains", "ORD-00042", "INV-") is False
    assert evaluate("contains", 12345, "234") is True
    assert evaluate("contains", None, "x") is False


def test_is_null_matches_null_and_empty_string():
    assert evaluate("is_null", None) is True
    assert evaluate("is_null", "") is True
    assert evaluate("is_null", "x") is False
    assert evaluate("is_null", 0) is False


def test_null_operand_never_matches_comparison_operators():
    for op in ("eq", "ne", "gt", "lt", "contains"):
        assert evaluate(op, None, "anything") is False


def test_condition_matches_uses_named_column_and_fails_closed():
    condition = Condition("tier", "ne", "VIP")
    assert condition.matches({"tier": "normal"}) is True
    assert condition.matches({"tier": "VIP"}) is False
    assert condition.matches({"tier": None}) is False
    assert condition.matches({"other": "normal"}) is False


def test_unknown_operator_is_rejected_at_evaluation():
    with pytest.raises(ConditionError, match="unknown condition operator"):
        evaluate("regex", "x", "y")


# --- load-time validation -----------------------------------------------

def test_invalid_operator_fails_policy_load(make_policy):
    with pytest.raises(PolicyError, match="unknown condition operator.*eq.*ne"):
        make_policy(
            """
            version: 1
            name: bad
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone:
                        transformer: mask
                        when: {column: status, op: regex, value: "^vip"}
            """
        )


def test_when_referencing_unknown_column_fails_validation(make_policy, inventories):
    policy = make_policy(
        """
        version: 1
        name: bad
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  phone:
                    transformer: mask
                    when: {column: no_such_column, op: eq, value: x}
        """
    )
    with pytest.raises(PolicyError, match="unknown column.*no_such_column"):
        policy.validate_against(inventories["sqlite"])


@pytest.mark.parametrize(
    "when, message",
    [
        ("{column: status, op: gt, value: '100'}", "numeric"),
        ("{column: status, op: lt, value: true}", "numeric"),
        ("{column: status, op: contains, value: 100}", "non-empty string"),
        ("{column: status, op: is_null, value: 1}", "does not take a 'value'"),
        ("{column: status, op: eq}", "requires a 'value'"),
        ("{column: status, op: eq, value: null}", "is_null"),
        ("{column: status, op: eq, value: [1, 2]}", "scalar"),
        ("{column: status, op: eq, value: x, extra: 1}", "unknown keys"),
        ("{op: eq, value: x}", "when.column"),
    ],
)
def test_malformed_when_fails_policy_load(make_policy, when, message):
    with pytest.raises(PolicyError, match=message):
        make_policy(
            f"""
            version: 1
            name: bad
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone:
                        transformer: mask
                        when: {when}
            """
        )


def test_when_must_be_a_mapping(make_policy):
    with pytest.raises(PolicyError, match="'when' must be a mapping"):
        make_policy(
            """
            version: 1
            name: bad
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone:
                        transformer: mask
                        when: "status == 'VIP'"
            """
        )


def test_condition_is_part_of_policy_fingerprint(make_policy):
    base = """
        version: 1
        name: fp
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  phone:
                    transformer: mask
                    {condition}
    """
    without = make_policy(base.format(condition=""))
    with_when = make_policy(
        base.format(condition="when: {column: status, op: ne, value: active}")
    )
    other_when = make_policy(
        base.format(condition="when: {column: status, op: eq, value: active}")
    )
    same_when = make_policy(
        base.format(condition="when: {column: status, op: ne, value: active}")
    )
    assert without.fingerprint != with_when.fingerprint
    assert with_when.fingerprint != other_when.fingerprint
    assert with_when.fingerprint == same_when.fingerprint
    column = without.datasets[0].tables["customers"].columns["phone"]
    assert "when" not in column.to_dict()


# --- end-to-end behaviour -----------------------------------------------

def test_conditional_rules_apply_per_row(workspace, orders_inventory, conditional_policy):
    result = execute_run(orders_inventory, conditional_policy, workspace, batch_size=2)
    rows = {row[0]: row for row in target_rows(result.output_path)}
    # phone: masked unless tier == 'VIP'; NULL tier never matches.
    assert rows[1][3] == "13800000001"  # VIP keeps the original
    assert rows[5][3] == "13800000005"  # NULL tier keeps the original
    for order_id in (2, 3, 4, 6):
        assert "****" in rows[order_id][3]
    # notes: nullified when the original amount > 1000000.
    assert rows[1][4] is None
    assert rows[2][4] is None
    assert rows[5][4] is None
    assert rows[3][4] == "small"
    assert rows[4][4] == "null amount"  # NULL amount -> condition not satisfied
    # Row 6: amount rounds to exactly 1000000, but the condition must use the
    # original 1000000.4 and therefore match.
    assert rows[6][2] == 1000000
    assert rows[6][4] is None
    # Per-rule hit/skip counts.
    assert result.condition_counts["orders.phone"] == {"matched": 4, "skipped": 2}
    assert result.condition_counts["orders.notes"] == {"matched": 4, "skipped": 2}
    # Skipped rows do not inflate the transformer counters.
    assert result.transform_counts["mask"]["seen"] == 4
    assert result.transform_counts["nullify"]["seen"] == 4


def test_condition_counts_survive_resume(tmp_path, orders_inventory, conditional_policy):
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    baseline = execute_run(
        orders_inventory, conditional_policy, baseline_paths, batch_size=2
    )
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            orders_inventory, conditional_policy, interrupted_paths,
            batch_size=2, interrupt_after_batches=1,
        )
    resumed = execute_run(
        orders_inventory, conditional_policy, interrupted_paths,
        batch_size=2, resume_run_id=excinfo.value.run_id,
    )
    assert resumed.condition_counts == baseline.condition_counts
    assert resumed.transform_counts == baseline.transform_counts
    assert resumed.output_hash == baseline.output_hash


def test_dry_run_reports_condition_counts(tmp_path, orders_inventory, conditional_policy):
    dry_workspace = tmp_path / "dry-workspace"
    paths = Paths.for_workspace(dry_workspace)
    result = execute_run(
        orders_inventory, conditional_policy, paths, batch_size=2, dry_run=True
    )
    assert result.dry_run
    assert result.condition_counts["orders.phone"] == {"matched": 4, "skipped": 2}
    assert result.condition_counts["orders.notes"] == {"matched": 4, "skipped": 2}
    assert not dry_workspace.exists()


def test_report_json_and_markdown_show_condition_counts(
    workspace, orders_inventory, conditional_policy
):
    result = execute_run(orders_inventory, conditional_policy, workspace, batch_size=2)
    findings = detect_inventory(orders_inventory)
    artifacts = generate_report(
        workspace, orders_inventory, conditional_policy, result, findings
    )
    payload = json.loads(artifacts["json"].read_text(encoding="utf-8"))
    assert payload["condition_counts"]["orders.phone"] == {"matched": 4, "skipped": 2}
    assert payload["condition_counts"]["orders.notes"] == {"matched": 4, "skipped": 2}
    phone_rule = payload["applied_policy"]["tables"]["orders"]["columns"]["phone"]
    assert phone_rule["when"] == {"column": "tier", "op": "ne", "value": "VIP"}
    markdown = artifacts["markdown"].read_text(encoding="utf-8")
    assert "条件规则命中统计" in markdown
    assert "tier 不等于" in markdown
    assert "amount 大于" in markdown
