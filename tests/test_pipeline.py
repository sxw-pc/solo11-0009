import sqlite3
from pathlib import Path

import pytest

from maskline.config import Paths
from maskline.pipeline.runner import execute_run
from maskline.policies import PolicyError, load_policy
from maskline.utils import sqlite_content_digest

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"

def rows(path, sql):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()

def test_end_to_end_pipeline_preserves_non_sensitive_columns(
    workspace, fixture_files, inventories, secret_store
):
    source = fixture_files["sqlite"]
    source_hash = sqlite_content_digest(source)
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, workspace,
        secrets_store=secret_store, batch_size=2,
    )
    assert sqlite_content_digest(source) == source_hash
    assert result.output_path.exists() and result.row_count == 15
    assert rows(result.output_path, "SELECT COUNT(*) FROM customers")[0][0] == 6
    assert rows(result.output_path, "SELECT COUNT(*) FROM orders")[0][0] == 9
    assert rows(result.output_path, "SELECT customer_id, status FROM customers ORDER BY 1") == rows(
        source, "SELECT customer_id, status FROM customers ORDER BY 1"
    )
    assert rows(result.output_path, "SELECT order_no, status FROM orders ORDER BY 1") == rows(
        source, "SELECT order_no, status FROM orders ORDER BY 1"
    )
    columns = (
        "full_name, phone, email, id_card, bank_card, address, "
        "birth_date, age, balance, notes"
    )
    transformed = rows(
        result.output_path,
        f"SELECT customer_id, {columns} FROM customers ORDER BY 1",
    )
    original = rows(source, f"SELECT customer_id, {columns} FROM customers ORDER BY 1")
    assert all(left[1:] != right[1:] for left, right in zip(transformed, original))
    assert all(left[0] == right[0] for left, right in zip(transformed, original))
    assert result.transform_counts["pseudonym"]["changed"] == 6
    assert result.transform_counts["nullify"]["changed"] == 6
    assert result.output_hash == sqlite_content_digest(result.output_path)

def test_rerun_is_idempotent(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    first = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store)
    second = execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store)
    assert first.output_hash == second.output_hash
    assert first.policy_changed is False
    assert second.policy_changed is False

def test_policy_change_is_marked_in_manifest(workspace, fixture_files, inventories, secret_store, make_policy):
    policy = load_policy(EXAMPLE)
    execute_run(inventories["sqlite"], policy, workspace, secrets_store=secret_store)
    changed = make_policy(
        """
        version: 1
        name: changed
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  phone:
                    transformer: mask
                    params: {keep_prefix: 2, keep_suffix: 2}
        """
    )
    result = execute_run(
        inventories["sqlite"], changed, workspace, secrets_store=secret_store
    )
    assert result.policy_changed is True
    assert result.output_hash != sqlite_content_digest(fixture_files["sqlite"])
    assert "policy_changed" in (workspace.manifest_dir / f"{inventories['sqlite'].fingerprint[:16]}.json").read_text()

def test_csv_dataset_is_masked_into_sqlite(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["csv"], policy, workspace, secrets_store=secret_store
    )
    assert result.row_count == 3
    output = rows(result.output_path, "SELECT contact_name, mobile, email, company_code FROM leads")
    assert len(output) == 3
    assert all(name.startswith("psn_") for name, *_ in output)
    assert all("****" in mobile for _, mobile, _, _ in output)
    assert all(len(email) == 64 for _, _, email, _ in output)

def test_dry_run_writes_nothing(tmp_path, inventories, secret_store):
    dry_workspace = tmp_path / "dry-run-workspace"
    paths = Paths.for_workspace(dry_workspace)
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, paths,
        secrets_store=secret_store, batch_size=2, dry_run=True,
    )
    assert result.dry_run and result.output_path is None and result.output_hash is None
    assert result.row_count == inventories["sqlite"].row_count
    assert not dry_workspace.exists()
    assert result.transform_counts["mask"]["changed"] > 0

def test_policy_rejects_unknown_column(inventories, make_policy):
    policy = make_policy(
        """
        version: 1
        name: bad
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  no_such_column: {transformer: mask}
        """
    )
    with pytest.raises(PolicyError, match="unknown column"):
        policy.validate_against(inventories["sqlite"])

def test_policy_rejects_unknown_transformer_and_missing_param(make_policy):
    with pytest.raises(PolicyError, match="unknown transformer"):
        make_policy(
            """
            version: 1
            name: bad
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone: {transformer: magic}
            """
        )
    with pytest.raises(PolicyError, match="missing required parameter"):
        make_policy(
            """
            version: 1
            name: bad
            datasets:
              - path: demo.sqlite
                tables:
                  customers:
                    columns:
                      phone: {transformer: generalize}
            """
        )
