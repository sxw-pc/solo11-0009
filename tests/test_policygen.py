import sqlite3

import pytest

from maskline.__main__ import main
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.policygen import generate_policy_draft, plan_drafts
from maskline.registry import inspect_dataset
from maskline.utils import MasklineError
from maskline.workflow import scan_paths


def _scan(workspace, *datasets):
    scan_paths(list(datasets), workspace)


def _generate(workspace, dataset, name="draft.yaml", **kwargs):
    return generate_policy_draft(dataset, workspace.root / name, workspace, **kwargs)


def _make_mixed_csv(tmp_path, name, sensitive_rows, total_rows):
    path = tmp_path / name
    lines = ["email,note"]
    for index in range(total_rows):
        if index < sensitive_rows:
            lines.append(f"user{index}@example.com,row-{index}")
        else:
            lines.append(f"not-an-email-{index},row-{index}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_plan_drafts_maps_sorts_and_skips_clean_columns():
    findings = [
        {"table_name": "b", "column_name": "z", "sensitive_type": "email",
         "confidence": "high", "score": 0.9},
        {"table_name": "a", "column_name": "clean", "sensitive_type": None,
         "confidence": "none", "score": 0.0},
        {"table_name": "a", "column_name": "x", "sensitive_type": "mobile_phone",
         "confidence": "low", "score": 0.3},
        {"table_name": "a", "column_name": "y", "sensitive_type": "person_name",
         "confidence": "medium", "score": 0.6},
        {"table_name": "a", "column_name": "w", "sensitive_type": "future_type",
         "confidence": "high", "score": 0.95},
    ]
    drafts = plan_drafts(findings)
    assert [(d.table, d.column) for d in drafts] == [
        ("a", "w"), ("a", "x"), ("a", "y"), ("b", "z"),
    ]
    by_column = {draft.column: draft for draft in drafts}
    assert by_column["z"].transformer == "hash" and by_column["z"].review == ""
    assert by_column["y"].transformer == "pseudonym" and by_column["y"].review == "review"
    assert by_column["x"].transformer == "nullify" and by_column["x"].review == "confirm"
    # Unknown future types fall back to conservative nullify, never crash.
    assert by_column["w"].transformer == "nullify" and by_column["w"].review == "confirm"


def test_draft_is_byte_identical_across_runs(workspace, fixture_files):
    _scan(workspace, fixture_files["sqlite"])
    first = _generate(workspace, fixture_files["sqlite"], "a.yaml")
    second = _generate(workspace, fixture_files["sqlite"], "b.yaml")
    assert first.output_path.read_bytes() == second.output_path.read_bytes()
    # Regenerating over the same file with --force keeps the same bytes too.
    third = generate_policy_draft(
        fixture_files["sqlite"], first.output_path, workspace, force=True
    )
    assert third.output_path.read_bytes() == first.output_path.read_bytes()
    assert third.backup_path is not None


def test_draft_passes_strict_loading_and_skips_clean_columns(
    workspace, fixture_files, inventories
):
    _scan(workspace, fixture_files["sqlite"])
    result = _generate(workspace, fixture_files["sqlite"])
    policy = load_policy(result.output_path)
    rule = policy.validate_against(inventories["sqlite"])
    customers = rule.tables["customers"].columns
    assert customers["full_name"].transformer == "pseudonym"
    assert customers["email"].transformer == "hash"
    assert customers["phone"].transformer == "mask"
    assert customers["phone"].params["keep_prefix"] == 3
    # Columns without findings (ids, dates, numbers, free text) stay out.
    for clean in ("customer_id", "birth_date", "age", "balance", "notes"):
        assert clean not in customers
    text = result.output_path.read_text(encoding="utf-8")
    assert "notes" not in text
    # Tables and columns are emitted in sorted order.
    assert text.index("customers:") < text.index("orders:")
    assert text.index("address:") < text.index("full_name:") < text.index("phone:")


def test_low_confidence_column_defaults_to_nullify_with_todo(workspace, tmp_path):
    dataset = _make_mixed_csv(tmp_path, "mixed.csv", sensitive_rows=3, total_rows=10)
    _scan(workspace, dataset)
    result = _generate(workspace, dataset)
    text = result.output_path.read_text(encoding="utf-8")
    assert "email: nullify  # TODO(confirm): low confidence email" in text
    assert "note" not in text  # no findings -> not drafted
    assert result.confirm_count == 1
    policy = load_policy(result.output_path)
    rule = policy.validate_against(inspect_dataset(dataset))
    assert rule.tables["mixed"].columns["email"].transformer == "nullify"


def test_medium_confidence_keeps_transform_with_review_comment(workspace, tmp_path):
    dataset = _make_mixed_csv(tmp_path, "medium.csv", sensitive_rows=6, total_rows=10)
    _scan(workspace, dataset)
    result = _generate(workspace, dataset)
    text = result.output_path.read_text(encoding="utf-8")
    assert "email: hash  # review: medium confidence email" in text
    assert result.confirm_count == 0


def test_refuses_to_overwrite_without_force(workspace, fixture_files):
    _scan(workspace, fixture_files["sqlite"])
    result = _generate(workspace, fixture_files["sqlite"])
    result.output_path.write_text("# hand edited\n", encoding="utf-8")
    with pytest.raises(MasklineError, match="--force"):
        _generate(workspace, fixture_files["sqlite"])
    assert result.output_path.read_text(encoding="utf-8") == "# hand edited\n"


def test_force_backs_up_hand_edits_before_overwriting(workspace, fixture_files):
    _scan(workspace, fixture_files["sqlite"])
    result = _generate(workspace, fixture_files["sqlite"])
    original = result.output_path.read_text(encoding="utf-8")
    result.output_path.write_text("# hand edited\n" + original, encoding="utf-8")
    regenerated = _generate(workspace, fixture_files["sqlite"], force=True)
    backup = regenerated.backup_path
    assert backup is not None and backup.name.endswith(".bak")
    assert backup.read_text(encoding="utf-8") == "# hand edited\n" + original
    assert regenerated.output_path.read_text(encoding="utf-8") == original


def test_missing_scan_is_an_error(workspace, fixture_files):
    with pytest.raises(MasklineError, match="maskline scan"):
        _generate(workspace, fixture_files["sqlite"])
    assert not (workspace.root / "draft.yaml").exists()


def test_generated_draft_runs_end_to_end(workspace, fixture_files, inventories, secret_store):
    _scan(workspace, fixture_files["sqlite"])
    result = _generate(workspace, fixture_files["sqlite"])
    policy = load_policy(result.output_path)
    run = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store, batch_size=2
    )
    assert run.row_count == 15
    assert run.transform_counts["pseudonym"]["changed"] == 6
    assert run.transform_counts["mask"]["changed"] > 0
    assert run.transform_counts["hash"]["changed"] == 6
    conn = sqlite3.connect(run.output_path)
    try:
        names = [row[0] for row in conn.execute("SELECT full_name FROM customers")]
    finally:
        conn.close()
    assert all(name.startswith("psn_") for name in names)


def test_cli_genpolicy_and_overwrite_guard(workspace, fixture_files, capsys):
    _scan(workspace, fixture_files["sqlite"])
    output = workspace.root / "cli-draft.yaml"
    argv = [
        "genpolicy", "--workspace", str(workspace.root),
        "--dataset", str(fixture_files["sqlite"]), "--output", str(output),
    ]
    assert main(argv) == 0
    assert output.exists()
    assert main(argv) == 2  # exists, no --force
    assert "output file exists" in capsys.readouterr().err
    assert main(argv + ["--force"]) == 0
    backups = list(workspace.root.glob("cli-draft.yaml.*.bak"))
    assert len(backups) == 1
