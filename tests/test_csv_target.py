import csv
import json
import sqlite3
from pathlib import Path

import pytest

from maskline.config import Paths
from maskline.dataset_io import read_csv_header
from maskline.detectors.engine import detect_inventory
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineError, PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.registry import inspect_dataset
from maskline.report import generate_report

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def read_csv_rows(path):
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        return header, list(reader)


def sqlite_rows(path, table):
    conn = sqlite3.connect(path)
    try:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
        select = ", ".join(f'"{name}"' for name in columns)
        rows = conn.execute(f'SELECT {select} FROM "{table}" ORDER BY rowid').fetchall()
        return columns, rows
    finally:
        conn.close()


def as_csv_cells(row):
    return ["" if value is None else str(value) for value in row]


def test_csv_target_matches_sqlite_target_field_by_field(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    sqlite_result = execute_run(
        inventories["csv"], policy, workspace,
        secrets_store=secret_store, batch_size=2, target_format="sqlite",
    )
    csv_result = execute_run(
        inventories["csv"], policy, workspace,
        secrets_store=secret_store, batch_size=2, target_format="csv",
    )
    assert csv_result.target_kind == "csv"
    assert csv_result.transform_counts == sqlite_result.transform_counts
    # Both runs share the workspace pseudonym mapping, so tokens must match.
    columns, sql_rows = sqlite_rows(sqlite_result.output_path, "leads")
    csv_file = csv_result.output_path / "leads.csv"
    header, csv_rows = read_csv_rows(csv_file)
    assert header == columns == read_csv_header(inventories["csv"].path)
    assert len(csv_rows) == len(sql_rows) == 3
    for sql_row, csv_row in zip(sql_rows, csv_rows):
        assert as_csv_cells(sql_row) == csv_row
    assert all(row[1].startswith("psn_") for row in csv_rows)
    # Re-running the CSV target is byte-identical.
    again = execute_run(
        inventories["csv"], policy, workspace,
        secrets_store=secret_store, batch_size=2, target_format="csv",
    )
    assert again.output_hash == csv_result.output_hash
    assert (again.output_path / "leads.csv").read_bytes() == csv_file.read_bytes()


def test_csv_target_multi_table_matches_sqlite_target(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    sqlite_result = execute_run(
        inventories["sqlite"], policy, workspace,
        secrets_store=secret_store, batch_size=2, target_format="sqlite",
    )
    csv_result = execute_run(
        inventories["sqlite"], policy, workspace,
        secrets_store=secret_store, batch_size=2, target_format="csv",
    )
    assert csv_result.row_count == sqlite_result.row_count == 15
    assert csv_result.transform_counts == sqlite_result.transform_counts
    for table in ("customers", "orders"):
        columns, sql_rows = sqlite_rows(sqlite_result.output_path, table)
        header, csv_rows = read_csv_rows(csv_result.output_path / f"{table}.csv")
        assert header == columns
        assert len(csv_rows) == len(sql_rows)
        for sql_row, csv_row in zip(sql_rows, csv_rows):
            assert as_csv_cells(sql_row) == csv_row


def test_csv_output_rfc4180_escaping_and_null_handling(tmp_path, workspace, make_policy):
    source = tmp_path / "nasty.sqlite"
    conn = sqlite3.connect(source)
    try:
        conn.execute(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, tag TEXT, amount REAL)"
        )
        conn.executemany(
            "INSERT INTO notes VALUES (?, ?, ?, ?)",
            [
                (1, "b1", "a,b", 1.5),
                (2, None, 'say "hi"', None),
                (3, "", "l1\nl2", 2.0),
                (4, "b4", "中文，逗号", 3.0),
                (5, "b5", "a\r\nb", None),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    inventory = inspect_dataset(source)
    policy = make_policy(
        """
        version: 1
        name: nasty
        datasets:
          - path: nasty.sqlite
            tables:
              notes:
                columns:
                  body: {transformer: nullify}
        """
    )
    result = execute_run(inventory, policy, workspace, target_format="csv")
    expected = (
        "id,body,tag,amount\r\n"
        "1,,\"a,b\",1.5\r\n"
        "2,,\"say \"\"hi\"\"\",\r\n"
        "3,,\"l1\nl2\",2.0\r\n"
        "4,,中文，逗号,3.0\r\n"
        "5,,\"a\r\nb\",\r\n"
    ).encode("utf-8")
    output_file = result.output_path / "notes.csv"
    assert output_file.read_bytes() == expected
    header, rows = read_csv_rows(output_file)
    assert header == ["id", "body", "tag", "amount"]
    assert rows[1] == ["2", "", 'say "hi"', ""]  # NULL -> empty field
    assert rows[2][2] == "l1\nl2"
    assert rows[4][2] == "a\r\nb"


def test_csv_target_empty_table_writes_header_only(tmp_path, workspace, make_policy):
    source = tmp_path / "empty.sqlite"
    conn = sqlite3.connect(source)
    try:
        conn.execute("CREATE TABLE things (id INTEGER PRIMARY KEY, name TEXT)")
        conn.commit()
    finally:
        conn.close()
    inventory = inspect_dataset(source)
    policy = make_policy(
        """
        version: 1
        name: empty
        datasets:
          - path: empty.sqlite
            tables:
              things:
                columns:
                  name: {transformer: nullify}
        """
    )
    result = execute_run(inventory, policy, workspace, target_format="csv")
    assert result.row_count == 0
    assert (result.output_path / "things.csv").read_bytes() == b"id,name\r\n"


def _interrupt_first_batch(paths, inventories, secret_store, policy):
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, batch_size=2,
            interrupt_after_batches=1, target_format="csv",
        )
    return excinfo.value.run_id


def test_csv_target_interrupt_resume_matches_baseline(tmp_path, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    baseline = execute_run(
        inventories["sqlite"], policy, baseline_paths,
        secrets_store=secret_store, batch_size=2, target_format="csv",
    )
    run_id = _interrupt_first_batch(interrupted_paths, inventories, secret_store, policy)
    out_dir = interrupted_paths.out_dir / "demo.masked"
    # Half-written output is recognizable by the .part/.journal suffixes and
    # no final CSV has appeared yet.
    assert (out_dir / "customers.csv.part").exists()
    assert (out_dir / "customers.csv.journal").exists()
    assert not (out_dir / "customers.csv").exists()
    with CheckpointStore(interrupted_paths.checkpoint_db) as store:
        assert store.get_run(run_id).status == "interrupted"
        assert store.get_checkpoint(run_id, "customers").rows_done == 2
    resumed = execute_run(
        inventories["sqlite"], policy, interrupted_paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.row_count == baseline.row_count
    assert resumed.transform_counts == baseline.transform_counts
    assert resumed.output_hash == baseline.output_hash
    for table in ("customers", "orders"):
        final = resumed.output_path / f"{table}.csv"
        assert final.read_bytes() == (baseline.output_path / f"{table}.csv").read_bytes()
        header, rows = read_csv_rows(final)
        assert len(rows) == baseline.table_rows[table]  # no duplicate rows
        assert all(len(row) == len(header) for row in rows)  # no torn rows
    assert not list(resumed.output_path.glob("*.part"))
    assert not list(resumed.output_path.glob("*.journal"))


def test_csv_target_resume_discards_torn_tail(tmp_path, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    baseline = execute_run(
        inventories["sqlite"], policy, baseline_paths,
        secrets_store=secret_store, batch_size=2, target_format="csv",
    )
    run_id = _interrupt_first_batch(interrupted_paths, inventories, secret_store, policy)
    out_dir = interrupted_paths.out_dir / "demo.masked"
    # Simulate a kill in the middle of writing a row and a journal line.
    with (out_dir / "customers.csv.part").open("ab") as fh:
        fh.write(b"torn,partial,row")
    with (out_dir / "customers.csv.journal").open("ab") as fh:
        fh.write(b"4 12")
    resumed = execute_run(
        inventories["sqlite"], policy, interrupted_paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.output_hash == baseline.output_hash
    assert resumed.transform_counts == baseline.transform_counts


def test_csv_target_resume_without_journal_scans_file(tmp_path, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    baseline = execute_run(
        inventories["sqlite"], policy, baseline_paths,
        secrets_store=secret_store, batch_size=2, target_format="csv",
    )
    run_id = _interrupt_first_batch(interrupted_paths, inventories, secret_store, policy)
    out_dir = interrupted_paths.out_dir / "demo.masked"
    (out_dir / "customers.csv.journal").unlink()
    resumed = execute_run(
        inventories["sqlite"], policy, interrupted_paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.output_hash == baseline.output_hash
    assert resumed.transform_counts == baseline.transform_counts


def test_csv_target_missing_partial_file_is_rebuilt(tmp_path, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    baseline = execute_run(
        inventories["sqlite"], policy, baseline_paths,
        secrets_store=secret_store, batch_size=2, target_format="csv",
    )
    run_id = _interrupt_first_batch(interrupted_paths, inventories, secret_store, policy)
    out_dir = interrupted_paths.out_dir / "demo.masked"
    # Lose the half-written file entirely: resume must rebuild the table.
    (out_dir / "customers.csv.part").unlink()
    (out_dir / "customers.csv.journal").unlink()
    resumed = execute_run(
        inventories["sqlite"], policy, interrupted_paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.output_hash == baseline.output_hash
    assert resumed.transform_counts == baseline.transform_counts
    for table in ("customers", "orders"):
        assert (resumed.output_path / f"{table}.csv").read_bytes() == (
            baseline.output_path / f"{table}.csv"
        ).read_bytes()


def test_csv_target_resume_at_table_boundary(tmp_path, inventories, secret_store):
    # Interrupt exactly after the first table was finalized and the second
    # table has one batch written: a mix of final CSV and .part files.
    policy = load_policy(EXAMPLE)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    baseline = execute_run(
        inventories["sqlite"], policy, baseline_paths,
        secrets_store=secret_store, batch_size=2, target_format="csv",
    )
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, interrupted_paths,
            secrets_store=secret_store, batch_size=2,
            interrupt_after_batches=4, target_format="csv",
        )
    run_id = excinfo.value.run_id
    out_dir = interrupted_paths.out_dir / "demo.masked"
    assert (out_dir / "customers.csv").exists()  # finalized before the interrupt
    assert (out_dir / "orders.csv.part").exists()
    assert not (out_dir / "orders.csv").exists()
    resumed = execute_run(
        inventories["sqlite"], policy, interrupted_paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.output_hash == baseline.output_hash
    assert resumed.transform_counts == baseline.transform_counts
    for table in ("customers", "orders"):
        assert (resumed.output_path / f"{table}.csv").read_bytes() == (
            baseline.output_path / f"{table}.csv"
        ).read_bytes()
    assert not list(resumed.output_path.glob("*.part"))
    assert not list(resumed.output_path.glob("*.journal"))


def test_csv_target_refuses_to_write_over_source(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    source = inventories["csv"].path
    before = source.read_bytes()
    with pytest.raises(PipelineError, match="over the source"):
        execute_run(
            inventories["csv"], policy, workspace,
            secrets_store=secret_store, target_format="csv",
            output_path=source.parent,
        )
    assert source.read_bytes() == before


def test_csv_target_refuses_foreign_directory(tmp_path, workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("do not delete", encoding="utf-8")
    with pytest.raises(PipelineError, match="non-empty"):
        execute_run(
            inventories["csv"], policy, workspace,
            secrets_store=secret_store, target_format="csv", output_path=foreign,
        )
    assert (foreign / "keep.txt").read_text(encoding="utf-8") == "do not delete"


def test_csv_target_output_must_be_a_directory(tmp_path, workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    with pytest.raises(PipelineError, match="directory"):
        execute_run(
            inventories["csv"], policy, workspace,
            secrets_store=secret_store, target_format="csv",
            output_path=tmp_path / "leads.csv",
        )


def test_unknown_target_format_is_rejected(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    with pytest.raises(PipelineError, match="unknown target format"):
        execute_run(
            inventories["csv"], policy, workspace,
            secrets_store=secret_store, target_format="parquet",
        )


def test_csv_target_report_and_manifest(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["csv"], policy, workspace,
        secrets_store=secret_store, target_format="csv",
    )
    findings = detect_inventory(inventories["csv"])
    artifacts = generate_report(workspace, inventories["csv"], policy, result, findings)
    payload = json.loads(artifacts["json"].read_text(encoding="utf-8"))
    assert len(payload["samples"]["leads"]) == 3
    sample = payload["samples"]["leads"][0]
    assert sample["after"]["contact_name"].startswith("psn_")
    assert sample["before"]["contact_name"] == "[源值已隐藏]"
    manifest = json.loads(
        (workspace.manifest_dir / f"{inventories['csv'].fingerprint[:16]}.json").read_text()
    )
    assert manifest["target_kind"] == "csv"
    assert manifest["output_hash"] == result.output_hash


def test_sqlite_manifest_keeps_legacy_keys(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    execute_run(inventories["csv"], policy, workspace, secrets_store=secret_store)
    manifest = json.loads(
        (workspace.manifest_dir / f"{inventories['csv'].fingerprint[:16]}.json").read_text()
    )
    assert manifest["target_kind"] == "sqlite"
    for key in (
        "run_id", "dataset", "dataset_fingerprint", "policy_name", "policy_path",
        "policy_fingerprint", "policy_changed", "previous_policy_fingerprint",
        "output", "output_hash", "row_count", "transformers", "transform_counts",
        "completed_at",
    ):
        assert key in manifest


def test_checkpoint_schema_is_unchanged_by_csv_target(workspace, inventories, secret_store):
    policy = load_policy(EXAMPLE)
    execute_run(
        inventories["csv"], policy, workspace,
        secrets_store=secret_store, target_format="csv",
    )
    conn = sqlite3.connect(workspace.checkpoint_db)
    try:
        run_columns = [row[1] for row in conn.execute("PRAGMA table_info(runs)")]
        checkpoint_columns = [row[1] for row in conn.execute("PRAGMA table_info(checkpoints)")]
    finally:
        conn.close()
    assert run_columns == [
        "run_id", "dataset_path", "dataset_fingerprint", "policy_path",
        "policy_fingerprint", "output_path", "status", "started_at", "updated_at",
    ]
    assert checkpoint_columns == [
        "run_id", "table_name", "last_rowid", "rows_done", "updated_at", "counts_json",
    ]
