"""Regression tests for messy real-world CSV exports.

Covers the record-stream contract of ``dataset_io.iter_csv_tuples`` (the
single source of CSV rows for scan, run, and reports): empty middle fields
stay positional, stray trailing commas never create phantom columns, blank
lines are not data, and quoted commas/newlines remain inside their field.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from maskline.config import Paths
from maskline.dataset_io import (
    iter_csv_dicts,
    iter_csv_tuples,
    read_column_samples,
    read_csv_header,
)
from maskline.detectors.engine import detect_inventory
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.registry import inspect_dataset
from maskline.report import generate_report

MESSY_CSV = "\n".join(
    [
        "name,phone,city,email,note",
        "张三,13812345678,北京,zhangsan@example.com,普通备注",
        "李四,,上海,lisi@example.com,中间空字段",
        "王五,13900001111,,wangwu@example.com,城市为空",
        "赵六,13711112222,广州,zhaoliu@example.com,行尾多逗号,,,",
        "",
        ",,,,",
        '钱七,"136,777,8888",深圳,qianqi@example.com,"含,逗号"',
        '孙八,13566667777,杭州,sunba@example.com,"第一行\n第二行"',
        "周九,13455556666,南京,zhoujiu@example.com,正常行",
        "",
    ]
)

VALID_ROWS = [
    ("张三", "13812345678", "北京", "zhangsan@example.com", "普通备注"),
    ("李四", "", "上海", "lisi@example.com", "中间空字段"),
    ("王五", "13900001111", "", "wangwu@example.com", "城市为空"),
    ("赵六", "13711112222", "广州", "zhaoliu@example.com", "行尾多逗号"),
    ("钱七", "136,777,8888", "深圳", "qianqi@example.com", "含,逗号"),
    ("孙八", "13566667777", "杭州", "sunba@example.com", "第一行\n第二行"),
    ("周九", "13455556666", "南京", "zhoujiu@example.com", "正常行"),
]


@pytest.fixture
def messy_csv(tmp_path) -> Path:
    path = tmp_path / "messy.csv"
    path.write_text(MESSY_CSV, encoding="utf-8", newline="")
    return path


@pytest.fixture
def messy_policy(make_policy):
    return make_policy(
        """
        version: 1
        name: messy-csv
        datasets:
          - path: messy.csv
            tables:
              messy:
                columns:
                  phone:
                    transformer: mask
                    params: {keep_prefix: 3, keep_suffix: 4}
        """
    )


def target_rows(path: Path, table: str) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
        select = ", ".join(f'"{name}"' for name in columns)
        return conn.execute(
            f'SELECT rowid, {select} FROM "{table}" ORDER BY rowid'
        ).fetchall()
    finally:
        conn.close()


def test_empty_middle_fields_stay_in_position(messy_csv):
    rows = list(iter_csv_tuples(messy_csv))
    assert rows[1] == VALID_ROWS[1]
    assert rows[1][1] == "" and rows[1][2] == "上海"
    assert rows[2][2] == "" and rows[2][3] == "wangwu@example.com"


def test_trailing_commas_never_create_extra_columns(messy_csv):
    header = read_csv_header(messy_csv)
    rows = list(iter_csv_tuples(messy_csv))
    assert all(len(row) == len(header) for row in rows)
    assert rows[3] == VALID_ROWS[3]


def test_short_rows_are_padded_and_long_rows_truncated(tmp_path):
    path = tmp_path / "ragged.csv"
    path.write_text("a,b,c\n1,2\n3,4,5,6,7\n", encoding="utf-8")
    assert list(iter_csv_tuples(path)) == [("1", "2", ""), ("3", "4", "5")]


def test_blank_lines_are_not_records(messy_csv):
    rows = list(iter_csv_tuples(messy_csv))
    assert rows == VALID_ROWS
    assert all(any(field != "" for field in row) for row in rows)


def test_quoted_commas_and_newlines_stay_in_their_field(messy_csv):
    rows = list(iter_csv_tuples(messy_csv))
    assert rows[4][1] == "136,777,8888"
    assert rows[4][4] == "含,逗号"
    assert rows[5][4] == "第一行\n第二行"


def test_dicts_and_samples_share_the_tuple_record_stream(messy_csv):
    tuples = list(iter_csv_tuples(messy_csv))
    dicts = list(iter_csv_dicts(messy_csv))
    header = read_csv_header(messy_csv)
    assert [tuple(row[name] for name in header) for row in dicts] == tuples
    assert all(set(row) == set(header) for row in dicts)
    for index, name in enumerate(header):
        samples = read_column_samples(messy_csv, "csv", "messy", name, 100)
        assert samples == [row[index] for row in tuples]


def test_inventory_counts_only_valid_records(messy_csv):
    inventory = inspect_dataset(messy_csv)
    table = inventory.table("messy")
    assert table is not None
    assert [column.name for column in table.columns] == read_csv_header(messy_csv)
    assert table.row_count == len(VALID_ROWS)
    assert inventory.row_count == len(VALID_ROWS)


def test_run_aligns_every_column_and_counts_only_valid_records(
    workspace, messy_csv, messy_policy
):
    inventory = inspect_dataset(messy_csv)
    result = execute_run(inventory, messy_policy, workspace)
    assert result.row_count == len(VALID_ROWS)
    assert result.table_rows == {"messy": len(VALID_ROWS)}

    rows = target_rows(result.output_path, "messy")
    assert [row[0] for row in rows] == list(range(1, len(VALID_ROWS) + 1))
    header = read_csv_header(messy_csv)
    phone_idx = header.index("phone")
    for (rowid, *values), source in zip(rows, VALID_ROWS):
        for index, source_value in enumerate(source):
            if index == phone_idx and source_value:
                expected = (
                    source_value[:3]
                    + "*" * (len(source_value) - 7)
                    + source_value[-4:]
                )
                assert values[index] == expected
            else:
                assert values[index] == source_value


def test_report_and_findings_use_the_same_rows(
    workspace, messy_csv, messy_policy
):
    inventory = inspect_dataset(messy_csv)
    result = execute_run(inventory, messy_policy, workspace)
    findings = detect_inventory(inventory)
    paths = generate_report(workspace, inventory, messy_policy, result, findings)
    markdown = paths["markdown"].read_text(encoding="utf-8")
    assert f"处理行数：{len(VALID_ROWS)}" in markdown
    assert '"rows_processed": 7' in paths["json"].read_text(encoding="utf-8")
    # The before/after samples pair source and target by shared rowid.
    for finding in findings:
        assert finding["table_name"] == "messy"
        assert finding["column_name"] in read_csv_header(messy_csv)


def test_interrupted_messy_csv_run_resumes_to_identical_output(
    tmp_path, messy_csv, messy_policy
):
    inventory = inspect_dataset(messy_csv)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    baseline = execute_run(inventory, messy_policy, baseline_paths, batch_size=2)

    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventory,
            messy_policy,
            interrupted_paths,
            batch_size=2,
            interrupt_after_batches=1,
        )
    resumed = execute_run(
        inventory,
        messy_policy,
        interrupted_paths,
        batch_size=3,
        resume_run_id=excinfo.value.run_id,
    )
    assert resumed.row_count == baseline.row_count == len(VALID_ROWS)
    assert resumed.output_hash == baseline.output_hash
    assert target_rows(resumed.output_path, "messy") == target_rows(
        baseline.output_path, "messy"
    )


def test_csv_of_only_blank_lines_yields_zero_records(tmp_path, workspace, make_policy):
    path = tmp_path / "emptyrows.csv"
    path.write_text("a,b\n\n,,\n\n", encoding="utf-8")
    inventory = inspect_dataset(path)
    assert inventory.row_count == 0
    policy = make_policy(
        """
        version: 1
        name: blank-only
        datasets:
          - path: emptyrows.csv
            tables:
              emptyrows:
                columns:
                  a: {transformer: nullify}
        """
    )
    result = execute_run(inventory, policy, workspace)
    assert result.row_count == 0
    assert target_rows(result.output_path, "emptyrows") == []
