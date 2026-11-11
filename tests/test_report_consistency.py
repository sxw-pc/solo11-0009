"""Consistency, resume/skip provenance, legacy parsing, and scale tests.

These tests pin the contract that the Markdown and JSON reports of one run are
rendered from the same data and that every statistic matches the persisted
metadata (checkpoints, manifest, audit head, mapping store, output digest).
"""

from __future__ import annotations

import json
import sqlite3
import time
import tracemalloc
from pathlib import Path

import pytest

from maskline.audit import AuditLog, head_path
from maskline.config import Paths
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.pseudomap import PseudoMap
from maskline.report import (
    ReportConsistencyError,
    generate_report,
    load_json_report,
    load_markdown_report,
    load_report,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _write_malformed_csv(path: Path, header: list[str], rows: list[list[str]]) -> Path:
    import csv

    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)
    return path


def _markdown_stats(markdown: str) -> dict[str, str]:
    stats = {}
    for line in markdown.splitlines():
        if line.startswith("- ") and "：" in line:
            key, value = line[2:].split("：", 1)
            stats[key] = value.strip("`")
    return stats


def test_markdown_and_json_reports_share_every_statistic(
    workspace, inventories, secret_store, audit_append
):
    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, workspace,
        secrets_store=secret_store, batch_size=4,
    )
    audit_entry = audit_append(workspace, result)
    artifacts = generate_report(
        workspace, inventories["sqlite"], policy, result,
        findings=[], audit_entry=audit_entry,
    )
    payload = load_json_report(artifacts["json"])
    parsed_md = load_markdown_report(artifacts["markdown"])
    run = payload["run"]
    md = _markdown_stats(artifacts["markdown"].read_text(encoding="utf-8"))

    assert parsed_md["run"]["run_id"] == run["run_id"]
    assert parsed_md["run"]["rows_processed"] == run["rows_processed"]
    assert parsed_md["run"]["skipped_rows"] == run["skipped_rows"]
    assert parsed_md["run"]["pseudomap_entries"] == run["pseudomap_entries"]
    assert parsed_md["run"]["resumed"] == run["resumed"]
    assert parsed_md["run"]["audit_anchor"] == run["audit_anchor"]
    assert parsed_md["run"]["audit_seq"] == run["audit_seq"]
    assert parsed_md["run"]["dataset_fingerprint"] == run["dataset_fingerprint"]
    assert parsed_md["run"]["output_hash"] == run["output_hash"]

    assert md["处理行数"] == str(run["rows_processed"])
    assert md["跳过异常行数"] == str(run["skipped_rows"])
    assert md["假名映射条目数"] == str(run["pseudomap_entries"])
    assert md["断点续跑"] == ("是" if run["resumed"] else "否")
    assert md["数据集指纹"] == run["dataset_fingerprint"]
    assert md["输出库哈希"] == run["output_hash"]
    assert md["审计链锚点"] == run["audit_anchor"]
    assert md["报告生成时间"] == payload["generated_at"]

    # Every persisted event appears identically in both formats.
    assert [event["event"] for event in parsed_md["events"]] == [
        event["event"] for event in payload["events"]
    ]
    assert [event["seq"] for event in parsed_md["events"]] == [
        event["seq"] for event in payload["events"]
    ]


def test_dataset_fingerprint_and_audit_anchor_match_stored_metadata(
    workspace, inventories, secret_store, audit_append
):
    from maskline.registry import inspect_dataset

    policy = load_policy(EXAMPLE)
    result = execute_run(
        inventories["sqlite"], policy, workspace, secrets_store=secret_store
    )
    audit_entry = audit_append(workspace, result)
    artifacts = generate_report(
        workspace, inventories["sqlite"], policy, result,
        findings=[], audit_entry=audit_entry,
    )
    payload = json.loads(artifacts["json"].read_text(encoding="utf-8"))

    # Fingerprint equals the freshly re-inspected source dataset.
    live = inspect_dataset(inventories["sqlite"].path)
    assert payload["run"]["dataset_fingerprint"] == live.fingerprint

    # Audit anchor equals the actual head file and the chained entry hash.
    head = json.loads(head_path(workspace.audit_path).read_text(encoding="utf-8"))
    assert payload["run"]["audit_anchor"] == head["last_hash"]
    assert payload["run"]["audit_anchor"] == audit_entry["entry_hash"]
    assert payload["run"]["audit_seq"] == head["count"] == audit_entry["seq"]
    assert AuditLog(workspace.audit_path).verify().head_hash == head["last_hash"]

    # Row counts match the output database and the checkpoints.
    conn = sqlite3.connect(result.output_path)
    try:
        output_rows = sum(
            conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            for table in ("customers", "orders")
        )
    finally:
        conn.close()
    assert output_rows == payload["run"]["rows_processed"] == result.row_count
    with CheckpointStore(workspace.checkpoint_db) as store:
        stored = sum(cp.rows_done for cp in store.list_checkpoints(result.run_id))
    assert stored == payload["run"]["rows_processed"]

    # Pseudonym mapping count matches the physical mapping store.
    with PseudoMap(workspace.pseudomap_db) as mapping:
        assert mapping.count() == payload["run"]["pseudomap_entries"]


def test_resume_run_records_interrupt_and_resume_events_in_both_reports(
    tmp_path, inventories, secret_store, audit_append
):
    policy = load_policy(EXAMPLE)
    paths = Paths.for_workspace(tmp_path / "resumed")
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], policy, paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    run_id = excinfo.value.run_id
    with CheckpointStore(paths.checkpoint_db) as store:
        assert [event.event for event in store.list_events(run_id)] == [
            "run_started", "run_interrupted",
        ]

    resumed = execute_run(
        inventories["sqlite"], policy, paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    with CheckpointStore(paths.checkpoint_db) as store:
        names = [event.event for event in store.list_events(run_id)]
    assert names == ["run_started", "run_interrupted", "run_resumed", "run_completed"]
    assert resumed.resumed is True

    audit_entry = audit_append(paths, resumed)
    artifacts = generate_report(
        paths, inventories["sqlite"], policy, resumed,
        findings=[], audit_entry=audit_entry,
    )
    payload = load_json_report(artifacts["json"])
    parsed_md = load_markdown_report(artifacts["markdown"])
    event_names = [event["event"] for event in payload["events"]]
    assert event_names == names
    assert parsed_md["run"]["resumed"] is True
    assert "断点恢复" in artifacts["markdown"].read_text(encoding="utf-8")
    assert "运行中断" in artifacts["markdown"].read_text(encoding="utf-8")
    # The completed event carries the final stats.
    completed = payload["events"][-1]
    assert completed["details"]["rows_processed"] == payload["run"]["rows_processed"]


def test_malformed_csv_rows_are_skipped_and_counted_consistently(
    tmp_path, secret_store, audit_append
):
    raw = tmp_path / "raw"
    raw.mkdir()
    header = ["lead_id", "contact_name", "mobile", "email"]
    good_rows = [
        ["1", "张三", "13800001111", "a@example.invalid"],
        ["2", "李四", "13900002222", "b@example.invalid"],
        ["4", "赵六", "13700004444", "d@example.invalid"],
    ]
    # Row 3 has too few columns; row 5 has too many. Both must be skipped.
    rows = [
        good_rows[0],
        good_rows[1],
        ["3", "王五"],
        good_rows[2],
        ["5", "钱七", "13600005555", "e@example.invalid", "extra-column"],
    ]
    csv_path = _write_malformed_csv(raw / "leads.csv", header, rows)

    from maskline.policies import load_policy
    from maskline.registry import inspect_dataset

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
name: skip-policy
datasets:
  - path: leads.csv
    tables:
      leads:
        columns:
          contact_name: {transformer: nullify}
          mobile:
            transformer: mask
            params: {keep_prefix: 3, keep_suffix: 2}
""".lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)
    inventory = inspect_dataset(csv_path)
    paths = Paths.for_workspace(tmp_path / "workspace")
    result = execute_run(inventory, policy, paths, batch_size=2)

    assert result.skipped_rows == 2
    assert result.row_count == 3
    reasons = {(sample["rowid"], sample["reason"]) for sample in result.skip_samples}
    assert (3, "row_arity_mismatch") in reasons
    assert (5, "row_arity_mismatch") in reasons

    audit_entry = audit_append(paths, result)
    artifacts = generate_report(
        paths, inventory, policy, result, findings=[], audit_entry=audit_entry
    )
    payload = load_json_report(artifacts["json"])
    parsed_md = load_markdown_report(artifacts["markdown"])
    assert payload["run"]["skipped_rows"] == 2
    assert parsed_md["run"]["skipped_rows"] == 2
    assert "跳过异常行数：2" in artifacts["markdown"].read_text(encoding="utf-8")
    with CheckpointStore(paths.checkpoint_db) as store:
        assert sum(cp.skipped_rows for cp in store.list_checkpoints(result.run_id)) == 2

    conn = sqlite3.connect(result.output_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM leads").fetchone()[0] == 3
    finally:
        conn.close()


def test_report_rejects_tampered_metadata(
    tmp_path, inventories, secret_store, audit_append
):
    policy = load_policy(EXAMPLE)
    paths = Paths.for_workspace(tmp_path / "ws")
    result = execute_run(
        inventories["sqlite"], policy, paths, secrets_store=secret_store
    )
    audit_entry = audit_append(paths, result)
    # Corrupt the manifest row count; the report must refuse to render.
    manifest = next(paths.manifest_dir.glob("*.json"))
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["row_count"] += 1
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ReportConsistencyError, match="manifest row_count"):
        generate_report(
            paths, inventories["sqlite"], policy, result,
            findings=[], audit_entry=audit_entry,
        )


def test_legacy_json_and_markdown_reports_remain_parseable(tmp_path):
    legacy_json = tmp_path / "legacy.json"
    legacy_json.write_text(
        json.dumps(
            {
                "run": {
                    "run_id": "run-20240101-000000-abcdef",
                    "dataset": "/data/demo.sqlite",
                    "dataset_fingerprint": "a" * 64,
                    "policy_name": "old",
                    "policy_fingerprint": "b" * 64,
                    "policy_changed": False,
                    "output": "/data/out.sqlite",
                    "output_hash": "c" * 64,
                    "rows_processed": 15,
                    "elapsed_seconds": 0.12,
                },
                "applied_policy": {"path": "demo.sqlite", "tables": {}},
                "transform_counts": {},
                "findings": [],
                "samples": {},
                "warnings": [],
                "generated_at": "2024-01-01T00:00:00+00:00",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    parsed = load_report(legacy_json)
    assert parsed["run"]["rows_processed"] == 15
    assert parsed["run"]["skipped_rows"] == 0
    assert parsed["run"]["pseudomap_entries"] == 0
    assert parsed["run"]["audit_anchor"] is None
    assert parsed["run"]["resumed"] is False
    assert parsed["events"] == []

    legacy_md = tmp_path / "legacy.md"
    legacy_md.write_text(
        "# maskline 脱敏报告\n\n"
        "- 运行 ID：`run-20240101-000000-abcdef`\n"
        "- 数据集：`/data/demo.sqlite`\n"
        "- 数据集指纹：`" + "a" * 64 + "`\n"
        "- 处理行数：15\n"
        "- 耗时：0.120 秒\n"
        "- 报告生成时间：2024-01-01T00:00:00+00:00\n\n"
        "## 字段发现\n",
        encoding="utf-8",
    )
    parsed_md = load_report(legacy_md)
    assert parsed_md["run"]["run_id"] == "run-20240101-000000-abcdef"
    assert parsed_md["run"]["rows_processed"] == 15
    assert parsed_md["run"]["skipped_rows"] == 0
    assert parsed_md["run"]["audit_anchor"] is None
    assert parsed_md["events"] == []


def test_repeated_resume_with_skips_keeps_exact_totals_and_output(
    tmp_path, secret_store
):
    import csv

    from maskline.policies import load_policy
    from maskline.registry import inspect_dataset
    from maskline.utils import sqlite_content_digest

    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    csv_path = raw_dir / "leads.csv"
    rows = [["1", "a", "13800001111", "a@x"]]
    rows.append(["2", "bad"])  # malformed rowid 2
    for index in range(3, 12):
        rows.append([str(index), f"n{index}", f"139{index:08d}", f"u{index}@x"])
    rows.append(["12", "bad2", "x", "y", "z"])  # malformed rowid 12
    for index in range(13, 21):
        rows.append([str(index), f"n{index}", f"139{index:08d}", f"u{index}@x"])
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["lead_id", "contact_name", "mobile", "email"])
        writer.writerows(rows)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
name: p
datasets:
  - path: leads.csv
    tables:
      leads:
        columns:
          mobile:
            transformer: mask
            params: {keep_prefix: 3, keep_suffix: 2}
""".lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)
    inventory = inspect_dataset(csv_path)
    baseline = execute_run(
        inventory, policy, Paths.for_workspace(tmp_path / "base"),
        batch_size=3,
    )
    paths = Paths.for_workspace(tmp_path / "multi")
    run_id = None
    for _ in range(4):
        kwargs = {} if run_id is None else {"resume_run_id": run_id}
        with pytest.raises(PipelineInterrupted) as excinfo:
            execute_run(
                inventory, policy, paths, batch_size=3,
                interrupt_after_batches=1, **kwargs,
            )
        run_id = excinfo.value.run_id
    resumed = execute_run(
        inventory, policy, paths, batch_size=3, resume_run_id=run_id
    )
    assert (resumed.row_count, resumed.skipped_rows) == (
        baseline.row_count,
        baseline.skipped_rows,
    ) == (18, 2)
    assert resumed.output_hash == baseline.output_hash
    assert sqlite_content_digest(resumed.output_path) == baseline.output_hash


def test_legacy_checkpoint_database_migrates_without_skipped_column(tmp_path):
    db = tmp_path / "data" / "checkpoints.sqlite"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY, dataset_path TEXT NOT NULL,
            dataset_fingerprint TEXT NOT NULL, policy_path TEXT NOT NULL,
            policy_fingerprint TEXT NOT NULL, output_path TEXT NOT NULL,
            status TEXT NOT NULL, started_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE checkpoints (
            run_id TEXT NOT NULL, table_name TEXT NOT NULL,
            last_rowid INTEGER NOT NULL, rows_done INTEGER NOT NULL,
            updated_at TEXT NOT NULL, counts_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY (run_id, table_name)
        );
        INSERT INTO runs VALUES ('r1', '/d.sqlite', 'fp', '/p.yaml', 'pfp',
                                 '/o.sqlite', 'interrupted', 't', 't');
        INSERT INTO checkpoints VALUES ('r1', 'customers', 5, 5, 't', '{}');
        """
    )
    conn.commit()
    conn.close()

    paths = Paths.for_workspace(tmp_path)
    with CheckpointStore(paths.checkpoint_db) as store:
        cp = store.get_checkpoint("r1", "customers")
        assert cp.rows_done == 5
        assert cp.skipped_rows == 0
        store.save_checkpoint("r1", "customers", 6, 6, {}, skipped_rows=1)
        assert store.get_checkpoint("r1", "customers").skipped_rows == 1
        event = store.add_event("r1", "run_resumed", {"reason": "test"})
        assert event.seq == 1 and event.event == "run_resumed"
        assert store.list_events("r1")[0].details == {"reason": "test"}


def test_report_generation_for_100k_rows_under_time_and_memory_budget(
    tmp_path, secret_store, audit_append
):
    # Build a 100k-row source dataset with a mask-only policy so the masking
    # run itself stays cheap; the budget applies to report generation.
    source = tmp_path / "big.sqlite"
    conn = sqlite3.connect(source)
    conn.execute("CREATE TABLE customers (customer_id INTEGER PRIMARY KEY, phone TEXT)")
    conn.executemany(
        "INSERT INTO customers VALUES (?, ?)",
        ((index, f"138{index % 100000000:08d}") for index in range(1, 100_001)),
    )
    conn.commit()
    conn.close()

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
name: big
datasets:
  - path: big.sqlite
    tables:
      customers:
        columns:
          phone:
            transformer: mask
            params: {keep_prefix: 3, keep_suffix: 4}
""".lstrip(),
        encoding="utf-8",
    )
    policy = load_policy(policy_path)
    from maskline.registry import inspect_dataset

    inventory = inspect_dataset(source)
    assert inventory.row_count == 100_000
    paths = Paths.for_workspace(tmp_path / "ws")
    result = execute_run(inventory, policy, paths, batch_size=5000)
    assert result.row_count == 100_000
    audit_entry = audit_append(paths, result)

    # Best of two timed runs: the first attempt pays cold-cache costs that are
    # environmental rather than part of the report-generation logic.
    timings: list[float] = []
    peak = 0
    for _ in range(2):
        tracemalloc.start()
        start = time.perf_counter()
        artifacts = generate_report(
            paths, inventory, policy, result, findings=[], audit_entry=audit_entry
        )
        timings.append(time.perf_counter() - start)
        _current, attempt_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak = max(peak, attempt_peak)
    elapsed = min(timings)

    assert elapsed < 5.0, f"report generation took {elapsed:.2f}s"
    assert peak < 100 * 1024 * 1024, f"peak memory {peak / 1024 / 1024:.1f} MiB"
    payload = load_json_report(artifacts["json"])
    assert payload["run"]["rows_processed"] == 100_000
    # Only five sample rows are held regardless of dataset size.
    assert len(payload["samples"]["customers"]) == 5
    assert artifacts["markdown"].stat().st_size > 0
