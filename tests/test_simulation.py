"""Tests for the policy impact simulation subsystem."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from maskline.audit import AuditLog, read_audit_entries
from maskline.registry import inspect_dataset
from maskline.simulation.errors import SimulationError
from maskline.simulation.metrics import (
    CoverageAccumulator,
    NumericAccumulator,
    jensen_shannon_divergence,
    linkage_metric,
    multiset_overlap,
    psi,
)
from maskline.simulation.report import render_comparison_markdown, render_simulation_markdown
from maskline.simulation.runner import LinkageSpec, run_simulation
from maskline.simulation.sampling import (
    SamplingConfig,
    execution_mode,
    sample_table,
)
from maskline.simulation.store import SimulationStore, compare_simulations
from maskline.simulation.workspace import (
    SimulationWorkspace,
    default_temp_root,
    sweep_stale_workspaces,
)
from maskline.utils import sqlite_content_digest

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


# --------------------------------------------------------------------------
# Pure metric helpers
# --------------------------------------------------------------------------

def test_coverage_accumulator_rates():
    acc = CoverageAccumulator()
    for before, after in [("a", "*"), ("b", "b"), (None, None), ("", "")]:
        acc.observe(before, after)
    metric = acc.to_metric()
    assert metric["total_values"] == 4
    assert metric["non_empty_values"] == 2
    assert metric["empty_values"] == 2
    assert metric["changed_values"] == 1
    assert metric["coverage_rate"] == 0.5


def test_psi_and_js_identical_distributions_are_zero():
    from collections import Counter
    counter = Counter({"a": 5, "b": 3, "c": 2})
    assert psi(counter, counter) == 0.0
    assert jensen_shannon_divergence(counter, counter) == 0.0


def test_psi_handles_disappearing_buckets_finitely():
    from collections import Counter
    value = psi(Counter({"a": 10}), Counter({"b": 10}))
    assert value > 0
    assert value != float("inf")


def test_linkage_metric_detects_full_break_and_retention():
    broken = linkage_metric([1, 2, 2, 3], [2, 3], ["x", "y", "y", "z"], ["p", "q"])
    # Multiset intersection of [2, 3] within [1, 2, 2, 3] counts each key once.
    assert broken["overlap_before"] == 2
    assert broken["overlap_after"] == 0
    assert broken["retention_rate"] == 0.0
    assert broken["fully_broken"] is True
    retained = linkage_metric([1, 2, 3], [2, 3], [1, 2, 3], [2, 3])
    assert retained["retention_rate"] == 1.0
    assert retained["fully_broken"] is False


def test_multiset_overlap_respects_multiplicity():
    assert multiset_overlap([1, 1, 2], [1, 1, 1]) == 2


def test_numeric_accumulator_detects_numeric_columns():
    acc = NumericAccumulator()
    for value in [1, 2.5, "3", None]:
        acc.observe(value)
    assert acc.is_numeric_column
    snap = acc.snapshot()
    assert snap["sum"] == pytest.approx(6.5)
    assert snap["min"] == pytest.approx(1.0)
    assert snap["max"] == pytest.approx(3.0)
    text = NumericAccumulator()
    for value in ["a", "b", "c"]:
        text.observe(value)
    assert not text.is_numeric_column


# --------------------------------------------------------------------------
# Sampling
# --------------------------------------------------------------------------

def test_sample_table_respects_capacity_and_is_deterministic(
    inventories, make_policy
):
    inventory = inventories["sqlite"]
    table = next(t for t in inventory.tables if t.name == "orders")
    config = SamplingConfig(sample_size=5, batch_size=2)
    first = sample_table(inventory, table, {"amount"}, config, "seed")
    second = sample_table(inventory, table, {"amount"}, config, "seed")
    assert first.row_count == table.row_count
    # Reservoir holds the requested capacity; edge rows are added on top.
    assert first.reservoir_size == 5
    assert len(first.rows) >= 5
    assert [rowid for rowid, _ in first.rows] == [rowid for rowid, _ in second.rows]
    # Every returned rowid is a real row of the table.
    assert all(1 <= rowid <= table.row_count for rowid, _ in first.rows)


def test_sample_table_captures_edge_rowids(inventories):
    inventory = inventories["sqlite"]
    table = next(t for t in inventory.tables if t.name == "customers")
    config = SamplingConfig(sample_size=2, batch_size=3)
    sample = sample_table(inventory, table, {"balance", "phone"}, config, "seed")
    assert sample.edge_rowids, "edge rows must be captured even with tiny reservoir"
    reasons = {reason for values in sample.edge_rowids.values() for reason in values}
    assert {"numeric_min", "numeric_max", "shortest", "longest"} & reasons


def test_execution_mode_switches_with_threshold(tmp_path):
    big = tmp_path / "big.sqlite"
    big.write_bytes(b"x" * 2048)
    config = SamplingConfig(sample_size=10, file_size_threshold=1024)
    assert execution_mode(big, config) == "streaming"
    small_config = SamplingConfig(sample_size=10, file_size_threshold=4096)
    assert execution_mode(big, small_config) == "batched"


# --------------------------------------------------------------------------
# Workspace isolation and cleanup
# --------------------------------------------------------------------------

def test_workspace_isolation_and_cleanup(workspace):
    first = SimulationWorkspace.create(workspace)
    second = SimulationWorkspace.create(workspace)
    try:
        assert first.temp_dir != second.temp_dir
        assert stat.S_IMODE(first.temp_dir.stat().st_mode) == 0o700
        assert first.pseudomap_db.parent == first.temp_dir
        assert default_temp_root(workspace).is_relative_to(workspace.data_dir)
        assert "out" not in default_temp_root(workspace).parts
    finally:
        first.cleanup()
        second.cleanup()
    assert not first.temp_dir.exists()
    assert not second.temp_dir.exists()


def test_sweep_removes_stale_directories(workspace):
    ws = SimulationWorkspace.create(workspace)
    old = ws.temp_dir
    os.utime(old, (0, 0))
    removed = sweep_stale_workspaces(workspace)
    assert removed == 1
    assert not old.exists()


# --------------------------------------------------------------------------
# End-to-end simulation
# --------------------------------------------------------------------------

def test_run_simulation_metrics_and_no_source_mutation(
    workspace, fixture_files, inventories, secret_store
):
    source = fixture_files["sqlite"]
    source_hash = sqlite_content_digest(source)
    result = run_simulation(
        source, EXAMPLE, workspace,
        sample_size=4, batch_size=3, secrets_store=secret_store,
        linkage_pairs=["orders.customer_id=customers.customer_id"],
        kpi_columns=["orders.amount", "customers.balance"],
    )
    doc = result.document
    assert result.status == "completed"
    assert doc["dataset"]["fingerprint"] == inventories["sqlite"].fingerprint
    # Source untouched.
    assert sqlite_content_digest(source) == source_hash
    # Every masked column reports full coverage.
    customers = next(t for t in doc["tables"] if t["table_name"] == "customers")
    for column in customers["columns"]:
        if column["transformer"]:
            assert column["coverage"]["coverage_rate"] == 1.0
            assert "distribution_shift" in column
    # Unmasked join key still present in the document.
    order_cid = next(
        c for t in doc["tables"] if t["table_name"] == "orders"
        for c in t["columns"] if c["column_name"] == "customer_id"
    )
    assert order_cid["transformer"] is None
    # Linkage across the unmasked foreign key is fully retained.
    linkage = doc["linkages"][0]
    assert linkage["retention_rate"] == 1.0
    assert linkage["fully_broken"] is False
    # Rounding decimals to two places barely moves the amount sum.
    amount = next(
        c for t in doc["tables"] if t["table_name"] == "orders"
        for c in t["columns"] if c["column_name"] == "amount"
    )
    assert amount["kpi"]["sum_deviation_rate"] < 0.01
    # Temp data is gone; nothing leaked into the formal output directory.
    assert not result.temp_dir.exists()
    assert not any(workspace.out_dir.iterdir())
    assert not list((workspace.data_dir / "sim-tmp").glob("sim-*"))
    # Persisted for comparison.
    stored = SimulationStore(paths=workspace).get(result.simulation_id)
    assert stored["simulation_id"] == result.simulation_id


def test_simulation_streaming_mode_on_large_file(
    workspace, fixture_files, secret_store
):
    result = run_simulation(
        fixture_files["sqlite"], EXAMPLE, workspace,
        sample_size=3, batch_size=2, file_size_threshold=1,
        secrets_store=secret_store,
    )
    assert set(result.document["sample"]["streaming_tables"]) == {
        "customers", "orders"
    }
    assert all(t["mode"] == "streaming" for t in result.document["tables"])


def test_simulation_handles_read_only_source(
    workspace, fixture_files, secret_store
):
    source = fixture_files["sqlite"]
    mode = source.stat().st_mode
    source.chmod(mode & ~0o222)
    try:
        result = run_simulation(
            source, EXAMPLE, workspace, sample_size=4,
            secrets_store=secret_store,
        )
        assert result.status == "completed"
    finally:
        source.chmod(mode)


def test_simulation_empty_table_warns(workspace, tmp_path, make_policy):
    import sqlite3
    empty_db = tmp_path / "empty.sqlite"
    conn = sqlite3.connect(empty_db)
    conn.execute("CREATE TABLE t_empty (id INTEGER PRIMARY KEY, name TEXT)")
    conn.commit()
    conn.close()
    policy = make_policy(
        """
        version: 1
        name: empty-case
        datasets:
          - path: "empty.sqlite"
            tables:
              t_empty:
                columns:
                  name: {transformer: nullify}
        """
    )
    result = run_simulation(empty_db, policy.source_path, workspace, sample_size=10)
    assert result.status == "completed_with_warnings"
    assert any("empty" in warning for warning in result.warnings)
    table = result.document["tables"][0]
    assert table["sampled_rows"] == 0


def test_simulation_rejects_invalid_policy(workspace, fixture_files, make_policy):
    policy = make_policy(
        """
        version: 1
        name: broken
        datasets:
          - path: "demo.sqlite"
            tables:
              customers:
                columns:
                  ghost_column: {transformer: mask}
        """
    )
    with pytest.raises(SimulationError, match="policy validation failed"):
        run_simulation(fixture_files["sqlite"], policy.source_path, workspace)


def test_simulation_requires_secret_for_hashing(workspace, fixture_files):
    with pytest.raises(SimulationError, match="SECRET"):
        run_simulation(fixture_files["sqlite"], EXAMPLE, workspace, sample_size=4)


def test_simulation_validates_linkage_and_kpi_references(
    workspace, fixture_files, secret_store
):
    with pytest.raises(SimulationError, match="unknown column"):
        run_simulation(
            fixture_files["sqlite"], EXAMPLE, workspace,
            secrets_store=secret_store,
            linkage_pairs=["orders.nope=customers.customer_id"],
        )
    with pytest.raises(SimulationError, match="KPI"):
        run_simulation(
            fixture_files["sqlite"], EXAMPLE, workspace,
            secrets_store=secret_store, kpi_columns=["no_dot"],
        )


def test_linkage_spec_parser():
    spec = LinkageSpec.parse("orders.customer_id=customers.customer_id")
    assert spec.key() == ("orders", "customer_id", "customers", "customer_id")
    with pytest.raises(SimulationError):
        LinkageSpec.parse("bad-format")


def test_csv_dataset_simulation(workspace, fixture_files, secret_store):
    result = run_simulation(
        fixture_files["csv"], EXAMPLE, workspace,
        sample_size=2, secrets_store=secret_store,
    )
    assert result.document["dataset"]["kind"] == "csv"
    leads = result.document["tables"][0]
    assert leads["table_name"] == "leads"
    assert leads["sampled_rows"] >= 1


# --------------------------------------------------------------------------
# Version comparison
# --------------------------------------------------------------------------

def test_compare_simulations_detects_rule_changes_and_breakage(
    workspace, fixture_files, secret_store, make_policy
):
    baseline = run_simulation(
        fixture_files["sqlite"], EXAMPLE, workspace,
        sample_size=8, secrets_store=secret_store,
        linkage_pairs=["orders.customer_id=customers.customer_id"],
    )
    strict = make_policy(
        """
        version: 1
        name: strict
        datasets:
          - path: "demo.sqlite"
            tables:
              customers:
                columns:
                  full_name: {transformer: nullify}
                  phone: {transformer: nullify}
              orders:
                columns:
                  customer_id: {transformer: pseudonym}
                  amount: {transformer: nullify}
        """
    )
    changed = run_simulation(
        fixture_files["sqlite"], strict.source_path, workspace,
        sample_size=8, secrets_store=secret_store,
        linkage_pairs=["orders.customer_id=customers.customer_id"],
        kpi_columns=["orders.amount"],
    )
    diff = compare_simulations(changed.document, baseline.document)
    assert diff["same_dataset"] is True
    names = {
        (item["table_name"], item["column_name"]): item["change"]
        for item in diff["columns"]
    }
    assert names[("customers", "full_name")] == "modified"
    assert names[("customers", "email")] == "removed_from_policy"
    assert names[("orders", "customer_id")] == "modified"
    assert diff["summary"]["fully_broken_linkages"] == 1
    broken = diff["linkages"][0]
    assert broken["retention_rate"]["current"] == 0.0
    assert broken["retention_rate"]["previous"] == 1.0
    markdown = render_comparison_markdown(diff)
    assert "仿真版本对比" in markdown
    assert render_simulation_markdown(changed.document).startswith(
        "# maskline 策略影响仿真评估报告"
    )


def test_store_latest_and_listing(workspace, fixture_files, secret_store):
    first = run_simulation(
        fixture_files["sqlite"], EXAMPLE, workspace,
        sample_size=4, secrets_store=secret_store,
    )
    second = run_simulation(
        fixture_files["sqlite"], EXAMPLE, workspace,
        sample_size=4, secrets_store=secret_store,
    )
    store = SimulationStore(paths=workspace)
    listing = store.list_for_dataset(first.document["dataset"]["fingerprint"])
    assert [row["simulation_id"] for row in listing][0] == second.simulation_id
    latest = store.latest_for_dataset(
        first.document["dataset"]["fingerprint"], exclude=second.simulation_id
    )
    assert latest["simulation_id"] == first.simulation_id


# --------------------------------------------------------------------------
# Audit integration
# --------------------------------------------------------------------------

def test_simulation_writes_audit_chain_entries(
    workspace, fixture_files, secret_store, monkeypatch
):
    from maskline.__main__ import main

    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(secret_store.source))
    exit_code = main([
        "simulate", "--workspace", str(workspace.root),
        "--dataset", str(fixture_files["sqlite"]),
        "--policy", str(EXAMPLE),
        "--sample-size", "4", "--no-report",
    ])
    assert exit_code == 0
    entries = read_audit_entries(workspace.audit_path)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["event_type"] == "policy_impact_simulation"
    assert entry["output_path"] is None and entry["output_hash"] is None
    verification = AuditLog(workspace.audit_path).verify()
    assert verification.entries == 1


def test_failed_simulation_is_audited(
    workspace, fixture_files, secret_store, monkeypatch, capsys
):
    from maskline.__main__ import main

    bad_policy = workspace.root / "bad.yaml"
    bad_policy.write_text(
        "version: 1\nname: bad\ndatasets:\n"
        "  - path: 'demo.sqlite'\n    tables:\n      customers:\n"
        "        columns:\n          ghost: {transformer: mask}\n",
        encoding="utf-8",
    )
    exit_code = main([
        "simulate", "--workspace", str(workspace.root),
        "--dataset", str(fixture_files["sqlite"]),
        "--policy", str(bad_policy),
    ])
    assert exit_code == 2
    entries = read_audit_entries(workspace.audit_path)
    assert len(entries) == 1
    assert entries[0]["status"] == "failed"
    assert "unknown column" in entries[0]["error"]
    AuditLog(workspace.audit_path).verify()


def test_store_concurrent_writers_do_not_lock(workspace):
    """Regression test: parallel connections must not fail on the WAL switch."""
    import threading

    store = SimulationStore(paths=workspace)
    doc_template = {
        "simulation_id": "sim-base",
        "kind": "policy_impact_simulation",
        "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00",
        "dataset": {"path": "d", "fingerprint": "fp", "kind": "sqlite",
                    "size_bytes": 1, "row_count": 1},
        "policy": {"name": "p", "version": 1, "fingerprint": "pf",
                   "source_path": "pol.yaml"},
        "sample": {"requested_sample_size": 1},
        "rows_processed": 1,
    }
    errors: list[Exception] = []

    def writer(identifier: int) -> None:
        try:
            # Each thread opens its own connection, mimicking separate processes.
            local = SimulationStore(paths=workspace)
            doc = dict(doc_template)
            doc["simulation_id"] = f"sim-concurrent-{identifier}"
            local.save(doc)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
        assert not thread.is_alive()
    assert not errors, errors
    assert len(store.list_for_dataset("fp")) == 10


def test_concurrent_simulations_isolate_temp_resources(
    workspace, fixture_files, secret_store, monkeypatch
):
    # Subprocesses resolve the secret through the documented environment
    # variable, exercising the same path as the CLI under parallel invocation.
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(secret_store.source))
    env = dict(os.environ)
    procs = [
        subprocess.Popen(
            [
                sys.executable, "-c",
                (
                    "from maskline.config import Paths, SecretStore; "
                    "from maskline.simulation import run_simulation; "
                    f"run_simulation(r'''{fixture_files['sqlite']}''', "
                    f"r'''{EXAMPLE}''', Paths.for_workspace(r'''{workspace.root}'''), "
                    "sample_size=3, secrets_store=SecretStore.from_env())"
                ),
            ],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for _ in range(4)
    ]
    for proc in procs:
        _stdout, stderr = proc.communicate(timeout=120)
        assert proc.returncode == 0, stderr.decode()
    # All temp dirs cleaned even with parallel runs.
    assert not list((workspace.data_dir / "sim-tmp").glob("sim-*"))
    # Each run still persisted its own result document.
    from maskline.simulation.store import SimulationStore
    listing = SimulationStore(paths=workspace).list_for_dataset(
        inspect_dataset(fixture_files["sqlite"]).fingerprint
    )
    assert len(listing) == 4


def test_concurrent_cli_simulations_keep_audit_chain_valid(
    workspace, fixture_files, secret_store, monkeypatch
):
    # Drive the real CLI handler from parallel threads: this exercises the
    # cross-process fcntl lock path (threads serialize on it within one
    # process) without the timeout noise of spawning cold Python interpreters.
    from maskline.__main__ import _cmd_simulate
    import argparse
    import threading

    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(secret_store.source))
    errors: list[str] = []

    def worker() -> None:
        args = argparse.Namespace(
            workspace=str(workspace.root),
            dataset=str(fixture_files["sqlite"]),
            policy=str(EXAMPLE),
            sample_size=3,
            batch_size=1000,
            file_size_threshold=100 * 1024 * 1024,
            linkage=[],
            kpi=[],
            temp_root=None,
            no_detect=False,
            no_save=False,
            no_report=True,
        )
        try:
            assert _cmd_simulate(args) == 0
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
        assert not thread.is_alive(), "simulation worker timed out"
    assert not errors, errors
    entries = read_audit_entries(workspace.audit_path)
    assert len(entries) == 6
    assert AuditLog(workspace.audit_path).verify().entries == 6
    assert not list((workspace.data_dir / "sim-tmp").glob("sim-*"))


def test_cli_simulate_diff_end_to_end(
    workspace, fixture_files, secret_store, monkeypatch, make_policy
):
    from maskline.__main__ import main

    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(secret_store.source))
    assert main([
        "simulate", "--workspace", str(workspace.root),
        "--dataset", str(fixture_files["sqlite"]), "--policy", str(EXAMPLE),
        "--sample-size", "6", "--no-report",
    ]) == 0
    strict = make_policy(
        """
        version: 1
        name: strict
        datasets:
          - path: "demo.sqlite"
            tables:
              customers:
                columns:
                  full_name: {transformer: nullify}
              orders:
                columns:
                  amount: {transformer: nullify}
        """
    )
    assert main([
        "simulate", "--workspace", str(workspace.root),
        "--dataset", str(fixture_files["sqlite"]), "--policy", str(strict.source_path),
        "--sample-size", "6", "--kpi", "orders.amount", "--no-report",
    ]) == 0
    store = SimulationStore(paths=workspace)
    fingerprint = inspect_dataset(fixture_files["sqlite"]).fingerprint
    listing = store.list_for_dataset(fingerprint)
    current_id, previous_id = [row["simulation_id"] for row in listing[:2]]
    # Default previous = latest other run for the same dataset.
    assert main([
        "simulate-diff", "--workspace", str(workspace.root),
        "--current", current_id, "--no-report",
    ]) == 0
    # Explicit previous selection.
    assert main([
        "simulate-diff", "--workspace", str(workspace.root),
        "--current", current_id, "--previous", previous_id,
    ]) == 0
    diff_path = workspace.reports_dir / f"{current_id}.compare.json"
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    assert diff["same_dataset"] is True
    assert diff["summary"]["modified"] >= 1
    # Unknown simulation id fails cleanly.
    assert main([
        "simulate-diff", "--workspace", str(workspace.root),
        "--current", "sim-does-not-exist",
    ]) == 2
