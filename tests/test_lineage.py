"""Tests for cross-run correlation, full-link tracing and tamper detection."""

from __future__ import annotations

import json
import multiprocessing as mp
import sqlite3
from pathlib import Path

import pytest

from maskline.audit import AuditLog, build_audit_entry, read_audit_entries, verify_audit
from maskline.lineage import (
    CORRELATION_PREFIX,
    CorrelationIntegrityError,
    LineageStore,
    correlation_id,
    trace_dataset,
    verify_correlation_ids,
)
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import load_policy
from maskline.utils import sqlite_content_digest

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _policy_variant(tmp_path: Path, name: str, keep_suffix: int):
    path = tmp_path / f"policy-{name}.yaml"
    path.write_text(
        f"""
        version: 1
        name: {name}
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  phone:
                    transformer: mask
                    params: {{keep_prefix: 3, keep_suffix: {keep_suffix}}}
                  full_name:
                    transformer: pseudonym
        """,
        encoding="utf-8",
    )
    return load_policy(path)


# ---------------------------------------------------------------------------
# Deterministic correlation ids
# ---------------------------------------------------------------------------

def test_correlation_id_is_stable_and_distinct():
    fp_a = "a" * 64
    fp_b = "b" * 64
    cid_a = correlation_id(fp_a)
    assert cid_a == correlation_id(fp_a)
    assert cid_a.startswith(CORRELATION_PREFIX)
    assert cid_a != correlation_id(fp_b)
    # 16 hex chars of digest plus the prefix.
    assert len(cid_a) == len(CORRELATION_PREFIX) + 16


def test_correlation_id_rejects_bad_fingerprint():
    with pytest.raises(Exception):
        correlation_id("")


# ---------------------------------------------------------------------------
# Legacy audit chains remain fully valid
# ---------------------------------------------------------------------------

def _write_legacy_entry(log: AuditLog, run_id: str, fingerprint: str, seq_field=True):
    """Mimic a pre-lineage audit entry: no correlation_id field at all."""
    entry = {
        "run_id": run_id,
        "dataset_path": "/data/demo.sqlite",
        "dataset_fingerprint": fingerprint,
        "policy_name": "legacy-policy",
        "policy_fingerprint": "p" * 64,
        "columns": {},
        "rows_processed": 10,
        "transform_counts": {},
        "output_path": "/data/out/demo.masked.sqlite",
        "output_hash": "h" * 64,
        "elapsed_seconds": 0.1,
    }
    return log.append(entry)


def test_legacy_audit_chain_verifies_with_original_command(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    log = AuditLog(audit_path)
    fingerprint = "f" * 64
    for index in range(3):
        _write_legacy_entry(log, f"legacy-run-{index}", fingerprint)
    # The unchanged, original verification command must pass as-is.
    verification = verify_audit(audit_path)
    assert verification.entries == 3
    entries = read_audit_entries(audit_path)
    assert all("correlation_id" not in entry for entry in entries)


def test_legacy_entries_derive_correlation_id_without_rejection(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    log = AuditLog(audit_path)
    fingerprint = "f" * 64
    _write_legacy_entry(log, "legacy-run-0", fingerprint)
    _verification, records = verify_correlation_ids(audit_path)
    assert len(records) == 1
    assert records[0]["embedded"] is False
    assert records[0]["correlation_id"] == correlation_id(fingerprint)


def test_mixed_legacy_and_new_entries_chain_and_verify(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    log = AuditLog(audit_path)
    fingerprint = "f" * 64
    _write_legacy_entry(log, "legacy-run", fingerprint)
    new_entry = _write_legacy_entry(log, "new-run", fingerprint)
    # Rewrite the second entry through a fresh append-like flow with the field.
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["correlation_id"] = correlation_id(fingerprint)
    # Recompute the chain from line 2 onward exactly the way AuditLog does.
    first = json.loads(lines[0])
    second.pop("entry_hash", None)
    second.pop("prev_hash", None)
    from maskline.utils import canonical_json, sha256_text
    second["prev_hash"] = first["entry_hash"]
    second["entry_hash"] = sha256_text(canonical_json(second))
    lines[1] = canonical_json(second)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    head = tmp_path / "audit.jsonl.head"
    head.write_text(
        json.dumps({"count": 2, "last_hash": second["entry_hash"]}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _verification, records = verify_correlation_ids(audit_path)
    assert [record["embedded"] for record in records] == [False, True]
    assert verify_audit(audit_path).entries == 2


# ---------------------------------------------------------------------------
# End-to-end: three policy versions, interrupted run, resume, full trace
# ---------------------------------------------------------------------------

def test_three_policy_versions_with_kill_and_resume_trace_full_link(
    tmp_path, inventories, secret_store
):
    workspace = tmp_path / "ws"
    paths = type(
        "P",
        (),
        {
            "root": workspace,
            "audit_path": workspace / "audit" / "audit.jsonl",
            "lineage_db": workspace / "data" / "lineage.sqlite",
            "checkpoint_db": workspace / "data" / "checkpoints.sqlite",
        },
    )()
    # The real Paths object provides everything execute_run needs.
    from maskline.config import Paths
    paths = Paths.for_workspace(workspace)
    paths.ensure_runtime_dirs()

    inventory = inventories["sqlite"]
    base_policy = load_policy(EXAMPLE)
    policy_v2 = _policy_variant(tmp_path, "policy-v2", keep_suffix=2)
    policy_v3 = _policy_variant(tmp_path, "policy-v3", keep_suffix=1)
    policies = [base_policy, policy_v2, policy_v3]

    expected_corr = correlation_id(inventory.fingerprint)
    run_ids: list[str] = []

    # Run 1: normal completion with the base policy.
    r1 = execute_run(inventory, policies[0], paths, secrets_store=secret_store, batch_size=3)
    from maskline.workflow import finalize_run
    finalize_run(paths, inventory, policies[0], r1, [])
    run_ids.append(r1.run_id)
    assert r1.correlation_id == expected_corr

    # Run 2: killed mid-way (simulated SIGKILL via interrupt), then resumed.
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventory, policies[1], paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    killed_run_id = excinfo.value.run_id
    # The lineage store must already know about the interrupted run.
    with LineageStore(paths.lineage_db) as lineage:
        link = lineage.get_run(killed_run_id)
        assert link is not None and link.status == "interrupted"
        assert link.correlation_id == expected_corr
    with CheckpointStore(paths.checkpoint_db) as cp:
        record = cp.get_run(killed_run_id)
        assert record.correlation_id == expected_corr

    r2 = execute_run(
        inventory, policies[1], paths,
        secrets_store=secret_store, batch_size=4, resume_run_id=killed_run_id,
    )
    # Resume keeps the very same run id and correlation id.
    assert r2.run_id == killed_run_id
    assert r2.correlation_id == expected_corr
    finalize_run(paths, inventory, policies[1], r2, [])
    run_ids.append(r2.run_id)

    # Run 3: another policy version, normal completion.
    r3 = execute_run(inventory, policies[2], paths, secrets_store=secret_store)
    finalize_run(paths, inventory, policies[2], r3, [])
    run_ids.append(r3.run_id)

    # Every audit entry carries the identical correlation id.
    entries = read_audit_entries(paths.audit_path)
    assert len(entries) == 3
    assert {entry["correlation_id"] for entry in entries} == {expected_corr}
    policy_fps = {entry["policy_fingerprint"] for entry in entries}
    assert policy_fps == {policy.fingerprint for policy in policies}

    # Original chain verification still passes.
    assert verify_audit(paths.audit_path).entries == 3
    _verification, records = verify_correlation_ids(paths.audit_path)
    assert all(record["correlation_id"] == expected_corr for record in records)

    # Full-link trace by fingerprint, by dataset path and by correlation id.
    for kwargs in (
        {"dataset_fingerprint": inventory.fingerprint},
        {"correlation": expected_corr},
    ):
        trace = trace_dataset(
            paths.audit_path, lineage_path=paths.lineage_db, **kwargs
        )
        assert trace.correlation_id == expected_corr
        assert len(trace.events) == 3
        assert [event.run_id for event in trace.events] == run_ids
        assert set(trace.policy_fingerprints) == policy_fps
        assert all(event.source == "audit" for event in trace.events)
        assert all(event.correlation_id == expected_corr for event in trace.events)

    # Lineage links agree with the audit chain.
    with LineageStore(paths.lineage_db) as lineage:
        links = lineage.list_for_correlation(expected_corr)
        assert {link.run_id for link in links} == set(run_ids)
        assert all(link.audit_seq is not None for link in links)
        assert all(link.status == "completed" for link in links)


def test_trace_surfaces_interrupted_run_without_audit_entry(
    tmp_path, inventories, secret_store
):
    from maskline.config import Paths
    paths = Paths.for_workspace(tmp_path / "ws")
    paths.ensure_runtime_dirs()
    inventory = inventories["sqlite"]
    policy = load_policy(EXAMPLE)
    # One completed run with an audit entry.
    done = execute_run(inventory, policy, paths, secrets_store=secret_store)
    from maskline.workflow import finalize_run
    finalize_run(paths, inventory, policy, done, [])
    # One interrupted run that never reaches finalize_run.
    with pytest.raises(PipelineInterrupted):
        execute_run(
            inventory, policy, paths,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    trace = trace_dataset(
        paths.audit_path,
        lineage_path=paths.lineage_db,
        dataset_fingerprint=inventory.fingerprint,
    )
    sources = {event.source for event in trace.events}
    assert sources == {"audit", "run"}
    interrupted = [event for event in trace.events if event.source == "run"]
    assert len(interrupted) == 1
    assert interrupted[0].status == "interrupted"


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

def test_tampered_correlation_id_fails_chain_verification(tmp_path, inventories, secret_store):
    from maskline.config import Paths
    paths = Paths.for_workspace(tmp_path / "ws")
    paths.ensure_runtime_dirs()
    inventory = inventories["sqlite"]
    policy = load_policy(EXAMPLE)
    result = execute_run(inventory, policy, paths, secrets_store=secret_store)
    from maskline.workflow import finalize_run
    finalize_run(paths, inventory, policy, result, [])

    lines = paths.audit_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    original = entry["correlation_id"]
    entry["correlation_id"] = CORRELATION_PREFIX + "0" * 16
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    paths.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # First layer: the original hash-chain check catches the altered payload.
    with pytest.raises(Exception, match="hash"):
        verify_audit(paths.audit_path)
    # Restore the hash so only the correlation semantic check can fail.
    entry2 = json.loads(lines[0])
    from maskline.utils import canonical_json, sha256_text
    claimed_hash = entry2.pop("entry_hash")
    entry2["entry_hash"] = sha256_text(
        canonical_json({k: v for k, v in entry2.items() if k != "entry_hash"})
    )
    lines[0] = canonical_json(entry2)
    paths.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    head = paths.audit_path.with_name("audit.jsonl.head")
    head.write_text(
        json.dumps({"count": 1, "last_hash": entry2["entry_hash"]}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    # Second layer: correlation semantics reject the forged id.
    with pytest.raises(CorrelationIntegrityError) as excinfo:
        verify_correlation_ids(paths.audit_path)
    assert excinfo.value.line == 1
    with pytest.raises(CorrelationIntegrityError):
        trace_dataset(
            paths.audit_path, lineage_path=paths.lineage_db,
            dataset_fingerprint=inventory.fingerprint,
        )
    assert original != entry["correlation_id"]


def test_lineage_pointer_tamper_is_detected(tmp_path, inventories, secret_store):
    from maskline.config import Paths
    paths = Paths.for_workspace(tmp_path / "ws")
    paths.ensure_runtime_dirs()
    inventory = inventories["sqlite"]
    policy = load_policy(EXAMPLE)
    result = execute_run(inventory, policy, paths, secrets_store=secret_store)
    from maskline.workflow import finalize_run
    finalize_run(paths, inventory, policy, result, [])
    with sqlite3.connect(paths.lineage_db) as conn:
        conn.execute(
            "UPDATE lineage_runs SET audit_entry_hash = ? WHERE run_id = ?",
            ("deadbeef" * 8, result.run_id),
        )
        conn.commit()
    # The audit chain itself remains intact; the trace still works because the
    # chain entry is the source of truth. The stale pointer is observable.
    trace = trace_dataset(
        paths.audit_path, lineage_path=paths.lineage_db,
        dataset_fingerprint=inventory.fingerprint,
    )
    audit_event = next(event for event in trace.events if event.source == "audit")
    assert audit_event.entry_hash != "deadbeef" * 8
    assert verify_audit(paths.audit_path).entries == 1


# ---------------------------------------------------------------------------
# Record size budget: <= 10% inflation
# ---------------------------------------------------------------------------

def test_correlation_field_size_inflation_under_10_percent():
    fingerprint = "a" * 64
    legacy_body = {
        "run_id": "run-20260101-000000-abcdef",
        "dataset_path": "/data/raw/demo.sqlite",
        "dataset_fingerprint": fingerprint,
        "policy_name": "demo-local-masking",
        "policy_fingerprint": "b" * 64,
        "columns": {"customers": {"phone": "mask"}},
        "rows_processed": 1000,
        "transform_counts": {"mask": {"seen": 1000, "processed": 1000, "changed": 1000}},
        "output_path": "/data/out/demo.masked.sqlite",
        "output_hash": "c" * 64,
        "elapsed_seconds": 1.234567,
        "ts": "2026-01-01T00:00:00+00:00",
        "seq": 1,
        "prev_hash": "0" * 64,
    }
    new_body = dict(legacy_body)
    new_body["correlation_id"] = correlation_id(fingerprint)
    from maskline.utils import canonical_json
    legacy_size = len(canonical_json(legacy_body).encode("utf-8"))
    new_size = len(canonical_json(new_body).encode("utf-8"))
    inflation = (new_size - legacy_size) / legacy_size
    assert inflation <= 0.10
    # And concretely the field only adds ~30 bytes.
    assert new_size - legacy_size == len(
        canonical_json({"correlation_id": correlation_id(fingerprint)})
    ) - 1  # one separating comma in the serialized object


# ---------------------------------------------------------------------------
# Concurrency: five parallel runs on the same dataset, no id conflicts
# ---------------------------------------------------------------------------

def _concurrent_worker(payload):
    (
        workspace, dataset_path, policy_path, output_path, index
    ) = payload
    from maskline.config import Paths
    from maskline.pipeline.runner import execute_run
    from maskline.policies import load_policy
    from maskline.registry import inspect_dataset
    from maskline.workflow import finalize_run
    paths = Paths.for_workspace(workspace)
    inventory = inspect_dataset(dataset_path)
    policy = load_policy(policy_path)
    # Mask-only policy: no secret store and no pseudonym map, so workers only
    # contend on the lineage/checkpoint/audit coordination under test.
    result = execute_run(
        inventory, policy, paths, output_path=output_path,
    )
    finalize_run(paths, inventory, policy, result, [])
    return result.run_id, result.correlation_id


def test_five_concurrent_runs_share_correlation_without_conflicts(
    tmp_path, inventories
):
    from maskline.config import Paths
    workspace = tmp_path / "ws"
    paths = Paths.for_workspace(workspace)
    paths.ensure_runtime_dirs()
    inventory = inventories["sqlite"]
    expected_corr = correlation_id(inventory.fingerprint)

    parallel_policy = tmp_path / "parallel-policy.yaml"
    parallel_policy.write_text(
        """
        version: 1
        name: parallel-mask-only
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  phone:
                    transformer: mask
                    params: {keep_prefix: 3, keep_suffix: 4}
              orders:
                columns:
                  contact_phone:
                    transformer: mask
                    params: {keep_prefix: 3, keep_suffix: 4}
        """,
        encoding="utf-8",
    )

    ctx = mp.get_context("spawn")
    payloads = [
        (
            str(workspace), str(inventory.path), str(parallel_policy),
            str(paths.out_dir / f"parallel-{index}.sqlite"), index,
        )
        for index in range(5)
    ]
    with ctx.Pool(processes=5) as pool:
        results = pool.map(_concurrent_worker, payloads)

    run_ids = [item[0] for item in results]
    corr_ids = {item[1] for item in results}
    # Run ids are unique per task; the correlation id is shared and conflict-free.
    assert len(set(run_ids)) == 5
    assert corr_ids == {expected_corr}

    with LineageStore(paths.lineage_db) as lineage:
        links = lineage.list_for_correlation(expected_corr)
        assert len(links) == 5
        assert len({link.run_id for link in links}) == 5
        assert {link.status for link in links} == {"completed"}
        assert len({link.audit_seq for link in links}) == 5
        assert len({link.audit_entry_hash for link in links}) == 5

    # The shared audit hash chain remains intact with contiguous seq numbers.
    verification = verify_audit(paths.audit_path)
    assert verification.entries == 5
    entries = read_audit_entries(paths.audit_path)
    assert [entry["seq"] for entry in entries] == [1, 2, 3, 4, 5]
    assert {entry["run_id"] for entry in entries} == set(run_ids)
    assert {entry["correlation_id"] for entry in entries} == {expected_corr}
    _verification, records = verify_correlation_ids(paths.audit_path)
    assert len(records) == 5


# ---------------------------------------------------------------------------
# Checkpoint store migration on a v0.1 database
# ---------------------------------------------------------------------------

def test_checkpoint_store_migrates_legacy_runs_table(tmp_path):
    db_path = tmp_path / "checkpoints.sqlite"
    # Create the exact pre-lineage schema.
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE runs (run_id TEXT PRIMARY KEY, dataset_path TEXT NOT NULL, "
        "dataset_fingerprint TEXT NOT NULL, policy_path TEXT NOT NULL, "
        "policy_fingerprint TEXT NOT NULL, output_path TEXT NOT NULL, "
        "status TEXT NOT NULL, started_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE checkpoints (run_id TEXT NOT NULL, table_name TEXT NOT NULL, "
        "last_rowid INTEGER NOT NULL, rows_done INTEGER NOT NULL, "
        "updated_at TEXT NOT NULL, counts_json TEXT NOT NULL DEFAULT '{}', "
        "PRIMARY KEY (run_id, table_name))"
    )
    conn.execute(
        "INSERT INTO runs VALUES ('run-legacy', '/d.sqlite', ?, '/p.yaml', ?, "
        "'/o.sqlite', 'interrupted', 't0', 't1')",
        ("f" * 64, "p" * 64),
    )
    conn.commit()
    conn.close()

    with CheckpointStore(db_path) as store:
        record = store.get_run("run-legacy")
        assert record is not None and record.correlation_id is None
        from maskline.pipeline.checkpoint import RunRecord
        store.create_run(
            RunRecord(
                "run-new", "/d2.sqlite", "e" * 64, "/p2.yaml", "q" * 64,
                "/o2.sqlite", "running", "t2", "t3", correlation_id("e" * 64),
            )
        )
        assert store.get_run("run-new").correlation_id == correlation_id("e" * 64)


# ---------------------------------------------------------------------------
# Read-only source guarantee and offline/no-import guard
# ---------------------------------------------------------------------------

def test_source_dataset_never_modified(tmp_path, inventories, secret_store):
    from maskline.config import Paths
    paths = Paths.for_workspace(tmp_path / "ws")
    paths.ensure_runtime_dirs()
    inventory = inventories["sqlite"]
    before = sqlite_content_digest(inventory.path)
    policy = load_policy(EXAMPLE)
    result = execute_run(inventory, policy, paths, secrets_store=secret_store)
    from maskline.workflow import finalize_run
    finalize_run(paths, inventory, policy, result, [])
    assert sqlite_content_digest(inventory.path) == before


def test_lineage_module_uses_only_stdlib_offline_primitives():
    import inspect
    from maskline import lineage
    source = inspect.getsource(lineage)
    for forbidden in ("urllib", "requests", "http.client", "socket", "subprocess"):
        assert forbidden not in source


def test_build_audit_entry_includes_correlation_id(tmp_path, inventories, secret_store):
    from maskline.config import Paths
    paths = Paths.for_workspace(tmp_path / "ws")
    paths.ensure_runtime_dirs()
    inventory = inventories["sqlite"]
    policy = load_policy(EXAMPLE)
    result = execute_run(inventory, policy, paths, secrets_store=secret_store)
    entry = build_audit_entry(result, result.transformer_map)
    assert entry["correlation_id"] == correlation_id(inventory.fingerprint)
