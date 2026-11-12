"""Namespace-partitioned pseudonym mapping stores.

Covers cross-namespace isolation, same-namespace reuse, concurrent writes,
legacy single-database compatibility, key-consistency checks, tamper
detection, capacity alerts, and resume/reveal interoperability.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sqlite3
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import pytest

fcntl = pytest.importorskip("fcntl", reason="file locks require a POSIX platform")

from maskline import pseudomap as pseudomap_module
from maskline.audit import read_audit_entries, verify_audit
from maskline.config import ConfigError, Paths, create_demo_secret
from maskline.pipeline.checkpoint import CheckpointStore
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.policies import PolicyError, load_policy
from maskline.pseudomap import (
    CAPACITY_WARNING_THRESHOLD,
    NamespaceBindingError,
    NamespaceError,
    NamespaceKeyMismatch,
    PseudoMap,
    ensure_namespace,
    namespace_key_fingerprint,
    reveal_token,
)
from maskline.registry import Catalog, inspect_dataset
from maskline.transformers.pseudonym import pseudonym_token
from maskline.workflow import finalize_run

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"
# Fingerprint of policies/example.yaml before namespaces existed; the
# namespace feature must not change legacy policy fingerprints.
EXAMPLE_FINGERPRINT = "9ecbfa88b9528c86263ea5e1bbebb72e26a5c3f87ab6036dd7814f086eaef6fc"


def write_csv(path: Path, names: list[str]) -> Path:
    lines = ["name,city"] + [f"{name},上海" for name in names]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def csv_policy(make_policy, filename: str, namespace: str | None = None):
    table = Path(filename).stem
    namespace_line = f'\n            namespace: "{namespace}"' if namespace is not None else ""
    return make_policy(
        f"""
        version: 1
        name: ns-test
        datasets:
          - path: "{filename}"{namespace_line}
            tables:
              {table}:
                columns:
                  name: {{transformer: pseudonym}}
        """
    )


def output_tokens(output_path: Path, table: str) -> list[str]:
    conn = sqlite3.connect(output_path)
    try:
        return [row[0] for row in conn.execute(f'SELECT name FROM "{table}" ORDER BY rowid')]
    finally:
        conn.close()


def run_csv(workspace, make_policy, secret_store, csv_path, namespace=None, **kwargs):
    inventory = inspect_dataset(csv_path)
    policy = csv_policy(make_policy, csv_path.name, namespace)
    return execute_run(inventory, policy, workspace, secrets_store=secret_store, **kwargs)


# ---------------------------------------------------------------------------
# Policy schema and path safety
# ---------------------------------------------------------------------------

def test_example_policy_fingerprint_is_stable():
    policy = load_policy(EXAMPLE)
    assert policy.fingerprint == EXAMPLE_FINGERPRINT
    assert all("namespace" not in rule.to_dict() for rule in policy.datasets)
    assert all(rule.namespace is None for rule in policy.datasets)


@pytest.mark.parametrize("namespace", ["finance", "biz_line-1", "A1", "x" * 64])
def test_valid_namespaces_are_accepted(make_policy, namespace):
    policy = csv_policy(make_policy, "alpha.csv", namespace)
    assert policy.datasets[0].namespace == namespace
    assert policy.datasets[0].to_dict()["namespace"] == namespace


@pytest.mark.parametrize(
    "namespace",
    ["../evil", "a/b", "a\\b", "has space", "dot.sqlite", "", "-lead", "_lead", "x" * 65, "。"],
)
def test_unsafe_namespaces_are_rejected(make_policy, namespace):
    with pytest.raises(PolicyError, match="invalid pseudonym namespace"):
        csv_policy(make_policy, "alpha.csv", namespace)


def test_non_string_namespace_is_rejected(make_policy):
    with pytest.raises(PolicyError, match="invalid pseudonym namespace"):
        make_policy(
            """
            version: 1
            name: bad
            datasets:
              - path: "alpha.csv"
                namespace: 123
                tables:
                  alpha:
                    columns:
                      name: {transformer: pseudonym}
            """
        )


def test_namespace_changes_policy_fingerprint(make_policy):
    plain = csv_policy(make_policy, "alpha.csv")
    namespaced = csv_policy(make_policy, "alpha.csv", "finance")
    assert plain.fingerprint != namespaced.fingerprint


def test_pseudomap_path_stays_inside_workspace(workspace):
    assert workspace.pseudomap_path(None) == workspace.pseudomap_db
    namespaced = workspace.pseudomap_path("finance")
    assert namespaced == workspace.pseudomap_dir / "finance.sqlite"
    assert namespaced.parent == workspace.pseudomap_dir
    for bad in ("../evil", "a/b", "..", "x.sqlite"):
        with pytest.raises(ConfigError, match="invalid pseudonym namespace"):
            workspace.pseudomap_path(bad)


# ---------------------------------------------------------------------------
# Isolation and reuse
# ---------------------------------------------------------------------------

def test_cross_namespace_isolation(tmp_path, workspace, make_policy, secret_store):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟", "李娜"])
    beta = write_csv(tmp_path / "beta.csv", ["张伟", "王芳"])
    first = run_csv(workspace, make_policy, secret_store, alpha, "biz-a")
    second = run_csv(workspace, make_policy, secret_store, beta, "biz-b")

    key = secret_store.get("pseudonym_key")
    default_token = pseudonym_token("张伟", key)
    token_a = output_tokens(first.output_path, "alpha")[0]
    token_b = output_tokens(second.output_path, "beta")[0]
    assert token_a != token_b, "same plaintext must not share pseudonyms across namespaces"
    assert token_a != default_token and token_b != default_token
    assert token_a == pseudonym_token("张伟", key, "biz-a")
    assert token_b == pseudonym_token("张伟", key, "biz-b")

    # Physical isolation: one database per namespace, each holding only its
    # own namespace's entries.
    path_a = workspace.pseudomap_path("biz-a")
    path_b = workspace.pseudomap_path("biz-b")
    assert path_a.exists() and path_b.exists() and path_a != path_b
    assert not workspace.pseudomap_db.exists()
    with PseudoMap(path_a, namespace="biz-a") as mapping:
        assert mapping.reveal(token_a) == "张伟"
        assert mapping.get(token_b) is None
        assert mapping.count() == 2
    with PseudoMap(path_b, namespace="biz-b") as mapping:
        assert mapping.reveal(token_b) == "张伟"
        assert mapping.get(token_a) is None
        assert mapping.count() == 2


def test_same_namespace_reuses_pseudonyms_across_datasets(
    tmp_path, workspace, make_policy, secret_store
):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟", "李娜"])
    beta = write_csv(tmp_path / "beta.csv", ["张伟", "王芳"])
    first = run_csv(workspace, make_policy, secret_store, alpha, "shared")
    second = run_csv(workspace, make_policy, secret_store, beta, "shared")

    token_alpha = output_tokens(first.output_path, "alpha")[0]
    token_beta = output_tokens(second.output_path, "beta")[0]
    assert token_alpha == token_beta, "datasets in one namespace must join on pseudonyms"
    with PseudoMap(workspace.pseudomap_path("shared"), namespace="shared") as mapping:
        # 张伟 shared, plus 李娜 and 王芳: three distinct plaintexts in one store.
        assert mapping.count() == 3
        assert mapping.reveal(token_alpha) == "张伟"


def test_default_mode_keeps_legacy_store_and_tokens(
    tmp_path, workspace, make_policy, secret_store
):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟"])
    result = run_csv(workspace, make_policy, secret_store, alpha)
    key = secret_store.get("pseudonym_key")
    assert workspace.pseudomap_db.exists()
    assert not workspace.pseudomap_dir.exists()
    assert output_tokens(result.output_path, "alpha") == [pseudonym_token("张伟", key)]
    assert result.pseudonym_namespace is None


# ---------------------------------------------------------------------------
# Namespace metadata binding and key consistency
# ---------------------------------------------------------------------------

def test_namespace_metadata_is_bound_in_catalog(
    tmp_path, workspace, make_policy, secret_store
):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟"])
    inventory = inspect_dataset(alpha)
    run_csv(workspace, make_policy, secret_store, alpha, "finance")
    with Catalog(workspace.meta_db) as catalog:
        assert catalog.get_namespace_key_fingerprint("finance") == namespace_key_fingerprint(
            "finance", secret_store.get("pseudonym_key")
        )
        assert catalog.dataset_namespace(inventory.fingerprint) == "finance"
        assert catalog.namespace_datasets("finance") == [inventory.fingerprint]


def test_key_mismatch_fails_before_execution(
    tmp_path, workspace, make_policy, secret_store
):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟"])
    run_csv(workspace, make_policy, secret_store, alpha, "finance")

    other_store = create_demo_secret(tmp_path / "other-secret.txt")
    assert other_store.get("pseudonym_key") != secret_store.get("pseudonym_key")
    forbidden_output = tmp_path / "must-not-exist.sqlite"
    with pytest.raises(NamespaceKeyMismatch, match="different pseudonym_key"):
        run_csv(
            workspace, make_policy, other_store, alpha, "finance",
            output_path=forbidden_output,
        )
    # The run must be rejected before any execution artifacts appear.
    assert not forbidden_output.exists()
    with CheckpointStore(workspace.checkpoint_db) as store:
        assert len(store.list_runs()) == 1


def test_dataset_cannot_be_rebound_to_another_namespace(
    tmp_path, workspace, make_policy, secret_store
):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟"])
    run_csv(workspace, make_policy, secret_store, alpha, "finance")
    with pytest.raises(NamespaceBindingError, match="already bound to namespace"):
        run_csv(workspace, make_policy, secret_store, alpha, "other-line")


def test_swapped_store_files_are_detected(tmp_path):
    path_a = tmp_path / "a.sqlite"
    path_b = tmp_path / "b.sqlite"
    with PseudoMap(path_a, create=True, namespace="ns-a"):
        pass
    with PseudoMap(path_b, create=True, namespace="ns-b"):
        pass
    swapped = tmp_path / "tmp.sqlite"
    os.rename(path_a, swapped)
    os.rename(path_b, path_a)
    os.rename(swapped, path_b)
    with pytest.raises(NamespaceError, match="belongs to namespace"):
        PseudoMap(path_a, namespace="ns-a")
    with PseudoMap(path_a) as mapping:  # read-only open adopts the stored marker
        assert mapping.namespace == "ns-b"


def test_ensure_namespace_direct(tmp_path, secret_store):
    key = secret_store.get("pseudonym_key")
    with Catalog(tmp_path / "meta.sqlite") as catalog:
        ensure_namespace(catalog, "finance", "fp-one", key)
        ensure_namespace(catalog, "finance", "fp-one", key)  # idempotent
        ensure_namespace(catalog, "finance", "fp-two", key)  # second dataset joins
        assert catalog.namespace_datasets("finance") == ["fp-one", "fp-two"]
        with pytest.raises(NamespaceKeyMismatch):
            ensure_namespace(catalog, "finance", "fp-three", key + "x")
        with pytest.raises(NamespaceBindingError):
            ensure_namespace(catalog, "other", "fp-one", key)


# ---------------------------------------------------------------------------
# Legacy single-database compatibility
# ---------------------------------------------------------------------------

def make_legacy_store(path: Path, entries: dict[str, str]) -> None:
    """A pre-upgrade mapping database: only pseudonym_map, no metadata table."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE pseudonym_map ("
            "token TEXT PRIMARY KEY, plaintext TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        for token, plaintext in entries.items():
            conn.execute(
                "INSERT INTO pseudonym_map VALUES (?, ?, ?)",
                (token, plaintext, "2025-01-01T00:00:00+00:00"),
            )
        conn.commit()
    finally:
        conn.close()


def test_legacy_store_reads_and_appends_without_token_changes(
    tmp_path, workspace, make_policy, secret_store
):
    key = secret_store.get("pseudonym_key")
    legacy_token = pseudonym_token("张伟", key)  # pre-upgrade derivation
    make_legacy_store(workspace.pseudomap_db, {legacy_token: "张伟"})

    alpha = write_csv(tmp_path / "alpha.csv", ["张伟", "李娜"])
    result = run_csv(workspace, make_policy, secret_store, alpha)

    # Historical entries still resolve, new entries append to the same store,
    # and the pseudonym for the legacy plaintext is unchanged.
    assert output_tokens(result.output_path, "alpha")[0] == legacy_token
    with PseudoMap(workspace.pseudomap_db) as mapping:
        assert mapping.namespace is None
        assert mapping.reveal(legacy_token) == "张伟"
        assert mapping.count() == 2
        assert mapping.reveal(pseudonym_token("李娜", key)) == "李娜"


def test_default_mode_rerun_is_idempotent(tmp_path, workspace, make_policy, secret_store):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟", "李娜"])
    first = run_csv(workspace, make_policy, secret_store, alpha)
    second = run_csv(workspace, make_policy, secret_store, alpha)
    assert first.output_hash == second.output_hash
    with PseudoMap(workspace.pseudomap_db) as mapping:
        assert mapping.count() == 2


# ---------------------------------------------------------------------------
# Concurrent writes
# ---------------------------------------------------------------------------

def put_entries(db_path: str, namespace: str, start: int, count: int) -> int:
    with PseudoMap(db_path, create=True, namespace=namespace) as mapping:
        for index in range(start, start + count):
            mapping.put(f"psn_{index:040d}", f"value-{index}")
        mapping.commit()
    return count


def test_concurrent_writes_from_threads_serialize(tmp_path):
    db_path = str(tmp_path / "shared.sqlite")
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(put_entries, db_path, "shared", start * 25, 25)
            for start in range(4)
        ]
        assert sum(future.result(timeout=60) for future in futures) == 100
    with PseudoMap(db_path, namespace="shared") as mapping:
        assert mapping.count() == 100
        assert mapping.reveal("psn_" + "0" * 37 + "042") == "value-42"


def test_concurrent_writes_from_processes_serialize(tmp_path):
    db_path = str(tmp_path / "shared.sqlite")
    context = mp.get_context("fork")
    with ProcessPoolExecutor(max_workers=4, mp_context=context) as pool:
        futures = [
            pool.submit(put_entries, db_path, "shared", start * 25, 25)
            for start in range(4)
        ]
        assert sum(future.result(timeout=60) for future in futures) == 100
    with PseudoMap(db_path, namespace="shared") as mapping:
        assert mapping.count() == 100


def test_exclusive_lock_is_held_while_open(tmp_path):
    db_path = tmp_path / "map.sqlite"
    lock_path = tmp_path / "map.sqlite.lock"
    with PseudoMap(db_path, create=True):
        assert lock_path.exists()
        fd = os.open(lock_path, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
    fd = os.open(lock_path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released on close
    finally:
        os.close(fd)


def test_concurrent_runs_sharing_one_namespace(
    tmp_path, workspace, make_policy, secret_store
):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟", "李娜"])
    beta = write_csv(tmp_path / "beta.csv", ["张伟", "王芳"])
    with ThreadPoolExecutor(max_workers=2) as pool:
        future_a = pool.submit(
            run_csv, workspace, make_policy, secret_store, alpha, "shared"
        )
        future_b = pool.submit(
            run_csv, workspace, make_policy, secret_store, beta, "shared"
        )
        first = future_a.result(timeout=120)
        second = future_b.result(timeout=120)
    token_a = output_tokens(first.output_path, "alpha")[0]
    token_b = output_tokens(second.output_path, "beta")[0]
    assert token_a == token_b
    with PseudoMap(workspace.pseudomap_path("shared"), namespace="shared") as mapping:
        assert mapping.count() == 3


# ---------------------------------------------------------------------------
# Capacity warning
# ---------------------------------------------------------------------------

def test_capacity_warning_is_audited(
    tmp_path, workspace, make_policy, secret_store, monkeypatch
):
    assert CAPACITY_WARNING_THRESHOLD == 1_000_000
    monkeypatch.setattr(pseudomap_module, "CAPACITY_WARNING_THRESHOLD", 3)
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟", "李娜", "王芳", "赵磊"])
    inventory = inspect_dataset(alpha)
    policy = csv_policy(make_policy, alpha.name, "finance")
    result = execute_run(inventory, policy, workspace, secrets_store=secret_store)
    assert result.pseudomap_entries == 4
    artifacts = finalize_run(workspace, inventory, policy, result, findings=[])

    warning = artifacts["capacity_warning"]
    assert warning is not None
    assert warning["event"] == "pseudomap_capacity_warning"
    assert warning["namespace"] == "finance"
    assert warning["entries"] == 4
    assert warning["threshold"] == 3
    entries = read_audit_entries(workspace.audit_path)
    warnings = [e for e in entries if e.get("event") == "pseudomap_capacity_warning"]
    assert len(warnings) == 1
    assert entries[0]["pseudonym_namespace"] == "finance"
    assert verify_audit(workspace.audit_path).entries == 2


def test_no_capacity_warning_below_threshold(
    tmp_path, workspace, make_policy, secret_store, monkeypatch
):
    monkeypatch.setattr(pseudomap_module, "CAPACITY_WARNING_THRESHOLD", 100)
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟", "李娜"])
    inventory = inspect_dataset(alpha)
    policy = csv_policy(make_policy, alpha.name, "finance")
    result = execute_run(inventory, policy, workspace, secrets_store=secret_store)
    artifacts = finalize_run(workspace, inventory, policy, result, findings=[])
    assert artifacts["capacity_warning"] is None
    events = [e.get("event") for e in read_audit_entries(workspace.audit_path)]
    assert "pseudomap_capacity_warning" not in events


# ---------------------------------------------------------------------------
# Resume and reveal interoperability
# ---------------------------------------------------------------------------

def test_namespaced_run_resumes_to_identical_output(
    tmp_path, make_policy, secret_store
):
    names = ["张伟", "李娜", "王芳", "赵磊", "陈静"]
    alpha = write_csv(tmp_path / "alpha.csv", names)
    baseline_paths = Paths.for_workspace(tmp_path / "baseline")
    interrupted_paths = Paths.for_workspace(tmp_path / "interrupted")

    baseline = run_csv(
        baseline_paths, make_policy, secret_store, alpha, "finance", batch_size=2
    )
    with pytest.raises(PipelineInterrupted) as excinfo:
        run_csv(
            interrupted_paths, make_policy, secret_store, alpha, "finance",
            batch_size=2, interrupt_after_batches=1,
        )
    run_id = excinfo.value.run_id
    inventory = inspect_dataset(alpha)
    policy = csv_policy(make_policy, alpha.name, "finance")
    resumed = execute_run(
        inventory, policy, interrupted_paths,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.output_hash == baseline.output_hash
    assert output_tokens(resumed.output_path, "alpha") == output_tokens(
        baseline.output_path, "alpha"
    )
    with PseudoMap(interrupted_paths.pseudomap_path("finance"), namespace="finance") as m:
        assert m.count() == len(names)


def test_reveal_token_per_namespace(tmp_path, workspace, make_policy, secret_store):
    alpha = write_csv(tmp_path / "alpha.csv", ["张伟"])
    beta = write_csv(tmp_path / "beta.csv", ["张伟", "王芳"])
    first = run_csv(workspace, make_policy, secret_store, alpha, "biz-a")
    run_csv(workspace, make_policy, secret_store, beta, "biz-b")
    token_a = output_tokens(first.output_path, "alpha")[0]

    assert reveal_token(workspace.pseudomap_path("biz-a"), token_a) == "张伟"
    with pytest.raises(Exception, match="token not found"):
        reveal_token(workspace.pseudomap_path("biz-b"), token_a)
    with pytest.raises(Exception, match="mapping database not found"):
        reveal_token(workspace.pseudomap_db, token_a)


def test_reveal_cli_with_namespace(
    tmp_path, workspace, make_policy, secret_store, capsys
):
    from maskline.__main__ import main

    alpha = write_csv(tmp_path / "alpha.csv", ["张伟"])
    result = run_csv(workspace, make_policy, secret_store, alpha, "finance")
    token = output_tokens(result.output_path, "alpha")[0]

    assert main([
        "reveal", "--workspace", str(workspace.root),
        "--namespace", "finance", "--token", token,
    ]) == 0
    assert capsys.readouterr().out.strip() == "张伟"
    # Traversal attempts through the CLI are rejected, not resolved.
    assert main([
        "reveal", "--workspace", str(workspace.root),
        "--namespace", "../escape", "--token", token,
    ]) == 2
    assert "invalid pseudonym namespace" in capsys.readouterr().err
