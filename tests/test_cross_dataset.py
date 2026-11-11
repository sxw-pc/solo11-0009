"""Cross-dataset determinism, idempotency, concurrency, and audit coverage."""

from __future__ import annotations

import csv
import sqlite3
import threading
from pathlib import Path

from maskline.audit import AuditLog, read_audit_entries, verify_audit
from maskline.pipeline.runner import execute_run
from maskline.pseudomap import PseudoMap
from maskline.registry import inspect_dataset
from maskline.workflow import finalize_run

VALUES = ("张伟", "李娜", "王芳")


def _write_datasets(raw: Path) -> tuple[Path, Path]:
    raw.mkdir(parents=True, exist_ok=True)
    csv_path = raw / "people.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "full_name"])
        for index, value in enumerate(VALUES, start=1):
            writer.writerow([index, value])
    sqlite_path = raw / "people.sqlite"
    conn = sqlite3.connect(sqlite_path)
    try:
        conn.execute("CREATE TABLE people (id INTEGER, full_name TEXT)")
        conn.executemany(
            "INSERT INTO people VALUES (?, ?)",
            [(index, value) for index, value in enumerate(VALUES, start=1)],
        )
        conn.commit()
    finally:
        conn.close()
    return csv_path, sqlite_path


def _policy_text() -> str:
    return """
    version: 1
    name: cross-dataset
    datasets:
      - path: "people.csv"
        tables:
          people:
            columns:
              full_name: {transformer: pseudonym}
      - path: "people.sqlite"
        tables:
          people:
            columns:
              full_name: {transformer: pseudonym}
    """


def _output_tokens(path: Path) -> dict[int, str]:
    conn = sqlite3.connect(path)
    try:
        return {
            int(row[0]): row[1]
            for row in conn.execute("SELECT id, full_name FROM people")
        }
    finally:
        conn.close()


def test_csv_and_sqlite_share_pseudonyms_and_reruns_are_idempotent(
    workspace, secret_store, tmp_path, make_policy
):
    csv_path, sqlite_path = _write_datasets(tmp_path / "raw")
    policy = make_policy(_policy_text())
    paths = workspace

    csv_result = execute_run(
        inspect_dataset(csv_path),
        policy,
        paths,
        secrets_store=secret_store,
        output_path=tmp_path / "out" / "csv.masked.sqlite",
    )
    sqlite_result = execute_run(
        inspect_dataset(sqlite_path),
        policy,
        paths,
        secrets_store=secret_store,
        output_path=tmp_path / "out" / "sqlite.masked.sqlite",
    )

    assert _output_tokens(csv_result.output_path) == _output_tokens(sqlite_result.output_path)
    with PseudoMap(paths.pseudomap_db) as mapping:
        assert mapping.count() == len(VALUES)
        for token in _output_tokens(csv_result.output_path).values():
            assert mapping.reveal(token) in VALUES
        inserted_after_first_run = mapping.count()

    csv_rerun = execute_run(
        inspect_dataset(csv_path),
        policy,
        paths,
        secrets_store=secret_store,
        output_path=tmp_path / "out" / "csv.rerun.sqlite",
    )
    sqlite_rerun = execute_run(
        inspect_dataset(sqlite_path),
        policy,
        paths,
        secrets_store=secret_store,
        output_path=tmp_path / "out" / "sqlite.rerun.sqlite",
    )
    assert _output_tokens(csv_rerun.output_path) == _output_tokens(csv_result.output_path)
    assert _output_tokens(sqlite_rerun.output_path) == _output_tokens(sqlite_result.output_path)
    with PseudoMap(paths.pseudomap_db) as mapping:
        assert mapping.count() == inserted_after_first_run

    # Every historical output remains revealable from the same mapping store.
    with PseudoMap(paths.pseudomap_db) as mapping:
        for output in (
            csv_result.output_path,
            sqlite_result.output_path,
            csv_rerun.output_path,
            sqlite_rerun.output_path,
        ):
            for token in _output_tokens(output).values():
                assert mapping.reveal(token) in VALUES


def test_audit_records_traceable_mapping_operations(
    workspace, secret_store, tmp_path, make_policy
):
    csv_path, _sqlite_path = _write_datasets(tmp_path / "raw")
    policy = make_policy(_policy_text())
    paths = workspace
    inventory = inspect_dataset(csv_path)
    result = execute_run(
        inventory,
        policy,
        paths,
        secrets_store=secret_store,
        output_path=tmp_path / "out" / "csv.masked.sqlite",
    )
    finalize_run(paths, inventory, policy, result, findings=[])
    entries = read_audit_entries(paths.audit_path)
    assert len(entries) == 1
    mapping = entries[0]["mapping"]
    assert mapping["database"] == str(paths.pseudomap_db)
    assert mapping["run_id"] == result.run_id
    assert mapping["inserted"] == len(VALUES)
    assert mapping["reused"] == 0
    assert mapping["collisions"] == 0
    assert mapping["operation_count"] == len(VALUES)
    assert {operation["action"] for operation in mapping["operations"]} == {"insert"}
    assert {operation["token"] for operation in mapping["operations"]} == set(
        _output_tokens(result.output_path).values()
    )
    assert verify_audit(paths.audit_path).entries == 1


def test_concurrent_runs_share_mapping_without_conflicts(
    workspace, secret_store, tmp_path, make_policy
):
    csv_path, sqlite_path = _write_datasets(tmp_path / "raw")
    policy = make_policy(_policy_text())
    paths = workspace
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def run(dataset: Path, output_name: str) -> None:
        try:
            barrier.wait()
            inventory = inspect_dataset(dataset)
            result = execute_run(
                inventory,
                policy,
                paths,
                secrets_store=secret_store,
                output_path=tmp_path / "out" / output_name,
                batch_size=2,
            )
            finalize_run(paths, inventory, policy, result, findings=[])
        except BaseException as exc:  # pragma: no cover - assertion helper
            errors.append(exc)

    threads = [
        threading.Thread(target=run, args=(csv_path, "csv.masked.sqlite")),
        threading.Thread(target=run, args=(sqlite_path, "sqlite.masked.sqlite")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []

    with PseudoMap(paths.pseudomap_db) as mapping:
        assert mapping.count() == len(VALUES)
    assert _output_tokens(tmp_path / "out" / "csv.masked.sqlite") == _output_tokens(
        tmp_path / "out" / "sqlite.masked.sqlite"
    )
    assert AuditLog(paths.audit_path).verify().entries == 2
