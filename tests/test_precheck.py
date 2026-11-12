import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from maskline.__main__ import main
from maskline.config import Paths
from maskline.precheck import (
    EXIT_DATASET,
    EXIT_POLICY,
    EXIT_SECRET,
    EXIT_TARGET,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _snapshot(*roots: Path) -> dict:
    """Content-addressed view of every file and directory under each root."""
    snap = {}
    for root in roots:
        if not root.exists():
            snap[str(root)] = "<absent>"
            continue
        for item in sorted(root.rglob("*")):
            key = str(item)
            snap[key] = (
                "<dir>" if item.is_dir()
                else hashlib.sha256(item.read_bytes()).hexdigest()
            )
    return snap


def _precheck(paths, dataset, policy=EXAMPLE, *extra):
    return main([
        "precheck",
        "--dataset", str(dataset),
        "--policy", str(policy),
        "--workspace", str(paths.root),
        *extra,
    ])


@pytest.fixture
def approved(tmp_path, fixture_files, secret_store):
    """Workspace with the dataset scanned and the example policy registered."""
    paths = Paths.for_workspace(tmp_path / "ws")
    assert main(["scan", str(fixture_files["sqlite"]), "--workspace", str(paths.root)]) == 0
    assert main(["register", "--policy", str(EXAMPLE), "--workspace", str(paths.root)]) == 0
    return paths


def test_precheck_pass_returns_zero(approved, fixture_files, capsys):
    code = _precheck(approved, fixture_files["sqlite"])
    out = capsys.readouterr().out
    assert code == 0
    assert "result: PASS" in out
    assert "[FAIL]" not in out and "[WARN]" not in out


def test_precheck_missing_secret_exit_code(approved, fixture_files, monkeypatch, capsys):
    monkeypatch.delenv("MASKLINE_SECRET_FILE")
    code = _precheck(approved, fixture_files["sqlite"])
    out = capsys.readouterr().out
    assert code == EXIT_SECRET
    assert "secret.file" in out
    assert "MASKLINE_SECRET_FILE" in out


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_precheck_world_readable_secret_blocked(approved, fixture_files, capsys):
    secret = Path(os.environ["MASKLINE_SECRET_FILE"])
    secret.chmod(0o644)
    code = _precheck(approved, fixture_files["sqlite"])
    out = capsys.readouterr().out
    assert code == EXIT_SECRET
    assert "secret.permissions" in out
    secret.chmod(0o600)


def test_precheck_unknown_column_exit_code(approved, fixture_files, make_policy, capsys):
    bad = make_policy(
        """
        version: 1
        name: typo-policy
        datasets:
          - path: demo.sqlite
            tables:
              customers:
                columns:
                  ful_name: {transformer: pseudonym}
        """
    )
    # Register it so only the schema check fails, not the registration check.
    assert main([
        "register", "--policy", str(bad.source_path),
        "--workspace", str(approved.root),
    ]) == 0
    code = _precheck(approved, fixture_files["sqlite"], bad.source_path)
    out = capsys.readouterr().out
    assert code == EXIT_POLICY
    assert "unknown column" in out


def test_precheck_insufficient_disk_exit_code(approved, fixture_files, capsys):
    code = _precheck(approved, fixture_files["sqlite"], EXAMPLE,
                     "--space-multiplier", "1e12")
    out = capsys.readouterr().out
    assert code == EXIT_TARGET
    assert "insufficient disk space" in out


def test_precheck_fingerprint_drift_exit_code(approved, fixture_files, capsys):
    conn = sqlite3.connect(fixture_files["sqlite"])
    try:
        conn.execute("UPDATE customers SET notes = 'tampered' WHERE rowid = 1")
        conn.commit()
    finally:
        conn.close()
    code = _precheck(approved, fixture_files["sqlite"])
    out = capsys.readouterr().out
    assert code == EXIT_DATASET
    assert "drifted" in out


def test_failure_exit_codes_are_distinct():
    assert len({EXIT_SECRET, EXIT_POLICY, EXIT_DATASET, EXIT_TARGET}) == 4


def test_precheck_writes_nothing_anywhere(approved, fixture_files, monkeypatch):
    watched = (approved.data_dir, approved.root / "audit")
    before = _snapshot(*watched)
    assert _precheck(approved, fixture_files["sqlite"]) == 0
    assert _precheck(approved, fixture_files["sqlite"],
                     EXAMPLE, "--space-multiplier", "1e12") == EXIT_TARGET
    monkeypatch.delenv("MASKLINE_SECRET_FILE")
    assert _precheck(approved, fixture_files["sqlite"]) == EXIT_SECRET
    assert _snapshot(*watched) == before


def test_precheck_creates_no_directories(tmp_path, fixture_files, secret_store):
    fresh = tmp_path / "fresh-workspace"
    code = main([
        "precheck",
        "--dataset", str(fixture_files["sqlite"]),
        "--policy", str(EXAMPLE),
        "--workspace", str(fresh),
    ])
    assert code != 0  # nothing is registered yet
    assert not fresh.exists()


def test_precheck_unregistered_policy_blocked(tmp_path, fixture_files, secret_store, capsys):
    paths = Paths.for_workspace(tmp_path / "ws")
    assert main(["scan", str(fixture_files["sqlite"]), "--workspace", str(paths.root)]) == 0
    code = _precheck(paths, fixture_files["sqlite"])
    out = capsys.readouterr().out
    assert code == EXIT_POLICY
    assert "not registered" in out


def test_precheck_unregistered_dataset_warns_only(tmp_path, fixture_files, secret_store, capsys):
    paths = Paths.for_workspace(tmp_path / "ws")
    assert main(["register", "--policy", str(EXAMPLE), "--workspace", str(paths.root)]) == 0
    code = _precheck(paths, fixture_files["sqlite"])
    out = capsys.readouterr().out
    assert code == 0
    assert "PASS WITH WARNINGS" in out
    assert "dataset.fingerprint" in out


def test_detector_version_mismatch_warns_only(approved, fixture_files, monkeypatch, capsys):
    monkeypatch.setattr("maskline.precheck.detector_version", lambda: "0" * 16)
    code = _precheck(approved, fixture_files["sqlite"])
    out = capsys.readouterr().out
    assert code == 0
    assert "detector.version" in out
    assert "PASS WITH WARNINGS" in out


def test_precheck_output_over_source_blocked(approved, fixture_files, capsys):
    code = _precheck(approved, fixture_files["sqlite"], EXAMPLE,
                     "--output", str(fixture_files["sqlite"]))
    out = capsys.readouterr().out
    assert code == EXIT_TARGET
    assert "source dataset" in out


def test_precheck_json_output(approved, fixture_files, capsys):
    code = _precheck(approved, fixture_files["sqlite"], EXAMPLE, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == code == 0
    assert payload["status"] == "pass"
    ids = {check["id"] for check in payload["checks"]}
    assert {
        "policy.load", "policy.schema", "policy.registered",
        "secret.file", "secret.permissions",
        "dataset.readable", "dataset.fingerprint", "detector.version",
        "registry.readable", "target.writable", "target.disk_space",
    } <= ids
    assert all(check["outcome"] in {"pass", "fail", "skip"} for check in payload["checks"])


def test_precheck_json_reports_blockers(approved, fixture_files, monkeypatch, capsys):
    monkeypatch.delenv("MASKLINE_SECRET_FILE")
    code = _precheck(approved, fixture_files["sqlite"], EXAMPLE, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_SECRET
    assert payload["status"] == "blocked"
    secret_check = next(c for c in payload["checks"] if c["id"] == "secret.file")
    assert secret_check["outcome"] == "fail"
    assert secret_check["level"] == "blocker"


def test_register_is_idempotent(tmp_path, capsys):
    paths = Paths.for_workspace(tmp_path / "ws")
    assert main(["register", "--policy", str(EXAMPLE), "--workspace", str(paths.root)]) == 0
    assert "already registered" not in capsys.readouterr().out
    assert main(["register", "--policy", str(EXAMPLE), "--workspace", str(paths.root)]) == 0
    assert "already registered" in capsys.readouterr().out


def test_scan_records_detector_version(approved, fixture_files):
    from maskline.detectors.engine import detector_version
    from maskline.registry import Catalog, inspect_dataset

    inventory = inspect_dataset(fixture_files["sqlite"])
    with Catalog(approved.meta_db) as catalog:
        records = catalog.datasets_for_path(str(inventory.path))
    assert records[-1]["detector_version"] == detector_version()
