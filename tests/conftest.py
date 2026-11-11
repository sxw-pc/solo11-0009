from __future__ import annotations

import textwrap

import pytest

from maskline.config import Paths, create_demo_secret
from maskline.fixturegen import generate_fixture
from maskline.policies import load_policy
from maskline.registry import inspect_dataset


@pytest.fixture
def audit_append():
    """Append an audit entry carrying every field the new reports rely on."""
    from maskline.audit import AuditLog

    def _append(paths, result):
        entry = {
            "run_id": result.run_id,
            "dataset_fingerprint": result.dataset_fingerprint,
            "rows_processed": result.row_count,
            "output_hash": result.output_hash,
            "transform_counts": result.transform_counts,
            "output_path": str(result.output_path),
            "policy_name": result.policy_name,
            "policy_fingerprint": result.policy_fingerprint,
            "dataset_path": str(result.dataset_path),
            "elapsed_seconds": round(result.elapsed_seconds, 6),
            "columns": result.transformer_map,
            "skipped_rows": result.skipped_rows,
            "pseudomap_entries": result.pseudomap_entries,
            "resumed": result.resumed,
            "events": result.events,
        }
        return AuditLog(paths.audit_path).append(entry)

    return _append

@pytest.fixture
def workspace(tmp_path):
    paths = Paths.for_workspace(tmp_path / "workspace")
    paths.ensure_runtime_dirs()
    return paths

@pytest.fixture
def secret_store(tmp_path, monkeypatch):
    path = tmp_path / "test-secret.txt"
    store = create_demo_secret(path)
    monkeypatch.setenv("MASKLINE_SECRET_FILE", str(path))
    return store

@pytest.fixture
def fixture_files(tmp_path):
    return generate_fixture(
        tmp_path / "raw", seed=7, customers=6, orders=9, leads=3
    )

@pytest.fixture
def inventories(fixture_files):
    return {
        "sqlite": inspect_dataset(fixture_files["sqlite"]),
        "csv": inspect_dataset(fixture_files["csv"]),
    }

@pytest.fixture
def make_policy(tmp_path):
    counter = {"value": 0}
    def factory(text: str):
        counter["value"] += 1
        path = tmp_path / f"policy-{counter['value']}.yaml"
        path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
        return load_policy(path)
    return factory
