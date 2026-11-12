from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from maskline.audit import AuditLog, read_audit_entries
from maskline.config import Paths
from maskline.dataset_io import DatasetError
from maskline.detectors.engine import analyze_values, detect_inventory
from maskline.gray import (
    GrayError,
    GraySnapshot,
    GrayTrialStore,
    purge_expired_trials,
    run_gray_trial,
)
from maskline.registry import Catalog, inspect_dataset
from maskline.resources import ResourceGovernor, ResourceLimitError, ResourceLimits
from maskline.rule_registry import RuleCatalog, RulePermissionError
from maskline.rules import (
    BUILTIN_VERSION,
    RuleError,
    builtin_rule_spec,
    compile_rule_set,
    load_rule_pack,
)
from maskline.workflow import scan_paths

EXAMPLE = Path(__file__).resolve().parents[1] / "policies" / "example.yaml"


def _write_pack(tmp_path: Path, text: str, filename: str = "rules.yaml"):
    path = tmp_path / filename
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return load_rule_pack(path)


def _create_version(paths: Paths, pack, actor: str = "alice"):
    with RuleCatalog(paths.rules_db, audit_path=paths.audit_path) as catalog:
        return catalog.create_version(pack, actor)


def _version_pack(tmp_path: Path, version: str, detectors: str, *, creator: str = "alice"):
    return _write_pack(
        tmp_path,
        f"""
        version: 1
        rule_version: {version}
        created_by: {creator}
        base: builtin-v1
        detectors:
{textwrap.indent(textwrap.dedent(detectors).strip() + chr(10), '          ')}
        """,
        filename=f"{version}.yaml",
    )


def _finding(findings, table, column):
    return next(
        item
        for item in findings
        if item["table_name"] == table and item["column_name"] == column
    )


def test_builtin_rule_snapshot_matches_existing_detectors(inventories):
    snapshot = compile_rule_set(builtin_rule_spec(), BUILTIN_VERSION)
    for inventory in inventories.values():
        legacy = detect_inventory(inventory)
        versioned = detect_inventory(inventory, rule_set=snapshot)
        assert versioned == legacy
        assert {item["rule_version"] for item in versioned} == {BUILTIN_VERSION}


def test_formal_scan_defaults_to_builtin_snapshot(workspace, inventories):
    direct = detect_inventory(inventories["sqlite"])
    summary = scan_paths([inventories["sqlite"].path], workspace)[0]
    assert summary.findings == direct
    assert {item["rule_version"] for item in summary.findings} == {BUILTIN_VERSION}


def test_rule_overlay_adds_and_adjusts_detectors(tmp_path):
    pack = _version_pack(
        tmp_path,
        "badge-v1",
        """
        ipv4:
          disabled: true
        mobile_phone:
          pattern: '(?<!\\d)1[3-9]\\d{9}(?!\\d)'
          validator: none
        person_name:
          surnames: "赵钱"
        address:
          min_length: 8
        badge:
          kind: regex
          pattern: '(?<!\\d)BADGE-\\d{6}(?!\\d)'
          value_pattern: 'BADGE-\\d{6}'
          require_fullmatch: true
        """,
    )
    paths = Paths.for_workspace(tmp_path / "workspace")
    created = _create_version(paths, pack)
    assert "ipv4" not in created.rule_set.detector_types()
    assert "badge" in created.rule_set.detector_types()
    badge = analyze_values(
        ["BADGE-123456", "BADGE-12345", "x"], rule_set=created.rule_set
    )
    assert badge.sensitive_type == "badge"
    assert badge.validate_rate == pytest.approx(1.0)
    names = analyze_values(["赵小明", "王小明"], rule_set=created.rule_set)
    assert names.sensitive_type == "person_name"
    assert names.candidates[0].matched_count == 1
    # Disabling a built-in detector only affects this version, not the base.
    base = compile_rule_set(builtin_rule_spec(), BUILTIN_VERSION)
    assert "ipv4" in base.detector_types()
    assert created.rule_set.fingerprint != base.fingerprint


def test_rollback_switches_formal_scan_and_restores_baseline(
    workspace, fixture_files, tmp_path
):
    baseline = scan_paths([fixture_files["sqlite"]], workspace)[0].findings
    assert _finding(baseline, "orders", "ip_address")["sensitive_type"] == "ipv4"

    pack = _version_pack(
        tmp_path,
        "no-ipv4",
        """
        ipv4:
          disabled: true
        """,
    )
    _create_version(workspace, pack, actor="alice")
    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        catalog.rollback("no-ipv4", "alice")

    changed = scan_paths([fixture_files["sqlite"]], workspace)[0].findings
    assert _finding(changed, "orders", "ip_address")["sensitive_type"] is None
    assert {item["rule_version"] for item in changed} == {"no-ipv4"}

    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        result = catalog.rollback(BUILTIN_VERSION, "alice")
    restored = scan_paths([fixture_files["sqlite"]], workspace)[0].findings
    assert _finding(restored, "orders", "ip_address")["sensitive_type"] == "ipv4"
    assert {item["rule_version"] for item in restored} == {BUILTIN_VERSION}
    assert result["previous_version"] == "no-ipv4"

    verification = AuditLog(workspace.audit_path).verify()
    events = [entry["event"] for entry in read_audit_entries(workspace.audit_path)]
    assert "rule_version_created" in events
    assert events.count("rule_rollback") == 2
    assert verification.entries == len(events)


def test_creator_only_can_adjust_scope_and_roll_back(workspace, fixture_files, tmp_path):
    pack = _version_pack(
        tmp_path,
        "owner-v1",
        """
        ipv4:
          disabled: true
        """,
    )
    record = _create_version(workspace, pack, actor="alice")
    assert record.created_by == "alice"

    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        with pytest.raises(RulePermissionError, match="creator"):
            catalog.rollback("owner-v1", "bob")
        with pytest.raises(RulePermissionError, match="creator"):
            catalog.set_gray_scope("owner-v1", ["demo.sqlite"], "bob")
        scope = catalog.set_gray_scope("owner-v1", ["demo.sqlite"], "alice")
    assert scope["datasets"] == ["demo.sqlite"]

    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        # A non-creator may inspect the version, but needs the scope to trial it.
        with pytest.raises(RulePermissionError):
            catalog.assert_can_trial("owner-v1", fixture_files["csv"], "bob")
        assert catalog.assert_can_trial("owner-v1", fixture_files["sqlite"], "bob")


def test_gray_trial_is_isolated_from_formal_findings_and_resources(
    workspace, fixture_files, tmp_path
):
    formal = scan_paths([fixture_files["sqlite"]], workspace)[0].findings
    formal_ipv4 = _finding(formal, "orders", "ip_address")
    assert formal_ipv4["sensitive_type"] == "ipv4"

    pack = _version_pack(
        tmp_path,
        "gray-v1",
        """
        ipv4:
          disabled: true
        """,
    )
    _create_version(workspace, pack, actor="alice")
    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        result = run_gray_trial(
            workspace,
            catalog,
            rule_version="gray-v1",
            dataset=fixture_files["sqlite"],
            actor="alice",
        )

    assert result.snapshot_path.exists()
    assert result.trial_id.startswith("gray-")
    assert not workspace.checkpoint_db.exists()
    assert not workspace.pseudomap_db.exists()
    assert not any(workspace.reports_dir.iterdir())
    assert not any(workspace.manifest_dir.iterdir())

    with Catalog(workspace.meta_db) as catalog:
        stored = catalog.findings_for(inspect_dataset(fixture_files["sqlite"]).fingerprint)

    def key_projection(records):
        return [
            {
                key: value
                for key, value in record.items()
                if key != "updated_at"
            }
            for record in sorted(
                records, key=lambda item: (item["table_name"], item["column_name"])
            )
        ]

    assert key_projection(stored) == key_projection(formal)
    assert {item["rule_version"] for item in stored} == {BUILTIN_VERSION}

    with GraySnapshot(result.snapshot_path) as snapshot:
        gray_findings = snapshot.findings()
    assert gray_findings
    assert {item["rule_version"] for item in gray_findings} == {"gray-v1"}
    assert _finding(gray_findings, "orders", "ip_address")["sensitive_type"] is None
    assert _finding(gray_findings, "customers", "phone")["sensitive_type"] == "mobile_phone"

    assert result.resource_limits["cpu_cores"] == 2
    assert result.resource_limits["memory_mb"] == 512
    created = datetime.fromisoformat(result.created_at)
    expires = datetime.fromisoformat(result.expires_at)
    assert expires - created == timedelta(days=7)

    events = [entry["event"] for entry in read_audit_entries(workspace.audit_path)]
    assert "gray_trial_started" in events
    assert "gray_trial_completed" in events
    assert "rule_version_created" in events
    AuditLog(workspace.audit_path).verify()


def test_missing_dataset_and_invalid_rule_leave_no_temp_resources(
    workspace, tmp_path
):
    before = set(workspace.gray_dir.iterdir()) if workspace.gray_dir.exists() else set()

    bad_rule = _write_pack(
        tmp_path,
        """
        version: 1
        rule_version: broken-regex
        created_by: alice
        base: builtin-v1
        detectors:
          broken:
            kind: regex
            pattern: "("
        """,
        filename="broken.yaml",
    )
    with pytest.raises(RuleError, match="not a valid regex"):
        _create_version(workspace, bad_rule, actor="alice")
    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        assert [record.version for record in catalog.list_versions()] == [BUILTIN_VERSION]

    good_rule = _version_pack(
        tmp_path,
        "trial-v1",
        """
        ipv4:
          disabled: true
        """,
    )
    _create_version(workspace, good_rule, actor="alice")
    missing = tmp_path / "missing.sqlite"
    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        with pytest.raises(DatasetError, match="not found"):
            run_gray_trial(
                workspace, catalog, rule_version="trial-v1", dataset=missing, actor="alice"
            )
    after = set(workspace.gray_dir.iterdir()) if workspace.gray_dir.exists() else set()
    assert after == before
    with GrayTrialStore(workspace.gray_db) as store:
        assert store.list() == []


def test_failed_trial_removes_snapshot_metadata_and_audits_failure(
    workspace, fixture_files, tmp_path, monkeypatch
):
    pack = _version_pack(
        tmp_path,
        "fail-v1",
        """
        ipv4:
          disabled: true
        """,
    )
    _create_version(workspace, pack, actor="alice")

    def explode(*_args, **_kwargs):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr("maskline.gray.detect_inventory", explode)
    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        with pytest.raises(GrayError, match="detector exploded"):
            run_gray_trial(
                workspace,
                catalog,
                rule_version="fail-v1",
                dataset=fixture_files["sqlite"],
                actor="alice",
            )

    assert list(workspace.gray_dir.iterdir()) == []
    with GrayTrialStore(workspace.gray_db) as store:
        assert store.list() == []
    entries = read_audit_entries(workspace.audit_path)
    failed = [entry for entry in entries if entry["event"] == "gray_trial_failed"]
    assert failed and failed[-1]["cleaned_up"] is True
    assert failed[-1]["error_type"] == "RuntimeError"
    AuditLog(workspace.audit_path).verify()


def test_expired_trial_is_cleaned_up(workspace, fixture_files, tmp_path):
    pack = _version_pack(
        tmp_path,
        "retain-v1",
        """
        ipv4:
          disabled: true
        """,
    )
    _create_version(workspace, pack, actor="alice")
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with RuleCatalog(workspace.rules_db, audit_path=workspace.audit_path) as catalog:
        result = run_gray_trial(
            workspace,
            catalog,
            rule_version="retain-v1",
            dataset=fixture_files["sqlite"],
            actor="alice",
            retention_days=0,
            now=start,
        )
    assert result.snapshot_path.exists()

    removed = purge_expired_trials(
        workspace,
        audit_path=workspace.audit_path,
        now=start + timedelta(seconds=2),
    )
    assert [record.trial_id for record in removed] == [result.trial_id]
    assert not result.snapshot_path.parent.exists()
    with GrayTrialStore(workspace.gray_db) as store:
        assert store.list() == []
    events = [entry["event"] for entry in read_audit_entries(workspace.audit_path)]
    assert "gray_trial_expired" in events
    AuditLog(workspace.audit_path).verify()


def test_resource_limits_validate_and_restore_process_limits(tmp_path):
    assert ResourceLimits().cpu_cores == 2
    assert ResourceLimits().memory_mb == 512
    with pytest.raises(ResourceLimitError):
        ResourceLimits(cpu_cores=0)
    with pytest.raises(ResourceLimitError):
        ResourceLimits(memory_mb=0)

    if not (hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity")):
        pytest.skip("CPU affinity is not supported on this platform")

    import resource

    before_affinity = set(os.sched_getaffinity(0))
    before_limit = resource.getrlimit(resource.RLIMIT_AS)
    with ResourceGovernor(ResourceLimits(cpu_cores=1, memory_mb=256)) as applied:
        assert applied["cpu_enforced"] is True
        assert applied["effective_cpu_cores"] == min(1, len(before_affinity))
        assert os.sched_getaffinity(0) == set(sorted(before_affinity)[:1])
        assert applied["memory_enforced"] is True
        assert applied["effective_memory_bytes"] <= 256 * 1024 * 1024
        assert resource.getrlimit(resource.RLIMIT_AS)[0] <= 256 * 1024 * 1024
    assert os.sched_getaffinity(0) == before_affinity
    assert resource.getrlimit(resource.RLIMIT_AS) == before_limit


@pytest.mark.skipif(os.name != "posix", reason="RLIMIT_AS is POSIX-only")
def test_memory_limit_blocks_large_allocation(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    code = textwrap.dedent(
        """
        from maskline.resources import ResourceGovernor, ResourceLimits

        try:
            with ResourceGovernor(ResourceLimits(memory_mb=64)):
                payload = bytearray(128 * 1024 * 1024)
        except MemoryError:
            raise SystemExit(0)
        raise SystemExit(1)
        """
    )
    env = dict(os.environ, PYTHONPATH=str(repo))
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(repo),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
