from __future__ import annotations

import csv
import sqlite3

import pytest

from maskline.audit import AuditLog
from maskline.classification.policy_export import build_policy_dict
from maskline.classification.service import (
    ClassificationService,
    ClassificationServiceError,
)
from maskline.classification.store import ClassificationStore, ClassificationStoreError
from maskline.config import Paths
from maskline.registry import Catalog


def _service(workspace: Paths, audit: bool = True) -> ClassificationService:
    store = ClassificationStore(workspace.classification_db)
    catalog = Catalog(workspace.meta_db)
    log = AuditLog(workspace.audit_path) if audit else None
    return ClassificationService(store, catalog, audit=log)


def _write_csv(path, header, rows):
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        if header is not None:
            writer.writerow(header)
        writer.writerows(rows)


def test_end_to_end_classification_with_builtin_standards(workspace, tmp_path):
    data = tmp_path / "people.csv"
    _write_csv(
        data,
        ["full_name", "phone", "email", "id_card", "notes"],
        [
            ["王安宁", "13800138000", "a@example.invalid", "999999197001010017", "x"],
            ["李溪晨", "13900139000", "b@example.invalid", "999999198512311238", "y"],
        ],
    )
    service = _service(workspace)
    service.ensure_builtin_packs()
    outcome = service.classify_dataset(data)
    assert len(outcome["results"]) == 5
    by_column = {r.column_name: r for r in outcome["results"]}
    id_card = by_column["id_card"]
    pipl = next(s for s in id_card.standards if s.standard_code == "pipl")
    assert pipl.level == "L4"
    assert pipl.special_category is True
    assert pipl.rule_pack_version_id >= 1
    # Every result carries all three standards.
    for result in outcome["results"]:
        assert {s.standard_code for s in result.standards} == {"pipl", "gbt35273", "gdpr"}
    stored = service.get_results(outcome["inventory"].fingerprint)
    assert len(stored) == 5
    service.store.close()
    service.catalog.close()


def test_headerless_csv_is_degraded_but_not_aborted(workspace, tmp_path):
    data = tmp_path / "no_header.csv"
    _write_csv(
        data,
        None,
        [
            ["王安宁", "13800138000", "999999197001010017"],
            ["李溪晨", "13900139000", "999999198512311238"],
        ],
    )
    service = _service(workspace)
    service.ensure_builtin_packs()
    outcome = service.classify_dataset(data)
    assert outcome["headerless"] is True
    alert_codes = {alert.code for alert in outcome["alerts"]}
    assert "headerless_file" in alert_codes
    columns = {r.column_name for r in outcome["results"]}
    assert columns == {"col_001", "col_002", "col_003"}
    # Content-only detection still classifies the ID column via sensitive_type.
    id_col = next(r for r in outcome["results"] if r.column_name == "col_003")
    pipl = next(s for s in id_col.standards if s.standard_code == "pipl")
    assert pipl.level == "L4" and pipl.match_basis == "sensitive_type"
    # Name-only rules must not fire when no header exists.
    name_col = next(r for r in outcome["results"] if r.column_name == "col_001")
    assert all(s.match_basis != "name" for s in name_col.standards)
    service.store.close()
    service.catalog.close()


def test_deeply_nested_column_emits_alert_and_uses_leaf_token(workspace, tmp_path):
    db = tmp_path / "nested.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE t (id INTEGER, "
        "\"payload.user.contact.mobile_number\" TEXT, plain_mobile TEXT)"
    )
    conn.executemany(
        "INSERT INTO t VALUES (?, ?, ?)",
        [(1, "13800138000", "13900139000"), (2, "13700137000", "13600136000")],
    )
    conn.commit()
    conn.close()
    service = _service(workspace)
    service.ensure_builtin_packs()
    outcome = service.classify_dataset(db, )
    alert_codes = {alert.code for alert in outcome["alerts"]}
    assert "nested_depth" in alert_codes
    deep = next(
        r for r in outcome["results"]
        if r.column_name == "payload.user.contact.mobile_number"
    )
    assert deep.degraded is True
    assert deep.semantic_key == "mobile_phone"
    service.store.close()
    service.catalog.close()


def test_batch_job_pins_one_rule_snapshot_without_version_conflict(workspace, tmp_path):
    first = tmp_path / "a.csv"
    second = tmp_path / "b.csv"
    _write_csv(first, ["phone"], [["13800138000"], ["13900139000"]])
    _write_csv(second, ["email"], [["a@example.invalid"], ["b@example.invalid"]])
    service = _service(workspace)
    service.ensure_builtin_packs()
    outcomes = service.classify_many([first, second])
    assert len(outcomes) == 2
    snapshots = [tuple(outcome["pack_version_ids"]) for outcome in outcomes]
    assert snapshots[0] == snapshots[1]
    # A failing dataset does not abort the batch.
    missing = tmp_path / "missing.csv"
    outcomes = service.classify_many([missing, first])
    assert outcomes[0].get("error")
    assert outcomes[0]["alerts"][0].code == "dataset_failed"
    assert outcomes[1].get("job_id")
    service.store.close()
    service.catalog.close()


def test_rule_pack_versions_are_append_only(workspace):
    service = _service(workspace)
    service.ensure_builtin_packs()
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        service.store.conn.execute(
            "UPDATE rule_pack_versions SET revision = 99 WHERE version_id = 1"
        )
    with pytest.raises(sqlite3.IntegrityError):
        service.store.conn.execute("DELETE FROM rule_pack_versions WHERE version_id = 1")
    service.store.close()
    service.catalog.close()


def test_manual_correction_is_immutable_and_audited(workspace, tmp_path):
    data = tmp_path / "people.csv"
    _write_csv(data, ["phone"], [["13800138000"], ["13900139000"]])
    service = _service(workspace)
    service.ensure_builtin_packs()
    outcome = service.classify_dataset(data)
    fp = outcome["inventory"].fingerprint
    result = service.correct_field(
        dataset_fingerprint=fp,
        table=outcome["inventory"].tables[0].name,
        column="phone",
        standard_code="pipl",
        level="L4",
        category="人工上调-敏感联系方式",
        controls=["encryption-at-rest", "separate-consent"],
        reason="业务评审确认该字段承载实名联系方式",
        operator="reviewer-a",
    )
    assert result["corrected"]["level"] == "L4"
    assert result["corrected"]["match_basis"] == "manual"
    stored = service.get_results(fp)[0]
    pipl = next(s for s in stored["standards"] if s["standard_code"] == "pipl")
    assert pipl["level"] == "L4" and stored["source"] == "manual"
    chain = service.verify_corrections()
    assert chain["corrections"] == 1
    corrections = service.store.list_corrections()
    assert corrections[0]["operator"] == "reviewer-a"
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        service.store.conn.execute(
            "UPDATE classification_corrections SET reason = 'tampered' WHERE correction_id = 1"
        )
    with pytest.raises(sqlite3.IntegrityError):
        service.store.conn.execute("DELETE FROM classification_corrections")
    # A forged row that does not continue the hash chain is detected.
    service.store.conn.execute(
        "INSERT INTO classification_corrections (correction_id, dataset_fingerprint, "
        "table_name, column_name, standard_code, previous_json, corrected_json, reason, "
        "operator, prev_hash, entry_hash, created_at) VALUES "
        "(999, ?, 'people', 'phone', 'pipl', '{}', '{}', 'forged', 'attacker', "
        "'0', '0', '2026-01-01T00:00:00+00:00')",
        (fp,),
    )
    with pytest.raises(ClassificationStoreError, match="chain broken"):
        service.verify_corrections()
    # The audit log received both the job and the correction.
    from maskline.audit import read_audit_entries

    events = [entry.get("event") for entry in read_audit_entries(workspace.audit_path)]
    assert "classification_correction" in events
    assert "classification_job" in events
    service.store.close()
    service.catalog.close()


def test_correction_rejects_level_unknown_to_the_standard(workspace, tmp_path):
    data = tmp_path / "people.csv"
    _write_csv(data, ["phone"], [["13800138000"], ["13900139000"]])
    service = _service(workspace, audit=False)
    service.ensure_builtin_packs()
    outcome = service.classify_dataset(data)
    fp = outcome["inventory"].fingerprint
    table = outcome["inventory"].tables[0].name
    with pytest.raises(ClassificationServiceError, match="level_order"):
        service.correct_field(
            dataset_fingerprint=fp,
            table=table,
            column="phone",
            standard_code="pipl",
            level="L9",
            category=None,
            controls=None,
            reason="bad level",
            operator="reviewer-a",
        )
    service.store.close()
    service.catalog.close()


def test_fingerprint_change_triggers_reclassification(workspace, tmp_path):
    data = tmp_path / "people.csv"
    _write_csv(data, ["phone"], [["13800138000"], ["13900139000"]])
    service = _service(workspace)
    service.ensure_builtin_packs()
    first = service.classify_dataset(data)
    first_fp = first["inventory"].fingerprint
    # Same content -> no re-run.
    report = service.reclassify_changed()
    assert report["unchanged"] and not report["reclassified"]
    # Content change -> new fingerprint -> automatic reclassification.
    _write_csv(data, ["phone"], [["13700137000"], ["13600136000"], ["13500135000"]])
    report = service.reclassify_changed()
    assert len(report["reclassified"]) == 1
    entry = report["reclassified"][0]
    assert entry["previous_fingerprint"] == first_fp
    assert entry["current_fingerprint"] != first_fp
    service.store.close()
    service.catalog.close()


def test_policy_export_produces_runnable_v1_policy(workspace, tmp_path):
    data = tmp_path / "people.csv"
    _write_csv(
        data,
        ["full_name", "id_card", "phone", "status"],
        [
            ["王安宁", "999999197001010017", "13800138000", "active"],
            ["李溪晨", "999999198512311238", "13900139000", "pending"],
        ],
    )
    service = _service(workspace, audit=False)
    service.ensure_builtin_packs()
    outcome = service.classify_dataset(data)
    records = service.get_results(outcome["inventory"].fingerprint)
    policy, notices = build_policy_dict(
        "derived", "people.csv", records, description="export test"
    )
    assert policy["version"] == 1
    table = next(iter(policy["datasets"][0]["tables"].values()))
    columns = table["columns"]
    assert columns["id_card"]["transformer"] == "pseudonym"
    assert "status" not in columns
    assert any(notice["column"] == "status" for notice in notices)
    # The exported document must pass the existing strict policy loader.
    from maskline.policies import load_policy

    policy_path = tmp_path / "derived.yaml"
    import yaml

    policy_path.write_text(
        yaml.safe_dump(policy, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    loaded = load_policy(policy_path)
    assert loaded.fingerprint
    service.store.close()
    service.catalog.close()


def test_custom_pack_is_versioned_and_used_by_jobs(workspace, tmp_path):
    custom = tmp_path / "custom.yaml"
    custom.write_text(
        """
version: 1
pack_id: pipl-custom
revision: 2
standard: {code: pipl, name: PIPL extended, version: "2021", description: ""}
level_order: [L1, L2, L3, L4]
level_names: {L1: org, L2: general, L3: elevated, L4: sensitive}
defaults: {fallback_level: L2, fallback_category: fallback, fallback_controls: [c1]}
controls_catalog: {c1: base, c2: extra}
aliases:
  - {canonical: mobile_phone, names: [hotline_no]}
rules:
  - id: custom-salary
    priority: 60
    match: {sensitive_types: [], name_patterns: ["*salary*"]}
    labels: {level: L4, category: 敏感个人信息-财产, controls: [c1, c2]}
    special_category: true
""",
        encoding="utf-8",
    )
    service = _service(workspace)
    service.ensure_builtin_packs()
    info = service.publish_custom_pack(custom)
    assert info["created"] is True
    # Re-publishing the same content is idempotent.
    again = service.publish_custom_pack(custom)
    assert again["created"] is False and again["version_id"] == info["version_id"]
    data = tmp_path / "payroll.csv"
    _write_csv(data, ["name", "salary"], [["王安宁", "10000"], ["李溪晨", "20000"]])
    outcome = service.classify_dataset(data)
    salary = next(r for r in outcome["results"] if r.column_name == "salary")
    pipl = next(s for s in salary.standards if s.standard_code == "pipl")
    assert pipl.matched_rule_id == "custom-salary"
    assert pipl.level == "L4" and pipl.special_category is True
    # The custom pipl snapshot must carry a new version id distinct from builtin.
    versions = service.store.active_versions()
    pipl_versions = [row for row in versions if row["standard_code"] == "pipl"]
    assert len(pipl_versions) == 1 and pipl_versions[0]["version_id"] == info["version_id"]
    service.store.close()
    service.catalog.close()
