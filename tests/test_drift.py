"""Cross-version drift detection: accuracy, noise tolerance, audit, upgrade."""

from __future__ import annotations

import json
import sqlite3
import textwrap
import time

import pytest

from maskline.audit import AuditIntegrityError, read_audit_entries, verify_audit
from maskline.drift import (
    DriftRulesError,
    compare_findings,
    load_ignore_rules,
)
from maskline.pipeline.runner import execute_run
from maskline.registry import Catalog
from maskline.workflow import finalize_run, scan_paths


# ---------------------------------------------------------------------------
# helpers


def _phones(count: int, start: int = 0) -> list[str]:
    return [f"138{(start + index):08d}" for index in range(count)]


def _emails(count: int, start: int = 0) -> list[str]:
    return [f"user{start + index}@example.com" for index in range(count)]


def _plain(count: int, start: int = 0) -> list[str]:
    return [f"row-{start + index:04d}" for index in range(count)]


def _write_sqlite(path, table: str, columns: list[tuple[str, list[str]]]) -> None:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        defs = ", ".join(f'"{name}" TEXT' for name, _values in columns)
        conn.execute(f'CREATE TABLE "{table}" ({defs})')
        placeholders = ", ".join("?" for _ in columns)
        rows = list(zip(*(values for _name, values in columns)))
        conn.executemany(f'INSERT INTO "{table}" VALUES ({placeholders})', rows)
        conn.commit()
    finally:
        conn.close()


def _drift_entries(paths) -> list[dict]:
    if not paths.audit_path.exists():
        return []
    return [
        entry
        for entry in read_audit_entries(paths.audit_path)
        if entry.get("kind") == "dataset_drift"
    ]


def _finding(
    table: str,
    column: str,
    sensitive_type: str | None,
    confidence: str,
    hit_rate: float,
    validate_rate: float = 1.0,
) -> dict:
    candidates = []
    if sensitive_type is not None:
        candidates.append(
            {
                "sensitive_type": sensitive_type,
                "score": round(hit_rate * validate_rate, 4),
                "hit_rate": round(hit_rate, 4),
                "validate_rate": round(validate_rate, 4),
            }
        )
    return {
        "dataset_fingerprint": "fp",
        "table_name": table,
        "column_name": column,
        "sensitive_type": sensitive_type,
        "confidence": confidence,
        "score": hit_rate * validate_rate,
        "hit_rate": hit_rate,
        "validate_rate": validate_rate,
        "sample_size": 100,
        "candidates": candidates,
    }


# ---------------------------------------------------------------------------
# scenario 1: fields added / removed


def test_field_added_and_removed_are_detected(workspace, tmp_path):
    dataset = tmp_path / "ds.sqlite"
    _write_sqlite(
        dataset,
        "users",
        [
            ("user_id", _plain(50)),
            ("email", _emails(50)),
            ("notes", _plain(50, start=1000)),
        ],
    )
    first = scan_paths([dataset], workspace)
    assert first[0].drift is None  # first registration: no baseline
    v1_fingerprint = first[0].inventory.fingerprint

    _write_sqlite(
        dataset,
        "users",
        [
            ("user_id", _plain(50)),
            ("email", _emails(50)),
            ("mobile", _phones(50)),  # new sensitive column; notes dropped
        ],
    )
    second = scan_paths([dataset], workspace)
    drift = second[0].drift
    assert drift is not None
    assert drift.baseline_fingerprint == v1_fingerprint
    assert drift.current_fingerprint == second[0].inventory.fingerprint

    kinds = {(event.drift_type, event.column) for event in drift.events}
    assert kinds == {("field_added", "mobile"), ("field_removed", "notes")}

    added = next(e for e in drift.events if e.drift_type == "field_added")
    assert added.table == "users"
    assert added.severity == "high"
    assert added.old is None
    assert added.new["sensitive_type"] == "mobile_phone"
    assert added.new["confidence"] == "high"

    removed = next(e for e in drift.events if e.drift_type == "field_removed")
    assert removed.old["sensitive_type"] is None
    assert removed.new is None

    summary = drift.summary()
    assert summary["field_added"] == 1
    assert summary["field_removed"] == 1
    assert summary["active"] == 2

    # historical findings of v1 are still queryable and untouched
    with Catalog(workspace.meta_db) as catalog:
        old_findings = catalog.findings_for(v1_fingerprint)
    assert {item["column_name"] for item in old_findings} == {
        "user_id",
        "email",
        "notes",
    }
    # the drift report is also indexed in the registry database
    with Catalog(workspace.meta_db) as catalog:
        stored = catalog.drift_reports_for(dataset)
    assert len(stored) == 1
    assert stored[0]["record"]["summary"]["active"] == 2
    assert stored[0]["audit_seq"] == drift.audit_seq


# ---------------------------------------------------------------------------
# scenario 2: sensitive type changes


def test_sensitive_type_changes_are_detected(workspace, tmp_path):
    dataset = tmp_path / "ds.sqlite"
    _write_sqlite(
        dataset,
        "contacts",
        [
            ("contact", _emails(60)),      # becomes phone numbers
            ("note", _plain(60)),          # becomes emails (newly sensitive)
            ("extra", _emails(60, 100)),   # becomes plain text (desensitized)
        ],
    )
    scan_paths([dataset], workspace)
    _write_sqlite(
        dataset,
        "contacts",
        [
            ("contact", _phones(60)),
            ("note", _emails(60, 200)),
            ("extra", _plain(60, 300)),
        ],
    )
    drift = scan_paths([dataset], workspace)[0].drift
    assert drift is not None
    by_column = {event.column: event for event in drift.events}
    assert set(by_column) == {"contact", "note", "extra"}
    assert all(e.drift_type == "type_changed" for e in drift.events)

    assert by_column["contact"].old["sensitive_type"] == "email"
    assert by_column["contact"].new["sensitive_type"] == "mobile_phone"
    assert by_column["contact"].severity == "high"

    assert by_column["note"].old["sensitive_type"] is None
    assert by_column["note"].new["sensitive_type"] == "email"
    assert by_column["note"].severity == "high"

    assert by_column["extra"].old["sensitive_type"] == "email"
    assert by_column["extra"].new["sensitive_type"] is None
    assert by_column["extra"].severity == "medium"


# ---------------------------------------------------------------------------
# scenario 3: confidence level adjustments


def test_confidence_level_adjustments_are_detected(workspace, tmp_path):
    dataset = tmp_path / "ds.sqlite"
    _write_sqlite(
        dataset,
        "metrics",
        [
            ("col_a", _phones(60) + _plain(40)),   # 0.60 medium -> 0.95 high
            ("col_b", _phones(95) + _plain(5)),    # 0.95 high -> 0.60 medium
        ],
    )
    scan_paths([dataset], workspace)
    _write_sqlite(
        dataset,
        "metrics",
        [
            ("col_a", _phones(95) + _plain(5)),
            ("col_b", _phones(60) + _plain(40)),
        ],
    )
    drift = scan_paths([dataset], workspace)[0].drift
    assert drift is not None
    by_column = {event.column: event for event in drift.events}
    assert set(by_column) == {"col_a", "col_b"}
    assert all(e.drift_type == "level_changed" for e in drift.events)

    assert by_column["col_a"].old["confidence"] == "medium"
    assert by_column["col_a"].new["confidence"] == "high"
    assert by_column["col_a"].new["sensitive_type"] == "mobile_phone"
    assert by_column["col_a"].severity == "high"  # escalation to high

    assert by_column["col_b"].old["confidence"] == "high"
    assert by_column["col_b"].new["confidence"] == "medium"
    assert by_column["col_b"].severity == "low"  # de-escalation


# ---------------------------------------------------------------------------
# scenario 4: sampling fluctuation within 5% must not alert


def test_sampling_fluctuation_within_tolerance_produces_no_events(
    workspace, tmp_path
):
    dataset = tmp_path / "ds.sqlite"
    _write_sqlite(
        dataset,
        "samples",
        [
            # 0.81 high -> 0.79 medium: level flip driven by 2% hit movement
            ("jitter_level", _phones(81) + _plain(19)),
            # 0.21 low (email) -> 0.19 none: type flip driven by 2% hit movement
            ("jitter_type", _emails(21) + _plain(79)),
            ("stable", _plain(100, start=500)),
        ],
    )
    scan_paths([dataset], workspace)
    _write_sqlite(
        dataset,
        "samples",
        [
            ("jitter_level", _phones(79) + _plain(21)),
            ("jitter_type", _emails(19) + _plain(81)),
            ("stable", _plain(100, start=500)),
        ],
    )
    drift = scan_paths([dataset], workspace)[0].drift
    assert drift is not None
    assert drift.events == []
    assert drift.suppressed == []
    assert drift.summary()["active"] == 0
    # the comparison itself is still attested in the audit chain
    entries = _drift_entries(workspace)
    assert len(entries) == 1
    assert entries[0]["events"] == []
    assert entries[0]["summary"]["active"] == 0


def test_tolerance_boundary_is_exactly_five_percent():
    base = [_finding("t", "c", "mobile_phone", "high", 0.80)]
    within = [_finding("t", "c", "mobile_phone", "medium", 0.75)]
    beyond = [_finding("t", "c", "mobile_phone", "medium", 0.74)]
    kwargs = dict(
        dataset_path="ds.sqlite",
        baseline_fingerprint="a",
        current_fingerprint="b",
    )
    assert compare_findings(base, within, **kwargs).events == []
    events = compare_findings(base, beyond, **kwargs).events
    assert [event.drift_type for event in events] == ["level_changed"]


# ---------------------------------------------------------------------------
# audit chain: drift records are append-only and tamper-evident


def test_drift_record_is_chained_and_tampering_is_detected(workspace, tmp_path):
    dataset = tmp_path / "ds.sqlite"
    _write_sqlite(dataset, "users", [("email", _emails(40))])
    v1 = scan_paths([dataset], workspace)[0].inventory.fingerprint
    _write_sqlite(dataset, "users", [("email", _emails(40)), ("mobile", _phones(40))])
    drift = scan_paths([dataset], workspace)[0].drift

    entries = _drift_entries(workspace)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["baseline_fingerprint"] == v1
    assert entry["current_fingerprint"] == drift.current_fingerprint
    assert entry["summary"]["active"] == 1
    assert entry["events"][0]["column"] == "mobile"
    assert drift.audit_seq == entry["seq"]
    assert drift.audit_entry_hash == entry["entry_hash"]
    verification = verify_audit(workspace.audit_path)
    assert verification.entries == 1

    # tampering with the drift record breaks the chain verification
    lines = workspace.audit_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["events"][0]["column"] = "tampered"
    payload["summary"]["active"] = 0
    lines[0] = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    workspace.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        verify_audit(workspace.audit_path)


def test_unchanged_dataset_triggers_no_drift_and_no_audit(workspace, tmp_path):
    dataset = tmp_path / "ds.sqlite"
    _write_sqlite(dataset, "users", [("email", _emails(30))])
    first = scan_paths([dataset], workspace)
    second = scan_paths([dataset], workspace)
    assert first[0].drift is None
    assert second[0].newly_registered is False
    assert second[0].drift is None
    assert not workspace.audit_path.exists()


# ---------------------------------------------------------------------------
# report: drift section matches the audit chain record exactly


def test_report_drift_section_matches_audit_record(workspace, tmp_path, make_policy):
    dataset = tmp_path / "ds.sqlite"
    _write_sqlite(dataset, "users", [("user_id", _plain(40)), ("email", _emails(40))])
    scan_paths([dataset], workspace)
    _write_sqlite(
        dataset,
        "users",
        [
            ("user_id", _plain(40)),
            ("email", _emails(40)),
            ("mobile", _phones(40)),
        ],
    )
    summary = scan_paths([dataset], workspace)[0]
    drift = summary.drift
    assert drift is not None

    policy = make_policy(
        """
        version: 1
        name: drift-report
        datasets:
          - path: ds.sqlite
            tables:
              users:
                columns:
                  mobile:
                    transformer: mask
                    params: {keep_prefix: 3, keep_suffix: 4}
        """
    )
    result = execute_run(summary.inventory, policy, workspace, batch_size=10)
    artifacts = finalize_run(
        workspace, summary.inventory, policy, result, summary.findings, drift=drift
    )
    payload = json.loads(artifacts["report"]["json"].read_text(encoding="utf-8"))
    drift_entry = _drift_entries(workspace)[0]

    report_drift = payload["drift"]
    assert report_drift["events"] == drift_entry["events"]
    assert report_drift["suppressed"] == drift_entry["suppressed"]
    assert report_drift["summary"] == drift_entry["summary"]
    assert report_drift["baseline_fingerprint"] == drift_entry["baseline_fingerprint"]
    assert report_drift["current_fingerprint"] == drift_entry["current_fingerprint"]
    assert report_drift["ignore_fingerprint"] == drift_entry["ignore_fingerprint"]
    assert report_drift["audit_seq"] == drift_entry["seq"]
    assert report_drift["audit_entry_hash"] == drift_entry["entry_hash"]

    # the masking run's own audit entry points back at the drift record
    run_entries = [
        entry
        for entry in read_audit_entries(workspace.audit_path)
        if entry.get("kind") != "dataset_drift"
    ]
    assert run_entries[-1]["drift_ref"]["audit_seq"] == drift_entry["seq"]
    assert run_entries[-1]["drift_ref"]["entry_hash"] == drift_entry["entry_hash"]

    markdown = artifacts["report"]["markdown"].read_text(encoding="utf-8")
    assert "跨版本漂移检测" in markdown
    assert "字段新增" in markdown
    assert "mobile" in markdown
    assert f"seq={drift_entry['seq']}" in markdown


def test_report_without_baseline_notes_no_comparison(workspace, tmp_path, make_policy):
    dataset = tmp_path / "ds.sqlite"
    _write_sqlite(dataset, "users", [("email", _emails(20))])
    summary = scan_paths([dataset], workspace)[0]
    policy = make_policy(
        """
        version: 1
        name: no-drift
        datasets:
          - path: ds.sqlite
            tables:
              users:
                columns:
                  email:
                    transformer: mask
                    params: {keep_prefix: 1, keep_suffix: 4}
        """
    )
    result = execute_run(summary.inventory, policy, workspace, batch_size=10)
    artifacts = finalize_run(
        workspace, summary.inventory, policy, result, summary.findings, drift=summary.drift
    )
    payload = json.loads(artifacts["report"]["json"].read_text(encoding="utf-8"))
    assert payload["drift"] is None
    markdown = artifacts["report"]["markdown"].read_text(encoding="utf-8")
    assert "跨版本漂移检测" in markdown
    assert "未执行跨版本对比" in markdown


# ---------------------------------------------------------------------------
# ignore rules: fingerprinted like policies, suppression stays auditable


def _write_rules(path, reason: str = "known test column") -> None:
    path.write_text(
        textwrap.dedent(
            f"""
            version: 1
            name: test-ignore
            rules:
              - table: users
                column: mobile
                drift_types: [field_added]
                reason: {reason}
            """
        ).lstrip(),
        encoding="utf-8",
    )


def test_ignore_rules_suppress_events_and_are_fingerprinted(workspace, tmp_path):
    dataset = tmp_path / "ds.sqlite"
    rules_path = tmp_path / "ignore.yaml"
    _write_rules(rules_path)
    rules = load_ignore_rules(rules_path)
    assert len(rules.fingerprint) == 64

    _write_sqlite(dataset, "users", [("email", _emails(40))])
    scan_paths([dataset], workspace, ignore_rules=rules)
    _write_sqlite(dataset, "users", [("email", _emails(40)), ("mobile", _phones(40))])
    drift = scan_paths([dataset], workspace, ignore_rules=rules)[0].drift

    assert drift.events == []
    assert len(drift.suppressed) == 1
    suppressed = drift.suppressed[0]
    assert suppressed.event.drift_type == "field_added"
    assert suppressed.event.column == "mobile"
    assert suppressed.rule_index == 0
    assert suppressed.rule.reason == "known test column"
    assert drift.ignore_fingerprint == rules.fingerprint

    entry = _drift_entries(workspace)[0]
    assert entry["ignore_fingerprint"] == rules.fingerprint
    assert entry["events"] == []
    assert entry["suppressed"][0]["rule"]["reason"] == "known test column"

    # modifying the rules file changes its fingerprint (same model as policies)
    _write_rules(rules_path, reason="quietly edited")
    modified = load_ignore_rules(rules_path)
    assert modified.fingerprint != rules.fingerprint


def test_ignore_rules_do_not_suppress_other_drift_types(workspace, tmp_path):
    dataset = tmp_path / "ds.sqlite"
    rules_path = tmp_path / "ignore.yaml"
    _write_rules(rules_path)  # only ignores field_added on users.mobile
    rules = load_ignore_rules(rules_path)

    _write_sqlite(dataset, "users", [("mobile", _emails(40))])
    scan_paths([dataset], workspace, ignore_rules=rules)
    _write_sqlite(dataset, "users", [("mobile", _phones(40))])
    drift = scan_paths([dataset], workspace, ignore_rules=rules)[0].drift
    assert [event.drift_type for event in drift.events] == ["type_changed"]
    assert drift.suppressed == []


@pytest.mark.parametrize(
    "text, message",
    [
        ("version: 2\nrules: []\n", "version"),
        ("version: 1\nrules: []\n", "non-empty"),
        ("version: 1\nrules:\n  - column: x\n", "table"),
        ("version: 1\nrules:\n  - table: t\n", "column"),
        (
            "version: 1\nrules:\n  - table: t\n    column: c\n    bogus: 1\n",
            "unknown keys",
        ),
        (
            "version: 1\nrules:\n  - table: t\n    column: c\n"
            "    drift_types: [nope]\n",
            "unknown drift type",
        ),
    ],
)
def test_ignore_rules_validation_errors(tmp_path, text, message):
    path = tmp_path / "bad.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(DriftRulesError, match=message):
        load_ignore_rules(path)


def test_ignore_rules_missing_file(tmp_path):
    with pytest.raises(DriftRulesError, match="not found"):
        load_ignore_rules(tmp_path / "missing.yaml")


# ---------------------------------------------------------------------------
# upgrade: historical registry databases migrate in place, old data intact


HISTORICAL_SCHEMA = """
CREATE TABLE datasets (
    fingerprint TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    row_count INTEGER NOT NULL,
    tables_json TEXT NOT NULL,
    registered_at TEXT NOT NULL
);
CREATE TABLE findings (
    dataset_fingerprint TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    sensitive_type TEXT,
    confidence TEXT NOT NULL DEFAULT 'none',
    score REAL NOT NULL DEFAULT 0,
    hit_rate REAL NOT NULL DEFAULT 0,
    validate_rate REAL NOT NULL DEFAULT 0,
    sample_size INTEGER NOT NULL DEFAULT 0,
    candidates_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (dataset_fingerprint, table_name, column_name)
);
"""


def test_historical_registry_upgrades_and_stays_queryable(workspace, tmp_path):
    dataset = tmp_path / "ds.sqlite"
    # current content of the dataset (the "new version")
    _write_sqlite(
        dataset,
        "users",
        [("user_id", _plain(40)), ("email", _emails(40)), ("mobile", _phones(40))],
    )
    # build a historical (schema v0) registry with findings for the old version
    meta = workspace.meta_db
    conn = sqlite3.connect(meta)
    try:
        conn.executescript(HISTORICAL_SCHEMA)
        conn.execute(
            "INSERT INTO datasets VALUES (?,?,?,?,?,?,?)",
            (
                "historical-fp",
                str(dataset.resolve()),
                "sqlite",
                1234,
                40,
                "[]",
                "2024-01-01T00:00:00+00:00",
            ),
        )
        for column, sensitive_type, confidence, hit in (
            ("user_id", None, "none", 0.0),
            ("email", "email", "high", 1.0),
        ):
            conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "historical-fp",
                    "users",
                    column,
                    sensitive_type,
                    confidence,
                    hit,
                    hit,
                    1.0 if sensitive_type else 0.0,
                    40,
                    "[]",
                    "2024-01-01T00:00:00+00:00",
                ),
            )
        conn.commit()
    finally:
        conn.close()

    # opening with the new code migrates additively; old rows stay queryable
    with Catalog(meta) as catalog:
        assert catalog.schema_version == 1
        findings = catalog.findings_for("historical-fp")
        assert [(f["column_name"], f["sensitive_type"]) for f in findings] == [
            ("email", "email"),
            ("user_id", None),
        ]
        tables = {
            row[0]
            for row in catalog.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"datasets", "findings", "drift_reports"} <= tables

    # scanning the updated dataset compares against the historical baseline
    summary = scan_paths([dataset], workspace)[0]
    drift = summary.drift
    assert drift is not None
    assert drift.baseline_fingerprint == "historical-fp"
    assert [(e.drift_type, e.column) for e in drift.events] == [
        ("field_added", "mobile")
    ]

    # historical findings were not modified by the upgrade or the scan
    with Catalog(meta) as catalog:
        findings = catalog.findings_for("historical-fp")
    assert [(f["column_name"], f["updated_at"]) for f in findings] == [
        ("email", "2024-01-01T00:00:00+00:00"),
        ("user_id", "2024-01-01T00:00:00+00:00"),
    ]


# ---------------------------------------------------------------------------
# performance: full comparison stays within 15% of the original scan time


def test_drift_comparison_stays_within_scan_time_budget(workspace, tmp_path):
    dataset = tmp_path / "big.sqlite"
    row_count = 100_000
    _write_sqlite(
        dataset,
        "bulk",
        [
            ("row_key", [f"key-{index:07d}" for index in range(row_count)]),
            ("amount", [f"{index % 1000}.5" for index in range(row_count)]),
            ("email", _emails(row_count)),
            ("note", _plain(row_count)),
        ],
    )
    started = time.perf_counter()
    scan_paths([dataset], workspace)
    scan_seconds = time.perf_counter() - started

    conn = sqlite3.connect(dataset)
    try:
        conn.execute("ALTER TABLE bulk ADD COLUMN mobile TEXT")
        conn.execute("UPDATE bulk SET mobile = printf('138%08d', rowid)")
        conn.commit()
    finally:
        conn.close()

    drift = scan_paths([dataset], workspace)[0].drift
    assert drift is not None
    assert [(e.drift_type, e.column) for e in drift.events] == [
        ("field_added", "mobile")
    ]
    assert drift.elapsed_seconds <= scan_seconds * 0.15
