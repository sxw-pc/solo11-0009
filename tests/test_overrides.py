import textwrap

import pytest

from maskline.overrides import (
    DECISION_NOT_SENSITIVE,
    DECISION_SENSITIVE,
    OverrideError,
    adjudicate_findings,
    load_overrides,
    resolve_operator,
)

OPERATOR = "sec-reviewer"


def write(tmp_path, text):
    path = tmp_path / "overrides.yaml"
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


def test_load_requires_reason_and_known_decision(tmp_path):
    with pytest.raises(OverrideError, match="reason"):
        load_overrides(
            write(
                tmp_path,
                """
                version: 1
                overrides:
                  - dataset: demo.sqlite
                    table: customers
                    column: phone
                    decision: force_sensitive
                """,
            ),
            operator=OPERATOR,
        )
    with pytest.raises(OverrideError, match="decision"):
        load_overrides(
            write(
                tmp_path,
                """
                version: 1
                overrides:
                  - dataset: demo.sqlite
                    table: customers
                    column: phone
                    decision: maybe_sensitive
                    reason: r
                """,
            ),
            operator=OPERATOR,
        )


def test_load_rejects_unknown_keys_and_bad_version(tmp_path):
    with pytest.raises(OverrideError, match="unknown keys"):
        load_overrides(
            write(
                tmp_path,
                """
                version: 1
                overrides:
                  - dataset: demo.sqlite
                    table: customers
                    column: phone
                    decision: force_sensitive
                    reason: r
                    note: extra
                """,
            ),
            operator=OPERATOR,
        )
    with pytest.raises(OverrideError, match="version"):
        load_overrides(
            write(tmp_path, "version: 2\noverrides: []\n"), operator=OPERATOR
        )


def test_operator_is_required_when_entries_exist(tmp_path, monkeypatch):
    monkeypatch.delenv("MASKLINE_OPERATOR", raising=False)
    path = write(
        tmp_path,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_not_sensitive
            reason: r
        """,
    )
    with pytest.raises(OverrideError, match="MASKLINE_OPERATOR"):
        load_overrides(path)
    empty = write(tmp_path, "version: 1\noverrides: []\n")
    assert load_overrides(empty).entries == ()


def test_duplicate_keys_are_rejected_not_last_wins(tmp_path):
    with pytest.raises(OverrideError, match="duplicate override"):
        load_overrides(
            write(
                tmp_path,
                """
                version: 1
                overrides:
                  - dataset: demo.sqlite
                    table: customers
                    column: phone
                    decision: force_sensitive
                    reason: first
                  - dataset: demo.sqlite
                    table: customers
                    column: phone
                    decision: force_not_sensitive
                    reason: second
                """,
            ),
            operator=OPERATOR,
        )


def test_ambiguous_dataset_patterns_are_rejected(tmp_path):
    with pytest.raises(OverrideError, match="ambiguous"):
        load_overrides(
            write(
                tmp_path,
                """
                version: 1
                overrides:
                  - dataset: "*.sqlite"
                    table: customers
                    column: phone
                    decision: force_sensitive
                    reason: a
                  - dataset: demo.sqlite
                    table: customers
                    column: phone
                    decision: force_not_sensitive
                    reason: b
                """,
            ),
            operator=OPERATOR,
        )


def test_fingerprint_is_stable_and_order_sensitive(tmp_path):
    text = """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_sensitive
            reason: r
    """
    first = load_overrides(write(tmp_path, text), operator=OPERATOR)
    second = load_overrides(write(tmp_path, text), operator=OPERATOR)
    assert first.fingerprint == second.fingerprint


def test_force_sensitive_raises_effective_confidence_and_keeps_detector_verdict(
    inventories, tmp_path
):
    path = write(
        tmp_path,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: customer_id
            decision: force_sensitive
            reason: internal employee id
        """,
    )
    overrides = load_overrides(path, operator=OPERATOR)
    findings = [
        {
            "table_name": "customers",
            "column_name": "customer_id",
            "sensitive_type": None,
            "confidence": "none",
            "detected_type": None,
            "detected_confidence": "none",
            "score": 0.0,
            "hit_rate": 0.0,
            "validate_rate": 0.0,
        }
    ]
    records, applied = adjudicate_findings(inventories["sqlite"], findings, overrides)
    assert records[0]["confidence"] == "high"
    assert records[0]["sensitive_type"] == "manual_adjudication"
    assert records[0]["detected_confidence"] == "none"
    assert records[0]["override"]["decision"] == DECISION_SENSITIVE
    assert applied.applied[0]["column"] == "customer_id"
    assert applied.unmatched == []


def test_force_not_sensitive_suppresses_but_policy_conflict_is_recorded(inventories, tmp_path):
    path = write(
        tmp_path,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: customers
            column: phone
            decision: force_not_sensitive
            reason: confirmed shared hotline
        """,
    )
    overrides = load_overrides(path, operator=OPERATOR)
    findings = [
        {
            "table_name": "customers",
            "column_name": "phone",
            "sensitive_type": "mobile_phone",
            "confidence": "high",
            "detected_type": "mobile_phone",
            "detected_confidence": "high",
            "score": 1.0,
            "hit_rate": 1.0,
            "validate_rate": 1.0,
        }
    ]
    records, applied = adjudicate_findings(
        inventories["sqlite"], findings, overrides,
        policy_columns={"customers": {"phone": "mask"}},
    )
    assert records[0]["confidence"] == "none"
    assert records[0]["sensitive_type"] is None
    assert records[0]["detected_type"] == "mobile_phone"
    assert len(applied.conflicts) == 1
    assert applied.conflicts[0].transformer == "mask"


def test_missing_table_and_column_are_unmatched(inventories, tmp_path):
    path = write(
        tmp_path,
        """
        version: 1
        overrides:
          - dataset: demo.sqlite
            table: no_such_table
            column: phone
            decision: force_sensitive
            reason: r
          - dataset: demo.sqlite
            table: customers
            column: no_such_column
            decision: force_sensitive
            reason: r
        """,
    )
    overrides = load_overrides(path, operator=OPERATOR)
    _records, applied = adjudicate_findings(inventories["sqlite"], [], overrides)
    kinds = {item.kind for item in applied.unmatched}
    assert kinds == {"table", "column"}
    assert applied.applied == []


def test_resolve_operator_reads_env(monkeypatch):
    monkeypatch.setenv("MASKLINE_OPERATOR", "  alice  ")
    assert resolve_operator() == "alice"
    monkeypatch.setenv("MASKLINE_OPERATOR", "   ")
    assert resolve_operator() is None
    monkeypatch.delenv("MASKLINE_OPERATOR")
    assert resolve_operator() is None
