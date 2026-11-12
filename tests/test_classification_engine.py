from __future__ import annotations

from maskline.classification.engine import ClassificationEngine, ColumnInput
from maskline.classification.rulepacks import builtin_rule_packs
from maskline.classification.semantic import SemanticResolver


def _engine() -> tuple[ClassificationEngine, dict[str, int]]:
    packs = builtin_rule_packs()
    versions = {pack.standard.code: index + 1 for index, pack in enumerate(packs)}
    return ClassificationEngine(packs, versions), versions


def _std(result, code: str):
    return next(item for item in result.standards if item.standard_code == code)


def test_id_card_gets_l4_and_special_category_under_pipl_and_gbt():
    engine, versions = _engine()
    result = engine.classify_column(
        "fp",
        ColumnInput("customers", "id_card", "id_card", "high"),
    )
    pipl = _std(result, "pipl")
    gbt = _std(result, "gbt35273")
    gdpr = _std(result, "gdpr")
    assert pipl.level == "L4" and pipl.special_category is True
    assert gbt.level == "L4" and gbt.special_category is True
    # GDPR treats national IDs as high-risk personal data, not Art.9 special category.
    assert gdpr.level == "L3" and gdpr.special_category is False
    assert all(std.rule_pack_version_id == versions[std.standard_code] for std in result.standards)


def test_ip_field_flagged_cross_border_in_every_standard():
    engine, _ = _engine()
    result = engine.classify_column(
        "fp", ColumnInput("orders", "client_ip", "ipv4", "high")
    )
    assert all(std.cross_border for std in result.standards)
    assert any(alert.code == "cross_border_name_hit" for alert in result.alerts)


def test_email_cross_border_flag_and_name_only_health_rule():
    engine, _ = _engine()
    email = engine.classify_column(
        "fp", ColumnInput("users", "email", "email", "high")
    )
    assert _std(email, "pipl").cross_border is True
    health = engine.classify_column(
        "fp", ColumnInput("users", "medical_history", None, "none")
    )
    pipl_health = _std(health, "pipl")
    assert pipl_health.level == "L4"
    assert pipl_health.special_category is True
    assert pipl_health.match_basis == "name"
    assert any(alert.code == "weak_evidence_match" for alert in health.alerts)


def test_unmapped_sensitive_type_uses_fallback_with_alert():
    engine, _ = _engine()
    result = engine.classify_column(
        "fp", ColumnInput("t", "mystery", "biometric_template", "medium")
    )
    pipl = _std(result, "pipl")
    assert pipl.match_basis == "fallback"
    assert pipl.level == "L2"
    assert any(alert.code == "rule_unmapped_sensitive" for alert in result.alerts)


def test_non_sensitive_column_stays_unclassified():
    engine, _ = _engine()
    result = engine.classify_column(
        "fp", ColumnInput("t", "status", None, "none")
    )
    assert all(std.level is None for std in result.standards)
    assert all(std.match_basis == "unclassified" for std in result.standards)


def test_semantic_resolver_maps_heteronyms_to_one_key():
    resolver = SemanticResolver.build(builtin_rule_packs())
    key_a, _ = resolver.resolve("contact_phone")
    key_b, _ = resolver.resolve("mobile")
    key_c, _ = resolver.resolve("联系电话")
    assert key_a == key_b == key_c == "mobile_phone"
    key_d, _ = resolver.resolve("payload.user.contact.mobile")
    assert key_d == "mobile_phone"


def test_semantic_consistency_unifies_heteronyms_and_alerts():
    engine, _ = _engine()
    phone_a = engine.classify_column(
        "fp", ColumnInput("customers", "phone", "mobile_phone", "high")
    )
    # Same semantics, weak content evidence so only a name-based match happens.
    phone_b = engine.classify_column(
        "fp", ColumnInput("leads", "hotline", None, "low")
    )
    results = engine.enforce_semantic_consistency([phone_a, phone_b])
    assert all(result.semantic_key == "mobile_phone" for result in results)
    levels = {_std(result, "pipl").level for result in results}
    assert levels == {"L3"}
    assert any(
        alert.code == "semantic_drift"
        for result in results
        for alert in result.alerts
    )


def test_headerless_column_skips_name_matching_but_keeps_content_match():
    engine, _ = _engine()
    result = engine.classify_column(
        "fp",
        ColumnInput(
            "t", "col_001", "id_card", "high", name_match_available=False, degraded=True
        ),
    )
    pipl = _std(result, "pipl")
    assert pipl.matched_rule_id == "pipl-id-card"
    assert pipl.match_basis == "sensitive_type"
    assert result.degraded is True
