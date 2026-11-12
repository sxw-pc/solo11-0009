from __future__ import annotations

import pytest

from maskline.classification.models import RulePackError
from maskline.classification.rulepacks import BUILTIN_PACK_DIR, builtin_rule_packs, load_rule_pack


def test_three_builtin_packs_load_with_fingerprints():
    packs = builtin_rule_packs()
    codes = {pack.standard.code for pack in packs}
    assert codes == {"gdpr", "gbt35273", "pipl"}
    fingerprints = [pack.fingerprint for pack in packs]
    assert all(len(fp) == 64 for fp in fingerprints)
    assert len(set(fingerprints)) == 3
    for pack in packs:
        assert pack.builtin is True
        assert pack.rules
        assert pack.fallback_level in pack.level_order


def test_pack_fingerprint_is_stable_and_content_sensitive(tmp_path):
    source = BUILTIN_PACK_DIR / "pipl.yaml"
    pack_a = load_rule_pack(source, builtin=True)
    pack_b = load_rule_pack(source, builtin=True)
    assert pack_a.fingerprint == pack_b.fingerprint
    text = source.read_text(encoding="utf-8")
    changed = tmp_path / "changed.yaml"
    changed.write_text(text.replace("revision: 1", "revision: 2"), encoding="utf-8")
    pack_c = load_rule_pack(changed)
    assert pack_c.fingerprint != pack_a.fingerprint


def test_pack_rejects_unknown_keys_and_bad_level(tmp_path):
    pack_path = tmp_path / "bad.yaml"
    pack_path.write_text(
        """
version: 1
pack_id: x
revision: 1
standard: {code: x, name: X, version: "1", description: ""}
level_order: [L1, L2]
level_names: {L1: low, L2: high}
defaults:
  fallback_level: L2
  fallback_category: c
  fallback_controls: [c1]
controls_catalog: {c1: control one}
rules:
  - id: r1
    priority: 1
    bogus: true
    match: {sensitive_types: [email], name_patterns: []}
    labels: {level: L9, category: c, controls: [c1]}
""",
        encoding="utf-8",
    )
    with pytest.raises(RulePackError):
        load_rule_pack(pack_path)


def test_pack_rejects_undeclared_control_and_duplicate_rule(tmp_path):
    pack_path = tmp_path / "bad2.yaml"
    pack_path.write_text(
        """
version: 1
pack_id: x
revision: 1
standard: {code: x, name: X, version: "1", description: ""}
level_order: [L1]
level_names: {L1: low}
defaults: {fallback_level: L1, fallback_category: c, fallback_controls: [c1]}
controls_catalog: {c1: control one}
rules:
  - id: r1
    priority: 1
    match: {sensitive_types: [email], name_patterns: []}
    labels: {level: L1, category: c, controls: [ghost]}
""",
        encoding="utf-8",
    )
    with pytest.raises(RulePackError, match="controls_catalog"):
        load_rule_pack(pack_path)


def test_pack_rejects_conflicting_aliases(tmp_path):
    pack_path = tmp_path / "bad3.yaml"
    pack_path.write_text(
        """
version: 1
pack_id: x
revision: 1
standard: {code: x, name: X, version: "1", description: ""}
level_order: [L1]
level_names: {L1: low}
defaults: {fallback_level: L1, fallback_category: c, fallback_controls: [c1]}
controls_catalog: {c1: control one}
aliases:
  - {canonical: a, names: [shared]}
  - {canonical: b, names: [shared]}
rules:
  - id: r1
    priority: 1
    match: {sensitive_types: [email], name_patterns: []}
    labels: {level: L1, category: c, controls: [c1]}
""",
        encoding="utf-8",
    )
    with pytest.raises(RulePackError, match="alias"):
        load_rule_pack(pack_path)


def test_custom_pack_extends_builtin_standard(tmp_path):
    pack_path = tmp_path / "custom.yaml"
    pack_path.write_text(
        """
version: 1
pack_id: pipl-custom
revision: 2
standard: {code: pipl, name: PIPL custom, version: "2021", description: ""}
level_order: [L1, L2, L3, L4]
level_names: {L1: org, L2: general, L3: elevated, L4: sensitive}
defaults: {fallback_level: L2, fallback_category: fallback, fallback_controls: [c1]}
controls_catalog: {c1: base control, c2: extra control}
cross_border_name_patterns: [email]
aliases:
  - {canonical: mobile_phone, names: [hotline]}
rules:
  - id: custom-salary
    priority: 60
    match: {sensitive_types: [], name_patterns: ["*salary*", "*工资*"]}
    labels: {level: L4, category: 敏感个人信息-财产信息, controls: [c1, c2]}
    special_category: true
""",
        encoding="utf-8",
    )
    pack = load_rule_pack(pack_path)
    assert pack.standard.code == "pipl"
    assert pack.revision == 2
    assert any(rule.rule_id == "custom-salary" for rule in pack.rules)
