from __future__ import annotations

import os
import textwrap
import threading
import time

import pytest

from maskline.__main__ import main
from maskline.audit import AuditLog, read_audit_entries
from maskline.config import Paths
from maskline.fixturegen import generate_linkage_fixture
from maskline.linkage.ignore import load_ignore_rules
from maskline.linkage.profile import profile_inventory
from maskline.linkage.scan import FileBudget, LinkScanOptions, run_linkscan
from maskline.linkage.store import LinkStore
from maskline.policies import load_policy
from maskline.registry import Catalog, inspect_dataset
from maskline.utils import MasklineError


@pytest.fixture
def link_paths(tmp_path):
    paths = Paths.for_workspace(tmp_path / "ws")
    paths.ensure_runtime_dirs()
    return paths


@pytest.fixture
def link_fixtures(tmp_path):
    return generate_linkage_fixture(
        tmp_path / "raw", seed=11, members=12, kyc=9, payments=6, orders=40, survey=8
    )


@pytest.fixture
def scanned(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    return run_linkscan(link_paths, target, LinkScanOptions()), link_fixtures


def _equality_pairs(outcome):
    return {
        tuple(sorted((edge.left.label, edge.right.label)))
        for edge in outcome.graph.equality_edges
    }


def _semantic_pairs(outcome):
    return {
        tuple(sorted((edge.left.label, edge.right.label)))
        for edge in outcome.graph.semantic_edges
    }


def _write_rules(tmp_path, body: str):
    path = tmp_path / "ignore.yaml"
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return load_ignore_rules(path)


def test_profile_flags_identifier_columns_as_keys(link_fixtures):
    inventory = inspect_dataset(link_fixtures["members"])
    profiled = profile_inventory(inventory, sample_limit=200)
    by_column = {item.profile.ref.column: item.profile for item in profiled}
    phone = by_column["phone"]
    assert phone.key_candidate
    assert "identifier-type:mobile_phone" in phone.key_reasons
    assert phone.sensitive_type == "mobile_phone"
    assert by_column["member_id"].key_candidate
    assert by_column["email"].key_candidate
    assert not by_column["full_name"].key_candidate
    # ISO dates look id-shaped but must not become key candidates
    assert not by_column["joined_at"].key_candidate
    # value fingerprints are stored for key candidates only
    hashes = {item.profile.ref.column: item.value_hashes for item in profiled}
    assert len(hashes["phone"]) == 12
    assert hashes["full_name"] == frozenset()


def test_equality_edges_connect_shared_keys(scanned):
    outcome, _fixtures = scanned
    pairs = _equality_pairs(outcome)
    assert ("kyc.csv:kyc.phone", "members.sqlite:members.phone") in pairs
    assert ("kyc.csv:kyc.id_card", "payments.csv:payments.id_card") in pairs
    assert ("members.sqlite:members.member_id", "orders.sqlite:orders.member_id") in pairs


def test_no_spurious_surrogate_key_edge(scanned):
    outcome, _fixtures = scanned
    pairs = _equality_pairs(outcome)
    # 1..N integer ranges overlap but the names share no entity token
    assert ("members.sqlite:members.member_id", "orders.sqlite:orders.order_id") not in pairs


def test_semantic_edges_link_person_names(scanned):
    outcome, _fixtures = scanned
    pairs = _semantic_pairs(outcome)
    assert ("members.sqlite:members.full_name", "payments.csv:payments.holder_name") in pairs
    assert ("members.sqlite:members.full_name", "survey.csv:survey.respondent_name") in pairs
    assert all(edge.kind == "semantic" for edge in outcome.graph.semantic_edges)


def test_critical_combo_risk(scanned):
    outcome, _fixtures = scanned
    assert len(outcome.risks) == 1
    risk = outcome.risks[0]
    assert risk.level == "critical"
    assert {
        "person_name",
        "id_card",
        "mobile_phone",
        "bank_card",
        "email",
        "address",
    } <= set(risk.sensitive_types)
    labels = {rule["label"] for rule in risk.combo_rules}
    assert "实名身份核验组合" in labels
    assert "金融账户控制组合" in labels
    assert len(risk.datasets) == 4
    assert risk.join_keys


def test_semantic_only_dataset_not_in_cluster(scanned):
    outcome, _fixtures = scanned
    for risk in outcome.risks:
        assert all("survey.csv" not in path for path in risk.datasets)


def test_findings_synced_to_catalog(scanned, link_paths):
    _outcome, fixtures = scanned
    inventory = inspect_dataset(fixtures["members"])
    with Catalog(link_paths.meta_db) as catalog:
        assert catalog.get_dataset(inventory.fingerprint) is not None
        findings = catalog.findings_for(inventory.fingerprint)
    phone = next(item for item in findings if item["column_name"] == "phone")
    assert phone["sensitive_type"] == "mobile_phone"
    assert phone["confidence"] == "high"


def test_incremental_second_scan_reuses_profiles(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    first = run_linkscan(link_paths, target, LinkScanOptions())
    assert first.stats["files_profiled"] == 5
    second = run_linkscan(link_paths, target, LinkScanOptions())
    assert second.stats["files_profiled"] == 0
    assert second.stats["files_reused"] == 5
    assert second.version_no == first.version_no + 1
    assert [(r.level, r.summary) for r in second.risks] == [
        (r.level, r.summary) for r in first.risks
    ]


def test_modified_dataset_triggers_reprofile(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    run_linkscan(link_paths, target, LinkScanOptions())
    with link_fixtures["kyc"].open("a", encoding="utf-8", newline="") as fh:
        fh.write("13912345678,999999199001011230,北京市演示区测试路9号\n")
    outcome = run_linkscan(link_paths, target, LinkScanOptions())
    assert outcome.stats["files_profiled"] == 1
    assert outcome.stats["files_reused"] == 4
    pairs = _equality_pairs(outcome)
    assert ("kyc.csv:kyc.phone", "members.sqlite:members.phone") in pairs


def test_removed_dataset_excluded_from_graph(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    first = run_linkscan(link_paths, target, LinkScanOptions())
    assert any(
        "payments.csv" in path for risk in first.risks for path in risk.datasets
    )
    link_fixtures["payments"].unlink()
    second = run_linkscan(link_paths, target, LinkScanOptions())
    assert second.stats["files_removed"] == 1
    assert all(
        "payments.csv" not in path for risk in second.risks for path in risk.datasets
    )
    # members + kyc still form a critical combination through the phone link
    assert any(risk.level == "critical" for risk in second.risks)


def test_versions_keep_history(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    run_linkscan(link_paths, target, LinkScanOptions())
    link_fixtures["payments"].unlink()
    run_linkscan(link_paths, target, LinkScanOptions())
    store = LinkStore(link_paths.linkgraph_db)
    try:
        assert store.latest_scan()["version_no"] == 2
        v1_risks = store.risks_for(1)
        assert any(
            "payments.csv" in path for risk in v1_risks for path in risk.datasets
        )
        v2_risks = store.risks_for(2)
        assert all(
            "payments.csv" not in path for risk in v2_risks for path in risk.datasets
        )
        assert len(store.edges_for(1)) > 0
    finally:
        store.close()


def test_full_rescan_reprofiles_everything(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    run_linkscan(link_paths, target, LinkScanOptions())
    outcome = run_linkscan(link_paths, target, LinkScanOptions(full_rescan=True))
    assert outcome.stats["files_profiled"] == 5
    assert outcome.stats["files_reused"] == 0


def test_corrupt_sqlite_skipped_with_warning(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    (target / "broken.sqlite").write_bytes(b"definitely not a sqlite database")
    outcome = run_linkscan(link_paths, target, LinkScanOptions())
    assert outcome.stats["files_skipped"] == 1
    assert outcome.stats["files_profiled"] == 5
    assert any("broken.sqlite" in warning.path for warning in outcome.warnings)
    assert outcome.risks  # the scan still completes and finds risks
    # a second scan retries the broken file and warns again without crashing
    second = run_linkscan(link_paths, target, LinkScanOptions())
    assert second.stats["files_skipped"] == 1


def test_bad_encoding_csv_skipped_with_warning(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    (target / "bad.csv").write_bytes(b"\xff\xfe\x00bad,\xffcsv\n1,2\n")
    outcome = run_linkscan(link_paths, target, LinkScanOptions())
    assert outcome.stats["files_skipped"] == 1
    assert any("bad.csv" in warning.path for warning in outcome.warnings)


def test_audit_trail_records_scan_events(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    (target / "broken.sqlite").write_bytes(b"junk")
    outcome = run_linkscan(link_paths, target, LinkScanOptions())
    verification = AuditLog(link_paths.audit_path).verify()
    assert verification.entries >= 3
    entries = read_audit_entries(link_paths.audit_path)
    events = [entry["event"] for entry in entries]
    assert "linkscan_started" in events
    assert "linkscan_file_skipped" in events
    assert "linkscan_completed" in events
    completed = [e for e in entries if e["event"] == "linkscan_completed"]
    assert completed[-1]["scan_id"] == outcome.scan_id
    assert completed[-1]["version_no"] == outcome.version_no
    assert completed[-1]["risk_levels"] == {"critical": 1}


def test_policy_export_is_loadable(link_paths, link_fixtures):
    target = link_fixtures["members"].parent
    outcome = run_linkscan(link_paths, target, LinkScanOptions(export_policy=True))
    policy_path = outcome.reports["policy"]
    policy = load_policy(policy_path)
    assert policy.name == f"linkage-suggested-v{outcome.version_no}"
    fixtures_by_name = {path.name: path for path in link_fixtures.values()}
    for rule in policy.datasets:
        inventory = inspect_dataset(fixtures_by_name[rule.path_pattern])
        policy.validate_against(inventory)
    rules = {rule.path_pattern: rule for rule in policy.datasets}
    kyc_columns = rules["kyc.csv"].tables["kyc"].columns
    assert kyc_columns["id_card"].transformer == "hash"  # critical override
    assert kyc_columns["address"].transformer == "generalize"
    member_columns = rules["members.sqlite"].tables["members"].columns
    assert member_columns["full_name"].transformer == "pseudonym"
    assert member_columns["phone"].transformer == "hash"
    payment_columns = rules["payments.csv"].tables["payments"].columns
    assert payment_columns["card_no"].transformer == "hash"


def test_ignore_rules_exclude_column(link_paths, link_fixtures, tmp_path):
    rules = _write_rules(
        tmp_path,
        """
        version: 1
        ignore:
          columns:
            - "members.sqlite:members.phone"
        """,
    )
    outcome = run_linkscan(
        link_paths, link_fixtures["members"].parent, LinkScanOptions(), rules
    )
    pairs = _equality_pairs(outcome)
    assert ("kyc.csv:kyc.phone", "members.sqlite:members.phone") not in pairs
    # the other links still work
    assert ("kyc.csv:kyc.id_card", "payments.csv:payments.id_card") in pairs
    assert ("members.sqlite:members.member_id", "orders.sqlite:orders.member_id") in pairs
    # and the ignored column contributes nothing to any combination
    for risk in outcome.risks:
        if any("members.sqlite" in path for path in risk.datasets):
            assert "mobile_phone" not in risk.sensitive_types


def test_ignore_rules_exclude_sensitive_type(link_paths, link_fixtures, tmp_path):
    rules = _write_rules(
        tmp_path,
        """
        version: 1
        ignore:
          sensitive_types:
            - "mobile_phone"
        """,
    )
    outcome = run_linkscan(
        link_paths, link_fixtures["members"].parent, LinkScanOptions(), rules
    )
    # equality edges are factual and stay, but the type leaves the combinations
    assert ("kyc.csv:kyc.phone", "members.sqlite:members.phone") in _equality_pairs(outcome)
    for risk in outcome.risks:
        assert "mobile_phone" not in risk.sensitive_types
    assert all(
        "mobile_phone" not in edge.reason for edge in outcome.graph.semantic_edges
    )


def test_ignore_rules_exclude_pair(link_paths, link_fixtures, tmp_path):
    rules = _write_rules(
        tmp_path,
        """
        version: 1
        ignore:
          pairs:
            - ["members.sqlite:members.phone", "kyc.csv:kyc.phone"]
        """,
    )
    outcome = run_linkscan(
        link_paths, link_fixtures["members"].parent, LinkScanOptions(), rules
    )
    pairs = _equality_pairs(outcome)
    assert ("kyc.csv:kyc.phone", "members.sqlite:members.phone") not in pairs
    assert ("kyc.csv:kyc.id_card", "payments.csv:payments.id_card") in pairs


def test_ignore_rules_exclude_dataset(link_paths, link_fixtures, tmp_path):
    rules = _write_rules(
        tmp_path,
        """
        version: 1
        ignore:
          datasets:
            - "payments.csv"
        """,
    )
    target = link_fixtures["members"].parent
    first = run_linkscan(link_paths, target, LinkScanOptions(), rules)
    assert first.stats["files_ignored"] == 1
    assert first.stats["files_seen"] == 4
    assert all(
        "payments.csv" not in path for risk in first.risks for path in risk.datasets
    )
    # stays ignored on the next scan without being re-profiled
    second = run_linkscan(link_paths, target, LinkScanOptions(), rules)
    assert second.stats["files_ignored"] == 1
    assert second.stats["files_profiled"] == 0


def test_empty_target_raises(link_paths, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(MasklineError):
        run_linkscan(link_paths, empty, LinkScanOptions())


def test_file_budget_limits_concurrency():
    budget = FileBudget(2)
    active = 0
    peak = 0
    lock = threading.Lock()

    def worker():
        nonlocal active, peak
        with budget:
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.02)
            with lock:
                active -= 1

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert peak == 2


def test_many_small_files_within_fd_budget(link_paths, tmp_path):
    raw = tmp_path / "many"
    raw.mkdir()
    for index in range(40):
        rows = "\n".join(f"K{index}-{item},v{item}" for item in range(5))
        (raw / f"t{index:02d}.csv").write_text(f"key,value\n{rows}\n", encoding="utf-8")
    before = len(os.listdir("/proc/self/fd"))
    outcome = run_linkscan(
        link_paths, raw, LinkScanOptions(workers=8, max_open_files=8)
    )
    after = len(os.listdir("/proc/self/fd"))
    assert outcome.stats["files_profiled"] == 40
    assert outcome.stats["files_skipped"] == 0
    assert outcome.graph.equality_edges == ()
    assert after <= before + 5


def test_cli_linkscan_and_links(link_paths, link_fixtures, capsys):
    target = str(link_fixtures["members"].parent)
    workspace = str(link_paths.root)
    assert main(["linkscan", target, "--workspace", workspace, "--export-policy"]) == 0
    assert main(["links", "--workspace", workspace]) == 0
    out = capsys.readouterr().out
    assert "critical=1" in out
    assert "version=v1" in out


def test_cli_links_without_scan(link_paths, capsys):
    assert main(["links", "--workspace", str(link_paths.root)]) == 0
    assert "no linkage scan" in capsys.readouterr().out
