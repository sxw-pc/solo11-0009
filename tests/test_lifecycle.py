"""End-to-end lifecycle tests covering every acceptance scenario."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from maskline.audit import AuditLog, verify_audit
from maskline.lifecycle.erase import EraseError, secure_erase
from maskline.lifecycle.manager import LifecycleError, LifecycleManager
from maskline.lifecycle.retention import RetentionPolicy, RetentionPolicyError
from maskline.lifecycle.types import ArtifactStatus, ArtifactType
from maskline.pipeline.errors import PipelineInterrupted
from maskline.pipeline.runner import execute_run
from maskline.pseudomap import PseudoMap, PseudoMapError

from lifecycle_helpers import (
    EPOCH,
    advance,
    custom_policy,
    pinned_clock,
    run_and_register,
)


# --------------------------------------------------------------------- retention policy

def test_default_retention_windows_are_type_specific():
    policy = RetentionPolicy.default()
    assert policy.schedule_for(ArtifactType.PSEUDOMAP).retention_days == 30
    assert policy.schedule_for(ArtifactType.CHECKPOINT).retention_days == 14
    assert policy.schedule_for(ArtifactType.REPORT).retention_days == 180
    assert policy.schedule_for(ArtifactType.OUTPUT).grace_days == 7


def test_policy_file_overrides_defaults_and_datasets(tmp_path):
    policy_file = tmp_path / "retention.yaml"
    policy_file.write_text(
        """
        grace_days: 5
        retention_days:
          pseudomap: 10
        datasets:
          fp-abc:
            grace_days: 2
            retention_days:
              pseudomap: 3
              output: 20
        """,
        encoding="utf-8",
    )
    policy = RetentionPolicy.from_file(policy_file)
    assert policy.schedule_for(ArtifactType.PSEUDOMAP).retention_days == 10
    assert policy.schedule_for(ArtifactType.PSEUDOMAP).grace_days == 5
    schedule = policy.schedule_for(ArtifactType.PSEUDOMAP, "fp-abc")
    assert schedule.retention_days == 3 and schedule.grace_days == 2
    other = policy.schedule_for(ArtifactType.OUTPUT, "fp-abc")
    assert other.retention_days == 20 and other.grace_days == 2
    assert policy.schedule_for(ArtifactType.OUTPUT).retention_days == 90


def test_policy_file_rejects_unknown_types_and_bad_days(tmp_path):
    policy_file = tmp_path / "bad.yaml"
    policy_file.write_text("retention_days:\n  bogus: 5\n", encoding="utf-8")
    with pytest.raises(RetentionPolicyError, match="unknown artifact type"):
        RetentionPolicy.from_file(policy_file)
    policy_file.write_text("grace_days: -1\n", encoding="utf-8")
    with pytest.raises(RetentionPolicyError, match="grace period"):
        RetentionPolicy.from_file(policy_file)


# ------------------------------------------------------------- registration & preview

def test_run_registers_every_artifact_with_expiry(workspace, inventories, secret_store):
    clock = pinned_clock()
    policy = custom_policy({"pseudomap": 30, "output": 90, "checkpoint": 14,
                            "report": 180, "manifest": 180})
    result, records = run_and_register(
        workspace, inventories["sqlite"], secret_store, clock, policy
    )
    types = {record.artifact_type for record in records}
    assert types == set(ArtifactType)
    by_type: dict[ArtifactType, object] = {}
    for record in records:
        by_type.setdefault(record.artifact_type, record)
    pseudomap = next(r for r in records if r.artifact_type is ArtifactType.PSEUDOMAP)
    assert pseudomap.expires_at == (EPOCH + timedelta(days=30)).isoformat(timespec="seconds")
    assert pseudomap.grace_ends_at == (EPOCH + timedelta(days=37)).isoformat(timespec="seconds")
    assert pseudomap.status is ArtifactStatus.ACTIVE
    assert all(record.content_hash for record in records)
    # Re-running the same shared artifacts refreshes them instead of duplicating rows.
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        all_records = manager.list_artifacts()
    pseudomap_rows = [r for r in all_records if r.artifact_type is ArtifactType.PSEUDOMAP]
    assert len(pseudomap_rows) == 1
    assert result.run_id  # sanity


def test_preview_is_read_only_and_accurate_across_expiry_dates(
    workspace, inventories, secret_store
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 10, "output": 20, "checkpoint": 5, "report": 40, "manifest": 40},
        grace_days=7,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        plan = manager.preview()
    assert plan.to_dict()["totals"] == {
        "ready_to_schedule": 0, "in_grace": 0, "grace_expired": 0, "blocked": 0,
    }
    # Day 6: checkpoints (5d) become schedulable; everything else stays active.
    advance(clock, 6)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        plan = manager.preview()
    assert len(plan.schedulable) == 1
    assert plan.schedulable[0].artifact.artifact_type is ArtifactType.CHECKPOINT
    assert plan.in_grace == [] and plan.grace_expired == [] and plan.blocked == []
    # Day 11: pseudomap (10d) is also due.
    advance(clock, 5)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        plan = manager.preview()
    due_types = {item.artifact.artifact_type for item in plan.schedulable}
    assert due_types == {ArtifactType.CHECKPOINT, ArtifactType.PSEUDOMAP}
    # Preview must not mutate any state.
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        assert all(r.status is ArtifactStatus.ACTIVE for r in manager.list_artifacts())


# ------------------------------------------------------------- scheduling & grace window

def test_schedule_moves_due_artifacts_into_revocable_grace(
    workspace, inventories, secret_store
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 10, "output": 90, "checkpoint": 5, "report": 90, "manifest": 90}
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    advance(clock, 6)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        plan = manager.schedule_due()
    assert len(plan.in_grace) == 1
    item = plan.in_grace[0]
    assert item.artifact.artifact_type is ArtifactType.CHECKPOINT
    assert item.artifact.status is ArtifactStatus.PENDING
    assert item.artifact.destroy_token and item.artifact.destroy_token.startswith("dtk-")
    verify_audit(workspace.audit_path)
    # Scheduling again is a no-op while the window is open.
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        again = manager.schedule_due()
    assert len(again.in_grace) == 1 and again.schedulable == []


def test_revoke_inside_grace_cancels_and_restarts_retention(
    workspace, inventories, secret_store
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 90, "output": 90, "checkpoint": 5, "report": 90, "manifest": 90}
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    advance(clock, 6)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        manager.schedule_due()
        target = next(
            r for r in manager.list_artifacts()
            if r.artifact_type is ArtifactType.CHECKPOINT
        )
        revoked = manager.revoke(target.artifact_id)
    assert revoked.status is ArtifactStatus.REVOKED
    assert revoked.destroy_token is None
    assert revoked.expires_at == (EPOCH + timedelta(days=11)).isoformat(timespec="seconds")
    # The batch item is marked skipped so a later destroy cannot resurrect it.
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        batches = manager.inventory.list_batches()
        items = manager.inventory.get_batch(batches[0]["destruction_id"])
    assert all(item["item_status"] == "skipped" for item in items)
    verify_audit(workspace.audit_path)
    # Revocation restarts the clock from day 6: the new expiry is day 11,
    # so it stays retained through day 10 and becomes due again on day 11.
    advance(clock, 4)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        assert manager.preview().schedulable == []
    advance(clock, 1)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        assert len(manager.preview().schedulable) == 1
    verify_audit(workspace.audit_path)


def test_revoke_after_grace_ends_is_refused(workspace, inventories, secret_store):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 90, "output": 90, "checkpoint": 5, "report": 90, "manifest": 90},
        grace_days=3,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    advance(clock, 6)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        manager.schedule_due()
        target = next(
            r for r in manager.list_artifacts()
            if r.artifact_type is ArtifactType.CHECKPOINT
        )
        artifact_id = target.artifact_id
    advance(clock, 3)  # grace ended at day 8; now day 9
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        with pytest.raises(LifecycleError, match="grace window"):
            manager.revoke(artifact_id)


# ------------------------------------------------------------- in-flight blocking

def test_inflight_run_blocks_its_artifacts_with_reason(
    workspace, inventories, secret_store
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 1, "output": 1, "checkpoint": 1, "report": 1, "manifest": 1}
    )
    with pytest.raises(PipelineInterrupted) as excinfo:
        execute_run(
            inventories["sqlite"], load_example_policy(), workspace,
            secrets_store=secret_store, batch_size=2, interrupt_after_batches=1,
        )
    run_id = excinfo.value.run_id
    # Register artifacts manually, pointing at the interrupted run's outputs.
    result_stub = _interrupted_stub(workspace, inventories, run_id)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        records = manager.register_run_artifacts(result_stub)
        advance(clock, 2)
        plan = manager.preview()
    assert len(plan.blocked) >= 3
    reasons = {item.artifact.artifact_type: item.blocked_reason for item in plan.blocked}
    assert ArtifactType.CHECKPOINT in reasons
    assert run_id in reasons[ArtifactType.CHECKPOINT]
    assert ArtifactType.PSEUDOMAP in reasons
    assert "in-flight" in reasons[ArtifactType.PSEUDOMAP]
    assert ArtifactType.OUTPUT in reasons
    # Scheduling must skip blocked items entirely.
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        scheduled = manager.schedule_due()
    assert all(
        item.artifact.status is ArtifactStatus.ACTIVE
        for item in scheduled.blocked
    )
    # After the run resumes to completion, blocking clears.
    resumed = execute_run(
        inventories["sqlite"], load_example_policy(), workspace,
        secrets_store=secret_store, batch_size=3, resume_run_id=run_id,
    )
    assert resumed.run_id == run_id
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        plan = manager.preview()
    assert plan.blocked == []


def load_example_policy():
    from maskline.policies import load_policy
    from lifecycle_helpers import EXAMPLE
    return load_policy(EXAMPLE)


def _interrupted_stub(workspace, inventories, run_id):
    from types import SimpleNamespace

    return SimpleNamespace(
        run_id=run_id,
        dataset_fingerprint=inventories["sqlite"].fingerprint,
        output_path=workspace.out_dir
        / f"{inventories['sqlite'].path.stem}.masked.sqlite",
        output_hash=None,
    )


# ------------------------------------------------------------- confirmed destruction

def test_pseudomap_requires_token_and_is_then_unreadable(
    workspace, inventories, secret_store
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 10, "output": 90, "checkpoint": 90, "report": 90, "manifest": 90},
        grace_days=3,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    # A token written before destruction must be resolvable.
    with PseudoMap(workspace.pseudomap_db) as mapping:
        token, plaintext = next(mapping.iter_entries(limit=1))
        assert mapping.reveal(token) == plaintext
    advance(clock, 10)  # retention ends day 10; grace window day 10 -> day 13
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        plan = manager.schedule_due()
        assert any(
            item.artifact.artifact_type is ArtifactType.PSEUDOMAP
            for item in plan.in_grace
        )
        pseudomap = next(
            r for r in manager.list_artifacts()
            if r.artifact_type is ArtifactType.PSEUDOMAP
        )
        artifact_id = pseudomap.artifact_id
        real_token = pseudomap.destroy_token
    advance(clock, 4)  # past the day-13 grace end
    # Without confirmation the mapping is refused even though grace expired.
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        with pytest.raises(LifecycleError, match="destroy token"):
            manager.destroy()
    # Wrong token is also refused.
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        with pytest.raises(LifecycleError, match="destroy token"):
            manager.destroy(confirmations={artifact_id: "dtk-wrong"})
    # The mapping file must still be intact after the refusals.
    assert workspace.pseudomap_db.exists()
    with PseudoMap(workspace.pseudomap_db) as mapping:
        assert mapping.reveal(token) == plaintext
    # Correct token: irreversibly erased, and the audit chain still verifies.
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        result = manager.destroy(confirmations={artifact_id: real_token})
    assert result.ok and result.audit_verified
    assert not workspace.pseudomap_db.exists()
    assert not Path(str(workspace.pseudomap_db) + "-wal").exists()
    with pytest.raises(PseudoMapError):
        PseudoMap(workspace.pseudomap_db)
    verification = verify_audit(workspace.audit_path)
    assert verification.entries >= 1
    entries = AuditLog(workspace.audit_path)
    from maskline.audit import read_audit_entries
    destroyed = [e for e in read_audit_entries(workspace.audit_path)
                 if e.get("event") == "lifecycle.destroyed"]
    assert len(destroyed) == 1
    evidence = destroyed[0]
    assert evidence["artifact_type"] == "pseudomap"
    assert evidence["evidence_hash"] and len(evidence["evidence_hash"]) == 64
    assert evidence["pre_hash"] and evidence["post_hash"]
    assert evidence["pre_hash"] != evidence["post_hash"]
    # The stored chain entry itself anchors the evidence; the evidence hash is
    # independently recomputable from the entry's payload fields.
    assert destroyed[0]["entry_hash"] == verification.head_hash
    from maskline.utils import canonical_json, sha256_text
    chain_keys = ("seq", "prev_hash", "entry_hash", "ts", "event", "evidence_hash")
    payload = {key: value for key, value in evidence.items() if key not in chain_keys}
    assert sha256_text(canonical_json(payload)) == evidence["evidence_hash"]
    # A certificate file was written and references the chained head.
    cert = json.loads((workspace.certificates_dir / "latest.json").read_text())
    assert cert["audit_head_hash"] == verification.head_hash
    assert cert["succeeded"][0]["artifact_id"] == artifact_id
    assert (workspace.certificates_dir / f"{evidence['destruction_id']}.json").exists()
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        row = manager.inventory.get(artifact_id)
    assert row.status is ArtifactStatus.DESTROYED and row.destroy_token is None


def test_non_pseudomap_artifact_destroys_after_grace_without_token(
    workspace, inventories, secret_store
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 90, "output": 5, "checkpoint": 90, "report": 90, "manifest": 90},
        grace_days=2,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    output = workspace.out_dir / f"{inventories['sqlite'].path.stem}.masked.sqlite"
    assert output.exists()
    advance(clock, 6)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        manager.schedule_due()
    advance(clock, 2)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        result = manager.destroy()
    assert result.ok
    assert not output.exists()
    verify_audit(workspace.audit_path)


def test_destroy_refused_inside_grace_window(workspace, inventories, secret_store):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 5, "output": 90, "checkpoint": 90, "report": 90, "manifest": 90},
        grace_days=7,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    advance(clock, 6)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        manager.schedule_due()
        with pytest.raises(LifecycleError, match="grace window"):
            manager.destroy()
    assert workspace.pseudomap_db.exists()


# ------------------------------------------------------------- erasure failure & resume

def test_failed_erasure_is_resumed_to_completion(
    workspace, inventories, secret_store, monkeypatch
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 5, "output": 90, "checkpoint": 90, "report": 90, "manifest": 90},
        grace_days=1,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    advance(clock, 5)  # retention ends day 5; grace window is day 5 -> day 6
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        plan = manager.schedule_due()
        assert any(
            item.artifact.artifact_type is ArtifactType.PSEUDOMAP
            for item in plan.in_grace
        )
        pseudomap = next(
            r for r in manager.list_artifacts()
            if r.artifact_type is ArtifactType.PSEUDOMAP
        )
        token = pseudomap.destroy_token
        artifact_id = pseudomap.artifact_id
    advance(clock, 2)  # past the day-6 grace end

    calls = {"count": 0}
    real_erase = secure_erase

    def flaky_erase(path, *, passes=1):
        calls["count"] += 1
        if calls["count"] == 1:
            raise EraseError("simulated locked file")
        return real_erase(path, passes=passes)

    monkeypatch.setattr("maskline.lifecycle.manager.secure_erase", flaky_erase)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        with pytest.raises(LifecycleError, match="failed to erase"):
            manager.destroy(confirmations={artifact_id: token})
    # The file is still present and the row is FAILED with an audit event.
    assert workspace.pseudomap_db.exists()
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        assert manager.inventory.get(artifact_id).status is ArtifactStatus.FAILED
        outstanding = manager.inventory.outstanding_items()
    assert len(outstanding) == 1 and outstanding[0]["artifact_id"] == artifact_id
    verify_audit(workspace.audit_path)
    # Re-run without monkeypatch: the leftover is cleaned up, no half-deleted state.
    monkeypatch.undo()
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        result = manager.destroy(confirmations={artifact_id: token})
    assert result.ok and len(result.succeeded) == 1
    assert not workspace.pseudomap_db.exists()
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        assert manager.inventory.outstanding_items() == []
        assert manager.inventory.get(artifact_id).status is ArtifactStatus.DESTROYED
    verify_audit(workspace.audit_path)


def test_secure_erase_overwrites_content_before_unlink(tmp_path):
    target = tmp_path / "secret.sqlite"
    target.write_bytes(b"plaintext-key-material" * 100)
    outcomes = secure_erase(target)
    assert not target.exists()
    primary = next(o for o in outcomes if o.path == target)
    assert primary.existed and primary.pre_hash != primary.post_hash
    # Idempotent: a second call on the missing path is not an error.
    again = secure_erase(target)
    assert again[0].existed is False


# ------------------------------------------------------------- audit chain integrity

def test_every_lifecycle_transition_appends_and_chain_verifies(
    workspace, inventories, secret_store
):
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 5, "output": 90, "checkpoint": 90, "report": 90, "manifest": 90},
        grace_days=2,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    baseline = verify_audit(workspace.audit_path).entries
    advance(clock, 6)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        manager.schedule_due()
        pseudomap = next(
            r for r in manager.list_artifacts()
            if r.artifact_type is ArtifactType.PSEUDOMAP
        )
        manager.revoke(pseudomap.artifact_id)
    assert verify_audit(workspace.audit_path).entries == baseline + 2
    # Tamper with a lifecycle entry: verification must fail at that line.
    from maskline.audit import read_audit_entries
    entries = read_audit_entries(workspace.audit_path)
    lines = workspace.audit_path.read_text(encoding="utf-8").splitlines()
    scheduled_index = next(
        i for i, entry in enumerate(entries) if entry.get("event") == "lifecycle.scheduled"
    )
    tampered = json.loads(lines[scheduled_index])
    tampered["items"][0]["path"] = "/tampered"
    lines[scheduled_index] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    workspace.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    from maskline.audit import AuditIntegrityError
    with pytest.raises(AuditIntegrityError):
        verify_audit(workspace.audit_path)


def test_rerun_after_partial_batch_destroys_remaining_items(
    workspace, inventories, secret_store, monkeypatch
):
    """Two items in one batch: first fails, second never runs; retry clears both."""
    clock = pinned_clock()
    policy = custom_policy(
        {"pseudomap": 5, "output": 5, "checkpoint": 90, "report": 90, "manifest": 90},
        grace_days=1,
    )
    run_and_register(workspace, inventories["sqlite"], secret_store, clock, policy)
    output = workspace.out_dir / f"{inventories['sqlite'].path.stem}.masked.sqlite"
    advance(clock, 5)  # inside the day-5 -> day-6 grace window
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        plan = manager.schedule_due()
        pseudomap = next(
            item.artifact for item in plan.in_grace
            if item.artifact.artifact_type is ArtifactType.PSEUDOMAP
        )
        token = pseudomap.destroy_token
        scheduled_types = {
            item.artifact.artifact_type for item in plan.in_grace
        }
        assert ArtifactType.OUTPUT in scheduled_types
    advance(clock, 2)  # past grace
    real_erase = secure_erase

    def fail_pseudomap_only(path, *, passes=1):
        if Path(path) == workspace.pseudomap_db:
            raise EraseError("locked")
        return real_erase(path, passes=passes)

    monkeypatch.setattr("maskline.lifecycle.manager.secure_erase", fail_pseudomap_only)
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        with pytest.raises(LifecycleError, match="failed to erase"):
            manager.destroy(confirmations={pseudomap.artifact_id: token})
    assert workspace.pseudomap_db.exists()
    assert not output.exists()  # the other batch item completed before the failure
    monkeypatch.undo()
    with LifecycleManager(workspace, policy, clock=clock) as manager:
        result = manager.destroy(confirmations={pseudomap.artifact_id: token})
    assert result.ok
    assert not workspace.pseudomap_db.exists()
    verify_audit(workspace.audit_path)
