"""CLI handlers for the ``maskline lifecycle`` subcommands."""

from __future__ import annotations

from argparse import Namespace

from .lifecycle.clock import Clock
from .lifecycle.manager import LifecycleError, LifecycleManager
from .lifecycle.retention import RetentionPolicy, RetentionPolicyError
from .utils import canonical_json


def _load_policy(args: Namespace) -> RetentionPolicy:
    if getattr(args, "retention_policy", None):
        return RetentionPolicy.from_file(args.retention_policy)
    return RetentionPolicy.default()


def _manager(args: Namespace, clock=None) -> LifecycleManager:
    from .config import Paths

    paths = Paths.for_workspace(args.workspace)
    paths.ensure_runtime_dirs()
    return LifecycleManager(paths, _load_policy(args), clock=clock or Clock.from_env())


def _print_plan(plan, as_json: bool) -> None:
    if as_json:
        print(canonical_json(plan.to_dict()))
        return
    totals = plan.to_dict()["totals"]
    print(
        f"待安排销毁={totals['ready_to_schedule']}  宽限中={totals['in_grace']}  "
        f"宽限已过待确认={totals['grace_expired']}  被在途任务阻止={totals['blocked']}"
    )
    labels = {
        "ready_to_schedule": "到期可安排",
        "in_grace": "宽限中(可撤销)",
        "grace_expired": "宽限已过(确认后销毁)",
        "blocked": "已拒绝",
        "active": "保留中",
        "destroyed": "已销毁",
        "failed": "销毁失败(可重跑)",
    }
    for item in plan.items:
        if item.state == "active":
            continue
        record = item.artifact
        line = (
            f"[{labels.get(item.state, item.state)}] {record.artifact_type.value:10s} "
            f"{record.path}  到期={record.expires_at} 宽限止={record.grace_ends_at}"
        )
        if item.blocked_reason:
            line += f"\n    原因: {item.blocked_reason}"
        if item.state == "grace_expired" and record.destroy_token:
            line += f"\n    确认令牌(销毁时必须回传): {record.destroy_token}"
        print(line)


def cmd_preview(args: Namespace) -> int:
    with _manager(args) as manager:
        plan = manager.preview()
    _print_plan(plan, args.json)
    return 0


def cmd_schedule(args: Namespace) -> int:
    with _manager(args) as manager:
        plan = manager.schedule_due()
    _print_plan(plan, args.json)
    return 0


def cmd_revoke(args: Namespace) -> int:
    with _manager(args) as manager:
        record = manager.revoke(args.artifact_id)
    print(
        f"已撤销 {args.artifact_id} ({record.artifact_type.value})；"
        f"新到期时间={record.expires_at}，新宽限截止={record.grace_ends_at}"
    )
    return 0


def cmd_destroy(args: Namespace) -> int:
    with _manager(args) as manager:
        confirmations: dict[str, str] = {}
        if args.token:
            confirmations = dict(
                pair.split("=", 1) for pair in args.token if "=" in pair
            )
        result = manager.destroy(
            args.destruction_id,
            confirmations=confirmations,
        )
    print(f"销毁批次={result.destruction_id}")
    for evidence in result.succeeded:
        print(
            f"  已销毁 {evidence['artifact_type']:10s} {evidence['path']}  "
            f"证据哈希={evidence['evidence_hash'][:16]}...  审计序号={evidence['audit_seq']}"
        )
    for skipped in result.skipped:
        print(f"  已跳过 {skipped['path']}: {skipped['reason']}")
    for failed in result.failed:
        print(f"  失败 {failed['path']}: {failed['error']}")
    print(
        f"审计链校验={'通过' if result.audit_verified else '未执行'}；"
        f"凭证={result.certificate_path}"
    )
    return 0


def cmd_list(args: Namespace) -> int:
    with _manager(args) as manager:
        records = manager.list_artifacts()
    if args.json:
        print(
            canonical_json(
                [
                    {
                        "artifact_id": record.artifact_id,
                        "type": record.artifact_type.value,
                        "path": str(record.path),
                        "status": record.status.value,
                        "run_id": record.run_id,
                        "expires_at": record.expires_at,
                        "grace_ends_at": record.grace_ends_at,
                    }
                    for record in records
                ]
            )
        )
        return 0
    for record in records:
        print(
            f"{record.artifact_id}  {record.artifact_type.value:10s} "
            f"{record.status.value:13s} 到期={record.expires_at}  {record.path}"
        )
    return 0


def cmd_batches(args: Namespace) -> int:
    with _manager(args) as manager:
        batches = manager.inventory.list_batches()
    for batch in batches:
        print(
            f"{batch['destruction_id']}  总数={batch['total']}  "
            f"成功={batch['succeeded']}  待处理={batch['outstanding']}"
        )
    return 0


LIFECYCLE_HANDLERS = {
    "preview": cmd_preview,
    "schedule": cmd_schedule,
    "revoke": cmd_revoke,
    "destroy": cmd_destroy,
    "list": cmd_list,
    "batches": cmd_batches,
}


def handle_lifecycle(args: Namespace) -> int:
    try:
        return LIFECYCLE_HANDLERS[args.lifecycle_command](args)
    except (LifecycleError, RetentionPolicyError) as exc:
        print(f"error: {exc}")
        return 2
