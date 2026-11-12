"""Command-line entry point for maskline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .audit import AuditLog, read_audit_entries
from .config import Paths, SecretStore
from .detectors.engine import detect_inventory
from .gray import (
    GraySnapshot,
    GrayTrialStore,
    purge_expired_trials,
    run_gray_trial,
)
from .policies import PolicyError, load_policy
from .pipeline.checkpoint import CheckpointStore
from .pipeline.runner import PipelineError, execute_run
from .pseudomap import PseudoMap, PseudoMapError
from .registry import inspect_dataset
from .resources import ResourceLimits
from .rule_registry import RuleCatalog, resolve_actor
from .rules import RuleError, load_rule_pack
from .utils import MasklineError
from .workflow import finalize_run, needs_secret, resolve_active_rule_set, scan_paths


def _common() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--workspace", default=None,
        help="runtime workspace directory (default: current directory)",
    )
    return parser


def _parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(prog="maskline", description="Offline sensitive data masker")
    parser.add_argument("--version", action="version", version=f"maskline {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", parents=[common], help="run the full offline demo")
    demo.add_argument("--policy", default=None, help="override the example policy path")
    demo.add_argument("--sample-limit", type=int, default=200)
    demo.add_argument("--batch-size", type=int, default=500)
    scan = sub.add_parser("scan", parents=[common], help="register datasets and detect columns")
    scan.add_argument("target", nargs="?", default="data/raw", help="file or directory")
    scan.add_argument("--sample-limit", type=int, default=200)
    run = sub.add_parser("run", parents=[common], help="mask a dataset with a policy")
    run.add_argument("--dataset", required=True)
    run.add_argument("--policy", required=True)
    run.add_argument("--output", default=None)
    run.add_argument("--batch-size", type=int, default=1000)
    run.add_argument("--sample-limit", type=int, default=200)
    run.add_argument("--dry-run", action="store_true", help="count only; write nothing")
    resume = sub.add_parser("resume", parents=[common], help="resume an interrupted run")
    resume.add_argument("--run-id", required=True)
    resume.add_argument("--batch-size", type=int, default=1000)
    resume.add_argument("--sample-limit", type=int, default=200)
    reveal = sub.add_parser("reveal", parents=[common], help="reveal a pseudonym token")
    reveal.add_argument("--token", required=True)
    audit = sub.add_parser("audit", parents=[common], help="inspect or verify the audit log")
    audit.add_argument("--verify", action="store_true", help="verify the whole hash chain")
    audit.add_argument("--tail", type=int, default=10)

    rules = sub.add_parser(
        "rules", parents=[common], help="manage versioned detector rule sets"
    )
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    rules_add = rules_sub.add_parser(
        "add", parents=[common], help="register a rule pack as a new version"
    )
    rules_add.add_argument("--file", required=True, help="rule pack YAML path")
    rules_add.add_argument("--actor", default=None, help="creator identity")
    rules_sub.add_parser("list", parents=[common], help="list rule versions")
    rules_sub.add_parser("current", parents=[common], help="show the active rule version")
    rules_show = rules_sub.add_parser("show", parents=[common], help="show a rule version")
    rules_show.add_argument("--version", required=True)
    rules_rollback = rules_sub.add_parser(
        "rollback", parents=[common], help="make a historical version active"
    )
    rules_rollback.add_argument("--version", required=True)
    rules_rollback.add_argument("--actor", default=None)
    rules_scope = rules_sub.add_parser(
        "scope", parents=[common], help="set the gray-trial dataset scope"
    )
    rules_scope.add_argument("--version", required=True)
    rules_scope.add_argument(
        "--dataset",
        action="append",
        required=True,
        help="dataset path pattern; may be repeated",
    )
    rules_scope.add_argument("--actor", default=None)

    gray = sub.add_parser(
        "gray", parents=[common], help="run isolated gray-release rule trials"
    )
    gray_sub = gray.add_subparsers(dest="gray_command", required=True)
    gray_run = gray_sub.add_parser(
        "run", parents=[common], help="trial one rule version on one dataset"
    )
    gray_run.add_argument("--rules-version", required=True)
    gray_run.add_argument("--dataset", required=True)
    gray_run.add_argument("--actor", default=None)
    gray_run.add_argument("--sample-limit", type=int, default=200)
    gray_run.add_argument("--cpu-limit", type=int, default=2, help="max CPU cores")
    gray_run.add_argument("--memory-mb", type=int, default=512, help="max memory (MB)")
    gray_run.add_argument(
        "--retention-days", type=int, default=7, help="temporary data retention"
    )
    gray_sub.add_parser("list", parents=[common], help="list gray trials")
    gray_show = gray_sub.add_parser("show", parents=[common], help="show trial findings")
    gray_show.add_argument("--trial-id", required=True)
    gray_sub.add_parser(
        "cleanup", parents=[common], help="remove expired trial snapshots now"
    )
    return parser


def _paths(args: argparse.Namespace) -> Paths:
    return Paths.for_workspace(args.workspace)


def _print_scan(summaries: list[Any]) -> None:
    for summary in summaries:
        inventory = summary.inventory
        print(
            f"{inventory.path}  kind={inventory.kind}  rows={inventory.row_count}  "
            f"fingerprint={inventory.fingerprint[:16]}...  "
            f"{'new' if summary.newly_registered else 'already registered'}"
        )
        for finding in summary.findings:
            if finding["confidence"] in {"high", "medium"}:
                print(
                    f"  ! {finding['table_name']}.{finding['column_name']} -> "
                    f"{finding['sensitive_type']} "
                    f"({finding['confidence']}, score={finding['score']:.2f})"
                )


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo
    run_demo(
        workspace=args.workspace,
        policy_path=args.policy,
        sample_limit=args.sample_limit,
        batch_size=args.batch_size,
    )
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    paths = _paths(args)
    summaries = scan_paths([args.target], paths, sample_limit=args.sample_limit)
    _print_scan(summaries)
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    paths = _paths(args)
    dataset = Path(args.dataset).expanduser().resolve()
    policy = load_policy(args.policy)
    inventory = inspect_dataset(dataset)
    policy.validate_against(inventory)
    if args.dry_run:
        findings = detect_inventory(
            inventory,
            sample_limit=args.sample_limit,
            rule_set=resolve_active_rule_set(paths, create=False),
        )
        secrets_store = SecretStore.from_env() if needs_secret(policy, inventory) else None
    else:
        paths.ensure_runtime_dirs()
        summaries = scan_paths([dataset], paths, sample_limit=args.sample_limit)
        findings = summaries[0].findings
        secrets_store = SecretStore.from_env() if needs_secret(policy, inventory) else None
    result = execute_run(
        inventory,
        policy,
        paths,
        secrets_store=secrets_store,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
        output_path=args.output,
    )
    print(
        f"run={result.run_id} rows={result.row_count} elapsed={result.elapsed_seconds:.3f}s"
    )
    for name, counts in sorted(result.transform_counts.items()):
        print(
            f"  {name}: seen={counts.get('seen', 0)} "
            f"processed={counts.get('processed', 0)} changed={counts.get('changed', 0)}"
        )
    if result.dry_run:
        print("dry-run: no target database, checkpoints, audit entries, or reports written")
        return 0
    artifacts = finalize_run(paths, inventory, policy, result, findings)
    print(f"output={result.output_path}")
    print(f"output_hash={result.output_hash}")
    print(f"report={artifacts['report']['markdown']}")
    print(f"audit_seq={artifacts['audit']['seq']}")
    if result.policy_changed:
        print("note: policy fingerprint differs from the previous manifest for this dataset")
    return 0


def _cmd_resume(args: argparse.Namespace) -> int:
    paths = _paths(args)
    store = CheckpointStore(paths.checkpoint_db)
    try:
        record = store.get_run(args.run_id)
    finally:
        store.close()
    if record is None:
        raise PipelineError(f"unknown run id: {args.run_id}")
    dataset = Path(record.dataset_path)
    inventory = inspect_dataset(dataset)
    if inventory.fingerprint != record.dataset_fingerprint:
        raise PipelineError("dataset content changed since the interrupted run")
    policy = load_policy(record.policy_path)
    if policy.fingerprint != record.policy_fingerprint:
        raise PipelineError("policy changed since the interrupted run")
    summaries = scan_paths([dataset], paths, sample_limit=args.sample_limit)
    findings = summaries[0].findings
    secrets_store = SecretStore.from_env() if needs_secret(policy, inventory) else None
    result = execute_run(
        inventory,
        policy,
        paths,
        secrets_store=secrets_store,
        batch_size=args.batch_size,
        resume_run_id=args.run_id,
    )
    artifacts = finalize_run(paths, inventory, policy, result, findings)
    print(f"resumed={result.run_id} rows={result.row_count}")
    print(f"output={result.output_path}")
    print(f"report={artifacts['report']['markdown']}")
    return 0


def _cmd_reveal(args: argparse.Namespace) -> int:
    paths = _paths(args)
    try:
        with PseudoMap(paths.pseudomap_db) as mapping:
            plaintext = mapping.reveal(args.token)
    except PseudoMapError as exc:
        raise MasklineError(str(exc)) from exc
    print(plaintext)
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    paths = _paths(args)
    if args.verify:
        verification = AuditLog(paths.audit_path).verify()
        print(
            f"audit chain OK: entries={verification.entries} "
            f"head={verification.head_hash}"
        )
        return 0
    if not paths.audit_path.exists():
        raise MasklineError(f"audit log not found: {paths.audit_path}")
    entries = read_audit_entries(paths.audit_path)
    for entry in entries[-args.tail:]:
        print(
            f"seq={entry.get('seq')} run={entry.get('run_id')} "
            f"rows={entry.get('rows_processed')} "
            f"policy={entry.get('policy_fingerprint', '')[:16]}... "
            f"output_hash={entry.get('output_hash', '')[:16]}..."
        )
    return 0


def _cmd_rules_add(args: argparse.Namespace) -> int:
    paths = _paths(args)
    pack = load_rule_pack(args.file)
    with RuleCatalog(
        paths.rules_db, audit_path=paths.audit_path, create=True
    ) as catalog:
        created = catalog.create_version(pack, resolve_actor(args.actor))
    print(
        f"rule_version={created.version} created_by={created.created_by} "
        f"base={created.base_version} fingerprint={created.fingerprint}"
    )
    print(f"detectors={', '.join(created.rule_set.detector_types())}")
    return 0


def _cmd_rules_list(args: argparse.Namespace) -> int:
    paths = _paths(args)
    with RuleCatalog(
        paths.rules_db, audit_path=paths.audit_path, create=True
    ) as catalog:
        active = catalog.active_version_tag()
        records = catalog.list_versions()
    for record in records:
        marker = "*" if record.version == active else " "
        print(
            f"{marker} {record.version}  created_by={record.created_by}  "
            f"base={record.base_version or '-'}  fingerprint={record.fingerprint[:16]}..."
        )
    return 0


def _cmd_rules_current(args: argparse.Namespace) -> int:
    paths = _paths(args)
    with RuleCatalog(paths.rules_db, audit_path=paths.audit_path, create=True) as catalog:
        record = catalog.get_version(catalog.active_version_tag())
    print(
        f"active={record.version} fingerprint={record.fingerprint} "
        f"created_by={record.created_by}"
    )
    return 0


def _cmd_rules_show(args: argparse.Namespace) -> int:
    paths = _paths(args)
    with RuleCatalog(paths.rules_db, audit_path=paths.audit_path, create=True) as catalog:
        record = catalog.get_version(args.version)
        scope = catalog.get_gray_scope(args.version)
    payload = record.to_record()
    payload["gray_scope"] = scope
    payload["spec"] = record.spec
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _cmd_rules_rollback(args: argparse.Namespace) -> int:
    paths = _paths(args)
    with RuleCatalog(paths.rules_db, audit_path=paths.audit_path, create=True) as catalog:
        result = catalog.rollback(args.version, resolve_actor(args.actor))
    print(
        f"rolled_back={result['previous_version']} -> {result['version']} "
        f"actor={result['actor']}"
    )
    return 0


def _cmd_rules_scope(args: argparse.Namespace) -> int:
    paths = _paths(args)
    with RuleCatalog(paths.rules_db, audit_path=paths.audit_path, create=True) as catalog:
        scope = catalog.set_gray_scope(
            args.version, args.dataset, resolve_actor(args.actor)
        )
    print(
        f"gray_scope rule_version={scope['rule_version']} "
        f"datasets={scope['datasets']} updated_by={scope['updated_by']}"
    )
    return 0


def _cmd_gray_run(args: argparse.Namespace) -> int:
    paths = _paths(args)
    limits = ResourceLimits(cpu_cores=args.cpu_limit, memory_mb=args.memory_mb)
    with RuleCatalog(
        paths.rules_db, audit_path=paths.audit_path, create=True
    ) as catalog:
        result = run_gray_trial(
            paths,
            catalog,
            rule_version=args.rules_version,
            dataset=args.dataset,
            actor=resolve_actor(args.actor),
            sample_limit=args.sample_limit,
            limits=limits,
            retention_days=args.retention_days,
            audit_path=paths.audit_path,
        )
    print(
        f"trial={result.trial_id} rule_version={result.rule_version} "
        f"rows_columns={result.findings_count} "
        f"high/medium={result.high_medium_count}"
    )
    print(f"snapshot={result.snapshot_path}")
    print(f"expires_at={result.expires_at}")
    for finding in result.findings:
        if finding["confidence"] in {"high", "medium"}:
            print(
                f"  ! {finding['table_name']}.{finding['column_name']} -> "
                f"{finding['sensitive_type']} "
                f"({finding['confidence']}, score={finding['score']:.2f}, "
                f"rule={finding['rule_version']})"
            )
    return 0


def _cmd_gray_list(args: argparse.Namespace) -> int:
    paths = _paths(args)
    purge_expired_trials(paths, audit_path=paths.audit_path)
    with GrayTrialStore(paths.gray_db) as store:
        records = store.list()
    for record in records:
        print(
            f"{record.trial_id}  rule={record.rule_version}  status={record.status}  "
            f"high/medium={record.high_medium_count}  expires={record.expires_at}"
        )
    return 0


def _cmd_gray_show(args: argparse.Namespace) -> int:
    paths = _paths(args)
    purge_expired_trials(paths, audit_path=paths.audit_path)
    with GrayTrialStore(paths.gray_db) as store:
        record = store.get(args.trial_id)
    if record is None:
        raise MasklineError(f"gray trial not found: {args.trial_id}")
    with GraySnapshot(record.snapshot_path, create=False) as snapshot:
        findings = snapshot.findings()
    print(
        f"trial={record.trial_id} rule={record.rule_version} "
        f"status={record.status} actor={record.actor}"
    )
    for finding in findings:
        print(
            f"  {finding['table_name']}.{finding['column_name']} -> "
            f"{finding['sensitive_type']} ({finding['confidence']}, "
            f"score={finding['score']:.2f}, rule={finding['rule_version']})"
        )
    return 0


def _cmd_gray_cleanup(args: argparse.Namespace) -> int:
    paths = _paths(args)
    removed = purge_expired_trials(paths, audit_path=paths.audit_path)
    print(f"expired_trials_removed={len(removed)}")
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    handlers = {
        "add": _cmd_rules_add,
        "list": _cmd_rules_list,
        "current": _cmd_rules_current,
        "show": _cmd_rules_show,
        "rollback": _cmd_rules_rollback,
        "scope": _cmd_rules_scope,
    }
    return handlers[args.rules_command](args)


def _cmd_gray(args: argparse.Namespace) -> int:
    handlers = {
        "run": _cmd_gray_run,
        "list": _cmd_gray_list,
        "show": _cmd_gray_show,
        "cleanup": _cmd_gray_cleanup,
    }
    return handlers[args.gray_command](args)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    handlers = {
        "demo": _cmd_demo,
        "scan": _cmd_scan,
        "run": _cmd_run,
        "resume": _cmd_resume,
        "reveal": _cmd_reveal,
        "audit": _cmd_audit,
        "rules": _cmd_rules,
        "gray": _cmd_gray,
    }
    try:
        return handlers[args.command](args)
    except (
        MasklineError,
        PolicyError,
        PipelineError,
        PseudoMapError,
        RuleError,
        FileNotFoundError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
