"""Command-line entry point for maskline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .audit import AuditLog, read_audit_entries
from .config import Paths, SecretStore
from .detectors.engine import detect_inventory
from .drift import load_ignore_rules
from .policies import PolicyError, load_policy
from .pipeline.checkpoint import CheckpointStore
from .pipeline.runner import PipelineError, execute_run
from .pseudomap import PseudoMap, PseudoMapError
from .registry import inspect_dataset
from .utils import MasklineError
from .workflow import (
    compare_dataset_versions,
    finalize_run,
    needs_secret,
    scan_paths,
)


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
    scan.add_argument(
        "--ignore-rules", default=None,
        help="YAML file with drift-ignore rules (fingerprinted like a policy)",
    )
    run = sub.add_parser("run", parents=[common], help="mask a dataset with a policy")
    run.add_argument("--dataset", required=True)
    run.add_argument("--policy", required=True)
    run.add_argument("--output", default=None)
    run.add_argument("--batch-size", type=int, default=1000)
    run.add_argument("--sample-limit", type=int, default=200)
    run.add_argument(
        "--ignore-rules", default=None,
        help="YAML file with drift-ignore rules (fingerprinted like a policy)",
    )
    run.add_argument("--dry-run", action="store_true", help="count only; write nothing")
    resume = sub.add_parser("resume", parents=[common], help="resume an interrupted run")
    resume.add_argument("--run-id", required=True)
    resume.add_argument("--batch-size", type=int, default=1000)
    resume.add_argument("--sample-limit", type=int, default=200)
    drift = sub.add_parser(
        "drift", parents=[common],
        help="compare the two latest registered versions of a dataset",
    )
    drift.add_argument("--dataset", required=True, help="dataset file path")
    drift.add_argument(
        "--ignore-rules", default=None,
        help="YAML file with drift-ignore rules (fingerprinted like a policy)",
    )
    reveal = sub.add_parser("reveal", parents=[common], help="reveal a pseudonym token")
    reveal.add_argument("--token", required=True)
    audit = sub.add_parser("audit", parents=[common], help="inspect or verify the audit log")
    audit.add_argument("--verify", action="store_true", help="verify the whole hash chain")
    audit.add_argument("--tail", type=int, default=10)
    return parser


def _paths(args: argparse.Namespace) -> Paths:
    return Paths.for_workspace(args.workspace)


def _load_ignore_rules(args: argparse.Namespace) -> Any:
    path = getattr(args, "ignore_rules", None)
    return load_ignore_rules(path) if path else None


def _print_drift(report: Any) -> None:
    summary = report.summary()
    print(
        f"  drift vs {report.baseline_fingerprint[:16]}...: "
        f"{summary['active']} active event(s), {summary['suppressed']} ignored "
        f"(audit seq={report.audit_seq})"
    )
    for event in report.events:
        print(
            f"    ! [{event.severity}] {event.drift_type} "
            f"{event.table}.{event.column}"
        )


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
        if summary.drift is not None:
            _print_drift(summary.drift)


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
    summaries = scan_paths(
        [args.target], paths,
        sample_limit=args.sample_limit,
        ignore_rules=_load_ignore_rules(args),
    )
    _print_scan(summaries)
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    paths = _paths(args)
    dataset = Path(args.dataset).expanduser().resolve()
    policy = load_policy(args.policy)
    inventory = inspect_dataset(dataset)
    policy.validate_against(inventory)
    if args.dry_run:
        findings = detect_inventory(inventory, sample_limit=args.sample_limit)
        secrets_store = SecretStore.from_env() if needs_secret(policy, inventory) else None
        drift = None
    else:
        paths.ensure_runtime_dirs()
        summaries = scan_paths(
            [dataset], paths,
            sample_limit=args.sample_limit,
            ignore_rules=_load_ignore_rules(args),
        )
        findings = summaries[0].findings
        drift = summaries[0].drift
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
    artifacts = finalize_run(paths, inventory, policy, result, findings, drift=drift)
    if drift is not None:
        _print_drift(drift)
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


def _drift_side_text(side: Any) -> str:
    if side is None:
        return "-"
    sensitive_type = side.get("sensitive_type") or "non-sensitive"
    return f"{sensitive_type}/{side.get('confidence', 'none')}"


def _cmd_drift(args: argparse.Namespace) -> int:
    paths = _paths(args)
    report = compare_dataset_versions(
        paths, args.dataset, ignore_rules=_load_ignore_rules(args)
    )
    if report is None:
        print(
            "no comparable registered versions: scan the dataset at least once "
            "before and once after a content change"
        )
        return 0
    summary = report.summary()
    print(f"dataset={report.dataset_path}")
    print(f"baseline={report.baseline_fingerprint}")
    print(f"current ={report.current_fingerprint}")
    print(f"ignore_rules_fingerprint={report.ignore_fingerprint or 'none'}")
    print(
        f"active={summary['active']} "
        f"(added={summary['field_added']} removed={summary['field_removed']} "
        f"type={summary['type_changed']} level={summary['level_changed']}) "
        f"suppressed={summary['suppressed']}"
    )
    for event in report.events:
        print(
            f"  [{event.severity}] {event.drift_type} {event.table}.{event.column}: "
            f"{_drift_side_text(event.old)} -> {_drift_side_text(event.new)}"
        )
    for item in report.suppressed:
        print(
            f"  [ignored by rule {item.rule_index}] {item.event.drift_type} "
            f"{item.event.table}.{item.event.column}"
        )
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
        if entry.get("kind") == "dataset_drift":
            summary = entry.get("summary", {})
            print(
                f"seq={entry.get('seq')} drift "
                f"events={summary.get('active', 0)} "
                f"suppressed={summary.get('suppressed', 0)} "
                f"baseline={entry.get('baseline_fingerprint', '')[:16]}... "
                f"current={entry.get('current_fingerprint', '')[:16]}..."
            )
        else:
            print(
                f"seq={entry.get('seq')} run={entry.get('run_id')} "
                f"rows={entry.get('rows_processed')} "
                f"policy={entry.get('policy_fingerprint', '')[:16]}... "
                f"output_hash={entry.get('output_hash', '')[:16]}..."
            )
    return 0


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
        "drift": _cmd_drift,
    }
    try:
        return handlers[args.command](args)
    except (MasklineError, PolicyError, PipelineError, PseudoMapError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
