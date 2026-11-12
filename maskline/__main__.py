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
from .drift import (
    DriftRecord,
    evaluate_version_drift,
    record_drift_comparison,
    verify_registry_drift_records,
)
from .policies import PolicyError, load_policy
from .pipeline.checkpoint import CheckpointStore
from .pipeline.runner import PipelineError, execute_run
from .pseudomap import PseudoMap, PseudoMapError
from .registry import Catalog, inspect_dataset
from .utils import MasklineError
from .workflow import (
    finalize_run,
    load_and_pin_ignore_rules,
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


def _drift_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ignore-rules",
        default=None,
        help="YAML file with fingerprint-verified drift ignore rules",
    )
    parser.add_argument(
        "--repin-ignore-rules",
        action="store_true",
        help="accept a changed ignore-rules fingerprint and update the registry pin",
    )
    parser.add_argument(
        "--drift-tolerance",
        type=float,
        default=0.05,
        help="sampling tolerance for hit/validate rate changes (default: 0.05)",
    )


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
    _drift_options(scan)
    run = sub.add_parser("run", parents=[common], help="mask a dataset with a policy")
    run.add_argument("--dataset", required=True)
    run.add_argument("--policy", required=True)
    run.add_argument("--output", default=None)
    run.add_argument("--batch-size", type=int, default=1000)
    run.add_argument("--sample-limit", type=int, default=200)
    run.add_argument("--dry-run", action="store_true", help="count only; write nothing")
    _drift_options(run)
    resume = sub.add_parser("resume", parents=[common], help="resume an interrupted run")
    resume.add_argument("--run-id", required=True)
    resume.add_argument("--batch-size", type=int, default=1000)
    resume.add_argument("--sample-limit", type=int, default=200)
    _drift_options(resume)
    reveal = sub.add_parser("reveal", parents=[common], help="reveal a pseudonym token")
    reveal.add_argument("--token", required=True)
    audit = sub.add_parser("audit", parents=[common], help="inspect or verify the audit log")
    audit.add_argument("--verify", action="store_true", help="verify the whole hash chain")
    audit.add_argument("--tail", type=int, default=10)
    drift = sub.add_parser(
        "drift",
        parents=[common],
        help="compare two registered dataset versions (registry-only, offline)",
    )
    drift.add_argument("--dataset", default=None, help="dataset path; newest version is current")
    drift.add_argument("--current-fingerprint", default=None)
    drift.add_argument("--baseline-fingerprint", default=None)
    drift.add_argument("--list", action="store_true", help="list recorded comparisons")
    drift.add_argument("--json", action="store_true", help="print the comparison as JSON")
    _drift_options(drift)
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


def _print_drift(record: DriftRecord | None) -> None:
    if record is None:
        return
    payload = record.to_report_dict()
    summary = payload["summary"]
    print(
        f"drift baseline={payload['baseline_fingerprint'][:16]}... "
        f"current={payload['current_fingerprint'][:16]}... "
        f"total={summary.get('total', 0)} ignored={summary.get('ignored', 0)} "
        f"audit_seq={payload['audit_seq']}"
    )
    for item in payload["drifts"]:
        print(
            f"  ! {item['drift_type']} {item['table']}.{item['column']} "
            f"severity={item['severity']}"
        )


def _record_drift(paths: Paths, summaries: list[Any]) -> None:
    for summary in summaries:
        if summary.drift is None:
            continue
        with Catalog(paths.meta_db) as catalog:
            record = record_drift_comparison(paths, catalog, summary.drift)
        _print_drift(record)


def _cmd_scan(args: argparse.Namespace) -> int:
    paths = _paths(args)
    if args.drift_tolerance < 0:
        raise MasklineError("drift tolerance must be non-negative")
    ignore_rules = load_and_pin_ignore_rules(
        paths, args.ignore_rules, repin=args.repin_ignore_rules
    )
    summaries = scan_paths(
        [args.target],
        paths,
        sample_limit=args.sample_limit,
        ignore_rules=ignore_rules,
        hit_rate_tolerance=args.drift_tolerance,
    )
    _print_scan(summaries)
    _record_drift(paths, summaries)
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    paths = _paths(args)
    if args.drift_tolerance < 0:
        raise MasklineError("drift tolerance must be non-negative")
    dataset = Path(args.dataset).expanduser().resolve()
    policy = load_policy(args.policy)
    inventory = inspect_dataset(dataset)
    policy.validate_against(inventory)
    drift = None
    if args.dry_run:
        findings = detect_inventory(inventory, sample_limit=args.sample_limit)
        secrets_store = SecretStore.from_env() if needs_secret(policy, inventory) else None
    else:
        paths.ensure_runtime_dirs()
        ignore_rules = load_and_pin_ignore_rules(
            paths, args.ignore_rules, repin=args.repin_ignore_rules
        )
        summaries = scan_paths(
            [dataset],
            paths,
            sample_limit=args.sample_limit,
            ignore_rules=ignore_rules,
            hit_rate_tolerance=args.drift_tolerance,
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
    artifacts = finalize_run(
        paths, inventory, policy, result, findings, drift_comparison=drift
    )
    print(f"output={result.output_path}")
    print(f"output_hash={result.output_hash}")
    print(f"report={artifacts['report']['markdown']}")
    print(f"audit_seq={artifacts['audit']['seq']}")
    _print_drift(artifacts["drift"])
    if result.policy_changed:
        print("note: policy fingerprint differs from the previous manifest for this dataset")
    return 0


def _cmd_resume(args: argparse.Namespace) -> int:
    paths = _paths(args)
    if args.drift_tolerance < 0:
        raise MasklineError("drift tolerance must be non-negative")
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
    ignore_rules = load_and_pin_ignore_rules(
        paths, args.ignore_rules, repin=args.repin_ignore_rules
    )
    summaries = scan_paths(
        [dataset],
        paths,
        sample_limit=args.sample_limit,
        ignore_rules=ignore_rules,
        hit_rate_tolerance=args.drift_tolerance,
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
        resume_run_id=args.run_id,
    )
    artifacts = finalize_run(
        paths, inventory, policy, result, findings, drift_comparison=drift
    )
    print(f"resumed={result.run_id} rows={result.row_count}")
    print(f"output={result.output_path}")
    print(f"report={artifacts['report']['markdown']}")
    _print_drift(artifacts["drift"])
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
        drift_records = verify_registry_drift_records(paths)
        print(
            f"audit chain OK: entries={verification.entries} "
            f"drift_records={drift_records} head={verification.head_hash}"
        )
        return 0
    if not paths.audit_path.exists():
        raise MasklineError(f"audit log not found: {paths.audit_path}")
    entries = read_audit_entries(paths.audit_path)
    for entry in entries[-args.tail:]:
        if entry.get("kind") == "drift_comparison":
            summary = entry.get("summary", {})
            print(
                f"seq={entry.get('seq')} kind=drift "
                f"baseline={str(entry.get('baseline_fingerprint', ''))[:16]}... "
                f"current={str(entry.get('current_fingerprint', ''))[:16]}... "
                f"total={summary.get('total', 0)} ignored={summary.get('ignored', 0)}"
            )
            continue
        print(
            f"seq={entry.get('seq')} run={entry.get('run_id')} "
            f"rows={entry.get('rows_processed')} "
            f"policy={entry.get('policy_fingerprint', '')[:16]}... "
            f"output_hash={entry.get('output_hash', '')[:16]}..."
        )
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    paths = _paths(args)
    if args.drift_tolerance < 0:
        raise MasklineError("drift tolerance must be non-negative")
    ignore_rules = load_and_pin_ignore_rules(
        paths, args.ignore_rules, repin=args.repin_ignore_rules
    )
    with Catalog(paths.meta_db) as catalog:
        if args.list:
            records = catalog.list_drift_comparisons(args.dataset)
            for record in records:
                summary = record.get("summary", {})
                print(
                    f"dataset={record['dataset_path']} "
                    f"baseline={record['baseline_fingerprint'][:16]}... "
                    f"current={record['current_fingerprint'][:16]}... "
                    f"total={summary.get('total', 0)} "
                    f"ignored={summary.get('ignored', 0)} "
                    f"audit_seq={record.get('audit_seq')}"
                )
            return 0

        current_fingerprint = args.current_fingerprint
        if args.dataset:
            resolved = str(Path(args.dataset).expanduser().resolve())
            versions = catalog.dataset_versions(resolved)
            if not versions:
                raise MasklineError(f"dataset is not registered: {resolved}")
            if current_fingerprint is None:
                current_fingerprint = versions[0]["fingerprint"]
            dataset_path = resolved
        elif current_fingerprint is not None:
            current_meta = catalog.get_dataset(current_fingerprint)
            if current_meta is None:
                raise MasklineError(
                    f"dataset fingerprint is not registered: {current_fingerprint}"
                )
            dataset_path = Path(current_meta["path"])
        else:
            raise MasklineError(
                "drift requires --dataset or --current-fingerprint"
            )

        baseline_fingerprint = args.baseline_fingerprint
        if baseline_fingerprint is None:
            baseline = catalog.previous_version(dataset_path, current_fingerprint)
            if baseline is None:
                print("no previous registered version; nothing to compare")
                return 0
            baseline_fingerprint = baseline["fingerprint"]
        comparison = evaluate_version_drift(
            catalog,
            dataset_path,
            current_fingerprint,
            baseline_fingerprint=baseline_fingerprint,
            ignore_rules=ignore_rules,
            tolerance=args.drift_tolerance,
        )
        if comparison is None:
            print("no previous registered version; nothing to compare")
            return 0
        record = record_drift_comparison(paths, catalog, comparison)
    if args.json:
        print(json.dumps(record.to_report_dict(), ensure_ascii=False, indent=2))
    else:
        _print_drift(record)
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
