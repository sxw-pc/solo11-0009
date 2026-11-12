"""Command-line entry point for maskline."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .audit import AuditLog, read_audit_entries
from .config import Paths, SecretStore
from .detectors.engine import detect_inventory
from .linkage.ignore import EMPTY_RULES, load_ignore_rules
from .linkage.model import LEVEL_LABELS
from .linkage.scan import LinkScanOptions, run_linkscan
from .linkage.store import LinkStore
from .policies import PolicyError, load_policy
from .pipeline.checkpoint import CheckpointStore
from .pipeline.runner import PipelineError, execute_run
from .pseudomap import PseudoMap, PseudoMapError
from .registry import inspect_dataset
from .utils import MasklineError
from .workflow import finalize_run, needs_secret, scan_paths


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
    linkscan = sub.add_parser(
        "linkscan", parents=[common],
        help="scan datasets for cross-dataset sensitive linkage risk",
    )
    linkscan.add_argument("target", nargs="?", default="data/raw", help="file or directory")
    linkscan.add_argument("--sample-limit", type=int, default=500)
    linkscan.add_argument("--workers", type=int, default=4)
    linkscan.add_argument("--max-open-files", type=int, default=None)
    linkscan.add_argument("--min-containment", type=float, default=0.6)
    linkscan.add_argument("--min-overlap", type=int, default=3)
    linkscan.add_argument("--ignore-rules", default=None, help="YAML ignore rules file")
    linkscan.add_argument(
        "--export-policy", action="store_true",
        help="also write a suggested masking policy YAML",
    )
    linkscan.add_argument(
        "--full-rescan", action="store_true",
        help="re-profile every dataset instead of reusing cached profiles",
    )
    links = sub.add_parser(
        "links", parents=[common],
        help="show the latest stored linkage graph and risk list",
    )
    links.add_argument("--version", type=int, default=None, help="version to show")
    linkdemo = sub.add_parser(
        "linkdemo", parents=[common],
        help="generate linkage fixtures and run a linkage scan",
    )
    linkdemo.add_argument("--sample-limit", type=int, default=500)
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
        findings = detect_inventory(inventory, sample_limit=args.sample_limit)
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


def _print_linkscan(outcome: Any) -> None:
    stats = outcome.stats
    print(f"linkscan scan={outcome.scan_id} version=v{outcome.version_no}")
    print(
        f"files: seen={stats['files_seen']} profiled={stats['files_profiled']} "
        f"reused={stats['files_reused']} skipped={stats['files_skipped']} "
        f"removed={stats['files_removed']} ignored={stats['files_ignored']}"
    )
    print(
        f"edges: equals={len(outcome.graph.equality_edges)} "
        f"semantic={len(outcome.graph.semantic_edges)} "
        f"clusters={len(outcome.graph.clusters)}"
    )
    counts = Counter(risk.level for risk in outcome.risks)
    if counts:
        summary = ", ".join(
            f"{level}={counts[level]}"
            for level in ("critical", "high", "medium", "low")
            if counts.get(level)
        )
        print(f"risks: {summary}")
    else:
        print("risks: none")
    for risk in outcome.risks:
        print(
            f"  {risk.risk_id} [{LEVEL_LABELS.get(risk.level, risk.level)}] "
            f"score={risk.score:.2f} {risk.summary}"
        )
    for warning in outcome.warnings:
        print(f"  warning: {warning.path} ({warning.stage}): {warning.message}")
    print(f"report: {outcome.reports['markdown']}")
    if "policy" in outcome.reports:
        print(f"policy: {outcome.reports['policy']}")


def _cmd_linkscan(args: argparse.Namespace) -> int:
    paths = _paths(args)
    ignore_rules = (
        load_ignore_rules(args.ignore_rules) if args.ignore_rules else EMPTY_RULES
    )
    options = LinkScanOptions(
        sample_limit=args.sample_limit,
        workers=args.workers,
        max_open_files=args.max_open_files,
        min_containment=args.min_containment,
        min_overlap=args.min_overlap,
        full_rescan=args.full_rescan,
        export_policy=args.export_policy,
    )
    outcome = run_linkscan(paths, args.target, options, ignore_rules)
    _print_linkscan(outcome)
    return 0


def _cmd_links(args: argparse.Namespace) -> int:
    paths = _paths(args)
    store = LinkStore(paths.linkgraph_db)
    try:
        latest = store.latest_scan()
        if latest is None:
            print("no linkage scan recorded yet; run linkscan first")
            return 0
        version = args.version or latest["version_no"]
        risks = store.risks_for(version)
        edges = store.edges_for(version)
        equals = sum(1 for edge in edges if edge.kind == "equals")
        semantic = sum(1 for edge in edges if edge.kind == "semantic")
        print(
            f"version=v{version} scan={latest['scan_id']} "
            f"finished={latest['finished_at']}"
        )
        print(f"edges: equals={equals} semantic={semantic} risks={len(risks)}")
        for risk in risks:
            print(
                f"  {risk.risk_id} [{LEVEL_LABELS.get(risk.level, risk.level)}] "
                f"score={risk.score:.2f} {risk.summary}"
            )
            for dataset in risk.datasets:
                print(f"    dataset: {dataset}")
    finally:
        store.close()
    return 0


def _cmd_linkdemo(args: argparse.Namespace) -> int:
    from .fixturegen import generate_linkage_fixture
    paths = _paths(args)
    paths.ensure_runtime_dirs()
    fixtures = generate_linkage_fixture(paths.linkraw_dir)
    print(f"Fixtures: {', '.join(path.name for path in fixtures.values())}")
    options = LinkScanOptions(sample_limit=args.sample_limit, export_policy=True)
    outcome = run_linkscan(paths, paths.linkraw_dir, options)
    _print_linkscan(outcome)
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
        "linkscan": _cmd_linkscan,
        "links": _cmd_links,
        "linkdemo": _cmd_linkdemo,
    }
    try:
        return handlers[args.command](args)
    except (MasklineError, PolicyError, PipelineError, PseudoMapError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
