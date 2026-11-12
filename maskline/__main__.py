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
from .exporter import (
    ExportError,
    execute_export,
    load_export_spec,
    spec_from_options,
    verify_subset,
)
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
    export = sub.add_parser(
        "export", parents=[common],
        help="export a filtered/pruned/sampled subset from a masked product",
    )
    export.add_argument("--spec", default=None, help="YAML export spec path")
    export.add_argument("--source", default=None, help="masked product (SQLite) to export from")
    export.add_argument("--name", default=None, help="export name (quick mode)")
    export.add_argument("--table", action="append", default=None,
                        help="table to include; repeatable, default: all tables")
    export.add_argument("--where", default=None, help="row filter expression (single table)")
    export.add_argument("--columns", default=None, help="comma-separated columns to keep")
    export.add_argument("--exclude-columns", default=None,
                        help="comma-separated columns to drop")
    export.add_argument("--sample", type=float, default=None, help="sampling ratio in (0, 1]")
    export.add_argument("--sample-seed", default=None, help="sampling seed (default: source hash)")
    export.add_argument("--format", choices=["sqlite", "csv"], default=None,
                        help="subset format (default: sqlite)")
    export.add_argument("--output", default=None, help="subset output path")
    export.add_argument("--batch-size", type=int, default=1000)
    export_verify = sub.add_parser(
        "export-verify", parents=[common],
        help="verify a subset against its .export.json provenance manifest",
    )
    export_verify.add_argument("manifest", help="path to the .export.json manifest")
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


def _cmd_export(args: argparse.Namespace) -> int:
    paths = _paths(args)
    if args.spec:
        selection_flags = [
            args.source, args.name, args.table, args.where, args.columns,
            args.exclude_columns, args.sample, args.sample_seed, args.format,
            args.output,
        ]
        if any(flag is not None for flag in selection_flags):
            raise MasklineError("--spec cannot be combined with selection flags")
        spec = load_export_spec(args.spec)
    else:
        if not args.source:
            raise MasklineError("--source is required when no --spec is given")
        spec = spec_from_options(
            source=args.source,
            name=args.name,
            tables=args.table,
            where=args.where,
            columns=args.columns,
            exclude_columns=args.exclude_columns,
            sample=args.sample,
            sample_seed=args.sample_seed,
            fmt=args.format,
            output=args.output,
        )
    result = execute_export(paths, spec, batch_size=args.batch_size)
    print(
        f"export={result.export_id} rows={result.row_count} "
        f"elapsed={result.elapsed_seconds:.3f}s"
    )
    for table, stats in sorted(result.table_stats.items()):
        print(
            f"  {table}: scanned={stats['scanned']} matched={stats['matched']} "
            f"exported={stats['exported']}"
        )
    print(f"subset={result.subset_path} format={result.subset_format}")
    print(f"integrity={result.subset_hash}")
    print(f"provenance={result.provenance_path}")
    print(f"registry={result.registry_path}")
    print(f"audit_seq={result.audit_seq}")
    return 0


def _cmd_export_verify(args: argparse.Namespace) -> int:
    details = verify_subset(args.manifest)
    print(
        f"subset OK: {details['subset']} format={details['format']} "
        f"rows={details['row_count']} integrity={details['integrity'][:16]}... "
        f"export={details['export_id']}"
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
        "export": _cmd_export,
        "export-verify": _cmd_export_verify,
    }
    try:
        return handlers[args.command](args)
    except ExportError as exc:
        print(f"error[{exc.code}]: {exc}", file=sys.stderr)
        return exc.exit_code
    except (MasklineError, PolicyError, PipelineError, PseudoMapError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
