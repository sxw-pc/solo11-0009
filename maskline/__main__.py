"""Command-line entry point for maskline."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__
from .audit import AuditLog, read_audit_entries
from .config import Paths, SecretStore
from .detectors.engine import detect_inventory
from .policies import PolicyError, load_policy
from .pipeline.checkpoint import CheckpointStore
from .pipeline.runner import PipelineError, execute_run
from .pseudomap import PseudoMap, PseudoMapError
from .registry import inspect_dataset
from .simulation.audit import build_simulation_audit_entry
from .simulation.errors import SimulationError
from .simulation.report import write_comparison_report, write_simulation_report
from .simulation.runner import run_simulation
from .simulation.store import SimulationStore, compare_simulations
from .simulation.workspace import new_simulation_id
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
    simulate = sub.add_parser(
        "simulate",
        parents=[common],
        help="evaluate policy impact on a dataset without writing masking artifacts",
    )
    simulate.add_argument("--dataset", required=True)
    simulate.add_argument("--policy", required=True)
    simulate.add_argument("--sample-size", type=int, default=10_000)
    simulate.add_argument("--batch-size", type=int, default=1000)
    simulate.add_argument(
        "--file-size-threshold", type=int, default=100 * 1024 * 1024,
        help="bytes above which a single file forces streaming sampling mode",
    )
    simulate.add_argument(
        "--linkage", action="append", default=[],
        help="cross-table join key pair, e.g. orders.customer_id=customers.customer_id "
             "(repeatable)",
    )
    simulate.add_argument(
        "--kpi", action="append", default=[],
        help="numeric business KPI column to score, e.g. orders.amount (repeatable)",
    )
    simulate.add_argument(
        "--temp-root", default=None,
        help="root directory for isolated simulation temp data "
             "(default: MASKLINE_SIM_TMP or <workspace>/data/sim-tmp)",
    )
    simulate.add_argument(
        "--no-detect", action="store_true",
        help="skip the sensitive-detection summary",
    )
    simulate.add_argument(
        "--no-save", action="store_true",
        help="do not persist the result for later version comparison",
    )
    simulate.add_argument(
        "--no-report", action="store_true",
        help="print structured JSON to stdout only; skip Markdown/JSON report files",
    )
    diff = sub.add_parser(
        "simulate-diff",
        parents=[common],
        help="compare two stored simulation results across policy versions",
    )
    diff.add_argument("--current", required=True, help="current simulation id")
    diff.add_argument(
        "--previous", default=None,
        help="previous simulation id (default: latest stored run for the same dataset)",
    )
    diff.add_argument(
        "--no-report", action="store_true",
        help="print structured JSON to stdout only; skip report files",
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
        policy_fingerprint = entry.get("policy_fingerprint") or ""
        output_hash = entry.get("output_hash") or ""
        print(
            f"seq={entry.get('seq')} run={entry.get('run_id')} "
            f"event={entry.get('event_type', 'masking_run')} "
            f"rows={entry.get('rows_processed')} "
            f"policy={policy_fingerprint[:16]}... "
            f"output_hash={output_hash[:16]}..."
        )
    return 0


def _record_simulation_audit(paths: Paths, entry: dict[str, Any]) -> None:
    """Append a simulation entry, creating runtime dirs for the audit chain."""
    paths.ensure_runtime_dirs()
    AuditLog(paths.audit_path).append(entry)


def _simulation_secret_store(
    dataset: Path, policy_path: str, paths: Paths
) -> SecretStore | None:
    """Load secrets only when the validated policy actually requires them."""
    inventory = inspect_dataset(dataset)
    policy = load_policy(policy_path)
    policy.validate_against(inventory)
    if not needs_secret(policy, inventory):
        return None
    if os.environ.get("MASKLINE_SECRET_FILE"):
        return SecretStore.from_env()
    # Fall back to the demo secret generated inside this workspace, matching the
    # convention used by `maskline demo`; real deployments set the env var.
    demo_secret = paths.data_dir / "demo-secret.txt"
    if demo_secret.is_file():
        return SecretStore.from_file(demo_secret)
    return SecretStore.from_env()


def _cmd_simulate(args: argparse.Namespace) -> int:
    paths = _paths(args)
    dataset = Path(args.dataset).expanduser().resolve()
    policy_path = Path(args.policy).expanduser().resolve()
    started = time.monotonic()
    # Reserved up front so even pre-run validation failures get a traceable id.
    simulation_id = new_simulation_id()
    try:
        secrets_store = _simulation_secret_store(dataset, args.policy, paths)
        result = run_simulation(
            dataset,
            policy_path,
            paths,
            sample_size=args.sample_size,
            batch_size=args.batch_size,
            file_size_threshold=args.file_size_threshold,
            linkage_pairs=args.linkage,
            kpi_columns=args.kpi,
            secrets_store=secrets_store,
            temp_root=Path(args.temp_root).expanduser() if args.temp_root else None,
            save_result=not args.no_save,
            detect=not args.no_detect,
        )
        simulation_id = result.simulation_id
        report_paths: dict[str, Path] | None = None
        if not args.no_report:
            report_paths = write_simulation_report(
                paths.reports_dir, result.simulation_id, result.document
            )
        audit_entry = build_simulation_audit_entry(
            simulation_id=result.simulation_id,
            document=result.document,
            status=result.status,
            extra={"report": str(report_paths["json"]) if report_paths else None},
        )
        _record_simulation_audit(paths, audit_entry)
        if args.no_report:
            print(json.dumps(result.document, ensure_ascii=False, indent=2))
        else:
            print(
                f"simulation={result.simulation_id} status={result.status} "
                f"rows={result.document['rows_processed']} "
                f"elapsed={result.elapsed_seconds:.3f}s"
            )
            print(f"report={report_paths['markdown']}")
            print(f"json={report_paths['json']}")
            for warning in result.warnings:
                print(f"warning: {warning}", file=sys.stderr)
        return 0
    except Exception as exc:
        # Every simulation attempt, including validation failures, is audited.
        # Handle the failure inside the command so it is recorded before main()
        # converts the error into an exit code.
        entry = build_simulation_audit_entry(
            simulation_id=simulation_id,
            document=None,
            status="failed",
            dataset_path=str(dataset),
            policy_path=str(policy_path),
            elapsed_seconds=time.monotonic() - started,
            error=str(exc),
        )
        try:
            _record_simulation_audit(paths, entry)
        except OSError:
            pass
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _cmd_simulate_diff(args: argparse.Namespace) -> int:
    paths = _paths(args)
    store = SimulationStore(paths=paths)
    current = store.get(args.current)
    if current is None:
        raise SimulationError(f"simulation not found: {args.current}")
    if args.previous:
        previous = store.get(args.previous)
        if previous is None:
            raise SimulationError(f"simulation not found: {args.previous}")
    else:
        previous = store.latest_for_dataset(
            current["dataset"]["fingerprint"], exclude=args.current
        )
        if previous is None:
            raise SimulationError(
                "no previous simulation found for this dataset; "
                "pass --previous explicitly"
            )
    diff = compare_simulations(current, previous)
    if args.no_report:
        print(json.dumps(diff, ensure_ascii=False, indent=2))
        return 0
    report_paths = write_comparison_report(paths.reports_dir, args.current, diff)
    summary = diff["summary"]
    print(
        f"current={args.current} previous={previous['simulation_id']} "
        f"new={summary['newly_covered']} removed={summary['removed_from_policy']} "
        f"modified={summary['modified']} broken_linkages={summary['fully_broken_linkages']}"
    )
    print(f"report={report_paths['markdown']}")
    print(f"json={report_paths['json']}")
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
        "simulate": _cmd_simulate,
        "simulate-diff": _cmd_simulate_diff,
    }
    try:
        return handlers[args.command](args)
    except (MasklineError, PolicyError, PipelineError, PseudoMapError,
            SimulationError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
