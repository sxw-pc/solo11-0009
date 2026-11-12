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
from .overrides import (
    OverrideError,
    load_default_overrides,
    load_overrides,
    resolve_operator,
)
from .policies import PolicyError, load_policy
from .pipeline.checkpoint import CheckpointStore
from .pipeline.runner import PipelineError, execute_run
from .pseudomap import PseudoMap, PseudoMapError
from .registry import inspect_dataset
from .utils import MasklineError
from .workflow import finalize_run, merge_run_findings, needs_secret, scan_paths


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
        "--overrides", default=None,
        help="override YAML file (default: <workspace>/overrides.yaml if present)",
    )
    scan.add_argument(
        "--no-overrides", action="store_true",
        help="ignore overrides entirely, including the workspace default file",
    )
    scan.add_argument("--operator", default=None, help="override operator identity")
    run = sub.add_parser("run", parents=[common], help="mask a dataset with a policy")
    run.add_argument("--dataset", required=True)
    run.add_argument("--policy", required=True)
    run.add_argument("--output", default=None)
    run.add_argument(
        "--overrides", default=None,
        help="override YAML file (default: <workspace>/overrides.yaml if present)",
    )
    run.add_argument(
        "--no-overrides", action="store_true",
        help="ignore overrides entirely, including the workspace default file",
    )
    run.add_argument("--operator", default=None, help="override operator identity")
    run.add_argument("--batch-size", type=int, default=1000)
    run.add_argument("--sample-limit", type=int, default=200)
    run.add_argument("--dry-run", action="store_true", help="count only; write nothing")
    resume = sub.add_parser("resume", parents=[common], help="resume an interrupted run")
    resume.add_argument("--run-id", required=True)
    resume.add_argument("--batch-size", type=int, default=1000)
    resume.add_argument("--sample-limit", type=int, default=200)
    resume.add_argument(
        "--overrides", default=None,
        help="override YAML file (default: <workspace>/overrides.yaml if present)",
    )
    resume.add_argument(
        "--no-overrides", action="store_true",
        help="ignore overrides entirely, including the workspace default file",
    )
    reveal = sub.add_parser("reveal", parents=[common], help="reveal a pseudonym token")
    reveal.add_argument("--token", required=True)
    audit = sub.add_parser("audit", parents=[common], help="inspect or verify the audit log")
    audit.add_argument("--verify", action="store_true", help="verify the whole hash chain")
    audit.add_argument("--tail", type=int, default=10)
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
            if finding["confidence"] not in {"high", "medium"}:
                continue
            override = finding.get("override")
            marker = "=" if override else "!"
            suffix = (
                f"  [人工裁定 {override['decision']}: {override['reason']}]"
                if override
                else ""
            )
            source_note = ""
            if override and override["decision"] == "force_sensitive":
                source_note = (
                    f"  (检测器原始结论: {finding.get('detected_type') or 'none'}, "
                    f"{finding.get('detected_confidence') or 'none'})"
                )
            print(
                f"  {marker} {finding['table_name']}.{finding['column_name']} -> "
                f"{finding['sensitive_type']} "
                f"({finding['confidence']}, score={finding['score']:.2f})"
                f"{suffix}{source_note}"
            )
        for finding in summary.findings:
            override = finding.get("override")
            if not override or override["decision"] != "force_not_sensitive":
                continue
            print(
                f"  ~ {finding['table_name']}.{finding['column_name']} -> "
                f"non-sensitive (人工裁定 force_not_sensitive: {override['reason']}; "
                f"检测器原始结论: {finding.get('detected_type') or 'none'}, "
                f"{finding.get('detected_confidence') or 'none'})"
            )
        for conflict in (summary.adjudications.conflicts if summary.adjudications else []):
            print(
                f"  ! conflict: {conflict.table}.{conflict.column} adjudicated "
                f"force_not_sensitive but policy still applies "
                f"'{conflict.transformer}'; masking is kept"
            )
        for item in summary.unmatched:
            print(
                f"  ! unmatched adjudication: {item.entry.dataset_pattern} "
                f"{item.entry.table}.{item.entry.column} "
                f"({item.entry.decision}): {item.reason}"
            )
        applied = summary.adjudications
        if (
            applied is not None
            and not applied.policy_checked
            and any(
                item["decision"] == "force_not_sensitive" for item in applied.applied
            )
        ):
            print(
                "  note: scan has no policy, so force_not_sensitive/policy conflicts "
                "are not evaluated; run re-checks and keeps masking on conflicts"
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
    explicit_overrides, use_default = _override_inputs(args)
    summaries = scan_paths(
        [args.target],
        paths,
        sample_limit=args.sample_limit,
        overrides=explicit_overrides,
        use_default_overrides=use_default,
        operator=resolve_operator(args.operator),
    )
    _print_scan(summaries)
    return 0


def _override_inputs(args: argparse.Namespace) -> tuple[Any, bool]:
    """Return (explicit overrides or None, whether to load the workspace default).

    --no-overrides wins only when --overrides is absent; combining them is a
    usage error. With neither flag the workspace `overrides.yaml` is used if it
    exists. `load_default_overrides` calls `load_overrides`, so the operator
    requirement applies to any file with entries, default or explicit.
    """
    explicit = getattr(args, "overrides", None)
    if getattr(args, "no_overrides", False):
        if explicit:
            raise OverrideError("--overrides and --no-overrides are mutually exclusive")
        return None, False
    if explicit:
        return (
            load_overrides(explicit, operator=resolve_operator(getattr(args, "operator", None))),
            False,
        )
    return None, True


def _cmd_run(args: argparse.Namespace) -> int:
    paths = _paths(args)
    dataset = Path(args.dataset).expanduser().resolve()
    policy = load_policy(args.policy)
    inventory = inspect_dataset(dataset)
    policy.validate_against(inventory)
    explicit_overrides, use_default = _override_inputs(args)
    if args.dry_run:
        if explicit_overrides is not None:
            overrides = explicit_overrides
        elif use_default:
            overrides = load_default_overrides(
                paths, operator=resolve_operator(args.operator)
            )
        else:
            overrides = None
        findings = detect_inventory(inventory, sample_limit=args.sample_limit)
        findings, adjudications = merge_run_findings(
            inventory, findings, overrides, policy
        )
        _print_adjudication_notes(adjudications)
        secrets_store = SecretStore.from_env() if needs_secret(policy, inventory) else None
    else:
        paths.ensure_runtime_dirs()
        summaries = scan_paths(
            [dataset],
            paths,
            sample_limit=args.sample_limit,
            overrides=explicit_overrides,
            policy=policy,
            use_default_overrides=use_default,
            operator=resolve_operator(args.operator),
            audit_adjudications=False,
        )
        findings = summaries[0].findings
        adjudications = summaries[0].adjudications
        _print_adjudication_notes(adjudications)
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
        paths, inventory, policy, result, findings, adjudications=adjudications
    )
    print(f"output={result.output_path}")
    print(f"output_hash={result.output_hash}")
    print(f"report={artifacts['report']['markdown']}")
    print(f"audit_seq={artifacts['audit']['seq']}")
    if result.policy_changed:
        print("note: policy fingerprint differs from the previous manifest for this dataset")
    return 0


def _print_adjudication_notes(adjudications: Any | None) -> None:
    if adjudications is None:
        return
    for conflict in adjudications.conflicts:
        print(
            f"  ! conflict: {conflict.table}.{conflict.column} adjudicated "
            f"force_not_sensitive but policy still applies "
            f"'{conflict.transformer}'; masking is kept (never under-mask)"
        )
    for item in adjudications.unmatched:
        print(f"  ! unmatched adjudication ({item.kind}): {item.reason}")


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
    # Only the workspace default is considered here; --overrides/--no-overrides
    # stay accepted so resume shares the same CLI surface as run.
    _, use_default = _override_inputs(args)
    overrides = None
    if use_default:
        overrides = load_default_overrides(
            paths, operator=resolve_operator(getattr(args, "operator", None))
        )
    summaries = scan_paths(
        [dataset],
        paths,
        sample_limit=args.sample_limit,
        overrides=overrides,
        policy=policy,
        use_default_overrides=False,
        operator=resolve_operator(getattr(args, "operator", None)),
        audit_adjudications=False,
    )
    findings = summaries[0].findings
    adjudications = summaries[0].adjudications
    _print_adjudication_notes(adjudications)
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
        paths, inventory, policy, result, findings, adjudications=adjudications
    )
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
    }
    try:
        return handlers[args.command](args)
    except (
        MasklineError,
        PolicyError,
        PipelineError,
        PseudoMapError,
        OverrideError,
        FileNotFoundError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
