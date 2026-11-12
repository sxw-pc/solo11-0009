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
from .policies import PolicyError, load_policy
from .pipeline.checkpoint import CheckpointStore
from .pipeline.runner import PipelineError, execute_run
from .registry import inspect_dataset
from .reveal.errors import RevealControlError
from .reveal.records import Scope
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
    keygen = sub.add_parser(
        "keygen", parents=[common],
        help="manage offline identity keys for controlled reveal",
    )
    keygen_sub = keygen.add_subparsers(dest="keygen_command", required=True)
    keygen_sub.add_parser("init", help="initialize the local keyring")
    keygen_new = keygen_sub.add_parser("new", help="create an operator or reviewer key")
    keygen_new.add_argument("--name", required=True)
    keygen_new.add_argument("--role", required=True, choices=("operator", "reviewer"))
    keygen_list = keygen_sub.add_parser("list", help="list keyring identities")
    keygen_rotate = keygen_sub.add_parser("rotate", help="rotate a key (history stays verifiable)")
    keygen_rotate.add_argument("--kid", required=True)
    keygen_revoke = keygen_sub.add_parser("revoke", help="revoke a key (all signatures rejected)")
    keygen_revoke.add_argument("--kid", required=True)
    request = sub.add_parser(
        "reveal-request", parents=[common],
        help="operator creates a signed, scoped reveal request",
    )
    request.add_argument("--operator-kid", required=True)
    request.add_argument("--run-id", required=True)
    request.add_argument("--dataset", required=True)
    request.add_argument("--table", required=True)
    request.add_argument("--column", action="append", required=True, dest="columns")
    request.add_argument("--reason", required=True)
    request.add_argument("--out", required=True)
    authorize = sub.add_parser(
        "authorize", parents=[common],
        help="reviewer signs a reveal request into an expiring authorization",
    )
    authorize.add_argument("--reviewer-kid", required=True)
    authorize.add_argument("--request", required=True, dest="request_path")
    authorize.add_argument("--expires-at", required=True, help="ISO-8601 UTC timestamp")
    authorize.add_argument("--max-rows", required=True, type=int)
    authorize.add_argument("--out", required=True)
    reveal = sub.add_parser(
        "reveal", parents=[common],
        help="execute a controlled reveal with a validated authorization chain",
    )
    reveal.add_argument("--request", required=True, dest="request_path")
    reveal.add_argument("--authorization", required=True)
    reveal.add_argument("--dataset", required=True)
    reveal.add_argument("--out", required=True)
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


def _cmd_keygen(args: argparse.Namespace) -> int:
    from .reveal import service

    paths = _paths(args)
    handler = args.keygen_command
    if handler == "init":
        service.keygen_init(paths)
        print(f"keyring initialized at {paths.keyring_dir}")
        return 0
    if handler == "new":
        record = service.keygen_generate(paths, args.name, args.role)
        print(
            f"created {record['role']} key name={record['name']} kid={record['kid']} "
            f"state={record['state']}"
        )
        return 0
    if handler == "list":
        for record in service.list_identities(paths):
            print(
                f"kid={record['kid']} name={record['name']} role={record['role']} "
                f"state={record['state']} version={record['version']}"
            )
        return 0
    if handler == "rotate":
        record = service.keygen_rotate(paths, args.kid)
        print(f"rotated kid={record['kid']} state={record['state']}")
        return 0
    if handler == "revoke":
        record = service.keygen_revoke(paths, args.kid)
        print(f"revoked kid={record['kid']} state={record['state']}")
        return 0
    raise MasklineError(f"unknown keygen command: {handler}")


def _cmd_reveal_request(args: argparse.Namespace) -> int:
    from .reveal import service

    paths = _paths(args)
    inventory = inspect_dataset(Path(args.dataset).expanduser().resolve())
    scope = Scope(
        run_id=args.run_id,
        dataset_fingerprint=inventory.fingerprint,
        table=args.table,
        columns=tuple(args.columns),
    )
    target = service.create_request(
        paths,
        operator_kid=args.operator_kid,
        scope=scope,
        reason=args.reason,
        out_path=args.out,
    )
    print(f"request written: {target}")
    print(f"dataset_fingerprint={inventory.fingerprint}")
    return 0


def _cmd_authorize(args: argparse.Namespace) -> int:
    from .reveal import service

    paths = _paths(args)
    target = service.create_authorization(
        paths,
        reviewer_kid=args.reviewer_kid,
        request_path=args.request_path,
        expires_at=args.expires_at,
        max_rows=args.max_rows,
        out_path=args.out,
    )
    print(f"authorization written: {target}")
    print(f"expires_at={args.expires_at} max_rows={args.max_rows}")
    return 0


def _cmd_reveal(args: argparse.Namespace) -> int:
    from .reveal import service

    paths = _paths(args)
    result = service.execute_reveal(
        paths,
        request_path=args.request_path,
        authorization_path=args.authorization,
        dataset_path=args.dataset,
        output_path=args.out,
    )
    print(
        f"reveal complete: rows={result.rows_revealed} "
        f"columns={','.join(result.columns_revealed)} output={result.output_path}"
    )
    print(
        f"authorization_id={result.authorization_id} request_id={result.request_id} "
        f"audit_seq={result.audit_seq}"
    )
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    paths = _paths(args)
    if args.verify:
        verification = AuditLog(paths.audit_path).verify()
        extra = ""
        # If a keyring is present, also authenticate every controlled-reveal entry.
        if (paths.keyring_dir / "keyring.json").exists():
            from .reveal import service as reveal_service

            mac = reveal_service.verify_audit(paths)
            extra = f" reveal_mac_verified={mac['reveal_mac_verified']}"
        print(
            f"audit chain OK: entries={verification.entries} "
            f"head={verification.head_hash}{extra}"
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
        "keygen": _cmd_keygen,
        "reveal-request": _cmd_reveal_request,
        "authorize": _cmd_authorize,
        "reveal": _cmd_reveal,
        "audit": _cmd_audit,
    }
    try:
        return handlers[args.command](args)
    except (MasklineError, PolicyError, PipelineError, RevealControlError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
