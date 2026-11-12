"""One-command end-to-end demo: fixtures, scan, mask, audit, and report."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditLog
from .config import Paths, SecretStore, create_demo_secret
from .fixturegen import generate_fixture
from .policies import Policy, load_policy
from .pipeline.runner import RunResult, execute_run
from .pseudomap import PseudoMap, PseudoMapError
from .workflow import finalize_run, scan_paths


@dataclass
class DemoResult:
    workspace: Path
    policy: Policy
    runs: list[RunResult] = field(default_factory=list)
    reports: list[Path] = field(default_factory=list)
    audit_entries: int = 0
    revealed_sample: tuple[str, str] | None = None


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent.parent / "policies" / "example.yaml"


def _secret_store(paths: Paths) -> SecretStore:
    env_path = os.environ.get("MASKLINE_SECRET_FILE")
    if env_path:
        return SecretStore.from_file(env_path)
    demo_path = paths.data_dir / "demo-secret.txt"
    if demo_path.exists():
        store = SecretStore.from_file(demo_path)
    else:
        store = create_demo_secret(demo_path)
    os.environ["MASKLINE_SECRET_FILE"] = str(demo_path)
    return store


def run_demo(
    workspace: str | Path | None = None,
    policy_path: str | Path | None = None,
    sample_limit: int = 200,
    batch_size: int = 500,
) -> DemoResult:
    paths = Paths.for_workspace(workspace)
    paths.ensure_runtime_dirs()
    fixture_paths = generate_fixture(paths.raw_dir)
    policy_file = Path(policy_path).expanduser().resolve() if policy_path else default_policy_path()
    if not policy_file.is_file():
        raise FileNotFoundError(f"example policy not found: {policy_file}")
    policy = load_policy(policy_file)
    secret_store = _secret_store(paths)
    summaries = scan_paths([paths.raw_dir], paths, sample_limit=sample_limit)
    result = DemoResult(workspace=paths.root, policy=policy)
    print(f"Workspace : {paths.root}")
    print(f"Policy    : {policy.name} ({policy.fingerprint[:16]}...)")
    print(f"Secret    : {secret_store.source}")
    print(f"Fixtures  : {fixture_paths['sqlite'].name}, {fixture_paths['csv'].name}")
    for summary in summaries:
        policy.validate_against(summary.inventory)
        finding_count = sum(
            1 for finding in summary.findings if finding["confidence"] in {"high", "medium"}
        )
        status = "registered" if summary.newly_registered else "already registered"
        print(
            f"\n[{summary.inventory.path.name}] {status}; "
            f"fingerprint={summary.inventory.fingerprint[:16]}...; "
            f"high/medium findings={finding_count}"
        )
        run_result = execute_run(
            summary.inventory,
            policy,
            paths,
            secrets_store=secret_store,
            batch_size=batch_size,
        )
        artifacts = finalize_run(
            paths, summary.inventory, policy, run_result, summary.findings
        )
        result.runs.append(run_result)
        report_md = artifacts["report"]["markdown"]
        result.reports.append(report_md)
        print(
            f"  rows={run_result.row_count} elapsed={run_result.elapsed_seconds:.2f}s "
            f"output={run_result.output_path}"
        )
        print(f"  report={report_md}")
        print(f"  audit entry seq={artifacts['audit']['seq']}")
    try:
        with PseudoMap(
            paths.pseudomap_db, current_kid=secret_store.current_kid()
        ) as mapping:
            for kid, token, plaintext in mapping.iter_records(limit=1):
                result.revealed_sample = (token, plaintext)
                print(
                    f"\nReveal sample: {token} -> {plaintext} "
                    f"(verified with kid={kid})"
                )
                break
    except PseudoMapError:
        pass
    verification = AuditLog(paths.audit_path).verify()
    result.audit_entries = verification.entries
    print(
        f"\nAudit chain OK: {verification.entries} entries, "
        f"head={verification.head_hash[:16]}..."
    )
    print(f"Reports: {paths.reports_dir}")
    return result
