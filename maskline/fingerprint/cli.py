"""CLI surface for the fingerprint subsystem.

Subcommands live under ``maskline fp-*`` and never share arguments with the
masking pipeline, so watermarking authority can be granted separately from the
pseudonym mapping authority.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

from ..utils import atomic_write_text, file_sha256
from .config import dump_fingerprint_config, load_fingerprint_config
from .detect import detect_attribution
from .embed import embed_delivery
from .keystore import (
    FingerprintPaths,
    generate_master_key,
    record_delivery_audit,
    reconcile_manifests_with_audit,
    resolve_master_key,
)
from .manifest import load_manifests, write_manifest


def add_fingerprint_parsers(subparsers: argparse._SubParsersAction) -> None:
    keygen = subparsers.add_parser(
        "fp-keygen", help="create the local fingerprint master key (0600)"
    )
    keygen.add_argument("--workspace", default=None)

    embed = subparsers.add_parser(
        "fp-embed", help="embed a delivery fingerprint into a masked table"
    )
    embed.add_argument("--workspace", default=None)
    embed.add_argument("--config", required=True, help="fingerprint YAML config")
    embed.add_argument("--input", required=True, help="masked table to deliver")
    embed.add_argument("--output", required=True, help="fingerprinted output path")
    embed.add_argument("--delivery-id", required=True)
    embed.add_argument("--key", default=None, help="master key file (else MASKLINE_FP_KEY)")
    embed.add_argument("--table", default=None, help="sqlite table name")
    embed.add_argument("--format", default=None,
                       choices=["csv", "jsonl", "sqlite"], help="override output format")
    embed.add_argument("--recipient", default=None, help="recorded in the audit entry")
    embed.add_argument("--notes", default="")
    embed.add_argument("--canary-count", type=int, default=None)

    verify = subparsers.add_parser(
        "fp-verify", help="attribute a suspect file against archived deliveries"
    )
    verify.add_argument("--workspace", default=None)
    verify.add_argument("--suspect", required=True)
    verify.add_argument("--key", default=None)
    verify.add_argument("--table", default=None)
    verify.add_argument("--manifests", default=None,
                        help="manifest directory (default: workspace fingerprints/)")
    verify.add_argument("--json", dest="json_out", default=None,
                        help="write the full attribution report as JSON")

    reconcile = subparsers.add_parser(
        "fp-reconcile", help="cross-check manifests against the audit chain"
    )
    reconcile.add_argument("--workspace", default=None)
    reconcile.add_argument("--json", dest="json_out", default=None)

    show_config = subparsers.add_parser(
        "fp-config", help="validate a fingerprint config and print its fingerprint"
    )
    show_config.add_argument("--config", required=True)

    bundle = subparsers.add_parser(
        "fp-bundle", help="export an offline verification bundle (manifests + verifier)"
    )
    bundle.add_argument("--workspace", default=None)
    bundle.add_argument("--out", required=True, help="output .zip path")
    bundle.add_argument("--key", default=None,
                        help="include the master key inside the bundle (sensitive; 0600)")


def _fp_paths(workspace: str | None) -> FingerprintPaths:
    return FingerprintPaths.for_workspace(workspace)


def cmd_fp_keygen(args: argparse.Namespace) -> int:
    paths = _fp_paths(args.workspace)
    paths.ensure()
    target = generate_master_key(paths.key_path)
    print(f"fingerprint master key written to {target} (mode 0600)")
    print("back it up separately; losing it makes every future verification impossible")
    return 0


def cmd_fp_embed(args: argparse.Namespace) -> int:
    paths = _fp_paths(args.workspace)
    paths.ensure()
    config = load_fingerprint_config(args.config)
    master_key, key_source = resolve_master_key(args.key, paths.key_path)
    result = embed_delivery(
        config,
        args.input,
        args.output,
        delivery_id=args.delivery_id,
        master_key=master_key,
        table=args.table,
        output_format=args.format,
        notes=args.notes,
        canary_count_override=args.canary_count,
    )
    manifest_path = write_manifest(result.manifest, paths.manifest_dir)
    audit_entry = record_delivery_audit(
        paths, result.manifest, result.output_path, args.recipient
    )
    print(f"delivery_id={result.manifest.delivery_id}")
    print(f"output={result.output_path} rows_in={result.rows_in} rows_out={result.rows_out}")
    print(f"canary_rows={result.canary_rows} skipped_null_keys={result.skipped_null_keys}")
    for spec in result.manifest.numeric_specs:
        print(
            f"  numeric {spec.column}: marked={spec.marked_cells} q={spec.quantum:g} "
            f"mean|delta|={spec.mean_abs_delta:g} max|delta|={spec.max_abs_delta:g}"
        )
    print(f"manifest={manifest_path} hash={result.manifest.manifest_hash[:16]}...")
    print(f"audit_seq={audit_entry['seq']} key_source={key_source}")
    return 0


def cmd_fp_verify(args: argparse.Namespace) -> int:
    paths = _fp_paths(args.workspace)
    master_key, _ = resolve_master_key(args.key, paths.key_path)
    manifest_dir = Path(args.manifests) if args.manifests else paths.manifest_dir
    manifests = load_manifests(manifest_dir)
    report = detect_attribution(args.suspect, manifests, master_key, table=args.table)
    print(f"suspect: {report.suspect_path} ({report.suspect_rows} rows)")
    print(f"checked {report.manifest_count} archived deliveries")
    print(f"verdict: {report.overall_verdict}")
    print(f"rationale: {report.rationale}")
    if report.primary_delivery_id:
        print(f"primary: {report.primary_delivery_id}")
    print("")
    for match in report.matches:
        numeric = match.channels.numeric
        canary = match.channels.canary
        order = match.channels.order
        print(
            f"- {match.delivery_id} [{match.verdict.band}] "
            f"score={match.verdict.score} p={match.combined_p_value:.3e} "
            f"share~{match.mixture_fraction:.0%} "
            f"numeric={numeric.matches}/{numeric.trials} "
            f"canary={canary.row_hits}h/{canary.surviving_canaries} "
            f"order={order.agreements}/{order.pairs}"
        )
    if args.json_out:
        target = Path(args.json_out)
        atomic_write_text(target, json.dumps(report.to_dict(), ensure_ascii=False,
                                             sort_keys=True, indent=2) + "\n")
        print(f"\njson report: {target}")
    return 0 if report.overall_verdict != "no_match" else 3


def cmd_fp_reconcile(args: argparse.Namespace) -> int:
    paths = _fp_paths(args.workspace)
    rows = reconcile_manifests_with_audit(paths)
    payload = {"reconciled": rows, "all_ok": all(row["reconciled"] for row in rows)}
    if args.json_out:
        atomic_write_text(Path(args.json_out),
                          json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    if not rows:
        print("no fingerprint_delivery audit entries found")
        return 0
    for row in rows:
        status = "OK" if row["reconciled"] else "MISMATCH"
        print(f"seq={row['seq']} delivery={row['delivery_id']} {status}")
    return 0 if payload["all_ok"] else 4


def cmd_fp_config(args: argparse.Namespace) -> int:
    config = load_fingerprint_config(args.config)
    print(dump_fingerprint_config(config).rstrip())
    print(f"config_fingerprint={config.fingerprint}")
    return 0


def cmd_fp_bundle(args: argparse.Namespace) -> int:
    paths = _fp_paths(args.workspace)
    manifests = load_manifests(paths.manifest_dir)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    included_key = False
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for manifest in manifests:
            name = f"manifests/{manifest.delivery_id}.json"
            archive.writestr(
                name,
                json.dumps(manifest.to_dict(), ensure_ascii=False, sort_keys=True, indent=2),
            )
        readme = (
            "Offline fingerprint verification bundle\n"
            "=======================================\n"
            "Contents: sealed delivery manifests only. No original data, no row\n"
            "values, no master key (unless explicitly included).\n\n"
            "Verification on an air-gapped host:\n"
            "  python -m maskline fp-verify --suspect <leak-file> \\\n"
            "      --key <master.key> --manifests manifests/ --json report.json\n"
        )
        if args.key:
            key_value, _ = resolve_master_key(args.key, paths.key_path)
            archive.writestr("master.key", key_value + "\n")
            archive.writestr(
                "WARNING.txt",
                "This bundle contains the master key. Treat it as a secret,\n"
                "transfer it out-of-band, and delete it after verification.\n",
            )
            included_key = True
        archive.writestr("README.txt", readme)
    try:
        out.chmod(0o600)
    except OSError:
        pass
    print(f"bundle={out} manifests={len(manifests)} key_included={included_key}")
    print(f"bundle_sha256={file_sha256(out)}")
    return 0


FP_HANDLERS = {
    "fp-keygen": cmd_fp_keygen,
    "fp-embed": cmd_fp_embed,
    "fp-verify": cmd_fp_verify,
    "fp-reconcile": cmd_fp_reconcile,
    "fp-config": cmd_fp_config,
    "fp-bundle": cmd_fp_bundle,
}
