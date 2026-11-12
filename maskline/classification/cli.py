"""CLI wiring for the compliance classification capability (`maskline classify ...`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..config import Paths
from ..registry import Catalog
from ..utils import MasklineError
from .policy_export import write_policy
from .service import ClassificationService, ClassificationServiceError
from .store import ClassificationStore, ClassificationStoreError

LEVEL_LABEL = {"L4": "L4", "L3": "L3", "L2": "L2", "L1": "L1"}


def build_classify_parser(sub: argparse._SubParsersAction) -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--workspace", default=None,
        help="runtime workspace directory (default: current directory)",
    )
    classify = sub.add_parser(
        "classify",
        parents=[common],
        help="compliance grading of sensitive fields (offline rule packs)",
    )
    classify_sub = classify.add_subparsers(dest="classify_command", required=True)

    run = classify_sub.add_parser("run", parents=[common], help="classify one or more datasets")
    run.add_argument("targets", nargs="+", help="dataset files (sqlite/csv)")
    run.add_argument(
        "--pack-versions",
        default=None,
        help="comma-separated rule pack version ids; defaults to the active snapshot",
    )
    run.add_argument("--sample-limit", type=int, default=200)
    run.add_argument("--max-nesting-depth", type=int, default=3)

    packs = classify_sub.add_parser("packs", parents=[common], help="list registered rule pack versions")
    packs.add_argument("add", nargs="?", help="path to a custom rule pack YAML to publish")

    results = classify_sub.add_parser("results", parents=[common], help="show stored classifications")
    results.add_argument("fingerprint", help="dataset fingerprint")

    correct = classify_sub.add_parser("correct", parents=[common], help="record a tamper-evident manual correction")
    correct.add_argument("--fingerprint", required=True)
    correct.add_argument("--table", required=True)
    correct.add_argument("--column", required=True)
    correct.add_argument("--standard", required=True)
    correct.add_argument("--level", default=None)
    correct.add_argument("--category", default=None)
    correct.add_argument("--controls", default=None, help="comma-separated control codes")
    correct.add_argument("--special", choices=["true", "false"], default=None)
    correct.add_argument("--cross-border", choices=["true", "false"], default=None)
    correct.add_argument("--reason", required=True)
    correct.add_argument("--operator", required=True)

    classify_sub.add_parser("verify", parents=[common], help="verify the correction hash chain")

    reclassify = classify_sub.add_parser(
        "reclassify", parents=[common], help="re-run datasets whose fingerprint changed"
    )
    reclassify.add_argument(
        "--pack-versions",
        default=None,
        help="comma-separated rule pack version ids; defaults to the active snapshot",
    )

    export = classify_sub.add_parser(
        "export", parents=[common], help="export classifications as a v1 masking policy YAML"
    )
    export.add_argument("fingerprint")
    export.add_argument("--name", default="classification-derived-policy")
    export.add_argument("--pattern", default=None, help="dataset path pattern for the policy")
    export.add_argument("--output", required=True)
    export.add_argument("--description", default="Generated from compliance classification results.")


def _service(paths: Paths, sample_limit: int = 200, max_nesting_depth: int = 3) -> ClassificationService:
    paths.ensure_runtime_dirs()
    store = ClassificationStore(paths.classification_db)
    catalog = Catalog(paths.meta_db)
    audit = AuditLog(paths.audit_path)
    return ClassificationService(
        store,
        catalog,
        audit=audit,
        max_nesting_depth=max_nesting_depth,
        sample_limit=sample_limit,
    )


def _parse_versions(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    return [int(part.strip()) for part in raw.split(",") if part.strip()]


def _print_alerts(alerts: list[Any]) -> None:
    for alert in alerts:
        payload = alert.to_dict() if hasattr(alert, "to_dict") else alert
        where = ""
        if payload.get("table"):
            where = f" {payload['table']}.{payload.get('column', '')}"
        print(f"  [{payload['severity'].upper()}] {payload['code']}{where}: {payload['message']}")


def _print_results(records: list[dict[str, Any]]) -> None:
    for record in records:
        print(
            f"\n{record['table_name']}.{record['column_name']}  "
            f"type={record.get('sensitive_type') or '-'}  "
            f"semantic={record.get('semantic_key') or '-'}  "
            f"source={record['source']}"
            + ("  [degraded]" if record.get("degraded") else "")
        )
        for std in record["standards"]:
            flags = []
            if std.get("special_category"):
                flags.append("特殊类别")
            if std.get("cross_border"):
                flags.append("跨境传输")
            flag_text = f" [{'/'.join(flags)}]" if flags else ""
            print(
                f"  - {std['standard_code']}: level={std.get('level') or '-'} "
                f"category={std.get('category') or '-'} "
                f"controls={','.join(std.get('controls', [])) or '-'}"
                f" rule={std.get('matched_rule_id') or '-'} basis={std['match_basis']}"
                f"{flag_text}"
            )


def handle_classify(args: argparse.Namespace) -> int:
    paths = Paths.for_workspace(args.workspace)
    command = args.classify_command

    if command == "packs":
        store = ClassificationStore(paths.classification_db)
        try:
            if args.add:
                service = _service(paths)
                try:
                    info = service.publish_custom_pack(args.add)
                finally:
                    service.store.close()
                    service.catalog.close()
                print(
                    f"pack={info['pack_id']} standard={info['standard_code']} "
                    f"version_id={info['version_id']} "
                    f"{'newly registered' if info['created'] else 'already registered'}"
                )
                return 0
            rows = store.list_versions()
        finally:
            store.close()
        if not rows:
            print("no rule packs registered; run 'maskline classify run' to auto-publish built-ins")
            return 0
        for row in rows:
            print(
                f"version_id={row['version_id']} standard={row['standard_code']} "
                f"pack={row['pack_id']} rev={row['revision']} "
                f"builtin={bool(row['builtin'])} fp={row['fingerprint'][:16]}..."
            )
        return 0

    if command == "run":
        service = _service(
            paths,
            sample_limit=args.sample_limit,
            max_nesting_depth=args.max_nesting_depth,
        )
        try:
            service.ensure_builtin_packs()
            versions = _parse_versions(args.pack_versions)
            outcomes = service.classify_many(args.targets, pack_version_ids=versions)
        finally:
            service.store.close()
            service.catalog.close()
        total_alerts = 0
        for outcome in outcomes:
            if outcome.get("error"):
                print(f"FAILED: {outcome['path']}: {outcome['error']}")
                _print_alerts(outcome["alerts"])
                continue
            inventory = outcome["inventory"]
            print(
                f"\n=== {inventory.path.name} job={outcome['job_id']} "
                f"fp={inventory.fingerprint[:16]}... "
                f"fields={len(outcome['results'])} alerts={len(outcome['alerts'])}"
                + (" [headerless degraded]" if outcome.get("headerless") else "")
                + f" pack_versions={outcome['pack_version_ids']}"
            )
            _print_results([item.to_dict() for item in outcome["results"]])
            if outcome["alerts"]:
                print("  alerts:")
                _print_alerts(outcome["alerts"])
            total_alerts += len(outcome["alerts"])
        print(f"\ndone: {len(outcomes)} dataset(s), {total_alerts} alert(s); no task was aborted")
        return 0

    if command == "results":
        store = ClassificationStore(paths.classification_db)
        try:
            records = store.classifications_for(args.fingerprint)
        finally:
            store.close()
        if not records:
            raise MasklineError(f"no classifications stored for fingerprint {args.fingerprint}")
        _print_results(records)
        return 0

    if command == "correct":
        service = _service(paths)
        try:
            controls = args.controls.split(",") if args.controls is not None else None
            outcome = service.correct_field(
                dataset_fingerprint=args.fingerprint,
                table=args.table,
                column=args.column,
                standard_code=args.standard,
                level=args.level,
                category=args.category,
                controls=controls,
                reason=args.reason,
                operator=args.operator,
                special_category=None if args.special is None else args.special == "true",
                cross_border=None if args.cross_border is None else args.cross_border == "true",
            )
        finally:
            service.store.close()
            service.catalog.close()
        entry = outcome["correction"]
        print(
            f"correction_id={entry['correction_id']} recorded (append-only); "
            f"hash={entry['entry_hash'][:16]}..."
        )
        return 0

    if command == "verify":
        store = ClassificationStore(paths.classification_db)
        try:
            verification = store.verify_correction_chain()
        except ClassificationStoreError as exc:
            raise MasklineError(str(exc)) from exc
        finally:
            store.close()
        print(
            f"correction chain OK: corrections={verification['corrections']} "
            f"head={verification['head_hash'][:16]}..."
        )
        return 0

    if command == "reclassify":
        service = _service(paths)
        try:
            service.ensure_builtin_packs()
            report = service.reclassify_changed(
                pack_version_ids=_parse_versions(args.pack_versions)
            )
        finally:
            service.store.close()
            service.catalog.close()
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    if command == "export":
        store = ClassificationStore(paths.classification_db)
        try:
            records = store.classifications_for(args.fingerprint)
            if not records:
                raise MasklineError(f"no classifications stored for fingerprint {args.fingerprint}")
            pattern = args.pattern
            if pattern is None:
                dataset = store.conn.execute(
                    "SELECT dataset_path FROM classification_jobs "
                    "WHERE dataset_fingerprint = ? ORDER BY rowid DESC LIMIT 1",
                    (args.fingerprint,),
                ).fetchone()
                pattern = Path(dataset["dataset_path"]).name if dataset else "*"
        finally:
            store.close()
        result = write_policy(
            args.output,
            policy_name=args.name,
            dataset_path_pattern=pattern,
            classifications=records,
            description=args.description,
        )
        print(f"policy written: {result['path']}")
        for notice in result["notices"]:
            print(f"  notice: {notice['table']}.{notice['column']} excluded ({notice['reason']})")
        return 0

    raise ClassificationServiceError(f"unknown classify command: {command}")
