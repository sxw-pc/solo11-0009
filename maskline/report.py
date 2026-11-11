"""Markdown and JSON run reports with safely redacted row samples.

Both formats are rendered from one in-memory report object, so every statistic
in the Markdown report is the same value the JSON report carries. Before any
file is written, the report object is cross-checked against the persisted run
metadata (checkpoints, manifest, audit anchor, mapping store, output digest);
a mismatch raises instead of emitting an inconsistent report.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import verify_audit
from .config import Paths
from .dataset_io import iter_csv_tuples, iter_table_rows
from .policies import DatasetRule, Policy
from .pseudomap import PseudoMap
from .registry import Catalog, DatasetInventory, TableInfo
from .utils import (
    MasklineError,
    atomic_write_text,
    quote_ident,
    sqlite_connect_readonly,
    sqlite_content_digest,
)
from .pipeline.checkpoint import CheckpointStore
from .pipeline.manifest import previous_manifest

REDACTED = "[源值已隐藏]"
UNMASKED = "[未脱敏，已隐藏]"
CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低", "none": "无"}
TRANSFORMER_LABELS = {
    "mask": "遮蔽",
    "hash": "HMAC 哈希",
    "generalize": "泛化",
    "pseudonym": "假名化",
    "nullify": "置空",
    "round": "取整",
}
EVENT_LABELS = {
    "run_started": "运行启动",
    "run_resumed": "断点恢复",
    "run_interrupted": "运行中断",
    "run_failed": "运行失败",
    "run_completed": "运行完成",
}

# Defaults used when parsing reports written by older versions that predate
# the resume/skip/anchor fields. Old files must stay readable forever.
_LEGACY_RUN_DEFAULTS = {
    "pseudomap_entries": 0,
    "skipped_rows": 0,
    "audit_seq": None,
    "audit_anchor": None,
    "resumed": False,
}


class ReportConsistencyError(MasklineError):
    """Raised when report data would not match the persisted run metadata."""


def _source_rows(
    inventory: DatasetInventory, table: TableInfo, limit: int
) -> list[tuple[int, tuple[Any, ...]]]:
    if inventory.kind == "sqlite":
        _columns, rows = iter_table_rows(inventory.path, table.name, 0, limit)
        return rows
    rows = []
    for index, values in enumerate(iter_csv_tuples(inventory.path), start=1):
        if index > limit:
            break
        rows.append((index, values))
    return rows


def _target_rows(output: Path, table: str, limit: int) -> dict[int, tuple[Any, ...]]:
    conn = sqlite_connect_readonly(output)
    try:
        columns = [row[1] for row in conn.execute(f"PRAGMA table_info({quote_ident(table)})")]
        if not columns:
            return {}
        select = ", ".join(quote_ident(name) for name in columns)
        rows = conn.execute(
            f"SELECT rowid, {select} FROM {quote_ident(table)} ORDER BY rowid LIMIT ?",
            (limit,),
        ).fetchall()
        return {int(row[0]): tuple(row[1:]) for row in rows}
    finally:
        conn.close()


def _finding_map(findings: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (finding["table_name"], finding["column_name"]): finding for finding in findings
    }


def _samples_for_table(
    inventory: DatasetInventory,
    table: TableInfo,
    rule: DatasetRule,
    findings: list[dict[str, Any]],
    output: Path,
) -> list[dict[str, Any]]:
    policy = rule.tables.get(table.name)
    configured = set(policy.columns) if policy else set()
    finding_map = _finding_map(findings)
    sensitive = set(configured)
    warnings = set()
    for column in table.columns:
        finding = finding_map.get((table.name, column.name))
        if finding and finding["confidence"] in {"high", "medium"}:
            sensitive.add(column.name)
            if column.name not in configured:
                warnings.add(column.name)
    target_rows = _target_rows(output, table.name, 5)
    samples = []
    for rowid, values in _source_rows(inventory, table, 5):
        after = target_rows.get(rowid, ())
        before_values: dict[str, Any] = {}
        after_values: dict[str, Any] = {}
        for index, column in enumerate(table.columns):
            source_value = values[index] if index < len(values) else None
            target_value = after[index] if index < len(after) else None
            if column.name in configured:
                before_values[column.name] = REDACTED
                after_values[column.name] = target_value
            elif column.name in warnings:
                before_values[column.name] = REDACTED
                after_values[column.name] = UNMASKED
            else:
                before_values[column.name] = source_value
                after_values[column.name] = target_value
        samples.append({"rowid": rowid, "before": before_values, "after": after_values})
    return samples


def _cell(value: Any) -> str:
    if value is None:
        return "NULL"
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if text != "" else '""'


def _validate_report_core(
    paths: Paths,
    inventory: DatasetInventory,
    result: Any,
    core: dict[str, Any],
    audit_entry: dict[str, Any] | None,
) -> None:
    """Cross-check every report statistic against persisted metadata."""
    run = core["run"]
    if run["dataset_fingerprint"] != inventory.fingerprint:
        raise ReportConsistencyError("dataset fingerprint differs from the live inventory")
    if run["dataset_fingerprint"] != result.dataset_fingerprint:
        raise ReportConsistencyError("dataset fingerprint differs from the run result")

    # Catalog record (the dataset may not be registered when the API is used
    # directly, so an absent record is tolerated; a present-but-different one
    # is not).
    with Catalog(paths.meta_db) as catalog:
        registered = catalog.get_dataset(inventory.fingerprint)
    if registered is not None and registered["fingerprint"] != inventory.fingerprint:
        raise ReportConsistencyError("dataset fingerprint differs from the catalog record")

    with CheckpointStore(paths.checkpoint_db) as store:
        record = store.get_run(result.run_id)
        if record is None:
            raise ReportConsistencyError(f"no checkpoint run record for {result.run_id}")
        if record.status != "completed":
            raise ReportConsistencyError(
                f"run {result.run_id} is not completed (status={record.status})"
            )
        if record.dataset_fingerprint != run["dataset_fingerprint"]:
            raise ReportConsistencyError("dataset fingerprint differs from checkpoint record")
        if record.output_path != run["output"]:
            raise ReportConsistencyError("output path differs from checkpoint record")
        checkpoints = store.list_checkpoints(result.run_id)
        stored_rows = sum(cp.rows_done for cp in checkpoints)
        stored_skipped = sum(cp.skipped_rows for cp in checkpoints)
        stored_events = store.list_events(result.run_id)
    if stored_rows != run["rows_processed"]:
        raise ReportConsistencyError(
            f"rows_processed={run['rows_processed']} but checkpoints hold {stored_rows}"
        )
    if stored_skipped != run["skipped_rows"]:
        raise ReportConsistencyError(
            f"skipped_rows={run['skipped_rows']} but checkpoints hold {stored_skipped}"
        )
    if len(stored_events) != len(core["events"]):
        raise ReportConsistencyError("event list differs from the persisted run events")

    manifest = previous_manifest(paths.manifest_dir, inventory.fingerprint)
    if manifest is None:
        raise ReportConsistencyError("run manifest is missing")
    if manifest["run_id"] != result.run_id:
        raise ReportConsistencyError("manifest run_id differs from the report run")
    if manifest["dataset_fingerprint"] != run["dataset_fingerprint"]:
        raise ReportConsistencyError("manifest fingerprint differs from the report")
    if manifest["output_hash"] != run["output_hash"]:
        raise ReportConsistencyError("manifest output_hash differs from the report")
    if manifest["row_count"] != run["rows_processed"]:
        raise ReportConsistencyError("manifest row_count differs from the report")
    if manifest["transform_counts"] != core["transform_counts"]:
        raise ReportConsistencyError("manifest transform counts differ from the report")

    output = Path(run["output"])
    if not output.exists():
        raise ReportConsistencyError(f"output database is missing: {output}")
    actual_digest = sqlite_content_digest(output)
    if actual_digest != run["output_hash"]:
        raise ReportConsistencyError("output_hash does not match the actual output database")

    if run["pseudomap_entries"] > 0:
        if not paths.pseudomap_db.exists():
            raise ReportConsistencyError("pseudonym mapping database is missing")
        with PseudoMap(paths.pseudomap_db) as mapping:
            actual_entries = mapping.count()
        if actual_entries != run["pseudomap_entries"]:
            raise ReportConsistencyError(
                f"pseudomap_entries={run['pseudomap_entries']} "
                f"but mapping store holds {actual_entries}"
            )

    if audit_entry is not None:
        if audit_entry["seq"] != run["audit_seq"]:
            raise ReportConsistencyError("audit seq differs from the appended entry")
        if audit_entry["entry_hash"] != run["audit_anchor"]:
            raise ReportConsistencyError("audit anchor differs from the appended entry")
        verification = verify_audit(paths.audit_path)
        if verification.head_hash != run["audit_anchor"]:
            raise ReportConsistencyError(
                "audit anchor does not match the audit head file"
            )
        if audit_entry["rows_processed"] != run["rows_processed"]:
            raise ReportConsistencyError("audit rows_processed differs from the report")
        if audit_entry["output_hash"] != run["output_hash"]:
            raise ReportConsistencyError("audit output_hash differs from the report")


def _build_report_core(
    inventory: DatasetInventory,
    policy: Policy,
    result: Any,
    findings: list[dict[str, Any]],
    samples: dict[str, list[dict[str, Any]]],
    warnings: list[dict[str, Any]],
    audit_entry: dict[str, Any] | None,
    generated_at: str,
) -> dict[str, Any]:
    """The single object every output format is rendered from."""
    return {
        "run": {
            "run_id": result.run_id,
            "dataset": str(inventory.path),
            "dataset_fingerprint": inventory.fingerprint,
            "policy_name": policy.name,
            "policy_fingerprint": policy.fingerprint,
            "policy_changed": result.policy_changed,
            "output": str(result.output_path),
            "output_hash": result.output_hash,
            "rows_processed": result.row_count,
            "elapsed_seconds": round(result.elapsed_seconds, 6),
            "pseudomap_entries": result.pseudomap_entries,
            "skipped_rows": result.skipped_rows,
            "audit_seq": audit_entry["seq"] if audit_entry else None,
            "audit_anchor": audit_entry["entry_hash"] if audit_entry else None,
            "resumed": result.resumed,
        },
        "applied_policy": policy.for_dataset(inventory.path).to_dict(),
        "transform_counts": result.transform_counts,
        "findings": findings,
        "samples": samples,
        "warnings": warnings,
        "events": [dict(event) for event in result.events],
        "generated_at": generated_at,
    }


def _markdown(inventory: DatasetInventory, policy: Policy, core: dict[str, Any]) -> str:
    run = core["run"]
    rule = policy.for_dataset(inventory.path)
    applied = {
        (table, column): detail
        for table, table_policy in rule.tables.items()
        for column, detail in table_policy.columns.items()
    }
    anchor = run["audit_anchor"] or "—"
    lines = [
        "# maskline 脱敏报告",
        "",
        f"- 运行 ID：`{run['run_id']}`",
        f"- 数据集：`{run['dataset']}`",
        f"- 数据集指纹：`{run['dataset_fingerprint']}`",
        f"- 策略：`{run['policy_name']}` (`{run['policy_fingerprint']}`)",
        f"- 策略变更：{'是' if run['policy_changed'] else '否'}",
        f"- 输出库：`{run['output']}`",
        f"- 输出库哈希：`{run['output_hash']}`",
        f"- 处理行数：{run['rows_processed']}",
        f"- 跳过异常行数：{run['skipped_rows']}",
        f"- 假名映射条目数：{run['pseudomap_entries']}",
        f"- 断点续跑：{'是' if run['resumed'] else '否'}",
        f"- 审计序列号：{run['audit_seq'] if run['audit_seq'] is not None else '—'}",
        f"- 审计链锚点：`{anchor}`",
        f"- 耗时：{run['elapsed_seconds']:.3f} 秒",
        f"- 报告生成时间：{core['generated_at']}",
        "",
        "## 执行节点",
        "",
        "| 序号 | 时间 | 事件 | 详情 |",
        "|---:|---|---|---|",
    ]
    for event in core["events"]:
        label = EVENT_LABELS.get(event["event"], event["event"])
        details = json.dumps(event.get("details", {}), ensure_ascii=False, sort_keys=True)
        lines.append(
            f"| {event['seq']} | {_cell(event['ts'])} | "
            f"{event['event']}（{label}） | `{_cell(details)}` |"
        )
    lines.extend(
        [
            "",
            "## 字段发现",
            "",
            "| 表 | 列 | 建议类型 | 置信度 | 得分 | 命中率 | 校验通过率 | 已配置策略 |",
            "|---|---|---|---|---:|---:|---:|---|",
        ]
    )
    for finding in core["findings"]:
        key = (finding["table_name"], finding["column_name"])
        detail = applied.get(key)
        configured = (
            f"{detail.transformer}" if detail else "—"
        )
        confidence = CONFIDENCE_LABELS.get(finding["confidence"], finding["confidence"])
        lines.append(
            f"| {_cell(finding['table_name'])} | {_cell(finding['column_name'])} | "
            f"{_cell(finding['sensitive_type'] or '—')} | {confidence} | "
            f"{finding['score']:.3f} | {finding['hit_rate']:.1%} | "
            f"{finding['validate_rate']:.1%} | {configured} |"
        )
    lines.extend(
        [
            "",
            "## 已应用策略",
            "",
            "| 表 | 列 | 转换器 | 参数 |",
            "|---|---|---|---|",
        ]
    )
    for (table, column), detail in applied.items():
        params = json.dumps(detail.params, ensure_ascii=False, sort_keys=True)
        lines.append(
            f"| {_cell(table)} | {_cell(column)} | "
            f"{TRANSFORMER_LABELS.get(detail.transformer, detail.transformer)} "
            f"(`{detail.transformer}`) | `{_cell(params)}` |"
        )
    lines.extend(
        [
            "",
            "## 转换统计",
            "",
            "| 转换器 | 见到值 | 非空处理 | 发生改变 |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, counts in sorted(core["transform_counts"].items()):
        lines.append(
            f"| {TRANSFORMER_LABELS.get(name, name)} (`{name}`) | "
            f"{counts.get('seen', 0)} | {counts.get('processed', 0)} | "
            f"{counts.get('changed', 0)} |"
        )
    lines.extend(["", "## 抽样前后对比", ""])
    for table in inventory.tables:
        rows = core["samples"].get(table.name, [])
        if not rows:
            continue
        lines.append(f"### {table.name}")
        lines.append("")
        header = "| rowid |"
        separator = "|---:|"
        for column in table.columns:
            header += f" {_cell(column.name)}（前） | {_cell(column.name)}（后） |"
            separator += "---|---|"
        lines.append(header)
        lines.append(separator)
        for sample in rows:
            row = f"| {sample['rowid']} |"
            for column in table.columns:
                row += (
                    f" {_cell(sample['before'].get(column.name))} | "
                    f"{_cell(sample['after'].get(column.name))} |"
                )
            lines.append(row)
        lines.append("")
    lines.extend(["", "## 未配置策略告警（疑似敏感但未配置）", ""])
    if core["warnings"]:
        lines.append("| 表 | 列 | 建议类型 | 置信度 | 得分 |")
        lines.append("|---|---|---|---|---:|")
        for warning in core["warnings"]:
            lines.append(
                f"| {_cell(warning['table_name'])} | {_cell(warning['column_name'])} | "
                f"{_cell(warning['sensitive_type'])} | "
                f"{CONFIDENCE_LABELS.get(warning['confidence'], warning['confidence'])} | "
                f"{warning['score']:.3f} |"
            )
        lines.append("")
        lines.append("> 以上字段疑似敏感但策略未覆盖，输出中仍可能包含原始值，请复核。")
    else:
        lines.append("无。所有高/中置信度敏感字段均已配置策略。")
    lines.append("")
    return "\n".join(lines)


def generate_report(
    paths: Paths,
    inventory: DatasetInventory,
    policy: Policy,
    result: Any,
    findings: list[dict[str, Any]],
    audit_entry: dict[str, Any] | None = None,
) -> dict[str, Path]:
    if result.output_path is None:
        raise ValueError("dry-run results do not produce reports")
    rule = policy.for_dataset(inventory.path)
    samples = {
        table.name: _samples_for_table(
            inventory, table, rule, findings, Path(result.output_path)
        )
        for table in inventory.tables
    }
    warnings = []
    for finding in findings:
        table_policy = rule.tables.get(finding["table_name"])
        configured = bool(
            table_policy and finding["column_name"] in table_policy.columns
        )
        if not configured and finding["confidence"] in {"high", "medium"}:
            warnings.append(finding)
    # One timestamp shared by both formats and the in-memory report object.
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    report_core = _build_report_core(
        inventory, policy, result, findings, samples, warnings,
        audit_entry, generated_at,
    )
    _validate_report_core(paths, inventory, result, report_core, audit_entry)
    paths.reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = paths.reports_dir / f"{result.run_id}.json"
    md_path = paths.reports_dir / f"{result.run_id}.md"
    atomic_write_text(
        json_path, json.dumps(report_core, ensure_ascii=False, indent=2) + "\n"
    )
    atomic_write_text(md_path, _markdown(inventory, policy, report_core))
    return {"markdown": md_path, "json": json_path}


# ---------------------------------------------------------------------------
# Parsing. Both current and legacy reports must remain readable.
# ---------------------------------------------------------------------------

def _normalize_legacy(payload: dict[str, Any]) -> dict[str, Any]:
    run = dict(payload.get("run", {}))
    for key, default in _LEGACY_RUN_DEFAULTS.items():
        run.setdefault(key, default)
    payload = dict(payload)
    payload["run"] = run
    payload.setdefault("events", [])
    return payload


def load_json_report(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict) or "run" not in payload:
        raise ReportConsistencyError(f"unrecognized JSON report structure: {path}")
    return _normalize_legacy(payload)


_BULLET_PATTERNS = {
    "run_id": re.compile(r"- 运行 ID：`([^`]*)`"),
    "dataset_fingerprint": re.compile(r"- 数据集指纹：`([^`]*)`"),
    "output_hash": re.compile(r"- 输出库哈希：`([^`]*)`"),
    "rows_processed": re.compile(r"- 处理行数：(\d+)"),
    "skipped_rows": re.compile(r"- 跳过异常行数：(\d+)"),
    "pseudomap_entries": re.compile(r"- 假名映射条目数：(\d+)"),
    "resumed": re.compile(r"- 断点续跑：(是|否)"),
    "audit_seq": re.compile(r"- 审计序列号：(\d+|—)"),
    "audit_anchor": re.compile(
        r"- 审计链锚点：`([^`]*)`|^- 审计链锚点：(—)$", re.MULTILINE
    ),
    "generated_at": re.compile(r"- 报告生成时间：(\S+)"),
}

_EVENT_ROW = re.compile(r"^\| (\d+) \| ([^|]+?) \| ([a-z_]+)（[^|]*） \| (.*) \|$")


def load_markdown_report(path: str | Path) -> dict[str, Any]:
    """Parse a Markdown report back into the same shape as the JSON report.

    Only the machine-readable run block and event table are extracted; the
    prose sections stay human-facing. Missing fields (legacy reports) are
    filled with the same defaults used for legacy JSON.
    """
    text = Path(path).read_text(encoding="utf-8")
    run: dict[str, Any] = {}
    for key, pattern in _BULLET_PATTERNS.items():
        match = pattern.search(text)
        if match is None:
            continue
        value = next(group for group in match.groups() if group is not None)
        if key in {"rows_processed", "skipped_rows", "pseudomap_entries", "audit_seq"}:
            run[key] = None if value == "—" else int(value)
        elif key == "resumed":
            run[key] = value == "是"
        elif key == "audit_anchor":
            run[key] = None if value == "—" else value
        else:
            run[key] = value
    events: list[dict[str, Any]] = []
    in_event_table = False
    for line in text.splitlines():
        if line.startswith("## 执行节点"):
            in_event_table = True
            continue
        if in_event_table and line.startswith("## "):
            break
        if not in_event_table:
            continue
        match = _EVENT_ROW.match(line)
        if not match:
            continue
        seq, ts, event, raw_details = match.groups()
        raw_details = raw_details.strip()
        if raw_details.startswith("`") and raw_details.endswith("`"):
            raw_details = raw_details[1:-1]
        raw_details = raw_details.replace("\\|", "|")
        try:
            details = json.loads(raw_details) if raw_details else {}
        except json.JSONDecodeError:
            details = {}
        events.append(
            {"run_id": run.get("run_id"), "seq": int(seq), "event": event,
             "ts": ts.strip(), "details": details}
        )
    for key, default in _LEGACY_RUN_DEFAULTS.items():
        run.setdefault(key, default)
    return {"run": run, "events": events, "generated_at": run.pop("generated_at", None)}


def load_report(path: str | Path) -> dict[str, Any]:
    """Parse either report format, including reports from older versions."""
    report_path = Path(path)
    if report_path.suffix.lower() == ".json":
        return load_json_report(report_path)
    if report_path.suffix.lower() in {".md", ".markdown"}:
        return load_markdown_report(report_path)
    raise ReportConsistencyError(
        f"unsupported report extension: {report_path}"
    )
