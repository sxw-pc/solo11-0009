"""Markdown and JSON run reports with safely redacted row samples."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Paths
from .dataset_io import iter_csv_tuples, iter_table_rows
from .overrides import (
    FORCE_NOT_SENSITIVE,
    FORCE_SENSITIVE,
    OverrideApplication,
)
from .policies import DatasetRule, Policy
from .registry import DatasetInventory, TableInfo
from .utils import atomic_write_text, quote_ident, sqlite_connect_readonly

REDACTED = "[源值已隐藏]"
UNMASKED = "[未脱敏，已隐藏]"
CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低", "none": "无"}
TYPE_LABELS = {"manual": "人工指定"}
OVERRIDE_LABELS = {
    FORCE_SENSITIVE: "强制敏感",
    FORCE_NOT_SENSITIVE: "强制非敏感",
}
TRANSFORMER_LABELS = {
    "mask": "遮蔽",
    "hash": "HMAC 哈希",
    "generalize": "泛化",
    "pseudonym": "假名化",
    "nullify": "置空",
    "round": "取整",
}


def _source_rows(inventory: DatasetInventory, table: TableInfo, limit: int) -> list[tuple[int, tuple[Any, ...]]]:
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


def _type_label(value: str | None) -> str:
    if not value:
        return "—"
    return TYPE_LABELS.get(value, value)


def _policy_conflicts(
    rule: DatasetRule, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """force_not_sensitive verdicts that contradict a configured transform.

    These are warnings only: execution deliberately keeps the policy transform
    because under-masking is not an acceptable failure mode.
    """
    conflicts: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("override_verdict") != FORCE_NOT_SENSITIVE:
            continue
        table_policy = rule.tables.get(finding["table_name"])
        if table_policy is None or finding["column_name"] not in table_policy.columns:
            continue
        detail = table_policy.columns[finding["column_name"]]
        conflicts.append(
            {
                "table_name": finding["table_name"],
                "column_name": finding["column_name"],
                "transformer": detail.transformer,
                "verdict": finding["override_verdict"],
                "reason": finding.get("override_reason", ""),
                "operator": finding.get("override_operator"),
                "override_at": finding.get("override_at"),
                "message": (
                    "人工裁定为非敏感，但策略仍配置了脱敏；"
                    "为遵守“宁多脱不漏脱”，本次运行仍然执行脱敏。"
                ),
            }
        )
    return conflicts


def _markdown(
    inventory: DatasetInventory,
    policy: Policy,
    result: Any,
    findings: list[dict[str, Any]],
    samples: dict[str, list[dict[str, Any]]],
    warnings: list[dict[str, Any]],
    override_application: OverrideApplication | None,
) -> str:
    rule = policy.for_dataset(inventory.path)
    conflicts = _policy_conflicts(rule, findings)
    applied = {
        (table, column): detail
        for table, table_policy in rule.tables.items()
        for column, detail in table_policy.columns.items()
    }
    lines = [
        "# maskline 脱敏报告",
        "",
        f"- 运行 ID：`{result.run_id}`",
        f"- 数据集：`{inventory.path}`",
        f"- 数据集指纹：`{inventory.fingerprint}`",
        f"- 策略：`{policy.name}` (`{policy.fingerprint}`)",
        f"- 策略变更：{'是' if result.policy_changed else '否'}",
        f"- 输出库：`{result.output_path}`",
        f"- 输出库哈希：`{result.output_hash}`",
        f"- 处理行数：{result.row_count}",
        f"- 耗时：{result.elapsed_seconds:.3f} 秒",
        f"- 报告生成时间：{datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "## 字段发现",
        "",
        "| 表 | 列 | 建议类型 | 置信度 | 得分 | 命中率 | 校验通过率 | 人工裁定 | 已配置策略 |",
        "|---|---|---|---|---:|---:|---:|---|---|",
    ]
    for finding in findings:
        key = (finding["table_name"], finding["column_name"])
        detail = applied.get(key)
        configured = (
            f"{detail.transformer}" if detail else "—"
        )
        confidence = CONFIDENCE_LABELS.get(finding["confidence"], finding["confidence"])
        override_mark = OVERRIDE_LABELS.get(finding.get("override_verdict"), "—")
        lines.append(
            f"| {_cell(finding['table_name'])} | {_cell(finding['column_name'])} | "
            f"{_cell(_type_label(finding['sensitive_type']))} | {confidence} | "
            f"{finding['score']:.3f} | {finding['hit_rate']:.1%} | "
            f"{finding['validate_rate']:.1%} | {override_mark} | {configured} |"
        )
    applied_overrides = (
        override_application.applied if override_application is not None else []
    )
    unmatched_overrides = (
        override_application.unmatched if override_application is not None else []
    )
    lines.extend(
        [
            "",
            "## 人工裁定",
            "",
        ]
    )
    if applied_overrides:
        lines.append("| 表 | 列 | 裁定 | 理由 | 操作者 | 时间 | 检测器原结论 |")
        lines.append("|---|---|---|---|---|---|---|")
        for item in applied_overrides:
            detected = (
                f"{_type_label(item.detected_sensitive_type)} / "
                f"{CONFIDENCE_LABELS.get(item.detected_confidence, item.detected_confidence)} "
                f"({item.detected_score:.3f})"
            )
            lines.append(
                f"| {_cell(item.entry.table)} | {_cell(item.entry.column)} | "
                f"{OVERRIDE_LABELS.get(item.entry.verdict, item.entry.verdict)} | "
                f"{_cell(item.entry.reason)} | "
                f"{_cell(findings_by_key_operator(findings, item.entry.table, item.entry.column))} | "
                f"{_cell(findings_by_key_at(findings, item.entry.table, item.entry.column))} | "
                f"{_cell(detected)} |"
            )
    else:
        lines.append("无。本次扫描没有人工裁定生效。")
    lines.extend(["", "## 未匹配的人工裁定", ""])
    if unmatched_overrides:
        lines.append("| 数据集 | 表 | 列 | 裁定 | 未匹配原因 |")
        lines.append("|---|---|---|---|---|")
        for item in unmatched_overrides:
            dataset = item.entry.dataset_pattern
            lines.append(
                f"| {_cell(dataset)} | {_cell(item.entry.table)} | "
                f"{_cell(item.entry.column)} | "
                f"{OVERRIDE_LABELS.get(item.entry.verdict, item.entry.verdict)} | "
                f"{_cell(item.reason)} |"
            )
        lines.append("")
        lines.append(
            "> 以上裁定未命中当前表结构，通常意味着列/表已被重命名或删除。"
            "请更新 overrides 文件；旧裁定不会静默失效。"
        )
    else:
        lines.append("无。所有人工裁定都匹配到了实际列。")
    lines.extend(["", "## 人工裁定与策略冲突", ""])
    if conflicts:
        lines.append("| 表 | 列 | 策略转换器 | 处理 |")
        lines.append("|---|---|---|---|")
        for conflict in conflicts:
            lines.append(
                f"| {_cell(conflict['table_name'])} | {_cell(conflict['column_name'])} | "
                f"`{conflict['transformer']}` | {conflict['message']} |"
            )
        lines.append("")
        lines.append(
            "> 冲突不改变执行结果：策略配置优先，脱敏仍会执行。"
            "如需真正取消脱敏，请同步修改策略 YAML。"
        )
    else:
        lines.append("无。")
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
    for name, counts in sorted(result.transform_counts.items()):
        lines.append(
            f"| {TRANSFORMER_LABELS.get(name, name)} (`{name}`) | "
            f"{counts.get('seen', 0)} | {counts.get('processed', 0)} | "
            f"{counts.get('changed', 0)} |"
        )
    lines.extend(["", "## 抽样前后对比", ""])
    for table in inventory.tables:
        rows = samples.get(table.name, [])
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
    if warnings:
        lines.append("| 表 | 列 | 建议类型 | 置信度 | 得分 |")
        lines.append("|---|---|---|---|---:|")
        for warning in warnings:
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
    report_core = {
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
        },
        "applied_policy": rule.to_dict(),
        "transform_counts": result.transform_counts,
        "findings": findings,
        "samples": samples,
        "warnings": warnings,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    paths.reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = paths.reports_dir / f"{result.run_id}.json"
    md_path = paths.reports_dir / f"{result.run_id}.md"
    atomic_write_text(json_path, json.dumps(report_core, ensure_ascii=False, indent=2) + "\n")
    markdown = _markdown(inventory, policy, result, findings, samples, warnings)
    atomic_write_text(md_path, markdown)
    return {"markdown": md_path, "json": json_path}
