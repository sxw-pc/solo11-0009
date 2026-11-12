"""Markdown and JSON run reports with safely redacted row samples."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Paths
from .dataset_io import iter_csv_tuples, iter_table_rows
from .policies import DatasetRule, Policy
from .registry import DatasetInventory, TableInfo
from .utils import atomic_write_text, quote_ident, sqlite_connect_readonly

REDACTED = "[源值已隐藏]"
UNMASKED = "[未脱敏，已隐藏]"
CONFIDENCE_LABELS = {"high": "高", "medium": "中", "low": "低", "none": "无"}
DECISION_LABELS = {
    "force_sensitive": "强制敏感",
    "force_not_sensitive": "强制非敏感",
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


def _finding_label(finding: dict[str, Any]) -> str:
    override = finding.get("override")
    if not override:
        return "—"
    label = DECISION_LABELS.get(override["decision"], override["decision"])
    return f"{label}：{override['reason']}"


def _detected_label(finding: dict[str, Any]) -> str:
    if not finding.get("override"):
        return CONFIDENCE_LABELS.get(finding["confidence"], finding["confidence"])
    detected = finding.get("detected_confidence") or "none"
    return CONFIDENCE_LABELS.get(detected, detected)


def _markdown(
    inventory: DatasetInventory,
    policy: Policy,
    result: Any,
    findings: list[dict[str, Any]],
    samples: dict[str, list[dict[str, Any]]],
    warnings: list[dict[str, Any]],
    adjudications: Any | None = None,
) -> str:
    rule = policy.for_dataset(inventory.path)
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
    ]
    if adjudications is not None and adjudications.applied:
        lines.append(
            f"- 人工裁定：{len(adjudications.applied)} 条已生效，"
            f"操作者 `{adjudications.operator}`，"
            f"裁定文件 `{adjudications.override_file}`，"
            f"指纹 `{adjudications.override_fingerprint}`"
        )
    elif adjudications is not None:
        lines.append("- 人工裁定：无生效条目")
    lines.extend(
        [
            "",
            "## 字段发现",
            "",
            "> 「结论」为检测器结果经人工裁定合并后的最终结论；「检测器」列始终显示原始检测结果。",
            "",
            "| 表 | 列 | 结论类型 | 结论置信度 | 检测器类型 | 检测器置信度 | 人工裁定 | 得分 | 命中率 | 校验通过率 | 已配置策略 |",
            "|---|---|---|---|---|---|---|---:|---:|---:|---|",
        ]
    )
    for finding in findings:
        key = (finding["table_name"], finding["column_name"])
        detail = applied.get(key)
        configured = f"{detail.transformer}" if detail else "—"
        effective = CONFIDENCE_LABELS.get(
            finding["confidence"], finding["confidence"]
        )
        detected = _detected_label(finding)
        detected_type = (
            finding.get("detected_type")
            if finding.get("override")
            else finding["sensitive_type"]
        )
        lines.append(
            f"| {_cell(finding['table_name'])} | {_cell(finding['column_name'])} | "
            f"{_cell(finding['sensitive_type'] or '—')} | {effective} | "
            f"{_cell(detected_type or '—')} | {detected} | "
            f"{_cell(_finding_label(finding))} | "
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
    lines.extend(["", "## 人工裁定冲突（强制非敏感但策略仍配置变换）", ""])
    conflicts = adjudications.conflicts if adjudications else []
    if conflicts:
        lines.append("| 表 | 列 | 裁定 | 理由 | 策略转换器 | 执行结果 |")
        lines.append("|---|---|---|---|---|---|")
        for conflict in conflicts:
            lines.append(
                f"| {_cell(conflict.table)} | {_cell(conflict.column)} | "
                f"{DECISION_LABELS.get(conflict.entry.decision, conflict.entry.decision)} | "
                f"{_cell(conflict.entry.reason)} | `{conflict.transformer}` | "
                "仍执行脱敏 |"
            )
        lines.append("")
        lines.append(
            "> 这些列被人工裁定为非敏感，但策略仍配置了变换。执行层保持脱敏："
            "宁可多脱，不能漏脱。请同步修改策略或撤销裁定以消除冲突。"
        )
    elif adjudications is not None and not adjudications.policy_checked and any(
        item["decision"] == "force_not_sensitive" for item in adjudications.applied
    ):
        lines.append(
            "> 本次扫描未加载策略，因此无法判断这些强制非敏感列是否仍被策略变换。"
            "执行前请用 run 复核；策略覆盖时仍会脱敏。"
        )
    else:
        lines.append("无。")
    lines.append("")
    lines.extend(["", "## 未匹配的人工裁定", ""])
    unmatched = adjudications.unmatched if adjudications else []
    if unmatched:
        lines.append("| 数据集规则 | 表 | 列 | 裁定 | 理由 | 未匹配原因 |")
        lines.append("|---|---|---|---|---|---|")
        for item in unmatched:
            lines.append(
                f"| {_cell(item.entry.dataset_pattern)} | {_cell(item.entry.table)} | "
                f"{_cell(item.entry.column)} | "
                f"{DECISION_LABELS.get(item.entry.decision, item.entry.decision)} | "
                f"{_cell(item.entry.reason)} | {_cell(item.reason)} |"
            )
        lines.append("")
        lines.append(
            "> 以上裁定没有匹配到当前的表或列（常见于列重命名、表删除）。"
            "它们当前不产生任何效果，请复核后更新或删除对应条目。"
        )
    else:
        lines.append("无。所有人工裁定均匹配到现有列。")
    lines.append("")
    return "\n".join(lines)


def generate_report(
    paths: Paths,
    inventory: DatasetInventory,
    policy: Policy,
    result: Any,
    findings: list[dict[str, Any]],
    adjudications: Any | None = None,
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
    adjudication_payload = None
    if adjudications is not None:
        adjudication_payload = {
            "operator": adjudications.operator,
            "source": adjudications.override_file,
            "fingerprint": adjudications.override_fingerprint,
            "applied": adjudications.applied,
            "conflicts": [
                {
                    "dataset": conflict.entry.dataset_pattern,
                    "table": conflict.table,
                    "column": conflict.column,
                    "decision": conflict.entry.decision,
                    "reason": conflict.entry.reason,
                    "transformer": conflict.transformer,
                    "execution": "masked",
                }
                for conflict in adjudications.conflicts
            ],
            "unmatched": [item.to_dict() for item in adjudications.unmatched],
        }
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
        "adjudications": adjudication_payload,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    paths.reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = paths.reports_dir / f"{result.run_id}.json"
    md_path = paths.reports_dir / f"{result.run_id}.md"
    atomic_write_text(json_path, json.dumps(report_core, ensure_ascii=False, indent=2) + "\n")
    markdown = _markdown(
        inventory, policy, result, findings, samples, warnings, adjudications
    )
    atomic_write_text(md_path, markdown)
    return {"markdown": md_path, "json": json_path}
