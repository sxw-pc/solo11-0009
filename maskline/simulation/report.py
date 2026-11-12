"""Human-readable Markdown rendering for simulation results and diffs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..utils import atomic_write_text

TRANSFORMER_LABELS = {
    "mask": "遮蔽",
    "hash": "HMAC 哈希",
    "generalize": "泛化",
    "pseudonym": "假名化",
    "nullify": "置空",
    "round": "取整",
}


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if text != "" else '""'


def _percent(value: Any) -> str:
    if value is None:
        return "—"
    return f"{value:.2%}"


def _number(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.4g}"
    return str(value)


def render_simulation_markdown(document: dict[str, Any]) -> str:
    dataset = document["dataset"]
    policy = document["policy"]
    sample = document["sample"]
    lines = [
        "# maskline 策略影响仿真评估报告",
        "",
        f"- 仿真 ID：`{document['simulation_id']}`",
        f"- 状态：`{document['status']}`",
        f"- 数据集：`{dataset['path']}`",
        f"- 数据集指纹：`{dataset['fingerprint']}`（{dataset['kind']}，{dataset['row_count']} 行）",
        f"- 策略：`{policy['name']}` 指纹 `{policy['fingerprint']}`",
        f"- 采样上限：每表 {sample['requested_sample_size']} 行；批大小 {sample['batch_size']}",
        f"- 流式模式表：{', '.join(sample['streaming_tables']) or '无'}",
        f"- 处理行数：{document['rows_processed']}；耗时：{document['elapsed_seconds']:.3f} 秒",
        f"- 生成时间：{document['created_at']}",
        "",
        "## 转换器执行统计（采样内）",
        "",
        "| 转换器 | 见到值 | 非空处理 | 发生改变 |",
        "|---|---:|---:|---:|",
    ]
    for name, counts in sorted(document.get("transform_counts", {}).items()):
        label = TRANSFORMER_LABELS.get(name, name)
        lines.append(
            f"| {label} (`{name}`) | {counts.get('seen', 0)} | "
            f"{counts.get('processed', 0)} | {counts.get('changed', 0)} |"
        )

    lines.extend(
        [
            "",
            "## 字段级指标：覆盖率 / 分布偏移 / 业务指标偏差",
            "",
            "| 表 | 列 | 转换器 | 脱敏覆盖率 | PSI | JS 散度 | 空值率(前→后) | 基数保留 | 总和偏差率 | 均值偏差率 |",
            "|---|---|---|---:|---:|---:|---|---:|---:|---:|",
        ]
    )
    for table in document["tables"]:
        for column in table["columns"]:
            coverage = column.get("coverage") or {}
            shift = column.get("distribution_shift") or {}
            kpi = column.get("kpi") or {}
            transformer = column.get("transformer") or "—"
            label = TRANSFORMER_LABELS.get(transformer, transformer)
            lines.append(
                f"| {_cell(table['table_name'])} | {_cell(column['column_name'])} | "
                f"`{transformer}`（{label}） | {_percent(coverage.get('coverage_rate'))} | "
                f"{_number(shift.get('psi'))} | {_number(shift.get('js_divergence'))} | "
                f"{_percent(shift.get('null_rate_before'))} → {_percent(shift.get('null_rate_after'))} | "
                f"{_percent(shift.get('distinct_retention'))} | "
                f"{_percent(kpi.get('sum_deviation_rate'))} | "
                f"{_percent(kpi.get('mean_deviation_rate'))} |"
            )

    lines.extend(["", "## 跨表关联保留率", ""])
    linkages = document.get("linkages", [])
    if not linkages:
        lines.append("未配置关联字段对（使用 `--linkage table.column=table.column` 指定）。")
    else:
        lines.extend(
            [
                "| 左字段 | 右字段 | 重叠(前) | 重叠(后) | 关联保留率 | 状态 |",
                "|---|---|---:|---:|---:|---|",
            ]
        )
        for item in linkages:
            left = f"{item['columns'][0]}.{item['columns'][1]}"
            right = f"{item['columns'][2]}.{item['columns'][3]}"
            status = "断裂" if item.get("fully_broken") else "保留"
            lines.append(
                f"| {_cell(left)} | {_cell(right)} | {item['overlap_before']} | "
                f"{item['overlap_after']} | {_percent(item['retention_rate'])} | {status} |"
            )

    lines.extend(["", "## 告警与边缘覆盖", ""])
    warnings = document.get("warnings", [])
    if warnings:
        for warning in warnings:
            lines.append(f"- ⚠️ {warning}")
    else:
        lines.append("- 无运行告警。")
    for table in document["tables"]:
        edges = table.get("edge_rowids") or {}
        if edges:
            formatted = ", ".join(
                f"rowid {rowid}（{', '.join(reasons)}）"
                for rowid, reasons in list(edges.items())[:8]
            )
            lines.append(f"- `{table['table_name']}` 边缘取值行：{formatted}")

    findings = document.get("findings_summary", [])
    lines.extend(["", "## 敏感识别摘要（高/中置信度）", ""])
    if findings:
        lines.extend(["| 表 | 列 | 类型 | 置信度 |", "|---|---|---|---|"])
        for finding in findings:
            lines.append(
                f"| {_cell(finding['table_name'])} | {_cell(finding['column_name'])} | "
                f"{_cell(finding.get('sensitive_type') or '—')} | {finding['confidence']} |"
            )
    else:
        lines.append("无高/中置信度敏感字段。")
    lines.append("")
    return "\n".join(lines)


def _delta_cell(item: dict[str, Any] | None, key: str, *, percent: bool = False) -> str:
    if not item or item.get(key) is None:
        return "—"
    detail = item[key]
    if detail.get("delta") is None:
        return "—"
    if percent:
        return f"{detail['previous']:.2%} → {detail['current']:.2%} (Δ {detail['delta']:+.4f})"
    return f"{_number(detail['previous'])} → {_number(detail['current'])} (Δ {detail['delta']:+.4f})"


def render_comparison_markdown(diff: dict[str, Any]) -> str:
    current = diff["current"]
    previous = diff["previous"]
    summary = diff["summary"]
    lines = [
        "# maskline 仿真版本对比",
        "",
        f"- 当前仿真：`{current['simulation_id']}` 策略指纹 `{current['policy_fingerprint']}`",
        f"- 历史仿真：`{previous['simulation_id']}` 策略指纹 `{previous['policy_fingerprint']}`",
        f"- 同一数据集：{'是' if diff['same_dataset'] else '否（跨数据集对比仅供参考）'}",
        f"- 新增覆盖字段：{summary['newly_covered']}；移除字段：{summary['removed_from_policy']}；"
        f"规则修改字段：{summary['modified']}；断裂关联：{summary['fully_broken_linkages']}",
        "",
        "## 字段指标变化",
        "",
        "| 表 | 列 | 变化 | 覆盖率变化 | PSI 变化 | JS 散度变化 | 总和偏差率变化 | 均值偏差率变化 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    change_labels = {
        "newly_covered": "新增覆盖",
        "removed_from_policy": "移除策略",
        "modified": "规则修改",
        "unchanged": "规则未变",
    }
    for item in diff["columns"]:
        lines.append(
            f"| {_cell(item['table_name'])} | {_cell(item['column_name'])} | "
            f"{change_labels.get(item['change'], item['change'])} | "
            f"{_delta_cell(item, 'coverage_rate', percent=True)} | "
            f"{_delta_cell(item, 'psi')} | {_delta_cell(item, 'js_divergence')} | "
            f"{_delta_cell(item, 'sum_deviation_rate', percent=True)} | "
            f"{_delta_cell(item, 'mean_deviation_rate', percent=True)} |"
        )

    lines.extend(["", "## 跨表关联保留率变化", ""])
    if not diff["linkages"]:
        lines.append("无关联字段对。")
    else:
        lines.extend(
            [
                "| 左字段 | 右字段 | 保留率变化 | 是否断裂 |",
                "|---|---|---|---|",
            ]
        )
        for item in diff["linkages"]:
            left = f"{item['left_table']}.{item['left_column']}"
            right = f"{item['right_table']}.{item['right_column']}"
            lines.append(
                f"| {_cell(left)} | {_cell(right)} | "
                f"{_delta_cell(item, 'retention_rate', percent=True)} | "
                f"{'是' if item['fully_broken'] else '否'} |"
            )
    lines.append("")
    return "\n".join(lines)


def write_simulation_report(
    reports_dir: Path, simulation_id: str, document: dict[str, Any]
) -> dict[str, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / f"{simulation_id}.sim.json"
    md_path = reports_dir / f"{simulation_id}.sim.md"
    import json

    atomic_write_text(
        json_path, json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    )
    atomic_write_text(md_path, render_simulation_markdown(document))
    return {"markdown": md_path, "json": json_path}


def write_comparison_report(
    reports_dir: Path, current_id: str, diff: dict[str, Any]
) -> dict[str, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / f"{current_id}.compare.json"
    md_path = reports_dir / f"{current_id}.compare.md"
    import json

    atomic_write_text(json_path, json.dumps(diff, ensure_ascii=False, indent=2) + "\n")
    atomic_write_text(md_path, render_comparison_markdown(diff))
    return {"markdown": md_path, "json": json_path}
