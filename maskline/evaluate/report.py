"""Markdown and JSON evaluation reports rendered from one canonical payload.

Both formats are generated from the same in-memory payload, so their numbers
cannot drift. A redaction guard scans the payload before rendering: the
evaluator only ever stores bucket ordinals, counts, proportions and hashes,
and the guard fails loudly if a raw value ever reaches the report layer.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..utils import MasklineError, atomic_write_text, sha256_text
from .engine import OTHER_LABEL, EvaluationResult

STATUS_LABELS = {
    "ok": "正常",
    "zero": "效用归零",
    "empty": "产物侧为空",
    "unavailable": "无法评估",
}


class ReportSafetyError(MasklineError):
    pass


def _percent(value: float) -> str:
    return f"{value * 100:.2f}%"


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if text != "" else '""'


def result_to_payload(result: EvaluationResult) -> dict[str, Any]:
    payload = asdict(result)
    payload["source_path"] = str(result.source_path)
    payload["product_path"] = str(result.product_path)
    return payload


def assert_no_plaintext(payload: dict[str, Any], forbidden_values: list[str]) -> None:
    """Fail closed if any non-empty source/product value appears verbatim."""
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    leaked = [value for value in forbidden_values if value and value in blob]
    if leaked:
        raise ReportSafetyError(
            "evaluation report would contain raw source/product values; "
            f"refusing to write it ({len(leaked)} leak(s))"
        )


def _render_table_section(table: dict[str, Any]) -> list[str]:
    lines = [
        f"### 表 {table['table']}",
        "",
        f"- 源数据行数：{table['source_rows']}；产物行数：{table['product_rows']}",
    ]
    if table.get("structural_note"):
        lines += [f"- 结构告警：{table['structural_note']}", ""]
        return lines
    lines += [
        "",
        "#### 列级指标",
        "",
        "| 列 | 状态 | 源基数(估) | 产物基数(估) | 基数保留率 | 源空值率 | 产物空值率 | 空值率变化 |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    zero_notes: list[str] = []
    for column in table["columns"]:
        card = column["cardinality"]
        nulls = column["null_rate"]
        lines.append(
            f"| {_cell(column['column'])} | {STATUS_LABELS.get(column['utility_status'], column['utility_status'])} | "
            f"{card['source_distinct_estimate']} | {card['product_distinct_estimate']} | "
            f"{_percent(card['retention_ratio'])} | {_percent(nulls['source'])} | "
            f"{_percent(nulls['product'])} | {nulls['delta']:+.4f} |"
        )
        if column.get("utility_note"):
            zero_notes.append(f"- **{_cell(column['column'])}：{column['utility_note']}**")
    if zero_notes:
        lines.append("")
        lines.extend(zero_notes)
    for column in table["columns"]:
        categorical = column.get("categorical_distribution")
        if categorical:
            lines += self_categorical_lines(column["column"], categorical)
        numeric = column.get("numeric_distribution")
        if numeric:
            lines += self_numeric_lines(column["column"], numeric)
    lines.append("")
    return lines


def self_categorical_lines(column: str, distribution: dict[str, Any]) -> list[str]:
    lines = [
        "",
        f"#### 类别分布差异：{column}（按内部匹配排序，桶名不含取值）",
        "",
        f"- 总变差距离 TVD：`{distribution['tvd']}`（0=完全一致，1=完全不同）",
        f"- 重值摘要容量：{distribution['heavy_hitter_capacity']}；"
        f"源侧精确：{'是' if distribution['source_sketch_exact'] else '否'}；"
        f"产物侧精确：{'是' if distribution['product_sketch_exact'] else '否'}",
        "",
        "| 桶 | 源计数 | 源占比 | 产物计数 | 产物占比 |",
        "|---|---:|---:|---:|---:|",
    ]
    for bucket in distribution["buckets"]:
        lines.append(
            f"| {_cell(bucket['bucket'])} | {bucket['source_count']} | "
            f"{_percent(bucket['source_share'])} | {bucket['product_count']} | "
            f"{_percent(bucket['product_share'])} |"
        )
    return lines


def self_numeric_lines(column: str, distribution: dict[str, Any]) -> list[str]:
    lines = [
        "",
        f"#### 数值分桶分布差异：{column}（{len(distribution['bucket_edges']) - 1} 个等宽桶）",
        "",
        f"- 总变差距离 TVD：`{distribution['tvd']}`（0=完全一致，1=完全不同）",
        f"- 落在源值域之外的产物值数：{distribution['product_out_of_range_values']}",
        "- 桶边界为源数据 min/max 的聚合结果，不输出任何单行取值。",
        "",
        "| 桶 | 下界 | 上界 | 源计数 | 源占比 | 产物计数 | 产物占比 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for bucket in distribution["buckets"]:
        if bucket["bucket"] == OTHER_LABEL or bucket.get("range") is None:
            lower = upper = OTHER_LABEL
        else:
            lower = bucket["range"]["lower"]
            upper = bucket["range"]["upper"]
        lines.append(
            f"| {_cell(bucket['bucket'])} | {_cell(lower)} | {_cell(upper)} | "
            f"{bucket['source_count']} | {_percent(bucket['source_share'])} | "
            f"{bucket['product_count']} | {_percent(bucket['product_share'])} |"
        )
    return lines


def _render_joins(joins: list[dict[str, Any]]) -> list[str]:
    lines = ["## 外键连接保持率", ""]
    if not joins:
        lines.append("未指定连接关系。")
        return lines
    lines += [
        "| 关系 | 状态 | 子表行数 | 空键行数 | 评估行数 | 匹配行数 | 连接保持率 |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for join in joins:
        if join["status"] != "ok":
            lines.append(
                f"| {_cell(join['relationship'])} | "
                f"{STATUS_LABELS.get(join['status'], join['status'])} | — | — | — | — | — |"
            )
            continue
        side = join["product"]
        lines.append(
            f"| {_cell(join['relationship'])} | 正常 | {side['child_rows']} | "
            f"{side['child_null_keys']} | {side['child_rows_evaluated']} | "
            f"{side['matched_rows']} | {_percent(side['retention_ratio'])} |"
        )
        if "source" in join:
            source = join["source"]
            lines.append(
                f"| └ 源侧对照 |  | {source['child_rows']} | {source['child_null_keys']} | "
                f"{source['child_rows_evaluated']} | {source['matched_rows']} | "
                f"{_percent(source['retention_ratio'])} |"
            )
    lines.append("")
    lines.append("> 连接保持率基于固定内存的布隆过滤器判定，存在已标定的假阳性上界，参数见 JSON 报告。")
    return lines


def _render_qi(qi_entries: list[dict[str, Any]]) -> list[str]:
    lines = ["## 准标识符等价类（重标识风险）", ""]
    if not qi_entries:
        lines.append("未通过 --quasi-identifier 指定准标识符组合。")
        return lines
    for entry in qi_entries:
        label = f"{entry['table']}（{', '.join(entry['columns'])}）"
        lines.append(f"### {label}")
        lines.append("")
        if entry["status"] != "ok":
            lines += [f"- 状态：{STATUS_LABELS.get(entry['status'], entry['status'])}（{entry['reason']}）", ""]
            continue
        lines += [
            f"- 总行数：{entry['rows_total']}；含空值组件、未参与分组的行数：{entry['rows_with_null_components']}",
            f"- 评估行数：{entry['rows_evaluated']}",
            f"- 等价类数量：{entry['equivalence_class_count']}",
            f"- **最小等价类规模：{entry['min_class_size']}**",
            f"- 最大等价类规模：{entry['max_class_size']}",
            f"- 单记录等价类数量：{entry['singleton_class_count']}",
            f"- **唯一化比例（单记录等价类占评估行数）：{_percent(entry['unique_ratio'])}**",
            "- 规模小于阈值的等价类数量："
            + "；".join(
                f"规模<{size}：{count} 个"
                for size, count in entry["classes_below_size"].items()
            ),
            f"- 是否触发磁盘外部聚合：{'是' if entry['external_spill_used'] else '否'}",
            "",
            "| 等价类规模 | 等价类数量 | 占比 |",
            "|---:|---:|---:|",
        ]
        for bucket in entry["class_size_distribution"]:
            lines.append(
                f"| {_cell(bucket['class_size'])} | {bucket['class_count']} | "
                f"{_percent(bucket['share'])} |"
            )
        lines.append("")
    return lines


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# maskline 脱敏产物量化评估报告",
        "",
        "本报告仅包含聚合统计、分桶结果与占比，不包含任何原始明文取值；"
        "评估全程未打开假名映射库。",
        "",
        "## 概要",
        "",
        f"- 评估 ID：`{payload['evaluation_id']}`",
        f"- 源数据集：`{payload['source_path']}`",
        f"- 源数据集 SHA-256：`{payload['source_hash']}`",
        f"- 脱敏产物：`{payload['product_path']}`",
        f"- 产物 SHA-256：`{payload['product_hash']}`",
        f"- 生成时间（UTC）：{payload['generated_at']}",
        f"- 外部聚合临时落盘字节数：{payload['spill_bytes']}",
        "",
        "### 评估参数",
        "",
        "| 参数 | 值 |",
        "|---|---|",
    ]
    for key, value in payload["config"].items():
        lines.append(f"| {_cell(key)} | {_cell(json.dumps(value, ensure_ascii=False))} |")
    lines += ["", "## 效用评估", ""]
    for table in payload["tables"]:
        lines.extend(_render_table_section(table))
    lines.extend(_render_joins(payload["joins"]))
    lines.append("")
    lines.extend(_render_qi(payload["quasi_identifiers"]))
    lines += ["## 告警", ""]
    if payload["warnings"]:
        for warning in payload["warnings"]:
            lines.append(f"- {warning}")
    else:
        lines.append("无。")
    lines.append("")
    return "\n".join(lines)


def write_reports(
    result: EvaluationResult,
    reports_dir: Path,
    forbidden_values: list[str] | None = None,
) -> dict[str, Path | str]:
    """Write JSON first, derive its hash, then render Markdown from it."""
    payload = result_to_payload(result)
    assert_no_plaintext(payload, forbidden_values or [])
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / f"{result.evaluation_id}.eval.json"
    md_path = reports_dir / f"{result.evaluation_id}.eval.md"
    json_text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_text(json_path, json_text)
    markdown = render_markdown(json.loads(json_text))
    atomic_write_text(md_path, markdown)
    return {
        "json": json_path,
        "markdown": md_path,
        "json_hash": sha256_text(json_text),
        "markdown_hash": sha256_text(markdown),
    }
