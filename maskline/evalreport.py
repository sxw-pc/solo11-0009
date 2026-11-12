"""Markdown / JSON rendering for evaluation reports (same numbers, two formats)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import Paths
from .evaluate import OTHER_LABEL
from .utils import atomic_write_text

STATUS_LABELS = {
    "preserved": "保持",
    "degraded": "下降",
    "lost": "归零",
    "empty": "两侧皆空",
}
KIND_LABELS = {
    "numeric": "数值",
    "categorical": "类别",
    "text": "高基数文本",
    "unknown": "未知",
}


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.1%}"


def _num(value: Any) -> str:
    return "—" if value is None else str(value)


def _tvd(value: float | None) -> str:
    return "—" if value is None else f"{value:.3f}"


def _cell(value: Any) -> str:
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if text else "—"


def _ratio(value: float | None) -> str:
    return "—" if value is None else f"{value:.3f}"


def _summary_lines(report: dict[str, Any]) -> list[str]:
    summary = report["summary"]
    counts = summary["status_counts"]
    lines = [
        "## 结论摘要",
        "",
        f"- 评估表数：{summary['tables']}，评估列数：{summary['columns']}",
        (
            f"- 列效用：保持 {counts.get('preserved', 0)} / "
            f"下降 {counts.get('degraded', 0)} / "
            f"归零 {counts.get('lost', 0)} / "
            f"两侧皆空 {counts.get('empty', 0)}"
        ),
    ]
    lost_columns = [
        f"{column['table']}.{column['column']}"
        for table in report["tables"]
        for column in table["columns"]
        if column["utility_status"] == "lost"
    ]
    if lost_columns:
        lines.append(f"- ⚠ 效用归零列：{'、'.join(lost_columns)}")
    if report["joins"]:
        rates = [
            join["product"]["preservation_rate"]
            for join in report["joins"]
            if join["product"]["preservation_rate"] is not None
        ]
        worst = f"{min(rates):.1%}" if rates else "—"
        lines.append(f"- 连接保持率：{len(report['joins'])} 项检查，产物最低 {worst}")
    else:
        lines.append("- 连接保持率：未指定外键关系（可用 --join 或源库外键约束）")
    if report["risks"]:
        parts = []
        for risk in report["risks"]:
            parts.append(
                f"{risk['table']}({'+'.join(risk['columns'])})："
                f"等价类 {risk['classes']}，最小规模 {_num(risk['min_class_size'])}，"
                f"唯一化比例 {_pct(risk['uniqueness_ratio'])}"
            )
        lines.append(f"- 重识别风险：{'；'.join(parts)}")
    else:
        lines.append("- 重识别风险：未指定准标识符组合（--qi）")
    lines.append(f"- 告警：{summary['warnings']} 条")
    lines.append("")
    return lines


def _utility_section(report: dict[str, Any]) -> list[str]:
    lines = [
        "## 效用评估（按表）",
        "",
    ]
    for table in report["tables"]:
        rows = table["rows"]
        lines.append(f"### 表 {table['table']}")
        lines.append("")
        lines.append(f"- 行数：源 {rows['source']} / 产物 {rows['product']}")
        if table["status"] == "missing_in_product":
            lines.append("- ⚠ 该表在产物中缺失，全部列效用记为归零")
            lines.append("")
            continue
        lines.append("")
        lines.append(
            "| 列 | 类型 | 基数（源→产物） | 基数比 | 空值率（源→产物） | 分布差异 TVD | 效用判定 | 标记 |"
        )
        lines.append("|---|---|---:|---:|---:|---:|---|---|")
        for column in table["columns"]:
            cardinality = column["cardinality"]
            null_rate = column["null_rate"]
            tvd = None
            if column["categorical"]:
                tvd = column["categorical"]["tvd"]
            elif column["numeric"]:
                tvd = column["numeric"]["tvd"]
            method_note = "（估计）" if cardinality["method"] == "hll_estimate" else ""
            lines.append(
                f"| {_cell(column['column'])} | {KIND_LABELS.get(column['kind'], column['kind'])} "
                f"| {_num(cardinality['source'])} → {_num(cardinality['product'])}{method_note} "
                f"| {_ratio(cardinality['ratio'])} "
                f"| {_pct(null_rate['source'])} → {_pct(null_rate['product'])} "
                f"| {_tvd(tvd)} "
                f"| {STATUS_LABELS.get(column['utility_status'], column['utility_status'])} "
                f"| {_cell(', '.join(column['flags']) or '—')} |"
            )
        lines.append("")
    return lines


def _distribution_section(report: dict[str, Any]) -> list[str]:
    lines = ["## 分布明细（分桶与占比）", ""]
    lines.append(
        "> 类别分布按各自频次排名对齐展示，不输出原始类别名；数值分桶边界由双侧"
        "最值外扩取整，不对应任何真实取值。样本量低于 "
        f"{report['parameters']['min_bucket_size']} 的桶已合并为“{OTHER_LABEL}”。"
    )
    lines.append("")
    any_detail = False
    for table in report["tables"]:
        for column in table["columns"]:
            categorical = column["categorical"]
            numeric = column["numeric"]
            if not categorical and not numeric:
                continue
            any_detail = True
            lines.append(f"### {table['table']}.{column['column']}")
            lines.append("")
            if categorical:
                lines.append(
                    f"类别分布（源基数 {categorical['distinct_source']} / "
                    f"产物基数 {categorical['distinct_product']}，"
                    f"TVD {_tvd(categorical['tvd'])}）："
                )
                lines.append("")
                lines.append("| 频次排名 | 源记录数 | 源占比 | 产物记录数 | 产物占比 |")
                lines.append("|---:|---:|---:|---:|---:|")
                for row in categorical["profile"]:
                    lines.append(
                        f"| 第 {row['rank']} 位 | {row['source_count']} | "
                        f"{_pct(row['source_share'])} | {row['product_count']} | "
                        f"{_pct(row['product_share'])} |"
                    )
                other = categorical["other"]
                if other:
                    lines.append(
                        f"| {OTHER_LABEL} | {other['source_count']} | "
                        f"{_pct(other['source_share'])} | "
                        f"{other['product_count']} | "
                        f"{_pct(other['product_share'])} |"
                    )
                lines.append("")
            if numeric:
                lines.append(
                    f"数值分桶（{numeric['bucket_count']} 桶，"
                    f"TVD {_tvd(numeric['tvd'])}）："
                )
                lines.append("")
                lines.append("| 分桶 | 源记录数 | 源占比 | 产物记录数 | 产物占比 |")
                lines.append("|---|---:|---:|---:|---:|")
                for bucket in numeric["buckets"]:
                    lines.append(
                        f"| {_cell(bucket['label'])} | {bucket['source_count']} | "
                        f"{_pct(bucket['source_share'])} | {bucket['product_count']} | "
                        f"{_pct(bucket['product_share'])} |"
                    )
                other = numeric["other"]
                if other:
                    lines.append(
                        f"| {OTHER_LABEL} | {other['source_count']} | "
                        f"{_pct(other['source_share'])} | "
                        f"{other['product_count']} | "
                        f"{_pct(other['product_share'])} |"
                    )
                lines.append("")
    if not any_detail:
        lines.append("无可展示的分布（所有列均为高基数文本或两侧皆空）。")
        lines.append("")
    return lines


def _join_section(report: dict[str, Any]) -> list[str]:
    lines = ["## 连接保持率（外键关系）", ""]
    if not report["joins"]:
        lines.append("未评估：未指定 --join，且源库未声明外键约束。")
        lines.append("")
        return lines
    lines.append(
        "| 子表.外键 | 父表.主键 | 来源 | 源保持率 | 产物保持率 | 产物孤儿行 |"
    )
    lines.append("|---|---|---|---:|---:|---:|")
    for join in report["joins"]:
        origin = "命令行" if join["origin"] == "cli" else "源库外键"
        lines.append(
            f"| {_cell(join['child_table'])}.{_cell(join['child_column'])} "
            f"| {_cell(join['parent_table'])}.{_cell(join['parent_column'])} "
            f"| {origin} "
            f"| {_pct(join['source']['preservation_rate'])} "
            f"| {_pct(join['product']['preservation_rate'])} "
            f"| {join['product']['orphan_rows']} |"
        )
    lines.append("")
    lines.append("> 保持率 = 非空外键中能在父表找到匹配的比例；NULL 外键不计入。")
    lines.append("")
    return lines


def _risk_section(report: dict[str, Any]) -> list[str]:
    lines = ["## 重识别风险（准标识符等价类，基于产物）", ""]
    if not report["risks"]:
        lines.append("未评估：未通过 --qi 指定准标识符组合。")
        lines.append("")
        return lines
    for risk in report["risks"]:
        lines.append(f"### {risk['table']}：{' + '.join(risk['columns'])}")
        lines.append("")
        lines.append(f"- 记录数：{risk['rows']}，等价类数：{risk['classes']}")
        lines.append(f"- 最小等价类规模：{_num(risk['min_class_size'])}")
        lines.append(
            f"- 唯一化记录：{risk['unique_rows']} 行"
            f"（唯一化比例 {_pct(risk['uniqueness_ratio'])}）"
        )
        lines.append("")
        lines.append("| 等价类规模 | 等价类数 | 覆盖记录数 |")
        lines.append("|---:|---:|---:|")
        tail_classes = 0
        tail_rows = 0
        for entry in risk["size_histogram"]:
            if "size" in entry and entry["size"] < 10:
                lines.append(
                    f"| {entry['size']} | {entry['classes']} | {entry['rows']} |"
                )
            else:
                tail_classes += entry["classes"]
                tail_rows += entry["rows"] if entry["rows"] is not None else 0
        if tail_classes:
            lines.append(f"| ≥10 | {tail_classes} | {tail_rows} |")
        lines.append("")
    return lines


def _warnings_section(report: dict[str, Any]) -> list[str]:
    lines = ["## 告警", ""]
    if report["warnings"]:
        for warning in report["warnings"]:
            lines.append(f"- {warning}")
    else:
        lines.append("无。")
    lines.append("")
    return lines


def _rules_section(report: dict[str, Any]) -> list[str]:
    rules = report["utility_rules"]
    lines = [
        "## 判定规则与隐私说明",
        "",
        "效用判定规则：",
        "",
        f"- 保持：{rules['preserved']}",
        f"- 下降：{rules['degraded']}",
        f"- 归零：{rules['lost']}",
        f"- 两侧皆空：{rules['empty']}",
        "",
        f"隐私说明：{report['privacy_note']}",
        "",
    ]
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    source = report["source"]
    product = report["product"]
    params = report["parameters"]
    lines = [
        "# maskline 脱敏产物评估报告",
        "",
        f"- 评估 ID：`{report['evaluation_id']}`",
        f"- 源数据集：`{source['path']}`（{source['kind']}，{source['rows']} 行）",
        f"- 源指纹：`{source['fingerprint']}`",
        f"- 脱敏产物：`{product['path']}`（{product['rows']} 行）",
        f"- 产物指纹：`{product['fingerprint']}`",
        f"- 生成时间：{report['generated_at']}",
        f"- 评估耗时：{report['elapsed_seconds']:.3f} 秒",
        (
            f"- 参数：数值分桶 {params['numeric_buckets']}，小样本阈值 "
            f"{params['min_bucket_size']}，类别上限 {params['categorical_max_distinct']}，"
            f"精确去重上限 {params['distinct_cap']}"
        ),
        "",
    ]
    lines += _summary_lines(report)
    lines += _utility_section(report)
    lines += _distribution_section(report)
    lines += _join_section(report)
    lines += _risk_section(report)
    lines += _warnings_section(report)
    lines += _rules_section(report)
    return "\n".join(lines)


def write_evaluation_reports(paths: Paths, report: dict[str, Any]) -> dict[str, Path]:
    """Write JSON and Markdown renderings of the same report dict."""
    paths.reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = paths.reports_dir / f"{report['evaluation_id']}.json"
    md_path = paths.reports_dir / f"{report['evaluation_id']}.md"
    atomic_write_text(json_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    atomic_write_text(md_path, render_markdown(report))
    return {"markdown": md_path, "json": json_path}
