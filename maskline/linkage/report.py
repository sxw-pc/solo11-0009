"""Linkage report writers: association graph JSON plus a Markdown risk list."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import Paths
from ..utils import atomic_write_text
from .graph import LinkGraph
from .model import LEVEL_LABELS, ColumnProfile, RiskFinding, ScanWarning

EDGE_KIND_LABELS = {"equals": "等值关联", "semantic": "语义关联"}


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if text != "" else '""'


def _graph_json(
    version_no: int,
    scan_id: str,
    target: str,
    profiles: dict[str, ColumnProfile],
    graph: LinkGraph,
    risks: list[RiskFinding],
    warnings: list[ScanWarning],
    stats: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": version_no,
        "scan_id": scan_id,
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stats": stats,
        "nodes": [
            {
                "key": profile.ref.key,
                "label": profile.ref.label,
                "path": profile.ref.dataset_path,
                "table": profile.ref.table,
                "column": profile.ref.column,
                "sensitive_type": profile.sensitive_type,
                "confidence": profile.confidence,
                "score": profile.score,
                "distinct_count": profile.distinct_count,
                "key_candidate": profile.key_candidate,
                "ignored": profile.ignored,
            }
            for profile in sorted(profiles.values(), key=lambda item: item.ref.key)
        ],
        "edges": [edge.to_record() for edge in (*graph.equality_edges, *graph.semantic_edges)],
        "clusters": [
            {
                "cluster_id": cluster.cluster_id,
                "datasets": list(cluster.datasets),
                "columns": [column.ref.label for column in cluster.columns],
                "join_keys": [column.ref.label for column in cluster.join_key_columns],
                "sensitive_types": cluster.sensitive_type_scores(),
            }
            for cluster in graph.clusters
        ],
        "risks": [risk.to_record() for risk in risks],
        "warnings": [warning.to_record() for warning in warnings],
    }


def _markdown(
    version_no: int,
    scan_id: str,
    target: str,
    profiles: dict[str, ColumnProfile],
    graph: LinkGraph,
    risks: list[RiskFinding],
    warnings: list[ScanWarning],
    stats: dict[str, Any],
) -> str:
    lines = [
        "# 跨数据集敏感关联风险报告",
        "",
        f"- 结果版本：v{version_no}",
        f"- 扫描 ID：`{scan_id}`",
        f"- 扫描目标：`{target}`",
        f"- 生成时间：{datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- 文件统计：共 {stats.get('files_seen', 0)} 个"
        f"（新画像 {stats.get('files_profiled', 0)} / "
        f"复用 {stats.get('files_reused', 0)} / "
        f"跳过 {stats.get('files_skipped', 0)} / "
        f"移除 {stats.get('files_removed', 0)} / "
        f"忽略 {stats.get('files_ignored', 0)}）",
        f"- 关联边：等值 {len(graph.equality_edges)} 条 / 语义 {len(graph.semantic_edges)} 条；"
        f"集群 {len(graph.clusters)} 个",
        "",
        "## 风险点清单",
        "",
    ]
    if risks:
        lines.append("| 风险 ID | 等级 | 组合评分 | 敏感组合 | 涉及数据集 | 关联键 | 管控建议 |")
        lines.append("|---|---|---:|---|---|---|---|")
        for risk in risks:
            datasets = "; ".join(Path(path).name for path in risk.datasets)
            join_keys = "、".join(risk.join_keys) or "—"
            lines.append(
                f"| {_cell(risk.risk_id)} | {LEVEL_LABELS.get(risk.level, risk.level)} | "
                f"{risk.score:.3f} | {_cell('、'.join(sorted(risk.sensitive_types)))} | "
                f"{_cell(datasets)} | {_cell(join_keys)} | {_cell(risk.recommendation)} |"
            )
        lines.append("")
        for risk in risks:
            lines.append(f"### {risk.risk_id}（{LEVEL_LABELS.get(risk.level, risk.level)}）")
            lines.append("")
            lines.append(f"- {risk.summary}")
            if risk.combo_rules:
                labels = "、".join(rule["label"] for rule in risk.combo_rules)
                lines.append(f"- 命中组合规则：{labels}")
            lines.append("| 字段 | 敏感类型 | 置信度 | 得分 | 关联键 |")
            lines.append("|---|---|---|---:|---|")
            confidence_labels = {"high": "高", "medium": "中", "low": "低", "none": "无"}
            for column in risk.columns:
                lines.append(
                    f"| {_cell(column['ref'])} | {_cell(column['sensitive_type'] or '—')} | "
                    f"{confidence_labels.get(column['confidence'], column['confidence'])} | "
                    f"{column['score']:.3f} | {'是' if column['join_key'] else '否'} |"
                )
            lines.append("")
    else:
        lines.append("无。当前数据集中未发现跨数据集敏感组合。")
        lines.append("")
    lines.extend(["## 关联关系图谱", ""])
    if graph.clusters:
        for cluster in graph.clusters:
            lines.append(
                f"### 集群 {cluster.cluster_id}"
                f"（{len(cluster.datasets)} 个数据集，{len(cluster.columns)} 个字段）"
            )
            lines.append("")
            join_keys = {column.ref.key for column in cluster.join_key_columns}
            for column in cluster.columns:
                tags = []
                if column.sensitive_type:
                    tags.append(f"{column.sensitive_type}（{column.confidence}，{column.score:.2f}）")
                if column.ref.key in join_keys:
                    tags.append("关联键")
                suffix = f" — {'；'.join(tags)}" if tags else ""
                lines.append(f"- `{_cell(column.ref.label)}`{suffix}")
            lines.append("")
            lines.append("| 左字段 | 右字段 | 重叠值数 | 包含度 |")
            lines.append("|---|---|---:|---:|")
            for edge in cluster.edges:
                lines.append(
                    f"| {_cell(edge.left.label)} | {_cell(edge.right.label)} | "
                    f"{edge.overlap} | {edge.containment:.1%} |"
                )
            lines.append("")
    else:
        lines.append("无跨数据集等值关联集群。")
        lines.append("")
    lines.extend(["## 语义关联提示", ""])
    if graph.semantic_edges:
        lines.append("| 左字段 | 右字段 | 依据 | 得分 |")
        lines.append("|---|---|---|---:|")
        for edge in graph.semantic_edges:
            lines.append(
                f"| {_cell(edge.left.label)} | {_cell(edge.right.label)} | "
                f"{_cell(edge.reason)} | {edge.score:.2f} |"
            )
        lines.append("")
        lines.append("> 语义关联表示字段含义相近但无法直接等值关联，供人工复核潜在关联维度。")
    else:
        lines.append("无。")
    lines.extend(["", "## 跳过文件告警", ""])
    if warnings:
        lines.append("| 文件 | 阶段 | 原因 |")
        lines.append("|---|---|---|")
        for warning in warnings:
            lines.append(
                f"| {_cell(warning.path)} | {_cell(warning.stage)} | {_cell(warning.message)} |"
            )
    else:
        lines.append("无。")
    lines.append("")
    return "\n".join(lines)


def write_linkage_reports(
    paths: Paths,
    version_no: int,
    scan_id: str,
    target: str,
    profiles: dict[str, ColumnProfile],
    graph: LinkGraph,
    risks: list[RiskFinding],
    warnings: list[ScanWarning],
    stats: dict[str, Any],
) -> dict[str, Path]:
    report_dir = paths.linkage_reports_dir
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / f"linkgraph-v{version_no}.json"
    md_path = report_dir / f"linkgraph-v{version_no}.md"
    payload = _graph_json(
        version_no, scan_id, target, profiles, graph, risks, warnings, stats
    )
    atomic_write_text(json_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    atomic_write_text(
        md_path,
        _markdown(version_no, scan_id, target, profiles, graph, risks, warnings, stats),
    )
    return {"json": json_path, "markdown": md_path}
