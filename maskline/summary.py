"""Cross-run summary reports for one source dataset (Markdown + JSON).

A summary aggregates every recorded run of one dataset fingerprint: per-round
sensitive-finding drift, policy diffs, masked artifact locations, and audit
anchor status. All source data is read through the existing read-only paths
(``sqlite_connect_readonly`` for SQLite state, plain reads for JSON); the only
writes are the two report files plus one entry appended to the audit chain.

Field names mirror the single-run report JSON (``run_id``, ``dataset``,
``dataset_fingerprint``, ``policy_name``, ``policy_fingerprint``, ``output``,
``output_hash``, ``rows_processed``, ``transform_counts``, ``applied_policy``,
``findings``, ``generated_at``) so downstream automation can reuse its parsing.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import AuditError, AuditLog, read_audit_entries, verify_audit
from .config import Paths
from .registry import DatasetInventory, inspect_dataset
from .report import CONFIDENCE_LABELS, TRANSFORMER_LABELS
from .utils import MasklineError, atomic_write_text, file_sha256, sqlite_connect_readonly

DETAIL_COLLAPSE_THRESHOLD = 50
SUMMARY_EVENT = "summary_report"
SENSITIVE_CONFIDENCES = ("high", "medium")

ANOMALY_LABELS = {
    "run_not_completed": "运行未完成",
    "audit_entry_missing": "缺少审计条目",
    "audit_chain_invalid": "审计链校验失败",
    "audit_log_missing": "审计日志缺失",
    "output_missing": "脱敏产物已清理",
    "report_missing": "单轮报告已清理",
    "report_unreadable": "单轮报告不可读",
}
AUDIT_STATUS_LABELS = {"ok": "校验通过", "invalid": "校验失败", "missing": "审计日志缺失"}
ANCHORED_LABELS = {True: "已锚定", False: "未锚定", None: "无法校验"}


# ---------------------------------------------------------------------------
# read-only collectors (no writes, every connection closed before returning)


def _read_checkpoint_state(
    paths: Paths, fingerprint: str
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Run records plus per-run checkpoint progress, read strictly read-only."""
    db = paths.checkpoint_db
    if not db.is_file():
        return [], {}
    conn = sqlite_connect_readonly(db)
    try:
        try:
            rows = conn.execute(
                "SELECT rowid AS order_hint, * FROM runs "
                "WHERE dataset_fingerprint = ? ORDER BY started_at, rowid",
                (fingerprint,),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        try:
            progress_rows = conn.execute(
                "SELECT run_id, SUM(rows_done) AS done FROM checkpoints GROUP BY run_id"
            ).fetchall()
            progress = {row["run_id"]: int(row["done"] or 0) for row in progress_rows}
        except sqlite3.OperationalError:
            progress = {}
    finally:
        conn.close()
    records = []
    for row in rows:
        record = dict(row)
        record["record_source"] = "checkpoint"
        records.append(record)
    return records, progress


def _read_dataset_registration(paths: Paths, fingerprint: str) -> dict[str, Any] | None:
    db = paths.meta_db
    if not db.is_file():
        return None
    conn = sqlite_connect_readonly(db)
    try:
        try:
            row = conn.execute(
                "SELECT * FROM datasets WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        except sqlite3.OperationalError:
            return None
    finally:
        conn.close()
    if row is None:
        return None
    item = dict(row)
    item["tables"] = json.loads(item.pop("tables_json"))
    return item


def _read_current_findings(paths: Paths, fingerprint: str) -> list[dict[str, Any]]:
    db = paths.meta_db
    if not db.is_file():
        return []
    conn = sqlite_connect_readonly(db)
    try:
        try:
            rows = conn.execute(
                "SELECT * FROM findings WHERE dataset_fingerprint = ? "
                "ORDER BY table_name, column_name",
                (fingerprint,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    finally:
        conn.close()
    result = []
    for row in rows:
        item = dict(row)
        item["candidates"] = json.loads(item.pop("candidates_json"))
        result.append(item)
    return result


def _read_audit_state(paths: Paths) -> dict[str, Any]:
    """Audit entries plus chain status; a broken chain never raises here."""
    if not paths.audit_path.exists():
        return {"status": "missing", "entries": [], "count": None, "head_hash": None, "error": None}
    try:
        verification = verify_audit(paths.audit_path)
        entries = read_audit_entries(paths.audit_path)
        return {
            "status": "ok",
            "entries": entries,
            "count": verification.entries,
            "head_hash": verification.head_hash,
            "error": None,
        }
    except AuditError as exc:
        try:
            entries = read_audit_entries(paths.audit_path)
        except AuditError:
            entries = []
        return {"status": "invalid", "entries": entries, "count": None, "head_hash": None,
                "error": str(exc)}


def _read_run_report(paths: Paths, run_id: str) -> tuple[dict[str, Any] | None, str | None]:
    """Per-run report JSON; returns (payload, anomaly_kind)."""
    path = paths.reports_dir / f"{run_id}.json"
    if not path.is_file():
        return None, "report_missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "report_unreadable"
    run_block = payload.get("run") if isinstance(payload, dict) else None
    if not isinstance(run_block, dict) or run_block.get("run_id") != run_id:
        return None, "report_unreadable"
    return payload, None


# ---------------------------------------------------------------------------
# assembly


def _synthesize_record(entry: dict[str, Any]) -> dict[str, Any]:
    """Checkpoint-style record for a run only visible in the audit log."""
    return {
        "run_id": entry["run_id"],
        "dataset_path": entry.get("dataset_path"),
        "dataset_fingerprint": entry.get("dataset_fingerprint"),
        "policy_path": None,
        "policy_fingerprint": entry.get("policy_fingerprint"),
        "output_path": entry.get("output_path"),
        "status": "completed",
        "started_at": entry.get("ts"),
        "updated_at": entry.get("ts"),
        "order_hint": 1_000_000_000 + int(entry.get("seq") or 0),
        "record_source": "audit",
    }


def _assemble_runs(
    records: list[dict[str, Any]],
    audit_state: dict[str, Any],
    paths: Paths,
    progress: dict[str, int],
    include_invalid: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    chain_status = audit_state["status"]
    audit_by_run = {
        entry["run_id"]: entry
        for entry in audit_state["entries"]
        if isinstance(entry.get("run_id"), str) and entry.get("event") != SUMMARY_EVENT
    }
    anomalies: list[dict[str, Any]] = []
    if chain_status == "missing":
        anomalies.append({
            "run_id": None,
            "kind": "audit_log_missing",
            "detail": f"audit log not found: {paths.audit_path}",
        })
    elif chain_status == "invalid":
        anomalies.append({
            "run_id": None,
            "kind": "audit_chain_invalid",
            "detail": audit_state["error"] or "audit chain verification failed",
        })
    runs: list[dict[str, Any]] = []
    for record in records:
        run_id = record["run_id"]
        entry = audit_by_run.get(run_id)
        report, report_anomaly = _read_run_report(paths, run_id)
        run_anomalies: list[dict[str, Any]] = []
        status = record.get("status") or "unknown"
        if status != "completed":
            run_anomalies.append({
                "kind": "run_not_completed",
                "detail": f"run status is {status!r}, expected 'completed'",
            })
        if chain_status == "ok" and entry is None:
            run_anomalies.append({
                "kind": "audit_entry_missing",
                "detail": "no audit entry anchors this run",
            })
        output_path = record.get("output_path")
        output_exists = None
        if output_path:
            output_exists = Path(output_path).is_file()
            if not output_exists:
                run_anomalies.append({
                    "kind": "output_missing",
                    "detail": f"masked output not found: {output_path}",
                })
        if report_anomaly:
            run_anomalies.append({
                "kind": report_anomaly,
                "detail": f"run report {run_id}.json is unavailable",
            })
        excluded_kinds = {"run_not_completed", "audit_entry_missing"}
        included = not any(a["kind"] in excluded_kinds for a in run_anomalies)
        if include_invalid:
            included = True
        anchored = None if chain_status != "ok" else entry is not None
        rows_processed = (entry or {}).get("rows_processed")
        if rows_processed is None:
            rows_processed = progress.get(run_id)
        run = {
            "run_id": run_id,
            "dataset": record.get("dataset_path"),
            "dataset_fingerprint": record.get("dataset_fingerprint"),
            "policy_name": (entry or {}).get("policy_name"),
            "policy_fingerprint": record.get("policy_fingerprint")
            or (entry or {}).get("policy_fingerprint"),
            "policy_changed": False,
            "output": output_path,
            "output_hash": (entry or {}).get("output_hash"),
            "rows_processed": rows_processed,
            "elapsed_seconds": (entry or {}).get("elapsed_seconds"),
            "transform_counts": (entry or {}).get("transform_counts"),
            "applied_policy": report.get("applied_policy") if report else None,
            "findings": report.get("findings") if report else None,
            "started_at": record.get("started_at"),
            "status": status,
            "included": included,
            "artifacts": {"output_exists": output_exists, "report_exists": report is not None},
            "audit": {
                "seq": (entry or {}).get("seq"),
                "entry_hash": (entry or {}).get("entry_hash"),
                "anchored": anchored,
            },
            "anomalies": run_anomalies,
            "_audit_columns": (entry or {}).get("columns"),
        }
        runs.append(run)
        anomalies.extend({"run_id": run_id, **anomaly} for anomaly in run_anomalies)
    included_runs = [run for run in runs if run["included"]]
    previous_fingerprint: str | None = None
    for run in included_runs:
        run["policy_changed"] = (
            previous_fingerprint is not None
            and run["policy_fingerprint"] != previous_fingerprint
        )
        previous_fingerprint = run["policy_fingerprint"]
    return runs, included_runs, anomalies


# ---------------------------------------------------------------------------
# drift / diff / trends


def _sensitive_findings(findings: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (finding["table_name"], finding["column_name"]): finding
        for finding in findings
        if finding.get("confidence") in SENSITIVE_CONFIDENCES
    }


def _compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "table_name": finding.get("table_name"),
        "column_name": finding.get("column_name"),
        "sensitive_type": finding.get("sensitive_type"),
        "confidence": finding.get("confidence"),
        "score": finding.get("score"),
    }


def _findings_drift(included_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    drift = []
    for previous, current in zip(included_runs, included_runs[1:]):
        entry: dict[str, Any] = {
            "from_run_id": previous["run_id"],
            "to_run_id": current["run_id"],
            "unavailable": False,
            "added": [],
            "removed": [],
            "confidence_changed": [],
        }
        if previous["findings"] is None or current["findings"] is None:
            entry["unavailable"] = True
            drift.append(entry)
            continue
        before = _sensitive_findings(previous["findings"])
        after = _sensitive_findings(current["findings"])
        entry["added"] = [
            _compact_finding(after[key]) for key in sorted(after.keys() - before.keys())
        ]
        entry["removed"] = [
            _compact_finding(before[key]) for key in sorted(before.keys() - after.keys())
        ]
        for key in sorted(before.keys() & after.keys()):
            old, new = before[key], after[key]
            if (old.get("sensitive_type"), old.get("confidence")) != (
                new.get("sensitive_type"),
                new.get("confidence"),
            ):
                entry["confidence_changed"].append({
                    "table_name": key[0],
                    "column_name": key[1],
                    "from": {
                        "sensitive_type": old.get("sensitive_type"),
                        "confidence": old.get("confidence"),
                    },
                    "to": {
                        "sensitive_type": new.get("sensitive_type"),
                        "confidence": new.get("confidence"),
                    },
                })
        drift.append(entry)
    return drift


def _full_policy_map(applied_policy: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result = {}
    for table, body in (applied_policy.get("tables") or {}).items():
        for column, detail in ((body or {}).get("columns") or {}).items():
            result[(table, column)] = {
                "transformer": (detail or {}).get("transformer"),
                "params": (detail or {}).get("params") or {},
            }
    return result


def _transformer_policy_map(columns: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (table, column): {"transformer": transformer, "params": None}
        for table, table_columns in (columns or {}).items()
        for column, transformer in (table_columns or {}).items()
    }


def _run_policy_map(
    run: dict[str, Any]
) -> tuple[dict[tuple[str, str], dict[str, Any]] | None, bool]:
    if run["applied_policy"] is not None:
        return _full_policy_map(run["applied_policy"]), True
    if run["_audit_columns"]:
        return _transformer_policy_map(run["_audit_columns"]), False
    return None, False


def _policy_changes(included_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    changes = []
    for previous, current in zip(included_runs, included_runs[1:]):
        if previous["policy_fingerprint"] == current["policy_fingerprint"]:
            continue
        entry: dict[str, Any] = {
            "from_run_id": previous["run_id"],
            "to_run_id": current["run_id"],
            "from_policy_fingerprint": previous["policy_fingerprint"],
            "to_policy_fingerprint": current["policy_fingerprint"],
            "detail_level": "fingerprint",
            "added_columns": [],
            "removed_columns": [],
            "changed_columns": [],
        }
        before, before_full = _run_policy_map(previous)
        after, after_full = _run_policy_map(current)
        if before is not None and after is not None:
            full = before_full and after_full
            entry["detail_level"] = "full" if full else "transformer"
            if not full:
                before = {key: {**value, "params": None} for key, value in before.items()}
                after = {key: {**value, "params": None} for key, value in after.items()}
            entry["added_columns"] = [
                {"table_name": key[0], "column_name": key[1], **after[key]}
                for key in sorted(after.keys() - before.keys())
            ]
            entry["removed_columns"] = [
                {"table_name": key[0], "column_name": key[1], **before[key]}
                for key in sorted(before.keys() - after.keys())
            ]
            for key in sorted(before.keys() & after.keys()):
                old, new = before[key], after[key]
                if old["transformer"] != new["transformer"] or (
                    full and old["params"] != new["params"]
                ):
                    entry["changed_columns"].append({
                        "table_name": key[0],
                        "column_name": key[1],
                        "from": old,
                        "to": new,
                    })
        changes.append(entry)
    return changes


def _trends(included_runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    trends = []
    for run in included_runs:
        findings = run["findings"]
        trends.append({
            "run_id": run["run_id"],
            "started_at": run["started_at"],
            "status": run["status"],
            "policy_fingerprint": run["policy_fingerprint"],
            "policy_changed": run["policy_changed"],
            "rows_processed": run["rows_processed"],
            "output_hash": run["output_hash"],
            "findings_total": len(findings) if findings is not None else None,
            "findings_high_medium": (
                sum(1 for f in findings if f.get("confidence") in SENSITIVE_CONFIDENCES)
                if findings is not None
                else None
            ),
        })
    return trends


# ---------------------------------------------------------------------------
# markdown rendering


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    text = str(value).replace("|", "\\|").replace("\n", " ")
    return text if text != "" else '""'


def _short(value: Any, length: int = 16) -> str:
    if not value:
        return "—"
    text = str(value)
    return f"{text[:length]}..." if len(text) > length else text


def _params_text(params: Any) -> str:
    if params is None:
        return "参数未记录"
    return f"`{json.dumps(params, ensure_ascii=False, sort_keys=True)}`"


def _finding_label(finding: dict[str, Any]) -> str:
    confidence = CONFIDENCE_LABELS.get(
        str(finding.get("confidence")), str(finding.get("confidence"))
    )
    return (
        f"{finding.get('table_name')}.{finding.get('column_name')}"
        f"（{finding.get('sensitive_type') or '—'}，{confidence}）"
    )


def _markdown(payload: dict[str, Any]) -> str:
    overview = payload["summary"]
    chain = payload["audit_chain"]
    chain_label = AUDIT_STATUS_LABELS.get(chain["status"], chain["status"])
    if chain["status"] == "ok":
        chain_text = f"{chain_label}（{chain['entries']} 条，头哈希 `{_short(chain['head_hash'])}`）"
    elif chain["status"] == "invalid":
        chain_text = f"{chain_label}：{chain['error']}"
    else:
        chain_text = chain_label
    lines = [
        "# maskline 汇总报告",
        "",
        f"- 数据集：`{overview['dataset']}`",
        f"- 数据集指纹：`{overview['dataset_fingerprint']}`",
        f"- 运行轮次：共 {overview['runs_total']} 轮"
        f"（纳入 {overview['runs_included']}，标注 {overview['runs_excluded']}）",
        f"- 首轮时间：{_cell(overview['first_run_at'])}",
        f"- 末轮时间：{_cell(overview['last_run_at'])}",
        f"- 审计链状态：{chain_text}",
        f"- 明细折叠：{'是（超过阈值，每轮明细见附录）' if overview['details_collapsed'] else '否'}",
        f"- 报告生成时间：{overview['generated_at']}",
        "",
        "## 核心变化趋势",
        "",
    ]
    trends = payload["trends"]
    if trends:
        lines.append("| # | 运行 ID | 开始时间 | 策略指纹 | 策略变更 | 处理行数 | 高/中敏感发现 | 输出哈希 |")
        lines.append("|---:|---|---|---|---|---:|---:|---|")
        for index, trend in enumerate(trends, start=1):
            lines.append(
                f"| {index} | `{trend['run_id']}` | {_cell(trend['started_at'])} | "
                f"`{_short(trend['policy_fingerprint'])}` | "
                f"{'是' if trend['policy_changed'] else '否'} | "
                f"{_cell(trend['rows_processed'])} | {_cell(trend['findings_high_medium'])} | "
                f"`{_short(trend['output_hash'])}` |"
            )
    else:
        lines.append("无纳入汇总的运行。")
    lines.extend(["", "## 策略调整差异", ""])
    changes = payload["policy_changes"]
    if not changes:
        lines.append("无。所有纳入运行使用相同的策略指纹。")
    for change in changes:
        lines.append(f"### `{change['from_run_id']}` → `{change['to_run_id']}`")
        lines.append("")
        lines.append(
            f"- 策略指纹：`{_short(change['from_policy_fingerprint'])}` → "
            f"`{_short(change['to_policy_fingerprint'])}`"
        )
        level_labels = {"full": "完整参数", "transformer": "转换器级", "fingerprint": "仅指纹"}
        lines.append(f"- 对比粒度：{level_labels.get(change['detail_level'], change['detail_level'])}")
        if change["detail_level"] == "fingerprint":
            lines.append("- 单轮报告与审计列信息均缺失，仅能确认策略指纹发生变化。")
        else:
            added = "、".join(
                f"{item['table_name']}.{item['column_name']}（{item['transformer']}）"
                for item in change["added_columns"]
            ) or "无"
            removed = "、".join(
                f"{item['table_name']}.{item['column_name']}（{item['transformer']}）"
                for item in change["removed_columns"]
            ) or "无"
            lines.append(f"- 新增列：{added}")
            lines.append(f"- 移除列：{removed}")
            if change["changed_columns"]:
                lines.append("- 变更列：")
                for item in change["changed_columns"]:
                    old, new = item["from"], item["to"]
                    lines.append(
                        f"  - {item['table_name']}.{item['column_name']}："
                        f"{old['transformer']} → {new['transformer']}"
                        f"（参数 {_params_text(old['params'])} → {_params_text(new['params'])}）"
                    )
            else:
                lines.append("- 变更列：无")
        lines.append("")
    lines.extend(["", "## 敏感发现漂移", ""])
    drift = payload["findings_drift"]
    if not drift:
        lines.append("无。可用于对比的连续运行不足两轮。")
    for entry in drift:
        lines.append(f"### `{entry['from_run_id']}` → `{entry['to_run_id']}`")
        lines.append("")
        if entry["unavailable"]:
            lines.append("- 无法对比：至少一轮的单轮报告已清理或不可读。")
        elif not entry["added"] and not entry["removed"] and not entry["confidence_changed"]:
            lines.append("- 无变化。")
        else:
            added = "、".join(_finding_label(item) for item in entry["added"]) or "无"
            removed = "、".join(_finding_label(item) for item in entry["removed"]) or "无"
            lines.append(f"- 新增发现：{added}")
            lines.append(f"- 消失发现：{removed}")
            if entry["confidence_changed"]:
                lines.append("- 置信度/类型变化：")
                for item in entry["confidence_changed"]:
                    old, new = item["from"], item["to"]
                    old_conf = CONFIDENCE_LABELS.get(old["confidence"], old["confidence"])
                    new_conf = CONFIDENCE_LABELS.get(new["confidence"], new["confidence"])
                    lines.append(
                        f"  - {item['table_name']}.{item['column_name']}："
                        f"{old['sensitive_type'] or '—'}（{old_conf}）→ "
                        f"{new['sensitive_type'] or '—'}（{new_conf}）"
                    )
            else:
                lines.append("- 置信度/类型变化：无")
        lines.append("")
    lines.extend(["", "## 审计锚点状态", ""])
    lines.append(f"- 审计链：{chain_text}")
    lines.append("")
    lines.append("| 运行 ID | 审计序号 | 锚点状态 |")
    lines.append("|---|---:|---|")
    for run in payload["runs"]:
        lines.append(
            f"| `{run['run_id']}` | {_cell(run['audit']['seq'])} | "
            f"{ANCHORED_LABELS[run['audit']['anchored']]} |"
        )
    lines.extend(["", "## 异常条目", ""])
    anomalies = payload["anomalies"]
    if anomalies:
        lines.append("| 运行 ID | 类型 | 说明 |")
        lines.append("|---|---|---|")
        for anomaly in anomalies:
            run_id = anomaly["run_id"] or "（全局）"
            label = ANOMALY_LABELS.get(anomaly["kind"], anomaly["kind"])
            lines.append(f"| `{run_id}` | {label} | {_cell(anomaly['detail'])} |")
    else:
        lines.append("无。所有运行的状态、产物与审计锚点均校验通过。")
    lines.append("")
    if overview["details_collapsed"]:
        lines.extend([
            "## 附录：每轮明细",
            "",
            f"> 历史运行超过 {overview['collapse_threshold']} 轮，每轮明细已折叠至本附录；"
            "主报告仅保留核心变化趋势。",
            "",
        ])
    else:
        lines.extend(["## 每轮明细", ""])
    for run in payload["runs"]:
        lines.extend(_run_detail_lines(run))
    return "\n".join(lines).rstrip("\n") + "\n"


def _run_detail_lines(run: dict[str, Any]) -> list[str]:
    included_text = "已纳入汇总" if run["included"] else "未纳入汇总（见异常条目）"
    output = run["output"] or "—"
    exists = run["artifacts"]["output_exists"]
    output_state = "存在" if exists else ("已清理" if exists is False else "未知")
    lines = [
        f"### `{run['run_id']}`（{_cell(run['started_at'])}）",
        "",
        f"- 状态：{run['status']}（{included_text}）",
        f"- 策略：{run['policy_name'] or '—'}（`{_short(run['policy_fingerprint'])}`）",
        f"- 输出：`{output}`（{output_state}）",
        f"- 输出哈希：`{_short(run['output_hash'], 32)}`",
        f"- 处理行数：{_cell(run['rows_processed'])}",
        f"- 审计锚点：seq={_cell(run['audit']['seq'])}，{ANCHORED_LABELS[run['audit']['anchored']]}",
    ]
    counts = run["transform_counts"] or {}
    if counts:
        parts = [
            f"{TRANSFORMER_LABELS.get(name, name)}（`{name}`）"
            f"seen={item.get('seen', 0)} processed={item.get('processed', 0)} "
            f"changed={item.get('changed', 0)}"
            for name, item in sorted(counts.items())
        ]
        lines.append(f"- 转换统计：{'；'.join(parts)}")
    else:
        lines.append("- 转换统计：无数据")
    applied = run["applied_policy"]
    if applied:
        policies = []
        for table, body in (applied.get("tables") or {}).items():
            for column, detail in ((body or {}).get("columns") or {}).items():
                transformer = (detail or {}).get("transformer")
                label = TRANSFORMER_LABELS.get(str(transformer), str(transformer))
                policies.append(
                    f"{table}.{column}={label}（`{transformer}`）"
                    f"{_params_text((detail or {}).get('params'))}"
                )
        lines.append(f"- 已应用策略：{'；'.join(policies) if policies else '无'}")
    else:
        lines.append("- 已应用策略：无数据（单轮报告已清理或不可读）")
    findings = run["findings"]
    if findings is None:
        lines.append("- 敏感发现：无数据（单轮报告已清理或不可读）")
    else:
        high_medium = sum(1 for f in findings if f.get("confidence") in SENSITIVE_CONFIDENCES)
        lines.append(f"- 敏感发现：高/中置信度 {high_medium} 项，共 {len(findings)} 项")
    if run["anomalies"]:
        labels = "；".join(
            ANOMALY_LABELS.get(item["kind"], item["kind"]) for item in run["anomalies"]
        )
        lines.append(f"- 异常：{labels}")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# public entry points


def collect_summary(
    paths: Paths,
    fingerprint: str,
    *,
    inventory: DatasetInventory | None = None,
    include_invalid: bool = False,
    collapse_threshold: int = DETAIL_COLLAPSE_THRESHOLD,
) -> dict[str, Any]:
    """Build the summary payload for one dataset fingerprint (read-only)."""
    if collapse_threshold < 1:
        raise MasklineError("collapse_threshold must be positive")
    registration = _read_dataset_registration(paths, fingerprint)
    records, progress = _read_checkpoint_state(paths, fingerprint)
    audit_state = _read_audit_state(paths)
    known = {record["run_id"] for record in records}
    for entry in audit_state["entries"]:
        if entry.get("event") == SUMMARY_EVENT:
            continue
        if entry.get("dataset_fingerprint") != fingerprint:
            continue
        run_id = entry.get("run_id")
        if not isinstance(run_id, str) or run_id in known:
            continue
        records.append(_synthesize_record(entry))
        known.add(run_id)
    if not records:
        raise MasklineError(f"no runs recorded for dataset fingerprint {fingerprint}")
    records.sort(
        key=lambda record: (
            record.get("started_at") or "",
            record.get("order_hint") or 0,
            record["run_id"],
        )
    )
    runs, included_runs, anomalies = _assemble_runs(
        records, audit_state, paths, progress, include_invalid
    )
    policy_changes = _policy_changes(included_runs)
    findings_drift = _findings_drift(included_runs)
    trends = _trends(included_runs)
    for run in runs:
        run.pop("_audit_columns", None)
    if inventory is not None:
        dataset, kind = str(inventory.path), inventory.kind
    elif registration is not None:
        dataset, kind = registration.get("path"), registration.get("kind")
    else:
        dataset, kind = records[0].get("dataset_path"), None
    started = [run["started_at"] for run in included_runs if run["started_at"]]
    return {
        "summary": {
            "dataset": dataset,
            "dataset_fingerprint": fingerprint,
            "dataset_kind": kind,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "runs_total": len(runs),
            "runs_included": len(included_runs),
            "runs_excluded": len(runs) - len(included_runs),
            "details_collapsed": len(runs) > collapse_threshold,
            "collapse_threshold": collapse_threshold,
            "first_run_at": min(started) if started else None,
            "last_run_at": max(started) if started else None,
        },
        "audit_chain": {
            "status": audit_state["status"],
            "entries": audit_state["count"],
            "head_hash": audit_state["head_hash"],
            "error": audit_state["error"],
        },
        "trends": trends,
        "policy_changes": policy_changes,
        "findings_drift": findings_drift,
        "current_findings": _read_current_findings(paths, fingerprint),
        "runs": runs,
        "anomalies": anomalies,
    }


def _unique_report_paths(reports_dir: Path, base: str) -> tuple[Path, Path, str]:
    for attempt in range(1000):
        candidate = base if attempt == 0 else f"{base}-{attempt + 1}"
        md_path = reports_dir / f"{candidate}.md"
        json_path = reports_dir / f"{candidate}.json"
        if not md_path.exists() and not json_path.exists():
            return md_path, json_path, candidate
    raise MasklineError(f"cannot allocate a unique summary report name for {base}")


def generate_summary(
    paths: Paths,
    *,
    fingerprint: str | None = None,
    dataset_path: str | Path | None = None,
    include_invalid: bool = False,
    collapse_threshold: int = DETAIL_COLLAPSE_THRESHOLD,
) -> dict[str, Any]:
    """Generate the summary MD + JSON and anchor them in the audit chain.

    Exactly one of ``fingerprint`` / ``dataset_path`` is required. Anomalies
    (cleaned artifacts, broken audit chain, unfinished runs) are annotated in
    the payload but never abort generation; if the audit chain itself is
    broken, the reports are still written and the append is skipped with the
    reason returned in ``audit_error``.
    """
    if (fingerprint is None) == (dataset_path is None):
        raise MasklineError("provide exactly one of fingerprint or dataset_path")
    inventory = inspect_dataset(dataset_path) if dataset_path is not None else None
    if inventory is not None:
        fingerprint = inventory.fingerprint
    assert fingerprint is not None
    payload = collect_summary(
        paths,
        fingerprint,
        inventory=inventory,
        include_invalid=include_invalid,
        collapse_threshold=collapse_threshold,
    )
    paths.reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path, json_path, base = _unique_report_paths(
        paths.reports_dir, f"summary-{fingerprint[:16]}-{stamp}"
    )
    atomic_write_text(json_path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    atomic_write_text(md_path, _markdown(payload))
    entry = {
        "event": SUMMARY_EVENT,
        "run_id": base,
        "dataset_path": payload["summary"]["dataset"],
        "dataset_fingerprint": fingerprint,
        "runs_total": payload["summary"]["runs_total"],
        "runs_included": payload["summary"]["runs_included"],
        "runs_excluded": payload["summary"]["runs_excluded"],
        "anomaly_count": len(payload["anomalies"]),
        "report_markdown": str(md_path),
        "report_json": str(json_path),
        "report_markdown_hash": file_sha256(md_path),
        "report_json_hash": file_sha256(json_path),
    }
    try:
        stored = AuditLog(paths.audit_path).append(entry)
        audit_error = None
    except AuditError as exc:
        stored, audit_error = None, str(exc)
    return {
        "markdown": md_path,
        "json": json_path,
        "audit": stored,
        "audit_error": audit_error,
        "payload": payload,
    }
