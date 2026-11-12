"""Translate linkage risk findings into a loadable masking policy suggestion.

The generated YAML conforms to the strict policy schema of ``policies.py`` so
it can be reviewed and then used directly with ``maskline run --policy``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..config import Paths
from ..policies import load_policy
from ..transformers import REGISTRY
from ..utils import atomic_write_text
from .model import LEVEL_ORDER, RiskFinding

BASE_SUGGESTIONS: dict[str, tuple[str, dict[str, Any]]] = {
    "person_name": ("pseudonym", {}),
    "mobile_phone": ("mask", {"keep_prefix": 3, "keep_suffix": 4}),
    "email": ("hash", {}),
    "id_card": ("mask", {"keep_prefix": 6, "keep_suffix": 4}),
    "bank_card": ("mask", {"keep_prefix": 6, "keep_suffix": 4}),
    "credit_code": ("mask", {"keep_prefix": 4, "keep_suffix": 4}),
    "address": ("generalize", {"mode": "address"}),
    "ipv4": ("nullify", {}),
}
CRITICAL_OVERRIDES: dict[str, tuple[str, dict[str, Any]]] = {
    "mobile_phone": ("hash", {}),
    "id_card": ("hash", {}),
    "bank_card": ("hash", {}),
    "credit_code": ("hash", {}),
}
FALLBACK = ("mask", {"keep_prefix": 2, "keep_suffix": 2})


def suggested_transformer(level: str, sensitive_type: str) -> tuple[str, dict[str, Any]]:
    if level == "critical" and sensitive_type in CRITICAL_OVERRIDES:
        transformer, params = CRITICAL_OVERRIDES[sensitive_type]
    else:
        transformer, params = BASE_SUGGESTIONS.get(sensitive_type, FALLBACK)
    resolved = REGISTRY.validate_params(transformer, params)
    return transformer, resolved


def build_suggested_policy(risks: list[RiskFinding], version_no: int) -> dict[str, Any]:
    """Build a policy-shaped dict covering every sensitive column in findings."""
    column_levels: dict[tuple[str, str, str], tuple[str, str]] = {}
    for finding in risks:
        for column in finding.columns:
            sensitive_type = column.get("sensitive_type")
            if not sensitive_type:
                continue
            key = (column["path"], column["table"], column["column"])
            current = column_levels.get(key)
            if current is None or LEVEL_ORDER[finding.level] > LEVEL_ORDER[current[0]]:
                column_levels[key] = (finding.level, sensitive_type)
    paths_by_name: dict[str, set[str]] = {}
    for path, _table, _column in column_levels:
        paths_by_name.setdefault(Path(path).name, set()).add(path)

    def display_path(path: str) -> str:
        name = Path(path).name
        return name if len(paths_by_name.get(name, ())) == 1 else path

    datasets: dict[str, dict[str, dict[str, Any]]] = {}
    for (path, table, column), (level, sensitive_type) in sorted(column_levels.items()):
        transformer, params = suggested_transformer(level, sensitive_type)
        tables = datasets.setdefault(display_path(path), {})
        tables.setdefault(table, {})[column] = {"transformer": transformer, "params": params}
    return {
        "version": 1,
        "name": f"linkage-suggested-v{version_no}",
        "description": "跨数据集关联风险建议脱敏策略，由 maskline linkscan 自动生成，请复核后使用",
        "datasets": [
            {
                "path": path,
                "tables": {
                    table: {"columns": columns} for table, columns in tables.items()
                },
            }
            for path, tables in datasets.items()
        ],
    }


def write_suggested_policy(
    paths: Paths, version_no: int, risks: list[RiskFinding]
) -> Path:
    policy = build_suggested_policy(risks, version_no)
    target_dir = paths.linkage_reports_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"linkgraph-v{version_no}.policy.yaml"
    text = yaml.safe_dump(policy, allow_unicode=True, sort_keys=False)
    atomic_write_text(target, text)
    load_policy(target)  # round-trip through the strict policy schema
    return target
