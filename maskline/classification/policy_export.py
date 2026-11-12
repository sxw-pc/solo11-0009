"""Turn classification results into a v1 masking policy consumable by `maskline run`.

The mapping is deterministic and lives entirely in this module so auditors can
read the exact level/control -> transformer decision in one place. Columns with
no classified label are omitted; their omission is reported back as a notice.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..utils import atomic_write_text

# Highest level across the applied standards decides the transformer.
LEVEL_RANK = {"L4": 4, "L3": 3, "L2": 2, "L1": 1, None: 0}

# Explicit control requirements take precedence over the level default.
CONTROL_TRANSFORMERS = (
    ("nullify", "nullify"),
    ("pseudonymization", "pseudonym"),
    ("hashing", "hash"),
    ("masking", "mask"),
    ("generalization", "generalize"),
)
LEVEL_DEFAULTS = {
    "L4": {"transformer": "pseudonym"},
    "L3": {"transformer": "mask", "params": {"keep_prefix": 1, "keep_suffix": 1}},
    "L2": {"transformer": "hash"},
    "L1": {"transformer": "round", "params": {"decimals": 2}},
}
# Generalization needs a mode parameter; only pick it for known numeric/date/address
# categories to stay inside what the transformer actually supports.
GENERALIZABLE_HINTS = ("date", "日期", "birth", "address", "地址", "age", "amount", "金额")


def _highest_level(standards: list[dict[str, Any]]) -> tuple[str | None, dict[str, Any]]:
    best = max(standards, key=lambda std: LEVEL_RANK.get(std.get("level"), 0))
    return best.get("level"), best


def _all_controls(standards: list[dict[str, Any]]) -> set[str]:
    controls: set[str] = set()
    for std in standards:
        controls.update(std.get("controls", []))
    return controls


def _transformer_for(record: dict[str, Any]) -> dict[str, Any] | None:
    standards = record.get("standards", [])
    level, _best = _highest_level(standards)
    if level is None:
        return None
    controls = _all_controls(standards)
    hint_text = " ".join(
        [
            " ".join(std.get("category") or "" for std in standards),
            record.get("column_name") or "",
            record.get("semantic_key") or "",
        ]
    ).lower()
    for control, transformer in CONTROL_TRANSFORMERS:
        if control not in controls:
            continue
        if transformer == "generalize" and not any(
            hint in hint_text for hint in GENERALIZABLE_HINTS
        ):
            continue
        if transformer == "mask":
            return {"transformer": "mask", "params": {"keep_prefix": 1, "keep_suffix": 1}}
        if transformer == "generalize":
            mode = (
                "date"
                if any(hint in hint_text for hint in ("date", "日期", "birth"))
                else "address"
            )
            return {"transformer": "generalize", "params": {"mode": mode}}
        return {"transformer": transformer}
    return dict(LEVEL_DEFAULTS[level])


def build_policy_dict(
    policy_name: str,
    dataset_path_pattern: str,
    classifications: list[dict[str, Any]],
    description: str = "",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    tables: dict[str, dict[str, Any]] = {}
    notices: list[dict[str, Any]] = []
    for record in classifications:
        table = record["table_name"]
        column = record["column_name"]
        transformer = _transformer_for(record)
        if transformer is None:
            notices.append(
                {
                    "table": table,
                    "column": column,
                    "reason": "no classified level; excluded from generated policy",
                }
            )
            continue
        tables.setdefault(table, {"columns": {}})
        tables[table]["columns"][column] = transformer
    policy = {
        "version": 1,
        "name": policy_name,
        "description": description,
        "datasets": [
            {"path": dataset_path_pattern, "tables": tables},
        ],
    }
    return policy, notices


def write_policy(
    output_path: str | Path,
    policy_name: str,
    dataset_path_pattern: str,
    classifications: list[dict[str, Any]],
    description: str = "",
) -> dict[str, Any]:
    policy, notices = build_policy_dict(
        policy_name, dataset_path_pattern, classifications, description
    )
    target = Path(output_path)
    text = yaml.safe_dump(policy, allow_unicode=True, sort_keys=False, default_flow_style=False)
    atomic_write_text(target, text)
    return {"path": target, "notices": notices, "policy": policy}
