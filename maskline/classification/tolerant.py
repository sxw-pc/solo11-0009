"""Tolerant dataset inspection for classification.

The main discovery pipeline rejects headerless CSV files outright. Classification
must not abort a whole batch because one file lacks a header, so this module
reconstructs a synthetic inventory instead:

* headerless CSV -> columns named ``col_001`` ... and a HEADERLESS degradation alert;
* deeply nested column paths (``a.b.c.d`` style names over the depth limit) ->
  the leaf token still participates in name matching but a NESTED_DEPTH alert is
  raised and the column is marked degraded.

Both degradations keep the rest of the dataset and every other dataset running.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..dataset_io import DatasetError, csv_table_name, dataset_kind
from ..detectors.patterns import EMAIL_RE, MOBILE_RE
from ..registry import ColumnInfo, DatasetInventory, TableInfo, inspect_dataset
from .models import Alert

DEFAULT_MAX_NESTING_DEPTH = 3
HEADERLESS_PREFIX = "col_"
# How many data rows to compare the first row against.
_HEADER_PROBE_ROWS = 20
# A header cell is typically short text with no spaces/punctuation noise; a data
# cell that matches a structured sensitive pattern is a strong data signal.
_DATA_PATTERNS = (MOBILE_RE, EMAIL_RE)


def _first_two_rows(path: Path) -> list[list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        rows: list[list[str]] = []
        for row in reader:
            if row:
                rows.append(row)
            if len(rows) >= _HEADER_PROBE_ROWS + 1:
                break
    return rows


def _same_shape(a: str, b: str) -> bool:
    def shape(value: str) -> str:
        return "".join("d" if char.isdigit() else ("c" if char.isalpha() else char) for char in value)

    return shape(a) == shape(b) and abs(len(a) - len(b)) <= 2


def _looks_headerless(path: Path) -> bool:
    rows = _first_two_rows(path)
    if len(rows) < 2:
        return False
    first, rest = rows[0], rows[1:]
    width = max(len(row) for row in rows)
    if len(first) != width:
        return False
    data_votes = 0
    strong_signal = False
    for index, cell in enumerate(first):
        text = cell.strip()
        peers = [row[index] for row in rest if index < len(row)]
        peer_values = [peer.strip() for peer in peers if peer.strip()]
        same_shape_as_peers = bool(
            peer_values
            and all(_same_shape(text, peer) for peer in peer_values[: _HEADER_PROBE_ROWS])
        )
        structured = (
            bool(text)
            and (
                any(pattern.search(text) for pattern in _DATA_PATTERNS)
                or text.replace(".", "", 1).replace("-", "", 1).isdigit()
            )
        )
        if structured:
            strong_signal = True
        if structured or same_shape_as_peers:
            data_votes += 1
    # Every column looks like data, and at least one structured (regex/numeric)
    # signal exists, before treating the file as headerless.
    return data_votes == width and strong_signal


@dataclass
class TolerantInventory:
    inventory: DatasetInventory
    alerts: list[Alert] = field(default_factory=list)
    headerless: bool = False

    @property
    def degraded(self) -> bool:
        return bool(self.alerts)


def _nesting_depth(column_name: str) -> int:
    # JSON-path style names such as payload.user.contact.mobile split on dots;
    # bracket notation payload[0][name] is normalized to the same shape first.
    normalized = column_name.replace("[", ".").replace("]", "")
    parts = [part for part in normalized.split(".") if part]
    return max(1, len(parts))


def _headerless_fingerprint(path: Path, rows: list[tuple[str, ...]]) -> str:
    import hashlib

    from ..utils import canonical_json

    digest = hashlib.sha256(b"maskline-headerless-csv-v1\x00")
    digest.update(str(path.name).encode("utf-8"))
    for row in rows:
        digest.update(canonical_json(list(row)).encode("utf-8") + b"\n")
    return digest.hexdigest()


def _inspect_headerless_csv(path: Path) -> TolerantInventory:
    rows: list[tuple[str, ...]] = []
    width = 0
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            rows.append(tuple(row))
            width = max(width, len(row))
    if width == 0:
        raise DatasetError(f"CSV file is empty: {path}")
    columns = tuple(
        ColumnInfo(f"{HEADERLESS_PREFIX}{index:03d}", "TEXT", True)
        for index in range(1, width + 1)
    )
    table_name = csv_table_name(path)
    fingerprint = _headerless_fingerprint(path, rows)
    table = TableInfo(name=table_name, columns=columns, row_count=len(rows))
    inventory = DatasetInventory(
        path=path.resolve(),
        kind="csv",
        fingerprint=fingerprint,
        size_bytes=path.stat().st_size,
        tables=(table,),
    )
    alert = Alert(
        code="headerless_file",
        severity="warning",
        message=(
            f"数据集 {path.name} 缺少表头，已按列序合成列名 "
            f"({columns[0].name}..{columns[-1].name})；仅依据内容识别结果分级，"
            "名称匹配规则不可用，请人工复核。"
        ),
        detail={"path": str(path), "column_count": width, "row_count": len(rows)},
    )
    return TolerantInventory(inventory=inventory, alerts=[alert], headerless=True)


def inspect_tolerant(
    path: str | Path, max_nesting_depth: int = DEFAULT_MAX_NESTING_DEPTH
) -> TolerantInventory:
    source = Path(path).expanduser().resolve()
    kind = dataset_kind(source)
    alerts: list[Alert] = []
    if kind == "csv":
        if _looks_headerless(source):
            return _inspect_headerless_csv(source)
        try:
            inventory = inspect_dataset(source)
        except DatasetError as exc:
            if "no header" in str(exc) or "empty column name" in str(exc):
                return _inspect_headerless_csv(source)
            raise
    else:
        inventory = inspect_dataset(source)
    deep_columns: list[dict[str, Any]] = []
    for table in inventory.tables:
        for column in table.columns:
            depth = _nesting_depth(column.name)
            if depth > max_nesting_depth:
                deep_columns.append(
                    {
                        "table": table.name,
                        "column": column.name,
                        "depth": depth,
                        "limit": max_nesting_depth,
                    }
                )
    for item in deep_columns:
        alerts.append(
            Alert(
                code="nested_depth",
                severity="warning",
                message=(
                    f"字段 {item['table']}.{item['column']} 嵌套深度 {item['depth']} "
                    f"超过阈值 {item['limit']}，降级为按叶节点名称与内容识别分级，请人工复核。"
                ),
                table=item["table"],
                column=item["column"],
                detail=item,
            )
        )
    return TolerantInventory(inventory=inventory, alerts=alerts)


def leaf_token(column_name: str) -> str:
    """Return the final path segment of a nested column name."""
    normalized = column_name.replace("[", ".").replace("]", "")
    parts = [part for part in normalized.split(".") if part]
    return parts[-1] if parts else column_name


def is_deep_column(column_name: str, max_nesting_depth: int = DEFAULT_MAX_NESTING_DEPTH) -> bool:
    return _nesting_depth(column_name) > max_nesting_depth
