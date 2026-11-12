"""Memory-bounded sampling with deterministic coverage of edge values.

The sampler never materializes a whole table: rows are streamed from the
read-only source in batches and fed to a per-table reservoir. On top of the
random reservoir, a bounded set of deterministic edge rows is captured for every
policy-covered column (NULL/empty, shortest, longest, numeric minimum, numeric
maximum) so rare boundary values are represented even when the reservoir would
miss them. Edge rows are located in a single pass by rowid and re-read
afterwards, keeping extra memory independent of table size.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Iterable

from ..pipeline.steps import source_batches
from ..registry import DatasetInventory, TableInfo

RowObserver = Callable[[int, tuple[Any, ...]], None]

DEFAULT_SAMPLE_SIZE = 10_000
# Files larger than this threshold force the small-batch streaming path.
DEFAULT_FILE_SIZE_THRESHOLD = 100 * 1024 * 1024  # 100 MiB
STREAM_BATCH_SIZE = 500

EDGE_NULL = "null_or_empty"
EDGE_SHORTEST = "shortest"
EDGE_LONGEST = "longest"
EDGE_MIN = "numeric_min"
EDGE_MAX = "numeric_max"
EDGE_CATEGORIES = (EDGE_NULL, EDGE_SHORTEST, EDGE_LONGEST, EDGE_MIN, EDGE_MAX)


@dataclass(frozen=True)
class SamplingConfig:
    sample_size: int = DEFAULT_SAMPLE_SIZE
    file_size_threshold: int = DEFAULT_FILE_SIZE_THRESHOLD
    batch_size: int = 1000

    def __post_init__(self) -> None:
        if self.sample_size < 1:
            raise ValueError("sample_size must be positive")
        if self.file_size_threshold < 1:
            raise ValueError("file_size_threshold must be positive")
        if self.batch_size < 1:
            raise ValueError("batch_size must be positive")


@dataclass
class TableSample:
    table_name: str
    row_count: int
    mode: str
    rows: list[tuple[int, tuple[Any, ...]]] = field(default_factory=list)
    reservoir_size: int = 0
    edge_rowids: dict[int, list[str]] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.rows


def execution_mode(path: Path, config: SamplingConfig) -> str:
    """Return ``streaming`` for oversized files, otherwise ``batched``.

    Both paths process rows incrementally; the streaming label additionally
    switches to small read batches and guarantees no table-wide buffer is ever
    allocated, so peak memory stays bounded for very large single files.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return "streaming"
    return "streaming" if size > config.file_size_threshold else "batched"


def _as_number(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        return None
    return number if number.is_finite() else None


class _EdgeTracker:
    """Remembers the first rowid attaining each edge category per column."""

    def __init__(self, column_index: dict[str, int]) -> None:
        self._index = column_index
        # state[column][category] = (rowid, sort_key)
        self._state: dict[str, dict[str, tuple[int, Any]]] = {
            name: {} for name in column_index
        }

    def observe(self, rowid: int, values: tuple[Any, ...]) -> None:
        for name, position in self._index.items():
            value = values[position] if position < len(values) else None
            state = self._state[name]
            if value is None or value == "":
                state.setdefault(EDGE_NULL, (rowid, 0))
                continue
            text = str(value)
            length = len(text)
            current_short = state.get(EDGE_SHORTEST)
            if current_short is None or length < current_short[1]:
                state[EDGE_SHORTEST] = (rowid, length)
            current_long = state.get(EDGE_LONGEST)
            if current_long is None or length > current_long[1]:
                state[EDGE_LONGEST] = (rowid, length)
            number = _as_number(value)
            if number is not None:
                current_min = state.get(EDGE_MIN)
                if current_min is None or number < current_min[1]:
                    state[EDGE_MIN] = (rowid, number)
                current_max = state.get(EDGE_MAX)
                if current_max is None or number > current_max[1]:
                    state[EDGE_MAX] = (rowid, number)

    def edge_rowids(self) -> dict[int, list[str]]:
        result: dict[int, list[str]] = {}
        for state in self._state.values():
            for category, (rowid, _key) in state.items():
                result.setdefault(rowid, []).append(category)
        return {rowid: sorted(set(categories)) for rowid, categories in sorted(result.items())}


class _Reservoir:
    """Algorithm R reservoir sampling, O(k) memory regardless of stream size."""

    def __init__(self, capacity: int, rng: random.Random) -> None:
        self.capacity = capacity
        self.rng = rng
        self.rows: list[tuple[int, tuple[Any, ...]]] = []
        self.seen = 0

    def offer(self, rowid: int, values: tuple[Any, ...]) -> None:
        self.seen += 1
        if len(self.rows) < self.capacity:
            self.rows.append((rowid, values))
            return
        slot = self.rng.randrange(self.seen)
        if slot < self.capacity:
            self.rows[slot] = (rowid, values)


def _stream_batches(
    inventory: DatasetInventory, table: TableInfo, mode: str, config: SamplingConfig
) -> Iterable[list[tuple[int, tuple[Any, ...]]]]:
    batch_size = STREAM_BATCH_SIZE if mode == "streaming" else config.batch_size
    yield from source_batches(inventory, table, 0, batch_size)


def sample_table(
    inventory: DatasetInventory,
    table: TableInfo,
    masked_columns: set[str],
    config: SamplingConfig,
    seed_text: str,
    observer: RowObserver | None = None,
) -> TableSample:
    """Sample one table in a single streaming pass plus bounded edge re-reads.

    ``observer`` is invoked for every streamed row (before sampling), which lets
    the runner accumulate full-dataset coverage and numeric KPI counters in the
    same pass and avoids a second scan of very large files.
    """
    mode = execution_mode(inventory.path, config)
    rng = random.Random(f"{seed_text}|{table.name}")
    reservoir = _Reservoir(config.sample_size, rng)
    column_index = {
        column.name: position
        for position, column in enumerate(table.columns)
        if column.name in masked_columns
    }
    edges = _EdgeTracker(column_index)
    total = 0
    for batch in _stream_batches(inventory, table, mode, config):
        for rowid, values in batch:
            total += 1
            if observer is not None:
                observer(rowid, values)
            reservoir.offer(rowid, values)
            if column_index:
                edges.observe(rowid, values)
    edge_map = edges.edge_rowids()
    chosen = {rowid for rowid, _values in reservoir.rows}
    extra = _reread_rows(inventory, table, [rowid for rowid in edge_map if rowid not in chosen])
    combined = dict(reservoir.rows)
    combined.update(extra)
    rows = sorted(combined.items())
    return TableSample(
        table_name=table.name,
        row_count=total,
        mode=mode,
        rows=rows,
        reservoir_size=len(reservoir.rows),
        edge_rowids={rowid: reasons for rowid, reasons in edge_map.items() if rowid in combined},
    )


def _reread_rows(
    inventory: DatasetInventory, table: TableInfo, rowids: list[int]
) -> dict[int, tuple[Any, ...]]:
    if not rowids:
        return {}
    wanted = set(rowids)
    found: dict[int, tuple[Any, ...]] = {}
    for batch in source_batches(inventory, table, 0, STREAM_BATCH_SIZE):
        for rowid, values in batch:
            if rowid in wanted:
                found[rowid] = values
            if len(found) == len(wanted):
                return found
    return found


def iter_all_rows(
    inventory: DatasetInventory, table: TableInfo, config: SamplingConfig
) -> Iterable[list[tuple[int, tuple[Any, ...]]]]:
    """Yield every row of a table in memory-bounded batches (full re-scan)."""
    mode = execution_mode(inventory.path, config)
    yield from _stream_batches(inventory, table, mode, config)
