"""Bounded-memory streaming aggregation primitives.

Every primitive in this module keeps a memory footprint that is independent of
the number of rows fed into it, so the evaluator can stream tens of millions
of rows without growing linearly with the input.

The primitives only ever see *values* from the datasets; nothing here persists
raw values beyond the life of one aggregation pass, and none of them know how
to reverse pseudonyms (the evaluation package never imports the pseudonym
mapping store).
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, Iterable, Iterator

# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


def _hash64(data: bytes, seed: int) -> int:
    """Deterministic 64-bit hash used by the probabilistic sketches."""
    digest = hashlib.blake2b(data, digest_size=8, key=struct.pack("<Q", seed)).digest()
    return struct.unpack("<Q", digest)[0]


def hash_value(value: Any, salt: str = "") -> int:
    """Hash a normalized cell value into a stable 64-bit integer."""
    payload = _value_bytes(value, salt)
    return _hash64(payload, seed=0x6D61736B6C696E65)


def _value_bytes(value: Any, salt: str) -> bytes:
    if salt:
        chunk = salt.encode("utf-8") + b"\x00"
    else:
        chunk = b""
    if value is None:
        return chunk + b"\x00null"
    if isinstance(value, bytes):
        return chunk + b"\x01b:" + value
    if isinstance(value, bool):
        return chunk + (b"\x01bool:1" if value else b"\x01bool:0")
    if isinstance(value, int):
        return chunk + b"\x01i:" + str(value).encode("ascii")
    if isinstance(value, float):
        return chunk + b"\x01f:" + repr(value).encode("ascii")
    return chunk + b"\x01s:" + str(value).encode("utf-8")


# ---------------------------------------------------------------------------
# HyperLogLog: distinct-count estimation, fixed 2^p registers
# ---------------------------------------------------------------------------


class HyperLogLog:
    """HyperLogLog cardinality estimator (standard Flajolet et al. 2007)."""

    def __init__(self, precision: int = 14) -> None:
        if not 4 <= precision <= 18:
            raise ValueError("HyperLogLog precision must be between 4 and 18")
        self.precision = precision
        self._m = 1 << precision
        if precision == 4:
            alpha = 0.673
        elif precision == 5:
            alpha = 0.697
        elif precision == 6:
            alpha = 0.709
        else:
            alpha = 0.7213 / (1.0 + 1.079 / self._m)
        self._alpha = alpha
        self._registers = bytearray(self._m)

    def add_hash(self, hashed: int) -> None:
        idx = hashed & (self._m - 1)
        remaining = hashed >> self.precision
        # Position of the leftmost 1-bit, plus one; at most 65 - p.
        rank = 64 - self.precision - remaining.bit_length() + 1
        if rank > self._registers[idx]:
            self._registers[idx] = rank

    def add(self, value: Any, salt: str = "") -> None:
        self.add_hash(hash_value(value, salt))

    def estimate(self) -> int:
        registers = self._registers
        m = self._m
        raw = self._alpha * m * m / sum(2.0 ** (-rank) for rank in registers)
        # Small-range correction.
        zeros = registers.count(0)
        if raw <= 2.5 * m and zeros:
            raw = m * math.log(m / zeros)
        return int(round(raw))


# ---------------------------------------------------------------------------
# Misra-Gries: bounded heavy-hitter frequency summary
# ---------------------------------------------------------------------------


class MisraGries:
    """Misra-Gries top-k summary with O(capacity) memory.

    Stored counts undercount true frequencies by at most ``error`` (the number
    of eviction rounds). ``exact`` stays True while no eviction happened, in
    which case every stored count is the true count.
    """

    def __init__(self, capacity: int = 4096) -> None:
        if capacity < 1:
            raise ValueError("MisraGries capacity must be positive")
        self.capacity = capacity
        self.counts: dict[Any, int] = {}
        self.error = 0
        self.observed = 0
        self.evictions = 0

    @property
    def exact(self) -> bool:
        return self.evictions == 0

    def add(self, value: Any) -> None:
        self.observed += 1
        current = self.counts.get(value)
        if current is not None:
            self.counts[value] = current + 1
            return
        if len(self.counts) < self.capacity:
            self.counts[value] = 1
            return
        # Eviction round: decrement every counter, drop the zeros.
        self.evictions += 1
        self.error += 1
        survivors: dict[Any, int] = {}
        for key, count in self.counts.items():
            if count > 1:
                survivors[key] = count - 1
        self.counts = survivors

    def items(self) -> list[tuple[Any, int]]:
        """(value, lower-bound count) pairs, heaviest first."""
        return sorted(self.counts.items(), key=lambda item: (-item[1], str(item[0])))

    def true_count_bounds(self) -> dict[Any, tuple[int, int]]:
        """Each tracked value's count lies in [lower, lower + error]."""
        return {key: (count, count + self.error) for key, count in self.counts.items()}


# ---------------------------------------------------------------------------
# Numeric range tracker: streaming min/max plus exact bucket accumulation
# ---------------------------------------------------------------------------


class NumericRangeTracker:
    """Two-phase numeric histogram: discover the range, then count buckets.

    Pass 1 (``observe``) only stores min/max. Once the edges are known the
    tracker is finalized into fixed-width buckets and rows are replayed
    through ``add_bucket``; memory stays O(bucket_count).
    """

    def __init__(self, bucket_count: int = 10) -> None:
        if bucket_count < 1:
            raise ValueError("bucket_count must be positive")
        self.bucket_count = bucket_count
        self.minimum: float | None = None
        self.maximum: float | None = None
        self.total = 0
        self.nulls = 0
        self.buckets: list[int] | None = None
        self.edges: list[float] | None = None

    def observe(self, value: float | None) -> None:
        if value is None:
            self.nulls += 1
            return
        self.total += 1
        if self.minimum is None or value < self.minimum:
            self.minimum = value
        if self.maximum is None or value > self.maximum:
            self.maximum = value

    def finalize_edges(self) -> list[float]:
        """Return the bucket boundary list of length bucket_count + 1."""
        if self.minimum is None or self.maximum is None:
            raise ValueError("cannot finalize a tracker without values")
        lo, hi = self.minimum, self.maximum
        if lo == hi:
            width = 0.0
        else:
            width = (hi - lo) / self.bucket_count
        edges = [lo + width * index for index in range(self.bucket_count)]
        edges.append(hi)
        self.edges = edges
        self.buckets = [0] * self.bucket_count
        return edges

    def add_bucket(self, value: float | None) -> None:
        if value is None or self.edges is None or self.buckets is None:
            return
        index = self._bucket_index(value)
        self.buckets[index] += 1

    def _bucket_index(self, value: float) -> int:
        assert self.edges is not None
        if value <= self.edges[0]:
            return 0
        if value >= self.edges[-1]:
            return self.bucket_count - 1
        # Binary search for the right edge; value falls in [edges[i], edges[i+1]).
        lo, hi = 0, self.bucket_count - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if value < self.edges[mid + 1]:
                hi = mid
            else:
                lo = mid + 1
        return lo


# ---------------------------------------------------------------------------
# Bloom filter: bounded-memory set membership for join retention
# ---------------------------------------------------------------------------


class BloomFilter:
    """Classic bit-array Bloom filter sized for a target false-positive rate."""

    def __init__(self, expected_items: int, false_positive_rate: float = 0.01) -> None:
        if expected_items < 0:
            raise ValueError("expected_items must be non-negative")
        if not 0.0 < false_positive_rate < 1.0:
            raise ValueError("false_positive_rate must be within (0, 1)")
        self.expected_items = max(expected_items, 1)
        self.false_positive_rate = false_positive_rate
        bit_count = max(
            8,
            int(math.ceil(-(self.expected_items) * math.log(false_positive_rate) / (math.log(2) ** 2))),
        )
        # Round up to a whole byte, and cap the footprint at 8 MiB.
        bit_count = min(((bit_count + 7) // 8) * 8, 8 * 1024 * 1024 * 8)
        self.bit_count = bit_count
        self.hash_count = max(1, int(round((bit_count / self.expected_items) * math.log(2))))
        self._bits = bytearray((bit_count + 7) // 8)
        self.items_added = 0

    def add_hash(self, hashed: int) -> None:
        self.items_added += 1
        bits = self._bits
        modulo = self.bit_count
        h1 = hashed & 0xFFFFFFFF
        h2 = (hashed >> 32) & 0xFFFFFFFF
        for index in range(self.hash_count):
            position = (h1 + index * h2) % modulo
            bits[position >> 3] |= 1 << (position & 7)

    def add(self, value: Any, salt: str = "") -> None:
        self.add_hash(hash_value(value, salt))

    def might_contain_hash(self, hashed: int) -> bool:
        bits = self._bits
        modulo = self.bit_count
        h1 = hashed & 0xFFFFFFFF
        h2 = (hashed >> 32) & 0xFFFFFFFF
        for index in range(self.hash_count):
            position = (h1 + index * h2) % modulo
            if not (bits[position >> 3] & (1 << (position & 7))):
                return False
        return True

    def might_contain(self, value: Any, salt: str = "") -> bool:
        return self.might_contain_hash(hash_value(value, salt))

    @property
    def byte_size(self) -> int:
        return len(self._bits)


# ---------------------------------------------------------------------------
# External hash aggregation: exact GROUP BY with bounded RAM
# ---------------------------------------------------------------------------


class ExternalHashCounter:
    """Exact frequency counter that spills partitioned runs to a temp dir.

    Keys are fixed-length fingerprints supplied by the caller, so raw values
    never land on disk. While the in-memory buffer stays below ``max_keys``
    nothing is written; once it overflows every key is routed to one of
    ``partitions`` spill files (also bounded per file). Partitions are read
    back one at a time and aggregated, keeping peak memory independent of the
    number of distinct keys.
    """

    def __init__(
        self,
        key_size: int = 16,
        max_keys: int = 200_000,
        partitions: int = 256,
        spill_dir: str | Path | None = None,
    ) -> None:
        if not 1 <= partitions <= 65536:
            raise ValueError("partitions must be between 1 and 65536")
        self.key_size = key_size
        self.max_keys = max_keys
        self.partitions = partitions
        self._spill_root = Path(spill_dir) if spill_dir else None
        self._owns_dir = spill_dir is None
        self._buffer: dict[bytes, int] = {}
        self._spill_paths: list[Path] | None = None
        self._handles: list[Any] | None = None
        self.spilled = False
        self.total_observations = 0

    def _ensure_spill(self) -> tuple[Path, list[Path]]:
        if self._spill_paths is not None:
            return self._spill_root, self._spill_paths  # type: ignore[return-value]
        if self._spill_root is None:
            self._spill_root = Path(tempfile.mkdtemp(prefix="maskline-eval-"))
        else:
            self._spill_root.mkdir(parents=True, exist_ok=True)
        self._spill_paths = [
            self._spill_root / f"part-{index:04d}.bin" for index in range(self.partitions)
        ]
        self._handles = [path.open("ab") for path in self._spill_paths]
        return self._spill_root, self._spill_paths

    def add(self, key: bytes) -> None:
        if len(key) != self.key_size:
            raise ValueError(f"key must be exactly {self.key_size} bytes")
        self.total_observations += 1
        current = self._buffer.get(key)
        if current is not None:
            self._buffer[key] = current + 1
            return
        if self.spilled:
            # Already in external mode: route straight to the partition. A key
            # may appear in several flush runs; the per-partition read merges
            # them, so no global key index is kept in memory.
            assert self._handles is not None
            partition = self._partition_of(key)
            self._handles[partition].write(key + struct.pack("<Q", 1))
            return
        if len(self._buffer) < self.max_keys:
            self._buffer[key] = 1
            return
        # Buffer full: enter external mode, flush the buffer once.
        self._flush_buffer()
        self._buffer[key] = 1

    def _partition_of(self, key: bytes) -> int:
        return int.from_bytes(key[:2], "big") % self.partitions

    def _flush_buffer(self) -> None:
        if not self._buffer:
            return
        _root, _paths = self._ensure_spill()
        assert self._handles is not None
        self.spilled = True
        for key, count in self._buffer.items():
            partition = self._partition_of(key)
            self._handles[partition].write(key + struct.pack("<Q", count))
        for handle in self._handles:
            handle.flush()
        self._buffer = {}

    def iter_counts(self) -> Iterator[tuple[bytes, int]]:
        """Yield (key_fingerprint, exact frequency) pairs after streaming."""
        if not self.spilled:
            yield from self._buffer.items()
            return
        self._flush_buffer()
        assert self._spill_paths is not None and self._handles is not None
        for handle in self._handles:
            handle.close()
        self._handles = None
        record_size = self.key_size + 8
        aggregate: dict[bytes, int] = {}
        for path in self._spill_paths:
            if not path.exists():
                continue
            aggregate.clear()
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(record_size)
                    if not chunk:
                        break
                    if len(chunk) != record_size:
                        raise ValueError("corrupt spill record in external aggregation")
                    key = chunk[: self.key_size]
                    count = struct.unpack("<Q", chunk[self.key_size :])[0]
                    aggregate[key] = aggregate.get(key, 0) + count
            yield from aggregate.items()

    def cleanup(self) -> None:
        if self._spill_paths is None or self._spill_root is None:
            return
        for path in self._spill_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        if self._owns_dir:
            try:
                os.rmdir(self._spill_root)
            except OSError:
                pass

    def __enter__(self) -> "ExternalHashCounter":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.cleanup()


def fingerprint_key(values: Iterable[Any], salt: str, size: int = 16) -> bytes:
    """Collapse a tuple of cell values into a fixed-length random fingerprint.

    A per-run random salt means the fingerprints cannot be precomputed by an
    attacker who happens to know the plaintext domain. Two independent hash
    constructions are concatenated (a keyed 64-bit blake2b and a salted FNV-1a
    64-bit pass), so a single-algorithm collision cannot merge two distinct
    equivalence classes while keeping the footprint at 16 bytes.
    """
    parts = [salt.encode("utf-8"), b"\x00"]
    for value in values:
        parts.append(_value_bytes(value, ""))
        parts.append(b"\x1e")
    payload = b"".join(parts)
    digest = hashlib.blake2b(payload, digest_size=8, key=struct.pack("<Q", 0x4556414C)).digest()
    return digest + struct.pack("<Q", _fnv1a_64(payload))


def _fnv1a_64(data: bytes) -> int:
    result = 0xCBF29CE484222325
    for byte in data:
        result ^= byte
        result = (result * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return result
