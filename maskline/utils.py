"""Small shared utilities: canonical hashing, SQLite access, atomic writes."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import urllib.parse
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock(key: str) -> threading.Lock:
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.Lock())


@contextmanager
def file_lock(lock_path: str | Path) -> Iterator[None]:
    """Exclusive lock shared by threads and processes.

    Many operations here are read-modify-write sequences (audit chain append,
    target existence check + rename). A per-thread lock serializes threads in
    one process; ``flock`` on a sidecar file serializes separate processes on
    POSIX systems. Neither lock file nor lock contents are part of any output.
    """
    target = Path(lock_path).expanduser()
    resolved = str(target.resolve())
    thread_lock = _thread_lock(resolved)
    with thread_lock:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a+", encoding="utf-8") as handle:
            locked = False
            try:
                try:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                    locked = True
                except ImportError:  # pragma: no cover - Windows fallback
                    pass
                yield
            finally:
                if locked:
                    try:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    except ImportError:  # pragma: no cover
                        pass


class MasklineError(RuntimeError):
    """Base class for user-facing maskline errors."""


def canonical_json(value: Any) -> str:
    """Stable JSON representation used by fingerprints and hash chains."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_text(path: Path, text: str, mode: int | None = None) -> None:
    """Write text via a sibling temp file and os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def sqlite_connect_readonly(path: Path) -> Any:
    """Open SQLite without any possibility of writing to the source file."""
    import sqlite3
    resolved = path.resolve()
    uri = "file:" + urllib.parse.quote(resolved.as_posix(), safe="/:") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def normalize_sqlite_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if isinstance(value, float):
        if value != value:  # NaN
            return {"__float__": "nan"}
        if value in (float("inf"), float("-inf")):
            return {"__float__": "inf" if value > 0 else "-inf"}
        return {"__float__": repr(value)}
    return value


def csv_content_digest(path: Path) -> str:
    """Hash a CSV file's header plus rows using the same canonical form as the
    dataset registry fingerprint. Rows are padded/truncated to the header width,
    matching :func:`maskline.dataset_io.iter_csv_tuples`.
    """
    import csv

    digest = hashlib.sha256(b"maskline-csv-v1\x00")
    with Path(path).open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise MasklineError(f"CSV file has no header: {path}") from exc
        digest.update(canonical_json(header).encode("utf-8") + b"\n")
        for row in reader:
            if len(row) < len(header):
                row = row + [""] * (len(header) - len(row))
            digest.update(canonical_json(list(row[: len(header)])).encode("utf-8") + b"\n")
    return digest.hexdigest()


def content_digest(path: Path, kind: str) -> str:
    """Logical content digest for a supported artifact format."""
    if kind == "sqlite":
        return sqlite_content_digest(path)
    if kind == "csv":
        return csv_content_digest(path)
    raise MasklineError(f"unsupported artifact format: {kind!r}")


def sqlite_content_digest(path: Path) -> str:
    """Hash schema plus rows, independent of page layout and row insertion noise."""
    conn = sqlite_connect_readonly(path)
    try:
        digest = hashlib.sha256()
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        for table in tables:
            digest.update(b"\x00table\x00" + table.encode("utf-8"))
            columns = [row[1] for row in conn.execute(f"PRAGMA table_info({quote_ident(table)})")]
            digest.update(canonical_json(columns).encode("utf-8"))
            order = ", ".join(quote_ident(col) for col in columns) or "rowid"
            rows = conn.execute(
                f"SELECT * FROM {quote_ident(table)} ORDER BY {order}"
            )
            for row in rows:
                payload = [normalize_sqlite_value(value) for value in tuple(row)]
                digest.update(canonical_json(payload).encode("utf-8"))
                digest.update(b"\n")
        return digest.hexdigest()
    finally:
        conn.close()
