"""Small shared utilities: canonical hashing, SQLite access, atomic writes."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None


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


class FileLock:
    """Advisory flock on a sidecar file, released on close or process death.

    The lock never goes stale: the OS releases it when the holder's file
    descriptor closes, even after SIGKILL. On platforms without fcntl the
    lock degrades to a no-op so single-process use keeps working.
    """

    def __init__(self, path: str | Path, *, blocking: bool = True) -> None:
        self.path = Path(path)
        self.blocking = blocking
        self._fd: int | None = None

    def acquire(self) -> None:
        if self._fd is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if fcntl is None:
            self._fd = -1
            return
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            flags = fcntl.LOCK_EX if self.blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
            fcntl.flock(fd, flags)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None or fd < 0:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @property
    def held(self) -> bool:
        return self._fd is not None

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


@contextlib.contextmanager
def file_lock(path: str | Path, *, blocking: bool = True) -> Iterator[FileLock]:
    """Context manager wrapper around FileLock."""
    lock = FileLock(path, blocking=blocking)
    lock.acquire()
    try:
        yield lock
    finally:
        lock.release()


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
