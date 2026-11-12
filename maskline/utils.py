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


class MasklineError(RuntimeError):
    """Base class for user-facing maskline errors."""


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Advisory exclusive lock backed by a sibling lock file.

    Used to serialize append-only writers (the audit hash chain) across
    threads and processes. The lock is purely advisory and never changes the
    content or hashing of the protected file. On platforms without ``fcntl``
    it degrades to a no-op; maskline targets local POSIX workspaces.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = path.with_name(path.name + ".lock")
    with lock_file.open("a+", encoding="utf-8") as handle:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - non-POSIX fallback
            yield
            return
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
