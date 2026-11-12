"""Reversible pseudonym mapping store, physically separate from output data.

The mapping database is equivalent to a key: anyone holding it can recover all
pseudonymized values. It must never be shipped with the masked output.

Mapping databases can be partitioned into namespaces (one SQLite file per
namespace, under ``Paths.pseudomap_dir``). Datasets sharing a namespace reuse
the same pseudonyms; different namespaces are physically isolated and derive
different tokens for the same plaintext. A database records its namespace in
its own metadata table so swapped or renamed files are detected, and the
catalog binds each namespace to the dataset fingerprints and pseudonym key it
was created with.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from .utils import MasklineError, sha256_text, validate_namespace

if TYPE_CHECKING:
    from .registry import Catalog


class PseudoMapError(MasklineError):
    pass


class PseudonymCollision(PseudoMapError):
    pass


class NamespaceError(PseudoMapError):
    pass


class NamespaceKeyMismatch(NamespaceError):
    pass


class NamespaceBindingError(NamespaceError):
    pass


# Audit warning threshold for the number of entries in one mapping database.
CAPACITY_WARNING_THRESHOLD = 1_000_000

_META_DDL = """
CREATE TABLE IF NOT EXISTS pseudomap_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""


class _FileLock:
    """Advisory flock on a sibling ``.lock`` file, released on close or crash."""

    def __init__(self, db_path: Path, exclusive: bool) -> None:
        self._fh: Any = None
        self._fcntl: Any = None
        try:
            import fcntl
        except ImportError:  # pragma: no cover - non-POSIX platforms
            return
        lock_path = db_path.with_name(db_path.name + ".lock")
        self._fh = lock_path.open("a+b")
        fcntl.flock(
            self._fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        )
        self._fcntl = fcntl

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            self._fcntl.flock(self._fh.fileno(), self._fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None


class PseudoMap:

    def __init__(
        self,
        path: str | Path,
        create: bool = False,
        namespace: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.namespace = (
            validate_namespace(namespace, PseudoMapError)
            if namespace is not None
            else None
        )
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif not self.path.exists():
            raise PseudoMapError(f"pseudonym mapping database not found: {self.path}")
        # Serialize concurrent masking tasks writing the same store; the kernel
        # releases the lock if a holder dies, so a crashed run cannot wedge it.
        self._lock = _FileLock(self.path, exclusive=create)
        try:
            self.conn = sqlite3.connect(self.path)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA busy_timeout = 5000")
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pseudonym_map (
                    token TEXT PRIMARY KEY,
                    plaintext TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self.conn.execute(_META_DDL)
            self._bind_namespace(create)
            self.conn.commit()
        except Exception:
            self._lock.release()
            raise
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _bind_namespace(self, create: bool) -> None:
        """Verify (and on first use record) which namespace this file serves."""
        stored = self._meta_get("namespace")
        if self.namespace is None:
            # Default single-database mode: legacy files carry no marker and
            # are accepted as-is; a namespaced file is still reported.
            self.namespace = stored
            return
        if stored is not None and stored != self.namespace:
            raise NamespaceError(
                f"mapping database {self.path} belongs to namespace {stored!r}, "
                f"not {self.namespace!r}; refusing to use a swapped or renamed store"
            )
        if stored is None:
            if not create:
                raise NamespaceError(
                    f"mapping database {self.path} has no namespace marker; "
                    "refusing to treat it as a namespaced store"
                )
            self._meta_set("namespace", self.namespace)

    def _meta_get(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM pseudomap_meta WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def _meta_set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO pseudomap_meta (key, value) VALUES (?, ?)",
            (key, value),
        )

    def close(self) -> None:
        try:
            self.commit()
            self.conn.close()
        finally:
            self._lock.release()

    def __enter__(self) -> "PseudoMap":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def commit(self) -> None:
        self.conn.commit()

    def put(self, token: str, plaintext: str) -> None:
        existing = self.get(token)
        if existing is not None:
            if existing != plaintext:
                raise PseudonymCollision(
                    f"pseudonym collision for token {token!r}; refusing to overwrite"
                )
            return
        self.conn.execute(
            "INSERT INTO pseudonym_map (token, plaintext, created_at) VALUES (?, ?, ?)",
            (token, plaintext, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )

    def get(self, token: str) -> str | None:
        row = self.conn.execute(
            "SELECT plaintext FROM pseudonym_map WHERE token = ?", (token,)
        ).fetchone()
        return row[0] if row else None

    def reveal(self, token: str) -> str:
        plaintext = self.get(token)
        if plaintext is None:
            raise PseudoMapError(f"token not found in mapping database: {token}")
        return plaintext

    def count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM pseudonym_map").fetchone()[0])

    def iter_entries(self, limit: int = 100) -> Iterator[tuple[str, str]]:
        rows = self.conn.execute(
            "SELECT token, plaintext FROM pseudonym_map ORDER BY created_at, token LIMIT ?",
            (limit,),
        )
        for row in rows:
            yield row[0], row[1]


def namespace_key_fingerprint(namespace: str, pseudonym_key: str) -> str:
    """Non-reversible fingerprint of the key a namespace was initialized with."""
    return sha256_text(
        f"maskline-namespace-key-v1\x00{namespace}\x00{pseudonym_key}"
    )


def ensure_namespace(
    catalog: "Catalog",
    namespace: str,
    dataset_fingerprint: str,
    pseudonym_key: str,
) -> None:
    """Validate namespace/key consistency and bind the dataset before a run.

    The first run using a namespace records its key fingerprint in the catalog;
    every later run must present the same pseudonym_key. Each dataset fingerprint
    is bound to exactly one namespace so a tampered policy cannot silently move
    a dataset into another namespace's store.
    """
    validate_namespace(namespace, NamespaceError)
    key_fingerprint = namespace_key_fingerprint(namespace, pseudonym_key)
    stored = catalog.get_namespace_key_fingerprint(namespace)
    if stored is None:
        catalog.register_namespace(namespace, key_fingerprint)
        stored = catalog.get_namespace_key_fingerprint(namespace)
    if stored != key_fingerprint:
        raise NamespaceKeyMismatch(
            f"namespace {namespace!r} was initialized with a different pseudonym_key; "
            "all runs sharing a namespace must use the same key"
        )
    owner = catalog.dataset_namespace(dataset_fingerprint)
    if owner is not None and owner != namespace:
        raise NamespaceBindingError(
            f"dataset {dataset_fingerprint[:16]}... is already bound to namespace "
            f"{owner!r}; refusing to rebind it to {namespace!r}"
        )
    catalog.bind_dataset(namespace, dataset_fingerprint)


def reveal_token(mapping_path: Path, token: str) -> str:
    with PseudoMap(mapping_path) as mapping:
        return mapping.reveal(token)
