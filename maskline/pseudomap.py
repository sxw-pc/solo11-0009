"""Reversible pseudonym mapping store, physically separate from output data.

The mapping database is equivalent to a key: anyone holding it can recover all
pseudonymized values. It must never be shipped with the masked output.

Key rotation
------------
Every mapping row records the ``kid`` of the pseudonym key that produced its
token. A composite primary key ``(kid, token)`` lets the same person have
independent mappings under several key generations at once: after rotation,
new tokens are written with the current kid while pre-rotation rows remain
untouched and stay revealable through their own kid.

Databases created before key ids existed (plain ``token`` primary key, no
``kid`` column) are migrated automatically on open. Their rows are tagged with
:data:`~maskline.config.DEFAULT_KID`; opening an old database never fails.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from .config import DEFAULT_KID
from .utils import MasklineError

if TYPE_CHECKING:
    from .config import SecretStore


class PseudoMapError(MasklineError):
    pass


class PseudonymCollision(PseudoMapError):
    pass


class PseudoMap:

    def __init__(
        self,
        path: str | Path,
        create: bool = False,
        current_kid: str = DEFAULT_KID,
    ) -> None:
        self.path = Path(path)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif not self.path.exists():
            raise PseudoMapError(f"pseudonym mapping database not found: {self.path}")
        self.current_kid = current_kid
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._ensure_schema()
        self.conn.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _has_kid_column(self) -> bool:
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(pseudonym_map)")}
        return "kid" in columns

    def _ensure_schema(self) -> None:
        existing = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pseudonym_map'"
        ).fetchone()
        if existing is None:
            self.conn.execute(
                """
                CREATE TABLE pseudonym_map (
                    kid TEXT NOT NULL,
                    token TEXT NOT NULL,
                    plaintext TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (kid, token)
                )
                """
            )
            self.conn.execute(
                "CREATE INDEX idx_pseudonym_map_token ON pseudonym_map(token)"
            )
            return
        if self._has_kid_column():
            return
        # Legacy database: (token PRIMARY KEY, plaintext, created_at). Rebuild
        # the table in one transaction and tag every row with the default kid.
        with self.conn:
            self.conn.execute("ALTER TABLE pseudonym_map RENAME TO pseudonym_map_legacy")
            self.conn.execute(
                """
                CREATE TABLE pseudonym_map (
                    kid TEXT NOT NULL,
                    token TEXT NOT NULL,
                    plaintext TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (kid, token)
                )
                """
            )
            self.conn.execute(
                "CREATE INDEX idx_pseudonym_map_token ON pseudonym_map(token)"
            )
            self.conn.execute(
                """
                INSERT INTO pseudonym_map (kid, token, plaintext, created_at)
                SELECT ?, token, plaintext, created_at
                FROM pseudonym_map_legacy
                """,
                (DEFAULT_KID,),
            )
            self.conn.execute("DROP TABLE pseudonym_map_legacy")

    def close(self) -> None:
        self.commit()
        self.conn.close()

    def __enter__(self) -> "PseudoMap":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def commit(self) -> None:
        self.conn.commit()

    def put(self, token: str, plaintext: str, kid: str | None = None) -> str:
        """Store a mapping under ``kid`` (defaulting to the active key).

        Returns the kid the row was written with. The same token under a
        different kid is a distinct mapping; the same ``(kid, token)`` pair
        must always resolve to the same plaintext.
        """
        kid = kid if kid is not None else self.current_kid
        existing = self.get(token, kid)
        if existing is not None:
            if existing != plaintext:
                raise PseudonymCollision(
                    f"pseudonym collision for kid {kid!r}, token {token!r}; "
                    "refusing to overwrite"
                )
            return kid
        self.conn.execute(
            "INSERT INTO pseudonym_map (kid, token, plaintext, created_at) "
            "VALUES (?, ?, ?, ?)",
            (kid, token, plaintext, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        return kid

    def get(self, token: str, kid: str | None = None) -> str | None:
        if kid is None:
            row = self.conn.execute(
                "SELECT plaintext FROM pseudonym_map WHERE token = ? ORDER BY kid LIMIT 1",
                (token,),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT plaintext FROM pseudonym_map WHERE kid = ? AND token = ?",
                (kid, token),
            ).fetchone()
        return row[0] if row else None

    def kid_for(self, token: str) -> str | None:
        """Return the kid recorded for a token (the first match if several)."""
        row = self.conn.execute(
            "SELECT kid FROM pseudonym_map WHERE token = ? ORDER BY kid LIMIT 1",
            (token,),
        ).fetchone()
        return row[0] if row else None

    def reveal(self, token: str, secrets_store: "SecretStore | None" = None) -> str:
        """Reveal a token, selecting the key by the kid stored on its row.

        With a :class:`~maskline.config.SecretStore` the stored plaintext is
        additionally checked against a fresh HMAC computed with that row's
        key, so a corrupted or tampered mapping cannot silently return a
        wrong value. Without a store (legacy callers/tests) the stored
        plaintext is returned directly.
        """
        row = self.conn.execute(
            "SELECT kid, plaintext FROM pseudonym_map WHERE token = ? ORDER BY kid LIMIT 1",
            (token,),
        ).fetchone()
        if row is None:
            raise PseudoMapError(f"token not found in mapping database: {token}")
        kid, plaintext = row[0], row[1]
        if secrets_store is not None:
            from .transformers.pseudonym import pseudonym_token

            key = secrets_store.key_for(kid).value
            if pseudonym_token(plaintext, key) != token:
                raise PseudoMapError(
                    f"token {token!r} does not verify against pseudonym key {kid!r}; "
                    "the mapping row or the key file may be wrong"
                )
        return plaintext

    def count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM pseudonym_map").fetchone()[0])

    def iter_entries(
        self, limit: int = 100
    ) -> Iterator[tuple[str, str]]:
        rows = self.conn.execute(
            "SELECT token, plaintext FROM pseudonym_map "
            "ORDER BY created_at, kid, token LIMIT ?",
            (limit,),
        )
        for row in rows:
            yield row[0], row[1]

    def iter_records(
        self, limit: int = 100
    ) -> Iterator[tuple[str, str, str]]:
        """Like :meth:`iter_entries` but yields ``(kid, token, plaintext)``."""
        rows = self.conn.execute(
            "SELECT kid, token, plaintext FROM pseudonym_map "
            "ORDER BY created_at, kid, token LIMIT ?",
            (limit,),
        )
        for row in rows:
            yield row[0], row[1], row[2]

    def kids_in_use(self) -> tuple[str, ...]:
        rows = self.conn.execute(
            "SELECT DISTINCT kid FROM pseudonym_map ORDER BY kid"
        ).fetchall()
        return tuple(row[0] for row in rows)


def reveal_token(
    mapping_path: Path,
    token: str,
    secrets_store: "SecretStore | None" = None,
) -> str:
    with PseudoMap(mapping_path) as mapping:
        return mapping.reveal(token, secrets_store)
