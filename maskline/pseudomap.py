"""Reversible pseudonym mapping store, physically separate from output data.

The mapping database is equivalent to a key: anyone holding it can recover all
pseudonymized values. It must never be shipped with the masked output.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .utils import MasklineError


class PseudoMapError(MasklineError):
    pass


class PseudonymCollision(PseudoMapError):
    pass


class PseudoMap:

    def __init__(self, path: str | Path, create: bool = False) -> None:
        self.path = Path(path)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif not self.path.exists():
            raise PseudoMapError(f"pseudonym mapping database not found: {self.path}")
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pseudonym_map (
                token TEXT PRIMARY KEY,
                plaintext TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self.conn.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        self.commit()
        self.conn.close()

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

    def iter_token_rows(self) -> Iterator[tuple[str, str]]:
        """Yield (token, plaintext) pairs ordered by token, for digesting."""
        cursor = self.conn.execute(
            "SELECT token, plaintext FROM pseudonym_map ORDER BY token"
        )
        for row in cursor:
            yield row[0], row[1]

    def iter_entries(self, limit: int = 100) -> Iterator[tuple[str, str]]:
        rows = self.conn.execute(
            "SELECT token, plaintext FROM pseudonym_map ORDER BY created_at, token LIMIT ?",
            (limit,),
        )
        for row in rows:
            yield row[0], row[1]


def reveal_token(mapping_path: Path, token: str) -> str:
    with PseudoMap(mapping_path) as mapping:
        return mapping.reveal(token)
