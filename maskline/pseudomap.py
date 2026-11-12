"""Reversible pseudonym mapping store, physically separate from output data.

The mapping database is equivalent to a key: anyone holding it can recover all
pseudonymized values. It must never be shipped with the masked output.

Entries are owned by the run that created them (``pseudonym_map.run_id``) and
reference-counted per run (``pseudonym_refs``): several runs of the same
dataset deterministically produce the same tokens, so a token may be needed
by a completed or legitimately interrupted run even after another run that
also used it turned out to be dirty. Cleanup therefore only removes entries
that were created by the dirty run and are referenced by no other run.
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
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pseudonym_refs (
                run_id TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (run_id, token)
            )
            """
        )
        self._migrate()
        self.conn.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _migrate(self) -> None:
        columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(pseudonym_map)")
        }
        if "run_id" in columns:
            return
        try:
            self.conn.execute("ALTER TABLE pseudonym_map ADD COLUMN run_id TEXT")
        except sqlite3.OperationalError:
            # Another process migrated concurrently; verify and move on.
            refreshed = {
                row[1] for row in self.conn.execute("PRAGMA table_info(pseudonym_map)")
            }
            if "run_id" not in refreshed:
                raise

    def close(self) -> None:
        self.commit()
        self.conn.close()

    def __enter__(self) -> "PseudoMap":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def commit(self) -> None:
        self.conn.commit()

    def put(self, token: str, plaintext: str, run_id: str | None = None) -> None:
        existing = self.get(token)
        if existing is not None:
            if existing != plaintext:
                raise PseudonymCollision(
                    f"pseudonym collision for token {token!r}; refusing to overwrite"
                )
        else:
            self.conn.execute(
                "INSERT INTO pseudonym_map (token, plaintext, created_at, run_id) "
                "VALUES (?, ?, ?, ?)",
                (token, plaintext, _now(), run_id),
            )
        if run_id is not None:
            self.conn.execute(
                "INSERT OR IGNORE INTO pseudonym_refs (run_id, token, created_at) "
                "VALUES (?, ?, ?)",
                (run_id, token, _now()),
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

    def count_refs(self, run_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM pseudonym_refs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return int(row[0])

    _REMOVABLE_SQL = """
            SELECT m.token FROM pseudonym_map m
            WHERE m.run_id = ?
              AND NOT EXISTS (
                  SELECT 1 FROM pseudonym_refs r
                  WHERE r.token = m.token AND r.run_id != ?
              )
            """

    def count_removable_entries(self, run_id: str) -> int:
        """How many entries ``remove_run_entries`` would drop (dry-run aid)."""
        row = self.conn.execute(
            f"SELECT COUNT(*) FROM ({self._REMOVABLE_SQL})",
            (run_id, run_id),
        ).fetchone()
        return int(row[0])

    def remove_run_entries(self, run_id: str) -> int:
        """Drop entries owned solely by ``run_id``; returns how many were removed.

        An entry is removed only when this run created it and no other run
        holds a reference to the same token. Entries created before run
        tracking existed (run_id IS NULL) are always kept. Idempotent.
        """
        rows = self.conn.execute(self._REMOVABLE_SQL, (run_id, run_id)).fetchall()
        tokens = [row[0] for row in rows]
        for token in tokens:
            self.conn.execute("DELETE FROM pseudonym_map WHERE token = ?", (token,))
        self.conn.execute("DELETE FROM pseudonym_refs WHERE run_id = ?", (run_id,))
        self.conn.commit()
        return len(tokens)

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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
