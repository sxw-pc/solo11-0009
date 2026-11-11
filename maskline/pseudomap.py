"""Reversible pseudonym mapping store, physically separate from output data.

The mapping database is equivalent to a key: anyone holding it can recover all
pseudonymized values. It must never be shipped with the masked output.

Writes are idempotent and concurrency-safe:

* ``token`` is unique, so the same plaintext always maps to the same token and
  a second run (or a concurrent run) reuses the existing entry instead of
  replacing it.
* an existing token is never overwritten; a token that already maps to a
  different plaintext raises :class:`PseudonymCollision`.
* every write attempt is recorded in an additive operation ledger so audit
  records can be traced back to the run that inserted or reused a token. Only
  tokens and actions are recorded, never plaintext.

The legacy ``pseudonym_map`` table layout (``token``, ``plaintext``,
``created_at``) is preserved as-is, so mapping databases produced by earlier
versions can be opened and revealed without being regenerated.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .utils import MasklineError

DEFAULT_BUSY_TIMEOUT = 30.0

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS pseudonym_map (
    token TEXT PRIMARY KEY,
    plaintext TEXT NOT NULL,
    created_at TEXT NOT NULL
)
"""

_OPERATIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS pseudonym_map_operations (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    action TEXT NOT NULL,
    run_id TEXT,
    created_at TEXT NOT NULL
)
"""


class PseudoMapError(MasklineError):
    pass


class PseudonymCollision(PseudoMapError):
    pass


class PseudoMap:

    def __init__(
        self,
        path: str | Path,
        create: bool = False,
        *,
        run_id: str | None = None,
        busy_timeout: float = DEFAULT_BUSY_TIMEOUT,
    ) -> None:
        self.path = Path(path)
        self.run_id = run_id
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif not self.path.exists():
            raise PseudoMapError(f"pseudonym mapping database not found: {self.path}")
        self.conn = sqlite3.connect(self.path, timeout=busy_timeout)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout * 1000)}")
        self._inserted = 0
        self._reused = 0
        self._collision_count = 0
        # Operations for callers that do not supply a run_id; run-scoped
        # operations are read back from the ledger when a summary is built.
        self._session_operations: list[dict[str, Any]] = []
        self._ensure_schema()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- schema ---------------------------------------------------------
    def _ensure_schema(self) -> None:
        """Create missing objects without rewriting an existing mapping table."""
        columns = self._columns("pseudonym_map")
        if not columns:
            self.conn.execute(_TABLE_SQL)
        else:
            missing = {"token", "plaintext"} - set(columns)
            if missing:
                raise PseudoMapError(
                    "pseudonym mapping database has an incompatible schema; "
                    f"missing column(s): {', '.join(sorted(missing))}"
                )
            # Older databases may not carry the optional created_at column.
            # Adding a nullable column is additive and keeps existing rows.
            if "created_at" not in columns:
                try:
                    self.conn.execute(
                        "ALTER TABLE pseudonym_map ADD COLUMN created_at TEXT"
                    )
                except sqlite3.OperationalError:
                    # Another process may have added it first.
                    if "created_at" not in self._columns("pseudonym_map"):
                        raise
            if not self._has_unique_token_index():
                try:
                    self.conn.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS "
                        "pseudonym_map_token_unique ON pseudonym_map(token)"
                    )
                except sqlite3.IntegrityError as exc:
                    raise PseudoMapError(
                        "pseudonym mapping database contains duplicate tokens "
                        "and cannot be made safe for idempotent writes"
                    ) from exc
        self.conn.execute(_OPERATIONS_TABLE_SQL)
        self.conn.commit()

    def _columns(self, table: str) -> dict[str, dict[str, Any]]:
        try:
            rows = self.conn.execute(f"PRAGMA table_info({_quote(table)})").fetchall()
        except sqlite3.Error:
            return {}
        return {
            str(row[1]): {
                "type": row[2],
                "notnull": bool(row[3]),
                "default": row[4],
                "pk": bool(row[5]),
            }
            for row in rows
        }

    def _has_unique_token_index(self) -> bool:
        for index in self.conn.execute(
            f"PRAGMA index_list({_quote('pseudonym_map')})"
        ).fetchall():
            if not index[2]:
                continue
            columns = [
                row[2]
                for row in self.conn.execute(
                    f"PRAGMA index_info({_quote(str(index[1]))})"
                ).fetchall()
            ]
            if columns == ["token"]:
                return True
        return False

    # -- lifecycle ------------------------------------------------------
    def close(self) -> None:
        self.commit()
        self.conn.close()

    def __enter__(self) -> "PseudoMap":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def commit(self) -> None:
        self.conn.commit()

    # -- writes ---------------------------------------------------------
    def put(self, token: str, plaintext: str, run_id: str | None = None) -> None:
        """Idempotently record ``plaintext -> token``.

        The insert itself is atomic (``ON CONFLICT DO NOTHING``), so two runs
        writing the same token race safely and neither replaces the other's
        entry. If the token already exists with different plaintext the write
        is rejected instead of overwritten.
        """
        action_run_id = run_id if run_id is not None else self.run_id
        now = _now()
        cursor = self.conn.execute(
            "INSERT INTO pseudonym_map (token, plaintext, created_at) "
            "VALUES (?, ?, ?) ON CONFLICT(token) DO NOTHING",
            (token, plaintext, now),
        )
        if cursor.rowcount:
            self._inserted += 1
            self._record(token, "insert", action_run_id, now)
            return
        existing = self.get(token)
        if existing == plaintext:
            self._reused += 1
            self._record(token, "reuse", action_run_id, now)
            return
        self._collision_count += 1
        self._record(token, "collision", action_run_id, now)
        raise PseudonymCollision(
            f"pseudonym collision for token {token!r}; refusing to overwrite"
        )

    def _record(
        self, token: str, action: str, run_id: str | None, created_at: str
    ) -> None:
        self.conn.execute(
            "INSERT INTO pseudonym_map_operations "
            "(token, action, run_id, created_at) VALUES (?, ?, ?, ?)",
            (token, action, run_id, created_at),
        )
        if run_id is None:
            self._session_operations.append(
                {
                    "token": token,
                    "action": action,
                    "run_id": None,
                    "created_at": created_at,
                }
            )

    # -- reads ----------------------------------------------------------
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
            "SELECT token, plaintext FROM pseudonym_map "
            "ORDER BY created_at, token LIMIT ?",
            (limit,),
        )
        for row in rows:
            yield row[0], row[1]

    def iter_operations(self, limit: int = 100) -> Iterator[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT seq, token, action, run_id, created_at "
            "FROM pseudonym_map_operations ORDER BY seq LIMIT ?",
            (limit,),
        )
        for row in rows:
            yield dict(row)

    # -- run-scoped summary --------------------------------------------
    def summary(self) -> dict[str, Any]:
        """Return this writer's counters plus traceable operation records."""
        if self.run_id is None:
            operations = list(self._session_operations)
        else:
            rows = self.conn.execute(
                "SELECT seq, token, action, run_id, created_at "
                "FROM pseudonym_map_operations WHERE run_id = ? ORDER BY seq",
                (self.run_id,),
            ).fetchall()
            operations = [dict(row) for row in rows]
        return {
            "database": str(self.path),
            "run_id": self.run_id,
            "inserted": self._inserted,
            "reused": self._reused,
            "collisions": self._collision_count,
            "operation_count": len(operations),
            "operations": operations,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def reveal_token(mapping_path: Path, token: str) -> str:
    with PseudoMap(mapping_path) as mapping:
        return mapping.reveal(token)
