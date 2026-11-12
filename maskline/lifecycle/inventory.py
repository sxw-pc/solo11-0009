"""SQLite-backed inventory of artifacts under lifecycle management.

Two tables live here:

* ``artifacts`` — one row per managed file, with its retention window,
  expiry/grace timestamps, current status and destroy token;
* ``destruction_items`` — one row per artifact inside each destruction batch,
  with per-item outcome. A crash mid-destruction leaves rows in ``pending`` or
  ``failed``; the next destruction run resumes exactly those items, so a file
  can never be stuck in a half-deleted state.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .types import ArtifactRecord, ArtifactStatus, ArtifactType
from ..utils import MasklineError


class LifecycleInventoryError(MasklineError):
    pass


class LifecycleInventory:

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                artifact_type TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                run_id TEXT,
                dataset_fingerprint TEXT,
                content_hash TEXT,
                size_bytes INTEGER,
                created_at TEXT NOT NULL,
                retention_days INTEGER NOT NULL,
                grace_days INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                grace_ends_at TEXT NOT NULL,
                status TEXT NOT NULL,
                destroy_token TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_artifacts_status
                ON artifacts(status);
            CREATE INDEX IF NOT EXISTS idx_artifacts_dataset
                ON artifacts(dataset_fingerprint);
            CREATE TABLE IF NOT EXISTS destruction_items (
                destruction_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                path TEXT NOT NULL,
                content_hash TEXT,
                item_status TEXT NOT NULL,
                error TEXT,
                destroyed_at TEXT,
                evidence_hash TEXT,
                PRIMARY KEY (destruction_id, artifact_id)
            );
            CREATE INDEX IF NOT EXISTS idx_destruction_status
                ON destruction_items(item_status);
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "LifecycleInventory":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ artifacts

    def upsert_artifact(self, record: ArtifactRecord) -> ArtifactRecord:
        """Register an artifact, or refresh an ACTIVE/REVOKED record at the same path."""
        existing = self.get_by_path(record.path)
        if existing is not None:
            if existing.status in (ArtifactStatus.ACTIVE, ArtifactStatus.REVOKED):
                self.conn.execute(
                    """
                    UPDATE artifacts SET
                        artifact_type = ?, run_id = ?, dataset_fingerprint = ?,
                        content_hash = ?, size_bytes = ?, created_at = ?,
                        retention_days = ?, grace_days = ?, expires_at = ?,
                        grace_ends_at = ?, status = ?, destroy_token = NULL,
                        updated_at = ?
                    WHERE artifact_id = ?
                    """,
                    (
                        record.artifact_type.value, record.run_id,
                        record.dataset_fingerprint, record.content_hash,
                        record.size_bytes, record.created_at, record.retention_days,
                        record.grace_days, record.expires_at, record.grace_ends_at,
                        ArtifactStatus.ACTIVE.value, record.updated_at or record.created_at,
                        existing.artifact_id,
                    ),
                )
                self.conn.commit()
                refreshed = self.get(existing.artifact_id)
                assert refreshed is not None
                return refreshed
            if existing.status is ArtifactStatus.DESTROYED:
                # Same path holds genuinely new content after a prior destruction.
                self.conn.execute(
                    "INSERT INTO artifacts "
                    "(artifact_id, artifact_type, path, run_id, dataset_fingerprint, "
                    "content_hash, size_bytes, created_at, retention_days, grace_days, "
                    "expires_at, grace_ends_at, status, destroy_token, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    self._insert_params(record),
                )
                self.conn.commit()
                return record
            raise LifecycleInventoryError(
                f"artifact at {record.path} is {existing.status.value}; revoke or finish "
                "its destruction before registering a replacement"
            )
        self.conn.execute(
            "INSERT INTO artifacts "
            "(artifact_id, artifact_type, path, run_id, dataset_fingerprint, "
            "content_hash, size_bytes, created_at, retention_days, grace_days, "
            "expires_at, grace_ends_at, status, destroy_token, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self._insert_params(record),
        )
        self.conn.commit()
        return record

    @staticmethod
    def _insert_params(record: ArtifactRecord) -> tuple[Any, ...]:
        return (
            record.artifact_id, record.artifact_type.value, str(record.path),
            record.run_id, record.dataset_fingerprint, record.content_hash,
            record.size_bytes, record.created_at, record.retention_days,
            record.grace_days, record.expires_at, record.grace_ends_at,
            record.status.value, record.destroy_token,
            record.updated_at or record.created_at,
        )

    def get(self, artifact_id: str) -> ArtifactRecord | None:
        row = self.conn.execute(
            "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        return _record_from_row(row) if row else None

    def get_by_path(self, path: str | Path) -> ArtifactRecord | None:
        row = self.conn.execute(
            "SELECT * FROM artifacts WHERE path = ?", (str(Path(path)),)
        ).fetchone()
        return _record_from_row(row) if row else None

    def list_artifacts(
        self, statuses: tuple[ArtifactStatus, ...] | None = None
    ) -> list[ArtifactRecord]:
        if statuses:
            placeholders = ", ".join("?" for _ in statuses)
            rows = self.conn.execute(
                f"SELECT * FROM artifacts WHERE status IN ({placeholders}) ORDER BY expires_at",
                tuple(status.value for status in statuses),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM artifacts ORDER BY created_at, artifact_id"
            ).fetchall()
        return [_record_from_row(row) for row in rows]

    def expired_active(self, now_iso: str) -> list[ArtifactRecord]:
        """Active (or revoked-but-retained) artifacts past their retention window."""
        rows = self.conn.execute(
            "SELECT * FROM artifacts WHERE status IN (?, ?) AND expires_at <= ? "
            "ORDER BY expires_at",
            (ArtifactStatus.ACTIVE.value, ArtifactStatus.REVOKED.value, now_iso),
        ).fetchall()
        return [_record_from_row(row) for row in rows]

    def grace_due(self, now_iso: str) -> list[ArtifactRecord]:
        """Pending artifacts whose revocable grace window has ended."""
        rows = self.conn.execute(
            "SELECT * FROM artifacts WHERE status = ? AND grace_ends_at <= ? "
            "ORDER BY grace_ends_at",
            (ArtifactStatus.PENDING.value, now_iso),
        ).fetchall()
        return [_record_from_row(row) for row in rows]

    def update_status(
        self,
        artifact_id: str,
        status: ArtifactStatus,
        now_iso: str,
        *,
        destroy_token: str | None = None,
        clear_token: bool = False,
    ) -> None:
        # By default the existing token is preserved (needed when a FAILED
        # erasure is retried). Passing clear_token=True wipes it; an explicit
        # destroy_token replaces it.
        if clear_token:
            token_value: str | None = None
        elif destroy_token is not None:
            token_value = destroy_token
        else:
            row = self.conn.execute(
                "SELECT destroy_token FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            token_value = row["destroy_token"] if row else None
        self.conn.execute(
            "UPDATE artifacts SET status = ?, destroy_token = ?, updated_at = ? "
            "WHERE artifact_id = ?",
            (status.value, token_value, now_iso, artifact_id),
        )
        self.conn.commit()

    def list_for_dataset(self, dataset_fingerprint: str) -> list[ArtifactRecord]:
        rows = self.conn.execute(
            "SELECT * FROM artifacts WHERE dataset_fingerprint = ? ORDER BY created_at",
            (dataset_fingerprint,),
        ).fetchall()
        return [_record_from_row(row) for row in rows]

    # ------------------------------------------------------------- destruction batch

    def create_destruction_batch(
        self, destruction_id: str, items: list[dict[str, Any]]
    ) -> None:
        for item in items:
            self.conn.execute(
                "INSERT INTO destruction_items "
                "(destruction_id, artifact_id, artifact_type, path, content_hash, "
                "item_status, error, destroyed_at, evidence_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
                (
                    destruction_id,
                    item["artifact_id"],
                    item["artifact_type"],
                    item["path"],
                    item.get("content_hash"),
                    item["item_status"],
                ),
            )
        self.conn.commit()

    def update_destruction_item(
        self,
        destruction_id: str,
        artifact_id: str,
        item_status: str,
        now_iso: str,
        *,
        error: str | None = None,
        evidence_hash: str | None = None,
    ) -> None:
        self.conn.execute(
            """
            UPDATE destruction_items SET
                item_status = ?, error = ?,
                destroyed_at = COALESCE(?, destroyed_at),
                evidence_hash = COALESCE(?, evidence_hash)
            WHERE destruction_id = ? AND artifact_id = ?
            """,
            (item_status, error, now_iso if item_status == "succeeded" else None,
             evidence_hash, destruction_id, artifact_id),
        )
        self.conn.commit()

    def get_batch(self, destruction_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM destruction_items WHERE destruction_id = ? ORDER BY artifact_type, artifact_id",
            (destruction_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def list_batches(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT destruction_id, "
            "SUM(CASE WHEN item_status='succeeded' THEN 1 ELSE 0 END) AS succeeded, "
            "SUM(CASE WHEN item_status IN ('pending','failed') THEN 1 ELSE 0 END) AS outstanding, "
            "COUNT(*) AS total, MIN(destroyed_at) AS started_at "
            "FROM destruction_items GROUP BY destruction_id ORDER BY destruction_id"
        ).fetchall()
        return [dict(row) for row in rows]

    def outstanding_items(self) -> list[dict[str, Any]]:
        """Items never finished across every batch — the resume set after a crash."""
        rows = self.conn.execute(
            "SELECT * FROM destruction_items WHERE item_status IN ('pending', 'failed') "
            "ORDER BY destruction_id, artifact_type, artifact_id"
        ).fetchall()
        return [dict(row) for row in rows]


def _record_from_row(row: sqlite3.Row) -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=row["artifact_id"],
        artifact_type=ArtifactType(row["artifact_type"]),
        path=Path(row["path"]),
        run_id=row["run_id"],
        dataset_fingerprint=row["dataset_fingerprint"],
        content_hash=row["content_hash"],
        size_bytes=row["size_bytes"],
        created_at=row["created_at"],
        retention_days=int(row["retention_days"]),
        grace_days=int(row["grace_days"]),
        expires_at=row["expires_at"],
        grace_ends_at=row["grace_ends_at"],
        status=ArtifactStatus(row["status"]),
        destroy_token=row["destroy_token"],
        updated_at=row["updated_at"],
    )
