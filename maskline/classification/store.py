"""SQLite persistence for rule-pack versions, classification results, and corrections.

Rule-pack versions and manual corrections are append-only. SQLite triggers reject
UPDATE and DELETE statements so tampering fails even when someone opens the file
directly; the correction table additionally carries a per-row hash chain that can
be verified independently of the main audit log.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..utils import canonical_json, sha256_text
from .models import RulePack

GENESIS_HASH = "0" * 64


class ClassificationStoreError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ClassificationStore:

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS rule_pack_versions (
                version_id INTEGER PRIMARY KEY AUTOINCREMENT,
                pack_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                standard_code TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                builtin INTEGER NOT NULL,
                source_path TEXT,
                content_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(pack_id, fingerprint)
            );
            CREATE TRIGGER IF NOT EXISTS rule_pack_versions_no_update
                BEFORE UPDATE ON rule_pack_versions
            BEGIN
                SELECT RAISE(ABORT, 'rule pack versions are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS rule_pack_versions_no_delete
                BEFORE DELETE ON rule_pack_versions
            BEGIN
                SELECT RAISE(ABORT, 'rule pack versions are append-only');
            END;

            CREATE TABLE IF NOT EXISTS classification_jobs (
                job_id TEXT PRIMARY KEY,
                dataset_fingerprint TEXT NOT NULL,
                dataset_path TEXT,
                pack_version_ids_json TEXT NOT NULL,
                degraded INTEGER NOT NULL DEFAULT 0,
                alert_count INTEGER NOT NULL DEFAULT 0,
                field_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS field_classification (
                dataset_fingerprint TEXT NOT NULL,
                table_name TEXT NOT NULL,
                column_name TEXT NOT NULL,
                semantic_key TEXT,
                sensitive_type TEXT,
                detection_confidence TEXT NOT NULL,
                degraded INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT 'auto',
                result_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (dataset_fingerprint, table_name, column_name)
            );

            CREATE TABLE IF NOT EXISTS classification_corrections (
                correction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_fingerprint TEXT NOT NULL,
                table_name TEXT NOT NULL,
                column_name TEXT NOT NULL,
                standard_code TEXT NOT NULL,
                previous_json TEXT NOT NULL,
                corrected_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                operator TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS classification_corrections_no_update
                BEFORE UPDATE ON classification_corrections
            BEGIN
                SELECT RAISE(ABORT, 'classification corrections are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS classification_corrections_no_delete
                BEFORE DELETE ON classification_corrections
            BEGIN
                SELECT RAISE(ABORT, 'classification corrections are append-only');
            END;

            CREATE TABLE IF NOT EXISTS dataset_classification_state (
                dataset_path TEXT PRIMARY KEY,
                dataset_fingerprint TEXT NOT NULL,
                job_id TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "ClassificationStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ----- rule pack versions -------------------------------------------------

    def publish_pack(self, pack: RulePack) -> tuple[int, bool]:
        """Insert a pack version once per fingerprint; return (version_id, created)."""
        existing = self.conn.execute(
            "SELECT version_id FROM rule_pack_versions WHERE pack_id = ? AND fingerprint = ?",
            (pack.pack_id, pack.fingerprint),
        ).fetchone()
        if existing:
            return int(existing["version_id"]), False
        cur = self.conn.execute(
            """
            INSERT INTO rule_pack_versions
                (pack_id, revision, standard_code, fingerprint, builtin,
                 source_path, content_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pack.pack_id,
                pack.revision,
                pack.standard.code,
                pack.fingerprint,
                1 if pack.builtin else 0,
                pack.source_path,
                json.dumps(pack.to_dict(), ensure_ascii=False, sort_keys=True),
                _now(),
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid), True

    def active_versions(self) -> list[dict[str, Any]]:
        """Highest version_id per standard code — the active snapshot for new jobs."""
        rows = self.conn.execute(
            """
            SELECT v.* FROM rule_pack_versions v
            JOIN (
                SELECT standard_code, MAX(version_id) AS max_id
                FROM rule_pack_versions GROUP BY standard_code
            ) latest ON latest.max_id = v.version_id
            ORDER BY v.standard_code
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def versions_for(self, version_ids: list[int]) -> list[dict[str, Any]]:
        if not version_ids:
            return []
        placeholders = ",".join("?" for _ in version_ids)
        rows = self.conn.execute(
            f"SELECT * FROM rule_pack_versions WHERE version_id IN ({placeholders}) "
            f"ORDER BY standard_code",
            tuple(version_ids),
        ).fetchall()
        found = {int(row["version_id"]) for row in rows}
        missing = sorted(set(version_ids) - found)
        if missing:
            raise ClassificationStoreError(
                f"rule pack versions no longer available: {missing}"
            )
        return [dict(row) for row in rows]

    def pack_version(self, version_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM rule_pack_versions WHERE version_id = ?", (version_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_versions(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT version_id, pack_id, revision, standard_code, fingerprint, "
            "builtin, source_path, created_at FROM rule_pack_versions ORDER BY version_id"
        ).fetchall()
        return [dict(row) for row in rows]

    # ----- jobs ---------------------------------------------------------------

    def record_job(
        self,
        job_id: str,
        dataset_fingerprint: str,
        dataset_path: str | None,
        pack_version_ids: list[int],
        degraded: bool,
        alert_count: int,
        field_count: int,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO classification_jobs
                (job_id, dataset_fingerprint, dataset_path, pack_version_ids_json,
                 degraded, alert_count, field_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                dataset_fingerprint,
                dataset_path,
                json.dumps(pack_version_ids),
                1 if degraded else 0,
                alert_count,
                field_count,
                _now(),
            ),
        )
        self.conn.execute(
            """
            INSERT INTO dataset_classification_state
                (dataset_path, dataset_fingerprint, job_id, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(dataset_path) DO UPDATE SET
                dataset_fingerprint=excluded.dataset_fingerprint,
                job_id=excluded.job_id,
                updated_at=excluded.updated_at
            """,
            (dataset_path, dataset_fingerprint, job_id, _now()),
        )
        self.conn.commit()

    def dataset_state(self, dataset_path: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM dataset_classification_state WHERE dataset_path = ?",
            (dataset_path,),
        ).fetchone()
        return dict(row) if row else None

    # ----- field classifications ----------------------------------------------

    def upsert_classification(self, record: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT INTO field_classification (
                dataset_fingerprint, table_name, column_name, semantic_key,
                sensitive_type, detection_confidence, degraded, source,
                result_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dataset_fingerprint, table_name, column_name) DO UPDATE SET
                semantic_key=excluded.semantic_key,
                sensitive_type=excluded.sensitive_type,
                detection_confidence=excluded.detection_confidence,
                degraded=excluded.degraded,
                source=excluded.source,
                result_json=excluded.result_json,
                updated_at=excluded.updated_at
            """,
            (
                record["dataset_fingerprint"],
                record["table_name"],
                record["column_name"],
                record.get("semantic_key"),
                record.get("sensitive_type"),
                record.get("detection_confidence", "none"),
                1 if record.get("degraded") else 0,
                record.get("source", "auto"),
                json.dumps(record, ensure_ascii=False, sort_keys=True),
                _now(),
            ),
        )
        self.conn.commit()

    def classifications_for(self, dataset_fingerprint: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT result_json FROM field_classification WHERE dataset_fingerprint = ? "
            "ORDER BY table_name, column_name",
            (dataset_fingerprint,),
        ).fetchall()
        return [json.loads(row["result_json"]) for row in rows]

    def get_classification(
        self, dataset_fingerprint: str, table: str, column: str
    ) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT result_json FROM field_classification "
            "WHERE dataset_fingerprint = ? AND table_name = ? AND column_name = ?",
            (dataset_fingerprint, table, column),
        ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def update_standard_result(
        self, dataset_fingerprint: str, table: str, column: str, standard_code: str,
        corrected: dict[str, Any],
    ) -> dict[str, Any]:
        record = self.get_classification(dataset_fingerprint, table, column)
        if record is None:
            raise ClassificationStoreError(
                f"no classification for {table}.{column} in dataset {dataset_fingerprint[:16]}"
            )
        standards = record["standards"]
        index = next(
            (i for i, item in enumerate(standards) if item["standard_code"] == standard_code),
            None,
        )
        if index is None:
            raise ClassificationStoreError(
                f"standard {standard_code!r} was not applied to {table}.{column}"
            )
        previous = standards[index]
        standards[index] = corrected
        record["source"] = "manual"
        self.conn.execute(
            "UPDATE field_classification SET result_json = ?, source = 'manual', "
            "updated_at = ? WHERE dataset_fingerprint = ? AND table_name = ? AND column_name = ?",
            (
                json.dumps(record, ensure_ascii=False, sort_keys=True),
                _now(),
                dataset_fingerprint,
                table,
                column,
            ),
        )
        self.conn.commit()
        return {"previous": previous, "record": record}

    # ----- immutable correction chain -----------------------------------------

    def append_correction(
        self,
        dataset_fingerprint: str,
        table: str,
        column: str,
        standard_code: str,
        previous: dict[str, Any],
        corrected: dict[str, Any],
        reason: str,
        operator: str,
    ) -> dict[str, Any]:
        last = self.conn.execute(
            "SELECT entry_hash FROM classification_corrections ORDER BY correction_id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["entry_hash"] if last else GENESIS_HASH
        body = {
            "dataset_fingerprint": dataset_fingerprint,
            "table_name": table,
            "column_name": column,
            "standard_code": standard_code,
            "previous": previous,
            "corrected": corrected,
            "reason": reason,
            "operator": operator,
            "prev_hash": prev_hash,
            "created_at": _now(),
        }
        entry_hash = sha256_text(canonical_json(body))
        cur = self.conn.execute(
            """
            INSERT INTO classification_corrections (
                dataset_fingerprint, table_name, column_name, standard_code,
                previous_json, corrected_json, reason, operator,
                prev_hash, entry_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dataset_fingerprint,
                table,
                column,
                standard_code,
                json.dumps(previous, ensure_ascii=False, sort_keys=True),
                json.dumps(corrected, ensure_ascii=False, sort_keys=True),
                reason,
                operator,
                prev_hash,
                entry_hash,
                body["created_at"],
            ),
        )
        self.conn.commit()
        return {
            "correction_id": int(cur.lastrowid),
            "entry_hash": entry_hash,
            "prev_hash": prev_hash,
            "created_at": body["created_at"],
        }

    def list_corrections(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM classification_corrections ORDER BY correction_id"
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["previous"] = json.loads(item.pop("previous_json"))
            item["corrected"] = json.loads(item.pop("corrected_json"))
            result.append(item)
        return result

    def verify_correction_chain(self) -> dict[str, Any]:
        rows = self.conn.execute(
            "SELECT * FROM classification_corrections ORDER BY correction_id"
        ).fetchall()
        previous = GENESIS_HASH
        for index, row in enumerate(rows, start=1):
            if row["prev_hash"] != previous:
                raise ClassificationStoreError(
                    f"correction chain broken at correction_id={row['correction_id']}: "
                    "previous hash mismatch"
                )
            body = {
                "dataset_fingerprint": row["dataset_fingerprint"],
                "table_name": row["table_name"],
                "column_name": row["column_name"],
                "standard_code": row["standard_code"],
                "previous": json.loads(row["previous_json"]),
                "corrected": json.loads(row["corrected_json"]),
                "reason": row["reason"],
                "operator": row["operator"],
                "prev_hash": row["prev_hash"],
                "created_at": row["created_at"],
            }
            expected = sha256_text(canonical_json(body))
            if expected != row["entry_hash"]:
                raise ClassificationStoreError(
                    f"correction chain broken at correction_id={row['correction_id']}: "
                    "entry hash mismatch"
                )
            previous = row["entry_hash"]
        return {"corrections": len(rows), "head_hash": previous}
