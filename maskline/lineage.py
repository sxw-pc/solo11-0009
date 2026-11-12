"""Cross-run lineage: deterministic correlation identifiers and trace queries.

A :func:`correlation_id` is derived *only* from a dataset content fingerprint,
so every masking run of the same source dataset -- independent policy versions,
independent processes, interrupted-and-resumed executions -- shares one stable
identifier without any coordination service or network access.

The lineage store is a local SQLite side database that links:

* registry data (dataset fingerprint, registered path),
* pipeline run metadata (run id, policy version, status from checkpoints),
* audit-chain events (seq number and entry hash from the JSONL hash chain).

It never duplicates the audit hash chain itself; it only stores pointers at it.
Old audit logs produced before this module existed have no ``correlation_id``
field and are handled transparently: the id is derived from the
``dataset_fingerprint`` already present in every legacy entry.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import (
    AuditError,
    AuditVerification,
    AuditIntegrityError,
    read_audit_entries,
    verify_audit,
)
from .utils import canonical_json, sha256_text

CORRELATION_PREFIX = "corr-"
CORRELATION_ID_LENGTH = 16  # 64 bits of a SHA-256 digest; collision-free in practice
LINEAGE_SCHEMA_VERSION = 1


class LineageError(RuntimeError):
    pass


class CorrelationIntegrityError(LineageError):
    """Raised when a correlation id inside the audit chain has been tampered with."""

    def __init__(self, line: int, message: str) -> None:
        super().__init__(f"correlation id invalid at audit line {line}: {message}")
        self.line = line


def correlation_id(dataset_fingerprint: str) -> str:
    """Return the stable correlation id for a dataset content fingerprint.

    The derivation is fully deterministic and offline, so concurrent runs and
    resumed runs always compute the same value and can never collide for
    distinct datasets (distinct 64-bit prefixes of SHA-256 digests).
    """
    if not isinstance(dataset_fingerprint, str) or not dataset_fingerprint:
        raise LineageError("dataset_fingerprint must be a non-empty string")
    digest = sha256_text(
        canonical_json({"scheme": "maskline-correlation-v1", "dataset_fingerprint": dataset_fingerprint})
    )
    return CORRELATION_PREFIX + digest[:CORRELATION_ID_LENGTH]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class RunLink:
    run_id: str
    correlation_id: str
    dataset_fingerprint: str
    policy_fingerprint: str
    policy_name: str | None
    status: str
    output_path: str | None
    started_at: str | None
    updated_at: str | None
    audit_seq: int | None
    audit_entry_hash: str | None


@dataclass(frozen=True)
class TraceEvent:
    """One event in a full-link trace, ordered by audit sequence / run start."""

    source: str  # "audit" | "run"
    seq: int | None
    run_id: str
    status: str | None
    policy_fingerprint: str | None
    policy_name: str | None
    ts: str | None
    rows_processed: int | None
    output_path: str | None
    output_hash: str | None
    entry_hash: str | None
    correlation_id: str
    dataset_fingerprint: str


@dataclass(frozen=True)
class TraceResult:
    correlation_id: str
    dataset_fingerprint: str
    runs: tuple[RunLink, ...]
    events: tuple[TraceEvent, ...]
    policy_fingerprints: tuple[str, ...] = field(default_factory=tuple)


class LineageStore:
    """SQLite side catalog joining registry, run metadata and audit pointers."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        # Concurrent processes may write at the same time; WAL plus a busy
        # timeout makes their short transactions serialize safely.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lineage_runs (
                run_id TEXT PRIMARY KEY,
                correlation_id TEXT NOT NULL,
                dataset_fingerprint TEXT NOT NULL,
                policy_fingerprint TEXT NOT NULL,
                policy_name TEXT,
                status TEXT NOT NULL,
                output_path TEXT,
                started_at TEXT,
                updated_at TEXT NOT NULL,
                audit_seq INTEGER,
                audit_entry_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_lineage_correlation
                ON lineage_runs(correlation_id);
            CREATE INDEX IF NOT EXISTS idx_lineage_dataset
                ON lineage_runs(dataset_fingerprint);
            """
        )
        self.conn.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES (?, ?)",
            ("schema_version", str(LINEAGE_SCHEMA_VERSION)),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "LineageStore":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def register_run(
        self,
        *,
        run_id: str,
        dataset_fingerprint: str,
        policy_fingerprint: str,
        policy_name: str | None,
        status: str,
        output_path: str | None,
        started_at: str | None = None,
    ) -> RunLink:
        """Record (or reaffirm) a run link. Re-registering the same run id is idempotent."""
        corr_id = correlation_id(dataset_fingerprint)
        now = _now()
        self.conn.execute(
            """
            INSERT INTO lineage_runs (
                run_id, correlation_id, dataset_fingerprint, policy_fingerprint,
                policy_name, status, output_path, started_at, updated_at,
                audit_seq, audit_entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            ON CONFLICT(run_id) DO UPDATE SET
                correlation_id=excluded.correlation_id,
                dataset_fingerprint=excluded.dataset_fingerprint,
                policy_fingerprint=excluded.policy_fingerprint,
                policy_name=COALESCE(excluded.policy_name, lineage_runs.policy_name),
                status=excluded.status,
                output_path=COALESCE(excluded.output_path, lineage_runs.output_path),
                started_at=COALESCE(lineage_runs.started_at, excluded.started_at),
                updated_at=excluded.updated_at
            """,
            (
                run_id, corr_id, dataset_fingerprint, policy_fingerprint,
                policy_name, status, output_path, started_at or now, now,
            ),
        )
        self.conn.commit()
        return self.get_run(run_id)  # type: ignore[return-value]

    def set_status(self, run_id: str, status: str) -> None:
        self.conn.execute(
            "UPDATE lineage_runs SET status = ?, updated_at = ? WHERE run_id = ?",
            (status, _now(), run_id),
        )
        self.conn.commit()

    def attach_audit(
        self, run_id: str, audit_seq: int, audit_entry_hash: str
    ) -> None:
        """Point a run link at its finalized audit-chain entry."""
        self.conn.execute(
            "UPDATE lineage_runs SET audit_seq = ?, audit_entry_hash = ?, "
            "updated_at = ? WHERE run_id = ?",
            (audit_seq, audit_entry_hash, _now(), run_id),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> RunLink | None:
        row = self.conn.execute(
            "SELECT * FROM lineage_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return _link_from_row(row) if row else None

    def list_for_correlation(self, corr_id: str) -> list[RunLink]:
        rows = self.conn.execute(
            "SELECT * FROM lineage_runs WHERE correlation_id = ? "
            "ORDER BY COALESCE(started_at, updated_at), run_id",
            (corr_id,),
        ).fetchall()
        return [_link_from_row(row) for row in rows]

    def list_for_dataset(self, dataset_fingerprint: str) -> list[RunLink]:
        return self.list_for_correlation(correlation_id(dataset_fingerprint))


def _link_from_row(row: sqlite3.Row) -> RunLink:
    return RunLink(
        run_id=row["run_id"],
        correlation_id=row["correlation_id"],
        dataset_fingerprint=row["dataset_fingerprint"],
        policy_fingerprint=row["policy_fingerprint"],
        policy_name=row["policy_name"],
        status=row["status"],
        output_path=row["output_path"],
        started_at=row["started_at"],
        updated_at=row["updated_at"],
        audit_seq=row["audit_seq"],
        audit_entry_hash=row["audit_entry_hash"],
    )


# ---------------------------------------------------------------------------
# Audit-chain correlation validation
# ---------------------------------------------------------------------------

def verify_correlation_ids(
    audit_path: str | Path,
) -> tuple[AuditVerification, list[dict[str, Any]]]:
    """Validate correlation ids embedded in audit entries.

    The hash chain itself is verified first with the original, unmodified
    :func:`maskline.audit.verify_audit` logic. Afterwards every entry carrying
    a ``correlation_id`` is checked against the id deterministically derived
    from its ``dataset_fingerprint``. Entries without the field (logs produced
    by older versions) are returned with ``correlation_id`` derived on the fly
    and are never treated as errors, keeping historical chains fully
    compatible. Returns the underlying chain verification so callers do not
    have to re-scan the whole log.
    """
    # Raises AuditIntegrityError / AuditError on any chain-level problem.
    verification = verify_audit(audit_path)
    entries = read_audit_entries(audit_path)
    records: list[dict[str, Any]] = []
    for line_number, entry in enumerate(entries, start=1):
        fingerprint = entry.get("dataset_fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise CorrelationIntegrityError(
                line_number, "entry is missing dataset_fingerprint"
            )
        expected = correlation_id(fingerprint)
        embedded = entry.get("correlation_id")
        if embedded is not None and embedded != expected:
            raise CorrelationIntegrityError(
                line_number,
                f"expected {expected} for dataset {fingerprint[:16]}..., "
                f"found {embedded!r}",
            )
        records.append(
            {
                "line": line_number,
                "seq": entry.get("seq"),
                "run_id": entry.get("run_id"),
                "correlation_id": embedded or expected,
                "embedded": embedded is not None,
                "dataset_fingerprint": fingerprint,
                "entry_hash": entry.get("entry_hash"),
            }
        )
    return verification, records


# ---------------------------------------------------------------------------
# Full-link tracing
# ---------------------------------------------------------------------------

def _audit_event(entry: dict[str, Any]) -> TraceEvent:
    fingerprint = entry["dataset_fingerprint"]
    embedded = entry.get("correlation_id")
    return TraceEvent(
        source="audit",
        seq=entry.get("seq"),
        run_id=entry.get("run_id"),
        status="completed",
        policy_fingerprint=entry.get("policy_fingerprint"),
        policy_name=entry.get("policy_name"),
        ts=entry.get("ts"),
        rows_processed=entry.get("rows_processed"),
        output_path=entry.get("output_path"),
        output_hash=entry.get("output_hash"),
        entry_hash=entry.get("entry_hash"),
        correlation_id=embedded or correlation_id(fingerprint),
        dataset_fingerprint=fingerprint,
    )


def trace_dataset(
    audit_path: str | Path,
    *,
    lineage_path: str | Path | None = None,
    dataset_fingerprint: str | None = None,
    correlation: str | None = None,
) -> TraceResult:
    """Collect the full cross-run trace for one source dataset.

    Pass either a ``dataset_fingerprint`` or an explicit ``correlation`` id.
    The audit JSONL is the primary evidence source (it covers legacy logs);
    the lineage store, when available, additionally surfaces interrupted and
    failed runs that never produced an audit entry.
    """
    if dataset_fingerprint is None and correlation is None:
        raise LineageError("trace requires dataset_fingerprint or correlation id")
    target_corr = correlation or correlation_id(dataset_fingerprint)  # type: ignore[arg-type]
    if dataset_fingerprint is None:
        dataset_fingerprint = ""

    if not Path(audit_path).exists():
        raise AuditError(f"audit log not found: {audit_path}")
    # Full chain verification before any tracing; a tampered chain aborts here.
    verify_audit(audit_path)
    entries = read_audit_entries(audit_path)

    # Validate correlation ids across the *whole* chain first, so a forged id
    # cannot hide by simply failing the filter below.
    for entry in entries:
        fingerprint = entry.get("dataset_fingerprint")
        embedded = entry.get("correlation_id")
        if embedded is None or not isinstance(fingerprint, str):
            continue
        if embedded != correlation_id(fingerprint):
            raise CorrelationIntegrityError(
                entry.get("seq", -1),
                f"correlation id does not match dataset fingerprint in run {entry.get('run_id')}",
            )

    matched: list[dict[str, Any]] = []
    resolved_fingerprint = dataset_fingerprint
    policies: list[str] = []
    for entry in entries:
        fingerprint = entry.get("dataset_fingerprint")
        if not isinstance(fingerprint, str):
            continue
        corr = entry.get("correlation_id") or correlation_id(fingerprint)
        if corr != target_corr:
            continue
        matched.append(entry)
        if not resolved_fingerprint:
            resolved_fingerprint = fingerprint
        if entry.get("policy_fingerprint") and entry["policy_fingerprint"] not in policies:
            policies.append(entry["policy_fingerprint"])

    events: list[TraceEvent] = [_audit_event(entry) for entry in matched]
    links: list[RunLink] = []

    if lineage_path is not None and Path(lineage_path).exists():
        with LineageStore(lineage_path) as store:
            links = store.list_for_correlation(target_corr)
        audited_runs = {event.run_id for event in events}
        for link in links:
            if link.dataset_fingerprint and not resolved_fingerprint:
                resolved_fingerprint = link.dataset_fingerprint
            if link.policy_fingerprint and link.policy_fingerprint not in policies:
                policies.append(link.policy_fingerprint)
            if link.run_id in audited_runs:
                continue
            # Runs that were killed / failed before an audit entry was written.
            events.append(
                TraceEvent(
                    source="run",
                    seq=link.audit_seq,
                    run_id=link.run_id,
                    status=link.status,
                    policy_fingerprint=link.policy_fingerprint,
                    policy_name=link.policy_name,
                    ts=link.updated_at,
                    rows_processed=None,
                    output_path=link.output_path,
                    output_hash=None,
                    entry_hash=link.audit_entry_hash,
                    correlation_id=link.correlation_id,
                    dataset_fingerprint=link.dataset_fingerprint,
                )
            )

    events.sort(key=lambda event: (event.seq is None, event.seq or 0, event.ts or "", event.run_id))
    return TraceResult(
        correlation_id=target_corr,
        dataset_fingerprint=resolved_fingerprint or "",
        runs=tuple(links) if links else tuple(),
        events=tuple(events),
        policy_fingerprints=tuple(policies),
    )
