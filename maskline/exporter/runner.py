"""Stream subsets out of an existing masked product without re-masking.

Guarantees:

- The masked product is opened read-only (``mode=ro`` + ``query_only``) and
  its content digest is verified against the run manifest before any row is
  read; a tampered or unregistered product is refused.
- Rows stream through filter -> sampling -> column pruning in bounded batches;
  memory use never depends on the product size.
- Pseudonym tokens are copied verbatim and validated against the shared
  mapping database, which is opened read-only so concurrent exports never
  conflict over it.
- The subset is written to a temp file and atomically renamed; failures never
  leave an invalid or empty output behind.
- Every attempt (success or failure) is appended to the audit hash chain.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import secrets
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..audit import AuditLog
from ..config import Paths
from ..dataset_io import (
    iter_table_rows,
    sanitize_table_name,
    sqlite_columns,
    sqlite_table_names,
)
from ..utils import (
    atomic_write_text,
    file_sha256,
    quote_ident,
    read_json,
    sqlite_connect_readonly,
    sqlite_content_digest,
)
from .errors import ExportError
from .filtering import FilterSyntaxError, RowFilter, compile_filter
from .spec import ExportSpec, TableSelection


@dataclass
class ExportResult:
    export_id: str
    spec_fingerprint: str
    source_path: Path
    source_output_hash: str
    subset_path: Path
    subset_format: str
    subset_hash: str
    row_count: int
    table_stats: dict[str, dict[str, int]]
    provenance_path: Path
    registry_path: Path
    audit_seq: int
    elapsed_seconds: float


@dataclass
class _TablePlan:
    selection: TableSelection
    source_columns: list[str]            # schema order
    kept_columns: list[str]              # schema order subset
    kept_types: dict[str, str]
    row_filter: RowFilter | None
    sample: float                        # effective ratio in (0, 1]
    pseudonym_columns: list[str] = field(default_factory=list)


def new_export_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"exp-{stamp}-{secrets.token_hex(3)}"


def _find_source_manifest(manifest_dir: Path, source: Path) -> tuple[dict[str, Any], Path]:
    best: tuple[dict[str, Any], Path] | None = None
    if manifest_dir.is_dir():
        for candidate in sorted(manifest_dir.glob("*.json")):
            data = read_json(candidate)
            if not isinstance(data, dict) or not data.get("output"):
                continue
            try:
                output = Path(data["output"]).expanduser().resolve()
            except OSError:
                continue
            if output != source:
                continue
            if best is None or str(data.get("completed_at", "")) > str(
                best[0].get("completed_at", "")
            ):
                best = (data, candidate)
    if best is None:
        raise ExportError(
            "EXPORT_MANIFEST_MISSING",
            f"no run manifest records masked product {source}; "
            "only products produced by `maskline run` can be exported",
        )
    return best


def _inspect_source(source: Path) -> dict[str, list[dict[str, Any]]]:
    conn = sqlite_connect_readonly(source)
    try:
        schema: dict[str, list[dict[str, Any]]] = {}
        for table in sqlite_table_names(conn):
            schema[table] = sqlite_columns(conn, table)
        return schema
    except sqlite3.Error as exc:
        raise ExportError(
            "EXPORT_SOURCE_NOT_FOUND", f"cannot read masked product {source}: {exc}"
        ) from exc
    finally:
        conn.close()


def _build_plans(
    spec: ExportSpec,
    schema: dict[str, list[dict[str, Any]]],
    transformers: dict[str, dict[str, str]],
) -> list[_TablePlan]:
    selections = list(spec.tables) if spec.tables is not None else [
        TableSelection(table) for table in schema
    ]
    plans: list[_TablePlan] = []
    for selection in selections:
        table = selection.table
        if table not in schema:
            raise ExportError(
                "EXPORT_TABLE_UNKNOWN",
                f"table {table!r} does not exist in the masked product "
                f"(available: {', '.join(schema)})",
            )
        source_columns = [column["name"] for column in schema[table]]
        known = set(source_columns)
        if selection.columns is not None:
            missing = [name for name in selection.columns if name not in known]
            if missing:
                raise ExportError(
                    "EXPORT_COLUMN_UNKNOWN",
                    f"table {table!r} has no column(s): {', '.join(missing)}",
                )
            keep = set(selection.columns)
            kept = [name for name in source_columns if name in keep]
        elif selection.exclude_columns is not None:
            missing = [name for name in selection.exclude_columns if name not in known]
            if missing:
                raise ExportError(
                    "EXPORT_COLUMN_UNKNOWN",
                    f"table {table!r} has no column(s): {', '.join(missing)}",
                )
            drop = set(selection.exclude_columns)
            kept = [name for name in source_columns if name not in drop]
        else:
            kept = list(source_columns)
        if not kept:
            raise ExportError(
                "EXPORT_SPEC_INVALID",
                f"column pruning removes every column of table {table!r}",
            )
        row_filter = None
        if selection.where is not None:
            try:
                row_filter = compile_filter(selection.where)
            except FilterSyntaxError as exc:
                raise ExportError(
                    "EXPORT_FILTER_INVALID", f"table {table!r} filter: {exc}"
                ) from exc
            unknown = sorted(row_filter.columns - known)
            if unknown:
                raise ExportError(
                    "EXPORT_COLUMN_UNKNOWN",
                    f"filter on table {table!r} refers to unknown column(s): "
                    + ", ".join(unknown),
                )
        table_transformers = transformers.get(table, {})
        pseudonym_columns = [
            name for name in kept if table_transformers.get(name) == "pseudonym"
        ]
        plans.append(
            _TablePlan(
                selection=selection,
                source_columns=source_columns,
                kept_columns=kept,
                kept_types={
                    column["name"]: column["declared_type"] for column in schema[table]
                },
                row_filter=row_filter,
                sample=float(selection.sample) if selection.sample is not None else 1.0,
                pseudonym_columns=pseudonym_columns,
            )
        )
    return plans


def _sample_keep(seed_material: str, table: str, rowid: int, ratio: float) -> bool:
    if ratio >= 1.0:
        return True
    digest = hashlib.sha256(
        f"{seed_material}\x00{table}\x00{rowid}".encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big") < int(ratio * (1 << 64))


def _row_batches(
    source: Path, table: str, batch_size: int
) -> Iterator[tuple[list[str], list[tuple[int, tuple[Any, ...]]]]]:
    after = 0
    while True:
        columns, batch = iter_table_rows(source, table, after_rowid=after, limit=batch_size)
        if not batch:
            return
        yield columns, batch
        after = batch[-1][0]


class _MappingView:
    """Read-only view over the shared pseudonym mapping database."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.conn = sqlite_connect_readonly(path)
        try:
            self.entries = int(
                self.conn.execute("SELECT COUNT(*) FROM pseudonym_map").fetchone()[0]
            )
        except sqlite3.Error as exc:
            self.conn.close()
            raise ExportError(
                "EXPORT_MAPPING_UNAVAILABLE",
                f"cannot read pseudonym mapping database {path}: {exc}",
            ) from exc
        self.sha256 = file_sha256(path)

    def close(self) -> None:
        self.conn.close()

    def missing_tokens(self, tokens: set[str]) -> set[str]:
        missing: set[str] = set()
        chunk = sorted(tokens)
        step = 500
        for offset in range(0, len(chunk), step):
            part = chunk[offset : offset + step]
            placeholders = ", ".join("?" for _ in part)
            found = {
                row[0]
                for row in self.conn.execute(
                    f"SELECT token FROM pseudonym_map WHERE token IN ({placeholders})",
                    part,
                )
            }
            missing.update(set(part) - found)
        return missing


def _open_mapping(paths: Paths, plans: list[_TablePlan]) -> _MappingView | None:
    needs_mapping = any(plan.pseudonym_columns for plan in plans)
    mapping_path = paths.pseudomap_db
    if not mapping_path.exists():
        if needs_mapping:
            raise ExportError(
                "EXPORT_MAPPING_UNAVAILABLE",
                "the export includes pseudonymized columns but the mapping "
                f"database is missing: {mapping_path}",
            )
        return None
    return _MappingView(mapping_path)


def _create_subset_schema(conn: sqlite3.Connection, plans: list[_TablePlan]) -> None:
    for plan in plans:
        definitions = ", ".join(
            f"{quote_ident(name)} {plan.kept_types.get(name) or 'TEXT'}"
            for name in plan.kept_columns
        )
        conn.execute(
            f"CREATE TABLE {quote_ident(plan.selection.table)} ({definitions})"
        )


def _insert_batch(
    conn: sqlite3.Connection,
    plan: _TablePlan,
    rows: list[tuple[int, tuple[Any, ...]]],
) -> None:
    if not rows:
        return
    column_sql = ", ".join(quote_ident(name) for name in plan.kept_columns)
    placeholders = ", ".join("?" for _ in range(len(plan.kept_columns) + 1))
    conn.executemany(
        f"INSERT INTO {quote_ident(plan.selection.table)} (rowid, {column_sql}) "
        f"VALUES ({placeholders})",
        [(rowid, *values) for rowid, values in rows],
    )


def _export_table(
    source: Path,
    plan: _TablePlan,
    seed_material: str,
    batch_size: int,
    mapping: _MappingView | None,
    sink_sqlite: sqlite3.Connection | None,
    sink_csv: "csv.writer | None",
    stats: dict[str, int],
) -> None:
    table = plan.selection.table
    keep_indexes = [plan.source_columns.index(name) for name in plan.kept_columns]
    pseudonym_indexes = [
        plan.kept_columns.index(name) for name in plan.pseudonym_columns
    ]
    for columns, batch in _row_batches(source, table, batch_size):
        stats["scanned"] += len(batch)
        kept_rows: list[tuple[int, tuple[Any, ...]]] = []
        for rowid, values in batch:
            if plan.row_filter is not None:
                row = dict(zip(columns, values))
                if not plan.row_filter.matches(row):
                    continue
            stats["matched"] += 1
            if not _sample_keep(seed_material, table, rowid, plan.sample):
                continue
            kept_rows.append((rowid, tuple(values[index] for index in keep_indexes)))
        if not kept_rows:
            continue
        if mapping is not None and pseudonym_indexes:
            tokens = {
                str(values[index])
                for _rowid, values in kept_rows
                for index in pseudonym_indexes
                if values[index] not in (None, "")
            }
            missing = mapping.missing_tokens(tokens)
            if missing:
                sample = ", ".join(sorted(missing)[:3])
                raise ExportError(
                    "EXPORT_MAPPING_UNAVAILABLE",
                    f"{len(missing)} pseudonym token(s) in table {table!r} are not "
                    f"present in the mapping database (e.g. {sample}); the subset "
                    "would not be resolvable",
                )
        stats["exported"] += len(kept_rows)
        if sink_sqlite is not None:
            with sink_sqlite:
                _insert_batch(sink_sqlite, plan, kept_rows)
        else:
            assert sink_csv is not None
            for _rowid, values in kept_rows:
                sink_csv.writerow(values)


def _provenance(
    spec: ExportSpec,
    export_id: str,
    source: Path,
    source_digest: str,
    manifest: dict[str, Any],
    manifest_path: Path,
    mapping: _MappingView | None,
    plans: list[_TablePlan],
    table_stats: dict[str, dict[str, int]],
    output: Path,
    fmt: str,
    integrity: str,
    seed_material: str,
) -> dict[str, Any]:
    algorithm = "sqlite-content-sha256" if fmt == "sqlite" else "file-sha256"
    return {
        "kind": "maskline.export",
        "version": 1,
        "export_id": export_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "spec": spec.to_dict(),
        "spec_fingerprint": spec.fingerprint,
        "sample_seed_material": seed_material,
        "source": {
            "path": str(source),
            "content_digest": source_digest,
            "run_id": manifest.get("run_id"),
            "dataset_fingerprint": manifest.get("dataset_fingerprint"),
            "manifest": str(manifest_path),
            "policy_name": manifest.get("policy_name"),
            "policy_fingerprint": manifest.get("policy_fingerprint"),
            "transformers": manifest.get("transformers", {}),
        },
        "mapping": (
            {
                "path": str(mapping.path),
                "sha256": mapping.sha256,
                "entries": mapping.entries,
            }
            if mapping is not None
            else None
        ),
        "tables": {
            plan.selection.table: {
                "columns": plan.kept_columns,
                "where": plan.selection.where,
                "sample": plan.sample,
                **table_stats[plan.selection.table],
            }
            for plan in plans
        },
        "subset": {
            "path": str(output),
            "file": output.name,
            "format": fmt,
            "row_count": sum(stat["exported"] for stat in table_stats.values()),
            "integrity": {"algorithm": algorithm, "value": integrity},
        },
    }


def _audit_success(
    paths: Paths,
    spec: ExportSpec,
    export_id: str,
    source: Path,
    source_digest: str,
    manifest: dict[str, Any],
    output: Path,
    fmt: str,
    integrity: str,
    table_stats: dict[str, dict[str, int]],
    started: float,
) -> dict[str, Any]:
    entry = {
        "kind": "export",
        "event": "export_completed",
        "export_id": export_id,
        "spec_name": spec.name,
        "spec_fingerprint": spec.fingerprint,
        "source_path": str(source),
        "source_output_hash": source_digest,
        "source_run_id": manifest.get("run_id"),
        "source_dataset_fingerprint": manifest.get("dataset_fingerprint"),
        "policy_name": manifest.get("policy_name"),
        "policy_fingerprint": manifest.get("policy_fingerprint"),
        "subset_path": str(output),
        "subset_format": fmt,
        "subset_hash": integrity,
        "rows_exported": sum(stat["exported"] for stat in table_stats.values()),
        "tables": table_stats,
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }
    return AuditLog(paths.audit_path).append(entry)


def _audit_failure(
    paths: Paths,
    spec: ExportSpec,
    export_id: str,
    exc: ExportError,
    started: float,
) -> None:
    entry = {
        "kind": "export",
        "event": "export_failed",
        "export_id": export_id,
        "spec_name": spec.name,
        "spec_fingerprint": spec.fingerprint,
        "source_path": str(spec.source),
        "error_code": exc.code,
        "error": str(exc),
        "elapsed_seconds": round(time.monotonic() - started, 6),
    }
    AuditLog(paths.audit_path).append(entry)


def _cleanup_temp(tmp_path: Path | None) -> None:
    if tmp_path is None:
        return
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(tmp_path) + suffix)
        if candidate.exists():
            try:
                candidate.unlink()
            except OSError:
                pass


def execute_export(
    paths: Paths,
    spec: ExportSpec,
    *,
    batch_size: int = 1000,
) -> ExportResult:
    if batch_size < 1:
        raise ExportError("EXPORT_SPEC_INVALID", "batch_size must be positive")
    started = time.monotonic()
    export_id = new_export_id()
    try:
        return _execute(paths, spec, export_id, batch_size, started)
    except ExportError as exc:
        _audit_failure(paths, spec, export_id, exc, started)
        raise
    except Exception as exc:
        wrapped = ExportError("EXPORT_INTERNAL", f"unexpected export failure: {exc}")
        _audit_failure(paths, spec, export_id, wrapped, started)
        raise wrapped from exc


def _execute(
    paths: Paths,
    spec: ExportSpec,
    export_id: str,
    batch_size: int,
    started: float,
) -> ExportResult:
    source = spec.source.expanduser().resolve()
    if not source.is_file():
        raise ExportError(
            "EXPORT_SOURCE_NOT_FOUND", f"masked product not found: {source}"
        )
    if source.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
        raise ExportError(
            "EXPORT_FORMAT_UNSUPPORTED",
            f"masked product must be a SQLite database, got: {source.name}",
        )
    fmt = spec.format
    if spec.output is not None:
        output = spec.output.expanduser().resolve()
    else:
        suffix = "sqlite" if fmt == "sqlite" else "csv"
        output = paths.out_dir / (
            f"{source.stem}.{sanitize_table_name(spec.name)}.subset.{suffix}"
        )
    if output == source:
        raise ExportError(
            "EXPORT_OUTPUT_INVALID", "refusing to overwrite the masked product itself"
        )
    manifest, manifest_path = _find_source_manifest(paths.manifest_dir, source)
    source_digest = sqlite_content_digest(source)
    if source_digest != manifest.get("output_hash"):
        raise ExportError(
            "EXPORT_SOURCE_TAMPERED",
            f"masked product {source} no longer matches the output hash recorded "
            f"in manifest {manifest_path.name}; refusing to export from it",
        )
    schema = _inspect_source(source)
    plans = _build_plans(spec, schema, manifest.get("transformers", {}))
    if not plans:
        raise ExportError(
            "EXPORT_NO_ROWS", f"masked product {source} contains no tables"
        )
    if fmt == "csv" and len(plans) != 1:
        raise ExportError(
            "EXPORT_FORMAT_UNSUPPORTED",
            "csv subsets contain exactly one table; select a single table "
            "(the product has: " + ", ".join(schema) + ")",
        )
    seed_material = (
        str(spec.sample_seed)
        if spec.sample_seed is not None
        else f"source:{source_digest}"
    )
    mapping = _open_mapping(paths, plans)
    table_stats: dict[str, dict[str, int]] = {
        plan.selection.table: {"scanned": 0, "matched": 0, "exported": 0}
        for plan in plans
    }
    tmp_path: Path | None = None
    created: list[Path] = []  # artifacts of this run, removed again on failure
    sink_sqlite: sqlite3.Connection | None = None
    csv_handle: Any = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
        os.close(fd)
        tmp_path = Path(tmp_name)
        csv_writer = None
        if fmt == "sqlite":
            sink_sqlite = sqlite3.connect(tmp_path)
            sink_sqlite.execute("PRAGMA journal_mode=DELETE")
            _create_subset_schema(sink_sqlite, plans)
            sink_sqlite.commit()
        else:
            csv_handle = tmp_path.open("w", encoding="utf-8", newline="")
            csv_writer = csv.writer(csv_handle)
            csv_writer.writerow(plans[0].kept_columns)
        for plan in plans:
            _export_table(
                source,
                plan,
                seed_material,
                batch_size,
                mapping,
                sink_sqlite,
                csv_writer,
                table_stats[plan.selection.table],
            )
            stats = table_stats[plan.selection.table]
            if stats["exported"] == 0:
                raise ExportError(
                    "EXPORT_NO_ROWS",
                    f"table {plan.selection.table!r} produced no rows "
                    f"(scanned={stats['scanned']}, matched={stats['matched']}); "
                    "no subset file was created",
                )
        if sink_sqlite is not None:
            sink_sqlite.commit()
            sink_sqlite.close()
            sink_sqlite = None
            integrity = sqlite_content_digest(tmp_path)
        else:
            assert csv_handle is not None
            csv_handle.close()
            csv_handle = None
            integrity = file_sha256(tmp_path)
        os.replace(tmp_path, output)
        tmp_path = None
        created.append(output)
        provenance = _provenance(
            spec, export_id, source, source_digest, manifest, manifest_path, mapping,
            plans, table_stats, output, fmt, integrity, seed_material,
        )
        payload = json.dumps(provenance, ensure_ascii=False, indent=2) + "\n"
        sidecar = output.with_name(output.name + ".export.json")
        atomic_write_text(sidecar, payload)
        created.append(sidecar)
        registry_path = paths.exports_dir / f"{export_id}.json"
        atomic_write_text(registry_path, payload)
        created.append(registry_path)
        audit_entry = _audit_success(
            paths, spec, export_id, source, source_digest, manifest, output, fmt,
            integrity, table_stats, started,
        )
    except Exception:
        for artifact in created:
            try:
                artifact.unlink()
            except OSError:
                pass
        raise
    finally:
        if sink_sqlite is not None:
            sink_sqlite.close()
        if csv_handle is not None:
            csv_handle.close()
        _cleanup_temp(tmp_path)
        if mapping is not None:
            mapping.close()
    return ExportResult(
        export_id=export_id,
        spec_fingerprint=spec.fingerprint,
        source_path=source,
        source_output_hash=source_digest,
        subset_path=output,
        subset_format=fmt,
        subset_hash=integrity,
        row_count=sum(stat["exported"] for stat in table_stats.values()),
        table_stats=table_stats,
        provenance_path=sidecar,
        registry_path=registry_path,
        audit_seq=int(audit_entry["seq"]),
        elapsed_seconds=time.monotonic() - started,
    )
