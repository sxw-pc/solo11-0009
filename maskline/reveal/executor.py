"""Execute a vetted controlled reveal and produce a plaintext output safely.

Safety properties enforced here, on top of :class:`AuthorizationValidator`:

* **Batch binding.** The target dataset's recomputed fingerprint and its
  manifest ``run_id`` must match the authorized scope. A different batch --
  even one with identical columns -- fails.
* **Row hard cap.** The table row count is checked against ``max_rows`` before
  any output is created, and a per-row counter provides a second guarantee.
* **Mid-flight expiry.** The clock is re-checked for every processed row; if
  the authorization expires while work is in progress the run aborts, the
  partial plaintext is securely erased, and an abort record is audited.
* **No plaintext on failure.** Output is built in a mode-``0600`` temp file
  and atomically renamed only on full success.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..audit import AuditLog
from ..dataset_io import sqlite_columns, sqlite_connect_readonly, sqlite_table_names
from ..pseudomap import PseudoMap
from ..registry import inspect_dataset
from ..utils import quote_ident, read_json, sqlite_content_digest
from .clock import Clock
from .errors import AuthorizationError, RevealControlError, ScopeError
from .keyring import Keyring
from .records import Scope
from .validator import AuthorizationValidator

TOKEN_PREFIX = "psn_"


@dataclass
class RevealResult:
    output_path: Path
    rows_revealed: int
    columns_revealed: tuple[str, ...]
    authorization_id: str
    request_id: str
    audit_seq: int


def secure_delete(path: Path) -> None:
    """Best-effort overwrite-and-unlink for a sensitive temporary file.

    On copy-on-write / journaling filesystems physical block erasure cannot be
    guaranteed from userspace; the guarantee that matters operationally is
    that no plaintext path remains after cleanup, which the unlink provides.
    """
    try:
        if not path.is_file():
            return
        size = path.stat().st_size
        with path.open("r+b", buffering=0) as fh:
            fh.write(os.urandom(min(size, 1 << 20)) if size else b"")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


class RevealExecutor:
    def __init__(
        self,
        keyring: Keyring,
        audit: AuditLog,
        clock: Clock,
        mapping: PseudoMap,
        *,
        manifest_dir: Path,
        validator: AuthorizationValidator | None = None,
    ) -> None:
        self.keyring = keyring
        self.audit = audit
        self.clock = clock
        self.mapping = mapping
        self.manifest_dir = Path(manifest_dir)
        self.validator = validator or AuthorizationValidator(keyring, audit, clock)

    # ------------------------------------------------------------ batch binding
    def _find_manifest_for_output(self, dataset: Path, output_hash: str) -> dict[str, Any] | None:
        """Locate the manifest of the masking run that produced this output.

        Manifests are indexed by the *source* dataset fingerprint, while the
        reveal target is a masked *output*. We therefore scan the manifest
        directory and match on the recorded ``output_hash`` (the SQLite content
        digest of the output), which uniquely identifies the producing batch.
        """
        if not self.manifest_dir.is_dir():
            return None
        for candidate in sorted(self.manifest_dir.glob("*.json")):
            record = read_json(candidate)
            if isinstance(record, dict) and record.get("output_hash") == output_hash:
                return record
        return None

    def _check_batch_binding(self, dataset: Path, scope: Scope) -> dict[str, Any]:
        """Bind the authorization to one concrete masked output batch.

        The reveal target is a masked output dataset. Its content is matched to
        exactly one run manifest, whose ``run_id`` is the masking batch that
        produced it. Both the dataset fingerprint and the run_id must match the
        authorized scope, so an authorization issued for one batch cannot be
        replayed against another -- even one with identical table/column names.
        """
        inventory = inspect_dataset(dataset)
        if inventory.fingerprint != scope.dataset_fingerprint:
            raise ScopeError(
                "target dataset fingerprint does not match the authorization scope; "
                "the authorization is bound to a different batch",
                reason="batch-mismatch",
            )
        table = inventory.table(scope.table)
        if table is None:
            raise ScopeError(
                f"authorized table {scope.table!r} does not exist in the target dataset",
                reason="scope-mismatch",
            )
        actual_columns = {column.name for column in table.columns}
        missing = [column for column in scope.columns if column not in actual_columns]
        if missing:
            raise ScopeError(
                f"authorized columns absent from the dataset: {', '.join(missing)}",
                reason="scope-mismatch",
            )
        # Masking always emits a SQLite target; only those can be batch-bound
        # through a manifest output_hash.
        if inventory.kind != "sqlite":
            raise ScopeError(
                f"controlled reveal supports SQLite masked outputs, got {inventory.kind}",
                reason="unsupported-target",
            )
        try:
            output_hash = sqlite_content_digest(dataset)
        except Exception as exc:  # pragma: no cover - defensive
            raise ScopeError(
                f"target cannot be batch-bound: {exc}",
                reason="batch-mismatch",
            ) from exc
        manifest = self._find_manifest_for_output(dataset, output_hash)
        if manifest is None:
            raise ScopeError(
                "no run manifest records this output; cannot confirm the authorized "
                "run batch",
                reason="batch-mismatch",
            )
        if manifest.get("run_id") != scope.run_id:
            raise ScopeError(
                f"authorization is bound to run {scope.run_id!r} but the dataset's "
                f"manifest records batch {manifest.get('run_id')!r}",
                reason="batch-mismatch",
            )
        return {"inventory": inventory, "manifest": manifest}

    def _reveal_value(self, value: Any) -> Any:
        if not isinstance(value, str) or not value.startswith(TOKEN_PREFIX):
            return value
        plaintext = self.mapping.get(value)
        if plaintext is None:
            raise RevealControlError(
                f"token {value} has no entry in the mapping database",
                reason="mapping-miss",
            )
        return plaintext

    def _assert_not_expired(self, vetted: dict[str, Any], rows_done: int) -> None:
        if self.clock.now() >= vetted["expires_at"]:
            raise AuthorizationError(
                "authorization expired during execution; aborting and erasing "
                "partial plaintext",
                reason="authorization-expired",
            )

    # ------------------------------------------------------------------ entrypoint
    def execute(
        self,
        *,
        request_path: str | Path,
        authorization_path: str | Path,
        dataset_path: str | Path,
        output_path: str | Path,
    ) -> RevealResult:
        dataset = Path(dataset_path).expanduser().resolve()
        output = Path(output_path).expanduser().resolve()
        context = {
            "request_path": str(request_path),
            "authorization_path": str(authorization_path),
            "dataset_path": str(dataset),
            "requested_output": str(output),
        }

        def deny_before_claim(exc: Exception) -> None:
            # No authorization has been claimed yet, so this is a plain denial;
            # it still leaves a forensic record in the audit chain.
            reason = getattr(exc, "reason", "reveal-control-error")
            self.validator.record_denial(reason, str(exc), **context)
            raise exc

        if output == dataset:
            deny_before_claim(ScopeError("output path must differ from the source dataset"))
        if output.exists():
            deny_before_claim(ScopeError(f"refusing to overwrite existing output: {output}"))

        # Recompute the scope directly from the request so callers cannot widen it.
        from .records import load_request

        try:
            request = load_request(request_path)
            requested_scope = Scope.from_message(request["message"]["scope"])
            binding = self._check_batch_binding(dataset, requested_scope)
        except RevealControlError as exc:
            deny_before_claim(exc)
        table_info = binding["inventory"].table(requested_scope.table)
        assert table_info is not None

        # Validate the full authorization chain and atomically claim it.
        vetted = self.validator.validate(
            str(request_path),
            str(authorization_path),
            requested_scope=requested_scope,
        )
        if table_info.row_count > vetted["max_rows"]:
            # The claim was already written; close it out as an abort so the
            # authorization can never be silently retried with different data.
            self.validator.log_abort(
                vetted,
                rows_revealed=0,
                reason="row-limit-exceeded",
                detail=(
                    f"dataset has {table_info.row_count} rows but the authorization "
                    f"caps at {vetted['max_rows']}"
                ),
            )
            raise AuthorizationError(
                f"row count {table_info.row_count} exceeds the authorized limit "
                f"{vetted['max_rows']}",
                reason="row-limit-exceeded",
            )

        output.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".reveal.", dir=output.parent)
        tmp_path = Path(tmp_name)
        os.close(fd)
        os.chmod(tmp_path, 0o600)
        rows_done = 0
        try:
            # Masking runs always emit a SQLite target; batch binding already
            # rejected anything else.
            rows_done = self._run_sqlite(
                dataset, tmp_path, vetted, requested_scope.table,
                tuple(requested_scope.columns),
            )
            os.replace(tmp_path, output)
        except BaseException as exc:
            secure_delete(tmp_path)
            reason = getattr(exc, "reason", "execution-aborted")
            self.validator.log_abort(
                vetted,
                rows_revealed=rows_done,
                reason=reason,
                detail=f"execution halted; partial output erased ({exc})",
            )
            raise
        completion = self.validator.log_completion(vetted, rows_done, str(output))
        return RevealResult(
            output_path=output,
            rows_revealed=rows_done,
            columns_revealed=tuple(sorted(requested_scope.columns)),
            authorization_id=vetted["authorization_id"],
            request_id=vetted["request_id"],
            audit_seq=completion["seq"],
        )

    # --------------------------------------------------------------- sqlite path
    def _run_sqlite(
        self,
        dataset: Path,
        tmp_path: Path,
        vetted: dict[str, Any],
        table: str,
        columns: tuple[str, ...],
    ) -> int:
        src = sqlite_connect_readonly(dataset)
        dest = sqlite3.connect(tmp_path)
        try:
            if table not in sqlite_table_names(src):
                raise ScopeError(f"table {table!r} not found in source", reason="scope-mismatch")
            schema = next(
                item[0]
                for item in src.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
                ).fetchall()
                if item[0]
            )
            dest.execute(schema)
            col_infos = sqlite_columns(src, table)
            col_names = [item["name"] for item in col_infos]
            for extra in columns:
                if extra not in col_names:
                    raise ScopeError(f"column {extra!r} not found", reason="scope-mismatch")
            select = ", ".join(quote_ident(name) for name in col_names)
            insert = ", ".join(quote_ident(name) for name in col_names)
            placeholders = ", ".join("?" for _ in col_names)
            rows_done = 0
            cursor = src.execute(
                f"SELECT {select} FROM {quote_ident(table)} ORDER BY rowid"
            )
            for source_row in cursor:
                self._assert_not_expired(vetted, rows_done)
                if rows_done >= vetted["max_rows"]:
                    raise AuthorizationError(
                        "row limit reached during streaming",
                        reason="row-limit-exceeded",
                    )
                values = list(source_row)
                for index, name in enumerate(col_names):
                    if name in columns:
                        values[index] = self._reveal_value(values[index])
                dest.execute(
                    f"INSERT INTO {quote_ident(table)} ({insert}) VALUES ({placeholders})",
                    values,
                )
                rows_done += 1
            dest.commit()
            return rows_done
        finally:
            dest.close()
            src.close()
