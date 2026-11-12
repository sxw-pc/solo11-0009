"""Persistent rule version catalog, permissions, gray scopes and rollback."""

from __future__ import annotations

import fnmatch
import getpass
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .audit import AuditLog
from .rules import (
    ACTIVE_VERSION_ALIAS,
    BUILTIN_VERSION,
    RESERVED_VERSION_TAGS,
    SYSTEM_ACTOR,
    RuleError,
    RulePack,
    RulePermissionError,
    RuleSet,
    apply_overlay,
    builtin_rule_set,
    builtin_rule_spec,
    compile_rule_set,
    fingerprint_spec,
    is_valid_version_tag,
)


def resolve_actor(explicit: str | None = None) -> str:
    """Resolve the operator identity used for ownership and audit checks."""
    if explicit and explicit.strip():
        return explicit.strip()
    configured = os.environ.get("MASKLINE_ACTOR")
    if configured and configured.strip():
        return configured.strip()
    try:
        return getpass.getuser() or "unknown"
    except (OSError, KeyError):
        return "unknown"


@dataclass(frozen=True)
class RuleVersion:
    version: str
    name: str
    description: str
    created_by: str
    created_at: str
    base_version: str
    fingerprint: str
    spec: dict[str, Any]
    builtin: bool
    rule_set: RuleSet

    def to_record(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "base_version": self.base_version,
            "fingerprint": self.fingerprint,
            "builtin": self.builtin,
            "detectors": list(self.rule_set.detector_types()),
        }


def _path_matches(pattern: str, path: Path) -> bool:
    normalized = pattern.replace("\\", "/")
    variants = {path.name, path.as_posix(), str(path)}
    return any(
        fnmatch.fnmatchcase(candidate, normalized)
        or fnmatch.fnmatchcase(candidate.replace("\\", "/"), normalized)
        or fnmatch.fnmatchcase(candidate, f"*{normalized}")
        for candidate in variants
    )


class RuleCatalog:
    """SQLite-backed registry of immutable rule versions.

    ``create=False`` is used by dry-run style callers: it never creates a
    database or schema, and simply falls back to the built-in rule set when no
    catalog exists.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        audit_path: str | Path | None = None,
        create: bool = True,
    ) -> None:
        self.path = Path(path).expanduser().resolve()
        self.audit_path = Path(audit_path) if audit_path else None
        self._create = create
        self.conn: sqlite3.Connection | None = None
        if not create:
            if not self.path.exists():
                return
            self.conn = sqlite3.connect(self.path)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self.path)
            self.conn.row_factory = sqlite3.Row
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS rule_versions (
                    version TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    base_version TEXT NOT NULL DEFAULT '',
                    fingerprint TEXT NOT NULL,
                    spec_json TEXT NOT NULL,
                    builtin INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS rule_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gray_scopes (
                    rule_version TEXT PRIMARY KEY,
                    datasets_json TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            self.conn.row_factory = sqlite3.Row
            self.conn.commit()
            self._ensure_builtin()
        if self.conn is not None:
            self.conn.row_factory = sqlite3.Row

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def __enter__(self) -> "RuleCatalog":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ state

    def _table_exists(self, name: str) -> bool:
        if self.conn is None:
            return False
        row = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None

    def _ensure_builtin(self) -> None:
        assert self.conn is not None
        row = self.conn.execute(
            "SELECT version FROM rule_versions WHERE version = ?",
            (BUILTIN_VERSION,),
        ).fetchone()
        now = _now()
        if row is None:
            spec = builtin_rule_spec()
            self.conn.execute(
                "INSERT INTO rule_versions "
                "(version, name, description, created_by, created_at, "
                "base_version, fingerprint, spec_json, builtin) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    BUILTIN_VERSION,
                    "Built-in detector rule set (legacy behaviour)",
                    "Snapshot of maskline's built-in detectors.",
                    SYSTEM_ACTOR,
                    now,
                    "",
                    fingerprint_spec(spec),
                    json.dumps(spec, ensure_ascii=False, sort_keys=True),
                ),
            )
        state = self.conn.execute(
            "SELECT value FROM rule_state WHERE key = 'active_version'"
        ).fetchone()
        if state is None:
            self.conn.execute(
                "INSERT INTO rule_state (key, value, updated_at) VALUES "
                "('active_version', ?, ?)",
                (BUILTIN_VERSION, now),
            )
        self.conn.commit()

    def _audit(self, entry: dict[str, Any]) -> None:
        if self.audit_path is None:
            return
        AuditLog(self.audit_path).append(entry)

    def active_version_tag(self) -> str:
        if self.conn is None or not self._table_exists("rule_state"):
            return BUILTIN_VERSION
        row = self.conn.execute(
            "SELECT value FROM rule_state WHERE key = 'active_version'"
        ).fetchone()
        return str(row[0]) if row else BUILTIN_VERSION

    def active_rule_set(self) -> RuleSet:
        return self.get_version(self.active_version_tag()).rule_set

    # --------------------------------------------------------------- versions

    def get_version(self, version: str) -> RuleVersion:
        if not is_valid_version_tag(version):
            raise RuleError(f"invalid rule version tag: {version!r}")
        if self.conn is None or not self._table_exists("rule_versions"):
            if version == BUILTIN_VERSION:
                rule_set = builtin_rule_set()
                return RuleVersion(
                    version=BUILTIN_VERSION,
                    name="Built-in detector rule set",
                    description="",
                    created_by=SYSTEM_ACTOR,
                    created_at="",
                    base_version="",
                    fingerprint=rule_set.fingerprint,
                    spec=rule_set.spec,
                    builtin=True,
                    rule_set=rule_set,
                )
            raise RuleError(f"unknown rule version: {version}")
        row = self.conn.execute(
            "SELECT * FROM rule_versions WHERE version = ?", (version,)
        ).fetchone()
        if row is None:
            if version == BUILTIN_VERSION:
                rule_set = builtin_rule_set()
                return RuleVersion(
                    version=BUILTIN_VERSION,
                    name="Built-in detector rule set",
                    description="",
                    created_by=SYSTEM_ACTOR,
                    created_at="",
                    base_version="",
                    fingerprint=rule_set.fingerprint,
                    spec=rule_set.spec,
                    builtin=True,
                    rule_set=rule_set,
                )
            raise RuleError(f"unknown rule version: {version}")
        try:
            spec = json.loads(row["spec_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuleError(f"rule version {version} has unreadable spec: {exc}") from exc
        rule_set = compile_rule_set(
            spec, version=row["version"], base_version=row["base_version"]
        )
        stored_fingerprint = row["fingerprint"]
        if rule_set.fingerprint != stored_fingerprint:
            raise RuleError(
                f"rule version {version} fingerprint mismatch; catalog may be corrupted"
            )
        return RuleVersion(
            version=row["version"],
            name=row["name"],
            description=row["description"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            base_version=row["base_version"],
            fingerprint=row["fingerprint"],
            spec=spec,
            builtin=bool(row["builtin"]),
            rule_set=rule_set,
        )

    def list_versions(self) -> list[RuleVersion]:
        if self.conn is None or not self._table_exists("rule_versions"):
            return [self.get_version(BUILTIN_VERSION)]
        rows = self.conn.execute(
            "SELECT version FROM rule_versions ORDER BY created_at, version"
        ).fetchall()
        return [self.get_version(row["version"]) for row in rows]

    def create_version(self, pack: RulePack, actor: str | None = None) -> RuleVersion:
        assert self.conn is not None, "catalog is read-only"
        actor = resolve_actor(actor)
        if pack.created_by is not None and pack.created_by != actor:
            raise RulePermissionError(
                f"rule pack created_by {pack.created_by!r} does not match actor {actor!r}"
            )
        if not is_valid_version_tag(pack.rule_version):
            raise RuleError(f"invalid rule version tag: {pack.rule_version!r}")
        if pack.rule_version in RESERVED_VERSION_TAGS:
            raise RuleError(f"rule version tag is reserved: {pack.rule_version!r}")
        if self.conn.execute(
            "SELECT 1 FROM rule_versions WHERE version = ?", (pack.rule_version,)
        ).fetchone():
            raise RuleError(f"rule version already exists: {pack.rule_version}")
        base_tag = pack.base
        if base_tag == ACTIVE_VERSION_ALIAS:
            base_tag = self.active_version_tag()
        base = self.get_version(base_tag).rule_set
        detectors, spec = apply_overlay(base.detectors, pack.detectors)
        rule_set = compile_rule_set(
            spec, version=pack.rule_version, base_version=base_tag
        )
        now = _now()
        try:
            self.conn.execute(
                "INSERT INTO rule_versions "
                "(version, name, description, created_by, created_at, "
                "base_version, fingerprint, spec_json, builtin) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    pack.rule_version,
                    pack.name,
                    pack.description,
                    actor,
                    now,
                    base_tag,
                    rule_set.fingerprint,
                    json.dumps(rule_set.spec, ensure_ascii=False, sort_keys=True),
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError as exc:
            raise RuleError(
                f"rule version already exists: {pack.rule_version}"
            ) from exc
        try:
            self._audit(
                {
                    "event": "rule_version_created",
                    "rule_version": pack.rule_version,
                    "rule_fingerprint": rule_set.fingerprint,
                    "base_version": base_tag,
                    "created_by": actor,
                    "detectors": list(rule_set.detector_types()),
                    "source": str(pack.source_path),
                }
            )
        except Exception:
            self.conn.execute(
                "DELETE FROM rule_versions WHERE version = ?", (pack.rule_version,)
            )
            self.conn.commit()
            raise
        return self.get_version(pack.rule_version)

    # -------------------------------------------------------------- permissions

    @staticmethod
    def _creator_allowed(record: RuleVersion, actor: str) -> bool:
        # The built-in snapshot is a shared baseline, not owned by an operator.
        if record.builtin and record.created_by == SYSTEM_ACTOR:
            return True
        return actor == record.created_by

    def assert_can_trial(
        self, version: str, dataset_path: str | Path, actor: str | None = None
    ) -> RuleVersion:
        actor = resolve_actor(actor)
        record = self.get_version(version)
        if self._creator_allowed(record, actor):
            return record
        path = Path(dataset_path).expanduser().resolve()
        scope = self.get_gray_scope(version)
        if scope:
            for pattern in scope["datasets"]:
                if _path_matches(pattern, path):
                    return record
        raise RulePermissionError(
            f"actor {actor!r} is not the creator of rule version {version!r} "
            f"and the dataset is outside its gray scope"
        )

    # --------------------------------------------------------------- gray scope

    def get_gray_scope(self, version: str) -> dict[str, Any] | None:
        if self.conn is None or not self._table_exists("gray_scopes"):
            return None
        row = self.conn.execute(
            "SELECT * FROM gray_scopes WHERE rule_version = ?", (version,)
        ).fetchone()
        if row is None:
            return None
        return {
            "rule_version": row["rule_version"],
            "datasets": json.loads(row["datasets_json"]),
            "updated_by": row["updated_by"],
            "updated_at": row["updated_at"],
        }

    def set_gray_scope(
        self,
        version: str,
        datasets: Iterable[str],
        actor: str | None = None,
    ) -> dict[str, Any]:
        assert self.conn is not None, "catalog is read-only"
        actor = resolve_actor(actor)
        record = self.get_version(version)
        if not self._creator_allowed(record, actor):
            raise RulePermissionError(
                f"only the creator of rule version {version!r} can adjust its gray scope"
            )
        patterns: list[str] = []
        for pattern in datasets:
            if not isinstance(pattern, str) or not pattern.strip():
                raise RuleError("gray scope dataset patterns must be non-empty strings")
            patterns.append(pattern.strip())
        if not patterns:
            raise RuleError("gray scope must contain at least one dataset pattern")
        now = _now()
        previous = self.get_gray_scope(version)
        self.conn.execute(
            "INSERT INTO gray_scopes "
            "(rule_version, datasets_json, updated_by, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(rule_version) DO UPDATE SET "
            "datasets_json=excluded.datasets_json, "
            "updated_by=excluded.updated_by, updated_at=excluded.updated_at",
            (version, json.dumps(patterns, ensure_ascii=False, sort_keys=True), actor, now),
        )
        self.conn.commit()
        try:
            self._audit(
                {
                    "event": "gray_scope_updated",
                    "rule_version": version,
                    "actor": actor,
                    "datasets": patterns,
                    "previous_datasets": previous["datasets"] if previous else None,
                }
            )
        except Exception:
            if previous is None:
                self.conn.execute(
                    "DELETE FROM gray_scopes WHERE rule_version = ?", (version,)
                )
            else:
                self.conn.execute(
                    "UPDATE gray_scopes SET datasets_json=?, updated_by=?, updated_at=? "
                    "WHERE rule_version=?",
                    (
                        json.dumps(previous["datasets"], ensure_ascii=False, sort_keys=True),
                        previous["updated_by"],
                        previous["updated_at"],
                        version,
                    ),
                )
            self.conn.commit()
            raise
        result = self.get_gray_scope(version)
        assert result is not None
        return result

    # ----------------------------------------------------------------- rollback

    def rollback(self, version: str, actor: str | None = None) -> dict[str, Any]:
        assert self.conn is not None, "catalog is read-only"
        actor = resolve_actor(actor)
        target = self.get_version(version)
        if not self._creator_allowed(target, actor):
            raise RulePermissionError(
                f"only the creator of rule version {version!r} can roll back to it"
            )
        previous = self.active_version_tag()
        now = _now()
        self.conn.execute(
            "UPDATE rule_state SET value = ?, updated_at = ? "
            "WHERE key = 'active_version'",
            (version, now),
        )
        self.conn.commit()
        try:
            self._audit(
                {
                    "event": "rule_rollback",
                    "rule_version": version,
                    "previous_version": previous,
                    "rule_fingerprint": target.fingerprint,
                    "actor": actor,
                }
            )
        except Exception:
            self.conn.execute(
                "UPDATE rule_state SET value = ?, updated_at = ? "
                "WHERE key = 'active_version'",
                (previous, _now()),
            )
            self.conn.commit()
            raise
        return {
            "version": version,
            "previous_version": previous,
            "fingerprint": target.fingerprint,
            "actor": actor,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _open_catalog(paths: Any, *, create: bool = True) -> RuleCatalog:
    return RuleCatalog(
        paths.rules_db, audit_path=paths.audit_path, create=create
    )


def create_rule_version(paths: Any, pack: RulePack, actor: str | None = None) -> RuleVersion:
    """Register a rule pack in a workspace (convenience wrapper)."""
    with _open_catalog(paths) as catalog:
        return catalog.create_version(pack, actor)


def rollback_rule_version(
    paths: Any, version: str, actor: str | None = None
) -> dict[str, Any]:
    """Switch the formal rule version (convenience wrapper)."""
    with _open_catalog(paths) as catalog:
        return catalog.rollback(version, actor)


def set_gray_scope(
    paths: Any, version: str, datasets: Iterable[str], actor: str | None = None
) -> dict[str, Any]:
    """Set a rule version's gray-trial scope (convenience wrapper)."""
    with _open_catalog(paths) as catalog:
        return catalog.set_gray_scope(version, datasets, actor)


def active_rule_set(paths: Any, *, create: bool = False) -> RuleSet:
    """Resolve the active formal rule set for a workspace."""
    with _open_catalog(paths, create=create) as catalog:
        return catalog.active_rule_set()
