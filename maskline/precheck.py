"""Read-only pre-run checks for approval gates.

`maskline precheck` verifies everything `maskline run` needs before the run
starts, and writes nothing: no target database, no checkpoints, no pseudomap,
no audit entries, no registry updates — the data/ and audit/ directories are
left byte-identical. The exit code is a bitmask so approval systems can tell
failure classes apart:

    0   all checks passed (warnings may still be present)
    1   secret problem (unset, unreadable, or group/other-readable)
    2   policy problem (invalid, unknown columns, fingerprint not registered)
    4   dataset problem (unreadable, or fingerprint drifted since registration)
    8   target problem (directory not writable, or not enough free disk space)
    16  registry problem (catalog unreadable or schema outdated)

Simultaneous failures combine bitwise (e.g. exit 3 = secret + policy).
"""

from __future__ import annotations

import json
import math
import os
import shutil
import sqlite3
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import ConfigError, Paths, SecretStore
from .dataset_io import DatasetError
from .detectors.engine import detector_version
from .policies import Policy, PolicyError, load_policy
from .registry import Catalog, DatasetInventory, inspect_dataset
from .utils import MasklineError

EXIT_SECRET = 1
EXIT_POLICY = 2
EXIT_DATASET = 4
EXIT_TARGET = 8
EXIT_REGISTRY = 16

EXIT_BIT_MEANING = {
    EXIT_SECRET: "secret",
    EXIT_POLICY: "policy",
    EXIT_DATASET: "dataset",
    EXIT_TARGET: "target",
    EXIT_REGISTRY: "registry",
}

DEFAULT_SPACE_MULTIPLIER = 2.0
SECRET_ENV_VAR = "MASKLINE_SECRET_FILE"
SECRET_TRANSFORMERS = {"hash", "pseudonym"}

_BLOCKER = "blocker"
_WARNING = "warning"

_PASS = "pass"
_FAIL = "fail"
_SKIP = "skip"

_REQUIRED_TABLES = {"datasets", "findings", "policies"}


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    category: str
    level: str  # "blocker" | "warning"
    outcome: str  # "pass" | "fail" | "skip"
    message: str
    exit_bit: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check_id,
            "category": self.category,
            "level": self.level,
            "outcome": self.outcome,
            "message": self.message,
        }


@dataclass
class PrecheckReport:
    dataset: str
    policy: str
    output: str
    space_multiplier: float
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        code = 0
        for check in self.checks:
            if check.level == _BLOCKER and check.outcome == _FAIL:
                code |= check.exit_bit
        return code

    @property
    def blockers(self) -> list[CheckResult]:
        return [
            check
            for check in self.checks
            if check.level == _BLOCKER and check.outcome == _FAIL
        ]

    @property
    def warnings(self) -> list[CheckResult]:
        return [
            check
            for check in self.checks
            if check.level == _WARNING and check.outcome == _FAIL
        ]

    @property
    def status(self) -> str:
        if self.blockers:
            return "blocked"
        if self.warnings:
            return "pass_with_warnings"
        return "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "exit_bit_meaning": {str(bit): name for bit, name in EXIT_BIT_MEANING.items()},
            "dataset": self.dataset,
            "policy": self.policy,
            "output": self.output,
            "space_multiplier": self.space_multiplier,
            "checks": [check.to_dict() for check in self.checks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_text(self) -> str:
        symbols = {_PASS: " OK ", _SKIP: "SKIP"}
        width = max(len(check.check_id) for check in self.checks)
        lines = []
        for check in self.checks:
            if check.outcome == _FAIL:
                symbol = "WARN" if check.level == _WARNING else "FAIL"
            else:
                symbol = symbols[check.outcome]
            lines.append(
                f"[{symbol}] {check.check_id:<{width}}  {check.level:<8}  {check.message}"
            )
        blockers = self.blockers
        warnings = self.warnings
        lines.append("")
        if blockers:
            lines.append(
                f"result: BLOCKED - {len(blockers)} blocker(s), "
                f"{len(warnings)} warning(s), exit code {self.exit_code}"
            )
        elif warnings:
            lines.append(
                f"result: PASS WITH WARNINGS - {len(warnings)} warning(s), exit code 0"
            )
        else:
            lines.append("result: PASS - all checks green, exit code 0")
        return "\n".join(lines)


def _ok(check_id: str, category: str, message: str, level: str = _BLOCKER) -> CheckResult:
    return CheckResult(check_id, category, level, _PASS, message)


def _fail(
    check_id: str, category: str, exit_bit: int, message: str, level: str = _BLOCKER
) -> CheckResult:
    return CheckResult(check_id, category, level, _FAIL, message, exit_bit)


def _warn(check_id: str, category: str, message: str) -> CheckResult:
    return CheckResult(check_id, category, _WARNING, _FAIL, message)


def _skip(check_id: str, category: str, message: str, level: str = _BLOCKER) -> CheckResult:
    return CheckResult(check_id, category, level, _SKIP, message)


def _human_bytes(value: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{int(value)}B" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}PiB"


def _dir_anchor(directory: Path) -> Path | None:
    """Nearest existing ancestor directory, or None if unusable."""
    candidate = directory
    while True:
        if candidate.is_dir():
            return candidate
        if candidate.exists():
            return None  # exists but is not a directory
        parent = candidate.parent
        if parent == candidate:
            return None
        candidate = parent


def _secret_permission_issue(path: Path) -> str | None:
    if os.name != "posix":
        return None
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        return (
            f"secret file {path} has permissions {mode:04o}; group/other users "
            "must have no access (run: chmod 600)"
        )
    return None


def _catalog_schema_problems(conn: sqlite3.Connection) -> list[str]:
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    problems = [f"missing table {name!r}" for name in sorted(_REQUIRED_TABLES - tables)]
    if "datasets" in tables:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(datasets)")}
        if "detector_version" not in columns:
            problems.append("datasets table lacks column 'detector_version'")
    return problems


def run_prechecks(
    paths: Paths,
    dataset: str | Path,
    policy_path: str | Path,
    *,
    output: str | Path | None = None,
    space_multiplier: float = DEFAULT_SPACE_MULTIPLIER,
) -> PrecheckReport:
    """Run every pre-run check. Never writes to the workspace."""
    if space_multiplier <= 0:
        raise MasklineError("space multiplier must be positive")
    dataset = Path(dataset).expanduser().resolve()
    policy_path = Path(policy_path).expanduser().resolve()
    checks: list[CheckResult] = []
    catalog: Catalog | None = None
    try:
        # 1. Policy loads under strict validation.
        policy: Policy | None = None
        try:
            policy = load_policy(policy_path)
            checks.append(
                _ok(
                    "policy.load",
                    "policy",
                    f"policy {policy.name!r} v{policy.version} valid; "
                    f"fingerprint={policy.fingerprint[:16]}...",
                )
            )
        except PolicyError as exc:
            checks.append(_fail("policy.load", "policy", EXIT_POLICY, str(exc)))

        # 2. Dataset opens read-only and fingerprints cleanly.
        inventory: DatasetInventory | None = None
        try:
            inventory = inspect_dataset(dataset)
            checks.append(
                _ok(
                    "dataset.readable",
                    "dataset",
                    f"{inventory.kind} dataset opens read-only; "
                    f"rows={inventory.row_count} "
                    f"size={_human_bytes(inventory.size_bytes)} "
                    f"fingerprint={inventory.fingerprint[:16]}...",
                )
            )
        except (DatasetError, OSError, ValueError, sqlite3.Error) as exc:
            checks.append(_fail("dataset.readable", "dataset", EXIT_DATASET, str(exc)))

        # 3. Policy tables/columns exist in the dataset.
        rule = None
        if policy is not None and inventory is not None:
            try:
                rule = policy.matching_rule(inventory.path)
            except PolicyError:
                rule = None
            try:
                matched = policy.validate_against(inventory)
                column_count = sum(len(t.columns) for t in matched.tables.values())
                checks.append(
                    _ok(
                        "policy.schema",
                        "policy",
                        f"all {column_count} configured columns exist "
                        f"in {inventory.path.name}",
                    )
                )
            except PolicyError as exc:
                checks.append(_fail("policy.schema", "policy", EXIT_POLICY, str(exc)))
        else:
            checks.append(
                _skip("policy.schema", "policy", "needs a valid policy and dataset")
            )

        # 4/5. Secret file availability and permissions (only when needed).
        needs_secret = None
        if rule is not None:
            needs_secret = any(
                column.transformer in SECRET_TRANSFORMERS
                for table in rule.tables.values()
                for column in table.columns.values()
            )
        if needs_secret is None:
            reason = "no policy rule matches the dataset"
            checks.append(_skip("secret.file", "secret", reason))
            checks.append(_skip("secret.permissions", "secret", reason))
        elif not needs_secret:
            reason = "policy uses no hash/pseudonym transformers"
            checks.append(_skip("secret.file", "secret", reason))
            checks.append(_skip("secret.permissions", "secret", reason))
        else:
            store: SecretStore | None = None
            try:
                store = SecretStore.from_env(SECRET_ENV_VAR)
                checks.append(
                    _ok(
                        "secret.file",
                        "secret",
                        f"{store.source} readable; entries: {', '.join(store.names())}",
                    )
                )
            except ConfigError as exc:
                checks.append(_fail("secret.file", "secret", EXIT_SECRET, str(exc)))
            if os.name != "posix":
                checks.append(
                    _skip(
                        "secret.permissions",
                        "secret",
                        "POSIX permission bits do not apply on this platform",
                    )
                )
            elif store is None:
                checks.append(
                    _skip("secret.permissions", "secret", "secret file not available")
                )
            else:
                issue = _secret_permission_issue(store.source)
                if issue is None:
                    checks.append(
                        _ok(
                            "secret.permissions",
                            "secret",
                            f"{store.source} is not group/other-readable",
                        )
                    )
                else:
                    checks.append(
                        _fail("secret.permissions", "secret", EXIT_SECRET, issue)
                    )

        # 6. Registry opens read-only and has the current schema.
        registry_missing = not paths.meta_db.exists()
        if registry_missing:
            checks.append(
                _skip(
                    "registry.readable",
                    "registry",
                    f"no registry at {paths.meta_db} yet; run 'maskline scan' "
                    "and 'maskline register' first",
                )
            )
        else:
            try:
                candidate = Catalog.open_readonly(paths.meta_db)
                problems = _catalog_schema_problems(candidate.conn)
                if problems:
                    checks.append(
                        _fail(
                            "registry.readable",
                            "registry",
                            EXIT_REGISTRY,
                            "registry schema is outdated ("
                            + "; ".join(problems)
                            + "); run 'maskline scan' once to upgrade",
                        )
                    )
                    candidate.close()
                else:
                    catalog = candidate
                    checks.append(
                        _ok(
                            "registry.readable",
                            "registry",
                            f"registry {paths.meta_db} opens read-only",
                        )
                    )
            except (sqlite3.Error, OSError) as exc:
                checks.append(
                    _fail(
                        "registry.readable",
                        "registry",
                        EXIT_REGISTRY,
                        f"cannot open registry read-only: {exc}",
                    )
                )

        # 7. Policy fingerprint matches a registration (approval record).
        if policy is None:
            checks.append(_skip("policy.registered", "policy", "policy did not load"))
        elif catalog is None:
            if registry_missing:
                checks.append(
                    _fail(
                        "policy.registered",
                        "policy",
                        EXIT_POLICY,
                        "policy fingerprint is not registered (no registry); run "
                        f"'maskline register --policy {policy_path}' after approval",
                    )
                )
            else:
                checks.append(
                    _skip("policy.registered", "policy", "registry unavailable")
                )
        else:
            record = catalog.get_policy(policy.fingerprint)
            if record is not None:
                checks.append(
                    _ok(
                        "policy.registered",
                        "policy",
                        f"fingerprint registered at {record['registered_at']} "
                        f"as {record['name']!r}",
                    )
                )
            else:
                checks.append(
                    _fail(
                        "policy.registered",
                        "policy",
                        EXIT_POLICY,
                        f"policy fingerprint {policy.fingerprint[:16]}... is not "
                        "registered; run 'maskline register --policy "
                        f"{policy_path}' after approval",
                    )
                )

        # Shared lookup for the dataset registration checks.
        registrations: list[dict[str, Any]] = []
        if catalog is not None and inventory is not None:
            registrations = catalog.datasets_for_path(str(inventory.path))
        registered = None
        if inventory is not None:
            registered = next(
                (
                    item
                    for item in registrations
                    if item["fingerprint"] == inventory.fingerprint
                ),
                None,
            )

        # 8. Dataset fingerprint has not drifted since registration.
        if inventory is None:
            checks.append(
                _skip("dataset.fingerprint", "dataset", "dataset not readable")
            )
        elif catalog is None:
            if registry_missing:
                checks.append(
                    _warn(
                        "dataset.fingerprint",
                        "dataset",
                        "dataset is not registered; run 'maskline scan' so "
                        "fingerprint drift can be checked",
                    )
                )
            else:
                checks.append(
                    _skip("dataset.fingerprint", "dataset", "registry unavailable")
                )
        elif registered is not None:
            checks.append(
                _ok(
                    "dataset.fingerprint",
                    "dataset",
                    f"fingerprint matches registration from {registered['registered_at']}",
                )
            )
        elif registrations:
            latest = registrations[-1]
            checks.append(
                _fail(
                    "dataset.fingerprint",
                    "dataset",
                    EXIT_DATASET,
                    f"fingerprint drifted since registration: "
                    f"current={inventory.fingerprint[:16]}... "
                    f"registered={latest['fingerprint'][:16]}...; re-scan and "
                    "re-approve if this change is expected",
                )
            )
        else:
            checks.append(
                _warn(
                    "dataset.fingerprint",
                    "dataset",
                    "dataset is not registered; run 'maskline scan' so "
                    "fingerprint drift can be checked",
                )
            )

        # 9. Detector version matches the one used at registration (warning).
        current_detector = detector_version()
        reference = registered or (registrations[-1] if registrations else None)
        if inventory is None:
            checks.append(
                _skip(
                    "detector.version",
                    "registry",
                    "dataset not readable",
                    level=_WARNING,
                )
            )
        elif catalog is None:
            checks.append(
                _skip(
                    "detector.version",
                    "registry",
                    "registry unavailable",
                    level=_WARNING,
                )
            )
        elif reference is None:
            checks.append(
                _warn(
                    "detector.version",
                    "registry",
                    "no scan record for this dataset; run 'maskline scan'",
                )
            )
        else:
            recorded = reference.get("detector_version") or ""
            if not recorded:
                checks.append(
                    _warn(
                        "detector.version",
                        "registry",
                        "registration predates detector versioning; "
                        "re-run 'maskline scan'",
                    )
                )
            elif recorded != current_detector:
                checks.append(
                    _warn(
                        "detector.version",
                        "registry",
                        f"detector version changed since registration "
                        f"(registered={recorded}, current={current_detector}); "
                        "re-run 'maskline scan'",
                    )
                )
            else:
                checks.append(
                    _ok(
                        "detector.version",
                        "registry",
                        f"detector version {current_detector} matches registration",
                        level=_WARNING,
                    )
                )

        # 10/11. Target directory writable and enough free disk space.
        if output is not None:
            output_path = Path(output).expanduser().resolve()
        else:
            stem = inventory.path.stem if inventory else dataset.stem
            output_path = paths.out_dir / f"{stem}.masked.sqlite"
        anchor = _dir_anchor(output_path.parent)
        if inventory is not None and output_path == inventory.path:
            checks.append(
                _fail(
                    "target.writable",
                    "target",
                    EXIT_TARGET,
                    "output path equals the source dataset; "
                    "run would refuse to overwrite it",
                )
            )
        elif output_path.exists() and output_path.is_dir():
            checks.append(
                _fail(
                    "target.writable",
                    "target",
                    EXIT_TARGET,
                    f"output path {output_path} is an existing directory",
                )
            )
        elif anchor is None:
            checks.append(
                _fail(
                    "target.writable",
                    "target",
                    EXIT_TARGET,
                    f"no usable ancestor directory for {output_path.parent}",
                )
            )
        elif not os.access(anchor, os.W_OK | os.X_OK):
            checks.append(
                _fail(
                    "target.writable",
                    "target",
                    EXIT_TARGET,
                    f"target directory {anchor} is not writable",
                )
            )
        else:
            note = (
                ""
                if output_path.parent.exists()
                else f"; {output_path.parent} will be created at run time"
            )
            checks.append(
                _ok(
                    "target.writable",
                    "target",
                    f"target {output_path} is writable (checked {anchor}){note}",
                )
            )
        if inventory is None:
            checks.append(
                _skip("target.disk_space", "target", "source size unknown")
            )
        elif anchor is None:
            checks.append(
                _skip(
                    "target.disk_space", "target", "no usable target directory"
                )
            )
        else:
            free = shutil.disk_usage(anchor).free
            required = math.ceil(inventory.size_bytes * space_multiplier)
            estimate = (
                f"source {_human_bytes(inventory.size_bytes)} "
                f"x {space_multiplier:g} = {_human_bytes(required)}"
            )
            if free >= required:
                checks.append(
                    _ok(
                        "target.disk_space",
                        "target",
                        f"free={_human_bytes(free)} >= required={_human_bytes(required)} "
                        f"({estimate})",
                    )
                )
            else:
                checks.append(
                    _fail(
                        "target.disk_space",
                        "target",
                        EXIT_TARGET,
                        f"insufficient disk space: free={_human_bytes(free)} < "
                        f"required={_human_bytes(required)} ({estimate})",
                    )
                )
    finally:
        if catalog is not None:
            catalog.close()

    return PrecheckReport(
        dataset=str(dataset),
        policy=str(policy_path),
        output=str(output_path),
        space_multiplier=space_multiplier,
        checks=checks,
    )
