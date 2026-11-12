"""Workspace paths and secret loading.

Secrets are never stored in code or policy files. The secret file is a local
YAML document pointed to by ``MASKLINE_SECRET_FILE``.

Key rotation model
------------------
The secret file may carry several pseudonym keys, each identified by a key id
(``kid``); exactly one entry is marked ``current: true``. New pseudonym
mappings are always produced with the current key, while historical mappings
keep the ``kid`` they were created with and can still be revealed as long as
that key remains present in the file. Rotation therefore means: add a new
entry, move the ``current`` marker to it, and keep the old entries in place.

Legacy flat files containing only ``hmac_salt`` / ``pseudonym_key`` are still
accepted; their single pseudonym key is exposed under :data:`DEFAULT_KID`.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import yaml

from .utils import MasklineError, atomic_write_text


class ConfigError(MasklineError):
    pass


#: kid assigned to legacy mappings and legacy single-key secret files.
DEFAULT_KID = "default"


@dataclass(frozen=True)
class PseudonymKey:
    """One versioned pseudonym key. The material never leaves this object."""

    kid: str
    value: str
    current: bool = False


@dataclass(frozen=True)
class Paths:
    """All runtime locations for one workspace (defaults to the current directory)."""
    root: Path
    @classmethod
    def for_workspace(cls, workspace: str | Path | None = None) -> "Paths":
        if workspace is None:
            workspace = os.environ.get("MASKLINE_HOME") or Path.cwd()
        return cls(Path(workspace).expanduser().resolve())
    @property
    def data_dir(self) -> Path:
        return self.root / "data"
    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"
    @property
    def out_dir(self) -> Path:
        return self.data_dir / "out"
    @property
    def meta_db(self) -> Path:
        return self.data_dir / "meta.sqlite"
    @property
    def checkpoint_db(self) -> Path:
        return self.data_dir / "checkpoints.sqlite"
    @property
    def pseudomap_db(self) -> Path:
        return self.data_dir / "pseudomap.sqlite"
    @property
    def manifest_dir(self) -> Path:
        return self.data_dir / "manifests"
    @property
    def audit_path(self) -> Path:
        return self.root / "audit" / "audit.jsonl"
    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    def ensure_runtime_dirs(self) -> None:
        for directory in (
            self.data_dir,
            self.raw_dir,
            self.out_dir,
            self.manifest_dir,
            self.audit_path.parent,
            self.reports_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


class SecretStore:
    """Named secrets read from one local YAML file.

    ``hmac_salt`` stays a single scalar (HMAC hashing is not versioned here),
    while pseudonym keys are kept as a kid -> :class:`PseudonymKey` mapping.
    """

    MIN_LENGTH = 16
    _PLACEHOLDER_MARKERS = ("REPLACE", "CHANGEME", "TODO")

    def __init__(
        self,
        values: Mapping[str, str],
        source: Path,
        pseudonym_keys: Mapping[str, PseudonymKey] | None = None,
    ) -> None:
        self._values = dict(values)
        self.source = source
        if pseudonym_keys is None:
            # Backwards-compatible construction with a flat name/value mapping.
            if "pseudonym_key" not in values:
                raise ConfigError("SecretStore requires a pseudonym_key")
            pseudonym_keys = {
                DEFAULT_KID: PseudonymKey(
                    kid=DEFAULT_KID, value=values["pseudonym_key"], current=True
                )
            }
        self._pseudo_keys: dict[str, PseudonymKey] = dict(pseudonym_keys)
        self._current_kid = next(
            (key.kid for key in self._pseudo_keys.values() if key.current), None
        )

    # ------------------------------------------------------------------ load
    @classmethod
    def from_file(cls, path: str | Path) -> "SecretStore":
        secret_path = Path(path).expanduser()
        if not secret_path.is_file():
            raise ConfigError(f"secret file not found: {secret_path}")
        try:
            raw = yaml.safe_load(secret_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"cannot read secret file {secret_path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError("secret file must be a mapping of name to value")

        if "keys" in raw:
            values, pseudo_keys = cls._parse_versioned(raw, secret_path)
        else:
            values, pseudo_keys = cls._parse_legacy(raw, secret_path)
        return cls(values, secret_path, pseudo_keys)

    @classmethod
    def _parse_legacy(
        cls, raw: Mapping[str, object], source: Path
    ) -> tuple[dict[str, str], dict[str, PseudonymKey]]:
        values: dict[str, str] = {}
        for name, value in raw.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ConfigError("secret names and values must be strings")
            cls._check_material(name, value)
            values[name] = value
        if "hmac_salt" not in values:
            raise ConfigError("secret file is missing required entry: hmac_salt")
        if "pseudonym_key" not in values:
            raise ConfigError("secret file is missing required entry: pseudonym_key")
        pseudo_keys = {
            DEFAULT_KID: PseudonymKey(
                kid=DEFAULT_KID, value=values["pseudonym_key"], current=True
            )
        }
        return values, pseudo_keys

    @classmethod
    def _parse_versioned(
        cls, raw: Mapping[str, object], source: Path
    ) -> tuple[dict[str, str], dict[str, PseudonymKey]]:
        hmac_salt = raw.get("hmac_salt")
        if not isinstance(hmac_salt, str):
            raise ConfigError("secret file is missing required entry: hmac_salt")
        cls._check_material("hmac_salt", hmac_salt)
        entries = raw.get("keys")
        if not isinstance(entries, list) or not entries:
            raise ConfigError(
                "secret file 'keys' must be a non-empty list of pseudonym key entries"
            )
        pseudo_keys: dict[str, PseudonymKey] = {}
        current_kids: list[str] = []
        for index, entry in enumerate(entries):
            label = f"pseudonym key entry #{index + 1}"
            if not isinstance(entry, dict):
                raise ConfigError(f"{label} must be a mapping with kid/value/current")
            kid = entry.get("kid")
            if not isinstance(kid, str) or not kid.strip():
                raise ConfigError(f"{label} is missing a non-empty string 'kid'")
            value = entry.get("value")
            if not isinstance(value, str):
                raise ConfigError(f"pseudonym key entry with kid {kid!r} is missing a string 'value'")
            cls._check_material(f"pseudonym key {kid!r}", value)
            current = entry.get("current", False)
            if not isinstance(current, bool):
                raise ConfigError(
                    f"pseudonym key entry with kid {kid!r} has a non-boolean 'current' flag"
                )
            if kid in pseudo_keys:
                raise ConfigError(
                    f"duplicate kid {kid!r} in secret file {source}: "
                    f"the kid is used by more than one key entry"
                )
            if current:
                current_kids.append(kid)
            pseudo_keys[kid] = PseudonymKey(kid=kid, value=value, current=current)
        if not current_kids:
            raise ConfigError(
                f"secret file {source} marks no current pseudonym key: "
                "set 'current: true' on exactly one 'keys' entry"
            )
        if len(current_kids) > 1:
            raise ConfigError(
                f"secret file {source} marks multiple current pseudonym keys "
                f"({', '.join(sorted(current_kids))}); exactly one entry may carry current: true"
            )
        return {"hmac_salt": hmac_salt}, pseudo_keys

    @classmethod
    def _check_material(cls, name: str, value: str) -> None:
        if any(marker in value.upper() for marker in cls._PLACEHOLDER_MARKERS):
            raise ConfigError(f"secret {name} still contains a placeholder")
        if len(value) < cls.MIN_LENGTH:
            raise ConfigError(
                f"secret {name} is too short (minimum {cls.MIN_LENGTH} characters)"
            )

    @classmethod
    def from_env(cls, variable: str = "MASKLINE_SECRET_FILE") -> "SecretStore":
        path = os.environ.get(variable)
        if not path:
            raise ConfigError(
                f"{variable} is not set; point it at a local secret file "
                "(see secret.example.txt)"
            )
        return cls.from_file(path)

    # -------------------------------------------------------------- accessors
    def get(self, name: str) -> str:
        """Return a scalar secret by name.

        ``pseudonym_key`` resolves to the material of the currently active
        pseudonym key so existing callers keep working; key rotation aware
        code should use :meth:`pseudonym_key` / :meth:`key_for` instead.
        """
        if name == "pseudonym_key":
            return self.current_pseudonym_key().value
        try:
            return self._values[name]
        except KeyError as exc:
            raise ConfigError(f"secret {name!r} is not defined in {self.source}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._values))

    def current_kid(self) -> str:
        assert self._current_kid is not None  # guaranteed at construction time
        return self._current_kid

    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._pseudo_keys))

    def current_pseudonym_key(self) -> PseudonymKey:
        return self._pseudo_keys[self.current_kid()]

    def pseudonym_key(self, kid: str | None = None) -> PseudonymKey:
        return self.key_for(kid if kid is not None else self.current_kid())

    def key_for(self, kid: str) -> PseudonymKey:
        try:
            return self._pseudo_keys[kid]
        except KeyError as exc:
            raise ConfigError(
                f"no pseudonym key with kid {kid!r} in {self.source}; "
                "restore that key entry to reveal mappings created with it"
            ) from exc


def create_demo_secret(path: Path, kid: str = DEFAULT_KID) -> SecretStore:
    """Generate a local random secret for the demo only; never commit it."""
    hmac_salt = secrets.token_urlsafe(48)
    pseudo_value = secrets.token_urlsafe(48)
    lines = [
        "# Generated by maskline demo. Keep this file local and private.\n",
        'hmac_salt: "' + hmac_salt + '"\n',
        "keys:\n",
        f"  - kid: {kid}\n",
        '    value: "' + pseudo_value + '"\n',
        "    current: true\n",
    ]
    atomic_write_text(path, "".join(lines), mode=0o600)
    return SecretStore.from_file(path)


def rotate_pseudonym_key(
    path: str | Path, new_kid: str, *, promote: bool = True
) -> SecretStore:
    """Add a fresh pseudonym key entry to an existing secret file.

    All previous entries (including their key material) are preserved so old
    mappings stay revealable. When ``promote`` is true the new entry becomes
    the single ``current`` key and every other entry loses that marker.
    Only kid metadata is ever rewritten; the returned store is the source of
    truth for the new key material.
    """
    secret_path = Path(path).expanduser()
    store = SecretStore.from_file(secret_path)
    if new_kid in store._pseudo_keys:
        raise ConfigError(
            f"cannot rotate to kid {new_kid!r}: that kid already exists in {secret_path}"
        )
    entries = [
        {
            "kid": key.kid,
            "value": key.value,
            "current": (promote is False and key.current),
        }
        for key in store._pseudo_keys.values()
    ]
    entries.append({"kid": new_kid, "value": secrets.token_urlsafe(48), "current": promote})
    document = {
        "hmac_salt": store.get("hmac_salt"),
        "keys": entries,
    }
    text = (
        "# Rotated by maskline. Keep this file local and private;\n"
        "# old key entries are retained to reveal historical mappings.\n"
        + yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    )
    atomic_write_text(secret_path, text, mode=0o600)
    return SecretStore.from_file(secret_path)


def resolve_secret_store(auto_generate_path: Path | None = None) -> SecretStore:
    """Load MASKLINE_SECRET_FILE, optionally generating one for demo mode."""
    path = os.environ.get("MASKLINE_SECRET_FILE")
    if path:
        return SecretStore.from_file(path)
    if auto_generate_path is None:
        return SecretStore.from_env()
    store = create_demo_secret(auto_generate_path)
    os.environ["MASKLINE_SECRET_FILE"] = str(auto_generate_path)
    return store
