"""Local identity keyring for offline two-person authorization.

Trust model
-----------
There is no CA and no server. An *identity* is a random 256-bit HMAC key held
in a file readable only by its owner (mode ``0600`` inside a ``0700``
directory). A public keyring manifest binds each key fingerprint to:

* a human name,
* a fixed role (``operator`` or ``reviewer``),
* a lifecycle state (``active`` / ``rotated`` / ``revoked``),
* an issue/version number used for rotation ordering.

The mapping database already proves that possession of a secret is the trust
anchor in this system. The two-person control therefore rests on the two
keys being held by two different people; the code enforces role and identity
separation, not physical custody. See ``docs/threat-model.md`` for the
residual risk and required operational controls.

Key files are the only place where secret material lives. The manifest stores
only fingerprints, so reading it grants no signing capability. Each key file
carries an HMAC over its own metadata so that replacing a key file with a
foreign one is detected.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..utils import atomic_write_text
from . import crypto
from .errors import KeyringError

ROLE_OPERATOR = "operator"
ROLE_REVIEWER = "reviewer"
ROLES = (ROLE_OPERATOR, ROLE_REVIEWER)

STATE_ACTIVE = "active"
STATE_ROTATED = "rotated"
STATE_REVOKED = "revoked"
# States allowed to validate historical artifacts.
VERIFIABLE_STATES = (STATE_ACTIVE, STATE_ROTATED)

KEYRING_VERSION = 1
KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Well-known kid under which the audit/clock MAC key is stored. It is not an
# identity, can never sign requests or authorizations, and is hidden from the
# normal listing.
AUDIT_KID = "audit-mac"


@dataclass(frozen=True)
class Identity:
    kid: str
    name: str
    role: str
    state: str
    version: int
    created_at: str
    rotated_at: str | None
    revoked_at: str | None

    def to_record(self) -> dict[str, Any]:
        return {
            "kid": self.kid,
            "name": self.name,
            "role": self.role,
            "state": self.state,
            "version": self.version,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "revoked_at": self.revoked_at,
        }


def _key_file(directory: Path, kid: str) -> Path:
    return directory / f"{kid}.key"


class Keyring:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.dir = self.root / "keys"
        self.manifest_path = self.root / "keyring.json"

    # ------------------------------------------------------------------ setup
    def exists(self) -> bool:
        return self.manifest_path.exists()

    def initialize(self, now_iso: str) -> bytes:
        """Create an empty keyring and the internal audit MAC key."""
        if self.exists():
            raise KeyringError(f"keyring already exists: {self.manifest_path}")
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        audit_material = crypto.new_secret()
        self._write_key_file(AUDIT_KID, audit_material, now_iso)
        manifest = {
            "version": KEYRING_VERSION,
            "algorithm": crypto.ALGORITHM,
            "created_at": now_iso,
            "identities": [],
        }
        self._write_manifest(manifest)
        return audit_material

    @property
    def audit_mac_key(self) -> bytes:
        return self._load_secret(AUDIT_KID)

    # ------------------------------------------------------------- read paths
    def _read_manifest(self) -> dict[str, Any]:
        if not self.exists():
            raise KeyringError(
                f"keyring not found at {self.manifest_path}; run 'keygen init' first"
            )
        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise KeyringError(f"keyring manifest is invalid JSON: {exc}") from exc
        if manifest.get("version") != KEYRING_VERSION:
            raise KeyringError(
                f"unsupported keyring version {manifest.get('version')!r}; "
                f"expected {KEYRING_VERSION}"
            )
        if not isinstance(manifest.get("identities"), list):
            raise KeyringError("keyring manifest has no identities list")
        return manifest

    def _write_manifest(self, manifest: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            self.manifest_path,
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )

    def list_identities(self) -> list[Identity]:
        manifest = self._read_manifest()
        return [Identity(**item) for item in manifest["identities"]]

    def get_identity(self, kid: str) -> Identity:
        for identity in self.list_identities():
            if identity.kid == kid:
                return identity
        raise KeyringError(f"unknown key id: {kid}")

    def _find_name(self, name: str) -> Identity | None:
        for identity in self.list_identities():
            if identity.name == name:
                return identity
        return None

    def _write_key_file(self, kid: str, material: bytes, now_iso: str) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        body = {
            "kid": kid,
            "algorithm": crypto.ALGORITHM,
            "created_at": now_iso,
            "key": crypto.encode_key(material),
        }
        envelope = dict(body)
        envelope["file_mac"] = crypto.tag(crypto.DOMAIN_KEYRING, material, body)
        atomic_write_text(
            _key_file(self.dir, kid),
            json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )

    def _load_secret(self, kid: str) -> bytes:
        """Load and self-verify a key file; never expose it elsewhere."""
        path = _key_file(self.dir, kid)
        if not path.is_file():
            raise KeyringError(f"private key file missing for kid {kid}: {path}")
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise KeyringError(f"key file {path} is invalid JSON") from exc
        encoded = envelope.get("key")
        try:
            material = crypto.decode_key(encoded)
        except ValueError as exc:
            raise KeyringError(f"key file {path}: {exc}") from exc
        body = {k: v for k, v in envelope.items() if k != "file_mac"}
        if envelope.get("kid") != kid or not crypto.verify_tag(
            crypto.DOMAIN_KEYRING, material, body, envelope.get("file_mac")
        ):
            raise KeyringError(
                f"key file {path} failed its integrity MAC; it may have been replaced",
                reason="key-file-tampered",
            )
        return material

    def load_signing_key(self, kid: str, *, require_role: str | None = None) -> tuple[Identity, bytes]:
        """Load a key that is permitted to sign a new artifact right now."""
        identity = self.get_identity(kid)
        if require_role is not None and identity.role != require_role:
            raise KeyringError(
                f"key {kid} has role {identity.role!r}, required {require_role!r}",
                reason="role-mismatch",
            )
        if identity.state != STATE_ACTIVE:
            raise KeyringError(
                f"key {kid} is {identity.state}; only active keys may sign",
                reason="key-not-active",
            )
        return identity, self._load_secret(kid)

    def load_verification_key(self, kid: str, *, require_role: str | None = None) -> tuple[Identity, bytes]:
        """Load a key allowed to validate an artifact it historically signed."""
        identity = self.get_identity(kid)
        if require_role is not None and identity.role != require_role:
            raise KeyringError(
                f"key {kid} has role {identity.role!r}, required {require_role!r}",
                reason="role-mismatch",
            )
        if identity.state not in VERIFIABLE_STATES:
            raise KeyringError(
                f"key {kid} is {identity.state}; its signatures are no longer accepted",
                reason="key-revoked",
            )
        return identity, self._load_secret(kid)

    # ------------------------------------------------------------ write paths
    def generate(self, name: str, role: str, now_iso: str) -> Identity:
        if role not in ROLES:
            raise KeyringError(f"role must be one of {', '.join(ROLES)}")
        if not KEY_NAME_RE.match(name):
            raise KeyringError(
                "identity name must be 1-64 chars of letters, digits, dot, dash or underscore"
            )
        manifest = self._read_manifest()
        if any(item["name"] == name for item in manifest["identities"]):
            raise KeyringError(f"an identity named {name!r} already exists")
        material = crypto.new_secret()
        kid = crypto.key_fingerprint(material)
        if any(item["kid"] == kid for item in manifest["identities"]):
            raise KeyringError("key fingerprint collision; retry")
        identity = Identity(
            kid=kid,
            name=name,
            role=role,
            state=STATE_ACTIVE,
            version=1,
            created_at=now_iso,
            rotated_at=None,
            revoked_at=None,
        )
        self._write_key_file(kid, material, now_iso)
        manifest["identities"].append(identity.to_record())
        self._write_manifest(manifest)
        return identity

    def _mutate(self, kid: str, new_state: str, now_iso: str) -> Identity:
        manifest = self._read_manifest()
        for item in manifest["identities"]:
            if item["kid"] == kid:
                if item["state"] == STATE_REVOKED:
                    raise KeyringError(f"key {kid} is already revoked")
                if item["state"] == new_state:
                    raise KeyringError(f"key {kid} is already {new_state}")
                item["state"] = new_state
                if new_state == STATE_ROTATED:
                    item["rotated_at"] = now_iso
                if new_state == STATE_REVOKED:
                    item["revoked_at"] = now_iso
                self._write_manifest(manifest)
                return Identity(**item)
        raise KeyringError(f"unknown key id: {kid}")

    def rotate(self, kid: str, now_iso: str) -> Identity:
        """Deactivate a key while keeping its historical signatures verifiable."""
        return self._mutate(kid, STATE_ROTATED, now_iso)

    def revoke(self, kid: str, now_iso: str) -> Identity:
        """Permanently reject a key, including artifacts signed earlier."""
        return self._mutate(kid, STATE_REVOKED, now_iso)
