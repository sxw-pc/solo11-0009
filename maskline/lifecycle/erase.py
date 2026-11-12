"""Irreversible file removal with a pre-delete overwrite pass.

Plain ``unlink`` only removes a directory entry; the bytes remain on disk and
can be recovered. For pseudonym mapping data — which is equivalent to a
plaintext key — we first overwrite the full file with cryptographic random
bytes, verify the overwrite landed, and only then unlink it. SQLite sidecar
files (``-wal`` / ``-shm``) receive the same treatment because they may hold
recently written mapping pages.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from ..utils import file_sha256


class EraseError(RuntimeError):
    pass


@dataclass(frozen=True)
class EraseOutcome:
    path: Path
    existed: bool
    size_bytes: int
    pre_hash: str | None
    post_hash: str | None


def _sidecar_paths(path: Path) -> list[Path]:
    return [Path(str(path) + suffix) for suffix in ("", "-wal", "-shm", "-journal")]


def _overwrite_once(path: Path) -> None:
    size = path.stat().st_size
    with path.open("r+b") as fh:
        remaining = size
        while remaining > 0:
            chunk = min(remaining, 1 << 20)
            fh.write(secrets.token_bytes(chunk))
            remaining -= chunk
        fh.flush()
        os.fsync(fh.fileno())


def secure_erase(path: str | Path, *, passes: int = 1) -> list[EraseOutcome]:
    """Overwrite and unlink a file plus its SQLite sidecars.

    Returns one outcome per physical file that existed. A missing primary file
    is treated as already erased (idempotent resume) but still returns an
    outcome so callers can record the evidence. Raises :class:`EraseError` if
    any existing file cannot be overwritten or removed; already-removed files
    are not an error, which is what makes a retry safe.
    """
    target = Path(path)
    outcomes: list[EraseOutcome] = []
    for candidate in _sidecar_paths(target):
        if not candidate.exists():
            if candidate == target:
                outcomes.append(
                    EraseOutcome(path=candidate, existed=False, size_bytes=0,
                                 pre_hash=None, post_hash=None)
                )
            continue
        size = candidate.stat().st_size
        pre_hash = file_sha256(candidate)
        if size > 0:
            try:
                for _ in range(max(1, passes)):
                    _overwrite_once(candidate)
                post_hash = file_sha256(candidate)
                if post_hash == pre_hash and size > 0:
                    raise EraseError(
                        f"overwrite verification failed for {candidate}: content unchanged"
                    )
            except OSError as exc:
                raise EraseError(f"cannot overwrite {candidate}: {exc}") from exc
        else:
            post_hash = pre_hash
        try:
            candidate.unlink()
        except OSError as exc:
            raise EraseError(f"cannot remove {candidate}: {exc}") from exc
        outcomes.append(
            EraseOutcome(path=candidate, existed=True, size_bytes=size,
                         pre_hash=pre_hash, post_hash=post_hash)
        )
    return outcomes
