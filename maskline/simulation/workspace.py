"""Isolated, self-cleaning temporary workspace for one simulation run.

Every simulation gets its own directory under the simulation temp root so that
concurrent runs never share a pseudonym database, staging file or lock. The
directory is created with 0700 permissions and removed unconditionally when the
workspace closes (including on errors); nothing is ever written inside the
formal output directory.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..config import Paths
from .errors import SimulationError

_WORKSPACE_PREFIX = "sim-"
_STALE_AFTER_SECONDS = 24 * 60 * 60


def default_temp_root(paths: Paths) -> Path:
    """Resolve the simulation temp root.

    Prefer MASKLINE_SIM_TMP, then a dedicated ``data/sim-tmp`` directory inside
    the workspace (never the formal output directory ``data/out``), falling back
    to the operating system temp location.
    """
    override = os.environ.get("MASKLINE_SIM_TMP")
    if override:
        return Path(override).expanduser().resolve()
    return (paths.data_dir / "sim-tmp").resolve()


def new_simulation_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"sim-{stamp}-{os.urandom(3).hex()}"


@dataclass
class SimulationWorkspace:
    simulation_id: str
    root: Path
    temp_dir: Path
    created_at: str

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, paths: Paths, temp_root: Path | None = None) -> "SimulationWorkspace":
        base = (temp_root or default_temp_root(paths)).expanduser().resolve()
        base.mkdir(parents=True, exist_ok=True)
        simulation_id = new_simulation_id()
        try:
            temp_dir = Path(
                tempfile.mkdtemp(prefix=f"{_WORKSPACE_PREFIX}{simulation_id}-", dir=base)
            )
        except OSError as exc:
            raise SimulationError(
                f"cannot create simulation temp directory under {base}: {exc}"
            ) from exc
        try:
            os.chmod(temp_dir, 0o700)
        except OSError:
            pass
        return cls(
            simulation_id=simulation_id,
            root=paths.root,
            temp_dir=temp_dir,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    def cleanup(self) -> None:
        """Remove the whole isolated directory; tolerate already-removed trees."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def close(self) -> None:
        self.cleanup()

    def __enter__(self) -> "SimulationWorkspace":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.cleanup()

    # -- per-run isolated resources ---------------------------------------
    @property
    def pseudomap_db(self) -> Path:
        return self.temp_dir / "pseudomap.sqlite"

    @property
    def staging_db(self) -> Path:
        return self.temp_dir / "staging.sqlite"

    def ensure_inside(self, path: Path) -> Path:
        """Return ``path`` after asserting it stays inside the temp dir."""
        resolved = path.expanduser().resolve()
        if self.temp_dir not in resolved.parents and resolved != self.temp_dir:
            raise SimulationError(
                f"refusing to write simulation artifact outside the temp dir: {resolved}"
            )
        return resolved


def sweep_stale_workspaces(paths: Paths, temp_root: Path | None = None) -> int:
    """Remove abandoned simulation directories older than the staleness window.

    Returns the number of directories removed. A directory that is still in use
    (for example by a concurrent simulation) is left untouched: removing it would
    fail on open files, and the error is swallowed per-entry.
    """
    base = (temp_root or default_temp_root(paths)).expanduser().resolve()
    if not base.exists():
        return 0
    cutoff = time.time() - _STALE_AFTER_SECONDS
    removed = 0
    for child in base.iterdir():
        if not child.is_dir() or not child.name.startswith(_WORKSPACE_PREFIX):
            continue
        try:
            if child.stat().st_mtime >= cutoff:
                continue
            shutil.rmtree(child)
            removed += 1
        except OSError:
            continue
    return removed
