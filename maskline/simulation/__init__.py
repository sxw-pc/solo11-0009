"""Policy impact simulation: evaluate masking rules without producing outputs.

The package reuses the existing policy parser, transformer registry, read-only
dataset iterators and sensitive detectors, so every declarative policy construct
supported by the formal masking pipeline is supported here unchanged. No source
data is modified and no formal masking artifact is ever written.
"""

from .errors import SimulationError
from .runner import SimulationResult, run_simulation
from .store import SimulationStore, compare_simulations
from .workspace import SimulationWorkspace, sweep_stale_workspaces

__all__ = [
    "SimulationError",
    "SimulationResult",
    "SimulationStore",
    "SimulationWorkspace",
    "compare_simulations",
    "run_simulation",
    "sweep_stale_workspaces",
]
