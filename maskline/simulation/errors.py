"""Errors raised by the simulation subsystem."""

from __future__ import annotations

from ..utils import MasklineError


class SimulationError(MasklineError):
    """A simulation could not be executed (bad policy, unreadable source, ...)."""
