"""Errors raised by the resource quota governor."""

from __future__ import annotations

from ..utils import MasklineError


class GovernorError(MasklineError):
    """Base class for governor-facing errors."""


class QuotaConfigError(GovernorError):
    """A quota configuration file or override is invalid."""


class GovernorStateError(GovernorError):
    """The persisted governor state is missing, locked, or inconsistent."""


class JobControlError(GovernorError):
    """A requested job control action is not valid for its current state."""
