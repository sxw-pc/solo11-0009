"""Typed errors for the controlled reveal workflow."""

from __future__ import annotations

from ..utils import MasklineError


class RevealControlError(MasklineError):
    """Base class for every controlled-reveal failure.

    The ``reason`` is a short stable slug (kebab-case) written into the audit
    record so that rejection statistics do not depend on human wording.
    """

    reason = "reveal-control-error"

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message)
        if reason is not None:
            self.reason = reason


class KeyringError(RevealControlError):
    reason = "keyring-error"


class AuthorizationError(RevealControlError):
    reason = "authorization-error"


class ScopeError(AuthorizationError):
    reason = "scope-mismatch"


class ReplayError(AuthorizationError):
    reason = "authorization-replay"


class ClockRollbackError(RevealControlError):
    reason = "clock-rollback"
