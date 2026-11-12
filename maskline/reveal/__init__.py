"""Offline two-person controlled re-identification workflow.

This package implements a *controlled reveal* mechanism on top of the reversible
pseudonym mapping database. Re-identification is never possible with the
mapping database and a key alone: it additionally requires

1. a reveal request signed by an operator key,
2. an authorization signed by a *different* reviewer key, carrying an expiry
   time and a maximum row limit, and
3. a successful local validation of the whole authorization chain before any
   plaintext is produced.

Every decision (including every rejection) is appended to the tamper-evident
audit log. There is no server and no third-party dependency: identity and
authorization are expressed with HMAC-SHA256 tags built from
:mod:`hmac`/:mod:`hashlib`, with domain-separated tag prefixes.
"""

from .errors import (
    AuthorizationError,
    ClockRollbackError,
    KeyringError,
    RevealControlError,
    ReplayError,
    ScopeError,
)

__all__ = [
    "RevealControlError",
    "AuthorizationError",
    "ClockRollbackError",
    "KeyringError",
    "ReplayError",
    "ScopeError",
]
