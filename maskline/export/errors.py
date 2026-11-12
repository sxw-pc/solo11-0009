"""Stable error codes for subset export and subset verification.

Every failure that callers are expected to handle carries a machine-readable
``code`` so scripts and partner-facing tooling do not have to parse prose.
"""

from __future__ import annotations

from typing import Any

from ..utils import MasklineError

# Source selection
SOURCE_NOT_FOUND = "EXPORT_SOURCE_NOT_FOUND"
SOURCE_UNSUPPORTED = "EXPORT_SOURCE_UNSUPPORTED"
SOURCE_UNREADABLE = "EXPORT_SOURCE_UNREADABLE"
SOURCE_INTEGRITY_MISMATCH = "EXPORT_SOURCE_INTEGRITY_MISMATCH"
SOURCE_UNREGISTERED = "EXPORT_SOURCE_UNREGISTERED"

# Specification
INVALID_SPEC = "EXPORT_INVALID_SPEC"
UNKNOWN_TABLE = "EXPORT_UNKNOWN_TABLE"
UNKNOWN_COLUMN = "EXPORT_UNKNOWN_COLUMN"
UNKNOWN_FILTER_COLUMN = "EXPORT_UNKNOWN_FILTER_COLUMN"
BAD_FILTER = "EXPORT_BAD_FILTER"
SAMPLE_OUT_OF_RANGE = "EXPORT_SAMPLE_OUT_OF_RANGE"
FORMAT_INCOMPATIBLE = "EXPORT_FORMAT_INCOMPATIBLE"

# Result selection
NO_MATCH = "EXPORT_NO_MATCH"
SAMPLE_EMPTY = "EXPORT_SAMPLE_EMPTY"

# Output
OUTPUT_EXISTS = "EXPORT_OUTPUT_EXISTS"
OUTPUT_INSIDE_SOURCE = "EXPORT_OUTPUT_INSIDE_SOURCE"
WRITE_FAILED = "EXPORT_WRITE_FAILED"

# Mapping reuse
MAPPING_REUSE_MISMATCH = "EXPORT_MAPPING_REUSE_MISMATCH"

# Audit trail
AUDIT_SYNC_FAILED = "EXPORT_AUDIT_SYNC_FAILED"

# Verification
VERIFY_MISSING_PROVENANCE = "EXPORT_VERIFY_MISSING_PROVENANCE"
VERIFY_INVALID_PROVENANCE = "EXPORT_VERIFY_INVALID_PROVENANCE"
VERIFY_OUTPUT_MISSING = "EXPORT_VERIFY_OUTPUT_MISSING"
VERIFY_OUTPUT_MISMATCH = "EXPORT_VERIFY_OUTPUT_MISMATCH"
VERIFY_INTEGRITY_MISMATCH = "EXPORT_VERIFY_INTEGRITY_MISMATCH"
VERIFY_SOURCE_MISMATCH = "EXPORT_VERIFY_SOURCE_MISMATCH"


class ExportError(MasklineError):
    """A subset export failure with a stable code and optional details."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.details = details

    def __str__(self) -> str:  # pragma: no cover - exercised through CLI
        return f"[{self.code}] {super().__str__()}"
