"""Export-specific exceptions with stable machine-readable error codes."""

from __future__ import annotations

from ..utils import MasklineError

# Stable error codes mapped to process exit codes for the CLI. The mapping is
# part of the public contract: partners and schedulers may rely on it.
ERROR_EXIT_CODES = {
    "EXPORT_SOURCE_NOT_FOUND": 10,
    "EXPORT_MANIFEST_MISSING": 11,
    "EXPORT_SOURCE_TAMPERED": 12,
    "EXPORT_SPEC_INVALID": 13,
    "EXPORT_TABLE_UNKNOWN": 14,
    "EXPORT_COLUMN_UNKNOWN": 15,
    "EXPORT_FILTER_INVALID": 16,
    "EXPORT_NO_ROWS": 17,
    "EXPORT_FORMAT_UNSUPPORTED": 18,
    "EXPORT_OUTPUT_INVALID": 19,
    "EXPORT_MAPPING_UNAVAILABLE": 20,
    "EXPORT_VERIFY_FAILED": 21,
    "EXPORT_INTERNAL": 22,
}


class ExportError(MasklineError):
    """An export failure carrying a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        if code not in ERROR_EXIT_CODES:
            raise ValueError(f"unknown export error code: {code}")
        super().__init__(message)
        self.code = code
        self.exit_code = ERROR_EXIT_CODES[code]
