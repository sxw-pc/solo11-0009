"""Sensitive-format detectors."""

from __future__ import annotations

from typing import Any

__all__ = ["DetectionResult", "analyze_column"]


def __getattr__(name: str) -> Any:
    # Import lazily so ``maskline.rules`` can import detector modules without
    # triggering the engine (which itself depends on the rule set types).
    if name in __all__:
        from .engine import DetectionResult, analyze_column

        return {
            "DetectionResult": DetectionResult,
            "analyze_column": analyze_column,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
