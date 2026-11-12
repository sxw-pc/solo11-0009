"""Independent read-only evaluation of masked data products.

Red lines enforced by this package:

* source and product are opened read-only only (SQLite ``mode=ro`` / CSV
  read handles); no writable handle is ever created here;
* the pseudonym mapping store is never imported or opened;
* reports contain bucket ordinals, counts, proportions and hashes only — raw
  cell values are never serialized;
* every aggregator is either a fixed-size sketch or an externally spilled
  exact counter, so memory does not grow with row count.
"""

from __future__ import annotations

from .access import EvaluationError
from .engine import (
    EvaluationConfig,
    EvaluationInputError,
    EvaluationResult,
    Evaluator,
    JoinSpec,
    QISpec,
)

__all__ = [
    "EvaluationError",
    "EvaluationConfig",
    "EvaluationInputError",
    "EvaluationResult",
    "Evaluator",
    "JoinSpec",
    "QISpec",
]
