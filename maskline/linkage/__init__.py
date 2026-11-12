"""Cross-dataset sensitive linkage risk identification."""

from .ignore import EMPTY_RULES, IgnoreRules, load_ignore_rules
from .model import (
    LEVEL_LABELS,
    RISK_LEVELS,
    Association,
    ColRef,
    ColumnProfile,
    RiskFinding,
    ScanWarning,
)
from .scan import LinkScanOptions, LinkScanOutcome, run_linkscan

__all__ = [
    "EMPTY_RULES",
    "LEVEL_LABELS",
    "RISK_LEVELS",
    "Association",
    "ColRef",
    "ColumnProfile",
    "IgnoreRules",
    "LinkScanOptions",
    "LinkScanOutcome",
    "RiskFinding",
    "ScanWarning",
    "load_ignore_rules",
    "run_linkscan",
]
