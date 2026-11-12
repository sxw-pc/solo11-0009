"""Offline sensitive-field compliance classification and label mapping.

This subpackage is an independent capability layered on top of three existing
maskline building blocks: detector findings (registry catalog), field metadata
(dataset inventory), and the rule-matching style of the policy engine. It adds
versioned compliance rule packs, three built-in standards, custom pack
extension, semantic unification, tamper-evident corrections, degraded handling
of headerless/deeply-nested inputs, and fingerprint-driven re-classification.
"""

from .engine import ClassificationEngine, ColumnInput
from .models import (
    Alert,
    ClassificationRule,
    FieldClassification,
    RulePack,
    RulePackError,
    StandardClassification,
)
from .policy_export import build_policy_dict, write_policy
from .rulepacks import builtin_rule_packs, load_rule_pack
from .semantic import SemanticResolver
from .service import ClassificationService, ClassificationServiceError
from .store import ClassificationStore, ClassificationStoreError
from .tolerant import DEFAULT_MAX_NESTING_DEPTH, TolerantInventory, inspect_tolerant

__all__ = [
    "Alert",
    "ClassificationEngine",
    "ClassificationRule",
    "ClassificationService",
    "ClassificationServiceError",
    "ClassificationStore",
    "ClassificationStoreError",
    "ColumnInput",
    "DEFAULT_MAX_NESTING_DEPTH",
    "FieldClassification",
    "RulePack",
    "RulePackError",
    "SemanticResolver",
    "StandardClassification",
    "TolerantInventory",
    "builtin_rule_packs",
    "build_policy_dict",
    "inspect_tolerant",
    "load_rule_pack",
    "write_policy",
]
