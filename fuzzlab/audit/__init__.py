"""Auditor rule engine: rules-as-data + full evaluation logging (Phase 2 T2.3).

Rules live as data (`rules/*.json`), not code, so the rule set is editable and
versioned without code changes. The engine evaluates every rule against every
injection point and records the outcome of each evaluation — fired and not-fired —
so the store holds negatives, giving later ML a trainable dataset.
"""

from fuzzlab.audit.rules import Rule, load_rules, matches
from fuzzlab.audit.engine import InjectionPoint, evaluate

__all__ = ["Rule", "load_rules", "matches", "InjectionPoint", "evaluate"]
