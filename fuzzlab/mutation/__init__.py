"""Mutation engine (component #9, Phase 8).

Generates new, **semantics-preserving** payload variants that defeat the lab WAF's
filters (D16) and reach new code, expanding beyond the static `references/` catalog —
guided by the bandit scheduler and grey-box coverage. It proposes payloads; it never
decides what to attack (scheduler) or whether a hit is real (oracle).

T8.1 ships the offline-testable heart: the typed, meaning-preserving operator framework
(`operators.py`) and the semantics validator (`semantics.py`).
"""

from __future__ import annotations

from fuzzlab.mutation.filtermodel import FilterModel, FilterResult
from fuzzlab.mutation.learn import Bypass, FilterLearner
from fuzzlab.mutation.operators import (MutationOperator, apply_chain,
                                        default_operators)
from fuzzlab.mutation.semantics import SemanticsValidator, canonicalize
from fuzzlab.mutation.xss import context_from_sink, xss_payloads

__all__ = [
    "MutationOperator",
    "default_operators",
    "apply_chain",
    "SemanticsValidator",
    "canonicalize",
    "xss_payloads",
    "context_from_sink",
    "FilterModel",
    "FilterResult",
    "FilterLearner",
    "Bypass",
]
