"""Filter-transformation learning (Phase 8 T8.3, FR-MUT-3).

Learn what the target's filter does to input — what it blocks, what it strips — and find
**semantics-preserving** operator chains that evade it. Offline this drives the
`FilterModel`; live, the same logic observes real canary round-trips (a `Filter` is any
object with ``evaluate(payload) -> FilterResult`` / ``caught(payload) -> bool``).

This is the bounded, exhaustive learner (which operators defeat this filter). The Phase
8 search (T8.4) layers bandit scheduling and grey-box coverage on top to prioritize.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from fuzzlab.mutation.filtermodel import FilterResult
from fuzzlab.mutation.operators import MutationOperator, default_operators
from fuzzlab.mutation.semantics import SemanticsValidator


class Filter(Protocol):
    def evaluate(self, payload: str) -> FilterResult: ...
    def caught(self, payload: str) -> bool: ...


@dataclass
class Bypass:
    variant: str
    operators: list[str]          # operator ids applied, in order
    semantics_ok: bool
    depth: int = field(default=0)


class FilterLearner:
    def __init__(self, flt: Filter, validator: SemanticsValidator | None = None):
        self.filter = flt
        self.validator = validator or SemanticsValidator()

    # --- observation ---------------------------------------------------------
    def evading_operators(self, base: str, vuln_class: str = "sql-injection",
                          operators: list[MutationOperator] | None = None) -> list[str]:
        """Single operators whose variant of a *caught* base evades the filter."""
        ops = operators or default_operators(vuln_class)
        out = []
        for op in ops:
            for variant in op.apply(base):
                if not self.filter.caught(variant):
                    out.append(op.id)
                    break
        return out

    def observe_transform(self, canary: str) -> dict:
        """What the filter does to a canary: hits and whether it strips (sanitizes)."""
        res = self.filter.evaluate(canary)
        return {"hits": res.hits, "action": res.action,
                "stripped": res.clean != canary, "clean": res.clean}

    # --- bypass search (bounded, prefers semantics-preserving) ---------------
    def learn_bypass(self, base: str, vuln_class: str = "sql-injection",
                     operators: list[MutationOperator] | None = None,
                     max_depth: int = 2) -> Bypass | None:
        """Bounded BFS over operator chains for a variant the filter does not catch.

        Prefers the shallowest chain, and semantics-preserving variants over trusted
        ones. Returns ``None`` if the base is already uncaught or nothing evades within
        ``max_depth``.
        """
        if not self.filter.caught(base):
            return Bypass(base, [], True, 0)             # already passes
        ops = operators or default_operators(vuln_class)
        # BFS layer by layer so the first hit is a shortest chain.
        frontier: list[tuple[str, list[str], bool]] = [(base, [], True)]
        seen = {base}
        best_trusted: Bypass | None = None
        for depth in range(1, max_depth + 1):
            nxt = []
            for payload, chain, preserving in frontier:
                for op in ops:
                    for variant in op.apply(payload):
                        if variant in seen:
                            continue
                        seen.add(variant)
                        ok = preserving and self.validator.preserves(
                            base, variant, vuln_class, trusted=not op.surface)
                        nxt.append((variant, chain + [op.id], ok))
                        if not self.filter.caught(variant):
                            bp = Bypass(variant, chain + [op.id], ok, depth)
                            if ok:
                                return bp                # semantics-preserving bypass wins
                            best_trusted = best_trusted or bp
            frontier = nxt
        return best_trusted
