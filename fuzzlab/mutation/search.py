"""Bandit-scheduled, coverage-guided mutation search (Phase 8 T8.4, FR-MUT-4).

Given a payload the filter catches, search for a **semantics-preserving** variant that
evades it and reaches new code. Operators are chosen with the Thompson bandit (reused
from the scheduler) so evasive, coverage-gaining operators get played more; the search
hill-climbs — accepting a variant as the new working point when it improves — and is
budget-bounded and reproducible under a fixed seed (NFR-MUT-bounded).

Coverage is read through an injected ``coverage_fn`` (payload → file→lines map): offline
a fake supplies it; live it sends the request and reads the grey-box coverage source.
With no ``coverage_fn`` the objective is pure evasion.

With an optional ``metric_logger`` (a :class:`fuzzlab.core.store.MetricLogger`, B0 /
CC-MUT-0011), each search step's reward and novelty signal is additionally logged to
``metric_series`` (``source="mutation"``, ``key="reward"``/``"novelty"``) for
observability. This is purely a side-channel emission — it never feeds back into the
bandit/hill-climb selection logic itself.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Mapping

from fuzzlab.core.store import MetricLogger
from fuzzlab.greybox.coverage import CoverageFrontier
from fuzzlab.mutation.learn import Filter
from fuzzlab.mutation.operators import MutationOperator, default_operators
from fuzzlab.mutation.semantics import SemanticsValidator
from fuzzlab.scheduler.bandit import ThompsonBandit

CoverageFn = Callable[[str], Mapping[str, object]]


@dataclass
class SearchResult:
    variant: str
    operators: list[str] = field(default_factory=list)
    evaded: bool = False
    semantics_ok: bool = True
    novel_lines: int = 0
    steps: int = 0

    def _key(self) -> tuple:
        # better = evading-and-preserving first, then more novelty, then shorter chain
        return (self.evaded and self.semantics_ok, self.novel_lines, -len(self.operators))


def _reward(evaded: bool, preserving: bool, novel: int) -> float:
    if not preserving:
        return 0.0                       # a meaning-changing variant is useless
    r = 0.6 if evaded else 0.0
    if novel > 0:
        r += 0.4
    return r


class MutationSearch:
    def __init__(self, flt: Filter, *, validator: SemanticsValidator | None = None,
                 scheduler: ThompsonBandit | None = None,
                 coverage_fn: CoverageFn | None = None,
                 operators: list[MutationOperator] | None = None,
                 seed: int = 0, budget: int = 40,
                 metric_logger: "MetricLogger | None" = None):
        self.filter = flt
        self.validator = validator or SemanticsValidator()
        self.scheduler = scheduler or ThompsonBandit(rng=random.Random(seed))
        self.coverage_fn = coverage_fn
        self.operators = operators
        self.budget = budget
        self.frontier = CoverageFrontier()
        # B0 emitter (CC-MUT-0011, R-05): optional buffered writer for this search's
        # per-step reward/novelty signal into `metric_series` (source="mutation"). Purely
        # additive/observational — never consulted by the search/selection logic itself.
        self.metric_logger = metric_logger

    def _novelty(self, payload: str) -> int:
        if self.coverage_fn is None:
            return 0
        return self.frontier.observe(self.coverage_fn(payload))   # records + returns new

    def search(self, base: str, vuln_class: str = "sql-injection") -> SearchResult:
        ops = self.operators or default_operators(vuln_class)
        op_by_id = {op.id: op for op in ops}
        arms = list(op_by_id)
        ctx = vuln_class

        best = SearchResult(base, [], not self.filter.caught(base), True,
                            self._novelty(base), 0)
        current, chain = base, []
        for step in range(1, self.budget + 1):
            arm = self.scheduler.select(ctx, arms)
            op = op_by_id[arm]
            variants = op.apply(current)
            if not variants:
                self.scheduler.update(ctx, arm, 0.0)     # no-op operator here
                continue
            step_reward = 0.0
            step_novel = 0
            accepted = None
            for v in variants:
                evaded = not self.filter.caught(v)
                preserving = self.validator.preserves(base, v, vuln_class,
                                                      trusted=not op.surface)
                novel = self._novelty(v)
                step_reward = max(step_reward, _reward(evaded, preserving, novel))
                step_novel = max(step_novel, novel)
                cand = SearchResult(v, chain + [arm], evaded, preserving, novel, step)
                if cand._key() > best._key():
                    best = cand
                if preserving and (evaded or novel > 0) and accepted is None:
                    accepted = v                          # hill-climb toward this variant
            self.scheduler.update(ctx, arm, step_reward)
            if self.metric_logger is not None:
                self.metric_logger.log("reward", step, step_reward)
                self.metric_logger.log("novelty", step, float(step_novel))
            if accepted is not None:
                current, chain = accepted, chain + [arm]
            # pure-evasion objective: stop once we have a preserving bypass
            if self.coverage_fn is None and best.evaded and best.semantics_ok:
                best.steps = step
                break
        return best

    def search_pool(self, pool, vuln_class: str = "sql-injection",
                    sink_context: str | None = None) -> list["SearchResult"]:
        """Run the search over every seed payload a `PayloadPool` provides for the class.

        This is the consumer for the `register_payload_source` plugin hook: plugin-
        contributed payloads (plus the built-ins) become the bases the mutation engine
        evolves against the filter. Returns one result per seed.
        """
        return [self.search(seed, vuln_class)
                for seed in pool.payloads(vuln_class, sink_context)]
