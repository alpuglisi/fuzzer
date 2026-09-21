"""The oracle: run applicable confirmation strategies; the sole finding-writer.

Given a candidate and a sender, the oracle tries each applicable
`ConfirmationStrategy` (cheapest/strongest first) and returns the first positive,
reproducible `Verdict` — writing a `finding` row when a store is attached. It never
guesses (fail-closed) and is the *only* component that writes `finding` labels; ML
writes scores/uncertainty, never labels (oracle/advisory split).
"""

from __future__ import annotations

import json

from fuzzlab.core.urls import to_path
from fuzzlab.oracle.probe import Candidate, Sender, Verdict
from fuzzlab.oracle.strategies import ConfirmationStrategy, default_strategies
from fuzzlab.scheduler.context import context_for


class _CostCounter:
    """Wrap a sender to count the probes one strategy makes (its cost, for the bandit)."""

    def __init__(self, inner: Sender):
        self._inner = inner
        self.count = 0

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query"):
        self.count += 1
        if method == "GET" and location == "query":
            return self._inner.send(url, param, value, timing=timing)
        return self._inner.send(url, param, value, timing=timing,
                                method=method, location=location)


class Oracle:
    def __init__(self, strategies: list[ConfirmationStrategy] | None = None,
                 store=None, run_id: int | None = None, browser=None, scheduler=None):
        self.strategies = (list(strategies) if strategies is not None
                           else default_strategies(browser=browser))
        self.store = store
        self.run_id = run_id
        # Optional bandit that orders the applicable mechanisms per context (Phase 4
        # T4.3): the productive mechanism is tried first, so a confirmation short-
        # circuits the expensive ones (fewer probes). None -> fixed cheapest-first order.
        self.scheduler = scheduler

    def confirm(self, candidate: Candidate, sender: Sender) -> Verdict | None:
        applicable = [s for s in self.strategies if s.applies(candidate)]
        if self.scheduler is not None and applicable:
            ctx = context_for(candidate.category or candidate.vuln_class,
                              candidate.location, candidate.sink_context)
            by_arm = {s.arm: s for s in applicable}
            ordered = [by_arm[a] for a in self.scheduler.order(ctx, list(by_arm))]
        else:
            ctx, ordered = None, applicable

        for strategy in ordered:
            if self.scheduler is not None:
                probe = _CostCounter(sender)             # measure this mechanism's cost
                verdict = strategy.confirm(candidate, probe)
            else:
                verdict = strategy.confirm(candidate, sender)
            confirmed = verdict is not None and verdict.confirmed
            if self.scheduler is not None:               # reward+cost only the tried arms
                self.scheduler.update(ctx, strategy.arm, 1.0 if confirmed else 0.0,
                                      cost=max(1, probe.count))
            if confirmed:
                self._write_finding(candidate, verdict)
                return verdict
        return None

    def _write_finding(self, candidate: Candidate, verdict: Verdict) -> None:
        if self.store is None or self.run_id is None:
            return
        self.store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (self.run_id, verdict.vuln_class, 1, verdict.mechanism,
             json.dumps(verdict.evidence), to_path(candidate.url), candidate.method,
             candidate.param),
        )
        self.store.conn.commit()
