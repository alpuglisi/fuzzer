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


class Oracle:
    def __init__(self, strategies: list[ConfirmationStrategy] | None = None,
                 store=None, run_id: int | None = None):
        self.strategies = list(strategies) if strategies is not None else default_strategies()
        self.store = store
        self.run_id = run_id

    def confirm(self, candidate: Candidate, sender: Sender) -> Verdict | None:
        for strategy in self.strategies:
            if not strategy.applies(candidate):
                continue
            verdict = strategy.confirm(candidate, sender)
            if verdict is not None and verdict.confirmed:
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
