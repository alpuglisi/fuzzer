"""The oracle: run applicable confirmation strategies; the sole finding-writer.

Given a candidate and a sender, the oracle tries each applicable
`ConfirmationStrategy` (cheapest/strongest first) and returns the first positive,
reproducible `Verdict` — writing a `finding` row when a store is attached. It never
guesses (fail-closed) and is the *only* component that writes `finding` labels; ML
writes scores/uncertainty, never labels (oracle/advisory split).
"""

from __future__ import annotations

import json

from fuzzlab.core import jsonbody
from fuzzlab.core.forms import FormEntries
from fuzzlab.core.urls import to_path, url_key
from fuzzlab.oracle.probe import Candidate, Sender, UnplaceableLocation, Verdict
from fuzzlab.oracle.strategies import ConfirmationStrategy, default_strategies
from fuzzlab.scheduler.context import context_for


class _CostCounter:
    """Wrap a sender to count the probes one strategy makes (its cost, for the bandit)."""

    def __init__(self, inner: Sender):
        self._inner = inner
        self.count = 0

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None):
        # the full `Sender` signature, forwarded exactly like `harness.auto`'s
        # `_CountingSender` (BUG-0071: a JSON-body / upload / XXE probe crashed `--bandit`)
        self.count += 1
        if entries is not None:
            return self._inner.send(url, param, value, timing=timing, method=method,
                                    location=location, entries=entries)
        if method == "GET" and location == "query":
            return self._inner.send(url, param, value, timing=timing)
        if content_type:
            return self._inner.send(url, param, value, timing=timing,
                                    method=method, location=location,
                                    content_type=content_type)
        return self._inner.send(url, param, value, timing=timing,
                                method=method, location=location)


class _FormBoundSender:
    """Sends a form point's sibling fields with every probe of it (forms phase 1).

    A send to the candidate's own URL (``url_key``), method and query/body location
    goes out as the form's full entry list with ``param`` set to ``value``; any other
    send (a stored-XSS observe page, another URL) passes through unchanged. The one
    place sibling fields are bound, so no strategy changes (reviewers A/B).

    A ``json`` point (forms phase 3, FR-FUZZ-47) is bound the same way: its siblings
    are the body's other leaves (paths and typed values, already redacted and made
    neutral by the point builder) and ``param`` names the leaf set to ``value``. A
    malformed JSON entry list or leaf name is refused (`UnplaceableLocation`), never
    sent as a bare field."""

    def __init__(self, inner: Sender, candidate: Candidate):
        self._inner = inner
        self._key = (url_key(candidate.url), candidate.method.upper(), candidate.location)
        self._base = self._json_base = None
        if candidate.location == jsonbody.LOCATION:
            try:
                self._json_base = jsonbody.normalize_entries(candidate.base_entries)
            except jsonbody.JsonPlacementError:
                self._json_base = None           # every own send is then refused
        else:
            self._base = FormEntries(tuple(e) for e in candidate.base_entries)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None):
        own = (entries is None and not content_type
               and (url_key(url), method.upper(), location) == self._key)
        if own and location == jsonbody.LOCATION:
            try:
                if self._json_base is None:
                    raise jsonbody.JsonPlacementError("malformed JSON entry list")
                entries = jsonbody.replace_leaf(self._json_base, param, value)
            except jsonbody.JsonPlacementError as exc:
                raise UnplaceableLocation(f"cannot place JSON leaf {param!r}: {exc}") \
                    from exc
        elif own and location in ("query", "body"):
            entries = self._base.replace(param, value)
        if entries is not None:
            return self._inner.send(url, param, value, timing=timing, method=method,
                                    location=location, entries=entries)
        if content_type:
            return self._inner.send(url, param, value, timing=timing, method=method,
                                    location=location, content_type=content_type)
        if method == "GET" and location == "query":
            return self._inner.send(url, param, value, timing=timing)
        return self._inner.send(url, param, value, timing=timing, method=method,
                                location=location)


class Oracle:
    def __init__(self, strategies: list[ConfirmationStrategy] | None = None,
                 store=None, run_id: int | None = None, browser=None, oob=None,
                 coverage=None, dbfault=None,
                 scheduler=None, plugins=None):
        self.strategies = (list(strategies) if strategies is not None
                           else default_strategies(browser=browser, oob=oob,
                                                   coverage=coverage, dbfault=dbfault))
        if plugins is not None:                          # register_oracle: plugin-supplied
            self.strategies += list(plugins.oracles())   # confirmers (the only writer path)
        self.plugins = plugins
        self.store = store
        self.run_id = run_id
        # Optional bandit that orders the applicable mechanisms per context (Phase 4
        # T4.3): the productive mechanism is tried first, so a confirmation short-
        # circuits the expensive ones (fewer probes). None -> fixed cheapest-first order.
        self.scheduler = scheduler

    def confirm(self, candidate: Candidate, sender: Sender) -> Verdict | None:
        """The confirming verdict, or None (greybox and other callers)."""
        return self.confirm_outcome(candidate, sender)[0]

    def confirm_outcome(self, candidate: Candidate,
                        sender: Sender) -> tuple[Verdict | None, Verdict | None]:
        """(confirming verdict or None, inconclusive verdict or None).

        A strategy that started a check but could not decide within its cost cap
        returns ``Verdict(confirmed=False, inconclusive=True)`` (FR-FUZZ-45). It is
        reported only when nothing confirms; any other non-confirming verdict is
        ignored, as before. Under a scheduler an inconclusive arm gets reward 0 and
        its real cost."""
        if candidate.base_entries:                       # a form point: send its siblings
            sender = _FormBoundSender(sender, candidate)
        applicable = [s for s in self.strategies if s.applies(candidate)]
        if self.scheduler is not None and applicable:
            ctx = context_for(candidate.category or candidate.vuln_class,
                              candidate.location, candidate.sink_context)
            by_arm = {s.arm: s for s in applicable}
            ordered = [by_arm[a] for a in self.scheduler.order(ctx, list(by_arm))]
        else:
            ctx, ordered = None, applicable

        inconclusive: Verdict | None = None
        placed, unplaceable = False, None
        for strategy in ordered:
            try:
                if self.scheduler is not None:
                    probe = _CostCounter(sender)         # measure this mechanism's cost
                    verdict = strategy.confirm(candidate, probe)
                else:
                    verdict = strategy.confirm(candidate, sender)
            except UnplaceableLocation as exc:
                # this mechanism cannot place the point (PA-0115): no verdict from it,
                # and no reward or cost for its arm; the others still run
                unplaceable = unplaceable or str(exc)
                continue
            placed = True
            confirmed = verdict is not None and verdict.confirmed
            if (not confirmed and verdict is not None and verdict.inconclusive
                    and inconclusive is None):
                inconclusive = verdict
            if self.scheduler is not None:               # reward+cost only the tried arms
                self.scheduler.update(ctx, strategy.arm, 1.0 if confirmed else 0.0,
                                      cost=max(1, probe.count))
            if confirmed:
                self._write_finding(candidate, verdict)
                if self.plugins is not None:             # on_finding: observe (never writes)
                    self.plugins.on_finding({
                        "vuln_class": verdict.vuln_class, "url": to_path(candidate.url),
                        "method": candidate.method, "param": candidate.param,
                        "mechanism": verdict.mechanism})
                return verdict, None
        if not placed and unplaceable is not None:
            # no mechanism could place it: unlabelled, never a negative (PA-0108)
            return None, Verdict(False, candidate.vuln_class or "", "unplaceable",
                                 {"unplaceable": candidate.location,
                                  "reason": unplaceable[:200]}, inconclusive=True)
        return None, inconclusive

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
