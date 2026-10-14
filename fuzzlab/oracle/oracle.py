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
from fuzzlab.core.urls import to_path, to_route_path, url_key
from fuzzlab.oracle.probe import (PRG_UNOBSERVED, Candidate, Probe, Sender,
                                  UnplaceableLocation, Verdict, accepts_prg)
from fuzzlab.oracle.strategies import ConfirmationStrategy, default_strategies
from fuzzlab.scheduler.context import context_for

#: The mechanism of the inconclusive verdict a candidate gets when every applicable
#: mechanism refused its location (FR-FUZZ-47); a cost-capped one keeps its own name.
UNPLACEABLE = "unplaceable"


def finding_url(candidate: Candidate) -> str:
    """The path a finding is recorded at: `to_path`, except that a ``fragment`` point
    keeps its SPA hash route (`core.urls.to_route_path`, the function its endpoint is
    stored with; PA-0003), so DOM XSS on ``/#/search?q`` and ``/#/track-result?q`` are
    two findings, not one at ``/`` (forms phase 3, FR-FUZZ-47). For any URL without a
    hash route the two are identical, so ground-truth findings are unchanged."""
    if candidate.location == "fragment":
        return to_route_path(candidate.url)
    return to_path(candidate.url)


class _CostCounter:
    """Wrap a sender to count the probes one strategy makes (its cost, for the bandit)."""

    def __init__(self, inner: Sender):
        self._inner = inner
        self.count = 0

    @property
    def prg_capable(self) -> bool:
        return accepts_prg(self._inner)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        # the full `Sender` signature, forwarded exactly like `harness.auto`'s
        # `_CountingSender` (BUG-0071: a JSON-body / upload / XXE probe crashed `--bandit`)
        self.count += 1
        if prg:                          # FR-FUZZ-49: only ever asked of a capable inner
            probe = self._inner.send(url, param, value, timing=timing, method=method,
                                     location=location, content_type=content_type,
                                     entries=entries, prg=True)
        elif entries is not None:
            probe = self._inner.send(url, param, value, timing=timing, method=method,
                                     location=location, entries=entries)
        elif method == "GET" and location == "query":
            probe = self._inner.send(url, param, value, timing=timing)
        elif content_type:
            probe = self._inner.send(url, param, value, timing=timing,
                                     method=method, location=location,
                                     content_type=content_type)
        else:
            probe = self._inner.send(url, param, value, timing=timing,
                                     method=method, location=location)
        if isinstance(probe, Probe):
            self.count += probe.follow_up_sends     # a PRG follow-up is its cost too
        return probe


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

    @property
    def prg_capable(self) -> bool:
        return accepts_prg(self._inner)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
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
        if prg:
            # FR-FUZZ-49: the sender's PRG follow-up is a plain GET it builds itself, so
            # no sibling is ever bound into it (P3)
            return self._inner.send(url, param, value, timing=timing, method=method,
                                    location=location, content_type=content_type,
                                    entries=entries, prg=True)
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


#: The run's PRG counters (FR-FUZZ-49), reported in the pipeline's metrics when non-zero:
#: follow-ups after a POST-family probe, after a GET probe, follow-ups that gave no
#: observation (another redirect, a timeout), the benign restores sent (P9), and the
#: restores whose send raised (contained, reviewers A S1 / B must-fix 1).
PRG_COUNTERS = ("prg_follow_ups", "prg_follow_ups_get", "prg_unobserved", "prg_restores",
                "prg_restore_failed")


class _PrgRun:
    """One opt-in strategy's run on a candidate (FR-FUZZ-49, P1): **every** send of the
    run -- probes, controls, baselines, second samples -- asks the sender for a PRG
    observation, so a strategy compares like with like (BUG-0117). It sets the
    property; the sender does the follow-up. Counts what the sender did."""

    def __init__(self, inner: Sender, counts: dict[str, int]):
        self._inner = inner
        self._counts = counts

    @property
    def prg_capable(self) -> bool:
        return accepts_prg(self._inner)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        probe = self._inner.send(url, param, value, timing=timing, method=method,
                                 location=location, content_type=content_type,
                                 entries=entries, prg=True)
        if isinstance(probe, Probe) and probe.follow_up_sends:
            key = "prg_follow_ups_get" if method.upper() == "GET" else "prg_follow_ups"
            self._counts[key] += probe.follow_up_sends
            if probe.prg == PRG_UNOBSERVED:
                self._counts["prg_unobserved"] += 1
        return probe


def _restore_value(candidate: Candidate) -> str:
    """The benign value a PRG restore sends (P9): the form's own default for the field
    when it is a string, else the importer's text filler."""
    from fuzzlab.tools.store_adapter import LADDER_TEXT
    default = None
    if candidate.base_entries and candidate.location == jsonbody.LOCATION:
        path = jsonbody.parse_name(candidate.param)
        try:
            leaves = jsonbody.normalize_entries(candidate.base_entries)
        except jsonbody.JsonPlacementError:
            leaves = []
        default = next((v for p, v in leaves if tuple(p) == path), None)
    elif candidate.base_entries:
        default = FormEntries(tuple(e) for e in candidate.base_entries).get(
            candidate.param)
    return default if isinstance(default, str) and default else LADDER_TEXT


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
        #: FR-FUZZ-49: what PRG observation cost this oracle's run (`PRG_COUNTERS`)
        self.prg_counts: dict[str, int] = dict.fromkeys(PRG_COUNTERS, 0)

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
        counts = dict.fromkeys(PRG_COUNTERS, 0)
        try:
            outcome = self._confirm_outcome(candidate, sender, counts)
            if counts["prg_follow_ups"]:
                self._restore(candidate, sender, counts)
        finally:
            for key, n in counts.items():
                self.prg_counts[key] += n
        return outcome

    @staticmethod
    def _restore(candidate: Candidate, sender: Sender, counts: dict[str, int]) -> None:
        """P9 (FR-FUZZ-49), best effort: after a candidate's PRG run made a follow-up
        after a POST-family probe, one benign send of the form's own default (or the
        filler) at the point leaves the page without the last payload. Not for a raw
        whole body (it has no field default) or a header point; no PRG asked.

        Total (reviewers A S1 / B must-fix 1): the verdict is already decided (and a
        finding may be written), so a restore send that raises never changes it. The
        failure is a per-unit containment boundary (PA-0086): counted
        (``prg_restore_failed``) and logged with the host and the error's class only,
        never swallowed silently; ``BaseException`` (an interrupt) still propagates."""
        if candidate.content_type or candidate.location not in (
                "query", "body", jsonbody.LOCATION):
            return
        try:
            ConfirmationStrategy._send(sender, candidate, _restore_value(candidate))
        except Exception as exc:                     # noqa: BLE001 - containment boundary
            counts["prg_restore_failed"] += 1
            from urllib.parse import urlsplit

            from fuzzlab.core.obs import get_logger
            get_logger("oracle").warning(
                "post/redirect/get restore failed",
                extra={"host": urlsplit(candidate.url).hostname or "",
                       "error": type(exc).__name__})
            return
        counts["prg_restores"] += 1

    def _confirm_outcome(self, candidate: Candidate, sender: Sender,
                         counts: dict[str, int]) -> tuple[Verdict | None, Verdict | None]:
        prg_ok = accepts_prg(sender)
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
            # FR-FUZZ-49 (P1): PRG observation is a property of an opt-in strategy's
            # whole run, set here once, never per send by the strategy
            opted = getattr(strategy, "prg", False) is True   # a plugin may lack it
            run = _PrgRun(sender, counts) if opted and prg_ok else sender
            try:
                if self.scheduler is not None:
                    probe = _CostCounter(run)            # measure this mechanism's cost
                    verdict = strategy.confirm(candidate, probe)
                else:
                    verdict = strategy.confirm(candidate, run)
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
                        "vuln_class": verdict.vuln_class, "url": finding_url(candidate),
                        "method": candidate.method, "param": candidate.param,
                        "mechanism": verdict.mechanism})
                return verdict, None
        if not placed and unplaceable is not None:
            # no mechanism could place it: unlabelled, never a negative (PA-0108)
            return None, Verdict(False, candidate.vuln_class or "", UNPLACEABLE,
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
             json.dumps(verdict.evidence), finding_url(candidate), candidate.method,
             candidate.param),
        )
        self.store.conn.commit()
