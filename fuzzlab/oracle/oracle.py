"""The oracle: run applicable confirmation strategies; the sole finding-writer.

Given a candidate and a sender, the oracle tries each applicable
`ConfirmationStrategy` (cheapest/strongest first) and returns the first positive,
reproducible `Verdict` — writing a `finding` row when a store is attached. It never
guesses (fail-closed) and is the *only* component that writes `finding` labels; ML
writes scores/uncertainty, never labels (oracle/advisory split).
"""

from __future__ import annotations

import json

from fuzzlab.core import jsonbody, trace
from fuzzlab.core.forms import FormEntries
from fuzzlab.core.urls import to_path, to_route_path, url_key
from fuzzlab.oracle.probe import (PRG_UNOBSERVED, Candidate, NotComparable,
                                  PrerequisiteUnavailable, Probe, ProbeUnobserved, Sender,
                                  UnplaceableLocation, Verdict, accepts_fetch,
                                  accepts_prg, require_observed)
from fuzzlab.oracle.strategies import ConfirmationStrategy, default_strategies
from fuzzlab.scheduler.context import context_for

#: The mechanism of the inconclusive verdict a candidate gets when every applicable
#: mechanism refused its location (FR-FUZZ-47); a cost-capped one keeps its own name.
UNPLACEABLE = "unplaceable"
#: The mechanism of the inconclusive verdict a candidate gets when a probe got no
#: response (`ProbeUnobserved`, BUG-0147) and nothing confirmed it.
UNOBSERVED = "unobserved"
#: ... and when a response a mechanism needed was not the application's own answer
#: (`NotComparable`, FR-FUZZ-63, BUG-0529): a throttled probe, a control or baseline
#: that was not comparable, a follow-up that got no observation. Its reason travels under
#: ``evidence["unobserved"]`` like `UNOBSERVED`'s.
NOT_COMPARABLE = "not-comparable"
#: ... and when the request's prerequisites could not be rebuilt (FR-FUZZ-67, BUG-0544):
#: a fresh form value could not be fetched and bound, or a sibling may never be sent. Its
#: reason travels under ``evidence["reason"]`` like `UNPLACEABLE`'s; nothing was sent.
UNBOUND = "unbound"


def finding_url(candidate: Candidate) -> str:
    """The path a finding is recorded at: `to_path`, except that a ``fragment`` point
    keeps its SPA hash route (`core.urls.to_route_path`, the function its endpoint is
    stored with; PA-0003), so DOM XSS on ``/#/search?q`` and ``/#/track-result?q`` are
    two findings, not one at ``/`` (forms phase 3, FR-FUZZ-47). For any URL without a
    hash route the two are identical, so ground-truth findings are unchanged."""
    if candidate.location == "fragment":
        return to_route_path(candidate.url)
    return to_path(candidate.url)


def _decides(strategy, candidate: Candidate) -> bool:
    """Does ``strategy`` decide ``candidate`` (FR-AUD-30, BUG-0523)? Every strategy
    decides a candidate that names no deciding mechanism; one that names it is decided
    only by the strategy with that arm. A strategy with no ``arm`` (a duck-typed plugin
    confirmer) decides no candidate that names one. The one predicate (PA-0003): read
    with ``getattr``, as the oracle reads ``prg`` and ``arm``."""
    return candidate.decided_by is None or \
        getattr(strategy, "arm", None) == candidate.decided_by


def _trace_strategy(outcome: str, verdict: Verdict | None = None,
                    detail: str | None = None, decides: bool = True) -> None:
    """FR-FUZZ-60: one strategy run's outcome, with the exchanges it made and (FR-FUZZ-62)
    the browser and out-of-band steps it recorded. A run that does not confirm is
    ``not_confirmed`` -- never "secure". ``decides`` (BUG-0523): whether this run decides
    the candidate (`_decides`); a confirmation always counts, so it is recorded true on
    one."""
    test, strategy, _role = trace.current()
    trace.emit("test.strategy", {
        "test": test, "strategy": strategy, "outcome": outcome,
        "mechanism": verdict.mechanism if verdict is not None else None,
        "detail": detail, "exchanges": trace.collected(),
        "steps": trace.collected_steps(),                 # FR-FUZZ-62
        "decides": decides or outcome == "confirmed"},     # BUG-0523
        scope=f"test:{test}" if test else "run")


class _CostCounter:
    """Wrap a sender to count the probes one strategy makes (its cost, for the bandit)."""

    def __init__(self, inner: Sender):
        self._inner = inner
        self.count = 0

    @property
    def prg_capable(self) -> bool:
        return accepts_prg(self._inner)

    @property
    def fetch_capable(self) -> bool:
        return accepts_fetch(self._inner)

    def fetch(self, url, *, route_url):
        self.count += 1                         # a binder's page fetch is its cost too
        return self._inner.fetch(url, route_url=route_url)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        # the full `Sender` signature, forwarded exactly like `harness.auto`'s
        # `_CountingSender` (BUG-0071: a JSON-body / upload / XXE probe crashed `--bandit`)
        self.count += 1
        try:
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
        except ProbeUnobserved as exc:
            self.count += exc.resent                # re-sent before giving up (BUG-0147)
            raise
        if isinstance(probe, Probe):
            self.count += probe.follow_up_sends     # a PRG follow-up or re-send is its cost too
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
    sent as a bare field.

    **Fresh bindings (FR-FUZZ-67, BUG-0544).** A stored entry list is evidence, not a
    replay template: an entry whose stored value is a placeholder (a CSRF token or an
    identifier blanked by redaction; ``candidate.bindings["fresh"]``) is never sent as
    stored. Before each own send the binder fetches the context's page
    (``bindings["page"]``) through the sender's ``fetch``, on the probe's own session
    route, finds the request template that page offers now
    (`core.forms.page_template_entries`) and binds those entries' current values into
    that one send, in memory only (D12). When it cannot (no page, a sender that cannot
    fetch, no answer, a non-2xx or lost-session answer, no matching form or link, a
    captured JSON body, a fresh value naming a host outside the lab) it raises
    `PrerequisiteUnavailable` and remembers why: nothing is sent, and a candidate no
    mechanism could send is inconclusive with that reason, never a negative."""

    def __init__(self, inner: Sender, candidate: Candidate):
        self._inner = inner
        self._key = (url_key(candidate.url), candidate.method.upper(), candidate.location)
        self._url = candidate.url
        self._base = self._json_base = None
        if candidate.location == jsonbody.LOCATION:
            try:
                self._json_base = jsonbody.normalize_entries(candidate.base_entries)
            except jsonbody.JsonPlacementError:
                self._json_base = None           # every own send is then refused
        else:
            self._base = FormEntries(tuple(e) for e in candidate.base_entries)
        bindings = candidate.bindings if isinstance(candidate.bindings, dict) else {}
        self._fresh = frozenset(n for n in (bindings.get("fresh") or ())
                                if isinstance(n, str))
        self._page = bindings.get("page") if isinstance(bindings.get("page"), str) else None
        self._unbound: str | None = None         # why a fresh binding failed (kept)

    @property
    def prg_capable(self) -> bool:
        return accepts_prg(self._inner)

    @property
    def fetch_capable(self) -> bool:
        return accepts_fetch(self._inner)

    def fetch(self, url, *, route_url):
        return self._inner.fetch(url, route_url=route_url)

    def _fresh_base(self):
        """``(the base entries for one send, the fetch's carry token)``: each fresh entry
        bound to the value the context's page offers now (FR-FUZZ-67). Raises
        `PrerequisiteUnavailable`, and keeps the reason for every later send."""
        if self._unbound is not None:
            raise PrerequisiteUnavailable(self._unbound)
        try:
            return self._bind_fresh()
        except PrerequisiteUnavailable as exc:
            self._unbound = str(exc)
            raise

    def _bind_fresh(self):
        from fuzzlab.audit.value_shape import names_outside_lab
        from fuzzlab.core.forms import page_template_entries
        from fuzzlab.core.redaction import page_url_is_clean
        from fuzzlab.core.urls import DestructiveUrlRefused, canonical_origin
        what = "fresh " + ", ".join(sorted(self._fresh))
        if self._base is None:
            raise PrerequisiteUnavailable(f"{what}: a captured JSON body has no page to "
                                          "bind them from")
        if not self._page:
            raise PrerequisiteUnavailable(f"{what}: no page to fetch them from")
        if not page_url_is_clean(self._page):
            # never a placeholder on the wire (PA-0100, D12; BUG-0544 review B1)
            raise PrerequisiteUnavailable(f"{what}: their page's URL carries a redacted "
                                          "value")
        try:
            same_origin = canonical_origin(self._page) == canonical_origin(self._url)
        except ValueError:
            same_origin = False
        if not same_origin:
            # a value fetched on another origin is another session's (SP-13, SP-16)
            raise PrerequisiteUnavailable(f"{what}: their page is on another origin than "
                                          "the request")
        if not accepts_fetch(self._inner):
            raise PrerequisiteUnavailable(f"{what}: the sender cannot fetch their page")
        try:
            with trace.role("bind"):
                page = self._inner.fetch(self._page, route_url=self._url)
        except ProbeUnobserved as exc:
            raise PrerequisiteUnavailable(f"{what}: their page got no response") from exc
        except DestructiveUrlRefused as exc:     # the send gate refuses the page itself
            raise PrerequisiteUnavailable(f"{what}: their page is refused by the send "
                                          "gate") from exc
        status = getattr(page, "status", 0) or 0
        if getattr(page, "session_lost", False) is True or not 200 <= status < 300:
            raise PrerequisiteUnavailable(f"{what}: their page answered {status}"
                                          + (" on a lost session"
                                             if getattr(page, "session_lost", False) is True
                                             else ""))
        note = getattr(page, "session", None)
        if isinstance(note, str) and note:
            # fetched without the session the probe carries (FR-SESS-20): its value is
            # not the probe's
            raise PrerequisiteUnavailable(f"{what}: their page was fetched without the "
                                          f"probe's session ({note})")
        method, location = self._key[1], self._key[2]
        template = page_template_entries(page.text or "", self._page, self._url, method,
                                         location, self._base)
        if template is None:
            raise PrerequisiteUnavailable(f"{what}: their page offers no matching form or "
                                          "link")
        bound = []
        for (name, value), (_n, now) in zip(self._base, template):
            if name in self._fresh:
                if names_outside_lab(now):
                    raise PrerequisiteUnavailable(f"{what}: {name!r} names a host outside "
                                                  "the lab (FR-AUD-20)")
                value = now
            bound.append((name, value))
        return FormEntries(bound), getattr(page, "carry", None)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        own = (entries is None and not content_type
               and (url_key(url), method.upper(), location) == self._key)
        base, carry = self._base, None
        if self._fresh and (url_key(url), method.upper()) == self._key[:2]:
            # FR-FUZZ-67 (BUG-0544 review B4): every send to the candidate's own request
            # carries the fresh values, or is never made -- a raw or JSON body, entries a
            # strategy built itself, another location: refused, whatever its shape
            if not (own and location in ("query", "body")):
                raise PrerequisiteUnavailable(
                    self._unbound or "fresh " + ", ".join(sorted(self._fresh))
                    + f": a {location} send of its own entries cannot carry them")
            base, carry = self._fresh_base()     # before each own send
        if own and location == jsonbody.LOCATION:
            try:
                if self._json_base is None:
                    raise jsonbody.JsonPlacementError("malformed JSON entry list")
                entries = jsonbody.replace_leaf(self._json_base, param, value)
            except jsonbody.JsonPlacementError as exc:
                raise UnplaceableLocation(f"cannot place JSON leaf {param!r}: {exc}") \
                    from exc
        elif own and location in ("query", "body"):
            entries = base.replace(param, value)
            if carry is not None:
                # what the fetch left for this one send: the page's cookies
                # (`RequestsProbeSender`), or the route it went out on, which the send
                # must take too (the seam; BUG-0544 review R2-2)
                entries.carry = carry
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

    @property
    def fetch_capable(self) -> bool:
        return accepts_fetch(self._inner)

    def fetch(self, url, *, route_url):
        return self._inner.fetch(url, route_url=route_url)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        probe = self._inner.send(url, param, value, timing=timing, method=method,
                                 location=location, content_type=content_type,
                                 entries=entries, prg=True)
        if isinstance(probe, Probe) and probe.prg_sends:
            key = "prg_follow_ups_get" if method.upper() == "GET" else "prg_follow_ups"
            self._counts[key] += probe.prg_sends
            if probe.prg == PRG_UNOBSERVED:
                self._counts["prg_unobserved"] += 1
        return probe


#: The `Sender.send` keyword defaults: `_SessionNotes` forwards only what differs, so
#: an inner sender is called exactly as a strategy would call it directly.
_SEND_DEFAULTS = (("timing", False), ("method", "GET"), ("location", "query"),
                  ("content_type", None), ("entries", None), ("prg", False))


class _SessionNotes:
    """Watches one strategy run's probes for a session note (FR-SESS-20, O2): a probe
    the sender sent without the run's session because its origin is not one of the
    session's (``Probe.session``). The oracle stamps it on the verdict's
    ``evidence["session"]``, so a confirmation (or an inconclusive result) made without
    the session says so."""

    def __init__(self, inner: Sender):
        self._inner = inner
        self.notes: set[str] = set()

    @property
    def prg_capable(self) -> bool:
        return accepts_prg(self._inner)

    def __getattr__(self, name):
        """Transparent for the rest of the sender's surface (a strategy probes it with
        ``getattr``); a correlated send (M10) is watched for the note too."""
        if name == "_inner":
            raise AttributeError(name)
        attr = getattr(self._inner, name)
        if name != "send_correlated" or not callable(attr):
            return attr

        def send_correlated(*args, **kwargs):
            probe, request_id = attr(*args, **kwargs)
            self._note(probe)
            return probe, request_id
        return send_correlated

    def _note(self, probe) -> None:
        note = getattr(probe, "session", None)
        if isinstance(note, str) and note:
            self.notes.add(note)

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        given = dict(timing=timing, method=method, location=location,
                     content_type=content_type, entries=entries, prg=prg)
        kwargs = {k: given[k] for k, default in _SEND_DEFAULTS if given[k] != default}
        probe = self._inner.send(url, param, value, **kwargs)
        self._note(probe)
        return probe


class _ObservedOnly:
    """Layer 1 of FR-FUZZ-63 (SP-56): every response a strategy reads is an observation
    of the application at all (`require_observed`) -- a throttled or unavailable answer,
    or a stand-in for no response on a non-timing send (on a timing send, anything but a
    read timeout, M7), ends the mechanism with `NotComparable` before the strategy reads
    it. The correlated send (M10's ``send_correlated``) is read the same way.

    It also counts a payload send whose PRG follow-up got no observation
    (`PRG_UNOBSERVED`, M4 as narrowed by B2): the strategy keeps reading the probe's own
    response (FR-FUZZ-50) and its other payloads still run; a run that then ends with no
    verdict is not comparable (`Oracle._confirm_outcome`), never a negative. A compared
    send (`ConfirmationStrategy._compared`, the ``control`` and ``baseline`` roles) is not
    counted: whether its follow-up was needed is its strategy's "observed alike" check.
    Forwards like `_SessionNotes`: only what differs from the protocol's defaults."""

    def __init__(self, inner: Sender):
        self._inner = inner
        self.unobserved_follow_ups = 0

    @property
    def prg_capable(self) -> bool:
        return accepts_prg(self._inner)

    def __getattr__(self, name):
        if name == "_inner":
            raise AttributeError(name)
        attr = getattr(self._inner, name)
        if name != "send_correlated" or not callable(attr):
            return attr

        def send_correlated(*args, **kwargs):
            probe, request_id = attr(*args, **kwargs)
            require_observed(probe)
            return probe, request_id
        return send_correlated

    def send(self, url, param, value, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None, entries=None, prg: bool = False):
        given = dict(timing=timing, method=method, location=location,
                     content_type=content_type, entries=entries, prg=prg)
        kwargs = {k: given[k] for k, default in _SEND_DEFAULTS if given[k] != default}
        probe = self._inner.send(url, param, value, **kwargs)
        require_observed(probe, timing=timing)
        if not timing and getattr(probe, "prg", None) == PRG_UNOBSERVED \
                and trace.current()[2] not in _COMPARED_ROLES:
            self.unobserved_follow_ups += 1
        return probe


#: The trace roles of a compared send (`ConfirmationStrategy._compared`; FR-FUZZ-60).
_COMPARED_ROLES = ("control", "baseline")


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
                 scheduler=None, plugins=None, peer=None):
        self.strategies = (list(strategies) if strategies is not None
                           else default_strategies(browser=browser, oob=oob,
                                                   coverage=coverage, dbfault=dbfault,
                                                   peer=peer))
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
        ignored, as before. A mechanism whose probe got no response
        (`ProbeUnobserved`, BUG-0147) gives no verdict; with no confirmation the result is
        inconclusive (``unobserved``). Under a scheduler an inconclusive arm gets reward 0
        and its real cost.

        A candidate whose request can never be rebuilt (``replay_refusal``, FR-FUZZ-67)
        is inconclusive (`UNBOUND`) with that reason before any strategy runs: nothing
        is sent, by any mechanism, the browser's included."""
        refusal = candidate.replay_refusal
        fresh = (candidate.bindings or {}).get("fresh") \
            if isinstance(candidate.bindings, dict) else None
        if not refusal and fresh and candidate.location == jsonbody.LOCATION:
            # no page holds a captured JSON body's leaves: nothing can bind them, so no
            # mechanism -- whatever it sends -- may run (BUG-0544 review B4)
            refusal = (f"fresh {', '.join(sorted(map(str, fresh)))}: a captured JSON body "
                       "has no page to bind them from")
        if refusal:
            return None, Verdict(False, candidate.vuln_class or "", UNBOUND,
                                 {"unbound": candidate.location,
                                  "reason": str(refusal)[:200]},
                                 inconclusive=True)
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
            with trace.role("restore"):
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
        unbound: str | None = None              # FR-FUZZ-67: why prerequisites failed
        # FR-AUD-30 (BUG-0523): a candidate naming its deciding mechanism is placed only
        # by that mechanism; its own refusal is the reason given, and its absence is one
        decider_reason: str | None = None
        missing = (f"deciding mechanism {candidate.decided_by} did not run"
                   if candidate.decided_by is not None and not any(
                       getattr(s, "arm", None) == candidate.decided_by for s in ordered)
                   else None)
        for strategy in ordered:
            # the sends of this strategy run, and its verdict, are one scope of the
            # trace (FR-FUZZ-60): explicit, never inferred from timestamps
            with trace.strategy_scope(getattr(strategy, "arm",
                                              type(strategy).__name__)):
                # FR-FUZZ-49 (P1): PRG observation is a property of an opt-in strategy's
                # whole run, set here once, never per send by the strategy
                opted = getattr(strategy, "prg", False) is True   # a plugin may lack it
                run = _PrgRun(sender, counts) if opted and prg_ok else sender
                observed = _ObservedOnly(run)                # FR-FUZZ-63 (layer 1)
                notes = _SessionNotes(observed)              # FR-SESS-20 (O2)
                try:
                    if self.scheduler is not None:
                        probe = _CostCounter(notes)          # measure this mechanism's cost
                        verdict = strategy.confirm(candidate, probe)
                    else:
                        verdict = strategy.confirm(candidate, notes)
                    if observed.unobserved_follow_ups and not (
                            verdict is not None and (verdict.confirmed
                                                     or verdict.inconclusive)):
                        # M4: a follow-up got no observation and nothing decided: the run
                        # read only what it could, so it is no negative (FR-FUZZ-63)
                        raise NotComparable("not comparable: a probe's follow-up got no "
                                            "observation")
                except UnplaceableLocation as exc:
                    # this mechanism cannot place the point (PA-0115): no verdict from it,
                    # and no reward or cost for its arm; the others still run. A request
                    # whose prerequisites could not be rebuilt (FR-FUZZ-67) likewise
                    if isinstance(exc, PrerequisiteUnavailable):
                        unbound = unbound or str(exc)
                    unplaceable = unplaceable or str(exc)
                    if candidate.decided_by is not None and _decides(strategy, candidate):
                        decider_reason = decider_reason or str(exc)
                    _trace_strategy("unplaceable", detail=str(exc)[:120],
                                    decides=_decides(strategy, candidate))
                    continue
                except ProbeUnobserved as exc:
                    # a probe got no response (BUG-0147, PA-0137(1), PA-0153): no verdict
                    # from this mechanism, never a negative, and the others still run.
                    # The unit is the mechanism, not the probe (a recorded deviation from
                    # PA-0137(4)): an HTTP strategy cannot tell a stand-in probe from a
                    # real one, so continuing could confirm on a response that never came.
                    # The sender has already retried an idempotent probe once. Reward 0 and
                    # the probes it sent, as for any inconclusive arm. Logged with the host
                    # and the error class only.
                    placed = placed or _decides(strategy, candidate)
                    comparable = isinstance(exc, NotComparable)      # FR-FUZZ-63
                    if self.scheduler is not None:
                        if comparable:
                            # the mechanism could not judge: charge its probes, never
                            # move its success estimate (A7)
                            charge = getattr(self.scheduler, "charge", None)
                            if charge is not None:
                                charge(ctx, strategy.arm, cost=max(1, probe.count))
                        else:
                            self.scheduler.update(ctx, strategy.arm, 0.0,
                                                  cost=max(1, probe.count))
                    if inconclusive is None:
                        inconclusive = Verdict(False, candidate.vuln_class or "",
                                               NOT_COMPARABLE if comparable else UNOBSERVED,
                                               {"unobserved": str(exc)[:200],
                                                "mechanism": getattr(strategy, "arm",
                                                                     type(strategy).__name__)},
                                               inconclusive=True)
                    from urllib.parse import urlsplit

                    from fuzzlab.core.obs import get_logger
                    if comparable:
                        get_logger("oracle").warning(
                            "response not comparable",
                            extra={"host": urlsplit(candidate.url).hostname or "",
                                   "error": getattr(exc, "response_class", None)
                                   or "follow-up"})
                    else:
                        get_logger("oracle").warning(
                            "probe got no response",
                            extra={"host": urlsplit(candidate.url).hostname or "",
                                   "error": type(exc.__cause__ or exc).__name__})
                    _trace_strategy("unobserved",
                                    detail=(str(exc)[:120] if comparable
                                            else type(exc.__cause__ or exc).__name__),
                                    decides=_decides(strategy, candidate))
                    continue
                placed = placed or _decides(strategy, candidate)
                if verdict is not None and notes.notes:
                    # the probes went without the run's session (FR-SESS-20, O2)
                    verdict.evidence["session"] = "; ".join(sorted(notes.notes))
                confirmed = verdict is not None and verdict.confirmed
                if (not confirmed and verdict is not None and verdict.inconclusive
                        and inconclusive is None):
                    inconclusive = verdict
                _trace_strategy("confirmed" if confirmed else
                                "inconclusive" if verdict is not None
                                and verdict.inconclusive else "not_confirmed", verdict,
                                decides=_decides(strategy, candidate))
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

        if not placed and unbound is not None and decider_reason in (None, unbound):
            # no mechanism could rebuild the request (FR-FUZZ-67): unlabelled, never a
            # negative, with the reason; nothing was sent at the candidate
            return None, Verdict(False, candidate.vuln_class or "", UNBOUND,
                                 {"unbound": candidate.location,
                                  "reason": unbound[:200]}, inconclusive=True)
        if not placed and (unplaceable is not None or missing is not None):
            # no deciding mechanism could place it: unlabelled, never a negative
            # (FR-FUZZ-47; BUG-0523: the decider's own reason first)
            reason = decider_reason or missing or unplaceable or ""
            return None, Verdict(False, candidate.vuln_class or "", UNPLACEABLE,
                                 {"unplaceable": candidate.location,
                                  "reason": reason[:200]}, inconclusive=True)
        return None, inconclusive

    def _write_finding(self, candidate: Candidate, verdict: Verdict) -> None:
        if self.store is None or self.run_id is None:
            return
        evidence = dict(verdict.evidence)
        if candidate.context_key is not None:
            # the request context the test confirmed (SP-57, FR-FUZZ-66): the finding is
            # that context's, and ML labels only rows of its key (BUG-0530)
            evidence["context_id"] = candidate.context_id
            evidence["context_key"] = list(candidate.context_key)
        cur = self.store.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
            "url, method, param) VALUES (?,?,?,?,?,?,?,?)",
            (self.run_id, verdict.vuln_class, 1, verdict.mechanism,
             json.dumps(evidence), finding_url(candidate), candidate.method,
             candidate.param),
        )
        self.store.conn.commit()
        # FR-FUZZ-60: the finding cites the test, the strategy run and exactly the
        # exchanges that run made (its trace scope), never a time window
        from fuzzlab.core.urls import canonical_origin
        test, strategy, _role = trace.current()
        url = finding_url(candidate)
        trace.emit("finding", {
            "finding_id": cur.lastrowid, "test": test, "strategy": strategy,
            "mechanism": verdict.mechanism, "vuln_class": verdict.vuln_class,
            "url": trace.safe_ref(url), "method": candidate.method,
            "param": candidate.param, "location": candidate.location,
            "origin": canonical_origin(candidate.url),
            "request_context": candidate.context_id,      # SP-57 (FR-FUZZ-66)
            "exchanges": trace.collected(),
            "steps": trace.collected_steps()},             # FR-FUZZ-62
            key=f"finding:{cur.lastrowid}", scope=f"test:{test}" if test else "run")
