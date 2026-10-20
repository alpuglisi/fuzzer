"""Shared types for the oracle: what it probes with and what it returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


#: Post/redirect/get observation (FR-FUZZ-49): a response with one of these statuses,
#: after any method, gets one follow-up GET of its ``Location`` when the strategy run
#: asked for it (``prg=True``) ...
PRG_ANY_METHOD = frozenset({301, 302, 303})
#: ... and one of these only after a GET: a browser re-sends a POST body on 307/308, so
#: a POST answered with one is never followed (no PRG observation; a stated residual).
PRG_GET_ONLY = frozenset({307, 308})
#: Every redirect status: a follow-up answered with one is no observation (one hop).
REDIRECT_STATUSES = PRG_ANY_METHOD | PRG_GET_ONLY
#: ``Probe.prg`` values for a follow-up that was sent: it gave an observation, or it
#: did not (a second redirect, a timeout). Any other non-None value is the reason a
#: PRG redirect was not followed (``"skipped: <reason>"``).
PRG_OBSERVED = "observed"
PRG_UNOBSERVED = "unobserved"


@dataclass
class Probe:
    """One response the oracle observed while confirming.

    ``followed`` (FR-FUZZ-49) is a **separate, whole** response: the one follow-up GET
    of this probe's redirect target that the sender made because the strategy run asked
    for PRG observation (``status``, ``headers``, ``text`` and its ``url``). This
    probe's own fields always stay the raw response (a 3xx and its ``Location``), which
    open-redirect, header-injection and timing read. ``prg`` says what happened:
    ``None`` (not asked, or not a PRG redirect), `PRG_OBSERVED`, `PRG_UNOBSERVED` (a
    follow-up was sent, but answered with another redirect, timed out or got no
    response), or ``"skipped: <reason>"`` (a gate refused the follow-up; nothing was sent)."""
    status: int
    text: str
    elapsed: float = 0.0                       # seconds
    headers: dict[str, str] = field(default_factory=dict)
    followed: Probe | None = field(default=None, repr=False)
    prg: str | None = None
    url: str | None = None                     # set on a follow-up: the URL it fetched
    #: How this probe's session differed from the run's, when it did (FR-SESS-20, O2):
    #: ``"anonymous (out of origin)"`` -- the sender sent it without the session because
    #: its origin is not one of the session's. The oracle carries it into the verdict's
    #: ``evidence["session"]``; greybox into the attempt's features.
    session: str | None = None
    #: Times the sender re-sent this probe (or its follow-up) after no response
    #: (BUG-0147): requests of the run too.
    resent: int = 0
    #: Each try of this request the sender actually made, in order, recorded where the
    #: try happens (FR-FUZZ-61): `attempt_record` dicts, the last one the outcome this
    #: probe reports. Empty: the sender does not record its tries (a test double).
    #: Trace evidence only; no verdict reads it. A follow-up's tries are on its own
    #: record (`prg_sent`), never here.
    attempts: list[dict] = field(default_factory=list, repr=False)
    #: The PRG follow-up the sender actually sent for this probe, observed or not
    #: (FR-FUZZ-61, BUG-0510): ``{"url", "outcome", "status", "elapsed_ms", "error",
    #: "attempts"}``, or None when none was sent. ``followed`` is the observation, which
    #: is None for a follow-up answered by another redirect, timed out or unobserved;
    #: this is the send. Trace evidence only; no verdict reads it.
    prg_sent: dict | None = field(default=None, repr=False)
    #: Whether this request carried the run's credential (FR-FUZZ-63, SP-56), set per
    #: probe by the sender that knows: False from the anonymous `RequestsProbeSender`
    #: and an anonymous seam send, True from a seam send on a session. None (a sender
    #: that does not say, a test double) is read as **carried** -- fail closed: a 401
    #: or a login redirect is then a refused credential, never the handler's answer.
    credentialed: bool | None = None
    #: On a sender's status-0 timeout stand-in: ``"read"`` (the request was sent and
    #: the answer was late, which is latency) or ``"connect"`` (nothing was sent,
    #: which proves nothing, M7). None: not a timeout, or a sender that does not say.
    timeout: str | None = None
    #: The request was sent on a session its manager already knew to be lost and could
    #: not yet recover (FR-FUZZ-65, FR-SESS-23's D window; `core.http.Request.
    #: session_lost`), set per probe by the seam sender. Layer 1 (`require_observed`)
    #: reads any answer to such a request as not comparable, whatever its class.
    session_lost: bool = False

    @property
    def prg_sends(self) -> int:
        """The PRG follow-up the sender made for this probe (0 or 1; FR-FUZZ-49)."""
        return 1 if self.prg in (PRG_OBSERVED, PRG_UNOBSERVED) else 0

    @property
    def follow_up_sends(self) -> int:
        """Requests the sender made for this probe beyond the probe itself -- its PRG
        follow-up and any re-send after no response: counted in the run's
        ``requests`` and a strategy's cost (FR-FUZZ-49 P8, BUG-0147)."""
        return self.prg_sends + self.resent


@dataclass
class Candidate:
    """A candidate injection point the oracle is asked to confirm."""
    url: str
    param: str
    method: str = "GET"
    location: str = "query"                    # query | body | fragment | ...
    vuln_class: str | None = None              # hint; None -> strategies self-select
    sink_context: str | None = None            # from the auditor's typing, if known
    category: str | None = None                # reference category; scopes strategies
    # Stored-XSS: where the payload is planted before it renders on `url` (M6).
    store_url: str | None = None
    store_param: str | None = None
    store_method: str = "POST"
    store_location: str = "body"               # body | query | json (FR-FUZZ-56)
    store_entries: tuple | None = None         # a JSON store body's other leaves
    # A whole-body point's real content type (e.g. "application/json"), from
    # `fuzzlab.audit.engine.InjectionPoint.body_content_type` -- `None` unless
    # the ground truth positively declared the format (CC-FUZZ-0032/FR-FUZZ-19).
    content_type: str | None = None
    # A crawled form's default entry list (or a crawled link's query, forms phase 2):
    # every probe of `param` sends the other fields too (FR-FUZZ-42/43); bound by
    # `Oracle.confirm`.
    base_entries: tuple[tuple[str, str], ...] | None = None
    # What a command-injection probe starts from in place of the app's own ip/host
    # default (`audit.value_shape.SAFE_HOST`; FR-AUD-20). None: the strategies' own.
    base_value: str | None = None
    # An open-redirect candidate's crawled URL seed (FR-AUD-21, BUG-0124): read only by
    # `OpenRedirectStrategy`'s second probe.
    redirect_seed: str | None = None
    # The one mechanism (an arm) that decides this candidate (FR-AUD-30, BUG-0523): from
    # the evidence when every row of its confirmation key names it. None: any decides.
    decided_by: str | None = None


@dataclass
class Verdict:
    confirmed: bool
    vuln_class: str
    mechanism: str
    evidence: dict[str, Any] = field(default_factory=dict)
    # A check that started but could not decide within its cost cap (FR-FUZZ-45):
    # never a confirmation, and never a negative -- the pipeline records the
    # candidate `inconclusive` (unlabelled) unless another strategy confirms.
    inconclusive: bool = False


class HeaderPointsStopped(RuntimeError):
    """A sender refuses every further header probe of this run: the main session was
    logged out right after one (it is bound to a probed header). Raised before the
    send; the pipeline leaves the remaining header points unconfirmed and reports the
    reason (forms phase 2, FR-FUZZ-43)."""


class UnplaceableLocation(ValueError):
    """A sender or executor cannot put a payload where the point says it goes. It
    refuses instead of sending it somewhere else (BUG-0115, PA-0115)."""


class ProbeUnobserved(RuntimeError):
    """A probe was sent but no response could be read: the connection was reset,
    refused or closed before a complete response (BUG-0147). The one transport class a
    sender maps to "not observed" (PA-0137(1), PA-0106); the message names the error
    class only, never the payload or URL. The oracle makes it no verdict from that
    mechanism, never a negative and never the end of the run. ``resent``: the requests
    the sender re-sent before giving up, which the run's counters still count.
    ``attempts``: each try the sender actually made (`Probe.attempts`, FR-FUZZ-61);
    empty when no try of this probe went out (its session's login got no response) or
    the sender does not record them."""

    def __init__(self, message: str = "", resent: int = 0,
                 attempts: list[dict] | None = None):
        super().__init__(message)
        self.resent = resent
        self.attempts: list[dict] = list(attempts or [])


class NotComparable(ProbeUnobserved):
    """A response a mechanism needed was not the application's own answer (SP-56,
    FR-FUZZ-63, BUG-0529): a throttle or unavailable server, a gateway, a refused
    credential, a policy block or an incomplete exchange answered a control, a baseline
    sample, a compared slot or a replay -- or any probe was throttled, or its follow-up
    got no observation. The mechanism gives no verdict: the candidate is inconclusive
    (``not-comparable``), never confirmed on it and never a negative. A
    `ProbeUnobserved`, so every existing no-verdict handler applies (the OOB wait, the
    cost counter, the oracle's branch). Raised only through `require_observed` /
    `require_comparable` or a strategy's "observed alike" PRG check. The message names a
    role and a class, never a URL or payload."""


#: The classes a control admits unless its strategy declares more (FR-FUZZ-63).
APPLICATION_ONLY = frozenset({"application"})
#: `NotComparable.response_class` for an answer to a request sent on a session known to
#: be lost (FR-FUZZ-65): not one of SP-56's classes, since no class is read.
LOST_SESSION = "lost-session"


def candidate_entry_names(candidate) -> tuple[str, ...]:
    """The names of a candidate's own point -- its parameter and its entries' names (a
    JSON leaf by its `jsonbody.display_name`; `core.redaction.is_credential_name` takes
    a string, never a path tuple). Read by SP-16's `login_facts` to tell a credential
    submission (FR-SESS-22)."""
    names: list[str] = [str(getattr(candidate, "param", "") or "")]
    for entry in getattr(candidate, "base_entries", None) or ():
        try:
            name = entry[0]
        except (TypeError, IndexError, KeyError):
            continue
        if isinstance(name, str):
            names.append(name)
        elif isinstance(name, (tuple, list)):
            from fuzzlab.core import jsonbody
            try:
                names.append(jsonbody.display_name(tuple(name)))
            except (ValueError, TypeError):
                continue
    return tuple(n for n in names if n)


def comparability(probe, *, url: str, candidate=None,
                  credentialed: bool | None = None) -> tuple[str, str]:
    """SP-56's class of one oracle `Probe` (`core.comparability.response_class`), with
    SP-16's facts (`session.detect.login_facts`): the request's credential from the
    probe itself unless the caller knows better (None reads as carried), a credential
    submission judged on ``url`` and the candidate's own entries when ``url`` is the
    candidate's, a login redirect resolved against the probe's own URL (a follow-up's).
    A `Probe` is a whole response or a sender's status-0 stand-in (incomplete)."""
    from fuzzlab.core.comparability import response_class
    from fuzzlab.core.urls import url_key
    from fuzzlab.session.detect import login_facts
    own = candidate is not None and url_key(url) == url_key(getattr(candidate, "url", ""))
    facts = login_facts(url, getattr(probe, "headers", None),
                        response_url=getattr(probe, "url", None),
                        entry_names=candidate_entry_names(candidate) if own else ())
    carried = getattr(probe, "credentialed", None) if credentialed is None else credentialed
    return response_class(getattr(probe, "status", None), getattr(probe, "headers", None),
                          complete=True, credentialed=carried is not False,
                          credential_submission=facts.credential_submission,
                          redirect_to_login=facts.redirect_to_login)


def require_observed(probe, *, timing: bool = False) -> None:
    """Layer 1 (FR-FUZZ-63): every response a mechanism reads is an observation of the
    application at all. Raises `NotComparable` for a throttled or unavailable answer
    (the probe or its PRG follow-up), and for a status-0 stand-in -- on a timing send
    only a **read** timeout is kept, as latency (M7); a connect timeout, or a stand-in
    whose kind its sender did not say, proves nothing. Which classes a control admits
    is layer 2's (`require_comparable`). ``resent`` carries what the sender re-sent, so
    cost counts stay exact.

    *(FR-FUZZ-65, D′.)* Before any class is read: an answer to a request sent on a
    session its manager knew to be lost (`Probe.session_lost`, the probe's or its
    follow-up's) is `NotComparable`, whatever its class -- a guest view, a 404 or a
    non-login redirect included -- for every send a mechanism reads (payloads,
    controls, baselines and replays alike)."""
    from fuzzlab.core.comparability import (INCOMPLETE, THROTTLE_OR_UNAVAILABLE,
                                            response_class)
    if not isinstance(probe, Probe):
        return
    for p, what in ((probe, "probe"), (probe.followed, "probe's follow-up")):
        if p is None:
            continue
        if p.session_lost is True:
            exc = NotComparable(f"not comparable: the {what} was sent on a lost session",
                                resent=probe.follow_up_sends, attempts=probe.attempts)
            exc.response_class = LOST_SESSION
            raise exc
        cls, why = response_class(p.status, p.headers, complete=True, credentialed=False,
                                  credential_submission=False, redirect_to_login=False)
        if cls == THROTTLE_OR_UNAVAILABLE or (
                cls == INCOMPLETE and not (timing and p is probe and p.timeout == "read")):
            exc = NotComparable(f"not comparable: the {what} was {why}",
                                resent=probe.follow_up_sends, attempts=probe.attempts)
            exc.response_class = cls
            raise exc


def require_comparable(probe, *, url: str, candidate=None, role: str,
                       admits=APPLICATION_ONLY, credentialed: bool | None = None) -> str:
    """Layer 2 (FR-FUZZ-63): a control, baseline sample, compared slot or replay counts
    only when its SP-56 class is one its strategy declares for that ``role``
    (``admits``; default application only). Returns the class; raises `NotComparable`
    otherwise. ``probe`` is the response the strategy judges (`_observed`)."""
    cls, why = comparability(probe, url=url, candidate=candidate, credentialed=credentialed)
    if cls not in admits:
        exc = NotComparable(f"not comparable: the {role} was {why}")
        exc.response_class = cls
        raise exc
    return cls


#: Outcomes of one try (FR-FUZZ-61): a complete response; a timeout; no complete
#: response (`ProbeUnobserved`'s class: reset, aborted, cut off); the connection itself
#: failed (refused, DNS, TLS, proxy).
ATTEMPT_OUTCOMES = ("response", "timeout", "unobserved", "error")
#: The attribute a sender sets on an exception it re-raises unchanged (a timeout or a
#: refused connection) to carry the tries made before it (`note_attempts`).
ATTEMPTS_ATTR = "fuzzlab_attempts"


def attempt_record(n: int, outcome: str, *, status: int | None = None,
                   elapsed: float = 0.0, error: str | None = None) -> dict:
    """One try a sender made (FR-FUZZ-61): its 1-based number, `ATTEMPT_OUTCOMES`
    value, status (a response only), measured time (``elapsed`` in seconds) and the
    error's class name. Never a URL, header or body."""
    if outcome not in ATTEMPT_OUTCOMES:
        raise ValueError(f"not an attempt outcome: {outcome!r}")
    return {"n": n, "outcome": outcome, "status": status,
            "elapsed_ms": round(elapsed * 1000, 1), "error": error}


def note_attempts(exc: BaseException, attempts: list[dict]) -> None:
    """Carry ``attempts`` on an exception a sender re-raises unchanged; an exception
    that refuses attributes simply carries none."""
    try:
        setattr(exc, ATTEMPTS_ATTR, list(attempts))
    except (AttributeError, TypeError):
        pass


def attempts_of(outcome) -> list[dict]:
    """The tries a sender recorded on a `Probe`, a `ProbeUnobserved` or an exception it
    re-raised (`note_attempts`); empty when it recorded none."""
    found = getattr(outcome, "attempts", None) \
        if isinstance(outcome, (Probe, ProbeUnobserved)) \
        else getattr(outcome, ATTEMPTS_ATTR, None)
    return [a for a in found if isinstance(a, dict)] if isinstance(found, list) else []


class Sender:
    """Duck-typed HTTP sender the oracle uses. Injected so tests need no network.

    Implementations return a :class:`Probe`. ``timing=True`` marks a
    timing-sensitive send (the real seam serializes those per host). ``method`` and
    ``location`` (``query``/``body``/``header``) place the payload; they default to
    GET/query so a sender that only handles that case can omit them (the oracle
    passes them only for non-default candidates, e.g. POST body). ``content_type``
    is only meaningful for a whole-body point (``param="body"``, no single named
    field, e.g. a JSON API): when set, the sender sends ``value`` as the raw body
    with that content type instead of form-encoding ``{param: value}``; ``None``
    keeps the existing form-encoded behavior (CC-FUZZ-0032/FR-FUZZ-19).
    """

    #: Whether this sender (through every wrapper) can make PRG follow-ups: real
    #: senders set it True, a wrapper reports its inner sender's (`accepts_prg`). The
    #: oracle asks for PRG observation only from a sender that says so.
    prg_capable = False

    def send(self, url: str, param: str, value: str, timing: bool = False,
             method: str = "GET", location: str = "query",
             content_type: str | None = None,
             entries=None, prg: bool = False) -> Probe:  # pragma: no cover - interface
        """``entries`` (a form's full entry list, ``param`` already set to ``value``)
        is sent as the whole query string or urlencoded body instead of ``{param:
        value}`` alone (forms phase 1).

        ``prg`` (FR-FUZZ-49) asks for post/redirect/get observation: when the response
        is a PRG redirect (`PRG_ANY_METHOD`, or `PRG_GET_ONLY` after a GET) whose
        target passes every send gate (same origin, `check_send_url`, transaction,
        account and login checks, auth endpoints, isolation, the header breaker), the
        sender makes one plain GET of it on the **same session route** as the probe
        (the run's session, the path's isolated copy, or anonymous) and attaches it as
        ``probe.followed``. Never on a timing send. A wrapper forwards it only when
        True, so a test double without it keeps working."""
        raise NotImplementedError


def accepts_prg(sender) -> bool:
    """Can ``sender`` make PRG follow-ups (FR-FUZZ-49)? Its own ``prg_capable``
    declaration, which a wrapper delegates to its inner sender. A sender that does not
    declare it (a test double, an older wrapper) never gets ``prg``."""
    return getattr(sender, "prg_capable", False) is True
