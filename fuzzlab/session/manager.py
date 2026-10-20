"""SessionManager: detection-only auth, per-host credentials (D12, D13).

Keeps tools authenticated by detecting each host's login dynamically and drawing
credentials saved per host. Exposes the addon interface the `core/` HTTP seam
uses — ``prepare(request, identity)`` / ``observe(request, response, identity)`` —
plus ``ensure(host, identity, base_url)`` for explicit/standalone use.

A session is keyed per ``(host, identity)`` (credentials are stored per host), but it
is **sent per origin** (FR-SESS-20, BUG-0134): only to the canonical origins in
``SessionState.origins`` (the base URL the login ran from, the login page, the
credential destination and the operator's ``auth_origins``). Another port of the same
host is another app: a request there goes out anonymously, never triggers a login
there, and is counted (`out_of_origin_sends`).

Login handshakes use an injected fetcher (its own cookie jar), separate from the
HTTP seam, so authenticating never recurses through session handling. With no
server-rendered login form and no Basic challenge, a single-page app's login is found
and performed in a scoped browser on a worker thread (`session.browserlogin`,
FR-SESS-19). A login the detector cannot parse fails loudly (``SessionAuthError``) —
never a silent unauthenticated run.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Sequence
from urllib.parse import urljoin, urlparse

from fuzzlab.core.comparability import (APPLICATION, AUTH_FAILURE, GATEWAY, INCOMPLETE,
                                        POLICY_BLOCK, THROTTLE_OR_UNAVAILABLE,
                                        response_class)
from fuzzlab.core.redaction import is_sensitive_name, looks_like_identifier
from fuzzlab.core.urls import canonical_origin, origin_scope, url_key
from fuzzlab.session import detect
from fuzzlab.session.state import SessionState, secure_only_of

ANONYMOUS = "anonymous"
_LOG = logging.getLogger(__name__)

#: What a send made without the session because its origin is not one of the
#: session's (FR-SESS-20) is labelled with: ``Probe.session`` and a verdict's
#: ``evidence["session"]``.
OUT_OF_ORIGIN = "anonymous (out of origin)"


#: The remedy every origin refusal names (O3, O13): two apps on one host share the
#: host-keyed credential entry unless their identities differ.
DISTINCT_IDENTITY_ADVICE = ("use a distinct identity name per app (fuzzlab session "
                            "set-credential --host <host> --identity <name-per-app>)")


def session_origins(*urls: str | None, auth_origins=()) -> frozenset[str]:
    """The canonical origins a session may be sent to (FR-SESS-20, BUG-0134): those of
    ``urls`` -- the base URL the login ran from, the login page, the credential
    destination -- plus the operator's ``auth_origins``. The one derivation (PA-0003)
    for a login, a browser login, an isolated copy's login and a Basic session."""
    return origin_scope(*urls) | origin_scope(*auth_origins)


#: The ``--auth-origin`` help shared by every session-using CLI (crawl, auto, session
#: print, greybox-run; FR-SESS-20, R5).
AUTH_ORIGIN_HELP = ("an origin, scheme://host[:port] with no path, that belongs to this "
                    "app (an SSO, an API or app shell on another port): it authorises "
                    "the login's credential destination there AND the session's sends "
                    "there (FR-SESS-20). Repeatable; its host must be in scope. Another "
                    "port of a host is another app unless named here")


def parse_auth_origins(values, scope_hosts) -> list[str]:
    """The canonical origins of ``--auth-origin`` values (FR-SESS-20, R5), or
    `ValueError`: each must be a bare http(s) origin (no user, path, query or fragment)
    whose host is in ``scope_hosts`` (the CLI's scope: the config's ``scope_hosts`` plus
    the target's host), compared canonically (review round 2, T5: ``localhost`` and
    ``127.0.0.1`` are one host). A usage error, checked before any side effect
    (PA-0079)."""
    from urllib.parse import urlsplit
    def as_url(name) -> str:
        name = str(name)
        return f"http://[{name.strip('[]')}]/" if ":" in name else f"http://{name}/"
    scope = origin_scope(*(as_url(h) for h in scope_hosts or ()))
    out: list[str] = []
    for value in values or ():
        text = str(value).strip()
        parts = urlsplit(text)
        try:
            parts.port
        except ValueError:
            parts = None
        if parts is None or parts.scheme.lower() not in ("http", "https") or \
                not parts.hostname or parts.username or parts.password or \
                parts.path not in ("", "/") or parts.query or parts.fragment or \
                "?" in text or "#" in text:
            raise ValueError(f"--auth-origin {text!r}: give a bare origin, "
                             f"scheme://host[:port] (no user, path, query or fragment)")
        origin = canonical_origin(text)
        if origin is None:
            raise ValueError(f"--auth-origin {text!r}: not an origin")
        # its host, canonically, against the scope's hosts (an origin compare: the
        # scope's origins on this origin's scheme and port)
        same_host = canonical_origin(as_url(parts.hostname))
        if same_host not in scope:
            raise ValueError(f"--auth-origin {text!r}: its host is not in scope "
                             f"({', '.join(sorted(scope_hosts or ())) or 'none'}); add "
                             f"it to scope_hosts first")
        out.append(origin)
    return out


def auth_origin_advice(origin: str | None) -> str:
    """The advice an origin refusal or warning names (O12): authorise the origin as an
    auth origin when it belongs to this app."""
    return (f"if {origin} belongs to this app, pass --auth-origin {origin} (crawl, auto, "
            f"session print, greybox-run; SessionManager(auth_origins=[{origin!r}]))")


class SessionAuthError(RuntimeError):
    """Raised when a host's login cannot be detected/completed (fail loud)."""


class IsolatedLoginFailed(SessionAuthError):
    """An isolated copy (FR-SESS-17) could not obtain a usable session of its own: the
    login was rejected, credentials were missing, the copy's login cap was reached, or
    the new session was not distinct. The one class a sender catches to fall back to an
    anonymous send; every other `SessionAuthError` (a transport refusal) propagates.

    ``reason`` is a fixed, report-safe text (no URL, no value): it is what a report or
    log shows; the message (``str``) may quote a URL from the underlying failure."""

    def __init__(self, message: str, reason: str = "isolated login rejected"):
        super().__init__(message)
        self.reason = reason


class SessionIsolationError(IsolatedLoginFailed):
    """An isolated copy's new session is not distinct from the run's session or another
    live copy's (FR-SESS-17). Its message names credentials, never their values."""


class LoginCapReached(IsolatedLoginFailed):
    """A manager built with ``max_logins`` has used them all for this host/identity."""


class SessionHealthUnknown(SessionAuthError):
    """An identity's session state stayed unknown past the pause bound, the run's pause
    budget or the re-login budget (FR-SESS-23). Sticky: every later `prepare` for that
    (host, identity) raises at once, with no clock and no network, until a check gives a
    definite answer. It ends a run as the ``max_reauth`` cap does."""


class IsolatedHealthUnknown(IsolatedLoginFailed):
    """An isolated copy's session state stayed unknown (FR-SESS-23): FR-SESS-17's one
    class a sender catches, so the copy is released and its path goes anonymous."""


# --- session health (FR-SESS-23, CC-SESS-0029, BUG-0533) ----------------------------------
#: A health verdict's states. STALE: the state judged was replaced (or moved to another
#: generation) before the verdict could be recorded, so it records nothing.
LIVE, LOST, INCONCLUSIVE, STALE = "live", "lost", "inconclusive", "stale"
_HEALTH_LOG = logging.getLogger("fuzzlab.session.health")
#: The first pause after an inconclusive check, doubling up to `PAUSE_MAX_STEP_S`; a
#: ``Retry-After`` is honoured up to the same bound.
PAUSE_FIRST_S = 5.0
PAUSE_MAX_STEP_S = 60.0
#: A redirect status the health walk may stop at (a login redirect) or follow.
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
#: `_draw_relogin`'s answer for D: no token and no stable protected resource, so the
#: identity carries on at once on the session it has (FR-SESS-23).
_SKIP_RELOGIN = object()


@dataclass(frozen=True)
class Health:
    """A health check's verdict for one session generation (FR-SESS-23). ``reason``
    names a class and a status only, never a URL, header value or body."""
    state: str
    reason: str = ""
    generation: int | None = None
    retry_after_s: float | None = None


@dataclass
class _HealthRecord:
    """One manager's health bookkeeping for one (host, identity), in memory."""
    #: the health lock: single flight of the check, and every write below but the
    #: bucket's (which the login lock guards)
    lock: threading.Lock = field(default_factory=threading.Lock)
    #: (generation, url key) -> when a live verdict for it was taken (the TTL cache)
    live: dict = field(default_factory=dict)
    #: generation -> the sequence number at which a live verdict's GET was **sent**
    live_seq: dict = field(default_factory=dict)
    verdict: tuple | None = None                  # (generation, state), the last one
    pause: dict | None = None                     # gen, until, step, began
    unknown: str | None = None                    # the sticky reason
    tokens: float | None = None                   # the re-login bucket (login lock)
    refill_at: float = 0.0
    relogin_due: bool = False                     # set by `_mark_lost`
    report: Counter = field(default_factory=Counter)


@dataclass
class _RunBudget:
    """What a run's manager shares with its isolated copies (FR-SESS-23): the pause
    budgets and the credential POSTs per account. A peer identity has its own manager,
    so its own budget."""
    lock: threading.Lock = field(default_factory=threading.Lock)
    prepare_s: float = 0.0       # spent by `prepare`'s pauses and the bucket's waits
    verify_s: float = 0.0        # spent by `verify_live`'s own waits, never `prepare`'s
    credential_posts: dict = field(default_factory=dict)       # account -> Counter


def _answer_classes(status, headers) -> tuple[str, str, str]:
    """SP-56's class of an answer to the credentialed health GET, the same answer's
    class to an uncredentialed request (a 407 is an auth failure either way), and the
    first one's reason."""
    as_sent, why = response_class(status, headers, complete=True, credentialed=True,
                                  credential_submission=False, redirect_to_login=False)
    to_anyone, _why = response_class(status, headers, complete=True, credentialed=False,
                                     credential_submission=False, redirect_to_login=False)
    return as_sent, to_anyone, why


def _not_the_applications(status, headers) -> bool:
    """B1: an incomplete, throttle, gateway or 407 answer is never evidence about the
    session (SP-56 classifies first)."""
    as_sent, to_anyone, _why = _answer_classes(status, headers)
    return as_sent in (INCOMPLETE, THROTTLE_OR_UNAVAILABLE, GATEWAY) or \
        (as_sent == AUTH_FAILURE and to_anyone == AUTH_FAILURE)


def admitted_refusal(status) -> bool:
    """Can ``status`` be a stable protected resource's recorded refusal status (M5, B1)?
    A non-2xx status below 500 that SP-56 classes as the application's answer or a
    policy block, read as the credentialed health GET will be read: never a throttle, a
    gateway or a 407. The one rule for a login's resource and for `adopt`."""
    if isinstance(status, bool) or not isinstance(status, int) or status <= 0 or \
            200 <= status < 300 or status >= 500:
        return False
    return _answer_classes(status, {})[0] in (APPLICATION, POLICY_BLOCK)


def _retry_after(headers) -> float | None:
    """A ``Retry-After`` in seconds, clipped to [0, `PAUSE_MAX_STEP_S`]; None when absent
    or not a number of seconds."""
    for name, value in (headers or {}).items():
        if str(name).lower() == "retry-after":
            try:
                return max(0.0, min(PAUSE_MAX_STEP_S, float(str(value).strip())))
            except ValueError:
                return None
    return None


def _header_value(headers, wanted: str) -> str:
    for name, value in (headers or {}).items():
        if str(name).lower() == wanted:
            return str(value)
    return ""


def health_verdict(state: SessionState, status, headers, body, page_url, *,
                   stopped_at_login: bool = False, refusal: bool = True) -> Health:
    """Is the answer to a credentialed GET of ``state``'s stable protected resource a
    live session, a lost one, or neither (FR-SESS-23)? Public and total over any state
    it is handed. The first row that holds decides:

    1. the walk stopped at a login redirect: LOST;
    2. SP-56 classes the answer incomplete, throttle-or-unavailable or gateway, or an
       auth failure for an uncredentialed request too (a 407): INCONCLUSIVE, its
       ``Retry-After`` kept -- before any refusal status is matched (B1);
    3. `detect.detect_logout`, credentialed and not a submission (Basic: no content):
       LOST;
    4. the resource's recorded refusal status, or a 2xx whose body hashes to its
       recorded refusal body: LOST (``refusal=False`` skips this row: a resource being
       chosen has none yet);
    5. any other 2xx: LIVE;
    6. anything else (a policy block that is not the recorded refusal, another status):
       INCONCLUSIVE."""
    gen = getattr(state, "generation", None)
    if stopped_at_login:
        return Health(LOST, f"a login redirect ({status})", gen)
    if _not_the_applications(status, headers):
        return Health(INCONCLUSIVE, _answer_classes(status, headers)[2], gen,
                      _retry_after(headers))
    if detect.detect_logout(status, headers, body or "", login_url=state.login_url,
                            page_url=page_url, content_check=state.kind != "basic",
                            login_fields=state.login_fields, credentialed=True,
                            credential_submission=False):
        return Health(LOST, f"an auth failure ({status})", gen)
    recorded = getattr(state, "probe_refusal_status", None)
    if refusal and recorded is not None and status == recorded:
        return Health(LOST, f"the resource's refusal status ({status})", gen)
    if 200 <= status < 300:
        if refusal and state.probe_refusal_digest and \
                _digest(body) == state.probe_refusal_digest:
            return Health(LOST, f"the resource's refusal body ({status})", gen)
        return Health(LIVE, "", gen)
    why = _answer_classes(status, headers)[2]
    return Health(INCONCLUSIVE, why or f"another status ({status})", gen,
                  _retry_after(headers))


def _plain_fetch_factory() -> Callable[[], Fetcher]:
    """The health GET's fetcher (FR-SESS-23): `requests.request` per hop, as the seam
    sends (no `requests.Session`, no browser header set), with the manager's 15 s
    timeout per hop (connect and read). It keeps the cookies each answer set, so a live
    answer's rotated session id can be adopted. It never posts."""
    def factory():
        import requests

        class _PlainFetcher:
            def __init__(self):
                self._jar: dict[str, str] = {}

            def get(self, url, headers=None, allow_redirects=True):
                r = requests.request("GET", url, headers=headers, timeout=15,
                                     allow_redirects=allow_redirects)
                self._jar.update(r.cookies.get_dict())
                return FetchResponse(r.status_code, dict(r.headers), r.text, r.url,
                                     _hops(r))

            def post(self, url, data=None, headers=None, allow_redirects=True):
                raise SessionAuthError("a health fetcher never posts")

            def cookies(self):
                return dict(self._jar)
        return _PlainFetcher()
    return factory


def _adopt_rotation(state: SessionState, jar) -> None:
    """A live answer that set a new value for one of the session's own cookies (a
    rotating id) is adopted, so a check never kills its own session. Only a cookie the
    state already holds, never a new name."""
    for name, value in (jar or {}).items():
        if name in (state.cookies or {}) and value and state.cookies[name] != value:
            state.cookies[name] = value


def _transport_errors() -> tuple:
    import requests
    return (requests.RequestException,)


def _stopped_at_login(resp) -> bool:
    """Did a ``stop_at`` walk (`SessionManager._navigate`) stop at a login redirect? It
    returns a redirect that carries a ``Location`` only when it stopped there."""
    return resp.status in _REDIRECTS and bool(_header_value(resp.headers, "location"))


#: The headers a session owns (FR-SESS-23, M6): with the state's own header names, a
#: request carrying only these is not a header probe, and may be covered by the cache.
#: The body's framing headers are exempt on purpose: otherwise every POST probe would
#: bypass it.
_SESSION_OWNED_HEADERS = frozenset({"cookie", "authorization", "content-type",
                                    "content-length"})


def _foreign_header(request, state: SessionState) -> bool:
    """Does ``request`` carry a header the session does not own (a header probe such as
    ``User-Agent`` or ``Referer``)? Such a request bypasses the live cache (M6)."""
    own = _SESSION_OWNED_HEADERS | {str(k).lower() for k in (state.headers or {})}
    return any(str(k).lower() not in own
               for k in (getattr(request, "headers", None) or {}))


#: An equal credential value at least this long is never accepted as distinct, whatever
#: its shape: distinctness-specific policy, OR-ed with the shared
#: `core.redaction.looks_like_identifier` (FR-SESS-17). A false "not distinct" only
#: costs an anonymous fallback.
DISTINCT_MIN_LEN = 16
#: The label of an isolated copy's requests (and `flow.identity`): ``<identity>#isolated:<n>``.
ISOLATED_LABEL = "{identity}#isolated:{n}"


@dataclass
class FetchResponse:
    status: int
    headers: dict[str, str]
    text: str
    #: the final URL after any redirects (None: the fetcher does not say)
    url: str | None = None
    #: the scheme of every hop, the final one included (empty: the fetcher does not say)
    history_schemes: tuple[str, ...] = field(default_factory=tuple)


def _hops(r) -> tuple[str, ...]:
    return tuple(urlparse(h.url).scheme.lower() for h in r.history) + \
        (urlparse(r.url).scheme.lower(),)


class Fetcher:
    """Login-handshake HTTP with its own cookie jar (default: requests-backed)."""

    def get(self, url: str, headers: dict[str, str] | None = None) -> FetchResponse: ...
    def post(self, url: str, data: Sequence[tuple[str, str]] | None = None,
             headers: dict[str, str] | None = None,
             allow_redirects: bool = True) -> FetchResponse: ...
    def cookies(self) -> dict[str, str]: ...


def _requests_fetch_factory() -> Callable[[], Fetcher]:
    def factory() -> Fetcher:
        import requests

        from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
        sess = requests.Session()
        sess.headers.update(DEFAULT_BROWSER_HEADERS)

        class _RequestsFetcher:
            def get(self, url, headers=None, allow_redirects=True):
                r = sess.get(url, headers=headers, timeout=15,
                             allow_redirects=allow_redirects)
                return FetchResponse(r.status_code, dict(r.headers), r.text, r.url,
                                     _hops(r))

            def post(self, url, data=None, headers=None, allow_redirects=True):
                r = sess.post(url, data=data, headers=headers, timeout=15,
                              allow_redirects=allow_redirects)
                return FetchResponse(r.status_code, dict(r.headers), r.text, r.url,
                                     _hops(r))

            def cookies(self):
                return sess.cookies.get_dict()

        return _RequestsFetcher()

    return factory


class SessionManager:
    def __init__(self, credentials, scope_hosts: list[str] | None = None,
                 fetch_factory: Callable[[], Fetcher] | None = None,
                 identities: list[str] | None = None, max_reauth: int = 3,
                 logger=None, store=None, auth_origins: list[str] | None = None,
                 max_logins: int | None = None, browser_login: bool | None = None,
                 health_ttl_s: float = 30.0, relogin_burst: int = 5,
                 relogin_refill_s: float = 120.0, max_pause_s: float = 300.0,
                 pause_budget_s: float = 600.0, clock: Callable[[], float] | None = None,
                 sleep: Callable[[float], None] | None = None,
                 health_fetch_factory: Callable[[], Fetcher] | None = None):
        """FR-SESS-23's keywords (CC-SESS-0029): ``health_ttl_s`` (a live verdict's
        cache window), ``relogin_burst`` and ``relogin_refill_s`` (the loss-driven
        re-login bucket), ``max_pause_s`` (one pause's bound) and ``pause_budget_s`` (the
        run's: `prepare`'s pauses and bucket waits share one, `verify_live`'s waits
        another), the injectable ``clock`` and ``sleep`` (monotonic seconds), and
        ``health_fetch_factory`` (the health GET's fetcher: by default the seam's plain
        `requests` per hop when the manager fetches from the network, else the injected
        ``fetch_factory``). An isolated copy takes the run's values and shares its
        budgets."""
        self._creds = credentials
        # FR-SESS-19: the browser login fallback for single-page apps. Default: on when
        # the manager's fetches go to the network (the default fetcher), off when a
        # fetcher double stands in for the site (a browser would not see that site).
        self._browser_login = (fetch_factory is None) if browser_login is None \
            else bool(browser_login)
        self._scope = set(scope_hosts or [])
        # extra origins credentials may be sent to (an auth service elsewhere), beyond
        # the login page's own origin and in-scope hosts (BUG-0081)
        self._auth_origins = {o for o in (canonical_origin(u) for u in auth_origins or [])
                              if o is not None}
        self._fetch_factory = fetch_factory or _requests_fetch_factory()
        self._identities = identities or [ANONYMOUS, "user", "admin"]
        self._max_reauth = max_reauth
        self._log = logger
        self._store = store       # optional: persist NON-SECRET session state (T1.7)
        self._state: dict[tuple[str, str], SessionState] = {}
        self._auth_endpoints: dict[str, set[str]] = {}
        # BUG-0113: the operator's base URL per session (a re-login reuses it, path and
        # all), and the set of operator-supplied bases (the only ones exempt from the
        # destructive-URL check during discovery).
        self._bases: dict[tuple[str, str], str] = {}
        self._operator_bases: set[str] = set()
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._failures: dict[tuple[str, str], int] = {}
        # forms phase 2 (FR-SESS-16): callbacks told when observe() logs a session out
        self._logout_listeners: list[Callable[[str, str], None]] = []
        # guards only the valid->invalid check-and-set in observe(), so concurrent
        # sends tell a listener once per logout; never held across a send or listener
        self._observe_guard = threading.Lock()
        # forms phase 2 (FR-SESS-17): a login-attempt cap (None: unlimited, as before);
        # an isolated copy's label and the manager it was copied from; a main manager's
        # registry of its live copies
        self._max_logins = max_logins
        self._attempts: dict[tuple[str, str], int] = {}
        self._label: str | None = None
        self._label_identity: str | None = None
        self._isolated_from: SessionManager | None = None
        self._copies: list[SessionManager] = []
        self._copies_guard = threading.Lock()
        # FR-SESS-20: sends made without the session because their origin is not one of
        # its origins (counted; each (origin, identity) logged once)
        self._origin_guard = threading.Lock()
        self._out_of_origin = 0
        self._out_of_origin_seen: set[tuple[str, str]] = set()
        self._persisted: dict[tuple[str, str], dict] = {}
        # FR-SESS-23: session health (the check, the pause, the re-login bucket)
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._health_ttl_s = float(health_ttl_s)
        self._relogin_burst = int(relogin_burst)
        self._relogin_refill_s = float(relogin_refill_s)
        self._max_pause_s = float(max_pause_s)
        self._pause_budget_s = float(pause_budget_s)
        self._health_ff = health_fetch_factory or \
            (_plain_fetch_factory() if fetch_factory is None else self._fetch_factory)
        self._run_budget = _RunBudget()
        self._health: dict[tuple[str, str], _HealthRecord] = {}
        self._generations: dict[tuple[str, str], int] = {}
        self._seq_lock = threading.Lock()
        self._seq = 0
        self._login_tl = threading.local()       # the login in progress on this thread
        if self._store is not None:
            for rec in self._store.all_session_states():
                self._persisted[(rec["host"], rec["identity"])] = rec
            if self._persisted and self._log:
                self._log.info("resuming known sessions",
                               extra={"count": len(self._persisted)})

    def persisted_state(self, host: str, identity: str) -> dict | None:
        """The last non-secret session state persisted for (host, identity), if any,
        with its ``secure_only`` (derived for records that predate it, failing closed —
        `state.secure_only_of`).

        Note: secrets are never persisted, so a resumed run still re-authenticates
        to obtain a live cookie/token; this is metadata (audit + continuity). Neither
        are a session's origins (FR-SESS-20): a resumed record never applies a session
        by itself.
        """
        rec = self._store.get_session_state(host, identity) if self._store is not None \
            else self._persisted.get((host, identity))
        if rec is None:
            return None
        return {**rec, "secure_only": secure_only_of(rec)}

    def _persist(self, state: SessionState) -> None:
        if self._store is not None:
            self._store.upsert_session_state(state.non_secret_state())

    def adopt(self, state: SessionState, *, protected_probe: str | None = None,
              refusal_status: int | None = None) -> SessionState:
        """Adopt an externally-captured session (FR-SESS-11).

        The escape hatch for logins detection can't parse (MFA, CAPTCHA, multi-step,
        exotic SPA): the proxy captures the session a human established with a manual
        browser login (FR-PROXY-9) and hands the resulting :class:`SessionState` here.
        We mark it valid, bring its host into scope, cache it for ``prepare``/``apply``,
        and persist only the NON-SECRET metadata (secrets stay in memory, like a
        normal login). No per-host config file is needed.

        The state must name the origins it was observed on (``state.origins``,
        FR-SESS-20; `proxy.SessionCapture` records them): a session with none is
        refused loudly, since it could be sent nowhere.

        *(FR-SESS-23.)* ``protected_probe`` gives the session a stable protected
        resource, with an optional ``refusal_status`` held to the login's admission
        (`admitted_refusal`: never a throttle, gateway or 407; refused loudly
        otherwise). The adopted state gets the next generation before it is installed,
        and it is installed and persisted under the lock `_mark_lost` compare-and-sets
        under, so a replaced state's row never lands after this one's.
        """
        if self._isolated_from is not None:
            raise SessionAuthError("an isolated session never adopts a captured one "
                                   "(a captured session is the operator's own)")
        if not state.origins:
            raise SessionAuthError(
                f"refusing to adopt the captured session of {state.identity}@{state.host}: "
                f"no origin was observed for it, so it could be sent nowhere (capture "
                f"its requests with their URLs; FR-SESS-20)")
        if refusal_status is not None and not admitted_refusal(refusal_status):
            raise SessionAuthError(
                f"refusing to adopt the captured session of {state.identity}@{state.host} "
                f"with refusal status {refusal_status!r}: a refusal status must be the "
                f"application's answer or a policy block below 500 (SP-56), never a "
                f"throttle, a gateway or a 407 (FR-SESS-23)")
        if protected_probe is not None:
            state.protected_probe = protected_probe
            state.probe_refusal_status = refusal_status
        # the operator's authorised auth origins are this session's too (R5, A-N2)
        state.origins = frozenset(state.origins) | frozenset(self._auth_origins)
        state.valid = True
        self._scope.add(state.host)
        self._install(state)
        if self._log:
            self._log.info("adopted captured session", extra=state.redacted())
        return state

    def _install(self, state: SessionState) -> None:
        """Make ``state`` the current state of its (host, identity) (FR-SESS-23, B3 and
        review round 4): number it with the next generation, install it and persist its
        non-secret row, all under `_observe_guard` -- the lock `_mark_lost`
        compare-and-sets and persists under. So an invalidation of the state this one
        replaces either lands wholly before it (its row first) or finds it replaced
        (no row): the rows' last word is always the current state's."""
        key = (state.host, state.identity)
        with self._observe_guard:
            state.generation = self._next_generation(key)
            self._state[key] = state
            self._persist(state)
            self._health_record(*key).relogin_due = False

    # -- addon interface used by the HTTP seam ----------------------------
    def prepare(self, request, identity: str) -> None:
        """Apply ``identity``'s session to ``request`` -- only when the request's
        canonical origin is one of the session's origins (FR-SESS-20, BUG-0134).

        A request to an in-scope host but another origin (another port: another app)
        goes out **without** the session, as that app's anonymous visitor: it never
        triggers a login there, is logged once per (origin, identity) and counted
        (`out_of_origin_sends`); the decision is recorded on the request itself
        (``request.session_decision = OUT_OF_ORIGIN``, R6) for its sender.

        *(FR-SESS-23.)* Before anything else: a sticky unknown identity raises
        `SessionHealthUnknown` at once (no clock, no network), and a pause of the
        current generation is waited out and re-checked (`_wait_out_pause`). The request
        then records the generation of the state applied (``session_generation``, set
        from that state, never re-read), and ``session_lost`` when that state is one
        this manager knows to be lost and could not yet recover (the re-login budget of
        an identity with no stable protected resource is spent)."""
        host = urlparse(request.url).hostname or ""
        identity = self._own_identity(identity)
        if identity == ANONYMOUS or host not in self._scope:
            return
        current = self._state_for(request.url, identity)
        if current is not None:
            key = (current.host, identity)
            rec = self._health_record(*key)
            if rec.unknown is not None:
                raise self._unknown(key, rec.unknown)          # sticky: no network
            pause = rec.pause
            if pause is not None and pause["gen"] == current.generation:
                self._wait_out_pause(current, identity)
        origin = canonical_origin(request.url)
        state = self._state_for(request.url, identity)
        if state is None:
            existing = self._state.get((host, identity))
            if existing is not None:
                # this host's session lives on other origins: never a login here (O3);
                # an https session's http request is still refused loudly (BUG-0098)
                _check_transport(existing, request.url)
                self._withhold(origin, identity, request)
                return
            # no session on this host yet: the operator's own base when one is known;
            # else the request's directory (never its origin: the app may live under a
            # path; never the probe URL itself: discovery must not replay a payload) —
            # BUG-0113. `ensure` refuses a base on another origin than the operator's.
            state = self.ensure(host, identity,
                                self._bases.get((host, identity)) or _directory(request.url))
        elif not state.valid or state.is_time_expired():
            state = self.ensure(state.host, identity,
                                self._bases.get((state.host, identity))
                                or _directory(request.url))
        _check_transport(state, request.url)          # BUG-0098: before any secret
        if origin is None or origin not in state.origins:
            self._withhold(origin, identity, request)  # FR-SESS-20: before any secret
            return
        request.headers = state.apply(request.headers)
        # FR-SESS-23 (F4): from the state just applied, never re-read from the manager
        request.session_generation = state.generation
        # D' (FR-FUZZ-65): a session known lost and not yet recovered (D's window)
        request.session_lost = not state.valid

    def authorize(self, request, identity: str, prepared_host: str | None = None) -> None:
        """Re-check an authenticated request after something (a plugin) edited it:
        raise `SessionAuthError` if it now goes to another host than the session was
        applied for, carries a session of that host to an origin that is not one of
        that session's origins (another port, FR-SESS-20), or goes over http with an
        https-established session (BUG-0098). A request sent anonymously (another
        origin's) may be edited on its own origin."""
        identity = self._own_identity(identity)
        if identity == ANONYMOUS:
            return
        host = urlparse(request.url).hostname or ""
        if prepared_host is not None and host != prepared_host:
            raise SessionAuthError(
                f"refusing to send {identity}@{prepared_host}'s session to {host!r}: "
                f"the request was retargeted after the session was applied")
        origin = canonical_origin(request.url)
        for state in self._states_on_host(prepared_host or host, identity):
            if (origin is None or origin not in state.origins) and \
                    _carries(request, state):
                raise SessionAuthError(
                    f"refusing to send {identity}@{state.host}'s session to {origin}: the "
                    f"request was retargeted after the session was applied, to an origin "
                    f"that is not one of the session's ({', '.join(sorted(state.origins))})")
        state = self._state_for(request.url, identity)
        if state is not None:
            _check_transport(state, request.url)

    def observe(self, request, response, identity: str) -> None:
        """Read one answer to a request this manager prepared (FR-SESS-23, BUG-0533). A
        forbidden answer is never, by itself, a lost session:

        - SP-56 classifies first: a throttle, gateway, 407, incomplete or other
          application answer changes nothing (counted by class).
        - A request from another generation (``session_generation``) says nothing about
          the current one; a signal on an invalid or paused generation is ignored.
        - **With a stable protected resource**, a loss shape (`detect.detect_logout`), a
          credentialed policy block (403, 451) or a credential submission's loss shape
          (`detect.login_facts` with `detect.request_entry_names`) triggers
          `check_health`; the resource's answer decides.
        - **With none**, only a loss shape that is not a submission counts: an
          unconfirmed loss (`_mark_lost`), whose re-login draws on the bucket.

        Listeners are told once per valid -> invalid transition seen on this send
        (FR-SESS-16), after the health lock is released."""
        if self._label is not None:
            if identity != self._label:
                return              # prepare() already refused it; nothing of ours
            identity = self._label_identity
        # by origin membership (FR-SESS-20): another app's login page on another port of
        # this host never logs this session out
        state = self._state_for(request.url, identity)
        if state is None:
            return
        seen_seq = self._next_seq()           # B2: the signal is seen now
        key = (state.host, identity)
        rec = self._health_record(*key)
        carried = getattr(request, "session_decision", None) != OUT_OF_ORIGIN
        body = _text(response.body)
        shape = detect.detect_logout(response.status, response.headers, body,
                                     login_url=state.login_url, page_url=request.url,
                                     content_check=state.kind != "basic",
                                     login_fields=state.login_fields, credentialed=carried,
                                     credential_submission=False)
        cls, _why = response_class(response.status, response.headers, complete=True,
                                   credentialed=carried, credential_submission=False,
                                   redirect_to_login=False)
        self._count(rec, f"class:{cls}")
        policy = cls == POLICY_BLOCK and carried
        if not shape and not policy:
            return
        generation = getattr(request, "session_generation", None)
        if generation is None:
            generation = state.generation           # unstated: the current one (fail closed)
        if generation != state.generation:
            self._count(rec, "stale_signals")
            return
        if not state.valid:
            return                                  # already lost (D's window included)
        pause = rec.pause
        if pause is not None and pause["gen"] == generation:
            return                                  # paused: prepare re-checks
        facts = detect.login_facts(request.url, response.headers, login_url=state.login_url,
                                   entry_names=detect.request_entry_names(
                                       request.url, request.body,
                                       _header_value(request.headers, "content-type")))
        submission = facts.credential_submission
        origin = canonical_origin(request.url)
        if not state.protected_probe:
            if shape and not submission:
                self._count(rec, "unconfirmed")
                if self._mark_lost(state, generation):
                    self._tell(origin, identity)
            return
        self._count(rec, "suspected" if shape else "policy_checks")
        _health, moved = self.check_health(state.host, identity, self._bases.get(key),
                                           generation=generation, signal_url=request.url,
                                           seen_seq=seen_seq,
                                           foreign=_foreign_header(request, state))
        if moved:
            self._tell(origin, identity)

    def _tell(self, origin: str | None, identity: str) -> None:
        """Tell the logout listeners (FR-SESS-16): inside the observing send, after the
        health lock is released; a listener's error propagates (PA-0106)."""
        for listener in list(self._logout_listeners):
            listener(origin, identity)

    def add_logout_listener(self, listener: Callable[[str, str], None]) -> None:
        """Call ``listener(origin, identity)`` each time `observe` sees a valid session
        of **this** manager logged out (FR-SESS-16): ``origin`` is the canonical origin
        of the response that showed it, always one of that session's origins
        (FR-SESS-20; a listener compares it with `session_origins_for`, never a host).
        It runs inside the send that observed the logout, so it must not block on a
        lock held across that send. Adding the same listener again does nothing."""
        if listener not in self._logout_listeners:
            self._logout_listeners.append(listener)

    # -- explicit / standalone -------------------------------------------
    def ensure(self, host: str, identity: str, base_url: str, *,
               operator: bool = False) -> SessionState:
        """Log ``identity`` in on ``host`` (once; single-flight), discovering the login
        from ``base_url``. ``operator=True`` marks ``base_url`` as the operator's own
        input (a CLI's ``--base-url``/``--start``/``--url``): it is remembered for
        re-logins and is the only kind of base exempt from the destructive-URL check
        during discovery (BUG-0113). Internal callers leave it False (fail closed).

        FR-SESS-20 (O3): it logs in only from an operator base or a base whose origin is
        one of the existing ``(host, identity)`` session's origins -- never from a base
        derived from a request on another origin. An operator base whose origin is not
        one of the existing session's (or of an earlier operator base's) is refused
        loudly (`SessionAuthError`), naming the remedy: a distinct identity per app."""
        if identity != ANONYMOUS:
            self._check_base(host, identity, base_url, operator=operator)
        if operator:
            # recorded on every operator call, a cached session included, so a later
            # re-login uses the operator's base (reviewer B, BUG-0113)
            self._operator_bases.add(url_key(base_url))
            self._bases[(host, identity)] = base_url
        if identity == ANONYMOUS:
            state = SessionState(host, identity, kind="none", valid=True)
            self._state[(host, identity)] = state
            return state
        if host not in self._scope:
            raise SessionAuthError(f"host {host!r} not in scope {sorted(self._scope)}")
        while True:
            # single-flight: concurrent expiry -> one login; the re-login token is drawn
            # in the same critical section as the login (FR-SESS-23, F5)
            with self._lock_for(host, identity):
                state = self._state.get((host, identity))
                if state is not None and state.valid and not state.is_time_expired():
                    return state
                # again under the lock: a concurrent login may have anchored it meanwhile
                self._check_base(host, identity, base_url, operator=operator)
                draw = self._draw_relogin((host, identity), state)
                if draw is _SKIP_RELOGIN:
                    return state      # D: no token, no resource: send on what there is
                if draw is None:
                    return self._log_in_locked(host, identity, base_url)
            self._sleep(draw)         # an empty bucket's wait holds no lock
            self._charge("prepare_s", draw)

    def _log_in_locked(self, host: str, identity: str, base_url: str) -> SessionState:
        """`ensure`'s login, under the (host, identity) login lock: the caps, the login,
        the isolated copy's distinctness, then the install (`_install`), which ends the
        old generation's pause first (login lock -> health lock)."""
        if self._failures.get((host, identity), 0) >= self._max_reauth:
            raise SessionAuthError(
                f"re-auth cap ({self._max_reauth}) reached for {identity}@{host}"
            )
        if self._max_logins is not None and \
                self._attempts.get((host, identity), 0) >= self._max_logins:
            raise LoginCapReached(
                f"login cap ({self._max_logins}) reached for the isolated session "
                f"{self._label or identity}@{host}", reason="isolated login cap reached")
        self._attempts[(host, identity)] = self._attempts.get((host, identity), 0) + 1
        from fuzzlab.core.credentials import CredentialError
        try:
            state = self._login(host, identity, base_url)
            if self._isolated_from is not None:
                self._check_isolated(host, identity, state)   # FR-SESS-17
        except SessionAuthError as exc:
            self._failures[(host, identity)] = self._failures.get((host, identity), 0) + 1
            if self._isolated_from is not None and \
                    not isinstance(exc, IsolatedLoginFailed):
                raise IsolatedLoginFailed(str(exc)) from exc
            raise
        except CredentialError as exc:
            if self._isolated_from is None:
                raise                                         # unchanged for a run
            self._failures[(host, identity)] = self._failures.get((host, identity), 0) + 1
            raise IsolatedLoginFailed(
                str(exc), reason="isolated login: no credentials") from exc
        self._failures[(host, identity)] = 0
        rec = self._health_record(host, identity)
        with rec.lock:                 # login -> health: a new generation ends a pause
            rec.pause = None
        self._count(rec, "logins")
        self._install(state)
        return state

    def _draw_relogin(self, key: tuple[str, str], state: SessionState | None):
        """The loss-driven re-login bucket (FR-SESS-23, M10, D), under the login lock.

        Returns None when the login may go ahead (the first login, a JWT refresh, or a
        token was drawn), `_SKIP_RELOGIN` when an identity with no stable protected
        resource has no token (D: it carries on at once on the session it has), or the
        seconds to wait for the next token (an identity with a resource, within the
        pause bound and the run's budget; otherwise `SessionHealthUnknown`)."""
        rec = self._health_record(*key)
        if state is None or state.valid or not rec.relogin_due:
            return None
        now = self._clock()
        if rec.tokens is None:
            rec.tokens, rec.refill_at = float(self._relogin_burst), now
        gained = (now - rec.refill_at) / self._relogin_refill_s
        if gained > 0:
            rec.tokens = min(float(self._relogin_burst), rec.tokens + gained)
            rec.refill_at = now
        if rec.tokens >= 1.0:
            rec.tokens -= 1.0
            self._count(rec, "relogins")
            return None
        if not state.protected_probe:
            self._count(rec, "relogins_skipped")
            return _SKIP_RELOGIN
        wait = (1.0 - rec.tokens) * self._relogin_refill_s
        with self._run_budget.lock:
            left = self._pause_budget_s - self._run_budget.prepare_s
        if wait > self._max_pause_s or wait > left:
            raise self._unknown(key, "re-login budget")
        return wait

    def session_header(self, host: str, identity: str, base_url: str, *,
                       operator: bool = False) -> str:
        """Standalone: a ready-to-use Cookie/Authorization header for an identity, for
        use against ``base_url``. Refuses (`SessionAuthError`) an https-established
        session for an http ``base_url`` (BUG-0098); a consumer that sends it to other
        URLs (greybox) must enforce the same floor per request (``secure_only``)."""
        state = self.ensure(host, identity, base_url, operator=operator)
        _check_origin(state, base_url)                # FR-SESS-20 (O10)
        _check_transport(state, base_url)
        applied = state.apply({})
        if "Cookie" in applied:
            return f"Cookie: {applied['Cookie']}"
        if "Authorization" in applied:
            return f"Authorization: {applied['Authorization']}"
        return ""

    def session_headers(self, host: str, identity: str, base_url: str, *,
                        operator: bool = False) -> dict[str, str]:
        """Standalone: every header the session sends (``Cookie`` and
        ``Authorization`` together, e.g. a browser login's bearer and the cookie the
        app's JS set, BUG-0132), under the same transport refusal as `session_header`.
        ``fuzzlab session print`` prints each. Both refuse a ``base_url`` whose origin is
        not one of the session's (FR-SESS-20, O10)."""
        state = self.ensure(host, identity, base_url, operator=operator)
        _check_origin(state, base_url)                # FR-SESS-20 (O10)
        _check_transport(state, base_url)
        return state.apply({})

    def session_origins_for(self, url: str, identity: str) -> frozenset[str]:
        """The origins of ``identity``'s session that covers ``url``'s origin (empty
        when none does): what a sender with its own copy of the session material
        (greybox) or a listener comparing a logout's origin uses (FR-SESS-20)."""
        state = self._state_for(url, self._own_identity(identity))
        return frozenset(state.origins) if state is not None else frozenset()

    @property
    def out_of_origin_sends(self) -> int:
        """Sends `prepare` made without the session because their origin is not one of
        its origins (FR-SESS-20; reported as ``session_out_of_origin``)."""
        with self._origin_guard:
            return self._out_of_origin

    # -- isolated copies (forms phase 2, FR-SESS-17) -------------------------
    def isolated_copy(self, identity: str, *, ordinal: int,
                      max_logins: int = 3) -> SessionManager:
        """A throwaway manager for ``identity``: its own login, so its own server-side
        session, for probing an in-app login form without ever sending the run's session
        there (FR-FUZZ-44).

        Built through ``__init__`` (never ``copy.copy``), so no mutable state is shared:
        its states, auth endpoints, locks, failures, login attempts and logout listeners
        start empty. It shares the credential store and the fetch factory (which must
        return a fresh fetcher, with its own jar, per call), and copies the scope, the
        authorised auth origins and the operator's bases, so a (re-)login is discovered
        from the operator's URL under the same credential-destination anchors, and its
        session gets the same origins as the run's (FR-SESS-20, O11). It has no
        store: never persisted (a persisted copy would overwrite the run's
        ``(host, identity)`` row). It answers only to its label
        ``<identity>#isolated:<ordinal>``, has at most ``max_logins`` login attempts, and
        accepts a new session only when it is distinct from the run's and from every
        other live copy's (`_check_isolated`). It is registered here until
        `release_copy`."""
        copy = SessionManager(self._creds, scope_hosts=sorted(self._scope),
                              fetch_factory=self._fetch_factory,
                              identities=list(self._identities),
                              max_reauth=self._max_reauth, logger=self._log, store=None,
                              max_logins=max_logins, browser_login=self._browser_login,
                              health_ttl_s=self._health_ttl_s,
                              relogin_burst=self._relogin_burst,
                              relogin_refill_s=self._relogin_refill_s,
                              max_pause_s=self._max_pause_s,
                              pause_budget_s=self._pause_budget_s, clock=self._clock,
                              sleep=self._sleep, health_fetch_factory=self._health_ff)
        # FR-SESS-23: the run's pause budgets and credential-POST count, shared (its
        # health records, generations and re-login bucket are its own)
        copy._run_budget = self._run_budget
        copy._auth_origins = set(self._auth_origins)
        copy._bases = dict(self._bases)
        copy._operator_bases = set(self._operator_bases)
        copy._label = ISOLATED_LABEL.format(identity=identity, n=ordinal)
        copy._label_identity = identity
        copy._isolated_from = self
        with self._copies_guard:
            self._copies.append(copy)
        return copy

    @property
    def label(self) -> str | None:
        """An isolated copy's request label (None for a run's own manager)."""
        return self._label

    def release_copy(self, copy: SessionManager) -> None:
        """Drop ``copy`` from the live copies (its session is simply abandoned)."""
        with self._copies_guard:
            if copy in self._copies:
                self._copies.remove(copy)

    def login_attempts(self) -> int:
        """Login attempts made through `ensure` (every host and identity)."""
        return sum(self._attempts.values())

    def _own_identity(self, identity: str) -> str:
        """An isolated copy maps its own label to its identity and refuses every other
        identity, the bare one and ``anonymous`` included; a run's manager is unchanged."""
        if self._label is None:
            return identity
        if identity == self._label:
            return self._label_identity or identity
        raise SessionAuthError(f"the isolated session {self._label!r} refuses requests "
                               f"labelled {identity!r}")

    def _check_isolated(self, host: str, identity: str, state: SessionState) -> None:
        """Raise `SessionIsolationError` unless ``state`` is distinct from the run's
        session and from every other live copy's (FR-SESS-17)."""
        main = self._isolated_from
        assert main is not None
        others = [("the run's session", main._state.get((host, identity)))]
        with main._copies_guard:
            others += [(c._label or "an isolated session", c._state.get((host, identity)))
                       for c in main._copies if c is not self]
        for whom, other in others:
            if other is None:
                continue
            problem = distinctness_problem(state, other)
            if problem is not None:
                why = f"not distinct from {whom}: {problem}"     # labels and names only
                raise SessionIsolationError(
                    f"the isolated session {self._label}@{host} is {why}",
                    reason=f"isolated session {why}")

    def verify_live(self, host: str, identity: str, base_url: str) -> bool:
        """Is the run's session for ``identity`` still logged in? A fresh health check
        (`check_health`, never the live cache): one GET of the session's stable
        protected resource (else ``base_url``, the operator's base) carrying the
        session's cookies and headers, walked hop by hop inside the session's origins,
        stopping at a login redirect, and judged by `health_verdict` (FR-SESS-23):

        - LIVE: True, and any sticky unknown is cleared (a definite answer);
        - LOST: False; the state is marked lost (`_mark_lost`, persisted) without telling
          listeners (the caller decides), and any sticky unknown is cleared;
        - an unapproved or other-origin hop: `SessionAuthError` ("cannot verify",
          FR-SESS-20, O5), as before;
        - INCONCLUSIVE: it waits **on its own** (5 s doubling to 60 s, ``Retry-After``
          honoured), at most ``max_pause_s`` per call and within its own run budget
          (never `prepare`'s), and checks again; still inconclusive, it returns True
          (today's "not lost"), logged once. It never records a pause for the identity
          and never sets or clears a sticky unknown;
        - STALE (the state was replaced while it checked): True, logged."""
        state = self._state.get((host, identity))
        if state is None or not state.valid:
            return False
        rec = self._health_record(host, identity)
        generation = state.generation
        began, step = self._clock(), PAUSE_FIRST_S
        while True:
            health, _moved = self.check_health(host, identity, base_url,
                                               generation=generation, use_cache=False,
                                               pause=False)
            if health.state != INCONCLUSIVE:
                break
            left = self._max_pause_s - (self._clock() - began)
            with self._run_budget.lock:
                budget_left = self._pause_budget_s - self._run_budget.verify_s
            wait = min(max(step, health.retry_after_s or 0.0), left, budget_left)
            if wait <= 0:
                break
            self._sleep(wait)
            self._charge("verify_s", wait)
            step = min(PAUSE_MAX_STEP_S, step * 2)
        if health.state in (LIVE, LOST):
            with rec.lock:
                rec.unknown = None                    # a definite answer
            return health.state == LIVE
        _HEALTH_LOG.warning("verify_live: session health %s; read as live (%s)",
                            health.state, health.reason)
        return True

    # -- session health (FR-SESS-23, CC-SESS-0029, BUG-0533) ---------------------------
    def check_health(self, host: str, identity: str, base_url: str | None = None, *,
                     generation: int | None = None, signal_url: str | None = None,
                     seen_seq: int | None = None, foreign: bool = False,
                     use_cache: bool = True, pause: bool = True) -> tuple[Health, bool]:
        """Is (host, identity)'s session of ``generation`` (default: the current one)
        live? The one owner of the answer (FR-SESS-23). Returns ``(Health,
        transitioned)``: ``transitioned`` is whether this call marked a valid session
        lost (its caller tells the listeners when the loss was seen on a send).

        - **Single flight** under the per-(host, identity) health lock; the verdict is
          recorded before the lock is released. A waiter re-checks under the lock.
        - **The cover (B2):** a live verdict covers a signal only when the signal was
          seen (``seen_seq``) before that verdict's GET was **sent**; a signal seen
          while the GET was in flight makes its own check. So N concurrent signals make
          at most two GETs.
        - **The cache (M6):** for ``health_ttl_s``, a live verdict also covers later
          signals of the same generation and URL key (``signal_url``), unless the
          request carried a header the session does not own (``foreign``).
          ``use_cache=False`` (a pause re-check, `verify_live`) reads neither.
        - **Compare-and-set (B3):** after the GET, still under the lock, the verdict
          counts only if the judged object is still the current state of its key and of
          the generation judged; otherwise it is STALE and records nothing (no live
          mark, no pause, no `_mark_lost`, no row, no listener).
        - LOST calls `_mark_lost` (its own compare-and-set). INCONCLUSIVE pauses the
          identity for that generation unless ``pause=False`` (`verify_live`).
        - An unapproved hop raises `SessionAuthError` (fail fast, never a pause)."""
        key = (host, identity)
        state = self._state.get(key)
        if state is None:
            return Health(STALE, "no session", generation), False
        rec = self._health_record(*key)
        gen = state.generation if generation is None else generation
        signal_key = url_key(signal_url) if signal_url else None
        with rec.lock:
            if state.generation != gen:
                return Health(STALE, "another generation", gen), False
            if rec.verdict == (gen, LOST):
                return Health(LOST, "already lost", gen), False
            now = self._clock()
            if use_cache:
                last = rec.live_seq.get(gen)
                if seen_seq is not None and last is not None and last > seen_seq:
                    self._count(rec, "covered")
                    return Health(LIVE, "covered", gen), False
                if signal_key is not None and not foreign:
                    hits = [at for (g, k), at in rec.live.items()
                            if g == gen and k == signal_key]
                    if hits and now - max(hits) < self._health_ttl_s:
                        self._count(rec, "cached")
                        return Health(LIVE, "cached", gen), False
            sent_seq = self._next_seq()           # B2: the cover point is the send
            started = self._clock()
            health = self._health_get(state, base_url or self._bases.get(key))
            health = dataclasses.replace(health, generation=gen)
            self._count(rec, "checks")
            self._count(rec, health.state)
            if not self._is_current(state, gen):
                self._count(rec, "stale_verdicts")       # B3: replaced while in flight
                return Health(STALE, "replaced while its check was in flight", gen), False
            moved = False
            if health.state == LIVE:
                rec.live_seq[gen] = max(rec.live_seq.get(gen, 0), sent_seq)
                if signal_key is not None:
                    rec.live[(gen, signal_key)] = started
            elif health.state == LOST:
                if rec.pause is not None and rec.pause["gen"] == gen:
                    rec.pause = None
                moved = self._mark_lost(state, gen)
            elif health.state == INCONCLUSIVE and pause:
                current = rec.pause
                if current is None or current["gen"] != gen:
                    rec.pause = {"gen": gen,
                                 "until": now + max(PAUSE_FIRST_S, health.retry_after_s or 0),
                                 "step": PAUSE_FIRST_S, "began": now}
                    self._count(rec, "pauses")
                    _HEALTH_LOG.warning("session health unknown; pausing the identity "
                                        "(%s)", health.reason)
            rec.verdict = (gen, health.state)     # recorded before the lock is released
        return health, moved

    def _health_get(self, state: SessionState, base_url: str | None) -> Health:
        """One GET of ``state``'s stable protected resource (else ``base_url``) with the
        session's own material, sent as the seam sends (`health_fetch_factory`), walked
        inside the session's origins and stopping at a login redirect, judged by
        `health_verdict`. A transport failure (a timeout included) is no response:
        INCONCLUSIVE. An unapproved hop raises (fail fast). A live answer's rotated
        session cookie is adopted."""
        target = state.protected_probe or base_url
        if not target:
            return Health(INCONCLUSIVE, "no resource and no base", state.generation)
        floor = bool(state.secure_only) or urlparse(target).scheme.lower() == "https"
        fetcher = self._health_ff()
        try:
            resp, page, _floor = self._navigate(fetcher, target, base_url or target, floor,
                                                headers=state.apply({}),
                                                session_origins=frozenset(state.origins),
                                                stop_at=state)
        except _transport_errors() as exc:
            return Health(INCONCLUSIVE, f"no response ({type(exc).__name__})",
                          state.generation)
        stopped = _stopped_at_login(resp)
        health = health_verdict(state, resp.status, resp.headers, resp.text, page,
                                stopped_at_login=stopped)
        if health.state == LIVE:
            cookies = getattr(fetcher, "cookies", None)
            _adopt_rotation(state, cookies() if callable(cookies) else None)
        return health

    def _is_current(self, state: SessionState, generation: int | None) -> bool:
        """B3: ``state`` is still the current object for its key, of ``generation``."""
        return self._state.get((state.host, state.identity)) is state and \
            state.generation == generation

    def _mark_lost(self, state: SessionState, generation: int | None) -> bool:
        """The one place a session is invalidated (FR-SESS-23; T19). Under
        `_observe_guard` it compare-and-sets on the **current state**: it changes nothing
        and returns False unless ``state`` is still the current object of its key and of
        ``generation``, and valid. Then it marks it invalid, makes the next login a
        loss-driven one (the bucket) and persists its row -- the persist inside the same
        critical section, so a replacement installed by `_install` writes its row after
        this one, never before. Returns whether it made the transition; its caller tells
        the listeners when the loss was seen on a send."""
        with self._observe_guard:
            if not self._is_current(state, generation):
                return False
            if not state.valid:
                return False
            state.valid = False
            self._health_record(state.host, state.identity).relogin_due = True
            self._persist(state)
        return True

    def _wait_out_pause(self, state: SessionState, identity: str) -> Health | None:
        """Wait a paused identity's pause out on the injectable sleep, holding no lock,
        then check again, until it is live, lost or unknown past the pause bound or the
        run's budget (`prepare`'s only; `verify_live` has its own wait). A loss found
        here has no culprit send: it is marked lost without telling the listeners.
        Returns the last verdict (None: the pause had ended)."""
        key = (state.host, identity)
        rec = self._health_record(*key)
        while True:
            pause = rec.pause
            if pause is None or pause["gen"] != state.generation:
                return None
            now = self._clock()
            with self._run_budget.lock:
                spent = self._run_budget.prepare_s
            over_budget = spent >= self._pause_budget_s
            if now - pause["began"] >= self._max_pause_s or over_budget:
                raise self._unknown(key, "pause budget" if over_budget else "pause bound")
            if now < pause["until"]:
                wait = min(pause["until"] - now, pause["began"] + self._max_pause_s - now,
                           max(0.0, self._pause_budget_s - spent))
                self._sleep(wait)
                self._charge("prepare_s", wait)
                continue
            health, _moved = self.check_health(state.host, identity, self._bases.get(key),
                                               generation=pause["gen"], use_cache=False)
            if health.state == STALE:
                with rec.lock:
                    if rec.pause is pause:
                        rec.pause = None
                return health
            if health.state == INCONCLUSIVE:
                with rec.lock:
                    pause["step"] = min(PAUSE_MAX_STEP_S, pause["step"] * 2)
                    pause["until"] = self._clock() + max(pause["step"],
                                                         health.retry_after_s or 0)
                continue
            with rec.lock:
                if rec.pause is pause:
                    rec.pause = None
            return health

    def _unknown(self, key: tuple[str, str], why: str) -> SessionAuthError:
        """Make (host, identity) sticky unknown and return the error to raise:
        `SessionHealthUnknown`, or `IsolatedHealthUnknown` for an isolated copy."""
        rec = self._health_record(*key)
        # no health lock: the bucket's caller holds the login lock, and an in-flight
        # check holds the health lock for its GET; a sticky identity reads no pause
        rec.unknown = why
        rec.pause = None
        self._count(rec, "unknown")
        if self._isolated_from is not None:
            return IsolatedHealthUnknown(f"isolated session health unknown ({why})",
                                         reason="isolated session health unknown")
        return SessionHealthUnknown(f"the session of {key[1]}@{key[0]} stayed unknown "
                                    f"({why}; FR-SESS-23)")

    def health_report(self) -> dict:
        """FR-SESS-23's counts: per ``"<host>/<identity>"`` the classes seen, signals,
        checks and their outcomes, pauses, re-logins drawn and skipped; plus the run's
        credential POSTs per account (``credential_posts``: ``submitted``, ``control``)
        and the seconds `prepare`'s and `verify_live`'s waits spent (``paused_s``,
        ``verify_paused_s``). No URL, header value or body."""
        with self._locks_guard:
            out: dict = {f"{h}/{i}": dict(r.report) for (h, i), r in self._health.items()}
        with self._run_budget.lock:
            out["credential_posts"] = {account: dict(kinds) for account, kinds in
                                       self._run_budget.credential_posts.items()}
            out["paused_s"] = self._run_budget.prepare_s
            out["verify_paused_s"] = self._run_budget.verify_s
        return out

    def _health_record(self, host: str, identity: str) -> _HealthRecord:
        with self._locks_guard:
            rec = self._health.get((host, identity))
            if rec is None:
                rec = self._health[(host, identity)] = _HealthRecord()
            return rec

    def _count(self, rec: _HealthRecord, name: str, n: int = 1) -> None:
        with self._locks_guard:
            rec.report[name] += n

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._seq += 1
            return self._seq

    def _next_generation(self, key: tuple[str, str]) -> int:
        with self._locks_guard:
            n = self._generations.get(key, 0) + 1
            self._generations[key] = n
            return n

    def _charge(self, which: str, seconds: float) -> None:
        with self._run_budget.lock:
            setattr(self._run_budget, which, getattr(self._run_budget, which) + seconds)

    def is_auth_endpoint(self, url: str) -> bool:
        """Is ``url`` one of this manager's sessions' auth endpoints (login page, form
        action, logout)? Compared by canonical origin and path (`url_key`, FR-SESS-20):
        ``/login`` on another port of the same host is another app's, not ours."""
        key = url_key(url)
        return any(url_key(known) == key
                   for known in self._auth_endpoints.get(canonical_origin(url), set()))

    def auth_endpoints(self, host: str) -> set[str]:
        """Every recorded auth endpoint on ``host`` (any port; loopback aliases one
        host)."""
        from fuzzlab.session.browserlogin import canonical_host
        mine = canonical_host(f"http://{host}/")
        return {u for origin, urls in self._auth_endpoints.items()
                if canonical_host(origin + "/") == mine for u in urls}

    def _record_auth_endpoints(self, *urls: str | None) -> None:
        """Record auth endpoints, each under its own canonical origin (FR-SESS-20)."""
        for u in urls:
            origin = canonical_origin(u) if u else None
            if origin is not None:
                self._auth_endpoints.setdefault(origin, set()).add(u)

    # -- origins (FR-SESS-20, BUG-0134) ------------------------------------
    def _state_for(self, url: str, identity: str) -> SessionState | None:
        """``identity``'s session whose origins include ``url``'s canonical origin: the
        session keyed by ``url``'s host first, else the one other session that lists the
        origin (an auth origin on another host); None when none does, or when more than
        one other session would (ambiguous: fail closed)."""
        origin = canonical_origin(url)
        if origin is None:
            return None
        own = self._state.get((urlparse(url).hostname or "", identity))
        if own is not None and origin in own.origins:
            return own
        others = [s for (_h, i), s in list(self._state.items())
                  if i == identity and s is not own and origin in s.origins]
        return others[0] if len(others) == 1 else None

    def _states_on_host(self, host: str, identity: str) -> list[SessionState]:
        """``identity``'s sessions with an origin on ``host`` (canonical: loopback aliases
        one host): those a request prepared for ``host`` may have carried."""
        from fuzzlab.session.browserlogin import canonical_host
        mine = canonical_host(f"http://{host}/")
        return [s for (_h, i), s in list(self._state.items())
                if i == identity and any(canonical_host(o + "/") == mine
                                         for o in s.origins)]

    def _check_base(self, host: str, identity: str, base_url: str, *,
                    operator: bool) -> None:
        """O3: a login base must be on one of the existing ``(host, identity)``
        session's origins, or, with none yet, on the operator base's origin when one was
        given. Refused loudly otherwise (D38: refuse rather than warn)."""
        origin = canonical_origin(base_url)
        state = self._state.get((host, identity))
        if state is not None:
            anchors, what = frozenset(state.origins), "established for"
        elif (host, identity) in self._bases:
            anchors = origin_scope(self._bases[(host, identity)])
            what = "anchored by the operator's base on"
        else:
            return                                     # no anchor yet: this one anchors
        if origin is None or origin not in anchors:
            kind = "the operator's base" if operator else "a login base"
            msg = (f"refusing {kind} {origin} for {identity}@{host}: that session is "
                   f"{what} {', '.join(sorted(anchors)) or 'no origin'}, and another port "
                   f"of the same host is another app; {DISTINCT_IDENTITY_ADVICE}")
            if self._isolated_from is not None:
                # an isolated copy's failures are the one class a sender falls back on
                raise IsolatedLoginFailed(msg, reason="isolated login: base on another "
                                                      "origin")
            raise SessionAuthError(msg)

    def _origins_of(self, base_url: str, *urls: str | None) -> frozenset[str]:
        """A new session's origins (O1): the base URL's, those of ``urls`` (the login
        page, the credential destination) and the operator's ``auth_origins``. An
        isolated copy computes the same set from the same inputs (O11)."""
        return session_origins(base_url, *urls, auth_origins=sorted(self._auth_origins))

    def _warn_other_origins(self, identity: str, host: str, seen: set[str],
                            origins: frozenset[str]) -> None:
        """O12: the login handshake fetched an origin the session will not be sent to
        (a post-login redirect to another port, say): say so, with the advice."""
        for origin in sorted(seen - set(origins)):
            (self._log or _LOG).warning(
                f"the login of {self._label or identity}@{host} was redirected to {origin}, "
                f"which is not one of the session's origins: the session is not sent "
                f"there (FR-SESS-20); {auth_origin_advice(origin)}")

    def _withhold(self, origin: str | None, identity: str, request) -> None:
        """Record on ``request`` (R6), count, and log once per (origin, identity) a send
        made without the session because its origin is not one of the session's
        (FR-SESS-20)."""
        request.session_decision = OUT_OF_ORIGIN    # core.http.Request's field (T4)
        with self._origin_guard:
            self._out_of_origin += 1
            first = (origin or "?", identity) not in self._out_of_origin_seen
            self._out_of_origin_seen.add((origin or "?", identity))
        if first:
            msg = (f"not sending {self._label or identity}'s session to {origin}: not one "
                   f"of the session's origins (sent anonymously; FR-SESS-20)")
            (self._log or _LOG).info(msg)

    # -- internals --------------------------------------------------------
    def _lock_for(self, host: str, identity: str) -> threading.Lock:
        with self._locks_guard:
            key = (host, identity)
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._locks[key] = lock
            return lock

    def _login(self, host: str, identity: str, base_url: str) -> SessionState:
        cred = self._creds.require(host, identity)   # CredentialError if missing
        fetcher = self._fetch_factory()
        seen: set[str] = set()       # every origin the login handshake fetched (O12)

        form, login_page_url, challenge, floor_https = \
            self._discover_login_form(fetcher, base_url, seen=seen)
        if form is None and challenge == "basic":
            # HTTP Basic has no form: the base URL itself challenges (BUG-0081). The
            # header goes only to that same in-scope origin.
            return self._basic_login(fetcher, host, identity, base_url, cred,
                                     secure_only=floor_https)
        if form is None:
            if not self._browser_login:
                raise SessionAuthError(
                    f"could not detect a login for {identity}@{host}: no login form "
                    f"found from {base_url} (multi-step/CAPTCHA logins are not "
                    f"auto-detected, and the browser login fallback, FR-SESS-19, is off "
                    f"for this manager; capture via the proxy post-Phase 6)")
            return self._browser_login_state(host, identity, base_url, cred)
        if not self._transport_ok(login_page_url, floor_https):
            raise SessionAuthError(
                f"refusing to log {identity}@{host} in: the login page {login_page_url} "
                f"was reached by a downgrade from https to http")
        if form.json_url is not None:          # the page's script sends it as JSON
            return self._json_login(fetcher, host, identity, base_url, cred, form,
                                    login_page_url, floor_https, seen)
        if form.submitter_overrides:
            # A browser would send the form where/how its submit button says, which
            # this login does not emulate: refuse rather than send it elsewhere.
            raise SessionAuthError(
                f"refusing to log {identity}@{host} in: the login form's submit button "
                f"overrides the form with {', '.join(form.submitter_overrides)} "
                f"(not supported; capture the session via the proxy instead)")
        if not self._credential_destination_ok(form.action_url, base_url,
                                               floor_https=floor_https):
            raise SessionAuthError(
                f"refusing to send {identity}@{host} credentials to "
                f"{canonical_origin(form.action_url)}: a downgrade from https to http, "
                f"or not the login page's origin, an in-scope host, or an authorised auth "
                f"origin; {auth_origin_advice(canonical_origin(form.action_url))}")
        self._count_credential_post(host, identity, "submitted")       # FR-SESS-23
        resp = self._post_credentials(fetcher, form.action_url,
                                      form.fill(cred.username, cred.password), base_url,
                                      floor_https=floor_https, seen=seen)
        if resp.status == 401 and "basic" in {k.lower(): v for k, v in
                                              resp.headers.items()}.get(
                                                  "www-authenticate", "").lower():
            return self._basic_login(fetcher, host, identity, base_url, cred,
                                     secure_only=floor_https)
        # A rejected login re-renders the login form (or answers 401/403). The mere
        # presence of a session cookie is NOT proof of authentication: servers hand an
        # anonymous session cookie to everyone (e.g. PHP's session_start() runs on every
        # page, so the fetcher's jar already holds a PHPSESSID from _discover_login_form's
        # GET, before any credentials are sent). Require a positive signal that the login
        # response left the login page behind before trusting the cookie. (BUG-0008)
        landed = getattr(resp, "url", None) or form.action_url
        login_fields = tuple(sorted(form.fields.names()))
        if resp.status in (401, 403) or detect.shows_login_form(
                resp.text, landed, form.action_url, login_fields):
            raise SessionAuthError(
                f"login for {identity}@{host} was rejected: credentials wrong, or the "
                f"login response was still a login page (status {resp.status})"
            )
        detected = detect.detect_session_credential(
            resp.status, resp.headers, resp.text, cookies=fetcher.cookies())
        if detected is None:
            raise SessionAuthError(
                f"login for {identity}@{host} submitted but no session credential was "
                f"detected in the response (status {resp.status})"
            )

        state = SessionState(host=host, identity=identity, kind=detected.kind,
                             cookies=dict(detected.cookies), headers=dict(detected.headers),
                             token_exp=detected.token_exp, login_url=form.action_url,
                             login_fields=login_fields,
                             logout_url=urljoin(base_url, "logout"),
                             secure_only=floor_https,
                             # FR-SESS-20: where this session may be sent
                             origins=self._origins_of(base_url, login_page_url,
                                                      form.action_url))
        if detected.kind == "basic":
            token = base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
            state.headers["Authorization"] = f"Basic {token}"

        # Record auth endpoints so fuzzing excludes them (T1.8).
        return self._established(fetcher, host, identity, base_url, state, seen,
                                 (form.action_url, login_page_url, state.logout_url),
                                 landing=getattr(resp, "url", None))

    # -- JSON login from the page's own script (FR-SESS-21) ---------------------------
    def _json_login(self, fetcher: Fetcher, host: str, identity: str, base_url: str,
                    cred, form, login_page_url: str, floor_https: bool,
                    seen: set[str]) -> SessionState:
        """A login form the page's script sends as JSON (`detect.json_login_target`):
        the form's entries, credentials in place, POSTed as a JSON object to that URL,
        which must pass `_credential_destination_ok` like a form's action.

        A cookie is not proof (BUG-0008): the same body with a wrong password goes
        first, on a fetcher of its own. The login holds only when the real one answers
        2xx with a credential the wrong one did not get: a cookie it set that the wrong
        attempt did not set, or a token in its JSON answer that the wrong answer lacks.
        Every failure is loud (FR-SESS-6). The password is never logged."""
        url = form.json_url
        if not self._credential_destination_ok(url, base_url, floor_https=floor_https):
            origin = canonical_origin(url)
            raise SessionAuthError(
                f"refusing to send {identity}@{host} credentials to {origin}: the page's "
                f"script logs in there, which is not the login page's origin, an in-scope "
                f"host, or an authorised auth origin; {auth_origin_advice(origin)}")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        def body(password: str) -> bytes:
            return json.dumps(dict(form.fill(cred.username, password))).encode()
        control = self._fetch_factory()
        self._count_credential_post(host, identity, "control")         # FR-SESS-23
        wrong = self._post_credentials(control, url, body(cred.password + WRONG_SUFFIX),
                                       base_url, floor_https=floor_https, seen=seen,
                                       headers=headers)
        wrong_cookies = set(control.cookies())
        before = fetcher.cookies()
        self._count_credential_post(host, identity, "submitted")
        resp = self._post_credentials(fetcher, url, body(cred.password), base_url,
                                      floor_https=floor_https, seen=seen, headers=headers)
        if not 200 <= resp.status < 300:
            raise SessionAuthError(f"login for {identity}@{host} was rejected: the JSON "
                                   f"login answered {resp.status}")
        after = fetcher.cookies()
        fresh = {n for n, v in after.items() if before.get(n) != v and n not in wrong_cookies}
        token = _json_token(resp.text)
        if token is not None and token == _json_token(wrong.text):
            token = None                       # a wrong password gets it too: not proof
        if fresh:
            detected = detect.DetectedCredential(kind="cookie", cookies=dict(after))
        elif token is not None:
            detected = detect.DetectedCredential(
                kind="bearer", cookies=dict(after),
                headers={"Authorization": f"Bearer {token}"},
                token_exp=detect.decode_jwt_exp(token))
        else:
            raise SessionAuthError(
                f"login for {identity}@{host} answered {resp.status} but gave no credential "
                f"that a wrong password does not also get (wrong password: {wrong.status}); "
                f"success could not be confirmed")
        state = SessionState(host=host, identity=identity, kind=detected.kind,
                             cookies=dict(detected.cookies), headers=dict(detected.headers),
                             token_exp=detected.token_exp, login_url=url,
                             logout_url=urljoin(base_url, "logout"),
                             secure_only=floor_https,
                             origins=self._origins_of(base_url, login_page_url, url))
        return self._established(fetcher, host, identity, base_url, state, seen,
                                 (url, login_page_url, state.logout_url))

    def _established(self, fetcher: Fetcher, host: str, identity: str, base_url: str,
                     state: SessionState, seen: set[str] | None,
                     auth_endpoints: tuple, *, landing: str | None = None) -> SessionState:
        """The common end of an HTTP login: the follow-up probe, then the session is
        valid, its auth endpoints recorded and its stable protected resource chosen
        (FR-SESS-23: the operator's base, else the post-login ``landing``). Its
        non-secret row is written when `ensure` installs it (`_install`), under the
        lock `_mark_lost` writes under (B3)."""
        if not self._verify_authenticated(fetcher, base_url, state, seen=seen):
            raise SessionAuthError(
                f"login for {identity}@{host} did not result in an authenticated "
                f"session (credentials wrong, or success could not be confirmed)"
            )
        state.valid = True
        self._warn_other_origins(identity, host, seen, state.origins)      # O12
        self._record_auth_endpoints(*auth_endpoints)
        self._record_resource(state, base_url, (landing,))
        if self._log:
            self._log.info("authenticated", extra=state.redacted())
        return state

    def _record_resource(self, state: SessionState, base_url: str,
                         extra: Sequence[str | None] = ()) -> None:
        """Choose an HTTP login's stable protected resource (FR-SESS-23, M4, M5) through
        the one owner (`_spa_probe`): the operator's base URL (rule 2, every session
        kind), then the post-login landing (rule 3). None when no candidate proves a
        live session apart from a lost one: its losses are then unconfirmed."""
        if state.protected_probe:
            return
        url, status, digest = self._spa_probe(state.host, base_url, state,
                                              [base_url, *extra])
        state.protected_probe, state.probe_refusal_status = url, status
        if digest is not None:
            state.probe_refusal_digest = digest

    def _count_credential_post(self, host: str, identity: str, kind: str) -> None:
        """Count one credential POST of the account (the credential store's key, D12):
        ``submitted`` (a login's) or ``control`` (a JSON login's wrong-password control).
        A run's isolated copies count into the same account (FR-SESS-23, R15)."""
        with self._run_budget.lock:
            kinds = self._run_budget.credential_posts.setdefault(f"{host}/{identity}",
                                                                Counter())
            kinds[kind] += 1

    # -- browser login for single-page apps (FR-SESS-19, CC-SESS-0021) -------------
    def _browser_login_state(self, host: str, identity: str, base_url: str,
                             cred) -> SessionState:
        """No server-rendered form and no Basic challenge: find and perform the login in
        a browser (`session.browserlogin`), detect the credential from the login
        request's own response (`detect.detect_session_credential`), and confirm it by
        a differential on a request the app made after the click (`_spa_probe`). Every
        failure is a loud `SessionAuthError` (FR-SESS-6)."""
        from fuzzlab.session import browserlogin
        try:
            obs = browserlogin.run(self._credential_destination_ok, base_url, cred,
                                   identity=self._label or identity,
                                   auth_origins=sorted(self._auth_origins))
        except browserlogin.BrowserLoginError as exc:
            raise SessionAuthError(
                f"could not log {identity}@{host} in: no server-rendered login form or "
                f"Basic challenge at {base_url}, and the browser login failed: {exc}"
            ) from None
        if not self._credential_destination_ok(obs.login_url, base_url,
                                               floor_https=obs.floor_https):
            raise SessionAuthError(                    # the route refused it already
                f"refusing {identity}@{host}'s browser login: its request went to "
                f"{canonical_origin(obs.login_url)}")
        if not 200 <= obs.status < 300:
            raise SessionAuthError(
                f"login for {identity}@{host} was rejected: the app's login request "
                f"answered {obs.status} (credentials wrong?)")
        # the credential the login response itself established: a cookie it set, then
        # a token in its JSON body; the first one the differential confirms is kept
        found = [detect.detect_session_credential(obs.status, obs.headers, obs.body,
                                                  cookies=obs.cookies or None),
                 detect.detect_session_credential(obs.status, obs.headers, obs.body)]
        tried = []
        for detected in found:
            if detected is None or detected.kind not in ("cookie", "bearer") or \
                    detected.kind in tried:
                continue
            tried.append(detected.kind)
            # BUG-0132: the cookies the app's own JS set after the login (Juice Shop's
            # `token`) are in the browser's jar, never in the login response; a
            # requests-based send needs them too (server-rendered pages read them)
            jar = _jar_cookies(obs.storage_state, host, secure_ok=obs.floor_https)
            state = SessionState(host=host, identity=identity, kind=detected.kind,
                                 cookies={**jar, **detected.cookies},
                                 headers=dict(detected.headers),
                                 token_exp=detected.token_exp, login_url=obs.login_url,
                                 logout_url=urljoin(base_url, "logout"),
                                 secure_only=obs.floor_https,
                                 browser_state=obs.storage_state,
                                 browser_cookies=tuple(sorted(
                                     set(jar) - set(detected.cookies))),
                                 # FR-SESS-20: the login page is the base URL itself
                                 origins=self._origins_of(base_url, obs.login_url))
            probe, refusal_status, refusal_digest = self._spa_probe(host, base_url, state,
                                                                    obs.probes)
            if probe is None:
                continue
            state.protected_probe, state.probe_refusal_status = probe, refusal_status
            state.probe_refusal_digest = refusal_digest
            state.valid = True
            self._record_auth_endpoints(obs.login_url, state.logout_url)
            # its non-secret row is written when `ensure` installs it (`_install`, B3)
            self._count_credential_post(host, identity, "submitted")   # FR-SESS-23
            if self._log:
                self._log.info("authenticated (browser login)", extra=state.redacted())
            return state
        if not tried:
            raise SessionAuthError(
                f"login for {identity}@{host} submitted in the browser but no session "
                f"credential was detected in the login response (status {obs.status})")
        raise SessionAuthError(
            f"login for {identity}@{host} did not result in an authenticated session: "
            f"no request the app made after the login click answers differently without "
            f"the credential ({len(obs.probes)} candidate(s); FR-SESS-5)")

    def _spa_probe(self, host: str, base_url: str, state: SessionState,
                   candidates) -> tuple[str | None, int | None, str | None]:
        """The one owner of "this URL tells a live session from a lost one" (FR-SESS-5,
        FR-SESS-19, FR-SESS-23; PA-0507(2)): a browser login's post-click GETs (rule 1)
        and an HTTP login's operator base and post-login landing (rules 2 and 3,
        `_record_resource`) are judged by the same test. The first candidate (at most
        eight) that is in the session's origins, approved by the operator's anchor and
        not an auth endpoint, and:

        - whose **credentialed** answer is LIVE by `health_verdict` on the walk that
          stops at a login redirect (M4(a));
        - whose **anonymous** answer (only the ambient jar cookies, reviewer A-S1) and
          **corrupted** answer (`_corrupted`, M4(b): an endpoint that only reacts to
          the *presence* of a credential is never one) agree as a refusal: both LOST by
          `health_verdict`; or the same status that `admitted_refusal` admits (a
          non-2xx below 500 that SP-56 classes as the application's or a policy block,
          never a throttle, gateway or 407; B1), recorded; or the same body, stable over
          two fetches each, that differs from the credentialed body (also stable),
          recorded as its sha256.

        Returns ``(url, refusal status, refusal digest)``, or ``(None, None, None)``.
        Each fetch uses a fresh login fetcher, walked by `_navigate` inside the
        session's origins only (FR-SESS-20, O5): a candidate on another origin is never
        fetched, and a hop out of the origins is refused before it is fetched. A live
        credentialed answer's rotated session cookie is adopted."""
        floor = bool(state.secure_only)
        good, bad_headers = state.apply({}), _corrupted(state).apply({})
        # the anonymous arm carries the same ambient jar cookies the corrupted arm
        # keeps (reviewer A-S1), so the two differ only by the credential
        ambient = SessionState(state.host, state.identity, cookies={
            n: v for n, v in (state.cookies or {}).items()
            if not credential_cookie(n, str(v), state)}).apply({}) or None
        # the state as a candidate is judged: no refusal recorded yet
        bare = dataclasses.replace(state, browser_state=None, probe_refusal_status=None,
                                   probe_refusal_digest=None)
        origins = frozenset(state.origins)

        def verdict(arm) -> str:
            resp, page, stopped, _fetcher = arm
            return health_verdict(bare, resp.status, resp.headers, resp.text, page,
                                  stopped_at_login=stopped, refusal=False).state

        seen: set[str] = set()
        for url in list(candidates)[:8]:
            if not url or url in seen:
                continue
            seen.add(url)
            if canonical_origin(url) not in origins or \
                    not self._navigation_ok(url, base_url, floor) or \
                    self.is_auth_endpoint(url):
                continue
            try:
                authed = self._probe_fetch(url, base_url, floor, origins, good, state)
                if verdict(authed) != LIVE:
                    continue                                      # M4(a)
                cookies = getattr(authed[3], "cookies", None)
                _adopt_rotation(state, cookies() if callable(cookies) else None)
                arms = [self._probe_fetch(url, base_url, floor, origins, ambient, state),
                        self._probe_fetch(url, base_url, floor, origins, bad_headers,
                                          state)]
            except (SessionAuthError, *_transport_errors()):
                continue                          # an unapproved hop: not this one
            if all(verdict(arm) == LOST for arm in arms):
                return url, None, None
            statuses = {arm[0].status for arm in arms}
            if len(statuses) != 1:
                continue
            status = statuses.pop()
            if admitted_refusal(status):
                return url, status, None
            if not 200 <= status < 300:
                continue
            try:
                again = [self._probe_fetch(url, base_url, floor, origins, ambient, state),
                         self._probe_fetch(url, base_url, floor, origins, bad_headers,
                                           state)]
                authed2 = self._probe_fetch(url, base_url, floor, origins, good, state)
            except (SessionAuthError, *_transport_errors()):
                continue
            texts = {arm[0].text for arm in arms + again}
            if len(texts) == 1 and authed[0].text == authed2[0].text and \
                    200 <= authed2[0].status < 300 and authed[0].text not in texts:
                return url, None, _digest(texts.pop())
        return None, None, None

    def _probe_fetch(self, url: str, base_url: str, floor: bool,
                     origins: frozenset[str], headers, state: SessionState):
        """One fresh-fetcher walk of a resource candidate that stops at a login
        redirect: ``(response, page_url, stopped_at_login, fetcher)``."""
        fetcher = self._fetch_factory()
        resp, page, _floor = self._navigate(fetcher, url, base_url, floor,
                                            headers=headers, session_origins=origins,
                                            stop_at=state)
        return resp, page, _stopped_at_login(resp), fetcher

    def _discover_login_form(self, fetcher: Fetcher, base_url: str, *,
                             seen: set[str] | None = None):
        """Look for a login form from the base URL and a few common login paths.
        Returns ``(form, login_page_url, challenge, floor_https)``; ``challenge`` is
        ``"basic"`` when the base URL answered 401 with a Basic ``WWW-Authenticate`` (no
        form needed); ``floor_https`` is True once the base URL or any hop visited was
        https.

        Redirects are followed **by hand** (`_navigate`, BUG-0097): every hop is
        authorised against the operator's input before it is fetched, so neither a
        request nor the page's trust can leave the approved origins."""
        candidates = [base_url] + [urljoin(base_url, p) for p in
                                   ("login", "login.php", "signin", "users/login")]
        challenge = None
        floor = urlparse(base_url).scheme.lower() == "https"
        for url in candidates:
            try:
                resp, page, page_floor = self._navigate(fetcher, url, base_url, floor,
                                                        seen=seen)
            except SessionAuthError:
                raise                                   # an unapproved hop: loud
            except Exception:  # noqa: BLE001 - a bad candidate URL is not fatal
                continue
            if url == base_url and resp.status == 401:
                www = {k.lower(): v for k, v in resp.headers.items()}.get(
                    "www-authenticate", "")
                if www.lower().startswith("basic"):
                    challenge = "basic"
            form = detect.find_login_form(resp.text, page)
            if form is not None:
                return form, page, challenge, page_floor
        return None, base_url, challenge, floor

    def _navigate(self, fetcher: Fetcher, url: str, base_url: str, floor_https: bool,
                  headers: dict | None = None,
                  session_origins: frozenset[str] | None = None,
                  seen: set[str] | None = None, stop_at: SessionState | None = None):
        """GET ``url`` following at most `MAX_LOGIN_HOPS` redirects by hand. Every hop
        must pass `_navigation_ok` **before** it is fetched. A fetcher that cannot be
        told not to follow redirects must report a final URL equal to the one asked
        for, or discovery refuses (it may have followed one unchecked — A3). With
        ``session_origins`` (`verify_live`, the probe differential), a hop to any origin
        outside them -- another port of the same host included -- is refused before it
        is fetched, so ``headers`` (a session) reach those origins only (FR-SESS-20,
        O5). ``seen`` collects the canonical origin of every hop fetched (O12). With
        ``stop_at`` (a session state; FR-SESS-23's health walk), the walk stops at the
        first hop whose ``Location`` `detect.redirect_is_logout` judges a login redirect
        for that session, and returns that redirect: a login on another origin (an IdP)
        is judged at its hop and never fetched. Returns ``(response, page_url,
        floor_https)``."""
        current = url
        for _ in range(MAX_LOGIN_HOPS + 1):
            if not self._navigation_ok(current, base_url, floor_https):
                origin = canonical_origin(current)
                raise SessionAuthError(
                    f"refusing to follow the login navigation to {current}: a downgrade "
                    f"from https to http, or not the base URL's origin, an in-scope host "
                    f"or an authorised auth origin; {auth_origin_advice(origin)}")
            if session_origins is not None and \
                    canonical_origin(current) not in session_origins:
                raise SessionAuthError(
                    f"refusing to carry the session to {canonical_origin(current)}: not "
                    f"one of its origins ({', '.join(sorted(session_origins))}) "
                    f"(FR-SESS-20)")
            floor_https = floor_https or urlparse(current).scheme.lower() == "https"
            if seen is not None and canonical_origin(current) is not None:
                seen.add(canonical_origin(current))
            resp, can_refuse = _get_no_redirects(fetcher, current, headers)
            if not can_refuse and getattr(resp, "url", None) != current:
                raise SessionAuthError(
                    f"the login fetcher cannot refuse redirects and did not report that "
                    f"{current} was not redirected; refusing (it may have left scope)")
            location = {k.lower(): v for k, v in resp.headers.items()}.get("location")
            if resp.status in _REDIRECTS and location:
                if stop_at is not None and detect.redirect_is_logout(
                        location, current, stop_at.login_url):
                    return resp, current, floor_https          # a login redirect: stop
                current = urljoin(current, location)
                continue
            return resp, current, floor_https
        raise SessionAuthError(f"more than {MAX_LOGIN_HOPS} redirects from {url}")

    def _navigation_ok(self, url: str, base_url: str, floor_https: bool) -> bool:
        """May discovery fetch ``url``? The transport deny first, then an origin the
        **operator** approved — the same anchor as `_credential_destination_ok` — and
        never a destructive URL (NFR-CRAWL-safe's rule, BUG-0111), unless it is an
        **operator-supplied** base itself (BUG-0113: a base derived from a request URL
        gets no exemption)."""
        from fuzzlab.core.urls import destructive_reason, url_key
        exempt = url_key(url) == url_key(base_url) and url_key(base_url) in self._operator_bases
        if not exempt and destructive_reason(url) is not None:
            return False
        return self._credential_destination_ok(url, base_url, floor_https=floor_https)

    # -- credential destinations (BUG-0081, BUG-0092, BUG-0097) -------------
    @staticmethod
    def _transport_ok(target: str, floor_https: bool) -> bool:
        """The transport deny: an http(s) URL, and https whenever the floor is https."""
        scheme = urlparse(target).scheme.lower()
        return scheme == "https" or (scheme == "http" and not floor_https)

    def _credential_destination_ok(self, target: str, base_url: str, *,
                                   floor_https: bool = False) -> bool:
        """May credentials (or a login navigation) go to ``target``?

        **Deny first** (BUG-0092, PA-0093): the scheme must be http or https, and https
        whenever the floor is (``base_url``, any discovery hop, or the page was https);
        nothing overrides it. **The anchor is operator input only** (BUG-0097,
        PA-0098), as origins (FR-SESS-20, R3; `_login_anchors`): ``target``'s origin must
        be ``base_url``'s own, its https upgrade on the same host at the default or the
        same port, or an authorised ``auth_origins`` entry (``--auth-origin``). An
        in-scope host on another port is no longer an anchor: another port is another
        app. A URL from response content (a redirect, a form action, a page) is checked
        against this anchor, never added to it."""
        floor_https = floor_https or urlparse(base_url).scheme.lower() == "https"
        if not self._transport_ok(target, floor_https):
            return False
        origin = canonical_origin(target)
        return origin is not None and origin in self._login_anchors(base_url)

    def _login_anchors(self, base_url: str) -> frozenset[str]:
        """Where a login may go (FR-SESS-20, R3): ``base_url``'s canonical origin; for an
        http base, its https upgrade on the same host at the default port or at the
        base's own port; and the operator's ``auth_origins``. Origins only, never a
        host compare (PA-0134)."""
        out = set(origin_scope(base_url)) | set(self._auth_origins)
        parts = urlparse(base_url)
        if parts.scheme.lower() == "http" and parts.hostname:
            authority = parts.netloc.rsplit("@", 1)[-1]           # host[:port], no userinfo
            bare = authority[:authority.rfind("]") + 1] if authority.startswith("[") \
                else authority.split(":", 1)[0]
            out |= origin_scope(f"https://{bare}/", f"https://{authority}/")
        return frozenset(out)

    def _post_credentials(self, fetcher: Fetcher, url: str, data,
                          base_url: str, *, floor_https: bool = False,
                          seen: set[str] | None = None,
                          headers: dict[str, str] | None = None) -> FetchResponse:
        """POST the credentials without letting the HTTP client follow redirects: a 307 /
        308 re-sends the body (the credentials) to wherever ``Location`` says. A 301 /
        302 / 303 becomes a body-less GET, followed only to an allowed origin over an
        allowed transport (the same deny-first predicate), walked by hand like discovery:
        every later hop is checked before it is fetched, destructive URLs included
        (BUG-0123). A refused hop leaves the POST's own response to be judged."""
        resp = _post_no_redirects(fetcher, url, data, headers)
        if seen is not None and canonical_origin(url) is not None:
            seen.add(canonical_origin(url))
        location = {k.lower(): v for k, v in resp.headers.items()}.get("location")
        if resp.status in (301, 302, 303) and location:
            nxt = urljoin(url, location)
            floor = floor_https or urlparse(url).scheme.lower() == "https"
            if self._credential_destination_ok(nxt, base_url, floor_https=floor):
                try:
                    landed, _page, _floor = self._navigate(fetcher, nxt, base_url, floor,
                                                           seen=seen)
                    return landed
                except SessionAuthError as exc:
                    (self._log or _LOG).warning(f"post-login redirect not followed: {exc}")
            else:
                origin = canonical_origin(nxt)
                (self._log or _LOG).warning(
                    f"the login redirected to {origin}, which is not one of the login's "
                    f"origins (FR-SESS-20): not followed, the session is not sent there; "
                    f"{auth_origin_advice(origin)}")
        return resp                          # 307/308 never followed: judged as is

    def _basic_login(self, fetcher: Fetcher, host: str, identity: str, base_url: str,
                     cred, *, secure_only: bool | None = None) -> SessionState:
        token = base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
        state = SessionState(host=host, identity=identity, kind="basic", cookies={},
                             headers={"Authorization": f"Basic {token}"}, token_exp=None,
                             # no login page: a Basic session's logout signal is the
                             # 401/403, never a redirect to some app page (BUG-0113)
                             login_url=None, logout_url=urljoin(base_url, "logout"),
                             secure_only=urlparse(base_url).scheme.lower() == "https"
                             if secure_only is None else secure_only,
                             # FR-SESS-20: the base URL is what challenged
                             origins=self._origins_of(base_url))
        if not self._verify_authenticated(fetcher, base_url, state):
            raise SessionAuthError(
                f"HTTP Basic login for {identity}@{host} was rejected (credentials "
                f"wrong: the base URL still challenges)")
        state.valid = True
        # rule 2 for Basic too (M4(b)): the base URL that challenged; its non-secret row
        # is written when `ensure` installs it (`_install`, B3)
        self._record_resource(state, base_url)
        if self._log:
            self._log.info("authenticated", extra=state.redacted())
        return state

    def _verify_authenticated(self, fetcher: Fetcher, base_url: str,
                              state: SessionState, *,
                              seen: set[str] | None = None) -> bool:
        """Secondary sanity check that the session is usable.

        The primary login-success decision is made in ``_login`` from the login
        POST response (a rejected login re-renders the login form / answers
        401/403). This is a follow-up probe with the established session: it must
        not bounce to an auth challenge or land back on a login page. It probes
        ``base_url`` (often public), so it is a guard against an outright-broken
        session, not proof of authentication on its own — hence the POST-response
        check upstream carries the weight (BUG-0008).

        *(FR-SESS-23, R8.)* Judged by `health_verdict` (the one loss predicate), with
        today's acceptance kept: LOST (an auth failure such as a credentialed 401, or
        this session's login form) fails it; a policy block (403, 451) fails it; any
        other answer -- a throttle or a 5xx included -- accepts it. This decides login
        success, not session loss.
        """
        # the probe walks redirects hop by hop too, inside the approved origins and over
        # the transport floor, carrying the session's headers (BUG-0097)
        floor = bool(state.secure_only) or urlparse(base_url).scheme.lower() == "https"
        # the session's origins only (FR-SESS-20, R3): a hop elsewhere is refused before
        # it is fetched, so its headers (a Basic or bearer token) never go there
        probe, page, _floor = self._navigate(fetcher, base_url, base_url, floor,
                                             headers=state.headers or None, seen=seen,
                                             session_origins=state.origins)
        # Basic: no page content is read (BUG-0113); only this session's login form
        # means "not logged in", never any password field (BUG-0113)
        if health_verdict(state, probe.status, probe.headers, probe.text, page,
                          refusal=False).state == LOST:
            return False
        cls, _why = response_class(probe.status, probe.headers, complete=True,
                                   credentialed=True, credential_submission=False,
                                   redirect_to_login=False)
        return cls != POLICY_BLOCK


def _credential_items(state: SessionState) -> dict[tuple[str, str], str]:
    out = {("cookie", k): str(v) for k, v in (state.cookies or {}).items()}
    out.update({("header", k): str(v) for k, v in (state.headers or {}).items()})
    return out


def _identifier_like(name: str, value: str) -> bool:
    """An equal credential that identifies a session: a sensitive name, an
    identifier-looking value (the shared predicate), or a long value (local policy)."""
    return (is_sensitive_name(name) or looks_like_identifier(value)
            or len(value) >= DISTINCT_MIN_LEN)


def distinctness_problem(new: SessionState, other: SessionState) -> str | None:
    """Why ``new`` is not a separate server-side session from ``other``, or None.

    Basic auth has no server-side session to re-bind (and the seam adopts no cookie),
    so it is distinct. Otherwise ``new`` must carry a credential, at least one of its
    cookie or header values must differ, and no credential with the same name may have
    the same identifier-like value (`_identifier_like`). The reason names the
    credential, never its value (FR-SESS-17)."""
    if new.kind == "basic":
        return None
    mine, theirs = _credential_items(new), _credential_items(other)
    if not mine:
        return "it carries no session credential"
    for (where, name), value in mine.items():
        if theirs.get((where, name)) == value and _identifier_like(name, value):
            return f"{where} {name!r} has the same identifier-like value"
    if all(theirs.get(key) == value for key, value in mine.items()):
        return "every credential is the same"
    return None


#: The most redirects login discovery follows from one candidate URL (BUG-0097).
MAX_LOGIN_HOPS = 5


#: A cookie value at least this long is matched by containment in `_carries` (T2).
CARRIED_MIN_LEN = 8


def _carries(request, state: SessionState) -> bool:
    """Does ``request`` carry any of ``state``'s secrets? What `prepare` applied, as
    `authorize` sees it (R7, narrowed in review round 2, T2):

    * a **secret-looking** value -- any Authorization value or its token, and a cookie
      value that `core.redaction.looks_like_identifier` holds for or that is at least
      `CARRIED_MIN_LEN` long -- counts when it is **contained** anywhere in the
      request's headers (an edited ``sid=<v>'OR1`` still carries it);
    * any other cookie (``language=en``, ``security=low``) counts only as its exact
      ``name=value`` pair in the ``Cookie`` header: a short plain value is common
      text (``en`` in ``Accept-Language``), and containment would refuse an
      anonymous request's own edit."""
    secrets: set[str] = set()
    for value in (state.headers or {}).values():
        _scheme, sep, token = str(value).partition(" ")
        secrets |= {str(value), token} if sep else {str(value)}
    pairs: set[str] = set()
    for name, value in (state.cookies or {}).items():
        value = str(value)
        if looks_like_identifier(value) or len(value) >= CARRIED_MIN_LEN:
            secrets.add(value)
        elif value:
            pairs.add(f"{name}={value}")
    secrets.discard("")
    headers = {str(k).lower(): str(v) for k, v in (request.headers or {}).items()}
    if any(secret in value for secret in secrets for value in headers.values()):
        return True
    sent_pairs = {p.strip() for p in headers.get("cookie", "").split(";")}
    return bool(pairs & sent_pairs)


def _check_origin(state: SessionState, url: str) -> None:
    """Never hand out a session for a URL whose origin is not one of its origins
    (FR-SESS-20, O10): `session_header(s)`, ``fuzzlab session print``."""
    origin = canonical_origin(url)
    if origin is None or origin not in state.origins:
        raise SessionAuthError(
            f"refusing to hand out the session of {state.identity}@{state.host} for "
            f"{origin}: not one of its origins ({', '.join(sorted(state.origins))}); "
            f"{DISTINCT_IDENTITY_ADVICE}")


def _check_transport(state: SessionState, url: str) -> None:
    """Never send an https-established session's secrets over http (BUG-0098)."""
    if state.secure_only and urlparse(url).scheme.lower() != "https":
        raise SessionAuthError(
            f"refusing to send the https session of {state.identity}@{state.host} over "
            f"plain http ({url.split('?', 1)[0]})")


def _accepts_allow_redirects(method) -> bool:
    import inspect
    try:
        params = inspect.signature(method).parameters
    except (TypeError, ValueError):
        return False
    return "allow_redirects" in params or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _get_no_redirects(fetcher, url: str,
                      headers: dict | None = None) -> tuple[FetchResponse, bool]:
    """``(fetcher.get(url) with redirects off, whether it could be told so)``."""
    if _accepts_allow_redirects(fetcher.get):
        return fetcher.get(url, headers=headers, allow_redirects=False), True
    return fetcher.get(url, headers=headers), False


def _post_no_redirects(fetcher, url: str, data, headers=None) -> FetchResponse:
    """``fetcher.post`` with redirects off. A fetcher without the keyword (an old test
    double, which never follows redirects anyway) is called without it. ``headers`` (a
    JSON login's content type, FR-SESS-21) are passed only when given."""
    import inspect
    try:
        params = inspect.signature(fetcher.post).parameters
    except (TypeError, ValueError):
        params = {}
    extra = {"headers": headers} if headers else {}
    if "allow_redirects" in params or any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return fetcher.post(url, data=data, allow_redirects=False, **extra)
    return fetcher.post(url, data=data, **extra)


#: Appended to the password for a JSON login's wrong-password control (FR-SESS-21).
WRONG_SUFFIX = "-fuzzlab-wrong"


def _json_token(text: str) -> str | None:
    """A token in a JSON answer (`detect.find_token_in_json`), or None."""
    try:
        return detect.find_token_in_json(json.loads(text or ""))
    except (ValueError, TypeError):
        return None


def _directory(url: str) -> str:
    """``url``'s directory: scheme, host and the path up to its last ``/``, with no
    query or fragment (``/app/x.php?q=1`` -> ``/app/``). A discovery base derived from
    a request (BUG-0113)."""
    parts = urlparse(url)
    path = parts.path or "/"
    return f"{parts.scheme}://{parts.netloc}{path[:path.rfind('/') + 1]}"


def _corrupt_token(token: str) -> str:
    """``token`` with its last character flipped: within the base64url alphabet the
    flip changes the character's high bits (index XOR 32), so a decoder that ignores a
    final segment's unused low bits still sees another value."""
    import string
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
    if not token:
        return "x"
    last = token[-1]
    new = alphabet[alphabet.index(last) ^ 32] if last in alphabet else \
        ("A" if last != "A" else "B")
    return token[:-1] + new


def _corrupted(state: SessionState) -> SessionState:
    """A copy of ``state`` with an invalid credential of the same shape (A-M1,
    BUG-0132), never stored:

    * a bearer token with its last character flipped (`_corrupt_token`);
    * a cookie whose value equals that token (the app's JS copy of it, Juice Shop's
      ``token`` cookie) carries the **same** corrupted token, so neither arm can keep
      the corrupted request authenticated through the other;
    * every other credential cookie -- one the login response set, or a jar cookie
      that looks like an identifier (`_identifier_like`) -- a random value under the
      same name;
    * an ambient jar cookie (a short, non-identifier value: a language or a banner
      choice) as it is: it is the request's shape, not its credential."""
    import dataclasses
    import secrets
    headers, tokens = {}, {}
    for name, value in (state.headers or {}).items():
        scheme, sep, token = str(value).partition(" ")
        bad = _corrupt_token(token if sep else str(value))
        headers[name] = f"{scheme} {bad}" if sep else bad
        tokens[token if sep else str(value)] = bad
    cookies = {}
    for name, value in (state.cookies or {}).items():
        value = str(value)
        if value in tokens:
            cookies[name] = tokens[value]
        elif credential_cookie(name, value, state):
            cookies[name] = secrets.token_hex(max(8, len(value) // 2))
        else:
            cookies[name] = value
    return dataclasses.replace(state, headers=headers, cookies=cookies,
                               browser_state=None)


def _header_tokens(state: SessionState) -> set[str]:
    """The credential values of ``state``'s headers (a bearer's token, a whole header
    value when it has no scheme)."""
    out = set()
    for value in (state.headers or {}).values():
        _scheme, sep, token = str(value).partition(" ")
        out.add(token if sep else str(value))
    return out


def credential_cookie(name: str, value: str, state: SessionState) -> bool:
    """Is cookie ``name=value`` of ``state`` a credential (BUG-0132, reviewer B)? The one
    predicate (PA-0003) the corrupted arm (`_corrupted`) and the crawler's session check
    (`browserauth.BrowserSession.checked_cookies`) share. A cookie the login response
    set is one. A cookie a browser login took from the app's jar
    (`SessionState.browser_cookies`) is one when its value equals a detected credential
    token (the app's copy of the bearer, Juice Shop's ``token``), or it looks like an
    identifier (`_identifier_like`: a sensitive name, an identifier-like or a long
    value). Only an ambient jar cookie (short and plain, e.g. a language choice) is
    not."""
    value = str(value)
    if name not in set(state.browser_cookies or ()):
        return True
    return value in _header_tokens(state) or _identifier_like(name, value)


def _jar_cookies(storage: dict | None, host: str, *, secure_ok: bool,
                 now: float | None = None) -> dict[str, str]:
    """The browser jar's cookies a requests-based send of this session may carry
    (BUG-0132): from a ``storage_state`` already cleaned of the password and filtered
    to the login scope (`browserlogin.drop_secret_values`, `filter_storage_state`),
    those whose domain matches the session's ``host`` (canonical: loopback aliases one
    host), not expired, and not ``secure`` unless the session is https-only
    (``secure_ok``: then every send of it is over https, FR-SESS-13). They then go
    through the session's one cookie path (`SessionState.apply`, sent only to the
    session's origins by `prepare`, FR-SESS-20, under its transport floor). An IP host matches only
    its own address (no parent domain, reviewer A-N2). A cookie's ``path`` is not kept:
    it is sent host-wide (a stated residual, FR-SESS-19)."""
    import time

    from fuzzlab.session.browserlogin import canonical_host
    import ipaddress
    now = time.time() if now is None else now
    mine = canonical_host(f"http://{host}/")
    try:                    # an IP host has no parent domain: exact match only (A-N2)
        ipaddress.ip_address((mine or "").strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False
    out: dict[str, str] = {}
    for c in (storage or {}).get("cookies", []) or []:
        domain = canonical_host("http://" + str(c.get("domain") or "").lstrip(".") + "/")
        if not domain or not mine or not (
                mine == domain or (not is_ip and mine.endswith("." + domain))):
            continue
        if c.get("secure") and not secure_ok:
            continue
        expires = c.get("expires")
        if isinstance(expires, (int, float)) and expires > 0 and expires < now:
            continue
        if c.get("name"):
            out[str(c["name"])] = str(c.get("value") or "")
    return out


def _digest(text: str | None) -> str:
    import hashlib
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def _text(body) -> str:
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return body or ""
