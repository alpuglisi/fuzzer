"""AU-SESS403 revision 3: a run-time prototype of the drafted design (DRAFT-AU-SESS403.md §3).

Not part of fuzzlab, and never collected by pytest. ``install()`` patches the drafted
behaviour onto ``fuzzlab.session.manager.SessionManager`` and ``fuzzlab.session.detect``,
so ``tests/test_session_forbidden_answers.py`` can be run:

- against the design before it is implemented (``-p proto_plugin``);
- against each named revert (``REVERT=<name>``). This is how reviewer B measured
  masking (``scratchpad/revB403/masked_reverts.py``).

Phase 2 implements the design in ``fuzzlab/`` and deletes this directory.

Status literals are allowed here: SP-56's guard scans ``fuzzlab/`` only. The
implementation decides through ``core.comparability`` exactly as the comments say.

``prepare`` and ``ensure`` are re-implemented here (copies of the base bodies, with the
design's additions), because the design puts its work inside them: the generation is
set from the state ``prepare`` applied (F4), and the re-login token is drawn under the
login lock (F5). The login lock is re-entrant here only so this wrapper can hold it
around the base ``ensure``; Phase 2 draws the token inside ``ensure`` itself.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import threading
import time
from collections import Counter
from urllib.parse import parse_qsl, urljoin, urlparse, urlsplit

REVERT = os.environ.get("REVERT", "")
#: Every revert this prototype can apply (``run_reverts.sh`` names the tests each must
#: fail): the design with one decision undone.
REVERTS = {
    "403": "detect_logout reads a 403 as a loss again (the old `status in (401, 403)` line)",
    "throttle": "a throttle answer (429, 503) is a loss signal",
    "throttle_refusal": "the resource's refusal status admits any non-2xx below 500 both refusal arms agree on, a throttle (429) or a 407 included (revision 2's admission; B1, P1)",
    "throttle_verdict": "health_verdict matches the recorded refusal status before it reads a throttle, gateway, 407 or incomplete answer as inconclusive (revision 2's order; B1)",
    "noconfirm": "observe marks a suspected loss lost without check_health",
    "nosubmission": "the credential-submission fact is dropped (always False)",
    "submission_ignored": "a credential submission's loss shape never triggers a check",
    "nogen": "observe does not compare the request's generation with the state's",
    "noflight": "waiters do not re-check under the lock (no live verdict covers an earlier signal)",
    "cover_at_record": "a live verdict's sequence number is taken when it is recorded, so it covers signals seen while its GET was in flight (revision 2; B2, P2)",
    "nocache": "no live cache",
    "cache_nogen": "the live cache is keyed without the generation",
    "cache_nourl": "the live cache is keyed without the signal's URL key",
    "foreign": "a request with a foreign header does not bypass the cache",
    "rule2verify": "the base URL is the resource when discovery was redirected and _verify_authenticated passed (revision 1's rule 2)",
    "nocorrupt": "the resource differential has no corrupted arm",
    "norefusal": "the resource's refusal status is not recorded or consulted",
    "nostop": "the health walk follows a login redirect instead of stopping at it",
    "redirect_live": "health_verdict reads a stop at a login redirect as LIVE",
    "content_rule_off": "detect_logout loses its 200 login-form rule",
    "basic_content": "health_verdict and observe read a Basic session's page content (BUG-0113's exception dropped)",
    "nosticky": "SessionHealthUnknown is not sticky",
    "nobudget": "no per-run pause budget",
    "nobucket": "re-logins are not limited",
    "nores_waits": "a no-resource identity whose re-login budget is spent waits for a token and then goes sticky unknown (revision 2), instead of carrying on at once (the owner's decision D)",
    "notify_pause": "a loss found by a pause re-check tells the listeners",
    "verifylive_false": "verify_live returns False on an inconclusive check",
    "verifylive_cache": "verify_live reads the live cache",
    "verifylive_clears_sticky": "verify_live's inconclusive branch clears an existing sticky unknown (revision 2; P3)",
    "verifylive_budget": "verify_live's waits are charged to the run's pause budget for prepare",
    "nocas": "the health check and _mark_lost do not compare-and-set against the current state and the generation judged, and prepare waits a pause of any generation (B3, P4)",
    "inconclusive_lost": "an inconclusive check is read as LOST",
    "inconclusive_live": "an inconclusive check is read as LIVE (no pause)",
    "hop_pauses": "an unapproved hop pauses instead of failing fast",
    "noadopt": "a live health answer's rotated session cookie is not adopted",
    "relogin_under_health_lock": "observe re-logs in at once while still holding the health lock",
    "policy_nocheck": "a policy block (403, 451) never triggers the check, even with a resource",
    "noentrynames": "request_entry_names returns nothing (a credential field name is missed)",
    "nocount": "credential POSTs are not counted",
    "publicbase": "the byte rule accepts a page whose refused and credentialed bodies are the same",
    "nogenrecord": "prepare does not record the generation on the request",
    "nologinlock": "ensure takes a fresh lock per call (no single flight)",
    "policy_loss": "detect_logout reads any policy block (403, 451) as a loss",
    "norule2": "the base URL is never a resource candidate (rule 2 dropped; the landing only)",
    "rule2_cookie_only": "rule 2 runs for cookie sessions only (M4(b) undone for Basic)",
    # T19's guard with one write form or the predicate call left unseen (proto_plugin
    # re-executes the test module's `loss_decision_offenders` with that branch off).
    "guard_noassign": "T19's guard misses an assignment to `.valid`",
    "guard_nosetattr": "T19's guard misses `setattr(x, 'valid', v)`",
    "guard_nodunder": "T19's guard misses `object.__setattr__(x, 'valid', v)` and `x.__setattr__('valid', v)`",
    "guard_nokeyword": "T19's guard misses a `valid=` keyword (dataclasses.replace)",
    "guard_nocall": "T19's guard misses a call of detect_logout outside its callers",
}
if REVERT and REVERT not in REVERTS:
    raise SystemExit(f"unknown REVERT {REVERT!r}; one of {sorted(REVERTS)}")

LIVE, LOST, INCONCLUSIVE, STALE = "live", "lost", "inconclusive", "stale"
_LOG = logging.getLogger("fuzzlab.session.health")
_INSTALLED = False


def skips_when_spent(state) -> bool:
    """The owner's decision D: which identity carries on at once when its re-login budget
    is spent -- one with no stable protected resource. A measurement may replace this
    module attribute to price an alternative (``measure_r3.py``); the design is this."""
    return not getattr(state, "protected_probe", None)


@dataclasses.dataclass(frozen=True)
class Health:
    """A health check's verdict for one session generation. ``reason`` names a class
    and a status only, never a URL, header value or body."""
    state: str
    reason: str = ""
    generation: int | None = None
    retry_after_s: float | None = None


@dataclasses.dataclass
class _Rec:
    """Per-(host, identity) health record of one manager (in memory)."""
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)
    live: dict = dataclasses.field(default_factory=dict)          # (gen, urlkey) -> at
    live_seq: dict = dataclasses.field(default_factory=dict)      # gen -> seq the LIVE GET was SENT at
    verdict: tuple | None = None                                  # (gen, state)
    pause: dict | None = None                                     # gen, until, step, began
    unknown: str | None = None                                    # sticky reason
    tokens: float | None = None
    refill_at: float = 0.0
    relogin_due: bool = False
    report: Counter = dataclasses.field(default_factory=Counter)


@dataclasses.dataclass
class _Shared:
    """What a run's manager shares with its isolated copies (F3): the pause budgets and
    the credential POSTs per account. A peer (another identity) has its own manager and
    so its own `_Shared` (`make_probe_sender` per identity, `auto_cli.py:381-389`)."""
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)
    prepare_s: float = 0.0           # spent by prepare's pauses and the bucket's waits
    verify_s: float = 0.0            # spent by verify_live's own waits, never prepare's
    credential_posts: dict = dataclasses.field(default_factory=dict)   # account -> Counter


def request_entry_names(url, body, content_type) -> tuple[str, ...]:
    """SP-16 (FR-SESS-23): the names a request carries -- its query's, a urlencoded
    body's, a JSON body's leaves by `jsonbody.display_name`; at most 64 KiB of body;
    multipart not read. Total: odd input reads as ``()``."""
    from fuzzlab.core import jsonbody
    if REVERT == "noentrynames":
        return ()
    names: list = []
    try:
        names += [k for k, _v in parse_qsl(urlsplit(url or "").query,
                                          keep_blank_values=True)]
    except (ValueError, TypeError):
        pass
    if isinstance(body, (bytes, bytearray)) and body:
        raw, ct = bytes(body[:65536]), str(content_type or "").lower()
        try:
            if "json" in ct:
                doc = jsonbody.loads(raw.decode("utf-8"))
                names += [jsonbody.display_name(p) for p, _v in (jsonbody.leaves(doc) or [])]
            elif "multipart" not in ct:
                names += [k for k, _v in parse_qsl(raw.decode("latin-1"),
                                                  keep_blank_values=True)]
        except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
            pass
    return tuple(n for n in names if isinstance(n, str) and n)


def _content_type(headers) -> str:
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type":
            return str(v)
    return ""


def _retry_after(headers) -> float | None:
    for k, v in (headers or {}).items():
        if str(k).lower() == "retry-after":
            try:
                return max(0.0, min(60.0, float(str(v).strip())))
            except ValueError:
                return None
    return None


def install() -> None:
    """Patch the drafted behaviour in (idempotent)."""
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True
    import requests

    from fuzzlab.core.comparability import (APPLICATION, AUTH_FAILURE, GATEWAY, INCOMPLETE,
                                            POLICY_BLOCK, THROTTLE_OR_UNAVAILABLE,
                                            response_class)
    from fuzzlab.core.urls import canonical_origin, url_key
    from fuzzlab.session import detect
    from fuzzlab.session import manager as M
    from fuzzlab.session.state import SessionState

    class SessionHealthUnknown(M.SessionAuthError):
        """An identity's session state stayed unknown past the pause bound or the run's
        pause budget. Sticky: every later `prepare` for it raises at once (FR-SESS-23)."""

    class IsolatedHealthUnknown(M.IsolatedLoginFailed):
        """An isolated copy's session state stayed unknown (FR-SESS-17's one class)."""

    M.SessionHealthUnknown = SessionHealthUnknown
    M.IsolatedHealthUnknown = IsolatedHealthUnknown
    M.Health = Health
    M.LIVE, M.LOST, M.INCONCLUSIVE, M.STALE = LIVE, LOST, INCONCLUSIVE, STALE
    detect.request_entry_names = request_entry_names
    net_errors = (requests.RequestException,)

    def _classes(status, headers):
        """SP-56's class of an answer to the credentialed health GET, and of the same
        answer to an uncredentialed request (a 407 is an auth failure either way)."""
        mine, why = response_class(status, headers, complete=True, credentialed=True,
                                   credential_submission=False, redirect_to_login=False)
        anyone, _w = response_class(status, headers, complete=True, credentialed=False,
                                    credential_submission=False, redirect_to_login=False)
        return mine, anyone, why

    def not_the_applications(status, headers) -> bool:
        """B1: a throttle, gateway, 407 or incomplete answer is never evidence about the
        session (SP-56 first)."""
        mine, anyone, _why = _classes(status, headers)
        return mine in (INCOMPLETE, THROTTLE_OR_UNAVAILABLE, GATEWAY) or \
            (mine == AUTH_FAILURE and anyone == AUTH_FAILURE)

    def admitted_refusal(status) -> bool:
        """B1: the resource's refusal status is a non-2xx below 500 that SP-56 classes as
        the application's answer or a policy block, read as the credentialed health GET
        will be read: never a throttle, a gateway or a 407."""
        if isinstance(status, bool) or not isinstance(status, int) or \
                200 <= status < 300 or status >= 500 or status <= 0:
            return False
        if REVERT == "throttle_refusal":
            return True
        return _classes(status, {})[0] in (APPLICATION, POLICY_BLOCK)

    # --- SP-16: the one predicate "this answer is a loss" (detect_logout) -----------
    def detect_logout(status, headers, body, login_url=None, page_url=None,
                      content_check=True, login_fields=None, *, credentialed=True,
                      credential_submission=False):
        if REVERT == "403" and status in (401, 403):
            return True
        if REVERT == "throttle" and status in (429, 503):
            return True
        if REVERT == "policy_loss" and status in (403, 451):
            return True
        location = ""
        try:
            location = next((str(v) for k, v in dict(headers or {}).items()
                             if str(k).lower() == "location"), "")
        except (TypeError, ValueError):
            location = ""
        try:
            to_login = bool(location) and detect.redirect_is_logout(location, page_url,
                                                                    login_url)
        except (ValueError, TypeError):
            to_login = False
        mine, _w = response_class(status, headers, complete=True,
                                  credentialed=credentialed is not False,
                                  credential_submission=credential_submission,
                                  redirect_to_login=to_login)
        anyone, _w = response_class(status, headers, complete=True, credentialed=False,
                                    credential_submission=credential_submission,
                                    redirect_to_login=to_login)
        if mine == AUTH_FAILURE and anyone != AUTH_FAILURE:   # never an intermediary's 407
            return True
        if REVERT != "content_rule_off" and status == 200 and content_check and \
                credentialed is not False and not credential_submission:
            if login_url and page_url:
                return detect.shows_login_form(body, page_url, login_url, login_fields)
            return detect.is_login_page(body)
        return False

    detect.detect_logout = detect_logout

    # --- the verdict: one owner, public (FR-SESS-23; disco may read it) -------------
    def health_verdict(state, status, headers, body, page_url, *,
                       stopped_at_login=False, refusal=True) -> Health:
        gen = getattr(state, "generation", None)
        if stopped_at_login:
            if REVERT == "redirect_live":
                return Health(LIVE, "", gen)
            return Health(LOST, f"a login redirect ({status})", gen)
        # B1: SP-56 first -- a throttle, gateway, 407 or incomplete answer is
        # inconclusive before any refusal status is matched
        if REVERT != "throttle_verdict" and not_the_applications(status, headers):
            return Health(INCONCLUSIVE, _classes(status, headers)[2], gen,
                          _retry_after(headers))
        content = state.kind != "basic" or REVERT == "basic_content"
        if detect.detect_logout(status, headers, body, login_url=state.login_url,
                                page_url=page_url, content_check=content,
                                login_fields=state.login_fields, credentialed=True,
                                credential_submission=False):
            return Health(LOST, f"an auth failure ({status})", gen)
        rs = getattr(state, "probe_refusal_status", None)
        if refusal and REVERT != "norefusal" and rs is not None and status == rs:
            return Health(LOST, f"the resource's refusal status ({status})", gen)
        if 200 <= status < 300:
            if refusal and state.probe_refusal_digest and \
                    M._digest(body) == state.probe_refusal_digest:
                return Health(LOST, f"the resource's refusal body ({status})", gen)
            return Health(LIVE, "", gen)
        _m, _a, why = _classes(status, headers)
        return Health(INCONCLUSIVE, why or f"another status ({status})", gen,
                      _retry_after(headers))

    M.health_verdict = health_verdict

    # --- a plain (seam-like) fetcher for health GETs ------------------------------
    def plain_fetch_factory():
        """``requests.request`` per hop, as the seam sends (no Session, no browser
        headers), with a 15 s timeout per hop (connect and read): its own response
        cookies are kept to adopt a rotation."""
        def factory():
            class _Plain:
                def __init__(self):
                    self._jar = {}

                def get(self, url, headers=None, allow_redirects=True):
                    r = requests.request("GET", url, headers=headers, timeout=15,
                                         allow_redirects=allow_redirects)
                    self._jar.update(r.cookies.get_dict())
                    return M.FetchResponse(r.status_code, dict(r.headers), r.text, r.url,
                                           M._hops(r))

                def post(self, url, data=None, headers=None, allow_redirects=True):
                    raise RuntimeError("a health fetcher never posts")

                def cookies(self):
                    return dict(self._jar)
            return _Plain()
        return factory

    # --- __init__ and copies -------------------------------------------------------
    orig_init = M.SessionManager.__init__

    def __init__(self, *args, health_ttl_s=30.0, relogin_burst=5, relogin_refill_s=120.0,
                 max_pause_s=300.0, pause_budget_s=600.0, clock=None, sleep=None,
                 health_fetch_factory=None, **kw):
        orig_init(self, *args, **kw)
        ff = kw.get("fetch_factory", args[2] if len(args) > 2 else None)
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._health_ttl_s = float(health_ttl_s)
        self._relogin_burst = int(relogin_burst)
        self._relogin_refill_s = float(relogin_refill_s)
        self._max_pause_s = float(max_pause_s)
        self._pause_budget_s = float(pause_budget_s)
        self._shared = _Shared()
        self._health_ff = health_fetch_factory or \
            (plain_fetch_factory() if ff is None else self._fetch_factory)
        self._hrecs: dict = {}
        self._gens: dict = {}
        self._tl = threading.local()
        self._seq_lock = threading.Lock()
        self._seq = 0
        if REVERT == "nologinlock":
            self._lock_for = lambda host, identity: threading.RLock()

    M.SessionManager.__init__ = __init__

    def _lock_for(self, host, identity):
        """The login lock, re-entrant in this prototype only (see the module doc)."""
        with self._locks_guard:
            key = (host, identity)
            lock = self._locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._locks[key] = lock
            return lock

    M.SessionManager._lock_for = _lock_for

    orig_isolated_copy = M.SessionManager.isolated_copy

    def isolated_copy(self, identity, *, ordinal, max_logins=3):
        copy = orig_isolated_copy(self, identity, ordinal=ordinal, max_logins=max_logins)
        for name in ("_clock", "_sleep", "_health_ttl_s", "_relogin_burst",
                     "_relogin_refill_s", "_max_pause_s", "_pause_budget_s", "_health_ff",
                     "_shared"):                        # F3: the run's budgets, shared
            setattr(copy, name, getattr(self, name))
        return copy

    M.SessionManager.isolated_copy = isolated_copy

    def _hrec(self, host, identity) -> _Rec:
        with self._locks_guard:
            rec = self._hrecs.get((host, identity))
            if rec is None:
                rec = self._hrecs[(host, identity)] = _Rec()
            return rec

    M.SessionManager._hrec = _hrec

    def _bump(self, rec, key, n=1) -> None:
        with self._locks_guard:
            rec.report[key] += n

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._seq += 1
            return self._seq

    def _charge(self, which, seconds) -> None:
        with self._shared.lock:
            setattr(self._shared, which, getattr(self._shared, which) + seconds)

    def health_report(self) -> dict:
        """Counts per (host, identity): classes seen, signals, checks and outcomes,
        pauses, re-logins (drawn and skipped); credential POSTs per account; the seconds
        spent by prepare's and verify_live's waits. No URL, value or body."""
        out = {f"{h}/{i}": dict(r.report) for (h, i), r in self._hrecs.items()}
        with self._shared.lock:
            out["credential_posts"] = {a: dict(c) for a, c in
                                       self._shared.credential_posts.items()}
            out["paused_s"] = self._shared.prepare_s
            out["verify_paused_s"] = self._shared.verify_s
        return out

    M.SessionManager.health_report = health_report

    # --- generations: every login and adopt -----------------------------------------
    def _next_gen(self, host, identity) -> int:
        with self._locks_guard:
            n = self._gens.get((host, identity), 0) + 1
            self._gens[(host, identity)] = n
            return n

    orig_login = M.SessionManager._login

    def _login(self, host, identity, base_url):
        self._tl.landing = None
        self._tl.base_redirected = False
        self._tl.account = f"{host}/{identity}"
        state = orig_login(self, host, identity, base_url)
        state.generation = _next_gen(self, host, identity)
        rec = _hrec(self, host, identity)
        with rec.lock:                    # login -> health: the one allowed lock order
            rec.pause = None              # a new generation ends the old one's pause
        _bump(self, rec, "logins")
        return state

    M.SessionManager._login = _login

    orig_adopt = M.SessionManager.adopt

    def adopt(self, state, *, protected_probe=None, refusal_status=None):
        if refusal_status is not None and not admitted_refusal(refusal_status):
            raise M.SessionAuthError("a refusal status must be the application's answer "
                                     "or a policy block (SP-56), never a throttle, a "
                                     "gateway or a 407")
        if protected_probe is not None:
            state.protected_probe = protected_probe
            state.probe_refusal_status = refusal_status
        # numbered before it is installed: no window where the current state has none
        state.generation = _next_gen(self, state.host, state.identity)
        return orig_adopt(self, state)

    M.SessionManager.adopt = adopt

    # --- credential POSTs counted per account (M10, F7) -----------------------------
    orig_post = M.SessionManager._post_credentials

    def _post_credentials(self, fetcher, url, data, base_url, **kw):
        resp = orig_post(self, fetcher, url, data, base_url, **kw)
        raw = data if isinstance(data, (bytes, bytearray)) else repr(data).encode()
        kind = "control" if M.WRONG_SUFFIX.encode() in raw else "submitted"
        if REVERT != "nocount":
            account = getattr(self._tl, "account", None) or "?"
            with self._shared.lock:
                self._shared.credential_posts.setdefault(account, Counter())[kind] += 1
        self._tl.landing = getattr(resp, "url", None)
        return resp

    M.SessionManager._post_credentials = _post_credentials

    orig_discover = M.SessionManager._discover_login_form

    def _discover_login_form(self, fetcher, base_url, *, seen=None):
        out = orig_discover(self, fetcher, base_url, seen=seen)
        form, page = out[0], out[1]
        self._tl.base_redirected = form is not None and page != base_url
        return out

    M.SessionManager._discover_login_form = _discover_login_form

    # --- the walk that stops at a login redirect ------------------------------------
    def _navigate_stop(self, fetcher, url, base_url, floor_https, headers,
                       session_origins, state):
        current = url
        for _ in range(M.MAX_LOGIN_HOPS + 1):
            if not self._navigation_ok(current, base_url, floor_https):
                raise M.SessionAuthError(f"refusing a health hop to {canonical_origin(current)}")
            if session_origins is not None and \
                    canonical_origin(current) not in session_origins:
                raise M.SessionAuthError(f"refusing to carry the session to "
                                         f"{canonical_origin(current)} (FR-SESS-20)")
            floor_https = floor_https or urlparse(current).scheme.lower() == "https"
            resp, can_refuse = M._get_no_redirects(fetcher, current, headers)
            if not can_refuse and getattr(resp, "url", None) != current:
                raise M.SessionAuthError("the fetcher cannot refuse redirects")
            location = {k.lower(): v for k, v in resp.headers.items()}.get("location")
            if resp.status in (301, 302, 303, 307, 308) and location:
                if REVERT != "nostop" and detect.redirect_is_logout(location, current,
                                                                    state.login_url):
                    return resp, current, True
                current = urljoin(current, location)
                continue
            return resp, current, False
        raise M.SessionAuthError(f"more than {M.MAX_LOGIN_HOPS} redirects")

    M.SessionManager._navigate_stop = _navigate_stop

    def _adopt_rotation(state, jar) -> None:
        """A live answer that set a new value for one of the session's own cookies (a
        rotating id) is adopted, so the check never kills its own session."""
        if REVERT == "noadopt":
            return
        for name, value in (jar or {}).items():
            if name in (state.cookies or {}) and value and state.cookies[name] != value:
                state.cookies[name] = value

    # --- the stable protected resource (rules 1-4; M4, M5, B1) ----------------------
    def _select_resource(self, state, base_url, candidates, *, ff=None):
        """``(url, refusal_status, refusal_digest)``: the first candidate whose
        credentialed answer is LIVE on the stop_at walk, and whose anonymous and
        corrupted answers agree as a refusal -- both lost-shaped, both the same admitted
        status (`admitted_refusal`, B1), or both the same stable 2xx body apart from the
        credentialed one (`_spa_probe`'s byte rule)."""
        ff = ff or self._fetch_factory
        floor = bool(state.secure_only) or urlparse(base_url).scheme.lower() == "https"
        good = state.apply({})
        bad = M._corrupted(state).apply({})
        ambient = SessionState(state.host, state.identity, cookies={
            n: v for n, v in (state.cookies or {}).items()
            if not M.credential_cookie(n, str(v), state)}).apply({}) or None
        origins = frozenset(state.origins)
        bare = dataclasses.replace(state, browser_state=None)
        bare.probe_refusal_status, bare.probe_refusal_digest = None, None

        def fetch(url, headers):
            f = ff()
            resp, page, stopped = _navigate_stop(self, f, url, base_url, floor, headers,
                                                 origins, state)
            return resp, page, stopped, f

        def verdict(arm):
            resp, page, stopped, _f = arm
            return health_verdict(bare, resp.status, resp.headers, resp.text, page,
                                  stopped_at_login=stopped, refusal=False).state

        seen: set = set()
        for url in candidates:
            if not url or url in seen:
                continue
            seen.add(url)
            if canonical_origin(url) not in origins or \
                    not self._navigation_ok(url, base_url, floor) or \
                    self.is_auth_endpoint(url):
                continue
            try:
                authed = fetch(url, good)
                if verdict(authed) != LIVE:
                    continue                                   # M4(a)
                _adopt_rotation(state, authed[3].cookies())
                anon = fetch(url, ambient)
                arms = [anon] if REVERT == "nocorrupt" else [anon, fetch(url, bad)]
            except (M.SessionAuthError, *net_errors):
                continue
            if all(verdict(a) == LOST for a in arms):
                return url, None, None
            statuses = {a[0].status for a in arms}
            if len(statuses) == 1:
                status = statuses.pop()
                if admitted_refusal(status):
                    return url, (None if REVERT == "norefusal" else status), None
                if 200 <= status < 300:
                    try:
                        again = [fetch(url, ambient)] + \
                            ([] if REVERT == "nocorrupt" else [fetch(url, bad)])
                        authed2 = fetch(url, good)
                    except (M.SessionAuthError, *net_errors):
                        continue
                    texts = {a[0].text for a in arms + again}
                    if REVERT == "publicbase" and len(texts) == 1:
                        return url, None, None
                    if len(texts) == 1 and authed[0].text == authed2[0].text and \
                            authed[0].text not in texts:
                        return url, None, M._digest(texts.pop())
        return None, None, None

    M.SessionManager._select_resource = _select_resource

    def _record_resource(self, state, base_url, extra=()):
        if getattr(state, "protected_probe", None):
            return
        if REVERT == "rule2verify" and getattr(self._tl, "base_redirected", False):
            state.protected_probe, state.probe_refusal_status = base_url, None
            return
        rule2 = REVERT != "norule2" and not (REVERT == "rule2_cookie_only"
                                             and state.kind != "cookie")
        url, rs, digest = _select_resource(self, state, base_url,
                                           [*([base_url] if rule2 else []), *extra])
        state.protected_probe = url
        state.probe_refusal_status = rs
        if digest is not None:
            state.probe_refusal_digest = digest

    orig_established = M.SessionManager._established

    def _established(self, fetcher, host, identity, base_url, state, seen, auth_endpoints):
        out = orig_established(self, fetcher, host, identity, base_url, state, seen,
                               auth_endpoints)
        _record_resource(self, out, base_url, [getattr(self._tl, "landing", None)])
        return out

    M.SessionManager._established = _established

    orig_basic = M.SessionManager._basic_login

    def _basic_login(self, fetcher, host, identity, base_url, cred, *, secure_only=None):
        out = orig_basic(self, fetcher, host, identity, base_url, cred,
                         secure_only=secure_only)
        _record_resource(self, out, base_url)
        return out

    M.SessionManager._basic_login = _basic_login

    # --- the health check: one owner (M7, B2, B3) -----------------------------------
    def _health_get(self, state, base_url):
        target = getattr(state, "protected_probe", None) or base_url
        floor = bool(state.secure_only) or urlparse(target).scheme.lower() == "https"
        f = self._health_ff()
        try:
            resp, page, stopped = _navigate_stop(self, f, target, base_url or target,
                                                 floor, state.apply({}),
                                                 frozenset(state.origins), state)
        except M.SessionAuthError:
            if REVERT == "hop_pauses":
                return Health(INCONCLUSIVE, "an unapproved hop", state.generation)
            raise                                           # fail fast (ADOPT)
        except net_errors as exc:
            return Health(INCONCLUSIVE, f"no response ({type(exc).__name__})",
                          state.generation)
        h = health_verdict(state, resp.status, resp.headers, resp.text, page,
                           stopped_at_login=stopped)
        if h.state == LIVE:
            _adopt_rotation(state, f.cookies())
        return h

    def _current(self, state, generation) -> bool:
        """B3: ``state`` is still the current object for its key, of ``generation``."""
        return self._state.get((state.host, state.identity)) is state and \
            getattr(state, "generation", None) == generation

    def _mark_lost(self, state, generation) -> bool:
        """The one place a session is invalidated: compare-and-set on the current state
        and its generation (B3). Returns whether this call made the transition (its
        caller tells the listeners when its ``notify`` is set). Never persists an object
        that is no longer current."""
        with self._observe_guard:
            if REVERT != "nocas" and not _current(self, state, generation):
                return False
            if not state.valid:
                return False
            state.valid = False
        _hrec(self, state.host, state.identity).relogin_due = True
        self._persist(state)
        return True

    M.SessionManager._mark_lost = _mark_lost

    def _tell(self, state, origin, identity, notify) -> None:
        if notify:
            for listener in list(self._logout_listeners):
                listener(origin, identity)

    def check_health(self, host, identity, base_url=None, *, generation=None,
                     signal_url=None, seen_seq=None, foreign=False, use_cache=True,
                     pause=True):
        """Is (host, identity)'s session of ``generation`` live? Single-flight; the
        verdict is recorded before the lock is released, and a waiter re-checks under
        the lock: (a) a live verdict whose GET was sent after a signal was seen covers
        that signal (B2), so N concurrent signals make at most two GETs; (b) for the TTL,
        a live verdict also covers later signals of the same (generation, URL key),
        unless the request carried a foreign header. After the GET, the verdict is STALE
        unless the judged state is still the current one, of the generation judged (B3).
        ``pause=False`` (verify_live) records no pause. Returns ``(Health,
        transitioned)``."""
        key = (host, identity)
        state = self._state.get(key)
        if state is None:
            return Health(STALE, "no session", generation), False
        rec = _hrec(self, host, identity)
        gen = state.generation if generation is None else generation
        urlk = url_key(signal_url) if signal_url else None
        with rec.lock:
            if getattr(state, "generation", None) != gen:
                return Health(STALE, "another generation", gen), False
            if REVERT != "noflight" and rec.verdict and rec.verdict[0] == gen and \
                    rec.verdict[1] == LOST:
                return Health(LOST, "already lost", gen), False
            now = self._clock()
            if use_cache and REVERT != "nocache":
                last = rec.live_seq.get(gen)
                if REVERT != "noflight" and seen_seq is not None and last is not None \
                        and last > seen_seq:
                    _bump(self, rec, "covered")
                    return Health(LIVE, "covered", gen), False
                if urlk is not None and (not foreign or REVERT == "foreign"):
                    hits = [at for (g, k), at in rec.live.items()
                            if (g == gen or REVERT == "cache_nogen")
                            and (k == urlk or REVERT == "cache_nourl")]
                    if hits and now - max(hits) < self._health_ttl_s:
                        _bump(self, rec, "cached")
                        return Health(LIVE, "cached", gen), False
            sent_seq = _next_seq(self)            # B2: the cover point is the send
            started = self._clock()
            h = _health_get(self, state, base_url or self._bases.get((host, identity)))
            if REVERT == "inconclusive_lost" and h.state == INCONCLUSIVE:
                h = Health(LOST, h.reason, gen)
            if REVERT == "inconclusive_live" and h.state == INCONCLUSIVE:
                h = Health(LIVE, h.reason, gen)
            h = dataclasses.replace(h, generation=gen)
            _bump(self, rec, "checks")
            _bump(self, rec, h.state)
            if REVERT != "nocas" and not _current(self, state, gen):
                _bump(self, rec, "stale_verdicts")     # B3: replaced while in flight
                return Health(STALE, "replaced while its check was in flight", gen), False
            moved = False
            if h.state == LIVE:
                seq = _next_seq(self) if REVERT == "cover_at_record" else sent_seq
                rec.live_seq[gen] = max(rec.live_seq.get(gen, 0), seq)
                if urlk is not None:
                    rec.live[(gen, urlk)] = started
            elif h.state == LOST:
                if rec.pause is not None and rec.pause["gen"] == gen:
                    rec.pause = None
                moved = _mark_lost(self, state, gen)
            elif h.state == INCONCLUSIVE and pause:
                p = rec.pause
                if p is None or p["gen"] != gen:
                    step = 5.0
                    rec.pause = {"gen": gen, "until": now + max(step, h.retry_after_s or 0),
                                 "step": step, "began": now}
                    _LOG.warning("session health unknown; pausing the identity",
                                 extra={"host": host, "reason": h.reason})
            rec.verdict = (gen, h.state)         # recorded before the lock is released
            if REVERT == "relogin_under_health_lock" and moved:
                self.ensure(host, identity, self._bases.get((host, identity))
                            or base_url or "")
        return h, moved

    M.SessionManager.check_health = check_health

    # --- observe ---------------------------------------------------------------------
    def _foreign(request, state) -> bool:
        own = {"cookie", "authorization", "content-type", "content-length"} | \
            {str(k).lower() for k in (state.headers or {})}
        return any(str(k).lower() not in own for k in (request.headers or {}))

    def observe(self, request, response, identity):
        if self._label is not None:
            if identity != self._label:
                return
            identity = self._label_identity
        state = self._state_for(request.url, identity)
        if state is None:
            return
        seen_seq = _next_seq(self)
        rec = _hrec(self, state.host, identity)
        cred = getattr(request, "session_decision", None) != M.OUT_OF_ORIGIN
        body = M._text(response.body)
        content = state.kind != "basic" or REVERT == "basic_content"
        shape = detect.detect_logout(response.status, response.headers, body,
                                     login_url=state.login_url, page_url=request.url,
                                     content_check=content,
                                     login_fields=state.login_fields, credentialed=cred,
                                     credential_submission=False)
        cls, _why = response_class(response.status, response.headers, complete=True,
                                   credentialed=cred, credential_submission=False,
                                   redirect_to_login=False)
        _bump(self, rec, f"class:{cls}")
        policy = cls == POLICY_BLOCK and cred
        if not shape and not policy:
            return
        if REVERT == "policy_nocheck" and not shape:
            return
        gen = getattr(request, "session_generation", None)
        if gen is None or REVERT == "nogen":
            gen = getattr(state, "generation", None)
        if gen != getattr(state, "generation", None):
            _bump(self, rec, "stale")
            return
        if not state.valid:
            return
        if rec.pause is not None and rec.pause["gen"] == gen:
            return
        submission = False
        if REVERT != "nosubmission":
            facts = detect.login_facts(request.url, response.headers,
                                       login_url=state.login_url,
                                       entry_names=request_entry_names(
                                           request.url, request.body,
                                           _content_type(request.headers)))
            submission = facts.credential_submission
        origin = canonical_origin(request.url)
        if not getattr(state, "protected_probe", None):
            if shape and not submission:
                _bump(self, rec, "unconfirmed")
                if _mark_lost(self, state, gen):
                    _tell(self, state, origin, identity, True)
            return
        if submission and REVERT == "submission_ignored":
            return
        if REVERT == "noconfirm" and shape and not submission:
            if _mark_lost(self, state, gen):
                _tell(self, state, origin, identity, True)
            return
        _bump(self, rec, "suspected" if shape else "policy_checks")
        h, moved = check_health(self, state.host, identity,
                                self._bases.get((state.host, identity)),
                                generation=gen, signal_url=request.url, seen_seq=seen_seq,
                                foreign=_foreign(request, state))
        if moved:
            _tell(self, state, origin, identity, True)

    M.SessionManager.observe = observe

    # --- prepare: sticky unknown, the pause, the generation applied -----------------
    def _unknown(self, key, why):
        rec = _hrec(self, *key)
        if REVERT != "nosticky":
            rec.unknown = why
        rec.pause = None
        cls = IsolatedHealthUnknown if self._isolated_from is not None else \
            SessionHealthUnknown
        if cls is IsolatedHealthUnknown:
            return cls(f"isolated session health unknown ({why})",
                       reason="isolated session health unknown")
        return cls(f"the session of {key[1]}@{key[0]} stayed unknown ({why})")

    def _wait_out_pause(self, state, identity):
        """Wait a paused identity's pause out, then check again, until it is live,
        lost or unknown past the bound or the run's budget (prepare's only; verify_live
        has its own wait). Never holds a lock while waiting. Returns the last Health."""
        key = (state.host, identity)
        rec = _hrec(self, *key)
        while True:
            p = rec.pause
            if p is None or (REVERT != "nocas"
                             and p["gen"] != getattr(state, "generation", None)):
                return None
            now = self._clock()
            spent = self._shared.prepare_s
            over_budget = REVERT != "nobudget" and spent >= self._pause_budget_s
            if now - p["began"] >= self._max_pause_s or over_budget:
                raise _unknown(self, key, "pause budget" if over_budget else "pause bound")
            if now < p["until"]:
                wait = min(p["until"] - now, p["began"] + self._max_pause_s - now)
                if REVERT != "nobudget":
                    wait = min(wait, max(0.0, self._pause_budget_s - spent))
                self._sleep(wait)
                _charge(self, "prepare_s", wait)
                continue
            h, moved = check_health(self, state.host, identity,
                                    self._bases.get(key), generation=p["gen"],
                                    use_cache=False)
            if h.state == STALE:
                if rec.pause is p:
                    rec.pause = None
                return h
            if h.state == INCONCLUSIVE:
                p["step"] = min(60.0, p["step"] * 2)
                p["until"] = self._clock() + max(p["step"], h.retry_after_s or 0)
                continue
            if rec.pause is p:
                rec.pause = None
            if h.state == LOST and moved and REVERT == "notify_pause":
                _tell(self, state, canonical_origin(state.protected_probe or ""),
                      identity, True)
            return h

    def _apply(self, request, identity) -> None:
        """The base `prepare`'s body (manager.py:321-358), plus F4: the request records
        the generation of the state it was given, set where that state is applied --
        never re-read from the manager afterwards."""
        host = urlparse(request.url).hostname or ""
        identity = self._own_identity(identity)
        if identity == M.ANONYMOUS or host not in self._scope:
            return
        origin = canonical_origin(request.url)
        state = self._state_for(request.url, identity)
        if state is None:
            existing = self._state.get((host, identity))
            if existing is not None:
                M._check_transport(existing, request.url)
                self._withhold(origin, identity, request)
                return
            state = self.ensure(host, identity,
                                self._bases.get((host, identity))
                                or M._directory(request.url))
        elif not state.valid or state.is_time_expired():
            state = self.ensure(state.host, identity,
                                self._bases.get((state.host, identity))
                                or M._directory(request.url))
        M._check_transport(state, request.url)
        if origin is None or origin not in state.origins:
            self._withhold(origin, identity, request)
            return
        request.headers = state.apply(request.headers)
        if REVERT != "nogenrecord":
            request.session_generation = getattr(state, "generation", None)

    def prepare(self, request, identity):
        host = urlparse(request.url).hostname or ""
        own = self._own_identity(identity)
        if own != M.ANONYMOUS and host in self._scope:
            state = self._state_for(request.url, own)
            if state is not None:
                key = (state.host, own)
                rec = _hrec(self, *key)
                if rec.unknown is not None:
                    raise _unknown(self, key, rec.unknown)       # sticky: no network
                if rec.pause is not None and (REVERT == "nocas" or
                                              rec.pause["gen"] ==
                                              getattr(state, "generation", None)):
                    _wait_out_pause(self, state, own)
        _apply(self, request, identity)

    M.SessionManager.prepare = prepare

    # --- ensure: the re-login token bucket, drawn under the login lock (M10, D, F5) --
    orig_ensure = M.SessionManager.ensure

    def ensure(self, host, identity, base_url, *, operator=False):
        key = (host, identity)
        if identity == M.ANONYMOUS or REVERT == "nobucket":
            return orig_ensure(self, host, identity, base_url, operator=operator)
        while True:
            with self._lock_for(host, identity):
                state = self._state.get(key)
                rec = _hrec(self, *key)
                if state is None or state.valid or not rec.relogin_due:
                    return orig_ensure(self, host, identity, base_url, operator=operator)
                now = self._clock()
                if rec.tokens is None:
                    rec.tokens, rec.refill_at = float(self._relogin_burst), now
                gained = (now - rec.refill_at) / self._relogin_refill_s
                if gained > 0:
                    rec.tokens = min(float(self._relogin_burst), rec.tokens + gained)
                    rec.refill_at = now
                if rec.tokens >= 1.0:
                    rec.tokens -= 1.0
                    rec.relogin_due = False
                    _bump(self, rec, "relogins")
                    # the login in the same critical section as the draw
                    return orig_ensure(self, host, identity, base_url, operator=operator)
                if REVERT != "nores_waits" and skips_when_spent(state):
                    # D: no resource and no token -- no login, no wait, no raise: the
                    # send carries on at once with the session it has (believed lost)
                    self._check_base(host, identity, base_url, operator=operator)
                    if operator:
                        self._operator_bases.add(url_key(base_url))
                        self._bases[key] = base_url
                    _bump(self, rec, "relogins_skipped")
                    return state
                wait = (1.0 - rec.tokens) * self._relogin_refill_s
                budget_left = self._pause_budget_s - self._shared.prepare_s
                if wait > self._max_pause_s or wait > budget_left:
                    raise _unknown(self, key, "re-login budget")
            self._sleep(wait)                     # no lock held while waiting
            _charge(self, "prepare_s", wait)

    M.SessionManager.ensure = ensure

    # --- verify_live (M9): its own wait, never the identity's pause or sticky -------
    def verify_live(self, host, identity, base_url):
        state = self._state.get((host, identity))
        if state is None or not state.valid:
            return False
        rec = _hrec(self, host, identity)
        if REVERT == "verifylive_cache" and rec.verdict == (state.generation, LIVE):
            return True
        gen = getattr(state, "generation", None)
        began, step = self._clock(), 5.0
        which = "prepare_s" if REVERT == "verifylive_budget" else "verify_s"
        while True:
            h, _moved = check_health(self, host, identity, base_url, generation=gen,
                                     use_cache=False, pause=False)
            if h.state != INCONCLUSIVE:
                break
            if REVERT == "verifylive_false":
                return False
            left = self._max_pause_s - (self._clock() - began)
            budget_left = self._pause_budget_s - getattr(self._shared, which)
            wait = min(max(step, h.retry_after_s or 0), left, budget_left)
            if wait <= 0:
                break
            self._sleep(wait)
            _charge(self, which, wait)
            step = min(60.0, step * 2)
        if h.state == LIVE:
            rec.unknown = None                    # a check succeeded
            return True
        if h.state == LOST:
            rec.unknown = None                    # check_health marked it lost (no notify)
            return False
        if h.state == INCONCLUSIVE and REVERT == "verifylive_clears_sticky":
            rec.unknown = None
        _LOG.warning("verify_live: session health %s; read as live", h.state)
        return True

    M.SessionManager.verify_live = verify_live
