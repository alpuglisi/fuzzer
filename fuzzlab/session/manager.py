"""SessionManager: detection-only auth, per-host credentials (D12, D13).

Keeps tools authenticated by detecting each host's login dynamically and drawing
credentials saved per host. Exposes the addon interface the `core/` HTTP seam
uses — ``prepare(request, identity)`` / ``observe(request, response, identity)`` —
plus ``ensure(host, identity, base_url)`` for explicit/standalone use.

Login handshakes use an injected fetcher (its own cookie jar), separate from the
HTTP seam, so authenticating never recurses through session handling. A login the
detector cannot parse fails loudly (``SessionAuthError``) — never a silent
unauthenticated run.
"""

from __future__ import annotations

import base64
import threading
from dataclasses import dataclass, field
from typing import Callable, Sequence
from urllib.parse import urljoin, urlparse

from fuzzlab.core.redaction import is_sensitive_name, looks_like_identifier
from fuzzlab.core.urls import canonical_origin
from fuzzlab.session import detect
from fuzzlab.session.state import SessionState, secure_only_of

ANONYMOUS = "anonymous"


class SessionAuthError(RuntimeError):
    """Raised when a host's login cannot be detected/completed (fail loud)."""


class IsolatedLoginFailed(SessionAuthError):
    """An isolated copy (FR-SESS-17) could not obtain a usable session of its own: the
    login was rejected, credentials were missing, the copy's login cap was reached, or
    the new session was not distinct. The one class a sender catches to fall back to an
    anonymous send; every other `SessionAuthError` (a transport refusal) propagates."""


class SessionIsolationError(IsolatedLoginFailed):
    """An isolated copy's new session is not distinct from the run's session or another
    live copy's (FR-SESS-17). Its message names credentials, never their values."""


class LoginCapReached(IsolatedLoginFailed):
    """A manager built with ``max_logins`` has used them all for this host/identity."""


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
                 max_logins: int | None = None):
        self._creds = credentials
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
        self._persisted: dict[tuple[str, str], dict] = {}
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
        to obtain a live cookie/token; this is metadata (audit + continuity).
        """
        rec = self._store.get_session_state(host, identity) if self._store is not None \
            else self._persisted.get((host, identity))
        if rec is None:
            return None
        return {**rec, "secure_only": secure_only_of(rec)}

    def _persist(self, state: SessionState) -> None:
        if self._store is not None:
            self._store.upsert_session_state(state.non_secret_state())

    def adopt(self, state: SessionState) -> SessionState:
        """Adopt an externally-captured session (FR-SESS-11).

        The escape hatch for logins detection can't parse (MFA, CAPTCHA, multi-step,
        exotic SPA): the proxy captures the session a human established with a manual
        browser login (FR-PROXY-9) and hands the resulting :class:`SessionState` here.
        We mark it valid, bring its host into scope, cache it for ``prepare``/``apply``,
        and persist only the NON-SECRET metadata (secrets stay in memory, like a
        normal login). No per-host config file is needed.
        """
        if self._isolated_from is not None:
            raise SessionAuthError("an isolated session never adopts a captured one "
                                   "(a captured session is the operator's own)")
        state.valid = True
        self._scope.add(state.host)
        self._state[(state.host, state.identity)] = state
        self._persist(state)
        if self._log:
            self._log.info("adopted captured session", extra=state.redacted())
        return state

    # -- addon interface used by the HTTP seam ----------------------------
    def prepare(self, request, identity: str) -> None:
        host = urlparse(request.url).hostname or ""
        identity = self._own_identity(identity)
        if identity == ANONYMOUS or host not in self._scope:
            return
        state = self._state.get((host, identity))
        if state is None or not state.valid or state.is_time_expired():
            # The operator's own base when one is known; else the request's directory
            # (never its origin: the app may live under a path; never the probe URL
            # itself: discovery must not replay a payload) — BUG-0113.
            self.ensure(host, identity,
                        self._bases.get((host, identity)) or _directory(request.url))
            state = self._state[(host, identity)]
        _check_transport(state, request.url)          # BUG-0098: before any secret
        request.headers = state.apply(request.headers)

    def authorize(self, request, identity: str, prepared_host: str | None = None) -> None:
        """Re-check an authenticated request after something (a plugin) edited it:
        raise `SessionAuthError` if it now goes to another host than the session was
        applied for, or over http with an https-established session (BUG-0098)."""
        identity = self._own_identity(identity)
        if identity == ANONYMOUS:
            return
        host = urlparse(request.url).hostname or ""
        if prepared_host is not None and host != prepared_host:
            raise SessionAuthError(
                f"refusing to send {identity}@{prepared_host}'s session to {host!r}: "
                f"the request was retargeted after the session was applied")
        state = self._state.get((host, identity))
        if state is not None:
            _check_transport(state, request.url)

    def observe(self, request, response, identity: str) -> None:
        host = urlparse(request.url).hostname or ""
        if self._label is not None:
            if identity != self._label:
                return              # prepare() already refused it; nothing of ours
            identity = self._label_identity
        state = self._state.get((host, identity))
        if state is None:
            return
        body = _text(response.body)
        if detect.detect_logout(response.status, response.headers, body,
                                login_url=state.login_url, page_url=request.url,
                                content_check=state.kind != "basic",
                                login_fields=state.login_fields):
            with self._observe_guard:
                was_valid = state.valid
                state.valid = False  # next prepare() re-authenticates
            self._persist(state)
            if was_valid:
                # inside the observing send; a listener's error propagates (PA-0106)
                for listener in list(self._logout_listeners):
                    listener(host, identity)

    def add_logout_listener(self, listener: Callable[[str, str], None]) -> None:
        """Call ``listener(host, identity)`` each time `observe` sees a valid session of
        **this** manager logged out (FR-SESS-16). It runs inside the send that observed
        the logout, so it must not block on a lock held across that send. Adding the
        same listener again does nothing."""
        if listener not in self._logout_listeners:
            self._logout_listeners.append(listener)

    # -- explicit / standalone -------------------------------------------
    def ensure(self, host: str, identity: str, base_url: str, *,
               operator: bool = False) -> SessionState:
        """Log ``identity`` in on ``host`` (once; single-flight), discovering the login
        from ``base_url``. ``operator=True`` marks ``base_url`` as the operator's own
        input (a CLI's ``--base-url``/``--start``/``--url``): it is remembered for
        re-logins and is the only kind of base exempt from the destructive-URL check
        during discovery (BUG-0113). Internal callers leave it False (fail closed)."""
        if operator:
            # recorded on every operator call, a cached session included, so a later
            # re-login uses the operator's base (reviewer B, BUG-0113)
            from fuzzlab.core.urls import url_key
            self._operator_bases.add(url_key(base_url))
            self._bases[(host, identity)] = base_url
        if identity == ANONYMOUS:
            state = SessionState(host, identity, kind="none", valid=True)
            self._state[(host, identity)] = state
            return state
        if host not in self._scope:
            raise SessionAuthError(f"host {host!r} not in scope {sorted(self._scope)}")
        lock = self._lock_for(host, identity)
        with lock:  # single-flight: concurrent expiry -> one login
            state = self._state.get((host, identity))
            if state is not None and state.valid and not state.is_time_expired():
                return state
            if self._failures.get((host, identity), 0) >= self._max_reauth:
                raise SessionAuthError(
                    f"re-auth cap ({self._max_reauth}) reached for {identity}@{host}"
                )
            if self._max_logins is not None and \
                    self._attempts.get((host, identity), 0) >= self._max_logins:
                raise LoginCapReached(
                    f"login cap ({self._max_logins}) reached for the isolated session "
                    f"{self._label or identity}@{host}")
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
                raise IsolatedLoginFailed(str(exc)) from exc
            self._failures[(host, identity)] = 0
            self._state[(host, identity)] = state
            return state

    def session_header(self, host: str, identity: str, base_url: str, *,
                       operator: bool = False) -> str:
        """Standalone: a ready-to-use Cookie/Authorization header for an identity, for
        use against ``base_url``. Refuses (`SessionAuthError`) an https-established
        session for an http ``base_url`` (BUG-0098); a consumer that sends it to other
        URLs (greybox) must enforce the same floor per request (``secure_only``)."""
        state = self.ensure(host, identity, base_url, operator=operator)
        _check_transport(state, base_url)
        applied = state.apply({})
        if "Cookie" in applied:
            return f"Cookie: {applied['Cookie']}"
        if "Authorization" in applied:
            return f"Authorization: {applied['Authorization']}"
        return ""

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
        from the operator's URL under the same credential-destination anchors. It has no
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
                              max_logins=max_logins)
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
                raise SessionIsolationError(
                    f"the isolated session {self._label}@{host} is not distinct from "
                    f"{whom}: {problem}")

    def verify_live(self, host: str, identity: str, base_url: str) -> bool:
        """Is the run's session for ``identity`` still logged in? One GET of ``base_url``
        (the operator's base) with a fresh fetcher carrying the session's cookies and
        headers, walked hop by hop inside the approved origins (`_navigate`). It fails on
        401/403 or on this session's login form, as `_verify_authenticated` does. On a
        failure the state is marked invalid (and persisted), so the next send re-logs in
        once; listeners are not told (the caller decides). An unapproved hop raises
        `SessionAuthError` (the caller treats it as "cannot verify")."""
        state = self._state.get((host, identity))
        if state is None or not state.valid:
            return False
        fetcher = self._fetch_factory()
        floor = bool(state.secure_only) or urlparse(base_url).scheme.lower() == "https"
        probe, page, _floor = self._navigate(fetcher, base_url, base_url, floor,
                                             headers=state.apply({}))
        ok = probe.status not in (401, 403) and (
            state.kind == "basic" or not detect.shows_login_form(
                probe.text, page, state.login_url, state.login_fields))
        if not ok:
            with self._observe_guard:
                state.valid = False
            self._persist(state)
        return ok

    def is_auth_endpoint(self, url: str) -> bool:
        host = urlparse(url).hostname or ""
        path = urlparse(url).path
        for known in self._auth_endpoints.get(host, set()):
            if urlparse(known).path == path:
                return True
        return False

    def auth_endpoints(self, host: str) -> set[str]:
        return set(self._auth_endpoints.get(host, set()))

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

        form, login_page_url, challenge, floor_https = \
            self._discover_login_form(fetcher, base_url)
        if form is None and challenge == "basic":
            # HTTP Basic has no form: the base URL itself challenges (BUG-0081). The
            # header goes only to that same in-scope origin.
            return self._basic_login(fetcher, host, identity, base_url, cred,
                                     secure_only=floor_https)
        if form is None:
            raise SessionAuthError(
                f"could not detect a login for {identity}@{host}: no login form found "
                f"from {base_url} (multi-step/CAPTCHA/SPA logins are not auto-detected; "
                f"capture via the proxy post-Phase 6)"
            )
        if not self._transport_ok(login_page_url, floor_https):
            raise SessionAuthError(
                f"refusing to log {identity}@{host} in: the login page {login_page_url} "
                f"was reached by a downgrade from https to http")
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
                f"origin (pass auth_origins=[...] to allow it)")
        resp = self._post_credentials(fetcher, form.action_url,
                                      form.fill(cred.username, cred.password), base_url,
                                      floor_https=floor_https)
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
                             secure_only=floor_https)
        if detected.kind == "basic":
            token = base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
            state.headers["Authorization"] = f"Basic {token}"

        if not self._verify_authenticated(fetcher, base_url, state):
            raise SessionAuthError(
                f"login for {identity}@{host} did not result in an authenticated "
                f"session (credentials wrong, or success could not be confirmed)"
            )
        state.valid = True
        # Record auth endpoints so fuzzing excludes them (T1.8).
        self._auth_endpoints.setdefault(host, set()).update(
            {form.action_url, login_page_url, state.logout_url})
        self._persist(state)   # NON-SECRET metadata only (T1.7)
        if self._log:
            self._log.info("authenticated", extra=state.redacted())
        return state

    def _discover_login_form(self, fetcher: Fetcher, base_url: str):
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
                resp, page, page_floor = self._navigate(fetcher, url, base_url, floor)
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
                  headers: dict | None = None):
        """GET ``url`` following at most `MAX_LOGIN_HOPS` redirects by hand. Every hop
        must pass `_navigation_ok` **before** it is fetched. A fetcher that cannot be
        told not to follow redirects must report a final URL equal to the one asked
        for, or discovery refuses (it may have followed one unchecked — A3). Returns
        ``(response, page_url, floor_https)``."""
        current = url
        for _ in range(MAX_LOGIN_HOPS + 1):
            if not self._navigation_ok(current, base_url, floor_https):
                raise SessionAuthError(
                    f"refusing to follow the login navigation to {current}: a downgrade "
                    f"from https to http, or not the base URL's origin, an in-scope host "
                    f"or an authorised auth origin (pass auth_origins=[...] to allow it)")
            floor_https = floor_https or urlparse(current).scheme.lower() == "https"
            resp, can_refuse = _get_no_redirects(fetcher, current, headers)
            if not can_refuse and getattr(resp, "url", None) != current:
                raise SessionAuthError(
                    f"the login fetcher cannot refuse redirects and did not report that "
                    f"{current} was not redirected; refusing (it may have left scope)")
            location = {k.lower(): v for k, v in resp.headers.items()}.get("location")
            if resp.status in (301, 302, 303, 307, 308) and location:
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
        PA-0098): ``target``'s origin must be ``base_url``'s own, that host upgraded
        http→https, an in-scope host (any port: host-level scope, D12), or an
        authorised ``auth_origins`` entry. A URL from response content (a redirect, a
        form action, a page) is checked against this anchor, never added to it."""
        floor_https = floor_https or urlparse(base_url).scheme.lower() == "https"
        if not self._transport_ok(target, floor_https):
            return False
        origin, base = canonical_origin(target), canonical_origin(base_url)
        if origin is None:
            return False
        if origin == base or origin in self._auth_origins:
            return True
        t, b = urlparse(target), urlparse(base_url)
        if t.scheme == "https" and b.scheme == "http" and \
                (t.hostname or "").lower() == (b.hostname or "").lower():
            return True
        host = (t.hostname or "").lower()
        return host in self._scope or f"{host}:{t.port}" in self._scope

    def _post_credentials(self, fetcher: Fetcher, url: str, data,
                          base_url: str, *, floor_https: bool = False) -> FetchResponse:
        """POST the credentials without letting the HTTP client follow redirects: a 307 /
        308 re-sends the body (the credentials) to wherever ``Location`` says. A 301 /
        302 / 303 becomes a body-less GET, followed only to an allowed origin over an
        allowed transport (the same deny-first predicate)."""
        resp = _post_no_redirects(fetcher, url, data)
        location = {k.lower(): v for k, v in resp.headers.items()}.get("location")
        if resp.status in (301, 302, 303) and location:
            nxt = urljoin(url, location)
            floor = floor_https or urlparse(url).scheme.lower() == "https"
            if self._credential_destination_ok(nxt, base_url, floor_https=floor):
                return fetcher.get(nxt)
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
                             if secure_only is None else secure_only)
        if not self._verify_authenticated(fetcher, base_url, state):
            raise SessionAuthError(
                f"HTTP Basic login for {identity}@{host} was rejected (credentials "
                f"wrong: the base URL still challenges)")
        state.valid = True
        self._persist(state)
        if self._log:
            self._log.info("authenticated", extra=state.redacted())
        return state

    def _verify_authenticated(self, fetcher: Fetcher, base_url: str,
                              state: SessionState) -> bool:
        """Secondary sanity check that the session is usable.

        The primary login-success decision is made in ``_login`` from the login
        POST response (a rejected login re-renders the login form / answers
        401/403). This is a follow-up probe with the established session: it must
        not bounce to an auth challenge or land back on a login page. It probes
        ``base_url`` (often public), so it is a guard against an outright-broken
        session, not proof of authentication on its own — hence the POST-response
        check upstream carries the weight (BUG-0008).
        """
        # the probe walks redirects hop by hop too, inside the approved origins and over
        # the transport floor, carrying the session's headers (BUG-0097)
        floor = bool(state.secure_only) or urlparse(base_url).scheme.lower() == "https"
        probe, page, _floor = self._navigate(fetcher, base_url, base_url, floor,
                                             headers=state.headers or None)
        if probe.status in (401, 403):
            return False
        if state.kind == "basic":       # Basic: 401/403 only, as in observe (BUG-0113)
            return True
        # only the login form itself means "not logged in": the base may be an app page
        # that has a password field of its own (BUG-0113)
        return not detect.shows_login_form(probe.text, page, state.login_url,
                                           state.login_fields)


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


def _post_no_redirects(fetcher, url: str, data) -> FetchResponse:
    """``fetcher.post`` with redirects off. A fetcher without the keyword (an old test
    double, which never follows redirects anyway) is called without it."""
    import inspect
    try:
        params = inspect.signature(fetcher.post).parameters
    except (TypeError, ValueError):
        params = {}
    if "allow_redirects" in params or any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return fetcher.post(url, data=data, allow_redirects=False)
    return fetcher.post(url, data=data)


def _directory(url: str) -> str:
    """``url``'s directory: scheme, host and the path up to its last ``/``, with no
    query or fragment (``/app/x.php?q=1`` -> ``/app/``). A discovery base derived from
    a request (BUG-0113)."""
    parts = urlparse(url)
    path = parts.path or "/"
    return f"{parts.scheme}://{parts.netloc}{path[:path.rfind('/') + 1]}"


def _text(body) -> str:
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return body or ""
