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
from typing import Callable
from urllib.parse import urljoin, urlparse

from fuzzlab.core.urls import canonical_origin
from fuzzlab.session import detect
from fuzzlab.session.state import SessionState

ANONYMOUS = "anonymous"


class SessionAuthError(RuntimeError):
    """Raised when a host's login cannot be detected/completed (fail loud)."""


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
    def post(self, url: str, data: dict[str, str] | None = None,
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
            def get(self, url, headers=None):
                r = sess.get(url, headers=headers, timeout=15, allow_redirects=True)
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
                 logger=None, store=None, auth_origins: list[str] | None = None):
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
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._failures: dict[tuple[str, str], int] = {}
        self._persisted: dict[tuple[str, str], dict] = {}
        if self._store is not None:
            for rec in self._store.all_session_states():
                self._persisted[(rec["host"], rec["identity"])] = rec
            if self._persisted and self._log:
                self._log.info("resuming known sessions",
                               extra={"count": len(self._persisted)})

    def persisted_state(self, host: str, identity: str) -> dict | None:
        """The last non-secret session state persisted for (host, identity), if any.

        Note: secrets are never persisted, so a resumed run still re-authenticates
        to obtain a live cookie/token; this is metadata (audit + continuity).
        """
        if self._store is not None:
            return self._store.get_session_state(host, identity)
        return self._persisted.get((host, identity))

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
        if identity == ANONYMOUS or host not in self._scope:
            return
        state = self._state.get((host, identity))
        if state is None or not state.valid or state.is_time_expired():
            self.ensure(host, identity, _base_url(request.url))
            state = self._state[(host, identity)]
        request.headers = state.apply(request.headers)

    def observe(self, request, response, identity: str) -> None:
        host = urlparse(request.url).hostname or ""
        state = self._state.get((host, identity))
        if state is None:
            return
        body = _text(response.body)
        if detect.detect_logout(response.status, response.headers, body,
                                login_url=state.login_url):
            state.valid = False  # next prepare() re-authenticates
            self._persist(state)

    # -- explicit / standalone -------------------------------------------
    def ensure(self, host: str, identity: str, base_url: str) -> SessionState:
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
            try:
                state = self._login(host, identity, base_url)
            except SessionAuthError:
                self._failures[(host, identity)] = self._failures.get((host, identity), 0) + 1
                raise
            self._failures[(host, identity)] = 0
            self._state[(host, identity)] = state
            return state

    def session_header(self, host: str, identity: str, base_url: str) -> str:
        """Standalone: a ready-to-use Cookie/Authorization header for an identity."""
        state = self.ensure(host, identity, base_url)
        applied = state.apply({})
        if "Cookie" in applied:
            return f"Cookie: {applied['Cookie']}"
        if "Authorization" in applied:
            return f"Authorization: {applied['Authorization']}"
        return ""

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

        form, login_page_url, challenge, https_seen = \
            self._discover_login_form(fetcher, base_url)
        # The transport floor (BUG-0092): once the operator's base URL, or any hop on the
        # way to the login page, was https, nothing after it may be plain http.
        floor_https = https_seen or urlparse(base_url).scheme.lower() == "https"
        if form is None and challenge == "basic":
            # HTTP Basic has no form: the base URL itself challenges (BUG-0081). The
            # header goes only to that same in-scope origin.
            return self._basic_login(fetcher, host, identity, base_url, cred)
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
        if not self._credential_destination_ok(form.action_url, login_page_url,
                                               floor_https=floor_https):
            raise SessionAuthError(
                f"refusing to send {identity}@{host} credentials to "
                f"{canonical_origin(form.action_url)}: a downgrade from https to http, "
                f"or not the login page's origin, an in-scope host, or an authorised auth "
                f"origin (pass auth_origins=[...] to allow it)")
        resp = self._post_credentials(fetcher, form.action_url,
                                      form.fill(cred.username, cred.password), login_page_url,
                                      floor_https=floor_https)
        if resp.status == 401 and "basic" in {k.lower(): v for k, v in
                                              resp.headers.items()}.get(
                                                  "www-authenticate", "").lower():
            return self._basic_login(fetcher, host, identity, base_url, cred)
        # A rejected login re-renders the login form (or answers 401/403). The mere
        # presence of a session cookie is NOT proof of authentication: servers hand an
        # anonymous session cookie to everyone (e.g. PHP's session_start() runs on every
        # page, so the fetcher's jar already holds a PHPSESSID from _discover_login_form's
        # GET, before any credentials are sent). Require a positive signal that the login
        # response left the login page behind before trusting the cookie. (BUG-0008)
        if resp.status in (401, 403) or detect.is_login_page(resp.text):
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
                             logout_url=urljoin(base_url, "logout"))
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
        Returns ``(form, login_page_url, challenge, https_seen)``; ``challenge`` is
        ``"basic"`` when the base URL answered 401 with a Basic ``WWW-Authenticate`` (no
        form needed). ``login_page_url`` is the page's final URL when the fetcher reports
        it, and ``https_seen`` says whether any hop to it was https (BUG-0092)."""
        candidates = [base_url] + [urljoin(base_url, p) for p in
                                   ("login", "login.php", "signin", "users/login")]
        challenge = None
        for url in candidates:
            try:
                resp = fetcher.get(url)
            except Exception:  # noqa: BLE001 - a bad candidate URL is not fatal
                continue
            if url == base_url and resp.status == 401:
                www = {k.lower(): v for k, v in resp.headers.items()}.get(
                    "www-authenticate", "")
                if www.lower().startswith("basic"):
                    challenge = "basic"
            page = getattr(resp, "url", None) or url       # where the page really is
            form = detect.find_login_form(resp.text, page)
            if form is not None:
                https_seen = "https" in (getattr(resp, "history_schemes", ()) or ())
                return form, page, challenge, https_seen
        return None, base_url, challenge, False

    # -- credential destinations (BUG-0081, BUG-0092) -----------------------
    @staticmethod
    def _transport_ok(target: str, floor_https: bool) -> bool:
        """The transport deny: an http(s) URL, and https whenever the floor is https."""
        scheme = urlparse(target).scheme.lower()
        return scheme == "https" or (scheme == "http" and not floor_https)

    def _credential_destination_ok(self, target: str, login_page_url: str, *,
                                   floor_https: bool = False) -> bool:
        """May credentials be sent to ``target``?

        **Deny first** (BUG-0092, PA-0093): the transport rule is checked before any
        allow and nothing overrides it — the scheme must be http or https, and https
        whenever the floor is (the operator's base URL, any discovery hop, or the login
        page itself was https). Only then may it be allowed: its origin is the login
        page's own, that host upgraded http→https, an in-scope host (any port, same or
        upgraded scheme), or an authorised ``auth_origins`` entry. A URL taken from
        response content (a form action, a redirect) is never trusted otherwise."""
        floor_https = floor_https or urlparse(login_page_url).scheme.lower() == "https"
        if not self._transport_ok(target, floor_https):
            return False
        origin, page = canonical_origin(target), canonical_origin(login_page_url)
        if origin is None:
            return False
        if origin == page or origin in self._auth_origins:
            return True
        t, p = urlparse(target), urlparse(login_page_url)
        if t.scheme == "https" and p.scheme == "http" and \
                (t.hostname or "").lower() == (p.hostname or "").lower():
            return True
        host = (t.hostname or "").lower()
        return host in self._scope or f"{host}:{t.port}" in self._scope

    def _post_credentials(self, fetcher: Fetcher, url: str, data: dict,
                          login_page_url: str, *, floor_https: bool = False) -> FetchResponse:
        """POST the credentials without letting the HTTP client follow redirects: a 307 /
        308 re-sends the body (the credentials) to wherever ``Location`` says. A 301 /
        302 / 303 becomes a body-less GET, followed only to an allowed origin over an
        allowed transport (the same deny-first predicate)."""
        resp = _post_no_redirects(fetcher, url, data)
        location = {k.lower(): v for k, v in resp.headers.items()}.get("location")
        if resp.status in (301, 302, 303) and location:
            nxt = urljoin(url, location)
            floor = floor_https or urlparse(url).scheme.lower() == "https"
            if self._credential_destination_ok(nxt, login_page_url, floor_https=floor):
                return fetcher.get(nxt)
        return resp                          # 307/308 never followed: judged as is

    def _basic_login(self, fetcher: Fetcher, host: str, identity: str, base_url: str,
                     cred) -> SessionState:
        token = base64.b64encode(f"{cred.username}:{cred.password}".encode()).decode()
        state = SessionState(host=host, identity=identity, kind="basic", cookies={},
                             headers={"Authorization": f"Basic {token}"}, token_exp=None,
                             login_url=base_url, logout_url=urljoin(base_url, "logout"))
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
        probe = fetcher.get(base_url, headers=state.headers or None)
        if probe.status in (401, 403):
            return False
        return not detect.is_login_page(probe.text)


def _post_no_redirects(fetcher, url: str, data: dict) -> FetchResponse:
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


def _base_url(url: str) -> str:
    parts = urlparse(url)
    return f"{parts.scheme}://{parts.netloc}"


def _text(body) -> str:
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return body or ""
