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


class Fetcher:
    """Login-handshake HTTP with its own cookie jar (default: requests-backed)."""

    def get(self, url: str, headers: dict[str, str] | None = None) -> FetchResponse: ...
    def post(self, url: str, data: dict[str, str] | None = None,
             headers: dict[str, str] | None = None) -> FetchResponse: ...
    def cookies(self) -> dict[str, str]: ...


def _requests_fetch_factory() -> Callable[[], Fetcher]:
    def factory() -> Fetcher:
        import requests

        sess = requests.Session()

        class _RequestsFetcher:
            def get(self, url, headers=None):
                r = sess.get(url, headers=headers, timeout=15, allow_redirects=True)
                return FetchResponse(r.status_code, dict(r.headers), r.text)

            def post(self, url, data=None, headers=None):
                r = sess.post(url, data=data, headers=headers, timeout=15,
                              allow_redirects=True)
                return FetchResponse(r.status_code, dict(r.headers), r.text)

            def cookies(self):
                return sess.cookies.get_dict()

        return _RequestsFetcher()

    return factory


class SessionManager:
    def __init__(self, credentials, scope_hosts: list[str] | None = None,
                 fetch_factory: Callable[[], Fetcher] | None = None,
                 identities: list[str] | None = None, max_reauth: int = 3,
                 logger=None, store=None):
        self._creds = credentials
        self._scope = set(scope_hosts or [])
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

        form, login_page_url = self._discover_login_form(fetcher, base_url)
        if form is None:
            raise SessionAuthError(
                f"could not detect a login for {identity}@{host}: no login form found "
                f"from {base_url} (multi-step/CAPTCHA/SPA logins are not auto-detected; "
                f"capture via the proxy post-Phase 6)"
            )
        resp = fetcher.post(form.action_url, data=form.fill(cred.username, cred.password))
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
        """Look for a login form from the base URL and a few common login paths."""
        candidates = [base_url] + [urljoin(base_url, p) for p in
                                   ("login", "login.php", "signin", "users/login")]
        for url in candidates:
            try:
                resp = fetcher.get(url)
            except Exception:  # noqa: BLE001 - a bad candidate URL is not fatal
                continue
            form = detect.find_login_form(resp.text, url)
            if form is not None:
                return form, url
        return None, base_url

    def _verify_authenticated(self, fetcher: Fetcher, base_url: str,
                              state: SessionState) -> bool:
        """Differential success: a protected probe is no longer a login page."""
        probe = fetcher.get(base_url, headers=state.headers or None)
        if probe.status in (401, 403):
            return False
        return not detect.is_login_page(probe.text)


def _base_url(url: str) -> str:
    parts = urlparse(url)
    return f"{parts.scheme}://{parts.netloc}"


def _text(body) -> str:
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return body or ""
