"""Manual-login session capture (FR-PROXY-9 / FR-SESS-11).

Some logins the session manager's detector cannot parse — MFA, CAPTCHA, multi-step,
exotic SPA flows. The escape hatch: a human logs in through the proxy with a real
browser, and this module *watches the flows* to capture the authenticated session
(the cookies the server set / the browser sends, plus any bearer token), then hands a
:class:`SessionState` to the session manager to **adopt** — no per-host config file.

It observes ``RawMessage`` bytes (the same the proxy already sees), so it needs no
special hooks. Captured secrets live only in memory and are handed to the manager,
which persists only non-secret metadata — the proxy never writes them to the store.

It also records the **canonical origins** of the observed URLs on the capture's host
(FR-SESS-20, BUG-0134): the captured session is sent only there, and the manager
refuses to adopt a capture with no observed origin (another port of the same host is
another app).
"""

from __future__ import annotations

from fuzzlab.core.urls import canonical_origin
from fuzzlab.proxy.message import RawMessage
from fuzzlab.session import detect
from fuzzlab.session.manager import SessionManager
from fuzzlab.session.state import SessionState


class SessionCapture:
    """Accumulate an authenticated session from observed login flows."""

    def __init__(self, host: str, identity: str = "user"):
        self.host = host
        self.identity = identity
        self._cookies: dict[str, str] = {}
        self._headers: dict[str, str] = {}
        self._token_exp: float | None = None
        self._login_url: str | None = None
        self._https_seen = False             # any https URL or Secure cookie (BUG-0098)
        self._origins: set[str] = set()      # observed origins on this host (FR-SESS-20)

    # --- observation ---------------------------------------------------------
    def observe_request(self, raw: bytes, url: str | None = None) -> None:
        """Capture the Cookie/Authorization the browser sends on an in-scope request."""
        msg = RawMessage.from_bytes(raw)
        cookie = msg.get("Cookie")
        if cookie:
            self._cookies.update(_parse_cookie_header(cookie.decode("latin-1", "replace")))
        auth = msg.get("Authorization")
        if auth:
            value = auth.decode("latin-1", "replace")
            self._headers["Authorization"] = value
            if value.lower().startswith("bearer "):
                self._token_exp = detect.decode_jwt_exp(value[7:].strip())
        if url is not None:
            self._login_url = url
            self._https_seen |= url.lower().startswith("https:")
            self._note_origin(url)

    def _note_origin(self, url: str) -> None:
        """Record ``url``'s canonical origin when it is on the capture's host (loopback
        aliases one host): the session is sent only to the origins it was seen on."""
        from fuzzlab.session.browserlogin import canonical_host
        origin = canonical_origin(url)
        if origin is not None and \
                canonical_host(url) == canonical_host(f"http://{self.host}/"):
            self._origins.add(origin)

    def observe_response(self, raw: bytes, url: str | None = None) -> None:
        """Capture cookies the server sets (Set-Cookie) during the login."""
        msg = RawMessage.from_bytes(raw)
        if url is not None:
            self._https_seen |= url.lower().startswith("https:")
            self._note_origin(url)
        for sc in msg.get_all("Set-Cookie"):
            text = sc.decode("latin-1", "replace")
            self._cookies.update(detect.parse_set_cookie(text))
            if any(a.strip().lower() == "secure" for a in text.split(";")[1:]):
                self._https_seen = True

    # --- result --------------------------------------------------------------
    def has_session(self) -> bool:
        return bool(self._cookies or self._headers)

    def state(self) -> SessionState | None:
        """The captured :class:`SessionState`, or ``None`` if nothing was seen yet."""
        if not self.has_session():
            return None
        kind = "cookie" if self._cookies else \
            ("bearer" if "Authorization" in self._headers else "none")
        return SessionState(
            host=self.host, identity=self.identity, kind=kind,
            cookies=dict(self._cookies), headers=dict(self._headers),
            token_exp=self._token_exp, login_url=self._login_url, valid=True,
            secure_only=self._https_seen, origins=frozenset(self._origins),
        )

    def adopt_into(self, manager: SessionManager) -> SessionState:
        """Hand the captured session to the manager to adopt (FR-SESS-11). The manager
        refuses it loudly when no origin was observed (FR-SESS-20)."""
        state = self.state()
        if state is None:
            raise ValueError("no session captured yet (no cookies/token observed)")
        return manager.adopt(state)


def _parse_cookie_header(value: str) -> dict[str, str]:
    """Parse a request ``Cookie: a=b; c=d`` header into a name→value dict."""
    out: dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            name, val = part.split("=", 1)
            name = name.strip()
            if name:
                out[name] = val.strip()
    return out
