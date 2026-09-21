"""Manual-login session capture (FR-PROXY-9 / FR-SESS-11).

Some logins the session manager's detector cannot parse — MFA, CAPTCHA, multi-step,
exotic SPA flows. The escape hatch: a human logs in through the proxy with a real
browser, and this module *watches the flows* to capture the authenticated session
(the cookies the server set / the browser sends, plus any bearer token), then hands a
:class:`SessionState` to the session manager to **adopt** — no per-host config file.

It observes ``RawMessage`` bytes (the same the proxy already sees), so it needs no
special hooks. Captured secrets live only in memory and are handed to the manager,
which persists only non-secret metadata — the proxy never writes them to the store.
"""

from __future__ import annotations

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

    def observe_response(self, raw: bytes, url: str | None = None) -> None:
        """Capture cookies the server sets (Set-Cookie) during the login."""
        msg = RawMessage.from_bytes(raw)
        for sc in msg.get_all("Set-Cookie"):
            self._cookies.update(detect.parse_set_cookie(sc.decode("latin-1", "replace")))

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
        )

    def adopt_into(self, manager: SessionManager) -> SessionState:
        """Hand the captured session to the manager to adopt (FR-SESS-11)."""
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
