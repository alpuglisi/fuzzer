"""Per-(host, identity) session state: cookies + headers/tokens.

Generalized beyond a cookie jar so it holds whatever the detected scheme uses —
a session cookie, a bearer/JWT header, or an HTTP Basic header. Secrets are
redacted for logging and never persisted in cleartext (the manager persists only
non-secret metadata).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class SessionState:
    host: str
    identity: str
    kind: str = "none"                       # 'cookie' | 'bearer' | 'basic' | 'none'
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)   # e.g. Authorization
    login_url: str | None = None
    logout_url: str | None = None
    token_exp: float | None = None           # unix ts, for JWT proactive refresh
    valid: bool = False
    #: established over https (the login's transport floor): its cookies, tokens and
    #: Basic header are never sent over plain http (BUG-0098, FR-SESS-13). ``None``
    #: (not given) derives it from ``login_url``: an https login is secure-only.
    secure_only: bool | None = None

    def __post_init__(self) -> None:
        if self.secure_only is None:
            self.secure_only = bool(self.login_url) and \
                str(self.login_url).lower().startswith("https:")

    def apply(self, headers: dict[str, str]) -> dict[str, str]:
        """Return ``headers`` with this session's cookies/auth headers merged in."""
        out = dict(headers)
        if self.cookies:
            existing = out.get("Cookie")
            jar = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            out["Cookie"] = f"{existing}; {jar}" if existing else jar
        for key, value in self.headers.items():
            out[key] = value
        return out

    def update_cookies(self, new_cookies: dict[str, str]) -> None:
        self.cookies.update(new_cookies)

    def is_time_expired(self, now: float | None = None, skew: float = 30.0) -> bool:
        """True when a JWT `exp` has passed (with a little skew for proactive refresh)."""
        if self.token_exp is None:
            return False
        now = time.time() if now is None else now
        return now >= (self.token_exp - skew)

    def redacted(self) -> dict[str, object]:
        """A log-safe view: presence of secrets, never their values."""
        return {
            "host": self.host,
            "identity": self.identity,
            "kind": self.kind,
            "valid": self.valid,
            "cookies": sorted(self.cookies.keys()),           # names only
            "auth_headers": sorted(self.headers.keys()),      # names only
            "token_exp": self.token_exp,
        }

    def non_secret_state(self) -> dict[str, object]:
        """What may be persisted to the store (no cookie/token values)."""
        return {
            "host": self.host,
            "identity": self.identity,
            "kind": self.kind,
            "valid": self.valid,
            "login_url": self.login_url,
            "logout_url": self.logout_url,
            "token_exp": self.token_exp,
            "secure_only": self.secure_only,
        }


def secure_only_of(record: dict | None) -> bool:
    """``secure_only`` for a persisted (metadata-only) session record. Records written
    before BUG-0098 lack the field: it is derived from the stored ``login_url`` scheme,
    and an unknown ``login_url`` fails closed (``True``; a fresh login recomputes it)."""
    if not record:
        return True
    if record.get("secure_only") is not None:
        return bool(record["secure_only"])
    login_url = record.get("login_url")
    if not login_url:
        return True
    return str(login_url).lower().startswith("https:")
