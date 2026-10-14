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
    # secrets: never in repr/str (FR-SESS-19, reviewer B6)
    cookies: dict[str, str] = field(default_factory=dict, repr=False)
    headers: dict[str, str] = field(default_factory=dict, repr=False)  # e.g. Authorization
    login_url: str | None = None
    logout_url: str | None = None
    token_exp: float | None = None           # unix ts, for JWT proactive refresh
    valid: bool = False
    #: established over https (the login's transport floor): its cookies, tokens and
    #: Basic header are never sent over plain http (BUG-0098, FR-SESS-13). ``None``
    #: (not given) derives it from ``login_url``: an https login is secure-only.
    secure_only: bool | None = None
    #: The login form's entry names (non-secret; in memory only). A page that shows a
    #: password form with exactly these names is the login form re-rendered in place,
    #: wherever it posts (BUG-0113).
    login_fields: tuple[str, ...] | None = None
    #: A browser login's ``storage_state()`` (cookies and per-origin localStorage), for
    #: an authenticated Playwright crawl to adopt (FR-SESS-19, FR-CRAWL-14). In memory
    #: only: never persisted, never in repr/str, never compared.
    browser_state: dict | None = field(default=None, repr=False, compare=False)
    #: A browser login's protected probe (FR-SESS-19): an in-scope GET the app made
    #: after the login click that answers 2xx with the credential and 401/403 (or a
    #: materially different body) without it. ``verify_live`` and the crawler's session
    #: check re-fetch it. In memory only.
    protected_probe: str | None = field(default=None, repr=False)
    #: sha256 of the probe's answer to a **corrupted** credential when that was 2xx
    #: (the differential was the body, A-M1): a live session's probe must answer
    #: something else. In memory only.
    probe_refusal_digest: str | None = field(default=None, repr=False)
    #: The names in ``cookies`` that a browser login adopted from the browser's own
    #: cookie jar (a cookie the app's JS set, e.g. Juice Shop's ``token``) rather than
    #: from the login response (BUG-0132). In memory only.
    browser_cookies: tuple[str, ...] = field(default=(), repr=False, compare=False)

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
            # no query or fragment is ever persisted (A-M2: a login URL may carry a
            # secret there)
            "login_url": _no_query(self.login_url),
            "logout_url": _no_query(self.logout_url),
            "token_exp": self.token_exp,
            "secure_only": self.secure_only,
        }


def _no_query(url: str | None) -> str | None:
    """``url`` without its query and fragment (None stays None)."""
    if not url:
        return url
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


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
