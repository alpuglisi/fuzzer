"""Inject a session into a Playwright browser context (Option A, browser path).

The session manager establishes the login once (detection-only, per-host
credentials); this formats the resulting session for a headless browser:

- cookie sessions -> ``context.add_cookies(...)``;
- bearer/JWT (or Basic) headers -> **the guarded route only**
  (``navguard.guard_page(headers=..., header_scope=...)``: ``route.fetch(headers=)``
  after ``in_scope`` passes, per redirect hop only when the hop is in scope). Never
  ``set_extra_http_headers``, which would hand them to every request the browser
  sends, wherever it goes (FR-CRAWL-14, reviewers A6/B7, PA-0002 sweep);
- a browser login's ``storage_state`` (cookies and localStorage, FR-SESS-19) ->
  ``browser.new_context(storage_state=...)``, filtered to in-scope origins first
  (reviewer A7).

Playwright itself is not imported here — this only shapes the data and applies it
to whatever context object it is given — so it stays unit-testable without a
browser.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse


def _ensure(manager, identity: str, base_url: str):
    return manager.ensure(urlparse(base_url).hostname or "", identity, base_url,
                          operator=True)


def _cookies_of(state, base_url: str) -> list[dict]:
    # Scoped to the origin root, as a server's `Set-Cookie: ...; path=/` would be: a
    # cookie keyed to a sub-path start page would not reach its sibling pages (BUG-0113).
    parts = urlparse(base_url)
    root = f"{parts.scheme}://{parts.netloc}/"
    return [{"name": name, "value": value, "url": root}
            for name, value in (getattr(state, "cookies", None) or {}).items()]


def playwright_auth(manager, identity: str, base_url: str):
    """Ensure a session for the base URL's host and return (cookies, headers).

    ``cookies`` is a list of Playwright cookie dicts ({name, value, url});
    ``headers`` is the session's header dict (e.g. Authorization for bearer), which a
    caller applies through ``guard_page(headers=...)`` only.
    """
    state = _ensure(manager, identity, base_url)
    return _cookies_of(state, base_url), dict(getattr(state, "headers", None) or {})


def header_scope_for(state, base_url: str,
                     in_scope: Callable[[str], bool]) -> Callable[[str], bool]:
    """Where the session's headers may go: an in-scope URL on the session's own host
    (loopback aliases one host), over https when the session is https-only (FR-SESS-13,
    BUG-0098)."""
    from fuzzlab.session.browserlogin import canonical_host
    host = canonical_host(base_url)
    secure_only = bool(getattr(state, "secure_only", False))

    def scope(url: str) -> bool:
        if not in_scope(url) or canonical_host(url) != host:
            return False
        return not secure_only or urlparse(url).scheme.lower() == "https"
    return scope


@dataclass
class BrowserSession:
    """What an authenticated browser context adopts (in memory only)."""
    cookies: list[dict] = field(repr=False)
    headers: dict[str, str] = field(repr=False)
    header_scope: Callable[[str], bool] = field(repr=False)
    #: the browser login's storage_state, in-scope origins only (None: none)
    storage_state: dict | None = field(repr=False)
    #: its in-scope localStorage entries, ``{origin: {name: value}}``
    local_storage: dict[str, dict[str, str]] = field(repr=False)
    #: ``(name, value)`` of the session's credential cookies -- not the ones a browser
    #: login adopted from the browser's jar (BUG-0132), which the context already gets
    #: from ``storage_state`` and which the app may legitimately change -- for the
    #: crawler's session check
    checked_cookies: list[tuple[str, str]] = field(default_factory=list, repr=False)


def browser_session(manager, identity: str, base_url: str, *,
                    in_scope: Callable[[str], bool], scope_urls=()) -> BrowserSession:
    """Ensure a session and shape it for a browser context: its cookies, its headers
    with `header_scope_for`, and a browser login's ``storage_state`` filtered to
    ``in_scope`` origins (`browserlogin.filter_storage_state`; cookies by the host of
    an in-scope ``scope_urls`` entry). FR-CRAWL-14."""
    from fuzzlab.session.browserlogin import filter_storage_state
    state = _ensure(manager, identity, base_url)
    raw = getattr(state, "browser_state", None)
    storage = filter_storage_state(raw, in_scope, [base_url, *scope_urls]) \
        if raw else None
    local = {o["origin"]: {e["name"]: e["value"] for e in o["localStorage"]}
             for o in (storage or {}).get("origins", []) if o["localStorage"]}
    cookies = _cookies_of(state, base_url)
    jar = set(getattr(state, "browser_cookies", None) or ())
    return BrowserSession(cookies=cookies,
                          headers=dict(getattr(state, "headers", None) or {}),
                          header_scope=header_scope_for(state, base_url, in_scope),
                          storage_state=storage, local_storage=local,
                          checked_cookies=[(c["name"], c["value"]) for c in cookies
                                           if c["name"] not in jar])


def context_options(session: BrowserSession | None) -> dict:
    """The ``browser.new_context(...)`` keywords that adopt ``session``: its browser
    login's ``storage_state``, already filtered to in-scope origins by
    `browser_session` (reviewer A7). The one adoption helper for every authenticated
    browser context (the crawl, FR-CRAWL-14; the auditor, CC-AUD-0040). Empty for no
    session or one without a browser state."""
    if session is None or not session.storage_state:
        return {}
    return {"storage_state": session.storage_state}


def apply_to_context(context, cookies, headers=None) -> None:
    """Add the session's cookies to a Playwright browser context. Headers are refused
    here: they go through the guarded route only (``guard_page(headers=...)``), never
    ``set_extra_http_headers`` (FR-CRAWL-14)."""
    if headers:
        raise ValueError("session headers are applied by the guarded route "
                         "(navguard.guard_page(headers=...)), never to the context")
    if cookies:
        context.add_cookies(cookies)
