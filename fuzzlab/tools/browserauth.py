"""Inject a session into a Playwright browser context (Option A, browser path).

The session manager establishes the login once (detection-only, per-host
credentials); this formats the resulting session for a headless browser:

- cookie sessions -> ``context.add_cookies(...)``
- bearer/JWT (or Basic) sessions -> ``context.set_extra_http_headers(...)``

Playwright itself is not imported here — this only shapes the data and applies it
to whatever context object it is given — so it stays unit-testable without a
browser.
"""

from __future__ import annotations

from urllib.parse import urlparse


def playwright_auth(manager, identity: str, base_url: str):
    """Ensure a session for the base URL's host and return (cookies, headers).

    ``cookies`` is a list of Playwright cookie dicts ({name, value, url});
    ``headers`` is an extra-HTTP-headers dict (e.g. Authorization for bearer).
    """
    parts = urlparse(base_url)
    host = parts.hostname or ""
    state = manager.ensure(host, identity, base_url, operator=True)
    # Scoped to the origin root, as a server's `Set-Cookie: ...; path=/` would be: a
    # cookie keyed to a sub-path start page would not reach its sibling pages (BUG-0113).
    root = f"{parts.scheme}://{parts.netloc}/"
    cookies = [{"name": name, "value": value, "url": root}
               for name, value in state.cookies.items()]
    headers = dict(state.headers)
    return cookies, headers


def apply_to_context(context, cookies, headers) -> None:
    """Apply cookies and extra headers to a Playwright browser context."""
    if cookies:
        context.add_cookies(cookies)
    if headers:
        context.set_extra_http_headers(headers)
