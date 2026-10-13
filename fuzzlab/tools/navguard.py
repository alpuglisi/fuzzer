"""Browser-side destructive-URL guard (NFR-CRAWL-safe / NFR-FUZZ-safe, BUG-0111).

A headless browser sends requests no link queue controls: redirects, page scripts'
``fetch``/XHR, ``<img>``/``<iframe>`` subresources, meta refreshes. ``guard_page``
installs a route on the page (or context) that aborts every request whose URL
``core.urls.destructive_reason`` flags, before it leaves the browser, unless that exact
URL (by ``url_key``) is in ``allow`` — the operator's explicit input.

Callers open their pages with ``service_workers="block"``: a service worker's own
requests bypass ``page.route``. WebSockets are not routed (they would need
``route_web_socket``); none of our targets' destructive actions use one, a stated gap.
"""

from __future__ import annotations

import logging
from typing import Callable

from fuzzlab.core.urls import destructive_reason, url_key


def make_route_handler(allow: frozenset[str] = frozenset(),
                       on_abort: Callable[[str, str], None] | None = None):
    """The route handler ``guard_page`` installs (split out so it is testable)."""
    def handler(route, request=None) -> None:
        req = request if request is not None else route.request
        url = req.url
        reason = destructive_reason(url)
        if reason is not None and url_key(url) not in allow:
            logging.info(f"blocked destructive browser request {url.split('?', 1)[0]} "
                         f"({reason!r})")
            if on_abort is not None:
                on_abort(url, reason)
            route.abort()
            return
        route.continue_()
    return handler


def guard_page(target, allow: frozenset[str] = frozenset(),
               on_abort: Callable[[str, str], None] | None = None) -> None:
    """Abort destructive requests from a Playwright ``Page`` or ``BrowserContext``."""
    target.route("**/*", make_route_handler(allow, on_abort))


#: Redirects a static fetch follows by hand (each hop checked first).
MAX_REDIRECTS = 5


def get_checked(session, url: str, timeout: float, may_follow: Callable[[str], bool]):
    """GET ``url`` with ``requests``, following redirects **by hand**: a hop is fetched
    only if ``may_follow(next_url)`` allows it (scope, and no destructive token). A
    refused hop is not followed; the redirect response itself is returned (BUG-0111).
    """
    from urllib.parse import urljoin
    resp = None
    for _ in range(MAX_REDIRECTS + 1):
        resp = session.get(url, timeout=timeout, allow_redirects=False)
        location = resp.headers.get("Location")
        if resp.status_code not in (301, 302, 303, 307, 308) or not location:
            return resp
        nxt = urljoin(url, location)
        if not may_follow(nxt):
            return resp
        url = nxt
    return resp
