"""Live Playwright-backed browser executor for M6 (on-host).

Backs the oracle's `BrowserExecutor` seam with a real headless browser: it defines
the sentinel before navigation, optionally performs a store step first (stored XSS),
loads the observe URL with the payload placed in the query or fragment, and reports
whether the tokened sentinel actually fired. Playwright is imported lazily so the
oracle/tests import cleanly without it; this runs where a browser is available (the
lab host), not in the offline test sandbox.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlencode, urlsplit, urlunsplit

from fuzzlab.oracle.browser import SENTINEL, ExecObservation, ExecRequest
from fuzzlab.oracle.probe import UnplaceableLocation


def _with_query(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = urlencode({param: value}) if not parts.query else \
        parts.query + "&" + urlencode({param: value})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _with_fragment(url: str, param: str, value: str) -> str:
    """``url`` with ``param=value`` in its fragment. A single-page app's hash route
    (``/#/search``, `core.urls.spa_route`) keeps its route: the pair goes into the
    route's own query (``/#/search?q=<value>``, forms phase 3), percent-encoded (a
    space is ``%20``: the app's router reads it, not a form decoder), never after a
    second ``#``. Any other fragment is replaced by the pair, as before."""
    from urllib.parse import quote

    from fuzzlab.core.urls import spa_route
    parts = urlsplit(url)
    pair = urlencode({param: value}, quote_via=quote)
    if spa_route(url) is not None:
        route, sep, query = parts.fragment.partition("?")
        fragment = route + "?" + (query + "&" if sep and query else "") + pair
    else:
        fragment = urlencode({param: value})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, fragment))


class PlaywrightBrowserExecutor:
    """Drive a headless browser to confirm stored/DOM XSS. Lab-only, loopback targets."""

    def __init__(self, headless: bool = True, timeout_ms: int = 8000,
                 storage_headers: dict | None = None):
        self._headless = headless
        self._timeout = timeout_ms
        self._headers = storage_headers or {}
        #: why this run has no browser (BUG-0126), once a launch has failed
        self._unavailable: str | None = None

    #: How long a loaded page may take to fire the sentinel: a single-page app renders
    #: after its own API calls, well after ``load`` (BUG-0126: 300 ms missed Juice Shop's
    #: search sink, which fires at about one second). Polled; the wait ends on the hit.
    SETTLE_MS = 4000
    _POLL_MS = 100

    def _wait_for_token(self, page, token: str) -> bool:
        deadline = time.monotonic() + self.SETTLE_MS / 1000
        while True:
            hits = page.evaluate("window.__fzlbHits||[]")
            if token in (hits or []):
                return True
            if time.monotonic() >= deadline:
                return False
            page.wait_for_timeout(self._POLL_MS)

    def run(self, request: ExecRequest, token: str) -> ExecObservation:
        # refuse, never relocate (BUG-0115, PA-0115): checked before any browser starts
        if request.param is not None and request.location not in ("query", "fragment"):
            return ExecObservation(False, detail=f"unplaceable location {request.location!r}")
        if request.store is not None and request.store.location not in ("body", "query"):
            return ExecObservation(False, detail="unplaceable store location "
                                                 f"{request.store.location!r}")
        from playwright.sync_api import sync_playwright

        init = (f"window.{SENTINEL}=window.{SENTINEL}||function(t){{"
                f"(window.__fzlbHits=window.__fzlbHits||[]).push(t);}};")
        from fuzzlab.core.urls import in_origin_scope, origin_scope, url_key
        from fuzzlab.tools.navguard import (browser_launch_args, checked_api_request,
                                            chromium_launch_kwargs, guard_page, release)
        # The browser reaches only the observe and store origins (BUG-0123).
        scope_urls = [request.url] + ([request.store.url] if request.store else [])
        origins = origin_scope(*scope_urls)
        def in_scope(url):
            return in_origin_scope(url, origins)
        if self._unavailable is not None:              # BUG-0126: no browser, no verdict
            raise UnplaceableLocation(self._unavailable)
        launch = chromium_launch_kwargs(browser_launch_args(scope_urls),
                                        headless=self._headless)       # BUG-0126
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(**launch)
            except Exception as exc:  # noqa: BLE001 - any launch failure: no browser here
                # BUG-0126: a browser that cannot start is "no verdict" from the browser
                # mechanisms (never a negative), remembered so later probes do not retry
                self._unavailable = ("browser unavailable: "
                                     f"{str(exc).splitlines()[0][:160]}")
                logging.warning(f"M6 browser execution disabled for this run: "
                                f"{self._unavailable}")
                raise UnplaceableLocation(self._unavailable) from None
            context = None
            try:
                context = browser.new_context(service_workers="block")   # BUG-0111
                context.add_init_script(init)
                if self._headers:
                    context.set_extra_http_headers(self._headers)
                page = context.new_page()
                # Abort destructive subresources/redirects; the navigation targets
                # themselves are the explicit (ground-truth) points (BUG-0111).
                allowed = {url_key(request.url)}
                if request.store is not None:
                    allowed.add(url_key(request.store.url))
                guard_page(context, allow=frozenset(allowed), in_scope=in_scope)
                page.on("dialog", lambda d: (page.evaluate(
                    f"window.{SENTINEL}('{token}')"), d.dismiss()))

                if request.store is not None:                 # stored XSS: plant first
                    s = request.store
                    if s.location == "body":
                        # API requests bypass `route`: scope-check, never redirect
                        checked_api_request(in_scope, s.url)
                        context.request.post(s.url, form={s.param: s.value},
                                             max_redirects=0)
                    else:
                        page.goto(_with_query(s.url, s.param, s.value),
                                  wait_until="load", timeout=self._timeout)

                target = request.url
                if request.param is not None and request.value is not None:
                    target = (_with_fragment if request.location == "fragment"
                              else _with_query)(request.url, request.param, request.value)
                page.goto(target, wait_until="load", timeout=self._timeout)
                fired = self._wait_for_token(page, token)     # BUG-0126: async sinks
                return ExecObservation(executed=fired,
                                       detail="playwright" if fired else "")
            finally:
                if context is not None:
                    release(context)
                browser.close()
