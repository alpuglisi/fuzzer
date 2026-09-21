"""Live Playwright-backed browser executor for M6 (on-host).

Backs the oracle's `BrowserExecutor` seam with a real headless browser: it defines
the sentinel before navigation, optionally performs a store step first (stored XSS),
loads the observe URL with the payload placed in the query or fragment, and reports
whether the tokened sentinel actually fired. Playwright is imported lazily so the
oracle/tests import cleanly without it; this runs where a browser is available (the
lab host), not in the offline test sandbox.
"""

from __future__ import annotations

import time
from urllib.parse import urlencode, urlsplit, urlunsplit

from fuzzlab.oracle.browser import SENTINEL, ExecObservation, ExecRequest


def _with_query(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = urlencode({param: value}) if not parts.query else \
        parts.query + "&" + urlencode({param: value})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _with_fragment(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query,
                       urlencode({param: value})))


class PlaywrightBrowserExecutor:
    """Drive a headless browser to confirm stored/DOM XSS. Lab-only, loopback targets."""

    def __init__(self, headless: bool = True, timeout_ms: int = 8000,
                 storage_headers: dict | None = None):
        self._headless = headless
        self._timeout = timeout_ms
        self._headers = storage_headers or {}

    def run(self, request: ExecRequest, token: str) -> ExecObservation:
        from playwright.sync_api import sync_playwright

        init = (f"window.{SENTINEL}=window.{SENTINEL}||function(t){{"
                f"(window.__fzlbHits=window.__fzlbHits||[]).push(t);}};")
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self._headless)
            try:
                context = browser.new_context()
                context.add_init_script(init)
                if self._headers:
                    context.set_extra_http_headers(self._headers)
                page = context.new_page()
                page.on("dialog", lambda d: (page.evaluate(
                    f"window.{SENTINEL}('{token}')"), d.dismiss()))

                if request.store is not None:                 # stored XSS: plant first
                    s = request.store
                    if s.location == "body":
                        context.request.post(s.url, form={s.param: s.value})
                    else:
                        page.goto(_with_query(s.url, s.param, s.value),
                                  wait_until="load", timeout=self._timeout)

                target = request.url
                if request.param is not None and request.value is not None:
                    target = (_with_fragment if request.location == "fragment"
                              else _with_query)(request.url, request.param, request.value)
                page.goto(target, wait_until="load", timeout=self._timeout)
                time.sleep(0.3)                               # let async sinks fire
                hits = page.evaluate("window.__fzlbHits||[]")
                fired = token in (hits or [])
                return ExecObservation(executed=fired,
                                       detail="playwright" if fired else "")
            finally:
                browser.close()
