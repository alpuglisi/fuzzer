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
import re
import time
from contextlib import suppress
from urllib.parse import urlencode, urlsplit, urlunsplit

from fuzzlab.oracle.browser import SENTINEL, ExecObservation, ExecRequest, NotObserved
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


#: What a failure text may not keep: a quoted string, or a ``scheme://`` token.
_QUOTED = re.compile(r"\"[^\"]*\"|'[^']*'")
_URL_TOKEN = re.compile(r"\S*://\S*")


def _failure_reason(exc) -> str:
    """Why the browser observed nothing (BUG-0137): the error's class and the first
    line of its text with every quoted string and every ``scheme://`` token removed,
    then capped. A URL carries the payload, and Playwright prints one quoted
    (``Navigation to "<url>" is interrupted by another navigation to "<url>"``) or
    after ``at`` (``net::ERR_ABORTED at <url>``): neither is ever kept (review A)."""
    first = str(exc).splitlines()[0] if str(exc) else ""
    text = _URL_TOKEN.sub("", _QUOTED.sub("", first)).replace('"', "").replace("'", "")
    text = " ".join(text.split())
    text = text[:-3] if text.endswith(" at") else text
    return f"the browser could not load the page ({type(exc).__name__}: {text[:120]})"


def _loaded(page, error) -> bool:
    """Has the page's document reached ``load`` (at any point so far)? Playwright
    answers at once for a load already fired."""
    try:
        page.wait_for_load_state("load", timeout=1)
        return True
    except error:
        return False


class PlaywrightBrowserExecutor:
    """Drive a headless browser to confirm stored/DOM XSS. Lab-only, loopback targets."""

    def __init__(self, headless: bool = True, timeout_ms: int = 8000,
                 storage_headers: dict | None = None):
        self._headless = headless
        self._timeout = timeout_ms
        self._headers = storage_headers or {}
        #: why this run has no browser (BUG-0126), once launches have failed
        self._unavailable: str | None = None
        self._failures = 0                             # launch failures in a row
        self._stop_failures = 0                        # driver stops failed in a row

    #: How long a loaded page may take to fire the sentinel: a single-page app renders
    #: after its own API calls, well after ``load`` (BUG-0126: 300 ms missed Juice Shop's
    #: search sink, which fires at about one second). Polled; the wait ends on the hit.
    SETTLE_MS = 4000
    _POLL_MS = 100
    #: How long the observe navigation waits for ``load`` after it commits (BUG-0137).
    #: Bounded and suppressed: a page whose script navigates to a refused URL before
    #: ``load`` never fires it (the aborted navigation stopped the load), and the
    #: sentinel wait that follows sees a sink whenever it fires.
    LOAD_WAIT_MS = 3000

    def _wait_for_token(self, page, hits: set, token: str, error, load_at=None,
                        cap: float | None = None) -> bool:
        """Wait up to `SETTLE_MS` for ``token`` in ``hits``, which the context's
        sentinel binding fills from any document of the page -- a hit before a
        navigation is kept (reviewers A and B). Waiting pumps Playwright's events; a page
        that closes or navigates under the wait is "not yet", never an error (only a
        Playwright error ends the wait, BUG-0137 review A-N1). Once ``load`` has fired
        (``load_at[0]``, a `time.monotonic()`), the wait lasts a full `SETTLE_MS` from
        it, up to ``cap`` (BUG-0137 review Z3): a slow page's sink is still seen."""
        settle = self.SETTLE_MS / 1000
        deadline = time.monotonic() + settle
        while token not in hits:
            if load_at is not None and load_at[0] is not None:
                after_load = load_at[0] + settle
                deadline = max(deadline, after_load if cap is None else
                               min(after_load, cap))
            if time.monotonic() >= deadline:
                break
            try:
                page.wait_for_timeout(self._POLL_MS)
            except error:                # the page or context went away: no more hits
                break
        return token in hits

    def run(self, request: ExecRequest, token: str) -> ExecObservation:
        # refuse, never relocate (BUG-0115, PA-0115): checked before any browser starts
        if request.param is not None and request.location not in ("query", "fragment"):
            return ExecObservation(False, detail=f"unplaceable location {request.location!r}")
        if request.store is not None and request.store.location not in ("body", "query"):
            return ExecObservation(False, detail="unplaceable store location "
                                                 f"{request.store.location!r}")
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright

        if self._unavailable is not None:              # BUG-0126: no browser, no verdict
            raise UnplaceableLocation(self._unavailable)
        try:
            manager = sync_playwright()
            pw = manager.__enter__()                   # the driver itself may not start
        except Exception as exc:  # noqa: BLE001 - reviewer A: a driver that cannot start
            self._launch_failed(exc)                   # is the same as no browser
        try:
            # a result, or the probe's own no-verdict (NotObserved / a launch failure),
            # or a defect: the driver's stop below never replaces any of them (Z2)
            return self._in_browser(pw, request, token, PlaywrightError)
        finally:
            self._stop_driver(manager, PlaywrightError)

    def _in_browser(self, pw, request: ExecRequest, token: str,
                    error) -> ExecObservation:
        from fuzzlab.core.urls import in_origin_scope, origin_scope, url_key
        from fuzzlab.tools.navguard import (browser_launch_args, checked_api_request,
                                            chromium_launch_kwargs, guard_page, release)
        # The browser reaches only the observe and store origins (BUG-0123).
        scope_urls = [request.url] + ([request.store.url] if request.store else [])
        origins = origin_scope(*scope_urls)

        def in_scope(url):
            return in_origin_scope(url, origins)
        launch = chromium_launch_kwargs(browser_launch_args(scope_urls),
                                        headless=self._headless)       # BUG-0126
        try:
            browser = pw.chromium.launch(**launch)
        except Exception as exc:  # noqa: BLE001 - any launch failure: no browser here
            self._launch_failed(exc)
        self._failures = 0
        context = page = None
        hits: set = set()
        load_ms = min(self.LOAD_WAIT_MS, self._timeout)
        try:
            context = browser.new_context(service_workers="block")   # BUG-0111
            # the sentinel is a binding: every document of the page calls back here,
            # so a hit survives the page navigating afterwards (reviewer B)
            context.expose_binding(SENTINEL, lambda _source, t: hits.add(str(t)))
            page = context.new_page()
            # Abort destructive subresources/redirects; the navigation targets
            # themselves are the explicit (ground-truth) points (BUG-0111).
            allowed = {url_key(request.url)}
            if request.store is not None:
                allowed.add(url_key(request.store.url))
            # storage headers go through the guarded route only, in scope, never
            # set_extra_http_headers (FR-CRAWL-14's mechanism, CC-FUZZ-0076)
            guard_page(context, allow=frozenset(allowed), in_scope=in_scope,
                       headers=dict(self._headers) or None)
            # a dialog is dismissed and never counted: the payloads call the
            # sentinel, and an app's own alert/confirm is not the probe's doing
            # (BUG-0129)
            page.on("dialog", lambda d: d.dismiss())

            if request.store is not None:                 # stored XSS: plant first
                s = request.store
                if s.location == "body":
                    # API requests bypass `route`: scope-check, never redirect
                    checked_api_request(in_scope, s.url)
                    context.request.post(s.url, form={s.param: s.value},
                                         max_redirects=0)
                else:
                    # the commit, then a bounded load, as the observe navigation
                    # (BUG-0137 review A-N3)
                    page.goto(_with_query(s.url, s.param, s.value),
                              wait_until="commit", timeout=self._timeout)
                    with suppress(error):
                        page.wait_for_load_state("load", timeout=load_ms)

            target = request.url
            if request.param is not None and request.value is not None:
                target = (_with_fragment if request.location == "fragment"
                          else _with_query)(request.url, request.param, request.value)
            # when the observe navigation's `load` fires (BUG-0137 review Z3)
            load_at: list = [None]
            page.once("load", lambda *_: load_at.__setitem__(0, time.monotonic()))
            # BUG-0137: wait for the commit only, then for `load` briefly: a load
            # that a refused navigation superseded never comes, and is not waited
            # out (it was `timeout_ms`, then a raise)
            page.goto(target, wait_until="commit", timeout=self._timeout)
            committed = time.monotonic()
            with suppress(error):
                page.wait_for_load_state("load", timeout=load_ms)
            fired = self._wait_for_token(                  # BUG-0126: async sinks
                page, hits, token, error, load_at,
                cap=committed + (self._timeout + self.SETTLE_MS) / 1000)
            loaded = fired or _loaded(page, error)
            if fired or token in hits:                     # re-read after `_loaded`
                return ExecObservation(executed=True, detail="playwright")
            if not loaded:
                # never loaded, even by the end of the sentinel wait, and no hit:
                # the page was not observed -- no verdict, never a negative
                raise NotObserved(
                    f"the page committed but did not finish loading within "
                    f"{load_ms} ms (a navigation superseded its load, or it is "
                    f"slow): not observed")
            return ExecObservation(executed=False, detail="")
        except error as exc:
            # BUG-0137: a page that failed to plant or load (a refused redirect, a
            # timeout, a crash) observed nothing: no verdict for this payload --
            # never a negative, never an exception that ends the run. A hit recorded
            # before the failure still counts: pending sentinel calls are pumped
            # first (review A-N2).
            if page is not None:
                with suppress(error):
                    page.wait_for_timeout(self._POLL_MS)
            if token in hits:
                return ExecObservation(executed=True, detail="playwright")
            raise NotObserved(_failure_reason(exc)) from None
        finally:
            if context is not None:
                release(context)
            with suppress(error):                   # BUG-0137: a dead browser closes too
                browser.close()

    def _stop_driver(self, manager, error) -> None:
        """Stop the Playwright driver (BUG-0137 review Z2). A Playwright error there is
        logged and contained: it never replaces the probe's result or its no-verdict.
        After `MAX_LAUNCH_FAILURES` stops in a row fail, the browser is unavailable for
        the run (BUG-0126's path): a driver that cannot stop is not reused."""
        try:
            manager.__exit__(None, None, None)
        except error as exc:
            self._stop_failures += 1
            logging.warning(f"M6: the Playwright driver did not stop cleanly "
                            f"({type(exc).__name__})")
            if self._stop_failures >= self.MAX_LAUNCH_FAILURES:
                self._unavailable = (f"browser unavailable: the Playwright driver did "
                                     f"not stop cleanly {self._stop_failures} times in "
                                     f"a row ({type(exc).__name__})")
                logging.warning(f"M6 browser execution disabled for this run: "
                                f"{self._unavailable}")
            return
        self._stop_failures = 0

    #: Launch failures in a row before the browser mechanisms are off for the run: one
    #: transient failure (memory pressure) does not silence M6 (reviewer A).
    MAX_LAUNCH_FAILURES = 2

    def _launch_failed(self, exc):
        """BUG-0126: a browser (or driver) that cannot start is "no verdict" from the
        browser mechanisms, never a negative and never a crash. After
        `MAX_LAUNCH_FAILURES` in a row it is remembered for the run, so later probes do
        not retry; the reason reaches every such candidate's inconclusive record."""
        why = f"browser unavailable: {str(exc).splitlines()[0][:160] if str(exc) else exc!r}"
        self._failures += 1
        if self._failures >= self.MAX_LAUNCH_FAILURES:
            self._unavailable = why
            logging.warning(f"M6 browser execution disabled for this run: {why}")
        raise UnplaceableLocation(why) from None
