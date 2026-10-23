"""BUG-0561 / PA-0561: a failed navigation is over only when its error page has LOADED.

`navguard._settle_failure` (SP-01, BUG-0522's fix) took a failed navigation as over as
soon as Chromium's error page (``chrome-error://chromewebdata/``) COMMITTED. That page
then still loads for 15-25 ms (p95 about 130 ms under disk I/O load). A navigation
started in that window -- disco's restore ``about:blank``, the spider's ``_window`` /
``_leave`` / pre-seed blank -- was sometimes dropped by Chromium, with no commit and no
error, and its ``goto`` waited out its whole timeout (15 s; about 1% of disco restores
under heavy disk I/O, every tree since BUG-0522). Now the failure also waits for that
error page's own ``load``, with what is left of the same `ERROR_PAGE_WAIT_MS` budget;
an expiry is counted and logged, never raised.

These tests drive `navguard.navigate` / `reload` against a page double on a fake clock
(``navguard.time``): deterministic, no browser. The double models what the RCA measured:
the error page commits a few event pumps after ``goto`` raised and loads ``LOAD_MS``
later, and an ``about:blank`` started from an error page that has not loaded yet is
dropped (it times out). The double drops it every time, where Chromium dropped about 6%
of such navigations (15 of 268): the model makes the measured hazard certain, so the
order is what is tested.
"""

from __future__ import annotations

import logging
import time

import pytest

#: Event pumps (`wait_for_timeout(20)`) after ``goto`` raised before the error page
#: commits, and how long it then takes to load (fake milliseconds).
COMMIT_PUMPS = 3
PUMP_MS = 20
LOAD_MS = 40
ERROR_URL = "chrome-error://chromewebdata/"
BASE = "http://127.0.0.1:9/"


def _playwright():
    try:
        from playwright.sync_api import Error
        from playwright.sync_api import TimeoutError as PWTimeout
    except ImportError as exc:
        from tests._browser import skip_or_fail
        skip_or_fail(f"playwright unavailable: {exc}")
    return Error, PWTimeout


class _Clock:
    """`navguard.time` on a fake clock: ``monotonic`` is fake, everything else real."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, ms: float) -> None:
        self.now += ms / 1000

    def __getattr__(self, name):
        return getattr(time, name)


class _Frame:
    def __init__(self, url: str):
        self.url = url


class _Page:
    """A Playwright page double. A failing ``goto`` / ``reload`` raises as Playwright
    does, and the browser's later work is scheduled on the fake clock: each commit lands
    on a given event pump after the raise (``framenavigated`` fires then), and an error
    page loads ``load_ms`` after its commit (None: never). Every step is appended to
    ``steps``: ``("goto", url)``, ``("commit", url)``, ``("wait-load", state, timeout,
    url)``, ``("load", url)``, ``("dropped", url)``."""

    def __init__(self, clock: _Clock, *, load_ms: float | None = LOAD_MS):
        self.Error, self.Timeout = _playwright()
        self.clock, self.load_ms = clock, load_ms
        self.main_frame = _Frame(BASE + "start")
        self.target = BASE + "start"                  # what a reload loads
        self.listeners: dict[str, list] = {"framenavigated": [], "requestfailed": []}
        self.steps: list[tuple] = []
        self.pumps = 0
        self.scheduled: list[tuple[int, str]] = []    # (pump, url) commits to come
        self.load_at: float | None = clock.now        # the current document's load

    # --- the Playwright API navguard uses ---------------------------------------------
    @property
    def url(self) -> str:
        return self.main_frame.url

    def on(self, event, fn):
        self.listeners[event].append(fn)

    def remove_listener(self, event, fn):
        self.listeners[event].remove(fn)

    def goto(self, url, *, wait_until, timeout):
        self.steps.append(("goto", url))
        if url == "about:blank":
            if not self._loaded():                  # Chromium's drop (BUG-0561)
                self.steps.append(("dropped", url))
                self.clock.advance(timeout)
                raise self.Timeout(f"Page.goto: Timeout {timeout}ms exceeded.")
            self._commit(url, error_page=False)
            return
        self.target = url
        if "overtaken" in url:
            self._schedule([(COMMIT_PUMPS, ERROR_URL), (COMMIT_PUMPS + 2, url)])
            raise self.Error(f'Page.goto: Navigation to "{url}" is interrupted by another '
                             f'navigation to "{ERROR_URL}"\nCall log:\n  - navigating')
        if "refused" in url:
            raise self.Error(f"Page.goto: net::ERR_ABORTED at {url}\nCall log:\n  - x")
        self._schedule([(COMMIT_PUMPS, ERROR_URL)])
        raise self.Error(f"Page.goto: net::ERR_HTTP_RESPONSE_CODE_FAILURE at {url}\n"
                         f"Call log:\n  - navigating to \"{url}\", waiting until")

    def reload(self, *, wait_until, timeout):
        self.steps.append(("reload", self.target))
        self._schedule([(COMMIT_PUMPS, ERROR_URL)])
        raise self.Error(f"Page.reload: net::ERR_HTTP_RESPONSE_CODE_FAILURE at "
                         f"{self.target}\nCall log:\n  - reloading")

    def wait_for_timeout(self, ms):
        self.clock.advance(ms)
        self.pumps += 1
        for at, url in [s for s in self.scheduled if s[0] == self.pumps]:
            self.scheduled.remove((at, url))
            self._commit(url, error_page=url.startswith("chrome-error:"))

    def wait_for_load_state(self, state, *, timeout):
        self.steps.append(("wait-load", state, timeout, self.url))
        if self._loaded():
            return
        if self.load_at is None or self.load_at - self.clock.now > timeout / 1000:
            self.clock.advance(timeout)
            raise self.Timeout(f'Timeout {timeout}ms exceeded waiting for "{state}"')
        self.clock.now = self.load_at
        self.steps.append(("load", self.url))

    # --- the browser's own work -------------------------------------------------------
    def _loaded(self) -> bool:
        return self.load_at is not None and self.clock.now >= self.load_at

    def _schedule(self, commits):
        self.pumps = 0
        self.scheduled = list(commits)

    def _commit(self, url, *, error_page: bool):
        self.main_frame.url = url
        self.steps.append(("commit", url))
        if error_page:
            self.load_at = (None if self.load_ms is None
                            else self.clock.now + self.load_ms / 1000)
        else:
            self.load_at = self.clock.now
        for fn in list(self.listeners["framenavigated"]):
            fn(self.main_frame)


class _Warnings(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def clock(monkeypatch):
    from fuzzlab.tools import navguard
    c = _Clock()
    monkeypatch.setattr(navguard, "time", c)
    return c


def _fail(page, how: str, url: str):
    """One failed navigation through SP-01; the raise is recorded as a step."""
    from fuzzlab.tools import navguard
    try:
        if how == "navigate":
            navguard.navigate(page, url, timeout_ms=15000)
        else:
            navguard.reload(page, timeout_ms=15000)
    except page.Error as exc:
        page.steps.append(("raise", str(exc).splitlines()[0]))
        return exc
    raise AssertionError(f"{how} of {url} did not raise")


@pytest.mark.parametrize("how", ["navigate", "reload"])
@pytest.mark.parametrize("failures", [1, 2])
def test_a_failure_raises_only_after_its_error_page_has_loaded(failures, how, clock):
    """BUG-0561: each failed navigation (one, and two in a row) raises only after its
    own error page committed AND ``wait_for_load_state("load")`` was awaited with what is
    left of the `ERROR_PAGE_WAIT_MS` budget; then the restore's ``about:blank`` lands.
    Before: the raise followed the commit at once, and the ``about:blank`` started while
    the error page still loaded (dropped: a 15 s timeout)."""
    from fuzzlab.tools import navguard
    page = _Page(clock)
    remaining = navguard.ERROR_PAGE_WAIT_MS - COMMIT_PUMPS * PUMP_MS
    expected = []
    for k in range(failures):
        url = f"{BASE}missing{k}" if how == "navigate" else page.target
        exc = _fail(page, how, url)
        assert getattr(exc, navguard.NAVIGATION_SETTLED_ATTR) == ERROR_URL
        verb, api = ("goto", "goto") if how == "navigate" else ("reload", "reload")
        expected += [(verb, url), ("commit", ERROR_URL),
                     ("wait-load", "load", pytest.approx(remaining), ERROR_URL),
                     ("load", ERROR_URL),
                     ("raise", f"Page.{api}: net::ERR_HTTP_RESPONSE_CODE_FAILURE at {url}")]
    assert page.steps == expected, (
        ("a failed navigation must raise only after its own error page's commit and "
         "then that page's load, awaited with the rest of the budget"), page.steps)
    nav = navguard.navigate(page, "about:blank", timeout_ms=15000, wait_until="load")
    assert page.url == "about:blank" and nav.reached
    assert ("dropped", "about:blank") not in page.steps


def test_an_error_page_that_never_loads_expires_within_the_budget_and_is_counted(clock):
    """The load wait shares the commit wait's budget: an error page that never loads
    ends the wait at `ERROR_PAGE_WAIT_MS` from the failure, the expiry is counted and
    logged (BUG-0561), and the failure's own error is raised -- never the wait's."""
    from fuzzlab.tools import navguard
    page = _Page(clock, load_ms=None)
    warned = _Warnings()
    logger = logging.getLogger("fuzzlab.navguard")
    level = logger.level
    logger.setLevel(logging.WARNING)
    logger.addHandler(warned)
    before = navguard.error_page_waits()
    start = clock.now
    try:
        exc = _fail(page, "navigate", BASE + "missing")
    finally:
        logger.removeHandler(warned)
        logger.setLevel(level)
    after = navguard.error_page_waits()
    spent_ms = (clock.now - start) * 1000
    remaining = navguard.ERROR_PAGE_WAIT_MS - COMMIT_PUMPS * PUMP_MS
    assert ("wait-load", "load", pytest.approx(remaining), ERROR_URL) in page.steps, \
        page.steps
    assert spent_ms == pytest.approx(navguard.ERROR_PAGE_WAIT_MS), spent_ms
    assert after["waited"] - before["waited"] == 1
    assert after["expired"] - before["expired"] == 1, (before, after)
    assert any("did not load" in m and "BUG-0561" in m for m in warned.messages), \
        warned.messages
    assert not isinstance(exc, page.Timeout)
    assert str(exc).startswith("Page.goto: net::ERR_HTTP_RESPONSE_CODE_FAILURE at ")
    # the commit did land: the cleanup keeps the error page, nothing more is navigated
    assert getattr(exc, navguard.NAVIGATION_SETTLED_ATTR) == ERROR_URL
    assert navguard.end_failed_load(page, exc, timeout_ms=15000) == "error-page"


def test_an_abort_and_an_overtaken_navigation_wait_as_before(clock):
    """Not pinning (they pass on 5502228 too): an abort (ERR_ABORTED: the previous
    document stays) waits for nothing; an overtaken navigation waits for the error page's
    commit and then its own late commit, and no load -- its last document is the
    overtaken navigation's own (not the error page), and a navigation started while it
    loads was never dropped in the BUG-0561 measurement (CC-CRAWL-0065)."""
    from fuzzlab.tools import navguard
    page = _Page(clock)
    before = navguard.error_page_waits()
    _fail(page, "navigate", BASE + "refused")
    assert page.steps == [("goto", BASE + "refused"),
                          ("raise", f"Page.goto: net::ERR_ABORTED at {BASE}refused")]
    assert navguard.error_page_waits() == before
    page.steps.clear()
    url = BASE + "overtaken"
    exc = _fail(page, "navigate", url)
    overtaken = (f'Page.goto: Navigation to "{url}" is interrupted by another '
                 f'navigation to "{ERROR_URL}"')
    assert page.steps == [("goto", url), ("commit", ERROR_URL), ("commit", url),
                          ("raise", overtaken)]
    assert getattr(exc, navguard.NAVIGATION_SETTLED_ATTR) == url
