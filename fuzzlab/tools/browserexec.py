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
import uuid
from contextlib import suppress
from fuzzlab.core import trace
from fuzzlab.core.urls import bind_query, place_query_param   # the one placement (SP-42)
from fuzzlab.oracle.browser import SENTINEL, ExecObservation, ExecRequest, NotObserved
from fuzzlab.oracle.probe import UnplaceableLocation


def _with_fragment(url: str, param: str, value: str) -> str:
    """``url`` with ``param=value`` in its fragment, through the one owner
    (`core.urls.place_route_query_param`, SP-42): a single-page app's hash route
    (``/#/search``) keeps its route and the pair goes into the route's own query, its
    first occurrence of ``param`` replaced in place (``%20`` for a space: the app's router
    reads it); any other fragment is replaced by the pair, as before."""
    from fuzzlab.core.urls import place_route_query_param
    return place_route_query_param(url, param, value)


#: What a failure text may not keep: a quoted string, or a ``scheme://`` token.


def _store_plan(store) -> tuple[str | None, bytes | None]:
    """``(refusal, json_body)`` of a store step: why it cannot be placed (checked before
    any browser starts; refuse, never relocate, PA-0115), and the JSON body a ``json``
    store sends (FR-FUZZ-56: the app's own body, the payload in the store leaf)."""
    from fuzzlab.tools.store_adapter import WRITE_METHODS   # SP-41
    method = (store.method or "").upper()
    # POST, or PUT/PATCH from an enumerated point (FR-FUZZ-56); never DELETE
    store_methods = WRITE_METHODS | {"POST"}
    if store.location not in ("body", "query", "json") or (
            store.location == "query" and method != "GET") or (
            store.location != "query" and method not in store_methods):
        return f"unplaceable store request {method} {store.location!r}", None
    if store.location != "json":
        return None, None
    from fuzzlab.core.jsonbody import JsonPlacementError, body_for
    try:
        return None, body_for(store.param, store.value, store.entries)
    except JsonPlacementError as exc:
        return f"unplaceable store leaf: {exc}", None


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



class _VisitTrace:
    """One M6 visit's steps (FR-FUZZ-62), noted where each happens, emitted once.

    Created by `PlaywrightBrowserExecutor.run` only when a trace recorder is active; it
    reads the test and strategy (`trace.current`) there, on the strategy's own greenlet.
    Playwright runs its callbacks (the route handler, the sentinel binding, page
    events) in other greenlets, where that context and the recorder are not visible
    (measured, CC-FUZZ-0102): so a callback only notes a stamped fact here, and `emit`,
    called by `run` once the browser and its driver are gone, records the visit's
    events, each with the stamp its step took (``time.time()`` when Python received the
    driver's event: not the browser's clock). Every method is total: the trace never
    changes what the visit does or returns."""

    #: Characters of an ``end`` detail kept.
    MAX_DETAIL = 200

    def __init__(self, request: ExecRequest, token: str):
        self.visit = uuid.uuid4().hex[:12]
        self.test, self.strategy, _role = trace.current()
        self._token = str(token)
        self._steps: list[tuple[float, int, dict]] = []
        self._ended = False
        self._launch_error: str | None = None
        self._unavailable = False
        self._paged = False
        self.answered = 0
        self._failed: list[str] = []
        self._refused: list[tuple[float, str, str]] = []
        self._load = None                  # (wall stamp, monotonic stamp) of `load`
        self._sentinel: float | None = None
        self._commit: float | None = None  # `Navigation.committed_at` (monotonic)
        self._superseded = False
        self._wait: tuple[float, float] | None = None

    # --- noting (each total) -----------------------------------------------------------
    def _note(self, step: str, body: dict, t: float | None = None) -> None:
        try:
            self._steps.append((time.time() if t is None else t, len(self._steps),
                                {"step": step, **body}))
        except Exception:  # noqa: BLE001 - the trace never changes the visit
            pass

    @staticmethod
    def _sent(url, param, value, location) -> dict:
        from fuzzlab.core.urls import canonical_origin
        body = {"url": trace.safe_ref(url), "origin": canonical_origin(url),
                "param": param, "location": location}
        if param is not None and value is not None:
            digest, length = trace.value_digest(value)
            body.update(value_sha=digest, value_len=length,
                        value_preview=trace.value_preview(param, value))
        return body

    @staticmethod
    def _failure(exc) -> dict:
        name = type(exc).__name__
        return {"outcome": "timeout" if "Timeout" in name else "error", "error": name}

    def refused_placement(self, step: str, request: ExecRequest, detail: str) -> None:
        """A placement refusal before any browser starts: the request is not sent, and
        the visit ends ``unplaceable`` here, never derived from the returned observation
        (which would read as "did not fire")."""
        try:
            if step == "store":
                s = request.store
                body = self._sent(s.url, s.param, s.value, s.location) | {
                    "method": (s.method or "").upper()}
            else:
                body = self._sent(request.url, request.param, request.value,
                                  request.location) | {"method": "GET"}
            self._note(step, body | {"outcome": "not_sent", "detail": detail[:120]})
            self.end("unplaceable", detail=detail)
        except Exception:  # noqa: BLE001
            pass

    def launch_failed(self, exc) -> None:
        """The browser or its driver could not start: its class only, never its text."""
        self._launch_error = type(exc).__name__
        self._note("launch", {"outcome": "failed", "error": self._launch_error})

    def unavailable(self) -> None:
        self._unavailable = True

    @staticmethod
    def started() -> tuple[float, float]:
        return time.time(), time.perf_counter()

    def store_done(self, started, s, status, exc=None) -> None:
        try:
            t, clock = started
            body = self._sent(s.url, s.param, s.value, s.location) | {
                "method": "GET" if s.location == "query" else (s.method or "").upper(),
                "elapsed_ms": round((time.perf_counter() - clock) * 1000, 1)}
            if isinstance(exc, PermissionError):     # `checked_api_request`'s refusal
                body.update(outcome="not_sent", detail="out of scope")
            elif exc is not None:
                body.update(self._failure(exc))
            elif isinstance(status, int):
                body.update(outcome="response", status=status)
            else:
                body.update(outcome="no_status")     # a double, or no response object
            self._note("store", body, t)
        except Exception:  # noqa: BLE001
            pass

    def navigate_done(self, started, request: ExecRequest, nav=None, exc=None) -> None:
        try:
            t, clock = started
            located = request.param is not None
            body = self._sent(request.url, request.param, request.value,
                              request.location if located else None)
            body.update(method="GET",
                        elapsed_ms=round((time.perf_counter() - clock) * 1000, 1))
            if located:
                body["value_sent"] = request.location != "fragment"
            if exc is not None:
                body.update(self._failure(exc))
            else:
                status = getattr(getattr(nav, "response", None), "status", None)
                body.update({"outcome": "response", "status": status}
                            if isinstance(status, int) else {"outcome": "no_status"})
                committed = getattr(nav, "committed_at", None)
                self._commit = committed if isinstance(committed, (int, float)) else None
                self._superseded = getattr(nav, "superseded", False) is True
            self._note("navigate", body, t)
        except Exception:  # noqa: BLE001
            pass

    def binding(self, hits: set):
        """The sentinel binding: today's ``hits.add``, and the stamp of this visit's own
        token."""
        def _hit(_source, t):
            hits.add(str(t))
            try:
                if str(t) == self._token and self._sentinel is None:
                    self._sentinel = time.time()
            except Exception:  # noqa: BLE001
                pass
        return _hit

    def on_load(self, load_at: list):
        """The ``load`` callback: today's ``load_at`` stamp, and this step's."""
        def _loaded(*_):
            load_at.__setitem__(0, time.monotonic())
            try:
                if self._load is None:
                    self._load = (time.time(), load_at[0])
            except Exception:  # noqa: BLE001
                pass
        return _loaded

    def on_abort(self, url, reason) -> None:
        """The guard refused a request (a destructive URL): never sent."""
        try:
            self._refused.append((time.time(), str(url), str(reason)))
        except Exception:  # noqa: BLE001
            pass

    def on_out_of_scope(self, url) -> None:
        """The guard refused a request or a WebSocket outside the scope: never sent."""
        self.on_abort(url, "out of scope")

    def on_response(self, _response) -> None:
        self.answered += 1

    def on_failed(self, request) -> None:
        try:
            self._failed.append(str(request.url))
        except Exception:  # noqa: BLE001
            pass

    def listen(self, page) -> None:
        """The page's network events, counted only: what the page received, and its
        requests that failed."""
        try:
            page.on("response", self.on_response)
            page.on("requestfailed", self.on_failed)
            self._paged = True
        except Exception:  # noqa: BLE001
            pass

    def waited(self, window_ms: float, waited_s: float) -> None:
        self._wait = (window_ms, round(waited_s * 1000, 1))

    # --- the end ----------------------------------------------------------------------
    def end(self, outcome: str, detail: str | None = None) -> None:
        if self._ended:
            return
        self._ended = True
        body = {"outcome": outcome}
        if detail:
            body["detail"] = str(detail)[:self.MAX_DETAIL]
        if self._wait is not None:
            body.update(window_ms=self._wait[0], waited_ms=self._wait[1])
        self._note("end", body)

    def end_returned(self, obs) -> None:
        try:
            self.end("executed" if getattr(obs, "executed", False) is True
                     else "not_executed")
        except Exception:  # noqa: BLE001
            pass

    def end_raised(self, exc) -> None:
        """`NotObserved` first: it subclasses `UnplaceableLocation`."""
        try:
            if isinstance(exc, NotObserved):
                self.end("not_observed", detail=str(exc))
            elif isinstance(exc, UnplaceableLocation):
                if self._unavailable:
                    detail = "browser unavailable for this run"
                elif self._launch_error is not None:
                    detail = f"browser unavailable ({self._launch_error})"
                else:
                    detail = f"not placed ({type(exc).__name__})"
                self.end("unplaceable", detail=detail)
            else:
                self.end("error", detail=type(exc).__name__)
        except Exception:  # noqa: BLE001
            pass

    # --- the one emit -------------------------------------------------------------------
    def _derived(self) -> None:
        """The steps known only once the visit is over: ``load``, ``sentinel``, the first
        refusal and the page counts."""
        if self._commit is not None:
            if self._load is not None:
                self._note("load", {"outcome": "fired", "after_commit_ms": round(
                    (self._load[1] - self._commit) * 1000, 1)}, self._load[0])
            else:
                self._note("load", {"outcome": "not_fired",
                                    "superseded": self._superseded})
        if self._sentinel is not None:
            self._note("sentinel", {"outcome": "fired", "after_load_ms": round(
                (self._sentinel - self._load[0]) * 1000, 1) if self._load else None},
                self._sentinel)
        if self._refused:
            from fuzzlab.core.urls import canonical_origin
            t, url, reason = self._refused[0]
            self._note("refused", {"url": trace.safe_ref(url),
                                   "origin": canonical_origin(url),
                                   "detail": reason[:120], "outcome": "not_sent"}, t)
        if self._paged:
            failed = list(self._failed)
            for _t, url, _r in self._refused:       # refused: never sent, not failed
                if url in failed:
                    failed.remove(url)
            self._note("page", {"outcome": "counted", "answered": self.answered,
                                "failed": len(failed), "refused": len(self._refused)})

    def emit(self) -> None:
        """Record the visit's events, each with its own stamp, in stamp order (the
        ``end`` last). Contained: a failure is logged with its class only and never
        replaces the visit's result."""
        try:
            self._derived()
            base = {"test": self.test, "strategy": self.strategy, "visit": self.visit}
            scope = f"test:{self.test}" if self.test else "run"
            last = max((t for t, _n, _b in self._steps), default=0.0)
            closing = {"page": 1, "end": 2}          # the visit's summary, then its end
            ordered = sorted(self._steps, key=lambda s: (
                closing.get(s[2]["step"], 0), s[0], s[1]))
            for t, _n, body in ordered:
                when = max(t, last) if body["step"] in ("page", "end") else t
                trace.emit_step("browser.step", base | body, scope=scope, t=when)
        except Exception as exc:  # noqa: BLE001 - the trace never changes the visit
            logging.warning(f"M6: the visit's trace steps were not recorded "
                            f"({type(exc).__name__})")


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
        # FR-FUZZ-62: one visit's steps, only with an active recorder (none: ``None``,
        # and every ``visit`` use below is skipped)
        visit = _VisitTrace(request, token) if trace.active() is not None else None
        manager = PlaywrightError = None
        entered = False
        try:
            # refuse, never relocate (BUG-0115, PA-0115): checked before any browser
            # starts. A refusal is the oracle's no-verdict signal, raised -- never a
            # returned observation, which its reader takes as "observed, not executed"
            # (BUG-0523, PA-0523)
            if request.param is not None and request.location not in ("query", "fragment"):
                detail = f"unplaceable location {request.location!r}"
                if visit is not None:
                    visit.refused_placement("navigate", request, detail)
                raise UnplaceableLocation(detail)
            if request.store is not None:
                refusal, _body = _store_plan(request.store)
                if refusal is not None:
                    if visit is not None:
                        visit.refused_placement("store", request, refusal)
                    raise UnplaceableLocation(refusal)
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright

            if self._unavailable is not None:          # BUG-0126: no browser, no verdict
                if visit is not None:
                    visit.unavailable()
                raise UnplaceableLocation(self._unavailable)
            try:
                manager = sync_playwright()
                pw = manager.__enter__()               # the driver itself may not start
            except Exception as exc:  # noqa: BLE001 - reviewer A: a driver that cannot
                if visit is not None:                  # start is the same as no browser
                    visit.launch_failed(exc)
                self._launch_failed(exc)
            entered = True
            # a result, or the probe's own no-verdict (NotObserved / a launch failure),
            # or a defect: the driver's stop below never replaces any of them (Z2)
            obs = self._in_browser(pw, request, token, PlaywrightError, visit)
            if visit is not None:
                visit.end_returned(obs)
            return obs
        except BaseException as exc:
            if visit is not None:
                visit.end_raised(exc)                  # contained; re-raised unchanged
            raise
        finally:
            try:
                if entered:
                    self._stop_driver(manager, PlaywrightError)
            finally:
                if visit is not None:
                    visit.emit()                       # contained (FR-FUZZ-62)

    def _in_browser(self, pw, request: ExecRequest, token: str,
                    error, visit: _VisitTrace | None = None) -> ExecObservation:
        from fuzzlab.core.urls import in_origin_scope, origin_scope, url_key
        from fuzzlab.tools.navguard import (browser_launch_args, checked_api_request,
                                            chromium_launch_kwargs, guard_page,
                                            load_state_reached, navigate, release)
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
            if visit is not None:
                visit.launch_failed(exc)
            self._launch_failed(exc)
        self._failures = 0
        context = page = None
        hits: set = set()
        load_ms = min(self.LOAD_WAIT_MS, self._timeout)
        try:
            context = browser.new_context(service_workers="block")   # BUG-0111
            # the sentinel is a binding: every document of the page calls back here,
            # so a hit survives the page navigating afterwards (reviewer B)
            context.expose_binding(SENTINEL, (lambda _source, t: hits.add(str(t)))
                                   if visit is None else visit.binding(hits))
            page = context.new_page()
            if visit is not None:                         # FR-FUZZ-62: counted only
                visit.listen(page)
            # Abort destructive subresources/redirects; the navigation targets
            # themselves are the explicit (ground-truth) points (BUG-0111).
            allowed = {url_key(request.url)}
            if request.store is not None:
                allowed.add(url_key(request.store.url))
            # storage headers go through the guarded route only, in scope, never
            # set_extra_http_headers (FR-CRAWL-14's mechanism, CC-FUZZ-0076)
            if visit is None:
                guard_page(context, allow=frozenset(allowed), in_scope=in_scope,
                           headers=dict(self._headers) or None)
            else:                                         # + recording-only refusals
                guard_page(context, frozenset(allowed), visit.on_abort,
                           in_scope=in_scope, on_out_of_scope=visit.on_out_of_scope,
                           headers=dict(self._headers) or None)
            # a dialog is dismissed and never counted: the payloads call the
            # sentinel, and an app's own alert/confirm is not the probe's doing
            # (BUG-0129)
            page.on("dialog", lambda d: d.dismiss())

            if request.store is not None:                 # stored XSS: plant first
                s = request.store
                _refusal, store_body = _store_plan(s)
                started = visit.started() if visit is not None else None
                try:
                    if store_body is not None:
                        # API requests bypass `route`: scope-check, never redirect
                        checked_api_request(in_scope, s.url)
                        resp = context.request.fetch(
                            s.url, method=s.method.upper(), data=store_body,
                            headers={"Content-Type": "application/json"},
                            max_redirects=0)
                    elif s.location == "body":
                        # API requests bypass `route`: scope-check, never redirect
                        checked_api_request(in_scope, s.url)
                        resp = context.request.fetch(s.url, method=s.method.upper(),
                                                     form={s.param: s.value},
                                                     max_redirects=0)
                    else:
                        # the commit, then a bounded load, as the observe navigation
                        # (BUG-0137 review A-N3; the one helper since BUG-0138)
                        # a `StoreStep` carries no query siblings (its `entries` are
                        # a JSON body's leaves): the standalone rule (FR-FUZZ-64)
                        resp = navigate(page, place_query_param(s.url, s.param, s.value),
                                        timeout_ms=self._timeout, wait_until="load",
                                        wait_ms=load_ms).response
                except BaseException as exc:
                    if visit is not None:
                        visit.store_done(started, s, None, exc)
                    raise
                if visit is not None:
                    visit.store_done(started, s, getattr(resp, "status", None))

            target = request.url
            if request.param is not None and request.value is not None:
                if request.location == "fragment":
                    target = _with_fragment(request.url, request.param, request.value)
                elif request.entries is not None:     # the bound rule (FR-FUZZ-64)
                    target = bind_query(request.url, request.entries, request.param,
                                        request.value)
                else:                                 # the standalone rule
                    target = place_query_param(request.url, request.param,
                                               request.value)
            # when the observe navigation's `load` fires (BUG-0137 review Z3)
            load_at: list = [None]
            page.once("load", (lambda *_: load_at.__setitem__(0, time.monotonic()))
                      if visit is None else visit.on_load(load_at))
            # BUG-0137: wait for the commit only, then for `load` briefly: a load
            # that a refused navigation superseded never comes, and is not waited
            # out (it was `timeout_ms`, then a raise); the one helper (BUG-0138),
            # which also ends the wait once that refused navigation is reported
            started = visit.started() if visit is not None else None
            try:
                nav = navigate(page, target, timeout_ms=self._timeout, wait_until="load",
                               wait_ms=load_ms)
            except BaseException as exc:
                if visit is not None:
                    visit.navigate_done(started, request, exc=exc)
                raise
            if visit is not None:
                visit.navigate_done(started, request, nav)
            waiting = time.monotonic()
            fired = self._wait_for_token(                  # BUG-0126: async sinks
                page, hits, token, error, load_at,
                cap=nav.committed_at + (self._timeout + self.SETTLE_MS) / 1000)
            if visit is not None:
                visit.waited(self.SETTLE_MS, time.monotonic() - waiting)
            loaded = fired or load_state_reached(page, "load")
            if fired or token in hits:                     # re-read after the load check
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
