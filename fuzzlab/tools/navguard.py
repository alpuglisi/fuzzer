"""Browser-side scope and destructive-URL guard (NFR-CRAWL/FUZZ/AUD-safe; BUG-0111,
BUG-0123).

A headless browser sends requests no link queue controls: redirects, page scripts'
``fetch``/XHR, ``<img>``/``<iframe>`` subresources, popups, WebSockets, preconnects.
Every one is checked where it is made (PA-0123):

* **the route** -- ``guard_page`` routes the whole browser *context* (popups included):
  a request outside the scope origins (``core.urls.in_origin_scope``) or one
  ``core.urls.destructive_reason`` flags is aborted before it is sent, unless, for the
  destructive rule only, that exact URL (by ``url_key``) is in ``allow`` -- the
  operator's explicit input, which never lifts scope. Playwright never routes a
  redirect's later hops, so the handler fetches each allowed request itself without
  following redirects and walks the chain, every hop checked the same way. **Those
  fetches are made by the Playwright driver, not by Chromium** (verified live), so for
  every routed request this predicate is the only guard; it is checked before every
  fetch, and the callers fix the scope before the browser starts;
* **Chromium's own traffic** -- what the route never sees (a preconnect, a DNS
  prefetch, a landing page the browser re-requests, background services, WebSocket
  connections) is confined by ``browser_launch_args``: no proxy, and nothing resolvable
  outside the scope ``host:port`` pairs, IP literals included.

Callers open their pages with ``service_workers="block"``: a service worker's own
requests bypass ``page.route``. WebSockets are routed with ``route_web_socket``.

A session's headers (a bearer) are added **by the route only**, to a request that passed
the scope predicate and the caller's header scope, and to each fetched redirect hop
that does -- never ``set_extra_http_headers`` (FR-CRAWL-14).

In an authenticated context (the caller's ``cookie_scope``, FR-SESS-20, BUG-0134) the
session never reaches an in-scope origin outside the session's: browser cookies are
port-agnostic, so the context's jar and its pages' ``document.cookie`` /
``localStorage`` would otherwise reach another app on another port of the host.
* **Documents** (a navigation, top-level or frame, and a redirect landing there) and
  **WebSockets** on such an origin are aborted (never connected): a document loaded
  there would run that app's script with the context's port-agnostic cookies.
* **Subresources** there (an image, a script, an XHR), the request and every redirect
  hop, are fetched through one dedicated cookie-less request context per guard
  (``isolated_request()``, a ``playwright.request.new_context()`` with no storage),
  each fetch with an explicit empty ``Cookie`` header so that context's own jar is
  never sent (review round 3, V1), never ``route.fetch`` or the context's request client, which would send the jar and
  write that origin's ``Set-Cookie`` into it; the answer is fulfilled with its
  ``Set-Cookie`` removed (review round 1, A-M1/A-M2: both seen live).
A ``request_refusal`` hook sees a request's body before it is sent (FR-SESS-19's login
window).

The crawler's **reveal window** (FR-CRAWL-15/16, W1-W3) uses two hooks: ``window`` on
the route (asked for every request after the scope and destructive checks, and for
each redirect hop, with whether it is a navigation) and ``ws_hold`` on WebSockets (an
in-scope socket goes through a forwarding handler; a page-to-server message is
forwarded only while ``ws_hold()`` is false, else dropped and reported).
"""

from __future__ import annotations

import contextlib
import logging
import time
import weakref
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlsplit

from fuzzlab.core.urls import canonical_origin, destructive_reason, document_key, url_key


def _scrubbed(text: str) -> str:
    """A log line with any FR-CRAWL-17 probe marker replaced (P4, review B-N2): a probe
    URL's path, or an error quoting the URL, never carries one into the log."""
    from fuzzlab.tools.spa import scrub_markers
    return scrub_markers(text)

#: Not network requests: never scope-checked.
_LOCAL_SCHEMES = ("data:", "blob:", "about:")
_REDIRECTS = (301, 302, 303, 307, 308)


def make_route_handler(allow: frozenset[str] = frozenset(),
                       on_abort: Callable[[str, str], None] | None = None, *,
                       in_scope: Callable[[str], bool],
                       on_out_of_scope: Callable[[str], None] | None = None,
                       api=None,
                       method_refusal: Callable[[str, str], str | None] | None = None,
                       observe: Callable[[object, object], None] | None = None,
                       request_refusal: Callable[[str, str, dict, object], str | None]
                       | None = None,
                       headers: dict[str, str] | None = None,
                       header_scope: Callable[[str], bool] | None = None,
                       window: Callable[[str, str, bool], str | None] | None = None,
                       cookie_scope: Callable[[str], bool] | None = None,
                       on_session_withheld: Callable[[str, str, str], None] | None = None,
                       isolated_request: Callable[[], object] | None = None):
    """The route handler ``guard_page`` installs (split out so it is testable).

    Scope first (BUG-0123): a URL ``in_scope`` refuses is aborted, whatever ``allow``
    says. Then the destructive check (BUG-0111), which ``allow`` may lift. An allowed
    request is fetched here with ``max_redirects=0``; a redirect chain is walked hop by
    hop through ``api`` (the context's request client, sharing its cookies), each hop
    checked like the first, and the request aborted at the first refused hop. A
    redirected navigation is answered with one redirect to its checked landing URL
    (so ``page.url`` and relative links stay right; the browser requests that page a
    second time), any other request with the landing response itself.

    ``method_refusal(method, url)`` (forms phase 3, FR-CRAWL-12): a reason aborts the
    first request whatever ``allow`` says (the crawler refuses a browser-initiated
    DELETE); ``on_abort`` is told. ``observe(request, response)`` is called with each
    request that was sent and its final response, before it is answered (the crawler
    reads already-loaded script bodies and captures request bodies there, FR-CRAWL-13);
    it is contained: a failing observer is logged and never changes the answer
    (PA-0086(2)).

    ``request_refusal(method, url, headers, body)`` (FR-SESS-19's login window): a
    reason aborts the request before it is sent, and every redirect hop that keeps the
    body (307/308) is asked again; the log line names the host only. ``headers`` (a
    session's headers, FR-CRAWL-14) are added **here only**, to ``route.fetch`` and to
    each fetched redirect hop, and only for a URL that passed ``in_scope`` and
    ``header_scope`` (default ``in_scope``) -- never ``set_extra_http_headers``, which
    would hand them to whatever the browser sends.

    ``cookie_scope`` (an authenticated context, FR-SESS-20): for an in-scope URL it
    refuses (another origin than the session's), a document request (a navigation, or
    a redirect hop of one) is aborted with ``"aborted"`` (``ERR_ABORTED``, as the reveal
    window does: the page stays where it is; ``"blockedbyclient"`` would commit
    Chromium's error page in its place, review round 2 T1), and
    ``on_session_withheld(url, kind, source)`` is told: ``kind`` is ``"document"`` for
    a page navigation's own target, ``"landing"`` for its redirect landing, ``"frame"``
    for a child frame's, and ``source`` the URL the request chain started at (the
    navigation's target). Any other request, and each such redirect hop, is fetched
    through the guard's one cookie-less request context (``isolated_request()``,
    called once when the handler is built and kept for the guard's life; kind
    ``"request"``), with an empty
    ``Cookie`` header and without the session's headers, and fulfilled with
    ``Set-Cookie`` removed. Without
    ``isolated_request`` such a request is aborted (fail closed). None: nothing is
    withheld (an unauthenticated context has no session to withhold).

    ``window(method, url, navigation)`` (the crawler's reveal window, FR-CRAWL-15/16):
    asked after the scope and destructive checks, before anything is fetched, for the
    request and again for every redirect hop (a navigation's hop is a navigation too);
    a reason aborts it. The caller keeps its own state (whether the window is open, what it
    blocked, which navigation targets to enqueue)."""
    def refused(url: str) -> bool:
        if not in_scope(url):
            logging.info(f"blocked out-of-scope browser request to "
                         f"{urlsplit(url).hostname or url[:40]!r}")
            if on_out_of_scope is not None:
                on_out_of_scope(url)
            return True
        reason = destructive_reason(url)
        if reason is not None and url_key(url) not in allow:
            logging.info(_scrubbed(f"blocked destructive browser request "
                                   f"{url.split('?', 1)[0]} ({reason!r})"))
            if on_abort is not None:
                on_abort(url, reason)
            return True
        return False

    def session_headers(url: str) -> dict[str, str]:
        """The session's headers for ``url``: only after ``in_scope`` (the caller has
        already refused anything else) and ``header_scope`` pass (FR-CRAWL-14)."""
        if not headers or not in_scope(url) or not (header_scope or in_scope)(url):
            return {}
        return dict(headers)

    def withheld(url: str) -> bool:
        """An authenticated context's request to an in-scope origin outside the
        session's (FR-SESS-20): the session must not reach it."""
        return cookie_scope is not None and in_scope(url) and not cookie_scope(url)

    def tell_withheld(url: str, kind: str, source: str) -> None:
        logging.info(f"sent no session to {urlsplit(url).hostname or '?'!r} "
                     f"({kind}: another origin than the session's, FR-SESS-20)")
        if on_session_withheld is not None:
            on_session_withheld(url, kind, source)

    # the guard's one cookie-less request context (R2, V1), made once, here, when the
    # guard is built: route handlers run concurrently, so a lazy "make it if missing"
    # in the handler made several (seen live)
    isolated = {"ctx": isolated_request() if isolated_request is not None else None}

    def isolated_fetch(url: str, method: str, data, req_headers):
        """One fetch through the guard's one cookie-less request context (R2), kept for
        the guard's life and disposed by its creator at teardown (the spider's
        ``_stop_browser``). Every fetch -- the request and every hop -- carries an
        explicit empty ``Cookie`` header, so whatever that context's own jar stored
        from an earlier answer is never sent: concurrent withheld fetches cannot carry
        one another's cookies (review round 3, V1: retiring a context once it held a
        cookie raced with fetches already in flight; seen live)."""
        sent = {k: v for k, v in (req_headers or {}).items()
                if k.lower() not in ("cookie", "authorization")}
        sent["cookie"] = ""                       # the jar is never sent (V1)
        return isolated["ctx"].fetch(url, method=method, max_redirects=0, data=data,
                                     headers=sent)

    def body_refused(method: str, url: str, req_headers, body) -> bool:
        why = request_refusal(method, url, req_headers, body) if request_refusal else None
        if why is None:
            return False
        logging.info(f"blocked a browser {method} to "
                     f"{urlsplit(url).hostname or '?'!r} ({why})")    # the host only
        if on_abort is not None:
            on_abort(url, why)
        return True

    def window_refused(method: str, url: str, navigation: bool) -> bool:
        why = window(method, url, navigation) if window is not None else None
        if why is None:
            return False
        logging.info(f"blocked a browser {method} to {urlsplit(url).hostname or '?'!r} "
                     f"in the reveal window ({why})")              # the host only
        return True

    def handler(route, request=None) -> None:
        req = request if request is not None else route.request
        url = req.url
        if url.lower().startswith(_LOCAL_SCHEMES):
            route.continue_()
            return
        # BUG-0136 (PA-0136): every abort of a document request -- a navigation,
        # top-level or frame, and each of its redirect hops -- uses "aborted"
        # (ERR_ABORTED), whatever the reason: the current document survives (the
        # default code commits Chromium's error page in its place) and `goto` of that
        # target still raises. A subresource keeps the default code.
        document = _is_document(req)

        def abort() -> None:
            route.abort(_abort_code(document)) if document else route.abort()

        if refused(url):
            abort()
            return
        navigation = document if window is not None else False
        if window is not None:
            if window_refused(req.method.upper(), url, navigation):
                # its target was kept by the caller
                abort()
                return
        why = method_refusal(req.method.upper(), url) if method_refusal else None
        if why is not None:
            logging.info(_scrubbed(f"blocked browser {req.method.upper()} "
                                   f"{url.split('?', 1)[0]} ({why})"))
            if on_abort is not None:
                on_abort(url, why)
            abort()
            return
        if body_refused(req.method.upper(), url, req.headers or {}, req.post_data_buffer):
            abort()
            return
        doc_kind = "frame" if document and _is_subframe(req) else "document"
        if withheld(url) and (document or isolated_request is None):
            tell_withheld(url, doc_kind if document else "request", url)
            abort()                              # FR-SESS-20 (R1): never loaded (T1)
            return
        stripped = False                         # an answer from the isolated context
        try:
            if withheld(url):
                tell_withheld(url, "request", url)
                first = isolated_fetch(url, req.method.upper(), req.post_data_buffer,
                                       req.headers)
                stripped = True
            else:
                extra = session_headers(url)
                first = route.fetch(max_redirects=0,
                                    headers=_merged(req.headers, extra)) \
                    if extra else route.fetch(max_redirects=0)
            final, final_url, method = first, url, req.method.upper()
            for _ in range(MAX_REDIRECTS + 1):
                location = final.headers.get("location")
                if final.status not in _REDIRECTS or not location:
                    break
                nxt = urljoin(final_url, location)
                if api is None or refused(nxt):
                    abort()
                    return
                if final.status in (301, 302, 303) and method not in ("GET", "HEAD"):
                    method = "GET"                          # as a browser does
                # a navigation's redirect hop is still a navigation (review A-S2)
                if window is not None and window_refused(method, nxt, navigation):
                    abort()
                    return
                keep_body = method not in ("GET", "HEAD")
                if keep_body and body_refused(method, nxt, req.headers or {},
                                              req.post_data_buffer):
                    abort()
                    return
                hop = {"content-type": req.headers.get("content-type", "")} \
                    if keep_body else {}
                if withheld(nxt):
                    # a landing there of a document is aborted; any other hop goes
                    # through the cookie-less context (FR-SESS-20, R1/R2)
                    if document or isolated_request is None:
                        landing = "frame" if doc_kind == "frame" else "landing"
                        tell_withheld(nxt, landing if document else "request", url)
                        abort()
                        return
                    tell_withheld(nxt, "request", url)
                    final = isolated_fetch(nxt, method,
                                           req.post_data_buffer if keep_body else None,
                                           hop)
                    stripped = True
                else:
                    hop.update(session_headers(nxt))        # in scope: checked above
                    final = api.fetch(nxt, method=method, max_redirects=0,
                                      data=req.post_data_buffer if keep_body else None,
                                      headers=hop or None)
                final_url = nxt
            else:
                logging.info(_scrubbed(f"blocked a browser redirect chain over "
                                       f"{MAX_REDIRECTS} hops from {url.split('?', 1)[0]}"))
                abort()
                return
        except Exception as exc:  # noqa: BLE001 - an unfetchable request is aborted
            logging.info(_scrubbed(f"browser request {url.split('?', 1)[0]} failed "
                                   f"({str(exc).splitlines()[0][:80]})"))
            abort()
            return
        if observe is not None:
            try:
                observe(req, final)
            except Exception as exc:  # noqa: BLE001 - an observer never breaks a request
                logging.info(_scrubbed(
                    f"request observer failed on {url.split('?', 1)[0]} "
                    f"({str(exc).splitlines()[0][:80] if str(exc) else exc!r})"))
        if document and doc_kind == "document" and \
                (stripped or final is first or not req.is_navigation_request()
                 or method not in ("GET", "HEAD")):
            _note_received(req, url, final)       # the body this page is given (Q2)
        if stripped:
            # an isolated answer never writes the context's jar (FR-SESS-20, R2)
            route.fulfill(response=final, headers=_without_set_cookie(final.headers))
        elif final is first:
            route.fulfill(response=first)
        elif req.is_navigation_request() and method in ("GET", "HEAD"):
            # the browser re-requests the (checked) landing URL itself, so page.url and
            # relative links are right; a GET or HEAD only, never a body (reviewers).
            # In an authenticated context a landing outside the session's origins was
            # aborted above (FR-SESS-20, R1), so this re-request stays on them
            status = 303 if req.method.upper() not in ("GET", "HEAD") else 302
            route.fulfill(status=status, headers={"location": final_url})
        else:
            # a body kept through 307/308 is never sent twice: the landing response is
            # the answer (a navigation's page.url stays the first URL)
            route.fulfill(response=final)
    return handler


def _is_document(req) -> bool:
    """A document request: a navigation (top-level or a frame's) or a ``document``
    resource (FR-SESS-20, R1)."""
    try:
        if req.is_navigation_request():
            return True
    except Exception:  # noqa: BLE001 - a request that cannot say counts by its type
        pass
    return getattr(req, "resource_type", None) == "document"


#: The abort code of a document request (BUG-0136, PA-0136): ERR_ABORTED leaves the
#: current document where it is; any other code commits Chromium's error page.
DOCUMENT_ABORT = "aborted"


def _abort_code(document: bool) -> str | None:
    """The code a guard aborts a request with: `DOCUMENT_ABORT` for a document
    request (a navigation, top-level or frame, and its redirect hops), else None (the
    default), whatever the reason (PA-0136: one rule, one place)."""
    return DOCUMENT_ABORT if document else None


#: page -> (document_key, HTML) of the last main-frame document its guard fulfilled (BUG-0138
#: review Q2): the bytes the browser received, still there when a script navigation
#: has replaced that document and the browser has dropped its body.
_RECEIVED: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _note_received(req, url: str, answer) -> None:
    """Keep the HTML of a main-frame document the guard is about to fulfil, for its
    page's `navigate` (never anything else: no subresource, no frame)."""
    from playwright.sync_api import Error
    try:
        page = getattr(req.frame, "page", None)
        if page is None or "text/html" not in (answer.headers or {}).get(
                "content-type", ""):
            return
        _RECEIVED[page] = (document_key(url), answer.text())
    # no frame (a service worker's request; a request double without one), or a page
    # that cannot be weakly referenced: nothing is kept
    except (AttributeError, Error, TypeError):
        return


def _received_html(page, url: str, response) -> str | None:
    """The HTML the guard fulfilled for this navigation of ``url`` (or its final URL),
    else the response's own body, else None."""
    got = _RECEIVED.get(page) if _is_weakref_able(page) else None
    if got is not None and got[0] in _navigation_keys(url, response):
        return got[1]
    return response_html(response) if response is not None else None


def _navigation_keys(url: str, response) -> set:
    """The documents a navigation of ``url`` may show (`core.urls.document_key`): the
    URL's own, and its response's final one. The one key for `_note_received`,
    `_received_html` and `shows_own_document` (BUG-0138 review A-S1)."""
    from playwright.sync_api import Error
    keys = {document_key(url)}
    if response is not None:
        try:
            keys.add(document_key(response.url))
        except (AttributeError, Error):    # a response double without a URL
            pass
    return keys


def _is_weakref_able(obj) -> bool:
    try:
        weakref.ref(obj)
        return True
    except TypeError:
        return False


def _is_subframe(req) -> bool:
    """A document request of a child frame (an iframe), not the page's own."""
    try:
        frame = req.frame
        return frame is not None and frame.parent_frame is not None
    except Exception:  # noqa: BLE001 - no frame (a service worker's): not a subframe
        return False


def _without_set_cookie(headers) -> dict[str, str]:
    """``headers`` without ``Set-Cookie`` (FR-SESS-20, R2)."""
    return {k: v for k, v in (headers or {}).items() if k.lower() != "set-cookie"}


def _merged(request_headers, extra: dict[str, str]) -> dict[str, str]:
    """The request's own headers with ``extra`` put in place of any header of the same
    name (case-insensitive): ``route.fetch(headers=)`` replaces the whole set."""
    names = {k.lower() for k in extra}
    out = {k: v for k, v in (request_headers or {}).items() if k.lower() not in names}
    out.update(extra)
    return out


def release(target) -> None:
    """Before closing a guarded context: close its pages first, so no navigation or
    request is in flight, then let route handlers fail silently instead of logging
    ``TargetClosedError`` futures at teardown. Unrouting while a page navigates could
    leave the driver never answering (seen: ``unroute_all`` hung after an app
    navigated during the M6 settle wait, 1 run in ~9)."""
    # until no page is left (bounded): a page may open a popup while another closes,
    # and a popup missed here would be unrouted before its context closes (reviewer B)
    for _ in range(3):
        pages = list(getattr(target, "pages", None) or [])
        if not pages:
            break
        for page in pages:
            try:
                page.close()
            except Exception:  # noqa: BLE001 - best effort, the browser is closing anyway
                pass
    try:
        target.unroute_all(behavior="ignoreErrors")
    except Exception:  # noqa: BLE001 - best effort, the browser is closing anyway
        pass


# --- guarded navigation (BUG-0138, PA-0138) -----------------------------------------
#: How long a load state is still waited for once a main-frame navigation of the page
#: has failed during the wait: a refused script navigation (ERR_ABORTED, BUG-0136) made
#: while the document was parsed stops its loading, so the state never comes.
SUPERSEDED_GRACE_MS = 300
_STEP_MS = 100


@dataclass(frozen=True)
class Navigation:
    """What a guarded navigation got: the main resource's ``response`` (None for a
    same-document navigation), whether the awaited load state was ``reached``, and
    whether the load was ``superseded`` (a main-frame navigation failed meanwhile);
    ``committed_at`` is the `time.monotonic()` of the commit; ``html`` is the HTML body
    the navigation received, taken at the commit (BUG-0138 review Q2: once a script
    navigation commits another document, the replaced one's body is gone)."""
    response: object
    reached: bool
    superseded: bool
    committed_at: float = 0.0
    html: str | None = None


class _NavigationFailures:
    """Notes each failed main-frame navigation request of ``page`` reported once it is
    ``armed``: at or after this navigation's commit (BUG-0138 review Q1). A failure
    reported earlier -- the previous page's pending navigation, cancelled by this one
    -- says nothing about this document's load. It arms on the main frame's own commit
    (``framenavigated``, review B-N1), so a refusal reported after the commit counts
    whether or not ``goto`` has returned yet; `navigate` also arms when ``goto``
    returns, for a page that reports no ``framenavigated``."""

    def __init__(self, page, *, armed: bool = False):
        from playwright.sync_api import Error
        self._page, self._error, self.failed = page, Error, []
        self.armed = armed
        page.on("requestfailed", self._on_failed)
        page.on("framenavigated", self._on_committed)

    def _on_committed(self, frame) -> None:
        try:
            if frame == self._page.main_frame:
                self.armed = True
        except self._error:        # the page has gone
            return

    def _on_failed(self, request) -> None:
        try:
            main = request.frame == self._page.main_frame
            navigation = request.is_navigation_request()
        except self._error:        # a request with no frame (a service worker's)
            return
        if main and navigation and self.armed:
            self.failed.append(time.monotonic())

    def close(self) -> None:
        remove = getattr(self._page, "remove_listener", None)   # a page double may lack it
        if remove is not None:
            try:
                remove("requestfailed", self._on_failed)
                remove("framenavigated", self._on_committed)
            except self._error:    # the page has gone: its listeners with it
                pass


def _await_state(page, state: str, wait_ms: float, failures: _NavigationFailures) -> bool:
    """Wait for ``state`` at most ``wait_ms``, in short steps, and no longer than
    `SUPERSEDED_GRACE_MS` after a main-frame navigation failed. Never raises."""
    from playwright.sync_api import Error
    try:
        from playwright.sync_api import TimeoutError as StepTimeout
    except ImportError:            # a Playwright double without it
        StepTimeout = Error
    deadline = time.monotonic() + wait_ms / 1000
    while True:
        end = deadline
        if failures.failed:
            end = min(end, failures.failed[0] + SUPERSEDED_GRACE_MS / 1000)
        left_ms = (end - time.monotonic()) * 1000
        if left_ms <= 0:
            return False
        try:
            page.wait_for_load_state(state, timeout=max(1, min(_STEP_MS, left_ms)))
            return True
        except StepTimeout:
            continue
        except Error:              # the page closed or the frame went away
            return False


def navigate(page, url: str, *, timeout_ms: float, wait_until: str = "domcontentloaded",
             wait_ms: float | None = None) -> Navigation:
    """**The** way a guarded page is navigated in fuzzlab (BUG-0138, PA-0138; an AST
    guard holds every other module to it). ``goto`` waits for the **commit** only, so a
    refused or failed own target still raises (BUG-0136). Then ``wait_until`` is waited
    for at most ``wait_ms`` (default ``timeout_ms``), suppressed, and no longer than
    `SUPERSEDED_GRACE_MS` after a main-frame navigation failed: a page whose script
    navigates to a refused URL while it is parsed never reaches it, and is never
    waited out. The caller reads the page as it is, or ``response``, when not
    ``reached``."""
    failures = _NavigationFailures(page)
    if _is_weakref_able(page):
        _RECEIVED.pop(page, None)          # only this navigation's document counts
    try:
        response = page.goto(url, wait_until="commit", timeout=timeout_ms)
        committed, failures.armed = time.monotonic(), True
        html = _received_html(page, url, response)
        reached = _await_state(page, wait_until,
                               timeout_ms if wait_ms is None else wait_ms, failures)
        return Navigation(response, reached, bool(failures.failed), committed, html)
    finally:
        failures.close()


def reload(page, *, timeout_ms: float, wait_until: str = "domcontentloaded",
           wait_ms: float | None = None) -> Navigation:
    """`navigate`'s rule for a reload (BUG-0138)."""
    failures = _NavigationFailures(page)
    if _is_weakref_able(page):
        _RECEIVED.pop(page, None)
    try:
        response = page.reload(wait_until="commit", timeout=timeout_ms)
        committed, failures.armed = time.monotonic(), True
        html = _received_html(page, page.url, response)
        reached = _await_state(page, wait_until,
                               timeout_ms if wait_ms is None else wait_ms, failures)
        return Navigation(response, reached, bool(failures.failed), committed, html)
    finally:
        failures.close()


def wait_for_state(page, state: str, timeout_ms: float) -> bool:
    """Wait for a load state of the current document (``networkidle`` after a load) by
    `navigate`'s rule: bounded, suppressed, and cut short when a main-frame navigation
    fails meanwhile. Whether it was reached."""
    failures = _NavigationFailures(page, armed=True)       # the document is committed
    try:
        return _await_state(page, state, timeout_ms, failures)
    finally:
        failures.close()


def load_state_reached(page, state: str = "load") -> bool:
    """Has the page's document reached ``state`` (at any point so far)? A check, not a
    wait: Playwright answers at once for a state already fired."""
    from playwright.sync_api import Error
    try:
        page.wait_for_load_state(state, timeout=1)
        return True
    except Error:
        return False


def shows_own_document(page, url: str, response) -> bool:
    """Does ``page`` still show the document this navigation of ``url`` loaded
    (BUG-0138 review Q2)? Not when a script navigation it allowed has committed another
    document since: then nothing live (title, links, final URL) is this URL's."""
    from playwright.sync_api import Error
    try:
        return document_key(page.url) in _navigation_keys(url, response)
    except Error:
        return False


def response_html(response) -> str | None:
    """The HTML body a navigation's ``response`` carried, or None (BUG-0138): what the
    browser already received, never fetched again. `navigate` reads it at the commit
    (`Navigation.html`)."""
    from playwright.sync_api import Error
    try:
        if "text/html" not in (response.headers or {}).get("content-type", ""):
            return None
        return response.text()
    except Error:                  # the body is gone (the page moved on)
        return None


def make_ws_handler(in_scope: Callable[[str], bool],
                    on_out_of_scope: Callable[[str], None] | None = None, *,
                    hold: Callable[[], bool] | None = None,
                    on_drop: Callable[[str, object], None] | None = None,
                    cookie_scope: Callable[[str], bool] | None = None,
                    on_session_withheld: Callable[[str, str, str], None] | None = None,
                    on_send: Callable[[str], None] | None = None):
    """WebSockets are routed separately from HTTP: an in-scope socket is connected
    through; an out-of-scope one is **never connected** -- Playwright then serves it as
    a mock with no server connection at all (BUG-0123). Not ``ws.close()``: called in
    a sync handler it deadlocks the dispatcher (seen live).

    ``hold`` (the crawler's reveal window, W3): an in-scope socket goes through a
    forwarding handler -- ``connect_to_server()``, then each page-to-server message is
    forwarded (``send``, a no-reply call that is safe in a sync handler) only while
    ``hold()`` is false; while it is true the message is dropped and ``on_drop(url,
    message)`` told (the crawler reads the text for a query load's values, FR-CRAWL-17
    B2); a forwarded one is reported to ``on_send(url)`` (the crawler's write baseline,
    FR-CRAWL-17 P1(b)). Server-to-page messages and closes are forwarded as Playwright
    does by default.

    ``cookie_scope`` (an authenticated context, FR-SESS-20, R1): an in-scope socket on
    another origin than the session's is never connected either (the browser would open
    it with the context's port-agnostic jar); ``on_session_withheld(url,
    "websocket", url)`` is told."""
    def handler(ws) -> None:
        if in_scope(ws.url) and cookie_scope is not None and not cookie_scope(ws.url):
            logging.info(f"blocked a WebSocket to {urlsplit(ws.url).hostname or '?'!r}: "
                         f"another origin than the session's (FR-SESS-20)")
            if on_session_withheld is not None:
                on_session_withheld(ws.url, "websocket", ws.url)
            return
        if in_scope(ws.url):
            server = ws.connect_to_server()
            if hold is not None:
                url = ws.url

                def from_page(message) -> None:
                    if hold():
                        logging.info(f"dropped a WebSocket message to "
                                     f"{urlsplit(url).hostname or '?'!r} in the reveal "
                                     f"window")
                        if on_drop is not None:
                            on_drop(url, message)
                        return
                    server.send(message)
                    if on_send is not None:
                        # a hook never breaks the forwarder (B3)
                        with contextlib.suppress(Exception):
                            on_send(url)
                ws.on_message(from_page)
            return
        logging.info(f"blocked out-of-scope WebSocket to "
                     f"{urlsplit(ws.url).hostname or ws.url[:40]!r}")
        if on_out_of_scope is not None:
            on_out_of_scope(ws.url)
    return handler


def guard_page(target, allow: frozenset[str] = frozenset(),
               on_abort: Callable[[str, str], None] | None = None, *,
               in_scope: Callable[[str], bool],
               on_out_of_scope: Callable[[str], None] | None = None,
               method_refusal: Callable[[str, str], str | None] | None = None,
               observe: Callable[[object, object], None] | None = None,
               request_refusal: Callable[[str, str, dict, object], str | None]
               | None = None,
               headers: dict[str, str] | None = None,
               header_scope: Callable[[str], bool] | None = None,
               window: Callable[[str, str, bool], str | None] | None = None,
               ws_hold: Callable[[], bool] | None = None,
               on_ws_drop: Callable[[str, object], None] | None = None,
               on_ws_send: Callable[[str], None] | None = None,
               cookie_scope: Callable[[str], bool] | None = None,
               on_session_withheld: Callable[[str, str, str], None] | None = None,
               isolated_request: Callable[[], object] | None = None) -> None:
    """Confine a Playwright ``BrowserContext`` (pass the context, so popups are covered
    too), WebSockets included. ``in_scope`` is required: there is no unscoped guard
    (BUG-0123). ``method_refusal``, ``observe``, ``request_refusal``, ``window``, the
    session ``headers`` (with ``header_scope``) and ``cookie_scope`` /
    ``on_session_withheld`` / ``isolated_request`` (FR-SESS-20): see
    `make_route_handler` (a WebSocket off the session's origins is never connected,
    `make_ws_handler`); ``ws_hold`` /
    ``on_ws_drop`` / ``on_ws_send``: see `make_ws_handler`. Session headers are applied by the route only
    (FR-CRAWL-14)."""
    api = getattr(target, "request", None)
    target.route("**/*", make_route_handler(allow, on_abort, in_scope=in_scope,
                                            on_out_of_scope=on_out_of_scope, api=api,
                                            method_refusal=method_refusal,
                                            observe=observe,
                                            request_refusal=request_refusal,
                                            headers=headers, header_scope=header_scope,
                                            window=window, cookie_scope=cookie_scope,
                                            on_session_withheld=on_session_withheld,
                                            isolated_request=isolated_request))
    route_ws = getattr(target, "route_web_socket", None)
    if route_ws is None:                            # an old Playwright: say so, loudly
        logging.warning("this Playwright cannot route WebSockets; the resolver rules "
                        "of browser_launch_args still confine them (BUG-0123)")
        return
    route_ws("**/*", make_ws_handler(in_scope, on_out_of_scope, hold=ws_hold,
                                     on_drop=on_ws_drop, cookie_scope=cookie_scope,
                                     on_session_withheld=on_session_withheld,
                                     on_send=on_ws_send))


_LOOPBACK_SPELLINGS = ("127.0.0.1", "localhost", "[::1]")


def browser_launch_args(scope_urls, *, any_port_hosts=()) -> list[str]:
    """Chromium arguments for every launch we make (BUG-0123): no proxy, nothing
    resolvable outside scope, and no background networking.

    ``--host-resolver-rules`` maps each scope ``host:port`` to itself and every other
    name to ``~NOTFOUND``. Chromium applies the rules to IP literals and matches them on
    ``host:port`` (default ports included), so ``203.0.113.9``, ``127.0.0.2`` or another
    port on ``127.0.0.1`` fail with ``ERR_NAME_NOT_RESOLVED`` (verified live). This
    confines what Chromium itself sends and a route cannot see -- a preconnect, a DNS
    prefetch, a landing page the browser re-requests. It does **not** confine routed
    requests, which the Playwright driver fetches (``guard_page``'s predicate is their
    only guard). A loopback origin admits all three loopback spellings on its
    port. ``any_port_hosts`` are hosts admitted on every port (the crawler's
    host-scoped external target, BUG-0050)."""
    rules = []
    for url in scope_urls:
        origin = canonical_origin(url) if url else None
        if origin is None:
            continue
        host, port = origin.split("://", 1)[1].rsplit(":", 1)
        spellings = _LOOPBACK_SPELLINGS if host == "127.0.0.1" else (host,)
        rules += [f"MAP {h}:{port} {h}:{port}" for h in spellings]
    rules += [f"EXCLUDE {h.lower()}" for h in any_port_hosts if h]
    rules = list(dict.fromkeys(rules)) + ["MAP * ~NOTFOUND"]
    return ["--no-sandbox", "--disable-dev-shm-usage", "--no-proxy-server",
            f"--host-resolver-rules={', '.join(rules)}", "--disable-background-networking",
            "--disable-component-update", "--disable-sync", "--disable-domain-reliability",
            "--no-pings", "--dns-prefetch-disable", "--disable-features=NetworkPrediction",
            "--no-default-browser-check", "--metrics-recording-only"]


def chromium_launch_kwargs(args: list[str], *, headless: bool = True) -> dict:
    """The keyword arguments of every Chromium launch we make (BUG-0126, PA-0003):
    ``args`` (from `browser_launch_args`), ``headless``, and the operator's configured
    binary (``PLAYWRIGHT_CHROMIUM_EXECUTABLE``) when set. One helper, so no launch site
    drifts from the others (the M6 executor ignored the binary and crashed a run)."""
    import os
    kwargs = {"headless": headless, "args": list(args)}
    exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
    if exe:
        kwargs["executable_path"] = exe
    return kwargs


def checked_api_request(in_scope: Callable[[str], bool], url: str) -> None:
    """Before a Playwright API-request call (``context.request.*``,
    ``pw.request.new_context().fetch``), which `route` never sees: refuse an
    out-of-scope URL. Callers pass ``max_redirects=0`` too."""
    if not in_scope(url):
        raise PermissionError(f"refusing an out-of-scope request to "
                              f"{urlsplit(url).hostname!r} (BUG-0123)")


#: Redirects a static fetch follows by hand (each hop checked first).
MAX_REDIRECTS = 5


def get_checked(session, url: str, timeout: float, may_follow: Callable[[str], bool]):
    """GET ``url`` with ``requests``, following redirects **by hand**: a hop is fetched
    only if ``may_follow(next_url)`` allows it (scope, and no destructive token). A
    refused hop is not followed; the redirect response itself is returned (BUG-0111).
    """
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
