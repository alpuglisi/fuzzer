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
"""

from __future__ import annotations

import logging
from typing import Callable
from urllib.parse import urljoin, urlsplit

from fuzzlab.core.urls import canonical_origin, destructive_reason, url_key

#: Not network requests: never scope-checked.
_LOCAL_SCHEMES = ("data:", "blob:", "about:")
_REDIRECTS = (301, 302, 303, 307, 308)


def make_route_handler(allow: frozenset[str] = frozenset(),
                       on_abort: Callable[[str, str], None] | None = None, *,
                       in_scope: Callable[[str], bool],
                       on_out_of_scope: Callable[[str], None] | None = None,
                       api=None,
                       method_refusal: Callable[[str, str], str | None] | None = None,
                       observe: Callable[[object, object], None] | None = None):
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
    (PA-0086(2))."""
    def refused(url: str) -> bool:
        if not in_scope(url):
            logging.info(f"blocked out-of-scope browser request to "
                         f"{urlsplit(url).hostname or url[:40]!r}")
            if on_out_of_scope is not None:
                on_out_of_scope(url)
            return True
        reason = destructive_reason(url)
        if reason is not None and url_key(url) not in allow:
            logging.info(f"blocked destructive browser request {url.split('?', 1)[0]} "
                         f"({reason!r})")
            if on_abort is not None:
                on_abort(url, reason)
            return True
        return False

    def handler(route, request=None) -> None:
        req = request if request is not None else route.request
        url = req.url
        if url.lower().startswith(_LOCAL_SCHEMES):
            route.continue_()
            return
        if refused(url):
            route.abort()
            return
        why = method_refusal(req.method.upper(), url) if method_refusal else None
        if why is not None:
            logging.info(f"blocked browser {req.method.upper()} {url.split('?', 1)[0]} "
                         f"({why})")
            if on_abort is not None:
                on_abort(url, why)
            route.abort()
            return
        try:
            first = route.fetch(max_redirects=0)
            final, final_url, method = first, url, req.method.upper()
            for _ in range(MAX_REDIRECTS + 1):
                location = final.headers.get("location")
                if final.status not in _REDIRECTS or not location:
                    break
                nxt = urljoin(final_url, location)
                if api is None or refused(nxt):
                    route.abort()
                    return
                if final.status in (301, 302, 303) and method not in ("GET", "HEAD"):
                    method = "GET"                          # as a browser does
                keep_body = method not in ("GET", "HEAD")
                final = api.fetch(nxt, method=method, max_redirects=0,
                                  data=req.post_data_buffer if keep_body else None,
                                  headers={"content-type": req.headers.get("content-type",
                                                                           "")}
                                  if keep_body else None)
                final_url = nxt
            else:
                logging.info(f"blocked a browser redirect chain over {MAX_REDIRECTS} "
                             f"hops from {url.split('?', 1)[0]}")
                route.abort()
                return
        except Exception as exc:  # noqa: BLE001 - an unfetchable request is aborted
            logging.info(f"browser request {url.split('?', 1)[0]} failed "
                         f"({str(exc).splitlines()[0][:80]})")
            route.abort()
            return
        if observe is not None:
            try:
                observe(req, final)
            except Exception as exc:  # noqa: BLE001 - an observer never breaks a request
                logging.info(f"request observer failed on {url.split('?', 1)[0]} "
                             f"({str(exc).splitlines()[0][:80] if str(exc) else exc!r})")
        if final is first:
            route.fulfill(response=first)
        elif req.is_navigation_request() and method in ("GET", "HEAD"):
            # the browser re-requests the (checked) landing URL itself, so page.url and
            # relative links are right; a GET or HEAD only, never a body (reviewers)
            status = 303 if req.method.upper() not in ("GET", "HEAD") else 302
            route.fulfill(status=status, headers={"location": final_url})
        else:
            # a body kept through 307/308 is never sent twice: the landing response is
            # the answer (a navigation's page.url stays the first URL)
            route.fulfill(response=final)
    return handler


def release(target) -> None:
    """Before closing a guarded context: close its pages first, so no navigation or
    request is in flight, then let route handlers fail silently instead of logging
    ``TargetClosedError`` futures at teardown. Unrouting while a page navigates could
    leave the driver never answering (seen: ``unroute_all`` hung after an app
    navigated during the M6 settle wait, 1 run in ~9)."""
    for page in list(getattr(target, "pages", None) or []):
        try:
            page.close()
        except Exception:  # noqa: BLE001 - best effort, the browser is closing anyway
            pass
    try:
        target.unroute_all(behavior="ignoreErrors")
    except Exception:  # noqa: BLE001 - best effort, the browser is closing anyway
        pass


def make_ws_handler(in_scope: Callable[[str], bool],
                    on_out_of_scope: Callable[[str], None] | None = None):
    """WebSockets are routed separately from HTTP: an in-scope socket is connected
    through; an out-of-scope one is **never connected** -- Playwright then serves it as
    a mock with no server connection at all (BUG-0123). Not ``ws.close()``: called in
    a sync handler it deadlocks the dispatcher (seen live)."""
    def handler(ws) -> None:
        if in_scope(ws.url):
            ws.connect_to_server()
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
               observe: Callable[[object, object], None] | None = None) -> None:
    """Confine a Playwright ``BrowserContext`` (pass the context, so popups are covered
    too), WebSockets included. ``in_scope`` is required: there is no unscoped guard
    (BUG-0123). ``method_refusal`` and ``observe``: see `make_route_handler`."""
    api = getattr(target, "request", None)
    target.route("**/*", make_route_handler(allow, on_abort, in_scope=in_scope,
                                            on_out_of_scope=on_out_of_scope, api=api,
                                            method_refusal=method_refusal,
                                            observe=observe))
    route_ws = getattr(target, "route_web_socket", None)
    if route_ws is None:                            # an old Playwright: say so, loudly
        logging.warning("this Playwright cannot route WebSockets; the resolver rules "
                        "of browser_launch_args still confine them (BUG-0123)")
        return
    route_ws("**/*", make_ws_handler(in_scope, on_out_of_scope))


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
