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
* **Chromium's own traffic** -- what the route never sees (a speculation-rules prefetch
  or prerender, a favicon, a preconnect, background services, a WebSocket the route
  admitted) goes through the **enforcer** ``browser_launch_args`` names
  (``--proxy-server``, loopback forced through it; BUG-0559 review round 2, BB-3): a
  loopback proxy in this process that refuses every request Chromium sends itself but
  a WebSocket the guard's socket handler admitted (`admit_socket`) and the browser's
  re-request of a redirect landing the route checked (`admit_landing`: Playwright never
  routes it). An ``https`` landing's tunnel carries that one exchange and is closed at
  the browser's next request on it (`_HeldTunnel`, review round 3: Chromium kept it in
  its pool and a later prefetch rode it); a certificate error's retry is admitted on the
  same ticket. In a guarded context every other request a page makes is answered by the
  route (fetched by the Playwright driver, never by Chromium), so nothing else
  Chromium sends on its own is ever needed: a preload of a host the session's cookies
  do not reach, or of a destructive
  URL, is refused there whatever the page's markup (measured on Chromium 141, both
  binaries, http and https). The resolver rules still name only the scope ``host:port``
  pairs;
* **Chromium's preloads, defence in depth** -- ``guard_page`` keeps a speculation rule
  set from being registered where a script can see it (`PRELOAD_OFF_JS`; the route drops
  the ``Speculation-Rules`` header, makes a page's parser-inserted rule sets inert and
  loads a popup's first document through a trampoline), and a consumer checks the
  document a load committed before it reads it (`committed_session_refusal`). These
  layers read the page and cannot see everything it registers (the parser decodes a
  character reference and builds a closed shadow root after the route looked); the
  enforcer is the defence.

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

**Where the session's cookies reach** (SP-74, BUG-0559): a context that carries a session
in its cookie jar (the caller's ``session_cookies``: the session's cookies as the context
holds them) never sends a request -- a navigation, top-level or frame, a redirect hop, a
subresource, a WebSocket -- to a host those cookies do not reach (`cookie_reaches`, RFC
6265's domain match: a host-only cookie reaches its own host only, a dotted domain also
the names under it, never an IP). Such a request would go out without the session to
what the crawl takes for the session's own origin (``in_origin_scope`` folds the loopback
aliases ``localhost`` / ``127.0.0.1`` / ``[::1]``, a host-only cookie reaches one of
them): it is aborted before it is sent, at every hop, and ``on_session_unreached`` is
told. A request to another origin than the session's keeps FR-SESS-20's disposition
(above); `checked_api_request` applies the same rule to an API request.

The crawler's **reveal window** (FR-CRAWL-15/16, W1-W3) uses two hooks: ``window`` on
the route (asked for every request after the scope and destructive checks, and for
each redirect hop, with whether it is a navigation) and ``ws_hold`` on WebSockets (an
in-scope socket goes through a forwarding handler; a page-to-server message is
forwarded only while ``ws_hold()`` is false, else dropped and reported).
"""

from __future__ import annotations

import codecs
import contextlib
import json
import logging
import os
import re
import socket
import socketserver
import threading
import time
import weakref
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlsplit

from fuzzlab.core.net import require_loopback
from fuzzlab.core.urls import canonical_origin, destructive_reason, document_key, url_key


def _scrubbed(text: str) -> str:
    """A log line with any FR-CRAWL-17 probe marker replaced (P4, review B-N2): a probe
    URL's path, or an error quoting the URL, never carries one into the log."""
    from fuzzlab.tools.spa import scrub_markers
    return scrub_markers(text)

#: Not network requests: never scope-checked.
_LOCAL_SCHEMES = ("data:", "blob:", "about:")
_REDIRECTS = (301, 302, 303, 307, 308)


# --- where a session's cookies reach (SP-74, BUG-0559) -----------------------------------
def cookie_reaches(cookie, host) -> bool:
    """Does the browser send ``cookie`` (as a context holds it: a Playwright cookie with a
    ``url``, or with a ``domain``) to a request for ``host``? **The** predicate (SP-74). A
    cookie added by URL, or with a domain without a leading dot, is host-only: that exact
    host (measured on Chromium 141: a ``127.0.0.1`` cookie, by URL or by bare domain, goes
    to ``127.0.0.1`` and not to ``localhost`` on the same port; Playwright's API request
    context with that storage state likewise). A dotted domain also reaches the hosts
    under it, never an IP address (RFC 6265 §5.1.3). A deny-only check: where the session
    goes is still decided by origin (``cookie_scope``, FR-SESS-20).

    An IPv6 literal compares without its brackets on both sides (BUG-0559 review round 1,
    BA-2): Chromium holds a cookie set for ``http://[::1]:P/`` with the domain ``[::1]``,
    brackets included, and sends it there (measured on Chromium 141: ``storage_state()``
    gives ``('sid', '[::1]')`` and ``context.cookies('http://[::1]:P/')`` returns it),
    while a URL's ``hostname`` -- the ``host`` every caller passes -- is ``::1``."""
    import ipaddress
    url = cookie.get("url")
    # one name per assignment, so PA-0134(3)'s host-compare guard sees the compare below
    if url:
        domain = (urlsplit(url).hostname or "").lower().strip("[]")
        host_only = True
    else:
        raw = str(cookie.get("domain") or "").lower()
        domain = raw.lstrip(".").strip("[]")
        host_only = not raw.startswith(".")
    host = str(host or "").lower().strip("[]")
    if not domain or not host:
        return False
    if host == domain:
        return True
    if host_only or not host.endswith("." + domain):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def held_session_cookies(cookies, storage_state=None, names=None) -> list[dict]:
    """The session's cookies as a context that adopted them holds them (SP-74's input):
    those added by URL (``context.add_cookies``) and those of an adopted
    ``storage_state`` (by domain), kept to ``names`` -- the session's credential cookies
    -- when given (``None``: every one is the session's)."""
    held = [*(cookies or ()), *((storage_state or {}).get("cookies") or ())]
    keep = None if names is None else set(names)
    return [dict(c) for c in held if c.get("name") and (keep is None or c["name"] in keep)]


def names_reaching(cookies, host) -> frozenset[str]:
    """The names of ``cookies`` (as a context holds them) of which a copy reaches
    ``host`` (`cookie_reaches`). A caller that cannot tell a session's credential cookies
    from its ambient ones (an operator's storage state) takes the session's to be those
    that reach the session's own start host (BUG-0559 review round 1, BA-1): an ambient
    cookie held for another host -- a loopback alias, another scope origin -- is never
    one, so it never makes the start host unreached."""
    return frozenset(str(c["name"]) for c in cookies or ()
                     if c.get("name") and cookie_reaches(c, host))


def unreached_session_cookies(session_cookies, host) -> list[str]:
    """The names of the session's cookies none of whose held copies reaches ``host``
    (`cookie_reaches`), sorted: a request there would go without (part of) the session."""
    copies: dict[str, list[dict]] = {}
    for c in session_cookies or ():
        copies.setdefault(str(c.get("name")), []).append(c)
    return sorted(n for n, held in copies.items()
                  if not any(cookie_reaches(c, host) for c in held))


def session_host_refusal(session_cookies, url, *, cookie_scope=None) -> str | None:
    """**Why a request for ``url`` by a context carrying ``session_cookies`` would go
    without the session** -- a host none of a session cookie's held copies reaches
    (`unreached_session_cookies`) -- or None (SP-74, BUG-0559). None as well for a
    context that carries no session in cookies, and for a URL ``cookie_scope`` puts on
    another origin than the session's (FR-SESS-20 decides that one: its documents are
    aborted and the rest goes cookie-less). The one decision of the guard's route, its
    WebSocket handler, `checked_api_request` and a crawler's load gate. The message names
    the host and the cause, never a URL."""
    if not session_cookies:
        return None
    if cookie_scope is not None and not cookie_scope(url):
        return None
    unreached = unreached_session_cookies(session_cookies, urlsplit(url).hostname or "")
    if not unreached:
        return None
    total = len({str(c.get("name")) for c in session_cookies})
    return (f"the session's cookies do not reach host {urlsplit(url).hostname or ''!r} "
            f"in the browser "
            f"({len(unreached)} of {total} scoped to another host; a host-only cookie "
            f"reaches its own host only): not sent, since it would go without the "
            f"session (SP-74)")


class SessionHostUnreached(PermissionError):
    """An API request of a context carrying a session, to a host its cookies do not
    reach (`checked_api_request`, SP-74): refused before it is sent. The message is
    `session_host_refusal`'s (the host and the cause, never a URL)."""


def committed_session_refusal(page, session_cookies, *, cookie_scope=None) -> str | None:
    """**Why the document ``page``'s main frame has committed is not the session's** -- a
    host the session's cookies do not reach (`session_host_refusal`) -- or None (SP-74,
    BUG-0559 review round 1, BA-3). Defence in depth behind the route and
    `PRELOAD_OFF_JS`: a navigation the route never saw (one a browser-process preload
    served) would commit an anonymous document under the session's context. Every
    consumer asks before it reads a load's content or a state: the auditor's fetcher,
    the spider's extraction, disco's state reads. A non-http(s) document
    (``about:blank``, the browser's error page) is None."""
    try:
        url = page.url or ""
    except Exception:  # noqa: BLE001 - a closed page has committed nothing
        return None
    if not str(url).lower().startswith(("http://", "https://")):
        return None
    return session_host_refusal(session_cookies, url, cookie_scope=cookie_scope)


# --- browser-process preloads (BUG-0559 review round 1, BA-3) ------------------------------
#: The response header that names an external speculation rule set (Chromium 141).
SPECULATION_RULES_HEADER = "speculation-rules"

#: **No speculation rule set is ever registered in a guarded page** (BUG-0559 review
#: round 1, BA-3). Chromium sends a speculation-rules prefetch from the browser process:
#: the route never sees it, nor the navigation it then serves (measured on Chromium 141,
#: the full browser and the headless shell: a prefetch of a loopback alias went with no
#: cookie, a same-origin ``/logout`` named by document rules went with the session past
#: the destructive rule, and a click then committed the alias's anonymous page). No launch
#: switch stops it where the parser or the browser decides (measured again in review
#: round 2 on both binaries, every shape: ``--disable-blink-features=SpeculationRules,
#: Prerender2,...`` -- Chromium 141 has no runtime feature gating rule sets --,
#: ``--disable-features=Prerender2,PrefetchUseContentRefactor,
#: SpeculationRulesPrefetchFuture,...``, a ``PreloadingConfig`` holdback); the "Preload
#: pages" preference does in the full browser's own profile only, never the headless
#: shell. The enforcer ``browser_launch_args`` names refuses whatever is still sent
#: (BUG-0559 review round 2, BB-3); this script is defence in depth under it, removing
#: the trigger where a script can see it. Installed on every guarded
#: context before any page script runs, takes every ``<script type=speculationrules>``
#: out of the document as it is inserted -- by the parser (which runs a microtask
#: checkpoint before it prepares a script), by a script, a fragment or ``document.write``,
#: into an open shadow root (``attachShadow``, or a parser's declarative one) -- before
#: its rules are registered, and again whenever it is re-inserted; removing a registered
#: one drops its rules. What it calls is captured before the page's scripts run, so a
#: page that replaces ``Element.prototype.remove`` or ``MutationRecord``'s getters does
#: not turn it off (measured). The route drops the ``Speculation-Rules`` header
#: (`_fulfil_preload_free`), and a popup's first document, which Chromium loads into the
#: Window of its initial ``about:blank`` where no init script runs again (measured), is
#: loaded through a same-URL trampoline (`_TRAMPOLINE_HTML`). Not reached by this layer: a
#: rule set in a *closed* shadow root -- the parser's, with its type written as a
#: character reference, or one a handler inside that root inserts -- and one a page gives
#: a ``window.open()`` popup still on its initial ``about:blank`` (measured by the review,
#: round 2); the enforcer refuses what they send.
PRELOAD_OFF_JS = r"""(() => {
  const apply = Reflect.apply, desc = Object.getOwnPropertyDescriptor;
  const E = Element.prototype, N = Node.prototype, R = MutationRecord.prototype;
  const nodeType = desc(N, 'nodeType').get, localName = desc(E, 'localName').get;
  const shadowRoot = desc(E, 'shadowRoot').get, getAttribute = E.getAttribute;
  const remove = E.remove, attach = E.attachShadow, qsaElement = E.querySelectorAll;
  const qsaDocument = Document.prototype.querySelectorAll;
  const qsaFragment = DocumentFragment.prototype.querySelectorAll;
  const recType = desc(R, 'type').get, recTarget = desc(R, 'target').get;
  const recAdded = desc(R, 'addedNodes').get;
  const listLength = desc(NodeList.prototype, 'length').get, item = NodeList.prototype.item;
  const trim = String.prototype.trim, lower = String.prototype.toLowerCase, Str = String;
  const taken = new WeakSet(), has = WeakSet.prototype.has, add = WeakSet.prototype.add;
  const observe = MutationObserver.prototype.observe;
  const OPTIONS = {subtree: true, childList: true, attributes: true,
                   attributeFilter: ['type']};
  const isRules = (t) => t !== null &&
    apply(lower, apply(trim, Str(t), []), []) === 'speculationrules';
  const off = (el) => {
    if (apply(nodeType, el, []) !== 1 || apply(localName, el, []) !== 'script') return;
    if (apply(has, taken, [el]) || isRules(apply(getAttribute, el, ['type']))) {
      apply(add, taken, [el]);
      apply(remove, el, []);
    }
  };
  const scan = (root) => {
    const t = apply(nodeType, root, []);
    const q = t === 1 ? qsaElement : t === 9 ? qsaDocument : t === 11 ? qsaFragment : null;
    if (q === null) return;
    const found = apply(q, root, ['script']), n = apply(listLength, found, []);
    for (let i = 0; i < n; i++) off(apply(item, found, [i]));
  };
  let mo = null;
  const watch = (root) => { apply(observe, mo, [root, OPTIONS]); scan(root); };
  const visit = (node) => {
    off(node);
    scan(node);
    if (apply(nodeType, node, []) === 1) {
      const sr = apply(shadowRoot, node, []);
      if (sr) watch(sr);
    }
  };
  mo = new MutationObserver((records) => {
    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      if (apply(recType, r, []) === 'attributes') { off(apply(recTarget, r, [])); continue; }
      const added = apply(recAdded, r, []), n = apply(listLength, added, []);
      for (let j = 0; j < n; j++) visit(apply(item, added, [j]));
    }
  });
  E.attachShadow = function attachShadow() {
    const root = apply(attach, this, arguments);
    watch(root);
    return root;
  };
  watch(document);
})();"""

#: The document a popup's first navigation is answered with (`PRELOAD_OFF_JS`): it
#: replaces itself with the same URL, now from a document that is not the initial
#: ``about:blank``, so Chromium gives the real one a new Window -- where the context's
#: init scripts run -- and the route serves it the answer it already fetched.
_TRAMPOLINE_HTML = ("<!doctype html><meta charset=utf-8><title></title>"
                    "<script>location.replace({url})</script>")

#: How long a popup's fetched answer waits for its trampoline's request, and how many
#: wait at once, per guard.
_KEPT_TTL_S = 30.0
_KEPT_MAX = 32


def _initial_window(req) -> bool:
    """Is ``req`` a navigation of a new page's main frame from the initial ``about:blank``
    that Chromium would reuse the Window of (`PRELOAD_OFF_JS`)? Playwright cannot name
    the frame of a popup's first navigation ("the request was issued before the frame is
    created", measured for ``window.open``, ``<a target=_blank rel=opener>``, a named
    target); a frame it can name counts when it is the main frame of a page with an
    opener, still on ``about:blank`` (``window.open()`` then ``w.location = url``). A
    request double without a frame is never one."""
    from playwright.sync_api import Error
    try:
        if not req.is_navigation_request():
            return False
    except Exception:  # noqa: BLE001 - a request that cannot say is not one
        return False
    try:
        frame = req.frame
    except Error as exc:
        return "not available" in str(exc)
    except Exception:  # noqa: BLE001 - a double: no frame to ask
        return False
    try:
        return frame is not None and frame.parent_frame is None and \
            frame.url == "about:blank" and frame.page.opener() is not None
    except Exception:  # noqa: BLE001 - a frame that cannot say is not one
        return False


def _trampoline_target(req, url: str) -> bool:
    """Is ``req`` the request a popup's trampoline (`_TRAMPOLINE_HTML`) made for ``url``:
    a GET navigation of a main frame whose document is at ``url``, or whose frame
    Playwright cannot name yet?"""
    from playwright.sync_api import Error
    try:
        if not req.is_navigation_request() or req.method.upper() != "GET":
            return False
        frame = req.frame
    except Error as exc:
        return "not available" in str(exc)
    except Exception:  # noqa: BLE001 - a double: never one
        return False
    try:
        return frame is not None and frame.parent_frame is None and \
            frame.url.split("#", 1)[0] == url
    except Exception:  # noqa: BLE001
        return False


#: A parser-inserted rule set's ``type`` in a page's HTML (`_inert_rule_sets`).
_RULES_TYPE = re.compile(r"""(<script\b[^>]*?\btype\s*=\s*)(["']?)\s*speculationrules\s*\2""",
                         re.IGNORECASE)
#: What `_inert_rule_sets` writes in its place: no script type the browser runs.
INERT_RULES_TYPE = "x-fuzzlab-inert"


def _inert_rule_sets(html: str | None) -> str | None:
    """``html`` (a main-frame document the route is about to give) with every
    ``<script type=speculationrules>`` written with an inert type, or None when it has
    none. The text layer under `PRELOAD_OFF_JS`, for a rule set the parser inserts where
    no script can see it -- a *closed* declarative shadow root (measured on Chromium 141:
    its prefetch of the alias went out with the script layer alone). Defence in depth
    only: the parser decodes a character reference in the type (``&#115;peculationrules``)
    after this text was read (BUG-0559 review round 2, BB-3), so the enforcer
    (`browser_launch_args`) is what refuses a preload."""
    if not html or "speculationrules" not in html.lower():
        return None
    out, n = _RULES_TYPE.subn(rf"\g<1>\g<2>{INERT_RULES_TYPE}\g<2>", html)
    return out if n else None


def _fulfil_preload_free(route, answer, *drop: str, html: str | None = None,
                         encoding: str | None = "utf-8") -> None:
    """Fulfil ``route`` with ``answer`` as received, less a ``Speculation-Rules`` header
    (`PRELOAD_OFF_JS`) and the header names in ``drop`` (lower case: ``set-cookie`` for
    an isolated answer, FR-SESS-20 R2); and, given its ``html`` (a main-frame document's,
    as `_note_received` decoded it with ``encoding``), with its parser-inserted rule sets
    inert (`_inert_rule_sets`), encoded back the same way -- never when ``encoding`` is
    None (a body that did not decode losslessly is given as it came; the enforcer stands
    behind it). An answer with none of them is given unchanged. The headers
    given are never empty: ``route.fulfill`` falls back to the answer's own headers --
    the dropped ones included -- for an empty set, so a ``Content-Length`` (always true
    of the body) then stands in."""
    names = {SPECULATION_RULES_HEADER, *drop}
    headers = dict(answer.headers or {})
    inert = _inert_rule_sets(html) if encoding else None
    body = None
    if inert is not None:
        try:
            body = inert.encode(encoding)     # the charset it was decoded with
        except (LookupError, UnicodeError):
            body = None
    if body is not None:
        given = {k: v for k, v in headers.items()
                 if k.lower() not in names | {"content-length", "content-encoding",
                                              "transfer-encoding"}}
        given["content-length"] = str(len(body))
        route.fulfill(status=answer.status, headers=given, body=body)
        return
    if not any(k.lower() in names for k in headers):
        route.fulfill(response=answer)
        return
    kept = {k: v for k, v in headers.items() if k.lower() not in names}
    if not kept:
        kept = {"content-length": str(len(answer.body()))}
    route.fulfill(response=answer, headers=kept)


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
                       isolated_request: Callable[[], object] | None = None,
                       session_cookies=None,
                       on_session_unreached: Callable[[str, str, str, str], None]
                       | None = None):
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
    blocked, which navigation targets to enqueue).

    ``session_cookies`` (a context carrying a session in its cookie jar, SP-74,
    BUG-0559): the session's cookies as the context holds them (`held_session_cookies`).
    A request to a host they do not reach (`session_host_refusal`; another origin than
    the session's stays ``cookie_scope``'s) is aborted before anything is sent -- the
    request itself and every redirect hop, a navigation or not -- right after the scope
    and destructive checks, and ``on_session_unreached(url, kind, source, reason)`` is
    told: ``kind`` as ``on_session_withheld``'s (``"document"``, ``"landing"``,
    ``"frame"``, ``"request"``), ``source`` the URL the chain started at. None or empty:
    nothing is refused by it (a context with no session cookie)."""
    session_cookies = [dict(c) for c in (session_cookies or ())]

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

    def unreached(url: str, kind: str, source: str) -> bool:
        """SP-74: a request of this session-carrying context to a host its cookies do
        not reach -- refused, told; another origin than the session's is FR-SESS-20's."""
        if not session_cookies or not in_scope(url):
            return False
        why = session_host_refusal(session_cookies, url, cookie_scope=cookie_scope)
        if why is None:
            return False
        logging.info(f"sent nothing to {urlsplit(url).hostname or '?'!r} ({kind}): the "
                     f"session's cookies do not reach that host (SP-74)")
        if on_session_unreached is not None:
            try:
                on_session_unreached(url, kind, source, why)
            except Exception as exc:  # noqa: BLE001 - a hook never lets a request out
                logging.info(f"session-unreached hook failed ({type(exc).__name__})")
        return True

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

    # BA-3 (BUG-0559 review round 1): a popup's first document, fetched and checked like
    # any other, waits here for the request its trampoline makes (`_TRAMPOLINE_HTML`):
    # url -> (answer, header names to drop, when kept, trampolines so far). A plain dict:
    # route handlers interleave on one thread, and a lock held across a switch would
    # deadlock it.
    kept: dict = {}

    def take_kept(req, url: str):
        now = time.monotonic()
        for key in [k for k, v in kept.items() if now - v[2] > _KEPT_TTL_S]:
            kept.pop(key, None)
        if url not in kept or not _trampoline_target(req, url):
            return None
        got = kept.pop(url, None)
        return None if got is None else got[:2]

    def trampoline(route, url: str, answer, drop: tuple) -> bool:
        """Answer a popup's first navigation with the trampoline and keep its fetched
        answer for the trampoline's own request; False once ``url`` was trampolined
        three times without that request coming (a frame Playwright never names): the
        answer is then given as it is, and logged."""
        hops = kept[url][3] + 1 if url in kept else 1
        if hops > 3:
            kept.pop(url, None)
            logging.info(f"a popup's first document on {urlsplit(url).hostname or '?'!r} "
                         f"is given without its trampoline (BUG-0559 review round 1)")
            return False
        while len(kept) >= _KEPT_MAX:
            kept.pop(next(iter(kept)), None)
        kept[url] = (answer, drop, time.monotonic(), hops)
        target = json.dumps(url).replace("<", "\\u003c")
        route.fulfill(status=200, body=_TRAMPOLINE_HTML.replace("{url}", target),
                      headers={"content-type": "text/html; charset=utf-8",
                               "cache-control": "no-store"})
        return True

    def handler(route, request=None) -> None:
        req = request if request is not None else route.request
        url = req.url
        if url.lower().startswith(_LOCAL_SCHEMES):
            route.continue_()
            return
        if kept and str(req.method).upper() == "GET":
            got = take_kept(req, url)
            if got is not None:
                # a trampoline's own request: the answer fetched for this popup's first
                # navigation, already checked and observed; nothing is sent again
                answer, drop = got
                html, charset = _note_received(req, url, answer)
                _fulfil_preload_free(route, answer, *drop, html=html, encoding=charset)
                return
        # BUG-0136 (PA-0136): every abort of a document request -- a navigation,
        # top-level or frame, and each of its redirect hops -- uses "aborted"
        # (ERR_ABORTED), whatever the reason: the current document survives (the
        # default code commits Chromium's error page in its place) and `goto` of that
        # target still raises. A subresource keeps the default code.
        document = _is_document(req)
        # BA-3: a popup's first navigation, from the initial about:blank whose Window
        # Chromium reuses -- where no init script runs again (measured)
        fresh = document and _initial_window(req)

        def abort() -> None:
            route.abort(_abort_code(document)) if document else route.abort()

        if refused(url):
            abort()
            return
        doc_kind = "frame" if document and _is_subframe(req) else "document"
        if unreached(url, doc_kind if document else "request", url):
            abort()                              # SP-74: never sent without the session
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
                hop_kind = ("frame" if doc_kind == "frame" else "landing") \
                    if document else "request"
                if unreached(nxt, hop_kind, url):
                    abort()                      # SP-74: the hop is never fetched
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
        html, charset = None, None                # a main-frame document's HTML, as given
        if document and doc_kind == "document" and \
                (stripped or final is first or not req.is_navigation_request()
                 or method not in ("GET", "HEAD")):
            # the body this page is given (Q2), decoded by its charset (never raising)
            html, charset = _note_received(req, url, final)
        relanding = final is not first and not stripped and \
            req.is_navigation_request() and method in ("GET", "HEAD")
        drop = ("set-cookie",) if stripped else ()
        if fresh and doc_kind == "document" and not relanding and \
                trampoline(route, url, final, drop):
            return                                   # BA-3: given to the trampoline
        # every answer is given without a `Speculation-Rules` header, and a page's
        # parser-inserted rule sets inert (BA-3)
        if stripped:
            # an isolated answer never writes the context's jar (FR-SESS-20, R2)
            _fulfil_preload_free(route, final, *drop)
        elif final is first:
            _fulfil_preload_free(route, first, html=html, encoding=charset)
        elif req.is_navigation_request() and method in ("GET", "HEAD"):
            # the browser re-requests the (checked) landing URL itself, so page.url and
            # relative links are right; a GET or HEAD only, never a body (reviewers).
            # In an authenticated context a landing outside the session's origins was
            # aborted above (FR-SESS-20, R1), so this re-request stays on them
            status = 303 if req.method.upper() not in ("GET", "HEAD") else 302
            # Playwright never routes that re-request: it goes through the enforcer,
            # which forwards this checked landing once and nothing else (BUG-0559 r2)
            admit_landing(final_url)
            route.fulfill(status=status, headers={"location": final_url})
        else:
            # a body kept through 307/308 is never sent twice: the landing response is
            # the answer (a navigation's page.url stays the first URL)
            _fulfil_preload_free(route, final, html=html, encoding=charset)
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


#: A charset a document names in its first bytes (``<meta charset>``, or ``http-equiv``'s
#: ``content``), as HTML's prescan reads it.
_META_CHARSET = re.compile(rb"""<meta[^>]*?charset\s*=\s*["']?\s*([A-Za-z0-9._:-]+)""",
                           re.IGNORECASE)
_HEADER_CHARSET = re.compile(r"""charset\s*=\s*["']?\s*([A-Za-z0-9._:-]+)""", re.IGNORECASE)
#: Python's names of the labels a browser reads as windows-1252.
_LATIN_CODECS = frozenset({"ascii", "iso8859-1", "latin-1", "cp1252"})


def decoded_text(body: bytes | None, content_type: str | None) -> tuple[str, str | None]:
    """**A response body as text, by its own charset, never raising** (BUG-0559 review
    round 2, BB-4: a strict UTF-8 read of an ISO-8859-1 page raised out of the route
    handler, so the request was never answered and the load timed out). The charset is
    a byte-order mark's, else the ``Content-Type``'s, else one the document names in its
    first 1024 bytes (a Latin-1 label read as windows-1252, as a browser does); an
    undeclared body is UTF-8 when it decodes as UTF-8, else windows-1252, else byte for
    byte. Returns the text and the codec it was decoded with -- None when the declared
    charset did not decode losslessly (undecodable bytes replaced): such text is read,
    never re-encoded and given in place of the body. The one decoder of a Playwright
    response body in fuzzlab (an AST guard holds every module to it).

    **Any label a target writes is safe** (BUG-0559 review round 3, BB-4): Python's
    registry also names codecs that are not text encodings (``hex``, ``base64``,
    ``rot13``, ``zlib``, ``bz2``, ``uu``, ``quopri``: ``bytes.decode`` raises
    ``LookupError``) and text codecs that refuse a document (``idna``, ``undefined``:
    ``UnicodeError``, with ``replace`` too). Such a label is unknown, as a browser
    treats a label it does not know: the next one decides (the document's own), else the
    undeclared order. Nothing a codec raises leaves this function."""
    data = bytes(body or b"")
    declared = [name for bom, name in ((codecs.BOM_UTF8, "utf-8-sig"),
                                       (codecs.BOM_UTF16_LE, "utf-16"),
                                       (codecs.BOM_UTF16_BE, "utf-16"))
                if data.startswith(bom)][:1]
    for match in (_HEADER_CHARSET.search(content_type or ""),
                  _META_CHARSET.search(data[:1024])):
        if match:
            name = match.group(1)
            declared.append(name.decode("ascii", "replace") if isinstance(name, bytes)
                            else name)
    for name in declared:                     # the first label known decides
        codec = _text_codec(name)
        if codec is None:
            continue                          # unknown, or no text encoding: not a label
        if codec in _LATIN_CODECS:
            # a Latin-1 label is read as windows-1252 (WHATWG), then byte for byte
            try:
                return data.decode("cp1252"), "cp1252"
            except UnicodeDecodeError:
                return data.decode("latin-1"), "latin-1"
        try:
            return data.decode(codec), codec
        except UnicodeDecodeError:            # the declared charset, lossy: read only
            try:
                return data.decode(codec, "replace"), None
            except Exception:  # noqa: BLE001 - it cannot replace (idna): not a label
                continue
        except Exception:  # noqa: BLE001 - a codec that refuses a document (undefined,
            continue       # idna): not a label either
    for codec in ("utf-8", "cp1252"):         # undeclared: UTF-8, else HTML's default
        try:
            return data.decode(codec), codec
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1"), "latin-1"


def _text_codec(label: str) -> str | None:
    """Python's name of the text encoding a charset ``label`` names, or None: an unknown
    label, or a codec that is not a text encoding (``hex``, ``base64``, ``rot13``, ...;
    `decoded_text`)."""
    try:
        info = codecs.lookup(label)
    except Exception:  # noqa: BLE001 - LookupError, or a label the registry chokes on
        return None
    if not getattr(info, "_is_text_encoding", True):
        return None
    return info.name


def response_text(response) -> str | None:
    """A Playwright response's body as text (`decoded_text`), or None when its body is
    gone or cannot be read -- never an exception. What every module reads a response
    body with, never ``response.text()`` (strict UTF-8)."""
    try:
        body = response.body()
        ctype = (response.headers or {}).get("content-type", "")
        return decoded_text(body, ctype)[0]       # never raises itself (BB-4, round 3)
    except Exception:  # noqa: BLE001 - a body the driver let go (or a double): none
        return None


def _note_received(req, url: str, answer) -> tuple[str | None, str | None]:
    """Keep the HTML of a main-frame document the guard is about to fulfil, for its
    page's `navigate` (never anything else: no subresource, no frame). Returns that HTML
    and the codec it was decoded with (`decoded_text`; the route reads them once more
    for `_fulfil_preload_free`), or ``(None, None)``. Never raises: the route answers
    every request (BUG-0559 review round 2, BB-4)."""
    from playwright.sync_api import Error
    try:
        page = getattr(req.frame, "page", None)
        if page is None or "text/html" not in (answer.headers or {}).get(
                "content-type", ""):
            return None, None
        html, charset = decoded_text(answer.body(), answer.headers.get("content-type"))
        _RECEIVED[page] = (document_key(url), html)
        return html, charset
    # no frame (a service worker's request; a request double without one), or a page
    # that cannot be weakly referenced: nothing is kept (`decoded_text` itself never
    # raises; a LookupError escaped it before, BB-4 review round 3)
    except (AttributeError, Error, LookupError, TypeError, ValueError):
        return None, None


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


def _merged(request_headers, extra: dict[str, str]) -> dict[str, str]:
    """The request's own headers with ``extra`` put in place of any header of the same
    name (case-insensitive): ``route.fetch(headers=)`` replaces the whole set."""
    names = {k.lower() for k in extra}
    out = {k: v for k, v in (request_headers or {}).items() if k.lower() not in names}
    out.update(extra)
    return out


#: How long a frozen page's already-started requests get to reach the guard before the
#: page closes (`close_pages`).
RELEASE_DRAIN_MS = 100


def close_pages(context, pages, before_close: Callable[[], None] | None = None) -> None:
    """Close ``pages`` of a guarded ``context`` without letting a request out (BUG-0504):
    the one way a guarded page is closed, mid-run (a popup) or at teardown (`release`).

    A request is guarded only if Playwright dispatches its route event while the page is
    alive. A navigation a page starts just before it closes (an app's timer) is paused at
    interception with its event not yet dispatched, and closing the page let it out
    un-intercepted (a refused ``/logout.php`` reached the server in 18 of 80 loaded M6
    runs; 0 of 160 with this order). So:

    1. every page is frozen (scripts disabled, loading stopped): nothing new starts;
    2. drained: `RELEASE_DRAIN_MS` of event dispatch, so a paused request gets the
       guard's own answer;
    3. ``before_close()`` if given (`release` adds its refusing route there);
    4. closed. Each step is best effort: a page already closed starts nothing."""
    pages = list(pages)
    for page in pages:
        try:
            cdp = context.new_cdp_session(page)
            cdp.send("Emulation.setScriptExecutionDisabled", {"value": True})
            cdp.send("Page.stopLoading")
        except Exception:  # noqa: BLE001 - a closed page starts nothing
            pass
    for page in pages:
        try:
            page.wait_for_timeout(RELEASE_DRAIN_MS)
        except Exception:  # noqa: BLE001 - a closed page has nothing to drain
            pass
    if before_close is not None:
        try:
            before_close()
        except Exception:  # noqa: BLE001 - a context already closed sends nothing
            pass
    for page in pages:
        try:
            page.close()
        except Exception:  # noqa: BLE001 - best effort, it may have closed itself
            pass


def release(target) -> None:
    """Before closing a guarded context: its pages closed through `close_pages`, with a
    route refusing everything added in between -- and never unroute (BUG-0504).

    ``unroute_all`` -- done after the pages closed since BUG-0128 -- *continued* a
    request paused at interception with no route left to handle it. The refusing route
    is added after the drain and before the close (the newest route answers first), so
    nothing dispatched from then on is fetched; it fails silently on a closed target
    (what ``unroute_all(behavior="ignoreErrors")`` was for). Popups opened meanwhile are
    closed too (bounded). No call here waits on in-flight work (PA-0128): the drain is
    a fixed timer."""
    def refuse(route, request=None):
        try:
            req = route.request
            document = req.is_navigation_request() or req.resource_type in (
                "document", "iframe")
            route.abort(_abort_code(document))
        except Exception:  # noqa: BLE001 - a closed target: nothing left to refuse
            pass
    refusing = [lambda: target.route("**/*", refuse)]
    # until no page is left (bounded): a page may open a popup while another closes,
    # and a popup missed here would be left open (reviewer B)
    for _ in range(3):
        pages = list(getattr(target, "pages", None) or [])
        if not pages:
            break
        close_pages(target, pages, refusing.pop() if refusing else None)
    for add in refusing:                   # no page at all: still refuse from now on
        try:
            add()
        except Exception:  # noqa: BLE001 - a context already closed sends nothing
            pass


# --- guarded navigation (BUG-0138, PA-0138) -----------------------------------------
#: How long a load state is still waited for once a main-frame navigation of the page
#: has failed during the wait: a refused script navigation (ERR_ABORTED, BUG-0136) made
#: while the document was parsed stops its loading, so the state never comes.
SUPERSEDED_GRACE_MS = 300
_STEP_MS = 100

#: How long a failed navigation waits, before it raises, for the commits its failure
#: starts (BUG-0522): Chromium commits its own error page tens of milliseconds after
#: ``goto`` raised (measured: p50 about 25-45 ms, worst 304 ms). An expiry is counted
#: (`error_page_waits`) and logged: it reopens BUG-0522 for that one navigation.
ERROR_PAGE_WAIT_MS = 3000
#: The first line of a failure Chromium answers with its own error page: a network
#: error other than an abort (ERR_ABORTED leaves the current document; BUG-0136). Only
#: the leading API and code decide -- never the URL after them (target text; PA-0022).
_ERROR_PAGE_FAILURE = re.compile(r"^\S+: net::ERR_(?!ABORTED\b)[A-Z_]+ at ")
#: ... or this navigation was overtaken by such an error page (an earlier failure's,
#: still coming): the overtaken navigation still lands afterwards (measured 30/30,
#: 6-69 ms later). End-anchored: the other navigation's URL closes the line.
_OVERTAKEN_BY_ERROR_PAGE = re.compile(
    r'^\S+: Navigation to ".*" is interrupted by another navigation to '
    r'"chrome-error://[^"]*"$')
#: The attribute a failed `navigate` / `reload` sets on the exception it raises: the URL
#: of the last main-frame commit its failure settled on (``chrome-error://...`` for the
#: browser's error page), or None when the wait expired.
NAVIGATION_SETTLED_ATTR = "navguard_settled_on"
_WAITS_LOCK = threading.Lock()
_ERROR_PAGE_WAITS = {"waited": 0, "expired": 0}
_log = logging.getLogger("fuzzlab.navguard")


def error_page_waits() -> dict:
    """How many failed navigations waited for their error page, and how many of those
    waits expired (BUG-0522), in this process."""
    with _WAITS_LOCK:
        return dict(_ERROR_PAGE_WAITS)


def _settles_on_error_page(exc) -> str | None:
    """What the browser still does after this failure: ``"error-page"`` (it commits
    its own error page), ``"overtaken"`` (an earlier failure's error page overtook this
    navigation, which still lands afterwards), or None (nothing more: an abort -- the
    guard's refusal, the current document kept --, a download, a timeout)."""
    text = str(exc or "")
    first = text.splitlines()[0] if text else ""
    if _ERROR_PAGE_FAILURE.match(first):
        return "error-page"
    if _OVERTAKEN_BY_ERROR_PAGE.match(first):
        return "overtaken"
    return None


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
        #: the main frame's commits (their URLs) since this navigation started (BUG-0522)
        self.commits: list[str] = []
        self.armed = armed
        page.on("requestfailed", self._on_failed)
        page.on("framenavigated", self._on_committed)

    def _on_committed(self, frame) -> None:
        try:
            if frame == self._page.main_frame:
                self.armed = True
                self.commits.append(str(getattr(frame, "url", "") or ""))
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


def _settle_failure(page, failures: _NavigationFailures, exc) -> None:
    """Before a failed navigation raises (BUG-0522): wait, at most `ERROR_PAGE_WAIT_MS`,
    for the commits its failure starts -- Chromium's error page; when this navigation
    was overtaken by one, that page and then this navigation's own late commit -- seen
    by ``failures``, which listens from before the navigation started: a fresh commit,
    never the page's current URL (an earlier failure's error page). Records the last
    such commit on ``exc`` (`NAVIGATION_SETTLED_ATTR`; None on expiry, counted and
    logged). Any navigation made before those commits would be overtaken by them: X1's
    cleanup, the next load, a restore. Never raises."""
    kind = _settles_on_error_page(exc)
    if kind is None:
        return
    end = time.monotonic() + ERROR_PAGE_WAIT_MS / 1000
    settled = None
    while True:
        commits = failures.commits
        at = next((i for i, u in enumerate(commits) if u.startswith("chrome-error:")),
                  None)
        if at is not None and (kind == "error-page" or len(commits) > at + 1):
            settled = commits[-1]
            break
        if time.monotonic() >= end:
            break
        try:
            page.wait_for_timeout(20)              # Playwright's events are pumped
        except Exception:  # noqa: BLE001 - the page has gone: nothing more will come
            break
    with _WAITS_LOCK:
        _ERROR_PAGE_WAITS["waited"] += 1
        if settled is None:
            _ERROR_PAGE_WAITS["expired"] += 1
    if settled is None:
        _log.warning(_scrubbed(f"a failed navigation's error page did not come within "
                               f"{ERROR_PAGE_WAIT_MS} ms (BUG-0522): the next navigation "
                               f"of this page may be overtaken"))
    with contextlib.suppress(Exception):           # an exception that takes no attribute
        setattr(exc, NAVIGATION_SETTLED_ATTR, settled)


def end_failed_load(page, error, *, timeout_ms: float) -> str:
    """**How a failed load ends the page's previous document** (BUG-0136 review X1,
    BUG-0522), for every caller whose own navigation raised: ``"error-page"`` when the
    failure settled on the browser's own error page (`navigate` waited for it), which
    has replaced the previous document -- nothing more is navigated, since a second
    navigation there is what overtook the next load (BUG-0522); else ``about:blank``
    (suppressed), so a document an abort left alive stops: ``"blank"``. An ``error``
    that `navigate` / `reload` did not raise carries no record and gets ``about:blank``."""
    settled = getattr(error, NAVIGATION_SETTLED_ATTR, None)
    if isinstance(settled, str) and settled.startswith("chrome-error:"):
        return "error-page"
    with contextlib.suppress(Exception):
        navigate(page, "about:blank", timeout_ms=timeout_ms, wait_until="load")
    return "blank"


def navigate(page, url: str, *, timeout_ms: float, wait_until: str = "domcontentloaded",
             wait_ms: float | None = None) -> Navigation:
    """**The** way a guarded page is navigated in fuzzlab (BUG-0138, PA-0138; an AST
    guard holds every other module to it). ``goto`` waits for the **commit** only, so a
    refused or failed own target still raises (BUG-0136). Then ``wait_until`` is waited
    for at most ``wait_ms`` (default ``timeout_ms``), suppressed, and no longer than
    `SUPERSEDED_GRACE_MS` after a main-frame navigation failed: a page whose script
    navigates to a refused URL while it is parsed never reaches it, and is never
    waited out. The caller reads the page as it is, or ``response``, when not
    ``reached``. A failure raises only once the commits it starts have landed
    (`_settle_failure`, BUG-0522); a failed load's cleanup is `end_failed_load`."""
    failures = _NavigationFailures(page)
    if _is_weakref_able(page):
        _RECEIVED.pop(page, None)          # only this navigation's document counts
    try:
        try:
            response = page.goto(url, wait_until="commit", timeout=timeout_ms)
        except Exception as exc:
            _settle_failure(page, failures, exc)
            raise
        committed, failures.armed = time.monotonic(), True
        html = _received_html(page, url, response)
        reached = _await_state(page, wait_until,
                               timeout_ms if wait_ms is None else wait_ms, failures)
        return Navigation(response, reached, bool(failures.failed), committed, html)
    finally:
        failures.close()


def reload(page, *, timeout_ms: float, wait_until: str = "domcontentloaded",
           wait_ms: float | None = None) -> Navigation:
    """`navigate`'s rule for a reload (BUG-0138, BUG-0522)."""
    failures = _NavigationFailures(page)
    if _is_weakref_able(page):
        _RECEIVED.pop(page, None)
    try:
        try:
            response = page.reload(wait_until="commit", timeout=timeout_ms)
        except Exception as exc:
            _settle_failure(page, failures, exc)
            raise
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
    except Error:                  # the response is gone (the page moved on)
        return None
    return response_text(response)  # by its charset, never raising (BB-4)


def make_ws_handler(in_scope: Callable[[str], bool],
                    on_out_of_scope: Callable[[str], None] | None = None, *,
                    hold: Callable[[], bool] | None = None,
                    on_drop: Callable[[str, object], None] | None = None,
                    cookie_scope: Callable[[str], bool] | None = None,
                    on_session_withheld: Callable[[str, str, str], None] | None = None,
                    on_send: Callable[[str], None] | None = None,
                    session_cookies=None,
                    on_session_unreached: Callable[[str, str, str, str], None]
                    | None = None):
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
    "websocket", url)`` is told.

    ``session_cookies`` (SP-74, BUG-0559): an in-scope socket on a host the session's
    cookies do not reach (`session_host_refusal`) is never connected either; it would
    open without the session. ``on_session_unreached(url, "websocket", url, reason)`` is
    told."""
    session_cookies = [dict(c) for c in (session_cookies or ())]

    def handler(ws) -> None:
        if in_scope(ws.url) and cookie_scope is not None and not cookie_scope(ws.url):
            logging.info(f"blocked a WebSocket to {urlsplit(ws.url).hostname or '?'!r}: "
                         f"another origin than the session's (FR-SESS-20)")
            if on_session_withheld is not None:
                on_session_withheld(ws.url, "websocket", ws.url)
            return
        why = session_host_refusal(session_cookies, ws.url, cookie_scope=cookie_scope) \
            if session_cookies and in_scope(ws.url) else None
        if why is not None:
            logging.info(f"blocked a WebSocket to {urlsplit(ws.url).hostname or '?'!r}: "
                         f"the session's cookies do not reach that host (SP-74)")
            if on_session_unreached is not None:
                with contextlib.suppress(Exception):
                    on_session_unreached(ws.url, "websocket", ws.url, why)
            return
        if in_scope(ws.url):
            # Chromium opens it through the enforcer, which tunnels only an admitted
            # socket (`admit_socket`, BUG-0559 review round 2)
            admit_socket(ws.url)
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
               isolated_request: Callable[[], object] | None = None,
               session_cookies=None,
               on_session_unreached: Callable[[str, str, str, str], None]
               | None = None) -> None:
    """Confine a Playwright ``BrowserContext`` (pass the context, so popups are covered
    too), WebSockets included. ``in_scope`` is required: there is no unscoped guard
    (BUG-0123). ``method_refusal``, ``observe``, ``request_refusal``, ``window``, the
    session ``headers`` (with ``header_scope``) and ``cookie_scope`` /
    ``on_session_withheld`` / ``isolated_request`` (FR-SESS-20): see
    `make_route_handler` (a WebSocket off the session's origins is never connected,
    `make_ws_handler`); ``ws_hold`` /
    ``on_ws_drop`` / ``on_ws_send``: see `make_ws_handler`. Session headers are applied by the route only
    (FR-CRAWL-14). ``session_cookies`` / ``on_session_unreached`` (SP-74, BUG-0559): every
    context that adopts a session's cookies passes them, as it holds them
    (`held_session_cookies`); nothing it sends goes to a host they do not reach.

    Every guarded context gets `PRELOAD_OFF_JS` before any of its pages runs a script
    (BUG-0559 review round 1, BA-3): a speculation-rules preload is sent by the browser
    process, past every rule of the route, so no rule set is ever registered."""
    init = getattr(target, "add_init_script", None)
    if init is None:                        # a double, or an old Playwright: loudly
        logging.warning("this target cannot take an init script; speculation-rules "
                        "preloads are not neutralised (BUG-0559)")
    else:
        init(PRELOAD_OFF_JS)                # the script itself (positional: ``script``)
    api = getattr(target, "request", None)
    target.route("**/*", make_route_handler(allow, on_abort, in_scope=in_scope,
                                            on_out_of_scope=on_out_of_scope, api=api,
                                            method_refusal=method_refusal,
                                            observe=observe,
                                            request_refusal=request_refusal,
                                            headers=headers, header_scope=header_scope,
                                            window=window, cookie_scope=cookie_scope,
                                            on_session_withheld=on_session_withheld,
                                            isolated_request=isolated_request,
                                            session_cookies=session_cookies,
                                            on_session_unreached=on_session_unreached))
    route_ws = getattr(target, "route_web_socket", None)
    if route_ws is None:                            # an old Playwright: say so, loudly
        logging.warning("this Playwright cannot route WebSockets; the enforcer of "
                        "browser_launch_args refuses them, none being admitted "
                        "(BUG-0123, BUG-0559)")
        return
    route_ws("**/*", make_ws_handler(in_scope, on_out_of_scope, hold=ws_hold,
                                     on_drop=on_ws_drop, cookie_scope=cookie_scope,
                                     on_session_withheld=on_session_withheld,
                                     on_send=on_ws_send, session_cookies=session_cookies,
                                     on_session_unreached=on_session_unreached))


_LOOPBACK_SPELLINGS = ("127.0.0.1", "localhost", "[::1]")


def origin_host_spellings(url: str) -> tuple[str, ...]:
    """The host names ``url``'s origin folds (`core.urls.canonical_origin`), as a URL's
    ``hostname`` spells them: a loopback host's three (``::1`` without brackets), any
    other host itself; none for a URL with no origin. What a caller asks
    `cookie_reaches` about when its question is "does this cookie reach the scope's
    host" (`browserlogin.filter_storage_state`, BUG-0559 review round 2)."""
    origin = canonical_origin(url) if url else None
    if origin is None:
        return ()
    host = origin.split("://", 1)[1].rsplit(":", 1)[0]
    if host == "127.0.0.1":
        return tuple(h.strip("[]") for h in _LOOPBACK_SPELLINGS)
    return (host.strip("[]"),)


def _proxy_endpoint(proxy: str) -> tuple[str, int]:
    """``host:port`` of a capture proxy, refused unless ``host`` is a loopback IP
    literal and ``port`` a port (CC-CRAWL-0031): the proxy is this machine's own
    recorder (``fuzzlab.disco``), never a remote hop."""
    host, sep, port = (proxy or "").rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536 \
            or host not in ("127.0.0.1", "[::1]"):
        raise ValueError(f"a capture proxy is a loopback IP literal and port, not {proxy!r}")
    require_loopback(host.strip("[]"), "capture proxy")
    return host, int(port)


# --- the enforcer: what Chromium sends past the route (BUG-0559 review round 2, BB-3) ----
#: How long a WebSocket the guard admitted (`admit_socket`) may take to reach the enforcer.
SOCKET_TICKET_TTL_S = 10.0
#: How long the enforcer waits for a request head, and the most it reads of one.
_HEAD_TIMEOUT_S = 30.0
_HEAD_MAX = 65536
_REFUSAL = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n"
            b"Connection: close\r\n\r\n")
_ENFORCE_LOCK = threading.Lock()
#: http landing key (`_landing_key`) -> expiry times of the landings the route checked
_TICKETS: dict[tuple, list[float]] = {}
#: (host, port) -> the tunnels admitted there and not yet carried (`_TunnelTicket`),
#: oldest first: a WebSocket's (`admit_socket`) and an https landing's (`admit_landing`)
_TUNNEL_TICKETS: dict[tuple[str, int], list] = {}
#: How many tunnels one ticket may open before one of them carries its traffic, and how
#: long after its first the others may come: the browser's retry after a certificate
#: error is a second ``CONNECT``, 4-12 ms after the first (BUG-0559 review round 3,
#: measured on Chromium 141 with ``ignore_https_errors``, both binaries)
_TICKET_TUNNELS_MAX = 4
_TICKET_RETRY_WINDOW_S = 3.0
#: upstream (None: direct) -> (pid, server); endpoint -> its upstream
_ENFORCERS: dict = {}
_ENFORCER_UPSTREAM: dict[str, tuple | None] = {}
_REFUSED = {"request": 0, "preload": 0, "connect": 0, "reuse": 0}


def _socket_key(host, port) -> tuple[str, int]:
    return str(host or "").lower().strip("[]"), int(port)


class _TunnelTicket:
    """One tunnel a guard admitted to a host and port (`admit_socket`, `admit_landing`),
    within `SOCKET_TICKET_TTL_S`. Tunnels open on it until one carries the browser's
    traffic -- a TLS handshake the browser abandoned on a certificate error carries none,
    and its retry is a second ``CONNECT`` (measured, BUG-0559 review round 3) --, at
    most `_TICKET_TUNNELS_MAX`, the later ones within `_TICKET_RETRY_WINDOW_S` of the
    first. The tunnel that carries it ``claims`` it, and no other tunnel opens on it. A
    ``landing`` ticket's tunnel carries one exchange (`_HeldTunnel`); a WebSocket's, the
    socket's life."""

    __slots__ = ("claimed", "expires", "first", "landing", "tunnels")

    def __init__(self, landing: bool, expires: float):
        self.landing, self.expires, self.tunnels, self.claimed = landing, expires, 0, False
        self.first = 0.0                  # when its first tunnel opened


def _admit_tunnel(url: str, *, landing: bool) -> None:
    parts = urlsplit(url or "")
    try:
        port = parts.port
    except ValueError:
        return
    if not parts.hostname:
        return
    if port is None:
        port = 443 if parts.scheme.lower() in ("wss", "https") else 80
    key, now = _socket_key(parts.hostname, port), time.monotonic()
    with _ENFORCE_LOCK:
        live = [t for t in _TUNNEL_TICKETS.get(key, ()) if t.expires > now and
                not t.claimed]
        _TUNNEL_TICKETS[key] = (live + [_TunnelTicket(landing,
                                                      now + SOCKET_TICKET_TTL_S)])[-64:]


def admit_socket(url: str) -> None:
    """One WebSocket to ``url``'s host and port that a guard's socket handler admitted
    (scope, FR-SESS-20, SP-74 checked) and is about to open (``connect_to_server``):
    the enforcer tunnels a ``CONNECT`` there within `SOCKET_TICKET_TTL_S` until one
    tunnel carries it (`_TunnelTicket`: a certificate error's retry included), and no
    other (BUG-0559 review rounds 2 and 3, BB-3)."""
    _admit_tunnel(url, landing=False)


def _landing_key(url: str):
    """What a checked redirect landing is matched by when the browser re-requests it:
    scheme, host, port, path and query, percent-decoded (Chromium re-encodes what the
    route wrote in ``Location``); None for a URL that is not an absolute http one."""
    from urllib.parse import unquote
    parts = urlsplit(url or "")
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError:
        return None
    if scheme != "http" or not parts.hostname:
        return None
    return ("landing", parts.hostname.lower().strip("[]"), port or 80,
            unquote(parts.path or "/"), unquote(parts.query))


def admit_landing(url: str) -> None:
    """The landing of a redirected navigation the route checked and answered with a
    redirect to it (`make_route_handler`): Playwright never routes the browser's
    re-request of it, which therefore goes through the enforcer -- forwarded once,
    within `SOCKET_TICKET_TTL_S` (a ``GET``/``HEAD``, never a preload); an ``https``
    landing admits tunnels to its host and port until one carries the browser's request
    (a certificate error's retry included), and that tunnel carries that one exchange
    only (`_TunnelTicket`, `_HeldTunnel`). Measured: an unadmitted re-request was
    refused and the redirected page never loaded (BUG-0559 review round 2); a tunnel
    kept in the browser's pool carried a later prefetch, and a certificate error's retry
    needed a second tunnel (review round 3)."""
    if urlsplit(url or "").scheme.lower() == "https":
        _admit_tunnel(url, landing=True)
        return
    key = _landing_key(url)
    if key is None:
        return
    now = time.monotonic()
    with _ENFORCE_LOCK:
        live = [t for t in _TICKETS.get(key, ()) if t > now]
        _TICKETS[key] = (live + [now + SOCKET_TICKET_TTL_S])[-64:]


def _take_ticket(key) -> bool:
    """Consume one live ticket of an http landing (`_landing_key`)."""
    if key is None:
        return False
    now = time.monotonic()
    with _ENFORCE_LOCK:
        live = [t for t in _TICKETS.pop(key, ()) if t > now]
        if not live:
            return False
        if live[1:]:
            _TICKETS[key] = live[1:]
        return True


def _take_tunnel(host, port):
    """The `_TunnelTicket` that admits a ``CONNECT`` to ``host:port`` (its tunnel
    counted), or None: the oldest live one not yet carried -- each is admitted just
    before the browser opens its connection."""
    key, now = _socket_key(host, port), time.monotonic()
    with _ENFORCE_LOCK:
        live = [t for t in _TUNNEL_TICKETS.pop(key, ()) if t.expires > now and
                not t.claimed]
        if live:
            _TUNNEL_TICKETS[key] = live
        for ticket in live:
            if ticket.tunnels == 0:
                ticket.first = now
            elif ticket.tunnels >= _TICKET_TUNNELS_MAX or \
                    now - ticket.first > _TICKET_RETRY_WINDOW_S:
                continue
            ticket.tunnels += 1
            return ticket
        return None


def _claim(ticket: _TunnelTicket) -> bool:
    """``ticket``'s traffic goes through the tunnel asking: False once another of its
    tunnels has carried it."""
    with _ENFORCE_LOCK:
        if ticket.claimed:
            return False
        ticket.claimed = True
        return True


def enforcer_refusals() -> dict:
    """What the enforcer refused in this process, by kind: ``preload`` (a request
    carrying ``Sec-Purpose``: a speculation-rules prefetch or prerender), ``request``
    (anything else Chromium sent itself), ``connect`` (a tunnel no guard admitted),
    ``reuse`` (traffic on an admitted tunnel past what its ticket admits -- a further
    request on an https landing's, a second tunnel carrying one ticket --: the tunnel is
    closed instead, BUG-0559 review round 3)."""
    with _ENFORCE_LOCK:
        return dict(_REFUSED)


def _authority(target: str) -> tuple[str | None, int]:
    """``host`` and ``port`` of a CONNECT target (``[::1]:443`` included)."""
    host, sep, port = (target or "").rpartition(":")
    if not sep or not port.isdigit() or not host:
        return None, 0
    return host.strip("[]"), int(port)


def _header(head: bytes, name: bytes) -> str:
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.strip().lower() == name:
            return value.strip().decode("latin-1")
    return ""


def _pump(src, dst) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    for s in (src, dst):
        with contextlib.suppress(OSError):
            s.shutdown(socket.SHUT_RDWR)


#: TLS record content types (RFC 8446 §5.1)
_TLS_HANDSHAKE, _TLS_APPLICATION_DATA = 22, 23
#: The largest encrypted record that cannot hold an HTTP request: an alert or a key
#: update (TLS 1.3 sends both as application data). The shortest request line with its
#: blank line is 18 bytes, and every cipher adds at least 16 to it.
_TLS_CONTROL_MAX = 33


def _tls13(record: bytes) -> bool | None:
    """Did the server choose TLS 1.3 in this ``ServerHello`` record (its
    ``supported_versions`` extension, RFC 8446 §4.2.1)? None when the record is not one
    that can be read."""
    try:
        if record[0] != _TLS_HANDSHAKE or record[5] != 2:     # handshake, server_hello
            return None
        body = record[9:9 + int.from_bytes(record[6:9], "big")]
        at = 2 + 32                                         # legacy_version, random
        at += 1 + body[at]                                  # legacy_session_id
        at += 2 + 1                                         # cipher_suite, compression
        end = at + 2 + int.from_bytes(body[at:at + 2], "big")
        at += 2
        while at + 4 <= end:
            kind = int.from_bytes(body[at:at + 2], "big")
            size = int.from_bytes(body[at + 2:at + 4], "big")
            if kind == 0x002B:                              # supported_versions
                return body[at + 4:at + 4 + size] == b"\x03\x04"
            at += 4 + size
        return False
    except IndexError:
        return None


class _HeldTunnel:
    """A tunnel a `_TunnelTicket` admitted, read at the TLS record layer only -- nothing is
    decrypted or re-signed (BUG-0559 review round 3). It ``claims`` its ticket when it
    carries the browser's traffic (a WebSocket's first application-data record past an
    alert's size, or its first plain byte; a landing's request): until then a handshake
    the browser abandons on a certificate error -- with an alert, which TLS 1.3 sends as
    application data (measured) -- leaves the ticket to the browser's retry, a second
    ``CONNECT`` (measured on Chromium 141 with ``ignore_https_errors``, both binaries:
    without it the redirected page, or the ``wss`` socket, never opened). Traffic past
    what the ticket admits -- a second tunnel carrying it, a landing's further request --
    closes the tunnel, counted (``reuse``).

    An https **landing**'s tunnel carries **one exchange**: Chromium keeps an idle tunnel
    in its pool, and a later same-origin speculation-rules prefetch carrying the session
    rode the landing's, past the route and the enforcer, which judges a ``CONNECT`` only
    (measured, both binaries). The browser's records go on until its request has been
    sent and the server has answered; its next request on the tunnel (an
    application-data record that can hold one, `_TLS_CONTROL_MAX`) is never forwarded --
    the tunnel is closed and counted (``reuse``), and the browser's retry on a new tunnel
    finds no ticket. HTTP/1.1 sends nothing between a request and the end of its answer
    (`browser_launch_args` disables HTTP/2 for Chromium's own traffic: a multiplexed
    connection would carry the prefetch beside the landing). The first application-data
    record of a TLS 1.3 client is its ``Finished`` (the ``ServerHello`` says which
    version; unreadable, it is taken as 1.2, so the tunnel errs towards closing). A
    landing's tunnel that does not speak TLS is closed."""

    def __init__(self, ticket: _TunnelTicket, *, via_proxy: bool):
        self.ticket, self.via_proxy = ticket, via_proxy
        self.tls13: bool | None = None
        self.client_data = 0              # the browser's application-data records so far
        self.claimed = False              # this tunnel carries the ticket's traffic
        self.sent = False                 # a landing's request has gone
        self.answered = False             # the server has sent something since

    def from_client(self, client, remote, buffered: bytes) -> None:
        """Forward the browser's records, whole; a socket's raw once it is claimed; a
        landing's until its next request."""
        buf = buffered
        try:
            while True:
                while buf:
                    if self.claimed and not self.ticket.landing:
                        remote.sendall(buf)        # a WebSocket's own traffic: as it comes
                        buf = b""
                        break
                    if buf[0] not in (20, 21, _TLS_HANDSHAKE, _TLS_APPLICATION_DATA):
                        if self.ticket.landing or not self._claim():
                            self._close(client, remote, "not TLS" if self.ticket.landing
                                        else "a tunnel carried already")
                            return
                        continue                   # a plain ws:// socket
                    if len(buf) < 5:
                        break
                    size = 5 + int.from_bytes(buf[3:5], "big")
                    if len(buf) < size:
                        break
                    record, buf = buf[:size], buf[size:]
                    if not self._admits(record):
                        self._close(client, remote, "a further request"
                                    if self.ticket.landing else "a tunnel carried already")
                        return
                    remote.sendall(record)
                data = client.recv(65536)
                if not data:
                    break
                buf += data
        except OSError:
            pass
        self._close(client, remote, None)

    def _claim(self) -> bool:
        if not self.claimed:
            self.claimed = _claim(self.ticket)
        return self.claimed

    def _admits(self, record: bytes) -> bool:
        if record[0] != _TLS_APPLICATION_DATA:
            return True
        self.client_data += 1
        if len(record) - 5 <= _TLS_CONTROL_MAX:
            # an alert or a key update -- a TLS 1.3 client gives up a handshake on a
            # certificate error with one (measured) --: it carries nothing, no request fits
            return True
        if not self.ticket.landing:
            return self._claim()          # a WebSocket: its handshake went, it is carried
        if self.tls13 and self.client_data == 1:
            return True                   # a TLS 1.3 client's Finished
        if self.answered:
            return False                  # the exchange is done: a further request
        if not self.sent:
            if not self._claim():
                return False              # another tunnel carried this landing
            self.sent = True
        return True

    def from_server(self, remote, client) -> None:
        """Relay the server's bytes; read its ``ServerHello`` (after a capture proxy's
        answer to the ``CONNECT``) and note any answer once the request has gone."""
        head = b""
        try:
            while True:
                data = remote.recv(65536)
                if not data:
                    break
                if self.sent:
                    self.answered = True
                if self.tls13 is None:
                    head += data
                    self._read_hello(head)
                client.sendall(data)
        except OSError:
            pass
        for s in (remote, client):
            with contextlib.suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)

    def _read_hello(self, head: bytes) -> None:
        if self.via_proxy:
            if b"\r\n\r\n" not in head:
                return
            head = head.split(b"\r\n\r\n", 1)[1]
        if len(head) < 5:
            return
        size = 5 + int.from_bytes(head[3:5], "big")
        if len(head) >= size or len(head) > 4096:
            self.tls13 = bool(_tls13(head[:size]))     # unreadable: 1.2, towards closing

    def _close(self, client, remote, why: str | None) -> None:
        if why is not None:
            with _ENFORCE_LOCK:
                _REFUSED["reuse"] += 1
            logging.info(f"closed a tunnel the enforcer admitted ({why}; BUG-0559)")
        for s in (client, remote):
            with contextlib.suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)


class _EnforcerHandler(socketserver.BaseRequestHandler):
    """One connection from Chromium, one request: a ``CONNECT`` the guard admitted is
    tunnelled (to its host, or through the capture proxy); the re-request of a redirect
    landing the route checked (`admit_landing`) is forwarded the same way, with
    ``Connection: close``; every other request is refused (403)."""

    def handle(self) -> None:
        client = self.request
        client.settimeout(_HEAD_TIMEOUT_S)
        head = b""
        try:
            while b"\r\n\r\n" not in head and len(head) < _HEAD_MAX:
                data = client.recv(4096)
                if not data:
                    return                       # a preconnect that sent nothing
                head += data
        except OSError:
            return
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        method, _sep, rest = line.partition(" ")
        target = rest.split(" ", 1)[0]
        if method.upper() == "CONNECT":
            host, port = _authority(target)
            ticket = _take_tunnel(host, port) if host is not None else None
            if ticket is not None:
                self._tunnel(client, host, port, head, ticket)
                return
            self._refuse(client, "connect", host or "?", "")
            return
        purpose = _header(head, b"sec-purpose")
        if not purpose and method.upper() in ("GET", "HEAD") and \
                _take_ticket(_landing_key(target)):
            self._forward(client, method.upper(), target, head)
            return
        self._refuse(client, "preload" if purpose else "request",
                     urlsplit(target).hostname or "?", purpose)

    def _forward(self, client, method: str, target: str, head: bytes) -> None:
        """One admitted landing re-request, sent on (origin-form to its host, or as it
        came to the capture proxy) with ``Connection: close``; the answer relayed back
        and the connection closed, so nothing else rides on it."""
        upstream = self.server.upstream
        lines = head[:head.index(b"\r\n\r\n")].split(b"\r\n")
        kept = [ln for ln in lines[1:] if ln.split(b":", 1)[0].strip().lower() not in
                (b"connection", b"proxy-connection", b"keep-alive", b"proxy-authorization")]
        first = lines[0]
        try:
            if upstream is not None:
                remote = socket.create_connection((upstream[0].strip("[]"), upstream[1]),
                                                  timeout=30)
            else:
                # the target as Chromium sent it, in origin form: its own bytes after
                # the authority, never rebuilt
                parts = urlsplit(target)
                after = target.split("://", 1)[-1]
                origin_form = after[after.index("/"):] if "/" in after else "/"
                first = f"{method} {origin_form} HTTP/1.1".encode()
                remote = socket.create_connection((parts.hostname, parts.port or 80),
                                                  timeout=30)
            remote.sendall(b"\r\n".join([first, *kept, b"Connection: close", b"", b""]))
        except OSError:
            with contextlib.suppress(OSError):
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                               b"Connection: close\r\n\r\n")
            return
        client.settimeout(None)
        _pump(remote, client)
        remote.close()

    @staticmethod
    def _refuse(client, kind: str, host: str, purpose: str) -> None:
        with _ENFORCE_LOCK:
            _REFUSED[kind] = _REFUSED.get(kind, 0) + 1
        # the host only, never the URL (a probe marker or a credential may ride in it)
        logging.info(f"refused a request the browser sent past the guard's route to "
                     f"{host!r} ({kind}{'; Sec-Purpose: ' + purpose if purpose else ''}; "
                     f"BUG-0559)")
        with contextlib.suppress(OSError):
            client.sendall(_REFUSAL)

    def _tunnel(self, client, host: str, port: int, head: bytes,
                ticket: _TunnelTicket) -> None:
        """Tunnel a ``CONNECT`` ``ticket`` admitted (`_HeldTunnel`): a WebSocket's for its
        life, an https landing's for its one exchange."""
        upstream = self.server.upstream
        end = head.index(b"\r\n\r\n") + 4
        try:
            if upstream is not None:            # the capture proxy answers the CONNECT
                remote = socket.create_connection((upstream[0].strip("[]"), upstream[1]),
                                                  timeout=10)
                remote.sendall(head[:end])
            else:
                remote = socket.create_connection((host, port), timeout=10)
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError:
            with contextlib.suppress(OSError):
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                               b"Connection: close\r\n\r\n")
            return
        remote.settimeout(None)
        client.settimeout(None)
        held = _HeldTunnel(ticket, via_proxy=upstream is not None)
        back = threading.Thread(target=held.from_server, args=(remote, client),
                                daemon=True, name="navguard-enforcer-tunnel")
        back.start()
        held.from_client(client, remote, head[end:])
        back.join()
        remote.close()


class _EnforcerServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, upstream):
        self.upstream = upstream
        super().__init__(("127.0.0.1", 0), _EnforcerHandler)


def _enforcer_endpoint(upstream: tuple | None) -> str:
    """``127.0.0.1:PORT`` of this process's enforcer for ``upstream`` (None: tunnels go
    to their host; a capture proxy's ``(host, port)``: through it), started on first use
    and kept for the process's life (a daemon thread on a loopback listener)."""
    with _ENFORCE_LOCK:
        got = _ENFORCERS.get(upstream)
        if got is not None and got[0] == os.getpid():
            host, port = got[1].server_address[:2]
            return f"{host}:{port}"
        server = _EnforcerServer(upstream)
        host, port = server.server_address[:2]
        require_loopback(host, "the browser's enforcing proxy")
        threading.Thread(target=server.serve_forever, daemon=True,
                         name="navguard-enforcer").start()
        _ENFORCERS[upstream] = (os.getpid(), server)
        _ENFORCER_UPSTREAM[f"{host}:{port}"] = upstream
        return f"{host}:{port}"


def browser_launch_args(scope_urls, *, any_port_hosts=(), proxy: str | None = None) -> list[str]:
    """Chromium arguments for every launch we make (BUG-0123): Chromium's own traffic
    through the enforcer, nothing resolvable outside scope, and no background
    networking.

    **The enforcer** (BUG-0559 review round 2, BB-3): ``--proxy-server`` names this
    process's loopback enforcer, with loopback forced through it (``<-loopback>``; its
    own ``host:port`` added to the resolver rules, without which ``MAP * ~NOTFOUND``
    refuses the proxy itself, measured for CC-CRAWL-0031). The Playwright driver fetches
    every routed request and never uses this switch (measured), so what reaches the
    enforcer is only what Chromium sends past the route: a speculation-rules prefetch
    or prerender (no launch switch stops one, measured on both binaries), a favicon,
    background services, a WebSocket, the re-request of a redirect landing (which
    Playwright never routes). It refuses all of it (403, counted in
    `enforcer_refusals`, logged by host) but a WebSocket a guard's socket handler
    admitted (`admit_socket`, one tunnel carries it) and a landing the route checked and
    answered with a redirect to (`admit_landing`, forwarded once, never a preload;
    measured: without it a redirected navigation never loaded). An unrouted page
    therefore loads nothing. A tunnel is admitted by host and port, and read at the TLS
    record layer only, never decrypted (`_HeldTunnel`, BUG-0559 review round 3): an
    ``https`` landing's carries its one exchange and is closed at the browser's next
    request on it; a ticket admits a certificate error's retry. ``--disable-http2`` keeps
    Chromium's own traffic on HTTP/1.1 (one request at a time on a connection; routed
    requests are the driver's and never see it); what a WebSocket's tunnel carries is
    not seen.

    ``proxy`` (CC-CRAWL-0031, the disco capture layer): a loopback ``host:port``
    recorder. Pass the same ``proxy`` to `chromium_launch_kwargs`, which gives it to
    the Playwright driver: every routed request goes through it, recorded. Chromium's
    switch still names the enforcer, here one that tunnels an admitted WebSocket
    through the recorder (recorded too); nothing else Chromium sends gets there.

    ``--host-resolver-rules`` maps each scope ``host:port`` to itself and every other
    name to ``~NOTFOUND``. Chromium applies the rules to IP literals and matches them on
    ``host:port`` (default ports included), so ``203.0.113.9``, ``127.0.0.2`` or another
    port on ``127.0.0.1`` fail with ``ERR_NAME_NOT_RESOLVED`` (verified live). Behind
    the enforcer they confine what Chromium still resolves itself (the enforcer's own
    address; anything that would bypass it). They do **not** confine routed
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
    enforcer = _enforcer_endpoint(_proxy_endpoint(proxy) if proxy is not None else None)
    rules.append(f"MAP {enforcer} {enforcer}")
    proxy_args = [f"--proxy-server=http://{enforcer}", "--proxy-bypass-list=<-loopback>"]
    rules = list(dict.fromkeys(rules)) + ["MAP * ~NOTFOUND"]
    # HTTP/1.1 for what Chromium sends itself: an https landing's tunnel is held to one
    # exchange (`_HeldTunnel`), which a multiplexed HTTP/2 connection would not be
    # (measured: Chromium chose h2 inside the tunnel when the server offered it). Routed
    # requests are fetched by the Playwright driver and do not see this switch
    proxy_args.append("--disable-http2")
    return ["--no-sandbox", "--disable-dev-shm-usage", *proxy_args,
            f"--host-resolver-rules={', '.join(rules)}", "--disable-background-networking",
            "--disable-component-update", "--disable-sync", "--disable-domain-reliability",
            "--no-pings", "--dns-prefetch-disable", "--disable-features=NetworkPrediction",
            "--no-default-browser-check", "--metrics-recording-only"]


def chromium_launch_kwargs(args: list[str], *, headless: bool = True,
                           proxy: str | None = None) -> dict:
    """The keyword arguments of every Chromium launch we make (BUG-0126, PA-0003):
    ``args`` (from `browser_launch_args`), ``headless``, and the operator's configured
    binary (``PLAYWRIGHT_CHROMIUM_EXECUTABLE``) when set. One helper, so no launch site
    drifts from the others (the M6 executor ignored the binary and crashed a run).

    ``proxy`` (CC-CRAWL-0031): the loopback recorder `browser_launch_args` was given.
    It becomes Playwright's launch ``proxy`` (loopback not bypassed), which the driver
    honours for the requests the route guard fetches (measured: they reach the proxy
    with the launch option, carrying the route's headers). Playwright also passes it to
    Chromium as a switch, before ``args``; the later switch -- the enforcer chained to
    this recorder -- is the one Chromium uses (measured, BUG-0559 review round 2).
    ``args`` built for another proxy, or for none, are refused: the two layers never
    disagree."""
    named = [a.split("=", 1)[1].removeprefix("http://") for a in args
             if a.startswith("--proxy-server=")]
    chained = _ENFORCER_UPSTREAM.get(named[-1], ()) if named else None
    if proxy is not None:
        host, port = _proxy_endpoint(proxy)
        if chained != (host, port):
            raise ValueError("chromium_launch_kwargs: args were not built for this proxy "
                             "(browser_launch_args(..., proxy=...))")
    elif chained is not None:
        raise ValueError("chromium_launch_kwargs: args name a proxy; pass it as proxy=")
    kwargs = {"headless": headless, "args": list(args)}
    if proxy is not None:
        kwargs["proxy"] = {"server": f"http://{host}:{port}", "bypass": "<-loopback>"}
    exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
    if exe:
        kwargs["executable_path"] = exe
    return kwargs


def checked_api_request(in_scope: Callable[[str], bool], url: str, *,
                        session_cookies=None,
                        cookie_scope: Callable[[str], bool] | None = None) -> None:
    """Before a Playwright API-request call (``context.request.*``,
    ``pw.request.new_context().fetch``), which `route` never sees: refuse an
    out-of-scope URL. Callers pass ``max_redirects=0`` too. ``session_cookies`` (a request
    made with a session's cookies, SP-74): a host they do not reach -- on the session's
    origin by ``cookie_scope`` -- raises `SessionHostUnreached` before anything is
    sent, as the route refuses it."""
    if not in_scope(url):
        raise PermissionError(f"refusing an out-of-scope request to "
                              f"{urlsplit(url).hostname!r} (BUG-0123)")
    why = session_host_refusal(session_cookies, url, cookie_scope=cookie_scope)
    if why is not None:
        raise SessionHostUnreached(why)


#: Redirects a static fetch follows by hand (each hop checked first).
MAX_REDIRECTS = 5


def get_checked(session, url: str, timeout: float, may_follow: Callable[[str], bool]):
    """GET ``url`` with ``requests``, following redirects **by hand**: a hop is fetched
    only if ``may_follow(next_url)`` allows it (scope, and no destructive token). A
    refused hop is not followed; the redirect response itself is returned (BUG-0111).

    Every body is read bounded (SP-60, BUG-0536): a ``requests.Session`` given here is
    bounded first (`core.bodyread.bound`, idempotent), so a body over a ceiling or past
    its deadline raises `bodyread.BodyIncomplete` and is never returned short. Another
    object (a test's in-memory site) is used as given.
    """
    from fuzzlab.core import bodyread
    bodyread.bound(session)
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
