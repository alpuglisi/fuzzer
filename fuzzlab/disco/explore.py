"""The interaction engine: explore an application's UI as a state graph, through the
capture proxy, so every request the UI can trigger is recorded with its cause.

**The browser** is launched like every other in fuzzlab (SP-03/SP-04): its whole
configuration from `navguard.chromium_launch_kwargs`, its arguments from
`navguard.browser_launch_args` -- here with ``proxy=`` the recorder's loopback endpoint
-- and its context guarded by `navguard.guard_page` (scope, destructive URLs, the
abort code), navigated only through `navguard.navigate` / `navguard.wait_for_state`, and
released through `navguard.release`. The context ignores HTTPS errors (the recorder
re-signs TLS) and blocks service workers (a worker's requests bypass the route and its
cache would hide traffic). Before each action the route's header hook (the guard's
``headers=``, read per request: in-scope requests only, never
``set_extra_http_headers``, FR-CRAWL-14) carries ``x-disco-action: <id>``: a non-secret
correlation tag the proxy records and strips.

**States.** A state is `fingerprint.state_fingerprint` of the page: its route and the
signatures of its visible interactive elements, text excluded, delegated candidates
excluded (`fingerprint.counts_for_state`). Breadth first from the
start URL: for each state, each actionable element not yet tried there (keyed by the
state and the element's signature) is acted on once, the network is waited out
(`wait_quiet`: no request in flight for ``idle_ms``, at most ``max_ms``), and a new
fingerprint becomes a frontier state. A state is restored by navigating to its entry
URL and replaying the path of actions that led to it; a state whose replay no longer
reproduces it is dropped (counted).

**Actionable elements** are found across the page's composed tree (`compose`,
FR-CRAWL-39): its document, every open shadow root, and every visible same-origin,
in-scope frame, each element's ancestry naming the shadow hosts and frames it is in.
They are found four ways: accessibility roles and native controls; elements with a
JavaScript click / pointer / key listener, asked of Chrome DevTools (catches a
framework's ``div`` buttons); ``cursor: pointer`` as a fallback; and **delegated**
candidates -- a labelled, non-semantic element under an ancestor, document or window
listening for clicks -- each tried once and kept only when its click caused a request
(one a window with no click just before did not see) or changed the state
(FR-CRAWL-40). Closed shadow roots, cross-origin and out-of-scope
frames and every bound a read hit are counted in the report, never read. Enumeration
runs again after every action, so dialogs and lazy panels are seen as they appear.

**Forms** are submitted valid-first (`formfill`): each control gets the first candidate
its own ``checkValidity()`` accepts, then the submitter is clicked; then up to
``max_perturbations`` submissions, each with one control perturbed.

**Safety rails** (never lifted by this module): an element whose label, name or link is
destructive (`core.urls.text_destructive_reason`, `destructive_reason`: logout, delete
account, reset, ...) or one the operator denies (``deny``) is never acted on; a form
that changes a credential (`store_adapter.credential_change_rule`) is never submitted
(a CAPTCHA form is: its CAPTCHA control gets a filler answer, D71); the route guard aborts destructive and out-of-scope requests whatever
the page does. In an authenticated run, landing on a login URL (`session.detect.
looks_like_login_url`) marks the session lost: the action that caused it is denied for
the rest of the run and the context is rebuilt from the storage state.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from fuzzlab.core.redaction import redact_url
from fuzzlab.core.urls import (destructive_reason, in_origin_scope, origin_scope,
                               spa_route, text_destructive_reason)
from fuzzlab.disco import compose, formfill
from fuzzlab.disco.capture import ACTION_HEADER
from fuzzlab.disco.fingerprint import (element_signature, normalise_route, state_fingerprint,
                                       state_signatures)
# the one script-route scanner both crawlers share (SP-47; D70's allowlist)
from fuzzlab.tools.spa import (ROUTE_OK, classify_route, query_url_refusal, route_url,
                               scan_script, seed_url, spa_fragment)
from fuzzlab.session.detect import looks_like_login_url
from fuzzlab.tools import navguard
from fuzzlab.tools.netquiet import Inflight

def _pw_error():
    """Playwright's error class (its timeouts subclass it): the one external failure an
    action, a navigation or a DevTools query maps to "not done" (PA-0106, PA-0137). Any
    other exception is a defect and propagates. Resolved lazily: importing this module
    needs no browser extra."""
    from playwright.sync_api import Error
    return Error


#: The enumeration's page scripts and bounds live in `compose` (FR-CRAWL-39): the
#: composed read (`compose.READ_JS`) and a submitter's form controls, marked
#: ``data-disco-field`` across the document's open shadow roots.
_FIELDS_JS = compose.FIELDS_JS


#: A control's verdict on its value: ``valid``; ``aria-invalid`` when the browser accepts
#: it but the page's own script marks it invalid (WAI-ARIA ``aria-invalid="true"``: a
#: framework validator the browser cannot see -- measured on Juice Shop, where such a
#: field kept the submit button disabled while ``checkValidity()`` passed); ``invalid``.
#: The control is blurred first: a framework shows its error state only once a control
#: is touched (measured: the same field read "false" while focused).
_VALID_JS = """(e) => { e.blur(); return !e.checkValidity() ? 'invalid'
  : (e.getAttribute('aria-invalid') === 'true' ? 'aria-invalid' : 'valid'); }"""

#: Response media whose body the harvest reads for links (an HTML document is read
#: from the rendered page instead).
_BODY_MEDIA = frozenset({"text/css", "application/javascript", "text/javascript",
                         "text/plain", "application/xml", "text/xml"})


@dataclass
class Step:
    """One replayable action: the element (its signature and which occurrence of that
    signature, in document order) and what was done with it."""
    signature: str
    kind: str                       # "click" | "submit" | "enter" | "perturb:<field>:<kind>"
    occurrence: int = 0

    def key(self) -> tuple[str, int, str]:
        return (self.signature, self.occurrence, self.kind)


@dataclass
class State:
    """A state and how to get back to it: ``entry_url`` then ``path``; when that no
    longer reproduces it (a page only a POST shows), ``fallback`` is tried.

    ``core`` is the state's *stable* element signatures (`fingerprint.state_signatures`:
    never a delegated candidate's). It starts as everything first seen; any restore
    that shows the same route with elements only gone, none new, narrows it to what is
    left: one-time or consumed UI -- a first-visit dialog, a
    cookie notice dismissed by an earlier action, a toast -- does not come back
    (measured on Juice Shop: its welcome dialog, then its dismissed cookie banner, each
    made the start page unrestorable). A restore succeeds when the route matches and
    every core element is present: what restoring is for is getting the pending
    actions' elements back."""
    fp: str
    url: str
    entry_url: str
    path: list[Step] = field(default_factory=list)
    fallback: "State | None" = None
    core: frozenset = frozenset()


class Frontier:
    """The states still to explore: a state on a route no known state is on goes before
    another state of a known route, and a route holds at most ``per_route`` states.
    Breadth first alone spent a whole budget on one page's overlays -- toasts, menus,
    tooltips, pagers -- and never explored the routes its side-nav opened (BUG-0501,
    measured on Juice Shop: 121 of 143 actions on its start page)."""

    def __init__(self, per_route: int):
        self.per_route = per_route
        self.new_routes: deque[State] = deque()
        self.overlays: deque[State] = deque()
        self.per: dict[str, int] = {}

    def push(self, state: State) -> bool:
        """Queue ``state``; False when its route is already full."""
        route = normalise_route(state.url)
        n = self.per.get(route, 0)
        if n >= self.per_route:
            return False
        self.per[route] = n + 1
        (self.new_routes if n == 0 else self.overlays).append(state)
        return True

    def pop(self) -> State:
        return self.new_routes.popleft() if self.new_routes else self.overlays.popleft()

    def __bool__(self) -> bool:
        return bool(self.new_routes or self.overlays)


@dataclass
class ExploreOptions:
    max_states: int = 60
    max_actions: int = 400
    deadline_s: float = 900.0
    idle_ms: int = 500
    max_quiet_ms: int = 8000
    nav_timeout_ms: int = 15000
    max_perturbations: int = 6
    max_same_signature: int = 2
    max_states_per_route: int = 8
    deny: tuple[str, ...] = ()
    headless: bool = True
    #: Browsers exploring frontier states at once (`Explorer.run`); 1 is sequential.
    workers: int = 1
    #: Loads of linked, never-requested in-scope URLs once the frontier is empty (the
    #: harvest, `Explorer._load`); their documents become states outside `max_states`.
    max_harvest: int = 500


#: The most workers a run may ask for (each is a browser).
#: FR-CRAWL-28: at most this many script path segments are kept per run.
MAX_SCRIPT_SEGMENTS = 20000
MAX_WORKERS = 8


@dataclass
class ExploreReport:
    states: int = 0
    actions: int = 0
    submissions: int = 0
    perturbations: int = 0
    refused: dict[str, int] = field(default_factory=dict)
    unrestorable: int = 0
    transient_dropped: int = 0
    route_capped: int = 0
    #: submit / Enter / perturbation steps whose filled values reached a request: what
    #: proves a submission happened (a "submit" step whose click did nothing is not one)
    submissions_sent: int = 0
    chrome_skipped: int = 0
    captcha_submissions: int = 0              # of `submissions_sent`, with a CAPTCHA
    #: the harvest: URLs found linked and never requested, loads made, states they gave
    harvest_found: int = 0
    harvest_loads: int = 0
    harvest_states: int = 0
    #: harvest loads answered with a document already known under another path (an
    #: app's catch-all shell, a soft 404): never explored again (BUG-0505)
    harvest_aliases: int = 0
    #: routes and route-query seeds read from the app's own scripts (FR-CRAWL-27; FR-CRAWL-12/17's
    #: scanners, `tools.spa.scan_script`), queued for the harvest
    script_routes: int = 0
    script_route_seeds: int = 0
    #: script bodies over `tools.spa.MAX_SCRIPT_BYTES`: not scanned for routes
    scripts_too_large: int = 0
    errors: int = 0
    session_lost: int = 0
    aborted: int = 0
    out_of_scope: dict[str, int] = field(default_factory=dict)
    budget_hit: str | None = None
    #: FR-CRAWL-39 (BUG-0551), per route, a page read again adds nothing
    #: (`compose.Coverage`): open shadow roots and same-origin frames read; what was
    #: not read, counted and never claimed -- closed shadow roots, cross-origin and
    #: out-of-scope frames, and what each bound of a read left out (`budget_limited`:
    #: ``elements``, ``candidates``, ``delegated``, ``nodes``, ``frames``, ``census``)
    shadow_roots: int = 0
    frames: int = 0
    closed_shadow_roots: int = 0
    frames_cross_origin: int = 0
    frames_out_of_scope: int = 0
    budget_limited: dict[str, int] = field(default_factory=dict)
    #: FR-CRAWL-40: delegated candidates tried, kept (their click made a request or
    #: changed the state), dropped, and never tried once the run's trials were spent
    delegated_trials: int = 0
    delegated_live: int = 0
    delegated_inert: int = 0
    delegated_unexplored: int = 0

    def refuse(self, why: str) -> None:
        self.refused[why] = self.refused.get(why, 0) + 1


class _Shared:
    """What every worker of one run shares, behind one lock (`Explorer.run`): the
    frontier and the states known, the steps seen and done, which routes each signature
    was seen on (chrome), the perturbed forms and denied steps, the action-id counter
    and the report. A worker holds its own browser, context, page, network-quiet
    tracking and action tag; nothing of those is shared."""

    def __init__(self, opts: ExploreOptions, report: ExploreReport):
        self.lock = threading.Condition(threading.RLock())
        self.frontier = Frontier(opts.max_states_per_route)
        self.known: set[str] = set()
        self.seen: set[tuple] = set()
        self.done: set[tuple] = set()
        self.sig_routes: dict[str, set[str]] = {}
        self.perturbed: set[tuple] = set()
        self.denied: set[tuple] = set()
        self.report = report
        self.seq = 0
        self.busy = 0             # workers holding a state (or seeding the root)
        self.stop: str | None = None
        self.started = 0.0
        self.failure: BaseException | None = None
        #: in-scope URLs some worker's browser requested, and the harvest queue: URLs a
        #: page or response links that nothing requested yet (`Explorer._gather`)
        self.requested: set[str] = set()
        self.harvest: dict[str, None] = {}
        #: routes and route-query seeds the app's scripts declare: loaded before any
        #: other harvest URL (the app's own navigable surface, not a linked asset)
        self.harvest_routes: dict[str, None] = {}
        self.bodies_read: set[str] = set()
        #: sha256 of each HTML document body loaded -> the path it was first loaded at:
        #: the same body under another path is an alias, never a new state (BUG-0505)
        self.documents: dict[str, str] = {}
        #: the path segments the app's scripts hold (`core.pathtemplate.code_segments`,
        #: FR-CRAWL-28), written to ``script_segments.json`` beside the action log
        self.code_segments: set[str] = set()
        #: delegated candidates' verdicts and the composed reads' coverage (FR-CRAWL-39/40)
        self.trials = compose.Trials(compose.MAX_DELEGATED_TRIALS)
        self.coverage = compose.Coverage()
        #: per route, the `request_key`s no longer evidence for a delegated trial: what a
        #: control window saw (the page's own traffic) and what a trial already counted
        #: (`Explorer._trial`)
        self.explained: dict[str, set[tuple[str, str]]] = {}
        #: the page shapes whose closed shadow roots were counted (`compose._census`)
        self.censused: set = set()


def request_key(method: str, url: str) -> tuple[str, str]:
    """What a delegated trial compares requests by: the method and the normalised route
    (`normalise_route`: digit runs folded, query values dropped), so a poll's next
    request is the same key as its last."""
    return (str(method or "").upper(), normalise_route(url))


def refusal(el: dict, deny: tuple[str, ...]) -> str | None:
    """Why an element is never acted on (the denylist), or None."""
    texts = [el.get("label"), el.get("name"), el.get("id")]
    for text in texts:
        reason = text_destructive_reason(text)
        if reason:
            return f"destructive:{reason}"
        low = str(text or "").lower()
        if any(d and d.lower() in low for d in deny):
            return "denied"
    for url in (el.get("href"), el.get("action")):
        if url and destructive_reason(url):
            return "destructive-url"
    return None


#: Input types that are clicked on their own (the rest are filled through their form).
CLICKED_INPUTS = frozenset({"checkbox", "radio", "submit", "button", "image", "reset"})


def is_fill_only(el: dict) -> bool:
    """A text-like control: filled when its form is submitted, never clicked alone."""
    tag = el.get("tag")
    return tag in ("select", "textarea") or (tag == "input" and
                                              el.get("type") not in CLICKED_INPUTS)


def is_submitter(el: dict) -> bool:
    return bool(el.get("in_form")) and el.get("tag") in ("button", "input") and \
        el.get("type") in ("submit", "image", "")


#: Input types Enter is pressed in (`enter_submits`).
ENTER_TYPES = frozenset({"text", "search", "email", "url", "tel", "number", ""})


def enter_submits(el: dict) -> bool:
    """Whether the explorer fills ``el``'s container and presses Enter in it: a text
    input, the last typed control of a container with no submit control, or the only
    one of a form-less container (a search box among a toolbar's buttons). A form that
    has its own submit control is submitted by clicking it instead."""
    if el.get("tag") != "input" or el.get("type") not in ENTER_TYPES or el.get("disabled"):
        return False
    if not el.get("last_typed"):
        return False
    return not el.get("submitters") or (not el.get("form_tag") and el.get("typed") == 1)


def is_distinctive(value: str) -> bool:
    """A filled value specific enough that finding it in a request means the form's
    data was sent (``1`` or ``test`` could be anywhere)."""
    return len(value) >= 5 and not value.isdigit()


def carries_value(req, values: list[str]) -> bool:
    """Whether a browser request carries one of ``values`` in its URL or body."""
    from urllib.parse import unquote_plus
    try:
        text = unquote_plus(req.url) + "\n" + (req.post_data or "")
    except (UnicodeDecodeError, ValueError):     # a binary body: the URL alone
        text = unquote_plus(req.url)
    return any(v in text for v in values)


def has_captcha(fields: list[dict]) -> bool:
    """Whether a form carries a CAPTCHA control (reported only: D71 fills it like any
    other control, with a filler answer; no CAPTCHA is solved)."""
    names = " ".join(str(f.get(k) or "") for f in fields for k in ("name", "id", "label"))
    return any(t in names.lower() for t in ("captcha", "turnstile"))


def form_refusal(fields: list[dict], submitter: dict) -> str | None:
    """Why a form is never submitted: it changes a credential. A CAPTCHA form is
    submitted like any other (D71)."""
    from fuzzlab.tools.store_adapter import credential_change_rule
    passwords = [f.get("name") or f.get("id") or "password" for f in fields
                 if f.get("type") == "password"]
    hidden = [f.get("name") for f in fields if f.get("type") == "hidden" and f.get("name")]
    reason = credential_change_rule(passwords, submitter.get("action") or "",
                                    submitters=[submitter.get("label") or "",
                                                submitter.get("name") or ""],
                                    hidden=hidden)
    return "credential-change" if reason else None


class Explorer:
    """One exploration. ``run()`` launches the browser, explores, and returns the
    report; ``actions_log`` (a path) receives one JSON line per action taken."""

    def __init__(self, start_url: str, *, scope_urls: list[str], proxy: str,
                 options: ExploreOptions | None = None, storage_state: dict | None = None,
                 actions_log: Path | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.start_url = start_url
        self.scope_urls = list(scope_urls)
        self.origins = origin_scope(*self.scope_urls)
        if not in_origin_scope(start_url, self.origins):
            raise ValueError("the start URL is outside the scope")
        self.proxy = proxy
        self.opts = options or ExploreOptions()
        self.storage_state = storage_state
        self.actions_log = actions_log
        self.clock = clock
        if not 1 <= self.opts.workers <= MAX_WORKERS:
            raise ValueError(f"workers must be 1..{MAX_WORKERS}")
        self.report = ExploreReport()
        self._shared = _Shared(self.opts, self.report)
        self._worker_state()

    def _worker_state(self) -> None:
        """This worker's own state (the rest is `_shared`)."""
        self._last_fields: list[dict] = []        # the fields of the last form filled
        self._fill_values: list[str] = []         # the distinctive values just filled
        self._values_sent = False                 # whether a request carried one
        self._action_seq = 0                      # the number of this worker's last tag
        # requests in flight, minus long-lived ones (SP-40); quiet is measured from
        # the later of its last change and the last action (`mark_activity`)
        self._net = Inflight(clock=self.clock)
        self._last_change = 0.0
        self._ctx = None
        self._tag_headers: dict[str, str] = {}      # the guard reads it per request
        self._responses: list = []                # in-scope responses since `_gather`

    def _clone(self) -> "Explorer":
        """Another worker of this run: the same configuration and `_shared` state."""
        other = object.__new__(Explorer)
        other.__dict__.update({k: v for k, v in self.__dict__.items()})
        other._worker_state()
        return other

    def _bump(self, counter: str, n: int = 1) -> None:
        with self._shared.lock:
            setattr(self.report, counter, getattr(self.report, counter) + n)

    # --- browser lifecycle -------------------------------------------------------
    def _in_scope(self, url: str) -> bool:
        return in_origin_scope(url, self.origins)

    def _new_context(self, browser, pw):
        state = None
        if self.storage_state is not None:
            from fuzzlab.session.browserlogin import filter_storage_state
            state = filter_storage_state(self.storage_state, self._in_scope, self.scope_urls)
        ctx = browser.new_context(service_workers="block", ignore_https_errors=True,
                                  storage_state=state)
        session_origins = origin_scope(self.start_url)
        authenticated = state is not None and len(self.origins) > 1
        navguard.guard_page(
            ctx, in_scope=self._in_scope, headers=self._tag_headers,
            on_out_of_scope=self._count_out_of_scope,
            on_abort=lambda url, why: self._count_abort(),
            cookie_scope=(lambda u: in_origin_scope(u, session_origins))
            if authenticated else None,
            isolated_request=(lambda: pw.request.new_context()) if authenticated else None)
        ctx.on("request", self._on_request)
        ctx.on("response", self._on_response)
        ctx.on("requestfinished", self._on_done)
        ctx.on("requestfailed", self._on_done)
        return ctx

    def _count_out_of_scope(self, url: str) -> None:
        from urllib.parse import urlsplit
        host = urlsplit(url).hostname or "?"
        with self._shared.lock:
            self.report.out_of_scope[host] = self.report.out_of_scope.get(host, 0) + 1

    def _count_abort(self) -> None:
        self._bump("aborted")

    def _refuse(self, why: str) -> None:
        with self._shared.lock:
            self.report.refuse(why)

    def _on_request(self, req) -> None:
        self._net.started(req)
        if self._in_scope(req.url):
            self._shared.requested.add(urldefrag(req.url)[0])
        if self._fill_values and not self._values_sent:
            self._values_sent = carries_value(req, self._fill_values)

    def _on_response(self, resp) -> None:
        if self._in_scope(resp.url):
            self._responses.append(resp)          # read later, never in the handler

    def _gather(self, page) -> None:
        """Queue for the harvest what the page and its responses since the last call
        link (`core.linkextract`): the rendered document's URLs, every response's
        header targets, and a stylesheet's, script's, robots.txt's or sitemap's own --
        in scope, not destructive, never requested."""
        from fuzzlab.core.linkextract import header_urls, html_urls, response_urls
        shared = self._shared
        found: list[str] = []
        try:
            found += html_urls(page.content(), page.url)
        except _pw_error():  # the page moved on under the read
            pass
        responses, self._responses = self._responses, []
        routes: list[str] = []
        for resp in responses:
            try:
                headers = resp.headers or {}
                found += header_urls(headers, resp.url)
                media = (headers.get("content-type") or "").split(";", 1)[0].strip()
                if media in _BODY_MEDIA and resp.url not in shared.bodies_read:
                    shared.bodies_read.add(resp.url)
                    text = resp.text()
                    found += response_urls(resp.url, media, text, {})
                    if "javascript" in media:          # its declared routes (FR-CRAWL-12)
                        routes += self._script_routes(text, page)
                        self._note_code_segments(text)
            except (_pw_error(), UnicodeDecodeError):  # a body the driver let go
                continue
        with shared.lock:
            for queue, urls in ((shared.harvest_routes, routes), (shared.harvest, found)):
                for url in urls:
                    if url in shared.requested or url in shared.harvest or \
                            url in shared.harvest_routes:
                        continue
                    if not self._in_scope(url) or destructive_reason(url):
                        continue
                    queue[url] = None
                    self.report.harvest_found += 1

    def _on_done(self, req) -> None:
        self._net.ended(req)

    def mark_activity(self) -> None:
        """An action (a click, a navigation) is activity itself: its requests reach the
        ``request`` event only after the handler runs (a debounce, a timer, a promise),
        so quiet is measured from the action, never from the last request before it
        (measured: a 120 ms click-to-fetch delay otherwise read every state before its
        render and lost the dialog's whole subtree)."""
        self._last_change = self.clock()

    def wait_quiet(self, page) -> bool:
        """Network quiescence: no request in flight for ``idle_ms`` since the last
        request or action (`mark_activity`), polled, at most ``max_quiet_ms``. Whether
        it was reached."""
        end = self.clock() + self.opts.max_quiet_ms / 1000
        idle = self.opts.idle_ms / 1000
        while self.clock() < end:
            last = max(self._last_change, self._net.last_change)
            if self._net.n == 0 and self.clock() - last >= idle:
                return True
            page.wait_for_timeout(50)
        return False

    def _tag(self, ctx, prefix: str) -> str:
        """Name the next action: every routed request from now on carries its id."""
        with self._shared.lock:
            self._shared.seq += 1
            self._action_seq = self._shared.seq
        action_id = f"{prefix}-{self._action_seq}"
        self._tag_headers[ACTION_HEADER] = action_id
        return action_id

    # --- page reading ----------------------------------------------------------------
    def enumerate(self, page, ctx) -> list[dict]:
        """The page's actionable elements across its composed tree (`compose.read_page`,
        FR-CRAWL-39), each marked ``data-disco-id`` in its own document and carrying
        ``frame`` (the frame-marker keys `_locate` follows). A delegated candidate
        already found inert, or never tried once the run's trials are spent, is
        described ``disabled``: kept, so the read stays a function of the page, never
        acted on (FR-CRAWL-40). What the read could not reach is counted in the report."""
        read = compose.read_page(page, ctx, self._in_scope,
                                 max_delegated=compose.MAX_DELEGATED,
                                 censused=self._shared.censused)
        els = read.elements
        counts: dict[str, int] = {}
        for el in els:
            el["signature"] = element_signature(el)
            el["occurrence"] = counts.get(el["signature"], 0)
            counts[el["signature"]] = el["occurrence"] + 1
        self._mark_delegated(els)
        self._note_coverage(page.url, read)
        return els

    @staticmethod
    def _find(els: list[dict], step: Step) -> dict | None:
        return next((e for e in els if e["signature"] == step.signature
                     and e["occurrence"] == step.occurrence), None)

    def _mark_delegated(self, els: list[dict]) -> None:
        """Describe ``disabled`` each delegated candidate the run will not act on: found
        inert, or still untried once `compose.Trials` is spent (counted unexplored)."""
        shared = self._shared
        with shared.lock:
            trials = shared.trials
            for el in els:
                if el.get("how") != "delegated":
                    continue
                verdict = trials.verdict(el["signature"])
                if verdict == "inert":
                    el["disabled"] = True
                elif verdict is None and trials.spent():
                    el["disabled"] = True
                    trials.unexplored.add(el["signature"])
            self.report.delegated_unexplored = len(trials.unexplored)

    def _note_coverage(self, url: str, read: compose.PageRead) -> None:
        """Add a read's notes to the report, live (`compose.Coverage`: per route, a page
        read again adds nothing)."""
        with self._shared.lock:
            for kind, n in self._shared.coverage.add(normalise_route(url), read).items():
                if kind.startswith("budget."):
                    bound = kind.split(".", 1)[1]
                    self.report.budget_limited[bound] = \
                        self.report.budget_limited.get(bound, 0) + n
                else:
                    setattr(self.report, kind, getattr(self.report, kind) + n)

    def fingerprint(self, page, ctx) -> tuple[str, list[dict]]:
        els = self.enumerate(page, ctx)
        return state_fingerprint(page.url, els), els

    def settled_fingerprint(self, page, ctx) -> tuple[str, list[dict]] | None:
        """`fingerprint` of a page that may still be navigating: a destroyed execution
        context (the page moved on mid-read) is waited out once; None if it persists."""
        for _ in range(2):
            try:
                return self.fingerprint(page, ctx)
            except _pw_error():
                self.wait_quiet(page)
        return None

    # --- acting ----------------------------------------------------------------------
    @staticmethod
    def _scope(page, el: dict):
        """What locates ``el`` and its form's controls: the page, or the frame locators
        down to its frame (`compose.frame_scope`). A selector pierces open shadow roots
        by itself."""
        return compose.frame_scope(page, el.get("frame"))

    def _locate(self, page, el: dict):
        return self._scope(page, el).locator(f'[data-disco-id="{el["disco_id"]}"]').first

    def _fill(self, page, loc, perturb: tuple[str, str] | None) -> list[dict] | None:
        """Fill the submitter's form valid-first; ``perturb`` = (field, kind) replaces
        one control's value. Returns the field descriptions, or None when refused.
        ``page`` locates the controls: the page, or the submitter's frame (`_scope`)."""
        fields = loc.evaluate(_FIELDS_JS)
        for f in fields:
            target = page.locator(f'[data-disco-field="{f["field"]}"]').first
            if formfill.skip_reason(f):
                continue
            try:
                if f["tag"] == "select":
                    value = formfill.choose_option(f)
                    if perturb and perturb[0] == f["field"]:
                        value = dict(formfill.perturbations(f, value)).get(perturb[1], value)
                    if value is not None:
                        target.select_option(value, timeout=2000)
                    continue
                if f["type"] in ("checkbox", "radio"):
                    if f.get("required") or f["type"] == "checkbox":
                        target.check(timeout=2000)
                    continue
                chosen = native = None
                for cand in formfill.candidates(f):
                    target.fill(cand, timeout=2000)
                    verdict = target.evaluate(_VALID_JS)
                    if verdict == "valid":
                        chosen = cand
                        break
                    if verdict == "aria-invalid" and native is None:
                        native = cand
                if chosen is None and native is not None:
                    # no candidate satisfied the script's validator: the first the
                    # browser accepted is still the best value to leave
                    target.fill(native, timeout=2000)
                    chosen = native
                if perturb and perturb[0] == f["field"]:
                    value = dict(formfill.perturbations(f, chosen)).get(perturb[1])
                    if value is not None:
                        target.fill(value, timeout=2000)
                        chosen = value
                if chosen and is_distinctive(chosen):
                    self._fill_values.append(chosen)
            except _pw_error() as exc:  # a control that will not take input
                logging.info("disco: a form control refused input (%s)", type(exc).__name__)
        return fields

    def act(self, page, ctx, el: dict, step: Step) -> bool:
        """Perform one step on ``el``. Whether it was performed."""
        if el.get("how") == "delegated":
            return self._act_delegated(page, ctx, el, step)
        loc = self._locate(page, el)
        prefix = "nav" if el.get("href") else "act"
        if step.kind != "click":
            perturb = None
            if step.kind.startswith("perturb:"):
                _, fid, kind = step.kind.split(":", 2)
                perturb = (fid, kind)
            self._fill_values, self._values_sent = [], False
            fields = self._fill(self._scope(page, el), loc, perturb)
            self._last_fields = fields or []
            # a form-less container has no action: the page's URL stands for it
            reason = form_refusal(self._last_fields,
                                  dict(el, action=el.get("action") or page.url))
            if reason:
                self._refuse(reason)
                self._fill_values = []
                return False
        if step.kind == "enter":
            self._tag(ctx, prefix)
            loc.press("Enter", timeout=3000)
            self.mark_activity()
            return True
        return self._click(ctx, loc, prefix)

    def _click(self, ctx, loc, prefix: str) -> bool:
        """Tag the next action and click ``loc``. Whether it was clicked."""
        self._tag(ctx, prefix)
        try:
            loc.click(timeout=3000)
        except _pw_error():  # covered or detached: one dispatched click
            try:
                loc.dispatch_event("click", timeout=2000)
            except _pw_error():  # not actionable at all
                return False
        self.mark_activity()
        return True

    def _act_delegated(self, page, ctx, el: dict, step: Step) -> bool:
        """A delegated candidate (FR-CRAWL-40): clicked when already found live; tried
        once when untried (`_trial`), and kept -- performed -- only when the click made
        a request or changed the state; never acted on once inert, while another worker
        tries it, or once the run's trials are spent (`compose.Trials`)."""
        sig = el["signature"]
        with self._shared.lock:
            claim = self._shared.trials.claim(sig)
            self.report.delegated_unexplored = len(self._shared.trials.unexplored)
        if claim == "live":
            return self._click(ctx, self._locate(page, el), "act")
        if claim != "trial":
            return False
        live = None
        try:
            live = self._trial(page, ctx, step)
        finally:
            with self._shared.lock:
                if live is None:                  # nothing was clicked
                    self._shared.trials.release(sig)
                else:
                    self._shared.trials.decide(sig, live)
                    self.report.delegated_trials += 1
                    if live:
                        self.report.delegated_live += 1
                    else:
                        self.report.delegated_inert += 1
        return bool(live)

    def _trial(self, page, ctx, step: Step) -> bool | None:
        """Click a delegated candidate and observe whether the click caused a request,
        the page's URL changed, a page opened, or the state's fingerprint changed; None
        when the candidate was gone before its click. The fingerprints are the
        explorer's own (`settled_fingerprint`), before and after, so "changed the state"
        means what it means everywhere else in the run.

        A request counts only when the click caused it (BUG-0551 review B3): a
        notification poll, a beacon or a keep-alive reaches ``request`` whatever was
        clicked. Just before the click, a **control window** leaves the page alone for
        as long as the trial will wait (the same quiet rule, `wait_quiet`, from an
        action mark). A request is evidence only when its `request_key` is not yet
        explained on this route (`_Shared.explained`): neither this or an earlier
        control window there saw it (the page's own traffic), nor did an earlier
        trial there already count it. Background traffic slower than a control window
        is therefore counted for at most one candidate per route (measured, BUG-0551
        review B3)."""
        seen: set[tuple[str, str]] = set()

        def on_request(req) -> None:
            seen.add(request_key(req.method, req.url))

        page.on("request", on_request)
        try:
            self.mark_activity()                   # the control window: nothing clicked,
            self.wait_quiet(page)                  # then the read the click acts on
            before = self.settled_fingerprint(page, ctx)
            target = self._find(before[1], step) if before else None
            if target is None:
                return None
            url, pages = page.url, len(ctx.pages)
            control = set(seen)
            seen.clear()
            if not self._click(ctx, self._locate(page, target), "act"):
                return False                       # not actionable: it does nothing
            self.wait_quiet(page)
            after = self.settled_fingerprint(page, ctx)
        finally:
            page.remove_listener("request", on_request)
        with self._shared.lock:
            explained = self._shared.explained.setdefault(normalise_route(url), set())
            explained |= control
            caused = seen - explained
            explained |= caused
        return bool(caused) or page.url != url or len(ctx.pages) != pages \
            or after is None or after[0] != before[0]

    def _close_popups(self, ctx, page) -> None:
        # frozen and drained through the guard first (BUG-0504, `navguard.close_pages`)
        navguard.close_pages(ctx, [other for other in list(ctx.pages) if other is not page])

    def restore(self, page, ctx, state: State) -> bool:
        """Bring ``page`` back to ``state``: a fresh document of its entry URL, then its
        path replayed. The page leaves for ``about:blank`` first: on a hash-routed app,
        navigating to ``/#/`` from ``/#/x`` is a same-document change, and the previous
        action's UI would survive the "restore" (measured on Juice Shop)."""
        self._tag(ctx, "restore")
        try:
            navguard.navigate(page, "about:blank", timeout_ms=self.opts.nav_timeout_ms)
            navguard.navigate(page, state.entry_url, timeout_ms=self.opts.nav_timeout_ms,
                              wait_until="load")
        except _pw_error():  # a refused or failed navigation: not restorable
            return False
        self.mark_activity()
        self.wait_quiet(page)
        try:
            for step in state.path:
                el = self._find(self.enumerate(page, ctx), step)
                if el is None:
                    # consumed UI (a notice dismissed for good): its effect persists;
                    # the reproduction check below decides whether that sufficed
                    continue
                if not self.act(page, ctx, el, step):
                    return False
                self.wait_quiet(page)
                self._close_popups(ctx, page)
        except _pw_error():                 # the replay's page went away under it
            return False
        got = self.settled_fingerprint(page, ctx)
        if got is not None and not self.reproduces(state, page.url, got):
            self.wait_quiet(page)                     # a render that lags its response
            got = self.settled_fingerprint(page, ctx)
        return got is not None and self.reproduces(state, page.url, got, settle=True)

    def reproduces(self, state: State, url: str, got, *, settle: bool = False) -> bool:
        """Does the page (``url``, its fingerprint and elements) reproduce ``state``?
        See `State`: the same fingerprint; or the same route with every core element
        present; or the same route with core elements only gone, none new -- then
        (``settle``) the core narrows to what is left."""
        fp, els = got
        if fp == state.fp:
            return True
        if normalise_route(url) != normalise_route(state.url):
            return False
        sigs = state_signatures(els)
        if state.core and state.core <= sigs:
            return True
        if sigs and sigs < state.core:
            if settle:
                state.core = sigs
                self._bump("transient_dropped")
            return True
        return False

    def _log_action(self, action_id_seq: int, state: State, el: dict, step: Step,
                    new_fp: str | None, url: str | None = None) -> None:
        """One ``actions.jsonl`` line; ``seq`` is the action id's number (``act-<seq>``
        on its captured requests). ``url`` is the page's URL after the action, redacted
        (`redact_url`): a hash route's query lives only there, never in the capture.
        A form step lists its controls' names and types, never values: which fields a
        user could see (`store_adapter.import_disco` reads both)."""
        if self.actions_log is None:
            return
        # ``action_id``: the id its requests carry (``act-``, ``nav-``), BUG-0512
        rec = {"seq": action_id_seq, "action_id": self._tag_headers.get(ACTION_HEADER),
               "state": state.fp, "route": normalise_route(state.url),
               "signature": el["signature"], "occurrence": step.occurrence,
               "kind": step.kind,
               "label": str(el.get("label") or "")[:60], "new_state": new_fp,
               "url": redact_url(url) if url else None}
        if step.kind != "click":
            rec["fields"] = [[f.get("name") or f.get("id") or "", f.get("type") or f.get("tag")]
                             for f in self._last_fields if f.get("name") or f.get("id")]
        with self._shared.lock, open(self.actions_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def _log_load(self, url: str) -> None:
        """One ``actions.jsonl`` line for a harvest load of a route URL (``kind``
        ``load``): its query names reach the importer only from here, as an action's
        page URL does (`store_adapter.import_disco` reads every line's ``url``). Every
        key an action line has is present, empty: a load acts on no element."""
        if self.actions_log is None:
            return
        rec = {"seq": self._action_seq, "action_id": self._tag_headers.get(ACTION_HEADER),
               "state": None, "route": normalise_route(url),
               "signature": None, "occurrence": 0, "kind": "load", "label": "",
               "new_state": None, "url": redact_url(url)}
        with self._shared.lock, open(self.actions_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    # --- the loop ----------------------------------------------------------------------
    def _explored_states(self) -> int:
        """States counted against ``max_states``: the harvest's documents are not."""
        return len(self._shared.known) - self.report.harvest_states

    def _budget(self) -> str | None:
        """The budget that ends the whole run (the deadline), or None. ``max_states``
        and ``max_actions`` end exploration only (`_note_budget`): what is already
        queued, and the harvest within ``max_harvest``, still run."""
        if self.clock() - self._shared.started > self.opts.deadline_s:
            return "deadline"
        return None

    def _actions_spent(self) -> bool:
        return self.report.actions >= self.opts.max_actions

    def _note_budget(self, hit: str) -> None:
        """Record the first budget hit (the caller holds the lock)."""
        if self.report.budget_hit is None:
            self.report.budget_hit = hit

    def _steps_for(self, page, el: dict, route: str) -> list[Step]:
        occ = el["occurrence"]
        if occ >= self.opts.max_same_signature:
            return []                     # a long list of one shape: its first few only
        if enter_submits(el):
            return [Step(el["signature"], "enter", occ)]
        if is_fill_only(el):
            return []
        if el.get("disabled") and not is_submitter(el):
            return []
        if not is_submitter(el):
            return [Step(el["signature"], "click", occ)]
        steps = [Step(el["signature"], "submit", occ)]
        if not el.get("form_tag") and el.get("typed") == 1:
            return steps       # a search box among buttons: its Enter step covers it
        try:
            fields = self._locate(page, el).evaluate(_FIELDS_JS)
        except _pw_error():  # the form went away
            return steps
        # one perturbation pass per form, not per button: a toolbar's buttons share the
        # container of its search box, and each re-perturbed it (BUG-0502)
        form_key = (route, tuple((f["tag"], f["type"], f["name"], f["id"]) for f in fields))
        with self._shared.lock:
            if form_key in self._shared.perturbed:
                return steps
            self._shared.perturbed.add(form_key)
        for f in fields:
            for kind, _value in formfill.perturbations(f, None):
                if len(steps) - 1 >= self.opts.max_perturbations:
                    return steps
                steps.append(Step(el["signature"], f"perturb:{f['field']}:{kind}", occ))
        return steps

    def run(self) -> ExploreReport:
        """Explore with ``opts.workers`` browsers. One worker runs here; more run on
        threads, each with its own Playwright instance (the sync API is per thread),
        browser, context and page, over the `_shared` frontier: a worker seeds the start
        state, then each pops a state, restores and explores it, and pushes what it
        finds, until the frontier is empty with no worker holding a state, or a budget
        is hit. The first exception a worker raises stops the others and is re-raised."""
        shared = self._shared
        shared.started = self.clock()
        shared.busy = 1                                  # the seeding worker
        workers = [self] + [self._clone() for _ in range(self.opts.workers - 1)]
        if len(workers) == 1:
            self._run_worker(seed=True)
        else:
            threads = [threading.Thread(target=w._run_worker, kwargs={"seed": i == 0},
                                        name=f"disco-worker-{i}", daemon=True)
                       for i, w in enumerate(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self._write_code_segments()
        if shared.failure is not None:
            raise shared.failure
        return self.report

    def _run_worker(self, *, seed: bool) -> None:
        from playwright.sync_api import sync_playwright
        shared = self._shared
        try:
            args = navguard.browser_launch_args(self.scope_urls, proxy=self.proxy)
            launch = navguard.chromium_launch_kwargs(args, headless=self.opts.headless,
                                                     proxy=self.proxy)
            with sync_playwright() as pw:
                browser = pw.chromium.launch(**launch)
                self._ctx = self._new_context(browser, pw)
                try:
                    self._work(browser, pw, seed=seed)
                finally:
                    navguard.release(self._ctx)
                    browser.close()
        except BaseException as exc:  # handed to run(), never lost
            with shared.lock:
                if shared.failure is None:
                    shared.failure = exc
                shared.stop = shared.stop or "error"
                shared.lock.notify_all()
            if self.opts.workers == 1:
                raise

    def _restore_any(self, page, ctx, state: State) -> bool:
        return self.restore(page, ctx, state) or (
            state.fallback is not None and self.restore(page, ctx, state.fallback))

    def _seed(self, page, ctx) -> None:
        """The start state: loaded, read and queued (the caller holds `busy`)."""
        shared = self._shared
        self._tag(ctx, "nav")
        nav = navguard.navigate(page, self.start_url, timeout_ms=self.opts.nav_timeout_ms,
                                wait_until="load")
        self._document_first(nav.response, self.start_url)    # records the start document
        self.mark_activity()
        self.wait_quiet(page)
        got = self.settled_fingerprint(page, ctx)
        if got is None:
            self._bump("unrestorable")
            return
        root = State(got[0], page.url, page.url,
                     core=state_signatures(got[1]))
        with shared.lock:
            shared.frontier.push(root)
            shared.known.add(got[0])
            self.report.states = 1
            # the origin's well-known files, read for the URLs they name
            from fuzzlab.core.linkextract import KNOWN_FILES
            for path in KNOWN_FILES:
                url = urljoin(self.start_url, path)
                if url not in shared.requested:
                    shared.harvest.setdefault(url, None)
        self._gather(page)

    def _next_state(self) -> "State | str | None":
        """The next state for this worker (marked busy) -- or, once the frontier is
        empty, the next harvest URL (a ``str``) -- or None when the run is over: a
        budget hit, a failure, or nothing left that no busy worker can refill."""
        shared = self._shared
        with shared.lock:
            while True:
                if shared.stop is not None:
                    return None
                hit = self._budget()
                if hit:
                    self._note_budget(hit)
                    shared.stop = hit
                    shared.lock.notify_all()
                    return None
                if shared.frontier and self._actions_spent():
                    self._note_budget("max_actions")   # nothing left to act with: the
                    while shared.frontier:              # harvest still loads
                        shared.frontier.pop()
                if shared.frontier:
                    shared.busy += 1
                    return shared.frontier.pop()
                url = self._next_harvest()
                if url is not None:
                    shared.busy += 1
                    return url
                if shared.busy == 0:
                    shared.lock.notify_all()
                    return None
                shared.lock.wait(0.5)

    def _next_harvest(self) -> str | None:
        """The next harvest URL nothing has requested since it was queued, within
        ``max_harvest`` (the caller holds the lock)."""
        shared = self._shared
        for queue in (shared.harvest_routes, shared.harvest):   # the app's routes first
            while queue:
                if self.report.harvest_loads >= self.opts.max_harvest:
                    self._note_budget("max_harvest")
                    return None
                url = next(iter(queue))
                del queue[url]
                if url not in shared.requested:
                    self.report.harvest_loads += 1
                    return url
        return None

    def _load(self, url: str, page):
        """One harvest load: the URL loaded in this worker's guarded page, its links
        gathered; an HTML document not seen before becomes a frontier state (explored
        like any other, outside ``max_states``). Returns the page to go on with."""
        shared = self._shared
        ctx = self._ctx
        self._tag(ctx, "harvest")
        try:
            nav = navguard.navigate(page, url, timeout_ms=self.opts.nav_timeout_ms,
                                    wait_until="load")
        except _pw_error():  # refused, failed, or a download: nothing to read
            self._bump("errors")
            return page
        self.mark_activity()
        self.wait_quiet(page)
        resp = nav.response
        media = ((resp.headers or {}).get("content-type", "") if resp else "").lower()
        route = spa_route(url) is not None
        if route:                 # a hash route's query lives only in the URL: logged
            self._log_load(url)
        # a script-declared route's URL may load as a same-document navigation (no
        # response); its fragment still names a route to explore
        if "html" in media or route:
            got = self.settled_fingerprint(page, ctx)
            first = None if route else self._document_first(resp, url)
            if first is not None and self._alias_state(page, first, got):
                with shared.lock:
                    self.report.harvest_aliases += 1     # the same app: not a new state
                return page
            if got is not None:
                state = State(got[0], page.url, page.url,
                              core=state_signatures(got[1]))
                with shared.lock:
                    if got[0] not in shared.known:
                        if shared.frontier.push(state):
                            shared.known.add(got[0])
                            self.report.harvest_states += 1
                            self.report.states = len(shared.known)
                            shared.lock.notify_all()
                        else:
                            self.report.route_capped += 1
        self._gather(page)
        return page

    def _document_first(self, resp, url: str) -> str | None:
        """The path an HTML body identical to ``resp``'s (a document load of ``url``)
        was first loaded at, when that is another path; None for a body not seen before
        (recorded under ``url``'s path), the same path, or a body the driver cannot
        give (BUG-0505)."""
        import hashlib
        if resp is None:
            return None
        try:
            body = resp.body()
        except _pw_error():
            return None
        digest = hashlib.sha256(body).hexdigest()
        path = urlsplit(url).path or "/"
        with self._shared.lock:
            first = self._shared.documents.setdefault(digest, path)
        return first if first != path else None

    @staticmethod
    def _hash_routed(page) -> bool:
        """Whether the page routes by its fragment: its URL or one of its links holds a
        ``#/`` (or ``#!/``) route -- the spider's evidence for hash mode (FR-CRAWL-12)."""
        if spa_fragment(page.url) is not None:
            return True
        try:
            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        except _pw_error():  # the page moved on under the read
            return False
        return any(spa_fragment(h) is not None for h in hrefs)

    def _alias_state(self, page, first: str, got) -> bool:
        """Whether a document already loaded at path ``first`` and now rendered in
        ``page`` is an alias, not a new state (BUG-0505): the app routes by its
        fragment (a hash router never reads the path, so every state of the document
        is the first path's), or the rendered state, read as if at ``first``, is a
        state already known (a soft 404, a catch-all). A history-mode route renders
        another view from the same shell: not an alias, explored."""
        if self._hash_routed(page):
            return True
        if got is None:
            return False
        rebased = urlunsplit(urlsplit(page.url)._replace(path=first))
        with self._shared.lock:
            return state_fingerprint(rebased, got[1]) in self._shared.known

    def _note_code_segments(self, text: str) -> None:
        """FR-CRAWL-28: the path segments a script body holds, kept for the importer's
        variation rule (at most `MAX_SCRIPT_SEGMENTS` per run)."""
        from fuzzlab.core.pathtemplate import code_segments
        found = code_segments(text)
        with self._shared.lock:
            room = MAX_SCRIPT_SEGMENTS - len(self._shared.code_segments)
            self._shared.code_segments.update(sorted(found - self._shared.code_segments)
                                              [:max(0, room)])

    def _write_code_segments(self) -> None:
        """``script_segments.json`` beside the action log: the run's code segments,
        sorted (`store_adapter.import_disco` reads it)."""
        if self.actions_log is None:
            return
        path = Path(self.actions_log).with_name("script_segments.json")
        path.write_text(json.dumps(sorted(self._shared.code_segments)), encoding="utf-8")

    def _script_routes(self, text: str, page) -> list[str]:
        """The routes and route-query seeds an app script declares (the spider's own
        scanners and refusals, `tools.spa`): each route's URL in the page's routing mode
        (hash when the page's URL or one of its links routes by fragment, as the spider
        decides it), and for each route a query names a seed with those names set to
        the filler. A parameterised, destructive or non-route path is left out, and a
        seed `query_url_refusal` refuses."""
        got = scan_script(text)
        if got is None:
            self._bump("scripts_too_large")
            return []
        routes, query = got
        if not routes and not query.pairs:
            return []
        page_url = page.url
        hash_mode = self._hash_routed(page)
        out: list[str] = []
        for path in routes:
            if classify_route(path)[0] == ROUTE_OK:
                out.append(route_url(page_url, path, hash_mode=hash_mode,
                                     base=self.start_url))
                self._bump("script_routes")
        for path, names in query.pairs.items():
            if classify_route(path)[0] != ROUTE_OK or not names:
                continue
            seed = seed_url(route_url(page_url, path, hash_mode=hash_mode,
                                      base=self.start_url), names)
            if query_url_refusal(seed) is None:
                out.append(seed)
                self._bump("script_route_seeds")
        return out

    def _release(self) -> None:
        with self._shared.lock:
            self._shared.busy -= 1
            self._shared.lock.notify_all()

    def _work(self, browser, pw, *, seed: bool) -> None:
        shared = self._shared
        page = self._ctx.new_page()
        if seed:
            try:
                self._seed(page, self._ctx)
            finally:
                self._release()
        # A step is taken once per route, not once per state: an overlay state's
        # pending work is what it added. A step on chrome -- an element seen on more
        # than one route (a header, a side-nav) -- is taken once in the whole run.
        # Per-state keys re-acted a header in every state (BUG-0502, measured on Juice
        # Shop: 7 header buttons in each of 60 states, most of 206 actions).
        while True:
            state = self._next_state()
            if state is None:
                return
            try:
                if isinstance(state, str):             # a harvest load
                    page = self._load(state, page)
                else:
                    page = self._process(state, page, browser, pw)
            finally:
                self._release()
            if shared.stop is not None:
                return

    def _process(self, state: State, page, browser, pw):
        """Explore one state's pending steps. Returns the page to go on with (a lost
        session rebuilds the context)."""
        shared = self._shared
        ctx = self._ctx
        authenticated = self.storage_state is not None and \
            not looks_like_login_url(self.start_url)
        if not self._restore_any(page, ctx, state):
            self._bump("unrestorable")
            return page
        got = self.settled_fingerprint(page, ctx)
        if got is None:
            self._bump("unrestorable")
            return page
        self._gather(page)
        route = normalise_route(state.url)
        with shared.lock:
            for el in got[1]:
                shared.sig_routes.setdefault(el["signature"], set()).add(route)
            fresh = [el for el in got[1]
                     if not any((route, el["signature"], el["occurrence"], k) in shared.seen
                                for k in ("click", "submit", "enter"))]
        pending = [(el, step) for el in fresh for step in self._steps_for(page, el, route)]
        dirty = False
        for el_desc, step in pending:
            with shared.lock:
                if shared.stop is not None:
                    return page
                hit = self._budget()
                if hit:
                    self._note_budget(hit)
                    shared.stop = hit
                    shared.lock.notify_all()
                    return page
                if self._actions_spent():
                    self._note_budget("max_actions")
                    return page
                key = (route, *step.key())
                if key in shared.seen or step.key() in shared.denied:
                    continue
                shared.seen.add(key)
                if step.key() in shared.done and \
                        len(shared.sig_routes.get(step.signature, ())) > 1:
                    self.report.chrome_skipped += 1
                    continue
            why = refusal(el_desc, self.opts.deny)
            if why:
                self._refuse(why)
                continue
            if dirty and not self._restore_any(page, ctx, state):
                self._bump("unrestorable")
                break
            dirty = False
            now = self.settled_fingerprint(page, ctx)
            el = self._find(now[1], step) if now else None
            if el is None:
                continue
            before_url = page.url
            try:
                performed = self.act(page, ctx, el, step)
            except _pw_error() as exc:  # one action failing ends only it
                logging.info("disco: action failed (%s)", type(exc).__name__)
                self._bump("errors")
                dirty = True
                continue
            if not performed:
                continue
            with shared.lock:
                shared.done.add(step.key())
                self.report.actions += 1
                if step.kind in ("submit", "enter"):
                    self.report.submissions += 1
                elif step.kind.startswith("perturb:"):
                    self.report.perturbations += 1
            self.wait_quiet(page)
            if step.kind != "click" and self._values_sent:
                self._bump("submissions_sent")
                if has_captcha(self._last_fields):
                    self._bump("captcha_submissions")
            self._fill_values = []
            self._close_popups(ctx, page)
            if authenticated and looks_like_login_url(page.url):
                with shared.lock:
                    self.report.session_lost += 1
                    shared.denied.add(step.key())
                navguard.release(ctx)
                ctx = self._ctx = self._new_context(browser, pw)
                page = ctx.new_page()
                dirty = True
                self._log_action(self._action_seq, state, el, step, None)
                continue
            got = self.settled_fingerprint(page, ctx)
            if got is None:
                self._bump("errors")
                dirty = True
                continue
            new_fp = got[0]
            core = state_signatures(got[1])
            self._gather(page)
            self._log_action(self._action_seq, state, el, step, new_fp, url=page.url)
            if new_fp != state.fp:
                dirty = True
                if page.url != before_url:
                    new = State(new_fp, page.url, page.url, core=core,
                                fallback=State(new_fp, page.url, state.entry_url,
                                               [*state.path, step], core=core))
                else:
                    new = State(new_fp, page.url, state.entry_url,
                                [*state.path, step], core=core)
                with shared.lock:
                    if new_fp not in shared.known and \
                            self._explored_states() >= self.opts.max_states:
                        self._note_budget("max_states")
                    if new_fp not in shared.known and \
                            self._explored_states() < self.opts.max_states:
                        if shared.frontier.push(new):
                            shared.known.add(new_fp)
                            self.report.states = len(shared.known)
                            shared.lock.notify_all()
                        else:
                            self.report.route_capped += 1
        return page
