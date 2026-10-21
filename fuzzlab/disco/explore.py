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
signatures of its visible interactive elements, text excluded. Breadth first from the
start URL: for each state, each actionable element not yet tried there (keyed by the
state and the element's signature) is acted on once, the network is waited out
(`wait_quiet`: no request in flight for ``idle_ms``, at most ``max_ms``), and a new
fingerprint becomes a frontier state. A state is restored by navigating to its entry
URL and replaying the path of actions that led to it; a state whose replay no longer
reproduces it is dropped (counted).

**Actionable elements** are found three ways: accessibility roles and native controls;
elements with a JavaScript click / pointer / key listener, asked of Chrome DevTools
(``DOMDebugger.getEventListeners``: catches a framework's ``div`` buttons); and
``cursor: pointer`` as a fallback. Enumeration runs again after every action, so
dialogs and lazy panels are seen as they appear.

**Forms** are submitted valid-first (`formfill`): each control gets the first candidate
its own ``checkValidity()`` accepts, then the submitter is clicked; then up to
``max_perturbations`` submissions, each with one control perturbed.

**Safety rails** (never lifted by this module): an element whose label, name or link is
destructive (`core.urls.text_destructive_reason`, `destructive_reason`: logout, delete
account, reset, ...) or one the operator denies (``deny``) is never acted on; a form
that changes a credential (`store_adapter.credential_change_rule`) is never submitted
(a CAPTCHA form is: its CAPTCHA control gets a filler answer, D71); the route guard aborts destructive and out-of-scope requests whatever
the page does.

**A lost session** (FR-CRAWL-41, BUG-0552). An authenticated run starts from a storage
state, or from a session provider (`ExploreSession`: the run's session manager, its
identity and base URL). Its contexts carry one session *generation*. After every
action, restore and load, the answers the context got since the last check are
classified by SP-56 (`core.comparability.response_class`, with SP-16's `login_facts`):
a credentialed auth failure (a 401 or a login redirect that is not a credential
submission) and a page at a login URL or showing this session's login form in place
(SP-16; without a known form, a password form where the page was seen without one: the
URL before an action, the state restored, the start page) are *suspected* losses, a
policy block (403) a suspected denial. With a provider, SP-61
(`SessionManager.check_health`) decides for the context's generation: live, a policy
block or an answer is an authorization denial and nothing changes, but a login page
after an action means the context lost its copy, whatever answer came with it; lost, the
provider gives a fresh session (a new login, never the snapshot the run started from),
which must pass its own protected check before the old context is released and
**closed** and a new one carries it. Without a provider, the start page is the run's
protected resource when SP-61's `health_verdict` reads it live with the context's
cookies and refused without them, and a suspicion is decided by a GET of it with the
context's cookies; with none, a loss shape is an unconfirmed loss and a policy block
never is one (PA-0533(1)). A loss nothing resolves ends the authenticated exploration,
its reason in the report (`auth_ended`). A generation found lost is recorded for every
worker at the verdict, before any recovery: no worker acts on it again, and each marks
what it sent on it. The action ids whose answers fell in a known-lost window are marked
(a ``session`` line in the action log, `ExploreReport.session_lost_actions`, read by
`disco.capture.lost_action_ids`): never authenticated coverage (D').
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

from fuzzlab.core.comparability import AUTH_FAILURE, POLICY_BLOCK, response_class
from fuzzlab.core.redaction import redact_url
from fuzzlab.core.urls import (destructive_reason, document_key, in_origin_scope,
                               origin_scope, spa_route, text_destructive_reason)
from fuzzlab.disco import formfill
from fuzzlab.disco.capture import ACTION_HEADER
from fuzzlab.disco.fingerprint import element_signature, normalise_route, state_fingerprint
# the one script-route scanner both crawlers share (SP-47; D70's allowlist)
from fuzzlab.tools.spa import (ROUTE_OK, classify_route, query_url_refusal, route_url,
                               scan_script, seed_url, spa_fragment)
from fuzzlab.session.detect import (login_facts, looks_like_login_url, request_entry_names,
                                    shows_login_form)
from fuzzlab.tools import navguard
from fuzzlab.tools.netquiet import Inflight

def _pw_error():
    """Playwright's error class (its timeouts subclass it): the one external failure an
    action, a navigation or a DevTools query maps to "not done" (PA-0106, PA-0137). Any
    other exception is a defect and propagates. Resolved lazily: importing this module
    needs no browser extra."""
    from playwright.sync_api import Error
    return Error


#: Listener types that make an element actionable.
ACTION_LISTENERS = ("click", "mousedown", "mouseup", "pointerdown", "pointerup",
                    "keydown", "touchstart", "dblclick")
#: Elements asked of DevTools per enumeration (bounded: one CDP call each).
MAX_CDP_CANDIDATES = 200
#: Elements described per enumeration.
MAX_ELEMENTS = 400

_ENUMERATE_JS = r"""
([maxElements, maxCand]) => {
  const NATIVE = 'a[href],button,input,select,textarea,summary,[role=button],[role=link],'
    + '[role=menuitem],[role=tab],[role=checkbox],[role=combobox],[role=option],'
    + '[role=switch],[role=radio],[onclick],[contenteditable=true],[tabindex]:not([tabindex="-1"])';
  const visible = (e) => {
    if (!e.isConnected) return false;
    const r = e.getClientRects();
    if (!r.length) return false;
    const s = getComputedStyle(e);
    return s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0';
  };
  document.querySelectorAll('[data-disco-id]').forEach(e => e.removeAttribute('data-disco-id'));
  document.querySelectorAll('[data-disco-cand]').forEach(e => e.removeAttribute('data-disco-cand'));
  const out = [];
  let n = 0;
  const cls = (e) => Array.from(e.classList || []).slice(0, 4).sort().join('.');
  const node = (e) => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (cls(e) ? '.' + cls(e) : '');
  const ancestry = (e) => {
    const out = []; let a = e.parentElement;
    while (a && a !== document.body && out.length < 3) { out.push(node(a)); a = a.parentElement; }
    return out.join('<');
  };
  const formLike = (e) => {        // a <form>, else the nearest ancestor holding typed inputs
    if (e.form) return e.form;
    const f = e.closest('form'); if (f) return f;
    let a = e.parentElement, n = 0;
    while (a && a !== document.body && n < 6) {
      if (a.querySelector('input:not([type=hidden]):not([type=button]):not([type=submit])'
                          + ':not([type=checkbox]):not([type=radio]),textarea,select')) return a;
      a = a.parentElement; n++;
    }
    return null;
  };
  window.__discoLayout = {cls, ancestry, formLike};
  const TYPED = 'input:not([type=hidden]):not([type=button]):not([type=submit])'
    + ':not([type=checkbox]):not([type=radio]):not([type=reset]):not([type=image]),textarea';
  const describe = (e, how) => {
    const id = String(n++);
    e.setAttribute('data-disco-id', id);
    const form = formLike(e);
    const typed = form ? Array.from(form.querySelectorAll(TYPED)) : [];
    const label = (e.getAttribute('aria-label') || e.getAttribute('title') || e.innerText
                   || e.value || e.getAttribute('placeholder') || '').trim().slice(0, 80);
    const tag = e.tagName.toLowerCase();
    const type = (e.getAttribute('type') || (tag === 'button' ? 'submit' : '')).toLowerCase();
    out.push({disco_id: id, how, tag, role: e.getAttribute('role') || '', type,
              name: e.getAttribute('name') || '', id: e.id || '', cls: cls(e), ancestry: ancestry(e),
              href: tag === 'a' ? e.href : '', label,
              // a form-less container has no action: location.href put the route into
              // every signature inside it, so a toolbar was new on each route (BUG-0502)
              action: form && form.tagName === 'FORM' ? (form.action || location.href) : '',
              in_form: !!form, disabled: !!e.disabled, cursor: getComputedStyle(e).cursor,
              // the Enter rule (`enter_submits`): what the element's container holds
              form_tag: !!(form && form.tagName === 'FORM'), typed: typed.length,
              last_typed: typed.length > 0 && typed[typed.length - 1] === e,
              submitters: form ? form.querySelectorAll(
                'button:not([type=button]):not([type=reset]),input[type=submit],'
                + 'input[type=image]').length : 0});
  };
  for (const e of document.querySelectorAll(NATIVE)) {
    if (out.length >= maxElements) break;
    // a disabled control is kept only as a submitter (filling its form enables it)
    if (visible(e) && (!e.disabled || (e.tagName === 'BUTTON' && formLike(e))))
      describe(e, 'native');
  }
  let c = 0;
  for (const e of document.querySelectorAll('div,span,li,img,svg,td,p,i,section,article,label')) {
    if (out.length + c >= maxElements || c >= maxCand) break;
    if (e.hasAttribute('data-disco-id') || !visible(e)) continue;
    if (e.closest('[data-disco-id]')) continue;
    if (getComputedStyle(e).cursor === 'pointer'
        && !(e.parentElement && getComputedStyle(e.parentElement).cursor === 'pointer')) {
      describe(e, 'pointer');
      continue;
    }
    e.setAttribute('data-disco-cand', String(c++));
  }
  return out;
}
"""

_CANDIDATES_JS = "() => Array.from(document.querySelectorAll('[data-disco-cand]'))"

_MARK_JS = r"""
(els) => {
  const out = [];
  for (const e of els) {
    let n = document.querySelectorAll('[data-disco-id]').length;
    e.setAttribute('data-disco-id', 'L' + n);
    const lay = window.__discoLayout;
    out.push({disco_id: 'L' + n, how: 'listener', tag: e.tagName.toLowerCase(),
              role: e.getAttribute('role') || '', type: '', name: '', id: e.id || '',
              cls: lay ? lay.cls(e) : '', ancestry: lay ? lay.ancestry(e) : '',
              href: '', label: (e.getAttribute('aria-label') || e.innerText || '').trim().slice(0, 80),
              action: '', in_form: !!e.closest('form'), cursor: getComputedStyle(e).cursor});
  }
  return out;
}
"""

_FIELDS_JS = r"""
(e) => {
  // markers of an earlier form go first: a stale data-disco-field="0" earlier in the
  // document was filled in place of this form's first control (BUG-0502)
  document.querySelectorAll('[data-disco-field]').forEach(c => c.removeAttribute('data-disco-field'));
  const lay = window.__discoLayout;
  const form = (lay && lay.formLike(e)) || e.form || e.closest('form') || e.parentElement;
  const ctrls = Array.from(form.querySelectorAll('input,select,textarea'));
  return ctrls.map((c, i) => {
    c.setAttribute('data-disco-field', String(i));
    const lab = (c.labels && c.labels[0] && c.labels[0].innerText) || '';
    return {field: String(i), tag: c.tagName.toLowerCase(), type: (c.getAttribute('type') || '').toLowerCase(),
            name: c.getAttribute('name') || '', id: c.id || '', label: lab.trim().slice(0, 80),
            aria_label: c.getAttribute('aria-label') || '', placeholder: c.getAttribute('placeholder') || '',
            autocomplete: c.getAttribute('autocomplete') || '', pattern: c.getAttribute('pattern') || '',
            min: c.getAttribute('min'), max: c.getAttribute('max'), step: c.getAttribute('step'),
            minlength: c.getAttribute('minlength'), maxlength: c.getAttribute('maxlength'),
            required: c.required, disabled: c.disabled, readonly: c.readOnly,
            value: c.type === 'password' ? '' : String(c.value || '').slice(0, 64),
            options: c.tagName === 'SELECT' ? Array.from(c.options).map(o => o.value) : []};
  });
}
"""


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

    ``core`` is the state's *stable* element signatures. It starts as everything first
    seen; any restore that shows the same route with elements only gone, none new,
    narrows it to what is left: one-time or consumed UI -- a first-visit dialog, a
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
    #: FR-CRAWL-41: the state showed a password form when it was found (an authenticated
    #: run): a restore that shows one is the state's own page, never a sign of a loss
    login_shown: bool = False


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
    #: FR-CRAWL-41: fresh sessions a run takes after losses before its authenticated
    #: exploration ends (each one a login through the session provider).
    max_session_recoveries: int = 3


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
    #: FR-CRAWL-41 (BUG-0552): losses of the session a context carried (confirmed by the
    #: protected check, or a loss shape with no provider to check), the suspicions
    #: checked, the policy blocks or answers a live check made an authorization denial,
    #: the fresh sessions installed (revalidated), the contexts re-given the live
    #: session they had lost, the action ids whose answers fell in a known-lost window
    #: (never evidence, D'), and why authenticated exploration ended, if it did
    session_lost: int = 0
    session_suspected: int = 0
    authorization_denials: int = 0
    session_recovered: int = 0
    session_reinstalled: int = 0
    session_lost_actions: list = field(default_factory=list)
    auth_ended: str | None = None
    aborted: int = 0
    out_of_scope: dict[str, int] = field(default_factory=dict)
    budget_hit: str | None = None

    def refuse(self, why: str) -> None:
        self.refused[why] = self.refused.get(why, 0) + 1


@dataclass
class ExploreSession:
    """The session provider of an authenticated exploration (FR-CRAWL-41): the run's
    `session.manager.SessionManager` -- the owner of whether the identity's session is
    live (SP-61, `check_health`) and of a fresh one (`ensure`) -- the identity explored
    as, and the operator's base URL that identity logs in from (``operator=True``). A
    context adopts its session through `tools.browserauth.browser_session` (the one
    adoption helper): cookies and a browser login's storage state; a session carried
    only in headers (a token login with no browser state) cannot be (the app's own
    script would not send it) and is refused loudly."""
    manager: object
    identity: str
    base_url: str


@dataclass
class _SessionMaterial:
    """What a context of one session generation adopts (FR-CRAWL-41): the generation
    (the session manager's, or 0 for a storage state), the storage state and cookies,
    where the session goes (``scope``: the session's origins), and its login page and
    form fields (SP-16's `shows_login_form` reads them; unknown for a storage state)."""
    generation: int | None
    storage_state: dict | None = field(default=None, repr=False)
    cookies: list = field(default_factory=list, repr=False)
    scope: Callable[[str], bool] | None = field(default=None, repr=False)
    login_url: str | None = None
    login_fields: tuple | None = None


class SessionUnavailable(RuntimeError):
    """The session provider gave no session a context can carry (FR-CRAWL-41): at the
    start it is raised (never a silent anonymous run); after a loss it ends the
    authenticated exploration with its message as the reason. Messages name no URL."""


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
        #: FR-CRAWL-41: the session every worker's context should carry (its generation,
        #: `_SessionMaterial`), the fresh sessions taken, and the lock a recovery holds
        #: (single flight: one worker logs in again, the others adopt what it got). Taken
        #: before `lock` when both are held, never while `lock` is held.
        self.auth_lock = threading.RLock()
        self.auth: "_SessionMaterial | None" = None
        self.recoveries = 0
        #: the generations a worker found lost (or unresolved): recorded at the verdict,
        #: under `auth_lock`, before any recovery, so that no worker whose context still
        #: carries one acts on it or clears its window (BUG-0552 review B1)
        self.lost_generations: set = set()
        #: a run without a session provider: the protected resource its suspicions are
        #: checked against (`Explorer._find_protected_resource`; None: none, a loss
        #: shape is an unconfirmed loss)
        self.protected: str | None = None


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


def _same_place(url: str, other: str) -> bool:
    """The same document (`core.urls.document_key`) and the same fragment: a page shown
    there now replaced the one seen there before, in place (FR-CRAWL-41)."""
    return document_key(url) == document_key(other) and \
        urlsplit(url or "").fragment == urlsplit(other or "").fragment


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
                 clock: Callable[[], float] = time.monotonic,
                 session: ExploreSession | None = None):
        self.start_url = start_url
        self.scope_urls = list(scope_urls)
        self.origins = origin_scope(*self.scope_urls)
        if not in_origin_scope(start_url, self.origins):
            raise ValueError("the start URL is outside the scope")
        if storage_state is not None and session is not None:
            raise ValueError("one session source: a storage state or a session provider")
        self.proxy = proxy
        self.opts = options or ExploreOptions()
        self.storage_state = storage_state
        self.session = session
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
        # FR-CRAWL-41, an authenticated context only: the requests that finished since
        # the last session checkpoint, the action ids requests went out under since then
        # (the window a loss marks), the session generation this context carries, and
        # the browser and Playwright instance a replacement context is made with
        self._answers: list = []
        self._window_tags: set = set()
        self._ctx_generation: int | None = None
        self._browser = None
        self._pw = None

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
        """A guarded context for this worker, carrying the run's session of the current
        generation (FR-CRAWL-41, `_current_session`): never the storage state the run
        started from once a newer generation exists. With more than one scope origin the
        guard keeps the session to its own origins (FR-SESS-20)."""
        self._browser, self._pw = browser, pw
        auth = self._current_session()
        ctx = browser.new_context(service_workers="block", ignore_https_errors=True,
                                  storage_state=auth.storage_state if auth else None)
        isolate = auth is not None and len(self.origins) > 1
        navguard.guard_page(
            ctx, in_scope=self._in_scope, headers=self._tag_headers,
            on_out_of_scope=self._count_out_of_scope,
            on_abort=lambda url, why: self._count_abort(),
            cookie_scope=auth.scope if isolate else None,
            isolated_request=(lambda: pw.request.new_context()) if isolate else None)
        if auth is not None and auth.cookies:
            from fuzzlab.tools import browserauth
            browserauth.apply_to_context(ctx, auth.cookies)
        ctx.on("request", self._on_request)
        ctx.on("response", self._on_response)
        ctx.on("requestfinished", self._on_done)
        ctx.on("requestfailed", self._on_done)
        if auth is not None:
            ctx.on("request", self._note_window_tag)
            ctx.on("requestfinished", self._note_answer)
        self._ctx_generation = auth.generation if auth is not None else None
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

    def _note_window_tag(self, req) -> None:
        """FR-CRAWL-41: the action id this request goes out under (the guard stamps the
        same one): a loss found at the next checkpoint marks every such id."""
        self._window_tags.add(self._tag_headers.get(ACTION_HEADER))

    def _note_answer(self, req) -> None:
        """FR-CRAWL-41: a request whose answer arrived whole (``requestfinished``): read
        at the next session checkpoint, never in the handler."""
        if self._in_scope(req.url):
            self._answers.append(req)

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

    # --- the session (FR-CRAWL-41, BUG-0552) -----------------------------------------------
    def _authenticated(self) -> bool:
        """An authenticated run: a session to explore with -- a storage state or a
        session provider -- and a start URL that is not itself a login page."""
        return (self.storage_state is not None or self.session is not None) and \
            not looks_like_login_url(self.start_url)

    def _current_session(self) -> "_SessionMaterial | None":
        """The session of the run's current generation (the first one made on first
        use), or None for an anonymous run."""
        if self.storage_state is None and self.session is None:
            return None
        shared = self._shared
        with shared.auth_lock:
            if shared.auth is None:
                if self.session is not None:
                    shared.auth = self._provider_session(revalidate=False)
                else:
                    from fuzzlab.session.browserlogin import filter_storage_state
                    origins = origin_scope(self.start_url)
                    shared.auth = _SessionMaterial(
                        0, storage_state=filter_storage_state(
                            self.storage_state, self._in_scope, self.scope_urls),
                        scope=lambda u: in_origin_scope(u, origins))
            return shared.auth

    def _provider_session(self, *, revalidate: bool,
                          lost: int | None = None) -> _SessionMaterial:
        """The provider's session, shaped for a context (`browserauth.browser_session`).
        After a loss (``lost``: the generation found lost) it must be another generation
        and ``revalidate`` asks SP-61 for a fresh protected check of it, which must be
        live. Raises `SessionUnavailable` (or the manager's `SessionAuthError`)."""
        from fuzzlab.session.manager import LIVE
        from fuzzlab.tools import browserauth
        sess = self.session
        host = urlsplit(sess.base_url).hostname or ""
        state = sess.manager.ensure(host, sess.identity, sess.base_url, operator=True)
        if not getattr(state, "valid", False):
            raise SessionUnavailable("the session provider has no live session (no "
                                     "login was drawn)")
        if lost is not None and state.generation == lost:
            raise SessionUnavailable("the session provider gave back the lost session")
        shaped = browserauth.browser_session(sess.manager, sess.identity, sess.base_url,
                                             in_scope=self._in_scope,
                                             scope_urls=self.scope_urls)
        if shaped.headers and not shaped.storage_state:
            raise SessionUnavailable("the session is carried in headers only (a token "
                                     "login with no browser state): a browser context "
                                     "cannot carry it")
        material = _SessionMaterial(state.generation, storage_state=shaped.storage_state,
                                    cookies=list(shaped.cookies), scope=shaped.cookie_scope,
                                    login_url=state.login_url,
                                    login_fields=state.login_fields)
        if revalidate:
            health, _moved = sess.manager.check_health(
                host, sess.identity, sess.base_url, generation=state.generation,
                use_cache=False, pause=False)
            if health.state != LIVE:
                raise SessionUnavailable(f"the fresh session failed its protected check "
                                         f"({health.state}: {health.reason})")
        return material

    def _generation_gone(self) -> bool:
        """BUG-0552 review B1: the session this context carries is no longer the run's
        -- a newer generation was installed, or a worker found this one lost (recorded
        at its verdict, before any recovery). An anonymous context carries none."""
        gen = self._ctx_generation
        if gen is None:
            return False
        shared = self._shared
        auth = shared.auth
        if auth is not None and auth.generation != gen:
            return True
        with shared.lock:
            return gen in shared.lost_generations

    def _gone_reason(self) -> str:
        auth = self._shared.auth
        if auth is not None and auth.generation != self._ctx_generation:
            return "a newer session was installed meanwhile"
        return "another worker found this session lost"

    def _note_gone(self) -> None:
        """Record that the generation this context carries is lost for every worker.
        The caller holds `auth_lock`: a worker that reads the record waits there for the
        recovery decision that follows, and adopts its session or stops."""
        if self._ctx_generation is not None:
            with self._shared.lock:
                self._shared.lost_generations.add(self._ctx_generation)

    def _session_current(self, page):
        """The page to go on with: this worker's context replaced when the session it
        carries is gone (another worker installed a newer generation or found this one
        lost) -- the action ids it sent since its last checkpoint marked first (stale),
        then, single flight, the newer session adopted or, when the run's authenticated
        exploration ended, nothing more (the caller reads ``stop``) -- and a page of
        this worker's live context when ``page`` was closed with a replaced one."""
        if self._generation_gone():
            reason = self._gone_reason()
            with self._shared.auth_lock:
                self._mark_window("stale", reason, empty_too=False)
                return self._recover_session(page, "stale", reason)
        if page.is_closed():
            return self._ctx.new_page()
        return page

    def _session_checkpoint(self, page, *, asked: str | None = None, places=(),
                            login_shown: bool = False, before_url: str | None = None,
                            action: bool = False):
        """Was the session this context carries lost since the last checkpoint (after
        an action, a restore, a load)? Returns ``(page, outcome)``: the page to go on
        with, and None, or ``(verdict, reason)`` when the answers since the last
        checkpoint fell in a known-lost window -- marked, logged, and the session
        recovered or the authenticated exploration ended (`_recover_session`).

        The suspicion (`_loss_signs`) is read through the session layer's owners only;
        the decision is SP-61's for the context's generation (`_confirm_loss`). A
        generation another worker found lost, or a newer one installed meanwhile, makes
        the window stale (the action not blamed). A lost, stale or unresolved verdict is
        recorded for every worker (`_Shared.lost_generations`) under `auth_lock`, before
        the recovery it starts (BUG-0552 review B1). ``asked``: the URL the step asked
        for (a link, a harvest URL, the state's): a login page asked for is no sign.
        ``places``: URLs whose page showed no password form (the state restored, the
        start page): one shown there now is in place. ``login_shown``: the page already
        showed one. ``before_url``: the page's URL before the action. ``action``: after
        an action, a login page on a session the provider's check finds live means the
        context no longer carries it (`reinstall`), whatever answer came with it;
        elsewhere such a page is the state's own."""
        shared = self._shared
        primary, page_sign = self._loss_signs(page, asked=asked, places=places,
                                              login_shown=login_shown,
                                              before_url=before_url)
        if self._generation_gone():
            verdict, reason = "stale", self._gone_reason()
        elif primary is None:
            self._window_tags = set()
            return page, None
        else:
            kind, reason, url = primary
            self._bump("session_suspected")
            verdict, why = self._confirm_loss(kind, url)
            if verdict == "live" and action and self.session is not None and \
                    page_sign is not None and page_sign[2]:
                # a login page after an action on a live session: the context no longer
                # carries it, whichever answer (a 401 its script read) came first (R2)
                verdict, reason, why = "reinstall", page_sign[0], ""
            if verdict == "live":
                # an answer or a policy block refused on a live session; a login page a
                # restore or a load shows is that state's own page
                if kind != "page":
                    self._bump("authorization_denials")
                self._window_tags = set()
                return page, None
            if why:
                reason = f"{reason}; {why}"
        with shared.auth_lock:
            if verdict in ("lost", "stale", "unknown"):
                self._note_gone()
            if verdict == "lost":
                self._bump("session_lost")
            self._mark_window(verdict, reason)
            page = self._recover_session(page, verdict, reason)
        return page, (verdict, reason)

    def _mark_window(self, verdict: str, reason: str, *, empty_too: bool = True) -> list:
        """Mark the action ids this context's requests went out under since its last
        clean checkpoint (D'): `session_lost_actions` and one ``session`` line. With
        ``empty_too`` false an empty window writes nothing."""
        window = sorted(t for t in self._window_tags if t)
        self._window_tags = set()
        if not window and not empty_too:
            return window
        with self._shared.lock:
            self.report.session_lost_actions.extend(window)
        self._log_session_event(verdict, reason, window)
        logging.warning("disco: the session was %s (%s); %d action id(s) marked",
                        verdict, reason, len(window))
        return window

    def _loss_signs(self, page, *, asked: str | None, places, login_shown: bool,
                    before_url: str | None):
        """The signs since the last checkpoint that the context's session may be lost:
        ``(primary, page_sign)``. ``primary`` is the one the check decides, ``(kind,
        reason, url)``: ``answer`` (SP-56 classes an answer a credentialed auth
        failure), else ``page`` (`_page_sign`), else ``policy`` (a credentialed policy
        block: only a protected check tells it from a denial), or None. ``page_sign``
        is the page's own, ``(reason, url, strong)``, read whatever the answers were
        (BUG-0552 review R2). Reasons name a class and a status, never a URL."""
        auth = self._shared.auth
        answers, self._answers = self._answers, []
        if auth is None:
            return None, None
        answer = policy = None
        for req in answers:
            got = self._answer_class(req, auth)
            if got is None:
                continue
            cls, why = got
            if cls == AUTH_FAILURE:
                answer = ("answer", why, req.url)
                break
            if cls == POLICY_BLOCK and policy is None:
                policy = ("policy", why, req.url)
        page_sign = self._page_sign(page, auth, asked=asked, places=places,
                                    login_shown=login_shown, before_url=before_url)
        shown = ("page", page_sign[0], page_sign[1]) if page_sign else None
        return answer or shown or policy, page_sign

    def _page_sign(self, page, auth: _SessionMaterial, *, asked: str | None, places,
                   login_shown: bool, before_url: str | None):
        """A page that *became* a login page: ``(reason, url, strong)`` or None. Never
        one the step asked for. At a login URL (unless the page before the action was
        one); else, unless the page already showed a password form: this session's
        login form (SP-16, when the provider knows it), or, with none known, any
        password form -- *strong* in place (at the URL before the action, of the state
        restored or of the start page: pages known without one; BUG-0552 review R1),
        *weak* elsewhere (a harvest load, a navigation: nothing was seen there before),
        and a weak one only where a protected check decides it (`_checkable`)."""
        url = page.url
        if asked and looks_like_login_url(asked):
            return None
        before_login = bool(before_url and looks_like_login_url(before_url))
        if looks_like_login_url(url):
            return None if before_login else ("the page is at a login URL", url, True)
        if login_shown or before_login:
            return None
        if auth.login_url is not None:
            return ("a login form is shown in place", url, True) \
                if self._shows_login(page) else None
        in_place = any(p and _same_place(url, p) for p in (before_url, *places))
        if not in_place and not self._checkable():
            return None
        if not self._shows_login(page):
            return None
        return ("a login form is shown in place", url, True) if in_place else \
            ("a password form is shown", url, False)

    def _checkable(self) -> bool:
        """Whether a suspicion here is decided by a protected check: the session
        provider's (SP-61), or, without one, the run's protected resource."""
        return self.session is not None or self._shared.protected is not None

    def _answer_class(self, req, auth: _SessionMaterial) -> tuple[str, str] | None:
        """SP-56's class of one answer the context got on the session's origins, with
        SP-16's facts (a credential submission, a redirect to a login page), or None
        for a request off the session's origins or one whose answer cannot be read."""
        url = req.url
        if auth.scope is not None and not auth.scope(url):
            return None
        try:
            resp = req.response()
            if resp is None:
                return None
            status, headers, resp_url = resp.status, dict(resp.headers or {}), resp.url
            body = req.post_data_buffer
            ctype = (req.headers or {}).get("content-type")
        except _pw_error():  # the context went away under the read
            return None
        facts = login_facts(url, headers, response_url=resp_url, login_url=auth.login_url,
                            entry_names=request_entry_names(url, body, ctype))
        sent = {"complete": True, "credential_submission": facts.credential_submission,
                "redirect_to_login": facts.redirect_to_login}
        cls, why = response_class(status, headers, credentialed=True, **sent)
        if cls == AUTH_FAILURE and \
                response_class(status, headers, credentialed=False, **sent)[0] == AUTH_FAILURE:
            return None    # an intermediary's demand (a 407): no answer about this session
        return cls, why

    def _shows_login(self, page) -> bool:
        """Whether the page shows this session's login form (SP-16's
        `shows_login_form`: its login page and fields when the provider knows them,
        else any password form)."""
        auth = self._shared.auth
        try:
            html = page.content()
        except _pw_error():  # the page moved on under the read
            return False
        return shows_login_form(html, page.url, auth.login_url if auth else None,
                                auth.login_fields if auth else None)

    def _confirm_loss(self, kind: str, url: str) -> tuple[str, str]:
        """SP-61's verdict on a suspicion, for the generation the context carries:
        ``("live" | "lost" | "stale" | "unknown", why)``. With a provider, its
        `check_health`. Without one, the run's protected resource
        (`_find_protected_resource`) fetched with this context's cookies and judged by
        SP-61's `health_verdict` (BUG-0552 review R3); with none, a loss shape is an
        unconfirmed loss and a policy block never is one (PA-0533(1)). Live, an answer
        or a policy block was an authorization denial (`_session_checkpoint` makes a
        login page after an action on a provider's live session a ``reinstall``)."""
        from fuzzlab.session.manager import LIVE, LOST, STALE, SessionAuthError
        if self.session is None:
            if self._shared.protected is None:
                return ("live", "") if kind == "policy" else \
                    ("lost", "unconfirmed: no protected check without a session provider")
            health = self._context_check()
        else:
            sess = self.session
            try:
                health, _moved = sess.manager.check_health(
                    urlsplit(sess.base_url).hostname or "", sess.identity, sess.base_url,
                    generation=self._ctx_generation, signal_url=url,
                    policy=kind == "policy", pause=False)
            except SessionAuthError as exc:
                return "unknown", \
                    f"the protected check could not run ({type(exc).__name__})"
        if health.state == LIVE:
            return "live", ""
        if health.state in (LOST, STALE):
            return ("lost" if health.state == LOST else "stale"), health.reason
        return "unknown", f"{health.state}: {health.reason}"

    # --- a protected check without a session provider (BUG-0552 review R3) -------------
    def _protected_get(self, url: str, storage_state: dict | None):
        """SP-61's verdict (`session.manager.health_verdict`) on one GET of ``url``:
        with ``storage_state`` (a context's cookies and storage) or with no credential
        at all (an empty ``Cookie``), from a request context of its own -- sent straight
        to the target, never through the capture proxy, so it is never recorded as the
        identity's exploration -- following no redirect (a login redirect is judged as
        one). The scope and destructive gates sit here, at the send (PA-0083(1)): disco's
        second send path of its own, beside the contract runner's. A failure to get an
        answer is INCONCLUSIVE; TLS is verified."""
        from fuzzlab.core.urls import check_send_url
        from fuzzlab.session.manager import INCONCLUSIVE, Health, health_verdict
        from fuzzlab.session.state import SessionState
        navguard.checked_api_request(self._in_scope, url)
        check_send_url(url, method="GET")
        api = self._pw.request.new_context(storage_state=storage_state) \
            if storage_state is not None else self._pw.request.new_context()
        try:
            resp = api.fetch(url, method="GET", max_redirects=0,
                             timeout=self.opts.nav_timeout_ms,
                             headers=None if storage_state is not None else {"cookie": ""})
            status, headers, body = resp.status, dict(resp.headers or {}), resp.text()
        except (_pw_error(), UnicodeDecodeError) as exc:
            return Health(INCONCLUSIVE, f"no response ({type(exc).__name__})", 0)
        finally:
            try:
                api.dispose()
            except _pw_error():  # gone with its Playwright instance
                pass
        state = SessionState(urlsplit(url).hostname or "", "explore", kind="cookie",
                             generation=0)
        return health_verdict(state, status, headers, body, url, refusal=False)

    def _context_check(self, url: str | None = None):
        """The run's protected resource (or ``url``) fetched with this context's own
        cookies and storage: is the session the context carries live?"""
        from fuzzlab.session.manager import INCONCLUSIVE, Health
        try:
            storage = self._ctx.storage_state()
        except _pw_error() as exc:  # the context went away under the read
            return Health(INCONCLUSIVE, f"no context ({type(exc).__name__})", 0)
        return self._protected_get(url or self._shared.protected, storage)

    def _find_protected_resource(self, page) -> None:
        """A storage-state run's protected resource (BUG-0552 review R3): the start
        page's URL, kept only when SP-61's verdict reads a GET of it with this context's
        cookies as live and one with no credential as refused (a login redirect, a 401,
        a login form). Its suspicions are then decided by a GET of it with the suspected
        context's cookies (`_context_check`); without one a loss shape stays an
        unconfirmed loss (PA-0533(1))."""
        from fuzzlab.session.manager import LIVE, LOST
        url = urldefrag(page.url)[0]
        if not self._in_scope(url) or destructive_reason(url) or looks_like_login_url(url):
            return
        if self._context_check(url).state != LIVE:
            return
        if self._protected_get(url, None).state != LOST:
            return
        with self._shared.lock:
            self._shared.protected = url

    def _recover_session(self, page, verdict: str, reason: str):
        """After a known-lost window: adopt a newer generation another worker installed,
        else (single flight, `auth_lock`) take a fresh session from the provider --
        revalidated by its own protected check -- or re-give the context the live
        session it lost (``reinstall``), at most ``max_session_recoveries`` times a run;
        then replace the context (`_replace_context`). A loss nothing resolves -- no
        provider, an unknown health, no fresh session, the cap -- ends authenticated
        exploration (`_end_authenticated`). Returns the page to go on with."""
        from fuzzlab.session.manager import SessionAuthError
        shared = self._shared
        with shared.auth_lock:
            if shared.stop is not None:
                return page
            current = shared.auth
            if current is None or current.generation == self._ctx_generation:
                if verdict == "unknown":
                    return self._end_authenticated(
                        page, f"the session's health could not be decided ({reason})")
                if self.session is None:
                    return self._end_authenticated(
                        page, f"the session was lost ({reason}) and no session provider "
                              f"is configured to refresh it")
                if shared.recoveries >= self.opts.max_session_recoveries:
                    return self._end_authenticated(
                        page, f"the session was lost again ({reason}) after "
                              f"{shared.recoveries} fresh session(s), the most a run takes")
                shared.recoveries += 1
                if verdict == "reinstall":
                    self._bump("session_reinstalled")
                else:
                    try:
                        fresh = self._provider_session(revalidate=True,
                                                       lost=self._ctx_generation)
                    except (SessionUnavailable, SessionAuthError) as exc:
                        why = str(exc) if isinstance(exc, SessionUnavailable) else \
                            type(exc).__name__
                        return self._end_authenticated(
                            page, f"no fresh session after a loss ({reason}): {why}")
                    shared.auth = fresh
                    self._bump("session_recovered")
        return self._replace_context(page, verdict, reason)

    def _replace_context(self, page, verdict: str | None = None, reason: str = ""):
        """Replace this worker's context with one carrying the run's current session:
        the old one released (its pages frozen, drained and closed through the guard, a
        refusing route left; SP-38) and **closed** before the new one is made, so
        repeated losses never leave a context open (BUG-0552). The action ids the old
        context sent after its window was marked are marked with the same ``verdict``
        (B1); the rest of what it was tracking goes with it. Returns the new context's
        page."""
        old = self._ctx
        if old is not None:
            navguard.release(old)
            try:
                old.close()
            except _pw_error():  # closed already, with its browser
                pass
        if verdict is not None:
            self._mark_window(verdict, reason, empty_too=False)
        self._answers, self._responses, self._window_tags = [], [], set()
        self._net = Inflight(clock=self.clock)
        self._ctx = self._new_context(self._browser, self._pw)
        return self._ctx.new_page()

    def _mark_leftover(self) -> None:
        """At a worker's end, its context released: the action ids it sent after its
        last checkpoint on a session that is gone are marked (B1)."""
        if self._window_tags and self._generation_gone():
            self._mark_window("stale", self._gone_reason(), empty_too=False)

    def _end_authenticated(self, page, reason: str):
        """End the run's authenticated exploration, saying why (``auth_ended``): the
        run explores as one identity, so nothing more is explored -- an anonymous
        continuation would be recorded under the identity's profile. Returns ``page``."""
        shared = self._shared
        with shared.lock:
            if self.report.auth_ended is None:
                self.report.auth_ended = reason
            shared.stop = shared.stop or "session-lost"
            shared.lock.notify_all()
        logging.warning("disco: authenticated exploration ended: %s", reason)
        return page

    def _log_session_event(self, verdict: str, reason: str, window: list[str]) -> None:
        """One ``session`` line in ``actions.jsonl``: the verdict, its reason, the
        generation the context carried and the action ids whose answers fell in the
        known-lost window. It has no ``seq`` (not an action): the action-log readers
        pass over it."""
        if self.actions_log is None:
            return
        rec = {"kind": "session", "session": verdict, "reason": reason,
               "generation": self._ctx_generation, "action_ids": window}
        with self._shared.lock, open(self.actions_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    def _lost_action(self, state: "State", el: dict, step: "Step", outcome) -> None:
        """An action whose answers fell in a known-lost window: denied for the rest of
        the run unless the window was stale (it may have ended the session itself), and
        logged with no new state and no URL (nothing it showed is the state's)."""
        verdict, _reason = outcome
        if verdict != "stale":
            with self._shared.lock:
                self._shared.denied.add(step.key())
        self._log_action(self._action_seq, state, el, step, None)

    def _restore_checked(self, page, state: "State"):
        """In an authenticated run: never on a session that is gone (`_session_current`
        first, B1), then `_restore_any` and a session checkpoint -- a password form now
        shown at the state's URL, by a state found without one, is in place (R1); a
        restore that ran on a lost session is tried once more on the recovered one.
        Returns ``(page, restored)``."""
        if not self._authenticated():
            return page, self._restore_any(page, self._ctx, state)
        page = self._session_current(page)
        if self._shared.stop is not None:
            return page, False
        check = {"asked": state.url, "places": (state.url, state.entry_url),
                 "login_shown": state.login_shown}
        restored = self._restore_any(page, self._ctx, state)
        page, lost = self._session_checkpoint(page, **check)
        if lost is None:
            return page, restored
        if self._shared.stop is not None:
            return page, False
        restored = self._restore_any(page, self._ctx, state)
        page, lost = self._session_checkpoint(page, **check)
        return page, restored and lost is None and self._shared.stop is None

    def _seed_session(self, page):
        """The start page on a live session: a checkpoint after its load -- the run's
        first look, so a password form wherever it landed is in place (R1); on a loss
        the page is loaded once more on the recovered session. None when it stays lost
        or the authenticated exploration ended."""
        page, lost = self._session_checkpoint(page, asked=self.start_url,
                                              places=(self.start_url, page.url))
        if lost is None:
            return page
        if self._shared.stop is not None:
            return None
        self._tag(self._ctx, "nav")
        navguard.navigate(page, self.start_url, timeout_ms=self.opts.nav_timeout_ms,
                          wait_until="load")
        self.mark_activity()
        self.wait_quiet(page)
        page, lost = self._session_checkpoint(page, asked=self.start_url,
                                              places=(self.start_url, page.url))
        return page if lost is None and self._shared.stop is None else None

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
        """The page's actionable elements, each marked ``data-disco-id``."""
        els = page.evaluate(_ENUMERATE_JS, [MAX_ELEMENTS, MAX_CDP_CANDIDATES])
        els += self._listener_elements(page, ctx)
        counts: dict[str, int] = {}
        for el in els:
            el["signature"] = element_signature(el)
            el["occurrence"] = counts.get(el["signature"], 0)
            counts[el["signature"]] = el["occurrence"] + 1
        return els

    @staticmethod
    def _find(els: list[dict], step: Step) -> dict | None:
        return next((e for e in els if e["signature"] == step.signature
                     and e["occurrence"] == step.occurrence), None)

    def _listener_elements(self, page, ctx) -> list[dict]:
        """Candidates with a JS action listener, asked of Chrome DevTools."""
        try:
            cdp = ctx.new_cdp_session(page)
        except _pw_error():  # a browser without CDP: the other two ways only
            return []
        try:
            arr = cdp.send("Runtime.evaluate", {"expression": f"({_CANDIDATES_JS})()"})
            obj = arr.get("result", {}).get("objectId")
            if not obj:
                return []
            props = cdp.send("Runtime.getProperties", {"objectId": obj, "ownProperties": True})
            hits = []
            for prop in props.get("result", []):
                el_id = (prop.get("value") or {}).get("objectId")
                if not el_id or not prop.get("name", "").isdigit():
                    continue
                found = cdp.send("DOMDebugger.getEventListeners", {"objectId": el_id})
                types = sorted({ln.get("type") for ln in found.get("listeners", [])
                                if ln.get("type") in ACTION_LISTENERS})
                if types:
                    hits.append((int(prop["name"]), types))
            if not hits:
                return []
            hits.sort()          # document order: CDP lists properties in no stated order
            handles = page.locator("[data-disco-cand]")
            chosen = [handles.nth(i) for i, _ in hits]
            marked = page.evaluate(_MARK_JS, [h.element_handle() for h in chosen])
            for desc, (_, types) in zip(marked, hits):
                desc["listeners"] = types
            return marked
        finally:
            try:
                cdp.detach()
            except _pw_error():  # the page may have gone already
                pass

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
    def _locate(self, page, el: dict):
        return page.locator(f'[data-disco-id="{el["disco_id"]}"]').first

    def _fill(self, page, loc, perturb: tuple[str, str] | None) -> list[dict] | None:
        """Fill the submitter's form valid-first; ``perturb`` = (field, kind) replaces
        one control's value. Returns the field descriptions, or None when refused."""
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
        loc = self._locate(page, el)
        prefix = "nav" if el.get("href") else "act"
        if step.kind != "click":
            perturb = None
            if step.kind.startswith("perturb:"):
                _, fid, kind = step.kind.split(":", 2)
                perturb = (fid, kind)
            self._fill_values, self._values_sent = [], False
            fields = self._fill(page, loc, perturb)
            self._last_fields = fields or []
            # a form-less container has no action: the page's URL stands for it
            reason = form_refusal(self._last_fields,
                                  dict(el, action=el.get("action") or page.url))
            if reason:
                self._refuse(reason)
                self._fill_values = []
                return False
        self._tag(ctx, prefix)
        if step.kind == "enter":
            loc.press("Enter", timeout=3000)
            self.mark_activity()
            return True
        try:
            loc.click(timeout=3000)
        except _pw_error():  # covered or detached: one dispatched click
            try:
                loc.dispatch_event("click", timeout=2000)
            except _pw_error():  # not actionable at all
                return False
        self.mark_activity()
        return True

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
        sigs = frozenset(e["signature"] for e in els)
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
                    self._mark_leftover()
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
        authenticated = self._authenticated()
        if authenticated:                         # FR-CRAWL-41: seeded on a live session
            if self.session is None:              # a protected check of its own (R3)
                self._find_protected_resource(page)
            page = self._seed_session(page)
            if page is None:
                return
            ctx = self._ctx
        got = self.settled_fingerprint(page, ctx)
        if got is None:
            self._bump("unrestorable")
            return
        root = State(got[0], page.url, page.url,
                     core=frozenset(e["signature"] for e in got[1]),
                     login_shown=authenticated and self._shows_login(page))
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
        authenticated = self._authenticated()
        if authenticated:
            page = self._session_current(page)        # FR-CRAWL-41: never a lost one (B1)
            if shared.stop is not None:
                return page
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
        if authenticated:            # FR-CRAWL-41: nothing read from a lost window
            page, lost = self._session_checkpoint(page, asked=url)
            if lost is not None:
                return page
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
                              core=frozenset(e["signature"] for e in got[1]),
                              login_shown=authenticated and self._shows_login(page))
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

    def _ready(self, page, state: State, step: Step, dirty: bool):
        """The page and ``step``'s element to act on: the state restored when ``dirty``,
        and never on a session that is gone (BUG-0552 review B1) -- checked again right
        before the act, so a loss another worker found while this one read its page
        means a restore on the adopted session first (once; a second loss leaves the
        step). Returns ``(page, el, end, dirty)``: ``end`` ``stop`` or ``unrestorable``
        ends the state; ``el`` None skips the step."""
        authenticated = self._authenticated()
        for _attempt in range(2):
            if authenticated and self._generation_gone():
                dirty = True               # `_restore_checked` adopts the session first
            if dirty:
                page, restored = self._restore_checked(page, state)
                if self._shared.stop is not None:
                    return page, None, "stop", False
                if not restored:
                    return page, None, "unrestorable", False
                dirty = False
            now = self.settled_fingerprint(page, self._ctx)
            el = self._find(now[1], step) if now else None
            if el is None or not (authenticated and self._generation_gone()):
                return page, el, None, False
            dirty = True
        return page, None, None, True

    def _process(self, state: State, page, browser, pw):
        """Explore one state's pending steps. Returns the page to go on with (a lost
        session replaces the context, FR-CRAWL-41)."""
        shared = self._shared
        authenticated = self._authenticated()
        page, restored = self._restore_checked(page, state)     # on a current session
        ctx = self._ctx
        if shared.stop is not None:
            return page
        if not restored:
            self._bump("unrestorable")
            return page
        got = self.settled_fingerprint(page, ctx)
        if got is None:
            self._bump("unrestorable")
            return page
        login_shown = authenticated and (state.login_shown or self._shows_login(page))
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
            page, el, end, dirty = self._ready(page, state, step, dirty)
            ctx = self._ctx
            if end is not None:
                if end == "unrestorable":
                    self._bump("unrestorable")
                return page
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
            if authenticated:          # FR-CRAWL-41 (BUG-0552): was the session lost?
                page, lost = self._session_checkpoint(
                    page, asked=el.get("href") or None, login_shown=login_shown,
                    before_url=before_url, action=True)
                if lost is not None:
                    self._lost_action(state, el, step, lost)
                    ctx = self._ctx
                    if shared.stop is not None:
                        return page
                    dirty = True
                    continue
            got = self.settled_fingerprint(page, ctx)
            if got is None:
                self._bump("errors")
                dirty = True
                continue
            new_fp = got[0]
            core = frozenset(e["signature"] for e in got[1])
            self._gather(page)
            self._log_action(self._action_seq, state, el, step, new_fp, url=page.url)
            if new_fp != state.fp:
                dirty = True
                shown = authenticated and self._shows_login(page)
                if page.url != before_url:
                    new = State(new_fp, page.url, page.url, core=core,
                                fallback=State(new_fp, page.url, state.entry_url,
                                               [*state.path, step], core=core,
                                               login_shown=shown),
                                login_shown=shown)
                else:
                    new = State(new_fp, page.url, state.entry_url,
                                [*state.path, step], core=core, login_shown=shown)
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
