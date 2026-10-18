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
the page does. In an authenticated run, landing on a login URL (`session.detect.
looks_like_login_url`) marks the session lost: the action that caused it is denied for
the rest of the run and the context is rebuilt from the storage state.
"""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from fuzzlab.core.urls import (destructive_reason, in_origin_scope, origin_scope,
                               text_destructive_reason)
from fuzzlab.disco import formfill
from fuzzlab.disco.capture import ACTION_HEADER
from fuzzlab.disco.fingerprint import element_signature, normalise_route, state_fingerprint
from fuzzlab.session.detect import looks_like_login_url
from fuzzlab.tools import navguard

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
    errors: int = 0
    session_lost: int = 0
    aborted: int = 0
    out_of_scope: dict[str, int] = field(default_factory=dict)
    budget_hit: str | None = None

    def refuse(self, why: str) -> None:
        self.refused[why] = self.refused.get(why, 0) + 1


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
        self.report = ExploreReport()
        self._last_fields: list[dict] = []        # the fields of the last form filled
        self._fill_values: list[str] = []         # the distinctive values just filled
        self._values_sent = False                 # whether a request carried one
        self._perturbed: set[tuple] = set()       # (route, field set): perturbed once
        self._seq = 0
        self._inflight = 0
        self._last_change = 0.0
        self._denied: set[tuple] = set()
        self._ctx = None
        self._tag_headers: dict[str, str] = {}      # the guard reads it per request

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
        ctx.on("requestfinished", self._on_done)
        ctx.on("requestfailed", self._on_done)
        return ctx

    def _count_out_of_scope(self, url: str) -> None:
        from urllib.parse import urlsplit
        host = urlsplit(url).hostname or "?"
        self.report.out_of_scope[host] = self.report.out_of_scope.get(host, 0) + 1

    def _count_abort(self) -> None:
        self.report.aborted += 1

    def _on_request(self, req) -> None:
        self._inflight += 1
        self._last_change = self.clock()
        if self._fill_values and not self._values_sent:
            self._values_sent = carries_value(req, self._fill_values)

    def _on_done(self, _req) -> None:
        self._inflight = max(0, self._inflight - 1)
        self._last_change = self.clock()

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
            if self._inflight == 0 and self.clock() - self._last_change >= idle:
                return True
            page.wait_for_timeout(50)
        return False

    def _tag(self, ctx, prefix: str) -> str:
        """Name the next action: every routed request from now on carries its id."""
        self._seq += 1
        action_id = f"{prefix}-{self._seq}"
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
                self.report.refuse(reason)
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
        for other in list(ctx.pages):
            if other is not page:
                try:
                    other.close()
                except _pw_error():  # it closed itself
                    pass

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
                self.report.transient_dropped += 1
            return True
        return False

    def _log_action(self, action_id_seq: int, state: State, el: dict, step: Step,
                    new_fp: str | None) -> None:
        if self.actions_log is None:
            return
        rec = {"seq": action_id_seq, "state": state.fp, "route": normalise_route(state.url),
               "signature": el["signature"], "kind": step.kind,
               "label": str(el.get("label") or "")[:60], "new_state": new_fp}
        with open(self.actions_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    # --- the loop ----------------------------------------------------------------------
    def _budget(self, started: float) -> str | None:
        if self.report.states >= self.opts.max_states:
            return "max_states"
        if self.report.actions >= self.opts.max_actions:
            return "max_actions"
        if self.clock() - started > self.opts.deadline_s:
            return "deadline"
        return None

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
        if form_key in self._perturbed:
            return steps
        self._perturbed.add(form_key)
        for f in fields:
            for kind, _value in formfill.perturbations(f, None):
                if len(steps) - 1 >= self.opts.max_perturbations:
                    return steps
                steps.append(Step(el["signature"], f"perturb:{f['field']}:{kind}", occ))
        return steps

    def run(self) -> ExploreReport:
        from playwright.sync_api import sync_playwright
        args = navguard.browser_launch_args(self.scope_urls, proxy=self.proxy)
        launch = navguard.chromium_launch_kwargs(args, headless=self.opts.headless,
                                                 proxy=self.proxy)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**launch)
            self._ctx = self._new_context(browser, pw)
            try:
                self._explore(browser, pw)
            finally:
                navguard.release(self._ctx)
                browser.close()
        return self.report

    def _restore_any(self, page, ctx, state: State) -> bool:
        return self.restore(page, ctx, state) or (
            state.fallback is not None and self.restore(page, ctx, state.fallback))

    def _explore(self, browser, pw) -> None:
        ctx = self._ctx
        started = self.clock()
        page = ctx.new_page()
        self._tag(ctx, "nav")
        navguard.navigate(page, self.start_url, timeout_ms=self.opts.nav_timeout_ms,
                          wait_until="load")
        self.mark_activity()
        self.wait_quiet(page)
        got = self.settled_fingerprint(page, ctx)
        if got is None:
            self.report.unrestorable += 1
            return
        root = State(got[0], page.url, page.url,
                     core=frozenset(e["signature"] for e in got[1]))
        fp = got[0]
        frontier = Frontier(self.opts.max_states_per_route)
        frontier.push(root)
        known = {fp}
        # A step is taken once per route, not once per state: an overlay state's
        # pending work is what it added. A step on chrome -- an element seen on more
        # than one route (a header, a side-nav) -- is taken once in the whole run.
        # Per-state keys re-acted a header in every state (BUG-0502, measured on Juice
        # Shop: 7 header buttons in each of 60 states, most of 206 actions).
        seen: set[tuple] = set()
        done: set[tuple] = set()
        sig_routes: dict[str, set[str]] = {}
        authenticated = self.storage_state is not None and \
            not looks_like_login_url(self.start_url)
        self.report.states = 1
        while frontier:
            hit = self._budget(started)
            if hit:
                self.report.budget_hit = hit
                return
            state = frontier.pop()
            if not self._restore_any(page, ctx, state):
                self.report.unrestorable += 1
                continue
            got = self.settled_fingerprint(page, ctx)
            if got is None:
                self.report.unrestorable += 1
                continue
            route = normalise_route(state.url)
            for el in got[1]:
                sig_routes.setdefault(el["signature"], set()).add(route)
            pending = [(el, step) for el in got[1]
                       if not any((route, el["signature"], el["occurrence"], k) in seen
                                  for k in ("click", "submit", "enter"))
                       for step in self._steps_for(page, el, route)]
            dirty = False
            for el_desc, step in pending:
                hit = self._budget(started)
                if hit:
                    self.report.budget_hit = hit
                    return
                key = (route, *step.key())
                if key in seen or step.key() in self._denied:
                    continue
                seen.add(key)
                if step.key() in done and len(sig_routes.get(step.signature, ())) > 1:
                    self.report.chrome_skipped += 1
                    continue
                why = refusal(el_desc, self.opts.deny)
                if why:
                    self.report.refuse(why)
                    continue
                if dirty and not self._restore_any(page, ctx, state):
                    self.report.unrestorable += 1
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
                    self.report.errors += 1
                    dirty = True
                    continue
                if not performed:
                    continue
                done.add(step.key())
                self.report.actions += 1
                if step.kind in ("submit", "enter"):
                    self.report.submissions += 1
                elif step.kind.startswith("perturb:"):
                    self.report.perturbations += 1
                self.wait_quiet(page)
                if step.kind != "click" and self._values_sent:
                    self.report.submissions_sent += 1
                    if has_captcha(self._last_fields):
                        self.report.captcha_submissions += 1
                self._fill_values = []
                self._close_popups(ctx, page)
                if authenticated and looks_like_login_url(page.url):
                    self.report.session_lost += 1
                    self._denied.add(step.key())
                    navguard.release(ctx)
                    ctx = self._ctx = self._new_context(browser, pw)
                    page = ctx.new_page()
                    dirty = True
                    self._log_action(self._seq, state, el, step, None)
                    continue
                got = self.settled_fingerprint(page, ctx)
                if got is None:
                    self.report.errors += 1
                    dirty = True
                    continue
                new_fp = got[0]
                core = frozenset(e["signature"] for e in got[1])
                self._log_action(self._seq, state, el, step, new_fp)
                if new_fp != state.fp:
                    dirty = True
                    if new_fp not in known and len(known) < self.opts.max_states:
                        if page.url != before_url:
                            new = State(new_fp, page.url, page.url, core=core,
                                        fallback=State(new_fp, page.url, state.entry_url,
                                                       [*state.path, step], core=core))
                        else:
                            new = State(new_fp, page.url, state.entry_url,
                                        [*state.path, step], core=core)
                        if frontier.push(new):
                            known.add(new_fp)
                            self.report.states = len(known)
                        else:
                            self.report.route_capped += 1
