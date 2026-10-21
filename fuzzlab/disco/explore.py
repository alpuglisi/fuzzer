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

**States** (FR-CRAWL-31, BUG-0539). A state's identity is its execution key
(`fingerprint.execution_key`, SP-62): the exact route (query values, numeric path
segments), the multiset of its visible interactive elements' signatures, the workflow
markers its controls hold, and the session generation. Every visited-state check reads
it. The structural key (`fingerprint.state_fingerprint`: folded route, set of
signatures) only schedules and folds: the frontier explores a new route, then a new
layout, then a variant of a known layout, and holds at most ``max_states_per_route``
states per folded route -- the rest are reported (`coverage_excluded`), never claimed
equivalent.

**Work** (FR-CRAWL-32). An action's work key is ``(execution key, element signature,
occurrence, kind)``, tracked by `WorkLedger` as pending, running, succeeded, refused,
retryable or failed. A failure never consumes the work: it is retried up to
``max_action_attempts`` times, then recorded failed and reported. A step already taken
in another state is scheduled after this state's own steps (deprioritised); it is
skipped only once two states on two routes gave it the same observed effect (requests
and transition).

**Restore** (FR-CRAWL-33). A state is restored by navigating to its entry URL and
replaying the path of actions that led to it, then checking its recorded contract
(`contract_mismatch`): the exact route, every mandatory element as many times as
recorded, every workflow marker. The contract is never rewritten or narrowed; a
feature is optional only when declared so with evidence (shown on the first visit only;
dismissed for good by its own control). A path step whose element is missing fails the
restore unless the element is declared optional. A path holding a step that sent a
non-idempotent request is never replayed: the state it reached is explored in place,
when it is reached, and later restores of it are unresolved. A failed restore marks
the state unresolved with its reason (`unresolved`).

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
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from fuzzlab.core.redaction import redact_url
from fuzzlab.core.urls import (destructive_reason, in_origin_scope, origin_scope,
                               spa_route, text_destructive_reason)
from fuzzlab.disco import formfill
from fuzzlab.disco.capture import ACTION_HEADER
from fuzzlab.disco.fingerprint import (element_multiset, element_signature, execution_key,
                                       execution_route, normalise_route,
                                       state_fingerprint, workflow_markers)
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
  // the control values that select a workflow (FR-CRAWL-31's markers): a select's
  // value, a box's checked state, ARIA selection; never typed text
  const selState = (e) => {
    const tag = e.tagName.toLowerCase(), parts = [];
    if (tag === 'select') parts.push('value=' + String(e.value).slice(0, 64));
    if (tag === 'input' && (e.type === 'checkbox' || e.type === 'radio'))
      parts.push('checked=' + e.checked);
    for (const a of ['aria-selected', 'aria-current', 'aria-checked']) {
      const v = e.getAttribute(a);
      if (v !== null && v !== '' && v !== 'false') parts.push(a + '=' + String(v).slice(0, 32));
    }
    return parts.join(';');
  };
  window.__discoLayout = {cls, ancestry, formLike, selState};
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
              sel: selState(e),
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
              action: '', in_form: !!e.closest('form'), cursor: getComputedStyle(e).cursor,
              sel: lay ? lay.selState(e) : ''});
  }
  return out;
}
"""

#: The page-level workflow markers (`fingerprint.workflow_markers`): each named hidden
#: input (at most 50, value cut at 65 characters: longer is no marker) and each
#: non-interactive ``aria-current`` element (a stepper's position; at most 20).
_MARKS_JS = r"""
() => {
  const out = [];
  const hidden = document.querySelectorAll('input[type=hidden][name]');
  for (let i = 0; i < hidden.length && i < 50; i++)
    out.push(['hidden', hidden[i].getAttribute('name') || '', String(hidden[i].value || '').slice(0, 65)]);
  const lay = window.__discoLayout;
  const cur = document.querySelectorAll('[aria-current]:not([aria-current="false"])');
  for (let i = 0; i < cur.length && i < 20; i++) {
    const e = cur[i];
    if (e.hasAttribute('data-disco-id')) continue;     // an enumerated element: its own sel
    const where = e.tagName.toLowerCase() + (lay ? '<' + lay.ancestry(e) : '');
    const idx = e.parentElement ? Array.from(e.parentElement.children).indexOf(e) : 0;
    out.push(['current', where, idx, String(e.getAttribute('aria-current')).slice(0, 32)]);
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


#: Request methods that are safe to repeat (RFC 9110 9.2.2: idempotent, no TRACE).
IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class Step:
    """One replayable action: the element (its signature and which occurrence of that
    signature, in document order) and what was done with it. ``safe`` is recorded when
    the step is taken: False when a non-idempotent request (any method outside
    `IDEMPOTENT`, sent or refused) was observed during it -- such a step is never
    replayed (FR-CRAWL-33)."""
    signature: str
    kind: str                       # "click" | "submit" | "enter" | "perturb:<field>:<kind>"
    occurrence: int = 0
    safe: bool = True

    def key(self) -> tuple[str, int, str]:
        return (self.signature, self.occurrence, self.kind)


def work_key(state_key: str, step: Step) -> tuple[str, str, int, str]:
    """FR-CRAWL-32: an action's unit of work -- the execution state it is taken in,
    then the element signature, its occurrence and the action kind."""
    return (state_key, step.signature, step.occurrence, step.kind)


@dataclass(frozen=True)
class Reading:
    """One read of a page: its execution key (`fingerprint.execution_key`, the state's
    identity), its structural key (`fingerprint.state_fingerprint`, scheduling and
    folding only), its URL, its elements, their multiset and its workflow markers."""
    key: str
    structure: str
    url: str
    els: list
    counts: tuple = ()
    markers: tuple = ()


@dataclass
class State:
    """A state and how to get back to it: ``entry_url`` then ``path``; when that no
    longer reproduces it (a page only a POST shows), ``fallback`` is tried.

    ``fp`` is the execution key. ``core`` (the element multiset) and ``markers`` are
    the state's contract, recorded when it was first read and **never rewritten**
    (FR-CRAWL-33, BUG-0539: narrowing them to what a restore showed accepted a wrong
    state and weakened it for good). ``optional`` lists ``(signature, count)`` declared
    optional for this state and ``optional_markers`` its declared optional markers:
    only the start state declares any, from a fresh second load (`Explorer._seed`).
    Run-wide declarations (a dismissed notice) live in `_Shared.optional`.
    ``unresolved`` is the reason a restore of it failed, once one did."""
    fp: str
    url: str
    entry_url: str
    path: list[Step] = field(default_factory=list)
    fallback: "State | None" = None
    core: tuple = ()
    markers: tuple = ()
    structure: str = ""
    optional: tuple = ()
    optional_markers: tuple = ()
    unresolved: str | None = None

    @classmethod
    def read(cls, got: Reading, *, entry_url: str, path=None,
             fallback: "State | None" = None) -> "State":
        """A state recorded from ``got``: its contract is what ``got`` shows."""
        return cls(got.key, got.url, entry_url, list(path or []), fallback,
                   core=got.counts, markers=got.markers, structure=got.structure)

    def replayable(self) -> bool:
        """Whether ``path`` holds only steps recorded safe to repeat."""
        return all(step.safe for step in self.path)


def contract_mismatch(state: State, got: Reading, optional=frozenset()) -> str | None:
    """Why ``got`` does not reproduce ``state`` (FR-CRAWL-33), or None when it does:

    * ``route``: the exact route (`fingerprint.execution_route`) differs;
    * ``core``: a mandatory element is missing, or present fewer times than recorded --
      a proper subset is never accepted;
    * ``markers``: a recorded workflow marker is not shown.

    Mandatory is the recorded contract minus what is declared optional: ``optional``
    (run-wide declared signatures) and the state's own ``optional`` counts and
    ``optional_markers``. A page with *more* than the contract (a notice shown again in
    another worker's context) reproduces it. Nothing here changes ``state``."""
    if got.key == state.fp:
        return None
    if execution_route(got.url) != execution_route(state.url):
        return "route"
    have = dict(got.counts)
    own = dict(state.optional)
    for sig, n in state.core:
        if sig in optional:
            continue
        if have.get(sig, 0) < n - own.get(sig, 0):
            return "core"
    shown = set(got.markers)
    skip = tuple(f"el:{sig}#" for sig in optional)
    for mark in state.markers:
        if mark in shown or mark in state.optional_markers or (skip and mark.startswith(skip)):
            continue
        return "markers"
    return None


#: A work item's status (FR-CRAWL-32). ``equivalent``: skipped because two states on two
#: routes gave the step the same observed effect.
PENDING, RUNNING, SUCCEEDED, REFUSED = "pending", "running", "succeeded", "refused"
RETRYABLE, FAILED, EQUIVALENT = "retryable", "failed", "equivalent"
#: `Explorer.act`'s outcomes.
ACTED, ACT_REFUSED, ACT_FAILED = "acted", "refused", "failed"


class WorkLedger:
    """The explorer's action work items and what their steps did (FR-CRAWL-32). Not
    thread-safe on its own: the explorer holds `_Shared.lock` around every call.

    * Each work item (`work_key`) is ``pending`` until claimed, ``running`` while taken,
      then ``succeeded`` or ``refused``; a failure makes it ``retryable`` until it has
      failed ``max_attempts`` times, then ``failed``. Only ``pending`` and
      ``retryable`` items can be claimed: a failure never consumes the work.
    * Each step (`Step.key`) records the effect it had in each state it was taken in:
      the requests it made and the transition. A step taken anywhere before is
      `performed` (the explorer schedules it after a state's own steps); it is
      `established` -- skipped as equivalent -- only once states on two routes gave it
      the same effect, and never after any two of its effects differed."""

    def __init__(self, max_attempts: int = 3):
        self.max_attempts = max_attempts
        self.status: dict[tuple, str] = {}
        self.attempts: dict[tuple, int] = {}
        self._effects: dict[tuple, list] = {}       # step key -> [effect, routes, diverged]

    def add(self, key: tuple) -> None:
        self.status.setdefault(key, PENDING)

    def open(self, key: tuple) -> bool:
        """Whether the item can still be taken."""
        return self.status.get(key, PENDING) in (PENDING, RETRYABLE)

    def claim(self, key: tuple) -> bool:
        """Mark the item running; False when it is not open."""
        if not self.open(key):
            return False
        self.status[key] = RUNNING
        return True

    def release(self, key: tuple) -> None:
        """A claimed item that was not attempted goes back to pending."""
        if self.status.get(key) == RUNNING:
            self.status[key] = PENDING

    def finish(self, key: tuple, status: str) -> None:
        self.status[key] = status

    def fail(self, key: tuple) -> bool:
        """Record one failed attempt; True when the item may be retried."""
        n = self.attempts[key] = self.attempts.get(key, 0) + 1
        retry = n < self.max_attempts
        self.status[key] = RETRYABLE if retry else FAILED
        return retry

    def observe(self, step_key: tuple, route: str, effect) -> None:
        entry = self._effects.get(step_key)
        if entry is None:
            self._effects[step_key] = [effect, {route}, False]
        elif entry[0] != effect:
            entry[2] = True
        else:
            entry[1].add(route)

    def performed(self, step_key: tuple) -> bool:
        return step_key in self._effects

    def established(self, step_key: tuple) -> bool:
        entry = self._effects.get(step_key)
        return entry is not None and not entry[2] and len(entry[1]) >= 2

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for status in self.status.values():
            out[status] = out.get(status, 0) + 1
        return dict(sorted(out.items()))


class Frontier:
    """The states still to explore, ordered by the structural key (scheduling only):
    a state on a route no known state is on goes first, then a state with a layout not
    seen before on a known route, then a variant of a known layout (the same layout,
    another execution state: ``?step=2``, another row count). A folded route holds at
    most ``per_route`` states; `excluded` counts, per route, the states refused for that
    (FR-CRAWL-31's coverage exclusion). Breadth first alone spent a whole budget on one
    page's overlays -- toasts, menus, tooltips, pagers -- and never explored the routes
    its side-nav opened (BUG-0501, measured on Juice Shop: 121 of 143 actions on its
    start page)."""

    def __init__(self, per_route: int):
        self.per_route = per_route
        self.new_routes: deque[State] = deque()
        self.new_layouts: deque[State] = deque()
        self.variants: deque[State] = deque()
        self.per: dict[str, int] = {}
        self.layouts: set[str] = set()
        self.excluded: dict[str, int] = {}

    def admit(self, state: State) -> bool:
        """Count ``state`` against its route's bound without queueing it (a state
        explored in place); False, counted in `excluded`, when the route is full."""
        route = normalise_route(state.url)
        n = self.per.get(route, 0)
        if n >= self.per_route:
            self.excluded[route] = self.excluded.get(route, 0) + 1
            return False
        self.per[route] = n + 1
        if state.structure:
            self.layouts.add(state.structure)
        return True

    def push(self, state: State) -> bool:
        """Queue ``state``; False when its route is already full."""
        first = self.per.get(normalise_route(state.url), 0) == 0
        new_layout = bool(state.structure) and state.structure not in self.layouts
        if not self.admit(state):
            return False
        queue = self.new_routes if first else (self.new_layouts if new_layout
                                               else self.variants)
        queue.append(state)
        return True

    def pop(self) -> State:
        for queue in (self.new_routes, self.new_layouts, self.variants):
            if queue:
                return queue.popleft()
        raise IndexError("pop from an empty frontier")

    def priority(self) -> bool:
        """Whether a state of a new route or a new layout is queued (ahead of the
        harvest); variants take turns with it (`Explorer._next_state`)."""
        return bool(self.new_routes or self.new_layouts)

    def __bool__(self) -> bool:
        return bool(self.new_routes or self.new_layouts or self.variants)


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
    #: Attempts of one action work item before it is recorded failed (FR-CRAWL-32).
    max_action_attempts: int = 3
    #: How deep states that cannot be replayed (reached by a non-idempotent step) are
    #: explored in place, one inside another (FR-CRAWL-33).
    max_live_depth: int = 3


#: The most workers a run may ask for (each is a browser).
#: FR-CRAWL-28: at most this many script path segments are kept per run.
MAX_SCRIPT_SEGMENTS = 20000
MAX_WORKERS = 8
#: Harvest loads taken per variant of a known layout, once no new route or layout is
#: queued (`Explorer._next_state`): a variant costs a restore and its steps, a load one
#: navigation.
HARVEST_PER_VARIANT = 4


@dataclass
class ExploreReport:
    states: int = 0
    actions: int = 0
    submissions: int = 0
    perturbations: int = 0
    refused: dict[str, int] = field(default_factory=dict)
    #: states whose restore failed (each counted once, by reason in `unresolved`)
    unrestorable: int = 0
    #: FR-CRAWL-33: unresolved states by reason -- ``route``, ``core``, ``markers`` (the
    #: contract did not hold), ``missing-step``, ``unsafe-step`` (a path step sent a
    #: non-idempotent request), ``replay-mutated``, ``navigation``, ``step-refused``,
    #: ``step-failed``, ``replay-error``, ``unreadable``, ``live-depth``
    unresolved: dict[str, int] = field(default_factory=dict)
    #: features declared optional, by evidence: ``first-visit`` (gone on a fresh second
    #: load of the start URL), ``dismissed`` (removed for good by its own control)
    optional_declared: dict[str, int] = field(default_factory=dict)
    #: replayed path steps skipped because their element is declared optional
    replay_skipped_optional: int = 0
    route_capped: int = 0
    #: FR-CRAWL-31: per folded route, states found and not explored because the route
    #: held `max_states_per_route` already (never claimed equivalent)
    coverage_excluded: dict[str, int] = field(default_factory=dict)
    #: states found and not explored because `max_states` was reached
    states_over_budget: int = 0
    #: states reached by a non-idempotent step, explored in place (never replayed)
    live_states: int = 0
    #: submit / Enter / perturbation steps whose filled values reached a request: what
    #: proves a submission happened (a "submit" step whose click did nothing is not one)
    submissions_sent: int = 0
    #: FR-CRAWL-32: steps skipped as equivalent (the same effect in states on two routes)
    chrome_skipped: int = 0
    #: steps scheduled after a state's own because they were taken in another state
    deprioritised: int = 0
    #: failed attempts retried, and work items that failed every attempt
    actions_retried: int = 0
    actions_failed: int = 0
    #: steps not taken because their state could not be restored in the middle of it
    steps_abandoned: int = 0
    #: elements past `max_same_signature` of one signature in a state: not acted on
    same_signature_capped: int = 0
    #: perturbation passes not run again for a form (route and field set) already
    #: perturbed: a bound on value variations, never on a form's submission
    perturbations_folded: int = 0
    #: the work items by final status (`WorkLedger.counts`)
    work: dict[str, int] = field(default_factory=dict)
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

    def refuse(self, why: str) -> None:
        self.refused[why] = self.refused.get(why, 0) + 1


class _Shared:
    """What every worker of one run shares, behind one lock (`Explorer.run`): the
    frontier, the states known (execution keys) and their layouts (structural keys),
    the work ledger, the declared optional features, the perturbed forms and denied
    steps, the action-id counter and the report. A worker holds its own browser,
    context, page, network-quiet tracking, action tag and session generation; nothing
    of those is shared."""

    def __init__(self, opts: ExploreOptions, report: ExploreReport):
        self.lock = threading.Condition(threading.RLock())
        self.frontier = Frontier(opts.max_states_per_route)
        #: execution keys of the states visited (FR-CRAWL-31: the visited-state check)
        self.known: set[str] = set()
        #: structural keys of those states: folding only (a harvest alias)
        self.structures: set[str] = set()
        self.work = WorkLedger(opts.max_action_attempts)
        #: signatures declared optional run-wide -> the evidence (FR-CRAWL-33)
        self.optional: dict[str, str] = {}
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
        #: harvest loads still due before the next variant (`Explorer._next_state`)
        self.harvest_credit = HARVEST_PER_VARIANT
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
        #: the session generation of this worker's context (FR-CRAWL-31's slot in the
        #: execution key): bumped when the context is rebuilt after a lost session
        self._generation = 0
        #: ``(method, url)`` of every request the page issues while an action or a
        #: replay is watched (None: not watching) -- what `Step.safe` is decided from
        self._watch: list[tuple[str, str]] | None = None
        self._restore_failure: str | None = None   # why the last restore failed
        self._mismatch: str | None = None          # the last `contract_mismatch`

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
        watch = self._watch
        if watch is not None:              # an out-of-scope or refused one counts too
            watch.append((str(getattr(req, "method", None) or "GET").upper(), req.url))
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
                    text = resp.text()
                    # read only once it was read: a body the driver let go is read
                    # from its next response (BUG-0539: a failure never consumes work)
                    shared.bodies_read.add(resp.url)
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

    def fingerprint(self, page, ctx) -> Reading:
        els = self.enumerate(page, ctx)
        marks = page.evaluate(_MARKS_JS)
        return self.reading(page.url, els, marks)

    def reading(self, url: str, els: list[dict], marks=()) -> Reading:
        """The two keys of a page (`fingerprint` module doc) from its read elements and
        page-level markers, in this worker's session generation."""
        markers = workflow_markers(els, marks)
        return Reading(key=execution_key(url, els, markers, self._generation),
                       structure=state_fingerprint(url, els), url=url, els=els,
                       counts=element_multiset(els), markers=markers)

    def settled_fingerprint(self, page, ctx) -> Reading | None:
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

    def act(self, page, ctx, el: dict, step: Step) -> str:
        """Perform one step on ``el``: `ACTED`, `ACT_REFUSED` (its form changes a
        credential) or `ACT_FAILED` (not actionable). A Playwright error on the way
        propagates (the caller maps it to a failed attempt, FR-CRAWL-32)."""
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
                return ACT_REFUSED
        self._tag(ctx, prefix)
        if step.kind == "enter":
            loc.press("Enter", timeout=3000)
            self.mark_activity()
            return ACTED
        try:
            loc.click(timeout=3000)
        except _pw_error():  # covered or detached: one dispatched click
            try:
                loc.dispatch_event("click", timeout=2000)
            except _pw_error():  # not actionable at all
                return ACT_FAILED
        self.mark_activity()
        return ACTED

    def _close_popups(self, ctx, page) -> None:
        # frozen and drained through the guard first (BUG-0504, `navguard.close_pages`)
        navguard.close_pages(ctx, [other for other in list(ctx.pages) if other is not page])

    def restore(self, page, ctx, state: State) -> bool:
        """Bring ``page`` back to ``state``: a fresh document of its entry URL, then its
        path replayed, then its recorded contract checked (`contract_mismatch`;
        FR-CRAWL-33). The page leaves for ``about:blank`` first: on a hash-routed app,
        navigating to ``/#/`` from ``/#/x`` is a same-document change, and the previous
        action's UI would survive the "restore" (measured on Juice Shop).

        Never accepted: a path holding a step recorded unsafe (it is not replayed at
        all); a path step whose element is missing, unless the element is declared
        optional (a dismissed notice: the skip is counted); a replay that sent a
        non-idempotent request; a page that does not hold the contract. On False,
        ``_restore_failure`` names the reason; ``state`` is never changed."""
        self._restore_failure = None
        if not state.replayable():
            self._restore_failure = "unsafe-step"
            return False
        self._tag(ctx, "restore")
        try:
            navguard.navigate(page, "about:blank", timeout_ms=self.opts.nav_timeout_ms)
            navguard.navigate(page, state.entry_url, timeout_ms=self.opts.nav_timeout_ms,
                              wait_until="load")
        except _pw_error():  # a refused or failed navigation: not restorable
            self._restore_failure = "navigation"
            return False
        self.mark_activity()
        self.wait_quiet(page)
        self._watch = []
        try:
            for step in state.path:
                el = self._find(self.enumerate(page, ctx), step)
                if el is None:
                    with self._shared.lock:
                        declared = step.signature in self._shared.optional
                    if not declared:
                        self._restore_failure = "missing-step"
                        return False
                    self._bump("replay_skipped_optional")   # its effect persists
                    continue
                outcome = self.act(page, ctx, el, step)
                if outcome != ACTED:
                    self._restore_failure = f"step-{outcome}"
                    return False
                self.wait_quiet(page)
                self._close_popups(ctx, page)
        except _pw_error():                 # the replay's page went away under it
            self._restore_failure = "replay-error"
            return False
        finally:
            sent, self._watch = self._watch or [], None
        if any(method not in IDEMPOTENT for method, _url in sent):
            self._restore_failure = "replay-mutated"
            return False
        got = self.settled_fingerprint(page, ctx)
        if got is not None and not self.reproduces(state, got):
            self.wait_quiet(page)                     # a render that lags its response
            got = self.settled_fingerprint(page, ctx)
        if got is None:
            self._restore_failure = "unreadable"
            return False
        if not self.reproduces(state, got):
            self._restore_failure = self._mismatch or "contract"
            return False
        return True

    def reproduces(self, state: State, got: Reading) -> bool:
        """Does the page read as ``got`` reproduce ``state`` (`contract_mismatch`, with
        the run's declared optional features)? Never changes ``state``."""
        with self._shared.lock:
            optional = frozenset(self._shared.optional)
        self._mismatch = contract_mismatch(state, got, optional)
        return self._mismatch is None

    def _log_action(self, action_id_seq: int, state: State, el: dict, step: Step,
                    new_fp: str | None, url: str | None = None) -> None:
        """One ``actions.jsonl`` line; ``seq`` is the action id's number (``act-<seq>``
        on its captured requests). ``url`` is the page's URL after the action, redacted
        (`redact_url`): a hash route's query lives only there, never in the capture.
        A form step lists its controls' names and types, never values: which fields a
        user could see (`store_adapter.import_disco` reads both). ``state`` and
        ``new_state`` are execution keys; ``replay_safe`` is `Step.safe` (FR-CRAWL-33)."""
        if self.actions_log is None:
            return
        # ``action_id``: the id its requests carry (``act-``, ``nav-``), BUG-0512
        rec = {"seq": action_id_seq, "action_id": self._tag_headers.get(ACTION_HEADER),
               "state": state.fp, "route": normalise_route(state.url),
               "signature": el["signature"], "occurrence": step.occurrence,
               "kind": step.kind,
               "label": str(el.get("label") or "")[:60], "new_state": new_fp,
               "url": redact_url(url) if url else None, "replay_safe": step.safe}
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
               "new_state": None, "url": redact_url(url), "replay_safe": None}
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
            self._bump("same_signature_capped")     # reported, never silent
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
        # container of its search box, and each re-perturbed it (BUG-0502). A bound on
        # value variations only: the form's submission is a step of every state.
        # the field *set*: a second identical dialog adds no value variation
        form_key = (route, tuple(sorted({(f["tag"], f["type"], f["name"], f["id"])
                                         for f in fields})))
        with self._shared.lock:
            if form_key in self._shared.perturbed:
                self.report.perturbations_folded += 1
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
        with shared.lock:
            self.report.work = shared.work.counts()
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
        """`restore` ``state``, else its fallback; on False ``_restore_failure`` is the
        first attempt's reason."""
        if self.restore(page, ctx, state):
            return True
        why = self._restore_failure
        if state.fallback is not None and self.restore(page, ctx, state.fallback):
            return True
        self._restore_failure = why
        return False

    def _unresolved(self, state: State, reason: str) -> None:
        """FR-CRAWL-33: ``state`` could not be brought back (or explored); its contract
        is kept as recorded and the reason reported."""
        state.unresolved = reason
        with self._shared.lock:
            self.report.unrestorable += 1
            self.report.unresolved[reason] = self.report.unresolved.get(reason, 0) + 1

    def _declare(self, signatures, evidence: str) -> None:
        """Declare ``signatures`` optional run-wide (FR-CRAWL-33), with the evidence."""
        with self._shared.lock:
            for sig in signatures:
                if sig not in self._shared.optional:
                    self._shared.optional[sig] = evidence
                    counts = self.report.optional_declared
                    counts[evidence] = counts.get(evidence, 0) + 1

    def _seed(self, page, ctx) -> None:
        """The start state: loaded, read, its first-visit features declared, queued (the
        caller holds `busy`)."""
        shared = self._shared
        self._tag(ctx, "nav")
        nav = navguard.navigate(page, self.start_url, timeout_ms=self.opts.nav_timeout_ms,
                                wait_until="load")
        self._document_first(nav.response, self.start_url)    # records the start document
        self.mark_activity()
        self.wait_quiet(page)
        got = self.settled_fingerprint(page, ctx)
        if got is None:
            self._unresolved(State("", self.start_url, self.start_url), "unreadable")
            return
        root = State.read(got, entry_url=page.url)
        self._gather(page)           # this document's bodies, before it is left
        self._first_visit(page, ctx, root, got)
        with shared.lock:
            shared.frontier.push(root)
            shared.known.add(root.fp)
            shared.structures.add(root.structure)
            self.report.states = 1
            # the origin's well-known files, read for the URLs they name
            from fuzzlab.core.linkextract import KNOWN_FILES
            for path in KNOWN_FILES:
                url = urljoin(self.start_url, path)
                if url not in shared.requested:
                    shared.harvest.setdefault(url, None)
        self._gather(page)

    def _first_visit(self, page, ctx, root: State, first: Reading) -> None:
        """Declare what the start document shows on the first visit only (FR-CRAWL-33):
        a fresh second load of it is read (`restore` with an empty path: about:blank,
        then the URL), and each element the first load held more often than the second
        is declared optional for ``root`` (``first-visit``; run-wide when it is gone
        altogether), each marker it lost too. A one-time welcome dialog (measured on
        Juice Shop, BUG-0501) is declared here, when the state is recorded -- never
        inferred later from what a restore happened to show."""
        self.restore(page, ctx, root)       # its verdict is not the point: the read is
        again = self.settled_fingerprint(page, ctx)
        if again is None or execution_route(again.url) != execution_route(first.url):
            return
        have = dict(again.counts)
        root.optional = tuple((sig, n - have.get(sig, 0)) for sig, n in first.counts
                              if have.get(sig, 0) < n)
        shown = set(again.markers)
        root.optional_markers = tuple(m for m in first.markers if m not in shown)
        self._declare([sig for sig, _n in root.optional if sig not in have], "first-visit")

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
                        self.report.states_over_budget += 1     # reported, not explored
                if shared.frontier.priority():
                    shared.busy += 1
                    return shared.frontier.pop()
                # a variant of a known layout and harvest loads take turns, weighted by
                # cost (a variant is a restore and its steps, a load one navigation): a
                # list that grows a row per click makes a new state each time
                # (FR-CRAWL-31), and the harvest waited for an empty frontier (BUG-0539)
                for turn in (("harvest", "variant") if shared.harvest_credit > 0
                             else ("variant", "harvest")):
                    if turn == "variant" and shared.frontier:
                        shared.harvest_credit = HARVEST_PER_VARIANT
                        shared.busy += 1
                        return shared.frontier.pop()
                    if turn == "harvest":
                        url = self._next_harvest()
                        if url is not None:
                            shared.harvest_credit = max(0, shared.harvest_credit - 1)
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
                state = State.read(got, entry_url=page.url)
                with shared.lock:
                    if got.key not in shared.known:
                        if shared.frontier.push(state):
                            shared.known.add(got.key)
                            shared.structures.add(got.structure)
                            self.report.harvest_states += 1
                            self.report.states = len(shared.known)
                            shared.lock.notify_all()
                        else:
                            self._excluded(state)
        self._gather(page)
        return page

    def _excluded(self, state: State) -> None:
        """A state its folded route's bound refused (the caller holds the lock):
        reported per route (FR-CRAWL-31), never taken for a known one."""
        route = normalise_route(state.url)
        self.report.route_capped += 1
        self.report.coverage_excluded[route] = self.report.coverage_excluded.get(route, 0) + 1

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
        is the first path's), or the rendered state, read as if at ``first``, has the
        layout of a state already known (a soft 404, a catch-all): a fold, so the
        structural key decides it (FR-CRAWL-31). A history-mode route renders another
        view from the same shell: not an alias, explored."""
        if self._hash_routed(page):
            return True
        if got is None:
            return False
        rebased = urlunsplit(urlsplit(page.url)._replace(path=first))
        with self._shared.lock:
            return state_fingerprint(rebased, got.els) in self._shared.structures

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
        # A step's work is per execution state (FR-CRAWL-32): the same Next in a
        # dialog's second stage is new work there. A step already taken in another
        # state is scheduled after the state's own (BUG-0502's budget: 7 Juice Shop
        # header buttons were re-acted in each of 60 states), and skipped only once
        # states on two routes gave it the same observed effect.
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
        """Explore one frontier state: restore it, then its pending steps
        (`_explore_here`). A state that cannot be restored is unresolved (FR-CRAWL-33).
        Returns the page to go on with (a lost session rebuilds the context)."""
        if not self._restore_any(page, self._ctx, state):
            self._unresolved(state, self._restore_failure or "restore")
            return page
        return self._explore_here(state, page, browser, pw, depth=0)

    def _pending(self, page, state: State, els: list[dict]) -> list[tuple[dict, Step]]:
        """The state's open work (FR-CRAWL-32): its steps whose work item is pending or
        retryable, the steps never taken anywhere first, then those taken in another
        state (deprioritised, never dropped)."""
        route = normalise_route(state.url)
        steps = [(el, step) for el in els for step in self._steps_for(page, el, route)]
        shared = self._shared
        with shared.lock:
            todo = [(el, s) for el, s in steps if shared.work.open(work_key(state.fp, s))]
            for _el, s in todo:
                shared.work.add(work_key(state.fp, s))
            fresh = [p for p in todo if not shared.work.performed(p[1].key())]
            repeats = [p for p in todo if shared.work.performed(p[1].key())]
            self.report.deprioritised += len(repeats)
        return fresh + repeats

    def _explore_here(self, state: State, page, browser, pw, *, depth: int):
        """Take ``state``'s pending steps; the page is in ``state`` now. Between two
        steps the state is restored when the first changed the page. Returns the page
        to go on with."""
        shared = self._shared
        authenticated = self.storage_state is not None and \
            not looks_like_login_url(self.start_url)
        got = self.settled_fingerprint(page, self._ctx)
        if got is None:
            self._unresolved(state, "unreadable")
            return page
        self._seen_as(state, got)
        self._gather(page)
        route = normalise_route(state.url)
        pending = deque(self._pending(page, state, got.els))
        dirty = False
        while pending:
            el_desc, step = pending.popleft()
            key = work_key(state.fp, step)
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
                if step.key() in shared.denied or not shared.work.open(key):
                    continue
                if shared.work.established(step.key()):
                    shared.work.finish(key, EQUIVALENT)
                    self.report.chrome_skipped += 1
                    continue
                shared.work.claim(key)
            why = refusal(el_desc, self.opts.deny)
            if why:
                self._refuse(why)
                self._finish(key, REFUSED)
                continue
            ctx = self._ctx
            if dirty and not self._restore_any(page, ctx, state):
                with shared.lock:
                    shared.work.release(key)
                    self.report.steps_abandoned += 1 + len(pending)
                self._unresolved(state, self._restore_failure or "restore")
                break
            dirty = False
            now = self.settled_fingerprint(page, ctx)     # the page just before the step
            if now is not None:
                self._seen_as(state, now)
            el = self._find(now.els, step) if now else None
            before_url = page.url
            outcome = ACT_FAILED                 # the element is not there to act on
            if el is not None:
                self._watch = []
                try:
                    outcome = self.act(page, ctx, el, step)
                except _pw_error() as exc:  # one attempt failing ends only it
                    logging.info("disco: action failed (%s)", type(exc).__name__)
            if outcome != ACTED:
                self._watch = None
                if outcome == ACT_REFUSED:
                    self._finish(key, REFUSED)
                else:
                    self._attempt_failed(key, el_desc, step, pending)
                    dirty = True
                continue
            with shared.lock:
                shared.work.finish(key, SUCCEEDED)
                self.report.actions += 1
                if step.kind in ("submit", "enter"):
                    self.report.submissions += 1
                elif step.kind.startswith("perturb:"):
                    self.report.perturbations += 1
            self.wait_quiet(page)
            sent, self._watch = self._watch or [], None
            step = replace(step, safe=all(m in IDEMPOTENT for m, _u in sent))
            if step.kind != "click" and self._values_sent:
                self._bump("submissions_sent")
                if has_captcha(self._last_fields):
                    self._bump("captcha_submissions")
            self._fill_values = []
            self._close_popups(self._ctx, page)
            if authenticated and looks_like_login_url(page.url):
                with shared.lock:
                    self.report.session_lost += 1
                    shared.denied.add(step.key())
                navguard.release(self._ctx)
                self._ctx = self._new_context(browser, pw)
                self._generation += 1             # FR-CRAWL-31's session generation
                page = self._ctx.new_page()
                dirty = True
                self._log_action(self._action_seq, state, el, step, None)
                continue
            after = self.settled_fingerprint(page, self._ctx)
            if after is None:
                self._bump("errors")
                dirty = True
                continue
            self._observe(route, step, sent, now, after)
            self._dismissal(now, after, step, before_url, page.url)
            self._gather(page)
            self._log_action(self._action_seq, state, el, step, after.key, url=page.url)
            if after.key != now.key:          # the step changed the page it acted on
                dirty = True
                new = self._child(state, step, after, before_url, page.url)
                live = not step.safe or not new.replayable()
                page = self._admit(new, page, browser, pw, live=live, depth=depth)
        return page

    def _finish(self, key: tuple, status: str) -> None:
        with self._shared.lock:
            self._shared.work.finish(key, status)

    def _attempt_failed(self, key: tuple, el_desc: dict, step: Step, pending) -> None:
        """FR-CRAWL-32: a failed attempt never consumes the work. It is queued again
        (after a restore) until it has failed ``max_action_attempts`` times, then it is
        recorded failed and reported."""
        with self._shared.lock:
            retry = self._shared.work.fail(key)
            self.report.errors += 1
            if retry:
                self.report.actions_retried += 1
            else:
                self.report.actions_failed += 1
        if retry:
            pending.append((el_desc, step))

    def _seen_as(self, state: State, got: Reading) -> None:
        """``got`` is ``state`` as the page shows it now (the state itself, or a restore
        its recorded contract accepted, FR-CRAWL-33): its key is visited too, so a step
        that leads back to it is no new state."""
        if got.key != state.fp:
            with self._shared.lock:
                self._shared.known.add(got.key)

    def _observe(self, route: str, step: Step, sent, before: Reading,
                 after: Reading) -> None:
        """Record the step's effect: the requests it made (method and folded route) and
        its transition -- none, or the state it led to -- judged against the page just
        before it (a start page read with its first-visit dialog is restored without
        it: every step there would otherwise be a transition)."""
        transition = "same" if after.key == before.key else after.key
        effect = (tuple(sorted({(m, normalise_route(u)) for m, u in sent})), transition)
        with self._shared.lock:
            self._shared.work.observe(step.key(), route, effect)

    def _dismissal(self, before: Reading | None, after: Reading, step: Step,
                   before_url: str, after_url: str) -> None:
        """Declare a dismissed feature optional (FR-CRAWL-33): a click, with no
        navigation, that removed its own element's signature and only removed (nothing
        new, nothing more often) -- a notice's "Got it", a banner's close. What it
        removed altogether is declared ``dismissed`` run-wide: once gone for good, it
        is not mandatory in any state's contract."""
        if step.kind != "click" or before is None or after_url != before_url:
            return
        was, now = dict(before.counts), dict(after.counts)
        if any(n > was.get(sig, 0) for sig, n in now.items()):
            return
        gone = [sig for sig in was if sig not in now]
        if step.signature in gone:
            self._declare(gone, "dismissed")

    def _child(self, state: State, step: Step, after: Reading, before_url: str,
               after_url: str) -> State:
        """The state ``step`` led to from ``state``: by its own URL when the step
        navigated (its path the fallback: a page only a POST shows), else by
        ``state``'s path plus ``step``."""
        path = [*state.path, step]
        if after_url != before_url:
            return State.read(after, entry_url=after_url,
                              fallback=State.read(after, entry_url=state.entry_url,
                                                  path=path))
        return State.read(after, entry_url=state.entry_url, path=path)

    def _admit(self, new: State, page, browser, pw, *, live: bool, depth: int):
        """A state a step led to: known (nothing), over a budget or its route's bound
        (reported), queued -- or, when it cannot be replayed (``live``: reached by a
        non-idempotent step), explored in place now, to ``max_live_depth`` (FR-CRAWL-33).
        Returns the page to go on with."""
        shared = self._shared
        with shared.lock:
            if new.fp in shared.known:
                return page
            if self._explored_states() >= self.opts.max_states:
                self._note_budget("max_states")
                self.report.states_over_budget += 1
                return page
            admitted = shared.frontier.admit(new) if live else shared.frontier.push(new)
            if not admitted:
                self._excluded(new)
                return page
            shared.known.add(new.fp)
            shared.structures.add(new.structure)
            self.report.states = len(shared.known)
            if live:
                self.report.live_states += 1
            shared.lock.notify_all()
        if not live:
            return page
        if depth + 1 > self.opts.max_live_depth:
            self._unresolved(new, "live-depth")
            return page
        return self._explore_here(new, page, browser, pw, depth=depth + 1)
