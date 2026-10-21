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
it. A delegated candidate (FR-CRAWL-40) is no part of either key or of a state's
contract (`fingerprint.counts_for_state`): which text leaves are candidates varies
with their text and order (BUG-0551 review B2 and R7). The structural key
(`fingerprint.state_fingerprint`: folded route, set of signatures) only schedules and
folds: the frontier explores a new route, then a new layout, then a variant of a known
layout, and holds at most ``max_states_per_route`` states per folded route -- the rest
are reported (`coverage_excluded`), never claimed equivalent.

**Work** (FR-CRAWL-32). An action's work key is ``(execution key, element signature,
occurrence, kind)``, tracked by `WorkLedger` as pending, running, succeeded, refused,
retryable or failed (a delegated candidate's also inert: its trial's verdict). A failure
never consumes the work: it is retried up to ``max_action_attempts`` times, then
recorded failed and reported. A step already taken
in another state is scheduled after this state's own steps (deprioritised); it is
skipped only once two states on two routes gave it the same observed effect (requests
and transition).

**Restore** (FR-CRAWL-33). A state is restored by navigating to its entry URL and
replaying the path of actions that led to it, then checking its recorded contract
(`contract_mismatch`): the exact route, every element exactly as many times as recorded
(neither a subset nor a superset), every workflow marker and no other. The contract is
never rewritten or narrowed; a feature is optional only when declared so with evidence
(shown on the first visit only; on the entry document, dismissed for good by its own
control, confirmed by a fresh load), and never one the state's own last step added. A
step is taken only on a page that holds its state's contract. A path step whose
element is missing fails the restore unless the element is declared optional. A path
holding a step that sent a
non-idempotent request is never replayed: the state it reached is explored in place,
when it is reached, and later restores of it are unresolved. A failed restore marks
the state unresolved with its reason (`unresolved`).

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
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from fuzzlab.core.comparability import AUTH_FAILURE, POLICY_BLOCK, response_class
from fuzzlab.core.redaction import redact_url
from fuzzlab.core.urls import (destructive_reason, document_key, in_origin_scope,
                               origin_scope, spa_route, text_destructive_reason)
from fuzzlab.disco import compose, formfill
from fuzzlab.disco.capture import ACTION_HEADER
from fuzzlab.disco.fingerprint import (element_multiset, element_signature, execution_key,
                                       execution_route, normalise_route,
                                       state_fingerprint, workflow_markers)
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


#: The enumeration's page scripts and bounds live in `compose` (FR-CRAWL-39): the
#: composed read (`compose.READ_JS`, which also reads each element's ``sel`` and each
#: document's page-level workflow markers, FR-CRAWL-31) and a submitter's form controls,
#: marked ``data-disco-field`` across the document's open shadow roots.
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

    ``fp`` is the execution key. ``core`` (the element multiset: never a delegated
    candidate's, `fingerprint.element_multiset`) and ``markers`` are the state's
    contract, recorded when it was first read and **never rewritten**
    (FR-CRAWL-33, BUG-0539: narrowing them to what a restore showed accepted a wrong
    state and weakened it for good). ``optional`` lists ``(signature, count)`` declared
    optional for this state and ``optional_markers`` its declared optional markers:
    only the start state declares any, from a fresh second load (`Explorer._seed`).
    Run-wide declarations (a dismissed notice) live in `_Shared.optional`. ``added``
    lists the signatures the last step of ``path`` added: a run-wide declaration never
    excuses them (review B1: a modal its own Close removed elsewhere is still this
    state's modal). ``unresolved`` is the reason a restore of it failed, once one did."""
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
    added: tuple = ()
    #: FR-CRAWL-41: the state showed a password form when it was found (an authenticated
    #: run): a restore that shows one is the state's own page, never a sign of a loss
    login_shown: bool = False

    @classmethod
    def read(cls, got: Reading, *, entry_url: str, path=None,
             fallback: "State | None" = None, added=(), login_shown: bool = False) -> "State":
        """A state recorded from ``got``: its contract is what ``got`` shows."""
        return cls(got.key, got.url, entry_url, list(path or []), fallback,
                   core=got.counts, markers=got.markers, structure=got.structure,
                   added=tuple(added), login_shown=login_shown)

    def replayable(self) -> bool:
        """Whether ``path`` holds only steps recorded safe to repeat."""
        return all(step.safe for step in self.path)


def contract_mismatch(state: State, got: Reading, optional=frozenset()) -> str | None:
    """Why ``got`` does not reproduce ``state`` (FR-CRAWL-33), or None when it does:

    * ``route``: the exact route (`fingerprint.execution_route`) differs;
    * ``core``: a mandatory element is missing, or present fewer times than recorded --
      a proper subset is never accepted;
    * ``extra``: an element is present more times than recorded, or a workflow marker
      the contract lacks is shown -- a superset is never accepted either (review B2: a
      server that moved on shows a later stage, the earlier stage's controls and more);
    * ``markers``: a recorded workflow marker is not shown.

    What is declared optional is excused both ways: ``optional`` (run-wide declared
    signatures, with their markers) -- never one the state's own last path step added
    (``state.added``) -- and the state's own ``optional`` counts and
    ``optional_markers``. A notice shown again in another worker's fresh context is
    declared (first visit, dismissed), so it reproduces. Nothing here changes
    ``state``."""
    if got.key == state.fp:
        return None
    if execution_route(got.url) != execution_route(state.url):
        return "route"
    excused = frozenset(optional) - frozenset(state.added)
    have, core, own = dict(got.counts), dict(state.core), dict(state.optional)
    for sig, n in core.items():
        if sig not in excused and have.get(sig, 0) < n - own.get(sig, 0):
            return "core"
    for sig, n in have.items():
        if sig not in excused and n > core.get(sig, 0):
            return "extra"
    shown, recorded = set(got.markers), set(state.markers)
    skip = tuple(f"el:{sig}#" for sig in excused)
    for mark in sorted(recorded - shown):
        if mark not in state.optional_markers and not (skip and mark.startswith(skip)):
            return "markers"
    for mark in sorted(shown - recorded):
        if mark not in state.optional_markers and not (skip and mark.startswith(skip)):
            return "extra"
    return None


#: A work item's status (FR-CRAWL-32). ``equivalent``: skipped because two states on two
#: routes gave the step the same observed effect. ``inert``: a delegated candidate whose
#: trial click caused nothing (FR-CRAWL-40) -- finished by that observed verdict, never
#: by a failure.
PENDING, RUNNING, SUCCEEDED, REFUSED = "pending", "running", "succeeded", "refused"
RETRYABLE, FAILED, EQUIVALENT, INERT = "retryable", "failed", "equivalent", "inert"
#: `Explorer.act`'s outcomes. A delegated candidate (`Explorer._act_delegated`) may also
#: be `ACT_INERT` (its run-wide verdict is inert) or `ACT_UNEXPLORED` (the run's trials
#: are spent: counted ``delegated_unexplored``; its work item stays pending, never done).
ACTED, ACT_REFUSED, ACT_FAILED = "acted", "refused", "failed"
ACT_INERT, ACT_UNEXPLORED = "inert", "unexplored"


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
    #: FR-CRAWL-41: fresh sessions a run takes after losses before its authenticated
    #: exploration ends (each one a login through the session provider).
    max_session_recoveries: int = 3


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
    #: FR-CRAWL-33: unresolved states by reason -- ``route``, ``core``, ``extra``,
    #: ``markers`` (the contract did not hold), ``missing-step``, ``unsafe-step`` (a path step sent a
    #: non-idempotent request), ``replay-mutated``, ``navigation``, ``step-refused``,
    #: ``step-failed``, ``replay-error``, ``unreadable``, ``live-depth``; ``session-lost``
    #: (FR-CRAWL-41: its restore was lost again on the recovered session)
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
        #: delegated candidates' verdicts and the composed reads' coverage (FR-CRAWL-39/40)
        self.trials = compose.Trials(compose.MAX_DELEGATED_TRIALS)
        self.coverage = compose.Coverage()
        #: per route, the `request_key`s no longer evidence for a delegated trial: what a
        #: control window saw (the page's own traffic) and what a trial already counted
        #: (`Explorer._trial`)
        self.explained: dict[str, set[tuple[str, str]]] = {}
        #: the page shapes whose closed shadow roots were counted (`compose._census`)
        self.censused: set = set()

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
        #: the session generation of this worker's context (FR-CRAWL-31's slot in the
        #: execution key): bumped when the context is rebuilt after a lost session
        #: (`_replace_context`, FR-CRAWL-41)
        self._generation = 0
        #: ``(method, url)`` of every request the page issues while an action or a
        #: replay is watched (None: not watching) -- what `Step.safe` is decided from
        self._watch: list[tuple[str, str]] | None = None
        self._restore_failure: str | None = None   # why the last restore failed
        self._mismatch: str | None = None          # the last `contract_mismatch`
        #: the delegated candidate whose trial `act` just decided (FR-CRAWL-40): its
        #: verdict is reopened when the session checkpoint finds the window lost
        self._trialled: str | None = None
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
        watch = self._watch
        if watch is not None:              # an out-of-scope or refused one counts too
            watch.append((str(getattr(req, "method", None) or "GET").upper(), req.url))
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
        self._generation += 1             # FR-CRAWL-31's session generation slot
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

    def _lost_window(self, key: tuple, state: "State", el: dict, step: "Step",
                     outcome) -> None:
        """An action whose answers fell in a known-lost window (FR-CRAWL-41): denied
        unless the window was stale and logged with no new state (`_lost_action`); its
        work item finished, its effect a lost session (FR-CRAWL-32). The context it ran
        in was replaced (`_replace_context`: another generation, FR-CRAWL-31) or the
        authenticated exploration ended."""
        self._lost_action(state, el, step, outcome)
        self._finish(key, SUCCEEDED)

    def _reopen_trial(self, sig: str) -> None:
        """A delegated trial observed in a known-lost window decides nothing (D'): the
        candidate is untried again, its trial and its inert count taken back."""
        with self._shared.lock:
            if self._shared.trials.reopen(sig):
                self.report.delegated_trials -= 1
                self.report.delegated_inert -= 1

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
        if lost is not None:
            self._restore_failure = "session-lost"
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
        """The page's actionable elements across its composed tree (`_read`)."""
        return self._read(page, ctx).elements

    def _read(self, page, ctx) -> compose.PageRead:
        """The page's composed read (`compose.read_page`, FR-CRAWL-39): its actionable
        elements, each marked ``data-disco-id`` in its own document and carrying
        ``frame`` (the frame-marker keys `_locate` follows) and ``sel`` (its workflow
        marker, FR-CRAWL-31), and its documents' page-level markers (``marks``). A
        delegated candidate already found inert, or never tried once the run's trials
        are spent, is described ``disabled``: kept, so the read stays a function of the
        page, never acted on (FR-CRAWL-40). What the read could not reach is counted in
        the report."""
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
        return read

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

    def fingerprint(self, page, ctx) -> Reading:
        """The page read once (`_read`: its elements and page markers, one snapshot) as
        its two keys (`reading`)."""
        read = self._read(page, ctx)
        return self.reading(page.url, read.elements, read.marks)

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

    def act(self, page, ctx, el: dict, step: Step) -> str:
        """Perform one step on ``el``: `ACTED`, `ACT_REFUSED` (its form changes a
        credential) or `ACT_FAILED` (not actionable); a delegated candidate also
        `ACT_INERT` or `ACT_UNEXPLORED` (`_act_delegated`). A Playwright error on the way
        propagates (the caller maps it to a failed attempt, FR-CRAWL-32)."""
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
                return ACT_REFUSED
        if step.kind == "enter":
            self._tag(ctx, prefix)
            loc.press("Enter", timeout=3000)
            self.mark_activity()
            return ACTED
        return self._click(ctx, loc, prefix)

    def _click(self, ctx, loc, prefix: str) -> str:
        """Tag the next action and click ``loc``: `ACTED`, or `ACT_FAILED` when it is
        not actionable at all."""
        self._tag(ctx, prefix)
        try:
            loc.click(timeout=3000)
        except _pw_error():  # covered or detached: one dispatched click
            try:
                loc.dispatch_event("click", timeout=2000)
            except _pw_error():  # not actionable at all
                return ACT_FAILED
        self.mark_activity()
        return ACTED

    def _act_delegated(self, page, ctx, el: dict, step: Step) -> str:
        """A delegated candidate (FR-CRAWL-40): clicked when already found live; tried
        once when untried (`_trial`), and kept -- `ACTED`, performed -- only when the
        click caused a request or changed the state; never acted on once inert
        (`ACT_INERT`: its work is finished by that verdict) or once the run's trials are
        spent (`ACT_UNEXPLORED`, counted). A trial that clicked nothing (the candidate
        gone, or not actionable) and one another worker is running are `ACT_FAILED`: a
        failed attempt, retried (FR-CRAWL-32), never a verdict."""
        sig = el["signature"]
        self._trialled = None
        with self._shared.lock:
            claim = self._shared.trials.claim(sig)
            self.report.delegated_unexplored = len(self._shared.trials.unexplored)
        if claim == "live":
            return self._click(ctx, self._locate(page, el), "act")
        if claim == "inert":
            return ACT_INERT
        if claim == "spent":
            return ACT_UNEXPLORED
        if claim != "trial":                       # another worker is trying it
            return ACT_FAILED
        live = None
        try:
            live = self._trial(page, ctx, step)
        finally:
            with self._shared.lock:
                if live is None:                  # nothing was clicked
                    self._shared.trials.release(sig)
                else:
                    self._shared.trials.decide(sig, live)
                    self._trialled = sig
                    self.report.delegated_trials += 1
                    if live:
                        self.report.delegated_live += 1
                    else:
                        self.report.delegated_inert += 1
        if live is None:
            return ACT_FAILED
        return ACTED if live else ACT_INERT

    def _trial(self, page, ctx, step: Step) -> bool | None:
        """Click a delegated candidate and observe whether the click caused a request,
        the page's URL changed, a page opened, or the state changed; None when nothing
        was clicked (the candidate was gone before its click, or no click reached it: a
        failed attempt, never a verdict, FR-CRAWL-32). The readings are the explorer's
        own (`settled_fingerprint`), before and after, so "changed the state" means what
        it means everywhere else in the run: another execution key (FR-CRAWL-31).

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
            target = self._find(before.els, step) if before else None
            if target is None:
                return None
            url, pages = page.url, len(ctx.pages)
            control = set(seen)
            seen.clear()
            if self._watch is not None:            # the step's requests are its click's:
                self._watch.clear()                # the control window's are the page's
            if self._click(ctx, self._locate(page, target), "act") != ACTED:
                return None                        # no click reached it: not a verdict
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
            or after is None or after.key != before.key

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
            self._unresolved(State("", self.start_url, self.start_url), "unreadable")
            return
        root = State.read(got, entry_url=page.url,
                          login_shown=authenticated and self._shows_login(page))
        self._gather(page)           # this document's bodies, before it is left
        page = self._first_visit(page, ctx, root, got)
        if shared.stop is not None:  # FR-CRAWL-41: the session ended on its reload
            return
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

    def _first_visit(self, page, ctx, root: State, first: Reading):
        """Declare what the start document shows on the first visit only (FR-CRAWL-33):
        a fresh second load of it is read (`restore` with an empty path: about:blank,
        then the URL), and each element the first load held more often than the second
        is declared optional for ``root`` (``first-visit``; run-wide when it is gone
        altogether), each marker it lost too. A one-time welcome dialog (measured on
        Juice Shop, BUG-0501) is declared here, when the state is recorded -- never
        inferred later from what a restore happened to show. In an authenticated run
        the second load is session-checked first (FR-CRAWL-41): a load in a known-lost
        window declares nothing (D'). Returns the page to go on with."""
        self.restore(page, ctx, root)       # its verdict is not the point: the read is
        if self._authenticated():
            page, lost = self._session_checkpoint(
                page, asked=root.url, places=(root.url, root.entry_url),
                login_shown=root.login_shown)
            if lost is not None:
                return page
        again = self.settled_fingerprint(page, ctx)
        if again is None or execution_route(again.url) != execution_route(first.url):
            return page
        have = dict(again.counts)
        root.optional = tuple((sig, n - have.get(sig, 0)) for sig, n in first.counts
                              if have.get(sig, 0) < n)
        shown = set(again.markers)
        root.optional_markers = tuple(m for m in first.markers if m not in shown)
        self._declare([sig for sig, _n in root.optional if sig not in have], "first-visit")
        return page

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
                state = State.read(got, entry_url=page.url,
                                   login_shown=authenticated and self._shows_login(page))
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
        """Explore one frontier state: restore it on a current session
        (`_restore_checked`, FR-CRAWL-41), then its pending steps (`_explore_here`). A state
        that cannot be restored is unresolved (FR-CRAWL-33). Returns the page to go on with
        (a lost session replaces the context)."""
        page, restored = self._restore_checked(page, state)
        if self._shared.stop is not None:
            return page
        if not restored:
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
        steps the state is restored when the first changed the page, and never acted on
        on a session that is gone (FR-CRAWL-41: `_bring_to`). Returns the page to go on
        with (a lost session replaces the context)."""
        shared = self._shared
        authenticated = self._authenticated()
        page, got = self._bring_to(state, page, restore=False)
        if got is None and shared.stop is not None:
            return page
        if got is None:
            self._unresolved(state, self._restore_failure or "unreadable")
            return page
        login_shown = authenticated and (state.login_shown or self._shows_login(page))
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
            # the page just before the step, holding the state's contract (restored
            # when the last step changed it, or when it drifted since: review B2), on a
            # session that is not gone (FR-CRAWL-41, BUG-0552 review B1)
            page, now = self._bring_to(state, page, restore=dirty)
            ctx = self._ctx
            if now is None:
                with shared.lock:
                    shared.work.release(key)
                    if shared.stop is None:
                        self.report.steps_abandoned += 1 + len(pending)
                if shared.stop is not None:
                    return page
                self._unresolved(state, self._restore_failure or "restore")
                break
            dirty = False
            el = self._find(now.els, step)
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
                elif outcome == ACT_INERT:      # a trial's verdict (FR-CRAWL-40): its
                    trialled, self._trialled = self._trialled, None   # click changed
                    if authenticated and trialled is not None:        # nothing
                        page, lost = self._session_checkpoint(
                            page, login_shown=login_shown, before_url=before_url,
                            action=True)
                        if lost is not None:    # observed in a known-lost window: no
                            self._reopen_trial(trialled)    # verdict (D', FR-CRAWL-41)
                            self._lost_window(key, state, el, step, lost)
                            if shared.stop is not None:
                                return page
                            dirty = True
                            continue
                    self._finish(key, INERT)    # never logged
                elif outcome == ACT_UNEXPLORED:     # the run's trials are spent: counted
                    with shared.lock:               # (delegated_unexplored), not done
                        shared.work.release(key)
                else:
                    self._attempt_failed(key, el_desc, step, pending)
                    dirty = True
                continue
            with shared.lock:            # performed; the work item finishes once its
                self.report.actions += 1  # effect was read (review B3)
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
            if authenticated:          # FR-CRAWL-41 (BUG-0552): was the session lost?
                page, lost = self._session_checkpoint(
                    page, asked=el.get("href") or None, login_shown=login_shown,
                    before_url=before_url, action=True)
                if lost is not None:
                    self._lost_window(key, state, el, step, lost)
                    if shared.stop is not None:
                        return page
                    dirty = True
                    continue
            after = self.settled_fingerprint(page, self._ctx)
            if after is None:                 # its effect could not be read (review B3)
                dirty = True
                if step.safe:                 # repeatable: a failed attempt, retried
                    self._attempt_failed(key, el_desc, step, pending)
                else:                         # a non-idempotent request went: never again
                    with shared.lock:
                        shared.work.finish(key, FAILED)
                        self.report.errors += 1
                        self.report.unresolved["unreadable"] = \
                            self.report.unresolved.get("unreadable", 0) + 1
                    self._log_action(self._action_seq, state, el, step, None)
                continue
            self._finish(key, SUCCEEDED)
            self._observe(route, step, sent, now, after)
            self._gather(page)
            self._log_action(self._action_seq, state, el, step, after.key, url=page.url)
            after_url = page.url
            # read before a dismissal's check reloads the page (FR-CRAWL-41)
            shown = authenticated and after.key != now.key and self._shows_login(page)
            # a dismissal's check reloads the entry document; it runs only for a safe
            # step from a state with no path, whose child is queued, never in place
            if self._dismissal(state, now, after, step, before_url, page):
                dirty = True
            if after.key != now.key:          # the step changed the page it acted on
                dirty = True
                new = self._child(state, step, now, after, before_url, after_url,
                                  login_shown=shown)
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

    def _bring_to(self, state: State, page, *, restore: bool):
        """``(page, reading)``: the page to go on with, read as ``state`` -- or a None
        reading (``_restore_failure`` says why). Restored first when ``restore``, or when
        the page no longer holds the state's contract (a late render, a server that moved
        on): a step is taken, and logged under the state's key, only on a page the
        contract accepted (review B2). The reading is then that state (`_seen_as`).

        In an authenticated run (FR-CRAWL-41, BUG-0552 review B1) never on a session
        that is gone: a restore goes through `_restore_checked` (the session adopted
        first, then checked), and the session is checked again after the read -- a
        loss another worker found meanwhile means one more restore on the adopted
        session; a second one leaves the state (``session-lost``)."""
        authenticated = self._authenticated()
        for _attempt in range(2):
            if authenticated and self._generation_gone():
                restore = True                 # `_restore_checked` adopts the session first
            if not restore:
                got = self.settled_fingerprint(page, self._ctx)
                if got is not None and (got.key == state.fp or self.reproduces(state, got)):
                    if not (authenticated and self._generation_gone()):
                        self._seen_as(state, got)
                        return page, got
                    restore = True
                    continue
            page, restored = self._restore_checked(page, state)
            if not restored:
                return page, None
            got = self.settled_fingerprint(page, self._ctx)
            if got is None:
                self._restore_failure = "unreadable"
                return page, None
            if got.key != state.fp and not self.reproduces(state, got):
                self._restore_failure = self._mismatch or "contract"
                return page, None
            if authenticated and self._generation_gone():
                restore = True
                continue
            self._seen_as(state, got)
            return page, got
        self._restore_failure = "session-lost"
        return page, None

    def _seen_as(self, state: State, got: Reading) -> None:
        """``got`` is ``state`` as the page shows it now: the state itself, or a page its
        recorded contract accepted (`_bring_to` calls it with no other reading). Its key
        is visited too, so a step that leads back to it is no new state."""
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

    def _dismissal(self, state: State, before: Reading, after: Reading, step: Step,
                   before_url: str, page) -> bool:
        """Declare a dismissed feature optional (FR-CRAWL-33), on evidence only (review
        B1: one click that closed a modal made the modal optional in every contract):

        * the state is an entry document as loaded (no path), and what the click
          removed was all in its recorded contract -- never a control a step added;
        * the step is a safe click (no non-idempotent request), with no navigation,
          that removed its own element's signature and only removed (nothing new,
          nothing more often): a notice's "Got it", a banner's close;
        * a fresh load of the entry URL (`restore`, empty path) still shows none of
          it: its effect persists.

        Then what it removed altogether is declared ``dismissed`` run-wide. Returns
        whether the page was reloaded for the check (the caller restores)."""
        if state.path or step.kind != "click" or not step.safe or page.url != before_url:
            return False
        was, now = dict(before.counts), dict(after.counts)
        if any(n > was.get(sig, 0) for sig, n in now.items()):
            return False
        gone = [sig for sig in was if sig not in now]
        recorded = dict(state.core)
        if step.signature not in gone or any(sig not in recorded for sig in gone):
            return False
        self.restore(page, self._ctx, state)    # a fresh entry document; its verdict
        if self._authenticated():               # is not the point: the read; never one
            _page, lost = self._session_checkpoint(     # in a known-lost window (D',
                page, asked=state.entry_url, places=(state.entry_url,),   # FR-CRAWL-41;
                login_shown=state.login_shown)  # a replaced page is the caller's
            if lost is not None:                # restore's, `_session_current`)
                return True
        again = self.settled_fingerprint(page, self._ctx)
        if again is not None and \
                execution_route(again.url) == execution_route(state.entry_url) and \
                not any(sig in dict(again.counts) for sig in gone):
            self._declare(gone, "dismissed")
        return True

    def _child(self, state: State, step: Step, before: Reading, after: Reading,
               before_url: str, after_url: str, *, login_shown: bool = False) -> State:
        """The state ``step`` led to from ``state``: by its own URL when the step
        navigated (its path the fallback: a page only a POST shows), else by
        ``state``'s path plus ``step``. ``added``: what the step added (more often
        than on the page before it), which no run-wide declaration excuses.
        ``login_shown``: the page showed a password form (FR-CRAWL-41)."""
        path = [*state.path, step]
        had = dict(before.counts)
        added = tuple(sig for sig, n in after.counts if n > had.get(sig, 0))
        if after_url != before_url:
            return State.read(after, entry_url=after_url, login_shown=login_shown,
                              fallback=State.read(after, entry_url=state.entry_url,
                                                  path=path, added=added,
                                                  login_shown=login_shown))
        return State.read(after, entry_url=state.entry_url, path=path, added=added,
                          login_shown=login_shown)

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
