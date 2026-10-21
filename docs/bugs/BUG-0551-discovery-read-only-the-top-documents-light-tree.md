# BUG-0551 — Discovery read only the top document's light tree: controls in shadow roots and frames, and delegated actions, were never candidates, and nothing said so

- Date: 2026-10-21
- Status: fixed (CC-CRAWL-0059), with stated residuals R1-R7
- Severity: high. The audit rated defect 13 CRITICAL. A whole class of an application's
  UI was invisible to both crawlers: a web component's form, an embedded settings
  frame, a list whose items a document-level handler serves. The run report gave no sign
  that anything was missed, so an endpoint reachable only through such UI was a silent
  coverage gap, never a reported one.

## Description
Both crawlers built their candidate lists from `document.querySelectorAll` over the top
document:

1. **disco** (`fuzzlab/disco/explore.py::_ENUMERATE_JS`): native controls, pointer
   elements and listener candidates, all from the top document's light tree. An open
   shadow root's content was never enumerated (Playwright's selectors pierce open shadow
   roots, but only for elements already chosen), and a frame's document was never read.
2. **disco's listener query** (`Explorer._listener_elements`) asked DevTools for each
   candidate's **own** listeners. A handler on an ancestor, the document or the window,
   serving the element it targets (event delegation), never made a non-semantic element
   without a pointer cursor actionable. The bounds (400 elements, 200 candidates) were
   applied in document order, and nothing reported what they left out.
3. **disco's form read** (`_FIELDS_JS`) cleared earlier `data-disco-field` markers with
   `document.querySelectorAll`. Once shadow controls are read, a stale marker in another
   shadow root is filled in place of this form's control, because a selector pierces open
   shadow roots. This is BUG-0502's marker defect in the composed tree.
4. **The spider's form read** (`fuzzlab/tools/spa.py::FORMS_JS`, also the session
   manager's browser login): forms and buttons came from `document.querySelectorAll`.
5. **No report** of a closed shadow root, an unread frame, or a bound that cut the list.

## Where encountered
The external adversarial audit at 6552276 (defect 13: `disco/explore.py` lines 99-169
and 650-701, `tools/spa.py` lines 490-549), by source tracing. It was reproduced on
c483dc1 in a real browser by `tests/test_disco_compose.py`, written first: a loopback app
served by the test, with an open-shadow-root search form, a closed shadow root, a
same-origin settings frame, a cross-origin frame, an out-of-scope frame, and tiles under
a document-level click listener.

## What it caused to fail
Measured on c483dc1 against the fixture (no lab or external target contacted). The
exploration made no request to any endpoint behind the new shapes:

- `POST /api/shadow/search` (the shadow root's search form), `/api/shadow/go`, and
  `/api/shadow/apply` (reachable only by replaying a shadow-root step);
- `POST /api/frame/save` and `/api/frame/apply` (the settings frame);
- `/api/tile/7` (the document-delegated tile).

The report had no field for shadow roots, frames, closed roots or cut candidates. The
spider's form read (`spa.FORMS_JS`) missed the shadow root's form. The pre-fix run of
the new tests is recorded in CC-CRAWL-0059's effectiveness.

## What the bug was identified to be
- **The enumeration's unit was the top document's light tree.** It never entered an open
  shadow root, never ran in a frame, and never recognised a closed root as something it
  could not see.
- **Listener discovery saw a candidate's own listeners only.** A delegated handler was
  invisible.
- **Markers were cleared in the light tree only**, which is safe only while only
  light-tree elements are marked.
- **The report counted what the explorer did, never what its reads could not reach.**

## Root cause analysis
Five Whys, from the symptom:

1. *Why was a web component's form never a candidate?* The enumeration was
   `document.querySelectorAll(NATIVE)`, which returns the top document's light-tree
   elements only.
2. *Why was that the query?* The enumeration modelled "the page's UI" as one document's
   element tree. That is the model the author's fixture (`tests/_disco_app.py`) and the
   one third-party app measured (Juice Shop, Angular Material: no shadow DOM, no frames,
   per-element listeners) both satisfy.
3. *Why did no test or lab show it?* PA-0501(2) grows the fixture only by "every shape
   that broke it there" on an app it ran against. None of the apps run had a web
   component, a frame or a root-delegated handler, so the fixture never violated the
   model. The spider's form read had the same model and the same history.
4. *Why did the runs not reveal it?* The explorer's report counts what it did. A page
   whose controls live in a shadow root reads as a page with few controls; nothing
   counted what a read could not reach.
5. *Why did both crawlers carry it independently?* Each had its own inline page script
   for "find the UI" (`_ENUMERATE_JS`, `FORMS_JS`). PA-0505(2) requires two discovery
   tools to share each kind of evidence's mechanism, but the tree walk was never seen as
   a mechanism (it was one call inside each script), so it had no owner and no guard.

**Root cause:** the crawlers' model of a page's UI ("the top document's light tree") was
an unstated assumption, embedded separately in each page script. No owner and no guard
existed for the tree walk, no fixture shape violated the assumption, and no report showed
what a read could not reach.

## Corrective action
CC-CRAWL-0059 (this lane, branch `lane/DISCO13`):

- **SP-70, the composed tree** (`fuzzlab/tools/composed.py::COMPOSED_JS`): one walk over a
  document and every open shadow root (each shadow tree right after its host), with
  composed queries, `composedClosest`, and a native fast path when no shadow host is
  below. On a page without shadow roots the order and the result are those of
  `querySelectorAll`.
- **disco's composed read** (`fuzzlab/disco/compose.py`, called by `Explorer.enumerate`):
  - It runs per document through DevTools' Command Line API (`Runtime.evaluate` with
    `includeCommandLineAPI`), so `getEventListeners` runs inside the read, one round
    trip per document. Measured: 13 ms for 6 005 elements, 34 ms for 24 005, against
    1.35 ms per candidate per CDP call before.
  - Each visible same-origin, in-scope frame is read in its own main-world context:
    `getEventListeners` sees only its own realm's listeners (measured). Contexts are
    found through `Runtime.enable`, by a marker the parent's read writes on the frame's
    window.
  - An element's ancestry continues past each shadow root (`^shadow<host`) and each
    frame (`^frame<iframe#id<@/path`), so its signature, the identity a step and a
    state use, names its component and frame. `_locate` follows the frame markers
    (`compose.frame_scope`), and a selector pierces open shadow roots.
  - Delegated candidates are kept: a labelled, non-semantic leaf (no candidate or
    described element inside it, under a quarter of the viewport, the first of its
    shape, at most 16 per read) whose composed path has a `click`/`dblclick`/`mouseup`/
    `pointerup` listener on an element, shadow root, document or window.
  - `Explorer._act_delegated` tries each once (`compose.Trials`, at most 48 per run). It
    keeps the candidate (a performed, logged action) only when the click made a request,
    changed the URL, opened a page or changed the explorer's own state fingerprint.
    Otherwise it is inert: never logged, never counted an action, described `disabled`
    from then on.
  - Reported (`ExploreReport`, in `explore.json`, live, per route, a re-read page adding
    nothing):
    - `shadow_roots` and `frames` read;
    - `closed_shadow_roots`, confirmed through `DOM.describeNode` on custom elements whose
      light tree renders nothing;
    - `frames_cross_origin` and `frames_out_of_scope`;
    - `budget_limited` per bound (elements, candidates, delegated, nodes, frames,
      census);
    - `delegated_trials`, `delegated_live`, `delegated_inert` and
      `delegated_unexplored`.
- **disco's form read** (`compose.FIELDS_JS`) clears markers across the document's
  composed tree, and reads a form's controls through it.
- **The spider's form read** (`spa.FORMS_JS`) finds forms, buttons and controls across
  open shadow roots. A password control inside a shadow root is never described: its
  container is read by its light tree (as before) and left out when it is itself in a
  shadow root. The browser login's X3 password clear and the G1 read resolve an id with
  `document.querySelector`, which no shadow root answers (residual R3).

## Recurrence review
Checked `docs/bugs/` (BUG-0123, BUG-0136 and BUG-0501..BUG-0541, the discovery,
browser-guard and audit records) and every PA naming disco, the spider, markers or
discovery shapes (PA-0111, PA-0123, PA-0136, PA-0138, PA-0501..PA-0507, PA-0510,
PA-0524).

- **No prior bug about shadow roots, frames as UI, or delegated handlers.** BUG-0123 and
  BUG-0136 concern frames as navigation targets (scope and abort), not as UI.
- **The same root-cause family recurs**, a discovery mechanism's unstated model of the
  page checked only against apps that satisfy it:
  - BUG-0501 / PA-0501: validated only on its author's fixture, it explored nothing on
    Juice Shop.
  - BUG-0502 / PA-0502(3): markers a mechanism writes are cleared before it reads them
    again. That class recurs here in the composed tree (description item 3).
  - BUG-0505 / PA-0505(2): two tools that discover the same surface share each kind of
    evidence's mechanism. Enumeration was not shared.
- **PA-0507(2)** (search for an existing implementation before registering a primitive):
  a search for `shadowRoot`, `contentDocument`, `frame_locator` and `child_frames`
  over `fuzzlab/` found none. SP-70 is new.

## Prior-preventive-action failure analysis
- **PA-0501 (BUG-0501): too narrow, and reactive.** (1) asks for a run on an app the
  author did not write; Juice Shop satisfied it. (2) adds to the fixture "every shape
  that broke it there". Both key the fixture on failures already observed, so a way the
  platform presents UI that no measured app uses is never tested. The rule was followed;
  it could not reach this class.
- **PA-0502(3) (BUG-0502): followed at the wrong layer, and not enforced.** "Markers ...
  are cleared before it reads them again" was implemented with a light-tree query, which
  the rule did not constrain (it named the markers, not where they live). No test checks
  how markers are cleared.
- **PA-0505(2) (BUG-0505): not applied to enumeration.** Its enforcement covers the
  script-route scanner (SP-47's guard) only. Nothing listed "which elements a page
  offers" as evidence both tools gather, so the two enumerations stayed independent.

## Preventive action
**PA-0551** (strengthens PA-0501(2), PA-0502(3) and PA-0505(2)):

1. **A crawler page script that discovers or locates UI reads the composed tree through
   the one owner** (SP-70, `tools.composed.COMPOSED_JS`). That covers every open shadow
   root, and each frame by its own read in its own realm. A light-tree-only DOM query in
   a page script is a reviewed allowance with its count and its reason. Enforced by a
   whole-package guard over every string constant of `fuzzlab/`, proven on synthetic
   offenders and near-misses.
2. **A discovery mechanism's fixture covers each way the platform presents UI**, not only
   the shapes a measured lab had. That means open and closed shadow roots, same-origin,
   cross-origin and out-of-scope frames, and delegated handlers, each with a
   real-browser test whose evidence is what the server received.
3. **What a read cannot reach, or a bound leaves out, is counted in the run report,
   never claimed.** That covers closed roots, unread frames and budget-limited
   candidates.

**PA-0002 sweep: every light-tree query in a page script, with its disposition** (the
guard's allowance list):
- **Fixed:** disco's enumeration (`READ_JS`), disco's form read (`FIELDS_JS`), and the
  spider's form read (`spa.FORMS_JS`).
- **Pinned by strict xfails:** `spa.G1_READ_JS`, the spider's G1 read of a FORMS_JS id,
  where a shadow control reads as missing. `session/browserlogin.py::_CLEAR_IF_PRESENT`,
  the X3 password clear (owner SESS; no CC-SESS number was assigned to this lane).
- **Allowed with a reason:**
  - `_LABELS_FN` and `CARD_LABELS_JS` query a detached clone;
  - `spa.REVEAL_JS`, `G1_OPTIONS_JS` and `MENU_ITEMS_JS` are the legacy spider's reveal
    and option scripts (FR-CRAWL-40's known gap);
  - the spider reads `<base>`.
- **Other browser reads swept:** the harvest's `page.content()` (`Explorer._gather`)
  serialises the top document's light tree, so links inside shadow roots and frames
  are reached by acting on them (they are now enumerated), not by the harvest
  (residual R5). `eval_on_selector_all("a[href]")` in `_hash_routed` and in the browser
  login goes through Playwright's selector engine, which pierces open shadow roots.

## Residuals
- **R1:** a closed shadow root is confirmed only on a custom element whose light tree
  renders nothing. A closed root that slots visible light children, or one on a
  non-custom host, is neither read nor counted.
- **R2:** a cross-origin frame, even an in-scope one, is not read inside the page. Its
  document is explored as a top-level page when the harvest reaches its URL.
- **R3:** the browser login (SESS) and the spider's G1 read resolve a FORMS_JS id with
  `document.querySelector`. Until both go through SP-70, FORMS_JS never describes a
  password control inside a shadow root. Pinned by two strict xfails in
  `tests/test_disco_compose.py`.
- **R4:**
  - A delegated verdict is one per element signature for the run, so a handler that
    acts only in some states is judged by its first trial.
  - A candidate another worker is trying is skipped.
  - Trials are bounded at 48 per run and 16 candidates per read; the excess is
    counted.
- **R5:** the harvest's link extraction reads the top document's serialised light tree.
- **R6:** listener, delegated and closed-root detection need DevTools (Chromium).
  Through Playwright alone, the read has shadow roots and frames but no listeners.
- **R7 (merge note):** a delegated element's `disabled` reflects a trial verdict, not
  the DOM. State identity reads only signatures, which `disabled` is not part of. Any
  new execution-state key (the AU-DISCO lane's defect-1 work) must not read `disabled`
  or `how == "delegated"` elements' flags.

## Review round 1 (2026-10-21, branch `lane/DISCO13-r1` from c219266)

The independent review of c219266 confirmed four defects in this lane's fix, each
reproduced in a real browser by the reviewer and by a refutation pass. They are part of
BUG-0551, not new bugs: the lane's own change carried them, and none had merged.

### Description
- **B1 (`compose.READ_JS`, `spa.FORMS_JS`).** A search or login widget whose input and
  button sit directly under its open shadow root (the usual layout of a Lit or Stencil
  component) was found but never filled or submitted. `READ_JS`'s `formLike` walked
  `parentElement`, which is null at the top of a shadow tree, so the button had no
  container: `in_form` false, clicked bare. The input had `typed` 0 and no step.
  `spa.FORMS_JS`'s container search had the same ancestor walk and found nothing.
- **B2 (`explore.py`, state identity).** Delegated candidates, including ones already
  found inert, were part of the state fingerprint, a state's core and `reproduces`.
  On any light page with a click listener on an ancestor, the document or the window,
  every labelled text leaf (`p`, `span`, `li`, `td`, ...) counted toward the state key,
  so a click that only swapped static text made a new state. That broke the
  fingerprint's contract ("a page whose data changes stays one state") and
  CC-CRAWL-0059's own risk statement (only shadow and frame elements change states).
- **B3 (`Explorer._trial`).** A trial judged a delegated candidate live whenever any
  request reached `page.on("request")` between the click and the after-read. A
  notification poll, a beacon or a keep-alive in that window made an inert candidate
  live: performed and logged on every state where it appeared, and `delegated_live`
  overstated.
- **B4 (`compose.READ_JS`, `Reader.census`).** Closed shadow roots were counted only
  on custom elements none of whose light children render. A closed root on a built-in
  host (`div`, `section`, `span`, `article`) or one that slots visible light children
  was neither read nor counted: `closed_shadow_roots` was 0 while a form was hidden.
  The lane listed this as residual R1, against its own PA-0551(3).

### Where encountered
Code review of c219266 (findings DISCO13-B1..B4), with the reviewer's probes run against
the lane tip in a real browser:
- B1: a page holding `<search-widget>` whose open root is
  `<input name=q placeholder=Search><button>Go</button>`. The server received
  `/api/search?q=` (empty); the action log was `[('click','Go')]` with 0 submissions.
  The same widget built in the light tree sent `q=test` through an Enter step and a
  submit step. `page.evaluate(spa.FORMS_JS, 20)` returned `[]`.
- B2: `<h1>Inbox</h1><button>Refresh</button><div id=list><p class=empty>No
  messages</p></div>` with `document.addEventListener('click', ...)`; Refresh fetches
  and replaces the list with `<ul><li class=msg>Hello</li></ul>`. c483dc1: 1 state.
  c219266: 2 states, the Refresh action changed the state, and both delegated trials
  were inert.
- B3: a `.tile` served by a document click listener, a `.note`, and
  `setInterval(() => fetch('/api/notifications'), 400)`. c219266: the log was
  `[('click','Open report'), ('click','Just a note')]`, 2 trials, 2 live. Without the
  poll, `Just a note` was inert.
- B4: `compose.read_page` on a `<div>` with a closed root holding a login form, and on
  `<x-card><span>Title</span></x-card>` whose closed root slots it: counts `{}`,
  distinct `{}`.

### What it caused to fail
- B1: a form-less component's search or login was never sent with a value. Its endpoint
  was reached, if at all, only with an empty parameter, and the spider never saw it as a
  form.
- B2: on most real pages (Bootstrap's data-api and jQuery register a document click
  listener; React 17+ one on its root) states multiplied on data changes, spending the
  state budget and replays on views that differed only by text.
- B3: an inert element was clicked and logged as an action wherever it appeared, and
  the report overstated what delegated discovery found.
- B4: the report claimed nothing was missing while a closed component hid a form.

### What the bug was identified to be
- B1: a light-tree **ancestor** walk (`parentElement`) inside a composed read. The
  lane composed every descendant query through SP-70, but not the walk up to a
  container. `FIELDS_JS` already fell back to `getRootNode()`; `READ_JS` and
  `FORMS_JS` did not.
- B2: membership of the state's element set depended on a heuristic whose output varies
  with text (an empty leaf is no candidate), order (the first of each shape, 16 per
  read) and size. The verdict flags were kept out of identity (R7), but the members
  were not.
- B3: "made a request" was measured as correlation in a time window, not causation.
- B4: a heuristic pre-filter (`suspects`) chose which hosts the complete DevTools check
  ran on, and its misses were documented instead of counted.

### Root cause analysis
Five Whys, from the four symptoms:

1. *Why did the lane ship four defects its tests passed?* Each test exercised one shape
   per mechanism, chosen to show the mechanism working: a shadow form inside a real
   `<form>` (reached through `e.form`); delegated tiles on a page whose other leaves never
   changed; a page with no background traffic; a closed root on an empty custom element.
2. *Why one shape each?* The lane's fixture plan (PA-0551(2)) listed **ways the
   platform presents UI** (open and closed roots, frame kinds, delegated handlers), not
   the **variants inside each way** that the code branches on (a container element or
   none; a static page or one whose text changes; a quiet page or a polling one; a host
   that renders nothing or one that slots its children).
3. *Why were the variants not derived from the code?* The new code's branch points
   (where `parentElement` ends, which elements feed the fingerprint, what the request
   listener collects, what the census pre-filter skips) were not enumerated against the
   tests. The risk statement was written from intent ("only shadow and frame elements
   change states") and not checked by a test on a light page with a document listener.
4. *Why did B4 survive the lane's own rule?* PA-0551(3) says what a read cannot reach
   is counted. The lane met it with a residual paragraph (R1), and no test or guard
   tells a documented gap from a counted one.
5. *Why did B2 and B3 escape the fingerprint and counter rules?* PA-0502(3) protects an
   element's identity from context, and PA-0502(1) requires counters of observed
   effects. Neither names a **state's membership** or the **cause** of an observed
   effect, so neither applied.

**Root cause:** the review-round defects share one cause: the lane tested each new
mechanism on a single confirming shape and never enumerated the inputs its code
branches on (container or none, static or changing text, quiet or busy network,
rendering or slotting host). The heuristic outputs it added (delegated membership,
trial verdicts, census suspects) were therefore never checked against the contracts
they fed (state identity, live counters, "counted, never claimed").

### Corrective action
CC-CRAWL-0059, review round 1 (branch `lane/DISCO13-r1`):
- **B1:** `READ_JS`'s `formLike` returns the shadow root its ancestor walk ends at when
  that root holds a typed control. A root is no `<form>`: no action, `form_tag` false,
  and `typed`, `last_typed` and `submitters` come from the root. `spa.FORMS_JS`
  considers the shadow root once its ancestor walk ends there, and describes such a
  container by its host. SP-70's `deepAll`/`deepFind` walk a shadow root passed as the
  root (the owner holds elements only in `deep`, so a root was queried natively,
  missing nested roots).
- **B2:** `fingerprint.counts_for_state` and `state_signatures`: a delegated candidate
  (`how == "delegated"`) is never part of the state key, a state's core, or
  `reproduces`. `explore.py` builds every core through `state_signatures`. Delegated
  candidates stay in the element list, so they are still stepped and tried.
- **B3:** `Explorer._trial` runs a **control window** just before the click: the page
  left alone for the same quiet wait (`mark_activity` then `wait_quiet`), then the read
  the click acts on (requests during it are the page's own too). A request is
  evidence only when its `request_key` (method and normalised route) is not explained
  on that route: neither a control window there saw it nor an earlier trial there
  counted it (`_Shared.explained`). Measured with a 4-candidate page, `idle_ms` 500,
  `max_quiet_ms` 1500: a 400 ms poll gave 0 false live of 9 over 3 runs, and a 1 s
  poll 0 of 12 over 4 runs. A 2.5 s poll gave 8 of 12 with the control window alone
  (the trial cycle phase-locks with the poll), and 3 and then 4 of 12 (at most one per
  run) once a key counts once per route. The DevTools signals were measured and rejected: `hasUserGesture` is true for
  every request in the 5 s after a click, poll included, and an initiator stack's async
  parent needs the Debugger domain enabled before the page schedules the timer.
- **B4:** `compose._census` replaces the suspects heuristic. One
  `DOM.getDocument({depth: -1, pierce: true})` per page lists every element hosting a
  closed root, in every shadow tree and every in-process frame document. Each is
  attributed to its frame by the `data-disco-frame` key its parent's read wrote, and
  only documents read count. Measured cost: about 25 us per node (230 ms for 6 000
  elements, 1.3-1.9 s for 24 000-30 000; `DOMSnapshot.captureSnapshot` costs the same).
  So a page is checked once per route and shape (each read document's digest of tag
  and child count in walk order), and a page whose documents read hold more than
  `MAX_NODES` elements, or that is read without DevTools, is not checked. Its elements
  are counted `budget.census`.

Tests (each fails on c219266, see CC-CRAWL-0059's effectiveness):
- B1: `tests/test_disco_compose.py::test_a_formless_widget_at_a_shadow_roots_top_is_filled_and_sent`
  and `::test_the_spiders_form_read_finds_a_formless_widget_at_a_shadow_roots_top`.
- B2: `::test_a_click_that_only_swaps_static_text_keeps_the_state` and
  `::test_a_delegated_candidate_is_no_part_of_a_states_identity`.
- B3: `::test_a_background_poll_never_makes_an_inert_candidate_live` (a 100 ms poll)
  and `::test_a_request_is_keyed_by_method_and_route`.
- B4: `::test_what_was_not_read_is_counted_never_claimed` (the fixture adds a closed
  root on a `<div>` and one on `<x-card>` slotting a visible child; exactly 3 counted)
  and `::test_the_census_counts_every_closed_root_of_the_documents_read`.

### Recurrence review (review round 1)
Checked `docs/bugs/` for state identity and counter bugs (BUG-0501, BUG-0502,
BUG-0505, BUG-0512; AU-DISCO's BUG-0539, not merged) and `docs/PREVENTIVE_ACTIONS.md`
(PA-0501, PA-0502, PA-0505, PA-0512, and this bug's PA-0551 as first written):
- **B2 recurs BUG-0501/BUG-0502's class:** something that varies (state classes, the
  route in a form action, here text-dependent membership) entered state identity and
  multiplied states.
- **B3 recurs BUG-0502's class:** a counter of intent or correlation reported as an
  effect (75 "submissions" there, delegated "live" here).
- **B1 and B4 recur this bug's own class** within its fix: a light-tree assumption (an
  ancestor walk) and an uncounted gap (closed roots).

### Prior-preventive-action failure analysis (review round 1)
- **PA-0502(3) (BUG-0502): too narrow.** "Element identity carries no context of where
  the element was seen" constrains a signature. It says nothing about which elements a
  state's key is built from, so a heuristic's membership was never checked against it.
  Its guard (`test_state_classes_never_change_a_signature`) tests signatures only.
- **PA-0502(1) (BUG-0502): too narrow.** "Effect counters count observed effects"
  was met literally: a request was observed. The rule does not ask whether the action
  caused it.
- **PA-0551(1) as first written: not enforced on ancestor walks.** Its guard scans
  descendant queries (`querySelector*`, `getElementsBy*`); a `parentElement` walk is a
  light-tree traversal it cannot see.
- **PA-0551(2) as first written: too coarse.** "Covers each way the platform presents
  UI" was met with one confirming variant per way.
- **PA-0551(3) as first written: not followed.** The lane wrote the closed-root gap
  down as residual R1 instead of counting it.

### Preventive action (review round 1)
PA-0551 is strengthened before it merges (texts in the lane's `doc_texts.md`):
- (2) now asks for the **variants each mechanism branches on**: a container element or
  none, a static page and one whose text changes under a document listener, a quiet
  network and a polling one, a host that renders nothing and one that slots its
  children.
- (3) is met only by a **complete count or a counted remainder** (`budget.*`), never a
  residual paragraph.
- New (4): an ancestor walk in a composed page script continues past the top of a
  shadow tree (the root, or `composedParent`).
- New (5): a heuristic candidate is kept only on evidence its own action caused,
  compared with a control observation without it. Its presence, verdict or flags never
  enter state identity.

**PA-0002 sweep (review round 1):**
- **Ancestor walks** in composed page scripts:
  - `READ_JS` `formLike` and `FORMS_JS`'s container search: fixed.
  - `FIELDS_JS`: already fell back to `getRootNode()`.
  - `READ_JS` `ancestry` and `delegating`: already continue through hosts.
  - The pointer check's `parentElement`: at a shadow tree's top, the element inherits
    the host's cursor, and is described itself (correct).
  - `closest('form')`: forms never span a shadow boundary.
- **State identity inputs:** `listener` and `pointer` elements are DOM-defined, not
  text-defined. Only delegated candidates were heuristic; they are now excluded. AU-DISCO's
  `element_multiset`/`execution_key` (d9e269e) read every element: see R7.
- **Time-window evidence:** the capture's action ids (`_tag`, BUG-0512) attribute every
  request after an action to it, a background poll included. That is attribution for
  the store, documented as such, not a verdict that keeps or drops anything; it is
  unchanged. `submissions_sent` already requires a distinctive filled value in the
  request (PA-0502(1)).
- **Partial detectors behind a "counted" claim:** the frame classification counts every
  frame it walks; the closed-root census was the only pre-filtered one.

### Residuals after review round 1
- **R1 (closed).** Every closed root of a document read is counted. A closed root
  attached where the page's composed shape (tags and child counts) did not change is
  counted once the shape next changes. A page past `MAX_NODES` elements, or read
  without DevTools, is counted `budget.census`.
- **R2-R6** are unchanged.
- **R7 (merge note, extended):** a delegated candidate is no part of state identity:
  neither its flags nor its membership. AU-DISCO's `element_multiset` and
  `execution_key` must filter `fingerprint.counts_for_state`, as `state_fingerprint`
  and `state_signatures` do, when the lanes merge.
- **R8 (new):** background traffic slower than a control window can still make one
  inert candidate per route and request key live. Measured: a 2.5 s poll, at most one
  per run (4 of 12 inert candidates over 4 runs).
- **R9 (new):** a delegated candidate that appears only after an action that changes
  nothing else in the state (Refresh rendering `li.msg`) is not tried there. Its state
  is unchanged and its steps were planned before the action. This is the behaviour of
  c483dc1 for such leaves.

## Merge integration with BUG-0539 (AU-DISCO), 2026-10-21
Merged onto AU-DISCO's merge (07792e0), as planned (AU-DISCO first). CC-CRAWL-0059's
merge-integration note lists the resolution.
- **R7 closed.** The execution key's multiset and workflow markers, and so every
  recorded contract (`explore.contract_mismatch`), leave a delegated candidate out
  (`fingerprint.counts_for_state`), as the structural key does. A delegated candidate's
  `aria-current` is read as a page marker: a stepper served by a document listener still
  tells its steps apart (BUG-0539 defect 1). Proven by
  `tests/test_disco_compose.py::test_a_delegated_candidate_is_no_part_of_the_execution_key_or_a_contract`
  and `::test_the_composed_read_carries_the_execution_keys_markers`.
- **R4 narrowed.** A candidate another worker is trying is a failed attempt, retried
  (FR-CRAWL-32), no longer skipped. A trial whose click reached nothing is released, not
  decided inert.
- **R10 (new, merge).** A delegated close control (a `span` "x" served by a document
  listener) is in no contract, so its notice is never declared `dismissed` (BUG-0539's
  dismissal rule needs the clicked element's own signature among what the click
  removed). A state that recorded such a notice is unresolved once it is gone, as
  BUG-0539's R7 states for a notice on a page reached by a step.
