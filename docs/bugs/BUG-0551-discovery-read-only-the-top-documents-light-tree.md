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
