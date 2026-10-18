# BUG-0501 — The disco explorer explored nothing on its first real single-page app, and the synthesizer collapsed its routes

- Date: 2026-10-18
- Status: fixed (CC-CRAWL-0032)
- Severity: high for the new discovery path: on Juice Shop the explorer made 0 actions
  (1 state), and after the first fix its inventory merged unrelated endpoints. Nothing
  outside `fuzzlab/disco` was affected; the legacy pipeline was untouched.

## Description
Pushed on 2026-10-17 (CC-CRAWL-0031) and validated only on a fixture the agent wrote,
the behavioural explorer and synthesizer failed on the first third-party app they met
(OWASP Juice Shop v20.3.0, an Angular Material SPA, run through `lab/labctl.sh`):

1. **Every state unrestorable.** A state was restored only if its fingerprint came back
   identical. Juice Shop's first-visit welcome dialog (6 elements) is not shown again
   after a reload, so the start page itself was "unrestorable" and the frontier emptied:
   1 state, 0 actions.
2. **Restores that did not reset.** On a hash-routed app, navigating to `/#/` from
   `/#/search` is a same-document change, so the previous action's UI survived the
   "restore" and replays toggled it the wrong way.
3. **Unstable signatures.** Element signatures included UI-state classes
   (`ng-untouched` / `ng-touched`, `search-container--visible`), so one element had
   another signature in another state.
4. **Consumed UI broke replays.** A path step on a notice dismissed for good (its
   cookie set) could not be replayed, so states behind it were dropped.
5. **No form submitted.** Angular forms have no `<form>` element and keep their submit
   button disabled until valid; the explorer filled only `<form>`s and skipped disabled
   elements: 0 submissions in 143 actions.
6. **Budget spent on overlays.** Breadth first spent the 60-state budget on the start
   page's toasts, menus, tooltips and pagers (121 of 143 actions on `/#/`); the routes
   the side-nav opened (contact, complain, profile) were reached once and never explored.
7. **Routes collapsed.** The synthesizer's slug rule templated any literal segment that
   varied over three siblings: every top-level route became `/{p1}` (`/redirect`,
   `/profile`, `/file-upload`...) and `/api/Users/`, `/api/Products/`, `/api/Feedbacks/`
   became `/api/{p1}/`, merging their parameters (a false "reached" for JUICE-0001).

## Where encountered
The owner asked how the spider performs. The first measurement of `fuzzlab disco
capture` on Juice Shop (authenticated as the lab identity), scored against
`lab/ground-truth-juice-shop` by `scripts/funnel_report.py`'s "reached" rule.

## What it caused to fail
Discovery on a real SPA: 1 state and 0 actions at first; after fixes 1-4, 60 states and
143 actions but 0 submissions and 2/15 answer-key inputs reached (and an inventory whose
merged endpoints would have sent wrong requests in Phase 3).

## What the bug was identified to be
The explorer's state model (identity, restore, replay, frontier, submitters) and the
synthesizer's slug rule were designed against the agent's own fixture, which had none
of the shapes common to third-party SPAs: one-time and dismissible UI, a hash router,
framework state classes, form-less forms with disabled submitters, overlay-heavy pages,
and resource-named URL segments.

## Root cause analysis (Five Whys)
1. Why did the explorer do nothing on Juice Shop? Its start state could not be restored.
2. Why not? Restore required an identical fingerprint, and a one-time dialog vanished.
3. Why was identical required? It held on the fixture, the only app it had run on.
4. Why only the fixture? The design was "measured" (CLAUDE.md rule 8) on the browser and
   proxy mechanics, but the exploration model was judged on its own fixture's results,
   and Phase 1 was reported as working from those.
5. Why did no rule stop that? PA-0111(3) requires a captured third-party shape for code
   that *emulates browser behaviour*; the explorer was not seen as such, and nothing
   requires a discovery mechanism to run on an app its author did not write before it
   is called working. **Root cause:** a discovery mechanism validated only against its
   author's own fixture.

## Corrective action (CC-CRAWL-0032)
- `State.core` and `Explorer.reproduces`: a restore succeeds when the route matches and
  every *stable* element is present; a restore showing elements only gone, none new,
  narrows the core (one-time and consumed UI).
- `Explorer.restore` leaves for `about:blank` before loading the entry URL (a fresh
  document on a hash-routed app); a replay step whose element is gone is skipped and the
  reproduction check decides.
- `fingerprint.stable_classes`: BEM modifiers and classes with a state-word part are
  dropped from signatures (`STATE_WORDS`; deliberately not `in`, `out`, `error`...).
- Form-like containers (the nearest ancestor holding typed inputs) define submitters and
  their fields; a disabled button there is enumerated as a submitter.
- `Frontier`: states on a new route before overlay states of a known route, at most
  `max_states_per_route` (8) per route.
- `synth.template_paths`: a slug needs every value seen as data in a captured response,
  and never the first segment.
- The fixture (`tests/_disco_app.py`) gains the third-party shapes: a one-time welcome
  overlay, a dismissible notice, a hash router, state classes. The pushed explorer on the
  new fixture: 1 state, 0 actions, 1 unrestorable, the POST never reached -- the Juice
  Shop failure, reproduced; fixed: 0 unrestorable, everything reached.

## Recurrence review
- **PA-0111(3)** (BUG-0110): "at least one fixture is a captured third-party target's
  shape, not only our own lab's" -- the same root cause (validation against our own
  shapes only), one component over.
- **PA-0052** (BUG-0050): a lab-shape assumption in the crawler's scope filter; the same
  class (an assumption only the author's environment satisfied).
- **PA-0006**: fixtures shaped like the real upstream.

## Prior-preventive-action failure analysis
PA-0111(3) did not prevent this because it is **scoped too narrowly and enforced too
narrowly**: its rule names code that emulates a browser or protocol behaviour (form
serialisation, redirects, cookies, headers), and its guard
(`tests/test_form_entries.py::test_every_rule_has_a_fixture`) covers only
`core.forms.RULES`. A browser-driving discovery mechanism is not an emulation, so the
rule was not seen to apply, and nothing checked it. PA-0052 covers scope filters only.

## Preventive action
PA-0501 (strengthens PA-0111(3) and PA-0006): a discovery or exploration mechanism is
not reported as working, and its fixture is not trusted, until it has run against at
least one application its author did not write, its own counters checked (states,
actions, submissions, unrestorable); every shape that broke it there joins its fixture
as a standing test. The PA-0002 sweep: the other discovery mechanism, the legacy spider,
was measured on third-party labs (Juice Shop, bWAPP, held-out labs) before this rule;
the auditor and session browser login were measured on Juice Shop and bWAPP. No other
discovery mechanism was validated on a fixture alone.
