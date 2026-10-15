# BUG-0151 — `spa.FORMS_JS` re-marks a hidden form's controls for an enclosing container

- Date: 2026-10-15
- Status: open in `spa.py` (owned by a concurrent lane); its consumer in the browser
  login is fixed (BUG-0148, CC-SESS-0025)
- Severity: medium. A pre-rendered hidden login form ended the browser login with a
  Playwright `TimeoutError` instead of a refusal; in the crawler, the stale marks can
  point a submission at the wrong container.

## Description
`FORMS_JS` (`fuzzlab/tools/spa.py`) collects each `<form>`, and also any ancestor of a
lone shown button that holds typed inputs. On a page whose login form is hidden (a
pre-rendered modal), the form's own submit is not shown, so the `<body>` becomes a
second container whose one shown button is the modal's opener. Marking that container
sets `data-fuzzlab-id` again on the same controls, so the first form's ids no longer
exist in the page.

## Where encountered
BUG-0148's section-0 measurement, in real Chromium on a synthetic Bootstrap-style modal
(BUG-0148, "Measurements", row 1).

## What it caused to fail
`browserlogin._pick_form` asked `page.is_enabled` of the first form's password id, which
waited out its timeout (10 s) and raised out of the whole login.

## What the bug was identified to be
One element carries one `data-fuzzlab-id`, but two containers claim it; the later
overwrites the earlier, and the description returned for the earlier still names the
lost ids.

## Root cause analysis
**Five Whys.** The login failed because a wait on a selector timed out. The selector
was gone because a later container re-marked the element. The container existed
because the hidden form's submit is not "shown", so the button-led container search
saw a lone opener. That search never asks whether an element is already claimed. And
no consumer was written to survive a missing mark.

**Root cause:** a marking script that can mark one element twice, and a consumer that
waited on a mark instead of reading it without waiting.

## Corrective action
- Consumer (BUG-0148, commit 223518b): `_pick_form` reads `is_visible` (no wait)
  before `is_enabled`, and catches a failure per form; a hidden form is refused, and the
  search goes on to the control that opens it.
- Producer: not fixed here. `spa.py` belongs to a concurrent lane; the defect is pinned
  by `tests/test_login_discovery.py::test_residual_forms_js_marks_stay_unique_for_a_hidden_form`
  (strict xfail) until that lane fixes it.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for marks or selectors that went
stale: BUG-0138 / PA-0138 (a wait on an event a refused action cancels) is the nearest:
a consumer waiting on something that may never come. Different object (a load state,
not a DOM mark), same failure shape on the consumer side. PA-0138(2) ("read from what is
there, never a wait on content") covers the consumer half; it was not applied to
selector waits inside a form picker.

## Prior-preventive-action failure analysis
PA-0138 (BUG-0138) named load states and navigation waits, and its AST guard looks for
navigation and load-state calls. A `page.is_enabled(selector, timeout=...)` wait on a
mark is neither, so the rule and its guard did not reach it (too narrow).

## Preventive action
PA-0157: a marking script gives each mark once; a consumer reads a mark without waiting
first and catches failures per candidate. Strengthens PA-0138(2) from load states to
DOM marks.
