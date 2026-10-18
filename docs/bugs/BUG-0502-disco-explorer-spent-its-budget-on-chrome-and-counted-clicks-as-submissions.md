# BUG-0502 — The disco explorer spent its budget re-acting a page's chrome, filled stale fields, and counted clicks as submissions

- Date: 2026-10-18
- Status: fixed (CC-CRAWL-0034)
- Severity: high for the new discovery path. On Juice Shop, most of the explorer's
  actions went to the same header buttons. Its reported "75 submissions" sent the
  values of 2 forms. A form's fields could be filled into another form's controls.
  Nothing outside `fuzzlab/disco` was affected.

## Description
Measured after BUG-0501's fix, on Juice Shop v20.3.0 (the run CC-CRAWL-0032 reports),
then on the extended fixture:

1. **Steps were keyed per state.** A step was skipped only if it had been taken *in
   the same state* (`(state fingerprint, signature, occurrence, kind)`). Every overlay
   state of a route re-acted every element the route already had. A header present on
   every page was re-acted in every state: 7 Juice Shop header buttons in each state,
   most of the 206 actions.
2. **The route was part of every form-less element's signature.** The enumerator gave
   an element in a form-less container `action = location.href`, and the signature
   includes `action`. So a toolbar was new on each route and could not be recognised
   as one element.
3. **A toolbar's buttons were "submitters".** A form-less container is the nearest
   ancestor holding a typed input. A header holding a search box made every header
   button a submitter, and each was perturbed. The submit counter counted those clicks
   as submissions: 75 reported on Juice Shop, while the capture holds 2 POSTs from a
   form (`/api/Complaints`).
4. **Stale field markers.** `_FIELDS_JS` marks a form's controls `data-disco-field=N`
   and never cleared earlier marks. A later form's field `0` resolved to the first
   `data-disco-field="0"` in the document, an earlier form's control, so values went
   into the wrong form. On the extended fixture, the toolbar search box took the task
   dialog's title, and the dialog never posted.
5. **Script-only validity was invisible.** A value was kept when `checkValidity()`
   passed. A framework validator the browser cannot see marks the control
   `aria-invalid="true"`, once the control is touched, and keeps the submit button
   disabled. Measured on Juice Shop's address form: its number field took "1" (the only
   candidate) and stayed invalid.
6. **Pattern candidates.** `_from_pattern` read `[\d]` as a backslash and gave `*`
   zero repetitions, so `-?[\d]*` produced "" and a required control stayed empty.
   Measured on Juice Shop's contact form (its CAPTCHA control).
7. **No Enter submission.** A search box with no submit control of its own (submitted
   by a key listener) was never submitted.

## Where encountered
The owner asked for the explorer's general gaps to be closed (2026-10-18). Reading the
Juice Shop run's `actions.jsonl` against its `capture.jsonl` showed defects 1-3. The
fixture shapes added to reproduce them exposed defect 4. A probe of the three Juice
Shop forms that stayed unsubmitted showed defects 5 and 6.

## What it caused to fail
- The explorer's budget, so most of Juice Shop's routes were never explored (29 states
  route-capped).
- The reported submission count (an overstated result, F-061).
- Correct form filling, whenever a page had marked an earlier form.
- Every form guarded by a script-only validator or a `[\d]`-class pattern.

## What the bug was identified to be
The explorer judged its work by its own actions, not by their effects. It deduplicated
steps by state, not by the element. Its element identity carried the current route. Its
submission counter counted submit clicks. It judged form validity by the browser alone.
It left its own DOM markers behind between forms.

## Root cause analysis (Five Whys)
1. Why did the Juice Shop run reach 2/15 with "75 submissions"? Its actions went to the
   header, and its submissions were not submissions.
2. Why did nobody see that? The counter read 75. CC-CRAWL-0032 recorded it, and the
   agent reported it, without comparing it with the capture (2 form POSTs).
3. Why was the counter not compared? PA-0501 asks that counters be *checked*. They
   were read, not reconciled with independent evidence of the effect.
4. Why could the counter lie? It counted the explorer's own intent, a "submit" step
   performed. PA-0110 requires reporting an effect only when verified, but the
   explorer's counters were never read against it.
5. Why did the fixture not catch the header? It had no chrome: no element shared by
   routes, and no form-less container holding both buttons and an input.
   **Root cause:** an exploration mechanism whose counters measure its own actions
   rather than their observed effects, validated by reading those counters.

## Corrective action (CC-CRAWL-0034)
- Each step is taken once per route (`(route, signature, occurrence, kind)`). A step on
  chrome (a signature seen on more than one route) is taken once in the run
  (`chrome_skipped`).
- A form-less container has no `action`: signatures no longer carry the route.
  `form_refusal` uses the page URL in its place.
- Perturbations run once per form (route plus field set), never through a search box's
  buttons. A form-less container with one typed input gets an Enter step
  (`enter_submits`).
- `_FIELDS_JS` clears every earlier `data-disco-field` mark first.
- A value is kept when the control, blurred, passes `checkValidity()` and is not
  `aria-invalid="true"` (`_VALID_JS`). Without one, the first value the browser
  accepted is kept. Numbers with no stated maximum get wider magnitudes.
- `_from_pattern` reads `\d` / `\w` / `\s` inside a class and repeats `*` once.
- `submissions_sent` counts submit, Enter and perturbation steps whose filled
  (distinctive) values reached a request. `captcha_submissions` counts only those.
- The fixture gains a toolbar on every route (a search box submitted by Enter, beside
  buttons), a script-only range validator shown by `aria-invalid` after blur with the
  button disabled until it holds, and a `-?[\d]*` control. The pushed explorer on the
  extended fixture made no POST, no PUT and no search. Fixed, all are reached.
- On Juice Shop (CC-CRAWL-0034's effectiveness): 2/15 answer-key inputs reached before,
  6/15 after (43 endpoints from 24). The run ended with its frontier empty, not on a
  budget. The counters were reconciled with the capture.

## Recurrence review
- **BUG-0501 / PA-0501** (the same component, the day before): the explorer was
  validated on its author's fixture, and PA-0501(1) asks that a mechanism's counters be
  checked on a third-party app. This bug is that run's counters taken at face value.
- **BUG-0109 / PA-0110:** "an operation reports success only when its effect is
  verified". This is the same root cause (an intent reported as an effect), in a report
  counter rather than a return value.
- BUG-0501 defect 3 (UI-state classes in signatures) is a sibling of defect 2 here.
  Both put volatile context into element identity.

## Prior-preventive-action failure analysis
- **PA-0501 was too weak.** "Its own counters checked" was satisfied by reading their
  values. It did not require reconciling a counter with independent evidence of what
  it counts. The run was recorded (CC-CRAWL-0032) and reported with "75 submissions".
- **PA-0110 was not applied** to report counters. It is phrased for operations that
  return success, and its guard covers one secret-file delete. The explorer's counters
  were designed without it.

## Preventive action
PA-0502 (strengthens PA-0501(1) and PA-0110):
1. A discovery mechanism's effect counters count observed effects: a submission is
   counted when its values reached a request, not when a submit click ran.
2. Each reported counter is reconciled with independent evidence (the capture) before
   it is recorded or reported.
3. Element identity carries no context of where the element was seen (route, URL,
   state), and markers a mechanism writes into a page are cleared before it reads them
   again.

The PA-0002 sweep:
- The disco counters: `captcha_submissions` counted attempts and now counts sent
  submissions. `perturbations` stays a count of steps performed, documented as such.
- The other DOM markers (`data-disco-id`, `data-disco-cand`) are cleared on every
  enumeration.
- The signature keys were reviewed: only `action` carried the route.
- The legacy spider's `forms_submitted` is the same class: it counts vetted submit
  clicks, not requests sent. It is not changed here. The spider is deprecated (D70),
  and its summary reports the effect beside it (`requests_captured`, the requests a
  submission's window captured). It is listed for its removal rather than rewritten.
