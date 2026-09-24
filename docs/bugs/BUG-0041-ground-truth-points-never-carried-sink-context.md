# BUG-0041 — `points_from_ground_truth` never propagated `sink_context`, silently defeating the first rule keyed on it

- Date: 2026-09-23
- Status: fixed
- Severity: medium (silent, dormant — zero observed impact until the first consumer existed; then a total, silent detection failure for that consumer)

## Description
`fuzzlab.harness.auto.points_from_ground_truth` builds a
`fuzzlab.audit.InjectionPoint` (the object rules/strategies actually operate on)
from each of a ground truth's enumerated *points* (`injection-points.json`,
`fuzzlab.labels.contract.InjectionPoint` — a deliberately slim shape: url,
method, param, location, rendering, client_only). `sink_context` is not one of
those fields; it lives only on the ground truth's scoring `Case`
(`labels.json`, `fuzzlab.labels.contract.Case`). Nothing in
`points_from_ground_truth` ever bridged the two, so every audit
`InjectionPoint` built from ground truth has had `sink_context=None`
(the dataclass default), for every category, every target, since this
function was written — regardless of what the corresponding `Case` actually
declared.

## Where encountered
Building real detection for `insecure_deserialization`
(`R-INSECURE-DESERIALIZATION`, `CC-AUD-0018`/`CC-FUZZ-0034`) — the project's
first audit rule to use the `sink_context_in` `when` predicate. Unit tests
that hand-construct a `Candidate`/`InjectionPoint` with `sink_context` set
directly all passed. The real, executed live-boot test
(`tests/test_multitarget_category4.py::test_both_apps_run_through_multitarget_for_real`,
a real `SpringBootLiveBootHarness` boot + real `run_targets()` call against
it) kept showing `netflix_report.tp == 0` despite the rule and strategy
both being independently correct and unit-verified.

## What it caused to fail
Any audit rule keyed on `sink_context_in` would nominate zero candidates for
*any* ground-truth-sourced point, project-wide, no matter how correctly the
rule and its paired oracle strategy were written — a structural,
silent false-negative source, indistinguishable from "no rule/strategy
exists yet" from the outside (the real symptom this session initially
observed and had to trace past). It had zero observed effect before this
change only because no rule had ever used `sink_context_in` before
(confirmed: `R-SSTI`/`R-SSRF`/`R-ACCESS-CONTROL` all key on `location_in`/
`method_in`/`name_regex` only).

## What the bug was identified to be
A missing field-propagation step in `points_from_ground_truth`: it reads
`gp.param`/`gp.location`/`gp.rendering`/`gp.method` from the enumerated point
but never looks up and carries over the matching `Case`'s `sink_context`.

## Root cause analysis
Five Whys:
1. Why did `R-INSECURE-DESERIALIZATION` never nominate `NFLX-0001` in the
   real run? Its `sink_context_in=["deserialization"]` predicate never
   matched — the point's `sink_context` was `None`.
2. Why was it `None`? `points_from_ground_truth` never set it when
   constructing the audit `InjectionPoint`.
3. Why not? The function only reads fields present on
   `fuzzlab.labels.contract.InjectionPoint` (the enumerated *point* shape),
   and that shape has no `sink_context` field at all.
4. Why does the *point* shape lack it, when `sink_context` clearly exists in
   this project's ground truth? By design (`fuzzlab.labels.contract`'s own
   two-shape split): a *point* is "where to probe" (discoverable pre-audit,
   symmetric with what a real crawl could find), a *case* is "the scored
   ground truth" (post-hoc typing, including `sink_context`, `vuln_class`,
   `expected_vulnerable`). `points_from_ground_truth` needed a value that
   only exists on the *other* shape and never fetched it.
5. Why did no rule need `sink_context` before now to expose this? Every
   prior rule (`R-SQLI-PARAM`, `R-XSS-REFLECT`, `R-SSRF`, `R-ACCESS-CONTROL`,
   etc.) happened to have an informative parameter name or location to key
   on instead. `insecure_deserialization`'s whole-body point (`param="body"`
   for every whole-body point of *any* class) has no such signal, forcing
   `sink_context_in` into service for the first time and finally exercising
   the untested path.

**Root cause:** `points_from_ground_truth` constructs its audit
`InjectionPoint` only from the ground truth's slim *point* shape and never
cross-references the corresponding scoring *case* for fields (like
`sink_context`) that exist only there — a real, silent propagation gap that
had no observable consequence until a rule finally depended on the missing
field.

## Corrective action
`points_from_ground_truth` now builds a
`{(url, method, param): sink_context}` lookup from `ground_truth.cases`
before its main loop, and passes the matching entry's `sink_context` into
each constructed `InjectionPoint` for `query`/`body`/`header` points (the
`is_dom`/skip branches are unaffected — no consumer needs `sink_context`
there). Pinned by a dedicated unit test,
`tests/test_auto.py::test_points_from_ground_truth_carries_sink_context_from_the_matching_case`.
Re-verified end to end (not just unit-level): the real
`test_multitarget_category4.py` live-boot run now shows
`netflix_report.tp == 1` for `NFLX-0001`, where it previously showed `0`
despite the rule/strategy both being independently correct.
(`CC-FUZZ-0034`, `docs/components/07-fuzzing-harness-and-oracle/change-control.md`)

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence
of the same bug, or a different bug with the same root cause.
**Found a related but not identical prior bug: `BUG-0006`**
("Automatic mode never nominated XSS — rule keyed on a label discovery
can't set", `PA-0006`). Both bugs are shaped like "a rule depends on
`sink_context`, and the point it evaluates doesn't have it." But the root
causes differ:
- `BUG-0006`'s root cause: in the **crawl/automatic** pipeline,
  `sink_context` is a genuinely *not-yet-determined* post-detection label —
  the crawl-discovered point cannot know it in advance, so a rule
  depending on it was structurally unsatisfiable at that stage. `PA-0006`'s
  fix is "a rule keys only on what its stage can know; a rule must not
  depend on a value derived later."
- This bug's root cause: in the **ground-truth-sourced** pipeline,
  `sink_context` *is* already known in advance (it is a real, populated
  field on the ground truth's own `Case`) — this is not a "value doesn't
  exist yet" problem at all, but a plain propagation/wiring omission: a
  known, available value was simply never copied from one object
  (`Case`) to another (`InjectionPoint`) in one specific function.

Because the root causes differ (unavailable-in-principle vs.
available-but-not-wired), this is **not** a recurrence in the sense
`docs/bugs/README.md` step 8 requires (no prior-PA-failure analysis is
owed — `PA-0006` was never meant to, and could not, have prevented this
different failure mode). It is recorded here as a related sibling for
future search (anyone hitting "a `sink_context`-keyed rule doesn't fire"
should check both this bug and `BUG-0006` for which of the two root causes
applies to their pipeline path), not as a case superseding `PA-0006`.

## Preventive action
See `PA-0043` (`docs/PREVENTIVE_ACTIONS.md`): whenever a ground-truth-driven
audit `InjectionPoint`/`Candidate` construction site is extended to carry a
new field sourced from the ground-truth contract, explicitly check whether
that field lives on the *point* shape or the *case* shape (they are not the
same object and are not automatically kept in sync) — and prove the new
field's real value with an end-to-end test through the actual construction
function, not only a hand-constructed unit fixture that already assumes the
field is present (the same masking `PA-0006` names, generalized: a
hand-built fixture that "helpfully" pre-supplies a field the real
construction path doesn't produce yet hides exactly this defect class,
whether the missing value is un-derivable-yet (`BUG-0006`) or simply
un-wired (`BUG-0041`).
