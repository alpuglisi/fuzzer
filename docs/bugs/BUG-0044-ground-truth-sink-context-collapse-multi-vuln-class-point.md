# BUG-0044 — `fuzzlab.harness.auto.points_from_ground_truth` silently collapsed two ground-truth cases sharing a `(url, method, param)` key but differing `vuln_class` down to ONE `sink_context`, discarding the other

- Date: 2026-09-23
- Status: fixed
- Severity: medium (a real, already-built, already-verified-live confirmation strategy was silently unable to generate even a candidate for a real ground-truth positive, in every scored `run_targets`/multitarget pipeline run, for as long as this project has had two cases sharing a point with different `sink_context` values — currently one instance, `TWCH-0013`/`TWCH-0015`, but the defect is general)

## Description

Building `CC-FUZZ-0041` (`HttpHeaderInjectionCrlfStrategy`/`R-HEADER-INJECTION`,
closing category 4's last known real detection gap, `http_header_injection`
at Twitch's `TWCH-0013`, `/generated/labgen-go-0025?destination=`) and
wiring it into `tests/test_multitarget_category4.py`'s real, full
`run_targets`/`RequestsProbeSender` pipeline surfaced that
`TWCH-0013` still scored as a missed (false negative) finding, despite
`HttpHeaderInjectionCrlfStrategy.confirm()` (already built, already
verified live directly against the real booted vulnerable/secure twins —
`tests/test_labgen_go_live_boot.py::
test_http_header_injection_strategy_closes_the_crlf_detection_gap`)
confirming the identical URL/param directly via a hand-built `Candidate`
moments earlier — the exact same shape of symptom `BUG-0043` diagnosed for
`open_redirect`, but a different root cause this time.

Tracing `fuzzlab.harness.auto.points_from_ground_truth` (the function that
turns `ground_truth.points`/`ground_truth.cases` into the `InjectionPoint`
rows `fuzzlab.audit.engine.evaluate()` actually runs rules against) showed
its `sink_context_by_point` lookup was a plain dict comprehension:

```python
sink_context_by_point = {
    (c.url, c.method.upper(), c.param): c.sink_context
    for c in ground_truth.cases
}
```

`ground_truth.cases` contains BOTH `TWCH-0013`
(`vuln_class="http_header_injection"`, `sink_context="header"`) and
`TWCH-0015` (`vuln_class="open_redirect"`, `sink_context="redirect"`) —
`fuzzlab.labels.contract`'s own supported, already-used
multi-vuln_class-per-endpoint pattern (`BUG-0043`'s own fix legitimately
added `TWCH-0015` at the SAME `(url, method, param)` key `TWCH-0013`
already used, since the same real sink is independently vulnerable to
both concerns). A dict comprehension over a list with duplicate keys keeps
only the LAST value written for that key — `TWCH-0015` came after
`TWCH-0013` in `ground_truth.cases`' own iteration order, so
`sink_context_by_point[(...,"destination")]` ended up `"redirect"`,
silently discarding `"header"`. The single `InjectionPoint` built for that
url/param therefore carried `sink_context="redirect"`, never `"header"` —
`R-HEADER-INJECTION`'s own `sink_context_in: ["header"]` gate never
matched it, so `evaluate()` never nominated a candidate for
`HttpHeaderInjectionCrlfStrategy` to even try.

## Where encountered

`tests/test_multitarget_category4.py::
test_both_apps_run_through_multitarget_for_real`, immediately after adding
`R-HEADER-INJECTION`/`HttpHeaderInjectionCrlfStrategy` and updating that
test's own hardcoded `tp`/recall assertions from 12/12 to 13/13 (per
PA-0042/PA-0043) — the test failed with `tp == 12`, not the expected `13`,
even though a direct, hand-built `Candidate` call to
`HttpHeaderInjectionCrlfStrategy().confirm(...)` against the identical
real booted URL/param had just confirmed successfully (the same
"confirm it directly first, then wire the pipeline" discipline `BUG-0043`
already established as this project's own regression check for this
class of gap).

## What it caused to fail

- `TWCH-0013`'s own `http_header_injection` positive was silently
  unreachable in every real, scored `run_targets`/multitarget pipeline
  run that also carries `TWCH-0015` (i.e., every run since `BUG-0043`'s
  own fix landed `TWCH-0015`) — not a new defect introduced by THIS
  change, but a latent one `BUG-0043`'s own fix introduced without
  noticing, since nothing needed a `sink_context`-gated rule at that
  point until now.
- More generally: ANY future case sharing a `(url, method, param)` key
  with another case (the exact pattern this project's own
  `fuzzlab.labels.contract` module explicitly supports and has already
  used twice, `TWCH-0013`/`TWCH-0015` and, structurally, wherever a future
  corpus does the same) is silently at risk of losing a
  `sink_context`-gated rule's own detection capability for whichever case
  happens to sort earlier in `ground_truth.cases`, for as long as this
  function's own lookup stays a scalar-valued dict keyed only on
  `(url, method, param)`.

## What the bug was identified to be

`fuzzlab/harness/auto.py::points_from_ground_truth`'s `sink_context_by_point`
mapping assumed one `sink_context` per `(url, method, param)` key, when
`fuzzlab.labels.contract`'s own data model (and this project's own prior,
deliberate design decision, `BUG-0043`'s `TWCH-0015` addition) allows more
than one case — with potentially different `sink_context` values — to
share that same key. The dict comprehension's last-write-wins collapse
silently discarded every value but the last.

## Root cause analysis

Five Whys:
1. Why did `TWCH-0013` show up as a missed (false negative) case in a
   real `run_targets` run, despite `HttpHeaderInjectionCrlfStrategy`
   confirming the identical candidate directly? No candidate was ever
   nominated for it under the `http-header-injection` category —
   `evaluate()`'s `R-HEADER-INJECTION` rule (`sink_context_in:
   ["header"]`) never matched the audited `InjectionPoint` for that
   url/param.
2. Why didn't it match? The `InjectionPoint`'s own `sink_context` field
   was `"redirect"`, not `"header"`.
3. Why was it `"redirect"`? `points_from_ground_truth`'s
   `sink_context_by_point` dict comprehension, built from
   `ground_truth.cases`, kept only the LAST case's `sink_context` for that
   `(url, method, param)` key — `TWCH-0015` (`sink_context="redirect"`)
   sorts after `TWCH-0013` (`sink_context="header"`) in
   `ground_truth.cases`' own list order, silently overwriting it.
4. Why does more than one case share that key at all? `BUG-0043`'s own
   fix legitimately added `TWCH-0015` at the SAME sink `TWCH-0013`
   already documents — a genuine, honest second vuln_class at one real
   sink, `fuzzlab.labels.contract`'s own explicitly supported pattern
   (`Case.key` includes `vuln_class`, so two cases sharing a url/param but
   differing vuln_class score independently — the data model was always
   correct here).
5. Why did nothing catch this when `TWCH-0015` was added? No
   `sink_context`-gated rule needed BOTH values at that shared point
   until `R-HEADER-INJECTION` was written — `R-OPEN-REDIRECT` (the rule
   that scores `TWCH-0015`) gates on `name_regex` only, never
   `sink_context`, so it was never sensitive to which value the
   collapsed dict happened to keep.

**Root cause:** `points_from_ground_truth`'s `sink_context_by_point`
lookup was written assuming a one-case-per-point invariant that this
project's own data model does not actually guarantee and had already,
deliberately, violated once (`TWCH-0015`) — the collapse was silent
because nothing exercised the specific combination of "two cases, one
point, different `sink_context`, and a `sink_context`-gated rule for the
one that loses" until this change.

## Corrective action

- `fuzzlab/harness/auto.py::points_from_ground_truth` — replaced the
  scalar-valued `sink_context_by_point` dict with
  `sink_contexts_by_point: dict[key, set[str | None]]`, collecting every
  distinct `sink_context` value per `(url, method, param)` key, and
  changed the point-building loop to emit one `InjectionPoint` per
  distinct value (sorted, for determinism) instead of one point with a
  single, possibly-wrong `sink_context`. For the overwhelming majority of
  points (one case per point), this emits exactly the same single point
  as before — verified no behavior change for every other existing
  ground-truth corpus by re-running the full non-slow suite plus every
  multitarget/live-boot test file (2103 passed, 18 pre-existing unrelated
  failures, same baseline as before this change) — only the one point
  with two distinct `sink_context` values (`TWCH-0013`/`TWCH-0015`'s
  shared `destination` sink) now emits two `InjectionPoint`s.
- Confirmed this duplication is harmless, not merely assumed: read
  `fuzzlab.harness.scoring.score` directly before relying on it —
  `detected_keys = {d.key for d in detections}` is a `set` keyed on
  `(url, method, param, vuln_class)` (never `sink_context`), so a
  duplicate point differing only in `sink_context` costs at most one
  extra, harmless re-probe of every OTHER (non-`sink_context`-gated) rule
  for that one point and can never double-count a TP/FP.
- Re-verified live, end to end: `tests/test_multitarget_category4.py::
  test_both_apps_run_through_multitarget_for_real` scored `TWCH-0013` as
  missed before this fix (with `R-HEADER-INJECTION`/
  `HttpHeaderInjectionCrlfStrategy` already in place) and as a true
  positive (`tp=13, fp=0`) after it.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of the same bug, or a different bug with the same root cause.

**Related but not identical to `BUG-0043`.** `BUG-0043` is about a
category-mapping/vuln_class-spelling mismatch that makes a whole category
unreachable or unscoreable; this bug is about a *different* pipeline
stage (building the audited `InjectionPoint` itself from ground truth)
silently losing per-case data (`sink_context`) when two cases share a
point — a genuinely distinct mechanism, not a recurrence of the same
root cause, even though both were found via the same "confirm the
strategy directly, then check it survives the real pipeline" discipline
`BUG-0042`/`BUG-0043` already established. No prior `BUG-NNNN`/`PA-NNNN`
addresses a collapsed one-to-many mapping in `points_from_ground_truth`
specifically — a genuinely new instance, not a repeat.

## Preventive action

See `PA-0046` (`docs/PREVENTIVE_ACTIONS.md`).
