# BUG-0040 — A ground-truth-only change silently broke two already-pushed, `slow`-marked recall assertions

- Date: 2026-09-23
- Status: fixed
- Severity: medium (silent; no wrong security verdict was ever produced, but a real, already-pushed test regression went undetected past a push and past the next check-in, purely because of which pytest marker happened to sit on the broken file)

## Description
`CC-LAB-0188` ("lab: Netflix's 5th real page, first `price_integrity_bypass`
instance") added a new ground-truth case, `NFLX-0005`, to
`lab/ground-truth-netflix-clone/`. That commit's own pre-push verification —
`python -m pytest -q -m "not slow"` — passed clean (1993 passed, the same 18
pre-existing unrelated failures) and the commit was pushed to
`origin/claude/category-4-build-t9uz3y`.

`tests/test_multitarget_category4.py` carries a module-level
`pytestmark = [pytest.mark.slow, ...]` (line ~191) — every test in that file
is excluded by `-m "not slow"`. Two of its tests hardcode Netflix's total
ground-truth case count as part of their recall assertions:
`test_both_apps_run_through_multitarget_for_real` (`1/4`) and
`test_netflix_multi_cell_boot_confirms_all_positives` (`4/4`). `NFLX-0005`
raised that count to 5, silently invalidating both assertions — but because
neither test runs under `-m "not slow"`, `CC-LAB-0188`'s own pre-push check
could not have caught it, and nothing else in that session's own routine
(which used `-m "not slow"` as its completion bar for every increment this
entire build) prompted running the slow suite either.

The break was only discovered while building `CC-LAB-0188`'s own detection
follow-on (`CC-FUZZ-0037`), whose own author deliberately re-ran the slow
suite as part of verifying the new detection capability — not because
anything in the routine process flagged the two now-failing tests.

## Where encountered
Building `PriceIntegrityBypassStrategy`/`R-PRICE-INTEGRITY`
(`CC-FUZZ-0037`/`CC-AUD-0025`), the detection follow-on for `CC-LAB-0188`'s
`price_integrity_bypass` lab page. The two broken tests were found by
actually re-running `tests/test_multitarget_category4.py` directly (which,
unlike `-m "not slow"`, has no marker filter and so still collects and runs
its slow-marked contents) during that follow-on's own verification — not by
any check `CC-LAB-0188`'s own commit ran.

## What it caused to fail
- `tests/test_multitarget_category4.py::test_both_apps_run_through_multitarget_for_real`
  — its hardcoded `netflix_report.recall == round(1/4, 4)` assertion, stale
  the moment Netflix's total case count became 5.
- `tests/test_multitarget_category4.py::test_netflix_multi_cell_boot_confirms_all_positives`
  — its hardcoded `4/4` recall assertion, stale for the same reason.
- **A third instance, found afterward by a full (non-`-m`-filtered) suite
  re-run rather than by this bug's own initial investigation**:
  `tests/test_auto.py::test_points_from_ground_truth_sets_body_content_type_only_for_json_cases`
  hardcoded Netflix's total whole-body-JSON point count at 3; correcting
  `NFLX-0005`'s own `param` to `"body"` (this same commit's other fix, see
  Corrective action) made it a 4th such point, breaking this assertion too.
  This file is **not** `slow`-marked — it was missed by the *first* `-m
  "not slow"` re-verification pass in this same investigation not because
  of the marker gap this bug is about, but because that pass ran before
  the `param` correction was made, and the correction's own second-order
  effect (changing a *different* count this file depends on) was only
  caught by a subsequent full-suite re-run performed as due diligence
  after the marker-gap fix, not by a targeted check. Recorded here as
  confirming evidence for this bug's own general theme (a ground-truth
  change can invalidate a hardcoded count in a file with no obvious
  connection to the diff) rather than as a fourth distinct root cause.

All three failures were real (each assertion no longer matched the true,
current ground-truth state) but the first two were structurally invisible
to this session's own routine `pytest -q -m "not slow"` pre-push gate —
exactly the gate every other increment in this session (`CC-LAB-0180`
through `CC-LAB-0188`) also used as its own "stable baseline" completion
bar.

## What the bug was identified to be
A hardcoded recall/count assertion, in a test file excluded from the
project's routine non-slow pre-push check by its own `pytest.mark.slow`
marker, depends on a ground-truth directory's total case count — and no
step in the routine change process re-runs (or even names) that specific
slow-marked file when a change touches only the ground truth it depends on,
not the file itself.

## Root cause analysis
Five Whys:
1. Why did two tests start failing after `CC-LAB-0188` was pushed? Their
   own hardcoded recall fractions (`1/4`, `4/4`) no longer matched reality
   once `NFLX-0005` raised Netflix's total ground-truth case count to 5.
2. Why didn't `CC-LAB-0188`'s own pre-push verification catch this?
   `python -m pytest -q -m "not slow"` was run and was green — but both
   affected tests are excluded from that run by a module-level
   `pytest.mark.slow` marker on `tests/test_multitarget_category4.py`.
3. Why wasn't the slow-marked file run anyway, given the change touched
   ground truth this file's own tests plainly consume? Nothing in
   `CC-LAB-0188`'s own diff touched `tests/test_multitarget_category4.py`
   itself, so there was no diff-shaped prompt to re-run it, and this
   session's own established completion bar throughout this entire build
   — repeated for every one of `CC-LAB-0180` through `CC-LAB-0188` — was
   "the non-slow suite stays green," never "also run every slow-marked
   file whose assertions might depend on ground-truth cardinality."
4. Why does this project even mark `tests/test_multitarget_category4.py`
   as `slow`, given it hardcodes exact-count assertions a routine
   ground-truth change can invalidate? Because its tests perform real
   `go build`/`mvn package` + live-boot round trips (expensive, correctly
   excluded from the fast iteration loop) — a reasonable reason to mark it
   slow, but one that has the side effect of also excluding its
   ground-truth-cardinality assertions from the routine safety net.
5. Why did this specific commit (as opposed to any of the eight prior
   `CC-LAB-018x` increments, most of which also added ground-truth cases)
   trigger the break? Every prior page-adding commit in this session
   happened to *also* edit `tests/test_multitarget_category4.py` in the
   same commit (to add its own new cell to `_twitch_cells()`/
   `_netflix_cells()` and update the recall assertion for its own new,
   still-undetected case) — which meant a human/agent editing that file
   was already looking straight at the current, correct assertions and
   fixing them in passing, incidentally covering this gap without anyone
   naming it as a rule. `CC-LAB-0188` was the first "lab page only, no
   `multitarget.py`/test-suite touch at all" commit in this exact
   sub-sequence to add a ground-truth case without also touching that
   file — because its own detection was deliberately deferred to a
   separate follow-on commit, so nothing in its own scope called for
   editing `test_multitarget_category4.py`. The safety net had been
   *incidental*, not structural, and this was the first commit shaped in
   a way that didn't trigger it.

**Root cause:** the project's routine per-increment completion check
(`pytest -q -m "not slow"`) does not, and structurally cannot, exercise any
assertion that lives in a `slow`-marked test file — and no other step in
the routine process re-runs a slow-marked file on a change that only edits
the ground truth that file's own hardcoded assertions depend on, unless
that same change happens to also touch the test file itself. The many prior
increments in this session were protected only by incidentally always
touching `test_multitarget_category4.py` in the same commit that changed
ground-truth cardinality; the first increment in this sub-sequence that
didn't do so (because its detection was deliberately deferred) exposed the
gap.

## Corrective action
- Corrected the two stale assertions in
  `tests/test_multitarget_category4.py` (`1/4`→`1/5`, `4/4`→`5/5`) in the
  same commit (`CC-FUZZ-0037`) that closed `CC-LAB-0188`'s own deferred
  detection gap, re-verified by actually re-running the slow suite (not
  merely editing the numbers to match a theoretical count).
- Corrected the third instance found afterward,
  `tests/test_auto.py::test_points_from_ground_truth_sets_body_content_type_only_for_json_cases`
  (its own hardcoded whole-body-JSON point count, `3`→`4`, plus a new
  explicit assertion for the corrected point's own
  `body_content_type == "application/json"`), found only by a full,
  unfiltered suite re-run performed as due diligence, not by a targeted
  grep — the gap that motivates `PA-0042`'s own grep-first instruction
  below, so the next occurrence is found by search rather than by chance.
- Also corrected, in the same pass, `NFLX-0005`'s own ground-truth `param`
  (`"monthly_charge"` → `"body"`, the project's real whole-body-JSON
  convention `fuzzlab.harness.auto.points_from_ground_truth` requires to
  mark a body point's Content-Type as `application/json`) — a related but
  distinct authoring mistake in the same original commit, caught by the
  same real end-to-end verification pass, not a second instance of this
  bug's own root cause.
- See `CHANGELOG.md`, `CC-FUZZ-0037`
  (`docs/components/07-fuzzing-harness-and-oracle/change-control.md`) for
  the full corrective-action record.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of the same bug, or a different bug with the same root cause.

- **`PA-0040`** (from `BUG-0038`) already establishes a related principle:
  "when a change registers an entry in a shared, cross-stack registry...
  run the whole-repo `pytest tests/` suite... before the change is
  pushed... not only the test file(s) judged directly relevant." This is
  the closest prior relative — the underlying lesson ("a partial/relevant-
  files-only run can miss a real break elsewhere") is the same *shape* of
  problem. But its trigger condition is written narrowly around **shared
  cross-stack module registries** with their own completeness tables
  (`fuzzlab.labgen.modules`'s `_DETERMINISM_CTX_BY_MODULE`), not around
  ground-truth directories or `pytest.mark.slow` exclusion specifically.
  `CC-LAB-0188` is a ground-truth-only change to one app's own directory,
  not a shared-registry registration — it does not match PA-0040's own
  named trigger, so this is not a case of PA-0040 being followed
  incorrectly; it is a case PA-0040's own scope never covered.
- **`PA-0038`** (from `BUG-0036`) requires running "that shape's own test
  module" for a new ground-truth directory. `CC-LAB-0188` did exactly
  that (its own dedicated `tests/test_labgen_spring_boot_subscription_
  price_integrity*.py` files were run and green). `PA-0038`'s own scope is
  the *new* ground truth's own dedicated test module, not a pre-existing,
  unrelated-looking, cross-cutting file elsewhere in the suite whose
  assertions merely happen to depend on that ground truth's total count.
  Following PA-0038 exactly would not have caught this.
- **`BUG-0039`** (`points_from_ground_truth` never propagated
  `sink_context`) is a related sibling in the same general territory
  (a ground-truth-driven pipeline defect discovered only by a real
  end-to-end run, not by unit tests) but its root cause is a missing
  field-propagation step in production code, not a stale hardcoded test
  assertion excluded by a pytest marker. Different root cause, no
  prior-PA-failure analysis owed for that one either.

**No prior bug or preventive action actually covers this specific failure
mode** (a `slow`-marked file's hardcoded ground-truth-cardinality assertion
going stale, unprotected by the routine non-slow pre-push check, on a
commit that doesn't happen to also touch that file). This is recorded as a
new class, not a recurrence of `PA-0038`/`PA-0040` — no prior-preventive-
action-failure analysis is owed, since neither PA's own stated scope
covers this trigger shape. It is, however, a **generalization point**: both
existing PAs and this one share the deeper theme "a partial/marker-filtered
test run is not a substitute for identifying every consumer of a value a
change alters" — a theme worth naming explicitly so a future, fourth
variant of it doesn't need its own from-scratch RCA.

## Preventive action
See `PA-0042` (`docs/PREVENTIVE_ACTIONS.md`): before considering any change
to a `lab/ground-truth-*/` directory's case *count* (an added or removed
`Case`, not just a field edit within an existing one) complete, grep the
test suite for every hardcoded fraction/count assertion that could depend
on that directory's total case count (e.g. `grep -rn "recall\|\.tp ==\|/[0-9]\+, 4)" tests/*multitarget*.py tests/*labels_contract*.py`
for the affected app) and explicitly re-run every file such a grep
surfaces — regardless of whether that file carries `pytest.mark.slow` and
is therefore excluded from the routine `-m "not slow"` pre-push check.
`pytest -q -m "not slow"` remains the correct fast-iteration gate; it is
never sufficient, on its own, to certify a ground-truth-cardinality change
complete.
