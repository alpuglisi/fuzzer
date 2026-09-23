# BUG-0043 — `open_redirect` was silently unreachable in a real scored `run_targets` pipeline: a missing `_VULN_TO_CATEGORY` entry, AND (once fixed) a wrongly-hyphenated `OpenRedirectStrategy.vuln_class` that made every real confirmation score as a false-positive/false-negative pair instead

- Date: 2026-09-23
- Status: fixed
- Severity: medium (a real, already-built, already-verified-live confirmation strategy was silently unreachable through the shared, scored pipeline every ground-truth-driven run uses, project-wide, for as long as `open_redirect` has existed as a concern — not just on this branch)

## Description

Building `CC-LAB-0199` (this stack's first `open_redirect`/`http_redirect_
location` instance, `go_net_http`'s `GET /auth/login-redirect?next=`) and
wiring its manifest cells into `tests/test_multitarget_category4.py::
_twitch_cells()` — the same real, full `run_targets`/`RequestsProbeSender`
pipeline every other Twitch cell already runs through — surfaced that the
new ground-truth case, `TWCH-0014` (`vuln_class="open_redirect"`), never
even got a `candidate` row nominated for it, despite `fuzzlab.oracle.
strategies.OpenRedirectStrategy` (already built) confirming the exact same
URL/param directly via a hand-built `Candidate` (verified first, before
touching the pipeline). Tracing `fuzzlab.harness.auto.run_auto`'s own
category-resolution path (`categories_from_vuln_classes` ->
`fuzzlab.core.runmode.to_category` -> `resolve_run`'s `plan.categories`
-> `fuzzlab.audit.engine.evaluate`, scoped to `plan.categories`) showed
`to_category("open_redirect")` returned `"open_redirect"` (underscore,
unchanged) rather than `"open-redirect"` (hyphen) — the actual category
`lab/audit/rules_data/default_rules.json`'s own `R-OPEN-REDIRECT` rule is
filed under. `fuzzlab.core.runmode._VULN_TO_CATEGORY` had no
`"open_redirect": "open-redirect"` entry, so `open-redirect` never entered
`plan.categories` at all, so `evaluate()` never nominated a candidate for
that category, so the oracle never even tried `OpenRedirectStrategy`
against the new page — the exact underscore/hyphen category-mapping
mismatch this project has already hit repeatedly (`access_control`,
`insecure_deserialization`, `jwt_algorithm_confusion`, and, per
`fuzzlab/core/runmode.py`'s own comment, at least four more found
proactively in one prior session).

That class of bug already has a generic guard test,
`test_every_ruled_strategy_category_is_reachable_from_its_vuln_class`
(`CC-FUZZ-0030`), specifically built to catch it. It did NOT catch this
instance. That guard iterates `fuzzlab.oracle.strategies.
_CATEGORY_TO_CLASS.items()` — the oracle's own internal, already-
self-consistent `category -> vuln_class` dict — and skips any pair where
`vuln_class == category` (reasoned: "identical either way, no
`_VULN_TO_CATEGORY` entry needed"). `_CATEGORY_TO_CLASS["open-redirect"]`
was itself `"open-redirect"` (identical, hyphenated both times), so the
guard's own early-continue fired and it never checked this pair at all.
The reason `_CATEGORY_TO_CLASS["open-redirect"] == "open-redirect"` in the
first place: `OpenRedirectStrategy.vuln_class` was itself set to the
literal string `"open-redirect"` (hyphenated) — copied from its own
`category` field, rather than underscored like every other strategy's
`vuln_class` in the file (`AccessControlIdorStrategy.vuln_class ==
"access_control"`, `InsecureDeserializationTypeConfusionStrategy.
vuln_class == "insecure_deserialization"`, etc. — all underscored,
matching ground truth's own `labels.json` `vuln_class` enum spelling,
while only `category` is hyphenated to match the rule's category slug).
`OpenRedirectStrategy` was the one strategy in the file that broke this
established convention.

This second defect was independent, and NOT surfaced merely by fixing the
first: after adding `"open_redirect": "open-redirect"` to
`_VULN_TO_CATEGORY` (closing the reachability gap), a real
`run_targets()` run against the real booted app still scored `TWCH-0014`
as a false positive/false negative pair, not a true positive — because
`fuzzlab.harness.scoring.score`'s matching key is the exact tuple `(url,
method, param, vuln_class)`, and the `finding` row's `vuln_class` comes
straight from the oracle `Verdict`'s own `vuln_class` field
(`OpenRedirectStrategy.confirm()` returns `Verdict(True, self.vuln_class,
...)`), which was `"open-redirect"` (hyphen) — never equal to ground
truth's own `"open_redirect"` (underscore) `Case.vuln_class`, regardless
of whether the category was reachable.

Fixing that second defect (re-hyphenating `OpenRedirectStrategy.
vuln_class` to `"open_redirect"`) also surfaced a third, genuine (not a
bug) finding while re-running the real pipeline: `R-OPEN-REDIRECT`'s own
`name_regex` (`url|next|redirect|return|dest|goto|continue|target`)
matches the substring `dest` inside `destination` — the exact parameter
name `CC-LAB-0198`'s own existing `http_header_injection` page already
uses (`/generated/labgen-go-0025?destination=`). Once `open-redirect`
became a reachable category for the first time, `OpenRedirectStrategy`
correctly, honestly confirmed that same page as ALSO open-redirect-
vulnerable (verified live: a plain external `destination=https://
evil.example/x`, no CRLF involved at all, produces a real `302 Location:
https://evil.example/x`) — a real, independent CWE-601 at a sink this
project already knew was CWE-113-vulnerable, which its existing secure
twin (`allowlist_and_runtime_crlf_rejection`) already independently
closes too (verified live: the same external-URL payload gets HTTP 400).
Ground truth had only ever labeled that url/param with the
`http_header_injection` class, so this genuine second finding initially
scored as a false alarm until a second, honest ground-truth case
(`TWCH-0015`, same url/param, `vuln_class="open_redirect"`) was added —
`fuzzlab.labels.contract`'s own supported multi-vuln_class-per-endpoint
pattern (`Case.key` includes `vuln_class`, so two cases sharing a
url/param but differing vuln_class score independently).

## Where encountered

`tests/test_multitarget_category4.py::
test_both_apps_run_through_multitarget_for_real`, while wiring
`lab/manifests/open_redirect_login_go_sample.yaml`'s cells into
`_twitch_cells()` for `CC-LAB-0199`. First noticed as `TWCH-0014` showing
up in `ScoreReport.missed` despite a direct, hand-built `Candidate` call
to `OpenRedirectStrategy().confirm(...)` against the identical real
booted URL/param confirming successfully moments earlier (the same
"confirm it directly first, then wire the pipeline" discipline this
task's own instructions required as a `BUG-0042` regression check).

## What it caused to fail

- `open_redirect`'s own ground-truth cases were silently unreachable in
  EVERY real, scored `run_targets`/multitarget pipeline run, project-wide,
  for as long as `open_redirect` has existed as a concern (`CC-LAB-0210`)
  — not specific to this branch or this new page. Category 5's own
  Booking.com pilot (`BKNG-0001`) shares the identical root cause and was
  never run through a scored multitarget pipeline to notice.
- Even after fixing the reachability gap, `OpenRedirectStrategy`'s own
  real confirmations against a real target would score as a permanent
  false-positive/false-negative pair rather than a true positive, in any
  component that computes `fuzzlab.harness.scoring.score` — silently
  understating recall and inflating the false-alarm count for every
  `open_redirect` positive case in the project, on every branch.
- `TWCH-0013`'s own existing page went undetected for a second, genuine
  vuln class (`open_redirect`) it has always had, simply because nothing
  had ever made that category reachable before to notice.

## What the bug was identified to be

Two independent, compounding defects in code that predates this branch's
own new page:
1. `fuzzlab.core.runmode._VULN_TO_CATEGORY` was missing an
   `"open_redirect": "open-redirect"` entry (a category-mapping gap).
2. `fuzzlab.oracle.strategies.OpenRedirectStrategy.vuln_class` was set to
   `"open-redirect"` (hyphenated, matching `category`) instead of
   `"open_redirect"` (underscored, matching ground truth and every other
   strategy's own convention) — a scoring-key spelling gap, independent
   of (1) and only visible once (1) was fixed.

## Root cause analysis

Five Whys:
1. Why did `TWCH-0014` show up as a missed (false negative) case in a
   real `run_targets` run, despite `OpenRedirectStrategy` confirming the
   identical candidate directly? No `candidate` row was ever nominated
   for it — `fuzzlab.audit.engine.evaluate()` is scoped to
   `plan.categories`, and `"open-redirect"` (the real `R-OPEN-REDIRECT`
   rule's category) was never in that set.
2. Why was `"open-redirect"` never in `plan.categories`? `runmode.
   to_category("open_redirect")` (the ground-truth vuln_class string,
   underscored) returned it UNCHANGED — `_VULN_TO_CATEGORY` has no entry
   for it, so the fallback (return the input as-is) applied.
3. Why didn't the existing generic guard test catch this missing entry,
   when it exists specifically to catch this bug class? It iterates
   `_CATEGORY_TO_CLASS.items()` — the oracle's OWN internal dict, not
   ground truth's real vuln_class strings — and
   `_CATEGORY_TO_CLASS["open-redirect"]` was itself `"open-redirect"`
   (identical to the category), which the guard's own `vuln_class ==
   category: continue` line treats as "no mapping needed," skipping the
   check entirely.
4. Why was `_CATEGORY_TO_CLASS["open-redirect"]` itself `"open-redirect"`
   rather than `"open_redirect"`? Because `OpenRedirectStrategy.
   vuln_class` (the source `_CATEGORY_TO_CLASS` is built from) was itself
   wrongly hyphenated, breaking the same underscore-for-vuln_class/
   hyphen-for-category convention every OTHER strategy in the file
   follows correctly.
5. Why did that wrong spelling ship and stay unnoticed until now? No
   existing test asserts a `ConfirmationStrategy.vuln_class` value
   against a real ground-truth `labels.json` file's own `vuln_class`
   spelling — `tests/test_oracle_vectors.py`'s own `open_redirect` tests
   build `Candidate(vuln_class="open-redirect")` themselves (hand-typed to
   already match the strategy under test) and never assert on
   `Verdict.vuln_class`'s own value, so a self-consistent-but-wrong
   spelling round-tripped cleanly through every existing test.

**Root cause:** `OpenRedirectStrategy` broke this project's own
established `vuln_class` (underscored, ground-truth-matching)/`category`
(hyphenated, rule-matching) naming convention when it was first written,
and the ONE guard test built specifically to catch category-mapping gaps
of this shape derives its check entirely from the oracle's own internal,
self-consistent state (`_CATEGORY_TO_CLASS`) rather than from what ground
truth actually contains — so a strategy's own self-consistent internal
mis-spelling made that guard blind to the exact class of bug it exists to
prevent.

## Corrective action

- `fuzzlab/core/runmode.py::_VULN_TO_CATEGORY` — added `"open_redirect":
  "open-redirect"`.
- `fuzzlab/oracle/strategies.py::OpenRedirectStrategy.vuln_class` —
  corrected from `"open-redirect"` to `"open_redirect"` (matching every
  other strategy's own underscore convention); `_CATEGORY_TO_CLASS[
  "open-redirect"]` updated to `"open_redirect"` to match.
- `tests/test_oracle_vectors.py::
  test_category_to_oracle_class_maps_every_new_category` — updated its
  one affected assertion (`category_to_oracle_class("open-redirect")`) to
  the corrected value.
- `tests/test_labgen_go_live_boot.py::
  test_real_boot_proves_the_open_redirect_differential_for_both_twins` —
  asserts `verdict.vuln_class == "open_redirect"` directly (a regression
  test for defect 2, not just a re-run of the pre-existing suite).
- New, stronger generic guard: `tests/test_oracle.py::
  test_ground_truth_vuln_classes_with_a_ruled_hyphenated_twin_are_mapped`
  — scans every real `lab/ground-truth*/labels.json` file for the
  vuln_class strings ground truth actually uses (not the oracle's own
  internal dict), and asserts `to_category` resolves any whose naive
  underscore->hyphen form names a real, ruled category. Verified to FAIL
  on the pre-fix code (reproduced the exact `open_redirect` gap) before
  the `_VULN_TO_CATEGORY` fix, and to pass after — a real regression test
  for defect 1, not a tautology.
- Third, genuine (not a bug) finding closed honestly rather than routed
  around: added `TWCH-0015` (`lab/ground-truth-twitch-clone/labels.json`/
  `expectedresults.csv`) — a second, honest `open_redirect` label at
  `CC-LAB-0198`'s own existing url/param (`/generated/labgen-go-0025`,
  `destination`), verified live on both twins (vulnerable: a plain
  external `destination` produces a real off-site `302`; secure: the
  identical payload is rejected with HTTP 400).
- Re-verified live, end to end: `tests/test_labgen_go_live_boot.py::
  test_real_boot_proves_the_open_redirect_differential_for_both_twins`
  and `tests/test_multitarget_category4.py::
  test_both_apps_run_through_multitarget_for_real` both pass against the
  real booted apps after all three fixes (the latter scored `TWCH-0014`
  as missed before fix 1, as a false-positive/false-negative pair after
  fix 1 alone, and as `tp=12, fp=0` — the correct outcome — only after
  fix 1 + fix 2 + the `TWCH-0015` ground-truth addition together).
- Swept (PA-0002) for other strategies whose `vuln_class` might likewise
  differ from its own `category` in the SAME way (hyphenated to match
  `category` instead of underscored to match ground truth): every other
  `vuln_class = "..."` assignment in `fuzzlab/oracle/strategies.py` was
  read directly (not grepped for a pattern that could itself miss a
  variant) — `OpenRedirectStrategy` was confirmed to be the only one.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of the same bug, or a different bug with the same root cause.

**Found a direct match at the root-cause level, not merely an analogous
class: this is the same underscore/hyphen category-mapping mismatch
`fuzzlab/core/runmode.py`'s own comment already documents finding
repeatedly** (`access_control`, `insecure_deserialization`,
`jwt_algorithm_confusion`, and — per that comment's own text —
`unrestricted_file_upload`, "the seventh instance of this same
underscore/hyphen mismatch found in this session"). No standalone
`BUG-NNNN` document exists for any of those prior instances (they were
fixed in-line, with the fix and its own reasoning recorded only in
`runmode.py`'s comment and in `CC-FUZZ-0030`'s change-control entry, not
in a dedicated bug report) — this is itself notable but is a documentation-
completeness gap for a PAST change, not something this entry can retroactively
fix; it is named here for the record.

## Prior-preventive-action failure analysis

The relevant guard, `test_every_ruled_strategy_category_is_reachable_
from_its_vuln_class` (built per `CC-FUZZ-0030`, itself presumably guided
by whatever preventive reasoning motivated it, though no dedicated
`PA-NNNN` entry for THAT specific guard was found in
`docs/PREVENTIVE_ACTIONS.md` at the time of this investigation), was
built with the RIGHT intent — catch exactly this mismatch class before it
ships — but checked the WRONG layer: it validates that the oracle's own
internal `_CATEGORY_TO_CLASS` dict and `runmode._VULN_TO_CATEGORY` stay
inverses of EACH OTHER, which only proves internal self-consistency. It
never cross-checks either of those dicts against what ground truth's real
`labels.json` files actually contain — the layer where `to_category` is
actually invoked at run time (`categories_from_vuln_classes` calls it with
`ground_truth.positives()`'s own `vuln_class` strings, never with
`_CATEGORY_TO_CLASS`'s own keys). This is the "wrong layer" failure mode
CLAUDE.md's own bug workflow names: the guard's assumption that "the
oracle's own vuln_class label for a category" and "what ground truth
spells that category's vuln_class as" are always the same string held for
every OTHER category by accident of consistent authorship, and broke
silently the one time a strategy's own `vuln_class` field was itself
mis-spelled — the guard was never actually testing the invariant it was
meant to test, in the one case that mattered.

## Preventive action

See `PA-0045` (`docs/PREVENTIVE_ACTIONS.md`): supersedes/strengthens the
implicit intent behind `CC-FUZZ-0030`'s own guard by adding a SECOND,
independent guard (`test_ground_truth_vuln_classes_with_a_ruled_
hyphenated_twin_are_mapped`) that checks the invariant against the real
data layer (every `lab/ground-truth*/labels.json` file's own `vuln_class`
strings) rather than against the oracle's own already-self-consistent
internal dictionary — closing the specific "checks internal consistency,
not real ground truth" failure mode named above, not merely restating
`CC-FUZZ-0030`'s original intent a second time.
