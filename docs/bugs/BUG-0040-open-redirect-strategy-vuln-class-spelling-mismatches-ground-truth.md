# BUG-0040 — `OpenRedirectStrategy.vuln_class` was hyphenated, so a confirmed finding never matched ground truth and scored as a false positive

## Description

After fixing `BUG-0039`, the same live reproduction against Booking.com's
real cells produced a real, confirmed `Verdict` for the vulnerable twin —
but `fuzzlab.harness.multitarget`'s own scoring run against the real
`lab/ground-truth-booking-clone/` ground truth recorded `tp=0, fp=1, fn=3`
instead of the expected `tp=1, fn=2`: the confirmed finding was counted as
a **false positive**, not a hit.

## Where encountered

The same standalone reproduction used for `BUG-0039`, extended to call the
real `fuzzlab.harness.multitarget.run_targets` end to end (not just
`OpenRedirectStrategy.confirm()` in isolation), before drafting
`CC-CORE-0021`'s change-control entry.

## What it caused to fail

`fuzzlab.harness.scoring.score()` matches a detection to a ground-truth
case by an exact `(url, method, param, vuln_class)` key
(`fuzzlab/harness/scoring.py`'s own docstring). The confirmed finding's
`vuln_class` is written verbatim from the confirming strategy's own
`vuln_class` class attribute (`fuzzlab.harness.integration.
detections_from_store` reads the `finding.vuln_class` column directly,
which `Oracle.confirm()` sets from the `Verdict.vuln_class`` the strategy
returned). `OpenRedirectStrategy.vuln_class` was `"open-redirect"`
(hyphenated), while every ground-truth case for this class — this
project's `labels.schema.json` `vuln_class` enum, every `open_redirect`
manifest's own `class:` field, `lab/safety_matrix.yaml`'s `open_redirect`
concern — uses `"open_redirect"` (underscored). The two strings never
match, so `case.key` and `Detection.key` always differ, and the real,
correctly-confirmed finding could never be credited as a true positive no
matter how correct the underlying detection was.

## What the bug was identified to be

Checked every other `ConfirmationStrategy.vuln_class` in `fuzzlab/oracle/
strategies.py`: `SqliErrorStrategy`/`SqliBooleanStrategy`/
`SqliTimingStrategy` all use `"sqli"`, `ReflectedXssStrategy` uses
`"xss-reflected"`, `SstiStrategy` uses `"ssti"`, `DomXssStrategy` uses
`"xss-dom"`, `StoredXssStrategy` uses `"xss-stored"` — every one of these
matches this project's own ground-truth `vuln_class` spelling for that
class exactly (confirmed against `labels.schema.json`'s enum and real
`labels.json` files). `OpenRedirectStrategy` alone used the *category*
spelling (`"open-redirect"`, matching its own `category` attribute and
`fuzzlab.oracle.strategies._CATEGORY_TO_CLASS`'s key) instead of the
`vuln_class` spelling — an isolated naming inconsistency in this one
strategy, not a systemic pattern (every sibling strategy already gets this
right). `fuzzlab/web/results.py`'s severity map already carries *both*
spellings (`"open-redirect": "medium", "open_redirect": "medium"`) —
independent, indirect evidence that this exact spelling ambiguity was
already a latent risk elsewhere in the codebase, just never traced back to
its source until this bug's own RCA.

## Root-cause analysis (Five Whys)

1. **Why did a correct detection score as a false positive?** The
   finding's `vuln_class` (`"open-redirect"`) never matched any ground-
   truth case's `vuln_class` (`"open_redirect"`), so `scoring.score()`
   could not link them.
2. **Why does `OpenRedirectStrategy.vuln_class` use the hyphenated form?**
   It was authored to match its own `category` attribute
   (`"open-redirect"`) rather than this project's established `vuln_class`
   convention for this class — plausibly because, at authoring time, no
   `open_redirect` ground truth existed anywhere in this project to check
   the spelling against (this project's corpus had no `open_redirect`
   manifests until category 5's `CC-LAB-0210`, long after this strategy
   was written).
3. **Why was this never caught before now?** No ground truth exercising
   `open_redirect` existed until `CC-LAB-0210` (2026-09-22/23), and no
   scoring run against real ground truth for this class had ever been
   attempted until this entry's own live-verification step — the same
   underlying timing gap `BUG-0039` shares (a code path only category 5's
   own new vuln class could ever reach).
4. **Why did nothing else catch the `vuln_class`/`category` spelling
   split?** There is no test asserting that every `ConfirmationStrategy`'s
   `vuln_class` attribute equals a real, schema-valid ground-truth
   `vuln_class` token — each strategy's own unit tests (`test_oracle_
   vectors.py` included) construct `Candidate`s directly and never
   round-trip through real ground-truth scoring, so a spelling mismatch
   with the *ground-truth* convention specifically was invisible to every
   existing test.
5. **Root cause:** `OpenRedirectStrategy.vuln_class` was authored using
   this module's own internal `category` spelling convention rather than
   the project-wide ground-truth `vuln_class` spelling convention every
   sibling strategy already follows, and no `open_redirect` ground truth
   existed to catch the divergence until now.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of this bug, or a different bug with the same root cause:

- **`BUG-0039`** (this same session, found immediately before this entry
  while verifying the same `open_redirect` mapping) shares the "first real
  exercise of a code path only category 5's new vuln class could reach"
  circumstance, but is a genuinely different root cause (a missing
  transport setting vs. a naming-convention mismatch) — not a recurrence,
  a sibling gap found by the same verification pass. No preventive-action
  failure analysis applies; this needs its own, narrower rule.
- No other prior bug or `PA-NNNN` addresses `vuln_class`/`category`
  spelling consistency specifically.

## Preventive action (`PA-0042`)

Added to `docs/PREVENTIVE_ACTIONS.md`: **before mapping a new vuln class
into `fuzzlab.core.runmode._VULN_TO_CATEGORY` (wiring a real confirmation
path for it), verify live, end to end, through `fuzzlab.harness.
multitarget.run_targets`'s own real scoring — not just
`ConfirmationStrategy.confirm()` in isolation — against real ground truth
for that class, checking the resulting `ScoreReport.tp`/`fp` values, not
only that a `Verdict` object was returned.** A strategy can confirm
correctly and still score as a false positive if its `vuln_class`
attribute's spelling doesn't match the ground-truth convention — a gap
`confirm()`'s own return value alone can never surface. Sweep (`PA-0002`):
checked every other `ConfirmationStrategy.vuln_class` against this
project's `labels.schema.json` enum and real `labels.json` files (see
"What the bug was identified to be" above) — no other strategy has this
mismatch; `open_redirect` was the only vuln class in this project's
history to reach real ground truth without first being scored end to end.

Corrective action for this specific bug is recorded in `CC-CORE-0021`'s
own change-control entry (`fuzzlab/oracle/strategies.py`'s
`OpenRedirectStrategy.vuln_class` corrected to `"open_redirect"`), not
repeated here.
