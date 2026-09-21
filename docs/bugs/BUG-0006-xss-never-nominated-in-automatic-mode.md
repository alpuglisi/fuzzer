# BUG-0006 — Automatic mode never nominated XSS (rule keyed on a label discovery can't set)

- Date: 2026-09-21
- Status: fixed
- Severity: high

## Description
The rules-as-data rule `R-XSS-REFLECT` fired only when an injection point already
had `sink_context ∈ {html, html-attribute, url-attribute, js}`. But `sink_context` is
a **label** — it is only known *after* probing (canary reflection typing) or from the
ground-truth cases; it is not an attribute the discovery/crawl layer sets on a point.
The automatic pipeline (`run_pipeline`) evaluates rules over points that carry no
`sink_context`, so `R-XSS-REFLECT` never fired, no XSS candidate was ever nominated,
and the oracle never got a chance to confirm reflected XSS. Automatic mode could
detect SQLi but was structurally blind to XSS.

## Where encountered
The first live automatic run on the host (`fuzzlab auto` against the lab) and the
ground-truth-points benchmark: `search.php?q` reflected XSS (PFF-0003) scored as a
false negative even though the oracle's M5 strategy can confirm it.

## What it caused to fail
On the live scored run, every reflected/DOM XSS case was a false negative regardless
of the oracle's ability to confirm it — because no XSS candidate reached the oracle.
The Phase 2 exit ("the oracle confirms the lab's known vulnerabilities … reflected
XSS by context") could not be met in automatic mode.

## What the bug was identified to be
`R-XSS-REFLECT`'s `when` predicate depended on a value (`sink_context`) that the
pipeline's upstream never populates, so the rule was dead in the automatic path. The
oracle's reflected-XSS strategy (M5) already types the reflection context itself from
the response (`candidate.sink_context or type_reflection(...)`) and is fail-closed —
so the *rule* only needed to nominate the candidate on what is known pre-detection
(the parameter's location), leaving the precise context decision to the oracle. The
`test_pipeline` fixture masked the gap by hand-setting `sink_context="html"` on the
search point — an input shape the live discovery path never produces.

## Root cause analysis
Five Whys:
1. Why were XSS cases missed? No XSS candidate was nominated for the oracle to confirm.
2. Why no candidate? `R-XSS-REFLECT` requires `sink_context`, which was unset.
3. Why unset? `sink_context` is a post-probe label; the pipeline evaluates rules over
   freshly-discovered points that have no sink typing.
4. Why did the rule depend on it anyway? The rule was authored assuming a prior
   sink-typing step (T2.4) populates it — but that step is not wired into the
   automatic pipeline, so the dependency was never satisfied.
5. Why wasn't it caught in tests? `test_pipeline` hand-set `sink_context="html"` on
   the XSS point, so the fixture didn't match what real discovery produces, and the
   dead rule looked alive.

**Root cause:** a nomination rule depended on a label that only exists post-detection
and that the pipeline never sets, and the test fixture hand-supplied that label so the
gap was invisible until a live run.

## Corrective action
- Changed `R-XSS-REFLECT`'s predicate to nominate on what discovery knows —
  `{"location_in": ["query", "body"]}` (symmetric with `R-SQLI-PARAM`). The oracle's
  M5 strategy does the precise reflection + context + unescaped confirmation and stays
  the sole, fail-closed finding-writer, so escaped/non-reflecting params are correctly
  not confirmed (no false positives). (CC-AUD-0009)
- Broadened nomination shifts negative training examples from "rule did not fire" to
  "oracle nominated but did not confirm", so `run_pipeline` now counts
  oracle-rejected candidates as negatives too (`oracle_rejected`), keeping the
  dataset's negatives meaningful. (CC-FUZZ-0010)
- Updated `test_audit_rules` to the nomination model and confirmed no fixture
  hand-sets a post-detection label to make a rule fire.

## Preventive action
PA-0006 (see `docs/PREVENTIVE_ACTIONS.md`): an integration/pipeline test must feed
inputs shaped like what the real upstream produces — do not hand-populate fields the
live path does not set (e.g. `sink_context` on a freshly-discovered point) to make a
downstream step succeed, or the test masks a wiring gap. A rule/step must key only on
what is available at that stage; anything derived later belongs to the stage that
derives it (here, the oracle types context).
