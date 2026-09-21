# BUG-0016 — Grey-box "new-code reward" starved by the global frontier (false NOTE)

- Date: 2026-09-21
- Status: fixed
- Severity: medium (misleading/contradictory output; the coverage-reward property was not
  actually demonstrated, though the exit still passed via db_fault)

## Description
`fuzzlab greybox-run` printed a self-contradictory summary on the host: step 6 declared
`PASS` (payload max reward 0.600 > baseline max 0.397, `db_fault=1`), yet step 5 reported
`new-code max: 0.000` and a NOTE "new-code reward did not exceed baseline — is the cov.php
shim installed…?" — even though the shim *was* installed and 338 novel lines were captured.
The "new-code" metric and its NOTE were wrong.

## Where encountered
On the host, `scripts/greybox_e2e.sh` step 5 (Part E), in
`on_host_verification_20260921_105007.txt` (commit 172060e). The exit self-check passed but
the summary contradicted it and emitted a false "shim not installed?" warning.

## What it caused to fail
No functional failure (the exit passed), but the output was misleading: it looked like the
grey-box coverage instrumentation was broken when it wasn't, and it did **not** actually
demonstrate the T3.7 property ("a request reaching new application code produces a higher
reward") — the payloads scored higher via db_fault/screening, with zero coverage credit.

## What the bug was identified to be
`run_greybox` used a single **global** `CoverageFrontier` and sent the benign **baseline
first** on each point. The baseline (running first) consumed the point's coverage as
"novel", so every subsequent attack probe saw `novel=0`. Two consequences: (a) the benign
baseline earned a large novelty-only reward (0.397), inverting the intended story; and (b)
`newcode_reward` (max reward among non-baseline probes with `novel>0`) was ~always 0, so
the NOTE (`newcode_reward <= baseline_reward`) fired spuriously. The NOTE also conflated
"no attack had global novelty" with "the shim isn't wired."

## Root cause analysis
Five Whys:
1. Why did the NOTE fire? `newcode_reward (0.0) <= baseline_reward (0.397)`.
2. Why was `newcode_reward` 0? No non-baseline probe had `novel>0`.
3. Why not? Novelty was measured against a **global run-wide frontier**, and the benign
   baseline ran first per point, consuming that point's lines before any attack probe.
4. Why did that also make the baseline look high-reward? Its reward was pure global-novelty
   (0.397), because it was the first to reach the point's code.
5. Why did the metric mislead about the shim? The NOTE inferred "shim not installed" from
   "no attack had novelty", which is an artifact of (3), not a signal about the shim.

**Root cause:** the reward's novelty and the `newcode_reward`/NOTE were computed against a
**global** frontier that the benign baseline fills first, instead of a **per-point
differential** (what the attack reaches beyond its own point's benign control). So the
metric measured frontier ordering, not "the attack reached new code", and the NOTE
diagnosed the wrong thing.

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. **Reoccurrence found (same class):**
the Part F "bandit beats the fixed order" exit uses `pipeline_requests_per_finding`, which
is dominated by crawl/screening and cannot move with the bandit's oracle-probe savings —
so that exit, too, **cannot measure the capability it claims** (flagged during review of
the earlier on-host log; not previously opened as a bug). Both are the same class as
BUG-0014 (documentation/verification claiming what wasn't actually shown): here a *metric /
self-test can pass or fire while not measuring the capability*.

## Prior-preventive-action failure analysis
PA-0015 (write runbook steps from an executed, verified run; ship a fail-loud self-test)
did not prevent this: the grey-box `[run]` flow *was* executed and its self-test passed —
but a self-test passing does not guarantee the **metric measures the right thing**. Part
E's exit passed for the wrong reason (db_fault, not coverage) while its own summary
contradicted it; Part F's metric can't move at all. PA-0015 covers "the step runs and its
assertion passes", not "the assertion/metric isolates the specific capability". That gap
let this class through.

## Corrective action
- `run_greybox` now measures each attack's coverage as a **per-point differential**:
  baselines are sent first to establish the point's benign coverage, and an attack's
  `new_lines_vs_baseline = |attack_lines − baseline_lines|` drives both the reward novelty
  and `newcode_reward`. The global frontier is kept only for the run-wide exploration total
  (`greybox_novel_lines`/`frontier_size`), never for per-attempt reward. Benign baselines
  now earn ~0 (true controls); an attack reaching new branches scores strictly higher.
- The CLI NOTE now fires only when **no application coverage was captured at all**
  (`coverage_lines_seen == 0`) — the genuine "shim not wired" case — and the summary prints
  `app coverage lines seen`. (CC-FUZZ-0017)
- Part F's runbook exit was reframed to verify the bandit by **what it learns** (posteriors)
  and documents the metric caveat, since `requests_per_finding` can't show the oracle-probe
  savings on this lab (oracle-probes-per-finding metric tracked as a follow-up).
- Tests: `tests/test_greybox_live.py` now asserts the baseline earns 0 and the attack's
  new-code credit is per-point, and a new regression proves a second point's attack still
  scores new lines even when those lines were globally seen by the first point.

## Preventive action
PA-0017 (see `docs/PREVENTIVE_ACTIONS.md`): an exit criterion / self-test metric must
**isolate and measure the specific capability it claims to prove**, via a controlled
comparison (e.g. attack-vs-its-own-baseline differential), not a proxy dominated by
unrelated work (a global frontier the control fills first; a total-requests count
dominated by discovery). A passing self-test is not sufficient if the metric doesn't
reflect the capability — and a diagnostic message must key on the actual failure it names
(e.g. "no coverage captured" ⇒ coverage-seen == 0), not on a derived artifact.
