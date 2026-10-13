# BUG-0072 — The unbudgeted pipeline wrote duplicate findings for one confirmation key

- Date: 2026-10-13
- Status: fixed (CC-FUZZ-0056; FR-FUZZ-32 amended)
- Severity: medium. It inflated `findings`, `pipeline_findings` and `requests`, and
  distorted `requests_per_finding`. It put duplicate rows in the report and on the run
  page, and wasted probes. Ground-truth TP scoring is set-keyed, so it was unaffected.

## Description
`points_from_ground_truth` deliberately emits one `InjectionPoint` per distinct
`sink_context` at a key (BUG-0046 / PA-0048). Those points audit to candidate rows with
the same confirmation key `(url, param, method, location, category)`. `_candidate_of`
builds the oracle `Candidate` **without** `sink_context`, so every row of a key sends an
*identical* confirmation. The unbudgeted loop confirmed every row, so a key confirmed
twice wrote two identical findings. The budgeted loop already confirmed once per key, so
budgeted and unbudgeted runs disagreed.

## Where encountered
The error-review phase. Repro: two points differing only in `sink_context` →
`confirmable_keys: 1`, `findings reported: 2`, two identical `('sqli', '/item', 'GET',
'id')` rows. Reachable on the main lab's `/search.php q` and twitch's
`/channels/redirect destination`.

## What it caused to fail
- The run's findings count and `requests_per_finding`.
- The report's and run page's findings lists.
- The CLI summary goldens: `tests/data/auto_summary/score_only.txt` and
  `budget_fallback_nolabels.txt` pinned the duplicate.
- A noisy timing strategy got a second chance on a rejected key, which biases toward
  false positives.

## What the bug was identified to be
The unbudgeted loop iterated rows, not keys, while a key is the unit of confirmation.

## Root cause analysis
Five Whys:
1. *Why two findings?* The loop called `oracle.confirm` once per row, and two rows
   shared a key.
2. *Why did two rows share a key?* BUG-0046's fix emits one point per `sink_context`
   on purpose.
3. *Why was that judged safe?* PA-0048 checked one consumer of a confirmation,
   ground-truth scoring (set-keyed), and declared duplicates "safe to emit".
4. *Why did the findings writer not dedupe?* It is not keyed by confirmation; `finding`
   has no `location`. The pipeline is the layer that knows the key.
5. *Why did no test catch it?* No invariant tied findings to distinct confirmed keys.
   The golden pinned the inflated count as expected output.

**Root cause:** a producer was allowed to emit duplicates after checking only one of the
duplicated unit's consumers, and no invariant enforced "one confirmation per key".

## Corrective action
In CC-FUZZ-0056:
- **The unbudgeted loop** confirms **each key once, on its first row in row order,
  whatever the verdict.** Later rows of a checked key are marked `checked` with no
  further probe. Row order (the bandit's) is kept.
- **No writer-level dedupe.** `finding` has no `location`, so it could merge genuinely
  different findings. It would hide the problem, not enforce the rule.
- **FR-FUZZ-32** is amended in place.
- **Deliberate changes, before → after:**
  - goldens `score_only.txt` and `budget_fallback_nolabels.txt`: `findings
    (oracle-confirmed): 4 → 3`, and `requests: 322 requests/finding: 80.5 → requests:
    306 requests/finding: 102.0` (the duplicate `/search.php q` confirmation is gone);
  - `run.txt` and `earlier.txt` are unchanged (re-run);
  - `test_unbudgeted_run_confirms_rows_in_their_original_order` now expects one confirm
    per key, with order kept.
- **Invariant test:** `tests/test_pipeline_invariants.py::
  test_one_confirmation_and_at_most_one_finding_per_key` covers unbudgeted, budgeted and
  fallback modes. In each, `oracle.confirm` calls == distinct keys, there are no
  duplicate finding rows, and findings ≤ distinct keys. It fails on the pre-fix code in
  the unbudgeted and fallback modes (verified on a copy).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0046 / PA-0048** introduced the duplicate points and declared them "safe to
  emit" because `scoring.score` is set-keyed. **This is a direct consequence of that
  rule:** a different consumer of the same duplicated unit.
- **BUG-0041:** the ground-truth points carried no `sink_context`. That is the same
  area, with a different cause.

**Result:** a recurrence of PA-0048's area. A prior-PA failure analysis follows.

## Prior-preventive-action failure analysis
**PA-0048 judged safety by one consumer** (ground-truth scoring) and never named the
others: the oracle loop and the findings writer. **It was too narrow.** It also asserted
safety in prose, with no invariant test, so the next consumer was **not enforced** either.

## Preventive action
**PA-0073** (in `docs/PREVENTIVE_ACTIONS.md`) strengthens PA-0048:
1. **When a producer may emit duplicates "safely", name every consumer of the duplicated
   unit and check each one.** "Safe" is a claim about all of them, not the first one
   looked at.
2. **Enforce the invariant in every mode.** Here, findings ≤ distinct confirmed keys,
   and confirmations == distinct keys, in unbudgeted, budgeted and fallback modes.
3. **A golden that pins a count is re-derived, not regenerated blindly.** A golden
   change is listed with before/after and its cause.

**Sweep (PA-0002):** the consumers of an audited point or candidate row:
- **Scoring:** set-keyed, safe.
- **Oracle loop:** fixed.
- **Findings writer:** reached only via the loop.
- **Budget prioritizer:** keyed by the first id per key, safe.
- **ML dataset:** one example per candidate row, by design. Duplicate rows share a label
  and a group (endpoint), so folds cannot split them.
- **Anomaly stage:** per candidate, by design.

**New latent defect logged:** the auditor's `sink_context` never reaches the oracle
(`_candidate_of` drops it), although the XSS strategy and `context_for` read
`candidate.sink_context`; the XSS strategy currently types context by reflection alone.
It is triaged to the next review batch, where passing it through must also join
`_confirmation_key`.
