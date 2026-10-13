# BUG-0088 — Bandit hierarchical backoff never took effect

- Date: 2026-10-13
- Status: fixed (CC-SCHED-0006, CC-UI-0049)
- Severity: medium-low. `fuzzlab auto --bandit` (which enables backoff) never transferred
  what one context learned to a cold sibling (T4.5's purpose).

## Description
With `backoff=True`, `_seed` gives a fresh (context, arm) a prior from its first
**parent** context that has a posterior. But `update` only ever wrote the leaf, so no
parent posterior ever existed and every cold context started from the catalog prior.
After 20 confirmed pulls in `sql-injection:query`, `sql-injection:body` still sat at
0.5.

## Where encountered
The error-review phase (`scratchpad/review7/r8_backoff.py`).

## What it caused to fail
FR-SCHED's T4.5 backoff, silently: the on and off behaviours were indistinguishable.

## What the bug was identified to be
A reader (`_seed`) of state that no writer produced.

## Root cause analysis
1. *Why a flat prior?* No parent posterior existed.
2. *Why none?* `update` wrote the leaf only.
3. *Why undetected?* The backoff test (`test_scheduler.py::test_backoff_inherits_parent_strength`)
   called `update()` on the **parent context directly**, which production never does
   (pulls are made in leaf contexts only), so it tested `_seed`, not the system.
4. *Why no on/off test?* No rule required a feature switch to show an observable
   difference.

**Root cause:** a feature tested through a state its producer never creates (a pull in
a parent context). That is BUG-0069's class, at the behaviour level.

## Corrective action
- **Pooling (CC-SCHED-0006).** With backoff on, `update` also updates each parent context
  (`context_parents`: the category, then the root `""`). Parents count the pull
  (`cost_n`) but no cost: cost ordering reads leaves only. The regret metric stays
  leaf-only. Backoff off is unchanged: no parents are ever created.
- **Labels (CC-UI-0049).** The ML tab and the diagnostics table label parent contexts
  "(pooled)", and the root "(all contexts, pooled)". A parent's mean cost shows
  "n/a (pooled)".
- **Existing stores:** parents start empty and accumulate from new pulls. They are not
  rebuilt from leaves, whose α/β mix catalog priors with evidence. Stated.
- **Tests** (`tests/test_scheduler_backoff.py`):
  - through the real oracle, a cold sibling is seeded above 0.5 and bounded by
    `backoff_strength`;
  - off → no parents;
  - parents count pulls with no cost and survive save/load;
  - the panels label pooled rows, and no pooled cost shows 0.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0069 / PA-0071** (a reader of a column with no production writer, masked by a
  hand-seeded fixture). **Same class at the behaviour level:** `_seed` read parent
  posteriors that only the test created (by pulling in a parent context).

**Result:** a recurrence of BUG-0069's class.

## Prior-preventive-action failure analysis
**PA-0071 was too narrow:** it was scoped to **store columns**, with a schema-derived
guard. Here the unwritten state is in memory (a dict of posteriors), outside the
guard's reach. Its rule 1 — "a test must not supply by hand a value production never
writes" — would have applied, but it was not followed, because the backoff test
predates it.

## Preventive action
**PA-0089** (strengthens PA-0071 from columns to any state):
1. **A feature switch is tested by its observable effect through the production
   path.** `backoff=True` must change a cold context's prior after real pulls. A flag
   whose on and off runs are indistinguishable in a test is a defect.
2. PA-0071 rule 1 applies to in-memory state as well as columns: a test never seeds
   state its producer does not create, unless it also tests the producer.

**Sweep (PA-0002)** — boolean options in the scheduler, ML and oracle constructors,
checked for an on-versus-off test through the production path:
- `cost_normalized`: `test_scheduler`;
- `hybrid`: `test_ml_anomaly`, `test_ml_budget_and_scope`, `test_ml_persist`;
- `holdout`: `test_ml_holdout_calibration`;
- `calibrate`: `test_ml_holdout_calibration`;
- `redact_secrets`: **no off-path test existed.** Added
  (`test_proxy_redaction.py::test_the_redaction_opt_out_keeps_raw_bytes`);
- `intercept_responses`: `test_proxy_response_intercept`, `test_web_intercept`;
- `allow_destructive`: `test_destructive_send_gate`;
- `backoff`: fixed here.
