# BUG-0077 — The bandit panel's pull counts counted prior mass as pulls

- Date: 2026-10-13
- Status: fixed (CC-UI-0048)
- Severity: low. A display defect on the ML tab. Scheduling was unaffected.

## Description
`mlview.bandit_panel` showed each arm's pulls as `α + β − 2`. That assumes a Beta(1,1)
prior. The scheduler seeds arms with **informed** priors (`arm_priors`), and
`ThompsonBandit.order` scores, and thus seeds and saves, every applicable arm. After
exactly one pull in total, the panel showed `error-signature` 3 pulls and
`boolean-differential` 1 pull (stored `cost_n` = 1 and 0).

## Where encountered
The error-review phase (a review agent; reproduced by me).

## What it caused to fail
The ML tab's bandit forest table, which is the only place a user sees how often each
arm was tried.

## What the bug was identified to be
A displayed count was reconstructed from parameters that also encode a prior, instead
of read from the counter the scheduler records (`cost_n`, migration 5).

## Root cause analysis
Five Whys:
1. *Why 3 pulls?* α + β − 2 with a prior of α = 3.
2. *Why that formula?* It assumed Beta(1,1), the default prior. Informed priors
   (`arm_priors`, CC-SCHED-0003) and backoff seeding (CC-SCHED-0004) break that.
3. *Why was it not updated?* Adding informed priors changed the meaning of α + β. No
   rule said to sweep the readers that reconstructed counts from it.
4. *Why did no test catch it?* The panel test pinned `α + β − 2 = 14` on a hand-seeded
   row whose own `cost_n` said 10. The test enshrined the formula.
5. *Why did no rule catch it?* None said "a count is read from its counter".

**Root cause:** a count reconstructed from parameters that are not a count.

## Corrective action
In CC-UI-0048:
- **The panel reads `cost_n`.** `pulls` is the stored `cost_n`, the scheduler's per-arm
  update counter. The column is NOT NULL DEFAULT 0 since migration 5, so a NULL can
  only be a hand-made row: it shows "n/a (legacy)", never 0. Rows from before migration
  5 read 0; that is a stated residual, from a store that old.
- **Tests:**
  - the panel test now asserts the recorded counters (10 and 8);
  - a production-writer test: one pull with informed priors shows 1 pull on the pulled
    arm and 0 on the others (it was 3 and 1).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0069 / PA-0071** (a reader depended on a column production never wrote; a
  fixture supplied it): **related.** Here the counter *was* written, and the reader
  ignored it in favour of a reconstruction. The test fixture again pinned a value
  production does not produce (pulls 14 against `cost_n` 10).

**Result:** not a recurrence of the same root cause; a sibling of PA-0071's "the test
pinned a non-production value". No prior PA covered reconstructed counts.

## Preventive action
**PA-0078** (in `docs/PREVENTIVE_ACTIONS.md`):
1. **A displayed count reads the recorded counter.** Never reconstruct it from parameters
   that also encode something else (a prior, a smoothing term, a default).
2. **A display test asserts the value a production writer records**, not a formula
   applied to a hand-seeded row.

**Sweep (PA-0002):** other counts shown in `mlview`, diagnostics, the run page and the
report:
- **Anomaly flagged counts:** read the stored flags (CC-UI-0046).
- **Oracle coverage:** a `GROUP BY oracle_status` count.
- **Holdout reveal counts:** counted from the reveal rows (`core/sealed.py`).
- **Mutation killed/survived:** counted from rows.
- **Model training rows:** recorded by the trainer.

No other reconstructed count was found.
