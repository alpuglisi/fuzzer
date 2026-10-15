# Bug investigations (formal CAPA)

A bug investigation document here is the **formal corrective and preventive action
(CAPA)** record. Since 2026-10-15 (`docs/QUALITY_POLICY.md` §4, D70) it is written only
for:
- a significant escape;
- a recurring or systemic defect;
- a security or data-integrity event;
- a **failed control** (a guard, hook or rule that let the defect through, or that
  blocked the wrong thing).

An ordinary defect gets an `ERROR_LOG.md` entry (reproduction, correction, regression
check, scope) and its regression test, and nothing more. The earlier rule, "every defect
gets a document and a new PA", produced 158 documents and 163 PAs with heavy overlap.
The lean quality review (`docs/quality/LEAN_QC_PROPOSAL_REV3.md`) found that this cost
delivery time without showing better quality.

## How this relates to the other logs

- `ERROR_LOG.md` (repo root) is the **running log of every defect** and its remediation.
- A **bug investigation document** here is the **rigorous CAPA record**: a structured
  root-cause analysis, a corrective and a systemic action, an owner, a due date and an
  effectiveness plan.
- The **controls** live in `docs/QUALITY_POLICY.md` (families L01..L12) and their history
  in `docs/PREVENTIVE_ACTIONS.md`, joined by `docs/quality/pa_control_map.tsv`. A CAPA
  **corrects the existing control** (its map row and its mechanism). It adds a new PA
  only for a mechanism no control covers.

## Required contents of every investigation

1. **Description** — a brief description of the bug.
2. **Where encountered** — file/tool/test/context where it showed up.
3. **What it caused to fail** — the observable failure or impact.
4. **What the bug was identified to be** — the specific defect.
5. **Root cause analysis** — the investigation, using an RCA strategy (e.g. Five
   Whys, or fault-tree / differential analysis), ending in the **root cause**.
6. **Corrective action** — what was changed to fix this instance (reference the
   commit / change-control entry that delivered it).
7. **Recurrence review** *(before deciding the preventive action)* — review the other
   bug logs in `docs/bugs/` **and** `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence
   of the *same bug* or a *different bug with the same root cause*. State what you
   checked and the result (which prior `BUG-NNNN`/`PA-NNNN`, or "none found").
8. **Prior-preventive-action failure analysis** *(required only when the recurrence
   review finds a match)* — a documented investigation of **why the earlier preventive
   action did not prevent this recurrence** (e.g. it was too narrow, targeted the wrong
   layer, was not actually followed, or was not enforced/verifiable). Name the prior
   `BUG-NNNN` and `PA-NNNN`. Do **not** proceed to a new preventive action until this is
   written.
9. **Systemic action** — the change, derived from the verified cause, that prevents
   recurrence of this *class* of defect. Prefer correcting the existing control (its map
   row and its mechanism) to a new PA. On a recurrence it must fix the failure mode found
   in step 8, not restate the prior rule.
10. **Owner, due date and effectiveness plan** — who owns the systemic action, by when,
    and the **predeclared criterion** that closes it: what will be observed, over which
    opportunities. Until then the CAPA status is `provisional`. A green regression test
    alone does not close a CAPA.

Step 7 sweeps the *bug history* for the same failure repeating despite a prior control.
The sweep of the *affected surface* for other instances (PA-0002, as rewritten) is
bounded by the mechanism and the risk; serious unrelated findings become separate items.

## File naming

`BUG-NNNN-short-slug.md`, numbered in order of discovery, newest numbers highest. When two
branches used one number, keep both and record an alias in the later one; never renumber
history. Preventive actions are `PA-NNNN` in `PREVENTIVE_ACTIONS.md` and reference their
originating `BUG-NNNN`.

## Template

```
# BUG-NNNN — <short title>

- Date: YYYY-MM-DD
- Status: investigating | fixed
- Severity: low | medium | high

## Description
## Where encountered
## What it caused to fail
## What the bug was identified to be

## Root cause analysis
<RCA strategy and steps>
**Root cause:** <the underlying cause>

## Corrective action
<what was changed; commit / change-control reference>

## Recurrence review
<other bugs in docs/bugs/ and rules in PREVENTIVE_ACTIONS.md checked for the same bug
or the same root cause; result — the matching BUG-NNNN/PA-NNNN, or "none found">

## Prior-preventive-action failure analysis
<ONLY when the recurrence review found a match: why the earlier PA did not prevent this —
too narrow / wrong layer / not followed / not enforced — naming the prior BUG-NNNN + PA-NNNN.
Omit this section when no recurrence was found.>

## Systemic action
<derived from the verified cause; the control corrected (map row / mechanism), or the new
PA-NNNN for an uncovered mechanism; on a recurrence, also fixes the step-8 failure mode>

## Owner, due date and effectiveness
- Owner: <role>  - Due: <date>
- Effectiveness criterion: <what will be observed, over which opportunities>
- Status: provisional | effective | failed (reopen the control)
```
