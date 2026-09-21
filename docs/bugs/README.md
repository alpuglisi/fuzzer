# Bug investigations

Every time a bug is discovered in the code, we generate a **bug investigation
document** here and add its preventive action to `docs/PREVENTIVE_ACTIONS.md`.
This is a required process for the project. See `CLAUDE.md` for how it fits the full
change process (the error-log line, the bug report, and the preventive-action rules
together — not just one of them).

## When

Any defect discovered in the code — a failing test, a wrong result, a crash, a
regression, a security-relevant flaw. If it caused something to fail (or would
have), it gets an investigation document.

## How this relates to the other logs

- `ERROR_LOG.md` (repo root) stays the **lightweight running log** of errors and
  their remediation — a quick, chronological record.
- A **bug investigation document** here is the **rigorous per-bug record**: a
  structured root-cause analysis with a corrective and a preventive action.
- `docs/PREVENTIVE_ACTIONS.md` is the **distilled rule list** — every preventive
  action, with no background, meant to be read and followed while working.

A single bug produces one `ERROR_LOG.md` line, one investigation document here,
and one (or more) preventive-action entries in `PREVENTIVE_ACTIONS.md`.

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
9. **Preventive action** — a change, derived from the root cause, that prevents
   recurrence of this *class* of bug. On a recurrence it must also address the failure
   mode found in step 8 — **strengthen or supersede** the prior PA (cross-reference it),
   not merely restate it. Also recorded in `PREVENTIVE_ACTIONS.md`.

This is distinct from PA-0002 (sweep the *codebase* for other instances of the bug and
remediate them): step 7 sweeps the *bug history* for the same failure repeating despite a
prior rule, and step 8 asks why prevention did not hold. Both apply.

## File naming

`BUG-NNNN-short-slug.md`, numbered in order of discovery, newest numbers highest.
Preventive actions are `PA-NNNN` in `PREVENTIVE_ACTIONS.md` and reference their
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

## Preventive action
<derived from the root cause; on a recurrence, also fixes the step-8 failure mode and
strengthens/supersedes the prior PA. Also added to PREVENTIVE_ACTIONS.md as PA-NNNN>
```
