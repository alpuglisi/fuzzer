# Bug investigations

Every time a bug is discovered in the code, we generate a **bug investigation
document** here and add its preventive action to `docs/PREVENTIVE_ACTIONS.md`.
This is a required process for the project.

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
7. **Preventive action** — a change, derived from the root cause, that prevents
   recurrence of this *class* of bug. Also recorded in `PREVENTIVE_ACTIONS.md`.

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

## Preventive action
<derived from the root cause; also added to PREVENTIVE_ACTIONS.md as PA-NNNN>
```
