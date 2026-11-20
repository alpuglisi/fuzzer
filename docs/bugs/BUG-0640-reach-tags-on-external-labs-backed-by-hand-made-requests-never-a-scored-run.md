# BUG-0640 — Three secDevLabs positives were tagged reachable from ground-truth points that no scored run could reach

- Date: 2026-11-20
- Status: fixed for copy-n-paste and mongection (CC-LAB-0360, commit 684fab9); comment-killer
  recorded open (its case has no store URL; an answer-key correction is the owner's call)
- Severity: medium. Five reachable-tagged positives were guaranteed false negatives on a
  freshly brought-up lab, and the answer keys' `[reach:]` tags overstated what fuzzlab
  measures there.

## Description
Lane ACC re-measured the 11 external labs at 2be7a50 with `fuzzlab auto --points
ground-truth`. Seven secDevLabs apps had never been scored by fuzzlab; their positives were
tagged `[reach: gt]` (or `crawl,gt`) from requests made by hand at bring-up. Three of
those labs scored zero on positives that a hand-made request reaches:
- **copy-n-paste** (tp=0, fn=3): its points (`/login user`, `/register user`) had no
  `json_body`, so each probe sent the one field. The Go handler binds every field and
  answers `400 "All fields are required"` before the query (measured 2026-11-20:
  `user=a'` alone → that 400; `user=a'&pass=x` → MariaDB error 1064). The page posts
  JSON `{user, pass[, passcheck]}` (`app/views/form.html:123-150`, `app/types/types.go:4-14`).
- **mongection** (tp=0, fn=2): its NoSQL injection (`{"$ne": ...}` in both login
  fields) answers *an account*; the lab's database is tmpfs and the fixture had no
  bootstrap, so a fresh lab had none. Measured: `{"$ne": null}` in both fields →
  `Bad Credentials` until one account was registered, then the welcome page.
  CC-LAB-0309's "checked live" was made after accounts had been created by hand.
- **comment-killer** (fn=1): SDLCK-0001 is a stored-XSS case without `source_url`, so
  `auto` never audits it (CC-LAB-0313 says so), yet it is tagged `[reach: gt]`.

## Where encountered
Lane ACC's baseline table (CC-LAB-0360), the first scored runs of these labs.

## What it caused to fail
Five positives (SDLCNP-0001/0002, SDLMG-0001/0002, SDLCK-0001) could never be detected
from a fresh lab, and their reach tags told a reader they were measured as reachable.

## What the bug was identified to be
Lab-data and fixture defects behind one process gap: a reach tag was assigned from a
hand-made request, whose conditions (every field present, an account existing, a store
URL) differed from what `auto` sends, and no scored run of the lab was ever recorded.

## Root cause analysis
Five Whys:
1. *Why tp=0?* The probes never reached the sink: a missing field (copy-n-paste), no
   account to answer (mongection), no store URL (comment-killer).
2. *Why was that not noticed when the labs were built?* Each lab's change-control entry
   records a manual live check of the sink, not a `fuzzlab auto --score` run
   (CC-LAB-0303, 0309, 0311/0313); only streaming and ecommerce-api record scored runs.
3. *Why did a manual check stand in for a run?* The reach tag's meaning ("a ground-truth
   pass reaches this point") was assumed to follow from "the sink is vulnerable" plus
   "the point names the right parameter".
4. *Why did nothing compare tags with runs?* No record of the scored runs existed in a
   form a test reads; the live test covers only bWAPP and Juice Shop.
5. *Why not covered by an existing rule?* PA-0042 asks that a class be verified live
   through fuzzlab's real scoring, but only when mapping a new class, and is enforced by
   nothing; PA-0311 asks a *negative* be backed by a live probe of every path.

**Root cause:** reach tags were set from hand-made requests and never checked against a
scored ground-truth run, because no such run was recorded in a checkable form.

## Corrective action
CC-LAB-0360 (commit 684fab9): copy-n-paste's points carry the JSON body the page sends
(FR-LAB-361); mongection gets an identity and a bootstrap that registers and verifies
one account (FR-LAB-360). Re-measured live: copy-n-paste tp 0→2 (requests 67→25),
mongection tp 0→2, fp 0 on both. SDLCK-0001 is recorded open (see "Open").

## Recurrence review
Checked `docs/bugs/` for reach tags and live-scoring gaps, and `docs/PREVENTIVE_ACTIONS.md`
for rules on ground truth and live scoring. Matches: **BUG-0040 / PA-0042** (a strategy
confirmed in isolation scored a false positive end to end: same root cause, a live check
that is not fuzzlab's scored run) and **BUG-0311 / PA-0311** (a ground-truth label proven
on the wrong path).

## Prior-preventive-action failure analysis
- **PA-0042** was scoped too narrowly (mapping a new vuln class into
  `_VULN_TO_CATEGORY`) and is not enforced (`Enforced by: none`). Adding a *lab* with
  already-mapped classes never triggered it, so copy-n-paste (sqli), mongection (nosqli)
  and comment-killer (xss-stored) were built without a scored run.
- **PA-0311** targets negatives and the paths an input reaches output by; it says
  nothing of what a positive's reach tag claims.

## Preventive action
**PA-0640** (strengthens PA-0042 and PA-0311(1)): a `[reach: gt]` tag on an external lab's
positive is backed by a recorded scored `fuzzlab auto --points ground-truth` run that
matched it; a positive that run missed is listed with its reason, `open: ...` when the tag
stays. The record is `docs/components/01-target-lab/external-lab-scores.json`, checked by
`tests/test_external_lab_scored_runs.py` (proven on this bug's own copy-n-paste shape).

Sweep (PA-0002): every external lab was re-run (CC-LAB-0360); every gt-tagged positive the
AFTER runs missed is in the record as `open:` with its cause. No other tag is unbacked.

## Open
SDLCK-0001 (no `source_url`: making it auditable means changing the case, an answer-key
correction left to the owner with upstream PR #568 as the evidence) and the other open
misses listed in CC-LAB-0360.
