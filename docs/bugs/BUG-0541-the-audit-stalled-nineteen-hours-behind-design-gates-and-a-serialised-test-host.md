# BUG-0541 — The audit stalled nineteen hours behind design gates, one item in work and a serialised test host
- Date: 2026-10-20
- Status: corrective action in force (process); verified by the next checkpoints
- Severity: high (process). The owner's goal metric (open audit defects) did not move from 05:00Z to past 23:54Z.

## Description
After defects 14–17 closed (05:00Z), no audit defect closed for 19 hours while three lanes, two to four reviewers and the orchestrator were busy throughout. The owner asked at 20:55Z, 21:32Z and 23:53Z why.

## Where encountered
The orchestration of the owner's 27-defect audit (goal ledger, `scripts/orchestration_guard.py report`), measured from the session's dispatch log and every `verify_change.py` output directory in the scratchpad.

## What it caused to fail
The goal: 23 of 27 defects open at 23:54Z, against 4 closed in the first 7.4 hours. The guard's stall (18.4 h), review-cap and budget triggers were all in force.

## What the defect was (measured)
1. **Design gates before code.** Defect 6 was dispatched at 06:14Z as "measure and draft only; do NOT implement", then went through four design-review rounds (10:19, 14:29, 17:29 and the confirming review); code started at 19:17Z: 13 hours of drafting and review for one defect. The site-tree bug went the same way (14:28Z → code at 19:17Z).
2. **One audit defect in work.** From 10:50Z to 21:34Z the three slots held defect 6, the site-tree bug (not an audit defect) and the test lock or the paused redaction design; the other 20 defects were never dispatched.
3. **The test host idle while the work was paper.** Between 05:00Z and 21:30Z verification runs held the host about 190 of 990 minutes (~19%); the rest went to drafts (one of 1,245 lines) and reviews.
4. **After the owner's 21:33Z switch, a serialised host and per-item harness cost.** One host-wide pytest lock (BUG-0532) serialises every run on 4 cores; a harness run is 6 (docs), 16 (~150 files) or 29 minutes (408 files). Each item took three or more (lane, revision, merge) plus lane proof matrices (60 reverts, 33 mutants) on the same lock. Measured waste in that window: a lane stopped its own run at 96% (28 min; recorded with the site-tree merge); a revision started a 131-file run without running the spider tests it touched (4 failures, 16 min, and a re-run; F-113); and the site-tree change edits `tests/conftest.py`, so the orchestrator's local merge of it first would have made every later verification of the branch a 29-minute full run.

## Root cause analysis (Five Whys)
1. Why did no defect close for 19 hours? Each item needed 9–18 hours from dispatch to a verified merge, and only one audit item was in work for most of the day.
2. Why so long per item? The orchestrator gated every defect behind a measured design draft and up to four two-reviewer rounds before any code, then a full harness, two implementation reviewers, a revision and two more harness runs.
3. Why that pipeline? It was the orchestrator's reading of "measure before design" (CLAUDE.md 8) and of the reviews' findings: each round found real issues, so each round looked justified, and no rule weighed the round against the goal's clock.
4. Why was the capacity unused? The orchestrator filled slots with whatever was in flight (a non-metric bug, process work) instead of the queue, and the stall trigger (PA-0141) was reported late (F-108) and then treated as a reporting duty, not a reason to change the pipeline.
5. Why did the switch not fix it? The switch cut review rounds but kept the per-item harness cost and the unbatched, unordered merges, on a host that serialises every pytest.

**Root cause:** the orchestrator ran each defect through a design-first, multi-gate pipeline sized for one item at a time, with no budget tying a gate's cost to the goal's clock, and treated the single test host's serialisation as a given instead of planning merges and runs around it.

## Corrective action
In force from 23:58Z (this session; recorded in CHANGELOG):
- Lanes implement first: the failing test, then the fix; no design draft or pre-change review unless the change alters a store or wire contract.
- A lane's test budget: targeted test files first (one invocation), each new test proven once on the pre-fix code, then one harness run with `--base` = its last green commit; no revert matrices or mutant suites except for a shared primitive's guard.
- Merges are pushed from each lane's verified commit as soon as it is green, ordered so a suite-wide change (`tests/conftest.py`) goes last, one full run instead of one per merge.
- The queue is batched into larger lanes (disco state 1–4 and 13; proxy framing 18–20; performance 22, 24, 25; legacy spider 5, 9–12; request identity 7, 8); at most one of three slots holds work that does not move the metric.

## Recurrence review
`docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` searched for stall, throughput, review round, budget, idle, lock, orchestration: **F-108** (the stall not reported until asked), **PA-0141..PA-0147** (progress governance: stall, review cap, budget, WIP), **BUG-0532 / PA-0532** (the host lock), **PA-0031** (pre-assigned numbers). Same class as F-108: progress not tied to the owner's metric.

## Prior-preventive-action failure analysis
- **PA-0141 (stall)** fired at ~11:00Z but required only a report and a process item; the report came late (F-108) and no item changed the pipeline itself (*not followed, and too narrow*: it names no cause to look for).
- **PA-0142 (review cap, 3 rounds)** was exceeded (defect 6: 6 rounds, site tree: 5) because each owner message reset the count and the orchestrator read each new message as leave to continue (*not enforced*: the guard logged "Last user message: none seen" after restarts and could not count).
- **PA-0145 (4 h budget)** was exceeded by both items without a decision being asked for (*not followed*).
- **PA-0532** serialised the host correctly but nothing planned around its throughput (*wrong layer*: a correctness rule with no capacity rule beside it).

## Preventive action
PA-0541 (below).
