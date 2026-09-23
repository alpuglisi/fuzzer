# Overnight autonomous build plan (2026-09-23)

Saved per the user's explicit instruction before logging off for the night.
This documents the orchestration mechanism, the standing decision-making
policy for every session involved, and the ordered phases this session will
drive through unattended. Nothing here overrides `CLAUDE.md`'s mandatory
bookkeeping (tests, CHANGELOG, change-control, bug protocol) — it only
governs *when* work happens and *who* decides at a fork in the road.

## Standing policy (applies to every session below, at every step)

- **Never stop building** because a category or task isn't finished. Keep
  working until it is.
- **At any decision point that would normally go to the user**, proceed with
  whatever recommendation you would have given them — do not pause and wait.
  This mirrors the pattern already established this session (AskUserQuestion
  answers of "proceed with your recommendation," "just do the plan," etc.).
- **Never skip the safety/process rules already in force**: lab-only/
  authorized-only traffic, no force-push, no rewriting shared branch history,
  full bug protocol for any real defect found, tests green before every
  push, drift-check (`git fetch` + compare) before every push.
- Going idle is only correct once a category (or, in later phases, the whole
  fuzzlab task list) is actually complete — not merely "waiting on
  something" without having checked what.

## Mechanism: how the 5-minute cadence actually works

The platform's own recurring-Routine scheduler has a **1-hour minimum**
interval (confirmed live: a `*/5 * * * *` cron was rejected with "the
minimum interval is 1 hour"). A true 5-minute cadence is achieved instead by
this orchestrating session (`session_01SrrzECYkKSAYXnFVSYsVjw`,
`claude/second-target-cat1-ecommerce`) waking **itself** every 5 minutes via
a chained `send_later` reminder (each firing reschedules the next one) and,
on each wake, manually firing a **poke-only Routine** (no schedule of its
own — created with neither `cron_expression` nor `run_once_at`) bound to
each of the 4 category sessions via `fire_trigger`. `fire_trigger` has no
hourly floor; only a Routine's own built-in cron schedule does.

An **hourly safety-net Routine**, self-bound to this same session, exists in
case the 5-minute `send_later` chain ever breaks (session restart, a missed
reschedule) — it resumes the same check/fire/reschedule loop.

## The 4 poke-only Routines (created 2026-09-23, fire on demand only)

| Category | Session ID | Branch | Trigger ID |
|---|---|---|---|
| 2 | `session_01SBHvRAhniKAQ5PGBaDtqD5` | `claude/category-2-build-bomomg` | `trig_015sfqyFFMgv2PGuXHyh5d2y` |
| 3 | `session_01TkbFTAcTEUYAfUUrYv1ZdW` | `claude/category-3-build-iuu5k9` | `trig_01LaWa4PTCJikQ3ZiA7QY1jP` |
| 4 | `session_018Y8cwvh62SEFvizs32op5z` | `claude/category-4-build-t9uz3y` | `trig_01VdmhRo7Sm31BNaa6wPrheN` |
| 5 | `session_01LKUDZ39Nc6kondRcqjXz3o` | `claude/category-5-build-6boejs` | `trig_01DPDYJwE8YBDTi49rF1okdm` |

Each Routine's prompt asks for a one/two-sentence status, tells the session
to go idle only if fully built, otherwise to keep building without stopping,
and to resolve any decision point itself rather than waiting on the user —
matching the standing policy above.

## Phase 1 (now → all 4 categories complete)

Every 5 minutes (via the `send_later` chain):
1. `fire_trigger` on all 4 poke-only Routines above.
2. Check each session's status (`get_session`/`list_sessions` — branch
   state, `post_turn_summary`).
3. If a session's own report or branch state indicates its category is
   genuinely complete (all planned cells built, tested, committed, pushed),
   stop poking that one; it may sit idle.
4. If not all 4 are complete, reschedule the next `send_later` wake for
   +5 minutes and repeat.

## Phase 2 (all 4 categories complete)

Merge and sync application code + docs across all 5 branches into one
unified state, using the same discipline already proven earlier this
session (see the merge commits on `claude/second-target-cat1-ecommerce`
around 2026-09-23, commits `94a12be`..`c2b8850`):
- Fetch each branch fresh immediately before merging it (drift-check).
- Merge sequentially (cat2 → cat3 → cat4 → cat5) into this branch.
- Resolve conflicts by inspection, not blind auto-merge: additive
  registries/enums/docs get unioned; append-only logs get concatenated and
  checked for duplicate headings/IDs; genuine cross-branch bookkeeping-ID
  collisions (BUG-NNNN/PA-NNNN/CC-*/FR-*) get renumbered, never silently
  overwritten.
- Run the full non-slow test suite after every merge step; only commit once
  green.
- Push the merged result back to all 5 branches as fast-forwards (verified
  ancestor check before every push, exactly as done earlier).

## Phase 3 (merge/sync complete)

Push the unified branch to `main`. Same discipline: fetch `main` fresh,
verify no destructive history rewrite is needed (fast-forward or a clean
merge commit only), full test suite green immediately before the push.

## Phase 4 (main is pushed — ongoing, does not stop)

Begin working the outstanding fuzzlab task list, deciding autonomously at
every fork per the standing policy above, continuing without stopping:

1. **`docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md`** — the 39 manufactured
   vulnerable/secure pairs across 33 (feature+language cell, CWE) groups.
   Work through them in the order listed (worst gaps — zero natural
   pairs — first), following that plan's own per-pair mechanics
   (alteration, `-altered` naming, `derived_from` manifest entry,
   validation via the gVisor sandbox where dynamic execution is needed).
2. After the corpus pairs: re-evaluate `docs/ARCHITECTURE.md` and
   `docs/DECISIONS_AND_ROADMAP.md` for the next concretely buildable,
   offline-capable item (category 6 in
   `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` is the most likely
   next one; `docs/ARCHITECTURE.md`'s stale "Build-status snapshot"
   section is also worth correcting while in there).
3. Anything genuinely requiring live network/browser access (the on-host
   items tracked in `docs/ON_HOST_TASKS.md`) is out of scope for this
   unattended run — flag it in the relevant doc rather than attempting it.
4. Keep applying full `CLAUDE.md` bookkeeping (tests, CHANGELOG,
   change-control, bug protocol, requirements.md currency) on every change,
   exactly as during the attended portion of this session.

## What "stop" actually means here

This plan does not stop working — it can only run out of concretely
buildable, offline-doable items. If that happens, the session should say so
plainly (not manufacture busywork) and keep the check-in cadence going in
case the user adds more scope later.
