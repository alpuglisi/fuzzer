# BUG-0141 — the orchestrating session ran about 15 hours without progress and without telling the user

- Date: 2026-10-15
- Status: fixed (mechanical enforcement in place; see Residuals)
- Severity: high. No code or lab was harmed, but about 15 hours of autonomous work produced
  one new finding against the stated goal. The user's time and trust were spent, and the
  loop stopped only when the user intervened. This is the same class of failure as
  BUG-0029, mirrored: there the session stopped when it should have kept going; here it
  kept going when it should have stopped and asked.

## Description
Between 2026-10-14 17:57 UTC and 2026-10-15 09:01 UTC, the orchestrating session drove
two feature lanes, two reviewer agents and a chain of bug fixes. The user's goal was "the
fuzzer navigates Juice Shop and Juice Shop's vulnerabilities are detected" (user,
2026-10-13 23:17; Juice Shop chosen 2026-10-14 03:40). Over those 15 hours:
- 39 commits, 22 of them review rounds, review fixes or follow-ups, and 6 merges;
- 42 review requests and 29 lane instructions;
- 82 lettered review-fix items (R1–R9, S1–S11, T1–T6, U1–U10, V1–V2, X1–X5, Y1–Y4,
  Z1–Z6, M0–M10, P1–P4, Q1–Q4, B1–B3, V1–V6);
- 6 bug numbers (BUG-0134 to BUG-0139), of which 3 were caused or triggered by fixes made
  in the same window.

The goal metric went from 6 confirmed findings per run to 6 per run, with 7 distinct
across runs. The one new finding, track-result DOM XSS, arrived at about 06:26.

The session sent the user no report and no notification in that time. The user found out
by asking, at 01:32 ("Oh god, this is still running?"), and again at 06:45 and 09:01.

## Where encountered
The orchestrating session's own conduct (this repository's multi-agent process). This is
not fuzzlab code. Data sources:
- the session transcript: user messages, dispatch tool calls, notifications;
- `git log --all` (`scratchpad/timeline.txt`, 121 commits since 2026-10-13 09:15);
- the coordinator's decision log (D1–D65);
- the retrospective of BUG-0110..0139.

## What it caused to fail
- **The user's goal.** Detection was flat for most of a day:

  | Window (UTC) | Hours | Confirmed per run | What was built |
  |---|---|---|---|
  | 10-14 04:00 → 17:57 | 14 | 1 → 6 | forms phase 3/4, SPA login, BUG-0132, PRG observation, BUG-0133: each one was aimed at a missed finding |
  | 10-14 17:57 → 10-15 09:01 | 15 | 6 → 6 (7 distinct) | origin-scoped sessions (a hardening the session opened itself), SPA query discovery (4 review rounds plus 3 rounds of merge follow-ups), BUG-0134..0139 |

- **The user's ability to steer.** No progress report reached the user unasked:
  - 0 PushNotification calls in the whole session;
  - the user asked for status, progress or an ETA 14 times in two days; each was
    answered, but none was anticipated.

  The user had said they could not watch the process. That made proactive reporting
  *more* necessary, not less.
- **Trust in the estimates.** At 01:32 the session said "roughly 2–3 hours" and
  recommended freezing scope. The push landed at 04:04, but the user had not been told
  the previous 8 hours had not moved the metric. Their question was what made it say so.

## What the bug was identified to be
The orchestration loop was driven by events and had no exit. Each lane or reviewer
notification (74 in the two days) was answered by dispatching the next step: the next
review round, the reviewers' fix list, a merge follow-up, the bug the last fix exposed.
No step compared the work with the goal. Nothing in the loop could end it except
running out of items, and the reviews, merges and fix chains kept generating items.

## Root cause analysis
Strategy: Five Whys on the stall, then a fault tree of what kept the loop running. Both
are checked against the counts above.

**Five Whys**
1. *Why did 15 hours produce one finding?* Most of the effort went into work that did not
   move the metric:
   - review rounds (4 design and code rounds on FR-CRAWL-17, 4 on origin scope, then
     merge follow-ups M0–M10, P1–P4 and B1–B3);
   - a security hardening the user had not asked for (origin-scoped sessions; useful,
     but not detection);
   - a 4-link fix chain in the browser navigation guard (BUG-0134 T1 → BUG-0136 →
     BUG-0137 → BUG-0138).
2. *Why was that not noticed?* Progress was never measured against the goal on a schedule.
   Live Juice Shop runs happened only at push points (three in the window). No ledger
   recorded the metric over time, so "busy" and "progressing" looked the same from
   inside the loop.
3. *Why did the session not investigate and fix the stall once it was visible?* Nothing
   prevented it. The session did see the stall. At 01:32 it told the user that detection
   had not improved since the last push, and why the work had taken so long. Then it went
   back to the same loop: it finished the in-flight items, and later started more.

   Recognising a failure to improve and investigating it is what building is. The
   "investigate why" step came at 06:45, and only because the user asked. The stall
   itself was a defect: the process was producing no progress. The session should have
   handled it the way this project handles every defect, with a root cause, a fix and a
   report, hours earlier and without being asked.

   Process rules written by earlier sessions gave it no prompt to do so:
   - **PA-0032** (from BUG-0029): check in only for "a genuine blocker".
   - **The overnight plan:** "Never stop building."
   - **MULTI_AGENT_ORCHESTRATION §1:** "never let an eligible [lane] sit idle".
   - **§5:** its list of reasons to stop had no "not progressing".

   None of these forbade the investigation; they simply never called for it. The
   user's instructions were not a cause. "Don't stop building" and "proceed with the
   recommended option" directed the session through decision points so the work would
   not wait on the user. They never asked for work to continue without progress. The
   session's failure was treating activity as building.
4. *Why did the work keep expanding instead of converging?*
   - **No review exit.** Reviewers asked to find problems always find some, and every
     fix list became new code to review: 147 messages to the two reviewers since 10-14
     00:00, and up to 4 rounds per item plus merge rounds. There was no round cap,
     and no split between must-fix and follow-up.
   - **Self-opened scope.** Reviewer remarks became new work items with full design
     gates: origin scope (task 23), the M6 write block (task 25), BUG-0118..0121. At
     decision points the session often picked the option that built more (both modes, a
     switch, an opt-in flag; D1, D2, D6, D29, D30, D34, D54), which added code and review
     surface.
   - **Overlapping lanes.** Two lanes edited `spider.py` and the navigation guard
     concurrently (D39 noted the "expected spider.py merge overlap"). Merging them cost
     M0–M10, P1–P4, B1–B3 and a regression on the merged tree (BUG-0138).
   - **Fix chains not stopped.** The navigation guard's chain reached 7 bugs across two
     days (retrospective C1) with no pause to measure the browser's real behaviour and
     redesign.
5. *Why did none of the existing safeguards catch it?* All of them were prose, addressed
   to the same coordinator whose judgment was failing: PA-0020's exact lesson, never
   applied to orchestration. The hooks the project has check bookkeeping (ERROR_LOG, CWE
   coverage), not progress. Context compaction (every 3–6 hours, 10 times since
   10-13) re-seeded each new context from a "pending tasks / next step" list, which
   carried the momentum forward and never the question of whether it was working.

**Root cause:** the orchestrating session treated activity as progress. It never measured
the work against the user's goal. When the lack of progress was visible (01:32), it did
not treat it as a defect to investigate and fix. Nothing mechanical existed to catch
either failure: no goal metric, checkpoint, stall trigger, cap on review rounds, gate on
self-opened scope, fix-chain trigger or time budget. So the only check left was the user
intervening.

**Contributing factors** (fault tree, each fed the loop):
- event-driven dispatch (every notification led to the next action);
- unbounded review rounds;
- self-opened scope, and picking the option that built more;
- concurrent lanes on the same files;
- a shared mechanism fixed forward instead of measured and redesigned;
- context compaction carrying forward a task list without the goal check;
- no proactive notification channel used.

## Corrective action
- 09:01 2026-10-15: dispatching stopped. Two lanes then in flight (the BUG-0118 safety
  lane and the verification-harness lane) were allowed to finish their current step and
  given nothing further.
- **A stall is now handled as a defect.** Once the stall trigger fires, the guard lets
  through only work aimed at the stall itself: a process or measurement item opened
  after it fired, to find out why the metric is not moving and fix that. It denies
  further dispatch of the stalled work and requires a report to the user. This is the
  "recognise, investigate, address" step the session skipped.
- `scripts/orchestration_guard.py` and three Claude Code hooks (`.claude/settings.json`):
  - a **PreToolUse** gate on every dispatch tool (Agent, Task, SendMessage, Workflow,
    remote create_session/send_message);
  - a **Stop** check;
  - a **SessionStart** report after startup, resume and compaction.

  The guard keeps a goal ledger (git-ignored, one per checkout). It reads the user's
  real messages and the session's notifications from the session transcript, so the
  session cannot clear an escalation itself.
- Docs:
  - PA-0141..PA-0147;
  - PA-0032 and the overnight plan's "never stop building" amended;
  - MULTI_AGENT_ORCHESTRATION §8;
  - the CLAUDE.md orchestration summary.
- `tests/test_orchestration_guard.py` (22 tests). It includes a replay of this incident:
  - the guard forces a report at 20:58;
  - it caps FR-CRAWL-17's review at the third round (22:30);
  - it holds origin scope (self-opened) from the start;
  - it denies further dispatch at 23:57 with a stall, until the user writes.

  That is about 6 hours in, instead of the user intervening about 15 hours in. All 8
  mutation checks of the guard's conditions were caught.

## Recurrence review
Checked `docs/bugs/` (BUG-0001..0140) and `docs/PREVENTIVE_ACTIONS.md` for session-conduct
and orchestration failures:
- **BUG-0029 / PA-0032**: the session paused to ask despite a "keep going" instruction.
  The same failure class (the session's stop/ask judgment against standing
  instructions), in the opposite direction. **Match.**
- **BUG-0019 / PA-0020, PA-0033**: a rule that relies on the session remembering it is not
  prevention; it needs a hook. Same root (an unenforced self-check). **Match.**
- **PA-0031** and MULTI_AGENT_ORCHESTRATION §1–§7: they govern how lanes are dispatched,
  numbered and verified, never whether to keep dispatching. Not a match, but they show
  the gap.
- `docs/OVERNIGHT_AUTONOMOUS_BUILD_PLAN.md` (2026-09-23): "Never stop building"; going
  idle "only once … actually complete". A standing policy that directly opposes a stall
  exit.

## Prior-preventive-action failure analysis
- **PA-0032 (BUG-0029)** was **too narrow, and it pushed the wrong way.** It sorted
  check-ins into two kinds: "genuine blockers", which were allowed, and "natural stopping
  points", which were forbidden. It never considered a third kind: *no progress*. Applied
  to a loop that never runs out of items, it suppressed exactly the check-in this
  incident needed. It was also never enforced (`Enforced by: none — a session-conduct
  rule`).
- **PA-0020 / PA-0033 (BUG-0019)** were **right but not applied** to this layer. Both say a
  self-check needs a hook. Hooks were built for bookkeeping only. PA-0033 even names
  "explicit, quantitative 'do more of X / don't stop' instructions" as needing their own
  mechanical check, yet "do not stop building" got none, and nothing measured whether
  "building" was progress.
- **The overnight plan and MULTI_AGENT §1** were **standing rules with no exit**. They were
  written for a backlog that shrinks; review-driven and fix-driven work grows.
- **MULTI_AGENT §5** was **too narrow.** Its list of reasons to stop and ask had no
  progress, budget or round condition.

The new preventive actions therefore:
- supersede PA-0032 for stalls;
- amend the overnight plan and §1;
- extend §5 with mechanical triggers;
- enforce each trigger with a hook and a test (PA-0020's principle, finally applied to
  orchestration).

## Preventive action
PA-0141..PA-0147 in `docs/PREVENTIVE_ACTIONS.md`, enforced by `scripts/orchestration_guard.py`:
- **PA-0141:** a goal ledger with a measured metric; a checkpoint every 3 h of unattended
  work; a 6 h stall stops dispatch until the user writes, and requires a push
  notification. Supersedes PA-0032 for stalls.
- **PA-0142:** at most 3 review rounds per item between user contacts; reviewers split
  must-fix from follow-up.
- **PA-0143:** work the session opens itself waits for the user, except a defect blocking
  active work.
- **PA-0144:** two bugs spawned by one item's fixes stop the item: measure, redesign, ask.
- **PA-0145:** a time budget per item (default 4 h); overrun means report and ask.
- **PA-0146:** at most 3 active items; no two active items on the same files without a
  declared order (declared files at `item add`, real branch diffs at every Stop).
- **PA-0147:** status replies lead with the guard's report. After a compaction, the
  summary's pending list is not authorization.

**PA-0002 sweep** (other instances of the class, across the repository's process
documents):
- `docs/OVERNIGHT_AUTONOMOUS_BUILD_PLAN.md`'s standing policy: amended.
- MULTI_AGENT_ORCHESTRATION §1 "never let an eligible one sit idle" and the CLAUDE.md
  summary of it: qualified.
- PA-0032: amended to point at PA-0141.

No other process document carries a "never stop" or "do not ask" rule
(`grep -n -i -E 'stop building|never stop|do not stop|keep building|do not wait' docs/*.md
CLAUDE.md`).

## Residuals
- **What the guard trusts.** The metric value comes from the session. A changed value
  needs an evidence file newer than the last checkpoint, but the guard cannot check
  that the file shows what the session claims. Tagging dispatches with `[item: …]` is
  enforced; choosing the right item is not.
- **Any user message clears an escalation,** including an unrelated one. PA-0147 requires
  the report to come first, so the user decides with the data in front of them.
- **Hook changes take effect only when hooks load.** In a session that was already
  running, that means after a restart or a hook review.
- **Sub-agents.** While a goal is open, a sub-agent's own untagged Agent calls are denied,
  except read-only types (Explore, Plan). Lanes should not spawn general-purpose
  sub-agents; when one must, its prompt carries the item tag.
