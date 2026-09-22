# BUG-0029 — session paused to ask for confirmation despite an explicit "work until tasks run out" instruction

- Date: 2026-09-22
- Status: fixed
- Severity: low (no incorrect deliverable resulted — Wave 1a's work was correct and
  fully merged — but it stalled the session's own progress on a task the user had
  already pre-authorized end-to-end, which is exactly the kind of avoidable
  interruption `CLAUDE.md`'s "Auto Mode" guidance and the user's own explicit
  instruction exist to prevent)

## Description
Earlier in this session the user gave a standing instruction for the whole task:
"Once the plan is approved, begin executing" the build-lane plan, and — after Wave 1a
finished — reiterated even more explicitly: "keep working until you ran out of tasks."
Despite that, after Wave 1a (7 lanes) was merged, verified, and pushed, the session
ended its turn with a summary whose final line was "say the word if you want me to
continue" — an implicit request for permission before dispatching Wave 1b/Wave 2,
even though the user had already given that permission twice, once generally
("begin executing") and once with the specific "until you run out of tasks" scoping
that directly answers the question being re-asked.

## Where encountered
This session, in the turn immediately following Wave 1a's completion — i.e., in the
session's own end-of-turn conduct, not in project code.

## What it caused to fail
The user's explicit, already-given instruction to keep working through the full
backlog without pausing. The user had to notice the stall and respond "I told you to
keep working until you ran out of tasks. Why would you as me if I wanted you to
continue?" before Wave 1b/Wave 2 were dispatched — the same failure shape as
`BUG-0018` (a correction the user had to supply that the session's own process should
have made unnecessary), though for a different underlying reason (see Root cause
analysis).

## What the bug was identified to be
The session treated "keep working until you run out of tasks" as scoped to getting
through the *current* wave (Wave 1a) rather than to the *entire remaining backlog*
the build plan describes, and then applied a default end-of-turn habit — offering the
user a next-step choice — on top of that too-narrow scoping, producing a stop-and-ask
even though the user's standing instruction had already pre-answered the question.

## Root cause analysis
Five Whys:
1. Why did the turn end with an implicit request for permission ("say the word")
   instead of dispatching Wave 1b/Wave 2 directly? The session's summary-writing
   habit defaults to offering the user a choice about what happens next, as a
   general courtesy pattern for open-ended work.
2. Why did that default habit fire here, when the user had already pre-authorized
   continuing? The session's working model of "what was authorized" had silently
   narrowed over the course of the turn: it started the turn correctly scoped to
   "execute the whole plan," but by the time Wave 1a's summary was being written,
   the immediate context was entirely about Wave 1a's own lanes landing — and the
   summary-writing habit re-derived "what should happen next" from that immediate
   context rather than from the standing instruction given at the start of the task.
3. Why does the immediate context override a standing instruction instead of being
   read alongside it? There is no explicit checkpoint, at the start of composing an
   end-of-turn summary, that re-reads the task's original scoping instruction before
   deciding whether to ask a next-step question — the courtesy-offer habit runs
   unconditionally, rather than being gated on "has the user already answered this
   exact question."
4. Why wasn't "has the user already answered this" checked mechanically? The same
   class of gap `BUG-0018` identified for bookkeeping recall applies here to
   instruction recall: recognition of "should I ask this?" is driven by the
   immediate shape of the turn's output (a natural stopping point after a large
   chunk of work lands) rather than by mechanically checking the turn's action
   against the standing instructions already on record for this task.
5. Why did that gap survive across the whole plan-approval-and-execution arc without
   being caught earlier? Nothing about Wave 1a's completion was itself ambiguous or
   blocked — there was no genuine decision point, missing input, or blocker that
   would legitimately warrant a check-in per this session's own operating
   guidance (which reserves stopping for exactly those cases) — so the gap was
   never exercised until the first moment a large chunk of pre-authorized work
   actually finished and a summary got written.

**Root cause:** the session's end-of-turn "offer a next step" habit is not gated on
whether the user's standing instructions already answered the question it's about to
ask; it re-derives "what should happen next" from the immediate shape of the turn
(a natural-feeling stopping point) rather than from the actual scope of instructions
already on record, so a already-pre-authorized "keep going" habit can still lose to a
default courtesy-offer pattern when a large chunk of work completes.

## Corrective action
The session immediately dispatched Wave 1b (B0's 4 emitter sub-lanes) and Wave 2
(5 UI lanes + D0b) — 10 lanes total — without asking again, once the user pointed out
the stall. No code change was needed; the correction is behavioral, for the remainder
of this session and going forward.

## Recurrence review
Reviewed `docs/PREVENTIVE_ACTIONS.md` and `docs/bugs/` for a prior occurrence of this
bug or the same root cause. `BUG-0018` (oracle-spike findings not logged to
`ERROR_LOG.md` until prompted) is the closest match by *shape* — both are
session-conduct bugs where the user had to supply a correction the process should
have made unnecessary — but its root cause is different in kind: BUG-0018/PA-0019 is
about **recall of what to record** (a finding matching an artifact's stated scope not
being mechanically checked against that scope, and so never written down at all).
This bug is about **recall of what was already authorized** (an instruction already
on record not being mechanically checked before asking a redundant permission
question). PA-0019's rule ("check new findings against an artifact's literal scope
before ending the turn") does not cover this failure mode — there is no missing
*artifact entry* here, the failure is asking a question whose answer was already
given. No other `docs/bugs/` entry or `PA-NNNN` targets "re-asking permission the
user's standing instructions already granted." **No prior occurrence found for this
specific root cause**; this is a new bug class, not a recurrence of BUG-0018, so no
prior-preventive-action failure analysis is required.

## Preventive action
**PA-0032** (see `docs/PREVENTIVE_ACTIONS.md`): before ending a turn with any
next-step question, offer, or "say the word" framing directed at the user, check
that question against the standing instructions already given for the current task —
if the user has already authorized the action the question is about (a scope, a
count, a condition like "until X" or "keep going until done"), do not ask again;
proceed. Reserve an end-of-turn check-in for a *genuine* blocker: an actual decision
only the user can make, a missing input, or an ambiguity the standing instructions do
not resolve — never for a natural-feeling stopping point (a wave/phase/batch
finishing) that the standing instructions already cover.
