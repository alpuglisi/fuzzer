# Multi-agent / multi-lane orchestration policy

Canonical policy doc (see `CLAUDE.md`'s "Canonical policy docs" list). This
governs how an orchestrating AI session runs concurrent build lanes and
sub-agents against this repository — process rules for the orchestrator
itself, distinct from the code-level rules in `docs/PREVENTIVE_ACTIONS.md`
(though one of those rules, `PA-0031`, is the enforceable distillation of
this doc's numbering-collision fix; see below).

## 1. Parallelism policy

- Run independent build lanes in parallel whenever their real dependencies
  are satisfied. A lane may itself spawn sub-agents for independently
  buildable sub-parts of its own scope.
- Lanes build out of order whenever their dependencies clear — do not force
  a rigid sequence when the actual dependency graph allows more parallelism.
- The moment an agent completes its lane successfully, reassign it (or
  dispatch a fresh one) to the next unblocked backlog item. Never let an
  eligible, dependency-satisfied lane sit idle while agent capacity is free.
- Scope to offline-buildable work. Nothing that sends real traffic to a
  target, touches production infrastructure, or otherwise carries genuine
  cross-component/downstream risk gets built or skipped silently — it gets
  **flagged** to the user for an explicit decision. This includes (but is
  not limited to): deleting a fixture or other hard-to-reverse repository
  content, re-pointing deployment/production configuration, and any change
  whose correctness cannot be verified within the current sandbox (e.g. no
  Docker/network access) — see §4.

## 2. Independent verification (never trust a self-report alone)

Before merging any lane's work:

- Read the actual diff. A lane's own summary describes what it *intended*
  to do, not necessarily what it did.
- Re-run the relevant test suite yourself, in the lane's own worktree or
  after merging into the integration branch — do not accept a reported pass
  count without reproducing it.
- Spot-check claimed behavior directly (e.g. actually invoke the new
  function/gate/checker, don't just read that a test exists for it).
- Check that the bookkeeping entries a lane claims to have added actually
  exist, with the exact IDs claimed (see §3).

This applies with equal weight to work done by a lane you dispatched and to
your own direct edits when reporting completion to the user.

## 3. Bottleneck reduction: pre-assigned bookkeeping numbers

**The problem.** Every code change here requires bookkeeping entries with
sequential IDs (`CC-<CODE>-NNNN` in a component's `change-control.md`,
`FR-<CODE>-N` in its `requirements.md`, and similarly `BUG-NNNN`/`PA-NNNN`
for bug fixes). When multiple lanes are dispatched concurrently and each is
told to "claim the next free number," they all branch from the same trunk
tip and usually compute the *same* "next free" number — so nearly every
concurrent merge collided, and each collision required manually renumbering
the later-arriving entry, fixing its own cross-references, and re-running
the full suite. Across the first large wave of lanes this session, this
renumbering dance was the single largest source of repetitive manual work
in the whole loop — larger than code review or test runs.

**The fix.** Before dispatching a wave of concurrent lanes:

1. Grep the current trunk state for the highest existing ID in each
   relevant sequence (`CC-<CODE>-NNNN`, `FR-<CODE>-N`, and `BUG-NNNN`/
   `PA-NNNN` if any lane is doing a bug fix).
2. Hand each lane its own reserved, non-overlapping number(s) directly in
   its dispatch prompt — state the exact number to use, not "find the next
   free one."
3. Instruct each lane to use that number *exactly* and to flag loudly
   (never silently improvise a different one) if it finds that number
   already taken at merge time — that signals something outside the plan
   happened and is worth surfacing, not papering over.

This turns numbering from a race condition into a static allocation decided
once, up front, by the one process that can see every lane's identity
before any of them starts writing. Confirmed working repeatedly this
session: waves dispatched with pre-assigned numbers needed at most a
trivial interleaving conflict (two lanes' bullets landing at the same line
of `CHANGELOG.md`, resolved by keeping both) — never an actual number
collision. This is codified as `PA-0031` in `docs/PREVENTIVE_ACTIONS.md`
because it is a rule about repository content (IDs must not collide), not
only a scheduling habit.

**Why per-lane verification wasn't also batched to save time.** A related
temptation is to also batch *test verification* — merge a whole wave's code
first, run the suite once at the end. This was considered and rejected:
per-lane verification (test the suite immediately after each lane merges,
before starting the next) is what actually caught the one real cross-lane
regression this session produced from a merge interaction, quickly and
cheaply, because the diff under suspicion was small and recent. Batching
would have made that harder to isolate, for no real time savings (the
renumbering churn — the actual bottleneck — is already eliminated by pre-
assigned numbering regardless of when tests run). Other rejected
alternatives (append-only fragment files instead of shared bookkeeping
files, fewer/larger lanes, a merge-queue bot) are documented in more detail
in the bottleneck-mitigation writeup produced this session; pre-assigned
numbering was preferred because it fixes the actual observed pain with zero
migration cost and zero new tooling.

## 4. Delegation mechanism fidelity

When a user's instructions specify **how** a delegated task must be carried
out — not just what it must produce (e.g. "spawn agents which spawn further
sub-agents to do X") — verifying the *output* is not sufficient. A delegated
agent can produce an equivalent-looking result via a different, unrequested
mechanism (e.g. doing research itself instead of actually dispatching
sub-agents), and that substitution can pass through completely undetected
unless it happens to self-report it.

Rule: whenever a delegation's instructions specify a required mechanism,
the delegation prompt must explicitly require the sub-agent to confirm, in
its final report, that the specified mechanism was actually used — and must
instruct it to **stop and flag**, not silently substitute, if the required
tool/capability turns out to be unavailable. The orchestrating session must
check for that confirmation before reporting the task complete to the user,
and must proactively disclose any mechanism substitution the moment it is
discovered, not only when a delegated agent happens to volunteer it.

## 5. Flagging genuine risk vs. proceeding autonomously

Auto-mode bias is to make the reasonable call and keep moving rather than
stop for every decision point. That bias does not extend to:

- Hard-to-reverse actions (deleting a fixture, force-pushing, dropping
  data).
- Changes whose correctness cannot actually be verified in the current
  environment (e.g. claiming a deployment works without any way to boot and
  test it).
- A design/scope decision a human maintainer would plausibly want to weigh
  in on (a naming convention baked into shared code, a scope narrowing that
  drops something previously claimed to be true).

For these, do the safe/verifiable parts, then stop and present the specific
open question with your recommendation — rather than either quietly forcing
a decision through or refusing to make any progress at all.

## 6. Shared strict-xfail sentinels across concurrent lanes

A cross-emitter (or otherwise cross-lane) offline check sometimes pins a
still-missing mechanism in another, concurrently-developing lane's own
scope with `xfail(strict=True)`, naming which lane owns fixing it (e.g. a
check enumerating every emitter's absent-input declaration mechanism, with
the ones that don't have one yet marked `xfail(strict=True)` rather than
silently skipped). This has already happened at least twice in this
project's Browsable Labs initiative: two concurrent lanes landed their own
fixes for markers a third lane's check had pinned, and each pinned marker
turned into an unexpected `XPASS(strict)` — a hard test failure — the
moment the fixing lane's own commits merged in, even though neither lane
knew about the other's marker at dispatch time.

**Rule:** the lane that lands the fix for a shared strict-xfail marker
deletes its own marker (or converts it to a positive confirmation) at merge
time, as part of that lane's own merge, not as a follow-up. A concurrent
lane must never delete another lane's still-relevant marker on its own
say-so. When a marker unexpectedly XPASSes after a merge because a
different, unrelated change happened to fix the underlying gap as a side
effect (not the lane's own stated purpose), the orchestrating session
converts it to a positive confirmation and records why in that merge's own
commit message — never silently deletes it without comment, and never
leaves a known-XPASSing strict marker in the tree past that merge.

This generalizes the pre-assigned-numbering fix in §3: a marker shared
across concurrent, not-yet-merged lanes is exactly the same kind of
race-prone shared state a bookkeeping ID is, and deserves the same
explicit, no-silent-improvisation discipline.
