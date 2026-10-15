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
  *Eligible* means within §8's limits. An item held by a trigger (a stall, the
  review-round cap, an overrun budget, a bug chain, or self-opened scope awaiting
  the user) is **not** eligible. Idle lanes are the correct state while the user
  decides (BUG-0141).
- Scope to offline-buildable work. Nothing that sends real traffic to a
  target, touches production infrastructure, or otherwise carries genuine
  cross-component/downstream risk gets built or skipped silently — it gets
  **flagged** to the user for an explicit decision. This includes (but is
  not limited to): deleting a fixture or other hard-to-reverse repository
  content, re-pointing deployment/production configuration, and any change
  whose correctness cannot be verified within the current sandbox (e.g. no
  Docker/network access) — see §4.
- **Never run two lanes on the same file concurrently without a planned merge
  order.** Before dispatch, list the files each lane will edit
  (`git diff --name-only` of its plan, or the modules its design names). If two
  lanes share a file, either serialise them (the second starts from the first's
  merged result) or split the file first; if they must run together, write the
  merge order and who resolves the overlap into both dispatch prompts. Hot files
  (today `fuzzlab/tools/spider.py` and `fuzzlab/tools/navguard.py`) are never
  shared. Two concurrent lanes on `spider.py` and `navguard.py` cost about three
  extra review rounds and a regression bug (BUG-0138) found only on the merged
  tree, after an earlier decision had already identified the cost.

## 2. Independent verification (never trust a self-report alone)

Before merging any lane's work:

- Read the actual diff. A lane's own summary describes what it *intended*
  to do, not necessarily what it did.
- **Re-run the tests with `scripts/verify_change.py --base <ref>`** yourself
  (`--full` for a merge to the integration branch). Never a hand-picked list of
  "relevant" tests: that wording produced hand-picked lists, and one missed a
  test broken for three review rounds. The harness is the rule made mechanical:
  - it verifies the **committed** HEAD in a fresh **detached** worktree and refuses
    a dirty tree (a tree caught mid-edit, or a lane's live worktree, has produced
    false "flaky" failures here);
  - it builds the list from **every test file that imports a changed `fuzzlab`
    module** (AST import analysis over `git diff --name-only <base>..HEAD --
    fuzzlab`, through helpers, lazy imports and string module names), plus every
    changed test file;
  - it adds **every whole-package guard** (lint, traceability, PA enforcement, the
    shared-primitive table, AST scans): they import nothing they check, so an
    import-based list misses them;
  - it runs **one pytest process at a time** (it waits for any other pytest on the
    host), with `FUZZLAB_REQUIRE_BROWSER=1`, `FUZZLAB_REQUIRE_LINT=1` and
    `FUZZLAB_REQUIRE_NETNS=1`, and runs live-boot, timing, procutil, multitarget and
    browser-heavy files in a **serial pass** after the parallel one;
  - it prints the file count and passed / failed / skipped, and records and stops
    only its own processes (never kill by name or pattern).

  Quote its file count and counts in the merge record. A reported pass count
  that the harness has not reproduced is not verification. A failing test is
  never written off as "flaky": root-cause it (load-dependent outcomes have each
  been a real defect or a real verification error here).
- Spot-check claimed behavior directly (e.g. actually invoke the new
  function/gate/checker, don't just read that a test exists for it).
- Check that the bookkeeping entries a lane claims to have added actually
  exist, with the exact IDs claimed (see §3), and that every new PA ends with
  its `- Enforced by:` line (`tests/test_pa_enforcement.py`).

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

§8's triggers are a fourth case, and they are mechanical. When one fires, stop
feeding that work, find out why it fired and fix that, and report.

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

## 7. Measure the real target and the real browser before design

Before a design (a design gate's draft, or a bug fix's planned change) relies on
how a real target or the real browser behaves, **measure it, and cite the
measurement in the design doc**: a short "Measured" section listing each platform
or target behaviour the design depends on, the probe that measured it (a script
or a real-browser test, committed or attached), and the observed result.
Examples of facts that were assumed and turned out wrong here: Playwright's route
sees only a redirect chain's first hop; an `ERR_ABORTED` navigation keeps the
current document; a script navigation refused during parsing never fires
`domcontentloaded`; Juice Shop's server reads the `token` cookie, not the bearer;
a server-side step rejects a quote before the sink.

- A design that names such a behaviour without a measurement does not pass its
  design gate; reviewers check the "Measured" section first.
- Keep a probe that pins a platform fact as a real-browser or real-process test
  (failing, not skipping, under `FUZZLAB_REQUIRE_BROWSER=1`), so a Playwright or
  Chromium upgrade re-checks it.
- A fake (a fake `Page`, route or session) may stand in for the platform only for
  a behaviour a real-browser test has already pinned.

Why: in BUG-0110..BUG-0139, 15 of 25 bugs came from a fixture that did not model
the real data path or from browser behaviour that was assumed rather than
measured (classes T1 and T2), and the most productive review technique was a
reviewer measuring in real Chromium.

## 8. Progress governance: the goal ledger and its triggers (BUG-0141)

An orchestrating session once ran about 15 hours on review rounds, self-opened
follow-ups and a fix chain. Its goal metric moved by one finding. It saw the stall,
did not investigate or fix it, and never told the user until they intervened. Busy
is not building. These rules are therefore enforced by `scripts/orchestration_guard.py` through Claude Code hooks
(`.claude/settings.json`). The hooks read the session transcript, so only a real
user message (or an answer to a question) clears an escalation.

**Before the first dispatch, open the goal ledger:**

    scripts/orchestration_guard.py goal open --text "<the user's goal>" \
        --metric "<the user's measure, e.g. confirmed findings per live run>" \
        --baseline N --evidence <output of the run that measured N> \
        --reviewer <reviewer agent id> ...

Register each work item before dispatching it, and tag every dispatch with it:

    scripts/orchestration_guard.py item add <ID> --title "..." --kind feature|bug|safety|process|measurement \
        --origin user|self [--blocks <active item>] [--spawned-by <item>] \
        [--files a.py,dir/] [--branch b --base ref] [--after <item>] [--budget-hours H]

Every Agent, SendMessage, Workflow or remote-session dispatch carries `[item: <ID>]`.
A review request also carries `[review]`, unless it goes to a registered reviewer.
Read-only agents (Explore, Plan) and messages that start with `STOP` are exempt.

| Trigger | Default | Effect | Cleared by |
|---|---|---|---|
| Checkpoint due (PA-0141) | 3 h since the last checkpoint or user message | Stop hook refuses to end the turn | `checkpoint --value N [--evidence …]` and a PushNotification with the `report` |
| Stall (PA-0141) | metric not improved for 6 h, no user message | only a process/measurement item opened after the stall (investigating and fixing why) may be dispatched; Stop needs a PushNotification | an improvement or a user message |
| Review cap (PA-0142) | 3 review requests for an item since the user last wrote | further review of that item denied | a user message |
| Self-opened scope (PA-0143) | item `--origin self`, not a blocking defect | dispatch for it denied | a user message after it was opened |
| Bug chain (PA-0144) | 2 bugs `--spawned-by` one item | dispatch for the item and its bugs denied | a user message (after a measured redesign is proposed) |
| Budget (PA-0145) | 4 h per active item | dispatch for it denied | a user message (restarts the budget) |
| WIP / overlap (PA-0146) | 3 active items; shared files | `item add` refused; Stop blocks on real branch overlap | finish, drop, or `--after` |
| No ledger | 2 dispatches in 2 h with no goal | Stop blocks | `goal open` |

**Reporting (PA-0147).**
- Answer every status question, and every checkpoint, with
  `scripts/orchestration_guard.py report` first.
- After a compaction, the SessionStart hook prints that report. Compare progress with
  the goal before the next dispatch; the summary's task list is not authorisation.

**Reviewers (PA-0142).** Each review request asks the reviewer to sort findings into
*must-fix* (correctness, safety, the goal) and *follow-up*. Only must-fix items go back
to the lane; follow-ups become `--origin self` ledger items for the user to choose from.

**Defaults** live in the ledger's `config` and can be changed per goal (edit
`.claude/orchestration/ledger.json`, which is git-ignored local state). Loosening a
default is itself a decision for the user.

