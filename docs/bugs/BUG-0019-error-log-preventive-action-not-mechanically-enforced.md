# BUG-0019 — PA-0019 is advisory-only and does not mechanically prevent recurrence

- Date: 2026-09-21
- Status: fixed
- Severity: low (no incorrect deliverable resulted from this instance — this bug
  is about the *enforcement mechanism* itself, found by inspection rather than by
  a fresh recurrence of BUG-0018)

## Description
BUG-0018 diagnosed that I don't reliably add `ERROR_LOG.md` entries for findings that
match its stated scope unless prompted, and its preventive action, PA-0019, is a written
rule telling me to check for this at the end of every turn. That rule depends entirely on
my own end-of-turn discipline — the same mechanism that already failed once in BUG-0018.
Nothing about PA-0019 changes *how* the check gets triggered; it only adds one more sentence
to the growing set of things I'm expected to remember to do. Asked directly whether this
is sufficient, the honest answer is no: an advisory rule with no external trigger is not a
preventive action against a *recall* failure, it's a restatement of the expectation that
already existed and was already missed.

## Where encountered
Immediately after closing BUG-0018 in this session, when asked to make the finding
actually preventable rather than documented.

## What it caused to fail
`docs/bugs/README.md`'s own definition of a preventive action: "a change, derived from the
root cause, that prevents recurrence of this class of bug." PA-0019's root cause (per
BUG-0018) is "I rely on a finding's narrative framing/salience... rather than mechanically
checking new findings against each artifact's actual stated scope." PA-0019 as written does
not fix that — it asks me to mechanically check, but supplies no mechanism that makes the
check happen independent of my own memory/attention in the moment. It is a rule *about* the
gap, applied at the same layer (my own end-of-turn judgement) where the gap lives.

## What the bug was identified to be
PA-0019 is enforced by nothing but my own re-reading of `docs/PREVENTIVE_ACTIONS.md`, which
is exactly the artifact-scope-checking step that BUG-0018 already showed I skip under normal
task pressure. A preventive action that lives entirely inside the same failure-prone process
it's meant to guard is not load-bearing.

## Root cause analysis
Five Whys:
1. Why doesn't PA-0019 prevent recurrence? Because following it still requires me to
   remember, unprompted, to consult it at the right moment — the same requirement that
   BUG-0018 showed fails silently.
2. Why was PA-0019 written that way? Every other preventive action in this project's history
   up to BUG-0018 targeted a defect in *project code or project process design* (a test
   fixture, a build step, a doc template) — something fixable by changing an artifact once,
   after which the fix is structurally in place. BUG-0018's defect is in my own runtime
   behavior, which has no artifact to edit; the closest available lever looked like "write
   the rule down," so that's what I did.
3. Why didn't I recognize that "write the rule down" wasn't a real fix for a *behavioral*
   root cause? I conflated "the rule is correctly derived from the root cause" (true — PA-0019
   accurately names the check that was missing) with "the rule is enforced" (false — nothing
   makes the check happen other than my own attention). `docs/bugs/README.md`'s definition of
   a preventive action doesn't explicitly distinguish these, and I didn't apply that
   distinction on my own before presenting PA-0019 as done.
4. Why does that distinction matter here specifically? Because the failure being prevented is
   itself a *memory/attention* failure (BUG-0018's root cause is about what I recall to check
   without being prompted). A rule whose entire enforcement path routes back through the same
   recall step it's trying to fix has no independent check on that step — it can fail the same
   way, for the same reason, with the new rule sitting unconsulted right alongside the old
   process.
5. Why wasn't this caught before the user pointed it out? I treated closing BUG-0018 (writing
   the RCA, the corrective action, and a plausible-sounding preventive action) as the finish
   line, rather than asking "does this preventive action have any enforcement path that isn't
   me, later, remembering to follow it" — a question that applies specifically when the root
   cause is my own behavior rather than a property of the codebase.

**Root cause:** For a bug whose root cause is my own missed/inconsistent self-check rather
than a defect in project code, an advisory preventive action (a rule for me to remember and
apply) has no enforcement mechanism independent of the exact failure it targets, so it cannot
be verified to hold and is not a structural fix — only a mechanical, externally-triggered
check (something that runs regardless of whether I remember to invoke it) closes that class
of gap.

## Corrective action
Added `.claude/hooks/check-error-log-bookkeeping.sh`, wired into a Stop hook in
`.claude/settings.json`. Before the session is allowed to stop, it inspects the files touched
by this turn's not-yet-pushed work (uncommitted changes plus any commits not yet on the
remote branch) and, if any of them are new/modified `docs/spikes/*.md` or `docs/bugs/*.md`
files, or add incident-shaped language (`fail`, `hang`, `workaround`, `killed`, `timed out`,
`crash`, `broken`, `regress`) to the diff, but `ERROR_LOG.md` is **not** among the touched
files, it blocks the stop (exit 2) with a message pointing at `CLAUDE.md`/PA-0019/PA-0020 and
naming which heuristic fired. It carries the same recursion guard as the pre-existing
`~/.claude/stop-hook-git-check.sh` (`stop_hook_active`), so it warns once per stop cycle
rather than looping if the finding genuinely doesn't need an entry. Pipe-tested against four
synthetic cases (clean tree; a synthetic spike doc with incident language and no `ERROR_LOG.md`
touch; the same with `stop_hook_active: true`; the same after also touching `ERROR_LOG.md`) —
all four behaved as designed. Committed to the repo (`.claude/settings.json`,
`.claude/hooks/check-error-log-bookkeeping.sh`) so it travels with the project rather than
living only in this container's personal config.

This is a heuristic, not a proof: it can miss a finding phrased without any of the listed
keywords and outside `docs/spikes|bugs`, and it can false-positive on an unrelated diff that
happens to contain one of the words. It converts the check from "something I must remember"
to "something that runs and must be dismissed or acted on," which is the actual gap identified
below — it does not claim semantic understanding of whether a given change truly needs an
`ERROR_LOG.md` entry.

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. This is a direct recurrence-of-kind
against **BUG-0018 / PA-0019**: same underlying gap (an `ERROR_LOG.md`-worthy finding not
mechanically caught), immediately following it in the same session, surfaced not by a fresh
missed finding but by inspecting PA-0019's own enforcement path on request. No other bug or
preventive action in the log targets "a behavioral preventive action lacks an external
enforcement mechanism" — the closest doc-process bugs (BUG-0014, BUG-0015) are about content
being wrong or unverified, not about a rule's enforceability, so those are a different failure
shape. This is the first bug whose subject is a *preventive action itself*.

## Prior-preventive-action failure analysis
PA-0019 did not prevent this recurrence because it was **the wrong layer**: it restated the
missed check as a rule for me to remember, when the root cause (BUG-0018) was precisely that
I do not reliably remember to run such checks unprompted. An advisory rule addressed to the
same fallible process it targets cannot be verified to hold and has no failure signal if it
doesn't — there is no way to tell, from the outside, whether PA-0019 "worked" on any given
turn short of a human independently re-checking `ERROR_LOG.md` themselves, which is exactly
the manual catch this project's bookkeeping process exists to avoid needing. PA-0019 was not
"not followed" through inattention in this instance — it was never given a way to be enforced
in the first place.

## Preventive action
**PA-0020** (see `docs/PREVENTIVE_ACTIONS.md`) — strengthens/supersedes PA-0019. When a
preventive action's root cause is *my own* missed or inconsistent self-check (as opposed to a
defect in project code, tests, or a process document), it is not considered a real preventive
action until it has an enforcement path that runs independent of my remembering to apply it —
in this project, a Claude Code hook (`.claude/settings.json` / `.claude/hooks/`) that inspects
actual session state (files changed, diff content) and blocks or warns mechanically. A written
rule may still record the *intent* (PA-0019 remains correct as a statement of what should be
checked), but the enforcement itself must not live solely in "remember to check this."
