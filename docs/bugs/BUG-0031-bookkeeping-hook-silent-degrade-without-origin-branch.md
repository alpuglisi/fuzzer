# BUG-0031 — bookkeeping Stop hook silently stops checking committed work when `origin/<branch>` doesn't exist

- Date: 2026-09-22
- Status: fixed
- Severity: medium (defeats the hook's entire purpose on the single most
  common branch state — freshly created, not yet pushed)

## Description
`.claude/hooks/check-error-log-bookkeeping.sh` (the Stop hook that
mechanically enforces the `ERROR_LOG.md` bookkeeping rule, added by
`PA-0020`/`BUG-0019`) only looks for not-yet-pushed commits by diffing
against `origin/<current-branch>`. If that ref doesn't exist — a branch that
has never been pushed, or a repo with no `origin` remote at all — the hook
silently falls back to checking only the uncommitted working-tree diff,
missing any already-committed work on the branch entirely.

## Where encountered
Script review of `.claude/hooks/check-error-log-bookkeeping.sh` requested
against the repo's shell scripts (2026-09-22), formalized in
`docs/change-requests/CR-LAB-0002-*.md` (§3.3) and independently reviewed by
two agents before this fix landed.

## What it caused to fail
On a freshly checked-out branch with no push yet (the routine state right
after `git checkout -b`), commit an incident-shaped fix (a crash, a failing
test, a workaround) and leave a clean working tree afterward: the hook's
`changed_files` (built only from `git diff` / `git diff --cached` /
untracked files, all empty in this state) is empty, `[[ -n "$changed_files"
]] || exit 0` fires immediately, and the hook exits 0 having examined
nothing — exactly the "found it, wrote it up, but never logged it" gap
`BUG-0018`/`BUG-0019` exist to mechanically close, on the branch state this
would happen in most often.

## What the bug was identified to be
```sh
current_branch=$(git branch --show-current)
upstream=""
if [[ -n "$current_branch" ]] && git rev-parse -q --verify "origin/$current_branch" >/dev/null 2>&1; then
  upstream="origin/$current_branch"
fi
```
`upstream` has exactly one source: the branch's own remote-tracking ref. No
fallback exists for the (common) case where that ref hasn't been created yet.

## Root cause analysis
Five Whys:
1. Why does the hook miss committed-but-unpushed work on a fresh branch?
   Because `upstream` stays empty when `origin/<branch>` doesn't exist, and
   `changed_files` has no other source for already-committed history.
2. Why was `origin/<branch>` the only source considered? `BUG-0019`'s fix
   (`PA-0020`) was scoped around the concrete recurrence it was built to
   catch — a finding made and written up, then the session ending before the
   push — and the reference implementation used the most direct signal for
   "not yet on the remote" (diffing against the branch's own pushed ref),
   without separately asking "what if that ref doesn't exist yet."
3. Why wasn't that gap caught when the hook was built? `BUG-0019`'s own
   corrective action describes the hook's trigger conditions (a new/modified
   `docs/bugs/`/`docs/spikes/` doc, or incident keywords in the diff) but its
   verification was aimed at those trigger conditions firing correctly on a
   diff that exists — not at whether `changed_files` itself could be silently
   empty despite real committed work being present.
4. Why is "branch not yet pushed" common enough to matter? It's the default
   state of a new working branch in this project's own workflow (create a
   branch, work, commit, and — per this session's own instructions — push
   only when explicit steps or hooks call for it) between the first commit
   and the first push, which can span an entire multi-commit turn.
5. Why does a no-`origin`-remote repo make it worse, not just the timing
   window? Because in that case `origin/<branch>` can *never* exist,
   regardless of how much is pushed to some other remote or branch — the
   check's only source of truth for "landed" is permanently unavailable, not
   just temporarily.

**Root cause:** the hook's "not yet landed" detection had exactly one
data source (`origin/<branch>`) for already-committed work, with no
fallback for the routine case — a branch not yet pushed, or no `origin`
remote configured — where that source doesn't exist, silently narrowing
"not yet landed" to "not yet committed" instead.

## Corrective action
Added a fallback: when `origin/<branch>` doesn't exist, use the merge-base
with the local default branch (checked in order: `origin/main`,
`origin/master`, `main`, `master` — the first one found, excluding the
current branch itself) so "not yet landed" is measured against where the
branch actually diverged:
```sh
current_branch=$(git branch --show-current)
upstream=""
if [[ -n "$current_branch" ]]; then
  if git rev-parse -q --verify "origin/$current_branch" >/dev/null 2>&1; then
    upstream="origin/$current_branch"
  else
    for ref in origin/main origin/master main master; do
      if git rev-parse -q --verify "$ref" >/dev/null 2>&1 && [[ "$ref" != "$current_branch" ]]; then
        upstream="$ref"
        break
      fi
    done
  fi
fi
```
The existing `git diff --name-only "$upstream"...HEAD` line is unchanged and
now correctly picks up every commit made since the branch diverged from
`main`/`master`. If none of the four fallback refs exist either (no
conventional default branch at all), `upstream` stays empty and the hook
keeps today's uncommitted-diff-only behavior — a narrower gap than before,
never a new one. Verified: `bash -n` on the hook script; manual construction
of the "current branch equals `main`" self-exclusion case (the `[[ "$ref" !=
"$current_branch" ]]` guard prevents a no-op self-diff). Reviewed and
approved via `docs/change-requests/CR-LAB-0002-*.md`.

**Disclosed, accepted scope widening (not a defect):** this fallback expands
the range of history the hook scans — from "nothing" (the silent gap) to
"every commit since divergence from `main`/`master`" — which, on a
long-lived unpushed branch, includes this repo's own bookkeeping files
(`docs/bugs/*`, `PREVENTIVE_ACTIONS.md`, `ERROR_LOG.md` itself), inherently
dense with incident language. The hook will correctly fire more often across
such a branch's full unpushed history, not only on the current turn's diff.
This is the intended effect of closing the gap, recorded explicitly per
`docs/change-requests/CR-LAB-0002-*.md` §4 rather than understated as a pure,
side-effect-free widening.

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. The hook itself
originates from **BUG-0019**/**PA-0020** ("a written rule alone does not
count as prevention — it must also have an enforcement path that runs
independent of my remembering to apply it"), which is the reason this
mechanism exists at all, but that bug's root cause and fix were about the
*absence* of any mechanical enforcement, not about a completeness gap
*within* the enforcement mechanism once built. **No prior bug or PA audited
the hook's own detection logic for gaps** (this is the first review of the
hook's implementation since it was introduced) — so this is a new defect in
a young piece of infrastructure, not a recurrence of BUG-0018 or BUG-0019's
specific root cause. No stronger match found.

## Preventive action
**PA-0033** (see `docs/PREVENTIVE_ACTIONS.md`): a mechanical enforcement hook
built to close a "the rule was correct but never applied" gap (per PA-0020's
pattern) must itself be reviewed for completeness of its *detection* logic,
not just its trigger conditions — specifically, enumerate every state the
signal it depends on (a ref, a file, an environment variable) can be in,
including states where that signal doesn't exist yet or never will (an
unpushed branch, a repo with no remote, a missing config file), and verify
the hook's behavior in each rather than only the state it was written and
tested against. This extends PA-0020's "enforcement must not depend on my
remembering" principle to the enforcement mechanism's own inputs: a hook
whose detection quietly narrows when its primary signal is absent is exactly
as fragile as the rule it replaced, just one layer further from view.
