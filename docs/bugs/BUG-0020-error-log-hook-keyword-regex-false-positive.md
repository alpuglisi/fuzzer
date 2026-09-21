# BUG-0020 — ERROR_LOG bookkeeping hook's keyword regex false-positives on "change"

- Date: 2026-09-21
- Status: fixed
- Severity: low (a false positive that erodes trust in a preventive control, not a
  missed real finding)

## Description
`.claude/hooks/check-error-log-bookkeeping.sh` (added in BUG-0019/PA-0020) matches
incident-shaped keywords against the diff with `grep -qiE "$keyword_regex"` and no word
boundaries. The keyword `hang` is a substring of `change`, `changed`, and `changes` —
words that appear in nearly every commit in this changelog-heavy project (`CHANGELOG.md`
itself literally instructs "add a dated bullet: what changed"). The very first real use of
the hook, on a purely decision-recording change with no incident at all, fired a false
positive on that basis.

## Where encountered
While committing the D20/`CR-LAB-0001` approval docs (no code, no incident) — running the
hook's pipe-test sanity check before committing, as has become the routine since BUG-0019.

## What it caused to fail
The hook's own purpose: distinguishing "this diff looks incident-shaped" from "this diff
does not." A keyword match that fires on ordinary changelog prose (an unavoidable word in
this project's own conventions) is worse than a narrower rule that fires less often but
means something when it does — a control that cries wolf on nearly every commit trains
whoever's using it to dismiss it reflexively, which defeats PA-0020's entire point (an
enforcement path independent of my own attention).

## What the bug was identified to be
`keyword_regex='fail|hang|workaround|killed|timed out|timeout|crash|broken|regress'` used
in `grep -E` (POSIX ERE) with no `\b` word-boundary anchors, so each term matches as a bare
substring anywhere in a line, not just as a whole word.

## Root cause analysis
Five Whys:
1. Why did it fire on a diff with no incident? `keyword_hits` was set because a line
   matched `hang` — but the actual matched text was inside "change"/"changes"/"changed",
   not a real occurrence of the word "hang".
2. Why did "change" match a pattern for "hang"? `grep -E` without `\b` matches the pattern
   as a substring anywhere in the line; "change" (c-h-a-n-g-e) contains the four-letter
   substring "hang" at positions 2-5.
3. Why wasn't that caught when the hook was built (BUG-0019)? The pipe-tests run then
   covered a clean tree, a synthetic incident doc, the recursion guard, and a diff that
   included `ERROR_LOG.md` — all either clearly incident-free-and-word-free or
   clearly-incident-shaped. None of those fixtures happened to contain an ordinary word
   that embeds one of the keywords as a substring, so the substring-vs-word-boundary gap
   had no test case to surface it.
4. Why didn't I anticipate that gap? I treated "these words look incident-specific enough
   that a substring match is fine" as an implicit assumption, without checking each keyword
   against common vocabulary this project's own prose already uses — `hang` inside `change`
   is the obvious one in hindsight, but I didn't do that check before shipping.
5. Why does that matter more here than in an ordinary grep script? Because this hook's
   entire value proposition (PA-0020) is that it runs independent of anyone remembering to
   double-check it — a heuristic that misfires on routine prose in a project whose own
   changelog convention uses the trigger word constantly will misfire on a large fraction of
   commits, which is a much more damaging failure mode for a "runs unattended and blocks"
   control than for an interactive linter a human can shrug off once.

**Root cause:** a substring-match keyword heuristic was shipped without checking each
keyword against the project's own routine vocabulary for accidental substring collisions —
the same class of gap as any unanchored pattern match, just not previously named as a rule
in this project.

## Corrective action
Anchored every keyword in `keyword_regex` with `\b` word boundaries and, where a keyword
has common inflections that matter (`fail`/`failed`/`failing`/`failure`, `crash`/`crashed`/
`crashing`, `regress`/`regressed`/`regression`), an explicit suffix group instead of a bare
substring, so "change"/"changed"/"changes" no longer match `hang`. Verified: the real
D20-approval diff (previously a false positive) now returns exit 0; a synthetic true
positive ("hung"/"killed"/"workaround") still returns exit 2; a synthetic
"change"/"changed"/"changes"-only diff no longer matches on keywords (though it can still
trigger via the separate `docs/spikes|bugs` path heuristic, unaffected by this fix, if the
file itself is new/modified in one of those directories).

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. No prior bug in this project
targets an unanchored substring-match heuristic; this is a distinct failure mode from every
other bug logged so far (all either code-behavior defects or process/enforcement gaps, not
a matching-heuristic's own precision). **No prior occurrence found.**

## Preventive action
**PA-0022** (see `docs/PREVENTIVE_ACTIONS.md`): any keyword/substring match used as a
mechanical heuristic (a hook, a lint rule, a build gate) must anchor on word boundaries
(`\b`) unless a bare substring is specifically intended, and must be checked against the
project's own routine vocabulary (changelog/commit-message conventions, common English
words) for accidental collisions before being trusted to run unattended — a quick check:
grep the heuristic's own keyword list against a sample of ordinary, incident-free
commit messages/diffs from this project and confirm zero matches.
