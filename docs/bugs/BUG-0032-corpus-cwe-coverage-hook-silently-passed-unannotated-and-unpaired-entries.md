# BUG-0032 — `check-corpus-cwe-coverage.sh` silently passed entries with no CWE field at all, and passed a class with orphaned vulnerable-only entries

## Description

`.claude/hooks/check-corpus-cwe-coverage.sh` (built in `PA-0033`'s own
change specifically to mechanically enforce the corpus's CWE-coverage and
pairs-per-class floors) had two defects of exactly the kind it exists to
catch:

1. An entry with **neither** the new `cwe_unique:` field **nor** the legacy
   `cwe:` field present at all fell into a bare `continue` with no problem
   ever recorded — the `if legacy_cwe is not None:` branch only fires when
   the *old* field is present, so an entry missing both fields silently
   passed, indistinguishable from a fully-compliant entry.
2. The "at least 5 vulnerable/idiomatic pairs per class" floor only counted
   `role: vulnerable` entries. A cell with 5 orphaned vulnerable entries and
   zero `role: idiomatic` entries satisfied the numeric floor and passed,
   even though the whole point of a "pair" is that both roles exist.

## Where encountered

External code review on `alpuglisi/fuzzer#1`, as two inline comments on
`.claude/hooks/check-corpus-cwe-coverage.sh` itself (one from an automated
reviewer, one independently from a human reviewer using the same tooling) —
both landed within minutes of each other, on the same two defects.

## What it caused to fail

Nothing failed loudly — again, that is the defect. The hook's own purpose is
to fail loudly (`Stop` hook, blocks the session from ending) on exactly these
two authoring gaps, and it did not, for either. Had either gap gone
unnoticed past this review, a future corpus entry missing CWE annotation
entirely, or a cell with only vulnerable examples and no idiomatic
counterpart, would have been mechanically approved as compliant.

## What the bug was identified to be

Two logic gaps in the hook's own Python body (embedded in the bash script),
both concrete edge cases the hook's own docstring/purpose claims to cover
but its actual conditional logic did not reach:
1. `cwe_unique is None and legacy_cwe is None` was never itself checked as
   its own failure case.
2. The pairs-per-class loop only incremented and checked `vulnerable_count`;
   `idiomatic_count` was never computed or compared against the same floor.

## Root cause analysis (Five Whys)

1. **Why did these two gaps ship in the hook itself?** Because the hook was
   written and *manually* validated against the specific failure modes the
   session was actively fixing at the time (entries with too few
   `cwe_unique` IDs; cross-entry ID collisions; too few total vulnerable
   entries) — not against every input shape its own stated purpose implies
   it should reject.
2. **Why wasn't it validated against those other input shapes?** Because
   validation consisted of running the hook against the *real, current*
   corpus state and confirming it caught the specific problems already known
   to be present there — not constructing synthetic adversarial fixtures
   (an entry with no CWE field at all; a cell with only vulnerable entries)
   the real corpus didn't happen to contain at validation time.
3. **Why didn't the real corpus happen to contain those shapes at validation
   time?** Because every entry the authoring session itself wrote always set
   *some* CWE field (even if the wrong one, format-wise) and always paired a
   vulnerable entry with an idiomatic one by construction — the gaps are
   invisible against self-authored data because the author's own habits
   don't produce the malformed shape the check exists to catch in *someone
   else's* future authoring.
4. **Root cause:** the hook (an enforcement mechanism built specifically
   because PA-0020/PA-0033 established that "my own missed self-check needs
   mechanical enforcement, not a clearer written rule") was itself validated
   only against the author's own already-compliant-by-habit data, the exact
   same class of gap PA-0020 was written to close for the *feature* it
   enforces — applied recursively to the *enforcement mechanism itself*,
   which received no equivalent adversarial self-check before being trusted.

## Corrective action

Both fixed in the same commit as this report, in
`.claude/hooks/check-corpus-cwe-coverage.sh`:
1. An entry with neither `cwe_unique:` nor `cwe:` now records an explicit
   problem (`"has no cwe_unique: (or legacy cwe:) field at all"`) instead of
   silently continuing.
2. The pairs-per-class check now counts `role: idiomatic` entries alongside
   `role: vulnerable` and requires `>= 5` of **each**, plus a secondary check
   that a vulnerable entry's `derived_from` (when set) actually names a file
   present in the same manifest, catching an orphaned reference even when
   the raw counts clear the floor.

Verified against three synthetic fixtures (not the real corpus, precisely
because root cause #2-#3 above is that the real corpus never exercised these
shapes): an entry missing both CWE fields (now flagged); a 5-vulnerable/
3-idiomatic cell (now flagged on the idiomatic-count floor, previously
passed); a genuine 5/5 paired, fully-annotated cell (still passes clean).

Also fixed, from a third (nit-severity) review comment on the same hook: the
no-upstream fallback now falls back to the merge-base with the repo's
default branch when a branch has no `origin/<branch>` tracking ref yet, so a
manifest edit already committed this turn on a fresh, unpushed branch is
still diffed and checked rather than silently skipped because every other
diff source (`git diff`, `git diff --cached`, untracked files) is empty by
the time the hook runs.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence
of "an enforcement mechanism built specifically to close a self-check gap
was not itself adversarially self-checked." `BUG-0030` (`PA-0033`'s own
origin) is the direct prior instance of the *feature* this hook enforces
having exactly this problem (the CWE research itself wasn't checked against
a real ceiling search); this bug is the same root-cause pattern recurring
one layer up, in the enforcement mechanism `BUG-0030`'s own corrective
action built. This **is** a recurrence of the same root-cause class (not a
new one), so a prior-preventive-action failure analysis is required.

## Prior-preventive-action failure analysis

`PA-0033` (from `BUG-0030`) mandates that a quantitative "do more of X"
instruction gets its own mechanical check, and names
`check-corpus-cwe-coverage.sh` as that check's concrete instance. It does
not, however, say anything about how the mechanical check itself must be
validated once built — it treats "a mechanical check exists" as sufficient,
with no requirement that the check be exercised against adversarial/edge-
case inputs (as opposed to the real, current, self-authored corpus) before
being trusted. That gap is exactly what let both defects in this report
ship inside the very hook `PA-0033` introduced. `PA-0033` was the right
layer (mechanical enforcement, not a written rule) but too narrow in scope
(it stopped at "build a check," not "prove the check itself is correct
against inputs its own author didn't happen to produce").

## Preventive action

See `docs/PREVENTIVE_ACTIONS.md` **PA-0034** (shared with `BUG-0031`, since
both bugs share the same "own-tests-pass, adversarial-input-untested" root
cause, applied to a code-generation feature and to an enforcement hook
respectively): any mechanical check built to enforce a quantitative/
structural floor (PA-0033's own class of artifact) must, before being
trusted, be run against at least one synthetic fixture *constructed to be
malformed in the specific way the check claims to catch* — not validated
solely by confirming it flags the real corpus's own currently-known
problems. This strengthens PA-0033: building the check is necessary but not
sufficient; the check needs its own adversarial self-check before the
"mechanical enforcement exists" claim can be trusted.
