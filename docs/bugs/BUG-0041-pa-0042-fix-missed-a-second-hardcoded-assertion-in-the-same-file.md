# BUG-0041 — `PA-0042`'s own fix missed a second hardcoded recall assertion living in the same test file

- Date: 2026-09-23
- Status: fixed
- Severity: low (silent; no wrong security verdict was ever produced, and the fix window was short — one independent re-verification pass after the responsible commit)

## Description
`CC-LAB-0197` (Netflix's 11th real page, `spring_boot`'s first `ssti`/
`template_render` instance on this app identity) added `NFLX-0011` to
`lab/ground-truth-netflix-clone/`. Per `PA-0042` (itself written from
`BUG-0040`, the immediately preceding entry in this same log), that
commit's own author grepped for hardcoded fraction/count assertions
depending on Netflix's ground-truth cardinality, found and correctly
updated `tests/test_multitarget_category4.py::
test_netflix_multi_cell_boot_confirms_all_positives`'s own `10/10`→`11/11`
recall assertion, re-ran the file, and reported it green.

An independent re-verification pass immediately after that commit was
pushed (this session's own standing practice of re-running tests after a
subagent reports a push) found `tests/test_multitarget_category4.py::
test_both_apps_run_through_multitarget_for_real` — a DIFFERENT test
function in the SAME file — still asserting the stale `netflix_report.recall
== round(1/10, 4)`, which should have become `1/11` the moment `NFLX-0011`
raised Netflix's total case count. This is a second, independent hardcoded
fraction for the same target, sitting a few hundred lines away in the same
file from the one `CC-LAB-0197`'s own PA-0042 pass had just fixed.

## Where encountered
An independent confirmatory test run (`tests/test_multitarget_category4.py`
et al.) performed immediately after `CC-LAB-0197` was reported pushed —
this session's own standing discipline of not treating a subagent's
self-report as sufficient without independent re-verification. The failure
was a real, reproducible `AssertionError` (`0.0909 != 0.1`), not a flake.

## What it caused to fail
`tests/test_multitarget_category4.py::test_both_apps_run_through_multitarget_for_real`
— a real, already-pushed test failure on `origin/claude/category-4-build-t9uz3y`
at `CC-LAB-0197`'s own commit, for exactly the duration between that push
and this independent re-verification catching it (this session's own
policy of never trusting a subagent's "tests pass" claim without a
separate run is what closed that window quickly).

## What the bug was identified to be
A single ground-truth-cardinality change can invalidate MORE THAN ONE
hardcoded fraction assertion in the SAME test file, when that file has
more than one test function scoring the same target (here: a
single-cell-boot test and a multi-cell-boot test, each with its own
independent, textually separate `recall == round(N/M, 4)` line). Fixing
and re-verifying one such assertion does not, by itself, prove no sibling
assertion in the same file was missed.

## Root cause analysis
Five Whys:
1. Why did `test_both_apps_run_through_multitarget_for_real` fail after
   `CC-LAB-0197`? Its own hardcoded `1/10` recall fraction went stale the
   moment `NFLX-0011` raised Netflix's total case count to 11.
2. Why didn't `CC-LAB-0197`'s own `PA-0042` pass catch this? It correctly
   found and fixed `test_netflix_multi_cell_boot_confirms_all_positives`'s
   own sibling assertion in the very same file, then reported the file as
   handled — the fix and the re-run both really happened, just against
   only one of the file's two independent assertions.
3. Why would fixing one assertion and re-running the file be mistaken for
   full coverage? `PA-0042`'s own wording says "re-run every FILE a grep
   surfaces" — file-level granularity. It does not say a single file can
   hold more than one occurrence of the pattern being searched for, so an
   agent that finds one match, fixes it, and sees the file pass has
   satisfied the letter of the instruction without having actually
   confirmed there wasn't a second, independent match elsewhere in that
   same file.
4. Why wasn't a second match found by a thorough grep? Not established
   with certainty (the responsible agent's own tool calls aren't
   inspectable from this vantage point) — but the plausible mechanism is
   a grep or manual read that stopped once it found *a* match resembling
   the pattern, rather than one that enumerates and accounts for *every*
   match in the file before considering the file's own remediation
   complete.
5. Why does this matter enough to write up, given the low severity? This
   project's own `test_multitarget_category4.py` has now grown two
   separate hardcoded-fraction test functions per target (a single-cell
   wiring test and a multi-cell boot test) as a *repeating, deliberate*
   pattern (see `CC-FUZZ-0032`'s own multi-cell-boot precedent) — meaning
   this exact "more than one assertion per file" shape is not a one-off
   coincidence in this codebase, but a structural feature of how this
   file is organized, and will recur on every future ground-truth-
   cardinality change to Netflix or Twitch unless the rule accounts for
   it explicitly.

**Root cause:** `PA-0042` verifies at file granularity ("re-run this
file") rather than match granularity ("confirm you found and fixed every
occurrence this grep pattern matches"), and this project's own
`test_multitarget_category4.py` is structurally organized to have more
than one independent hardcoded-fraction assertion per target within a
single file — a gap `PA-0042`'s own wording did not anticipate when it was
written from `BUG-0040`.

## Corrective action
Corrected `test_both_apps_run_through_multitarget_for_real`'s own stale
`1/10`→`1/11` recall assertion and its paired `macro_recall` assertion,
in the working tree immediately following `CC-LAB-0197`'s own push (not
folded into that commit, since it had already landed) — re-verified by
running `tests/test_multitarget_category4.py`, `tests/test_auto.py`, and
`tests/test_labels_contract_category4.py` together (21 passed). See
`CHANGELOG.md` for the commit record.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of the same bug, or a different bug with the same root cause.

**Found a direct match: `BUG-0040`/`PA-0042`, the immediately preceding
entry in this same log.** This is the same bug CLASS (a ground-truth-
cardinality change silently invalidating a hardcoded recall/count
assertion that a routine check failed to catch) recurring within the same
session, on the very next increment that touched Netflix's ground truth
after `PA-0042` was written specifically to prevent it.

## Prior-preventive-action failure analysis
`PA-0042` was followed, not skipped — `CC-LAB-0197`'s own author did grep,
did find a match, did fix it, and did re-run the file. The failure mode is
therefore not "the rule was ignored" but **"the rule was satisfied at the
wrong granularity."** `PA-0042`'s own wording ("re-run every file such a
grep surfaces") treats a file as the unit of verification, when the real
invariant that matters is "every individual assertion, wherever it
lives." A file that happens to contain two independent occurrences of the
same pattern (as `test_multitarget_category4.py` now structurally does,
by this project's own deliberate single-cell + multi-cell test-pairing
convention) can pass a file-level check while still hiding one unfixed
occurrence. This is too narrow a formulation, not a wrong layer or an
unenforced rule — `PA-0042` needs to name the match-level invariant
explicitly, not just the file-level one.

## Preventive action
See `PA-0043` (`docs/PREVENTIVE_ACTIONS.md`): sharpens `PA-0042` from
file-level to match-level verification — when fixing a hardcoded ground-
truth-cardinality-dependent assertion that a grep surfaces, count how many
times that grep matched (e.g. `grep -c` the target's own recall/tp
pattern across the whole file, not just the first hit) and confirm that
exact count of assertions was edited, not just that the file as a whole
now passes. Applies with specific force to
`tests/test_multitarget_category4.py`'s own now-repeating single-cell +
multi-cell test-pairing shape, where a change to one target's cardinality
routinely touches two independent assertions in the same file, not one.
