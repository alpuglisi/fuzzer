# BUG-0036 — `lab/ground-truth-expedia-clone/` shipped without `expectedresults.csv`

## Description

`CC-LAB-0214` (category 5's Expedia pilot, the `spel_injection`/CWE-917
shape) created a new ground-truth directory,
`lab/ground-truth-expedia-clone/`, with `labels.json` and
`injection-points.json` but not the third file
`fuzzlab.labels.contract.load()` requires, `expectedresults.csv`. The
commit's own message states "Whole-repo pytest run per PA-0036: 1709
passed, 30 skipped" with no failures recorded, but a subsequent whole-repo
run (during a separate cross-branch bookkeeping-ID collision fix on this
same branch, unrelated to this bug) failed two tests in
`tests/test_labgen_spel_injection.py` with `FileNotFoundError`.

## Where encountered

`tests/test_labgen_spel_injection.py::test_the_verdict_agrees_with_this_apps_own_ground_truth`
and
`::test_expedia_ground_truth_directory_loads_independently_of_the_default_one`,
during a whole-repo `pytest -m "not slow"` run on branch
`claude/category-5-build-6boejs`, run as this project's standard
verification step before pushing an unrelated fix (renumbering this
branch's own `FR-LAB-102`/`103` after a fresh cross-branch collision was
found against categories 1, 2, and 3).

## What it caused to fail

Both failing tests call `fuzzlab.labels.contract.load("lab/ground-truth-
expedia-clone")`, which internally calls `_load_expected_csv()` and opens
`<dir>/expectedresults.csv` unconditionally (no existence check, no
fallback) before cross-validating it against `labels.json`. The file did
not exist, so both tests failed with a plain `FileNotFoundError` at
collection/setup time, not a contract-mismatch `ContractError` — the
directory was never even complete enough to reach the actual
cross-validation logic this loader exists to run.

## What the bug was identified to be

Every other second-target ground-truth directory in this corpus
(`lab/ground-truth-forgecart/`, `lab/ground-truth-meadowmart/`,
`lab/ground-truth-booking-clone/`, `lab/ground-truth-netflix-clone/`,
`lab/ground-truth-twitch-clone/`, `lab/ground-truth-huddlehub/`, etc.)
ships all three files (`labels.json`, `injection-points.json`,
`expectedresults.csv`) as one atomic unit — this is the established,
already-followed convention, not a new requirement. `lab/ground-truth-
expedia-clone/`'s authoring commit (`339fd89`) added only the first two,
omitting the third entirely. This is an authoring omission specific to
this one new directory, not a defect in `fuzzlab.labels.contract`'s
loader (which behaves exactly as every other ground-truth directory's own
passing tests already rely on it to).

## Root-cause analysis (Five Whys)

1. **Why did the whole-repo suite fail?** Two tests in
   `tests/test_labgen_spel_injection.py` raised `FileNotFoundError`
   looking for `lab/ground-truth-expedia-clone/expectedresults.csv`,
   which did not exist.
2. **Why did the new ground-truth directory not include that file?** The
   authoring change created `labels.json` (the case data) and
   `injection-points.json` (the point inventory) but never generated the
   corresponding `expectedresults.csv` row(s), even though
   `fuzzlab.labels.contract.load()` — the same loader this shape's own
   tests call — requires all three files present and mutually consistent
   for any ground-truth directory, no exceptions.
3. **Why was that not caught before the commit was pushed?** The
   change's own commit message records a whole-repo `pytest` run
   (1709 passed, 30 skipped) with no failures — but
   `tests/test_labgen_spel_injection.py`'s own two ground-truth-loading
   tests are not `slow`-marked and would have been included in any
   `pytest`/`pytest -m "not slow"` invocation that actually collected
   this file; the recorded pass count is inconsistent with both tests
   having been exercised against the directory as it was actually
   committed (either the stated run predates the directory being written
   in its final, incomplete form, or ran before both new test files were
   staged) — a sequencing gap between "ran the suite" and "committed the
   fixture the suite depends on," not a suite that ran and passed
   incorrectly.
   A second, independent factor compounds this: `.gitignore` has a
   blanket `*.csv` rule with per-directory `!lab/ground-truth-<app>/*.csv`
   negations (one exists for `lab/ground-truth/` and one for
   `lab/ground-truth-booking-clone/`, added in `CC-LAB-0090`) — but no
   such negation was ever added for `lab/ground-truth-expedia-clone/`.
   Even had the file been authored locally, `git add`/`git status` would
   have silently treated it as an ignored generated artifact rather than
   a tracked fixture, so it could never have reached the commit without
   that exception also being added.
4. **Why did nothing else catch a ground-truth directory silently missing
   a required file?** There is no repo-wide completeness check
   independent of a given shape's own test file asserting "every
   directory under `lab/ground-truth-*/` has all three of `labels.json`/
   `injection-points.json`/`expectedresults.csv`" — the only thing that
   currently verifies this is each shape's own test module explicitly
   calling `contract.load()` on its own directory, so the gap is only
   ever caught by the specific shape's own tests being run, not by a
   standing, shape-agnostic guard.
5. **Root cause:** ground-truth-directory completeness (all three sibling
   files present and mutually consistent) is enforced only per-shape, by
   that shape's own test module calling the shared loader — there is no
   standing, repo-wide guard that would catch a *new* directory missing a
   required file independent of whether its own test suite actually ran
   to completion against the final committed state.

## Corrective action

Authored `lab/ground-truth-expedia-clone/expectedresults.csv` (one row,
`EXPD-0001`, matching `labels.json`'s existing case exactly — same
`case_id`/`url`/`method`/`param`/`location`/`category`/
`expected_vulnerable`, matching the established column convention from
`lab/ground-truth-booking-clone/expectedresults.csv`). Also added the
missing `!lab/ground-truth-expedia-clone/*.csv` negation to `.gitignore`
(immediately after the existing `CC-LAB-0090` booking-clone negation),
without which the new CSV would have remained untracked/ignored even
after being authored. Verified with `pytest
tests/test_labgen_spel_injection.py`: 9 passed (up from 7 passed 2
failed). Whole-repo `pytest -m "not slow"` re-run: 1865 passed, 8
skipped — no regression elsewhere.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of this bug, or a different bug with the same root cause,
before deciding the preventive action below:

- **BUG-0035** (this same branch, `CC-LAB-0210`) is the closest prior
  bug: also a same-change authoring omission caught by a whole-repo
  `pytest` run that happened after, rather than gating, the push, and
  also concluded that "the pre-push verification step checked only files
  it judged directly relevant rather than the whole-repo suite." That
  root cause **partially recurs here** — but the failure mode is
  different in one material way: BUG-0035's own shape-specific test file
  DID exercise the broken code path when run in isolation (it caught
  nothing because the break was in a *different*, shared-registry test
  file its author didn't think to run); here, this shape's OWN test file
  (`test_labgen_spel_injection.py`) is exactly the file that fails, and
  the commit message's own claimed whole-repo run result is inconsistent
  with that file having actually been exercised against the final
  committed tree. BUG-0035's preventive action (a completeness-of-
  registration guard, `_DETERMINISM_CTX_BY_MODULE`) does not cover this
  case — that guard is specific to the shared module registries, not
  ground-truth directory contents — so this needs its own, narrower rule
  rather than restating BUG-0035's.
- No other prior bug or `PA-NNNN` addresses ground-truth-directory
  file-set completeness specifically.

## Preventive action (`PA-0038`)

Added to `docs/PREVENTIVE_ACTIONS.md`: **before considering any new
`lab/ground-truth-*/` directory complete, (a) confirm all three files
(`labels.json`, `injection-points.json`, `expectedresults.csv`) show as
tracked/addable via `git status`/`git add -n` — not silently caught by
`.gitignore`'s blanket `*.csv` rule, which requires its own
`!lab/ground-truth-<app>/*.csv` negation per directory — and (b) run that
shape's own test module as its own explicit, separate `pytest`
invocation (not just as part of a claimed whole-repo run) and
paste/quote its literal pass count into the change-control entry's
Effectiveness section**. Neither check alone would have caught this bug
in isolation as cleanly as the two together: a whole-repo run's aggregate
pass count does not, on its own, prove any specific new test file was
actually collected and exercised against the final committed tree (this
bug's own authoring commit claimed a passing whole-repo run while
shipping a ground-truth directory its own new tests could not have
passed against), and a file that exists on disk but is gitignored would
still show as "present" to a casual `ls` check without ever reaching the
repository. This strengthens BUG-0035's related but narrower finding:
BUG-0035 already established that a change with more than one dependent
test surface needs the *whole* suite run, not just the files judged
directly relevant; this rule adds that even a claimed whole-repo pass is
not sufficient evidence on its own for a *new* test file's own
directory-completeness contract — that file's own targeted run and its
literal reported count must be the evidence quoted in the change-control
entry, not an aggregate number alone — and that "the file exists" must be
verified against `git`, not the filesystem alone.
