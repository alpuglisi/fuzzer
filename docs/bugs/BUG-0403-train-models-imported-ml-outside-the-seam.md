# BUG-0403 — `fuzzlab train models` imported `fuzzlab.ml` outside the optional-ML seam

- Date: 2026-10-15
- Status: fixed
- Severity: medium (a no-ML install would crash on `fuzzlab train models`)

## Description

The new `fuzzlab/train_cli.py` (CC-FUZZ-0400) imported
`fuzzlab.ml.model_registry.list_models` directly inside `models_main`. FR-ML-6 requires
every module outside `fuzzlab/ml/` to reach the ML package only through
`fuzzlab.plugins.optional.import_ml`, so that a no-ML build exits with the standard
"ML not installed" message instead of crashing.

## Where encountered

The clean-tree full-suite run of commit `31b5013` (`pytest -m "not slow"` in a detached
worktree): `tests/test_ml_import_guard.py::test_no_module_outside_ml_imports_it_except_through_import_ml`
failed, naming `fuzzlab/train_cli.py`.

## What it caused to fail

- The guard test failed.
- In a no-ML build, `fuzzlab train models` would have raised `ModuleNotFoundError`
  rather than exiting 2 with `ML_UNAVAILABLE`.
- No other command was affected: the rest of `train_cli` imports no ML module.

## What the bug was identified to be

A lazy `from fuzzlab.ml.model_registry import list_models` in a module outside
`fuzzlab/ml/`, instead of `import_ml("fuzzlab.ml.model_registry")`.

## Root cause analysis

Five Whys:

1. *Why the direct import?* The new module was written against the ML API without
   checking the optional-ML rule (FR-ML-6) for a new caller.
2. *Why wasn't it caught before the commit?* The pre-commit verification ran the test
   files that **import** the changed modules (the lane's process rule) plus the new test
   files. `tests/test_ml_import_guard.py` imports none of them: it scans `fuzzlab/` **by
   path** (AST).
3. *Why does the import-based list miss it?* A repo-wide guard finds a new module by
   walking the package. It never imports it, so `grep -l <module path> tests/` cannot
   list the guard as affected.
4. *Why rely on that list?* The rule "run every test file that imports a module you
   changed" was treated as the complete pre-commit set. The full suite was a later step,
   on the clean tree.
5. *Why did that matter?* The commit was pushed before the full run. The full run did
   catch it, but after the push, not before.

**Root cause:** the pre-push verification set was derived from imports alone. It
structurally excludes the repository's path-scanning guard tests (33 `.py` files today), which
are exactly the tests that judge a **new** module.

## Corrective action

- `models_main` now reaches the registry through `import_ml("fuzzlab.ml.model_registry")`.
  Without the ML package it prints `fuzzlab train models: <ML_UNAVAILABLE> (fuzzlab.ml)`
  and exits 2.
- Tests: `tests/test_ml_import_guard.py` (green), and
  `tests/test_train_cli.py::test_models_without_the_ml_package_exits_2_with_the_standard_message`.
- Delivered by CC-FUZZ-0401.

## Recurrence review

- **PA-0040.** "Run the whole-repo suite, not only the relevant files, for a shared
  cross-stack registry." Same family (a narrowed test set misses a cross-cutting
  check), different trigger (a shared registry).
- **PA-0044 and PA-0045.** Grep the *whole* suite, slow-marked included, for
  assertions depending on ground-truth cardinality. The same family again, for
  ground-truth changes.
- **PA-0063(3), PA-0081(2), PA-0125(3).** These *create* path-scanning guards. They do
  not say when to run them.
- **Result:** a recurrence of the "narrowed verification set misses a cross-cutting
  check" family (BUG-0038/PA-0040, BUG-0040/PA-0044).

## Prior-preventive-action failure analysis

PA-0040 and PA-0044 failed to prevent this for three reasons:

- **Too narrow.** Each is keyed to one trigger (a shared registry; a ground-truth
  cardinality change). A new module under `fuzzlab/` is neither, so neither applied.
- **Wrong layer.** Both say what to run when *X* changes. Neither names the class of
  test an import-based list cannot find: guards that discover code by path. The lane's
  own process rule ("run every test file that imports a module you changed") was
  followed exactly, and it excludes that class by construction.
- **Not enforced.** Nothing mechanical lists the path-scanning guards for a change.

## Preventive action

**PA-0403** strengthens PA-0040 and PA-0044 from per-trigger rules into a standing rule
about the verification set.

1. Before a change that adds or edits a module under `fuzzlab/` is pushed, its
   verification includes **every path-scanning guard test**, not only the files that
   import the changed modules. These are the tests that discover code by walking
   `fuzzlab/` or `tests/` (`grep -rlE --include="*.py" "rglob|ast.parse\(.*read_text" tests/`). An
   import-based list is necessary but never sufficient: it cannot find a guard that
   judges a *new* module.
2. When the full suite is the backstop, it runs **before** the push of the commit it
   certifies, on the clean committed tree.

PA-0002 sweep: the lane's other new modules were checked against every path-scanning
guard: `fuzzlab/cli_taxonomy.py`, `fuzzlab/core/storepath.py`, `fuzzlab/core/modelinfo.py`,
`fuzzlab/train_cli.py`. Only `train_cli.py` had this defect (the full clean-tree run of the
corrected tree is recorded in CC-FUZZ-0401).
