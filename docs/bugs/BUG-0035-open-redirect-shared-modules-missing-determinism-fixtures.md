# BUG-0035 — `CC-LAB-0210`'s new shared-vocabulary modules shipped without their `_DETERMINISM_CTX_BY_MODULE` fixture entries

## Description

`CC-LAB-0210` (category 5's Booking.com pilot, the `open_redirect`/CWE-601
shape) registered three new modules in the shared, cross-stack
`fuzzlab.labgen.modules` registries (`redirect_target_allowlist` — a
transform, `http_redirect_return` — a sink, `redirect_response` — a
complexity), for the shared minimal-pair vocabulary, following the exact
precedent `L-P3.3c-DOM`'s `dom_url_source`/`dom_text_content`/
`dom_innerhtml_echo` set. The commit that added them
(`542a15b`) was verified against `tests/test_labgen_open_redirect.py` and
`tests/test_labgen_php_laravel_harder_shapes.py` run directly, and pushed.
A first whole-repo `pytest tests/` run — done as this same change's own
closing verification step, before the change was considered complete —
failed two tests in `tests/test_labgen_modules.py`.

## Where encountered

`tests/test_labgen_modules.py::test_every_module_renders_deterministically_twice`
and `::test_every_registered_module_has_a_determinism_ctx_fixture`, during
a whole-repo `pytest tests/` run on branch `claude/category-5-build-6boejs`.

## What it caused to fail

- `test_every_module_renders_deterministically_twice` raised `KeyError:
  'redirect_target_allowlist'` — the test iterates every module in
  `SOURCES`/`TRANSFORMS`/`SINKS`/`COMPLEXITIES` and looks up its fixture
  context in `_DETERMINISM_CTX_BY_MODULE`, with no entry for any of the
  three new names.
- `test_every_registered_module_has_a_determinism_ctx_fixture` (the guard
  test this file's own comment describes as existing specifically "against
  a new module being added to a registry without also being added to
  `_DETERMINISM_CTX_BY_MODULE`") failed its set-equality assertion for the
  same reason, naming all three missing entries explicitly.

No production code was wrong — both new registrations rendered correctly
(confirmed separately by `tests/test_labgen_open_redirect.py`, including a
real live-boot proof). The defect was confined to test fixture
completeness for the shared package's own registries.

## What the bug was identified to be

`_DETERMINISM_CTX_BY_MODULE` (`tests/test_labgen_modules.py`) is a
hand-kept dict, one entry per module name across all four shared
registries, that a same-file guard test (`test_every_registered_module_
has_a_determinism_ctx_fixture`) asserts stays exhaustive. `CC-LAB-0210`
added three new registry entries in `fuzzlab/labgen/modules/__init__.py`
without adding the three corresponding fixture entries in this
test-adjacent table — an authoring omission in the same change, not a
defect in the guard mechanism itself (which caught it correctly, on its
very first run against the new code).

## Root-cause analysis (Five Whys)

1. **Why did the whole-repo suite fail?** Two new tests in
   `tests/test_labgen_modules.py` had no fixture entry for three newly
   registered module names.
2. **Why did the new module registrations not include fixture entries?**
   The change's own author (this session) copied the `L-P3.3c-DOM`
   precedent for *where and how* to register a shared-vocabulary-only
   module (`fuzzlab/labgen/modules/__init__.py`'s `SOURCES`/`TRANSFORMS`/
   `SINKS`/`COMPLEXITIES` dicts) but did not also check
   `tests/test_labgen_modules.py` for a parallel completeness table that
   `L-P3.3c-DOM`'s own three entries also had to satisfy.
3. **Why was that not caught before the commit was pushed?** The
   pre-push verification ran `tests/test_labgen_open_redirect.py` (the new
   shape's own test module, all passing) and
   `tests/test_labgen_php_laravel_harder_shapes.py` (the closest existing
   `php_laravel`-specific test file, also passing) — both directly
   relevant to the change, but neither imports or exercises
   `tests/test_labgen_modules.py`'s shared-package completeness table.
4. **Why was the whole-repo suite not run before that push?** The
   change's own scope (`CC-LAB-0210`) touches two registries — the
   `php_laravel`-specific one (covered by the harder-shapes test file) and
   the shared, cross-stack one (covered by a *different* test file,
   `test_labgen_modules.py`, not obviously implied by "I changed
   `php_laravel`'s own module set"). The verification step run before
   pushing was scoped to "files I directly authored/expect to be affected"
   rather than "the whole suite," which is what this project's own
   Definition-of-Done (`CLAUDE.md` step 2: "run the suite (`pytest`); keep
   it green") already requires, but was not yet completed at push time —
   it was completed immediately afterward, in the same continuous session,
   as the change's own closing verification.
5. **Root cause:** a cross-cutting change (one that touches a *shared*
   registry consumed by more than one stack-specific module set) has more
   than one test file's completeness table to satisfy, and the session's
   pre-push verification step checked only the files it judged directly
   relevant rather than running the whole-repo suite that step 2 of this
   project's own Definition-of-Done already mandates — the full suite
   check happened, but after the push rather than gating it.

## Corrective action

Added the three missing `_DETERMINISM_CTX_BY_MODULE` entries
(`redirect_target_allowlist`, `http_redirect_return`, `redirect_response`),
matching the file's own `L-P3.3c-DOM` precedent's comment convention
(`tests/test_labgen_modules.py`). Verified with a second whole-repo
`pytest tests/` run: 1618 passed, 30 skipped, 0 failed. Delivered in the
same `CC-LAB-0210` change-control entry (its Effectiveness section records
both whole-repo run results), on this same branch, before the change was
considered complete or a PR opened.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of this bug, or a different bug with the same root cause,
**before** deciding the preventive action below, per this project's
standing discipline:

- **`PA-0001`/`PA-0027`** (hand-maintained completeness registries must
  stay in sync with what they enumerate, and a test must fail loud when
  they drift) is the *closest* prior rule, and it is not a failure of that
  rule — `_DETERMINISM_CTX_BY_MODULE`'s own guard test is a direct
  instance of PA-0001/PA-0027's discipline, and it worked exactly as
  designed: it failed loud, on the very first run against the new code,
  naming the exact three missing entries. This is not a recurrence of
  BUG-0025 (PA-0027's origin, a *different* root cause — a test computing
  its expected set from a stale literal instead of a live predicate); here
  the table and its guard were both correct, current, and functioning.
- No other `docs/bugs/` entry matches this root cause (a cross-cutting
  registry change with more than one completeness table to satisfy, and a
  pre-push verification scoped to "directly relevant files" rather than
  the whole suite). This is a **new** root cause, not a recurrence, so no
  prior-preventive-action failure analysis is owed — the gap is in this
  session's own verification sequencing, not in an existing PA that failed
  to prevent it.

## Preventive action

**`PA-0036`** (new, see `docs/PREVENTIVE_ACTIONS.md`): when a change
registers a module (or any entry) in a **shared, cross-stack** registry
consumed by more than one stack-specific module set or more than one
test file's own completeness table (as opposed to a change confined to one
stack's own emitter-local registry), the whole-repo `pytest tests/` suite
must be run and green **before** the change is pushed/considered
complete — not only the test file(s) judged directly relevant to the
change. This is a sharpening of `CLAUDE.md`'s own Definition-of-Done step 2
("run the suite; keep it green") for the specific case where "the suite"
that matters is not obviously implied by which production file was edited.

Sweep (`PA-0002`): this change (`CC-LAB-0210`) is the only change in this
session/branch that touched a shared, cross-stack registry; no other
instance of this gap exists to remediate.
