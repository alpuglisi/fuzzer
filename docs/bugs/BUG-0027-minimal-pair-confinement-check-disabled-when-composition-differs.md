# BUG-0027 — `check_minimal_pair`'s content-confinement check silently disabled
whenever the two variants' compositions differ by name (the common case)

- Date: 2026-09-22
- Status: fixed
- Severity: high (safety-relevant checker fails open on its own core invariant)

## Description

`fuzzlab/labgen/minimal_pair.py::check_minimal_pair()` exists to guarantee a
vulnerable/secure cell pair differs **only** in its declared transform/sink region —
the whole point being that a fuzzer/mutation-engine training signal built from the
pair is attributable to the actual security-relevant difference, never incidental
noise (the module's own docstring, quoting `CR-LAB-0001` §3 and
`docs/LAB_SEED_AUTHORING_PLAYBOOK.md` step 5/6).

The content-confinement half of that check (`_check_file_pair()`'s
"differ outside any declared transform/sink change" band check) only ran when the
two variants' `// Module composition: ...` sequences were **name-identical**
position-for-position. Whenever any position's module name legitimately differed
(`any_declared_difference = True`), the confinement check was skipped in its
entirety for the **whole file** — not narrowed, not still checking the rest of the
file, just not run at all. A real vulnerable/secure pair's composition names are
essentially always different at the transform position (e.g. `identity` vs.
`param_bind`), so this was not an edge case: it was the disabled state for exactly
the comparison the checker exists to make.

## Where encountered

Found while implementing `CC-LAB-0055`/`FR-LAB-53` (adding `pair_by` to
`check_minimal_pair`, per lane L-P3.3c-G3's finding — see `CC-LAB-0048`, which
worked around the *pairing* half of this module's limitations without noticing this
second, independent gap in the confinement check itself). No prior lane's
`ERROR_LOG.md` entry names this specific gap; `CC-LAB-0048`'s note describes only
the strict-path-pairing limitation.

## What it caused to fail

Nothing failed *loudly* — that is the defect. Concretely:
`tests/test_labgen_minimal_pair.py::test_unrelated_rewrite_before_the_transform_region_now_caught`
(new, added by this fix) demonstrates the failure mode directly: take a real
`php_current` vulnerable/secure pair (`identity` -> `param_bind`, a legitimate
declared difference), and additionally rewrite the *source* line
(`$_GET['id']` -> `$_POST['id']`) — a change with nothing to do with the declared
transform difference, and one `check_minimal_pair()`'s own docstring says must be
caught ("everything else ... must be identical"). Before this fix,
`check_minimal_pair()` returned `None` (no exception) for this input, because
`any_declared_difference` was `True` (the transform names differ) and the band
check was gated off entirely by that one boolean, regardless of where the *other*
difference was. Any caller relying on this checker as a build-time gate (the
`--check` CLI gate in `fuzzlab/labgen/cli.py`, and every `tests/test_labgen_*_g*.py`
lane's own minimal-pair test) would accept a secure "twin" that silently changed
something the invariant is supposed to forbid, as long as it also touched its
transform.

## What the bug was identified to be

`_check_file_pair()` computed the empirical content-difference band (via
longest-common-prefix/-suffix line trim, excluding the composition comment line)
unconditionally, but only *validated* it — requiring it be empty — inside the
`if not any_declared_difference:` branch. There was no code path that validated
the band at all when `any_declared_difference` was `True`; the function fell
straight through to `check_identifier_stability()` regardless of the band's
size or location.

## Root cause analysis

Five whys:

1. **Why did a twin that rewrote an unrelated line pass `check_minimal_pair()`?**
   Because `_check_file_pair()` never inspected `v_middle`/`s_middle` (the computed
   diff band) in the code path taken whenever the two compositions differ by name.
2. **Why does that code path exist without a confinement check?** Because the
   *only* confinement check implemented compares the band against "empty" — a
   boundary that is only meaningful when nothing is declared different (composition
   identical ⇒ band must be empty). When something *is* declared different, "empty"
   is the wrong expected value, and no alternative, non-trivial boundary was ever
   computed for that case.
3. **Why was no alternative boundary computed?** Because deriving one appears, at
   first, to require re-rendering a module to know exactly which lines belong to
   it — something this checker's own docstring explicitly refuses to do (it is a
   standalone, non-rendering checker) — so the "boundary" problem looked
   unsolvable within the checker's existing constraints and was left unaddressed.
4. **Why was this not caught by the existing test suite?**
   `tests/test_labgen_minimal_pair.py`'s own positive fixture (`real_pair`) *always*
   has composition names differing at the transform position by construction (that
   is what makes it a real vulnerable/secure pair), so `any_declared_difference` is
   `True` for every existing positive-path test — the disabled branch was the one
   under test the whole time, and every negative-path (violation) fixture instead
   targeted the identifier-stability check or the *no*-declared-difference branch
   (`test_content_diff_reported_when_no_composition_difference_exists`,
   `test_unrelated_identifier_rename_with_no_composition_change_is_caught`), never
   "a real pair that also has an unrelated change."
5. **Root cause:** the confinement check conflated "I cannot state an exact
   boundary from composition-name-matching alone" with "I cannot state *any* useful
   boundary" — but a useful, independently-derivable boundary *does* exist without
   re-rendering: a `transform` module's own self-identifying comment line
   (`// {name} transform: ...`, a convention every template in
   `fuzzlab.labgen.modules.transforms` already follows) marks, on each side
   independently, where the fixed source/depth fragments end and the
   transform/sink region begins in the assembled file (fragments concatenate in
   declared order). The checker never looked for it.

## Corrective action

`fuzzlab/labgen/minimal_pair.py`:

- Added `_first_variable_marker_line()`: locates, in one side's own stripped
  content, the line of its own first `transform`-category composition entry's
  self-identifying comment (`// {name} transform: ...`), returning `None` when the
  marker cannot be found (a non-`php_current`-convention emitter) so the check
  degrades to its old behavior rather than false-positiving on a stack it does not
  understand.
- `_check_file_pair()` now always additionally requires (regardless of
  `any_declared_difference`, and independent of whether the two sides' composition
  names match): the empirically-found content divergence (`prefix_len`) may not
  start before the earlier of the two sides' own transform-marker line. A
  divergence located before that point is, by construction, not attributable to
  any declared transform/sink difference and now raises `MinimalPairViolation`
  ("files differ before the declared transform/sink region ...").
- `check_identifier_stability()` is now called *before* this new check (previously
  after the disabled confinement check), so a handler/function-name rename —
  itself a difference that legitimately precedes the transform marker — still
  surfaces as the specific, existing "function/handler identifier" violation
  rather than the new generic boundary message.
- This closes the **leading**-region gap concretely. It does **not** close a
  symmetric **trailing**-region gap (a rewrite inside the sink's own rendered
  SQL/HTML, downstream of the transform region) — no sink template in
  `fuzzlab.labgen.modules.sinks` follows a matching self-identifying-comment
  convention, and deriving an exact trailing boundary without one would require
  re-rendering a module standalone, which this checker's docstring already refuses
  to do. Recorded here, not silently assumed solved (mirrors the existing,
  already-documented "composition sequences must have equal length" scope limit).
- New regression tests in `tests/test_labgen_minimal_pair.py`:
  `test_a_real_transform_rename_alone_still_passes` (no false positive on the
  existing real, legitimate pair),
  `test_unrelated_rewrite_before_the_transform_region_now_caught` (the direct
  regression for this bug), and
  `test_content_confinement_runs_even_when_variable_categories_is_narrowed`
  (the new check does not depend on the caller's `variable_categories` value).
- Delivered alongside `CC-LAB-0055`/`FR-LAB-53` (the `pair_by` capability change,
  a separate, non-defect enhancement bundled in the same change).

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence of
the same bug, or a different bug with the same root cause, before deciding the
preventive action.

- `CC-LAB-0048`'s own text ("that checker pairs strictly by file path and cannot
  itself compare two distinctly-named cells") documents the **pairing** gap this
  same change also fixes (`pair_by`), but does not mention the confinement-check
  gap at all — the two are independent defects in the same module, found together
  only because fixing the first required reading the whole function closely enough
  to notice the second. No `BUG-NNNN`/`PA-NNNN` previously named either.
- **PA-0028** (`SemanticsValidator` fail-open on untrusted SQL comment-append,
  this same session) is the closest existing preventive action in *shape*: both
  are a validator that returns "no violation" from a code path that never actually
  evaluated the risky case. However PA-0028 is scoped to semantics/equivalence
  validators specifically (fragment-level AST/canonical-form comparisons); this
  bug is a structural confinement check over composed template output, a
  different mechanism in a different subsystem (LAB, not MUT). This is not a
  recurrence of PA-0028 under its own terms, but the same general failure
  *pattern* — "a checker's happy-path code silently skips the check that matters
  most, rather than running a narrower version of it" — recurring in a second,
  unrelated subsystem in the same session.
- No prior `BUG-NNNN` addresses `fuzzlab.labgen.minimal_pair` at all. This is a
  new preventive action, not a strengthening of an existing one, though it is
  written to generalize the pattern PA-0028 already named once this session (see
  below).

## Preventive action

**PA-0029** (new) — recorded in `docs/PREVENTIVE_ACTIONS.md`:

Generalizes PA-0028's fail-closed doctrine beyond semantics validators: **any
checker whose "no violation found" verdict is reached by a code path that gates
off (skips entirely, rather than narrows) part of its own stated invariant under
some condition** must have a test whose positive fixture actually exercises that
gated-off branch with an *additional*, unrelated defect injected into it — never
only a fixture where the gating condition happens not to trigger. Concretely for
`fuzzlab.labgen.minimal_pair`: every future emitter/module category added to
`DEFAULT_VARIABLE_CATEGORIES` or to the module registries must have a
corresponding "a legitimate declared difference *plus* an unrelated rewrite is
still caught" regression test, not only a "declared difference alone passes"
test — the shape `test_unrelated_rewrite_before_the_transform_region_now_caught`
now provides for the transform/leading-region case. The PA-0002 sweep for this
class checked every call site of `check_minimal_pair`/`get_minimal_pair_checker`
in `fuzzlab/` and `tests/` (`fuzzlab/labgen/cli.py`,
`fuzzlab/labgen/conformance/tier0.py`, and every `tests/test_labgen_*.py` lane
test): all of them call the shared function directly and therefore inherit this
fix automatically; `fuzzlab/labgen/conformance/` is a concurrently-owned
directory this change does not modify, and `fuzzlab/labgen/cli.py`'s own
`_weakened_twin()`-based calls already compare same-path renders, so they gain
the new leading-region check "for free" with no call-site change needed.
