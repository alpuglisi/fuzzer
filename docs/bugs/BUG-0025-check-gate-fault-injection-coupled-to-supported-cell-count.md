# BUG-0025 — `lab-generate --check` gate regression tests inject their fault via a global call counter, so widening an emitter's supported shapes silently changes (or disables) the fault

- Date: 2026-09-21
- Status: fixed
- Severity: medium

## Description

Two of `tests/test_labgen_cli.py`'s fault-injection tests for the
`fuzzlab lab-generate --check` build-gate suite (`flaky_fault`, which simulates a
nondeterministic emitter, and `rename_fault`, which simulates a minimal-pair
violation) decided *whether to corrupt this render* from the parity of a **single
global call counter** incremented once per rendered cell. The parity a given cell's
own render lands on therefore depends on how many *other* supported cells precede it
in the pass — i.e. on the number of cells the emitter declares support for, which is
not a property either test is about.

The same file also hardcoded `SUPPORTED_CELL_IDS` — the subset of the example
manifest's cells `php_current` renders — as a literal set, although
`PhpCurrentEmitter.supports()` is the authority for exactly that.

## Where encountered

While implementing lane L-P1.2b (`docs/LAB_IMPLEMENTATION_PLAN.md` §2.2: the harder
SQLi/XSS shapes), which widens `php_current`'s `_MODULE_SET_BY_SHAPE` by four shapes.
One of those, `(xss, html_attribute_unquoted)`, is matched by `LABGEN-EX-0003`, a cell
in `lab/manifests/example_phase0_scaffold.yaml` that had been correctly skipped as
unsupported since Phase 0. The example manifest's supported-cell count therefore went
from 3 to 4, and
`tests/test_labgen_cli.py::test_check_fails_loud_on_nondeterministic_render` failed:
the `--check` run still exited 1 (a *different* gate, the minimal-pair checker, tripped
on the by-product of the injected fault), but the determinism gate the test exists to
exercise no longer failed at all, so the asserted "determinism check"/"regeneration"
wording was absent from the output.

## What it caused to fail

- Directly: the two tests above became coupled to an unrelated property (supported-cell
  cardinality). With 4 supported cells, `flaky_fault` corrupted *both* whole-tree
  renders of the regenerate-and-diff comparison identically, so the determinism gate
  saw two identical trees and passed — the test was no longer testing the gate. It
  failed loudly this time only by luck: it asserts on the *message*, not merely on the
  exit code, and another gate happened to produce a nonzero exit.
- `rename_fault` was the same defect one step short of firing: with an even number of
  supported cells preceding it, `LABGEN-EX-0001`'s renders all land on the same parity,
  so whether the minimal-pair fault is injected at all is decided by cell count.
- Latent: `SUPPORTED_CELL_IDS`, as a hand-maintained literal, has to be edited by hand on
  every widening of `supports()` — the maintenance burden that makes a silently-skipped
  cell easy to miss (the same lockstep failure as BUG-0022).

## What the bug was identified to be

Fault injection keyed on `call_count["n"] % 2` where `call_count` is incremented once per
*cell* render, while the property under test (does a second whole-tree render differ from
the first?) is per *pass*. The correct key is per cell identity:

```python
render_counts[cell.cell_id] = render_counts.get(cell.cell_id, 0) + 1
if render_counts[cell.cell_id] % 2 == 0:  # corrupt every second render OF THIS CELL
```

which is invariant under any change to the number of cells in the manifest or the number
the emitter supports.

## Root cause analysis

Five whys:

1. **Why did the determinism-gate test stop exercising the determinism gate?** The
   injected corruption applied to both whole-tree renders instead of one.
2. **Why did it apply to both?** The fault fires on even values of a counter incremented
   once per cell render; with an even number of supported cells per pass, each cell's
   renders in pass 1 and pass 2 land on the same parity.
3. **Why was the counter per cell render rather than per pass, or per cell identity?**
   It was written as the simplest possible "corrupt every other call" switch, without
   stating what "every other" is *relative to*.
4. **Why did nothing catch that the switch's granularity was wrong?** Nothing could: the
   test passed at the cell count that happened to exist when it was written (3, odd), and
   a fault-injection fixture has no independent check that the fault it injects actually
   reached the code path it targets.
5. **Root cause:** a test fixture's behavior was made a function of an incidental
   property of the collection under test (how many records it holds / how many of them
   the component supports) instead of a function of the record it is meant to perturb.
   The same root shape produced the hardcoded `SUPPORTED_CELL_IDS` literal in the same
   file: a test encoding a *derived* property of a capability registry as a standalone
   constant.

## Corrective action

Delivered in this lane's commit (change control `CC-LAB-0040`):

- `tests/test_labgen_cli.py`: both `flaky_fault` and `rename_fault` now count renders
  **per `cell_id`**, so the injected fault is invariant under any change in cell count
  or supported-shape set.
- `tests/test_labgen_cli.py`: `SUPPORTED_CELL_IDS` is now **derived** by asking
  `PhpCurrentEmitter().supports()` about every cell of the example manifest, so it
  tracks `_MODULE_SET_BY_SHAPE` automatically.
- PA-0002 sweep for the class, across `tests/`: the other counter-driven fault
  injections — `tests/test_labgen_gates.py::test_regenerate_and_diff_catches_a_nondeterministic_generator`
  and `tests/test_labgen_conformance_tier3.py`'s non-deterministic-emitter fixture —
  count *whole-tree generate calls*, one per pass, which is the correct granularity for
  the property they test; they are left unchanged (recorded here rather than silently
  skipped). No other test in the repo keys a fixture on a global per-record counter's
  parity, and no other test hardcodes a set a capability registry defines.

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for the same bug and for a
different bug with the same root cause. Three relevant prior items, all matches on root
cause rather than on symptom:

- **PA-0001 (from BUG-0001)** — "in tests, do not hardcode a value that a
  source-of-truth constant or registry in the code already defines; derive the
  expectation from that source." The `SUPPORTED_CELL_IDS` literal is a direct instance:
  `_MODULE_SET_BY_SHAPE` (via `supports()`) is that registry.
- **PA-0024 (from BUG-0022)** — the per-shape capability registry / per-record metadata
  lockstep rule, which required a whole-collection regression test when `supports()` is
  widened. It got the *coverage* obligation right, but says nothing about test fixtures
  that are themselves sensitive to how many records that widening adds.
- **PA-0013 (from an earlier bug)** — "a self-test assertion must reflect the true
  contract of the system under test." Adjacent, about the assertion, not about the
  fixture that sets up the condition being asserted.

## Prior-preventive-action failure analysis

**PA-0001 did not prevent the hardcoded set** because it is phrased in terms of a
*value* a constant or registry "already defines" — a schema version, a `FEATURE_VERSION`,
an enum's members. The set of manifest cells an emitter supports is not a value any
constant states; it is *computed* by a predicate (`supports()`) over another collection
(a manifest's cells). The author of that literal could read PA-0001 and conclude, not
unreasonably, that no registry defined the value being written down. PA-0001 was
therefore too narrow at the "what counts as a source of truth" boundary: it covered
stated values but not derived ones.

**PA-0024 did not prevent the fault-injection coupling** because it targets the wrong
layer. It obliges a widening change to *exercise every existing record* that could newly
match the widened shape — which this lane did (see
`tests/test_labgen_harder_shapes.py::test_every_cell_of_every_manifest_that_targets_php_current_renders`)
— but it says nothing about existing tests whose *fixtures* silently change behavior when
the number of matching records changes. That is the inverse direction of the same
lockstep: PA-0024 asks "does the new record get tested?", and the gap here was "do the
old tests still test what they claim once the record count moves?".

## Preventive action

**PA-0027** (new; strengthens PA-0001 and complements PA-0024) — recorded in
`docs/PREVENTIVE_ACTIONS.md`:

A test's expectations *and its fault injection* must both be functions of the specific
record under test, never of the collection's cardinality or iteration position. Two
concrete obligations:

1. Any fixture that perturbs "every other"/"the second" invocation must key its counter
   on the identity of the thing it perturbs (a `cell_id`, a path, a request), not on a
   global call counter — otherwise it is a function of how many *other* records the run
   happens to include.
2. PA-0001 extends to *derived* sources of truth: if a predicate or registry in the code
   can compute the set/subset a test asserts on (e.g. `Emitter.supports()` over a
   manifest's cells), the test computes it from that predicate instead of restating it as
   a literal.
