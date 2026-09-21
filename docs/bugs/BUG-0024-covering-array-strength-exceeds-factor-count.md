# BUG-0024 — Covering-array resolver silently returns zero cells when `strength` exceeds the factor count

- Date: 2026-09-21
- Status: fixed
- Severity: medium

## Description

`fuzzlab.labgen.resolver.expand()` (and its `validate_covering_array_config()` gate)
accepted a covering-array config whose `strength` (t-way covering) exceeds the number
of factors it varies over — or, for a `sub_models` entry, whose own `strength` exceeds
that entry's own field count — and passed it straight through to `covertable.make()`.
`covertable.make()` does not raise for this shape; it silently returns an empty array.

## Where encountered

While implementing lane L-P1.1 (T-LAB2.1: wire the covering-array resolver into
manifest loading, `fuzzlab.labgen.schema`), writing a regression test for an
`axis_ranges` block that varies a single axis (`sink_context_family`) at the default
`strength: 2`. The block validated against both the manifest JSON Schema and
`validate_covering_array_config()` without error, then `resolver.expand()` returned
`[]` — zero generated cells, with no exception anywhere in the path.

## What it caused to fail

Nothing failed loudly. A syntactically- and semantically-plausible `axis_ranges` block
(one real axis, default strength) would silently produce a manifest with zero
generated cells instead of the two the axis's two levels obviously call for. In a real
manifest this is the worst kind of defect: a corpus-generation run reports success and
simply omits an entire axis's cells, with no exception, no test failure signal, and no
diagnostic — discoverable only by manually checking the resulting cell count against
expectation, which is exactly the class of check `fingerprint_gate.py`/`leakage_probe.py`
(2.3) depend on having correct cell data to run against in the first place.

## What the bug was identified to be

`validate_covering_array_config()` checks `strength` is a positive integer, but never
checks it against the number of factors being covered (nor, for a `sub_models` entry,
against that entry's own field count). `covertable.make()` itself has no such check
either — verified directly against the installed 3.2.0 package:

```python
>>> from covertable import make, sorters
>>> make({"a": ["x", "y"]}, strength=2, sorter=sorters.hash)
[]
```

A t-way covering array is undefined for fewer than t factors, so this is always a
caller-error input, never a valid degenerate case that should return no rows.

## Root cause analysis

Five whys:

1. **Why did an axis_ranges block generate zero cells?** `resolver.expand()` returned
   `[]` for a valid-looking config.
2. **Why did it return `[]`?** `covertable.make()` returned `[]` for a config where
   `strength` (2) exceeds the factor count (1).
3. **Why didn't `validate_covering_array_config()` catch this before calling
   `covertable.make()`?** It only allowlists which *keys* may appear and checks
   `strength`'s *type* (positive int) — it never checks `strength` against the
   *cardinality* of what it is being asked to cover.
4. **Why was this specific check missing** when this module's whole documented purpose
   is guarding against `covertable.make()`'s silent-failure surface (its docstring
   names two such shapes explicitly, both citing PA-0010)? The two shapes the module's
   author enumerated and defended against (silently-swallowed unrecognized kwarg,
   unpinned sorter default) were identified by reading `covertable.main.make`'s
   signature and the plan's own risk notes — but nobody separately verified
   `covertable.make()`'s behavior against every structurally-invalid *value* combination
   the allowlisted kwargs can take, only against a wrong *key*.
5. **Why didn't a review catch the gap?** The module's tests (`test_labgen_resolver.py`)
   cover the two enumerated shapes thoroughly but never exercised `strength` relative to
   factor count at all — the golden-file/pairwise tests all use `strength <=
   len(factors)` by construction, so nothing forced this input shape to be tried until a
   consumer (this task's `axis_ranges` wiring) happened to construct a single-axis block.

**Root cause:** the adapter's threat model for "third-party API silently accepts and
mishandles an input instead of raising" was scoped to the *key surface* (allowlisting
kwargs) and one specific *value default* (the sorter), but not swept across the
*value-shape preconditions* the library's own algorithm silently assumes (here: t-way
coverage requires at least t factors/fields) — an incomplete application of the same
principle the module already claims to follow (PA-0010).

## Corrective action

`validate_covering_array_config()` now rejects `strength > len(factors)`, and for each
`sub_models` entry, rejects (a) a non-positive/non-int `strength` override and (b) that
entry's own `strength > len(fields)` — both checked before `covertable.make()` is ever
called, each with a `CoveringArrayError` naming the exceeded cardinality. Two new
regression tests in `tests/test_labgen_resolver.py` first reproduce `covertable.make()`'s
own silent `[]` (mirroring the existing kwarg-swallow test's own documentation style),
then assert the adapter now rejects the same input, plus a boundary test confirming
`strength == len(factors)` is still accepted. See `CC-LAB-0029`.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence of the same
bug or the same root cause. Found one: **BUG-0009** (`docs/bugs/BUG-0009-greybox-coverage-empty-fragile-pcov-guard.md`),
whose preventive action **PA-0010** is the exact rule this resolver module's own
docstring cites as its motivation — "confirm the expected granularity... before passing
it" and "verify the actual produced signal end to end... 'loads ≠ works'." This is not a
second appearance of the *identical* bug (a different library, a different call site),
but it is the *same root cause*: a well-intentioned adapter/guard applies PA-0010's
principle to some but not all of the ways the wrapped call can silently mishandle a
structurally-invalid input, so a novel input shape slips through the part of the surface
the guard never enumerated.

## Prior-preventive-action failure analysis

PA-0010 (from BUG-0009) reads, in full: "When an API takes a filter/selector argument,
confirm the expected granularity (file vs directory vs prefix vs glob) before passing
it... And verify the actual produced signal end to end, not just that the dependency is
present." This resolver module (`fuzzlab/labgen/resolver.py`) explicitly cites PA-0010
twice in its own module docstring as the reason it exists, and did apply it — to the
*kwarg-key* surface (an allowlist rejecting any key `covertable.make()` would otherwise
silently swallow) and to the *sorter default* (pinned explicitly rather than trusted).
Both of those were correctly identified failure modes. What PA-0010, as written, does
not make explicit is that this same discipline must be applied *per allowlisted key's
own value-shape preconditions*, not just to the key surface and one flagged default —
so a careful, PA-0010-citing author still produced an incomplete guard, because PA-0010
itself only prescribes the general instinct ("confirm granularity", "verify the
signal") rather than a checklist step that would have surfaced "what value-shape
preconditions does this library's algorithm silently assume, for *every* allowlisted
parameter, not just the one already flagged as risky." The prior PA was not "not
followed" — it was followed for the two shapes its own author recognized, but the rule
as written gave no mechanism to reliably identify the *rest* of a library's structural
preconditions.

## Preventive action

**PA-0026 — supersedes/strengthens PA-0010:** When building an explicit-allowlist
adapter around a third-party function specifically *because* that function silently
accepts and mishandles some input classes (PA-0010's original filter/granularity case,
and this module's kwarg/sorter case), the adapter's author must, for **every**
allowlisted parameter, enumerate the value-shape preconditions the wrapped
implementation assumes but does not itself validate (cardinality relationships between
parameters, minimum/maximum counts, ordering assumptions, mutual exclusivity, etc.) —
not only the one input class that originally motivated writing the adapter — and add an
explicit precondition check plus a test that first reproduces the library's own silent
failure for each one found, mirroring this bug's tests
(`test_strength_exceeding_factor_count_rejected_not_silently_empty`,
`test_sub_model_strength_exceeding_its_own_field_count_rejected` in
`tests/test_labgen_resolver.py`). Per PA-0002, this also means sweeping every existing
PA-0010-motivated adapter in the codebase for the same gap — done here: `resolver.py`
has exactly one wrapped call (`covertable.make()`) and its only other cardinality
relationship (`sub_models[].strength` vs. `sub_models[].fields`) is now covered
alongside the top-level one; no other PA-0010-cited allowlist adapter exists in the
codebase as of this writing (`grep -rln PA-0010 --include='*.py'` finds only
`fuzzlab/labgen/resolver.py`, `fuzzlab/labgen/schema.py` — this task's own new
cross-reference comment, not a separate adapter — and their two test files; the other
hits are prose mentions in `docs/bugs/BUG-0012-*.md`, `CHANGELOG.md`, and this
component's `change-control.md`, none of which describe a second wrapped call).
