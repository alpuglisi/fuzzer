# `patterns/` — pattern-card provenance corpus (scaffold)

Owned by LAB (D20), per `docs/change-requests/CR-LAB-0001-manifest-generator-realism-and-variation.md`
Addendum A and `docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md`.

**Status: scaffold only.** This directory proves the shape end to end with
3 illustrative example cards. It is **not** the 25-30-card first-wave corpus
called for in CR-LAB-0001 §8 Phase 0 — that requires human OSV/GHSA triage
per `docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md` (cluster-then-sample
selection, a human picking `root_cause` wording, real `source_url`s) and is
explicitly **out of scope** for this delivery (see the LAB change-control
entry `CC-LAB-0015`). It is tracked as a separate, human-supervised
follow-up task.

## Layout

```
lab/patterns/
  cards/pc-*.yaml            # the corpus (schema: lab/schemas/pattern_card.schema.json)
  provenance.yaml            # cell_id -> [card_id, ...] — the ONLY link to a manifest
  taxonomy/classes-v1.yaml   # class vocabulary every card's `class` must appear in
```

## The one-directional rule (do not violate)

A pattern card documents *why* a cell exists. It is never read by
`fuzzlab.labgen.verdict` and a manifest cell never carries a card
reference — the artifact (the generated cell) must be unchanged by whether
provenance for it exists, the same invariant SLSA/in-toto provenance formats
enforce for build artifacts (CR-LAB-0001 Addendum A). `provenance.yaml` is
generator-docs output only, keyed the other way around: `cell_id -> [card_id]`.

`tests/test_labgen_gates.py::test_provenance_is_one_directional_no_leak_into_verdict_source`
enforces this mechanically: no card ID and no `pattern://`-style string may
appear anywhere in `lab/manifests/*.yaml` or in `fuzzlab/labgen/verdict.py`'s
source.

## What's real here vs. illustrative

- `taxonomy/classes-v1.yaml` — 2 classes only (the ones the example cards
  use), not the full ~10-class first-wave taxonomy.
- `cards/pc-*.yaml` — 3 example cards. Their `source_url`s are
  **placeholders**, explicitly marked as such in each card's `notes` field —
  none has been triaged against a real OSV/GHSA advisory yet. Do not cite
  these cards as real disclosures.
- `provenance.yaml` — maps the illustrative example manifest's cell IDs
  (`lab/manifests/example_phase0_scaffold.yaml`) to the example cards above.

## Follow-up (separate, human-supervised task)

Authoring the real first-wave corpus (~31 cards across the 10 classes in
`docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md` §5) requires a human to triage
real candidates and write `root_cause` in their own words — an LLM may only
label a candidate's class, never author `root_cause` text (see that plan's
§3 step 6 and `CR-LAB-0001` Addendum C point 3). Not attempted here.
