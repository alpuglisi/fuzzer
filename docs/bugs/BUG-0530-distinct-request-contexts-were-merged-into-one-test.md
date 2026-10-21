# BUG-0530 — Distinct request contexts were merged into one test

- Date: 2026-10-21
- Status: fixed (CC-FUZZ-0111, CC-AUD-0056, CC-CORE-0073, CC-ML-0501)
- Severity: high (BLOCKER in the owner's audit, defect 8)

## Description

Four layers each decided "which rows are the same test" with a hand-written tuple that
left out fields of the request: the importer kept one `parameter` row per (endpoint,
name); the point builder deduplicated on (path, method, name); the pipeline confirmed
once per (url, param, method, location, category); the ML label join matched a finding to
candidates on (run, path, param, category, method). Requests that a server routes to
different handlers -- the same name in the query and in the body, under another operation
selector, with another content type, after another store request -- were tested once, on
whichever row came first, and every other row was marked `checked` and labelled.

## Where encountered

Owner-supplied adversarial audit at 6552276, defect 8, reproduced offline (a temporary
real store). Measured on 8100959 by the parked tests of `DRAFT-AU-REQID8.md` §1.1 (9 strict
xfails), restored as `tests/test_request_contexts.py`.

## What it caused to fail

- POST `/api` with `q` in the query and in the body: only the query point was built.
- `op=safe&q=` and `op=search&q=`: one confirmation key; the `op=search` sink was never
  probed and its rows were marked checked: a negative nobody measured.
- Two captured JSON bodies to one endpoint, a form and a JSON body of one endpoint, two
  crawled links of one parameter: one context kept, the others dropped at import.
- A raw JSON body and a form field named `body`, and two stored cases rendered on one page:
  one test each.
- The `op=safe` finding labelled the never-confirmed `op=search` rows positive in the ML
  dataset.

## What the bug was identified to be

No owner defined the request a test sends. `store_adapter._get_parameter` (endpoint,
name), `injection_points_from_store`'s `seen` (path, method, name) and
`pipeline._confirmation_key` (5-tuple) each keyed on what was at hand; `ml.dataset`'s join
keyed on (run, path, param, category, method). Siblings (FR-FUZZ-42/43), JSON leaves
(FR-FUZZ-47), content types (FR-FUZZ-19) and store requests (FR-AUD-24) were added to the
evidence and the `Candidate` over time, and to none of the keys.

## Root cause analysis (Five Whys)

1. Why was the `op=search` sink never probed? Its rows shared `_confirmation_key` with
   the `op=safe` rows.
2. Why did they share it? The key listed five fields; the request has more: siblings,
   occurrence/JSON path, content type, setup, identity.
3. Why five? BUG-0072 made the key "the identical confirmation" (PA-0073); the fields that
   make confirmations differ were added later, each to the evidence and the `Candidate`,
   none to the key.
4. Why was the key not updated? No test related the key to the fields a sender or a
   strategy reads. The importer and the builder had the same kind of dedup with fewer
   fields, recorded as residuals ("one confirmation per (url, param, method, location)",
   "the first crawled link wins", "the first one's leaf wins a name").
5. **Root cause:** "which rows are one test" was decided at four places, each by a
   hand-written tuple, and nothing tied those tuples to what the request contains.

## Corrective action

- `core/reqctx.py` (SP-57, CC-CORE-0073): one versioned request-context identity (origin,
  path, raw query, fragment, method, location, target, placement rule, sibling entries
  with the target's slot as a placeholder, content type, setup steps, refused siblings,
  identity scope) and one `confirmation_key` (context id, category, plus the seed for
  `SEED_CATEGORIES`), computed from a candidate's evidence (older rows on read).
- The importer writes one row per context (CC-AUD-0056); the engine stamps
  `context_id`/`identity_scope`; the builder dedups on `point_key`; the pipeline confirms
  on `confirmation_key`; the finding records `context_id`/`context_key`; ML labels by it
  (CC-FUZZ-0111, CC-ML-0501).
- Tests: `tests/test_request_contexts.py` (each reproduction, failing on c483dc1, plus
  SP-57's guards); amended with before/after: `test_forms_phase2` (two link/form context
  tests), `test_unplaceable_confirmation` (the stored-case/ordinary-point key).

## Recurrence review

Checked `docs/bugs/` and `PREVENTIVE_ACTIONS.md` for identity keys that omit a
distinguishing field:
- BUG-0046 / PA-0048: a (url, method, param) lookup collapsed `sink_context`.
- BUG-0072 / PA-0073: `_confirmation_key` introduced; "duplicates are safe" checked for
  every consumer.
- BUG-0075 / PA-0076: the label join omitted the method.
- BUG-0138 (SP-08 `document_key`): a key omitted the query.

Same root cause: yes (an identity key omitting a field that distinguishes the unit).

## Prior-preventive-action failure analysis

- **PA-0076(1)/(3) -- wrong layer.** Worded for *joins between two tables*. The merges here
  were *dedup keys inside one table or loop* (`seen`, `_get_parameter`,
  `_confirmation_key`), so PA-0076(3)'s sweep ("a new value of an identity field becomes
  possible") never ran when forms phases 1-3 added siblings, JSON leaves, content types
  and store requests.
- **PA-0073 -- not enforced at the level it claimed.** It asserted "rows that would send
  the oracle the identical confirmation share one key"; its invariant test varies only url
  and param, so nothing checked the claim against the fields that make confirmations
  differ.
- **PA-0048 -- too narrow.** It called duplicates "safe" for scoring and named consumers,
  not the importer's own dedup.
- **Stated residuals hid merges.** "First wins" was recorded as a residual instead of a
  pinned defect (PA-0054(3) applied to emitters only).

## Preventive action

**PA-0530** (strengthens PA-0073 and PA-0076(3)):
1. Whether two units are one request, test or label (a dedup set, a lookup key, a
   confirmation key, a join) is decided by the one versioned identity owner (SP-57), never
   a hand-written tuple.
2. Every field a sender, strategy or executor can read from a candidate is in that
   identity or in its exclusion table with a reason; a guard fails on an unclassified
   field (proven on a synthetic offender), and every identity field is shown to move the
   id while no excluded one does.
3. A row is marked done only by its own unit's work.
4. A stated residual that merges distinct inputs ("first wins") is a defect to pin with a
   strict xfail naming its owner, never a residual.

- Enforced by: tests/test_request_contexts.py::test_every_candidate_field_is_in_the_identity_or_excluded, tests/test_request_contexts.py::test_the_field_guard_catches_a_synthetic_offender, tests/test_request_contexts.py::test_every_identity_field_moves_the_context, tests/test_request_contexts.py::test_no_excluded_field_moves_the_context, tests/test_request_contexts.py::test_the_seed_categories_are_the_strategies_that_read_the_original_value, tests/test_request_contexts.py::test_the_seed_guard_catches_a_synthetic_offender, tests/test_request_contexts.py::test_the_pipeline_tests_a_context_that_only_its_siblings_reach

PA-0002 sweep (by mechanism: every dedup key over requests): `_get_parameter` (all callers),
`_import_link_sets`, `_import_forms`, `_store_request`, `import_disco`'s form-body `dict`,
the builder's `seen`, `_confirmation_key`, the ML label join -- fixed. Kept, with reason:
`header_points_from_store`'s per-page `seen` (one header point per page and name, by
design), `harness.scoring`'s case key (ground truth's own key; a set), PA-0048's
`sink_contexts_by_point` (those duplicates are one context), `pipeline._dedup` (template
clusters: defect 10's item), `ml.dataset.candidate_keys` (a coarse cross-run metric, not a
label). Pinned to their owners: the crawler's form and request signatures (CRAWL), POST
action query points (AU-REQID-POSTQ), per-occurrence binding and raw link-set text
(follow-ups of AU-REQID8, R1/R2).
