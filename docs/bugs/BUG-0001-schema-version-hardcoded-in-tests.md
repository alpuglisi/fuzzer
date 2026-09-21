# BUG-0001 — Schema-version assertions hardcoded in tests

- Date: 2026-09-21
- Status: fixed
- Severity: low

## Description
Two core foundation tests asserted the store's schema version equals the literal
`1`. When migration 2 was later added (self-describing findings, T0.7), both tests
failed even though the schema change was correct and intended.

## Where encountered
`tests/test_core_foundations.py` — `test_migrations_are_idempotent` and
`test_store_run_and_body_roundtrip` — while adding migration 2 during the Phase 0
integration-harness work.

## What it caused to fail
Two unit tests failed (`assert 2 == 1`), turning an otherwise-clean suite red and
briefly making a correct change look like a regression.

## What the bug was identified to be
The tests hardcoded the schema **head version** as the literal `1` instead of
deriving it from the migration registry, which is the source of truth for that
value. A normal additive migration (raising the head to 2) therefore broke them.

## Root cause analysis
Five Whys:
1. Why did the tests fail? They asserted `schema_version == 1`, but it was `2`.
2. Why was it `2`? Migration 2 was legitimately added; the head advanced by design.
3. Why didn't the assertion track that? It used a literal `1` rather than computing
   the expected head.
4. Why was a literal used? When the tests were written only migration 1 existed, so
   `1` looked like a stable constant.
5. Why is that a defect pattern? The test duplicated a value that already has a
   single source of truth in the code (the `MIGRATIONS` registry), coupling the
   test to a number that is expected to change.

**Root cause:** a test assertion duplicated a value that the code already defines
authoritatively (the migration head), instead of deriving it — an over-specified,
brittle test, so a correct and expected change to that value broke the test.

## Corrective action
Both assertions now derive the head from the registry:
`max(v for v, _ in migrations.MIGRATIONS)`. Delivered in commit `30ea97d`
(change-control CC-CORE-0003). Suite returned to green (30/30).

## Preventive action
PA-0001 (see `docs/PREVENTIVE_ACTIONS.md`): in tests, do not hardcode a value that
a source-of-truth constant or registry in the code already defines (schema head
version, `FEATURE_VERSION`, enum members, etc.) — derive the expectation from that
source so an intended change updates it automatically. Reserve literal expected
values for genuinely fixed external contracts (e.g. the ground-truth files).
