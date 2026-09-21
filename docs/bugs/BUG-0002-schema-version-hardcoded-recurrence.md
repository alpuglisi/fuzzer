# BUG-0002 — Schema-version assertion hardcoded (recurrence of BUG-0001)

- Date: 2026-09-21
- Status: fixed
- Severity: low

## Description
A second test hardcoded the schema head version (`== 2`). Adding migration 3
(non-secret session-state persistence, T1.7) advanced the head to 3 and broke it —
the same class of defect as BUG-0001.

## Where encountered
`tests/test_harness.py:65` (`test_score_from_store_and_metrics`), while adding
migration 3 for T1.7.

## What it caused to fail
`assert 3 == 2` — the harness store-integration test failed after a correct,
intended schema addition.

## What the bug was identified to be
Another test coupling to a literal that the migration registry already defines —
an instance of the BUG-0001 class that BUG-0001's fix did not remediate. BUG-0001
fixed the two tests that were failing at the time (in `test_core_foundations.py`)
but did not sweep the codebase for other instances, and this one — in a different
file, not failing then — was left in place until migration 3 tripped it.

## Root cause analysis
Five Whys:
1. Why did it fail? It asserted `== 2`, but the head is now 3.
2. Why is it 3? Migration 3 was added by design; the head advanced.
3. Why didn't the assertion track that? It hardcoded `2` rather than deriving from
   `migrations.MIGRATIONS`.
4. Why was it still hardcoded, given PA-0001 existed? BUG-0001's corrective action
   fixed only the instances that were failing then; it did not search for other
   instances of the same pattern, so this latent one survived.
5. Why didn't PA-0001 prevent it? PA-0001 is a forward-looking rule for new code; it
   did not call for remediating *existing* violations, so a latent instance
   remained until a later migration triggered it.

**Root cause:** a preventive action was added for a bug class without sweeping and
remediating the existing instances of that class, leaving a latent instance that a
later change tripped.

## Corrective action
Derived the assertion from the registry:
`assert store.schema_version() == max(v for v, _ in migrations.MIGRATIONS)`
(PA-0001-compliant). Swept `tests/` for other hardcoded schema-version literals —
none remain. Suite green (71/71).

## Preventive action
PA-0002 (see `docs/PREVENTIVE_ACTIONS.md`): when a bug investigation adds a
preventive action, **sweep the codebase for all existing instances of that bug
class and remediate them** (or record why not) — not just the instance that
triggered the investigation. A forward-only rule leaves latent instances that
resurface later.
