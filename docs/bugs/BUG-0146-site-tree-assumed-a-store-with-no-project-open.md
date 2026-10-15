# BUG-0146 — merged: the site tree assumed a store, and fell back to the built-in default, with no project open

- Date: 2026-10-15
- Status: fixed
- Severity: medium.
  - `/api/sitetree/version` returned 500 whenever no project was open, which is the
    start-screen state.
  - Where the config had no store key, the site tree would have read `./fuzzlab.db`
    implicitly, against FR-UI-458 and PA-0452.

## Description
The site-tree lane (CC-UI-0500..0503) and the project-files lane (CC-UI-0450) were built
concurrently from the same base:
- **The site tree** wired `store_path=lambda: cfg.get("store_path", "fuzzlab.db")`.
- **The project-files lane** made `cfg` answer `None` when no project is open, and made
  the default store never used implicitly.

Each was correct on its own branch. Merged, `store_version(None)` raised `TypeError`.

## Where encountered
Integration full suite: three tests in `tests/test_web_projects.py` failed with
`TypeError` (`expected str … not NoneType`) in `sitetree.store_version`:
- `test_an_older_startup_project_is_never_touched_until_migration_is_accepted`;
- `test_a_newer_project_is_refused_and_never_written`;
- `test_with_no_project_open_nothing_creates_a_file`.

## What it caused to fail
Those tests. On the merged product, the site-tree page's version poll failed in the
start-screen state.

## What the bug was identified to be
A cross-lane contract change, "the store may be absent", was not applied to the other
lane's new consumer. Each lane's tests used a store that always existed.

## Root cause analysis
**Method: change analysis** (the base, each lane, the merge).
- **The project-files lane changed a shared contract:** `cfg["store_path"]` may now be
  `None`, and the default is never implicit.
- **The site tree's new consumer** was written against the old contract in parallel.
- **The overlap was predicted by file:** both lanes touch `web/app.py`. The overlap in
  *contract* (who reads `store_path`) was not.
- **The integration is the first point** where both meet.

**Root cause:** a contract change in one concurrent lane had no mechanism to reach
another lane's new consumers. Impact was identified by files, not by the consumers of
the changed contract (the same failure as the BUG-0141 supplement's analysis).

## Corrective action
In the 2026-10-15 integration (CC-UI-0055):
- the site tree is wired to `cfg.get("store_path")`, with no implicit default;
- `sitetree.store_version(None)` returns `None` (no store, no fingerprint);
- the read-only test snapshots after the app opens its startup project. That open
  records the project row by design (FR-UI-455); the routes themselves still write
  nothing.

## Recurrence review
- **BUG-0138:** the merged-tree regression of two concurrent lanes, and the same class.
- **BUG-0452 / PA-0452:** the default store is never implicit; it was violated here by
  the other lane's wiring.
- **The BUG-0141 supplement:** impact identified by recall and files, not by contract
  consumers.

## Prior-preventive-action failure analysis
- **PA-0146** (no two concurrent items on one file without a declared order) passed,
  because the shared *file* was an append point in `app.py`. It does not cover a shared
  *contract*.
- **PA-0452** was enforced by a test the site-tree lane never ran: it predated that
  lane's base.

## Preventive action
PA-0152: a change to a shared contract (a config key's possible values, a function's
return shape, a table's reader) names its consumers from the code (`grep` the key or
function across `fuzzlab/`) in its change-control Impact. Concurrent lanes are told of
it at dispatch, and at integration every consumer added by any lane is checked against
the new contract by the merged full suite before any push.
