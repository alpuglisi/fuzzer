# BUG-0114 — The destructive-URL rule missed `update` and `insert`

- Date: 2026-10-13
- Status: fixed (CC-CORE-0039)
- Severity: high. A crawl that reached bWAPP's `update.php` would have rebuilt its whole
  database on a plain GET.

## Description
BUG-0111's `DESTRUCTIVE_TOKENS` (`core.urls.destructive_reason`) did not include
`update` or `insert`:
- bWAPP's `update.php` drops and rebuilds its database on an unauthenticated GET
  (`update.php:91`);
- `insecure_crypt_storage_2.php?insert=` appends to a password file.

Nothing links to either page today. But selector-form navigation (forms phase 1) or any
seed list would reach them, and the deny rule would have let the GET through.

## Where encountered
The read-only gap map of bWAPP's source (`scratchpad/bwapp-gapmap.md`, section (b)),
made before forms phase 1 enabled form navigation. Reviewers A and B both asked for it.

## What it caused to fail
NFR-CRAWL-safe and NFR-FUZZ-safe (latent: not yet triggered).

## What the bug was identified to be
An incomplete token list. BUG-0111 drew it from general knowledge, not from the
destructive endpoints of the target actually in use.

## Root cause analysis
1. *Why missing?* The list was written from common destructive verbs.
2. *Why not checked against bWAPP?* No rule required enumerating an adopted lab's
   destructive endpoints from its source.
3. *Why did no test catch it?* The tests checked the tokens listed, not a real target's
   endpoints.

**Root cause:** the deny rule was never validated against the real target's destructive
endpoints.

## Corrective action
- `insert` joins `DESTRUCTIVE_TOKENS`.
- `update` (and `upgrade`, after reviewer B's nit) is denied in three shapes:
  - **as a script name:** `update.php`, `upgrade.php` (pairs with
    `php`/`asp`/`aspx`/`jsp`/`cgi`/`pl`/`py`);
  - **as a query verb:** `?action=update`, `op`, `do`, `cmd`, `task`, `mode`,
    `method`, `func`;
  - **next to a database word:** `update_db.php`, `db_update.php`, `/schema/update`,
    and the run-together tokens `updatedb` / `dbupdate`.
- **Why not the bare word** (found by the full suite after review): our own ForgeCart
  lab's ground truth requires the crawl to reach the REST routes
  `/admin/customers/update` and `/webhooks/customers/update`. The bare word would also
  block every `update_profile.php` page. bWAPP's `update.php` is linked from no page
  and is not a picker option, so the narrower rule loses no safety for the lab as
  shipped. It went back to both reviewers (PA-0093(2)).
- **Accepted false negatives of the narrowing** (reviewer A): extensionless routes
  named `update` that rewrite data on a GET, in no database or verb context. Also
  `update.phtml` (`phtml` is not yet in the extension list; reviewer B's optional nit,
  to be added with the next `core/urls` change), and `?a=update` where the parameter is
  not a known verb slot.

  A third-party lab with one adds it when it is adopted (PA-0114's from-source
  enumeration).
- `tests/test_forms_phase1.py::test_bwapps_destructive_gets_are_refused` checks every
  bWAPP GET that destroys or rewrites state, from its source.
- Endpoints the URL rule cannot catch are listed with what covers them instead:
  - `restrict_folder_access.php` deletes `documents/.htaccess` on a visit. That is the
    page's own demonstration, and a stated residual;
  - `csrf_1.php`'s password change is covered because credential parameters are never
    fuzzed.

## Recurrence review
- **The prior is BUG-0111 / PA-0112**, the same rule: a destructive list missing
  entries. PA-0112 traced *that* NFR-CRAWL-safe was enforced, not *how completely* for a
  given target.

## Prior-preventive-action failure analysis
PA-0112 is too narrow. Its guard proves that a test exists, but not that the rule
covers the destructive actions of the target being tested.

## Preventive action
**PA-0114** (strengthens PA-0112):
- when a new third-party lab is adopted, its destructive endpoints are enumerated from
  its source and checked against `destructive_reason` with a test, before any crawl;
- endpoints the rule cannot catch are listed with their compensating control, or as a
  stated residual.

**Sweep:** the bWAPP enumeration above (gap map section (b)). The project's own labs
were swept under BUG-0111.
