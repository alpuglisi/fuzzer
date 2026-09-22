# BUG-0028 — `LiveBootHarness` silently followed real HTTP redirects and its
seeded schema had no columns for Eloquent's default timestamps, both masking
or breaking real responses the auth/G4 live-boot coverage needed to observe

- Date: 2026-09-22
- Status: fixed
- Severity: medium (a conformance harness silently mis-reporting or
  outright breaking a real, observable response it exists to prove)

## Description

Extending `fuzzlab.labgen.conformance.live_boot.LiveBootHarness` coverage to
the auth (`CC-LAB-0056`/`FR-LAB-54`) and G4 real-page manifests surfaced two
independent defects in the harness itself (not in any `php_laravel`-emitted
code), both introduced by `CC-LAB-0054` and both invisible until a real
login/session redirect and a real Eloquent `->save()` were actually
exercised for the first time:

1. **`LiveBootHarness.request()` silently followed HTTP redirects**, even
   for `POST`. `urllib.request`'s default opener auto-follows a `301`/
   `302`/`303` for a `POST` too (converting it to a `GET` on the redirect
   target — `urllib.request.HTTPRedirectHandler.redirect_request`'s own
   documented behavior), so a real login success (`/login.php`'s own `302`
   to `/profile.php`) was silently replaced by whatever the redirect target
   returned — a `404` when that manifest alone has no `/profile.php` route
   registered, which reads as "the request failed" when the opposite was
   true: authentication had actually succeeded.
2. **The harness's seeded SQLite `users` table had no `created_at`/
   `updated_at` columns.** `App\Models\User` (the checked-in skeleton's
   default Eloquent model, which the G4 write endpoint's
   `$storedOwner->save()` uses) has Eloquent's default `$timestamps = true`,
   so every `->save()` unconditionally sets `updated_at` — a real
   `SQLSTATE[HY000]: no such column: updated_at` `QueryException`, a genuine
   `500`, on every G4 write.

## Where encountered

Building `tests/test_labgen_conformance_live_boot.py::
test_live_boot_auth_manifest_sqli_bypasses_login_and_register_inserts_a_row`
(defect 1) and `::test_live_boot_g4_manifest_stored_bio_round_trips_write_then_read`
(defect 2), both new for `CC-LAB-0056`/`FR-LAB-54`. Neither of `CC-LAB-0054`'s
two original tests (`forms`, `numeric`) exercises a page that redirects or an
Eloquent `->save()`, so neither defect could have surfaced there.

## What it caused to fail

- Defect 1: a `POST /login.php` with the seeded identity's own correct
  credentials returned `404` from `LiveBootHarness.post()`, which looks like
  "the page does not exist" or "the login failed" — the opposite of what
  actually happened (a successful login issuing a real `302` to
  `/profile.php`, silently chased to a `GET` on a URL this manifest never
  registers a route for).
- Defect 2: `POST /edit_profile.labgen-plrp-0401.php` (any G4 write) returned
  a real `500` unconditionally, for every payload, vulnerable or secure
  cell alike — never a usable write, let alone a differential.

## What the bug was identified to be

1. `LiveBootHarness.request()` called `urllib.request.urlopen(req, ...)`
   directly, which installs `urllib.request`'s default `OpenerDirector` —
   including `HTTPRedirectHandler`, which follows `301`/`302`/`303` for
   `POST` (not just `GET`/`HEAD`) per its own `redirect_request()` docstring.
   The harness's own `HttpResponse` therefore reported the *final*, chased
   response's status/body, never the real page's own first response.
2. `fuzzlab/labgen/conformance/live_boot.py`'s `_SCHEMA_SQL` (added by
   `CC-LAB-0054`) covered only the columns the two manifests it drove at the
   time actually read/wrote (`username`/`email`/`password`/`full_name`/
   `bio`) — a `DB::table('users')` codepath (`login.php`/`register.php`)
   that never touches timestamps. It did not anticipate a second, Eloquent
   (`App\Models\User`) codepath (`profile.php`/`edit_profile.php`) whose
   default `$timestamps = true` behavior needs those two columns to exist
   whether or not any generated cell ever reads them.

## Root cause analysis

Five whys:

1. **Why did a successful login read as a `404`?** Because
   `LiveBootHarness.request()` returned the response `urlopen()` gave it
   after silently following the real `302` to a route-less URL, not the
   `302` the app actually sent.
2. **Why does `request()` follow redirects at all when its own docstring
   frames every method (`get`/`post`/`fetch`) as "a real HTTP request
   against the booted app"?** Because it used the stdlib's default opener
   with no redirect policy of its own — redirect-following is `urllib`'s
   *default*, not something this harness ever decided it wanted, and no
   test until now sent a request whose real answer is a redirect at all.
3. **Why did the seeded schema omit two columns a default Eloquent model
   needs?** Because `_SCHEMA_SQL` was authored against the two manifests
   `CC-LAB-0054` actually drove, both of which reach `users`/`products`/
   `posts` exclusively through `DB::table(...)` (the query builder), never
   through an Eloquent model instance — so no code path in that session's
   own scope ever exercised a model's default behaviors.
4. **Why wasn't either gap caught by `CC-LAB-0054`'s own tests?** Because
   its own module docstring explicitly named the auth/G2/G4/search
   manifests as **not yet driven** ("need additional seed data ... a future
   change should extend `_SCHEMA_SQL`/`_SEED_SQL` and add their own test
   functions") — i.e. this is exactly the kind of gap that specific,
   explicit scope note flagged as unverified, not a silent omission.
5. **Root cause:** the harness's HTTP client and seeded schema were each
   built to be *sufficient*, not *general* — correct for every behavior the
   two manifests actually exercised, but never checked against the stdlib's
   own documented defaults (redirect-following) or the skeleton's own
   default model behavior (timestamps) for a behavior no existing manifest
   happened to trigger. Both gaps are the same shape: "works for the cases
   in hand," discovered only because this task's job was specifically to
   extend to cases outside that hand.

## Corrective action

`fuzzlab/labgen/conformance/live_boot.py`:

- Added `_NoRedirectHttpErrorProcessor` (an `urllib.request.HTTPErrorProcessor`
  override that hands back every response — `2xx`/`3xx`/`4xx`/`5xx` alike —
  unmodified) and a single shared `_NO_REDIRECT_OPENER` built from it.
  `LiveBootHarness.request()` now opens through that opener instead of the
  bare `urlopen()`, so a `301`/`302`/`303` is reported exactly as the app
  sent it, on every call (`get`/`post`/`fetch` all funnel through
  `request()`) — this can only make a previously-misreported response
  correctly reported; it cannot change any already-passing test's outcome
  since neither `forms` nor `numeric` (`CC-LAB-0054`) exercises a redirect.
- Added `created_at TEXT`/`updated_at TEXT` (nullable) to `_SCHEMA_SQL`'s
  `users` table, with a comment naming exactly which Eloquent default
  behavior needs them and why `DB::table('users')`-only code paths are
  unaffected (they never set those columns, and `NOT NULL` was not added,
  so the pre-existing `register.php` `INSERT` — which never mentions them —
  still succeeds unchanged).
- New regression coverage: `tests/test_labgen_conformance_live_boot.py::
  test_live_boot_auth_manifest_sqli_bypasses_login_and_register_inserts_a_row`
  asserts a real `302` on both a correct-credentials login and a successful
  SQLi bypass (defect 1's direct regression test — it would have silently
  received a `404`/whatever `/profile.php` returns instead, before the fix);
  `::test_live_boot_g4_manifest_stored_bio_round_trips_write_then_read`
  asserts a real `302` from the G4 write endpoint and a real `200` from the
  subsequent read (defect 2's direct regression test — every assertion in
  it would have failed on the pre-fix unconditional `500`).
- Delivered alongside `CC-LAB-0056`/`FR-LAB-54`.

## Recurrence review

Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence
of the same bug, or a different bug with the same root cause, before
deciding the preventive action.

- No prior `BUG-NNNN` touches `fuzzlab.labgen.conformance.live_boot` — this
  is the module's second change (`CC-LAB-0054` introduced it) and its first
  bug report.
- **PA-0025** ("a tool-oracle wrapper... must independently verify... that
  the tool actually reached and exercised the target") is adjacent in
  spirit (both are about a wrapper's status conclusion not matching what
  the underlying real thing actually did) but is scoped to tool-oracle
  *output* classification (`confirmed_secure` from a match-only tool); this
  bug is an HTTP client silently transforming the response itself before
  the caller ever sees a status to classify. Not the same mechanism, and
  PA-0025 does not mention redirects, timestamps, or `live_boot.py`.
- **PA-0005/PA-0008/PA-0009** ("verify a capability is actually usable, not
  assumed") is the closest doctrine in the same module (`live_boot_available()`
  already follows it for composer/php/Packagist) but was never applied to
  the HTTP client's *behavior* once a connection is established, only to
  whether a connection can be established at all — a real gap in how far
  that doctrine had been carried inside this same module.
- No prior occurrence found; this is a new preventive action, not a
  strengthening of an existing one.

## Preventive action

**PA-0030** (new) — recorded in `docs/PREVENTIVE_ACTIONS.md`:

A harness that claims to report "the real app's response" (any wrapper over
a real HTTP client, not just this one) must not silently apply a client
**default** that transforms what the server actually sent before the
caller sees it — redirect-following, retry-on-error, automatic decompression
changing an observable byte count, etc. — unless that transformation is the
literal thing under test. Building such a harness against only the small set
of endpoints in hand at the time is not enough: before extending a harness's
*coverage* (new manifests, new endpoints, new response shapes) to a
previously untested category of real behavior (a redirect, a write through a
different persistence layer/ORM than the ones already exercised, an
authenticated flow), enumerate what that behavior needs from BOTH the client
library's own documented defaults and the framework/ORM's own default
behaviors (timestamps, casts, soft deletes, etc.) that no existing case
happened to trigger — the same "enumerate every precondition, not only the
one that motivated the change" discipline PA-0026 already requires of
allowlist adapters, applied here to a live HTTP+ORM conformance harness
being widened to a genuinely new category of endpoint rather than to a
third-party function's parameters. The PA-0002 sweep for this class checked
every existing call site of `LiveBootHarness.request()`/`.get()`/`.post()`/
`.fetch()` (the two `CC-LAB-0054` tests and this change's three new ones,
all in `tests/test_labgen_conformance_live_boot.py`, and
`fuzzlab.labgen.conformance.tier1.Tier1Case`'s use of `.fetch()` as a
`Tier1Client`, which carries no manifest-specific redirect/ORM assumption of
its own): all of them funnel through the one fixed `request()` method, so
all inherit both fixes automatically with no call-site change needed.
