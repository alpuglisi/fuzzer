# BUG-0054 — `spring_boot` POST routes crashed on a bare `POST`: PA-0054's `GET`-only sweep never exercised them

- Date: 2026-09-25
- Status: fixed (2 confirmed crashes; declared absent-input behavior added to all 16 routes)
- Severity: medium

## Description

Two `spring_boot` POST routes crashed on a bare request (no body, no query,
no multipart part) before this change:

- `/api/profiles/avatar` (`LABGEN-JV-0011`/`0012`, ReelQueue): a bare `POST`
  answered 500 on **both** twins. The source read the required multipart
  `file` part directly off the raw request (`request.getPart("file")`) with
  no null guard; a bare `POST` has no such part, and `getPart` throws
  `ServletException` before the null check that would have run afterward.
- `/api/content/thumbnail-import` (`LABGEN-JV-0017`/`0018`, ReelQueue): a
  bare `POST` answered 502 on the vulnerable twin. The query-carried
  `thumbnail_url` parameter had no required-parameter guard, so the SSRF
  sink attempted to fetch a `null`/empty URL and the resulting
  `IllegalArgumentException`/connection failure surfaced as an upstream
  error.

Beyond outright crashes, several other routes reached their sink with
undeclared, silently-tolerated empty input: a malformed
`{"monthly_charge":}` JSON output from `/api/subscription/change-plan`, the
secure billing twin's `""==""` information disclosure, and incidental
OGNL/SpEL 400s that happened to look like a "clean" rejection but were not
actually a *declared* behavior anywhere in the route profile.

## Where encountered

Reproduced live in Phase 1 of `docs/LAB_LANE4_SPRING_BOOT_PLAN.md` (§5 step
2): every real `spring_boot` cell booted as one vulnerable app and one
secure app (their 16 routes are pairwise distinct within each group, so
booting them together does not hit the same-route twin collision, S1), then
a bare request with each route's own method sent to every route. Confirmed
again by `tests/test_labgen_spring_boot_absent_input_live_boot.py`
(written failing-first, commit `0a30407`, before the fix in commit
`19e1328`): it failed on both twin groups (avatar bare `POST` 500 on both
twins, thumbnail-import 502 on the vulnerable twin, and every undeclared
absent-input status), while the pre-existing `GET`-only sweep passed
against the identical, unfixed build.

## What it caused to fail

Once ReelQueue got a homepage, nav, and a client page per API
(`CC-LAB-0244`), the avatar-upload and thumbnail-import client pages'
"Send" buttons — or any anonymous visitor probing those two URLs directly —
would trigger a raw 500/502 instead of a clean, declared rejection, failing
the Browsable Labs acceptance criterion
(`docs/LAB_BROWSABLE_APPS_PLAN.md` point 6). A 500/502 from missing input is
also exactly the noise an error-based detection oracle can mistake for a
real SSRF/upload-vulnerability signal on a bare URL.

## What the bug was identified to be

The same defect class as `BUG-0051`/`BUG-0052`, in a third emitter: a
missing absent-input behavior at the source module — no default and no
required-input guard, so "the input is absent" was never modelled and the
sink (or, for the multipart case, the servlet API itself) ran anyway. This
instance additionally involves two *input channels* — a required multipart
part and a required query parameter on a POST — that `PA-0053`/`PA-0054`'s
prior wording ("named request parameter") did not clearly name at all.

## Root cause analysis

Five Whys:

1. *Why did a bare `POST /api/profiles/avatar` 500?* `request.getPart("file")`
   threw `ServletException: the request was rejected because no multipart
   boundary was found` (or similar) before any null check ran.
2. *Why was there no null check before `getPart`?* The `spring_boot` route
   profile (`_PAGE_PARAMS`) had no declared absent-input behavior for this
   route at all — its entry was the empty dict `{}` — so the source template
   had nothing to guard against.
3. *Why did the emitter allow an undeclared route to exist?* Nothing in the
   emitter enforced that every route profile declare an absent-input
   behavior; declaration was opt-in, added ad hoc as each cell was built.
4. *Why didn't `PA-0053`/`PA-0054`'s existing mechanical checks catch this
   before Lane 4 built ReelQueue's whole-app build?* `PA-0054`'s live
   enforcement is a bare **`GET`** sweep of every served route. Spring Boot
   answers a `POST`-only `@PostMapping` route's bare `GET` with its own
   framework-level `405 Method Not Allowed`, returned by the dispatcher
   before the handler method — and therefore the source/sink code — ever
   runs. The sweep passed cleanly on the unfixed build precisely because it
   never reached the code path that crashes.
5. *Why did `PA-0054` specify `GET`?* It generalized `PA-0053`'s original
   bare-`GET` sweep (written for `php_laravel`/`django`, both effectively
   GET-routed stacks for every point that mattered there) to "a bare request
   to every route the build serves" without stating the request must use
   **that route's own declared HTTP method** — an implicit assumption that
   happened to hold for the first two emitters it was applied to, but not
   for `spring_boot`, whose 16 real routes are overwhelmingly `POST`
   (13 of 16).

**Root cause:** `PA-0054`'s absent-input sweep contract under-specified the
request method, implicitly assuming "bare request" means "bare `GET`" — true
only for a GET-dominant stack. A framework's own method-routing layer can
silently absorb a `GET` probe against a POST-only route with a `405` before
ever exercising the handler, so a `GET`-only sweep is structurally blind to
this entire crash class on a POST-heavy stack, however long the defect has
been present.

## Corrective action

`CC-LAB-0244` (FR-LAB-165): every `spring_boot` route profile now declares
exactly one of seven `ABSENT_INPUT_KINDS` values —
`default_value`/`required_param`/`required_header`/`required_multipart`/
`empty_body_400`/`no_input`/`form_when_absent` — covering every input
channel a route can read (query, header, multipart part, whole body), not
only a named query parameter. Each is rendered in the source region,
identically on both twins, before any sink runs:

- `/api/profiles/avatar` → `required_multipart`: the multipart part is
  checked for presence before `getPart` is trusted to return a real file,
  answering a handled 400 when absent.
- `/api/content/thumbnail-import` → `required_param`: the query-carried
  `thumbnail_url` is checked before the SSRF sink runs.
- Every other route received its own correct declaration (see
  `docs/LAB_LANE4_SPRING_BOOT_PLAN.md` §2e's table), closing the
  undeclared-empty-input gap on the other routes named above.

Also added: `tests/test_labgen_spring_boot_absent_input_live_boot.py`, an
**own-method** bare-request sweep — a bare request using each route's own
declared method (`GET` for `GET` routes, an empty-body `POST` for `POST`
routes), asserting the **declared** absent-input status on both twins (not
merely `< 500`), plus a bare `GET` of every route asserting `< 500`
independently. Verified: this sweep failed on the pre-fix build (2/5 shown
crashing/undeclared in the reproduction sample; all 16 routes had at least
one undeclared or crashing case) and passes in full after the fix (16/16
routes, both twins).

## Recurrence review

Checked every `docs/bugs/BUG-*.md` and `docs/PREVENTIVE_ACTIONS.md` for
"absent/missing parameter", "None/null reaches the sink", "500 on a bare
request":

- **Match: `BUG-0051`/`PA-0053`** and **`BUG-0052`/`PA-0054`** — the same
  underlying defect (absent request input reaching a sink unguarded and
  crashing), in `php_laravel` and `django` respectively; `spring_boot` is the
  third emitter with an independent instance of the same class.
- No other bug in `docs/bugs/` shares this root cause.

## Prior-preventive-action failure analysis

`PA-0054` (from `BUG-0052`, itself strengthening `PA-0053`/`BUG-0051`) did
not prevent this recurrence. Its rule was right in spirit (declare
absent-input behavior for every route, enforce beyond link reachability) and
even anticipated this exact bug class in general terms, but it failed on
**enforcement precision**, in three specific ways this bug exposes:

1. **A `GET`-only sweep.** `PA-0054` part (2) named a bare "request" but its
   only implementation (`django`'s own sweep) sent a bare `GET` to every
   route. On a POST-dominant stack, the framework's own method routing masks
   the very code path the sweep exists to exercise, so the check passes
   while the underlying defect remains completely unexercised — worse than
   not checking at all, since a passing suite gave false confidence.
2. **"Named request parameter" wording too narrow.** `PA-0054` part (1)'s
   phrasing ("declare each named request parameter's absent-input
   behavior") does not clearly cover a required multipart part or a
   required whole body, both real input channels this bug's two crashes
   came from.
3. **`BUG-0052`'s own sweep note deferred `spring_boot` by name** ("Remaining
   stacks... are Browsable Labs Lanes 3-6, each of which must now apply
   PA-0054's route-enumerated sweep") without itself pinning the known
   exposure with a failing/`xfail(strict=True)` test in the meantime — the
   same "remember to do it later" gap `PA-0002`/`PA-0020`/`PA-0033` exist to
   close, recurring a third time in this specific spot.

## Preventive action

**PA-0056** (strengthens `PA-0054`, see `docs/PREVENTIVE_ACTIONS.md`, fixing
all three failure modes above):

1. The per-route bare-request sweep must send the request using **that
   route's own declared HTTP method** (a bare `POST` with an empty body for
   a `POST` route), not only a bare `GET` — a `GET`-only sweep is necessary
   but never sufficient once any route in the build is not `GET`.
2. "Absent-input behavior" must be declared and enforced for **every input
   channel** a route can read — query parameter, header, multipart part, or
   whole body — not only a named query parameter.
3. A `PA-0002` sweep that names another emitter as still owing this class
   (rather than fixing it directly) must pin every named, un-fixed instance
   with a failing-by-design offline check (an `xfail(strict=True)` live test
   or an offline declaration-coverage test) in the same change that defers
   it — a prose "Lane N must do this later" sentence with no enforcement is
   not a preventive action.

**PA-0002 sweep (this change):** `spring_boot` fixed in full (16/16 routes
declared and passing the own-method sweep on both twins). A new offline
cross-emitter module,
`tests/test_absent_input_declarations_cross_emitter.py`, pins the other five
emitters that still lack a declaration mechanism
(`go_net_http`/`ruby_rails`/`node_express`/`python_fastapi`/`php_current`)
with `xfail(strict=True)`, each naming its owning Browsable Labs lane (or
"no lane assigned" for `php_current`), and checks `php_laravel`'s existing
declaration coverage directly rather than assuming it — satisfying this
preventive action's rule 3 for the emitters this lane does not itself fix.
