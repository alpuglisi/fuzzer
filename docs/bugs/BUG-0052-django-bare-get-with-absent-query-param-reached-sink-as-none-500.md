# BUG-0052 — `django` (PicTrail) routes 500'd on a bare GET: the absent query parameter reached the sink as `None`

- Date: 2026-09-25
- Status: fixed (5 routes); no known remaining instance in the `django` emitter
- Severity: medium

## Description

The `django` emitter's `get_param` source rendered
`x = request.GET.get("<param>")` with no default for every route. When the
parameter is absent, `x` is `None`, and every sink that uses it crashed with
an unhandled exception (Django answers HTTP 500, `DEBUG = False`):

- `/post` (PicTrail post detail, `LABGEN-DJ-0007`, vulnerable twin) and the
  illustrative `/api/products` cell (`LABGEN-DJ-0001`, vulnerable twin):
  `"... WHERE id = " + str(id)` became `... WHERE id = None` -- SQLite
  `no such column: None`.
- `/explore` (`LABGEN-DJ-0015`, vulnerable twin): `"... ORDER BY " + str(sort)`
  became `ORDER BY None` -- the same error.
- `/upload/link-preview` (`LABGEN-DJ-0011`, vulnerable twin):
  `requests.get(None)` raised `MissingSchema`; **and its secure twin**
  (`LABGEN-DJ-0012`): `socket.gethostbyname(urlparse(None).hostname)` raised
  too -- both twins 500'd.

The secure twins of `/post`/`/api/products` answered 404 (a bound `NULL`
matches no row) and `/explore`'s secure twin fell back to `id` -- so the
crash was also a twin-distinguishing signal on a bare URL.

## Where encountered

Reproduced live against the pre-change emitter (exported from `HEAD` and
booted with `DjangoLiveBootHarness`, every `django` cell, a bare `GET` of every
served route, 2026-09-25): `LABGEN-DJ-0001`, `-0007`, `-0011`, `-0012`,
`-0015` -> 500; everything else 200/400/404. It was anticipated for `/post`
and `/upload/link-preview` by `docs/LAB_LANE2_DJANGO_PICTRAIL_PLAN.md` §2d
(decided up front, per PA-0053), and confirmed plus extended to `/explore`
and the illustrative `/api/products` by `CC-LAB-0242`'s own PA-0053 bare-GET
sweep (the new `tests/test_labgen_django_navigability_live_boot.py`).

## What it caused to fail

Once PicTrail got a homepage and nav (`CC-LAB-0242`), the nav's "Post" and
"Explore" links and the catalog's links would have led straight to an HTTP
500, failing the Browsable Labs acceptance criterion
(`docs/LAB_BROWSABLE_APPS_PLAN.md` point 6). A 500 from a missing input is
also exactly the noise an error-based detection oracle can mistake for a
SQLi signal on the bare URL.

## What the bug was identified to be

The same defect as BUG-0051, in a different emitter: a missing absent-input
behavior at the **source** module -- no default and no required-parameter
guard, so "parameter absent" was never modelled and `None` flowed into sinks
that are only correct for a present value. `PA-0039`'s `str(...)` cast (from
BUG-0037, in this very emitter) was present on every one of these sinks and
did not help: it turns the `TypeError` into the literal text `None`, which
then fails at the SQL layer instead.

## Root cause analysis

Five Whys:

1. *Why did a bare `GET /post` 500?* The SQL text was `... WHERE id = None`.
2. *Why `None`?* `get_param.py.j2` rendered `request.GET.get("id")` with no
   default, and `str(None)` is `"None"`.
3. *Why no default?* The `django` route profiles (`_ROUTE_PARAMS`) had no way
   to declare one -- the per-profile default mechanism BUG-0051 added exists
   only in the `php_laravel` emitter.
4. *Why was this still present after BUG-0051/PA-0053?* BUG-0051's PA-0002
   sweep deliberately did not crawl other stacks ("none of them has a
   browsable whole-app build yet") and deferred them to each Browsable Labs
   lane's own crawl. So the one standing check PA-0053 names only fires once a
   stack has a homepage and a crawlable whole-app build -- the defect sat
   known-class but unfixed in `django` until this lane built one.
5. *Why is enforcement gated on a crawl?* PA-0053 names the navigability
   crawl as its enforcement, and a crawl can only reach what is linked: a
   route that is not (yet) linked from anywhere is invisible to it, however
   long it has had the defect.

**Root cause:** absent request input is still not a first-class, *declared*
part of a generated route's contract in every emitter; PA-0053's only
mechanical enforcement is a link-reachability crawl, which structurally
cannot cover a route before it is linked, so a known bug class was allowed to
persist in un-crawled emitters.

## Corrective action

`CC-LAB-0242` (FR-LAB-160): the `django` route profile gains two
source-region keys, rendered by `get_param.py.j2` identically on both twins
(each minimal pair still differs only in its transform region):

- `default_value` -- `request.GET.get("<param>") or "<default>"`: `/post` and
  `/api/products` default to `"1"` (the real page's own `?? '1'`, the same
  default Lane 1 gave `/product.php`/`/blog_post.php`); `/explore` defaults to
  `"id"` (the key its secure twin's allowlist already falls back to).
- `required_param` -- a handled JSON 400 before any transform or sink:
  `/upload/link-preview` (its corpus source, `vulnerable-oembed-unfurl-4.py`,
  defines no default URL, and any default would make the vulnerable twin
  fetch it -- R4).

`/settings` and `/inbox` read the POST body and now answer a `GET` with their
form page before the source runs. Verified: every page's own live-boot gate
(bare `GET` status on both twins), the navigability crawl, and its sweep of a
bare `GET` of every served route (all < 500).

## Recurrence review

Checked every `docs/bugs/BUG-*.md` and `docs/PREVENTIVE_ACTIONS.md` for
"absent/missing parameter", "None/null reaches the sink", "500 on a bare
request":

- **Match: `BUG-0051` / `PA-0053`** -- identical bug (absent query parameter
  reaching a sink as the language's null and crashing the page), different
  emitter (`php_laravel` there, `django` here).
- **Match: `BUG-0037` / `PA-0039`** -- the same root cause in this very
  emitter (`sql_string_literal`'s missing POST parameter); `PA-0039`'s cast is
  exactly what turned this instance's `TypeError` into a SQL error instead.
- Related, not the same root cause: `PA-0037` part 2 (a suite of
  single-purpose requests never exercises a real request pattern) and
  `PA-0034` (orthogonal adversarial inputs for new sinks).

## Prior-preventive-action failure analysis

`PA-0053` (from `BUG-0051`, strengthening `PA-0039`) did not prevent this
recurrence. Its *rule* was right and covered this case in words ("in every
emitter and for every route"); it failed on **enforcement scope**:

1. *Enforced only through link reachability.* Its sole mechanical check is
   the navigability crawl, which sees only linked routes. `django` had no
   homepage, so nothing was linked and nothing was checked.
2. *Sweep deferred instead of pinned.* BUG-0051's PA-0002 sweep recorded the
   other emitters as "not crawled here" and handed them to future lanes,
   with no failing/xfail test and no offline check pinning the known
   exposure -- the same "remember to do it later" gap PA-0020/PA-0033 exist
   to close.
3. `PA-0039` (from `BUG-0037`) was followed to the letter here (every sink
   casts with `str(...)`) and still did not prevent the crash, confirming
   BUG-0051's finding that its type-level remedy is the wrong layer.

## Preventive action

**PA-0054** (strengthens `PA-0053`, see `docs/PREVENTIVE_ACTIONS.md`): the
absent-input contract is enforced by the **emitter's own route enumeration**,
not only by link reachability -- (1) each emitter's route profile declares
every named request parameter's absent-input behavior explicitly (a default
or a required-parameter 4xx), checked **offline** over every route the
emitter's manifests produce (here
`tests/test_labgen_django_browsable.py::test_every_get_param_route_declares_its_absent_input_behavior`);
and (2) each live navigability test also sends a bare `GET` to **every route
the build serves**, enumerated from the emitter's own served-URL function
(`served_url_for`), not only the ones a crawl reaches
(`tests/test_labgen_django_navigability_live_boot.py::test_pa_0053_bare_get_sweep_no_route_answers_5xx`).
A PA-0002 sweep that finds the class in an emitter it does not fix must pin it
with a failing-by-design (`xfail(strict=True)`) or offline test, never a prose
deferral.

**PA-0002 sweep (this change):** the `django` emitter in full -- every cell of
every `django` manifest, bare `GET` against every served route live (18 cell
routes + 3 site routes: none >= 500 after the fix), plus the offline
declaration check over every `get_param` route. `post_param` sources
(`/api/login`, `/inbox`) were checked too: `/inbox` now renders its form on
`GET`; the illustrative POST-only `/api/login` answers a clean 404 on a bare
request (its bound/unbound lookup of `'None'` matches no user) -- not a crash,
recorded rather than changed. Remaining stacks (`go_net_http`, `spring_boot`,
`ruby_rails`, `node_express`, `python_fastapi`) are Browsable Labs Lanes 3-6,
each of which must now apply PA-0054's route-enumerated sweep (not only a
crawl) before its pages count as converted; `php_laravel`'s remaining known
instances are already pinned by strict xfails (BUG-0051).
