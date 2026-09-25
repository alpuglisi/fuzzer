# BUG-0051 — `php_laravel` pages linked from the site nav/catalog 500'd (or redirected nowhere) on a bare GET: the absent query parameter reached the sink as `null`

- Date: 2026-09-25
- Status: fixed (4 instances); 1 same-class instance and the illustrative covering-array cells flagged, see Preventive action / sweep
- Severity: medium

## Description

The `php_laravel` emitter's `get_param` source rendered
`$x = $request->query('<param>');` with no default for every page. When the
parameter is absent, `$x` is `null`, and the sink used it as-is:

- `/product.php`, `/blog_post.php` (`sql_numeric_lookup`, vulnerable twin):
  `DB::select("SELECT * FROM products WHERE id = " . $id)` became
  `... WHERE id = ` -- invalid SQL, an uncaught `QueryException`, HTTP 500.
- `/booking/continue` (`http_redirect_return`, vulnerable twin):
  `return redirect(null)` threw, HTTP 500.
- `/comments/share` (`raw_redirect_dispatch`, vulnerable twin):
  `header("Location: " . null)` sent an empty `Location:` -- a dead-end 302
  (its secure twin answered 400).

The real pages these reproduce never had the gap: the pre-cutover
`puppy-fort-factory/blog_post.php`/`product.php` both read
`$id = $_GET['id'] ?? '1';` (`git show 876d2f9^:puppy-fort-factory/blog_post.php`).

## Where encountered

`/product.php`/`/blog_post.php`: flagged (not fixed) by `CC-LAB-0240` as a
pre-existing gap, and tracked as gap 3 of `docs/LAB_LANE1_REMAINING_GAPS_PLAN.md`
(`CC-LAB-0241`) -- the site's own nav (`layouts/site.blade.php`) and home page
link to both URLs with no `?id=`, so a real visitor clicking "Product" or
"Blog" hit the 500. `/booking/continue`/`/comments/share`: surfaced by
`CC-LAB-0241`'s new spider-based navigability test
(`tests/test_labgen_navigability_live_boot.py`), which crawls each app from
`/` and follows `/catalog`'s links to every GET route.

## What it caused to fail

A browsable lab whose nav bar leads to an HTTP 500 (Puppy Fort Factory's
"Product"/"Blog" links; Booking's `/booking/continue` catalog link) or to a
redirect with no target (CircleFeed's `/comments/share`). It also would have
failed the Browsable Labs acceptance criterion (`docs/LAB_BROWSABLE_APPS_PLAN.md`
point 6: every ground-truth URL returns what a real anonymous visitor gets),
and a 500 from missing input is exactly the noise a detection oracle can
mistake for an error-based SQLi signal on the bare URL.

## What the bug was identified to be

A missing default at the **source** module: the generated read of an optional
query parameter carried no fallback, so "parameter absent" was never modelled
and `null` flowed into sinks that are only correct for a present value.

## Root cause analysis

Five Whys:

1. *Why did `GET /product.php` 500?* The SQL text was `... WHERE id = ` with
   nothing after it.
2. *Why was nothing after it?* `$id` was `null`, and PHP's `.` coerces `null`
   to `''` silently -- no error at the concatenation, only at the database.
3. *Why was `$id` null?* `get_param.php.j2` rendered `$request->query('id')`
   with no second argument; the page profile had no way to declare the real
   page's `?? '1'`.
4. *Why was the missing default never noticed?* Every test of these cells --
   offline source assertions and live-boot requests alike -- sent the
   parameter (`?id=1`, a payload). No test ever requested a generated page the
   way its own nav links to it: bare. The migration reproduced the real page's
   *vulnerability* shape faithfully but not its *absent-input* behavior, and no
   check compared the two.
5. *Why did no check exist?* The project's existing rule for this class
   (`PA-0039`) was scoped to a cross-language *port* and to a type-level fix
   (cast to string); PHP needs no cast, so the rule looked satisfied, and it
   named no live check that sends an absent parameter.

**Root cause:** absent request input was never treated as a first-class case
of a generated page's contract -- no mechanism let a page profile declare the
real page's default, and no standing test exercised any generated route
without its parameters, so a `null` reaching a sink was invisible until a
crawl clicked the site's own links.

## Corrective action

`CC-LAB-0241` (FR-LAB-159): a per-profile `default_value` key
(`_DEFAULT_VALUE_KEY` in `fuzzlab/labgen/emitters/php_laravel/__init__.py`),
rendered by `get_param.php.j2` as `$request->query('<param>', '<default>')`,
set on `/product.php`/`/blog_post.php` (`'1'`, the real pages' own default)
and `/booking/continue`/`/comments/share` (`'/'`, the safe target the secure
twins already fall back to). Source region, identical on both twins, so each
minimal pair still differs only in its transform. Every other `get_param`
cell renders byte-identically (asserted in
`tests/test_labgen_php_laravel_lane1_gaps.py`). Bare-URL 200s asserted live in
both `tests/test_labgen_conformance_live_boot.py` (SQLite) and
`tests/test_labgen_conformance_live_boot_mariadb.py` (MariaDB), and by the
navigability crawl.

## Recurrence review

Checked every `docs/bugs/BUG-*.md` title/root cause and `docs/PREVENTIVE_ACTIONS.md`
for "missing/absent parameter", "None/null reaches sink", "500 on a missing
input":

- **Match: `BUG-0037` / `PA-0039`** -- the `django` emitter's
  `sql_string_literal` vulnerable sink crashed (500) on a missing POST
  parameter because `None` was concatenated into SQL text. Same bug (an
  absent request parameter reaching a sink as the language's null and
  crashing the page), different emitter.
- Related, not the same root cause: `PA-0034` (adversarial orthogonal inputs
  for new sinks -- names "an absent auth context", not an absent parameter),
  `PA-0037` part 2 (a suite of individually-correct tests can in aggregate
  never exercise a real request pattern -- here the pattern is "the bare URL
  the nav links to"), `PA-0050` (a probe must target a known-served endpoint).

## Prior-preventive-action failure analysis

`PA-0039` (from `BUG-0037`) did not prevent this recurrence because it was
**too narrow in three ways and not enforced**:

1. *Wrong trigger scope.* It is worded as a rule for "a cross-language module
   port". `php_laravel`'s `get_param` is not a port of anything in that sense,
   so the rule never fired for it -- although `php_laravel` has exactly the same
   exposure.
2. *Wrong layer / type-level fix.* Its remedy is "defensively cast to the
   language's own string type". That fixes Python's `TypeError`, but PHP's `.`
   already coerces `null` to `''` -- the cast is a no-op there, and the page
   still fails at the SQL/redirect layer. The defect is semantic (the page has
   no defined behavior for absent input), not a type error.
3. *Sweep too narrow.* Its PA-0002 sweep covered only
   `fuzzlab/labgen/emitters/django/templates/`, not other emitters.
4. *Not enforced.* It named no standing test that sends an absent parameter,
   so compliance depended on an author remembering to think about it.

## Preventive action

**PA-0053** (strengthens/supersedes `PA-0039`'s scope, see
`docs/PREVENTIVE_ACTIONS.md`): every request parameter a generated page reads
must have a defined absent-input behavior -- the real page's own default (a
per-profile default like `_DEFAULT_VALUE_KEY`), or a handled 4xx before any
sink -- in **every** emitter, not only in a cross-language port; a type cast
alone does not satisfy it. Enforced mechanically, not by memory: the live-boot
navigability crawl (`tests/test_labgen_navigability_live_boot.py`) requests
every link-reachable page bare and asserts the anonymous visitor's status, and
every Browsable Labs lane (2-6) must extend that crawl to its own app before
its pages count as converted.

**PA-0002 sweep (this change):** the crawl itself was the sweep for
`php_laravel` -- all four builds (PFF merged, CircleFeed, Huddle Hub, Booking),
every GET route `/catalog` lists. Results: `/product.php`, `/blog_post.php`,
`/booking/continue`, `/comments/share` fixed here. Not fixed, recorded:
(a) Huddle Hub's `/messages/unfurl` vulnerable twin (`file_get_contents(null)`
-> 500) -- no safe default exists (any URL default would make the vulnerable
twin fetch it), it needs a new missing-required-parameter 400 guard; flagged
as a follow-up and pinned by a strict xfail in the navigability test.
(b) The illustrative covering-array cells `/cell/labgen-pl-0001`, `-0007`,
`-0009`, `-0011`, `-0013`, `-0014` (`/example/product`, `/catalog`,
`/inventory` profiles) also 500 on a bare GET. They carry no ground-truth case
(outside the acceptance criterion), and whether each 500 is only the absent
parameter or also these illustrative identifier/alias shapes' own schema
assumptions under the live-boot harness was not isolated here -- each needs a
per-cell default decision (a sort column, a join alias), not a mechanical
one. Recommended in the same follow-up rather than changed here (their exact
source lines are asserted by `tests/test_labgen_php_laravel.py` and probed by
the identifier-SQLi build-time oracle). Other stacks (`django`,
`go_net_http`, `spring_boot`, `ruby_rails`, `node_express`, `python_fastapi`)
were not crawled here: none of them has a browsable whole-app build yet, and
Browsable Labs Lanes 2-6 each carry this same crawl as their acceptance test
(`docs/LAB_BROWSABLE_APPS_PLAN.md` point 6) -- PA-0053 makes the bare-request
check an explicit part of it.
