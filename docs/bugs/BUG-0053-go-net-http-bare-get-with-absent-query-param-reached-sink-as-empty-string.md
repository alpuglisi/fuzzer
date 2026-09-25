# BUG-0053 — `go_net_http` (LoopCast) routes 502/500'd on a bare GET: the absent query parameter reached the sink as an empty string

- Date: 2026-09-25
- Status: fixed (3 routes); no known remaining instance in the `go_net_http` emitter
- Severity: medium

## Description

The `go_net_http` emitter's `read_url_query_param` source rendered
`x := r.URL.Query().Get("<param>")` with no default and no required-parameter
guard for every route. When the parameter is absent, `x` is `""`, and every
sink that uses it crashed or behaved unsafely with an empty value:

- `/api/clips/thumbnail` (`LABGEN-GO-0003`, vulnerable twin) and
  `/clips/download` (`LABGEN-GO-0015`, vulnerable twin): `client.Get("")`
  fails to connect (an empty URL has no scheme/host) -- the Go HTTP client
  returns an error, which the handler maps to `502`.
- `/clips/export` (`LABGEN-GO-0021`/`LABGEN-GO-0022`, both twins): opening a
  file whose name is the empty string fails -- `500`, on both twins, since
  the export sink was not yet twin-differentiated at the absent-input level.

## Where encountered

Reproduced live against the pre-change emitter (exported from `HEAD` and
booted with `GoLiveBootHarness`, with the export directory absent, a bare
`GET` of each route, 2026-09-25): `LABGEN-GO-0003` and `LABGEN-GO-0015` ->
502; `LABGEN-GO-0021`/`LABGEN-GO-0022` -> 500 (Gate 0's observation, taken
before any fix and before the export directory was seeded, per
`docs/LAB_LANE3_GO_NET_HTTP_TWITCH_PLAN.md`'s own R9). Anticipated by that
plan's §2d absent-input table (decided up front, per PA-0054) and confirmed
live after the fix: all three routes (both twins where applicable) now
answer `400` on a bare request (see Corrective action).

## What it caused to fail

Once LoopCast got a homepage and nav (`CC-LAB-0243`), the nav's "Export
clips"/"Download a clip" links and the catalog's own links to the thumbnail
proxy would have led straight to a `5xx`, failing the Browsable Labs
acceptance criterion (`docs/LAB_BROWSABLE_APPS_PLAN.md` point 6). A `5xx`
from a missing input is also exactly the noise an error-based detection
oracle can mistake for an SSRF/path-traversal signal on the bare URL.

## What the defect was identified to be

The same defect as BUG-0051/BUG-0052, in a third emitter: a missing
absent-input behavior at the **source** module -- no default and no
required-parameter guard, so "parameter absent" was never modelled and `""`
flowed into sinks that are only correct for a present value.

## Root cause analysis

Five Whys:

1. *Why did a bare `GET /api/clips/thumbnail` 502?* `client.Get("")` failed
   to connect.
2. *Why an empty URL?* `read_url_query_param.go.j2` rendered
   `r.URL.Query().Get("url")` with no default, and an absent query parameter
   is `""` in Go, not `nil` -- there was nothing to guard against.
3. *Why no default/guard?* The `go_net_http` route profile (`_ROUTE_PARAMS`)
   had no way to declare one -- the same gap BUG-0051 found in `php_laravel`
   and BUG-0052 found in `django`, in this stack's own emitter.
4. *Why was this still present after BUG-0051/BUG-0052/PA-0054?* PA-0054
   (from BUG-0052) explicitly named `go_net_http` as one of the remaining
   stacks that "must now apply PA-0054's route-enumerated sweep... before
   its pages count as converted" -- i.e. PA-0054 anticipated this exact
   discovery and assigned it to this lane's own Browsable Labs conversion,
   rather than claiming to have already fixed it. This bug is that
   anticipated sweep finding it, not a new failure of enforcement.
5. *Why is the sweep lane-gated rather than immediate?* A route-enumerated
   offline/live sweep needs the emitter's own `served_url_for`-equivalent
   and route-profile machinery to exist first (PA-0054's own mechanism);
   `go_net_http` had neither before this lane, so the earliest the sweep
   could run here is exactly now.

**Root cause:** the same absent-input-declaration gap as BUG-0051/BUG-0052,
present in a third emitter that PA-0054 had already identified as needing
its own sweep -- found and fixed by that lane's mandated application of
PA-0054, not by a lapse in PA-0054 itself.

## Corrective action

`CC-LAB-0243` (FR-LAB-162): the `go_net_http` route profile gains a
`required_400` `absent_input` declaration for `/api/clips/thumbnail`,
`/clips/download` and `/clips/export` -- rendered identically on both twins
in `read_url_query_param.go.j2`'s source region, before any sink runs.
Verified live (both twins where applicable): a bare request to all three
routes now answers `400`, not `500`/`502`.

## Recurrence review

Checked every `docs/bugs/BUG-*.md` and `docs/PREVENTIVE_ACTIONS.md` for
"absent/missing parameter", "None/null/empty reaches the sink", "5xx on a
bare request":

- **Match: `BUG-0051` / `PA-0053`** -- identical bug class (absent query
  parameter reaching a sink as the language's zero-value and crashing or
  misbehaving), different emitter (`php_laravel` there, `go_net_http` here).
- **Match: `BUG-0052` / `PA-0054`** -- the same bug class, a second
  recurrence (`django`), which is exactly what produced `PA-0054`'s
  strengthened, route-enumerated enforcement.
- No other distinct root cause found.

## Prior-preventive-action failure analysis

Unlike `BUG-0052`'s relationship to `PA-0053`, this is **not** a case of
`PA-0054` failing to prevent a recurrence it should have caught. `PA-0054`'s
own text (added by `BUG-0052`) explicitly named `go_net_http` as one of
"Remaining stacks... [that] must now apply PA-0054's route-enumerated sweep
(not only a crawl) before its pages count as converted" -- i.e. it already
scoped this exact discovery to this lane's own work, rather than asserting
the class was already closed everywhere. `PA-0054`'s two mechanical
enforcement points (an offline per-route declaration check, and a live bare-
request sweep of every served route) are precisely the mechanism this lane
used to find and fix all three instances here, on the first attempt, with no
un-pinned residue. `PA-0054` therefore worked exactly as designed; no failure
mode to correct.

## Preventive action

**PA-0055** (completes `PA-0054`'s named sweep for `go_net_http`, Lane 3; no
new rule -- `PA-0054`'s existing rule already covers this class and enforcement
mechanism in full): the `go_net_http` emitter's absent-input contract is now
declared and enforced exactly as `PA-0054` requires --

1. every named request parameter's absent-input behavior is declared in the
   route profile (`_ROUTE_PARAMS`'s `absent_input` key, one of
   `ABSENT_INPUT_KINDS`), checked **offline** over every route the emitter's
   manifests produce
   (`tests/test_labgen_go_net_http_browsable.py::test_every_route_declares_its_absent_input_behavior`);
2. the live navigability test sends a bare request to **every route the
   build serves**, enumerated from `served_url_for`, not only the ones a
   crawl reaches
   (`tests/test_labgen_go_net_http_navigability_live_boot.py::test_pa_0053_bare_request_sweep_no_route_answers_5xx`).

**PA-0002 sweep (this change):** the `go_net_http` emitter in full -- every
cell of every `go_net_http` manifest, bare request against every served
route live (28 cell routes + 1 site route: none >= 500 after the fix). The
remaining Browsable Labs lanes (`spring_boot`, `ruby_rails`, `node_express`,
`python_fastapi`) are Lanes 4-6, each of which must apply `PA-0054`'s
route-enumerated sweep before its pages count as converted, per `PA-0054`'s
own text -- unchanged by this entry.
