# BUG-0055 — `ruby_rails` (ForgeCart) served Rails' development-mode exception pages: any anonymous error response printed the generated controller source and revealed which twin is vulnerable

- Date: 2026-09-25
- Status: fixed in `ruby_rails`. One same-class instance in another lane's
  emitter is pinned and flagged (see Preventive action / sweep).
- Severity: high. The lab's ground truth was readable by an anonymous
  request, which contaminates every measurement of a scanner run against
  this target.

## Description

`RailsLiveBootHarness` boots the assembled app with `RAILS_ENV=development`
(`fuzzlab/labgen/conformance/rails_live_boot.py:276`). The skeleton's
`config/environments/development.rb` kept the defaults `rails new` writes:

- `config.consider_all_requests_local = true`. Every 4xx/5xx an anonymous
  client triggered was Rails' interactive **detailed exception page**. Its
  "Extracted source" section prints the generated controller around the
  raising line.
  - A bare `POST /admin/customers/update` (the vulnerable
    `LABGEN-RR-RP-0004`) returned a roughly 121 KB 400 page showing
    `# permit_bang_unrestricted: every key in attrs is accepted…`.
  - A bare `PATCH /cell/labgen_rr_0005` (the secure twin, `LABGEN-RR-0005`)
    showed `# strong_params_explicit_allowlist: …`.
  - **The transform, and so the cell's verdict, was readable by anyone.**
  - The development 404 page also listed the entire route table, controller
    names included.
- `config.action_view.annotate_rendered_view_with_filenames = true`. Every
  rendered page carried `<!-- BEGIN app/views/cell_labgen_rr_rp_0001/show.html.erb -->`,
  which is each cell's view path and therefore its cell ID.

## Where encountered

Found during `CC-LAB-0245`'s Phase 1 research (Browsable Labs Lane 5,
`docs/LAB_LANE5_RUBY_RAILS_FORGECART_PLAN.md` §2a, R1/R2), by a live boot of
the pre-change whole ForgeCart build (12 cells) and a bare request to every
route. Both twins' debug pages were independently reproduced live by the
plan's round-1 accuracy reviewer. After the fix, the regression checks were
re-run with the pre-fix setting temporarily restored, and they fail as
intended:

- `tests/test_labgen_ruby_rails_navigability_live_boot.py::test_bug_0055_no_debug_page_content_and_no_view_annotations`:
  the 404 page for `/cell/labgen_rr_0002` carried `Routing Error`,
  `Full Trace`, `Application Trace` and `labgen`;
- `tests/test_labgen_ruby_rails_browsable.py` O6;
- `tests/test_labgen_debug_pages_disabled.py::test_ruby_rails_booted_environment_has_debug_pages_off`.

## What it caused to fail

- **Fingerprint and leakage independence.** The design contract (point 2)
  and the lab's twin model require that nothing served lets a visitor tell a
  vulnerable twin from its secure twin. Any request that produced an error
  exposed the twin's transform directly.
- **The Browsable Labs acceptance criterion.** Point 6 requires "the
  response a real anonymous visitor would get". This lane's declared
  absent-input 4xx responses (PA-0054) would have been served as
  source-revealing debug dumps.
- **Measurement integrity.** Every `run_targets`/multitarget run against
  ForgeCart (`tests/test_multitarget_ruby_rails_forgecart.py`,
  `test_multitarget_category1_combined.py`) exposed generated source to the
  tool being measured.

## What the bug was identified to be

A missing stack-level configuration requirement in the `ruby_rails` port.
Its served build never disabled the framework's debug and exception-detail
output, which every other served stack in this project does:

| Stack | Setting |
|---|---|
| `php_laravel` | `APP_DEBUG=false`, in `stack_env.py:83` and the harness's own `.env` |
| `django` | `DEBUG = False` (`CC-LAB-0090`, `stack_env.py:151`) |
| `node_express` | `ENV NODE_ENV=production` in its Dockerfile |
| `python_fastapi` | schema/docs routes off (`main.py.j2:34`) |

## Root cause analysis

Five Whys:

1. *Why could an anonymous request tell the twins apart?* The 400/404
   responses were Rails' detailed exception pages, which print generated
   source and the route table.
2. *Why detailed pages?* The harness boots `development`, and the
   skeleton's `development.rb` had `consider_all_requests_local = true`,
   Rails' development default.
3. *Why was a development default left on in a served lab?* The harness
   chose `development` for an unrelated reason (the skeleton carries no
   `master.key`/credentials, and production's secret handling is stricter;
   `rails_live_boot.py:263-278`). Nobody re-checked what else that
   environment turns on.
4. *Why was that not caught when the stack was ported?* The "debug pages
   off in every served build" requirement existed only as prose
   (`docs/LAB_IMPLEMENTATION_PLAN.md:775`: "production-equivalent mode by
   default as a blanket rule") and as per-stack, author-remembered
   implementations, each with its own local test (for example
   `tests/test_labgen_node_express_stack_env.py:54`). Nothing checked it
   across stacks, so a new stack started from nothing.
5. *Why did no live test notice?* Every Rails live-boot test asserted the
   status or body of a success path. The lane-level bare-request sweeps
   (PA-0053/PA-0054) assert only the status of error responses (`< 500`),
   never their content. A debug page and a static error page with the same
   status are indistinguishable to them.

**Root cause:** a cross-stack security requirement (framework debug output
disabled in every served build) was enforced only by each stack's author
remembering to implement it, with no cross-stack mechanical check. Every
live check looked at status codes, never at error-response content. So a
stack port whose harness picked a development-mode runtime for an unrelated
reason silently shipped the framework's source-revealing debug pages.

## Corrective action

`CC-LAB-0245` (FR-LAB-166), commit `8670847`:

- `ruby_rails` skeleton `config/environments/development.rb`:
  `consider_all_requests_local = false` and
  `annotate_rendered_view_with_filenames = false`. Errors now render the
  checked-in static `public/400.html`, `404.html` and so on. Verified live:
  byte-equal static pages, and no `Extracted source`, trace, `permit`,
  `YAML.` or `labgen` in any error body across a sweep of every served
  route.
- The harness keeps `RAILS_ENV=development`. The plan's R2 decision rule
  rejected switching to `production` in this lane, because `force_ssl`,
  eager loading and assets form a separate, unverified surface; that is left
  to Lane 7's serving decision, which `PA-0057`'s check keeps honest.
- Standing tests:
  - `tests/test_labgen_debug_pages_disabled.py`: cross-emitter, one check
    per stack;
  - O6 and O7 in `tests/test_labgen_ruby_rails_browsable.py`. O7 is a
    standing check that no test or detection code comes to depend on Rails
    debug-page content, and it has its own adversarial self-test;
  - the live `BUG-0055` checks in
    `tests/test_labgen_ruby_rails_navigability_live_boot.py`.

## Recurrence review

I checked every `docs/bugs/BUG-*.md` and `docs/PREVENTIVE_ACTIONS.md` for
"debug page", "DEBUG", "stack trace", "exception page", "information
disclosure", "fingerprint" and "stack port".

- **No prior bug has this root cause.** The debug-page requirement was met
  at design time for every earlier stack (`CC-LAB-0090`'s `DEBUG = False`;
  `php_laravel`'s `APP_DEBUG=false`), so it never produced a bug report.
  `BUG-0037` mentions `DEBUG = False` only as working correctly.
- **Closest prior rule: `BUG-0037`/`PA-0039`.** PA-0039 says a cross-language
  port must re-verify every language-specific runtime assumption the source
  shape relied on. It is the same failure family: a port silently loses a
  property its predecessors had.
- **Rails-port siblings: `BUG-0034`/`PA-0036` and `BUG-0035`/`PA-0037`.**
  These are two earlier defects where the `ruby_rails` port broke a
  stack-level convention the harness's single-request tests never exercised.
  They have different root causes (inflector round trip; an unpinned
  transitive gem), but show the same pattern: stack-level skeleton and
  harness properties of this port were checked less than its modules.
- **`BUG-0051`/`PA-0053` and `BUG-0052`/`PA-0054` (absent input) were
  reviewed as the dispatch required.**
  - They are not the same root cause.
  - But the enforcement gap overlaps: PA-0054's live sweep asserts only
    `< 500`, so it could not see this defect. It also could not see this
    lane's absent-`yaml_payload` path, which reached `YAML.*_load` as `nil`
    and was hidden by the sink's catch-all `rescue` as a 200.
  - That path was fixed in `CC-LAB-0245` as a declared PA-0054 conformance
    change (a handled 400 via `params.require`). It is **not** a bug under
    the plan's §2d rule, because it was twin-identical, under 500, and never
    sent by a detection probe.
  - **The sweep found no absent-input crash in `ruby_rails`**: every served
    route's bare request answered its declared status (200/400/401/404) both
    before and after, except that `yaml_payload`'s behavior moved from a
    rescued 200 to the declared 400.

## Prior-preventive-action failure analysis

- **`PA-0039` (from `BUG-0037`) did not prevent this.**
  - *Too narrow:* it is scoped to porting a source/transform/sink/complexity
    **module** across languages, not a stack's skeleton or harness runtime
    configuration.
  - *Not enforced:* it is advisory, with no mechanical check, so the Rails
    port's development-mode harness never met it.
- **`PA-0053` and `PA-0054` (from `BUG-0051`/`BUG-0052`) could not have caught
  it, because they are enforced at the wrong layer for this failure mode.**
  Their live halves assert error-response **status** (`< 500`), not
  **content** and not the declared status. A detailed exception page with
  status 400 passes a "< 500" sweep exactly as a static 400 does. So does a
  rescued 200 that hid an absent input from its sink.
- **The prose requirement (`docs/LAB_IMPLEMENTATION_PLAN.md:775`) was never a
  PA.** No preventive-action mechanism, and so no PA-0002 sweep, ever
  covered stacks added later. This is the PA-0020/PA-0033 lesson (a rule
  addressed to memory is not prevention) applied to a design-time
  requirement.

## Preventive action

**PA-0057** (strengthens `PA-0039`'s scope and `PA-0054`'s live half; see
`docs/PREVENTIVE_ACTIONS.md`):

1. Every stack's served build, meaning the real deployment path **and**
   every test-time live-boot launch, must run with its framework's debug,
   exception-detail and source-annotating output disabled. This is enforced
   mechanically by `tests/test_labgen_debug_pages_disabled.py`: one check per
   stack, reading the governing setting at the place the running app takes
   it from. A new stack, harness or launch site extends it in the same
   change.
2. Every live navigability or bare-request sweep asserts each response's
   **declared** status, not a range, and asserts that error-response
   **content** carries no debug or generated-source markers.

**PA-0002 sweep (this change): every emitter's debug posture**, read at the
place each running app takes it from:

- `ruby_rails`: fixed here.
- `php_laravel`: `APP_DEBUG=false` in both the deployment `.env` and the
  harness `.env`. Clean.
- `django`: `DEBUG = False`. Clean.
- `python_fastapi`: no `debug=True`, docs routes off. Clean.
- `spring_boot`: no devtools or actuator, no stack-trace properties. Clean.
- `go_net_http`: no `net/http/pprof`. Clean.
- `php_current`: served by no harness or deployment. Nothing to check.
- **`node_express`: the deployment Dockerfile sets `NODE_ENV=production`,
  but the three test-time `node app.js` launches do not**
  (`tests/test_labgen_node_bff_app.py`,
  `tests/test_labgen_node_bff_multitarget.py`,
  `tests/test_multitarget_category1_combined.py`, all
  `env={**os.environ, "PORT": ...}`). Express's default error handler then
  writes `err.stack` into error responses. This was found by reading and is
  not live-verified here.
  - `node_express` is Browsable Labs Lane 6's emitter, being changed
    concurrently, so it is **pinned** by the strict xfail
    `test_every_test_time_node_launch_sets_production` (PA-0054(3)) and
    **flagged** to the orchestrator, not fixed in this lane.
