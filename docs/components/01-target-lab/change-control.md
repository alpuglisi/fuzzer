# Target Lab and Ground Truth — Change Control Log

Component code: **LAB**. Entry format and required fields: see
`../README.md`. Newest first.

### CC-LAB-0055 — `minimal_pair.py`: `pair_by` (path-independent pairing) + a real content-confinement defect fix (FR-LAB-53) (2026-09-22)
- Change: two independent fixes to `fuzzlab/labgen/minimal_pair.py`, both closing gaps
  lane L-P3.3c-G3 found and worked around rather than fixed (`CC-LAB-0048`; see also
  `docs/bugs/BUG-0027-*.md`'s full RCA for the second):
  1. **`pair_by` (enhancement, not a defect fix — the checker already did what its own
     docstring said).** `check_minimal_pair(vulnerable, secure, *, pair_by=None)`: an
     optional `EmittedFile -> Hashable` key function. `None` (the default) keeps the
     original, literal-path pairing unchanged for every existing caller
     (`fuzzlab/labgen/cli.py`, every `tests/test_labgen_*.py` lane test). When given,
     files on each side are grouped by `pair_by(file)` instead of by path, so two
     independently-authored cells that render to two different paths (G3's
     `login.php`/its `.php`-suffixed secure-twin URL) can be compared directly, without
     needing "each cell against its own weakened self" as G3's own test had to. An
     ambiguous mapping (two files on one side sharing a key) raises `MinimalPairError`
     (a setup problem), never silently picks one.
  2. **Content-confinement defect fix (`BUG-0027`, full bug protocol).** The
     "differ outside any declared transform/sink change" band check only ran when the
     two variants' composition sequences were name-identical; whenever any position
     legitimately differed by name (`any_declared_difference = True` — true for
     essentially every real vulnerable/secure pair, since their transform names differ),
     the check was skipped entirely for the whole file, not narrowed. Fixed by deriving,
     from *each side's own* composition metadata independently (never from
     name-matching between the two sides), a structural lower bound on where the
     transform/sink region can begin: a `transform` module's own self-identifying
     comment line (`// {name} transform: ...`, a convention every template in
     `fuzzlab.labgen.modules.transforms` follows). Content found to differ before that
     line is now a `MinimalPairViolation` regardless of whether composition names
     match. `check_identifier_stability()` now runs before this new check, so a
     handler/function-name rename still surfaces as the specific existing
     "function/handler identifier" violation rather than the new generic one. The
     symmetric trailing-region gap (a rewrite inside a sink's own rendered SQL/HTML) is
     **not** closed — no sink template self-identifies the way transform templates do,
     and closing it would need re-rendering a module standalone, which this checker's
     docstring already refuses to do; recorded as a residual gap, not silently assumed
     solved (`docs/bugs/BUG-0027-*.md`'s corrective-action section).
- Impact (other components / project): none outside LAB. `fuzzlab/labgen/cli.py` and
  `fuzzlab/labgen/conformance/tier0.py` (concurrently-owned; not modified by this
  change) call `check_minimal_pair`/`get_minimal_pair_checker` without `pair_by`, so
  both inherit the confinement-check fix automatically with no call-site change, and
  neither loses any existing behavior.
- Risk (level; mitigation or accepted-risk justification): **low** for `pair_by` (purely
  additive, opt-in, default preserves exact prior behavior — regression-tested by
  `test_default_pairing_still_rejects_two_differently_pathed_cells`). **Low-medium** for
  the confinement fix: it can only make the checker *stricter* (catch a real class of
  violation it previously missed), never more permissive, so the risk is a false
  positive on an emitter that does not follow the `// {name} transform:` convention --
  mitigated by degrading to the pre-fix (no additional check) behavior whenever the
  marker cannot be found on either side, rather than raising on an unrecognized
  convention.
- Deliverables:
  - [x] `check_minimal_pair(..., pair_by=None)` + `_first_variable_marker_line()` — done
  - [x] `tests/test_labgen_minimal_pair.py`: 7 new tests (`test_default_pairing_
        still_rejects_two_differently_pathed_cells`, `test_pair_by_lets_two_
        differently_pathed_cells_be_compared`, `test_pair_by_still_reports_a_real_
        violation`, `test_pair_by_ambiguous_mapping_raises_setup_error`,
        `test_a_real_transform_rename_alone_still_passes`, `test_unrelated_rewrite_
        before_the_transform_region_now_caught`, `test_content_confinement_runs_even_
        when_variable_categories_is_narrowed`) — done
  - [x] Bookkeeping: this entry, `FR-LAB-53`, `CHANGELOG.md`, `ERROR_LOG.md`,
        `docs/bugs/BUG-0027-*.md`, `docs/PREVENTIVE_ACTIONS.md` PA-0029 — done
- Effectiveness (assessed 2026-09-22): the real `php_current` positive fixture
  (`real_pair`) still passes unchanged (no false positive introduced); a hand-verified
  negative fixture that previously passed silently (declared transform rename plus an
  unrelated source-line rewrite) now correctly raises; two independently-pathed
  authored cells are now comparable via `pair_by` without reaching for the
  own-weakened-twin workaround; full suite green: 1521 passed, 8 skipped (up from a
  ~1512/8 baseline reported at the start of this lane -- the concurrent live-boot lane
  changed that baseline independently, per this lane's own instructions to expect it).

### CC-LAB-0054 — real, on-host live-boot conformance harness for php_laravel (FR-LAB-52) (2026-09-22)
- Change: built the Tier 1/2 live-boot capability `docs/LAB_IMPLEMENTATION_PLAN.md`
  ~line 154 named as blocked on on-host dependencies that "do not exist" — they now do,
  for real, in this offline sandbox (PHP 8.4 + Composer with real Packagist network
  access, no Docker daemon required: Docker was only ever the deployment/isolation
  mechanism, not a functional requirement, confirmed against `StackEnv.entrypoint_cmd`
  which is already `php artisan serve`, not a container-only command).
  1. **A real, minimal Laravel 13 project skeleton**, checked in at
     `fuzzlab/labgen/emitters/php_laravel/stack/skeleton/` — a real `composer
     create-project laravel/laravel .` output (resolved `laravel/framework` `v13.32.0`,
     matching `PHP_LARAVEL_STACK_ENV.framework_version` exactly), trimmed of `vendor/`,
     `.git/`, `tests/`, `.github/`, `resources/{css,js}`, `public/favicon.ico`,
     `routes/web.php` (overlaid per-manifest by the harness) and the dev-only
     composer/npm tooling this task's harness never runs. Confirmed
     `StackEnv.index_php_content()` already byte-matches Laravel 13's real generated
     `public/index.php` (no change needed there). One real skeleton edit:
     `bootstrap/app.php` disables Laravel's session-CSRF middleware globally
     (`validateCsrfTokens(except: ['*'])`) — the real `puppy-fort-factory/` pages this
     stack reproduces have no CSRF framework of their own, so leaving Laravel's default
     enabled would silently add an unmodeled security control on every migrated POST
     page (discovered for real: `contact.php`/`newsletter.php` both returned HTTP 419
     until this was disabled).
  2. **`fuzzlab/labgen/conformance/live_boot.py`** (new): `LiveBootHarness` assembles a
     temp-directory app from the skeleton + a manifest's real `LaravelEmitter.render()`/
     `route_fragment_for()` output (the missing whole-build assembly step
     `route_accumulator.py`'s own docstring already flagged as future work — no existing
     `fuzzlab.labgen.cli` path does this; `render_manifest`/`tier3.render_whole_sample`
     merge per-cell files only, never the scaffold or the accumulated routes file), runs
     a real `composer install --no-dev`, writes a harness-only SQLite `.env`
     (`DB_CONNECTION=sqlite`, explicitly never `StackEnv.env_file_content()`'s own
     production `mysql` default — see FR-LAB-52 point 2 for why conflating the two would
     be unsafe), seeds a minimal `products`/`posts`/`users` SQLite schema/seed covering
     exactly what the currently-driven manifests' rendered controllers touch, boots a
     real `php artisan serve` on a free local port, and exposes `.get()`/`.post()`
     (stdlib `urllib`, no new dependency) plus a `fetch()` method that implements
     `tier1.Tier1Client` for real — the first real client that protocol has ever had.
     Capability-probed via `live_boot_available()` (composer + php + skeleton present +
     real Packagist reachability, PA-0005/PA-0008/PA-0009), never a bare tool-presence
     guess. Teardown (`close()`/`__exit__`) always terminates the `php artisan serve`
     process (SIGTERM then SIGKILL on a 5s timeout) and removes its temp directory, on
     every exit path including an exception, per PA-0012's bounded-teardown convention
     applied to a subprocess.
  3. **`tests/test_labgen_conformance_live_boot.py`** (new, real, on-host): two tests,
     both actually run and passed in this sandbox (44.7s combined). Verified no leaked
     `php artisan serve` process or temp directory after a run.
     - `test_live_boot_forms_manifest_serves_real_pages` — boots
       `phase3_laravel_real_pages_forms.yaml` (`contact.php`/`newsletter.php`, no DB),
       POSTs a `<script>` payload at each real pinned URL, and asserts a real HTTP 200
       whose body contains the HTML-entity-escaped form of the payload and never the raw
       payload — the actual, observable security property the `html_entity_escape`
       transform claims.
     - `test_live_boot_numeric_manifest_sqli_twin_round_trips_a_payload` — boots
       `phase3_php_laravel_real_pages_numeric.yaml` against the seeded SQLite `products`
       table, sends the same `1 OR 1=1` boolean-injection payload at `product.php`'s real
       vulnerable (`LABGEN-RPL-PRODUCT`) and secure (`LABGEN-RPL-PRODUCT-BOUND`) twins,
       and asserts the raw-concatenation cell's real response body contains every seeded
       row while the bound-parameter cell's does not — a real, observed payload
       differential end to end (task instruction 4's third bullet), not an inference from
       source text.
  4. **New `pytest.mark.slow`** (`pyproject.toml`'s `[tool.pytest.ini_options] markers` —
     this project's first use of a slow-test marker convention, documented there):
     applied to both new tests. Not added to default `addopts` (a plain `pytest -q` still
     collects and runs them here, where composer/network are both available, exactly as
     this task's own instruction 8 requires) — the marker exists so `pytest -m slow` /
     `pytest -m "not slow"` can select or deselect them explicitly elsewhere, alongside
     the `pytest.mark.skipif(not live_boot_available())` guard that already makes the
     test suite degrade to a clean skip (not a failure, not extra wall-clock time beyond
     one fast capability probe) in any environment lacking composer/network.
  5. **Not covered by this pass** (see FR-LAB-52's own "coverage actually proven"
     bullet): the auth/G2/G4/search real-page manifests need additional seed data (a
     real login row, a stored-second-order write-then-read round trip) this change did
     not build. `docs/LAB_IMPLEMENTATION_PLAN.md` ~line 154 updated to describe this
     narrowed, accurate state rather than "on-host dependencies do not exist".
- Impact (other components / project): none outside LAB. No existing emitter output,
  manifest, or `--check` gate path is touched — `live_boot.py`/its test are additive,
  new files only, and `bootstrap/app.php`/the new `skeleton/` tree are new files this
  harness alone reads (no existing test or CLI path reads `stack/skeleton/`). Not wired
  into `fuzzlab.labgen.cli`'s `--check` gate suite (deliberately: that suite runs for
  every manifest/emitter on every invocation, and a real `composer install` per
  invocation would make it silently network-dependent and orders of magnitude slower for
  every existing user — this is a separate, explicitly opt-in-by-marker conformance
  check, run directly via pytest, matching this task's own "not something that silently
  triples every `pytest -q` run" instruction applied one level up, to `--check` too).
- Verification: `pytest tests/test_labgen_conformance_live_boot.py -q` → 2 passed (real
  run, this session, 2026-09-22). Full suite: see `docs/ARCHITECTURE.md`'s updated build
  status and this session's own report for the exact before/after pass count.
- Rollback: delete `fuzzlab/labgen/conformance/live_boot.py`,
  `tests/test_labgen_conformance_live_boot.py`, and
  `fuzzlab/labgen/emitters/php_laravel/stack/skeleton/`; revert the `pyproject.toml`
  `markers` addition. No other file depends on any of them.

### CC-LAB-0053 — L-P3.3c-CUT prep: parity/cutover coverage gate + migration-exemption register (2026-09-22)
- Change: built the **coverage gate** plan §4.3.6.6 point 3 describes, and only that —
  the atomic cutover (`L-P3.3c-CUT`: deleting `puppy-fort-factory/`, re-pointing
  `lab/compose.yaml`/`lab/web.Dockerfile`/`deploy.sh`/`fuzzlab/mutation/filtermodel.py`'s
  WAF-rules path) is untouched and stays blocked on human sign-off (high blast radius,
  hard to reverse). New `fuzzlab/labgen/cutover_gate.py` (a sibling of
  `regression_gate.py`, not an addition to it — that module diffs two already-loaded
  `GroundTruth` snapshots, schema-shaped and manifest-independent by design; this gate
  instead walks manifest cells through an emitter's `supports()`, a different shape of
  computation, so it gets its own module and mirrors that module's `diff_*`/`assert_*`
  two-function convention rather than being force-fit into it) exposes
  `assert_cutover_coverage()`/`diff_cutover_coverage()`: every `PFF-` case in
  `lab/ground-truth/labels.json` must be covered by at least one emitted `php_laravel`
  cell or named in the new `lab/ground-truth/migration-exemptions.yaml` (machine-readable,
  one `{pff_case, reason}` entry per exemption, read by the gate itself, malformed/
  duplicate entries raise loud). Coverage is derived, never hand-maintained
  (PA-0001/PA-0027): `compute_php_laravel_coverage()` walks every `lab/manifests/*.yaml`
  cell through `LaravelEmitter.supports()` and the new
  `fuzzlab.labgen.emitters.php_laravel.ground_truth_cases_for(cell)`, which extends
  (rather than duplicates) `CC-LAB-0052`'s `_GROUND_TRUTH_CASE_KEY`/
  `_CANONICAL_CELL_KEY` page-profile convention with two more keys that convention alone
  cannot express: `ground_truth_case_by_family` (a page whose one profile spans more than
  one `PFF-` case by sink family — `search.php`'s `PFF-0002`/`PFF-0003`) and
  `secondary_ground_truth_cases` (a page reproducing an extra, non-primary case as
  boilerplate on every cell rather than one canonical cell — `login.php`'s already-hashed
  `PFF-1008` password condition). Both new keys are popped in `render()`/
  `_render_write_controller()` alongside the existing metadata keys, so neither can leak
  a case ID into a generated file (FR-LAB-2, same discipline `_GROUND_TRUTH_CASE_KEY`
  already has). The exemption register lists `PFF-1002` (`track.php` performs no
  database query at all — no sink to model, per plan §4.3.6.6's own finding) and
  `PFF-0007`/`PFF-0008` (DOM XSS — client-rendered, never reaches the server; exempted
  per the D-open-1/D-open-2 decisions recorded in plan §4.3.6.7, both decided
  2026-09-22). Also documented the D-open-1 live-crawler-discoverability gap in
  `docs/ON_HOST_RUNBOOK.md` (Part C), per that decision's own requirement.
- Impact (other components / project): none outside LAB — `cutover_gate.py` is a new,
  standalone, generator-build-time module with no runtime callers yet (parallel to
  `regression_gate.py`'s own pre-CLI existence); the two new `php_laravel` page-profile
  keys are additive, popped before render, and do not change any emitted file's bytes
  (verified: the whole-manifest Tier-3 regeneration tests for `search.php`/`login.php`'s
  manifests still pass unchanged). Directly informs `L-P3.3c-CUT` (not yet dispatched):
  running `assert_cutover_coverage()` today is exactly the go/no-go signal that lane
  needs, and it is currently green.
- Risk (level; mitigation or accepted-risk justification): low. The gate is additive and
  read-only against the real repo (loads `labels.json`/`lab/manifests/*.yaml`/the new
  exemptions file; writes nothing); the two new page-profile keys are optional, defaulted
  metadata read only by the new function. Main risk is an exemption reason going stale if
  a later change resolves what it cites — mitigated by each reason citing a specific,
  dated decision (D-open-1/D-open-2, or the §4.3.6.6 `track.php` finding) rather than a
  vague "not yet done", so staleness is checkable by re-reading the cited section.
- Deliverables:
  - [x] `lab/ground-truth/migration-exemptions.yaml` — `PFF-1002`/`PFF-0007`/`PFF-0008`,
    each with a reason citing a specific decision — done.
  - [x] `fuzzlab/labgen/cutover_gate.py` (`CutoverGateError`, `CutoverCoverageDiff`,
    `load_exemptions`, `compute_php_laravel_coverage`, `diff_cutover_coverage`,
    `assert_cutover_coverage`) — done.
  - [x] `fuzzlab/labgen/emitters/php_laravel/__init__.py`: `ground_truth_cases_for()`,
    `_GROUND_TRUTH_CASE_BY_FAMILY_KEY`, `_SECONDARY_GROUND_TRUTH_CASES_KEY`, `search.php`/
    `login.php` profiles updated, both new keys popped in `render()`/
    `_render_write_controller()` — done.
  - [x] `tests/test_labgen_cutover_gate.py` — fixture-based gate-mechanics tests
    (malformed registers, missing file, raising/non-raising paths, PA-0027's
    supports()-derivation check) plus the real-repo run (`assert_cutover_coverage()`
    against the actual `lab/ground-truth/`/`lab/manifests/`, and a pinned assertion on
    the exemption register's contents) — done, 16 tests, all passing.
  - [x] `docs/ON_HOST_RUNBOOK.md` Part C: documented the D-open-1 live-crawler-
    discoverability gap — done.
  - [x] `CHANGELOG.md`, this entry, `FR-LAB-51` — done.
- Effectiveness (assessed 2026-09-22): the gate ran clean against the current repo —
  `pytest tests/test_labgen_cutover_gate.py` passes all 16 tests, including
  `test_every_real_pff_case_is_covered_or_exempted` and
  `test_covered_and_exempted_partition_every_labels_json_case`, which together confirm
  all 16 `PFF-` cases in `labels.json` are covered (10: `PFF-0001`, `PFF-0002`,
  `PFF-0003`, `PFF-0004`, `PFF-0005`, `PFF-0006`, `PFF-1001`, `PFF-1003`, `PFF-1004`,
  `PFF-1005`, `PFF-1006`, `PFF-1007`, `PFF-1008` — 13 covered) or exempted (`PFF-1002`,
  `PFF-0007`, `PFF-0008` — 3 exempted), with none uncovered. Full suite:
  `pytest -q` — 1512 passed, 8 skipped (the prior 1496/8 baseline plus this change's 16
  new tests, no regressions).

### CC-LAB-0052 — L-P3.3c consolidation: one unified URL-pinning mechanism replacing five independent ones (2026-09-22)
- Change: six sub-lanes (L-P3.3c-G1..G6) were dispatched concurrently against
  `fuzzlab/labgen/emitters/php_laravel/__init__.py` and `route_accumulator.py`. Because they
  ran without seeing each other's code, each built its own, mutually-incompatible mechanism
  for keeping a migrated real page at its real `.php`-suffixed URL (§4.3.6.6a): G5 (merged,
  `CC-LAB-0050`) a `url_path` pin + an instance-level double-claim guard; G1 a
  `served_url_for`/`ground_truth_url_cell_id` pair; G2 its own, differently-shaped
  `url_path` key plus a `DuplicateRouteError` whole-file scan; G3 `real_page`/
  `canonical_cell_id` with an explicit twin-URL convention and HTTP-method support; G4 a
  hand-authored `_REAL_URL_ROUTES` registry plus its own `stored_second_order`/write-endpoint
  axis; G6 left `search.php` deliberately unpinned and flagged the decision for
  `L-P3.3c-CUT`. This entry replaces all five mechanisms (G5's included) with **one**:
  1. **`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY`**, generalizing G3's design (chosen as the
     target shape because it is the most complete — canonical-cell-per-page, HTTP-method
     support, and an explicit twin-URL convention — and because G5's already-merged
     single-cell case is exactly the trivial case of "canonical cell, no twins"). A page
     profile carrying `real_page: True` names, via `canonical_cell_id`, the one cell served
     at the page's real URL and method; every other cell of that page is served at
     `_twin_url_for()`'s distinct, still-`.php`-suffixed variant (e.g.
     `/login.labgen-pla-0002.php`); `canonical_cell_id: None` (explicit) is the legal,
     flagged-open state G6's `search.php` needs — every cell of such a page falls back to
     the plain illustrative `/cell/<slug>` URL until `L-P3.3c-CUT` resolves it.
  2. **One shared derivation, `_served_route_for()`/`served_url_for()`** (PA-0003/PA-0021):
     called by `route_fragment_for()` (which registers the route),
     `identifier_sqli.probe_cell_for()` and `auth_session.login_url_for()` (which probe or
     post to it) — never re-derived. Applied *twice* for a `stored_second_order` cell (once
     for its read page, once for its write page), which is what let G4's
     `/profile.php`/`/edit_profile.php` pair fold into the same mechanism as every other
     lane's single-page real pages, without its own registry.
  3. **One `route_accumulator.fragment_for_cell` signature**, reconciling G3's
     (`method: str = "GET"`, an uppercase `_METHOD_HELPERS` dict including PUT/PATCH/DELETE)
     and G4's (`http_method`/`action`, lowercase, a smaller GET/POST set) shapes into
     `fragment_for_cell(*, cell_id, controller_class, url_path, method="GET",
     action="show")`. `RouteAccumulator.render_file`'s duplicate-URL guard (G2's
     `DuplicateRouteError`, kept as the shared safety net) now scans every `Route::` line
     of a fragment (`re.finditer`, not `re.search`) rather than only the first, since a
     `stored_second_order` cell's fragment now legitimately carries two lines.
  4. **Content migrated onto the unified mechanism, nothing discarded:** G1's
     `product.php`/`blog_post.php` pages and bound-parameter twins; G2's
     `products.php`/`api/products.php` pages and the `json_view` module category
     (`JSON_FIELD_CASTS`, `VIEWS`) unchanged (a different axis than URL pinning); G3's
     `login.php`/`register.php` pages, `_SESSION_LOGIN_KEY`/`_REGISTER_INSERT_KEY` complexity
     tails, and `auth_session.py` (updated to call `served_url_for` under its new name);
     G4's `stored_second_order` support (`SUPPORTED_CONTEXT_DEPTHS`), the `WRITES` module
     category and `stored_field_write.php.j2`, and the real `/profile.php`/`/edit_profile.php`
     pair, now expressed as two ordinary real-page profiles instead of `_REAL_URL_ROUTES`;
     G6's `search.php` six-cell page, the `html_attribute_quoted`/`sql_string_literal_like`
     sinks, the `(raw_concat, html_attribute_quoted)` safety-matrix row, and its
     deliberately-unpinned flag, preserved verbatim. G1's naming-safety finding (a
     `LABGEN-PFF-<case-id>` cell name would leak a ground-truth case ID into generated
     provenance, an FR-LAB-2 violation) is generalized into `_GROUND_TRUTH_CASE_KEY`, an
     optional, always-popped page-profile field every real-page profile now carries and a
     standing test (in each migrated lane's own test file) asserts never reaches a rendered
     file. Every lane's own manifest cell IDs are kept as authored (`LABGEN-PLRP-`,
     `LABGEN-RPL-`, `LABGEN-PLA-`, `LABGEN-PL-RP-`, ...) — the prefix mismatch is noted, not a
     mechanism collision, and not fixed here.
  5. **G2's route-line-sorted test fix lands, not a reverted version**:
     `tests/test_labgen_php_laravel_harder_shapes.py`'s
     `test_the_routes_file_carries_one_sorted_line_per_cell` continues to assert
     `route_lines == sorted(route_lines)` (a text-sort that happens to still coincide with
     cell-ID order for the illustrative-only sample manifest it runs over), and this lane's
     dedicated `test_labgen_php_laravel_real_pages_*` files instead assert the sorted-cell-ID
     invariant directly wherever a `.php`-suffixed URL no longer embeds the cell's slug.
     `SingleStatementComplexity.render()` now passes the whole context (`template.render(
     **ctx)`, G3's fix) rather than two hand-picked keys, so `session_login`/
     `register_insert` reach their template without a second place having to learn every new
     key.
- Design decision made autonomously (Auto Mode: the URL-naming bikeshed was blocking four
  lanes' merges, and a reasonable call was preferred to stalling): the twin-URL suffix
  convention (`/login.labgen-pla-0002.php`, embedding the cell slug before the `.php`
  suffix) is G3's own choice, adopted unchanged rather than redesigned. **A human reviewer
  may want to revisit this specifically** — an alternative (e.g. a query-string discriminator,
  or a `/variants/<slug>/login.php` prefix) was not evaluated against it. Flagged in
  `requirements.md` §8 as open for review, not as a defect.
- Impact (other components / project): none outside LAB. `fuzzlab/labgen/modules/__init__.py`
  (php_current) and `fuzzlab/labgen/conformance/static_precheck.py` gained G6's two sinks and
  static-precheck row (`php_current`'s own `_MODULE_SET_BY_SHAPE` is unchanged — that emitter
  is not the migration target, §4.3.6.6b). `lab/safety_matrix.yaml` gained G6's
  `(raw_concat, html_attribute_quoted)` row (additive, same `version: 1`).
  `lab/identities/identities.yaml` gained G4's `profile_bio_user_a` resource and its three
  authz expectations. Five worktree branches (`worktree-agent-a416d1ea63045d177` [G1],
  `-a4352a9e9c3535d45` [G2], `-a96cec86a7cb390b6` [G3], `-a41d184fd5b052e71` [G4],
  `-ab0e87dc363eec472` [G6]) are now superseded by this consolidation and should not be
  merged separately.
- Risk (level; mitigation or accepted-risk justification): **low**. (a) *The twin-URL naming
  convention is a judgment call, not a verified-safe default* — mitigated by flagging it
  explicitly here and in `requirements.md` for human review, and by the mechanism being
  structurally reversible (renaming the convention touches `_twin_url_for()` alone). (b)
  *`search.php`'s canonical-cell decision remains unresolved* — accepted, per G6's own
  finding: it is explicitly `L-P3.3c-CUT`'s call, not this pass's, and resolving it here
  would have been inventing a policy decision rather than consolidating five existing ones.
  (c) *Five branches' worth of manifests/tests/templates were re-authored from their
  `git diff`s rather than merged mechanically* — mitigated by the full suite passing (see
  below) with every migrated manifest exercised by both a dedicated test file and the
  cross-manifest `PA-0024` sweeps in `test_labgen_php_laravel_harder_shapes.py`.
- Deliverables:
  - [x] Unified `_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY` mechanism in
        `emitters/php_laravel/__init__.py`, replacing G5's `_pinned_url_claims` and every
        unmerged lane's own key — done
  - [x] `route_accumulator.fragment_for_cell(method=, action=)` unified signature;
        multi-line-aware `DuplicateRouteError` scan — done
  - [x] `WRITES`/`stored_field_write.php.j2` (G4), `VIEWS`/`json_view.php.j2` (G2),
        `html_attribute_quoted_echo`/`sql_string_literal_like` sinks (G6) merged into
        `modules.py`/`stack_env.py`/`templates/` — done
  - [x] Five manifests migrated: `phase3_php_laravel_real_pages_{numeric,g2,auth,g4,search}
        .yaml` — done
  - [x] Five dedicated test files rewritten against the unified mechanism, plus
        `tests/test_labgen_php_laravel_real_pages_forms.py` (G5) and
        `tests/test_labgen_php_laravel_harder_shapes.py` updated for it — done
  - [x] `CC-LAB-0046`/`0047`/`0048`/`0049`/`0051` and `FR-LAB-44`/`45`/`46`/`47`/`49` entries
        (below), describing the final unified mechanism rather than each lane's discarded
        plumbing — done
  - [x] `docs/ARCHITECTURE.md`, `requirements.md` §8 open-questions update — done
  - [ ] Not this pass: resolving `search.php`'s canonical cell (`L-P3.3c-CUT`); the
        twin-URL-naming human review; D-open-1/D-open-2 (unrelated, unresolved) — pending
- Effectiveness (assessed 2026-09-22): full suite **1494 passed / 8 skipped / 0 failed**.
  The two `test_mutation_operators.py` MUT failures this task's brief flagged as
  pre-existing/out-of-scope (`test_every_surface_variant_preserves_semantics`,
  `test_sql_equivalent_needs_trusted_provenance`) were confirmed failing on trunk before
  this pass started, and confirmed fixed — independently of this pass, by `BUG-0026`
  (commit `c6953c4`, already on this branch) — by the time this pass finished; this pass
  touches neither `fuzzlab/mutation/` nor `tests/test_mutation_operators.py`. Every migrated
  lane's manifest cells render, pass Tier-0 `php -l`
  (skip-guarded), Tier-3 byte-identical regeneration, minimal-pair, and (for G1/G2/G3/G4) the
  real regression gate both ways (pinned URLs accepted, idiomatic ones rejected).

### CC-LAB-0051 — L-P3.3c-G6: `search.php` (three sinks x vulnerable/secure) + the `html_attribute_quoted` shape, deliberately left unpinned (2026-09-22)
- Change: executed group **G6** of `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6's per-page
  migration table — `puppy-fort-factory/search.php`, one `?q=` reaching three sinks (a
  `LIKE '%q%'` SQL string literal, an HTML body reflection, and a quoted attribute
  reflection), as six cells in `lab/manifests/phase3_php_laravel_real_pages_search.yaml`
  (`LABGEN-PL-RP-0001`..`0006`, reproducing `PFF-0002`/`PFF-0003`) — plus the
  `(raw_concat, html_attribute_quoted)` safety-matrix row this page's third sink needed, the
  first shape on which `php_laravel`'s inventory is a strict superset of `php_current`'s
  (`test_laravel_carries_every_shape_php_current_supports` relaxed from equality to `>=`
  accordingly; `php_current`'s own `_MODULE_SET_BY_SHAPE` is untouched — it is not the
  migration target, §4.3.6.6b). New sink modules `html_attribute_quoted_echo` and
  `sql_string_literal_like` (the latter a second *rendering* of the existing
  `sql_string_literal` family, not a new one — search.php's `LIKE` filter has no
  login-style password condition to fold in) were registered in both `php_laravel`'s and
  `php_current`'s sink registries (for the shared minimal-pair vocabulary), with a
  `sink_override_by_family` page-profile key so one profile can pick a different sink
  rendering per sink family on the same page.

  **`search.php` is deliberately left with no canonical cell.** Its page profile carries
  `real_page: True` but `canonical_cell_id: None` (explicit) — the unified mechanism's
  legal, flagged-open state (see `CC-LAB-0052`): Laravel cannot register six
  `GET /search.php` routes for six cells (three sink behaviors x vulnerable/secure), and
  which cell should own that URL — or whether the `Cell` IR needs a multi-sink page
  composition that does not exist today — is a policy decision this lane, and the
  consolidation pass that followed it, both decline to make. **Still open for
  `L-P3.3c-CUT`.** Every cell of this page is served at its plain, illustrative
  cell-ID-derived `/cell/<slug>` URL in the meantime; only `cell.route.path` (which the
  regression gate diffs by `case_id`, never by what a route actually serves) carries the
  real `/search.php` string.
- Impact (other components / project): `fuzzlab/labgen/modules/__init__.py` (php_current) and
  `fuzzlab/labgen/conformance/static_precheck.py` gained the two new sinks and an
  `(xss, html_attribute_quoted) -> INFORMATIVE` precheck row respectively; both additive,
  neither widens `php_current`'s own supported-shape map. `lab/safety_matrix.yaml` gained one
  row under the existing `version: 1` (additive per the file's own append-only rule).
- Risk (level; mitigation or accepted-risk justification): **low**, with one **accepted, open**
  risk: `search.php`'s real URL is not served by any generated route, so a build that later
  needs to fingerprint or crawl the real `/search.php` path against this stack's output would
  find nothing there. Accepted because inventing a canonical-cell choice (or a multi-sink page
  composition) is explicitly out of scope for a migration lane and belongs to `L-P3.3c-CUT`,
  which owns emitting the candidate ground truth the regression gate runs against.
- Deliverables:
  - [x] `lab/manifests/phase3_php_laravel_real_pages_search.yaml` (6 cells) — done
  - [x] `html_attribute_quoted_echo`/`sql_string_literal_like` sinks in both emitters'
        registries; `sink_override_by_family` page-profile mechanism — done
  - [x] `(raw_concat, html_attribute_quoted)` safety-matrix row — done
  - [x] `tests/test_labgen_php_laravel_search_page.py` (11 tests: shape registration/scoring,
        the deliberately-unpinned flag read from the profile itself, six-distinct-URL route
        registration, minimal pair, Tier-0/Tier-3, `lab-generate --check`) — done
  - [x] Bookkeeping: this entry, `FR-LAB-49`, `docs/ARCHITECTURE.md`, `CHANGELOG.md` — done
  - [ ] Not this lane: resolving the canonical-cell decision — pending, `L-P3.3c-CUT`
- Effectiveness (assessed 2026-09-22): all six cells render and derive both verdicts per
  sink family; the new shape scores `VULNERABLE`/`SECURE` correctly against the matrix; full
  suite green (see `CC-LAB-0052` for the exact pass/skip count).

### CC-LAB-0049 — L-P3.3c-G4: `edit_profile.php` -> `profile.php`, the stored second-order pair, and the first write endpoint (2026-09-22)
- Change: executed group **G4** of `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.3's per-page
  inventory — the stored second-order pair (`PFF-0005` vulnerable / `PFF-1007` secure),
  the first `context_depth == "stored_second_order"` cells `php_laravel` renders
  (`SUPPORTED_CONTEXT_DEPTHS = ("direct", "stored_second_order")`; `same_file_helper`/
  `cross_file` remain refused, since those need pass-through-helper *fragments* this lane's
  axis does not) and the first **write** endpoint any emitter in this project emits (no
  emitter previously reproduced the real app's write page for a stored cell —
  `php_current._render_depth` returns no fragments for this depth at all). New `WRITES`
  module category (`stored_field_write.php.j2`): an Eloquent attribute assignment plus
  `save()`, persisting the tainted parameter **verbatim** (Eloquent binds it, so the write
  itself is not an injection point — the vulnerability is decided at the read endpoint,
  where the cell's transform pipeline applies). Two cells in
  `lab/manifests/phase3_php_laravel_real_pages_g4.yaml` (`LABGEN-PLRP-0401`/`0402`), each a
  three-file cell (read controller + Blade view + write controller). `lab/identities/
  identities.yaml` gained the owning identity for the stored `bio` (resource
  `profile_bio_user_a`, owner `user_a`) plus three authz expectations, since a stored
  second-order payload is written by, and read back as, some identity.

  **URL mechanism migrated from this lane's own `_REAL_URL_ROUTES` registry onto the
  unified mechanism** (see `CC-LAB-0052`): `/profile.php` (the read page) and
  `/edit_profile.php` (the write page) are now two ordinary `real_page` profiles, each with
  its own `canonical_cell_id` (`LABGEN-PLRP-0401` owns `/profile.php`, matching where
  `PFF-0005` is labelled; `LABGEN-PLRP-0402` owns `/edit_profile.php`, matching `PFF-1007`).
  The non-owning cell of each page now gets the same `.php`-suffixed twin-URL every other
  lane's twin gets (`/edit_profile.labgen-plrp-0401.php`,
  `/profile.labgen-plrp-0402.php`), rather than this lane's original fallback to the plain
  cell-ID-derived `/cell/<slug>` — so every cell still answers both its read and write
  endpoints, just via the same mechanism as G1/G2/G3/G5 rather than a fourth one.
- Impact (other components / project): none outside LAB. `StackEnv.file_roles` gained one
  additive `write_controller` path template; every pre-existing (`direct`-depth) cell's
  emitted file set, route line and content are unchanged.
- Risk (level; mitigation or accepted-risk justification): **low**. The write endpoint
  carries no transform (identical between a vulnerable cell and its secure twin by
  construction), so it cannot itself introduce a minimal-pair violation; a dedicated test
  confirms the two cells' write controllers are byte-identical outside their per-cell
  identifiers.
- Deliverables:
  - [x] `SUPPORTED_CONTEXT_DEPTHS`, `_render_write_controller`, `WRITES`/
        `stored_field_write.php.j2` — done
  - [x] `lab/manifests/phase3_php_laravel_real_pages_g4.yaml` (2 cells) — done
  - [x] `lab/identities/identities.yaml` additions — done
  - [x] `tests/test_labgen_php_laravel_real_pages_g4.py` (12 tests: three-file rendering,
        write-controller content/parity, both read+write routes per cell via the unified
        mechanism, real-URL-owner-matches-label, unknown-verb refusal, identity graph,
        Tier-0/Tier-3, `lab-generate --check`) — done
  - [x] Bookkeeping: this entry, `FR-LAB-47`, `docs/ARCHITECTURE.md`, `CHANGELOG.md` — done
- Effectiveness (assessed 2026-09-22): both cells derive the verdict their `PFF-` case
  labels, both routes (read+write) resolve for both cells, and the write controllers are
  confirmed identical outside per-cell identifiers; full suite green (see `CC-LAB-0052` for the exact pass/skip count).

### CC-LAB-0048 — L-P3.3c-G3: `login.php` (vulnerable + secure twin) + `register.php`, the auth pages (2026-09-22)
- Change: executed group **G3** of `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.3's per-page
  inventory — `login.php` (`PFF-0004` vulnerable `username` + `PFF-1008` true-negative
  `password` condition, plus an authored secure twin) and `register.php` (`PFF-1004`,
  secure-only), in `lab/manifests/phase3_php_laravel_real_pages_auth.yaml`
  (`LABGEN-PLA-0001`/`0002`/`0003`). The first two-cell (canonical + twin) real page in this
  emitter, and the source of the **unified URL-pinning mechanism** the consolidation pass
  (`CC-LAB-0052`) generalized project-wide: `real_page`/`canonical_cell_id` page-profile
  keys, the `.php`-suffixed twin-URL convention (`/login.labgen-pla-0002.php`), and
  `route_accumulator.fragment_for_cell`'s HTTP-method parameter (`login.php`/`register.php`
  are POST pages; the pre-existing accumulator hardcoded `Route::get`, an accepted risk
  `CC-LAB-0050` flagged and this lane's own contribution resolves). Two new complexity-tail
  flags on the existing `single_statement` template (never new composition modules, so
  `minimal_pair`'s shared vocabulary stays untouched): `session_login` (the real login page's
  session-establishment + redirect tail) and `register_insert` (the real register page's
  prepared `INSERT` after its duplicate-username check). New
  `emitters/php_laravel/auth_session.py`: a thin, offline-testable adapter over the
  LAB-owned `fuzzlab.labgen.identity_session.IdentitySessionStore` (lane L-P2.2) that builds
  a login POST from this stack's own page profile and URL — no session-holding logic is
  reinvented (PA-0001/PA-0021).
- Impact (other components / project): none outside LAB. `fuzzlab.labgen.identity_session`
  is read, not modified. `SingleStatementComplexity.render()` now passes its whole context
  to the template (`**ctx`) rather than two hand-picked keys, so every pre-existing profile
  (which declares neither `session_login` nor `register_insert`) renders byte-identically.
- Risk (level; mitigation or accepted-risk justification): **low**. The login pair's
  security-relevant difference is confirmed to sit only in the transform region via the
  shared minimal-pair checker (run against each cell's own weakened twin, since that checker
  pairs strictly by file path and cannot itself compare two distinctly-named cells).
- Deliverables:
  - [x] `_SESSION_LOGIN_KEY`/`_REGISTER_INSERT_KEY` complexity-tail flags — done
  - [x] `route_accumulator.fragment_for_cell(method=)` — done
  - [x] `emitters/php_laravel/auth_session.py` — done
  - [x] `lab/manifests/phase3_php_laravel_real_pages_auth.yaml` (3 cells) — done
  - [x] `tests/test_labgen_php_laravel_real_pages_auth.py` (14 tests: label agreement,
        canonical/twin URL split, session/insert tail content, `auth_session` adapter
        round-trip, minimal pair, regression gate both ways, Tier-0/Tier-3,
        `lab-generate --check`) — done
  - [x] Bookkeeping: this entry, `FR-LAB-46`, `docs/ARCHITECTURE.md`, `CHANGELOG.md` — done
- Effectiveness (assessed 2026-09-22): both `login.php` cells derive their labelled verdicts,
  `register.php` derives SECURE, the routes file registers the real URL plus the twin's
  variant with no collision, and `auth_session` successfully drives a fake login POST end to
  end; full suite green (see `CC-LAB-0052` for the exact pass/skip count).

### CC-LAB-0047 — L-P3.3c-G2: `products.php` + `api/products.php`, the JSON `view` module category (2026-09-22)
- Change: executed group **G2** of `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.3's per-page
  inventory — the catalog listing (`PFF-1001`) and its JSON feed (`PFF-1003`), both
  secure-only, same SQL position, differing only in presentation. New `view` module category
  (`CR-LAB-0001` Addendum D names it; nothing had needed it before this page):
  `JsonViewModule`/`json_view.php.j2` renders a Laravel Eloquent API Resource class from the
  page profile's declared `json_fields` (an ordered `(name, cast)` tuple; `JSON_FIELD_CASTS`
  is a closed, validated set), with the controller-side bridge statement
  (`view_bridge_code`) rebinding `$rows` so the existing `single_statement` complexity closes
  the method unchanged. A view module's name is recorded on its own `// View category: ...`
  provenance line, never in `// Module composition: ...` (the same reason the `route`
  category is never in that line — `minimal_pair` classifies every composition-line name
  through the shared registries and raises for one it cannot find).
- Impact (other components / project): none outside LAB. `StackEnv.file_roles` gained one
  additive `json_view` path template.
- Risk (level; mitigation or accepted-risk justification): **low**. `json_fields` is
  required and validated (bare-identifier field names, a closed cast set) rather than
  defaulted, so a page profile naming an unknown or malformed field fails loud at build time
  rather than reaching PHP source unvalidated.
- Deliverables:
  - [x] `VIEWS`/`JsonViewModule`/`json_view.php.j2`/`JSON_FIELD_CASTS` — done
  - [x] `lab/manifests/phase3_php_laravel_real_pages_g2.yaml` (2 cells) — done
  - [x] `tests/test_labgen_php_laravel_real_pages_g2.py` (13 tests: label agreement, view
        category presence/absence, resource-class content and field casts, a validation
        failure case, the shared route-accumulator duplicate-URL guard, regression gate,
        minimal pair, Tier-0/Tier-3, `lab-generate --check`) — done
  - [x] Bookkeeping: this entry, `FR-LAB-45`, `docs/ARCHITECTURE.md`, `CHANGELOG.md` — done
- Effectiveness (assessed 2026-09-22): both cells derive SECURE matching their true-negative
  labels, the JSON resource emits the real endpoint's exact field set/order/casts, and the
  bare listing's controller carries no resource collection call; full suite green (see
  `CC-LAB-0052` for the exact pass/skip count).

### CC-LAB-0046 — L-P3.3c-G1: `product.php` + `blog_post.php`, numeric-literal SQLi on two real tables (2026-09-22)
- Change: executed group **G1** of `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.3's per-page
  inventory — the two real numeric-literal-SQLi pages (`PFF-0001`/`PFF-0006`), plus an
  authored bound-parameter twin for each, in
  `lab/manifests/phase3_php_laravel_real_pages_numeric.yaml`. One module set, two page
  profiles, no new modules — the real pages' only documented difference (verbose vs.
  suppressed DB errors) is an observability axis, not a `(transform, sink_context)` fact, so
  it is recorded and deliberately not modelled (the same omission `php_current`'s own
  real-pages sample already makes for this pair). This lane's own contribution to the
  unified mechanism (`CC-LAB-0052`) is the public name `served_url_for()` and the finding
  that a case-ID-derived cell name (`LABGEN-PFF-<case-id>`) would leak ground-truth
  provenance into generated files (an FR-LAB-2 violation) — resolved by a page-derived
  naming convention instead (`LABGEN-RPL-<PAGE>`) and, in the unified mechanism, by the
  always-popped `_GROUND_TRUTH_CASE_KEY` metadata field every real-page profile now carries.
- Impact (other components / project): none outside LAB.
- Risk (level; mitigation or accepted-risk justification): **low**. No new module, sink
  family or safety-matrix row.
- Deliverables:
  - [x] `lab/manifests/phase3_php_laravel_real_pages_numeric.yaml` (4 cells) — done
  - [x] `tests/test_labgen_php_laravel_real_pages_numeric.py` (10 tests: label agreement,
        `real_page`/`canonical_cell_id` self-declaration, the case-ID-never-leaks guard,
        `served_url_for` agreement with the registered route, regression gate both ways,
        minimal pair, Tier-3, `lab-generate --check`) — done
  - [x] Bookkeeping: this entry, `FR-LAB-44`, `docs/ARCHITECTURE.md`, `CHANGELOG.md` — done
- Effectiveness (assessed 2026-09-22): both canonical cells derive the verdict their `PFF-`
  case labels, both twins are served at distinct suffixed URLs, and no ground-truth case ID
  reaches a generated file; full suite green (see `CC-LAB-0052` for the exact pass/skip count).

### CC-LAB-0050 — L-P3.3c-G5: `contact.php` + `newsletter.php` reproduced as `php_laravel` cells, with `.php`-pinned routes (2026-09-22)
*(`CC-LAB-0050` and `FR-LAB-48` were pre-assigned to this sub-lane by the orchestrating
session, with `CC-LAB-0046`..`0049`/`0051` and `FR-LAB-44`..`0047`/`49` reserved for the five
concurrent sibling sub-lanes G1–G4/G6 — so no merge-time renumbering should be needed.)*
*(Addendum, `CC-LAB-0052`, 2026-09-22: the `url_path` pin and instance-level double-claim
guard this entry describes below were superseded by the unified
`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY` mechanism the consolidation pass introduced —
`contact.php`/`newsletter.php` are the trivial, single-cell case of that mechanism and their
served behavior is unchanged; only the plumbing moved. This entry is left as written per the
append-only rule; see `CC-LAB-0052` for the current mechanism.)*
- Change: executed group **G5** of `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6's per-page
  migration table — the two real **escaped-echo form pages** of `puppy-fort-factory/`,
  reproduced in Laravel/Blade idiom on the `php_laravel` emitter, in four pieces:
  1. **A new real-page manifest**, `lab/manifests/phase3_laravel_real_pages_forms.yaml`,
     with two cells: `LABGEN-PLRP-1005` (`contact.php`, POST `message`, `PFF-1005`) and
     `LABGEN-PLRP-1006` (`newsletter.php`, POST `email`, `PFF-1006`). Both are
     `(xss, html_body)` with a single `html_entity_escape` op, so the derived verdict is
     SECURE — exactly the label `lab/ground-truth/labels.json` already carries for both
     cases. Kept as its own manifest rather than appended to
     `phase3_php_laravel_sample.yaml` for two reasons: that file is the *illustrative*
     inventory (its own header says so, and its test asserts a closed 20-cell verdict map),
     and five sibling sub-lanes were editing this area concurrently. The cell-ID prefix is
     `LABGEN-PLRP-` ("php_laravel real pages"), numerically mirroring the `PFF-` case each
     cell reproduces so the cutover's coverage gate has a legible mapping; it collides with
     neither `php_current`'s `LABGEN-RP-` real pages nor the `PFF-` ground-truth namespace.
  2. **No new modules, verified rather than assumed.** The plan predicted "no new modules"
     for this group; re-reading L-P3.3b's live inventory confirmed it. The only thing the
     real pages needed that the illustrative `html_body` page did not is the **taint
     origin**: `contact.php`/`newsletter.php` reflect a POST body parameter, not a stored
     field, so their page profiles use the existing `source_override: post_param`
     mechanism (the shape's default source is `read_stored_field`, the stored-XSS origin).
     No new sink family, op, safety-matrix row or template was added, and no other
     emitter — `php_current` included — was touched.
  3. **Migrated routes keep the real app's exact `.php` URL** (§4.3.6.6a, the single most
     likely way to get this lane wrong). A page profile may now pin the URL its cells are
     served at via a new `url_path` key, so `routes/web.php` emits
     `Route::get('/contact.php', …)` instead of this stack's default cell-ID-derived
     `/cell/<slug>`. Without the pin, every migrated `PFF-` case would *relocate* and
     T-LAB0.9's additive-only gate (`fuzzlab/labgen/regression_gate.py`) would correctly
     fail the cutover. Three details make the pin safe rather than a new footgun:
     `_url_path_for()` gained an optional page argument (its previous single-argument
     behavior is unchanged, so illustrative pages and their twins keep their own URLs);
     `route_fragment_for()` refuses a *second* cell claiming an already-claimed pinned URL,
     since a page that needs a vulnerable cell plus a secure twin cannot pin one path for
     both; and the identifier-SQLi route-rewrite adapter
     (`emitters/php_laravel/identifier_sqli.py`) now resolves the same pin, so an oracle
     can never probe a URL the generated app does not serve. The pin is routing metadata
     and is popped before the render context, like `source_override`.
  4. **The conformance sweep is `supports()`-derived and spans every manifest**
     (§4.3.6.6 point 1 — the `BUG-0022`/`PA-0024` pattern, with `PA-0027(b)`'s
     derived-set rule): `tests/test_labgen_php_laravel_real_pages_forms.py` runs Tier-3
     regenerate-and-diff, the one-unique-path-per-file check and Tier-0 `php -l` over every
     cell of every committed manifest this emitter supports — computed from
     `Emitter.supports()`, never a hand-kept list — plus a guard test asserting that derived
     set really spans more than this group's own manifest (otherwise the sweeps could pass
     vacuously). The per-page acceptance criteria of §4.3.6.6 point 2 are each asserted from
     a source of truth: the expected verdict, URL, method and parameter location are read
     out of `labels.json` (not restated), and the URL constraint is demonstrated against the
     **real** regression gate — the pinned `.php` URLs pass `assert_no_regression`, the
     idiomatic extension-less ones raise `RegressionGateError`.
- Impact (other components / project): none outside LAB. No shared module was touched
  (`fuzzlab/labgen/modules.py`, `minimal_pair.py`, `regression_gate.py`, `conformance/` and
  every other emitter are unchanged); `puppy-fort-factory/` is read-only evidence here and
  is not modified or deleted (that is L-P3.3c-CUT). `lab/ground-truth/` is unchanged — this
  lane *reads* it as the oracle. The new manifest is picked up automatically by the existing
  `lab/manifests/*.yaml` glob sweeps (`test_labgen_gates.py`,
  `test_labgen_corpus_analysis.py`, `test_labgen_php_laravel_harder_shapes.py`'s PA-0024
  test), all of which stay green.
- Risk (level; mitigation or accepted-risk justification): **low–medium**. (a) *Pinned-URL
  collision* — mitigated by the fail-loud claim check plus a test. (b) *Concurrent sibling
  sub-lanes* editing `_PAGE_PROFILES` and this emitter's docstrings: mitigated by keeping
  every change additive and localized (new profile keys/entries, one new optional
  parameter), but textual merge conflicts in `_PAGE_PROFILES`, `docs/ARCHITECTURE.md`'s
  php_laravel paragraph and `requirements.md` are expected and must be resolved by the
  merging session, not force-resolved. (c) **Accepted, and flagged for L-P3.3c-CUT:**
  `RouteAccumulator.fragment_for_cell` hardcodes `Route::get`, so these POST-only real pages
  (and G3's `login.php`/`register.php`) register a GET route. Harmless today — nothing runs
  the generated app — but a real cutover build must register the method
  `cell.route.method`/`labels.json` names, or a POST to `/contact.php` would 405. Left
  deliberately to one cross-group fix rather than six conflicting edits to a shared
  accumulator. (d) The sink fragment wraps the value in a `div` where the real pages use
  `blockquote`/`p`, and `newsletter.php`'s `FILTER_VALIDATE_EMAIL` check is not modelled —
  both documented in the manifest/profiles as not verdict-relevant (the sink *context family*
  is what the matrix is keyed on; the matrix has no op for the email check, the same
  reasoning that exempts `track.php`'s int cast).
- Deliverables:
  - [x] `lab/manifests/phase3_laravel_real_pages_forms.yaml` (2 cells, `PFF-1005`/`PFF-1006`) — done
  - [x] `url_path` route pin + fail-loud single-claim guard in `emitters/php_laravel/__init__.py` — done
  - [x] `contact.php`/`newsletter.php` page profiles (with `post_param` source override) — done
  - [x] identifier-SQLi adapter resolves the pin — done
  - [x] `tests/test_labgen_php_laravel_real_pages_forms.py` (16 tests: label-derived verdicts,
        route/method/param agreement with ground truth, the real regression gate both ways,
        pin-collision guard, minimal pair, `supports()`-derived Tier-0/Tier-3 sweeps over every
        manifest, `lab-generate --check`) — done
  - [x] Bookkeeping: this entry, `FR-LAB-48`, `docs/ARCHITECTURE.md`, `CHANGELOG.md` — done
  - [ ] Not this lane: the other page groups, DOM XSS (`PFF-0007`/`0008`), the cutover — pending
- Effectiveness (assessed 2026-09-22): the two `PFF-` cases are reproduced and pass every
  §4.3.6.6 point-2 criterion; full suite 1413 passed / 8 skipped with the 2 pre-existing
  MUT failures in `tests/test_mutation_operators.py` unchanged and untouched by this lane.
  The URL-pin decision is now enforced by a test against the real gate rather than by a
  paragraph of plan prose, which is the part most likely to have been got wrong silently.

### CC-LAB-0045 — L-P1.3: the metadata leakage probe becomes a required `--check` gate, with per-class thresholds (2026-09-22)
*(`CC-LAB-0045` was pre-assigned to this lane by the orchestrating session, with
`CC-LAB-0044` reserved for the concurrent lane L-P3.3b — so, unlike CC-LAB-0040..0043,
this entry needed no merge-time renumbering. `FR-LAB-43` likewise.)*
- Change: implemented `docs/LAB_IMPLEMENTATION_PLAN.md` §2.3's second half (its first
  half, the χ² fingerprint gate, is `CC-LAB-0040`/L-P3.4 and is untouched here), in
  three pieces:
  1. **Per-class AUC thresholds in `fuzzlab/labgen/leakage_probe.py`** — the §2.3
     decision of 2026-09-21 ("per-class thresholds, not one global 0.55-0.60 band"),
     modelled on the existing `PER_CLASS_FEATURE_EXCLUSIONS` dict as the plan asked:
     `PER_CLASS_AUC_THRESHOLDS: dict[str, ClassThreshold]`, where `ClassThreshold`
     carries `(auc_threshold, status, justification)` and validates all three.
     **The design tension this had to resolve, and how:** that module's own docstring
     (point 5) and the comment above `PER_CLASS_FEATURE_EXCLUSIONS` both stated flatly
     that a per-class *threshold* is a loophole — "a per-class threshold would just
     disable the gate for that class". That warning is honored rather than overridden,
     by making the override one-directional: a class's effective pass line is
     `min(its own permutation-null percentile, its configured threshold)`. A configured
     number can therefore only ever make the gate **stricter**; raising one above a
     class's own null has literally no effect, so the dict cannot be used to turn a red
     class green. The two docstrings were updated in place to say this (a new point 6)
     rather than left contradicting the code.
     Every shipped value is `status="provisional"`, seeded from
     `PROVISIONAL_THRESHOLD_BAND = (0.55, 0.60)` — mid-band for the dense classes
     (`sqli`, `xss`, `sqli_error`, `secure`), top-of-band for the two classes whose
     legitimate-signal feature `latency_ms` is already excluded
     (`sqli_blind_time`, `race_condition`), and top-of-band for the
     `DEFAULT_CLASS_THRESHOLD` an unregistered class falls back to. Each carries a
     written rationale, and `format_leakage_report` prints every class's number *with
     its PROVISIONAL/CALIBRATED status and rationale*, plus an explicit NOTE naming the
     classes whose verdict currently rests on an uncalibrated number — the §2.3
     requirement that a future calibration pass be able to tell which numbers still
     need a properly-sized permutation null.
  2. **A gate wrapper.** `probe_leakage` stays the pure measurement function it always
     was (it still never raises on a leaky result, and its existing signature/fields are
     untouched); `run_leakage_gate` is the new raising wrapper, and it names **every**
     violation found, global and per-class, in one `MetadataLeakageError` — the same
     "one error listing all violations" convention `run_fingerprint_gate` uses.
     `InsufficientCorpusError` is deliberately a *separate* type: "we could not measure"
     is not "we measured a leak", and a caller must be able to skip on the former.
     `insufficiency_reason()` names the specific shortfall (empty / <2 classes /
     `MIN_CELLS_FOR_GATE` / `MIN_GROUPS_FOR_GATE` / `MIN_CELLS_PER_CLASS_FOR_GATE` / no
     in-scope feature with any variance). Two additive, backward-compatible extensions
     support this: a `feature_scope` parameter that may only **narrow** the closed
     allowlist (never widen it), and new `LeakageResult.per_class` /
     `.per_class_leaks` / `.gate_passes` / `.provisional_classes` members appended with
     defaults so the pre-existing `leaks` field keeps its exact prior meaning.
     `corpus_analysis.stratified_split`'s use of `grouped_cv` is unaffected — that
     function's signature and construction are untouched.
  3. **Wired into `fuzzlab/labgen/cli.py`'s `run_checks` as required step 9**, following
     step 8's pattern exactly: a single adapter
     (`leakage_probe_records_from_manifest`) between the schema and a deliberately
     schema-independent probe, reusing `corpus_analysis.generating_rule_id` as the
     grouping key rather than deriving a second one (PA-0003/PA-0021), a lazy import so
     a missing scikit-learn becomes a fail-closed `--check` failure instead of an import
     crash, and a SKIP with an explicit printed reason when the corpus cannot support
     the measurement. The gate's report is printed on the **pass** path too, because a
     provisional-threshold annotation only shown on failure would never be read.
- **Honest limitation, recorded rather than built around.** The lane brief expected the
  harder-shapes manifest's new cell-count/class/transform variation (L-P1.2b) to make
  this gate meaningful. It does not, for a reason no amount of corpus variation fixes:
  five of the seven allowlisted features (`status_code`, `response_length`,
  `header_count`, `latency_ms`, `content_type`) are observations of a **live response**,
  and the sixth (`param_name_length`) lives in each emitter's private per-route page
  profile, not in the `Cell` IR (`ParamSpec` carries `location`/`encoding`, never a
  name). Only `path_depth` is manifest-derivable, hence
  `cli.MANIFEST_DERIVABLE_LEAKAGE_FEATURES = ("path_depth",)`. Imputing the rest would be
  feeding a stage inputs the real upstream never produced, which PA-0006 forbids, so the
  probe is told the true scope via `feature_scope` and skips loudly instead. Consequence:
  on every manifest shipped today the gate prints
  `metadata leakage gate SKIPPED -- the corpus has 13 cell(s); the gate needs >= 40 ...`
  and passes. The gate is nonetheless proven to run for real, and to both pass and fail
  correctly, on manifest-derived corpora through the real CLI (see Deliverables).
  Making it non-vacuous on the real corpus needs observed response metadata recorded per
  cell at build time — a separate, real deliverable, not an oversight; noted in
  `FR-LAB-43` and flagged to the orchestrating session.
- Impact (other components / project): **LAB only.** `fuzzlab lab-generate --check`
  gains a ninth gate; `fuzzlab/labgen/leakage_probe.py` and `fuzzlab/labgen/cli.py` are
  the only source files changed. No emitter, no `schema.Cell`, no
  `fingerprint_gate.py`, no safety matrix, no ground-truth contract, and no other
  component is touched. `corpus_analysis.py` is read but not modified; its `grouped_cv`
  call site keeps working (asserted by the unchanged
  `tests/test_labgen_corpus_analysis.py`). The one interface change is additive:
  `probe_leakage` gains an optional `feature_scope` keyword and `LeakageResult` gains
  four defaulted members, so every pre-existing caller compiles and behaves identically.
- Risk (level; mitigation or accepted-risk justification): **Low-to-moderate, and the
  moderate part is stated rather than hidden.** (a) *A new required gate could fail a
  build spuriously.* Mitigated structurally: the gate refuses to judge a corpus it
  cannot measure (typed `InsufficientCorpusError` → printed skip, never a failure), and
  the per-class thresholds can only tighten against an empirically-derived null, never
  replace it. (b) *The threshold numbers are guesses.* Accepted and labelled: every one
  is `provisional`, inside the plan's own band, printed as such on every run, and
  asserted to be so by a test — the plan explicitly sanctions provisional values at this
  phase. (c) *The gate is currently vacuous on real manifests.* Accepted, documented in
  three places (the constant's docstring, the printed skip reason, `FR-LAB-43`), and
  reported to the orchestrating session rather than concealed by loosening the
  sufficiency floors to force a run on 13 cells — which would have produced a
  meaningless verdict, the exact failure mode PA-0017 warns about (a metric that does
  not measure the capability it claims to).
- Deliverables:
  - [x] `PER_CLASS_AUC_THRESHOLDS` + `ClassThreshold` + `THRESHOLD_STATUSES` +
        `PROVISIONAL_THRESHOLD_BAND` + `class_threshold()` — done
  - [x] Per-class one-vs-rest AUC and per-class permutation nulls, computed from the
        same cross-validated probabilities as the global AUC (never a second fit) — done
  - [x] `run_leakage_gate` / `LeakageGateReport` / `MetadataLeakageError` /
        `InsufficientCorpusError` / `insufficiency_reason` / `format_leakage_report` — done
  - [x] Additive `feature_scope` (narrow-only) + explicit rejection of an in-scope
        feature missing from a cell (PA-0006, never silently imputed) — done
  - [x] `cli.run_checks` step 9 + `leakage_probe_records_from_manifest` + `path_depth`
        + `MANIFEST_DERIVABLE_LEAKAGE_FEATURES` — done
  - [x] Tests: 14 new in `tests/test_labgen_leakage_probe.py` (reusing that module's own
        `_leaky_corpus`/`_clean_corpus` fixtures, not re-authored ones) + 7 new in
        `tests/test_labgen_cli.py`, including a real gate PASS and a real gate FAIL
        driven through `run_checks` on manifest-derived corpora built by re-pathing the
        real real-pages cells between php_current's two existing renderable depths — done
  - [x] CHANGELOG line, this entry, `FR-LAB-43`, `docs/ARCHITECTURE.md` — done
- Effectiveness (assessed 2026-09-22): **Partially achieved, precisely.** The mechanism
  is complete and demonstrably correct: `pytest` 1337 passed / 8 skipped / 2 failed
  (the two are the pre-existing, already-logged `tests/test_mutation_operators.py`
  MUT-component failures, confirmed identical to this branch's baseline before any of
  this lane's changes — unrelated to LAB). The gate genuinely fails a build when a
  feature trivially predicts the class, and genuinely passes when it does not, both
  proven end to end through `cli.run_checks`. What is *not* achieved is the plan's
  implicit hope that §2.2's corpus variation would make this gate bite on real
  manifests: it skips on all of them, for the feature-availability reason above. Judge
  again once per-cell observed response metadata exists.

### CC-LAB-0044 — L-P3.3b: the `php_laravel` full module inventory (every shape, Laravel/Eloquent/Blade idiom) (2026-09-22)
*(Number pre-assigned to this lane by the orchestrating session — `CC-LAB-0044`/`FR-LAB-42`,
with the concurrent lane L-P1.3 holding `CC-LAB-0045`/`FR-LAB-43` — so, unlike every prior
lane, no post-merge renumbering was needed and none was done. Both prerequisites were
confirmed merged in this worktree before work began: L-P3.3a's `StackEnv`/route-accumulator
foundation (`CC-LAB-0029`) and L-P1.2b's harder shapes on `php_current` (`CC-LAB-0043`).)*
- Change: built `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3 **step 2** — the full-depth module
  inventory for the second PHP emitter — in five pieces:
  1. **This emitter's own module registries**, `fuzzlab/labgen/emitters/php_laravel/modules.py`
     plus its own Jinja2 template tree (`templates/{sources,transforms,sinks,complexities}/`):
     three sources (`get_param`, `post_param`, `read_stored_field`), seven transform ops
     (`identity`, `param_bind`, `html_entity_escape`, `identifier_charset_filter`,
     `identifier_allowlist`, `url_scheme_allowlist`, `attr_value_allowlist`), seven sinks and
     two complexities. Mirrors `fuzzlab.labgen.modules`' composition *shape* (Addendum C's
     porting instruction, the same convention `node_express` follows) with entirely new code:
     nothing is imported from or added to that package, and `emitters/php_current/` is
     untouched — verified against the final diff, not assumed.
  2. **All seven shapes rendered in Laravel idiom**, not transliterated PHP:
     `sql_numeric_literal` via `DB::select` raw-vs-bound `?`; `sql_string_literal` via the
     query builder's `whereRaw()` vs. value-binding `where()` (the real Laravel footgun);
     `sql_identifier` via `orderByRaw()`, whose very existence is the reason an identifier
     position is not a value position; `sql_join_alias` with the alias substituted three
     times in one statement; and the three HTML shapes as **Blade views**. An HTML-sink cell
     is therefore a two-file cell here — a controller (`role="controller"`) plus its own
     `resources/views/cells/<cell-slug>.blade.php` (`role="view"`, a new
     `StackEnv.file_roles` entry) — because a Laravel controller returns a view rather than
     echoing. Both files carry the `// Module composition: ...` provenance line (in the view,
     as a raw `<?php` header block that Blade passes through) so the minimal-pair invariant is
     evaluated on each.
  3. **Two contracts this port discovered and now documents**, both load-bearing for any
     future emitter that wants the shared checkers rather than the naive fallbacks:
     (a) *module names are the project's shared composition vocabulary.*
     `fuzzlab.labgen.minimal_pair` builds its category map from `fuzzlab.labgen.modules`'
     registries and **raises** for a name it cannot classify, so L-P3.3a's stack-local names
     (`get_query_param`, `db_select_raw`) would have made every Laravel cell fail the
     minimal-pair gate with a setup error the moment the emitter was wired into `--check`;
     they are renamed to the shared vocabulary and a test asserts every registry key is
     classifiable. (b) *a sink never escapes anything itself* — so the Blade sinks echo
     `{!! ... !!}` and `html_entity_escape` applies Laravel's `e()` helper in the controller,
     keeping the security-relevant difference inside the declared transform region instead of
     moving it into a second file. (Both are recorded as an open question in `requirements.md`
     §8: the general fix is a pluggable category map on `minimal_pair`, a sibling lane's file,
     which no second stack needs yet.)
  4. **Manifest + conformance.** `lab/manifests/phase3_php_laravel_sample.yaml` widened from
     L-P3.3a's 2 foundation cells to **20** (a vulnerable/secure pair per value-context shape;
     a triple or quadruple per harder shape — no transform / the plausible-but-wrong fix /
     the textbook-but-inapplicable `param_bind` / the context-correct fix). Verdicts are
     derived by `verdict()` against the pinned matrix, never asserted in the manifest, and no
     safety-matrix row was added or changed (every `(op, family)` pair these cells need
     already existed — checked, not assumed). `php_laravel` is registered in
     `fuzzlab/labgen/cli.py`'s `EMITTER_REGISTRY`, which is what makes
     `fuzzlab lab-generate --manifest … --emitter php_laravel --check` runnable; it passes end
     to end over all 20 cells / 28 emitted files: name-leak scanner, secret scanner
     (Gitleaks present on this host, so it ran for real), determinism, minimal pair, Tier 0
     `php -l` (ran for real — `php` is present — including the `.blade.php` views) and Tier 3
     whole-sample regeneration.
  5. **The identifier-SQLi oracle adapter**, `emitters/php_laravel/identifier_sqli.py`. The
     brief asked whether `fuzzlab.labgen.identifier_sqli_assertion` is reusable as-is for a
     Laravel-rendered cell; **verified rather than assumed, and the answer is "almost"**. It
     is genuinely stack-agnostic except for one assumption — that a cell is served at
     `cell.route.path` — which holds for filesystem-routed `php_current` but not for this
     router-dispatched stack, where each cell is served at its own `/cell/<slug>` URL
     precisely so twins can coexist in one build. The adapter is therefore a **route rewrite
     and nothing else**: it rewrites the cell's route, fills the probe metadata from this
     emitter's own page profile (PA-0001), and delegates to the shared assertion, so no
     verdict derivation, oracle call, comparison or fail-closed branch is duplicated
     (PA-0003/PA-0021) and that shared module is unchanged. A test demonstrates the mismatch
     the adapter exists for, rather than asserting it in prose only.
- Reason: `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3 step 2 and its own reasoning for assigning
  full depth to this stack — "Phase 1's hard-shape work on `php_current` is directly portable
  here once it exists, whereas assigning full depth to Node/Express or FastAPI would mean
  re-deriving those shapes from scratch on an unrelated stack". It is also the prerequisite
  for L-P3.3c (the real `puppy-fort-factory/` migration, §4.3 step 6), which this lane
  deliberately does not attempt.
- Scope discipline (per the task brief, checked against the final diff): `fuzzlab/labgen/modules/`,
  `fuzzlab/labgen/emitters/php_current/`, `node_express`, `python_fastapi` and
  `fuzzlab/labgen/schema.py` are **all untouched** — the `Cell` IR needed no new field (the
  render-only metadata this port needs lives in the emitter's page profiles, the same split
  `php_current` uses). The two shared files this lane does touch are its own stack's
  (`emitters/php_laravel/*`) plus one additive `EMITTER_REGISTRY` entry in
  `fuzzlab/labgen/cli.py`, without which §4.3 step 3's `--check` requirement is not
  demonstrable.
- Files:
  - `fuzzlab/labgen/emitters/php_laravel/modules.py` (new), `…/templates/**` (new: 16
    fragments), `…/identifier_sqli.py` (new)
  - `fuzzlab/labgen/emitters/php_laravel/__init__.py` (shape map, page profiles, composition
    assembly, view emission, `context_depth` guard), `…/stack_env.py` (`view` file role)
  - `fuzzlab/labgen/cli.py` (`EMITTER_REGISTRY` += `php_laravel`)
  - `lab/manifests/phase3_php_laravel_sample.yaml` (2 → 20 cells)
  - `tests/test_labgen_php_laravel_harder_shapes.py` (new, 60 tests),
    `tests/test_labgen_php_laravel.py` (three L-P3.3a tests updated — see below)
  - `CHANGELOG.md`, `ERROR_LOG.md`, `docs/ARCHITECTURE.md`,
    `docs/components/01-target-lab/{requirements.md,change-control.md}`
- Tests: new `tests/test_labgen_php_laravel_harder_shapes.py` mirrors
  `tests/test_labgen_harder_shapes.py` (L-P1.2b's own file) section for section: inventory
  (including a test that compares this stack's shape set against `php_current`'s **live
  registry**, so "full depth" cannot silently lapse when that emitter grows a shape),
  per-cell derived verdicts, the Laravel idiom each shape renders to, the module fragments'
  authoring-gap guards, PA-0024's whole-collection "render every `php_laravel` cell of every
  manifest" standing test, the conformance tiers, and the oracle adapter. Three tests in
  `tests/test_labgen_php_laravel.py` encoded L-P3.3a's deliberate foundation-only scope and
  were updated rather than deleted: the "XSS not supported yet" assertion is inverted (and a
  genuinely-unsupported shape now carries the declare-unsupported-and-skip check), the
  unknown-op test uses a name that is really unknown (`html_entity_escape` is a registered op
  now), and the hand-kept cell-ID roster is replaced by the derived invariant per PA-0027(b).
  Full suite: **1374 passed, 8 skipped, 2 failed** — the two failures are the pre-existing
  `tests/test_mutation_operators.py` MUT-component ones already logged in `ERROR_LOG.md`
  (2026-09-21), verified as pre-existing via that entry rather than assumed; baseline before
  this lane was 1314 passed with the same two failures.
- Follow-ups (named, not silently deferred): `context_depth` is **not** ported to this stack
  and non-`direct` cells are refused loudly rather than rendered as `direct`;
  `minimal_pair`'s single-registry category map should become pluggable when a third stack
  reaches full depth; `lab-generate` still has no clean CLI error for an emitter/manifest
  stack mismatch (pre-existing, reproduces with `php_current` too). All three are in
  `requirements.md` §8.

### CC-LAB-0043 — L-P1.2b: the harder SQLi/XSS shapes + identifier-SQLi oracle wiring (2026-09-21)
*(Numbered `CC-LAB-0043` rather than the `CC-LAB-0040` this lane claimed "from the top of
this log at authoring time" — by merge time, lanes L-P3.4 (`CC-LAB-0040`), L-P1.4
(`CC-LAB-0041`), and L-P2.5 (`CC-LAB-0042`) had already landed and taken the numbers this
lane also reached for. Reconciled per this project's standing multi-lane policy: keep this
entry's full content, renumber it to the next free number, fix its own internal
`FR-LAB-38` cross-reference (see below, now `FR-LAB-41`); BUG-0025/PA-0027 needed no
renumbering (genuinely free at merge time). This lane's worktree was created from a stale
UI-redesign branch lineage and was recovered onto the live branch tip (fetch + hard reset,
per the sync check in this task's brief) before any work began.)*
- Change: built the "module half" of `docs/LAB_IMPLEMENTATION_PLAN.md` §2.2 (its oracle
  half is `CC-LAB-0032`/L-P1.2a), moving the corpus off textbook `?id=1` value-context
  cells and onto the two shapes the plan's research identified as highest
  value-per-hour, in four pieces:
  1. **New `sink_context.family` values + additive safety-matrix rows.**
     `sql_identifier` (the tainted value *is* a column identifier, e.g.
     `ORDER BY $sort`), `sql_join_alias` (a JOIN alias — a connector position,
     substituted three times in one statement), and `url_javascript_scheme` (a value
     inside a `javascript:` URL). Two new concern IDs — `sql_identifier_substitution`
     (an attacker chooses *which* identifier the query names, needing no syntax break at
     all) and `js_context_break` — and four new ops: `identifier_charset_filter`,
     `identifier_allowlist`, `url_scheme_allowlist`, `attr_value_allowlist`. All 15 rows
     are brand-new `(op, sink_family)` pairs, so per `lab/safety_matrix.yaml`'s own
     append-only rule they land under the **same `version: 1`** — no existing pair's
     meaning changes and a v1 corpus re-derives identically. **`verdict()`'s derivation
     logic is untouched** (task constraint), as is `lab/schemas/safety_matrix.schema.json`
     (the new rows need no schema change — `op`/`sink_family` are open strings by design).
     The two rows that carry the most teaching weight: `(param_bind, sql_identifier) ->
     no_effect` (no dialect can bind an identifier placeholder — the textbook fix is
     *inapplicable*, not omitted) and `(html_entity_escape, url_javascript_scheme) ->
     partial` (correct escaping, wrong context: still VULNERABLE, difficulty raised —
     the D20 binary-verdict mechanism, never a third verdict value).
     `(identifier_charset_filter, *) -> partial` is deliberately not `neutralises`: it
     blocks every syntax-break character and none of the real defect.
  2. **Eight new `php_current` module fragments** (`fuzzlab/labgen/modules/`), following
     Addendum C's composition convention exactly — transforms
     `identifier_charset_filter` (a *guard-statement* transform, a third composition
     shape alongside the `bound`-flag and expression-wrapping ones),
     `identifier_allowlist`, `url_scheme_allowlist`, `attr_value_allowlist`; sinks
     `sql_identifier_order_by`, `sql_join_alias_lookup`, `html_js_url_echo`,
     `html_attribute_unquoted_echo`. Both new SQL sinks branch on `bound` to render a
     real prepared statement that binds an unrelated WHERE value *while the identifier
     stays concatenated* — the generated-code evidence for the matrix row above.
     `_MODULE_SET_BY_SHAPE` gains the four shapes; `_PAGE_PARAMS` gains four illustrative
     pages (`/catalog.php`, `/inventory.php`, `/share_link.php`, `/theme.php`), which are
     **not** claimed as real `puppy-fort-factory/` pages (that app has no
     identifier-position or `javascript:`-URL page to reproduce) and are wired to no
     `lab/ground-truth/` label. One minimal emitter addition: a page profile may set
     `source_override`, because one `(class, family)` shape can be reached by two taint
     origins on two pages (`?theme=` on `/theme.php` vs the stored `bio` on
     `/example/profile.php`) — kept as render-only metadata rather than forking the
     verdict-relevant shape vocabulary. Side effect worth naming: the illustrative
     manifest's `LABGEN-EX-0003` (`xss`/`html_attribute_unquoted`), skipped as unsupported
     since Phase 0, now renders.
  3. **Manifest + conformance.** `lab/manifests/phase1_harder_shapes_sample.yaml`, 13
     cells: each shape authored as a *triple* (no transform → VULNERABLE/trivial; the
     plausible-but-wrong fix → VULNERABLE/easy via `partial`; the context-correct fix →
     SECURE), plus the `param_bind`-at-an-identifier cell. Verdicts are derived, never
     asserted. `fuzzlab lab-generate --check` passes end to end over all 13 (name-leak
     scanner, secret scanner, determinism, minimal pair, Tier 0 `php -l` — `php` is
     present on this host so the lint ran for real, not skipped — and Tier 3 whole-sample
     regeneration). `STATIC_PRECHECK_BY_SHAPE` gains all four shapes as
     **uninformative**; the escaping-mismatch ones are the interesting entries — unlike
     `(xss, html_body)`, where a *missing* `htmlspecialchars()` is a textbook static
     finding, here the escaping is present and only the context is wrong, so a taint
     engine reports clean and its clean scan is evidence of nothing.
  4. **Oracle wiring (the point of L-P1.2a existing).** New
     `fuzzlab/labgen/identifier_sqli_assertion.py`: `build_identifier_sqli_request()` /
     `assert_identifier_sqli_cell()` turn a resolved `Cell` plus the emitter's
     render-only probe metadata into an `IdentifierSqliOracleRequest`, run
     `run_identifier_sqli_oracle()`, and compare its outcome against the cell's
     **derived** verdict (`verdict()` against the pinned matrix — never a hand-asserted
     expectation, NFR-LAB-label-accuracy). Fail-closed with no escape hatch: a mismatch
     *and* an `inconclusive` probe both raise. Plus `IdentifierSqliTier2Oracle`, a
     structurally-typed `conformance.tier2.Tier2Oracle` adapter so these cells run through
     the existing tiered harness rather than a parallel one; it raises rather than
     collapsing `inconclusive` into `False`, which Tier 2's boolean `confirm()` contract
     would otherwise turn into a fail-open. `oracle_wrapper.py` is untouched (task
     constraint); `identifier_sqli_oracle.py` is used as-is, unmodified.
- Impact (other components / project): LAB-internal plus two test-side fixes. No other
  component imports `fuzzlab.labgen` (the oracle/assertion modules are generator-build-time
  tooling, never `fuzzlab.oracle`). `fuzzlab/labgen/__init__.py` re-exports the seven new
  assertion names. No emitter other than `php_current` is touched (node_express,
  python_fastapi, php_laravel and their modules are untouched, per task constraint), and
  `schema.py`'s `Cell` dataclass is **structurally unchanged** — no field added, removed or
  reordered (the log was checked first: L-P2.3's `sink_endpoint` and L-P2.4's `param` had
  already landed, and both are *read* by the new assertion module rather than extended).
  Three existing test files changed: `tests/test_labgen_cli.py` (BUG-0025, below) and
  `tests/test_labgen_php_current.py` + `tests/test_labgen_conformance_static_precheck.py`,
  whose "this shape is unsupported/unregistered" stand-ins were
  `(xss, html_attribute_unquoted)` — now a supported, registered shape — and were moved
  onto an LDAP-filter shape no lane has authored.
- Risk (medium; mitigations): four risks, named rather than implied.
  1. **The `identifier_charset_filter` cells cannot be oracle-confirmed today** (see
     `requirements.md` §8). The filter 400s the CASE-WHEN payload, so both probes come back
     unhealthy and L-P1.2a's prober correctly returns `inconclusive`; confirming them needs
     an *identifier-swap* differential (two bare, legal identifiers, diff the responses) —
     exactly the strategy no sqlmap technique implements. That is a small additive
     `DifferentialMode` on `identifier_sqli_oracle.py`, deliberately **not** done here
     (another lane's module, and this lane has no mandate to change its interface).
     Mitigation: the gap is asserted as a test
     (`test_the_charset_filtered_cell_is_the_documented_case_when_blind_spot`, plus a
     real-HTTP reproduction), the failure message names the cause, and the gate fails
     closed rather than passing the cell.
  2. **The difficulty tier for `param_bind` at an identifier position is `trivial`** even
     though that cell is one of the subtlest in the corpus: `verdict()`'s difficulty score
     counts partially-credited missing concerns plus pipeline length, and a `no_effect` op
     contributes neither. Accepted for now (changing it means changing `verdict()`'s
     derivation, which this task forbids); recorded as an open question, since difficulty
     tiers are corpus metadata later ML work may lean on.
  3. **No oracle covers the escaping-context-mismatch XSS cells.** Assessed rather than
     assumed: `oracle_wrapper` is sqlmap/commix/SSTImap (SQLi/cmdi/SSTI), `nuclei_oracle`
     is path-traversal templates only, so the only existing mechanism that could apply is
     `zap_oracle`'s whole-app scan (which already filters alerts by name). Whether ZAP's
     active scanner recognizes a `javascript:`-URL or unquoted-attribute context at all is
     unknown and must be checked **against the real binary** (PA-0005's convention) — it is
     on-host Tier-2 work, and ZAP is not installed here. No new XSS oracle was written
     speculatively; documented in `identifier_sqli_assertion.py`'s docstring and §8.
  4. **Illustrative, not real, pages** for all four shapes — flagged in the manifest, the
     emitter docstring and here, so a later reader cannot mistake them for reproductions.
- Deliverables:
  - [x] New families + 15 additive safety-matrix rows under v1, `verdict()` untouched — done.
  - [x] Eight module fragments + registry entries + `_MODULE_SET_BY_SHAPE`/`_PAGE_PARAMS`
        wiring + `source_override` — done.
  - [x] `lab/manifests/phase1_harder_shapes_sample.yaml` (13 cells) renders, `--check`
        green, Tier 0 (real `php -l`) and Tier 3 pass — done.
  - [x] `static_precheck` flags for all four shapes — done.
  - [x] `identifier_sqli_assertion.py` + `IdentifierSqliTier2Oracle` + `__init__` exports
        — done.
  - [x] Tests: `tests/test_labgen_harder_shapes.py` (matrix rows, derived verdicts per
        cell, emitter shapes/content, module authoring-gap guards, the PA-0024
        whole-collection "every php_current cell of every manifest renders" regression,
        Tier 0/3, real `--check`) and `tests/test_labgen_identifier_sqli_assertion.py`
        (wiring and every fail-closed path against an injected fake runner, plus four
        *unmocked* real-HTTP end-to-end assertions over local servers modelling the
        vulnerable, allowlisted and charset-filtered pages, per PA-0005) — done.
  - [x] BUG-0025 (a real defect this lane surfaced and fixed) — full protocol done:
        `ERROR_LOG.md` line, `docs/bugs/BUG-0025-*.md` with recurrence review and
        prior-PA failure analysis for PA-0001/PA-0024, new PA-0027, and the PA-0002
        codebase sweep for the class (two instances fixed in `tests/test_labgen_cli.py`;
        the whole-tree counters in `test_labgen_gates.py`/`test_labgen_conformance_tier3.py`
        assessed as correct-granularity and recorded as deliberately unchanged).
  - [ ] An identifier-swap `DifferentialMode` on `identifier_sqli_oracle.py` — out of
        scope here (that module belongs to L-P1.2a); see risk 1 / `requirements.md` §8.
  - [ ] On-host Tier-1/Tier-2 confirmation of any of these cells against the live
        containerized lab, and the ZAP-vs-`javascript:`-URL question — on-host work, out of
        scope for an offline session.
- Effectiveness (assessed 2026-09-21): met this delivery's bar. The two harder shapes are
  now expressible, derivable and renderable end to end, with both halves of every shape
  present (a family that only ever appeared as VULNERABLE would make the family itself the
  label — asserted as a test), and the identifier cells are the first in this project whose
  label is checked at build time by a *tool* oracle rather than by hand — including a real,
  unmocked HTTP pass. Full suite: 1225 passed / 8 skipped / 2 pre-existing unrelated
  `tests/test_mutation_operators.py` failures (confirmed pre-existing by extracting the
  branch tip into a scratch directory and re-running that file there with none of this
  lane's changes present: the same 2 fail, 10 pass).

### CC-LAB-0030 — T-LAB0.9: regression/additive-only build gate + multi-artifact ground-truth columns (Addendum B) (2026-09-21)
*(Numbered `CC-LAB-0030` rather than `CC-LAB-0029` at merge time — this lane's worktree
also diverged onto a stale, unrelated UI-redesign branch lineage before starting;
self-diagnosed via the sync check in this task's own brief and recovered with
`git fetch . claude/trusting-noether-heon0n:refs/remotes/origin/...` + `git reset --hard`
onto the live branch tip before any other work began. It independently claimed
`CC-LAB-0029` too, colliding with lane L-P2.1's identity/ownership graph entry (below),
which merged first — reconciled per this project's standing multi-lane policy: keep both
entries' content, renumber the later-landing one, fix cross-references. No content
changed beyond the number and its own internal FR-LAB reference below (`FR-LAB-27` →
`FR-LAB-28`).)*
- Change: two linked pieces, per `CR-LAB-0001` Addendum B and
  `docs/LAB_IMPLEMENTATION_PLAN.md` §1.1 (T-LAB0.9), landed together as decided
  (option (b) — consumer sweep first, not deferred):
  1. **FUZZ-consumer sweep** (done first, per the plan's explicit decision): read every
     consumer of `fuzzlab.labels.contract.Case`/`GroundTruth` (`.cases`, `.positives()`,
     `.negatives()`, `case_by_id`) across `fuzzlab/harness/` (`integration.py`,
     `scoring.py`, `auto.py`, `multitarget.py`) and `fuzzlab/greybox/run.py` (no consumers
     exist under `fuzzlab/report/`). Finding: none assumes exactly one location per case
     in a way the new fields would break — every consumer keys off the existing
     `url`/`method`/`param`/`vuln_class`/`location`/`source_url` fields directly (e.g.
     `scoring.score()`'s `case.key`, `auto.points_from_ground_truth()`'s per-case
     `source_url` stored-XSS handling); none enumerates "all locations of a case" in a
     way `related_endpoints` could violate. **No harness/report code changed** — the
     sweep confirmed graceful degradation already holds, since the new fields are inert
     to every current call site.
  2. **`Case` extension** (`fuzzlab/labels/contract.py`): added
     `primary_endpoint: str | None`, `primary_role: str | None`,
     `related_endpoints: tuple[dict, ...]`, `flow_variant: str` (default `"direct"`),
     following the Juliet/SARIF one-row-per-finding shape Addendum B adopted (primary
     location = where the untrusted value reaches the dangerous operation, never where
     it's set; `related_endpoints` items are `{"endpoint", "role"}` with role drawn from
     `source | propagator | sanitizer | sink`; `flow_variant` one of `direct |
     same_file_helper | cross_file | stored_second_order | cross_service`). All four are
     additive metadata only — `load_labels()` defaults them when absent so every
     pre-existing case (including the real `lab/ground-truth/labels.json`, left
     otherwise untouched) round-trips unchanged.
  3. **Schema + CSV extension**: `fuzzlab/labels/schemas/labels.schema.json`'s `case`
     `$defs` entry gained the four properties (all optional, `related_endpoints` items
     schema-validated, `primary_role`/`flow_variant` enum-constrained) — confirmed a
     case omitting them still validates (real ground truth), and a bad `flow_variant`
     value is rejected. `lab/ground-truth/expectedresults.csv` gained the four trailing
     columns for every existing row (`primary_endpoint` mirrors `url`, `primary_role` is
     `sink`, `related_endpoints` empty, `flow_variant` `direct` — all single-location
     cases). Confirmed `_load_expected_csv` (uses `csv.DictReader`, reads only
     `case_id`/`expected_vulnerable`) is unaffected by the new columns, as the task's own
     up-front analysis predicted.
  4. **The gate itself**: new module `fuzzlab/labgen/regression_gate.py`, following the
     `gates.py`/`secret_scanner.py`/`fingerprint_gate.py` convention — typed error
     (`RegressionGateError`, an `AssertionError` naming every violation, not just the
     first), no silent pass. Deliberately schema-shaped rather than manifest-shaped: it
     diffs two already-loaded `GroundTruth` snapshots by `case_id`
     (`diff_ground_truth`/`assert_no_regression`), so it needs no generator-emitted
     directory to exist yet (T-LAB0.10's CLI isn't built) and is reusable as-is once that
     CLI's `--check` exists. `check_no_regression(baseline_dir, candidate_dir, *,
     loader=contract.load)` wires directory loading with an injectable `loader` (no
     subprocess involved here, so the injection point is the loader, not a `Runner`, per
     this module's own actual dependency shape). Fails loud on any case ID missing from
     the candidate, any changed page (`url`), or any changed verdict
     (`expected_vulnerable`); a candidate that only *adds* cases passes cleanly
     (additive-only, the whole point).
- Bug found: none — this was pure additive feature work, not a defect fix. No
  `ERROR_LOG.md`/`docs/bugs/`/`docs/PREVENTIVE_ACTIONS.md` entries required (confirmed
  via `check-error-log-bookkeeping.sh`, which flagged nothing).
- Impact (other components / project): FUZZ-touching by design (`CR-LAB-0001` §4 calls
  this out explicitly) but net effect on FUZZ is nil for now — the consumer sweep found
  nothing to change in `fuzzlab/harness/` or `fuzzlab/greybox/`. Any future FUZZ work
  that wants to *use* `related_endpoints` for partial credit (explicitly deferred per
  Addendum B: "could be added later as a scorer change, without a schema migration") is
  unaffected and starts from a clean, already-swept baseline. No other component's
  contracts change.
- Risk (level; mitigation): low. The schema/dataclass change is additive-only and
  covered by round-trip tests against both the real ground truth and a synthetic
  multi-location fixture; the gate's diff logic is covered by unit tests over
  in-memory `GroundTruth` objects (no filesystem dependency) plus directory-loading
  tests against the real `lab/ground-truth/` and deliberately shrunk/altered temp-dir
  fixtures (missing case, flipped verdict) mirroring `test_labgen_gates.py`'s own
  convention.
- Deliverables:
  - [x] FUZZ-consumer sweep across `fuzzlab/harness/`, `fuzzlab/greybox/`,
        `fuzzlab/report/` — done, no consumer needed changes.
  - [x] `Case` extension (`primary_endpoint`/`primary_role`/`related_endpoints`/
        `flow_variant`) in `fuzzlab/labels/contract.py` — done.
  - [x] `fuzzlab/labels/schemas/labels.schema.json` extended, optional/defaulted — done.
  - [x] `lab/ground-truth/expectedresults.csv` gained the four trailing columns — done.
  - [x] `fuzzlab/labgen/regression_gate.py`
        (`RegressionGateError`/`RegressionDiff`/`diff_ground_truth`/
        `assert_no_regression`/`check_no_regression`) — done.
  - [x] Tests: `tests/test_labgen_regression_gate.py` (17 tests: `Case` defaults/explicit
        values, schema round-trip for a multi-location case, schema rejection of a bad
        `flow_variant`, diff logic clean/additive/missing/changed-page/changed-verdict,
        `assert_no_regression` fail-loud with every violation named, `check_no_regression`
        against real ground truth and against shrunk/flipped-verdict fixtures, injected
        loader) — done, all pass.
  - [ ] Wiring `regression_gate.check_no_regression` into a `fuzzlab lab-generate
        --check` CLI — out of scope for this task per the plan (T-LAB0.10, not started;
        this gate is built so that CLI can call it without a rewrite).
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — the gate correctly
  passes the real ground truth against itself and against an additive superset, and
  fails loud (naming the exact case ID and the exact violation kind) on both a shrunk
  and a verdict-flipped fixture, which is the acceptance test the plan itself specifies.
  Full suite 886 passed / 8 skipped / 2 pre-existing unrelated
  `test_mutation_operators.py` failures (baseline at this lane's synced start: 868
  passed / 9 skipped / same 2 failures per the task brief; the +18/-1 shift versus that
  baseline reflects this change's own +17 new tests plus one unrelated shift from other
  lanes merged onto the branch tip before this lane started, not a regression this
  change introduced).

### CC-LAB-0029 — Identity/ownership graph schema + loader (L-P2.1, `CR-LAB-0001` §8) (2026-09-21)
- Change: added the Phase 2 identity/ownership graph — `lab/identities/identities.yaml`
  (named test identities, resource ownership, and `authz_expectations` connecting an
  accessing identity to a target resource and a binary `allowed | denied` outcome, D20's
  binary-verdict convention), its JSON Schema (`lab/schemas/identities.schema.json`), and
  a new loader module `fuzzlab/labgen/identity.py`: frozen dataclasses `Identity`,
  `Resource`, `AuthzExpectation`, a small container dataclass `IdentityGraph` (flat lists
  plus `identity_by_id`/`resource_by_id`/`expectations_for_cell` lookup helpers, mirroring
  `fuzzlab.labels.contract.GroundTruth`'s shape), and `load_identities(path) ->
  IdentityGraph`. Validates against the JSON Schema the same way
  `fuzzlab.labgen.schema.validate_manifest` validates manifests, raising a typed
  `IdentityGraphError` (never a raw `KeyError`/`jsonschema.ValidationError`/YAML error) —
  matching this project's `ManifestError`/`ContractError` naming convention. Adds
  duplicate-`identities[].id`/`resources[].resource_id` checks mirroring
  `fuzzlab.labels.contract.load_labels`'s duplicate-`case_id` pattern, plus
  dangling-reference checks (`resources[].owner`,
  `authz_expectations[].accessing_identity`/`target_resource` must resolve to a
  declared identity/resource) that the JSON Schema alone cannot express. This is
  genuinely novel schema ground for the project (no external prior-art schema to adapt
  — crAPI/vAPI leave ownership implicit, AuthProbe discovers it at runtime; see
  `docs/LAB_IMPLEMENTATION_PLAN.md` §3.1 for the full research trail already recorded
  before this task began) — the concrete first-draft field shape from that doc was
  implemented as-is with no deviation (see Effectiveness below for the one addition:
  cross-reference validation, which the plan's schema sketch did not explicitly call out
  but is a natural extension of "fail loud on a duplicate ID").
  **Critical constraint honored:** decoupled from the manifest/`Cell` IR the verdict
  engine consumes, the same way `lab/patterns/provenance.yaml` is decoupled from
  manifest cells (`CR-LAB-0001` Addendum A) — `fuzzlab/labgen/verdict.py` carries zero
  reference to `identity.py` or this file's content, and is never imported by it. Added
  `fuzzlab/labgen/identity.py` to `fuzzlab/labgen/__init__.py`'s re-exports, matching the
  existing docstring/`__all__` convention.
- Impact (other components / project): none on existing components — this is new,
  additive schema/loader code with no caller yet. The plan names L-P2.2 (a LAB-owned
  session helper, a separate concurrent lane) as the next consumer of `Identity`; this
  lane's dataclasses are kept simple/stable (plain frozen dataclasses, no behavior) so
  L-P2.2 can import `Identity` without coupling to this loader's internals. No change to
  `fuzzlab.labgen.verdict`'s input contract or to any existing manifest/schema file.
- Risk (level; mitigation or accepted-risk justification): low. New, isolated files;
  the one architecturally load-bearing constraint (verdict-engine decoupling) is
  enforced by both a substring test and an AST-import test
  (`tests/test_labgen_identity.py::test_verdict_module_never_imports_identity` /
  `test_verdict_module_has_no_ast_import_of_identity`), mirroring the existing
  `provenance.yaml` leak-check convention (`test_labgen_gates.py`).
- Deliverables:
  - [x] `lab/schemas/identities.schema.json` — JSON Schema for the identity graph
  - [x] `lab/identities/identities.yaml` — first-draft example data (Phase 2 scaffold,
        illustrative `cell_id`s; no real IDOR/BOLA cell exists yet per Addendum E's
        indefinite deferral)
  - [x] `fuzzlab/labgen/identity.py` — dataclasses + `load_identities()` + validation +
        duplicate/dangling-reference checks + `IdentityGraphError`
  - [x] `fuzzlab/labgen/__init__.py` — re-export `identity`
  - [x] `tests/test_labgen_identity.py` — schema validation, round-trip load,
        duplicate-ID checks, dangling-reference checks, verdict-decoupling proof (17
        tests, all passing)
  - [x] `CHANGELOG.md`, this change-control entry, `requirements.md` FR-LAB-27
- Effectiveness (assessed 2026-09-21): met. `python -m pytest -q
  tests/test_labgen_identity.py` — 17 passed. Full suite:
  `python -m pytest -q` — 886 passed, 8 skipped, 2 pre-existing failures in
  `tests/test_mutation_operators.py` (confirmed pre-existing on trunk before this
  change via a stash-and-rerun check, unrelated to `fuzzlab.labgen` — not touched or
  introduced by this change). One deviation from the plan doc's literal first-draft
  schema: `expected_outcome` values are hyphen-free `allowed`/`denied` strings exactly
  as specified (no deviation there), but the loader adds cross-reference validation
  (owner/accessing_identity/target_resource must resolve) beyond what the plan's YAML
  sketch showed — a natural extension of "fail loud on a duplicate ID" the task
  description asked for, not a field-shape change.

### CC-LAB-0031 — T-LAB2.1: wire the covering-array resolver into manifest loading (2026-09-21)
*(Numbered `CC-LAB-0031` rather than `CC-LAB-0029` at merge time — this lane independently
claimed `CC-LAB-0029` too, colliding with both lane L-P2.1's identity/ownership graph
entry above (which kept `CC-LAB-0029`) and lane L-P0.9's regression-gate entry above
(renumbered to `CC-LAB-0030`), both of which merged first. Reconciled per this project's
standing multi-lane policy: keep all three entries' full content, renumber this
later-landing one to the next free number, fix its own internal cross-references
(`FR-LAB-27` → `FR-LAB-29` below). No content changed beyond the numbers.)*
- Change: `fuzzlab.labgen.resolver.expand()` (T-LAB0.3, previously built but "dormant" —
  never called outside its own tests) is now reachable from a manifest. Extended
  `lab/schemas/manifest.schema.json` with an optional `axis_ranges` array, additive
  alongside the existing explicit `cells` array (top-level `anyOf` now requires at
  least one of the two, instead of always requiring `cells`). Each `axis_range` block's
  `factors`/`strength`/`sub_models`/`constraints` map straight onto
  `resolver.expand()`'s own accepted shape (deliberately — this task read the
  resolver's actual function signature first rather than inventing a new shape it
  can't consume); its recognized factor axis names are `class`, `stack_profile`,
  `sink_context_family`, `transform`, `route_method`, `route_path`, each placed into
  the matching `Cell` field, with any non-factor field required as the block's own
  fixed value (fail-closed `ManifestError`, never a silent default) —
  `sink_context_family` additionally requires a `sink_context_neutralizations`
  family->required_neutralizations map, since that field is a function of family, not
  an independent covering-array axis. `fuzzlab.labgen.schema.Manifest.from_dict()`
  expands every `axis_ranges` block (in order) and appends the generated cells after
  any explicit `cells`, before the existing duplicate-`cell_id` check runs over the
  combined list — the emitter and verdict engine downstream are unchanged, since both
  paths produce the identical `Cell` IR.
  While implementing this, found and fixed **BUG-0024**: `resolver.validate_covering_array_config()`
  did not reject a `strength` exceeding the number of factors (nor a `sub_models`
  entry's own `strength` exceeding its own field count) — `covertable.make()` silently
  returns `[]` for that shape rather than raising, which a single-axis `axis_ranges`
  block at the schema's own documented default (`strength: 2`, per `CR-LAB-0001`) would
  have hit silently. Both cardinalities are now checked before `covertable.make()` is
  ever called. See `docs/bugs/BUG-0024-covering-array-strength-exceeds-factor-count.md`
  and `docs/PREVENTIVE_ACTIONS.md` `PA-0026` (supersedes `PA-0010`).
- Impact (other components / project): unblocks Phase 1/2's remaining tasks that
  depend on real cell-count variation (2.2's harder SQLi/XSS shapes, 2.3's χ²/leakage
  build gates, 2.4's stratified splits — `docs/LAB_IMPLEMENTATION_PLAN.md` §2.1's own
  "Depends on" note). No change to `fuzzlab.labgen.emitter`/`emitters/php_current`,
  `fuzzlab.labgen.verdict`, or any other downstream consumer of `Cell` — they see the
  same IR regardless of which manifest path produced it. No change to
  `fuzzlab.labgen.verdict`'s derivation logic itself (out of this task's scope by
  design).
- Risk (level; mitigation): medium — a wrong axis-name mapping or a missing
  fixed-value/neutralization-lookup entry would silently mis-place a Cell field or
  (per BUG-0024) silently produce too few/zero cells. Mitigated by: (a) every
  axis-name-to-Cell-field placement failing closed with `ManifestError` rather than
  defaulting when neither a factor nor a fixed value is present; (b) a test
  (`test_axis_range_factor_names_match_schema_allowlist`) asserting the loader's
  `AXIS_RANGE_FACTOR_NAMES` allowlist and the JSON Schema's own
  `axis_range.factors.properties` keys can never drift apart (PA-0010); (c) the
  BUG-0024 fix closing the specific silent-empty-array path found while building this;
  (d) a byte-for-byte regression requirement on both existing Phase 0 example
  manifests (`example_phase0_scaffold.yaml`, `phase0_real_pages_sample.yaml`), each
  re-asserted by an explicit end-to-end test.
- Deliverables:
  - [x] `lab/schemas/manifest.schema.json`: `axis_ranges` top-level property + new
    `$defs/axis_range` shape — done.
  - [x] `fuzzlab.labgen.schema._expand_axis_range`/`_expand_axis_ranges`, wired into
    `Manifest.from_dict` — done.
  - [x] `fuzzlab.labgen.resolver`: BUG-0024 fix (strength-vs-cardinality checks) — done.
  - [x] Tests: axis-range expansion (cell count, pairwise coverage, fixed-field
    propagation, cell-id generation, determinism, append-after-explicit-cells,
    duplicate-id-across-both-sources, each fail-closed error path, schema-allowlist
    drift guard) in `tests/test_labgen_schema.py`; BUG-0024 regression tests in
    `tests/test_labgen_resolver.py` — done, all passing.
  - [x] Regression: both existing Phase 0 manifests re-verified to load identically
    (`test_load_example_manifest_end_to_end`, new
    `test_load_real_pages_sample_manifest_end_to_end_regression`) — done.
  - [ ] 2.2's actual harder-shape manifest authoring using `axis_ranges` — a separate,
    later lane per §2.1's own scope note.
- Effectiveness (assessed 2026-09-21): effective — full suite green (886 passed, 8
  skipped, plus 2 pre-existing unrelated failures in `tests/test_mutation_operators.py`
  confirmed present on the clean pre-change tree and untouched by this change); new
  axis-range tests pass; both existing manifests' cell counts/IDs unchanged.

### CC-LAB-0032 — L-P1.2a: identifier/alias/connector-position SQLi oracle (sqlmap spot-check + custom prober) (2026-09-21)
*(Numbered `CC-LAB-0032` rather than `CC-LAB-0029` at merge time — this lane independently
claimed `CC-LAB-0029` too, colliding with lane L-P2.1's identity/ownership graph entry, lane
L-P0.9's regression-gate entry (`CC-LAB-0030`), and lane L-P1.1's resolver-wiring entry
(`CC-LAB-0031`), all of which merged first. Reconciled per this project's standing
multi-lane policy: keep all entries' full content, renumber this later-landing one to the
next free number, fix its own internal `FR-LAB-27` cross-reference (see below, now
`FR-LAB-30`). No content changed beyond the numbers.)*
- Change: per `docs/LAB_IMPLEMENTATION_PLAN.md` sec 2.2's "spot-check first, then build
  the fallback regardless" decision, this task did both, in order:
  1. **Spot-check.** Installed the real sqlmap (`apt-get install -y sqlmap`, 1.8.4, none
     previously on this host) and ran it against three hand-built PHP 8.4 + PDO/SQLite
     test cases, at `--level=5 --risk=3 --technique=BEUSTQ`:
     - An unsanitized `ORDER BY $sort` (no character filtering) — sqlmap **found it**, via
       its built-in "boolean-based blind ... ORDER BY or GROUP BY clause (JSON)" heuristic
       (appends a `CASE WHEN ... END` after the identifier; works because nothing stops
       trailing SQL syntax).
     - An unsanitized JOIN alias, `... JOIN items $alias ON i1.id = $alias.id` — sqlmap
       **found it** too (time-based blind), but only because its payload's trailing `--
       <rand>` comment truncates the rest of the line, including the second substitution
       of the same tainted value in the `ON` clause — comment-based statement truncation,
       not identifier-aware detection.
     - A column-name parameter restricted to `^[A-Za-z0-9_]+$` (application-level
       character allowlist; no space/quote/paren/comment reaches the query) where the real
       defect is that the *value* is not checked against a real column allowlist
       (`?col=secret` manually confirmed to leak the `secret` column) — sqlmap
       **reported "all tested parameters do not appear to be injectable"** (8879/8879
       requests rejected by the allowlist with HTTP 400; none of sqlmap's payloads are
       built from identifier-safe characters alone). This is the decisive case: it
       confirms the plan's research finding (sqlmap GitHub issues #97/#2459/#490 — no
       identifier-substitution payload strategy exists in sqlmap) for exactly the shape
       the harder SQLi cells (a later, separate lane, L-P1.2b) will emit, even though the
       two looser cases above happened to be catchable through incidental syntax leakage.
  2. **Fallback (built regardless, per the plan's decision).** Added
     `fuzzlab/labgen/identifier_sqli_oracle.py`, a third, independent oracle sibling to
     `oracle_wrapper.py`/`nuclei_oracle.py` (never imported by, and never modifying,
     either): `run_identifier_sqli_oracle()` fires a baseline probe plus a
     boolean-differential TRUE/FALSE pair (`(CASE WHEN (<condition>) THEN <col_a> ELSE
     <col_b> END)`, substituted whole into the declared identifier position) and classifies
     by diffing either the response bodies (`response_diff` mode — row order/value
     differences) or elapsed time (`timing_blind` mode — a `SLEEP()` gated behind the same
     CASE-WHEN, for endpoints whose body never reveals row-level differences). Returns the
     same fail-closed `confirmed_vulnerable | confirmed_secure | inconclusive` contract as
     `oracle_wrapper.Verdict`/`nuclei_oracle.NucleiVerdict`, as its own independent
     `IdentifierSqliVerdict` enum. DBMS phrasing lives behind a small `_DialectPhrasing`
     registry (`SqlDialect.MYSQL` implemented per task scope; `POSTGRESQL`/`SQLITE` named
     in the enum with a `DialectNotImplementedError` rather than guessed syntax, and the
     registry is the only thing a future dialect addition touches — no control-flow
     rewrite). Reuses only `oracle_wrapper.assert_loopback` directly (this module fires
     HTTP requests via an injected `HttpRunner`, not a subprocess, so it has no textual
     need for `locate_tool`/`ToolNotFoundError`, though `fuzzlab.labgen` still re-exports
     both from `oracle_wrapper` for any caller that wants them). **PA-0025 applied
     proactively** (not as a bug fix — designed in from the start, since the spot-check's
     own third case is exactly this failure mode): a "no differential" result is never
     read as secure unless an independent baseline probe (a definitely-valid identifier
     value) came back healthy first, and two probes that both error out identically (the
     allowlist-rejection pattern the spot-check produced) are classified `inconclusive`,
     never `confirmed_secure`.
- Impact (other components / project): none outside LAB. Read-only against
  `oracle_wrapper.assert_loopback`; `oracle_wrapper.py`, `nuclei_oracle.py`, and every
  emitter/module file are untouched (out of scope for this lane — L-P1.2b, a later,
  separate lane, will actually author the harder SQLi shapes in `php_current` that this
  oracle will validate). `fuzzlab/labgen/__init__.py` re-exports the new module's public
  names.
- Risk (level; mitigation): low — new, additive module; no change to any other module's
  behavior. The main risk for a caller is misreading a `response_diff` "secure" verdict
  when `column_a`/`column_b` happen to sort/render identically for reasons unrelated to
  the injection (documented in the request dataclass's docstring: callers must pick two
  columns whose values actually differ across rows). Mitigated by requiring a healthy
  baseline before any verdict, and by shipping both a response-diff and a timing-blind
  mode so a caller whose endpoint doesn't reveal row-level differences in the body still
  has a working oracle.
- Deliverables:
  - [x] Sqlmap spot-check against three real test cases, documented in the module
        docstring and here — done.
  - [x] `fuzzlab/labgen/identifier_sqli_oracle.py` (`SqlDialect`, `DifferentialMode`,
        `IdentifierSqliVerdict`, `IdentifierSqliOracleRequest`,
        `run_identifier_sqli_oracle`, `default_http_runner`) — done.
  - [x] 24 offline tests (every classification branch — response-diff and timing-blind,
        including the PA-0025 "both probes error identically" case — via an injected fake
        HTTP runner; argv/URL construction; session-refresh/bounded-retry parity with
        `oracle_wrapper`/`nuclei_oracle`) — done, all pass.
  - [x] 3 real, unmocked integration tests (PA-0005) exercising `default_http_runner`'s
        actual `requests` call against real local HTTP servers (vulnerable/secure/
        unreachable) — done, all pass; not skip-guarded (no external tool binary is
        involved, unlike `nuclei_oracle`'s skip-guarded suite).
  - [x] `fuzzlab/labgen/__init__.py` export additions — done.
  - [ ] PostgreSQL/SQLite dialect phrasing — explicitly out of scope (task said "at least
        MySQL"); the registry is structured so adding them is additive.
  - [ ] Wiring this oracle into an actual `php_current` identifier-context SQLi cell —
        L-P1.2b, a separate, later lane per the plan's dependency map.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — the spot-check
  reproduced the plan's research finding against the real, currently-installed sqlmap
  binary (not just inferred from 2012-era GitHub issues), and the new oracle's
  classification logic is exercised for every branch by injected-runner tests, including
  the exact allowlist-rejection failure mode the spot-check surfaced, and the real
  `default_http_runner` code path is proven end to end by 3 unmocked integration tests
  (PA-0005). Full suite: 896 passed / 8 skipped / 2 pre-existing unrelated
  `test_mutation_operators.py` failures (confirmed pre-existing by stashing this change
  and re-running against branch tip unchanged: same 2 failures, 10 passed in that file
  alone).

### CC-LAB-0033 — LAB-owned session helper for build-time oracle confirmation (lane L-P2.2, §3.2) (2026-09-21)
*(Numbered `CC-LAB-0033` rather than `CC-LAB-0029` at merge time — this lane independently
claimed `CC-LAB-0029` too, colliding with lanes L-P2.1 (`CC-LAB-0029`), L-P0.9
(`CC-LAB-0030`), L-P1.1 (`CC-LAB-0031`), and L-P1.2a (`CC-LAB-0032`), all of which merged
first. Reconciled per this project's standing multi-lane policy: keep all entries' full
content, renumber this later-landing one to the next free number, fix its own internal
`FR-LAB-27` cross-reference (see below, now `FR-LAB-31`). No content changed beyond the
numbers.)*
- Change: added `fuzzlab/labgen/identity_session.py`. Some manifest cells (stored
  cross-site-scripting and other second-order sinks) need build-time oracle
  confirmation (`oracle_wrapper.py`) to submit a payload as one known,
  generator-controlled test identity and observe the sink under another (or the
  same) identity — this module is the narrow session-holder that makes that
  possible: `IdentitySessionStore` holds one cookie jar per identity id it was
  constructed with, `login(identity_id) -> Session` logs in (or re-logs-in,
  replacing rather than duplicating that identity's jar entry) and returns the
  resulting session, and `refresh_session_for(identity_id)` returns a
  zero-argument callable of exactly `oracle_wrapper.SessionRefresh`'s shape
  (`Callable[[], Mapping[str, str]]`) so it slots directly into any
  `*OracleRequest.refresh_session` field with no adapter. Cookie extraction
  (splitting a `Set-Cookie`/`Cookie` response-header key's leading `name=value`
  pair out, passing every other header through) mirrors, rather than reinvents,
  the convention `oracle_wrapper._resolve_session` already uses on the consumer
  side. `fuzzlab.labgen.identity.Identity` (lane L-P2.1, concurrent, not yet
  merged into this worktree) is imported opportunistically with a fallback: if
  unavailable, a local `IdentityLike` `Protocol` (an `id: str` field) is used
  instead, so this module can be built and tested independently of that lane —
  the module docstring notes swapping to the real import once L-P2.1 merges,
  which should need no other change since `Identity` already satisfies the
  Protocol structurally. Explicitly out of scope, and left out on purpose (see
  module docstring): re-auth on expiry, JWT handling, auto-exclusion of auth
  endpoints, and anything defending against an unknown/adversarial target —
  those are the toolkit's own, separate Session-manager component's concerns,
  not this helper's; this helper only ever talks to identities the generator
  itself declared (an unknown identity id raises `UnknownIdentityError`, and a
  duplicate identity id at construction raises `DuplicateIdentityError`, fail
  loud rather than silently coexisting). Re-exported from
  `fuzzlab/labgen/__init__.py` (`IdentitySessionStore`, `IdentitySession` (the
  module's `Session`, aliased to avoid a name clash with any future `Session`
  export), `IdentityLike`, `UnknownIdentityError`, `DuplicateIdentityError`).
- Impact (other components / project): none outside LAB. Read-only against
  `oracle_wrapper`'s `SessionRefresh` type/shape and `_resolve_session`
  convention (imported directly only in this module's own test suite, to prove
  composition); `oracle_wrapper.py` itself is untouched. No `fuzzlab.oracle`
  (runtime detection oracle) involvement, matching every other `labgen`
  build-time module. Depends structurally (duck-typed, not by hard import) on
  lane L-P2.1's future `Identity` shape (an `id: str` field) — no other
  coupling.
- Risk (level; mitigation): low. This is a narrow, offline, fully
  fake-transport-tested helper with no network or subprocess access of its own
  (it delegates the actual login call to an injected `LoginTransport`, the same
  dependency-injection convention `oracle_wrapper.py` uses for its `Runner`).
  The one real risk — silently drifting from `oracle_wrapper.SessionRefresh`'s
  contract — is mitigated by a dedicated test
  (`test_composes_with_oracle_wrapper_resolve_session_convention`) that feeds
  this module's output straight through `oracle_wrapper._resolve_session` and
  asserts the split comes out identically to a hand-built `Cookie`/headers pair.
- Deliverables:
  - [x] `fuzzlab/labgen/identity_session.py` — done
  - [x] `tests/test_labgen_identity_session.py` (11 cases: cookie-splitting,
    other-header passthrough, two-identity isolation, refresh-not-duplicate on
    a second `login()`, unknown/duplicate-identity errors, and the
    `oracle_wrapper`-composition check) — done, all passing
  - [x] `fuzzlab/labgen/__init__.py` exports — done
  - [x] `CHANGELOG.md` line, this change-control entry, `FR-LAB-31` — done
- Effectiveness (assessed 2026-09-21): met intent — `python -m pytest -q`
  (full suite) passes 880/880 non-skipped tests including all 11 new ones (8
  pre-existing skips, unrelated to this change); two pre-existing failures in
  `tests/test_mutation_operators.py` were confirmed present before this change
  too (reproduced on a clean stash of this worktree's diff) and are unrelated
  to LAB/`identity_session` — out of this lane's scope to fix.

### CC-LAB-0034 — `fuzzlab lab-generate` CLI (T-LAB0.10, L-P0.10) (2026-09-21)
*(Numbered `CC-LAB-0034` rather than `CC-LAB-0029` at merge time — this lane
independently claimed `CC-LAB-0029` too, colliding with lanes L-P2.1, L-P0.9,
L-P1.1, L-P1.2a, and L-P2.2, all of which merged first. Reconciled per this
project's standing multi-lane policy: keep all entries' full content, renumber
this later-landing one to the next free number. At merge time, confirmed the
resolver-hook gap this entry names below is already closed (transparent, no
CLI change needed, since L-P1.1 moved axis-range expansion into
`Manifest.from_dict()` itself); the regression-gate gap is deliberately left
open — see the updated Deliverables below.)*
- Change: added `fuzzlab/labgen/cli.py` (`main(argv) -> int`, parsing `--manifest
  <path> --out <dir> [--emitter NAME] [--check]`) and a one-line `lab-generate`
  branch in `fuzzlab/cli.py`'s existing subcommand dispatch, following the exact
  pattern every other subcommand (`web`/`session`/`crawl`/.../`report`) already
  uses. `--manifest`/`--out` load a manifest via `fuzzlab.labgen.schema
  .load_manifest` and render every cell the selected emitter supports via
  `fuzzlab.labgen.conformance.tier3.render_whole_sample` (the existing helper
  that already drives a real `Emitter` over a whole cell set), writing the
  result to `--out`. The emitter is looked up by name from a small
  `EMITTER_REGISTRY: dict[str, type[Emitter]]` (default `"php_current"`), never
  hardcoded, so a future emitter (Phase 3, built by parallel lanes) registers
  itself without a CLI rewrite. `--check` runs, in order: the name-leak scanner
  (`gates.scan_generated_tree_for_name_leaks`), the secret scanner
  (`secret_scanner.scan_tree_for_secrets`, Gitleaks-backed), a real-emitter
  regenerate-and-diff determinism check
  (`conformance.tier3.regenerate_and_diff_emitter`), the minimal-pair checker
  (`minimal_pair.check_minimal_pair`), and conformance Tier 0 (lint +
  minimal-pair diff) and Tier 3 (whole-lab regeneration) again as their own
  registered step, per the task's explicit instruction to register both
  separately from the standalone minimal-pair/determinism steps. Every gate
  failure is collected (not fail-fast) and printed with `--check` returning
  exit code 1 naming every failing gate; a clean tree exits 0.
- Design notes/deviations from the literal task brief, made explicit rather than
  silently substituted:
  - **Resolver wiring (L-P1.1) not yet landed as of this lane's own authoring** --
    `fuzzlab.labgen.schema.load_manifest` did no axis-range expansion at that time.
    By merge time, L-P1.1 had landed and moved that expansion *into*
    `Manifest.from_dict()` itself (not a separate hook this CLI needs to call) --
    so `load_manifest` now expands `axis_ranges` transparently and this CLI needed
    no code change at all to pick it up, exactly the "upgrades automatically"
    convention this lane's own docstring anticipated (mirroring
    `conformance.tier0.get_minimal_pair_checker`'s same convention). Confirmed by
    a new merge-time test loading a manifest with an `axis_ranges` block through
    this CLI's own `render_manifest`.
  - **Minimal-pair checker wired against a generic self-pair, not manifest-declared
    twins.** `fuzzlab.labgen.minimal_pair`'s own test module explicitly documents that
    it does not attempt "manifest-level twin pairing" (two different cell_ids, e.g.
    the example manifest's `LABGEN-EX-0001`/`0002`, legitimately emit different
    handler names and are not a valid input to it). This CLI instead pairs each
    supported cell against `dataclasses.replace(cell, transform=Pipeline(()))` --
    the *same* cell identity with its transform pipeline emptied, exactly the
    fixture shape `tests/test_labgen_minimal_pair.py`'s own positive fixture uses --
    so the check works for any manifest, not only one that happens to author
    explicit vulnerable/secure twin cells.
  - **Regenerate-and-diff wired against the real emitter (Tier 3), not
    `gates.regenerate_and_diff`.** `gates.regenerate_and_diff` only proves
    determinism for the Phase-0 *scaffold* renderer
    (`fuzzlab.labgen.subseed.render_cell_stub`), not a real `Emitter` -- it is not
    meaningful against this CLI's actual output. `conformance.tier3
    .regenerate_and_diff_emitter` is the emitter-level counterpart that already
    exists for exactly this purpose and is used instead; it doubles as this
    change's Tier 3 registration (item 4 of the task brief), so it is invoked once
    as the named "regenerate-and-diff determinism check" step and again as the
    explicit "conformance Tier 3" step, both real, non-redundant in intent (the
    task brief lists them as two separate line items).
  - **`fingerprint_gate.py` deliberately not wired**, per the task brief's own
    instruction: it needs a real multi-stack corpus (Phase 3) to mean anything.
  - **The regression/additive-only gate (L-P0.9) was not wired as of this lane's
    own authoring** (its module did not exist in this worktree yet) and **remains
    deliberately unwired at merge time**, even though L-P0.9's
    `fuzzlab.labgen.regression_gate.check_no_regression` has since landed on
    trunk: that function needs a *candidate ground-truth directory*
    (`labels.json`/`injection-points.json`/`expectedresults.csv`-shaped, per
    `fuzzlab.labels.contract.load`'s cross-validated contract), and no
    Cell-to-GroundTruth converter exists yet to derive that shape from a
    rendered manifest's cells. Building one under time pressure inside this
    merge, rather than as its own reviewed deliverable, is exactly the kind of
    improvisation this project's process is meant to prevent -- so the lane's
    `# TODO(L-P0.9)` marker is kept (renamed `# TODO(L-P0.9-integration)` to
    reflect that L-P0.9 itself has landed and only the CLI-side wiring remains),
    and this is flagged here as a real, still-open follow-up rather than
    silently built or silently dropped.
- Impact (other components / project): none outside this component -- pure
  addition of a CLI entry point over already-built, already-tested pieces. No
  change to `fuzzlab.labgen.schema`, `.gates`, `.secret_scanner`, `.minimal_pair`,
  `.emitter`, `.emitters.php_current`, or `.conformance` (all read-only imports).
- Risk (level; mitigation): low. The CLI is read-only with respect to the target
  (D11 unaffected -- it writes local files only, sends no traffic) and every gate
  it calls already has its own dedicated test coverage; this change adds
  end-to-end coverage of the wiring itself, not the gates' own logic.
- Deliverables:
  - [x] `fuzzlab/labgen/cli.py` (`main`, `EMITTER_REGISTRY`, `render_manifest`,
    `run_checks`) — done.
  - [x] `fuzzlab/cli.py` `lab-generate` dispatch branch + usage line — done.
  - [x] 11 end-to-end tests (`tests/test_labgen_cli.py`): clean-tree pass, one
    per wired gate's own known-bad fixture (name-leak, secret, determinism,
    minimal-pair, Tier 0 lint), unknown-emitter/missing-manifest error paths,
    and a generic-weakened-twin-pairing check against a hand-built cell reusing
    `tests/test_labgen_minimal_pair.py`'s own `_base_cell` helper — done.
  - [x] Resolver wiring (L-P1.1) — confirmed transparent at merge time, no CLI
    code change needed (`Manifest.from_dict()` expands `axis_ranges` internally).
  - [ ] Regression/additive-only gate (L-P0.9) — genuinely still open at merge
    time: needs a Cell-to-GroundTruth converter that does not exist yet (see the
    design-notes paragraph above); flagged as a real follow-up, not silently
    built or dropped. Marker renamed `# TODO(L-P0.9-integration)`.
- Effectiveness (assessed 2026-09-21): effective for the gates actually wired —
  `fuzzlab lab-generate --check` passes clean on the real example manifest and
  fails loud (exit 1, naming the gate) when any wired gate's own known-bad
  fixture is injected via a test-double emitter wrapper; full repo test suite
  green after merge (see the merge commit for the exact pass count). 2
  pre-existing failures in `tests/test_mutation_operators.py` confirmed
  unrelated to this change and present before it, in a different lane's
  component. The regression-gate integration gap above is real and open, not
  assessed as met.

### CC-LAB-0035 — Node/Express emitter, Tier-A depth (L-P3.1) (2026-09-21)
*(Numbered `CC-LAB-0035` rather than `CC-LAB-0029` at merge time — this lane
independently claimed `CC-LAB-0029` too, colliding with lanes L-P2.1, L-P0.9,
L-P1.1, L-P1.2a, L-P2.2, and L-P0.10, all of which merged first. Reconciled per
this project's standing multi-lane policy: keep all entries' full content,
renumber this later-landing one to the next free number, fix its own internal
`FR-LAB-27` cross-reference (see below, now `FR-LAB-33`). No content changed
beyond the numbers.)*
- Change: added `fuzzlab/labgen/emitters/node_express/` — the second concrete
  `Emitter` implementation (after `php_current`), covering Tier-A scope only
  (`sqli`/`sql_numeric_literal`, `sqli`/`sql_string_literal`,
  `xss`/`html_body` — the same three shapes `php_current` proves), per the
  Phase-3 pacing decision ("stack 1 full depth, stacks 2-3 Tier-A-only") in
  `docs/LAB_IMPLEMENTATION_PLAN.md` §4. Introduces a self-contained JS
  module-composition inventory (`node_express/modules.py` + `templates/`),
  this component's first `StackEnv` (`node_express/stack_env.py`, per
  `CR-LAB-0001` Addendum D) with a digest-pinned Node 22 LTS base image, and
  this component's first `route`-category accumulator
  (`NodeExpressEmitter.render_route_accumulator`, building `app.js` from the
  whole supported-cell set sorted by `cell_id`, deliberately separate from
  `Emitter.render(cell)`'s per-cell contract — see the emitter module's own
  docstring for why). Ships a real npm-registry-resolved
  `package-lock.json` (`express@4.22.3`, `mysql2@3.24.4`) and a digest-pinned
  `Dockerfile` (`NODE_ENV=production` set per the framework-debug-page
  research). New manifest `lab/manifests/phase3_node_express_sample.yaml`
  (8 cells, 4 vulnerable/secure pairs). Did not touch `emitter.py`'s ABC,
  `php_current`, or any existing file under `fuzzlab/labgen/modules/`, per
  this lane's scope discipline — `node_express` owns its entire module
  registry independently.
- Impact (other components / project): none outside LAB. No change to
  `verdict.py`'s derivation logic, `fuzzlab.labgen.schema`'s `Cell`/
  `SinkContext` IR, or any other lane's files. Establishes the accumulator/
  per-cell-render split future routed emitters (Laravel's `routes/web.php`,
  L-P3.3a) are expected to follow — flagged in both this entry and
  `requirements.md`'s FR-LAB-33 for whichever lane next needs it, since the
  generic `fuzzlab.labgen.conformance.tier3` module (a sibling lane's file,
  not modified here) has no built-in concept of an accumulator's
  whole-corpus cardinality yet.
- Risk (level; mitigation or accepted-risk justification): low. The base
  image digest was read from a Docker Hub image-layer page during authoring
  (2026-09-21) rather than confirmed via a live `docker pull` (no Docker
  daemon in this build environment) — the Dockerfile documents the exact
  re-pin command to run before a real build, so this cannot silently drift
  unnoticed. A CycloneDX SBOM was not generated (`syft` not installed in
  this environment) — the intended command is documented in
  `requirements.md` rather than skipped silently, and no image build
  actually happened, so nothing ships without an SBOM that wasn't already
  going to need re-verification before a real build anyway.
- Deliverables:
  - [x] `StackEnv` for `node_express` (digest-pinned base image,
    `is_multi_file=True`, `route` accumulator) — done
  - [x] Tier-A module inventory (3 shapes, ported from `php_current`'s
    categories) — done
  - [x] Conformance pass: Tier 0 (`node --check`, skip-guarded) + Tier 3
    (whole-manifest regenerate-and-diff, per-cell + accumulator) against
    `lab/manifests/phase3_node_express_sample.yaml` — done
  - [x] Digest-pinned base image + real `package-lock.json` — done
  - [ ] CycloneDX SBOM via `syft` — blocked: `syft` not installed in this
    build environment; command documented, not run
  - [x] Per-module unit tests + end-to-end per-cell tests (supports/
    determinism/verdict-cross-check/`node --check`) — done, 68 new tests,
    full suite green
- Effectiveness (assessed 2026-09-21): all 68 new tests pass, including the
  real `node --check` lint pass (node v22.22.2 available in this build
  environment) and the real Tier-3 whole-manifest regenerate-and-diff for
  both per-cell controllers and the route accumulator. The full project
  test suite was re-run and stayed green with only additions (see
  `CHANGELOG.md` for the exact count). Not yet assessed: real container
  build/boot (no Docker daemon here) and live oracle confirmation (Tier 1/2,
  explicitly out of this lane's scope per the task) — those remain
  `[design]`-tier claims until a lane with on-host resources exercises them.

### CC-LAB-0036 — Python/FastAPI emitter, Tier-A depth (L-P3.2) (2026-09-21)
*(Numbered `CC-LAB-0036` rather than `CC-LAB-0029` at merge time — this lane
independently claimed `CC-LAB-0029` too, colliding with lanes L-P2.1, L-P0.9,
L-P1.1, L-P1.2a, L-P2.2, L-P0.10, and L-P3.1, all of which merged first.
Reconciled per this project's standing multi-lane policy: keep all entries'
full content, renumber this later-landing one to the next free number. No
content changed beyond the number.)*
- Change: added `fuzzlab/labgen/emitters/python_fastapi/`, the second Phase-3
  stack emitter (alongside `php_current`), Tier-A depth per `CR-LAB-0001` Addendum
  C's stack-pacing decision. Covers the same three well-documented value-context
  shapes `php_current` proves (`sql_numeric_literal`/`sql_string_literal` SQLi,
  `html_body` XSS), ported to FastAPI + SQLAlchemy + Jinja2 idiom, deliberately
  excluding identifier/alias/connector-position SQLi and escaping-context-mismatch
  XSS (deferred, per the pacing decision). Architecture:
  - A fully independent module-composition system
    (`fuzzlab/labgen/emitters/python_fastapi/modules.py` + its own
    `templates/{sources,transforms,sinks,complexities,scaffold}/*.j2`), mirroring
    `fuzzlab.labgen.modules`'s architecture but not extending it — no cross-import
    between this and `php_current`/`fuzzlab.labgen.modules`, per the Phase 3 lane
    map's "no stack's emitter package imports another's" rule. Op-name vocabulary
    (`identity`/`param_bind`/`html_entity_escape`) is intentionally shared with
    `lab/safety_matrix.yaml` and `php_current` — the safety matrix is stack-agnostic
    by design, so no new matrix entries were needed.
  - `StackEnv` (Addendum D's schema: `language`/`framework`/`framework_version`/
    digest-pinned `base_image`/`workdir`/`entrypoint_cmd`/`is_multi_file`/
    `scaffold_files`/`accumulators`/`file_roles`) defined package-locally
    (`fuzzlab.labgen.schema` does not yet have a shared `StackEnv` as of this
    lane's build; `schema.py` is a lane-map "shared read-only file" other Phase-3
    lanes should not edit concurrently without coordinating, so promoting this to
    a shared location is left to a future cross-cutting task, not this lane).
  - **No `route` accumulator module** — per `CR-LAB-0001` Addendum D's
    FastAPI-specific research, a one-time static discovery scaffold
    (`app/main.py`, using `pkgutil.iter_modules()`/`importlib` over a `routers/`
    package, sorted by module name for determinism) is used instead; `render()`
    returns exactly one per-cell router file, and the scaffold is a separate,
    once-per-build output (`STACK_ENV.scaffold_files` / `render_scaffold_files()`),
    since `fuzzlab.labgen.emitter.Emitter`'s ABC has no per-stack-scaffold method
    yet (a real interface gap, not closed here — `emitter.py` is out of this
    lane's scope per the task brief).
  - **FastAPI debug-page correctness requirement, met**: the scaffold constructs
    `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` — FastAPI serves
    these by default regardless of any debug flag (`docs/LAB_IMPLEMENTATION_PLAN.md`
    Phase 3's framework-debug-page research), so this is asserted by a live
    `TestClient`-backed test (404 on all three routes), not left as an
    unverified docstring claim.
  - Digest-pinned base image: `python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e`,
    fetched live against the Docker Hub registry API's `docker-content-digest`
    response header on 2026-09-21 (this environment's egress allowlist covers
    `registry-1.docker.io`/`auth.docker.io`). Exact-pinned `requirements.txt`
    lockfile for the generated app's own dependencies (fastapi 0.141.1, uvicorn
    0.53.0, sqlalchemy 2.0.54, jinja2 3.1.6, pydantic 2.13.5 — versions confirmed
    current against PyPI's JSON API the same day), per this task's own brief
    ("a `requirements.txt` with pinned versions is fine if this project doesn't
    otherwise standardize on Poetry/pip-tools" — it doesn't; `pyproject.toml` uses
    compatible-release ranges for fuzzlab's own deps, a different artifact).
    CycloneDX SBOM generation via `syft` is documented (intended command in this
    package's module docstring) but not run — `syft` isn't installed in this
    build environment and this task does not install new system tools to get one,
    per the task brief's own "skip, don't block" instruction.
  - New sample manifest `lab/manifests/phase3_python_fastapi_sample.yaml` (six
    cells, three vulnerable/secure pairs, illustrative synthetic routes — this
    stack has no real hand-built app to migrate, unlike `php_laravel`).
  - Conformance: passes Tier 0 (`python -m py_compile` lint — new
    `lint_python`/`python_available` added to `fuzzlab.labgen.conformance.tier0`
    alongside the existing `lint_php`/`php_available`, same skip-guarded
    convention; minimal-pair diff via `_naive_minimal_pair_check` directly,
    since `fuzzlab.labgen.minimal_pair`'s real checker is PHP-comment-syntax-
    specific by its own documented scope — not yet extended to other languages,
    a documented, not-yet-attempted extension point, not a defect) and Tier 3
    (whole-manifest regenerate-and-diff, via the existing stack-agnostic
    `fuzzlab.labgen.conformance.tier3` machinery, unmodified).
  - New optional dependency extra `labgen-python-fastapi` in `pyproject.toml`
    (`fastapi`/`uvicorn`/`sqlalchemy`/`httpx`) for the `TestClient`-backed
    end-to-end tests, skip-guarded when absent (PA-0005) — this emitter's own
    render/module code needs no new fuzzlab dependency (only `jinja2`, already a
    main dependency).
- Impact (other components / project): none outside LAB. No changes to
  `fuzzlab/labgen/emitter.py`'s ABC, `fuzzlab/labgen/emitters/php_current/`, any
  existing file under `fuzzlab/labgen/modules/`, or `fuzzlab/labgen/schema.py` —
  fully additive, per this lane's scope discipline and the Phase 3 lane map's
  cross-lane coordination notes. `lab/safety_matrix.yaml` required no new entries
  (op vocabulary already covers this stack's shapes). `docs/ARCHITECTURE.md`
  updated to record the second emitter landing.
- Risk (level; mitigation): low. New, isolated package; no shared file touched
  except additive entries in `pyproject.toml` (`[project.optional-dependencies]`,
  `[tool.setuptools.package-data]`) and `fuzzlab/labgen/conformance/tier0.py`
  (two new functions, existing ones untouched). Verified with a live
  `TestClient` smoke test (not just source inspection) that the rendered app
  actually starts, routes resolve, `/docs`/`/redoc`/`/openapi.json` 404, and the
  vulnerable/secure sink pairs behave as their derived verdicts say.
- Deliverables:
  - [x] `fuzzlab/labgen/emitters/python_fastapi/` (`__init__.py`, `modules.py`,
        `templates/{sources,transforms,sinks,complexities,scaffold}/*.j2`) — done.
  - [x] `StackEnv` + static-discovery scaffold (`app/main.py`) with
        `/docs`/`/redoc`/`/openapi.json` disabled — done, test-asserted live.
  - [x] Digest-pinned base image + `requirements.txt` lockfile — done.
  - [x] SBOM generation command documented; not run (`syft` unavailable) — done
        (documented), generation itself a follow-up.
  - [x] `lab/manifests/phase3_python_fastapi_sample.yaml` — done.
  - [x] Tier 0 (`python -m py_compile` + minimal-pair) and Tier 3 (whole-manifest
        regenerate-and-diff) conformance passes — done.
  - [x] Per-module unit tests (`tests/test_labgen_python_fastapi_modules.py`) +
        end-to-end/`TestClient` tests (`tests/test_labgen_python_fastapi_sample.py`)
        + conformance-suite tests (`tests/test_labgen_python_fastapi_conformance.py`)
        — done, 60 new tests, all passing (2 skip-guarded on the optional
        `labgen-python-fastapi` extra, which is installed in this build
        environment so they ran and passed here).
  - [ ] Real puppy-fort-factory-style page migration — not applicable to this
        stack (no real hand-built FastAPI app exists to migrate; only
        `php_laravel`, Phase 3's other PHP lane, has a migration deliverable,
        per D20 §7.2).
  - [ ] Identifier/alias/connector-position SQLi, escaping-context-mismatch XSS
        on this stack — explicitly deferred per the Tier-A pacing decision.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar. Every sample
  cell's derived verdict matches its intended label via the same shared
  `verdict()`/`lab/safety_matrix.yaml` every other stack's cells go through (no
  stack-specific verdict logic exists or was added); a live `TestClient` run
  confirms the generated app actually starts and serves; `python -m py_compile`
  confirms every generated `.py` file (per-cell and scaffold) is syntactically
  valid; Tier 3 confirms byte-identical regeneration across the whole sample
  manifest. Full suite: 929 passed / 8 skipped, same 2 pre-existing unrelated
  `test_mutation_operators.py` failures (last logged baseline, `CC-LAB-0028`:
  868 passed / 9 skipped / same 2 failures) — no reduction, only additions.

### CC-LAB-0037 — `php_laravel` StackEnv + route accumulator + conformance pass (lane L-P3.3a) (2026-09-21)
*(Numbered `CC-LAB-0037` rather than `CC-LAB-0029` at merge time — this lane
independently claimed `CC-LAB-0029` too, colliding with lanes L-P2.1, L-P0.9,
L-P1.1, L-P1.2a, L-P2.2, L-P0.10, L-P3.1, and L-P3.2, all of which merged
first. Reconciled per this project's standing multi-lane policy: keep all
entries' full content, renumber this later-landing one to the next free
number. No content changed beyond the number.)*
- Change: added `fuzzlab/labgen/emitters/php_laravel/`, the second PHP emitter
  (`docs/LAB_IMPLEMENTATION_PLAN.md` §4.3 steps 1/3/4/5 — steps 2 and 6 are
  separate later lanes, L-P3.3b and L-P3.3c, explicitly not attempted here):
  - `stack_env.py` — `StackEnv` (`CR-LAB-0001` Addendum D's schema):
    `language="php"`, `framework="laravel"`, `framework_version="13.32.0"`,
    `base_image="php:8.3-fpm-alpine@sha256:62f4c401dc970c352223dd018e4f2c9d1c480e07f67351cd31bec2d1f8a8fb42"`
    (both resolved for real, not guessed — `laravel/framework` via a real
    `composer update --no-dev --no-scripts --no-install` against Packagist,
    the base image digest via `docker buildx imagetools inspect
    php:8.3-fpm-alpine`, both run 2026-09-21), `is_multi_file=True`,
    `scaffold_files`/`accumulators`/`file_roles`. `StackEnv.env_file_content()`
    forces `APP_DEBUG=false`/`APP_ENV=production` in the generated `.env` —
    a correctness requirement per the task brief and D20 (Laravel's Ignition
    debug page leaks full stack traces plus every env var, including DB/API
    credentials, when debug mode is on; mirrors the FastAPI lane's `/docs`
    disable), not an optional follow-up.
  - `route_accumulator.py` — the `route`-category accumulator module
    (`routes/web.php`), cardinality `accumulator` per Addendum D:
    `RouteAccumulator.render_file()` always sorts fragments by cell ID at
    call time, regardless of the input mapping's own iteration order, per
    Addendum D's explicit "never by append/iteration order" rule. Kept
    outside `Emitter.render()`'s own per-cell return value and out of
    `fuzzlab/labgen/conformance/tier3.py`'s shared `render_whole_sample`
    (which raises on two cells emitting the same path — correct for
    `php_current`'s one-file-per-cell model, but structurally unable to
    merge multiple cells into one accumulator path without a change that
    belongs with whichever lane needs it for a second accumulator-bearing
    stack); `assemble_routes_file()` is this lane's own whole-manifest
    assembly step, exercised directly by this lane's tests. See that
    module's docstring for the full reasoning and the flagged gap.
  - `__init__.py` — `LaravelEmitter(Emitter)`, supporting exactly one shape
    (`sqli`/`sql_numeric_literal`, Eloquent `DB::select()` idiom, raw
    concatenation vs. `param_bind`) — deliberately not the full module
    inventory (that is L-P3.3b, which ports `php_current`'s shapes plus
    Phase 1's harder identifier/alias/connector-position SQLi and
    escaping-context-mismatch XSS shapes once this foundation exists).
    Every module here is new to this directory; nothing is imported from or
    added to `fuzzlab/labgen/modules/` (that package is `php_current`'s
    plain-PHP idiom) and `php_current`'s own files are untouched, per this
    lane's scope discipline.
  - `stack/composer.json` + `stack/composer.lock` — a real lockfile (74
    packages, generated against Packagist, not hand-written) pinning the
    stack's base Laravel dependency set. `stack/README.md` records the SBOM
    gap: `syft` was not available on this build host (`which syft` — not
    found), so CycloneDX SBOM generation was skipped per this task's own
    documented fallback; the intended command is recorded there.
  - `lab/manifests/phase3_php_laravel_sample.yaml` — a new, deliberately
    minimal manifest (one vulnerable/secure twin pair, mirroring
    `example_phase0_scaffold.yaml`'s illustrative SQLi pair shape) — enough
    to prove the scaffold renders and passes the conformance suite, not a
    real page and not the full shape inventory, per the task brief's own
    "keep this manifest deliberately minimal" instruction.
  - `tests/test_labgen_php_laravel.py` — 19 new tests: `StackEnv` pinning/
    debug-mode assertions, basic render/determinism/unsupported-shape
    checks mirroring `test_labgen_php_current.py`'s shape, route-accumulator
    sort-order determinism, Tier 0 (`php -l`, skip-guarded per PA-0005) and
    Tier 3 (`regenerate_and_diff_emitter`) conformance passes against the
    new sample manifest, plus a dedicated accumulator-regeneration
    determinism test (the accumulator-specific extension of the Tier-3
    pattern noted above).
- Impact (other components / project): none outside LAB. Read-only against
  `fuzzlab.labgen.emitter`'s types, `fuzzlab.labgen.schema`, and
  `fuzzlab.labgen.conformance.{tier0,tier3}` (used, not modified) — no other
  component's contracts change. `php_current` and `fuzzlab/labgen/modules/`
  are untouched, per scope discipline. Unblocks lane L-P3.3b (module
  inventory) and, downstream of that, L-P3.3c (real-app migration); also
  gives L-P3.4 (`stack` field + fingerprint-gate wiring) a second real stack
  name (`php_laravel`) once one more Phase-3 stack lane lands alongside it.
- Risk (level; mitigation): low. New, additive emitter/manifest/test code in
  a new directory; no shared module, schema, or conformance-suite file was
  modified. The one structural gap flagged rather than silently worked
  around — `conformance/tier3.py`'s `render_whole_sample` cannot yet merge
  multiple cells into one accumulator path — is fully documented in
  `route_accumulator.py`'s docstring and worked around locally (this lane's
  own `assemble_routes_file`/dedicated test) rather than papered over; a
  future accumulator-bearing stack lane (or a dedicated follow-up) should
  extend `tier3.py` itself once a second such stack needs it, rather than
  each stack re-inventing its own workaround indefinitely.
- Deliverables:
  - [x] `StackEnv` for `php_laravel` (pinned framework version, digest-pinned
        base image, `is_multi_file=True`, debug mode forced off) — done.
  - [x] `route`-category accumulator module, sorted by cell ID at render
        time — done.
  - [x] Conformance-suite pass: Tier 0 (lint) + Tier 3 (whole-lab
        regeneration) against a new minimal manifest — done, fully
        exercised offline for real.
  - [x] Digest-pinned base image + `composer.lock` — done (real lockfile,
        74 packages).
  - [ ] CycloneDX SBOM via `syft` — not done; `syft` unavailable on this
        build host, intended command documented in `stack/README.md`.
  - [x] Tests (19 new, all passing) mirroring `test_labgen_php_current.py`'s
        shape, scaled to this lane's foundation-only scope — done.
  - [ ] Full module inventory (harder SQLi/XSS shapes) — explicitly out of
        scope for this lane (L-P3.3b).
  - [ ] `puppy-fort-factory/` migration — explicitly out of scope for this
        lane (L-P3.3c).
- Effectiveness (assessed 2026-09-21): met this lane's own foundation-only
  bar — `StackEnv`, the route accumulator, and one trivial shape render,
  lint clean, and regenerate byte-identically (both the per-cell files via
  the shared Tier-3 driver and the accumulator file via this lane's own
  dedicated determinism test); debug mode is verifiably off in the
  generated `.env`. Full suite: 888 passed / 8 skipped / 2 pre-existing,
  unrelated `test_mutation_operators.py` failures (same 2 as `CC-LAB-0027`'s
  own recorded baseline) — 19 new tests added, zero regressions.

### CC-LAB-0038 — `sink_endpoint` distinct from `injection_endpoint` (L-P2.3) (2026-09-21)
*(This lane's worktree was created onto a stale, unrelated branch lineage with no
`fuzzlab/labgen/` directory present at all; self-diagnosed via the task's own sync
check and recovered with `git fetch . claude/trusting-noether-heon0n:refs/remotes/
origin/claude/trusting-noether-heon0n` + `git reset --hard` onto the live branch tip
before any work began. Numbered `CC-LAB-0038` rather than the `CC-LAB-0029` this
lane's own report expected as "simply the next number" — by merge time, eight other
concurrent lanes (L-P2.1, L-P0.9, L-P1.1, L-P1.2a, L-P2.2, L-P0.10, L-P3.1, L-P3.2,
L-P3.3a) had already claimed and reconciled numbers up through `CC-LAB-0037`.
Reconciled per this project's standing multi-lane policy: keep this entry's full
content, renumber it to the next free number, fix its own internal `FR-LAB-27`
cross-reference (see below, now `FR-LAB-36`). See also the merge-time addendum below,
closing this entry's own flagged schema gap.)*
- Change: extended `fuzzlab.labgen.schema.Cell` with an optional
  `sink_endpoint: Route | None = None` field (`docs/LAB_IMPLEMENTATION_PLAN.md` §3.3),
  reusing the existing `Route` type. `None` (the default) means same-endpoint —
  today's entire corpus, and `Cell.from_dict` only sets it when a manifest cell
  actually declares `sink_endpoint`, so every pre-existing cell is unaffected.
  Populated only for stored/second-order cells (e.g. a stored-XSS cell whose
  injection point, `route`, is a profile-bio write endpoint, distinct from
  `sink_endpoint`, the profile-view page that actually echoes and executes the
  payload). `fuzzlab.labgen.verdict`'s derivation logic is untouched by design —
  `sink_endpoint` is render/tracking metadata, the same category as `identity.py`'s
  data, never a verdict input.
  Confirmed `fuzzlab.labgen.emitters.php_current`'s existing `read_stored_field`
  source module (already built, `CC-LAB-0022`) composes with a `sink_endpoint` cell
  by hand-rendering a stored-XSS test cell end to end. That composition surfaced one
  genuine, narrow gap (not a new module category, matching this project's own
  "extend, don't rebuild" convention): `PhpCurrentEmitter.render()` resolved its
  `_PAGE_PARAMS` page profile — and its `// Real page:` comment — from `cell.route`
  unconditionally, which is correct for a same-endpoint cell but wrong for a
  `sink_endpoint` cell, since php_current only ever renders the sink side of a
  stored-XSS shape (the `ReadStoredFieldSource` module's own docstring already says
  so). Fixed with one `render_route = cell.sink_endpoint or cell.route` line and its
  two downstream uses — no new module, no restructuring.
- Impact (other components / project): LAB only. `verdict.py` untouched (see above).
  `lab/schemas/manifest.schema.json` was deliberately **not** touched by this lane,
  per its own scope discipline — its new tests exercise
  `Cell.from_dict`/`Manifest.from_dict(..., validate=False)` directly rather than
  the full YAML+jsonschema `load_manifest()` path, so a manifest author who wants
  to declare `sink_endpoint` in an actual YAML manifest file could not yet do so
  through the validated loader. **Closed at merge time**: added a `sink_endpoint`
  property to the cell definition in `lab/schemas/manifest.schema.json`
  (`"$ref": "#/$defs/route"`, mirroring `route`'s own shape exactly, optional —
  `additionalProperties: false` on the cell schema meant the field was otherwise
  silently rejected by `load_manifest()`'s validation step). This is a field
  addition, not a restructuring, so it stays easy to reconcile with the concurrent
  `schema.py`/`manifest.schema.json` lanes (L-P1.1's `axis_ranges`, already merged;
  L-P2.4's parameter-encoding, not yet merged).
- Risk (level; mitigation): low. Purely additive dataclass field with a safe default;
  regression-tested against both existing Phase 0 manifests to confirm byte-identical
  render output. The one behavior change inside `php_current` (page-profile
  resolution) is exercised by the same regression tests and only changes behavior
  when `sink_endpoint` is set, which no existing cell does.
- Deliverables:
  - [x] `Cell.sink_endpoint: Route | None = None` in `fuzzlab/labgen/schema.py` — done
  - [x] `php_current` render()'s page-profile/comment resolution made sink_endpoint-aware — done
  - [x] Hand-built stored-XSS test cell round-trips + renders via `php_current` — done
  - [x] Regression: both existing manifests still load/render identically — done
  - [x] `docs/components/01-target-lab/requirements.md` — new `FR-LAB-36` — done
  - [x] `lab/schemas/manifest.schema.json` `sink_endpoint` property — closed at merge
        time (see Impact above); a new regression test asserts a manifest
        declaring `sink_endpoint` now loads through the full validated
        `load_manifest()` path, not just `validate=False`.
- Effectiveness (assessed 2026-09-21): full suite green for this change (8 new tests
  in `tests/test_labgen_sink_endpoint.py`, all passing; 877 passed / 8 skipped overall,
  2 pre-existing unrelated failures in `tests/test_mutation_operators.py` confirmed
  present before this change too, outside LAB/this lane's scope). Full suite re-run
  after the merge-time schema fix; see the merge commit for the exact count.

### CC-LAB-0040 — Stack axis in `labels.json` + fingerprint-independence gate wired into `--check` (§4.4, lane L-P3.4) (2026-09-21)
- Change: `docs/LAB_IMPLEMENTATION_PLAN.md` §4.4's two halves, now that three stack
  emitters (`php_current`, `node_express`, `python_fastapi`) plus `php_laravel`'s
  foundation have landed:
  1. **Check-first finding (no redundant field added).** `fuzzlab.labgen.schema.Cell`
     already carries `stack_profile: str` as a **required** field; `lab/schemas/
     manifest.schema.json` requires it per cell; it is a recognized `axis_ranges` factor
     axis (`AXIS_RANGE_FACTOR_NAMES`); `fuzzlab.labgen.subseed` already mixes it into
     every per-cell sub-seed; and all four emitters' sample manifests populate it
     meaningfully and distinctly (`php_current` in `phase0_real_pages_sample.yaml` /
     `example_phase0_scaffold.yaml`, `node_express` in `phase3_node_express_sample.yaml`,
     `python_fastapi` in `phase3_python_fastapi_sample.yaml`, `php_laravel` in
     `phase3_php_laravel_sample.yaml`). §4.4's "add `stack` (or `stack_profile`) to
     `Cell`" was therefore **already satisfied**, and was deliberately *not* re-added in
     another spelling — a second field of the same meaning is exactly the two-writers
     divergence PA-0003/PA-0021 forbid.
  2. **The real gap: the ground-truth side.** `fuzzlab.labels.contract.Case` and
     `fuzzlab/labels/schemas/labels.schema.json` had no per-case stack field at all, so
     the stack axis stopped at the manifest and never reached `labels.json` (§4.4's
     other half, and the artifact any downstream leakage/fingerprint analysis actually
     reads). Added an optional `stack: str | None` to `Case`, read in `load_labels()`,
     and an optional `stack` string property (`minLength: 1`, so an empty stack name
     fails closed rather than being recorded as meaningless) to the schema's `case`
     `$defs`. **Inline**, per the settled research decision in the plan's §4 (OWASP
     Benchmark's `expectedresults.csv`; CrossVul/CVEfixes/DiverseVul/ICVul), not a
     separate analysis-only file. Additive and inert: absent → `None`, no scorer keys on
     it, not part of `Case.key`, and `lab/ground-truth/labels.json` (the hand-built PHP
     app, single-stack by construction) is left untouched — backfilling it belongs to
     the D20 §7.2 `php_laravel` migration that retires it, not here.
  3. **Gate wiring (`fuzzlab/labgen/cli.py`).** `run_checks()` gained step 8: the
     fingerprint-independence gate (`fuzzlab.labgen.fingerprint_gate
     .run_fingerprint_gate`, `CR-LAB-0001` §3), a required step whenever — and only
     whenever — the loaded manifest's cells span >= `MIN_STACKS_FOR_FINGERPRINT_GATE`
     (2) distinct `stack_profile` values. Two new small public helpers, so both halves
     are testable and neither is buried in the gate step: `corpus_records_from_manifest()`
     (the single adapter between `Cell` and the gate's deliberately schema-independent
     `{stack, vuln_class}` record shape — the gate keeps depending on nothing from
     `schema.py`) and `fingerprint_gate_config()` (derives `expected_classes`/
     `expected_stacks` from the corpus at hand, never placeholders).
     `fingerprint_gate.py`'s own chi-square logic was **not** touched.
  Three deliberate design calls in that wiring, each documented at its site:
  - **Corpus scope = all `manifest.cells`, not `_supported_cells()`.** Fingerprint
    independence is a property of the *authored corpus's* metadata shape, and a
    multi-stack manifest is by construction never fully renderable by one emitter, so
    filtering by this emitter's `supports()` would measure the wrong population.
  - **`min_classes_per_stack` = `min(3, <distinct classes in corpus>)`.**
    `CR-LAB-0001` §3/§4's canonical 3 is applied as a *ceiling*: today's manifests
    author only two classes (`sqli`, `xss`), so a flat 3 would fail every real manifest
    for a reason unrelated to fingerprint leakage. The enforced property is "every stack
    carries *every* class the corpus has, up to 3", which is the actual anti-fingerprint
    requirement and tightens by itself as more classes land. `min_stacks_per_class`
    stays at the canonical 2.
  - **Single-stack manifests skip the gate, loudly.** With one stack, "every class on
    >= 2 stacks" is unsatisfiable and the chi-square contingency table is degenerate, so
    the step prints an explicit SKIPPED line naming the stacks found and why — not a
    silent no-op (and not a failure: single-stack is not a leakage problem). Every
    existing sample manifest is single-stack, so no existing `--check` invocation changes
    behavior.
  - **Fail-closed on a missing optional dependency.** `MissingStatsDependencyError`
    (scipy / the `labgen-stats` extra) is caught separately and becomes a `--check`
    failure naming the extra — never a silent pass, per PA-0021/PA-0025's fail-closed
    doctrine.
- Impact (other components / project): FUZZ consumes `fuzzlab.labels.contract` — no
  consumer change needed, for the same reason `CC-LAB-0030`'s sweep established: every
  consumer keys off `url`/`method`/`param`/`vuln_class`/`location`, and the new field is
  inert to all of them (re-checked: no reader of `Case` enumerates its fields or
  round-trips it). No emitter module inventory or template file was touched, and
  `fingerprint_gate.py` is unchanged.
- Risk (level; mitigation or accepted-risk justification): **Low-to-moderate.**
  (a) `--check` gains a step that can newly fail a build — mitigated by it being
  inapplicable (and explicitly skipped) for every manifest that exists today, so the
  only builds it can fail are genuinely multi-stack ones, which is its purpose.
  (b) The `min_classes_per_stack` ceiling is a deliberate, documented relaxation of a
  canonical value; **accepted risk**, with the mitigation that it is expressed as
  `min(canonical, corpus)` rather than a hardcoded 2, so it re-tightens automatically
  and cannot silently stay loose once a third class lands. (c) The stack↔verdict half of
  the gate is not fed from the CLI (no `verdict` key in the records), because a cell's
  verdict is derived from `lab/safety_matrix.yaml` via `fuzzlab.labgen.verdict` at a
  repo-relative default path that **no production code currently loads** — reading it in
  the CLI would make `--check` silently cwd-dependent. The gate's own documented and
  tested "verdict key absent → skip that check" path handles it, and this is recorded as
  an open deliverable rather than hidden: wiring it needs a cwd-independent
  safety-matrix location (or an explicit `--safety-matrix` argument), which is a
  separate change.
- Deliverables:
  - [x] Confirm `Cell.stack_profile` already exists and is populated by all four
        emitters' sample manifests — done; no redundant field added.
  - [x] Optional per-case `stack` in `fuzzlab.labels.contract.Case` + `labels.schema.json`.
  - [x] `corpus_records_from_manifest()` / `fingerprint_gate_config()` +
        `run_checks()` step 8 in `fuzzlab/labgen/cli.py`.
  - [x] Tests: two-stack balanced (gate passes) and confounded (gate fails loud)
        manifest fixtures, built by relabelling the real `phase0_real_pages_sample.yaml`
        cells onto a second stack; single-stack skip-with-reason; scipy-absent
        fail-closed; end-to-end `--check` nonzero exit on a confounded manifest on disk;
        record-level fixtures (`_balanced_independent_corpus`,
        `_skewed_but_covered_corpus`) **reused** from
        `tests/test_labgen_fingerprint_gate.py` rather than re-authored, per this lane's
        scope discipline. `tests/test_labels_contract.py` gained the `stack`
        present/absent/empty-string cases plus a "real ground truth still loads" guard.
  - [x] Full suite run: 1170 passed, 8 skipped, plus 2 **pre-existing, unrelated**
        failures in `tests/test_mutation_operators.py` (MUT component) reproduced on a
        pristine detached worktree of this branch's tip — see `ERROR_LOG.md`'s entry;
        not caused by and not in scope for this lane.
- Effectiveness (assessed pending): pending — becomes measurable once a genuinely
  multi-stack manifest ships as a lab artifact (today the gate's live path is exercised
  only by tests, since every sample manifest is single-stack by design).

### CC-LAB-0041 — Stratified splits + de-duplication + diversity artifact (§2.4, lane L-P1.4) (2026-09-21)
*(Numbered `CC-LAB-0041` rather than `CC-LAB-0040` at merge time — this lane
independently claimed `CC-LAB-0040`, colliding with lane L-P3.4's stack/fingerprint-gate
entry above, which merged first. Reconciled per this project's standing multi-lane
policy: keep both entries' full content, renumber this later-landing one, fix its own
internal `FR-LAB-38` cross-reference (see below, now `FR-LAB-39`). This lane's worktree
also started on a stale, unrelated UI-redesign branch lineage; self-diagnosed via the
sync check in the task brief and recovered by re-fetching and hard-resetting onto the
live branch tip, confirming `fuzzlab/labgen/resolver.py`'s merged axis-range/
covering-array wiring, before any other work began.)*
- Change: added `fuzzlab/labgen/corpus_analysis.py`, read-only corpus-analysis tooling
  over an already-built cell set, implementing all three pieces of
  `docs/LAB_IMPLEMENTATION_PLAN.md` §2.4:
  1. `stratified_split()` — a train/holdout `CorpusSplit` stratified by `vuln_class`
     and **grouped by generating-rule ID**, so near-duplicate cells never land on both
     sides. Per §2.4's explicit instruction it **reuses** `leakage_probe`'s own
     cross-validation grouping rather than re-deriving one: that construction
     (`StratifiedGroupKFold(n_splits=..., shuffle=True, random_state=...)`) was
     extracted from `leakage_probe._cross_val_auc` into a new
     `leakage_probe.grouped_cv()`, which `_cross_val_auc` now calls — so the package has
     exactly one grouped-CV constructor with two callers (PA-0003/PA-0021), not a copy.
     `fold` selects which of `n_splits` folds is the holdout so the whole fold set is
     reachable. The "no group on both sides" property is re-checked as a post-condition
     and raised on (`CorpusSplitError`) rather than trusted.
  2. `duplication_report()` — the corpus's near-duplicate definition, made explicit as
     `DuplicateSignature`: `(vuln_class, sink_context.family,
     sorted(required_neutralizations), ordered transform-shape)`, **regardless of cell
     ID** (and of `route`/`sink_endpoint`/`param`/`stack_profile`) — plus the
     duplicate/near-duplicate rate, the redundant-cell count, and every duplicate
     group's cell IDs.
  3. `diversity_report()` / `corpus_report()` / `write_corpus_report()` — class ×
     transform × verdict counts plus marginals, emitted as a deterministic,
     key-sorted-JSON build **ARTIFACT**. `fuzzlab lab-generate` gained
     `--corpus-report <path>` (plus `write_corpus_report_artifact()`), on a code path
     deliberately independent of `--check`'s pass/fail suite so an informative report
     can never fail a build.
- Design decisions (judgement calls, stated because they are not facts):
  - **Why a new module** rather than an addition to `gates.py` or `fingerprint_gate.py`:
    the three pieces share one concept (the generating-rule group) that no existing
    module owns, and two of the three are deliberately non-gating, so folding them into
    a gate module would blur exactly the gate-vs-artifact distinction §2.4 draws.
    `leakage_probe.py` is the (non-gating) metadata-leakage probe and is owned by
    another lane; it is *reused*, not extended into.
  - **Generating-rule ID is derived from the near-duplicate signature.** No `Cell` field
    records which rule produced a cell (`Cell` is out of this lane's scope by
    instruction) and `cell_id` prefixes are per-manifest namespaces (`LABGEN-RP-`), too
    coarse to group by — every cell in a manifest would be one group and no split would
    be possible. The signature is the best available proxy and is exactly the right one
    here: grouping by it makes "no near-duplicate spans the split" true by construction.
    Documented as the single place to change if `Cell` ever gains a real `rule_id`.
  - **`transform-shape` is the ordered op tuple**, not a multiset/length:
    `verdict.verdict()` is explicitly order-sensitive over `Pipeline.ops`, so
    order-differing pipelines are different cells. Conversely
    `required_neutralizations` is sorted, being a set of concerns, so authoring order
    cannot split one group in two.
  - **`stack_profile` and `route` are excluded** from the signature, matching §2.4's
    candidate tuple. Excluding `stack_profile` makes groups larger, the conservative
    direction for a split (it can only reduce leakage); stack-vs-class balance stays
    `fingerprint_gate.py`'s job. Excluding `route` is what makes the existing corpus's
    real near-duplicates visible at all — `phase0_real_pages_sample.yaml`'s
    `/product.php` and `/blog_post.php` cells are deliberately the same shape on two
    different real pages; a route-sensitive definition would report a 0% duplicate rate
    and say nothing.
  - **An `(op, sink_family)` pair the safety matrix does not cover** is recorded as
    `UNDERIVABLE_VERDICT` and counted, not raised. `verdict()` fails loud by design and
    a *gate* should let that propagate, but an informative artifact must not take a
    build down — while an authoring gap must still be visible rather than silently
    dropped from the counts. The matrix is an explicit optional argument, never loaded
    implicitly, so the artifact cannot report verdicts derived under a different matrix
    than the corpus was built with.
  - Typed errors at the boundary per PA-0021: `CorpusSplitError` for an unsplittable
    corpus, `MissingSplitDependencyError` (mirroring
    `fingerprint_gate.MissingStatsDependencyError`) instead of a raw `ImportError` when
    scikit-learn is absent. scikit-learn is imported lazily *inside*
    `stratified_split()`, so the de-duplication and diversity reports — the parts a
    build artifact needs — work without it.
- Impact (other components / project): none outside `fuzzlab/labgen/`. New module plus
  two small, additive edits: `leakage_probe.py` (one extracted `grouped_cv()` helper;
  `probe_leakage`'s behavior is byte-for-byte unchanged — the same construction, same
  arguments, now via a named function) and `cli.py` (one new opt-in flag, default off;
  omitting it leaves the CLI's behavior identical). Nothing reads or writes a `Cell`,
  the verdict engine, or any emitter — read-only analysis, per this lane's scope
  discipline. `docs/ARCHITECTURE.md` updated (the Phase-0/1 generator-tooling
  paragraph).
- Risk (level; mitigation or accepted-risk justification): low. The new module is
  additive and has no callers in any build gate; the one behavior-adjacent edit
  (`leakage_probe.grouped_cv` extraction) is a pure refactor covered by the existing
  `tests/test_labgen_leakage_probe.py` suite, which still passes unchanged. `cli.py` is
  touched by concurrent lanes, so the edit was kept to one flag, one import line, and
  one small function to keep merges easy. Accepted risk, named rather than designed
  around: with today's tiny fixture corpora, `StratifiedGroupKFold` emits sklearn's
  "least populated class in y has only N members" `UserWarning` (the real-pages
  manifest has only 2 `xss` cells in 2 groups). It is not suppressed — the warning is
  true and informative, and `CorpusSplit` carries per-side class counts so a caller can
  see exactly how far stratification actually held. It will stop firing once §2.1/§2.2
  produce a corpus with real per-class volume, which is also when the split's fold
  count becomes worth calibrating.
- Deliverables:
  - [x] `fuzzlab/labgen/corpus_analysis.py` (split + dedup + diversity artifact) — done
  - [x] `fuzzlab/labgen/leakage_probe.py` `grouped_cv()` extraction (one shared
        grouped-CV construction, two callers) — done
  - [x] `fuzzlab/labgen/cli.py` `--corpus-report <path>` artifact wiring, independent of
        `--check` — done
  - [x] Tests: `tests/test_labgen_corpus_analysis.py` (46 new tests, fixtures = the real
        `lab/manifests/*.yaml` example manifests, with the whole-collection sweeps
        parametrized over `glob("*.yaml")` so a newly-added manifest is covered
        automatically per PA-0024) — done, all passing. Full suite
        (`python -m pytest -q`): **1203 passed, 8 skipped**, plus the 2 pre-existing
        `tests/test_mutation_operators.py` failures, confirmed pre-existing by running
        that file in a detached checkout at this branch's HEAD *without* this change
        (identical failures) — a MUT-component concern in
        `fuzzlab.mutation.semantics.SemanticsValidator.preserves`, not touched here, and
        already recorded as pre-existing by `CC-LAB-0039`.
  - [x] `docs/components/01-target-lab/requirements.md` `FR-LAB-39` — done
  - [x] `docs/ARCHITECTURE.md` generator-tooling paragraph — done
  - [x] CHANGELOG.md line — done
- Effectiveness (assessed 2026-09-21): validated against the real corpus, not only
  synthetic fixtures. On `lab/manifests/phase0_real_pages_sample.yaml` the dedup report
  finds exactly the two deliberate near-duplicate pairs the manifest's own comments
  describe (`LABGEN-RP-0001`/`0003` and `0002`/`0004`, the `/product.php` and
  `/blog_post.php` cells) — 8 cells, 6 distinct signatures, a 25% near-duplicate rate —
  and a 3-fold split provably keeps each of those pairs on one side. The diversity
  artifact shows both `VULNERABLE` and `SECURE` verdicts across the manifest's
  minimal-pair structure with zero underivable verdicts, and the same artifact bytes are
  produced on a re-run.

### CC-LAB-0039 — Parameter location/encoding axis (§3.4, lane L-P2.4) (2026-09-21)
*(Numbered `CC-LAB-0039` rather than `CC-LAB-0029` at merge time — this lane
independently claimed `CC-LAB-0029` too, colliding with nine other concurrently
landed lanes (L-P2.1, L-P0.9, L-P1.1, L-P1.2a, L-P2.2, L-P0.10, L-P3.1, L-P3.2,
L-P3.3a). Reconciled per this project's standing multi-lane policy: keep this
entry's full content, renumber it to the next free number, fix its own internal
`FR-LAB` cross-reference (see below, now `FR-LAB-37`). `schema.py`'s merge with
lane L-P2.3 (also merged first, also touching `Cell`) was a clean, non-overlapping
field addition — both `sink_endpoint` and `param` now coexist on `Cell` exactly as
each lane designed them.)*
- Change: added the parameter location/encoding axis from
  `docs/LAB_IMPLEMENTATION_PLAN.md` §3.4:
  - `fuzzlab.labgen.schema.ParamSpec` (new frozen dataclass: `location` in
    `query | body | header | cookie | json`, `encoding` in `raw |
    url_encoded | double_url_encoded | base64`, both validated in
    `__post_init__`/`from_dict`) and a new optional `Cell.param: ParamSpec`
    field (defaults to `query`/`raw` so every existing cell, which omits the
    field, keeps meaning exactly what it meant). Put on `Cell`, not
    `SinkContext` -- see the design-decision note below.
  - `lab/schemas/manifest.schema.json`: a matching optional `param` object
    on `$defs/cell` (`additionalProperties: false`, both sub-fields as JSON
    Schema `enum`s), so a manifest can declare the axis and invalid values
    are rejected at validation time, not silently accepted.
  - `fuzzlab.labgen.oracle_wrapper`: closed two real gaps found while
    checking the existing header/cookie/encoding handling per the task
    instructions (`ParamLocation`/`_resolve_session`/`_build_sstimap_argv`):
    (1) `ParamLocation` only had `QUERY`/`BODY`/`HEADER` -- `COOKIE`/`JSON`
    added, with new `_mark_cookie_param`/`_mark_json_param` marking helpers
    (SSTImap's own `-P` sweep already supports a `C` category per Spike
    003's `QBHC`; only the wrapper's marker-substitution side was missing).
    JSON has no SSTImap-native `-P` category, so it shares `BODY`'s `B` flag
    and is marked via the new JSON-aware helper instead of the
    form-urlencoded one. (2) no encoding support existed at all -- new
    `Encoding` enum (`RAW | URL_ENCODED | DOUBLE_URL_ENCODED | BASE64`) and
    `_encode_marker()`, wired into `ServerSideTemplateInjectionOracleRequest`
    (new `encoding` field) and `_build_sstimap_argv`, which now encodes the
    marker before substitution and passes the *encoded* form to `-M` so
    SSTImap looks for what actually travels on the wire. Deliberately not
    added to `SqlInjectionOracleRequest`/`CommandInjectionOracleRequest`:
    those two delegate parameter-selection to sqlmap's/commix's own `-p`
    flag rather than the wrapper's own marker mechanism, so `param_location`
    there is already vestigial/documentation-only and an `encoding` field
    would be an unwired phantom axis value.
  - Design decision (per the task's own stated heuristic): `SinkContext` is
    the verdict-derivation contract (`family` + `required_neutralizations`,
    consumed directly by `fuzzlab.labgen.verdict.verdict()`) -- the same
    `(transform, sink_context)` pair must always derive the same verdict.
    Parameter location/encoding never changes that contract: a cookie vs. a
    query parameter, or a base64- vs. raw-encoded value, doesn't change what
    a pipeline must neutralize for the *generated code* to be SECURE. It
    changes only how the cell is rendered into a request and how the
    build-time oracle must construct its confirmation request -- the same
    "render/tracking metadata, not a verdict input" category §3.3's
    `sink_endpoint` is in. Put on `Cell`, matching that precedent.
  - Resolver integration (`fuzzlab.labgen.resolver`'s axis-range/manifest
    mechanism, lane L-P1.1) was **not yet landed** in this worktree at
    implementation time (`resolver.py` only has the standalone covering-array
    `expand()` utility; no per-cell axis-range wiring into manifest loading
    exists yet) -- deferred per the task's own explicit fallback: a manifest
    can still list `param.location`/`param.encoding` explicitly per cell
    today, which is exactly what `ParamSpec`/the schema change support.
    Revisit wiring `param` as a resolver axis once L-P1.1 merges.
- Impact (other components / project): `fuzzlab.labgen.schema` (new field,
  additive/backward-compatible -- every existing manifest and test that
  omits `param` is unaffected) and `fuzzlab.labgen.oracle_wrapper` (new enum
  values + one new dataclass field, both additive; no existing call site's
  behavior changes since `encoding` defaults to `RAW` and the new
  `ParamLocation` members are opt-in). No other component reads `Cell.param`
  yet (the `php_current` emitter is untouched by this change, per this
  lane's scope discipline -- wiring `param` into code rendering is future
  work, tracked implicitly by this entry, not claimed as done here).
- Risk (level; mitigation or accepted-risk justification): low. Both changed
  files are touched by concurrent lanes (L-P2.3/L-P2.5 on `schema.py` per
  the plan's own note in §7); the diff is a minimal, additive field (one new
  dataclass, one new optional `Cell`/JSON-Schema field) rather than a
  restructuring, to keep merges easy as instructed. The JSON-schema-level
  `enum` constraints fail closed on an invalid value rather than silently
  accepting it.
- Deliverables:
  - [x] `ParamSpec` dataclass + `Cell.param` field, `schema.py` — done
  - [x] `lab/schemas/manifest.schema.json` optional `param` property — done
  - [x] `oracle_wrapper.py` cookie/JSON marking + encoding gap-fill — done
  - [x] `docs/components/01-target-lab/requirements.md` `FR-LAB-37` — done
  - [x] Tests: `tests/test_labgen_param_axis.py` (32 new tests: schema
        validation/round-trip for all 5x4 location/encoding combinations,
        verdict-orthogonality, and oracle-wrapper cookie/JSON marking +
        all three non-raw encodings against a fake runner) — done, all
        passing; full suite run (`python -m pytest -q`): 901 passed, 8
        skipped, 2 pre-existing failures in `tests/test_mutation_operators.py`
        unrelated to this change (confirmed via `git stash` bisection: fail
        identically with this change reverted; a different lane's concern,
        not fixed here to stay in scope).
  - [x] CHANGELOG.md line — done
- Effectiveness (assessed 2026-09-21): the new axis validates end-to-end
  (manifest dict -> `Cell.param` -> unaffected verdict derivation) and the
  oracle-wrapper gap-fill is exercised against a fake runner for a
  cookie-located, base64-encoded cell exactly as the task specified,
  confirming both `confirmed_vulnerable` and `confirmed_secure` outcomes
  still classify correctly through the new marking/encoding path.

### CC-LAB-0042 — `context_depth` axis wired into the manifest/`Cell` IR (§3.5, lane L-P2.5) (2026-09-21)
*(Numbered `CC-LAB-0042` rather than the `CC-LAB-0040` this lane claimed as "next free at
authoring time" — by merge time, lanes L-P3.4 (`CC-LAB-0040`) and L-P1.4 (`CC-LAB-0041`)
had already landed and taken the numbers this lane also reached for. Reconciled per this
project's standing multi-lane policy: keep this entry's full content, renumber it to the
next free number, fix its own internal `FR-LAB-38` cross-reference (see below, now
`FR-LAB-40`). This lane's worktree was also created onto a stale, unrelated UI-redesign
branch lineage with no `fuzzlab/labgen/` directory present at all — self-diagnosed via
this task's own sync check and recovered with `git fetch . claude/trusting-noether-heon0n:
refs/remotes/origin/claude/trusting-noether-heon0n` + `git reset --hard` onto the live
branch tip before any work began, the same stale-worktree condition `CC-LAB-0030`/
`CC-LAB-0038` record.)*
- Change: added the `context_depth` axis from `docs/LAB_IMPLEMENTATION_PLAN.md` §3.5 —
  the **generator-input** counterpart of the ground-truth `Case.flow_variant` field
  L-P0.9/`CC-LAB-0030` already added. `flow_variant` records, after the fact, the depth
  a case was generated at; `context_depth` lets a manifest *declare* the depth to
  generate at, before generation.
  1. **`fuzzlab/labgen/schema.py`**: new module constants `CONTEXT_DEPTHS`
     (`direct | same_file_helper | cross_file | stored_second_order` — the four
     reachable levels this lane is scoped to), `UNREACHABLE_CONTEXT_DEPTHS`
     (`cross_service`, named by Addendum B but generatable by nothing yet) and
     `DEFAULT_CONTEXT_DEPTH`; a new optional `Cell.context_depth: str = "direct"` field
     (minimal and additive, same pattern as `sink_endpoint`/`param`, to keep merges with
     the concurrent lanes easy as instructed); and a `Cell.__post_init__` validator that
     raises `ManifestError` — never a raw `ValueError` — on an unknown level, and raises
     a *distinct, actionable* error for a known-but-unreachable level (`cross_service`),
     naming why it is unreachable and which four levels are reachable, rather than
     silently rendering something meaningless.
  2. **Consistency with `sink_endpoint` (L-P2.3/`CC-LAB-0038`), not duplication of it**:
     `stored_second_order` is *by definition* exactly the case where the payload executes
     on a different endpoint than the one it was submitted to — which `sink_endpoint`
     already expresses. So the two fields are kept **biconditionally** consistent in
     `__post_init__`: that depth requires a `sink_endpoint` distinct from `route`, and a
     cell carrying such a `sink_endpoint` may not declare any other depth.
     `context_depth` names the flow shape; `sink_endpoint` names the second endpoint that
     shape requires. Backward compatibility is handled by *derivation*, not by
     loosening: `Cell.from_dict` derives `stored_second_order` when `context_depth` is
     omitted and a distinct `sink_endpoint` is declared, so every pre-existing stored
     cell and L-P2.3 fixture stays valid and means exactly what it meant.
  3. **Ground-truth side**: checked for an existing Cell-to-GroundTruth path before
     building anything — there is none (`fuzzlab.labgen.cli.run_checks` records the gap
     as `# TODO(L-P0.9-integration)`; FR-LAB-32 states it), so no ground-truth pipeline
     was built speculatively. Instead the *mapping* was put in one shared place,
     `schema.flow_variant_for(cell) -> str` (PA-0003/PA-0021), documented as having no
     production caller yet and existing so the converter has one obvious call to make.
     It is an identity mapping by construction (the two vocabularies are deliberately
     the same), and a test asserts every `CONTEXT_DEPTHS` level is accepted by
     `fuzzlab/labels/schemas/labels.schema.json`'s own `flow_variant` enum (derived from
     that schema, not restated — PA-0001), so the two sides cannot drift.
  4. **Not a verdict input**: a depth hop is a pure pass-through that neutralizes
     nothing, so `fuzzlab.labgen.verdict` is untouched and a cell's verdict stays a
     function of `(transform, sink_context, safety_matrix)` alone (D20) at every depth —
     the same render/tracking-metadata category as `sink_endpoint`/`param`. A test
     asserts the vulnerable sink line is byte-present at both `direct` and
     `same_file_helper`.
  5. **`lab/schemas/manifest.schema.json`**: a new `$defs/context_depth` enum (the four
     reachable levels only, so `cross_service` fails at validation time too), referenced
     from the cell definition (needed: the cell schema is `additionalProperties: false`),
     from `axis_range.factors` (as a covering-array axis), and as an `axis_range`
     block-level fixed value — plus a block-level fixed `sink_endpoint` for a
     `stored_second_order` level.
  6. **Resolver axis wiring** (possible now that L-P1.1 has merged, unlike L-P2.4's
     `param` which had to defer it): `context_depth` added to
     `AXIS_RANGE_FACTOR_NAMES` and placed by `_expand_axis_range`, omitted from the
     generated cell dict when neither a factor nor a fixed value so an axis-range block
     written before this axis expands byte-for-byte as before. A block-level fixed
     `sink_endpoint` is carried onto `stored_second_order` cells, and a fixed
     `sink_endpoint` on a block whose levels never include that depth is **rejected**
     before expansion rather than silently dropped (PA-0010).
  7. **`php_current` rendering** — a new `depth` module category
     (`fuzzlab/labgen/modules/depths/` + registry `DEPTHS`:
     `passthrough_helper`, `helper_call`, `cross_file_require`), deliberately its own
     category and *not* a `transform` op, since `transform` op names are the
     verdict-relevant vocabulary `verdict()` walks. `direct` adds nothing (today's
     inline body, byte-identical); `same_file_helper` routes the tainted value through a
     pass-through helper defined in the same file (Juliet's own same-file-helper flow
     shape); `cross_file` renders the *identical* flow with the helper in a second
     emitted file (`EmittedFile(role="helper")`, pulled in by `require_once`), so the
     two levels differ only in file placement — exactly the distinction the axis exists
     to measure; `stored_second_order` needs no fragment, its depth already being
     expressed structurally by `sink_endpoint` routing the emitter to the sink page,
     where the value is read from storage rather than from the request. Keyed by
     fragment rather than by level, with the placement decision in the emitter next to
     the file-assembly it drives.
- Bug found: none — pure additive feature work, no defect fixed, so no `ERROR_LOG.md` /
  `docs/bugs/` / `docs/PREVENTIVE_ACTIONS.md` entries are required (checked against
  `ERROR_LOG.md`'s own literal scope line per PA-0019: nothing broke and was fixed here;
  the stale-worktree condition was a known, already-documented environment condition this
  task's brief anticipated and gave the recovery for).
- Impact (other components / project): LAB only. `verdict.py` untouched (see above).
  Other emitters (`node_express`, `python_fastapi`, `php_laravel`) untouched, per this
  lane's scope discipline — they still render every cell as if `context_depth` were
  `direct`; wiring depth into them is future work, flagged here rather than claimed.
  `cross_service` deliberately not attempted (it needs real ≥2-service wiring, which
  several single-service stack emitters do not by themselves provide) and made to fail
  loud in two places instead. No other component's contracts change; no FUZZ-side change
  (the ground-truth field `flow_variant` was already added by `CC-LAB-0030`).
- Risk (level; mitigation): low-to-moderate. The `Cell` field itself is a minimal,
  additive, safely-defaulted field. The one genuinely opinionated choice is the
  **biconditional** `stored_second_order` ⇔ distinct-`sink_endpoint` invariant, which
  makes a previously-legal in-memory shape (`Cell(sink_endpoint=…)` constructed directly
  with the default depth) illegal; mitigated by the `from_dict` derivation (every
  manifest/dict path is unaffected) and verified by sweeping the codebase for direct
  `Cell(...)` constructions that set `sink_endpoint` — there are none outside
  `from_dict`. The new render paths only activate for a non-`direct` cell, which no
  existing manifest declares, and a whole-corpus regression test asserts every cell of
  every existing manifest still renders as one file with no depth machinery (PA-0024).
- Deliverables:
  - [x] `CONTEXT_DEPTHS`/`UNREACHABLE_CONTEXT_DEPTHS`/`DEFAULT_CONTEXT_DEPTH` +
        `Cell.context_depth` + `__post_init__` validation, `fuzzlab/labgen/schema.py` — done
  - [x] `Cell.from_dict` derivation from a distinct `sink_endpoint` — done
  - [x] `schema.flow_variant_for(cell)` shared depth → `flow_variant` mapping — done
  - [x] `lab/schemas/manifest.schema.json`: `$defs/context_depth` + cell property +
        axis-range factor + block-level fixed `context_depth`/`sink_endpoint` — done
  - [x] Axis-range wiring (`AXIS_RANGE_FACTOR_NAMES`, `_expand_axis_range`) — done
  - [x] `fuzzlab/labgen/modules/depths/` (3 templates) + `DEPTHS` registry +
        `php_current` depth composition and second-file emission — done
  - [x] Tests: `tests/test_labgen_context_depth.py` (30 tests) — done
  - [x] `docs/components/01-target-lab/requirements.md` — new `FR-LAB-40` + §5
        interface note for `flow_variant_for` — done
  - [x] `CHANGELOG.md` line — done
  - [ ] Depth rendering in the Phase 3 emitters (`node_express`, `python_fastapi`,
        `php_laravel`) — deliberately out of this lane's scope (the brief limits emitter
        work to `php_current`); they accept the field and ignore it today.
  - [ ] `cross_service` depth — out of scope per §3.5; fails loud in both the dataclass
        and the JSON Schema until real cross-service wiring exists.
  - [ ] A `flow_variant_for()` production caller — blocked on the Cell-to-GroundTruth
        converter that does not exist (FR-LAB-32's `# TODO(L-P0.9-integration)`); not
        built speculatively.
- Effectiveness (assessed 2026-09-21): meets §3.5's own acceptance bar — one cell per
  reachable depth level round-trips through the full validated `load_manifest()`/
  `Manifest.from_dict(validate=True)` path and renders through `php_current` with the
  depth confirmable in the rendered PHP (helper defined in the same file / in a second
  `role="helper"` file pulled in by `require_once` / the sink page reading from storage),
  and both an unreachable (`cross_service`) and an unknown level raise at the dataclass
  *and* at the JSON-Schema layer. Renders are asserted deterministic at every level
  (NFR-LAB-reproducible). Full suite (`python -m pytest -q`): **1187 passed, 8 skipped**,
  plus the same 2 pre-existing, unrelated `tests/test_mutation_operators.py` failures
  (`test_every_surface_variant_preserves_semantics`,
  `test_sql_equivalent_needs_trusted_provenance`) that `CC-LAB-0038`/`CC-LAB-0039`
  already recorded as present before and outside this lane's scope — a MUT-component
  concern, not touched here.

### CC-LAB-0028 — Nuclei path-traversal/LFI oracle wrapper (Addendum E, Spike 004) (2026-09-21)
*(Numbered `CC-LAB-0028` rather than `CC-LAB-0017` at merge time — this lane's worktree
diverged onto a stale, unrelated branch lineage before starting, self-diagnosed and
recovered via a documented sync commit onto a point that itself predated
`CC-LAB-0018`-`0027` landing, so it independently claimed `0017` too. Its own
`BUG-0018`/`PA-0019` bug-protocol IDs collided with already-merged, unrelated numbers
(`BUG-0018` is an existing oracle-spike-logging bug; `PA-0019` is an existing
bookkeeping-hook rule) and were renumbered to `BUG-0023`/`PA-0025` — see that bug doc's
own note. Its files were verified independently (read in full, re-run against current
trunk) and copied in. No other content changed.)*
- Change: added `fuzzlab/labgen/nuclei_oracle.py`, a second, independent tool-oracle
  wrapper (`docs/LAB_SEED_AUTHORING_PLAYBOOK.md` Addendum E) extending the validated set
  from {sqlmap, commix, SSTImap, ZAP} to include **Nuclei**, scoped to **path traversal /
  local file inclusion only** for this task. Kept as its own module, never an extension
  of `oracle_wrapper.py`: sqlmap/commix/SSTImap each auto-detect against a declared
  `-p`-style parameter, but Nuclei has no such mechanism — it matches hand-authored YAML
  **templates** against a target, so the oracle here is two things together: (1) one
  hand-authored template, `lab/nuclei-templates/path-traversal-etc-passwd.yaml` (four
  dot-dot-slash/null-byte/double-encoding payload variants against `/etc/passwd`,
  matched on status 200 + a `root:...:0:0:` regex); (2) `run_path_traversal_oracle()`,
  which scopes the template to a declared `(endpoint_path, param_name)` pair via
  Nuclei's own `-var` template-variable substitution (the closest equivalent to
  sqlmap's/commix's `-p`, since a template's request shape is otherwise fixed at
  authoring time) and returns the same fail-closed `confirmed_vulnerable |
  confirmed_secure | inconclusive` verdict shape as `oracle_wrapper.Verdict`, defined as
  its own independent type — this module never imports `oracle_wrapper`'s sqlmap/commix
  dataclasses, and `oracle_wrapper.py` itself is untouched; it reuses only the three
  generic safety/lookup helpers (`assert_loopback`, `locate_tool`, `ToolNotFoundError`
  via `locate_tool`) that encode no sqlmap/commix-specific behavior. Same bounded
  subprocess-timeout × max-attempts contract and session-refresh support as
  `oracle_wrapper`, via an independently defined (structurally identical) injected
  `Runner`. Every entry point calls `assert_loopback` before invoking `nuclei`.
- Bug found and fixed while building this (`BUG-0023`, see that doc for the full RCA): a
  first-draft classifier treated "nuclei exits 0 with zero JSONL matches" as
  `confirmed_secure`, but Nuclei — unlike sqlmap/commix, which print an explicit
  "not vulnerable" marker only after actually probing — also exits 0 with zero matches
  against a target it never reached at all (a closed port), since it has no dedicated
  secure-side marker. Fixed by checking `stderr` for Nuclei's own host-unreachable
  health-check line (`_HOST_UNREACHABLE_RE`) before ever returning `confirmed_secure`,
  downgrading to `inconclusive` instead; `_build_nuclei_argv()` deliberately never
  passes `-silent`, which would suppress that exact diagnostic. Full bug protocol:
  `ERROR_LOG.md`, `docs/bugs/BUG-0023-*.md` (five-whys RCA; recurrence review found
  related-but-not-identical prior art in PA-0007/BUG-0008, no prior-PA-failure analysis
  needed), `PA-0025` (generalizes the fail-closed doctrine to match-only-output
  tool-oracles; swept `oracle_wrapper.py` per PA-0002 and confirmed it does not share
  this gap, since sqlmap/commix's marker-based design is immune to it by construction).
- Impact (other components / project): none outside LAB. Read-only against
  `oracle_wrapper`'s three generic safety/lookup helpers; no other component's contracts
  change. `docs/LAB_SEED_AUTHORING_PLAYBOOK.md` updated to record Nuclei as the fourth
  (now fifth counting SSTImap) validated tool-oracle, narrowing its own running
  "remains unintegrated" note.
- Risk (level; mitigation): low-to-moderate for the class of bug found (a fail-open
  security-oracle defect is high-severity by nature), but caught and fixed during this
  same task's development, before shipping or being relied upon by any other code path.
  Mitigated going forward by: the explicit host-unreachable regex check as a hard gate
  before `confirmed_secure`; a dedicated parametrized test covering five distinct
  unreachable-host stderr phrasings; a defense-in-depth test proving the unreachable
  check wins even if a template match somehow also appears in the same run; 3
  skip-guarded real-`nuclei`-binary integration tests (vulnerable/secure/unreachable)
  that are the actual regression guard against this bug class recurring silently.
- Deliverables:
  - [x] `fuzzlab/labgen/nuclei_oracle.py` (`PathTraversalOracleRequest`,
        `run_path_traversal_oracle`, `NucleiOracleVerdict`, `NucleiVerdict`) — done.
  - [x] `lab/nuclei-templates/path-traversal-etc-passwd.yaml` — done.
  - [x] Host-unreachable stderr detection before ever returning `confirmed_secure` — done.
  - [x] 26 offline tests (every classification/argv/retry/session-refresh branch via an
        injected fake runner) — done, all pass.
  - [x] 3 skip-guarded real-`nuclei`-binary integration tests (vulnerable/secure/
        unreachable, against hermetic local HTTP servers) — done, skip cleanly when
        `nuclei` isn't installed (PA-0005).
  - [x] `docs/spikes/SPIKE-004-nuclei-vs-dvwa.md` — done.
  - [x] Full bug protocol for `BUG-0023` — done.
  - [ ] XXE, open redirect, known-CVE Nuclei templates — explicitly out of scope, a
        separate, larger undertaking per this task's own brief.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — the wrapper
  correctly classifies all three cases (vulnerable/secure/unreachable) against a real
  `nuclei` binary where available, and against an injected fake runner otherwise; the
  security-relevant defect this task's own methodology was designed to catch (a
  three-case, not two-case, validation) was in fact caught before shipping. Full suite
  868 passed / 9 skipped / 2 pre-existing unrelated `test_mutation_operators.py`
  failures (baseline before this change: 842 passed, same 2 failures, 6 skipped).

### CC-LAB-0027 — T-LAB0.7: tiered emitter conformance suite (2026-09-21)
*(Numbered `CC-LAB-0027` rather than `CC-LAB-0023` at merge time — this lane's worktree
was based on a commit predating `CC-LAB-0024`-`0026` landing (including the sibling
`minimal_pair` lane, `CC-LAB-0025`), so it independently claimed `0023` too. Its own
`BUG-0021`/`PA-0023` bug-protocol IDs also collided with the already-merged
`CC-PROXY-0016` fix's numbers and were renumbered to `BUG-0022`/`PA-0024` — see that bug
doc for the full note. Its files were verified independently (read in full, re-run
against current trunk) and copied in; its Tier-0 test file's "naive fallback" tests were
updated in this reconciliation to call `_naive_minimal_pair_check` directly rather than
through `get_minimal_pair_checker()`, since that function now always resolves to the
real, landed `fuzzlab.labgen.minimal_pair.check_minimal_pair` in this branch — exactly
the upgrade-with-no-caller-change the module's own design anticipated, just exercised
sooner than this lane's own authoring context assumed. No other content changed.)*
- Change: added `fuzzlab/labgen/conformance/`, the stack-agnostic, HTTP-level tiered
  conformance suite `docs/LAB_PHASE_0_PLAN.md` T-LAB0.7 requires any future emitter to
  pass, for every `(class, sink_context)` it declares support for. Four tiers, fastest
  first, per `CR-LAB-0001` Addendum C:
  - **Tier 0** (`tier0.py`) — lint (real `php -l`, skip-guarded per PA-0005) + a
    minimal-pair diff check. `get_minimal_pair_checker()` prefers the real, sibling-owned
    `fuzzlab.labgen.minimal_pair.check_minimal_pair` (now landed as `CC-LAB-0025`) over a
    naive, deliberately conservative positional fallback — comparing twins by position,
    not path, since `php_current` names one output file per `cell_id`, not per page.
    Fully exercised offline for real.
  - **Tier 1** (`tier1.py`) — in-process functional + security assertion. Built as an
    honestly-labeled `[design]` interface, not exercised against a live app/DB: this
    session is offline-only, and T-LAB0.7's own rule against an in-memory-SQLite
    substitute (dialect-dependent false passes for SQLi cells) means there is no
    meaningful offline stand-in. `Tier1Case`/`Tier1Client` (a `Protocol`) plus the
    decision logic (`evaluate_tier1_response`) are tested only against synthetic,
    hand-written response strings via a `FakeTier1Client` test double; `run_tier1_case`
    raises `OnHostRequiredError` when no client is supplied, rather than a silent no-op
    pass.
  - **Tier 2** (`tier2.py`) — the full container-based oracle, "the only tier that
    actually confirms a label." Also `[design]` — no offline stand-in is meaningful at
    all; tests only prove the on-host-required guard and the result-plumbing wiring via a
    test double, never a live confirmation (the module's own docstring says this
    explicitly).
  - **Tier 3** (`tier3.py`) — whole-lab regeneration. Fully exercised offline for real:
    `regenerate_and_diff_emitter()` renders every supported cell of a manifest via a real
    `Emitter` twice and byte-diffs the whole tree — run against **both** existing Phase-0
    manifests (`example_phase0_scaffold.yaml`, `phase0_real_pages_sample.yaml`) in full,
    not a hand-picked subset (this is what surfaced `BUG-0022` below).
  - **`static_precheck.py`** — the `informative | uninformative` flag mechanism
    (`CR-LAB-0001` Addendum C point 4), kept as its own small registry rather than in
    `lab/safety_matrix.yaml` (that schema field hasn't landed there yet, and that file is
    owned by a sibling lane). `run_static_precheck()` never calls a checker on an
    uninformative shape, and raises rather than silently passing/skipping an informative
    shape with no checker supplied.
  A Tier-0 or Tier-1 pass is never recorded as oracle confirmation — only a real Tier-2
  run is (T-LAB0.7's own rule).
- Bug found and fixed while building this (`BUG-0022`, see that doc for the full RCA):
  running Tier 3 against the *entire* illustrative manifest for the first time revealed
  that `CC-LAB-0022`'s real-page extension had widened `php_current.supports()` to
  accept `(xss, html_body)` without adding the page profile the pre-existing illustrative
  manifest's matching cell (`LABGEN-EX-0004`, `/example/profile.php`) needs — `render()`
  raised instead of the documented supports-then-render contract holding. Fixed with a
  one-line `_PAGE_PARAMS` addition to `fuzzlab/labgen/emitters/php_current/__init__.py`.
  Full bug protocol: `ERROR_LOG.md`, `docs/bugs/BUG-0022-*.md` (five-whys RCA; recurrence
  review checked BUG-0009/PA-0008-9 and BUG-0016/PA-0017, found neither shares this exact
  root cause), `PA-0024` (an emitter capability-registry extension must exercise every
  existing manifest cell that could newly match, as a standing test — the new
  whole-manifest Tier-3 tests are that standing test going forward).
- Impact (other components / project): none outside LAB. Read-only against
  `fuzzlab.labgen.emitter`'s types, `fuzzlab.labgen.schema.Cell`, and (via
  `get_minimal_pair_checker()`) `fuzzlab.labgen.minimal_pair` — no other component's
  contracts change. The one production-code change is the `BUG-0022` one-line fix in
  `emitters/php_current/__init__.py`.
- Risk (level; mitigation): low. New, additive test-suite/interface code; the one real
  production fix is a one-line, additive `_PAGE_PARAMS` entry verified by a new
  whole-manifest regression test that would have caught the original defect.
  Tier 1/2's `[design]`-only status is stated explicitly in each module's own docstring
  and enforced by their own tests (both raise `OnHostRequiredError` rather than
  no-op-passing without a real client/oracle) — a future caller cannot mistake a green
  Tier 1/2 test in this suite for a live confirmation.
- Deliverables:
  - [x] Tier 0 (`tier0.py`) — real lint + minimal-pair diff (auto-upgrading to the real
        checker) — done, fully exercised offline.
  - [x] Tier 1 (`tier1.py`) — interface + decision logic, `[design]`, tested via a fake
        client — done.
  - [x] Tier 2 (`tier2.py`) — interface, `[design]`, tested via a test double proving
        wiring and the on-host-required guard only — done.
  - [x] Tier 3 (`tier3.py`) — whole-lab regeneration, byte-diffed across both existing
        Phase-0 manifests in full — done, fully exercised offline.
  - [x] `static_precheck.py` — `informative | uninformative` flag mechanism — done.
  - [x] 31 new tests across 5 test files — done, all pass.
  - [x] `BUG-0022` found, fixed, and given the full bug protocol — done.
  - [ ] Wiring a real in-process app + real DB container (Tier 1) and a real
        container-based oracle (Tier 2) — on-host work, explicitly out of scope for this
        session.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — Tiers 0/3 proven for
  real against both existing manifests; Tiers 1/2's interfaces are honestly labeled and
  refuse to run without their real on-host dependencies rather than silently no-op
  passing; the suite caught a real, previously-undiscovered defect (`BUG-0022`) the first
  time it was run against a whole manifest rather than hand-picked cells. Full suite 842
  passed / 6 skipped / 2 pre-existing unrelated `test_mutation_operators.py` failures
  (baseline before this change: 811 passed, same 2 failures, 6 skipped).

### CC-LAB-0026 — fingerprint-independence build gate (`CR-LAB-0001` §3/§4) (2026-09-21)
*(Numbered `CC-LAB-0026` rather than `CC-LAB-0022` at merge time — this lane's worktree
was based on a commit predating `CC-LAB-0020`-`0025` landing, so it independently
claimed `0022` too. Its two genuinely new files were verified independently — read in
full, then copied into trunk and re-run — with fresh bookkeeping written here rather
than carrying over its isolated-worktree numbering. No content changed.)*
- Change: added `fuzzlab/labgen/fingerprint_gate.py`, the **mandatory** (not optional,
  unlike the non-gating `leakage_probe.py` reference implementation owned by a sibling
  lane) build gate `CR-LAB-0001` §3 requires once the generator goes multi-stack
  (Phase 3): guards against a stack becoming a de facto proxy for a vulnerability class
  or verdict — a detector learning "every Flask cell is SSTI" (teaching a `Server:
  Werkzeug` header) instead of the real signal. Deliberately schema-independent: a
  "corpus record" is a plain mapping with `stack`/`vuln_class`/(optional)`verdict` keys,
  never a `fuzzlab.labgen.schema.Manifest`/`Cell` object, so this gate can run against a
  metadata export, a test fixture, or a future manifest without depending on that
  schema's shape (or vice versa). Two independent checks, per the CR's own named
  checks: (1) `check_min_stacks_per_class`/`check_min_classes_per_stack` — deterministic
  coverage checks defaulting to the CR's own canonical thresholds (every class on >= 2
  stacks, every stack carrying >= 3 classes), failing loud with a typed
  `FingerprintIndependenceError` naming exactly what fell short (an optional
  `expected_classes`/`expected_stacks` list additionally flags a class/stack wholly
  absent from the corpus, rather than silently not checking it); (2)
  `check_stack_class_independence`/`check_stack_verdict_independence` — a chi-square
  test of independence (`scipy.stats.chi2_contingency`) between stack and
  vuln_class/verdict; a hand-constructed test corpus demonstrates why both halves matter
  by passing every coverage check while still being strongly, statistically confounded
  — only the chi-square test catches that shape. A degenerate contingency table (a
  stack/class that never co-occurs with anything) becomes a typed
  `FingerprintIndependenceError`, not a raw `scipy` `ValueError`. `run_fingerprint_gate()`
  runs all four checks and raises one error listing every violation found (not just the
  first), or returns a `FingerprintGateReport` with the computed statistics when the
  corpus passes. New optional `labgen-stats` extras group (`scipy>=1.11,<2` — the first
  use of scipy in this project) in `pyproject.toml`, imported lazily inside the
  chi-square functions (never at module import time): a missing install raises a typed
  `MissingStatsDependencyError` naming the extra, never a raw `ImportError` (PA-0005's
  established pattern).
- Impact (other components / project): none outside LAB. Schema-independent by design,
  so no coupling to `fuzzlab.labgen.schema`/`verdict`/`emitter`/`modules` (none
  imported); not yet wired into any build gate/CLI — there is no real multi-stack
  corpus to run it against yet (Phase 3), per the module's own docstring.
- Risk (level; mitigation): low. New, additive, read-only code with no callers yet and
  no dependency on any other component's contracts. The chi-square half's correctness is
  verified against exact, deterministic hand-constructed corpora (a perfectly balanced
  corpus yields p=1.0/chi2=0.0 exactly; a fully confounded corpus yields p<0.001), not
  randomized sampling, so results are reproducible; a dedicated test corpus proves the
  coverage checks alone are insufficient (passes coverage, still fails chi-square),
  justifying why both halves are mandatory rather than either alone.
- Deliverables:
  - [x] `fuzzlab/labgen/fingerprint_gate.py` (`check_min_stacks_per_class`,
        `check_min_classes_per_stack`, `check_stack_class_independence`,
        `check_stack_verdict_independence`, `run_fingerprint_gate`,
        `FingerprintIndependenceError`, `MissingStatsDependencyError`) — done.
  - [x] Coverage checks with CR-LAB-0001's own canonical thresholds as defaults — done.
  - [x] Chi-square independence test for stack<->class and stack<->verdict — done.
  - [x] Typed `MissingStatsDependencyError` for a missing `scipy` install — done.
  - [x] 18 new tests (coverage pass/fail, chi-square pass/fail, the
        coverage-passes-but-chi-square-fails demonstration, degenerate-table handling,
        missing-dependency simulation, `run_fingerprint_gate` end-to-end) — done, all
        pass.
  - [ ] Wiring into an actual build gate/CLI once a real multi-stack corpus exists
        (Phase 3) — explicitly out of scope per the plan.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — 18 new tests pass,
  including the coverage-insufficient-alone demonstration that justifies the gate's own
  two-halves design; full suite 811 passed / 6 skipped / 2 pre-existing unrelated
  `test_mutation_operators.py` failures (baseline before this change: 793 passed, same 2
  failures, 6 skipped).

### CC-LAB-0025 — minimal-pair invariant checker, pulled forward from Phase 1 (2026-09-21)
*(This lane's worktree was based on a commit predating `CC-LAB-0020`-`0024` landing.
Rather than merge its branch wholesale (would reintroduce duplicate/stale content its
own worktree never saw land), its two genuinely new files
(`fuzzlab/labgen/minimal_pair.py`, `tests/test_labgen_minimal_pair.py`) were verified
independently — read in full, then copied into trunk and re-run against trunk's current
`emitter.py`/`modules/` — and this entry writes fresh bookkeeping rather than carrying
over its isolated-worktree numbering.)*
- Change: added `fuzzlab/labgen/minimal_pair.py`, a standalone, offline checker over two
  already-rendered `EmittedFiles` results (never renders anything itself) asserting a
  cell's vulnerable and secure twins form a valid minimal pair per `CR-LAB-0001` §3 and
  `docs/LAB_SEED_AUTHORING_PLAYBOOK.md` steps 5/6 — everything outside the declared
  transform/sink region must be byte-identical. Region detection is emitter-agnostic: it
  parses the `// Module composition: a -> b -> c` provenance comment any
  module-composition emitter writes (this project's established convention, per
  `fuzzlab/labgen/emitters/php_current/__init__.py`), classifies each named position by
  its module's own registered `category` via read-only lookup against
  `fuzzlab.labgen.modules`' registries, and independently cross-checks the empirically
  differing content region via a longest-common-prefix/longest-common-suffix trim over
  each file's lines (excluding the composition comment itself) — when the composition
  sequences are name-for-name identical, this middle band is required to be empty,
  catching the Juliet-style failure mode the playbook itself cites: an unrelated
  identifier rename with no declared composition change slipping through as "a small
  diff." `check_identifier_stability()` separately asserts every declared
  function/handler name (`function NAME(`) is byte-identical between twins. Raises
  `MinimalPairViolation` (a real invariant violation, naming exactly what differed) or
  the base `MinimalPairError` (the check itself couldn't be evaluated — no composition
  comment found, or a composition names an unregistered module) — never a silent pass.
  Explicitly out of scope for this Phase-0-pulled-forward delivery, per the module's own
  docstring: unequal-length composition sequences between twins (raises
  `MinimalPairError`, not a guess) and non-PHP identifier extraction (currently
  `function NAME(`/`$var`-oriented).
- Impact (other components / project): none outside LAB. Read-only against
  `fuzzlab.labgen.emitter`'s `EmittedFile`/`EmittedFiles` types and
  `fuzzlab.labgen.modules`' registries; does not modify either. Not yet wired into any
  build gate or CLI — a standalone checker exercised via its own test suite today, same
  convention as `gates.py`'s name-leak scanner and `secret_scanner.py` before their own
  eventual `--check` CLI wiring.
- Risk (level; mitigation): low. New, additive, read-only code with no callers yet. The
  positive fixture in its test suite is a *real* `php_current`-rendered pair (same cell
  identity, `dataclasses.replace`'d transform field only), not a synthetic string —
  proving the checker actually accepts a real minimal pair, not just an idealized one; 9
  hand-constructed negative fixtures cover file-set/role mismatches, missing composition
  comments, unrelated content drift with no composition change, identifier renames,
  composition-length mismatches, unregistered module names, and both directions of the
  `variable_categories` restriction.
- Deliverables:
  - [x] `fuzzlab/labgen/minimal_pair.py` (`check_minimal_pair`, `check_identifier_stability`,
        `MinimalPairError`, `MinimalPairViolation`) — done.
  - [x] Emitter-agnostic region detection via the composition-comment convention — done.
  - [x] Content-confinement cross-check independent of the composition parse — done.
  - [x] 16 new tests (positive real-pair fixture + 9 hand-constructed negative cases +
        6 direct `check_identifier_stability` cases) — done, all pass.
  - [ ] Wiring into an actual build gate/CLI — not yet, same as the sibling gates above.
  - [ ] Variable-length transform pipelines between twins — not supported, documented
        limitation, not silently mishandled.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — 16 new tests pass
  against a real rendered pair and 9 distinct hand-constructed violation shapes; full
  suite 793 passed / 6 skipped / 2 pre-existing unrelated `test_mutation_operators.py`
  failures (baseline before this change: 777 passed, same 2 failures, 6 skipped).

### CC-LAB-0024 — T-LAB0.6: Gitleaks secret-scanner build gate (2026-09-21)
*(Numbered `CC-LAB-0024` rather than `CC-LAB-0020` at merge time — this lane's worktree
was based on a commit that predated `CC-LAB-0020`-`0023` landing, so it independently
claimed `0020` too. It also landed on a shared branch with the `CC-PROXY-0016` fix below
(an environment quirk, not this lane's own doing); its offending commit was amended in
place before merging to remove a real-shaped secret literal from `tests/test_labgen_
secret_scanner.py` that GitHub's push protection correctly rejected, so no commit on
`claude/trusting-noether-heon0n` ever contains it. No other content changed; purely a
numbering fix plus the fixture rewrite noted below.)*
*(This lane's worktree also hit the stale-worktree-lineage environment quirk noted in
CC-LAB-0019 — its initial `git log`/checkout showed an unrelated UI-redesign branch with no
`fuzzlab/labgen/` at all. Confirmed as a worktree-creation artifact, not a missing-history
problem: `git reset --hard claude/trusting-noether-heon0n` (the branch holding the merged
Phase 0 lanes, verified present in the shared object store) recovered the correct tree
before any of this entry's work began. No files were manually re-imported.)*
- Change: added the T-LAB0.6 **secret-scanner** build gate, separate from and
  complementary to the existing name-leak scanner (`fuzzlab/labgen/gates.py` +
  `denylist.py`, untouched by this change): (1) `.gitleaks.toml` at the repo root
  (the first root-level external-tool config file in this repo) extending
  Gitleaks' default ruleset via `[extend] useDefault = true`, with one
  `[allowlist]` regex (`(?i)(FAKE|EXAMPLE|PLACEHOLDER|NOTREAL|CHANGEME)`) so a
  seeded fake credential the generator legitimately emits as vulnerable-code
  content (e.g. a hardcoded fake DB password demonstrating CWE-798) does not
  false-positive the build, while an unmarked real-shaped secret still does —
  verified empirically against the installed binary (an unmarked AWS-shaped key
  is still flagged; AWS's own `AKIAIOSFODNN7EXAMPLE` docs example and a
  `FAKE`/`PLACEHOLDER`-marked value are both suppressed); (2)
  `fuzzlab/labgen/secret_scanner.py`, a thin wrapper mirroring
  `oracle_wrapper.py`'s established external-tool-wrapping pattern (PA-0005): a
  dependency-injected `Runner`, a typed `ToolNotFoundError` instead of a raw
  `FileNotFoundError`, and a structured `SecretScanResult`/`SecretLeak`. Runs
  `gitleaks detect --no-git -s <tree> -c .gitleaks.toml -f json -r <report>
  --exit-code 1` against a tree written to a temp directory. Fails loud
  (`SecretScanError`) on: an exit code other than 0/1, an exit-1 with an empty
  report (a scanner-malfunction shape, not a clean pass), a report that isn't
  valid JSON, or a report entry missing an expected field — per the plan's own
  rule that the gate must fail the build on a scanner *crash*, not just a hit;
  (3) `tests/test_labgen_secret_scanner.py`: a should-flag/should-not-flag
  fixture corpus (real-shaped AWS/Stripe/PEM-key secrets vs. `FAKE`/`EXAMPLE`/
  `PLACEHOLDER`-marked and ordinary-clean content) run against the real
  `gitleaks` binary (skip-guarded to when it's on PATH, satisfying PA-0005's
  "at least one test exercising the real implementation"), plus
  injected-fake-runner tests proving every crash path above actually raises.
  Verified Gitleaks is installable in this sandbox: `apt-get install -y
  gitleaks` succeeds (Ubuntu noble-updates universe package, 8.16.0), so no
  environment-blocked fallback was needed — the real binary is used both in
  ad hoc verification and in the test suite's real-binary-path tests. The
  should-flag fixtures' AWS/Stripe secrets are assembled from string fragments
  at test-run time (`_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"`, similarly for the
  Stripe key) rather than written as one contiguous literal in the source —
  Gitleaks itself still scans the fully-assembled bytes written to a temp file
  at test time, so detection coverage is unaffected, but no commit's diff
  contains a string that trips GitHub's own push-protection secret scanning
  (an earlier version of this fixture did, and was rejected on push; see
  `ERROR_LOG.md`).
- Impact (other components / project): none outside LAB. This gate is not yet
  wired into a CI/pre-commit invocation (T-LAB0.10's `fuzzlab lab-generate
  --check` CLI, still `[planned]`) — today it is exercised as a pytest test
  module, the same convention `gates.py`'s name-leak scanner already uses per
  `tests/test_labgen_gates.py`'s own docstring ("the same way this repo
  already treats reproducibility/schema checks as part of the test suite
  rather than a separate ad hoc script").
- Risk (level; mitigation or accepted-risk justification): low. The allowlist
  regex is a plain substring match on the flagged secret's own text, verified
  both to suppress marked-fake values and to still catch an unmarked
  real-shaped one (see the fixture corpus); a real secret with no marker is
  never suppressed by this config. Accepted risk: the allowlist is a
  convention (generator authors must remember to mark seeded fake secrets),
  not currently enforced at generation time — acceptable for Phase 0's single,
  hand-authored example emitter; worth revisiting if/when the emitter corpus
  grows and starts emitting such content non-trivially.
- Deliverables:
  - [x] `.gitleaks.toml` (repo root) extending the default ruleset with a
    fake/example-secret allowlist — done
  - [x] `fuzzlab/labgen/secret_scanner.py` wrapper (structured result,
    injected runner, fail-closed on crash) — done
  - [x] `tests/test_labgen_secret_scanner.py` should-flag/should-not-flag
    fixture corpus + crash-handling tests — done (23 tests, all passing with
    the real `gitleaks` binary present)
  - [x] `requirements.md` — new `FR-LAB-22` + `NFR-LAB-no-secret-leak` — done
  - [ ] Wire into `fuzzlab lab-generate --check` (T-LAB0.10) — todo, blocked
    on that CLI existing
- Effectiveness (assessed 2026-09-21): met its intent — the gate correctly
  flags unmarked real-shaped secrets and passes marked-fake/clean content in
  the fixture corpus, and every injected-crash path raises rather than
  passing silently. Full suite: 777 passed, 2 pre-existing unrelated
  `test_mutation_operators.py` failures, 6 skipped (baseline before this
  change: 754 passed, same 2 failures, 6 skipped).

### CC-LAB-0023 — T-LAB0.11: leakage-probe reference implementation (2026-09-21)
*(This lane's worktree diverged onto the same stale, unrelated UI-redesign branch lineage
that hit a sibling lane earlier — a harness/environment quirk, confirmed via `git cat-file`
that the correct trunk commit was reachable from its object store despite its checked-out
branch being wrong. The agent's own verification (checking for LAB-related commit names in
its history) was reasonable but insufficient — it found some LAB-adjacent docs commits from
a different point in project history and judged its lineage acceptable, missing that
`fuzzlab/labgen/` itself (with `oracle_wrapper.py`, `resolver.py`, `emitter.py`, etc.) was
entirely absent. It also, appropriately, declined a mid-task instruction to `git reset
--hard` onto a named branch, treating an unverifiable destructive command from an
in-conversation message as suspicious — sound instinct in general, though in this
particular case the instruction was genuine and correct. Its work was fully committed
regardless, so nothing was lost: only its two genuinely new files
(`fuzzlab/labgen/leakage_probe.py`, `tests/test_labgen_leakage_probe.py`) were copied into
this branch, verified independently, with fresh bookkeeping written here rather than
carrying over its isolated-worktree `CC-LAB-0014`/`FR-LAB-8` numbers, which only made sense
relative to that disconnected lineage.)*
- Change: added `fuzzlab/labgen/leakage_probe.py`, the T-LAB0.11 reference implementation
  (design already settled by `docs/LAB_PHASE_0_PLAN.md`, not build-gating yet per that
  plan): `probe_leakage(cells, ...)` detects whether a corpus's non-payload metadata
  (status code, response length, header count, latency, param-name length, path depth,
  content-type — a closed `FEATURE_ALLOWLIST`, `ValueError` on any key outside it) leaks the
  vulnerability label — i.e. whether a classifier could cheat on superficial fingerprints
  instead of the real signal. Uses a deliberately weak `LogisticRegression` +
  `StandardScaler`/`OneHotEncoder` pipeline, `StratifiedGroupKFold` grouped by
  generating-rule ID (never a random split — near-duplicate cells from the same rule must
  land on the same side), and a **permutation-null threshold** (200 label shuffles, 99th
  percentile of the resulting AUC distribution — not a fixed constant). `PER_CLASS_FEATURE_
  EXCLUSIONS` lets `latency_ms` be excluded for `sqli_blind_time`/`race_condition` (timing
  *is* the vulnerability there), each with a written one-line justification; every
  `LeakageResult` reports the exclusion count so the mechanism can't quietly launder a red
  result green. Returns data (`LeakageResult.leaks`), never raises on a leaky corpus — only
  on malformed input. `scikit-learn`/`numpy` added as a new, **optional** `labgen` extras
  group in `pyproject.toml` (not a main dependency — nothing else in `fuzzlab/labgen/` needs
  it, so it's declared where it's actually imported, per PA-0005, without forcing the
  dependency on everyone). Deliberately **not** added to `fuzzlab/labgen/__init__.py`'s
  eager imports for the same reason — eagerly importing it there would make `scikit-learn` a
  hard requirement just to `import fuzzlab.labgen` at all; it's reached via
  `from fuzzlab.labgen import leakage_probe` instead, which only needs `scikit-learn`
  installed at the point it's actually used.
- Impact (other components / project): a standalone reference implementation with no
  callers yet and no wiring into `gates.py` or any build step — per the plan, full
  build-gating starts in Phase 1 once real variation exists. No other component's contracts
  change; `oracle_wrapper.py`, `zap_oracle.py`, `resolver.py`, `schema.py`, `verdict.py`,
  `subseed.py`, `gates.py`, `denylist.py`, `emitter.py`, `modules/`, `emitters/` untouched.
- Risk (level; mitigation): low — unused by any other code path yet, so a defect here
  affects nothing currently running. Mitigated by: the closed feature allowlist (raises
  rather than silently accepting a payload-derived field); the permutation-null threshold
  instead of a guessed constant; 9 new tests (a synthetic corpus with status code
  deterministically tied to the label — must flag `leaks=True` above threshold; a synthetic
  clean corpus with independent features — must flag `leaks=False`; generating-rule grouping
  sanity; per-class exclusion application and reporting; allowlist closure; exclusion
  justification presence; input-validation error paths).
- Deliverables:
  - [x] `fuzzlab/labgen/leakage_probe.py` (`probe_leakage`, `LeakageResult`,
        `FEATURE_ALLOWLIST`, `PER_CLASS_FEATURE_EXCLUSIONS`) — done.
  - [x] Permutation-null threshold (not a fixed constant) — done.
  - [x] `StratifiedGroupKFold` grouped by generating-rule ID — done.
  - [x] Per-class feature exclusions with written justification + reported count — done.
  - [x] 9 new tests (leaky/clean synthetic corpora, grouping, exclusions, allowlist,
        validation) — done, all pass.
  - [ ] Wiring into an actual build gate — explicitly out of scope per the plan (Phase 1).
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — 9 new tests pass; full
  suite 754 passed / 6 skipped / 2 pre-existing unrelated `test_mutation_operators.py`
  failures (unaffected). Not yet assessable: whether the permutation-null threshold's
  99th-percentile choice holds up as sensitive-but-not-oversensitive once run against a real,
  generated corpus rather than small synthetic fixtures — that is Phase 1's real test.

### CC-LAB-0022 — T-LAB0.4 extension: `php_current` generalizes to a small real-page sample (2026-09-21)
*(Numbered `CC-LAB-0022` rather than `CC-LAB-0020` at merge time — this lane's worktree
was based on a commit that predated `CC-LAB-0020`/`CC-LAB-0021` (the OSV/GHSA sourcing
tool and the ZAP oracle) landing, so it independently claimed `0020` too. No content
changed; purely a numbering fix.)*
- Change: extended `fuzzlab/labgen/modules/` and `fuzzlab/labgen/emitters/php_current/`
  (built in `CC-LAB-0019`) to render a small **real** sample of four actual
  `puppy-fort-factory/` pages instead of just one illustrative pair, per
  `docs/LAB_PHASE_0_PLAN.md`'s Phase 0 exit criterion (a manifest describing real pages,
  regenerated byte-identically) — proving the module inventory generalizes, and
  surfacing what was actually missing from it when confronted with real page shapes.
  Sample (matching `puppy-fort-factory/VULNERABILITIES.md` and
  `lab/ground-truth/labels.json`'s `PFF-0001`/`PFF-0004`/`PFF-0005`/`PFF-0006`):
  - `product.php` (sqli, `sql_numeric_literal`, GET `id`) — the same shape `CC-LAB-0019`'s
    illustrative pair already modeled, now tied to the real page/table.
  - `blog_post.php` (sqli, `sql_numeric_literal`, GET `id`) — a **second** real page
    reusing the exact same module set as `product.php` (only the per-page table/column
    profile differs), proving reuse across pages rather than one page in isolation. Does
    **not** model the page's error-suppression nuance (`@mysqli_query`, "blind" vs.
    "error-based") — the safety-matrix/verdict model has no concept for that distinction;
    noted explicitly in the emitter's own module docstring rather than silently dropped.
  - `login.php` (sqli, `sql_string_literal`, POST `username`) — a distinct sink-context
    family (quoted-string vs. numeric-literal SQL position) and a distinct source origin
    (`$_POST`, not `$_GET`). The `password` field is rendered as sink boilerplate, not a
    separate injection-point cell (correctly non-vulnerable per
    `lab/ground-truth/labels.json`'s `PFF-1008`: md5-hashed before use).
  - `profile.php` (xss, `html_body`, stored `bio`) — a distinct vulnerability class, a
    distinct source (`read_stored_field`: a value read from an already-stored record, not
    a request parameter — the first source module that isn't request-derived), and a
    distinct sink (`html_body_echo`).
  New modules: `sources/post_param`, `sources/read_stored_field`,
  `transforms/html_entity_escape` (wraps `value_expr` in `htmlspecialchars(...)` directly,
  a second valid composition shape alongside `param_bind`'s downstream-flag pattern),
  `sinks/sql_string_literal_lookup`, `sinks/html_body_echo`, `complexities/render_only`
  (no `return $row;` — needed once a cell has no DB row to return). `php_current` itself
  was generalized from one hardcoded module/param set to a
  `(vuln_class, sink_context.family) -> module set` registry plus a per-real-page static
  parameter profile (table/column/param names; a stored-field expression for `profile.php`)
  keyed by `cell.route.path` — the `Cell` IR itself (owned by a sibling lane, not modified)
  carries only what `verdict()` needs, so this render-only metadata lives in the emitter,
  not the IR. New manifest `lab/manifests/phase0_real_pages_sample.yaml` (8 cells: 4
  vulnerable/secure pairs, IDs prefixed `LABGEN-RP-`), kept separate from the original
  illustrative `example_phase0_scaffold.yaml` (unchanged, still renders identically).
- Impact (other components / project): additive only, confined to
  `fuzzlab/labgen/{modules,emitters/php_current}` and a new manifest file; no change to
  `fuzzlab/labgen/{schema,verdict,subseed,gates,denylist,resolver,oracle_wrapper}.py` (not
  touched) or to `puppy-fort-factory/`/`lab/ground-truth/` (read for reference only, not
  written). `lab/safety_matrix.yaml` already covered every `(op, sink_family)` pair this
  sample needed (`sql_string_literal`/`html_body` `raw_concat`/`param_bind`/
  `html_entity_escape` entries already existed from `CC-LAB-0016`) — no matrix change
  needed.
- Risk (level; mitigation): **low**. New, additive rendering code and a new manifest file
  not wired into any build that touches the real, currently-served lab; every cell's
  derived verdict is cross-checked against the real page's documented status
  (`test_verdict_matches_the_real_pages_documented_vulnerability_status`), so a
  module/profile authoring mistake that silently flipped a verdict would fail loud in CI,
  not slip through as a quiet mislabel.
- Deliverables:
  - [x] `post_param`, `read_stored_field` source modules — done.
  - [x] `html_entity_escape` transform module — done.
  - [x] `sql_string_literal_lookup`, `html_body_echo` sink modules — done.
  - [x] `render_only` complexity module — done.
  - [x] `php_current` generalized to a module-set + page-profile registry covering 3
        sink-context families across 2 vulnerability classes — done.
  - [x] `lab/manifests/phase0_real_pages_sample.yaml` (8 cells, 4 real pages) — done.
  - [x] Tests: per-module unit tests for every new fragment, an end-to-end test per real
        cell (supports/determinism/verdict-cross-check/structural content
        assertions/`php -l`) — done (`tests/test_labgen_modules.py`,
        `tests/test_labgen_php_current_real_pages.py`).
  - [ ] Remaining ~26 real `puppy-fort-factory/` pages — not started, separate, larger,
        later task (T-LAB0.7/Phase 3), per this task's own scope.
  - [ ] `blog_post.php`'s error-suppression ("blind") nuance modeled at the
        manifest/verdict level — not started; no schema concept for it yet, noted as a
        known simplification, not silently dropped.
- Effectiveness (assessed 2026-09-21): met this task's own bar — the module inventory
  built for one illustrative pair (`CC-LAB-0019`) generalized to 4 real pages/2 vuln
  classes/3 sink-context families with only 6 new small fragments and one per-page
  profile table, not a rewrite; every real-sample cell's derived verdict matches its real
  page's documented status; every cell renders real, byte-deterministic, `php -l`-valid
  PHP. Not yet assessable: whether this pace of "a few new fragments per new real page"
  holds up once the sample grows toward the full ~30-page app — deferred to that later
  task's own CC entry.

### CC-LAB-0019 — T-LAB0.4: emitter interface + module-composition + `php_current` emitter (2026-09-21)
*(This lane's worktree diverged onto an unrelated, stale UI-redesign branch lineage from
before the Phase 0 foundation landed anywhere — a harness/environment quirk, not something
the lane did wrong. It manually re-imported the foundation files verbatim via `git show`
to unblock itself and recorded that import as its own change-control entries; those
duplicate-import entries are **not** carried into this log, since nothing was actually
imported into this branch — the foundation already exists here via the real `CC-LAB-0016`/
`CC-LAB-0018` entries. Only this lane's genuinely new work (the files listed below) was
merged in, verified independently, and given this fresh entry number.)*
- Change: added `fuzzlab/labgen/emitter.py` (the `Emitter` ABC — `render(cell) ->
  EmittedFiles`, `supports(vuln_class, sink_context) -> bool`; `EmittedFiles` is a tuple of
  `EmittedFile{path, content, role}`, deliberately not a single-file pair, so a future
  routed, multi-file emitter — Laravel/Express, `CR-LAB-0001` Addendum D — isn't structurally
  precluded even though `php_current` only ever returns one file today); `fuzzlab/labgen/
  modules/{sources,transforms,sinks,complexities}/` (the composable Jinja2-template
  inventory Addendum C's architecture correction requires instead of one monolithic
  template per cell — `get_param` source, `identity`/`param_bind` transforms, a
  `sql_numeric_lookup` sink that branches on a `bound` flag a transform publishes so one
  sink fragment serves both twins of a minimal pair, and a `single_statement` complexity
  wrapper; every `jinja2.Environment` sets `trim_blocks=True, lstrip_blocks=True,
  keep_trailing_newline=True` explicitly, never Jinja2's defaults); and
  `fuzzlab/labgen/emitters/php_current/` (the first, reproduction emitter, assembling those
  modules into one illustrative raw-concat-numeric-lookup vulnerable/secure SQLi pair —
  matching `lab/manifests/example_phase0_scaffold.yaml`'s `LABGEN-EX-0001`/`0002` cells).
  `render()` fails loud (raises) on an unsupported `(vuln_class, sink_context)` pair or an
  op it has no transform module for, rather than guessing — same "fail loud on an authoring
  gap" discipline `fuzzlab.labgen.verdict.verdict()` already uses. Added `jinja2>=3.1,<4` to
  `pyproject.toml`'s main dependencies (previously declared only under the `web` extra; now
  imported directly and unconditionally by `fuzzlab/labgen/modules/__init__.py`, PA-0005)
  plus package-data for the `.j2` template files.
- Impact (other components / project): the module-composition inventory + `php_current`
  prove the emitter architecture end to end for one cell shape; reproducing all ~30 of
  today's real `puppy-fort-factory/` pages is explicitly separate, later work (tracked as
  task #9 in this session's backlog / `docs/LAB_PHASE_0_PLAN.md` T-LAB0.7/Phase 3), not
  attempted here. No other component's contracts change; `fuzzlab/oracle/`,
  `fuzzlab/harness/`, `fuzzlab/web/`, `oracle_wrapper.py`, `nuclei_oracle.py` (if it exists
  by the time this lands), and `resolver.py` are all untouched.
- Risk (level; mitigation): low — new, self-contained code with no live-lab dependency; a
  defect here affects only the not-yet-used generator path, not anything currently served.
  Mitigated by: `render()`'s fail-loud discipline; 20 new tests (the `Emitter` ABC contract
  and `EmittedFiles`' multi-file shape; each module fragment rendering correctly in
  isolation; an end-to-end `php_current` render that is byte-deterministic across two calls
  and whose vulnerable/secure diff is confined to the transform/sink region — the minimal-
  pair property; a real `php -l` syntax-check of the generated output, since PHP 8.4 is
  available in this environment).
- Deliverables:
  - [x] `fuzzlab/labgen/emitter.py` (the `Emitter` ABC + `EmittedFile`/`EmittedFiles`) — done.
  - [x] `fuzzlab/labgen/modules/{sources,transforms,sinks,complexities}/` inventory — done
        (small, illustrative set; not exhaustive — Phase 1/3 work).
  - [x] `fuzzlab/labgen/emitters/php_current/` — done (one illustrative vulnerable/secure
        pair, not the full ~30-page migration).
  - [x] 20 new tests incl. a real `php -l` syntax-check — done, all pass.
  - [ ] Reproducing today's real ~30 PHP pages byte-identically (the actual Phase 0 exit
        criterion) — not started, tracked as a separate, later task.
  - [ ] T-LAB0.7's tiered conformance suite — not started, blocked on this entry landing
        (now unblocked).
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — 20 new tests pass; full
  suite 642 passed / 5 skipped / 2 pre-existing unrelated `test_mutation_operators.py`
  failures (unaffected). Also surfaced, incidentally (unrelated to this change, logged
  separately): a genuine, reproducible-but-intermittent cross-thread SQLite race in
  `tests/test_web_repeater.py` (PROXY/UI component) — see `ERROR_LOG.md`, tracked as
  follow-up, not caused by or fixed in this entry. Not yet assessable: whether
  `php_current`'s module set is rich enough to reproduce the real app without rework — that
  is the next task's real test.

### CC-LAB-0021 — ZAP whole-app safety-net oracle: Spike 005 + new wrapper module (2026-09-21)
*(Numbered `CC-LAB-0021` rather than `CC-LAB-0019` at merge time — this lane's worktree
was based on a commit that predated `CC-LAB-0019`/`CC-LAB-0020` (the emitter and the
OSV/GHSA sourcing tool) landing, so it independently claimed `0019` too. No content
changed; purely a numbering fix.)*
- Change: two parts, completing this project's four-tool integration list
  (`LAB_SEED_AUTHORING_PLAYBOOK.md`'s "SSTImap/Nuclei/ZAP remain unintegrated" line,
  `CR-LAB-0001`'s tool-mapping table — Nuclei is a separate, concurrent lane's work, not
  touched here). (1) `docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md` —
  downloaded the official `zaproxy/zaproxy` v2.16.1 Linux release tarball (Apache-2.0,
  ~234MB, reachable through this environment's proxy even though Docker Hub is not) into
  the session scratchpad, reused Spike 003's already-validated vulnerable/secure Flask
  twin pair (permission explicitly given to reuse an existing spike target rather than
  clone a new app), and ran ZAP's own "Automation Framework"
  (`zap.sh -cmd -autorun <plan.yaml>`, a single headless invocation that crawls, scans,
  and exits on its own — no daemon or API-polling loop needed) against both. Correct
  positive: a dedicated **"Server Side Template Injection"** active-scan rule fired at
  High risk/High confidence on the vulnerable endpoint, plus (incidentally, validating
  `CR-LAB-0001`'s separately-listed "ZAP active scan ... for reflected/stored XSS" path
  for free) a **"Cross Site Scripting (Reflected)"** alert on the same parameter. Correct
  negative: neither alert on the secure twin — only routine header/info-disclosure noise
  present on almost any target (missing CSP header, missing anti-clickjacking header,
  version-disclosure header, etc.), which is itself the spike's central design finding:
  an *unscoped* "any ZAP alert" verdict would flag every target, secure ones included, on
  noise unrelated to the class under test. Also found and designed around (no code defect,
  no `ERROR_LOG.md` entry needed): ZAP's own process exit code reflects its own opaque,
  whole-app policy, not the one class a caller declares, so the wrapper never adds an
  `exitStatus` job or inspects the exit code for its verdict — it always parses the
  Automation Framework's own JSON report; a stale process squatting on ZAP's port (an
  unrelated leftover Flask instance from earlier in the same session) causes a fast, clean
  `BindException` failure, not a hang, but the general port-collision/stale-state risk is
  real for a heavier daemon than the other three tools spawn, mitigated by giving every
  invocation its own fresh, temporary ZAP home directory; Firefox is absent in this
  environment (harmless — only affects the AJAX/client spider, which this wrapper doesn't
  use) and ZAP's telemetry "call home" step is blocked by the egress proxy and logs an
  `ERROR`-level line on every run (harmless and non-blocking — confirms the wrapper must
  never treat "any ERROR in stderr" as a failure signal by itself).
  (2) Added `fuzzlab/labgen/zap_oracle.py` (a **new, separate module** — deliberately not
  merged into `oracle_wrapper.py`, which other lanes own and which is shaped for
  per-parameter tools; ZAP is a whole-app scanner with no single declared parameter).
  `ZapWholeAppScanRequest` (target_url, optional `alert_name_pattern`, `risk_threshold`,
  crawl/scan duration caps, timeout, `max_attempts`, `tool_path`, isolable
  `zap_home_dir`/`report_dir`) and `run_zap_whole_app_scan()` build a YAML Automation plan
  via `yaml.safe_dump` (PyYAML — already a declared project dependency per Lane B's
  `schema.py`/`verdict.py`), invoke it as one bounded subprocess call through the same
  `Runner` protocol `oracle_wrapper` defines (imported, not duplicated), and classify the
  result by parsing the JSON report against the caller's declared scope. Reuses
  `oracle_wrapper`'s `assert_loopback`, `locate_tool`, `Verdict`, `OracleRunResult`,
  `ToolNotFoundError`, `OracleSafetyError`, and `default_runner` directly (imported, not
  reimplemented) — only the request/verdict *shape* differs from the other three tools
  (`ZapScanVerdict` instead of `OracleVerdict`: a `checked_for` scope description and a
  *list* of matching/all alerts instead of one raw-output string), because ZAP's job is
  structurally a list-producing whole-app scan, not a single parameter's pass/fail.
- Impact (other components / project): completes `LAB_SEED_AUTHORING_PLAYBOOK.md`'s named
  four-tool set (sqlmap, commix, SSTImap, ZAP) with Nuclei tracked separately by a
  concurrent lane; the playbook's "SSTImap/Nuclei/ZAP remain unintegrated" line now reads
  "SSTImap and ZAP integrated; Nuclei remains unintegrated." New `requirements.md`
  FR-LAB-20 (FR-LAB-11 covers the per-parameter contract; this is a structurally different
  whole-app contract, so a new stable ID rather than an amendment). No other component's
  contracts change; `fuzzlab/oracle/`, `fuzzlab/harness/`, `fuzzlab/web/` untouched;
  `oracle_wrapper.py`, `resolver.py`, `schema.py`, `verdict.py`, `subseed.py`, `gates.py`,
  `denylist.py`, and any `nuclei_oracle.py` are untouched (other lanes' files) —
  `fuzzlab/labgen/__init__.py` gains only additive re-exports for the two new symbols.
- Risk (level; mitigation): medium (same class as `CC-LAB-0016`/`CC-LAB-0017`: a defect
  here could make a generated cell's ground-truth label wrong). Mitigated by: the manual
  curl+ZAP validation of both twins before any test was written (both directions, through
  the wrapper itself, before the offline suite existed); parsing the tool's own detailed,
  structured report rather than trusting its opaque exit code (the same discipline already
  applied to sqlmap/commix, generalized here to a fourth, differently-shaped tool);
  deleting any pre-existing report file before each attempt so a crash can never be
  misclassified from stale data left by an earlier run; per-invocation isolated temp
  directories (never a shared/reused ZAP home or report path unless the caller explicitly
  opts in) so no invocation can inherit another's state; 22 new offline tests (loopback
  refusal, missing-binary, plan construction incl. include-paths/report-template/no-
  exitStatus-job/`-dir` isolation, scoped and unscoped verdict classification, risk-
  threshold filtering and case-insensitivity, bounded timeout/retry exhaustion and early
  stop, crash-with-no-report, malformed-report-JSON, the stale-report-not-classified case,
  and temp-dir ownership/cleanup for both the wrapper-owned and caller-supplied cases) plus
  1 new real, skip-guarded integration test (PA-0005) that shells out to the real
  downloaded ZAP against a genuinely non-vulnerable static-HTML endpoint. ZAP is not a
  declared project dependency (a ~230MB JVM app, heavier than the other three CLI tools);
  the integration test skips cleanly, not fails, when it isn't reachable (`PATH` or
  `FUZZLAB_ZAP_PATH`).
- Deliverables:
  - [x] `docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md` — done.
  - [x] `fuzzlab/labgen/zap_oracle.py` (`ZapWholeAppScanRequest`, `ZapScanVerdict`,
        `run_zap_whole_app_scan`) — done.
  - [x] Scoped (`alert_name_pattern`) and unscoped (whole-app safety-net) verdict modes,
        risk-threshold filtering — done.
  - [x] Never trusts ZAP's own exit code; always parses the JSON report; per-invocation
        isolated temp dirs; stale-report protection — done.
  - [x] 22 new offline tests + 1 new skip-guarded real-binary integration test — done (all
        pass; also verified manually end to end against the real vulnerable/secure Flask
        apps through the wrapper before the test suite was written).
  - [x] `docs/LAB_SEED_AUTHORING_PLAYBOOK.md` "SSTImap/Nuclei/ZAP remain unintegrated"
        line updated — done.
  - [x] `requirements.md` FR-LAB-20 added — done.
  - [ ] An original Tier-A seed whose security assertion actually calls this wrapper (or
        the sqlmap/commix/SSTImap one) — not started, tracked in the playbook (unchanged
        from `CC-LAB-0016`/`CC-LAB-0017`).
- Effectiveness (assessed 2026-09-21): effective against its own test suite — full suite
  644 passed / 6 skipped (6 of the skips are this and prior lanes' real-binary integration
  tests skipping cleanly without the real tools on `PATH`; the baseline before this change
  was 622 passed / 5 skipped), plus the 2 known pre-existing, unrelated
  `test_mutation_operators.py` failures (untouched, out of scope). All 23 zap_oracle tests
  (22 offline + 1 integration) pass with the real ZAP binary wired in via
  `FUZZLAB_ZAP_PATH`. Full effectiveness (a real seed's label correctly confirmed by this
  wrapper against a real vulnerable/secure twin pair, or as a genuine supplementary
  safety-net check across a generated app) is assessed once the playbook's own next step is
  attempted, same as the prior three tool-oracle entries.

### CC-LAB-0017 — SSTImap oracle support: Spike 003 + wrapper extension (2026-09-21)
*(Numbered `CC-LAB-0017` rather than `CC-LAB-0016` at merge time — this lane's worktree
was based on a commit that predated `CC-LAB-0016` (Phase 0 foundation) landing, so it
independently claimed `0016` too. No content changed; purely a numbering fix.)*
- Change: two parts, following this project's established "spike, then wrap" rigor
  (per `LAB_SEED_AUTHORING_PLAYBOOK.md`'s "SSTImap/Nuclei/ZAP remain unintegrated" line
  and `CR-LAB-0001`'s tool-mapping table, "SSTI / code injection → SSTImap").
  (1) `docs/spikes/SPIKE-003-sstimap-vs-ssti-flask-hacking-playground.md` — cloned
  `vladko312/SSTImap` (GPL-3.0, license read directly, cite-only per this project's
  existing posture) and `filipkarc/ssti-flask-hacking-playground` (Apache-2.0, license
  read directly) into the session scratchpad, ran the app natively (loopback-only), and
  confirmed a real Jinja2 SSTI (`?user={{7*7}}` → `Hi 49`) manually with curl before
  ever touching the tool, per this project's established discipline. Authored a minimal
  secure twin (`secure_app.py`, scratchpad only, not committed) differing only in the
  one transform that matters (`user` passed as a Jinja2 context variable and referenced
  via `{{ user }}`, instead of `.format()`-ed into the template source before
  compilation) since the demo app ships no secure twin of its own. Ran `sstimap.py`
  headlessly against both: correct positive (Jinja2 engine, rendered technique, full
  capabilities) on the vulnerable endpoint; correct "Tested parameters appear to be not
  injectable" on the secure twin; both in under 2 seconds, no hang, no interactive
  prompt. Two design-relevant findings, neither a defect: SSTImap has no `-p`-style
  parameter selector — the equivalent scoping mechanism is its own marker substituted at
  the declared parameter's exact value plus its `-P` location-category restriction
  (verified directly: a marked run ignored an irrelevant static field in well under a
  second, and even an *unmarked* run with every field present tested only the one
  reflected parameter, thanks to SSTImap's own reflection/stability pre-check — a real
  negative finding, not relied upon as a substitute for explicit scoping); and SSTImap
  has no sqlmap-style 401/403 auth-abort behavior (`core/matcher.py` read directly: the
  status code is only ever one of several boolean-blind matching signals, never a hard
  gate), so no `--ignore-code`-equivalent field was needed. No hang, crash, or
  status-code mishandling was found, so nothing was logged to `ERROR_LOG.md` for the
  spike itself (contrast Spikes 001/002, each of which surfaced a real workaround-worthy
  defect in the tool/target interaction being validated).
  (2) Extended `fuzzlab/labgen/oracle_wrapper.py` (from `CC-LAB-0015`) with SSTI support,
  reusing the existing pattern exactly: `VulnClass.SERVER_SIDE_TEMPLATE_INJECTION`,
  `ServerSideTemplateInjectionOracleRequest` (no `secure_status_codes` field — see the
  spike finding above), and `run_server_side_template_injection_oracle`, dispatched from
  the existing `run_oracle`. New helpers `_mark_query_param`/`_mark_body_param` build the
  marked URL/body; `_build_sstimap_argv` places the marker in the right location
  (query/body/header) and sets `-P`/`-M` accordingly, splits a `;`-joined cookie string
  into SSTImap's stackable `-C Field=Value` flags, and reuses `assert_loopback`,
  `locate_tool`, `_resolve_session` (the `refresh_session` callback), and `_run_bounded`
  (the bounded timeout × `max_attempts` safety valve) completely unchanged — no parallel
  design was introduced. Verdict markers tuned against SSTImap's real output
  (`"identified the following injection point"` / `"appear(?:s)? to be not injectable"`),
  confirmed correct against both the real vulnerable and real secure endpoint through the
  wrapper itself before writing the offline test suite.
- Impact (other components / project): extends `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`'s
  validated tool-oracle set from {SQL injection, OS command injection} to {SQL injection,
  OS command injection, server-side template injection}; the playbook's "SSTImap/Nuclei/
  ZAP remain unintegrated" line now reads "SSTImap integrated; Nuclei/ZAP remain
  unintegrated." `requirements.md` FR-LAB-11 amended in place (not superseded — it already
  described a per-class, per-tool contract; this generalizes points (a)/(c)/(d) to state
  which parts are SQLi-specific vs. shared, and lists the new dataclass/function). No
  other component's contracts change; `fuzzlab/oracle/`, `fuzzlab/harness/`, and
  `fuzzlab/web/` are untouched; no overlap with Lane B's concurrently-developed
  `lab/generator/`, `lab/safety_matrix.yaml`, `lab/patterns/`, or `lab/manifests/` paths.
- Risk (level; mitigation): medium (same class as `CC-LAB-0015`: a defect here could make
  a generated cell's ground-truth label wrong). Mitigated by: reusing the already-tested
  `assert_loopback`/`locate_tool`/`_resolve_session`/`_run_bounded`/`_classify` machinery
  unchanged rather than re-implementing it for a third tool; the manual curl confirmation
  of both twins before the tool was ever invoked; 12 new offline unit tests (loopback
  refusal, missing-binary, marker+`-P` construction for all three `ParamLocation` values
  incl. that untouched fields are never swept, custom-marker `-M`, cookie→stackable-`-C`
  splitting, absence of a `secure_status_codes` field, vulnerable/secure/timeout
  classification, `run_oracle` dispatch) plus 1 new real, skip-guarded integration test
  (PA-0005) that shells out to the real cloned `sstimap.py` against the same non-vulnerable
  echo endpoint the sqlmap/commix integration tests already use. Neither SSTImap nor the
  demo app is a declared project dependency; the integration test skips cleanly, not
  fails, when the binary isn't reachable (`PATH` or `FUZZLAB_SSTIMAP_PATH`).
- Deliverables:
  - [x] `docs/spikes/SPIKE-003-sstimap-vs-ssti-flask-hacking-playground.md` — done.
  - [x] `VulnClass.SERVER_SIDE_TEMPLATE_INJECTION`,
        `ServerSideTemplateInjectionOracleRequest`,
        `run_server_side_template_injection_oracle`, `run_oracle` dispatch — done.
  - [x] Marker + `-P`/`-M` scoping (Spike 003's `-p`-equivalent) for all three
        `ParamLocation` values — done.
  - [x] 12 new offline tests + 1 new skip-guarded real-binary integration test — done
        (all pass; also verified manually end to end against the real vulnerable/secure
        Flask apps before the test suite was written).
  - [x] `docs/LAB_SEED_AUTHORING_PLAYBOOK.md` "SSTImap/Nuclei/ZAP remain unintegrated"
        line and "Recommended next action" step 1 updated — done.
  - [x] `requirements.md` FR-LAB-11 amended in place — done.
  - [ ] An original Tier-A seed whose security assertion actually calls this wrapper
        (playbook step 2) — not started, tracked there (unchanged from `CC-LAB-0015`).
- Effectiveness (assessed 2026-09-21): effective against its own test suite — full suite
  546 passed / 5 skipped (3 of the skips are this change's + the prior change's
  integration tests skipping cleanly without the real binaries on `PATH`; 2 pre-existing),
  plus the 2 known pre-existing, unrelated `test_mutation_operators.py` failures (untouched,
  out of scope). All 48 labgen-oracle-wrapper tests (33 sqlmap/commix + 12 SSTI offline + 3
  integration) pass with the three real binaries wired in via
  `FUZZLAB_SQLMAP_PATH`/`FUZZLAB_COMMIX_PATH`/`FUZZLAB_SSTIMAP_PATH`. Full effectiveness (a
  real seed's label correctly confirmed by this wrapper against a real vulnerable/secure
  twin pair) is assessed once playbook step 2 is attempted, same as `CC-LAB-0015`.

### CC-LAB-0015 — Reusable sqlmap/commix oracle wrapper (Lane A, `LAB_SEED_AUTHORING_PLAYBOOK.md` step 1) (2026-09-21)
- Change: added `fuzzlab/labgen/oracle_wrapper.py` (+ minimal `fuzzlab/labgen/__init__.py`
  re-exporting only its own public API) — the reusable, importable wrapper the playbook's
  "Recommended next action" step 1 called for, replacing "ad-hoc CLI invocations" with a
  shared function per validated class. `run_sql_injection_oracle(SqlInjectionOracleRequest)`
  and `run_command_injection_oracle(CommandInjectionOracleRequest)` (plus a
  type-dispatching `run_oracle`) each: (1) validate the target is loopback
  (`assert_loopback`) before doing anything else, raising `OracleSafetyError` otherwise —
  never silently proceeding (CLAUDE.md safety section, Addendum E); (2) locate the tool
  executable via `PATH` or an injectable `tool_path`, raising a typed, actionable
  `ToolNotFoundError` instead of a raw `FileNotFoundError` (BUG-0007/PA-0021's pattern,
  applied here proactively rather than as a fix); (3) translate a caller-given
  `secure_status_codes` list into sqlmap's `--ignore-code` automatically (Spike 001's
  401/403 lesson) — commix has no equivalent flag, so this field only exists on the
  SQLi request; (4) always scope the tool invocation to the one declared `param_name` via
  `-p` (Spike 002's parameter-sweep lesson) — never a blind sweep; (5) run under a hard
  per-attempt subprocess timeout via a dependency-injected `Runner` callable (never
  `subprocess` touched globally, never the tool's own less-reliable internal timeout
  flags), with a bounded `max_attempts` loop that calls an optional `refresh_session`
  callback fresh on every attempt before rebuilding the argv — so total wall time is
  always bounded by `timeout_s * max_attempts` regardless of how the caller configures
  retries or session refresh (Spike 002's rotating-CSRF-token lesson, part 2). Verdicts
  are exactly `confirmed_vulnerable | confirmed_secure | inconclusive`
  (`fuzzlab.labgen.oracle_wrapper.Verdict`); a timeout, non-zero exit with no verdict
  marker in the tool's own output, or an ambiguous/missing marker is always
  `inconclusive` — a crash or hang is never treated as "secure" (fail-closed). Verdict
  markers and the tool-exit-code check were tuned against the two tools' **real** output
  (see Deliverables) after an initial draft wrongly gated on exit code 0, which both
  sqlmap and commix violate on a legitimate "not injectable" finding, not only on a
  crash — caught by the real-binary integration test before it shipped, not left latent.
  Deliberately self-contained: no manifest/cell schema type is imported or assumed
  (Lane B owns that schema, built concurrently); callers pass plain, explicit parameters
  instead. Deliberately unrelated to and never imported by `fuzzlab/oracle/` (the FUZZ
  component's runtime detection oracle) — same word, different tool, different component.
- Decision point (session/token-refresh vs. bounded-retry safety valve, both named in the
  brief as the two options for Spike 002's CSRF-rotation lesson, "pick the simpler, more
  robust one"): implemented the **bounded timeout × bounded max_attempts loop as the
  mandatory safety valve**, plus a **lightweight optional `refresh_session` callback**
  called once per attempt (not per-HTTP-request inside the tool's own crawl) as the
  session-refresh half. Rejected: building generic per-HTTP-request session-refresh
  hooks into sqlmap's/commix's own request loop (e.g. proxying every request through a
  refreshing middleman) — that requires reverse-engineering and staying in sync with each
  tool's internal request architecture (a much larger, more fragile surface, and neither
  tool exposes a stable public hook for it), whereas a subprocess timeout is a property of
  *any* subprocess regardless of what it does internally, so it robustly bounds a hang from
  *any* cause (a stale token, a network stall, an unrelated bug in the tool), not only the
  one cause Spike 002 happened to hit. The per-attempt `refresh_session` callback still
  covers the common case (a fresh cookie/CSRF token per *attempt*, sufficient for a tool run
  short enough that the token doesn't rotate mid-run) without the larger integration cost.
- Impact (other components / project): fulfills `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`'s
  "Recommended next action" step 1 (marked done there, pointing here). Unblocks step 2
  (an original Tier-A seed's security assertion becomes a call to this wrapper). No other
  component's contracts change; `fuzzlab/oracle/`, `fuzzlab/harness/`, and `fuzzlab/web/`
  are untouched. New `requirements.md` FR-LAB-11 documents the wrapper's contract (FR-LAB-10
  already covered "use the tool headlessly"; FR-LAB-11 covers the wrapper's own interface
  guarantees, which are new). Lane B's concurrently-developed manifest/schema/gates work is
  unaffected — this module takes no dependency on it and was designed not to.
- Risk (level; mitigation): medium (a defect here could make a generated cell's ground-truth
  label wrong, silently corrupting every downstream metric — the same risk class
  `CC-LAB-0002` already flagged for hand-authored labels). Mitigated by: fail-closed
  verdict logic (ambiguity is always `inconclusive`, never a guess); the mandatory
  loopback check with no bypass; 33 offline unit tests covering every branch (loopback
  accept/reject incl. no-scheme/spoofed-suffix hosts, tool-found/not-found via injected
  `shutil.which`, `--ignore-code` construction present/absent, parameter-scoping for both
  tools, cookie/header merging and `refresh_session` cookie-splitting, bounded-retry
  exhaustion and early-stop, timeout/non-zero-exit/vulnerable/secure/ambiguous/both-markers
  classification, `run_oracle` dispatch + rejection of an unknown request type, all three
  `ParamLocation` values); plus 2 real, skip-guarded integration tests (PA-0005) that
  actually shell out to a real cloned `sqlmap`/`commix` against a genuinely non-vulnerable
  local echo endpoint and assert a real `confirmed_secure` verdict end to end — these
  caught the exit-code-gating defect described above before it shipped. Neither tool is a
  declared project dependency (they are external, licensed-separately tools the wrapper
  merely shells out to, matching sqlmap's/commix's own licensing — nothing from either is
  vendored or copied); the integration tests skip cleanly, not fail, when the binaries
  aren't reachable (checked via `PATH` or `FUZZLAB_SQLMAP_PATH`/`FUZZLAB_COMMIX_PATH`).
- Deliverables:
  - [x] `fuzzlab/labgen/oracle_wrapper.py` + minimal `fuzzlab/labgen/__init__.py` — done.
  - [x] `--ignore-code` auto-construction from `secure_status_codes` (Spike 001) — done.
  - [x] Mandatory single-parameter scoping for both tools (Spike 002 part 1) — done.
  - [x] Bounded timeout × bounded-attempt safety valve + per-attempt `refresh_session`
        (Spike 002 part 2) — done.
  - [x] Loopback-only safety guard, no bypass — done.
  - [x] Typed `ToolNotFoundError` (never a raw `FileNotFoundError`) — done.
  - [x] 33 offline tests, injected fake runner, every branch — done (all pass).
  - [x] 2 skip-guarded real-binary integration tests (real `sqlmap`/`commix` cloned this
        session, not committed; a non-vulnerable local echo endpoint) — done (both pass
        when the binaries are present; both skip cleanly otherwise).
  - [x] `docs/LAB_SEED_AUTHORING_PLAYBOOK.md` "Recommended next action" step 1 marked done,
        pointing here — done.
  - [ ] An original Tier-A seed whose security assertion actually calls this wrapper
        (playbook step 2) — not started, tracked there.
- Effectiveness (assessed 2026-09-21): effective against its own test suite — 35 new tests
  (33 offline + 2 real-binary integration) all pass; the integration tests exercise the
  actual code path the offline suite's fake runner bypasses (PA-0005) and, in doing so,
  caught and fixed a wrong assumption (exit-code-0 gating) that the offline suite alone
  could not have caught since it only asserts what its own author assumed about the real
  tools' behavior. Full effectiveness (a real seed's label correctly confirmed by this
  wrapper against a real vulnerable/secure twin pair) is assessed once playbook step 2
  is attempted.

### CC-LAB-0020 — T-LAB0.8: mechanical OSV/GHSA pull + candidate-list tooling (2026-09-21)
*(Numbered `CC-LAB-0020` rather than `CC-LAB-0019` at merge time — this lane's worktree
was based on a commit that predated `CC-LAB-0019` (the emitter) landing, so it
independently claimed `0019` too. No content changed; purely a numbering fix.)*
- Change: added `fuzzlab/tools/pattern_corpus_sourcing.py`, implementing steps
  1-5 (pull, index, scope, rank, cluster) of the pattern-corpus sourcing
  pipeline in `docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md` (Revision 2) —
  **deliberately not** step 6/7 (human triage, card authoring), per that
  plan's own explicit rule ("human, on cluster representatives only") and per
  the task brief for this entry.
  - **Pull:** `sync_advisory_database()` clones/pulls `github/advisory-database`
    (git, not the OSV or GHSA APIs — confirmed against the plan's own
    research: the OSV REST API has no CWE filter, and unauthenticated GHSA
    GraphQL is rate-limited to 0 req/hour) into a local, gitignored cache
    (`.cache/advisory-database`, new `.gitignore` entry — never the
    deliverable; the deliverable stays the small, hand-curated
    `lab/patterns/cards/*.yaml`). Verified the real repository's OSV JSON
    schema directly: cloned a small sparse slice
    (`advisories/github-reviewed/2024/01`) during development to confirm
    `id`/`summary`/`details`/`published`/`database_specific.cwe_ids`/
    `affected[].package.ecosystem` match this module's parser — that probe
    checkout was discarded, not committed.
  - **Index:** `iter_advisories()`/`parse_advisory_file()` parse only
    `github_reviewed` advisories (the plan measured ~90% of the rest as
    unusable, median 321 characters, no structured prose).
  - **Scope:** `scope()` filters by the plan's target ecosystems (npm, PyPI,
    Packagist, Maven), a 24-month currency window, and a new, versioned CWE/
    keyword crosswalk (`lab/patterns/sourcing/crosswalk.yaml`, all ten
    first-wave classes from the plan's §5, including the CWE-94
    keyword-gating correction for SSTI's under-counted crosswalk). A
    multi-CWE advisory's losing class matches are recorded in
    `other_matches`, never silently dropped, per the plan's precedence rule
    (declaration order in the crosswalk file).
  - **Rank:** `rank()` scores by prose length + a structured-heading bonus
    (plan step 4); EPSS/KEV tiebreakers from the plan are **not** implemented
    (another external network dependency this environment's egress proxy
    does not clear for osv.dev-adjacent domains — confirmed by a direct
    reachability check during this delivery) and are flagged as a documented,
    easy follow-up rather than silently attempted and failing.
  - **Cluster:** `cluster_by_shape()` is a lightweight, dependency-free
    token-overlap (Jaccard) greedy clustering — an explicit, documented
    stand-in for the plan's eventual embedding-based clustering (avoids
    pulling in a heavy ML dependency / model download for this delivery);
    swapping in a real embedding model later is scoped to this one function.
  - **Emit:** `run_refresh()` writes a per-quarter candidate list
    (`lab/patterns/refresh/<quarter>-candidates.json`) and a human-readable
    report (`lab/patterns/refresh/<quarter>.md`), and appends one line to
    `lab/patterns/REFRESH_LOG.md` (new, per the plan's exact file layout) —
    **idempotent**: re-running against an unchanged upstream commit SHA
    overwrites the quarter's files with identical content and does not
    append a duplicate log line (deduped by SHA).
  - A test (`test_run_refresh_never_writes_to_cards_or_provenance`) asserts
    a `run_refresh()` call leaves `lab/patterns/cards/*.yaml` and
    `lab/patterns/provenance.yaml` byte-for-byte unchanged — mechanically
    enforcing this entry's scope boundary, not just stating it.
  - Live network: confirmed `git ls-remote` reachability to
    `github.com/github/advisory-database` directly in this environment
    (`osv.dev` itself is proxy-blocked here, consistent with the plan's own
    "GHSA git mirror is the primary and effectively only source" finding).
    A full clone (~3.3 GB, ~4 min per the plan) is intentionally **not**
    exercised by this delivery or its test suite — too heavy for a routine
    test run; the one live test is a cheap reachability probe only, and is
    auto-skipped (not failed) if the environment running it can't reach
    GitHub, matching this repo's existing `skipif`-on-capability-probe
    convention (e.g. `tests/test_lab_waf.py`'s `PHP is None` guard).
- Impact (other components / project): none — new, self-contained tool file
  plus new data files under `lab/patterns/sourcing/`; does not import from or
  get imported by `fuzzlab/labgen/`, `fuzzlab/oracle/`, `fuzzlab/harness/`, or
  `fuzzlab/web/`. Does not modify `lab/patterns/cards/`,
  `lab/patterns/provenance.yaml`, or `lab/patterns/taxonomy/classes-v1.yaml`
  (that taxonomy is card-authoring vocabulary — a separate concern from this
  tool's own sourcing-scope crosswalk, which is why the crosswalk lives at
  `lab/patterns/sourcing/crosswalk.yaml` rather than being folded into it).
- Risk (level; mitigation): **low**. No secrets involved (anonymous,
  unauthenticated git access only); the cache directory is gitignored so a
  multi-gigabyte clone can never be committed by accident. Main risk
  accepted: the clustering heuristic is a simplification of the plan's
  eventual embedding-based approach and may under- or over-cluster on real,
  messier advisory prose than the synthetic test fixtures — mitigated by
  keeping the human triage step (step 6) fully in the loop regardless (this
  tool narrows hundreds of candidates to tens, it never decides for the
  human), and by the fact that a clustering miss costs a human an extra
  minute reviewing one more representative, not a wrong card.
- Deliverables:
  - [x] `fuzzlab/tools/pattern_corpus_sourcing.py`: pull/index/scope/rank/
        cluster/emit pipeline + CLI (`probe`, `refresh`) — done.
  - [x] `lab/patterns/sourcing/crosswalk.yaml`: versioned CWE/keyword
        crosswalk, all ten first-wave classes — done.
  - [x] `.gitignore`: `.cache/` entry for the local advisory-database mirror
        — done.
  - [x] 34 offline tests (`tests/test_pattern_corpus_sourcing.py`): parsing,
        crosswalk matching incl. keyword-gating, scoping, ranking,
        clustering (incl. order-independence and max-alternates), candidate-
        list shape (asserts no card-authoring fields leak in), git-sync layer
        via a fake runner, `run_refresh()` end-to-end + idempotency + the
        never-touches-cards-or-provenance guard, CLI smoke tests, one
        auto-skipped live reachability probe — done.
  - [x] `FR-LAB-18` added to `requirements.md`; status line and interfaces
        section updated — done.
  - [ ] The real 25-30/~31-card corpus authoring (plan steps 6/7) — **not
        started, separate human-supervised follow-up task**, unaffected by
        this entry (this tool produces its *input*, nothing more).
  - [ ] EPSS/KEV ranking tiebreakers — not implemented (network-dependency
        risk in this environment); documented as a follow-up, not silently
        dropped.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — 34 new
  tests pass, including a live-verified real advisory JSON schema match
  (checked directly against a real, small sparse clone during development,
  discarded afterward) and a live (auto-skip-guarded) reachability check
  that actually ran and passed in this environment. Full suite: 656 passed,
  5 skipped, 2 pre-existing unrelated `test_mutation_operators.py` failures
  (baseline was 622/5/2 before this entry — delta is exactly the 34 new
  tests). Also observed, unrelated to this change: an intermittent flake in
  `tests/test_web_repeater.py::test_route_send_reaches_upstream_when_authorized`
  (an SQLite thread-affinity error in `fuzzlab/web/proxycontrol.py`/
  `fuzzlab/proxy/repeater.py`, out of this entry's scope — not investigated
  or fixed here, flagged for whoever owns that component). Not yet
  assessable: whether the mechanical scope/rank/cluster output actually
  reduces a human's real triage effort as intended against the real, full
  ~35,729-advisory corpus — that can only be judged once someone runs
  `refresh` for real and does the step-6 triage it's meant to support.

### CC-LAB-0018 — T-LAB0.3: real covering-array resolver over `covertable` (2026-09-21)
*(Numbered `CC-LAB-0018` rather than `CC-LAB-0017` at merge time — this lane's worktree
was based on a commit that predated `CC-LAB-0017` (SSTImap support) landing, so it
independently claimed `0017` too. No content changed; purely a numbering fix.)*
- Change: added `fuzzlab/labgen/resolver.py`, the real covering-array expansion
  engine called for by `docs/LAB_PHASE_0_PLAN.md` T-LAB0.3 (previously
  "deliberately dormant" in `fuzzlab/labgen/schema.py`, which is unchanged by
  this entry — this is new, additive, self-contained code, not a rewrite of
  the manifest IR).
  - Uses `covertable` 3.2.0 (Apache-2.0), exact-pinned in `pyproject.toml`
    (`covertable==3.2.0`, not a range) — a version bump is treated as a
    `manifest_version` bump per the plan's own rule, documented in the
    module's docstring rather than mechanically enforced (no corpus depends
    on this yet to enforce it against).
  - `validate_covering_array_config()` validates a raw `{factors, strength?,
    sub_models?, constraints?}` mapping against an **explicit allowlist**
    before any of it reaches `covertable.make()`. Verified directly against
    the installed 3.2.0 package's source (`covertable/main.py`) and with a
    live reproduction in `tests/test_labgen_resolver.py` that
    `covertable.make(..., some_bogus_kwarg=True)` runs successfully and
    silently ignores the bogus kwarg via its own `**params` — exactly the
    "wrong-granularity/silently-wrong-answer" failure mode
    `docs/PREVENTIVE_ACTIONS.md` PA-0010 warns about. The adapter raises
    `CoveringArrayError` for any key outside `{factors, strength, sub_models,
    constraints}` instead.
  - `expand()` always calls `covertable.make()` with `sorter=covertable.sorters.hash`
    passed explicitly — never the library's default — per the plan's own
    instruction that array-stability across covertable releases isn't
    documented. `sorter` is deliberately excluded from the allowlist so a
    caller cannot override the pin even accidentally.
  - Supports pairwise (default `strength=2`) and mixed-strength expansion via
    `sub_models`, and declarative, JSON-serializable `constraints` (validated
    via `json.dumps()` round-trip, which also rejects covertable's own `"fn"`
    constraint operator since a Python callable isn't JSON-serializable — an
    intentional restriction, not an oversight, since the whole point of this
    allowlist is a manifest-embeddable, non-code representation).
  - Snapshot-tested (`tests/golden/labgen_covering_array_v1.json`) against a
    synthetic 3-axis model (class/stack_profile/sink_context_family) — not the
    real Phase 0/1 corpus, which doesn't need this yet — plus a determinism
    check that spawns three separate subprocesses under different
    `PYTHONHASHSEED` values and asserts byte-identical output (the pinned
    `sorters.hash` is FNV-1a32-based, not Python's randomized string hash, so
    this is a real, not merely same-process, determinism guarantee).
  - Added `resolver` to `fuzzlab/labgen/__init__.py`'s re-exports (additive
    only — `oracle_wrapper.py` untouched).
- Impact (other components / project): none yet — `resolver.py` is new,
  self-contained, and is not called from `fuzzlab.labgen.schema`'s manifest
  loading or from any other component. Wiring it into manifest loading (so a
  manifest can declare axis sets instead of enumerating cells) is separate,
  later work, per the task brief for this entry and per the plan's own
  phasing (Phase 1 is where covering-array expansion actually turns on for
  the real corpus).
- Risk (level; mitigation): **low**. New dependency (`covertable`) is
  Apache-2.0, exact-pinned, and used only by this new module; its
  `sorters.hash` sort is FNV-1a32 (a fixed, documented, unsalted hash) rather
  than anything cryptographic or randomized, so no salt/secret-handling risk.
  Main risk accepted: `covertable`'s own array-construction algorithm
  (greedy + backtracking + optional constraint propagation) is third-party
  code this project does not re-verify at that level — mitigated by treating
  its output as opaque and testing only the *properties* this project
  actually depends on (every pairwise combination covered at least once,
  determinism, constraint satisfaction), not its internal implementation.
- Deliverables:
  - [x] `fuzzlab/labgen/resolver.py`: `validate_covering_array_config()` +
        `expand()` — done.
  - [x] `covertable==3.2.0` declared in `pyproject.toml` — done.
  - [x] Snapshot test + PA-0010 kwargs-allowlist test + determinism-across-processes
        test + sub_models/constraints behavioral tests
        (`tests/test_labgen_resolver.py`, 16 tests) — done.
  - [x] `FR-LAB-17` added to `requirements.md`; status line and interfaces
        section updated — done.
  - [ ] Wiring `expand()` into `fuzzlab.labgen.schema`'s manifest loading (so
        a manifest can declare axis sets instead of enumerating cells) — not
        started; explicitly out of scope for this entry, tracked for Phase 1.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — 16 new
  tests pass, including a live reproduction of the exact silent-swallow
  failure mode this module exists to prevent, and a cross-process determinism
  check (stronger than a same-process one, since `PYTHONHASHSEED`
  randomization is invisible within one process). Full suite: 610 passed, 4
  skipped, 2 pre-existing unrelated `test_mutation_operators.py` failures
  (baseline was 594/4/2 before this entry — the delta is exactly the 16 new
  tests). Not yet assessable: whether `covertable`'s array sizes actually
  match or beat ACTS's published reference sizes for this project's real
  Phase-1 axis model, since that model doesn't exist yet — deferred to
  Phase 1's own CC entry when `expand()` is actually wired in.

### CC-LAB-0016 — Phase 0 foundation: pipeline verdict engine, safety matrix, determinism + name-leak gates, patterns/ scaffold (2026-09-21)
*(Renumbered from `CC-LAB-0015` at merge time — both this entry and the one above were
authored concurrently from the same base commit and independently numbered themselves
`CC-LAB-0015`. No content changed; this is purely a numbering fix so the append-only log
has no duplicate ID.)*
- Change: first real code delivery for `CR-LAB-0001`/D20's Phase 0 ("Foundation").
  Built:
  - `lab/schemas/manifest.schema.json` and `lab/schemas/safety_matrix.schema.json`
    (JSON Schema) — `transform` as an ordered pipeline of ops (never a single enum)
    and `sink_context` as a structured `{family, required_neutralizations}` object
    (never a bare string), per `CR-LAB-0001` §3. Sanity-checked (not migrated)
    against two real `puppy-fort-factory/VULNERABILITIES.md` shapes (`product.php`'s
    raw-concat numeric-context SQLi; `profile.php`'s stored-XSS shape recast as an
    escaping-context mismatch) via `lab/manifests/example_phase0_scaffold.yaml`.
  - `fuzzlab/labgen/verdict.py` (T-LAB0.1/T-LAB0.2): `SafetyMatrix` loader/validator
    for `lab/safety_matrix.yaml` (v1, an open append-only registry) and the pure,
    versioned `verdict(pipeline, sink_context, matrix)` function implementing D20's
    **binary** verdict — a `partial` effect stays VULNERABLE and only raises a
    `difficulty` tier, never a third verdict value. Snapshot-tested against
    `tests/golden/labgen_verdict_v1.json` (same convention as
    `tests/test_features_golden.py`), plus 13 behavioral tests covering the
    escaping-context-mismatch and pipeline-order-sensitivity shapes.
  - `fuzzlab/labgen/schema.py` (T-LAB0.3 foundation, deliberately dormant): manifest
    loader/validator + the `Pipeline`/`SinkContext`/`Cell`/`Manifest` IR. No
    covering-array expansion yet — Phase 0's manifest lists cells explicitly, one
    axis level each, per `docs/LAB_PHASE_0_PLAN.md`'s own allowance for this task.
  - `fuzzlab/labgen/subseed.py` (T-LAB0.5 scaffold): `derive_subseed()`
    (`HMAC-SHA256(root_seed, cell_id\|transform\|sink_family\|stack_profile)`),
    `canonical_json()` (sorted keys, no floats, stdlib `json` only — no formatter,
    per that task's own rule), and `render_cell_stub()`, a minimal deterministic
    per-cell renderer built only to give the determinism gate something real to
    regenerate — explicitly **not** T-LAB0.4's real per-stack/module-composition
    emitter.
  - `fuzzlab/labgen/gates.py` + `denylist.py` (T-LAB0.5/T-LAB0.6): `regenerate_and_diff()`
    (runs the scaffold generator twice from the same manifest+seed, raises on any
    byte difference) and `scan_name_leaks()`/`scan_generated_tree_for_name_leaks()`
    (NFR-LAB-no-leak), matching on vulnerability-class-name substrings with a
    letter-boundary rule (rejects `xss` inside `maxssl`, accepts `xss_payload`) and
    validated against a should-flag/should-not-flag fixture set per
    `docs/LAB_PHASE_0_PLAN.md` T-LAB0.6's own requirement that a scanner's
    no-false-negatives property be established by testing, not code review.
  - `lab/patterns/` provenance-corpus **scaffold**: `taxonomy/classes-v1.yaml` (2
    classes), 3 example `cards/pc-*.yaml` (schema: `lab/schemas/pattern_card.schema.json`),
    and a one-directional `provenance.yaml` (`cell_id -> [card_id]`) per Addendum A —
    the manifest carries no card reference, mechanically enforced by
    `tests/test_labgen_gates.py::test_provenance_is_one_directional_no_leak_into_verdict_source`.
    **The full 25-30-card first-wave corpus is explicitly out of scope for this
    entry** — it requires human OSV/GHSA triage per
    `docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md` and is tracked as a separate,
    human-supervised follow-up task (see `lab/patterns/README.md`).
  - Added `PyYAML>=6.0,<7` to `pyproject.toml` (PA-0005: it is imported directly by
    `fuzzlab/labgen/schema.py` and `verdict.py` and was previously present only
    transitively).
  - **Location decision (documented per `docs/LAB_PHASE_0_PLAN.md`'s own open
    "confirm paths" review point):** Python code lives under `fuzzlab/labgen/`, not
    `lab/generator/` as that plan tentatively proposed, because `lab/` is not in
    `pyproject.toml`'s `[tool.setuptools.packages.find]` include list (not an
    importable package root) and a sibling, concurrently-developed module
    (`fuzzlab/labgen/oracle_wrapper.py`, the sqlmap/commix oracle wrapper, a
    separate work item) already lives there — splitting Phase 0's code across two
    import roots would cost more at merge time than it would gain. Data/config
    assets (`manifests/`, `safety_matrix.yaml`, `patterns/`) live under `lab/` as
    that plan specifies, since they are data, not import targets.
  - **Explicitly not built here** (separate follow-up tasks, not attempted):
    T-LAB0.3's real covering-array expansion; T-LAB0.4's per-stack,
    module-composition emitter (`sources`/`transforms`/`sinks`/`complexities`
    modules per NIST VTSG's schema); T-LAB0.7's tiered conformance suite; the full
    pattern-card corpus; migrating or reproducing `puppy-fort-factory/`'s real ~30
    pages (this delivery sits alongside it, unchanged, per the additive-only
    mandate — nothing in `puppy-fort-factory/` or `lab/ground-truth/` was touched).
- Impact (other components / project): none yet on other components' contracts —
  `fuzzlab/labgen/` is new, self-contained, and imports nothing from `fuzzlab.oracle`,
  `fuzzlab.web`, or the not-yet-existing `oracle_wrapper.py`. FUZZ's label-contract
  schema (`fuzzlab/labels/`) is untouched; the CR-LAB-0001 §4 FUZZ-schema impact
  (`stack_profile`, `sink_endpoint`, identity model) lands in Phase 2, not here.
- Risk (level; mitigation): **low**. The scaffold renderer/regenerate-diff gate is
  self-contained test infrastructure, not wired into any build that touches the
  real lab; a bug there cannot affect `puppy-fort-factory/`'s served behavior. The
  main risk accepted: the safety-matrix v1 entries and example manifest are
  illustrative (sanity-checked against real page shapes, not migrated from them),
  so Phase 1's real rebuild may need additional matrix entries not yet anticipated
  here — expected and additive, not a defect in this delivery.
- Deliverables:
  - [x] `lab/schemas/manifest.schema.json` + `safety_matrix.schema.json` — done.
  - [x] `fuzzlab/labgen/verdict.py`: versioned, snapshot-tested `verdict()` — done.
  - [x] `fuzzlab/labgen/schema.py`: manifest IR (resolver dormant, per plan) — done.
  - [x] `fuzzlab/labgen/subseed.py`: sub-seed derivation + canonical serialization
        scaffold — done.
  - [x] `fuzzlab/labgen/gates.py`: regenerate-and-diff + name-leak scanner build
        gates, wired as pytest tests (`tests/test_labgen_gates.py`) — done.
  - [x] `lab/patterns/` scaffold: taxonomy + 3 example cards + one-directional
        `provenance.yaml` — done.
  - [ ] Full 25-30-card pattern corpus — **not started, separate human-supervised
        follow-up task** (out of scope for this entry).
  - [ ] T-LAB0.3 covering-array machinery, T-LAB0.4 module-composition emitter,
        T-LAB0.7 tiered conformance suite — not started, tracked in
        `docs/LAB_PHASE_0_PLAN.md`.
  - [ ] Real Phase-0 manifest reproducing today's ~30 PHP pages byte-identically —
        not started; this entry's example manifest is illustrative only.
- Effectiveness (assessed 2026-09-21): met this delivery's own bar — 60 new tests
  (schema validation incl. rejecting the pre-D20 bare-string/single-enum shapes;
  13 verdict behavioral tests + a golden-file snapshot; sub-seed determinism;
  regenerate-and-diff catching an injected nondeterminism bug in a monkeypatched
  generator; the name-leak scanner's should-flag/should-not-flag fixture set,
  including the `xss`-inside-`maxssl` collision case; the pattern-corpus shape)
  all pass; full suite otherwise green (561 passed, 2 skipped, 2 pre-existing
  unrelated `test_mutation_operators.py` failures, unaffected). Not yet assessable:
  whether the safety-matrix/manifest schema holds up unchanged once Phase 1
  actually rebuilds real cells against it — that is this delivery's real test and
  is deferred to the Phase 1 CC entry.

### CC-LAB-0014 — D20: manifest-driven generator target shape decided (2026-09-21)
- Change: approved `docs/change-requests/CR-LAB-0001-manifest-generator-realism-and-variation.md`
  and recorded **D20** in `docs/DECISIONS_AND_ROADMAP.md`. Three scope-gating decisions:
  (1) binary verdict model (a partially neutralized case is VULNERABLE-but-harder via a
  `difficulty` tier, not a third `hardened` verdict value); (2) the existing hand-built
  Puppy Fort Factory app is migrated into the generator at Phase 3, not kept as a
  permanent separate fixture; (3) the pattern-provenance corpus (`patterns/`) lives under
  LAB, not IND. Also decided: the three vulnerability classes with no mature automated
  security-assertion oracle (IDOR/BOLA, business-logic flaws, race conditions) are
  deferred indefinitely — no paid expert consultation for now. No code changed; this is a
  decision-of-record entry. `docs/ARCHITECTURE.md` §"Components and subcomponents" #1 and
  this component's `requirements.md` (new FR-LAB-8/9/10) updated to match.
- Impact (other components / project): pins the target shape for all future LAB-track
  implementation work (Phase 0 onward, per `CR-LAB-0001` §8); no other component's
  contracts change yet. `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`'s gap-classes question
  marked decided.
- Risk (level; mitigation): none — decision-of-record only, no code delivered.
- Deliverables:
  - [x] `CR-LAB-0001` §7 decisions recorded, status flipped to APPROVED — done.
  - [x] D20 added to `docs/DECISIONS_AND_ROADMAP.md`; lab-track phase-list pointer
        corrected to reference `CR-LAB-0001` §8 as authoritative (the two had drifted
        apart) — done.
  - [x] `docs/ARCHITECTURE.md` and `01-target-lab/requirements.md` updated — done.
  - [ ] Phase 0 implementation (schema, safety matrix, generator scaffolding) — not
        started; tracked separately per `CR-LAB-0001` §8.
- Effectiveness (assessed 2026-09-21): not yet assessable — this entry records a
  decision, not a built capability; effectiveness lands with Phase 0's own CC entry.

### CC-LAB-0013 — Fix (BUG-0017): self-healing `labctl.sh reset` (recurrence of BUG-0013) (2026-09-21)
- Change: the BUG-0013 self-heal (force-clear a wedged podman stack) was inlined in the
  `up)` case only; `reset)` still recreated with a bare `compose down -v` + `up` and hit the
  same podman-compose limitation ("cannot remove … as it is running", `exit status 125`),
  wedging the stack and blocking `scripts/greybox_e2e.sh` step 1. Factored the force-clean
  sequence into one shared helper `_force_clean()` (`podman rm -f` of the three project
  containers — force-removes running/wedged ones — then `podman pod prune -f`,
  `podman network rm`, and an optional `podman volume rm` on `drop-volume`; no-op without
  podman) and routed **both** subcommands through it: `up` → `_force_clean keep-volume` on
  failure (data preserved); `reset` → `_force_clean drop-volume` before the recreate and
  again + retry if the recreate fails. The PA-0018 sweep (enumerating lifecycle paths by
  operation) also hardened `down` to `_force_clean keep-volume` on failure, so even a wedged
  teardown succeeds; `status`/`logs`/`exec`/`snapshot`/`restore`/`pin` don't touch container
  lifecycle and stay out of scope.
- Impact (other components / project): unblocks Part E on-host — `labctl.sh reset` now
  produces a clean, freshly-seeded stack and recovers a wedged one, so
  `scripts/greybox_e2e.sh` proceeds. docker compose (which recreates/tears down in place)
  is unaffected. No Python code changed.
- Risk (level; mitigation): low–medium — `reset` intentionally drops the DB volume; the
  extra force-clean only removes containers/pod/network (and the volume it already drops).
  Guarded: `|| true` on each cleanup, podman-only, a final `up` that fails loudly if
  recovery didn't work. Verified statically (the sandbox has no podman): a mocked
  podman/compose harness exercises `up` and `reset` on both the happy path and the
  first-`up`-fails fallback and asserts every path exits 0 (6/6); `bash -n` clean.
- Deliverables:
  - [x] Shared `_force_clean()` helper; `up` + `reset` + `down` all routed through it — done.
  - [x] Static exit-code verification (mocked podman/compose, both branches) — done.
  - [x] RCA `docs/bugs/BUG-0017-*` incl. recurrence review (BUG-0013) + prior-PA-failure
    analysis (PA-0014 trigger-scoped, PA-0002 swept the narrow framing, PA-0003 not
    applied); rule PA-0018 — done.
- Effectiveness (assessed 2026-09-21): both container-recreate paths now self-heal via one
  helper; the recurrence review re-keyed the self-heal from the *trigger* (env/profile
  change) to the *mechanism* (podman can't remove/recreate a running stack) and to all
  recreate paths (PA-0018). Suite 416 passed / 6 skipped. On-host re-run of
  `greybox_e2e.sh` pending with the user.

### CC-LAB-0012 — Fix (BUG-0015): `labctl.sh up` exit status 0 on success without a profile (2026-09-21)
- Change: the `up)` case's profile notice was `[ -n "${PFF_PROFILE:-}" ] && echo ...`, a
  trailing `A && B` that returns non-zero when no profile is set — making `labctl.sh up`
  exit 1 on success and aborting `set -e` callers (e.g. `scripts/waf_evasion_e2e.sh` stopped
  silently after step 1). Now an `if [ -n ... ]; then echo ...; fi`, which returns 0 either
  way. Introduced by CC-LAB-0010's profile support.
- Impact (other components / project): unblocks Part J — `waf_evasion_e2e.sh` (no profile)
  now proceeds past enabling the WAF. The with-profile path (h2 desync) was already fine.
- Risk (level; mitigation): low — a one-line control-flow fix. Verified with
  `bash -c 'set -e; ...'` that the no-profile tail exits 0; swept the other `&&` sites
  (`labctl.sh:42`, `greybox_e2e.sh:128` — both exempt from set -e). New rule PA-0016
  (static exit-code checks for on-host scripts, since the sandbox can't run them).
- Deliverables:
  - [x] `if`-form profile notice; exit-code verification; `&&`-site sweep — done.
  - [x] RCA `docs/bugs/BUG-0015-*` (recurrence of BUG-0014 + prior-PA-0015 analysis); PA-0016 — done.
- Effectiveness (assessed 2026-09-21): `up` returns 0 on the no-profile success path; Part J
  can proceed. Confirmed indirectly on-host: Parts I/K passed; J stopped exactly at this
  exit-status boundary and is now fixed.

### CC-LAB-0011 — Fix (BUG-0013): self-healing `labctl.sh up` under podman-compose (2026-09-21)
- Change: `lab/labctl.sh` `up` is now self-healing. podman-compose cannot recreate a
  running stack in place when env/profile change (it errors on existing container names /
  dependent containers and can wedge the pod), so on `up` failure labctl runs `down`
  (keeping the DB volume), force-clears any wedged podman containers/pod/network
  (`podman rm -f pff-lab_{frontend,web,db}_1`, `podman pod rm -f`, `podman network rm`), and
  retries `up`. The happy path is unchanged; the fallback runs only on failure and only
  force-cleans when `podman` is present.
- Impact (other components / project): unblocks Parts J and K on-host —
  `PFF_WAF=on ./labctl.sh up` and `PFF_PROFILE=desync ./labctl.sh up` now apply on a
  running stack and recover a wedged one, so `scripts/waf_evasion_e2e.sh` /
  `scripts/h2_desync_e2e.sh` proceed. docker compose (which recreates in place) is
  unaffected.
- Risk (level; mitigation): low–medium — the force-clean removes the lab's containers (data
  is in the named volume, kept by `down`). Guarded: fallback only on failure, podman-only
  force-clean, `|| true` on each cleanup, and a final `up` that fails loudly if recovery
  didn't work. `tests/test_lab_downgrade.py` still validates the compose/profile config.
- Deliverables:
  - [x] Self-healing `up` (down + force-clean + retry) in `labctl.sh` — done.
  - [x] RCA `docs/bugs/BUG-0013-*` incl. recurrence + prior-PA-failure analysis; PA-0014 — done.
- Effectiveness (assessed 2026-09-21): recovers a wedged stack and applies env/profile
  changes on-host; the recurrence review captured the previously-unguarded "assumed compose
  capability" class as PA-0014.

### CC-LAB-0010 — `labctl.sh` compose-profile support (h2→h1 desync front-end) (Phase 9 on-host) (2026-09-21)
- Change: `lab/labctl.sh` now honors `PFF_PROFILE` and passes `--profile <name>` as a
  **top-level** compose flag (before the subcommand) on `up`, so
  `PFF_PROFILE=desync ./labctl.sh up` brings up the opt-in h2→h1 downgrade front-end
  (D17). Fixed the `compose.yaml` comment that suggested the (non-working)
  `./labctl.sh up --profile desync` form. Used by `scripts/h2_desync_e2e.sh` (Part K).
- Impact (other components / project): unblocks the Phase 9 protocol last mile
  (CC-PROXY-0011) — the raw h2c client needs the front-end running. Default behavior is
  unchanged (no profile → the front-end stays off, as before).
- Risk (level; mitigation): low — additive; the desync front-end remains opt-in and
  loopback-only. `tests/test_lab_downgrade.py` already asserts the profile gating and
  loopback binding; the change only affects how the profile is passed.
- Deliverables:
  - [x] `PFF_PROFILE` → top-level `--profile` on `up`; corrected compose comment — done.
- Effectiveness (assessed 2026-09-21): effective — `PFF_PROFILE=desync ./labctl.sh up`
  starts web+db+frontend; `scripts/h2_desync_e2e.sh` drives the live front-end.

### CC-LAB-0009 — Grey-box instrumentation: pcov + cov.php shim, prepend chain, DB snapshot (Phase 3 T3.1/T3.5) (2026-09-21)
- Change: instrumented the lab image for grey-box runs. `lab/web.Dockerfile` installs pcov
  (`pcov.enabled=1`, `pcov.directory=/var/www/html`). New `puppy-fort-factory/includes/
  cov.php` is a no-op unless a request carries `X-Fzl-Cov`; when present it writes one JSON
  side-channel file per request (`/tmp/fzl-cov/<id>`) with covered app lines **and** a
  per-request `db_fault`/`db_error` marker (from PHP's error state). Because
  `auto_prepend_file` is single-valued, the WAF and the shim are chained through new
  `includes/prepend.php` (the Dockerfile now prepends that, not `waf.php` directly) — this
  also **fixes** the double-`auto_prepend_file` mistake the old runbook prose would have
  produced (the last line silently wins, disabling the WAF). `lab/compose.yaml` bind-mounts
  the host `${FZL_COV_DIR:-/tmp/fzl-cov}` and sets `FZL_COV_DIR`. `lab/labctl.sh` gains
  `snapshot`/`restore` (fast `mariadb-dump`/restore for deterministic resets, T3.5).
  `scripts/greybox_e2e.sh` orchestrates the whole Part E flow (build → health → curl
  self-test → snapshot → `fuzzlab greybox-run` → exit check). `lab/.snapshots/` is gitignored.
- Impact (other components / project): backs the grey-box readers/driver (CC-FUZZ-0016)
  with live sources, making Part E a one-command run. Both instrumentation paths self-gate,
  so the default app and **every ground-truth label are unchanged** (WAF off unless
  `PFF_WAF=on`; coverage a no-op unless `X-Fzl-Cov` is sent). Loopback-only; lab-only.
- Risk (level; mitigation): low–medium — enabling pcov globally adds per-request overhead
  and the prepend chain touches the WAF wiring. Mitigated by: the shim self-gating on the
  header (no cost on ordinary traffic beyond pcov idle), the chain preserving WAF ordering
  (WAF first, may block/exit; coverage second), the side-channel file being written under
  a dedicated `/tmp/fzl-cov` mount, and `scripts/greybox_e2e.sh` self-testing both signals
  before the run. Container-side, so not covered by the Python suite; validated on-host by
  the script's curl self-test.
- Deliverables:
  - [x] pcov in the image; `cov.php` coverage + per-request db_fault shim — done.
  - [x] `prepend.php` chain (fixes single-valued `auto_prepend_file`) — done.
  - [x] compose side-channel mount + `FZL_COV_DIR`; `labctl.sh snapshot/restore` — done.
  - [x] `scripts/greybox_e2e.sh` orchestration; `.gitignore` for snapshots — done.
- Effectiveness (assessed 2026-09-21): pending live confirmation on the host — the script's
  step-3 self-test asserts coverage is recorded and an error-based SQLi sets db_fault
  before the run proceeds. Offline, the readers/driver are covered by CC-FUZZ-0016's tests.
- Follow-up fix (2026-09-21, same day): first live run recorded an *empty* coverage file.
  Two causes: the shim gated pcov on `function_exists('\pcov\start')` (unreliable
  leading-backslash form) — now `extension_loaded('pcov')`; and `pecl install pcov` ran
  without `$PHPIZE_DEPS`, so the build could no-op — now installs the build deps and
  asserts `php -m | grep pcov` at build time (a broken layer fails the build). Added
  `labctl.sh exec` and a pcov-loaded precheck in the script. The `mysqli` install got the
  same build-time load check (PA-0002 sweep). Full RCA in
  `docs/bugs/BUG-0009-greybox-coverage-empty-fragile-pcov-guard.md`; rules PA-0008/PA-0009;
  see ERROR_LOG (grey-box self-test entry).

### CC-LAB-0008 — Multi-target evaluation harness (Phase 10 T10.5) (2026-09-21)
- Change: `fuzzlab/harness/multitarget.py` runs the full pipeline against several targets
  — each a `TargetSpec` (name, base-url, optional ground-truth contract) — one `run_auto`
  per target, and produces a **transfer summary**: per-target scores (tp/fp/fn,
  precision/recall from the existing scoring), macro precision/recall over the scored
  targets, a `found_on` list, and a `generalizes` verdict (real vulnerabilities — recall
  > 0 — on ≥ 2 scored targets). The network is injected via `sender_for(spec)` so it is
  offline-testable; `format_transfer` renders a deterministic summary.
- Impact (other components / project): the generalization/transfer capability for
  Phase 10 — evidence the toolkit isn't overfit to the Puppy Fort Factory. The live run
  against an external validation lab (Juice Shop/WAVSEP, D10) is the on-host T10.6 exit;
  the eventual manifest-generated second target (option C) plugs in as just another
  `TargetSpec`. No schema change; reuses `run_auto` + `ScoreReport`.
- Risk (level; mitigation): low — a thin orchestration over the existing pipeline, behind
  an injected sender seam. Mitigated by 4 tests (`tests/test_multitarget.py`): two scored
  targets both confirm SQLi and `generalizes` is True with macro metrics; a mixed
  scored/unscored run summarizes correctly and does not over-claim generalization;
  `format_transfer` text; empty target list. Suite 385 passed / 4 skipped.
- Deliverables:
  - [x] `run_targets` + `transfer_summary` + `format_transfer` (T10.5) — done.
  - [ ] Live transfer run against an external lab (T10.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the harness runs multiple
  targets and reports per-target + macro transfer metrics with a generalization verdict;
  the live external-lab transfer is on-host.

### CC-LAB-0007 — Opt-in h2→h1 downgrade front-end (Phase 9 T9.5, D17) (2026-09-21)
- Change: added a **default-off** front-end reverse proxy to the lab as a desync research
  target. `lab/downgrade/nginx.conf` accepts HTTP/2 (h2c) and proxies **HTTP/1.1** to
  `web:80` (`http2 on;` + `proxy_http_version 1.1;`) — the h2→h1 downgrade topology. A new
  `frontend` compose service (nginx 1.27) is gated behind the **`desync` compose profile**,
  so a plain `up` never starts it and the default lab is unchanged; loopback-only host
  port (`PFF_DOWNGRADE_PORT`, default 8081). Recorded as decision **D17**.
- Impact (other components / project): gives the PROXY component's raw-frame HTTP/2 client
  (T9.3) a self-owned target for the Phase 9 desync exit (T9.6). Off by default → D7
  reproducibility and all prior phases unaffected. Lab-only, never exposed.
- Risk (level; mitigation): medium (a desync target is security-sensitive) — mitigated by
  default-off profile gating, loopback-only binding, lab-only posture, and it being
  infrastructure we own. Mitigated for correctness by 7 tests (`tests/test_lab_downgrade.py`,
  incl. a `docker compose config` profile-gating check when the CLI is present): the
  frontend is profile-gated, loopback-only, mounts the config, depends on web; the default
  services are unchanged; the nginx config does the h2→h1 downgrade; `.env.example`
  documents the port. Suite 348 passed / 4 skipped.
- Deliverables:
  - [x] nginx h2→h1 config + profile-gated compose service + env (T9.5) — done.
  - [ ] Bring it up on-host and demonstrate an h2→h1 desync primitive (T9.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the front-end is off by
  default and, when the `desync` profile is enabled, downgrades HTTP/2 to HTTP/1.1 to the
  app; the live desync demonstration is on-host.

### CC-LAB-0006 — Configurable lab WAF (Phase 8 prerequisite, D16) (2026-09-21)
- Change: added a **configurable, deliberately naive request prefilter** to the lab
  (`puppy-fort-factory/includes/waf.php` + `config/waf-rules.json`), wired globally via
  PHP `auto_prepend_file` (a conf.d ini in `web.Dockerfile`), with `PFF_WAF`/
  `PFF_WAF_MODE` env passthrough in `compose.yaml`/`.env.example`. Modes: `block` (403),
  `sanitize` (strip the matched fragment), `log` (observe). The signatures are naive on
  purpose (e.g. `union select` but not `union/**/select`; `<script>` but not
  `<svg onfocus=>`) — a realistic-but-bypassable filter. **Default OFF:** the file is a
  no-op unless `PFF_WAF` is enabled, so the app and all existing ground-truth labels are
  unchanged (D7 reproducibility preserved). Recorded as decision **D16**.
- Impact (other components / project): resolves the deferred "WAF in the lab" question
  and gives the Phase 8 mutation engine (MUT) a real target for filter-transformation
  learning (FR-MUT-3) and its defeat-the-filter exit. Shared ruleset lets the toolkit
  model the filter offline. No change to the app's behavior while off.
- Risk (level; mitigation): low — off by default and factored so the meaning-bearing
  logic (`pff_waf_check_value`) is pure and testable. Mitigated by 5 tests
  (`tests/test_lab_waf.py`, PHP-CLI driven, skip if `php` absent): ruleset well-formed +
  unique ids; default-off wiring; naive payloads caught; classic bypasses evade;
  benign passes and `sanitize` strips the match. Suite 278 passed / 3 skipped.
- Deliverables:
  - [x] `waf.php` prefilter (block/sanitize/log) + `waf-rules.json` — done.
  - [x] Global wiring via `auto_prepend_file`; env config; default off — done.
  - [x] Offline PHP-driven tests + ruleset validation — done.
  - [ ] Enable on-host and confirm block/sanitize behavior against the live lab — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the filter catches the naive
  payloads and lets the classic bypasses through, exactly the target Phase 8 needs; live
  block/sanitize verification is on-host.

### CC-LAB-0005 — `labctl.sh` probes for a working Compose provider (2026-09-21)
- Change: `labctl.sh` no longer assumes a `docker`/`podman` CLI implies a Compose
  provider. It probes `docker compose`, `podman compose`, `docker-compose`, and
  `podman-compose` (in that order) via `<cand> version` and uses the first that runs;
  if none works it exits with an install hint (`sudo dnf install -y podman-compose`
  or `docker-compose-plugin`) instead of the raw "looking up compose provider failed"
  dump. Lab README and `docs/ON_HOST_RUNBOOK.md` note the provider prerequisite.
- Impact (other components / project): fixes a confusing bring-up failure on a Fedora
  host that had podman-docker but no compose provider; unblocks the on-host lab. No
  change to the compose stack itself.
- Risk (level; mitigation): low — a shell provider-detection change only. Applies
  PA-0004 (fix the repo, not just the environment, after an environment-only
  incident). Verified by inspection here (this sandbox has no compose provider to run
  it against); to be exercised on the host.
- Deliverables:
  - [x] Provider probing + clear install hint in `labctl.sh` — done.
  - [x] Prerequisite documented (lab README, on-host runbook) — done.
  - [ ] Confirmed `up`/`status`/`reset` on the host with a provider installed — on-host.
- Effectiveness (assessed 2026-09-21): expected effective — the script now selects an
  available provider and gives an actionable message when none exists; live bring-up
  pending on the host.

### CC-LAB-0004 — App DB defaults to the `pff` user, not `root` (BUG-0004) (2026-09-21)
- Change: `puppy-fort-factory/config/config.php` now defaults `DB_USER`/`DB_PASS` to
  the dedicated lab application user (`pff` / `pff_lab_pw`) instead of `root` / empty.
  Updated the app README manual-setup steps to create the least-privilege `pff` user
  (with the exact SQL) and to stop pointing the app at `root`; aligned the
  `schema.sql` import comment to `sudo mysql` (socket auth). No change to the
  containerized path's behavior (compose already supplies `PFF_DB_USER=pff`).
- Impact (other components / project): fixes BUG-0004 — the shipped default targeted
  the DB `root` account, which modern MariaDB authenticates over the unix socket and
  refuses over TCP (`Access denied for user 'root'`), so any run where the PFF_DB_*
  env was not supplied (a manual LAMP setup, or env not propagated) failed to
  connect. The repo default now matches what the lab actually provisions. Unblocks
  the on-host Phase 1/2/3 activities. `config.php` lints clean (`php -l`).
- Risk (level; mitigation): low — a defaults-only change; env vars still override and
  the container path is unchanged. Lab-only throwaway credentials (already present in
  `lab/.env.example`); the DB is never published and the web tier is loopback-only.
- Deliverables:
  - [x] `config.php` defaults → `pff` (never root); explanatory comment — done.
  - [x] App README manual setup creates `pff`, drops root; schema.sql import note — done.
  - [x] `php -l` clean; sole `root` literal removed — done.
  - [ ] Live connect verified on the host (container `labctl.sh up` and/or manual) — on-host.
- Effectiveness (assessed 2026-09-21): expected effective — the only `root` literal in
  the app is removed and the default now matches the provisioned `pff` user; live DB
  connection to be confirmed on the host.

### CC-LAB-0003 — Containerized lab (2026-09-21)
- Change: added `lab/` — a `compose.yaml` (PHP/Apache `web` + `mariadb:11.4` `db`),
  `web.Dockerfile` (`php:8.3-apache` + `mysqli`, room for pcov/Xdebug later), a
  `.env.example`, a `labctl.sh` (up/down/reset/status/logs/pin), and a README.
  The app is bind-mounted (live edits); the DB is seeded on first start from
  `schema.sql`. Realizes Phase 0 T0.2 and decision D7.
- Impact (other components / project): gives every tool a reproducible, pinned
  target and one-command up/reset; the integration harness (T0.7) will run against
  it in automatic mode. No code change to the app; it reads `PFF_DB_*` from the
  environment, which compose supplies.
- Risk (level; mitigation): medium — a deliberately vulnerable app must never be
  exposed. Mitigated by publishing the web tier on `127.0.0.1` only and not
  publishing the DB at all; local-only lab credentials in `.env` (real secrets
  stay in the keyring); SELinux `:Z` bind-mount options documented for Fedora.
  Reproducibility risk (floating tags) mitigated by a documented digest-pin step
  (`labctl.sh pin`), to be locked during build.
- Deliverables:
  - [x] `compose.yaml`, `web.Dockerfile`, `.env.example`, `labctl.sh`, README — done.
  - [x] `docker compose config` validates (syntax + env interpolation) — done.
  - [ ] Actual bring-up + `curl` smoke test — todo (run in the user's Fedora/Podman
    environment; this sandbox has the docker CLI but no daemon).
  - [ ] Pin base images to digests — todo (build-time, `labctl.sh pin`).
  - [ ] Grey-box coverage (pcov/Xdebug) in the image — todo (Phase 3).
- Effectiveness (assessed 2026-09-21): partially verified — the compose file
  validates and the init ordering was checked against `schema.sql` (fresh install
  seeds everything incl. `posts`). End-to-end bring-up is pending in an environment
  with a running container daemon.

### CC-LAB-0002 — Ground-truth label contract implemented (2026-09-21)
- Change: authored the machine-readable, out-of-band ground-truth contract for the
  current lab under `lab/ground-truth/` — `labels.json` (8 vulnerable cases + true
  negatives, opaque `PFF-NNNN` case IDs), `injection-points.json` (parameter-
  discovery ground truth incl. client-only fragment/query points), and
  `expectedresults.csv` (Benchmark-style mirror). Added JSON Schemas
  (`fuzzlab/labels/schemas/`) and a validating loader (`fuzzlab/labels/contract.py`)
  that cross-checks labels.json against expectedresults.csv so they cannot drift.
  Realizes Phase 0 T0.6 and decision D9.
- Impact (other components / project): gives the integration harness (T0.7) a
  scored source of truth and the ML track (D10) its labels; the crawler/auditor
  discovery can be measured against `injection-points.json`. No change to the app
  itself; the files are read from disk and never served by the target.
- Risk (level; mitigation): medium — wrong labels silently corrupt every downstream
  metric. Mitigated by schema validation, the labels/CSV cross-check (a flipped
  verdict is caught), opaque case IDs (no class leaks into the ID a tool sees), and
  authoring directly from `VULNERABILITIES.md`. Labels are hand-authored for now;
  the generator (D8) will emit them later.
- Deliverables:
  - [x] JSON Schemas for labels + injection points — done.
  - [x] `labels.json`, `injection-points.json`, `expectedresults.csv` — done.
  - [x] Validating loader + cross-check; 5 tests — done.
  - [ ] Grey-box instrumentation signals (Phase 3) — todo.
  - [ ] Generator-emitted labels (D8, Lab track) — todo.
- Effectiveness (assessed 2026-09-21): effective — the loader validates and loads
  the real contract (8 positives, negatives present) and catches an injected
  labels/CSV drift; opaque-ID and client-only-point assertions pass.

### CC-LAB-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — the Puppy Fort Factory app
  (~30 pages, ~10 JavaScript-rendered) with a hand-written `VULNERABILITIES.md`,
  deployed by copy-to-webroot on a bare Fedora host.
- Impact (other components / project): the crawler, auditor, and fuzzer target
  this app; ground truth is currently prose, which the integration harness cannot
  consume, so automated scoring is not yet possible.
- Risk (level; mitigation): low. Hand-maintained labels can drift from the app;
  mitigated going forward by the machine-readable label contract (D9) and the
  manifest-driven generator (D8), and by pinning the environment (D7).
- Deliverables:
  - [x] Vulnerable app built and deployed — done.
  - [x] Human-readable vulnerability map — done.
  - [ ] Machine-readable label contract — todo (Phase 0 T0.6).
  - [ ] Containerize with pinned versions — todo (Phase 0 T0.2).
  - [ ] Grey-box instrumentation — todo (Phase 3).
  - [ ] Manifest-driven generator — todo (Lab track).
- Effectiveness (assessed or pending): pending — this is the baseline record.
