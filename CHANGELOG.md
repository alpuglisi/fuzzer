# Changelog

A running record of notable changes to this project and **why** each was made.
Newest entries at the top. When you make a change, add a dated bullet: what
changed, and the reason. Reference the commit hash where useful.

Format per entry: `- <area>: <what changed> — <why>` (commit `<hash>`).

**Every change updates both logs:** this high-level CHANGELOG *and* the
change-control log of each affected component under `docs/components/`. This file
is the project-level history; the component logs are the lower-level controlled
records (see `docs/components/README.md`). For the full change process — bookkeeping,
bug protocol, and the preventive-action rules that must be followed — see `CLAUDE.md`.

## 2026-09-22

- UI: built R1 of the layout redesign (`docs/UI_LAYOUT_REDESIGN.md`) — real,
  deep-linkable per-section routes (`/`, `/launch`, `/proxy`, `/runs`, `/ml`,
  `/diagnostics`) replacing the single hash-tab document, and a new Overview
  dashboard (`/`) with KPI tiles, a recent-runs table, and quick actions wired to
  real store data (`results.overview_summary()`), so the panel scales past one
  ever-growing document and has a real landing page (CC-UI-0025, FR-UI-9).
- FUZZ: built the previously-unbuilt M8 out-of-band (OOB) callback oracle mechanism —
  `fuzzlab/oracle/oob.py::OobListener` (a loopback-only, default-off local canary
  tracker) plus `CommandInjectionOobStrategy`, confirming blind command injection
  when a target executes an injected shell fragment that fetches a unique canary URL
  but leaves no timing/response signal. Wired through `Oracle(oob=...)`,
  `run_pipeline`/`run_auto`, and the new `fuzzlab auto --oob` flag (default off, same
  gating shape as `--browser`/the proxy's `--authorized`). `CC-FUZZ-0019`/`FR-FUZZ-8`.
- LAB: fixed `live_boot_available()`'s network-reachability probe, which tested a bare
  raw-socket TCP connect instead of the actual, proxy-aware composer-driven Packagist
  round trip `composer install` itself performs — in a sandbox where real HTTPS only
  completes through a configured proxy, the raw-socket probe could report "available"
  without predicting whether the real, gated operation would complete in bounded time,
  letting a live-boot test hang instead of pass/skip. Replaced with
  `_composer_network_probe()` (a real, bounded `composer show -a` round trip); `_run()`
  now wraps a `subprocess.TimeoutExpired` from any pipeline step in a clear
  `LiveBootError` instead of letting it propagate uncaught. `CC-LAB-0059`/`FR-LAB-56`,
  `BUG-0029`, `PA-0032`.
- Docs: added `docs/VULN_CORPUS_EXPANSION_PLAN_SITE_ARCHETYPES.md` — a
  proposed extension to `docs/VULN_CORPUS_EXPANSION_PLAN.md` that sources
  corpus collection from concrete popular-website categories and their
  real architectures/tech stacks (rather than a generic feature catalog
  alone), reusing the base plan's Phase 3 CWE-mapping/pair-manufacturing/
  validation methodology unchanged. **Planning only — not executed**; per
  explicit instruction, dispatch awaits separate human go-ahead.
- Research: Phase 3 CWE mapping for the "file handling" corpus cell
  (`docs/research/corpus-examples/file-handling/{php,node,python}/manifest.yaml`,
  12 entries) — appended `cwe`/`suggested_op`/`suggested_sink_family` to each
  entry per `docs/VULN_CORPUS_EXPANSION_PLAN.md` Phase 3's handoff spec
  (CWE-434 for the upload-extension-check pairs, CWE-22 for the
  path-traversal-confinement pairs; new proposed vocabulary — e.g.
  `no_extension_check`/`mime_type_check`/`extension_allowlist_mime_check`/
  `filename_charset_sanitize`/`realpath_confine`/`path_prefix_check` against
  `fs_web_root_write`/`fs_path_read` — since none of `lab/safety_matrix.yaml`'s
  current SQLi/XSS ops or sink families fit a file-handling shape).
  Documentation/metadata-only: no source files altered, no pairs built, no
  validation attempted; `validated: false`/`validated_by: []` left unchanged
  on all 12 entries.
- Research: Phase 3 CWE mapping for the "search-export" corpus cell
  (`docs/research/corpus-examples/search-export/{php,node,python}/manifest.yaml`,
  10 entries) — appended `cwe`/`suggested_op`/`suggested_sink_family` to each
  entry per `docs/VULN_CORPUS_EXPANSION_PLAN.md` Phase 3's handoff spec.
  CWE-89 for every SQLi shape, CWE-1336 for the Node Handlebars-report SSTI
  entry, CWE-611 for the PHP XXE tutorial entry. Reused
  `lab/safety_matrix.yaml`'s existing vocabulary wherever the shape was
  genuinely the same: `raw_concat`/`sql_string_literal` for the three plain
  raw-concat-WHERE PHP entries, `param_bind`/`sql_string_literal` for the two
  fully-parameterized idiomatic entries (Node's knex.raw() builder, Python's
  Django `.filter(Q(...))`), and `identifier_allowlist` (reused, applied at a
  new `sql_order_by_clause` sink family) for Python's `hasattr()`-gated
  `sort_by` allowlist. New vocabulary proposed only for genuinely new shapes:
  `orm_order_by_unvalidated`/`sql_order_by_clause` for Node's raw ORDER-BY
  interpolation next to an otherwise-parameterized query,
  `orm_raw_escape_hatch`/`sql_where_clause_fragment` for Python's Django
  `.extra(where=...)` misuse, `driver_escape_string`/`sql_string_literal`
  (reused family) for PHP's `mysqli_real_escape_string()` idiomatic entry,
  `template_compile_user_content`/`template_render_pipeline` for the Node
  Handlebars SSTI entry (no idiomatic counterpart collected — flagged as a
  gap, not invented), and `xml_external_entities_enabled`/`xml_parse_input`
  for the PHP XXE entry. Documentation/metadata-only: no source files
  altered, no pairs built, no validation attempted; `validated: false`/
  `validated_by: []` left unchanged on all 10 entries.
- Research: Phase 3 CWE mapping for the "ecommerce-logic" corpus cell
  (`docs/research/corpus-examples/ecommerce-logic/{php,node,python}/manifest.yaml`,
  10 entries) — appended `cwe`/`suggested_op`/`suggested_sink_family` to each
  entry per `docs/VULN_CORPUS_EXPANSION_PLAN.md` Phase 3's handoff spec:
  CWE-840+CWE-20 (`client_trusted_amount` vs. `server_recomputed_amount` into
  a new `payment_charge_amount` sink family) for the client-trusted-price/
  amount shapes (Node's 3 vulnerable + 2 idiomatic entries, Python's and
  PHP's price-recomputation entries), and CWE-362+CWE-367 (`unlocked_check_
  then_act` into a new `single_use_resource_redemption`/`db_counter_increment`
  sink family, named per the actual counter being raced) for the non-atomic
  coupon-redemption race entries (PHP's `mucms` example, Python's
  `MasaiShop` example) — none of `lab/safety_matrix.yaml`'s current SQLi/XSS
  vocabulary fits a business-logic shape, so all six proposed names are new.
  Flagging a schema-fit concern for whoever does this feature's actual
  `safety_matrix.yaml` handoff: the race-condition shapes don't really cash
  out as an `(op, sink_family)` "transform applied to a sink" pair the way
  SQLi/XSS do — there's no vulnerable-side *transform* to size the effect of,
  the defect is the *absence* of a lock/transaction around an existing
  check-then-act, and the corpus itself is missing a real, licensed "locked"
  idiomatic counterpart in every language collected (see the PHP and Python
  manifests' own "Skipped for no license" notes) — this class may need a
  distinct vocabulary/gate design rather than being forced into the
  injection-class `op`/`sink_family`/`effect` triple. Documentation/metadata-
  only: no source files altered, no pairs built, no validation attempted;
  `validated: false`/`validated_by: []` left unchanged on all 10 entries.
- Research: Phase 3 CWE mapping for the "user-generated content / stored XSS"
  corpus cell
  (`docs/research/corpus-examples/ugc-xss/{php,node,python}/manifest.yaml`,
  9 entries) — appended `cwe`/`suggested_op`/`suggested_sink_family` to each
  entry per `docs/VULN_CORPUS_EXPANSION_PLAN.md` Phase 3's handoff spec.
  CWE-79 on every entry (stored XSS via comment rendering). All entries reuse
  the existing `html_body` sink family (its scope already covers a stored-XSS
  case, `raw_concat`/`profile.php`'s bio field, so no new "stored" sink family
  was needed even for the Node `innerHTML`/`dangerouslySetInnerHTML`
  examples). `suggested_op` reuses `raw_concat` for every no-sanitization
  vulnerable entry and the existing `html_entity_escape` for the one plain
  `htmlspecialchars()` idiomatic entry; three new allowlist-sanitizer ops are
  proposed since no existing op models that mechanism: `wp_kses_post`,
  `dompurify_sanitize`, `bleach_clean`. Documentation/metadata-only —
  `validated`/`validated_by` untouched, no source files altered.

- Research: Phase 3 CWE mapping for the "auth-session" corpus cell
  (`docs/research/corpus-examples/auth-session/{php,node,python}/manifest.yaml`,
  12 entries) — appended `cwe`/`suggested_op`/`suggested_sink_family` to each
  entry per `docs/VULN_CORPUS_EXPANSION_PLAN.md` Phase 3's handoff spec
  (CWE-347 for the JWT algorithm/key-confusion pairs, CWE-330/CWE-338 for the
  weak/predictable token-generation pairs; new proposed vocabulary — e.g.
  `jwt_alg_unchecked`/`jwt_alg_allowlist`/`jwt_alg_none_default`/
  `jwt_none_alg_opt_in`/`predictable_token_source`/`weak_prng_token`/
  `csprng_token` against `jwt_signature_verification`/`session_token_generation`
  — since none of `lab/safety_matrix.yaml`'s current SQLi/XSS ops or sink
  families fit an auth/session shape). Documentation/metadata-only: no source
  files altered, no pairs built, no validation attempted; `validated: false`/
  `validated_by: []` left unchanged on all 12 entries.
- Research: Phase 3 CWE mapping for the "access control" corpus cell
  (`docs/research/corpus-examples/access-control/{php,node,python}/manifest.yaml`,
  10 entries) — appended `cwe`/`suggested_op`/`suggested_sink_family` to each
  entry per `docs/VULN_CORPUS_EXPANSION_PLAN.md` Phase 3's handoff spec
  (CWE-639/CWE-862 on every entry for the missing-ownership-check IDOR/BOLA
  shape, plus CWE-306 where the vulnerable route also lacks any
  authentication check and CWE-915 where a mass-assignment sub-pattern is
  present; new proposed vocabulary — `no_ownership_check`,
  `ownership_query_filter`, `ownership_check_after_fetch`,
  `identity_match_before_fetch` against `db_row_by_id_lookup`/
  `keyed_resource_lookup` — since none of `lab/safety_matrix.yaml`'s current
  SQLi/XSS ops or sink families fit an access-control shape). Documentation/
  metadata-only: no source files altered, no pairs built, no validation
  attempted; `validated: false`/`validated_by: []` left unchanged on all 10
  entries.
- Planning: marked Phase 2 wave 1 (the six priority-9 feature rows) complete
  in `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s Status checklist, after
  independently re-verifying the full collected corpus (gitleaks re-scan
  across all ~65 files: no leaks; YAML-validated every `manifest.yaml`; full
  test suite green: 1530 passed/8 skipped). Wave 2 (rows 7-11, priority 6)
  remains undispatched.
- Research: Phase 2 corpus collection for the "file handling" feature row
  (priority 9, row 4) of `docs/VULN_CORPUS_EXPANSION_PLAN.md` — added
  `docs/research/corpus-examples/file-handling/{php,node,python}/` with
  12 real, license-triaged, commit-pinned examples (4 per language, two
  matched vulnerable/idiomatic pairs each: an upload handler with no/weak
  extension check vs. an allowlist+content-type check, and a download/serve
  endpoint with an unconfined user-supplied path vs. a realpath/allowlist-
  confined one) covering CWE-434 unrestricted upload and CWE-22 path
  traversal. `gitleaks` scanned every copied file (no leaks; one unrelated
  hardcoded demo credential found by manual read in a source file's
  unrelated config block was excluded from the excerpt rather than copied
  in and redacted). Reference/staging only, not read by lab generation per
  the plan's validation gate.
- Research: Phase 2 corpus collection for the "e-commerce (cart/checkout/
  payment/coupons, incl. billing/invoicing/subscriptions)" feature row
  (priority 9, row 6) of `docs/VULN_CORPUS_EXPANSION_PLAN.md` — added
  `docs/research/corpus-examples/ecommerce-logic/{node,php,python}/` with
  10 real, license-triaged, commit-pinned examples (5 Node/2 PHP/3 Python)
  covering business-logic price/quantity tampering (CWE-840, client-
  trusted charge amounts) and single-use-resource race conditions
  (CWE-362/367/841, non-atomic coupon-redemption check-then-act), as the
  plan anticipated for this harder-to-grep class: the PHP cell landed at
  the 2-example floor and pairs two different real shapes (a coupon race
  and a price-recomputation idiomatic contrast) rather than a same-shape
  pair, and Python's race example has no locked idiomatic counterpart
  under an acceptable license — both gaps documented honestly in their
  manifests rather than padded. `gitleaks` scanned every copied file
  (redacted two hardcoded Stripe test-mode keys it flagged in Node
  sources; zero leaks in the final copies); reference/staging only, not
  read by lab-generation code per the plan's Phase 3 handoff gate.
- Research: Phase 2 corpus collection for the "Authentication / session
  management" feature row (priority 9, row 2) of
  `docs/VULN_CORPUS_EXPANSION_PLAN.md` — added
  `docs/research/corpus-examples/auth-session/{php,node,python}/` with 12
  real, license-triaged, commit-pinned examples (4 per language, two
  matched vulnerable/idiomatic pairs each). Covers CWE-347 JWT algorithm/
  key confusion in all three stacks (firebase/php-jwt CVE-2015-2965,
  auth0/node-jsonwebtoken GHSA-8cf7-32gw-wr33, PyJWT GHSA-jq35-7prp-9v3f —
  each pair is the library's own real pre-fix/post-fix commit, not a
  synthetic recreation) and CWE-330 weak/predictable token generation
  (InvoicePlane CVE-2021-29023 reset token, a HubSpot OAuth-quickstart
  session secret via `Math.random()` vs. an Auth0 OIDC sample's
  `crypto.randomBytes()`, and DOAJ's own weaker login-code vs. its
  stronger `uuid4()`-based reset token in the same file). Session-fixation
  and reset-token-flow-binding shapes were surveyed but not added, to
  avoid padding past the plan's 3-5-per-cell target once two solid pairs
  per language were in hand — noted explicitly in each `manifest.yaml` as
  a gap for a possible follow-up pass. `gitleaks` (installed) scanned
  every file; no leaks found, no redaction needed. Reference/staging
  only, not read by lab generation per the plan's validation gate.
- Research: Phase 2 corpus collection for the "Authorization / access
  control" feature row (priority 9, row 1) of
  `docs/VULN_CORPUS_EXPANSION_PLAN.md` — added
  `docs/research/corpus-examples/access-control/{php,node,python}/` with
  10 real, license-triaged, commit-pinned examples (4 PHP, 4 Node, 2
  Python — Python held at the 2-example floor since several otherwise-good
  vulnerable-IDOR candidates had no declared license and were cited-only
  per the plan's license gate). Covers the classic "my-resource-by-ID"
  IDOR/BOLA shape (CWE-639/862/863): route param trusted with no
  session-ownership check vs. the same lookup scoped by
  `current_user`/`$_SESSION['user_id']`, including one naturally-occurring
  same-repo pair (GuusK/disruptIT) where the vulnerable and fixed shapes
  sit in adjacent routes of the same file/commit, and one same-file
  contrastive example (cupengus1/vulnerable-shop) where the real fix is
  left in as an inactive commented-out block alongside the active
  vulnerable code. Gitleaks (installed) found no leaks; two demo
  credentials found by manual review (a hardcoded JWT secret, two fixture
  passwords in an in-memory user array) were redacted regardless
  (`redacted: true`) since they were credential-shaped even though not
  live secrets.

- Research: Phase 2 corpus collection for the "search/filtering (merged
  with reporting/exports/dashboards)" feature row (priority 9, row 5) of
  `docs/VULN_CORPUS_EXPANSION_PLAN.md` — added
  `docs/research/corpus-examples/search-export/{php,node,python}/` with
  10 real, license-triaged, commit-pinned examples (4 PHP, 3 Node, 3
  Python) prioritizing shapes beyond fuzzlab's existing raw-concat/
  param-bind SQLi modeling: multi-param WHERE-clause building reused
  across count/list/export queries, an ORM `.extra(where=...)`/raw-
  ORDER-BY escape-hatch misuse contrasted with the same app's safe
  `.filter(Q(...))`/parameterized-builder path, and SSTI in a Handlebars-
  based report-export pipeline (CWE-89/943/1336); the Python cell's XXE/
  SSTI half is recorded half-populated (no license-clean real example
  found this pass) and the PHP XXE example is a labeled tutorial
  snippet, per Phase 2's honesty rules. `gitleaks` scanned every copied
  file (one hardcoded DB credential found and redacted before commit);
  reference/staging only, not read by lab generation per the plan's
  validation gate.
- Research: Phase 2 corpus collection for the "file handling" feature row
  (priority 9, row 4) of `docs/VULN_CORPUS_EXPANSION_PLAN.md` — added
  `docs/research/corpus-examples/file-handling/{php,node,python}/` with
  12 real, license-triaged, commit-pinned examples (4 per language, two
  matched vulnerable/idiomatic pairs each: an upload handler with no/weak
  extension check vs. an allowlist+content-type check, and a download/serve
  endpoint with an unconfined user-supplied path vs. a realpath/allowlist-
  confined one) covering CWE-434 unrestricted upload and CWE-22 path
  traversal. `gitleaks` scanned every copied file (no leaks; one unrelated
  hardcoded demo credential found by manual read in a source file's
  unrelated config block was excluded from the excerpt rather than copied
  in and redacted). Reference/staging only, not read by lab generation per
  the plan's validation gate.
- Research: Phase 2 corpus collection for the "user-generated content"
  feature row (priority 9, row 3) of `docs/VULN_CORPUS_EXPANSION_PLAN.md`
  — added `docs/research/corpus-examples/ugc-xss/{php,node,python}/` with
  9 real, license-triaged, commit-pinned examples (3 per language, each
  with a matched vulnerable/idiomatic pair per Phase 2's pairing rule)
  covering stored-XSS-via-comment-rendering and sanitizer-vs-raw-output
  contrasts, deliberately beyond fuzzlab's existing basic reflected
  `html_body`/`html_attribute_quoted` shapes. `gitleaks` scanned every
  copied file (no leaks); reference/staging only, not read by lab
  generation per the plan's validation gate.
- Planning: completed `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s Phase 1 — merged
  real research on common web-app feature areas and on which are
  disproportionately exploited (OWASP Top 10/WSTG, CWE Top 25, PortSwigger,
  documented CVE/HackerOne patterns) into one commonality x exploitability
  ranked table of 19 features, applying the plan's own boundary-rule merges
  (social features into access-control, billing into e-commerce) and its
  "score 3 only with 2 independent source types" discipline (several rows
  honestly capped at 2 where a second type couldn't be found). Chatbots/AI
  assistants flagged as scored low on evidence-scope grounds (governed by a
  separate OWASP LLM Top 10), not a real-world-risk judgment.
- Planning: hardened `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s Phase 3 via a
  3-cycle review→research→revise pass (real research: pairs-per-CWE floor
  scaled to available source material rather than a fixed number, grounded
  in Juliet/OWASP Benchmark/CVEfixes conventions; `difftastic`/Semgrep/
  Bandit/Psalm/eslint-plugin-security as concrete structural-diff and
  static-analysis tools; a new "Validation execution sandbox" doctrine
  covering zero-outbound-network, ephemeral filesystem, resource limits,
  and gVisor over plain Docker for actually running deliberately-
  vulnerabilized code — a real risk surface this project's existing
  lab-only doctrine didn't cover) plus a 2-cycle whole-document pass that
  found and fixed a cross-phase inconsistency (`validated`/`validated_by`
  fields shown only in Phase 3's example despite being set by Phase 2).
- Planning: extended `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s Phase 3 with a
  deliberate-vulnerability-injection requirement — after a CWE is matched to a
  collected feature/language example, alter that real code so it manufactures a
  matched vulnerable/safe pair (more than one per CWE), require every pair to pass
  a structural + behavioral/static validation check before it's trusted, and hard-gate
  any data reaching a lab-generation-facing file behind an explicit `validated: true`
  flag — nothing collected or altered feeds `safety_matrix.yaml`/module templates
  until fully validated.
- LAB: real MariaDB-backed live-boot mode (`fuzzlab.labgen.conformance.live_boot
  .MariaDbServer`, starting a real local `mariadbd` and importing the real
  `puppy-fort-factory/sql/schema.sql` verbatim) re-proves every real-page manifest
  group `LiveBootHarness` drives against the actual database engine `lab/compose.yaml`
  is built around (previously only proven against a SQLite test-harness substitute) —
  and resolves `search.php`'s long-open canonical-cell decision (`LABGEN-PL-RP-0001`,
  the LIKE-clause SQLi cell, is now canonical; `PFF-0003`'s reflected XSS is a genuine,
  documented downgrade to `lab/ground-truth/migration-exemptions.yaml`, a real
  multi-sink page composition having been judged out of scope). Surfaced two real,
  reported MySQL-vs-SQLite dialect/schema differences (a `TrimStrings`-vs-MariaDB
  `--`-comment interaction, and a real schema/Eloquent-timestamps gap in G4's write
  path) — see `CC-LAB-0058`/`FR-LAB-55` for the full detail — why: closes a real
  verification gap (never before proven against the actual target DB engine) and
  removes the last manifest the live-boot harness could not drive.
- Governance: codified this session's multi-agent orchestration policy as a canonical doc,
  `docs/MULTI_AGENT_ORCHESTRATION.md` (parallelism/idle-lane policy, independent
  verification discipline, pre-assigned bookkeeping numbers to avoid concurrent-lane ID
  collisions, delegation mechanism-fidelity requirement, and when to flag risk vs. proceed
  autonomously), with a summary + pointer added to `CLAUDE.md` and the concrete
  numbering rule added as `PA-0031` in `docs/PREVENTIVE_ACTIONS.md` — so a policy that had
  only existed as this session's own working practice (and a one-off explainer file sent
  to the user) survives past this session and is enforced/read the same way every other
  project rule is.
- Planning: revised `docs/VULN_CORPUS_EXPANSION_PLAN.md` via a 3-cycle
  review→research→revise pass — added a commonality×exploitability scoring
  rubric to merge Phase 1's two research angles into one ranked list, concrete
  Phase 2 per-cell example counts/source-quality bar/license and secrets
  handling (grounded in this project's own D12 no-secrets rule), a canonical
  `manifest.yaml` metadata convention reconciling three previously-inconsistent
  ideas of where per-example metadata lives, and a Phase 3 handoff format that
  checks proposed `op`/`sink_family` names against `lab/safety_matrix.yaml`'s
  actual current vocabulary before minting new ones. Note: the dispatched
  agent lacked Agent/Task-tool access and did the cycle's research itself via
  direct WebSearch rather than spawning separate sub-agents as instructed;
  flagged to and accepted by the user as-is (see BUG-REPORT sent this session
  on the broader gap this revealed in delegation verification).
- Planning: added `docs/VULN_CORPUS_EXPANSION_PLAN.md`, a research plan for
  broadening the generated lab beyond SQLi/XSS — Phase 1 catalogs common web-app
  feature areas and cross-references which are disproportionately exploited in
  practice (OWASP/CWE-grounded, not theoretical); Phase 2 (deferred until Phase 1
  lands) collects real per-feature, per-language GitHub source examples; Phase 3
  (CWE mapping) explicitly deferred further still. This is the research front end
  of "Track A" (broaden vulnerability classes) from the earlier bottleneck/scope
  discussion — additive, does not touch the generator itself yet.
- LAB: extended `fuzzlab.labgen.conformance.live_boot.LiveBootHarness` real on-host
  live-boot proof to three more real-page manifest groups — `auth` (a real SQLi
  boolean-injection login bypass and a real `register.php` `INSERT`), `g2`
  (`products.php`/`api/products.php`'s real JSON feed), and `g4` (the
  `edit_profile.php` -> `profile.php` stored-second-order write-then-read round
  trip) — bringing live-boot coverage to 5 of the 6 `phase3_php_laravel_real_pages_*`
  manifests (`search.php` remains genuinely unpinned pending `L-P3.3c-CUT`, per its
  own manifest header). Along the way, fixed two real defects in the harness itself
  (silent redirect-following masking a real login success as a `404`; a seeded
  schema missing the columns Eloquent's default timestamps need, breaking every G4
  write) — see `docs/bugs/BUG-0028-*.md` (`CC-LAB-0056`/`FR-LAB-54`, `PA-0030`).

- LAB: `fuzzlab.labgen.minimal_pair.check_minimal_pair()` gained an optional `pair_by`
  key function so two independently-authored cells rendering to different file paths
  (lane L-P3.3c-G3's `login.php`/its secure twin, `CC-LAB-0048`) can be paired and
  checked directly, without breaking existing path-based callers — and fixed a real
  defect where its content-confinement check was silently skipped whenever the two
  variants' `// Module composition: ...` sequences differed by name (the common case
  for a real vulnerable/secure pair), letting an unrelated rewrite outside the
  declared transform/sink region pass undetected (`CC-LAB-0055`/`FR-LAB-53`,
  `docs/bugs/BUG-0027-*.md`, `docs/PREVENTIVE_ACTIONS.md` PA-0029).
- LAB: built a real, on-host live-boot conformance harness for `php_laravel`
  (`CC-LAB-0054`/`FR-LAB-52`) — the Tier 1/2 gap `docs/LAB_IMPLEMENTATION_PLAN.md`
  ~line 154 named as blocked on on-host dependencies that "do not exist". A checked-in
  real Laravel 13 skeleton (`fuzzlab/labgen/emitters/php_laravel/stack/skeleton/`,
  trimmed from a real `composer create-project laravel/laravel`) plus new
  `fuzzlab.labgen.conformance.live_boot.LiveBootHarness` assembles a manifest's real
  `LaravelEmitter` output onto it, runs a real `composer install`, seeds a real SQLite
  DB, boots a real `php artisan serve`, and makes real HTTP requests — proving (for the
  `phase3_laravel_real_pages_forms` and `phase3_php_laravel_real_pages_numeric`
  manifests) that the generated app actually boots, serves its pinned real URLs, and
  shows a real vulnerable/secure payload differential on the `product.php` SQLi twin.
  Skip-guarded (`live_boot_available()`) and marked `pytest.mark.slow` (new marker,
  documented in `pyproject.toml`), so it degrades to a clean skip without
  composer/network and does not change default `pytest -q` behavior elsewhere. Fixed a
  real defect discovered while wiring this (Laravel's default session-CSRF middleware
  returning HTTP 419 for the migrated POST pages, which have no CSRF framework of their
  own) by disabling it in the new skeleton. Auth/G2/G4/search real-page manifests remain
  undriven by this harness (need additional seed data) — see `CC-LAB-0054` for the exact
  scope.
- LAB: built the `L-P3.3c-CUT` parity/cutover coverage gate (plan §4.3.6.6
  point 3) ahead of the cutover itself, which stays blocked on human sign-off.
  `fuzzlab.labgen.cutover_gate` asserts every `PFF-` case in
  `lab/ground-truth/labels.json` is covered by at least one emitted
  `php_laravel` cell (derived from `LaravelEmitter.supports()` over every
  `lab/manifests/*.yaml` cell, PA-0001/PA-0027) or named in the new
  machine-readable `lab/ground-truth/migration-exemptions.yaml`. Extended the
  existing `_GROUND_TRUTH_CASE_KEY`/`_CANONICAL_CELL_KEY` page-profile
  convention (rather than a second mechanism) with
  `ground_truth_case_by_family` (search.php's `PFF-0002`/`PFF-0003` split by
  sink family) and `secondary_ground_truth_cases` (login.php's boilerplate
  `PFF-1008` password condition), both read by the new
  `ground_truth_cases_for()`. The register lists `PFF-1002` (track.php has no
  sink at all) and `PFF-0007`/`PFF-0008` (DOM XSS, exempted per the D-open-1/
  D-open-2 decisions above). Gate is green: all 16 `labels.json` cases are
  covered or exempted, no gap found. Documented the D-open-1 crawler-
  discoverability gap in `docs/ON_HOST_RUNBOOK.md`. (`CC-LAB-0053`,
  `FR-LAB-51`; `tests/test_labgen_cutover_gate.py`)
- LAB (planning): decided the two open questions in
  `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.7 blocking `L-P3.3c`'s remaining
  scope. D-open-1: retiring `puppy-fort-factory/` does **not** require
  reproducing Layer B (the JS-rendered pages) — every automated consumer
  already reads ground-truth JSON, not the PHP files, so only the manual
  live-crawler runbook exercise is affected; that gap must be documented in
  `docs/ON_HOST_RUNBOOK.md` rather than built around. D-open-2: DOM XSS
  (`L-P3.3c-DOM`, `PFF-0007`/`PFF-0008`) is **out** of the cutover's "full
  coverage" bar — it is new sink-class capability, not a migration, and
  blocking the whole cutover on it would hold back everything already built;
  `L-P3.3c-DOM` becomes ordinary deferred backlog instead. Both cases are to
  be listed in `lab/ground-truth/migration-exemptions.yaml` citing these
  decisions. This unblocks `L-P3.3c-CUT` from waiting on either.
- LAB: consolidated lane L-P3.3c's six concurrent sub-lanes (G1–G6, migrating real
  `puppy-fort-factory/` pages onto the `php_laravel` emitter) onto one unified
  URL-pinning mechanism (`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY`, generalizing G3's
  design, of which the already-merged G5 mechanism is the trivial single-cell case),
  replacing five independent, mutually-incompatible mechanisms the sub-lanes built
  without seeing each other's code — because the URL-naming bikeshed was blocking four
  lanes' merges. Migrated every lane's manifests, tests and genuine findings (G1's
  numeric-page twins, G2's `json_view` module category, G3's session/register-insert
  auth pages + `auth_session.py` adapter, G4's `stored_second_order`/write-endpoint
  support, G6's `search.php` + `html_attribute_quoted` shape — left deliberately
  unpinned, open for `L-P3.3c-CUT`) onto the single mechanism; reconciled
  `route_accumulator.fragment_for_cell`'s method/action parameter shape and its
  duplicate-URL guard into one. Full suite: 1494 passed / 8 skipped, 0 failed (the two
  `test_mutation_operators.py` MUT failures flagged as pre-existing/out-of-scope by this
  task's brief were independently fixed by `BUG-0026` (commit `c6953c4`), already on this
  branch before this change landed) (`CC-LAB-0046`..`0049`/`0051`/`0052`, `FR-LAB-44`..
  `47`/`49`/`50`).
- MUT: fixed `SemanticsValidator` (`fuzzlab/mutation/semantics.py`) failing open on an
  untrusted SQL `--` comment-append (accepted as semantics-preserving without vetted
  provenance) and failing closed on a case-insensitive SQL `case-toggle` (AST equality
  was case-sensitive) — chronic failures in
  `tests/test_mutation_operators.py::test_every_surface_variant_preserves_semantics` and
  `::test_sql_equivalent_needs_trusted_provenance`, first noted found-not-fixed by lane
  L-P3.4 and re-confirmed by many subsequent runs. See `BUG-0026`, `PA-0028`,
  `CC-MUT-0008`.
- LAB: reproduced the real `contact.php` and `newsletter.php` pages (`PFF-1005`/`PFF-1006`)
  as `php_laravel` cells — the first page group of the `puppy-fort-factory/` migration
  (lane L-P3.3c-G5, `CC-LAB-0050`, `FR-LAB-48`). Both are secure-only escaped-echo
  (`xss`/`html_body` + `html_entity_escape`) cells in the new
  `lab/manifests/phase3_laravel_real_pages_forms.yaml`, deriving the SECURE verdict
  `lab/ground-truth/labels.json` already carries, and needing no new module. Their routes
  **keep the real app's exact `.php`-suffixed URLs** via a new `url_path` page-profile pin,
  because T-LAB0.9's additive-only gate would otherwise see every migrated case *relocate*
  to Laravel's idiomatic extension-less path — now enforced by a test against the real
  regression gate rather than by plan prose. Tier-0/Tier-3 conformance for this emitter is
  swept over every committed manifest's cells, computed from `Emitter.supports()`
  (PA-0024/PA-0027).
- LAB: made the metadata leakage probe a required `fuzzlab lab-generate --check` gate
  and gave it the per-class thresholds `docs/LAB_IMPLEMENTATION_PLAN.md` §2.3 decided on
  (lane L-P1.3, `CC-LAB-0045`, `FR-LAB-43`) — `leakage_probe.run_leakage_gate` now wraps
  the (still non-raising) `probe_leakage` measurement, judging each class's one-vs-rest
  AUC against `min(its own permutation null, its configured `PER_CLASS_AUC_THRESHOLDS`
  line)`. Strictest-of-two is deliberate: it implements §2.3's per-class decision while
  honoring the module's standing warning that a per-class threshold must never be usable
  to switch the gate off for a class. Every shipped threshold is marked `provisional`
  (seeded from the report's 0.55-0.60 band) and the gate prints each one's
  provisional-vs-calibrated status, so a later calibration pass can see which numbers
  still need a properly-sized permutation null. Honest limitation recorded rather than
  papered over: a manifest carries only one of the seven allowlisted features
  (`path_depth`) — the other six are live-response observations — so on every sample
  manifest shipped today the gate SKIPS with an explicit printed reason rather than
  pretending to measure.
- LAB: gave the `php_laravel` emitter the **full module inventory** (plan §4.3 step 2, lane
  L-P3.3b, `CC-LAB-0044`/`FR-LAB-42`) — every shape `php_current` supports, ported to
  Laravel/Eloquent/Blade idiom via this stack's own module registries (nothing shared with
  `php_current`'s plain-PHP package): the four SQL shapes through `DB::select`/`whereRaw()`/
  `orderByRaw()`, and the three HTML shapes as per-cell Blade views, which makes an HTML cell
  a two-file `controller` + `view` cell here. Laravel is the one stack the plan assigns full
  depth, because Phase 1's hard-shape work is directly portable to a second PHP stack. The
  sample manifest grew 2 → 20 cells and `fuzzlab lab-generate --emitter php_laravel --check`
  passes end to end (Tier 0 `php -l` over all 28 files + Tier 3), which is why the emitter is
  now registered in the CLI's `EMITTER_REGISTRY`. The identifier-SQLi build assertion reaches
  these cells through a route-rewrite adapter only — verified, not assumed: that module is
  stack-agnostic apart from assuming a cell is served at `cell.route.path`, which a
  router-dispatched stack is not.
- Planning docs: fleshed out lane L-P3.3c (the `puppy-fort-factory/` → `php_laravel`
  migration) in `docs/LAB_IMPLEMENTATION_PLAN.md` from a one-paragraph milestone into an
  executable breakdown (new §4.3.6.1–4.3.6.7 plus per-sub-lane rows in the §7 lane map),
  via three iterative review → research → revise passes — so the lane can be built without
  further clarification. Substantive findings folded in, not just restructuring: the
  fixture's scope is three layers (labeled cells, unlabeled crawler surface, and non-page
  assets like `waf-rules.json`/`cov.php`/`schema.sql` that production code and compose
  read), so "delete the directory" needed a concrete re-homing plan; `search.php`'s
  LIKE-clause SQLi is an existing `sql_string_literal` shape rather than a new family, but
  its quoted-attribute XSS needs the missing `raw_concat × html_attribute_quoted` matrix
  row; DOM XSS (`PFF-0007/0008`) has no family, op, or emitter concept at all and is carved
  out as a decision rather than assumed; `track.php` issues no query so it is exempted, not
  modeled; `edit_profile`→`profile` is one `stored_second_order` cell; and, most sharply,
  Laravel's idiomatic extension-less routes would *relocate* all 16 `PFF-` cases and trip
  T-LAB0.9's additive-only regression gate, so migrated routes keep the `.php` suffix. Two
  scope questions (whether the JS-rendered crawler surface must be reproduced, and whether
  DOM XSS blocks the cutover) are left explicitly open for the user. Documentation only —
  no code, tests, or manifests touched.
- Feature (UI, Wave-0 lane X0): registered `fuzzlab lab-generate` as a launchable activity in the
  web launcher, in its own **"Lab / authoring"** group. Added a loader + `_REGISTRY` entry and an
  optional `group` field to the command spec (`commandspec.py`), and made `_group_activities`
  (`app.py`) bucket by that spec group (falling back to the name-map / "Other"). lab-generate sends
  no traffic (renders files; `--check` runs offline gates), so it carries no `authorized` gate.
  Reason: one consistent control plane for every CLI; establishes the U0↔X0 grouping contract.
  Fields stay argparse-derived (PA-0001). CC-UI-0024.
- Docs (UI): added `docs/UI_IMPLEMENTATION_PLAN.md` — a single tracked plan for the remaining web
  UI work: the settled build policy (no build step; hand-roll where cheap; vendor one zero-dep
  static file only for charts), the five locked decisions, the outstanding deliverables (U0, U1–U5,
  B0, X0) as clear/executable/lane-organized spec blocks, and a wave/dependency map sized for
  parallel-agent dispatch. Includes a research-refinement loop (mark gaps → web-research agents →
  fold findings back). Round 1 folded in: full-page MPA (no HTMX); charts = **uPlot 1.6.32**
  (vendored, canvas, re-theme on `[data-theme]`); findings facet sidebar + SQLite-backed saved
  views + hand-rolled DataTable; one shared byte-exact message editor with a vanilla splitter and
  hand-rolled highlighting; TensorBoard-style diagnostics + validated `metric_series` schema +
  `MetricLogger` + LTTB downsampling; advisory-framed read-only ML panels. Reason: prepare the UI
  track for distributed, out-of-order lane builds. CC-UI-0023, FR-UI-8.
- Docs (UI): completed the plan's 3-round research-refinement loop (13 web-research markers).
  Round 2 added the PRG+303 cross-section pivot + a URL/server/localStorage state rule (U0), a
  WAL + `open_store()` SQLite-concurrency design for `metric_series` (B0/CORE), a zero-new-dep
  three-layer test strategy (§7), and a concrete Overview spec (U1). Round 3 added a cross-cutting
  accessibility spec (native `<table>` not `role=grid`; APG Disclosure/Splitter; canvas +
  visually-hidden table; not-color-alone per theme), the shared `createChart` uPlot wrapper
  (probe-resolved tokens, destroy+recreate on theme/density, ResizeObserver, leak-safe teardown),
  and a **new lane U6 — control-plane hardening** (Host allow-list + Origin/`Sec-Fetch-Site`
  same-origin + `/api/*` custom-header + tight CSP; Starlette ≥ 1.0.1 for CVE-2026-48710; the
  same-site-lab landmine), plus two §2 invariants (accessible; not-itself-an-attack-surface).
  CC-UI-0023.

## 2026-09-21

- LAB: carried the stack axis end to end and made the fingerprint-independence gate
  actually gate (plan §4.4, lane L-P3.4) — `Cell.stack_profile` already existed and is
  populated by all four emitters' sample manifests, so no redundant field was added;
  the real gap was the ground-truth side, which gained an optional per-case `stack`
  (`fuzzlab.labels.contract.Case` + `labels.schema.json`, inline per the §4 research
  decision, additive and inert to every existing case). `fuzzlab lab-generate --check`
  now runs `fingerprint_gate.run_fingerprint_gate` as a required step whenever the
  manifest's cells span 2+ distinct stack profiles, with `expected_classes`/
  `expected_stacks` derived from that manifest, and skips it with an explicit printed
  reason for a single-stack manifest (where the gate is ill-defined, not merely
  unhelpful) — so a multi-stack corpus can no longer ship with stack fingerprints
  predicting the vulnerability class (`CR-LAB-0001` §3, `CC-LAB-0040`, `FR-LAB-38`).
- LAB: added `fuzzlab.labgen.corpus_analysis` (plan §2.4, lane L-P1.4) — read-only corpus
  tooling: a train/holdout split grouped by generating-rule ID (reusing `leakage_probe`'s
  own `StratifiedGroupKFold` grouping, now extracted as the one shared `grouped_cv()`) so
  near-duplicate cells can never span a split; an explicit near-duplicate definition
  (`(vuln_class, sink_context, ordered transform-shape)`, regardless of cell ID) and
  duplicate-rate report; and a class × transform × verdict diversity **artifact**, written
  by the new `fuzzlab lab-generate --corpus-report <path>` on a path independent of
  `--check` — so the corpus can be measured and split honestly for ML work, while staying
  clearly distinct from the χ²-balance *gate* (`fingerprint_gate.py`) it sits alongside
  (`CC-LAB-0041`, `FR-LAB-39`, renumbered from a concurrently-claimed
  `CC-LAB-0040`/`FR-LAB-38` which collided with lane L-P3.4).
- LAB: added the `context_depth` axis to the manifest/`Cell` IR (`direct`,
  `same_file_helper`, `cross_file`, `stored_second_order`) — the generator-input
  counterpart of the ground-truth `Case.flow_variant` field, so a manifest can *declare*
  how far a cell's tainted value travels to its sink instead of only recording it after
  the fact; kept biconditionally consistent with `sink_endpoint` (a `stored_second_order`
  cell is exactly one whose payload executes on a different endpoint), wired as a
  covering-array axis, rendered by `php_current` via a new `depth` module category, with
  `schema.flow_variant_for()` as the one shared depth→ground-truth-label mapping and
  Addendum B's unreachable `cross_service` level failing loud rather than rendering
  something meaningless (`CC-LAB-0042`, `FR-LAB-40`, renumbered from a concurrently-claimed
  `CC-LAB-0040`/`FR-LAB-38` which collided with lanes L-P3.4/L-P1.4, lane L-P2.5).
- LAB: built lane L-P1.2b (`docs/LAB_IMPLEMENTATION_PLAN.md` §2.2) — the corpus's harder
  shapes: new `sink_context.family` values `sql_identifier`, `sql_join_alias` (injection
  into a column identifier or JOIN alias, not a literal value) and `url_javascript_scheme`
  (escaping-context-mismatch XSS), their additive `lab/safety_matrix.yaml` v1 rows (new
  ops `identifier_charset_filter`, `identifier_allowlist`, `url_scheme_allowlist`,
  `attr_value_allowlist`; new concerns `sql_identifier_substitution`, `js_context_break`;
  no change to `verdict()`), eight new `php_current` module fragments, a 13-cell manifest
  `lab/manifests/phase1_harder_shapes_sample.yaml`, and `fuzzlab.labgen
  .identifier_sqli_assertion` — which wires lane L-P1.2a's `run_identifier_sqli_oracle`
  in as the real build-time security assertion for the identifier cells (fail-closed:
  a verdict mismatch *or* an inconclusive probe fails the build). Why: the plan's
  highest value-per-hour finding — textbook `?id=1` cells are detected by every tool,
  these two shapes are not (a real sqlmap 1.8.4 spot-check missed the identifier-swap
  case entirely). Also renders the illustrative manifest's `LABGEN-EX-0003`, skipped as
  unsupported since Phase 0. See `docs/components/01-target-lab/change-control.md`
  `CC-LAB-0043` and `FR-LAB-41` (renumbered from a concurrently-claimed
  `CC-LAB-0040`/`FR-LAB-38` which collided with lanes L-P3.4/L-P1.4/L-P2.5).
- LAB: fixed BUG-0025 — the `lab-generate --check` gate tests injected their fault on a
  *global* per-cell-render counter's parity, so widening an emitter's supported shapes
  (above) silently stopped the determinism gate's own regression test from exercising it;
  fault injection is now keyed per `cell_id` and the supported-cell set is derived from
  `Emitter.supports()` instead of hardcoded. New rule PA-0027 (strengthens PA-0001,
  complements PA-0024); see `docs/bugs/BUG-0025-check-gate-fault-injection-coupled-to-supported-cell-count.md`.
- LAB: built T-LAB0.9, the regression/additive-only build gate
  (`fuzzlab.labgen.regression_gate.check_no_regression`) that diffs a candidate
  ground-truth snapshot against the hand-authored `lab/ground-truth/` by case ID and
  fails loud on any missing case, changed page, or changed verdict — the mechanical
  enforcement of "never reduce functionality" — plus, per `CR-LAB-0001` Addendum B, the
  `primary_endpoint`/`primary_role`/`related_endpoints`/`flow_variant` multi-artifact
  ground-truth fields on `fuzzlab.labels.contract.Case`, its JSON Schema, and
  `expectedresults.csv` (all additive/defaulted; a FUZZ-consumer sweep across
  `fuzzlab/harness/` and `fuzzlab/greybox/` done first, per plan, found no consumer
  needed changes). See `docs/components/01-target-lab/change-control.md` `CC-LAB-0030`.
- LAB: added `lab/identities/identities.yaml` (identity/ownership graph — named test
  identities, resource ownership, and binary `allowed|denied` authz expectations,
  D20/CR-LAB-0001 §8), its JSON Schema (`lab/schemas/identities.schema.json`), and a
  new loader module `fuzzlab.labgen.identity` (`load_identities()` → `IdentityGraph`,
  with duplicate-ID and dangling-reference checks and a typed `IdentityGraphError`,
  mirroring `fuzzlab.labgen.schema`/`fuzzlab.labels.contract.load_labels`'s
  conventions) — L-P2.1, genuinely novel schema ground per the Phase 2 research
  already recorded in `docs/LAB_IMPLEMENTATION_PLAN.md` §3.1. Deliberately decoupled
  from the manifest/`Cell` IR the same way `lab/patterns/provenance.yaml` is
  decoupled from it (CR-LAB-0001 Addendum A): `fuzzlab.labgen.verdict` never imports
  `identity.py`, asserted by a new test mirroring
  `test_labgen_gates.py::test_provenance_is_one_directional_no_leak_into_verdict_source`.
- Lab (LAB, T-LAB2.1, lane L-P1.1): wired `fuzzlab.labgen.resolver`'s covertable-backed
  covering-array expansion into `fuzzlab.labgen.schema`'s manifest loader — a manifest
  may now declare an `axis_ranges` block (e.g. every `class` x every
  `sink_context.family`, pairwise) alongside today's explicit `cells` list, expanded
  into the same `Cell` IR before any emitter sees it. `lab/schemas/manifest.schema.json`
  gained the `axis_range` shape (additive; explicit-cells-only manifests are unaffected —
  both example manifests still load byte-for-byte identically, asserted by regression
  tests). While wiring this, found and fixed BUG-0024: `resolver.validate_covering_array_config()`
  did not reject a `strength` exceeding the factor count (or a `sub_models` entry's
  `strength` exceeding its own field count), which `covertable.make()` silently turns
  into an empty array rather than an error — see `docs/bugs/BUG-0024-covering-array-strength-exceeds-factor-count.md`
  and new rule `PA-0026` (supersedes `PA-0010`). `CC-LAB-0031` (renumbered from a
  concurrently-claimed `CC-LAB-0029`, which collided with lane L-P2.1's identity-graph
  entry; see `CC-LAB-0031` for the note), `FR-LAB-29` (renumbered from a concurrently
  claimed `FR-LAB-27` for the same reason).
- LAB (L-P1.2a): spot-checked the real, apt-installed sqlmap 1.8.4 against three
  hand-built PHP/PDO test cases and confirmed the plan's research finding for the
  case that matters — a bare-identifier-allowlisted column-name injection (real
  vuln, `?col=secret` swaps a whole column) is reported "not injectable" by sqlmap
  even at `--level=5 --risk=3`, since its payloads all require characters an
  allowlist strips. Built `fuzzlab/labgen/identifier_sqli_oracle.py`, a new
  sibling oracle module (same fail-closed `confirmed_vulnerable |
  confirmed_secure | inconclusive` pattern as `nuclei_oracle.py`) implementing
  the CASE-WHEN boolean-differential prober the plan called for, in both a
  response-diff and a timing-blind mode, MySQL dialect implemented with the
  registry structured for Postgres/SQLite later; `oracle_wrapper.py` itself is
  untouched. (`CC-LAB-0032`, renumbered from a concurrently-claimed `CC-LAB-0029`
  which collided with lanes L-P2.1/L-P0.9/L-P1.1; `FR-LAB-30`, renumbered from a
  concurrently-claimed `FR-LAB-27` for the same reason.)
- LAB (lane L-P2.2): added `fuzzlab/labgen/identity_session.py`, a small
  LAB-owned session-holder (one cookie jar per known, generator-controlled
  test identity) so build-time oracle confirmation of stored/second-order
  cells can log in as a declared test identity and reuse its session — a
  narrow helper, deliberately not the toolkit's own separate Session-manager
  component (`CC-LAB-0033`, renumbered from a concurrently-claimed
  `CC-LAB-0029` which collided with lanes L-P2.1/L-P0.9/L-P1.1/L-P1.2a).
- Lab (L-P0.10, T-LAB0.10): added the `fuzzlab lab-generate --manifest <path> --out
  <dir> [--emitter NAME] [--check]` CLI (`fuzzlab/labgen/cli.py`), wired into
  `fuzzlab/cli.py`'s existing subcommand dispatch. Renders a manifest's supported
  cells via a registry-looked-up emitter (default `php_current`, so Phase 3's
  additional emitters need no CLI rewrite) and, with `--check`, runs the name-leak
  scanner, secret scanner, a real-emitter regenerate-and-diff determinism check,
  the minimal-pair checker (against a generic transform-emptied twin of each
  cell, so it works for any manifest, not only one authoring explicit twin
  pairs), and conformance Tier 0/Tier 3 -- all offline gates that already existed.
  This lane's own worktree predated L-P1.1/L-P0.9 landing. At merge time,
  confirmed the resolver wiring (L-P1.1) is already transparent to this CLI --
  `Manifest.from_dict()` expands `axis_ranges` internally now, so `load_manifest`
  needed no CLI-side change at all. The regression/additive-only gate (L-P0.9)
  is intentionally left as the lane's own `# TODO(L-P0.9-integration)` marker
  (renamed from `# TODO(L-P0.9)` since L-P0.9 itself has landed): wiring it for
  real needs a Cell-to-GroundTruth converter (deriving `labels.json`/
  `injection-points.json`/`expectedresults.csv`-shaped data from a rendered
  manifest's cells) that does not exist yet -- a separate, real deliverable,
  not something to improvise inside this merge. 11 new end-to-end tests
  (`tests/test_labgen_cli.py`), reusing each gate's own known-bad fixtures from
  `tests/test_labgen_gates.py`, `tests/test_labgen_secret_scanner.py`, and
  `tests/test_labgen_minimal_pair.py` rather than re-authoring them.
- LAB: added the Node/Express emitter (`fuzzlab/labgen/emitters/node_express/`),
  Tier-A depth (L-P3.1) — the second stack after `php_current`, covering the
  same three well-documented SQLi/XSS shapes, with its own self-contained JS
  module inventory, this component's first `StackEnv` and `route`-category
  accumulator (`CR-LAB-0001` Addendum D), a digest-pinned Node 22 LTS
  Dockerfile, a real npm-resolved lockfile, and a new sample manifest
  (`lab/manifests/phase3_node_express_sample.yaml`) proven through Tier 0/3
  of the conformance suite (`CC-LAB-0035`, renumbered from a concurrently-claimed
  `CC-LAB-0029` which collided with lanes L-P2.1/L-P0.9/L-P1.1/L-P1.2a/L-P2.2/L-P0.10).
- LAB: added the Python/FastAPI emitter, Tier-A depth (`fuzzlab/labgen/emitters/python_fastapi/`,
  lane L-P3.2, `CC-LAB-0036`, renumbered from a concurrently-claimed `CC-LAB-0029`
  which collided with lanes L-P2.1/L-P0.9/L-P1.1/L-P1.2a/L-P2.2/L-P0.10/L-P3.1) —
  the third Phase-3 stack lane to land, alongside
  `php_current`. Ports the same three Tier-A shapes (`sql_numeric_literal`/
  `sql_string_literal` SQLi, `html_body` XSS) to FastAPI + SQLAlchemy + Jinja2
  idiom via a fully independent module-composition system (own registries,
  own Jinja2 templates — no cross-import with `php_current`/`fuzzlab.labgen.modules`,
  per the Phase 3 lane map's "no stack's emitter package imports another's" rule).
  Uses a one-time static discovery scaffold (`pkgutil.iter_modules()`/`importlib`
  over a `routers/` package) instead of a `route` accumulator, per `CR-LAB-0001`
  Addendum D's FastAPI-specific research, and disables `/docs`/`/redoc`/`/openapi.json`
  in that same scaffold (a correctness requirement, not a follow-up — FastAPI
  serves these by default regardless of any debug flag). Digest-pinned base
  image (`python:3.12-slim-bookworm@sha256:392307...`, fetched live against the
  Docker Hub registry API), an exact-pinned `requirements.txt` lockfile for the
  generated app's own dependencies, and a documented (not yet run — `syft` isn't
  installed in this build environment) SBOM-generation command. New sample
  manifest `lab/manifests/phase3_python_fastapi_sample.yaml`; passes Tier 0
  (`python -m py_compile` lint, added to `fuzzlab.labgen.conformance.tier0`
  alongside the existing `php -l` check; minimal-pair diff via the naive
  fallback, since the real checker is PHP-comment-syntax-specific) and Tier 3
  (whole-manifest regenerate-and-diff). No changes to `emitter.py`'s ABC,
  `php_current`, `fuzzlab.labgen.modules`, or `fuzzlab.labgen.schema` — fully
  additive, per this lane's scope discipline. Full suite after this change:
  929 passed / 8 skipped, same 2 pre-existing unrelated
  `test_mutation_operators.py` failures already present before this change
  (last logged baseline, `CC-LAB-0028`: 868 passed / 9 skipped / same 2
  failures) — no reduction in the pre-existing baseline, only additions.
- LAB (lane L-P3.3a): added `fuzzlab/labgen/emitters/php_laravel/`, the second PHP
  emitter (Laravel/Eloquent idiom, distinct from `php_current`'s plain-PHP idiom) —
  a `StackEnv` (pinned `laravel/framework` 13.32.0, digest-pinned
  `php:8.3-fpm-alpine` base image, `.env` scaffold with `APP_DEBUG=false`/
  `APP_ENV=production` forced), a `route`-category accumulator module for
  `routes/web.php` sorted by cell ID at render time (`CR-LAB-0001` Addendum D),
  and `LaravelEmitter` supporting one trivial shape (`sqli`/`sql_numeric_literal`)
  against a new, deliberately minimal `lab/manifests/phase3_php_laravel_sample.yaml`
  — proven via Tier 0 (`php -l`) and Tier 3 (whole-lab regeneration) of the
  existing conformance suite plus a dedicated accumulator-determinism test. A real
  `composer.lock` (74 packages) was generated against Packagist; a CycloneDX SBOM
  was not (no `syft` on this build host — intended command documented instead).
  Foundation-only, by design: the full module inventory (harder SQLi/XSS shapes,
  lane L-P3.3b) and the `puppy-fort-factory/` migration (lane L-P3.3c) are separate,
  later lanes this work unblocks — see `CC-LAB-0037` (renumbered from a
  concurrently-claimed `CC-LAB-0029` which collided with lanes
  L-P2.1/L-P0.9/L-P1.1/L-P1.2a/L-P2.2/L-P0.10/L-P3.1/L-P3.2).
- Lab (L-P2.3): added `Cell.sink_endpoint: Route | None = None` (default `None` =
  same-endpoint, unchanged behavior for the entire existing corpus) so a stored/
  second-order cell can name a sink page distinct from its injection-point `route`
  (e.g. a profile-bio write endpoint whose payload executes on a separate view page).
  `verdict.py` untouched — it is render/tracking metadata, not a verdict input.
  Composing this with `php_current`'s existing `read_stored_field` source
  (CC-LAB-0022) surfaced one genuine gap: `render()` resolved its page profile from
  `cell.route` unconditionally, so it raised for a cell whose injection route has no
  page profile of its own; fixed by resolving the page profile from `sink_endpoint`
  when set, falling back to `route` otherwise. At merge time, also added the missing
  `sink_endpoint` property to `lab/schemas/manifest.schema.json` (mirroring `route`'s
  own `$ref`), since this lane's own tests exercised the new field only via
  `Manifest.from_dict(..., validate=False)` — without the schema property, a real,
  schema-validated manifest could never actually populate `sink_endpoint`
  (`CC-LAB-0038`, renumbered from a concurrently-claimed `CC-LAB-0029` which collided
  with lanes L-P2.1/L-P0.9/L-P1.1/L-P1.2a/L-P2.2/L-P0.10/L-P3.1/L-P3.2/L-P3.3a).
- Lab (LAB): added the parameter location/encoding axis (§3.4, lane L-P2.4) —
  `fuzzlab.labgen.schema.ParamSpec` (`location`: query/body/header/cookie/json,
  `encoding`: raw/url_encoded/double_url_encoded/base64) as a new optional
  `Cell.param` field, with a matching optional property in
  `lab/schemas/manifest.schema.json`; put on `Cell` rather than `SinkContext`
  because it never changes the verdict-derivation contract, only how a cell is
  rendered/confirmed. Closed two real gaps found in
  `fuzzlab.labgen.oracle_wrapper` while checking its existing handling:
  cookie/JSON marking support and a new `Encoding` enum wired into SSTImap's
  marker mechanism. Resolver-axis wiring (lane L-P1.1) deferred — not yet
  landed in this worktree; a manifest lists the axis explicitly per cell for
  now. See `CC-LAB-0039` (renumbered from a concurrently-claimed `CC-LAB-0029`
  which collided with nine other lanes) / `FR-LAB-37` (renumbered from a
  concurrently-claimed `FR-LAB-27` for the same reason).
- Docs: fleshed `docs/LAB_IMPLEMENTATION_PLAN.md`'s Phase 2 (§3) and Phase 3 (§4)
  from milestone-level bullets into full task breakdowns matching Phase 0/1's
  granularity, and added a new §7 lane/dependency map covering every Phase 0-3
  task (Phase 4 excluded, per its own milestone-only rationale). Phase 2 gets a
  concrete first-draft identity/ownership schema (`lab/identities/identities.yaml`),
  a LAB-owned session-helper design, and task breakdowns for the
  `sink_endpoint`/parameter-location-encoding/`context_depth` axes. Phase 3 is
  split into three fully independent per-stack lanes (Node/Express and
  Python/FastAPI at Tier-A depth, PHP/Laravel at full depth including the D20
  app migration, working-assigned as "stack 1" since its hard-shape work is
  directly portable from Phase 1's own SQLi/XSS hardening), plus a cross-cutting
  `stack`-field/fingerprint-gate lane. §7 assigns every task a lane ID, real
  dependency (not phase order), and wave number, sized for maximum concurrent
  agent dispatch under the project's standing multi-lane orchestration policy —
  12 lanes are immediately dispatchable with zero dependencies.
- Docs: recorded the final open decision in `docs/LAB_IMPLEMENTATION_PLAN.md` —
  Spring Boot's near-term scope (whether to formally drop the optional fourth
  stack, or leave it an undecided line item) is left deliberately open, a
  conscious deferral rather than an oversight, separate from the Phase 3
  pacing decision already made for the three required stacks. 15 of 16
  flagged items are now decided; only Phase 4's SSRF/GraphQL design research
  (deliberately deferred as premature) remains open.
- Docs: recorded the project owner's decisions on every judgment/scope call
  `docs/LAB_IMPLEMENTATION_PLAN.md` had flagged, closing 14 of 16 open items.
  Decided: T-LAB0.9 sweeps FUZZ consumers alongside its schema change;
  leakage-probe thresholds are per-class, seeded provisionally from the
  report's 0.55-0.60 band and recalibrated once Phase 1 has real data; the
  sqlmap fallback design gets a real-binary spot-check first; Lab-track
  Phase 2 proceeds independently of the toolkit's Session-manager phase,
  building its own small session helper rather than waiting (the two serve
  different consumers — build-time oracle confirmation vs. adversarial
  tooling); Phase 3 pacing is stack 1 full depth + stacks 2-3 Tier-A-only
  (confirmed non-blocking to upgrade later, since the module-composition
  architecture makes that additive, not a rewrite — it defers cost, it
  doesn't eliminate it); the pattern-card authoring pass is scheduled for
  after the rest of the build; the pattern corpus versions independently of
  the manifest (follows directly from the already-adopted provenance-
  separation principle); and the SBOM vulnerable-dependency allowlist
  question is deferred, since no scanning-based build gate currently
  consumes the SBOMs this project will generate. Two items remain open:
  Spring Boot's near-term scope (a separate question from the Phase 3
  pacing decision) and Phase 4's SSRF/GraphQL design passes (deliberately
  left unresearched as premature). The document's status line and §6 were
  rewritten accordingly to distinguish resolved items from the two still
  open.
- Docs: reviewed `docs/LAB_IMPLEMENTATION_PLAN.md` again for areas needing more
  clarity/research/information, identified four new gaps beyond the first pass,
  and dispatched four more parallel web-enabled research agents (each with a
  purpose-built prompt) to close them. Headline results: **SBOM/digest-pinning
  tooling** — recommends Syft (CycloneDX output), a quarterly local digest-diff
  script instead of a bot (Renovate/Dependabot judged overkill at this scale);
  **framework debug-page false-positive contract** — found no comparable
  prior-art project (DVWA/Juice Shop/WebGoat/OWASP Benchmark) has actually
  solved this; documents each target framework's exact debug-mode exposure and
  disable flag (flagging FastAPI's `/docs`/`/redoc`/`/openapi.json` as needing
  an explicit, separate disable regardless of debug mode) plus a ZAP
  rules-file/Alert-Filter allowlist as a second line of defense; **`stack`
  field placement in the label contract** — prior art and the general ML
  shortcut-learning literature both favor inlining `stack` in `labels.json`
  over a schema split, resolving one of `CR-LAB-0001` §7's originally deferred
  questions; **DOM XSS fixture authoring** — confirmed hand-authoring is the
  field norm (no templated approach found in any surveyed project), refined to
  recommend a per-sink-type template with an explicit vulnerable/safe swap
  point to preserve this project's existing minimal-pair discipline, with a
  concrete 5-8 item sink taxonomy specified. All four folded into the relevant
  plan sections and the consolidated open-items list (§6), which now tracks 15
  items total (8 resolved by research, 6 remaining as judgment/scope
  `[decision needed]` calls, 1 deliberately left unresearched as premature).
- Docs: dispatched four parallel web-enabled research agents against the four
  genuine **[research needed]** items flagged in `docs/LAB_IMPLEMENTATION_PLAN.md`
  (identifier/alias/connector-position SQLi oracle coverage; `authz_expectations`
  placement prior art; FastAPI route-accumulator necessity; complexity-as-file-
  count-multiplier prior art) and folded their findings into the document.
  Headline results: sqlmap does not reliably detect identifier-context SQLi
  (documented, long-standing limitation — a custom differential-response prober
  is recommended instead, alongside `oracle_wrapper.py`, not inside it); no
  external project declares ownership/authz as static ground-truth data, so
  `identities`/`authz_expectations` is novel schema ground, recommended (by
  analogy to this project's own `provenance.yaml` precedent, not an external
  citation) to live in a separate side file; FastAPI's `APIRouter` needs the
  same central-registration accumulator as Laravel/Express by default, but a
  one-time static discovery scaffold can avoid it; no prior art exists for
  file-depth as a combinable generator axis, so a two-fixed-depth-level spike is
  recommended before generalizing it. The fifth originally-flagged item (Phase
  4's SSRF/GraphQL design passes) was deliberately left undispatched, since the
  plan itself judged that research premature this far from the phase it serves —
  noted explicitly in the consolidated list rather than silently skipped. All
  remaining `[decision needed]` items are judgment/scope calls research cannot
  resolve and stay open for the project owner.
- Docs: added `docs/LAB_IMPLEMENTATION_PLAN.md` — a task-level implementation plan
  for the lab generator's remaining work, covering Phase 0's two open tasks
  (T-LAB0.9, flagged for a FUZZ-consumer review before the ground-truth schema
  change; T-LAB0.10, unblocked on review — the existing `fuzzlab/cli.py` dispatch
  pattern already confirms the proposed subcommand shape) and Phases 1-4 per
  `CR-LAB-0001` §8, at full task granularity for Phase 1 and milestone granularity
  for Phases 2-4 (deliberately not detailed further out, since Phase 1's own
  results should inform Phase 3's pacing decision). Explicitly marks every open
  research/decision item (leakage-probe threshold, identifier/alias/connector-
  position SQLi oracle coverage, `authz_expectations` placement, Phase 3 pacing,
  the FastAPI route-accumulator question, the complexity-as-file-count-multiplier
  interaction) rather than building through them speculatively, consolidated in
  a numbered list at the end for quick reference. A process/planning document,
  not a component code change — no `CC-LAB-NNNN` entry, per this project's own
  governance-doc convention (matching `docs/LAB_PHASE_0_PLAN.md`'s own precedent).
- Feature (LAB, `CC-LAB-0028`, Addendum E, Spike 004): added
  `fuzzlab/labgen/nuclei_oracle.py`, a second, independent tool-oracle wrapper
  extending the validated-oracle set from {sqlmap, commix, SSTImap, ZAP} to include
  **Nuclei** for **path traversal / local file inclusion only**. Kept separate from
  `oracle_wrapper.py`: Nuclei has no per-parameter auto-detection the way
  sqlmap/commix/SSTImap do — it matches hand-authored YAML templates instead, so the
  oracle is the bundled template (`lab/nuclei-templates/path-traversal-etc-passwd.yaml`)
  plus this thin wrapper together. `run_path_traversal_oracle()` scopes to a declared
  `(endpoint_path, param_name)` pair via Nuclei's own template-variable mechanism
  (`-var`) and returns the same fail-closed `confirmed_vulnerable | confirmed_secure |
  inconclusive` verdict shape as an independent type, reusing only
  `oracle_wrapper`'s generic `assert_loopback`/`locate_tool`/`ToolNotFoundError` safety
  primitives. Found and fixed a real, security-relevant defect during development
  (`BUG-0023`): a first-draft classifier treated "exit 0, zero matches" as
  `confirmed_secure`, but Nuclei also exits 0 with zero matches against a target it
  never reached (no dedicated "not vulnerable" marker, unlike sqlmap/commix) — fixed by
  checking `stderr` for Nuclei's own host-unreachable signal before ever returning
  `confirmed_secure`, and never passing `-silent` (which would suppress that signal).
  New `PA-0025` generalizes the fail-closed doctrine to match-only-output tool oracles.
  Validated end to end against a real vulnerable/secure/unreachable three-case test
  (`docs/spikes/SPIKE-004-nuclei-vs-dvwa.md`). 26 offline tests + 3 skip-guarded
  real-`nuclei`-binary integration tests. This lane's worktree diverged onto a stale,
  unrelated branch lineage before starting (self-diagnosed and recovered via a
  documented sync commit) and was based on a point predating several later Phase 0
  merges; its files were verified independently (read in full, re-run against current
  trunk) and copied in, with fresh bookkeeping (`CC-LAB-0028`, `FR-LAB-26`,
  `BUG-0023`/`PA-0025` — renumbered from this lane's own worktree-local
  `BUG-0018`/`PA-0019`, which collided with already-merged, unrelated numbers) written
  here. Full suite 868 passed / 9 skipped / 2 pre-existing unrelated
  `test_mutation_operators.py` failures.
- Feature (LAB, `CC-LAB-0027`, T-LAB0.7): added `fuzzlab/labgen/conformance/`, the
  stack-agnostic tiered emitter conformance suite any future emitter must pass, per
  `docs/LAB_PHASE_0_PLAN.md` T-LAB0.7: **Tier 0** (lint + minimal-pair diff, fully
  exercised offline — real `php -l`, and a minimal-pair check that upgrades
  automatically to the real, sibling-owned `fuzzlab.labgen.minimal_pair` now that it
  has landed, per `get_minimal_pair_checker()`'s own no-caller-change-needed design);
  **Tier 1** (in-process functional + security assertion, built as an honestly-labeled
  `[design]` interface — no live app/DB in this offline session, tested only against
  synthetic responses via a fake client); **Tier 2** (the full container-based oracle,
  "the only tier that actually confirms a label," also `[design]` — no offline stand-in
  is meaningful, tests only prove the on-host-required guard and result-plumbing); **Tier
  3** (whole-lab regeneration, fully exercised offline — two full renders of a real
  emitter's output, byte-diffed, run against both existing Phase-0 manifests in full,
  not a hand-picked subset). Also adds `static_precheck.py`, the `informative |
  uninformative` static-checker flag mechanism (`CR-LAB-0001` Addendum C point 4). A
  Tier-0/1 pass is never recorded as oracle confirmation — only a real Tier-2 run is.
  Found and fixed a real regression while building this (`BUG-0022`): running Tier 3
  against the *entire* illustrative manifest for the first time revealed
  `CC-LAB-0022`'s real-page extension had widened `php_current.supports()` to accept
  `(xss, html_body)` without a page profile for the pre-existing illustrative cell of
  that shape, so `render()` crashed instead of honoring the documented
  supports-then-render contract. Fixed with a one-line `_PAGE_PARAMS` addition; the real
  fix is the new standing whole-manifest Tier-3 tests that guard against this class of
  regression going forward (`PA-0024`). 31 new tests. This lane's worktree was based on
  a commit predating several later Phase 0 merges (including the sibling `minimal_pair`
  lane); its files were verified independently (read in full, re-run against current
  trunk — its own Tier-0 "naive fallback" tests were updated to call the fallback
  directly, since `get_minimal_pair_checker()` now always resolves to the real,
  landed `minimal_pair.check_minimal_pair`) and copied in, with fresh bookkeeping
  (`CC-LAB-0027`, `FR-LAB-25`, `BUG-0022`/`PA-0024` — renumbered from this lane's own
  worktree-local `BUG-0021`/`PA-0023`, which collided with the already-merged
  `CC-PROXY-0016` PROXY fix's numbers) written here. Full suite 842 passed / 6 skipped
  / 2 pre-existing unrelated `test_mutation_operators.py` failures.
- Feature (LAB, `CC-LAB-0026`, `CR-LAB-0001` §3): added `fuzzlab/labgen/fingerprint_gate.py`,
  the mandatory fingerprint-independence build gate for once the generator goes
  multi-stack (Phase 3) — guards against a stack becoming a de facto proxy for a
  vulnerability class or verdict (e.g. "every Flask cell is SSTI," teaching a
  `Server: Werkzeug` header instead of the real signal). Schema-independent: operates on
  plain `{stack, vuln_class, verdict}` mappings, never `fuzzlab.labgen.schema`. Two
  independent halves: deterministic coverage checks (`check_min_stacks_per_class`/
  `check_min_classes_per_stack`, defaulting to the CR's own canonical thresholds — every
  class on >= 2 stacks, every stack carrying >= 3 classes) and a chi-square test of
  independence (`scipy.stats.chi2_contingency`) between stack and vuln_class/verdict —
  a hand-constructed test corpus demonstrates a shape that passes every coverage check
  while still being strongly, statistically confounded, which only the chi-square half
  catches. `run_fingerprint_gate()` runs all four and raises one error listing every
  violation, or returns a report with the computed statistics. New optional
  `labgen-stats` extra (`scipy>=1.11,<2`, the first use of scipy in this project),
  imported lazily inside the chi-square functions — a missing install raises a typed
  `MissingStatsDependencyError`, never a raw `ImportError`. 18 new tests. This lane's
  worktree was based on a commit predating several later Phase 0 merges; its two
  genuinely new files were verified independently (read in full, re-run against current
  trunk) and copied in, with fresh bookkeeping written here. Full suite 811 passed / 6
  skipped / 2 pre-existing unrelated `test_mutation_operators.py` failures.
- Feature (LAB, `CC-LAB-0025`, minimal-pair invariant pulled forward from Phase 1): added
  `fuzzlab/labgen/minimal_pair.py`, a standalone offline checker that a cell's
  vulnerable/secure `EmittedFiles` differ only within the declared transform/sink region
  (`CR-LAB-0001` §3, `docs/LAB_SEED_AUTHORING_PLAYBOOK.md` steps 5/6) — parses the
  `// Module composition: a -> b -> c` provenance comment any module-composition emitter
  writes, classifies each position by its module's registered category, and independently
  cross-checks the empirically differing content region via longest-common-prefix/suffix
  trim, catching the Juliet-style failure mode where an unrelated identifier rename slips
  through as "a small diff." `check_identifier_stability()` additionally asserts declared
  function/handler names are byte-identical across twins. Explicitly out of scope for this
  Phase-0-pulled-forward delivery: unequal-length transform pipelines between twins (raises
  `MinimalPairError` rather than silently passing) and non-PHP identifier extraction. 16 new
  tests using a real `php_current`-rendered pair as the positive fixture. This lane's
  worktree was based on a commit predating several later Phase 0 merges; only its two
  genuinely new files were verified independently (re-read, re-run against current trunk's
  `emitter`/`modules`) and copied in, with fresh bookkeeping written here rather than
  carrying over its isolated-worktree numbering. Full suite 793 passed / 6 skipped / 2
  pre-existing unrelated `test_mutation_operators.py` failures.
- Feature (LAB, `CC-LAB-0024`, T-LAB0.6): added the Gitleaks-based secret-scanner
  build gate — `.gitleaks.toml` (repo root) extending Gitleaks' default ruleset with
  an allowlist for explicitly `FAKE`/`EXAMPLE`/`PLACEHOLDER`-marked seeded credentials,
  `fuzzlab/labgen/secret_scanner.py` (a thin wrapper mirroring `oracle_wrapper.py`'s
  injected-runner pattern, fails the build on a scanner crash as well as a real hit),
  and `tests/test_labgen_secret_scanner.py`'s should-flag/should-not-flag fixture
  corpus — a separate, complementary gate to the existing name-leak scanner, not an
  extension of it. Gitleaks (8.16.0) was installable via `apt-get` in this sandbox, so
  the real binary is used in the test suite rather than a mocked fallback. An earlier
  version of the should-flag fixtures embedded real-shaped secret literals directly in
  the test source, which GitHub's own push-protection scanning (correctly) rejected on
  push; the fixtures were rewritten to assemble each secret from fragments at test-run
  time so no single literal in the source matches a real-secret pattern, while Gitleaks
  itself still scans the fully-assembled bytes at test time, so detection coverage is
  unaffected. This lane's worktree landed on a shared branch with the `CC-PROXY-0016`
  fix below; its offending commit was amended in place to remove the secret before
  merging, so no commit on `claude/trusting-noether-heon0n` ever contains it.
- Fix (PROXY, `CC-PROXY-0016`, BUG-0021): `RepeaterController` cached a single `sqlite3`
  connection as shared instance state and reused it across whichever OS thread happened
  to call it, causing an intermittent `sqlite3.ProgrammingError` (cross-thread SQLite
  use) in `tests/test_web_repeater.py` — now keeps the connection per calling thread
  (`threading.local()`), sharing one `repeater` run row across threads. New PA-0023.
- Feature (LAB, `CC-LAB-0023`, T-LAB0.11): added `fuzzlab/labgen/leakage_probe.py` — the
  metadata leakage-probe reference implementation (a deliberately weak classifier,
  `StratifiedGroupKFold` grouped by generating-rule ID, a permutation-null AUC threshold
  rather than a fixed constant, per-class feature exclusions with written justification and
  visible reporting). Not build-gating yet, per `docs/LAB_PHASE_0_PLAN.md` T-LAB0.11 — a
  reference implementation, wired into an actual gate once Phase 1's real variation exists.
  `scikit-learn`/`numpy` added as a new optional `labgen` extras group (not a main
  dependency, and deliberately not eagerly imported by `fuzzlab/labgen/__init__.py`, so the
  rest of the package needs neither). This lane's worktree diverged onto the same stale,
  unrelated branch lineage that hit an earlier lane; its two genuinely new files were merged
  in after independent verification, with fresh bookkeeping written here (its own isolated
  worktree's `CC-LAB-0014`/`FR-LAB-8` numbers only made sense relative to that disconnected
  lineage). It also declined a mid-task instruction to hard-reset its branch, treating it as
  an unverifiable destructive command — reasonable caution, though in this case the
  instruction was genuine; no work was lost either way since everything was already
  committed. 9 new tests, full suite 754 passed / 6 skipped / 2 pre-existing unrelated
  failures.
- Feature (LAB, `CC-LAB-0022`, T-LAB0.4 extension): expanded `php_current`'s module
  inventory and per-page profile registry to render a small **real** sample of four
  actual `puppy-fort-factory/` pages — `product.php`, `blog_post.php` (same
  `sql_numeric_literal` shape as `product.php`, proving module reuse across real pages,
  not just within one illustrative pair), `login.php` (`sql_string_literal`, POST-sourced),
  and `profile.php` (stored XSS, `html_body`, sourced from a stored field rather than a
  request parameter) — spanning two vulnerability classes and three sink-context families,
  matching `puppy-fort-factory/VULNERABILITIES.md` and `lab/ground-truth/labels.json`'s
  `PFF-0001`/`PFF-0004`/`PFF-0005`/`PFF-0006`. New modules: `post_param`/`read_stored_field`
  sources, `html_entity_escape` transform, `sql_string_literal_lookup`/`html_body_echo`
  sinks, `render_only` complexity. New manifest `lab/manifests/phase0_real_pages_sample.yaml`
  (8 cells, 4 vulnerable/secure pairs), kept separate from the original illustrative
  `example_phase0_scaffold.yaml`. Every cell's derived verdict (`fuzzlab.labgen.verdict`)
  matches the real page's documented status; every rendered cell is byte-deterministic and
  `php -l`-valid. Does not reproduce the remaining ~26 real pages (separate, later,
  larger task) or model `blog_post.php`'s error-suppression nuance (noted, not silently
  dropped, in the emitter's own docstring). 47 new tests; full suite 689 passed / 5 skipped
  / 2 pre-existing unrelated `test_mutation_operators.py` failures.
- Feature (LAB, `CC-LAB-0019`, T-LAB0.4): `fuzzlab/labgen/emitter.py` (the `Emitter` ABC —
  `render(cell) -> EmittedFiles`, `supports()`; `EmittedFiles` a tuple, never assumed
  single-file, for future routed/multi-file stacks per `CR-LAB-0001` Addendum D), a
  composable Jinja2-template module inventory under `fuzzlab/labgen/modules/`
  (source/transform/sink/complexity fragments, per Addendum C's module-composition
  correction — never one monolithic template per cell), and the first (`php_current`)
  emitter assembling them into one real, byte-deterministic, `php -l`-checked
  vulnerable/secure SQLi pair. `jinja2` moved to main dependencies (previously `web`-extra
  only). This lane's worktree diverged onto a stale, unrelated branch lineage before
  starting (an environment quirk); only its genuinely new files were merged in after
  independent verification, discarding its duplicate re-import of already-merged Phase 0
  foundation content. 20 new tests, full suite 642 passed / 5 skipped / 2 pre-existing
  unrelated failures. Also surfaced (unrelated, logged separately) a real, intermittent
  cross-thread SQLite race in `tests/test_web_repeater.py` — see `ERROR_LOG.md`.
- Feature (LAB, T-LAB0.8, mechanical tooling only): `fuzzlab/tools/pattern_corpus_sourcing.py`
  — a pull/index/scope/rank/cluster pipeline that produces a structured candidate
  list for human triage from `github/advisory-database` (git-clone pull, per
  `docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md` Revision 2, never the OSV/GHSA APIs),
  scoped by a new `lab/patterns/sourcing/crosswalk.yaml` (the ten first-wave
  classes' CWE/keyword rules). Deliberately stops short of card authoring: never
  writes `lab/patterns/cards/`, never touches `provenance.yaml`. Clustering is a
  lightweight, dependency-free token-overlap heuristic (a documented stand-in for
  the plan's eventual embedding-based clustering). Idempotent (dedupes
  `REFRESH_LOG.md` entries by commit SHA); git layer fully mockable, one
  auto-skipped live reachability probe. 34 offline tests. `CC-LAB-0020` (renumbered
  from a same-base `CC-LAB-0019` collision with the emitter change above, no
  content changed).
- Feature (LAB, `CC-LAB-0021`): validated OWASP ZAP as a fourth independent tool-oracle
  and a structurally different one (`docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md`
  — real official ZAP 2.16.1 release, reused Spike 003's Flask SSTI twin pair as the
  target, ZAP's own headless "Automation Framework" run as one bounded subprocess call)
  per `CR-LAB-0001`'s "Whole-app safety net → OWASP ZAP daemon mode / Automation
  Framework — Supplementary" mapping, and added a new, separate module
  `fuzzlab/labgen/zap_oracle.py` (`ZapWholeAppScanRequest` /
  `run_zap_whole_app_scan`) — because ZAP is a whole-app active scanner with no single
  declared parameter (unlike sqlmap/commix/SSTImap), so it needed its own request/verdict
  shape (scope by declared alert-name pattern instead of parameter) rather than being
  merged into `oracle_wrapper.py`, while reusing that module's loopback-safety/typed-error/
  bounded-timeout machinery directly. Key finding: ZAP correctly raised a dedicated
  "Server Side Template Injection" alert (plus reflected XSS) on the vulnerable endpoint
  and neither on the secure twin, but also raised several routine header/info-disclosure
  alerts on *both* — confirming the wrapper must always classify against the caller's
  declared scope, never "any alert at all," and must never trust ZAP's own opaque exit
  code for the verdict. 22 new offline tests + 1 new skip-guarded real-ZAP integration
  test, all passing. Completes the playbook's four-tool integration list (SSTImap and ZAP
  integrated; Nuclei remains a separate, concurrent lane's work).
- Feature (LAB, `CC-LAB-0017`): validated SSTImap as a third independent tool-oracle
  (`docs/spikes/SPIKE-003-sstimap-vs-ssti-flask-hacking-playground.md` — real Jinja2 SSTI
  app, GPL-3.0/Apache-2.0 licenses read directly, manual curl confirmation before ever
  touching the tool) and extended `fuzzlab/labgen/oracle_wrapper.py` with
  `ServerSideTemplateInjectionOracleRequest` / `run_server_side_template_injection_oracle`,
  reusing the existing loopback-safety, tool-location, and bounded-timeout×max-attempts
  machinery unchanged — because SSTI is the third validated class named in
  `LAB_SEED_AUTHORING_PLAYBOOK.md`'s "SSTImap/Nuclei/ZAP remain unintegrated" line and
  `CR-LAB-0001`'s tool-mapping table, and this project's own "spike, then wrap" discipline
  (established for sqlmap/commix) applies to every new tool-oracle, not just the first two.
  SSTImap needed its own scoping mechanism (a marker + `-P` location restriction, since it
  has no `-p` flag) and, per Spike 003, no `--ignore-code` equivalent (verified by reading
  its source: no 401/403 special-casing exists). 12 new offline tests + 1 new skip-guarded
  real-`sstimap` integration test, all passing.
- Feature (LAB, T-LAB0.3, CR-LAB-0001/D20): `fuzzlab/labgen/resolver.py` — a real
  covering-array expansion engine over `covertable` 3.2.0 (exact-pinned), with an
  explicit kwargs allowlist (an unrecognized/mistyped option raises instead of
  being silently ignored by `covertable.make()`'s own `**params`, per PA-0010)
  and the sorter always pinned to `covertable.sorters.hash`. Supports pairwise
  (default) and mixed-strength (`sub_models`) expansion plus declarative,
  JSON-serializable `constraints`. Snapshot-tested against a synthetic axis-set
  model and verified deterministic across separate processes/`PYTHONHASHSEED`
  values. Not yet wired into manifest loading — Phase 0's manifest still lists
  cells explicitly. `CC-LAB-0018` (renumbered from a same-base `CC-LAB-0017`
  collision with the SSTImap change above, no content changed).
- Decision (LAB, D20 clarification): resolved a conflict between D20 ("migrate the
  hand-built app") and an earlier draft of `docs/LAB_PHASE_0_PLAN.md` (which had read a
  separate "additive-only" instruction as "never remove the hand-built app," and
  concluded the opposite). Confirmed with the user: additive-only governs the toolkit's
  own capabilities/robustness/stack breadth, not any one hand-built artifact's permanence
  — the app is retired once the generator reproduces it and the Phase 3 PHP/Laravel
  emitter lands. `LAB_PHASE_0_PLAN.md` and `docs/DECISIONS_AND_ROADMAP.md` (D20)
  corrected; Phase 0's own exit criterion is unaffected either way.
- Tooling: gitignored `.claude/worktrees/` — background-agent scratch git worktrees for
  in-progress parallel work (e.g. the Lane A/B oracle-wrapper and lab-generator-Phase-0
  builds) showed up as untracked and tripped the git-status Stop hook; they're never a
  deliverable and should never be committed.
- Feature (LAB, `CC-LAB-0015`): added `fuzzlab/labgen/oracle_wrapper.py`, the reusable
  sqlmap/commix oracle wrapper called for by `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`'s
  "Recommended next action" step 1 — a plain, schema-independent Python function per
  validated class (`run_sql_injection_oracle`, `run_command_injection_oracle`) that
  automates both spikes' lessons (`SPIKE-001`'s `--ignore-code` auth-bypass, `SPIKE-002`'s
  mandatory single-parameter scoping and a bounded timeout/retry safety valve against a
  hung tool), enforces the loopback-only safety rule before every invocation, and returns
  a fail-closed `confirmed_vulnerable | confirmed_secure | inconclusive` verdict — because
  the playbook's own seed pipeline now needs this wrapper, not hand-written exploit code,
  as the security assertion for every SQLi/command-injection cell. 33 offline tests (every
  branch, injected fake runner) + 2 skip-guarded tests against the real cloned binaries.
- Feature (LAB, Phase 0 foundation, CR-LAB-0001/D20): built the lab-generator
  foundation — `fuzzlab/labgen/` (`schema.py` manifest IR, `verdict.py` the
  versioned/snapshot-tested binary-verdict engine, `subseed.py` sub-seed
  derivation + canonical serialization, `gates.py` the regenerate-and-diff and
  name-leak build gates); `lab/schemas/manifest.schema.json` and
  `safety_matrix.schema.json` (pipeline-valued transform + structured
  sink-context safety matrix, per CR-LAB-0001 §3); `lab/safety_matrix.yaml` v1
  and an illustrative `lab/manifests/example_phase0_scaffold.yaml`; and a
  `lab/patterns/` provenance-corpus scaffold (3 example cards, taxonomy,
  one-directional `provenance.yaml`, per Addendum A). Full 25-30-card corpus
  authoring, the real per-stack emitter (T-LAB0.4), and the covering-array
  resolver (T-LAB0.3) remain separate follow-up work — this delivery proves
  the pipe, it does not migrate the existing PHP app. `CC-LAB-0016` (built
  concurrently with, and independently of, `CC-LAB-0015`'s oracle wrapper —
  renumbered from a same-base collision at merge time, no content changed).
- Fix (BUG-0020, tooling/process): `.claude/hooks/check-error-log-bookkeeping.sh`'s
  keyword regex matched `hang` as an unanchored substring of `change`/`changed`/`changes` —
  words this project's own changelog convention uses constantly — false-positiving on its
  first real, incident-free use. Anchored all keywords with `\b` word boundaries and
  inflection groups; new rule PA-0022 (check a keyword heuristic against the project's own
  routine vocabulary before trusting it unattended). See `docs/bugs/BUG-0020-*`.
- Decision (LAB, D20): approved `CR-LAB-0001` — binary verdict model, migrate the
  existing hand-built app into the generator (Phase 3), `patterns/` corpus lives under
  LAB not IND. The three no-oracle gap classes (IDOR/BOLA, business logic, race
  conditions) are deferred indefinitely, no paid consult for now. `docs/ARCHITECTURE.md`,
  `01-target-lab/requirements.md` (new FR-LAB-8/9/10), and the lab-track phase list in
  `docs/DECISIONS_AND_ROADMAP.md` (which had drifted from `CR-LAB-0001` §8's more
  detailed breakdown) updated to match. See CC-LAB-0014.
- Docs (process, bookkeeping reconciliation): audited `ERROR_LOG.md` against every
  `docs/bugs/BUG-NNNN-*.md` investigation and `docs/PREVENTIVE_ACTIONS.md` rule in both
  directions. Found two gaps and closed them: (1) the `ERROR_LOG.md` entry for "Credential
  host-key mismatch (BUG-0007) + ground-truth path traceback" and its change-control entry
  (CC-CORE-0017) existed, but the required `docs/bugs/BUG-0007-*.md` investigation and
  preventive action did not — backfilled the RCA (a recurrence of the BUG-0003/PA-0003
  shared-normalization-convention class, plus a narrower typed-error-boundary gap) and
  added PA-0021, strengthening PA-0003 to a general obligation rather than one scoped to
  the example it was written against. (2) BUG-0001 and BUG-0002 (hardcoded schema-version
  test assertions) had investigation docs and PA-0001/PA-0002 but no `ERROR_LOG.md` line —
  added both. Every `BUG-NNNN` now has all three linked artifacts (`ERROR_LOG.md` line,
  investigation doc, preventive action) in both directions; no other gaps found.
- Fix (BUG-0019, tooling/process): PA-0019 (BUG-0018's fix) was an advisory rule with no
  enforcement path independent of remembering to apply it — the same recall failure it was
  meant to prevent. Added a Claude Code Stop hook, `.claude/hooks/check-error-log-bookkeeping.sh`
  (wired via `.claude/settings.json`), that inspects this turn's not-yet-pushed changes and
  blocks the session from ending when they look incident-shaped but `ERROR_LOG.md` wasn't
  touched. New rule PA-0020, superseding PA-0019's enforcement; see `docs/bugs/BUG-0019-*`.
- Fix (BUG-0018, process): the sqlmap/commix oracle-spike findings (below) were fully
  written up in their spike documents but not added to `ERROR_LOG.md` until the user asked
  for it. RCA found reliance on a finding's narrative framing to decide whether the
  `CLAUDE.md` bookkeeping checklist applied, instead of checking it against each artifact's
  literal stated scope; rule PA-0018's own neighbor here is unrelated — see
  `docs/bugs/BUG-0018-*`; new rule PA-0019. The PA-0002 sweep of this session's own conduct
  found one more un-logged instance (Docker Hub pulls blocked by this environment's egress
  policy during Spike 001) and logged it; a second candidate (Spike 001's PHP-8.4/Laravel
  vendor-compatibility patching) was reviewed and deliberately not logged separately, since
  it's throwaway spike-environment friction already fully captured in that spike's own
  write-up.
- Docs (LAB, lab-generator program): recorded two oracle-tool design gaps found while
  validating the manifest generator's planned tool-oracle architecture (`CR-LAB-0001`
  Addendum E) against real vulnerable targets — sqlmap refusing to test past a 401/403
  "secure" response (Spike 001, vAPI) and commix hanging on an ambient rotating CSRF
  token then looping on an irrelevant form field (Spike 002, DVWA). Neither is a fuzzlab
  code defect (no oracle-wrapper code exists yet), so logged in `ERROR_LOG.md` as Open
  design requirements per its own scope note, not a full `BUG-NNNN`/`PA-NNNN` — both are
  cross-referenced to `docs/spikes/SPIKE-001-*`/`SPIKE-002-*` and the fix requirement
  already tracked in `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`.
- Feature (UI, layout redesign): rebuilt the **Launch view** inside the shell as the approved
  **master-detail** — a grouped activity picker (Discovery / Attack / Analysis, with
  traffic/auth/destr gate tags + selection accent bar) on the left, and the selected activity's
  configurable form on the right (tags, Dry-run/Run/Stop, argparse fields, inline option
  checkboxes, D14 category pills, plugins panel, dry-run preview + live SSE console). Brought
  forward from R1 at the user's request so the reviewed mockup is what ships. Command-spec form
  contract unchanged (same data-dest/data-type hooks → runner/dry-run/gating/SSE untouched);
  full suite green (499/6) + light/dark screenshots. CC-UI-0022, FR-UI-8.
- Feature (UI, layout redesign R0): reframed the web panel in a persistent **app shell** — a
  left-sidebar nav (grouped Workbench / Analysis) + a top context bar (target / scope /
  authorized / proxy chips) — over a new **design-token** stylesheet (`web/static/tokens.css`:
  light / dark / system theme + compact density, persisted per-viewer, applied before first
  paint). Rewrote `base.html`, retokenized `app.css` as a CSS-grid shell (every component
  class preserved), added `initShell()` for theme/density/collapse + the proxy chip, and merged
  a shared `_shell_context` into every page — because the top hash-tab masthead did not scale
  and the UI needed one retheme point to build R1–R3 on. **Chrome only:** hash-based section
  switching and all launcher/proxy/results behavior are unchanged; the no-auto-run / loopback /
  authorized / read-only / redaction invariants are untouched. Full suite green (499 passed /
  6 skipped) + real-browser screenshot verification (light + dark). D-UI-shell, CC-UI-0021,
  FR-UI-8.
- Docs (UI): added `docs/UI_LAYOUT_REDESIGN.md`, a design record for reworking the panel's
  layout/IA — grounded in a cross-tool UX review (Rapid7, Tenable, Qualys VMDR,
  Greenbone/OpenVAS, NodeWare, Burp Suite, OWASP ZAP). Proposes an app shell (left sidebar +
  top context bar) over a deep-linkable multi-page app with a shared design system (tokens +
  light/dark/density, one DataTable with faceted filters + saved views, one proxy message
  editor, list→detail, command palette + send-to), an Overview dashboard, a Findings
  workbench, and a rebuilt Proxy workbench, with an incremental R0–R3 migration that keeps
  the safety invariants. Design only; see CC-UI-0020.
- Feature (UI, Phase 2.4): Proxy Scope + Match-Replace — completes the Proxy workbench.
  `ProxyController` gained live scope (default-deny include/exclude) and ordered
  match-replace (byte rewrites) management, exposed via `GET|POST /api/proxy/scope`, `DELETE
  /api/proxy/scope/{index}`, `GET|POST /api/proxy/matchreplace`, `DELETE
  /api/proxy/matchreplace/{index}`, `POST /api/proxy/matchreplace/{index}/toggle` (409
  without the in-process proxy; bad target / missing header_name → 400). The Proxy tab's
  Scope · Match-Replace card lists/adds/removes both rule kinds (with a match-replace enable
  toggle). With History + Intercept + Repeater, the Proxy workbench (revamp ask #2) is now
  complete. Tests: `test_web_scope.py` (controller effects incl. a real rewrite via
  `engine.matchreplace.apply`; routes + validation). Suite 496 passed / 6 skipped. See
  CC-UI-0019.
- Feature (UI, Phase 2.3): Proxy Repeater — persisted replay tabs. Added a `RepeaterController`
  over the existing `Repeater` backend (own SocketSender + lazily-opened store; list/create/
  from-flow/send) and routes `GET|POST /api/proxy/repeater/tabs`, `POST
  /api/proxy/repeater/from-flow/{id}`, `POST /api/proxy/repeater/tabs/{id}/send` (byte-exact
  replay, `authorized`-gated). The Proxy tab's Repeater card has a tabs dropdown, new-tab form,
  editable raw request, Send, and a response viewer; a History flow gains "→ Repeater". Fixed
  a CRLF bug: a `<textarea>` normalizes newlines to LF (breaking HTTP framing) — the client now
  restores CRLF (`toWire`) for edited requests in both repeater and intercept-forward; the API
  stays byte-exact. Tests: `test_web_repeater.py` (controller + routes incl. a real over-socket
  send) and a real-browser regression `test_web_repeater_browser.py`. Suite 490 passed /
  6 skipped. See CC-UI-0018.
- Feature (UI + proxy, Phase 2.2): live Intercept — pause / edit / drop / forward. Added a
  gated **response-intercept hook** to `ProxyEngine` + `Interceptor.intercept_responses`
  (default off, so the default path stays byte-exact); request interception unchanged
  (CC-PROXY-0015). `ProxyController` gained `pending_view` / `forward` / `drop` /
  `set_intercept_responses`, with routes `GET /api/proxy/intercept/pending`, `POST
  /api/proxy/intercept/{id}/forward|drop`, and the toggle extended for responses (409
  without an in-process proxy). The Proxy tab's Intercept card renders request/response
  toggles, a polled pending table, and an editable raw-bytes textarea with Forward / Drop
  (rows DOM-built from untrusted traffic). Verified in a real browser holding an in-flight
  request and over real sockets (an edited request reaches the upstream). New tests:
  `test_proxy_response_intercept.py`, `test_proxy_intercept_live.py`, `test_web_intercept.py`.
  Suite 484 passed / 6 skipped. See CC-PROXY-0015, CC-UI-0017.
- Feature (UI, Phase 2.1): Proxy tab flow History (read-only). Added `fuzzlab/web/proxyview.py`
  (store-backed `list_flows` + `flow_detail` over `flow`/`body`/`flow_fts`; newest-first, FTS
  search, redacted raw request/response) and routes `GET /api/proxy/flows[?q=]` +
  `/api/proxy/flows/{id}`. The Proxy tab renders a History sub-panel (search, flows table,
  req/resp viewer) and a live proxy-status line; rows come from recorded traffic so they're
  built with DOM `textContent` (no stored-XSS). Read-only, cross-process, never creates the
  store. Tests: `test_web_proxy_history.py` (7) + the browser smoke extended to the Proxy tab.
  Suite 474 passed / 6 skipped. See CC-UI-0016.
- Feature (UI, Phase 1): Activity Launcher. The read-only preview is now an interactive
  launcher — a form per activity rendered server-side from each command spec (widget per
  flag type, keyed by argparse dest), with **Dry-run** (previews the exact command, sends
  nothing), gated **Run** streaming the child's output live over SSE, and **Stop**. Traffic
  tools' Run is disabled unless `authorized` (and `--authorized` is pre-checked when the
  panel is authorized). Adds a D14 **category picker** (`--categories` as checkboxes from the
  known categories) and a **Plugins** panel + `GET /api/plugins`. Verified end-to-end in a
  real browser (`test_web_launcher_browser.py`: dry-run preview + a run streaming to
  `[exit …]`), plus extended frontend tests. Suite 467 passed / 6 skipped. See CC-UI-0015.
- Feature (UI, Phase 0.4): unified serve mode with an in-process proxy — completes the
  Phase-0 foundations. Added `fuzzlab/web/proxycontrol.py` (`ProxyConfig`/`ProxyController`)
  that builds the proxy engine (Scope + MatchReplace + Interceptor + SocketSender + optional
  history/CA) and owns its lifecycle; `create_app(proxy=)` starts/stops it via a FastAPI
  lifespan so live interception shares the panel's event loop (its futures aren't
  cross-process — D19). New `GET /api/proxy/status` + `POST /api/proxy/intercept`; `serve()`
  refuses a non-loopback proxy host; `fuzzlab web --with-proxy` (new `web_main`) runs the
  proxy in-process and requires `--authorized` (it forwards traffic). Opt-in, loopback-only,
  separate port; dormant by default. Records D18 (subprocess launch) + D19 (in-process
  proxy). 7 new tests (`test_web_proxy_serve.py`); suite 462 passed / 6 skipped. See
  CC-UI-0014. Proxy code unchanged (the response-intercept hook is Phase 2).
- Feature (UI, Phase 0.3): launcher runner + dry-run + live output. Added
  `fuzzlab/web/runner.py` (`build_argv`/`display_command`; an async `Runner` that spawns a
  tool as `python -m fuzzlab.cli <name> <flags>` and streams stdout/stderr as SSE, with
  stop) and four endpoints: `POST /api/launch/dry-run` (previews the exact command, sends
  nothing — FR-UI-5), `POST /api/launch` (no-auto-run gate: a traffic tool is 403 unless
  `authorized:true`), `GET /api/launch/{token}/stream` (SSE), `POST /api/launch/{token}/stop`.
  Safe by construction: only flags the command spec declares reach argv (no arbitrary-arg
  injection) and no shell is used. 12 new tests (`test_web_runner.py`) incl. a real
  child-process stream; suite 455 passed / 6 skipped. See CC-UI-0013. (Launcher UI forms
  wired to these endpoints land in Phase 1.)
- Feature (UI, Phase 0.2): frontend foundation for the revamp. Reworked `fuzzlab/web/app.py`
  from hand-rendered HTML to **jinja2 templates** (`web/templates/`) + a **static asset
  pipeline** (`web/static/app.css`, `app.js` mounted at `/static`); the index is now a
  **tabbed shell** (Launcher / Proxy / Results / ML / Diagnostics) rendered server-side with
  a vanilla-JS toggler (no-JS shows all panels). The Launcher previews every activity from
  the command-spec registry; Results keeps the runs dashboard; Proxy/ML/Diagnostics are
  stubs for Phases 2–4. Added `fuzzlab/web/sse.py` (SSE plumbing for later live streams).
  No JSON-API/behavior/schema change; read-only + loopback + no-auto-run invariants intact.
  jinja2 (a declared `web` extra) is now used; templates/static added to package-data. New
  tests: `test_web_frontend.py` (10) + `test_web_sse.py` (5); suite 443 passed / 6 skipped.
  See CC-UI-0012, FR-UI-7. (uPlot charting deferred to first use in Phase 4.)
- Feature (UI, Phase 0.1): added `fuzzlab/web/commandspec.py`, a registry that introspects
  each launchable activity's own `argparse` parser into a machine-readable form schema
  (name/type/required/default/choices/multiple; per-command sends-traffic + derived
  authorized/destructive gates). Every tool now exposes a `build_parser()` and its `main()`
  delegates to it — a behavior-preserving refactor across CRAWL/AUD/FUZZ/MUT/PROXY/SESS +
  UI(report). This is the single-source-of-truth backbone for the launcher (FR-UI-6): a new
  tool flag appears in the UI automatically, nothing hand-mirrored (PA-0001/PA-0003). No CLI
  behavior/flags/defaults change; no traffic; no schema change. 17 new tests
  (`tests/test_web_commandspec.py`); suite 433 passed / 6 skipped. See CC-UI-0011 (+
  CC-CRAWL-0006, CC-AUD-0014, CC-FUZZ-0018, CC-MUT-0007, CC-PROXY-0014, CC-SESS-0009).
- Docs (UI): added `docs/UI_REVAMP_PLAN.md`, the tracked design plan to grow the read-only
  web control panel into a full local control plane — an activity launcher (per-tool flag
  forms, dry-run, live output), a proxy workbench (history/intercept/repeater/scope), a
  dedicated ML tab, and a TensorBoard-like diagnostics tab — with the Phase-0 foundations,
  the exists-vs-needs-building split, and the invariants (no-auto-run/loopback/authorized/
  read-only/redaction) each phase must preserve. Design only; see CC-UI-0010.
- Fix (BUG-0017, on-host): `scripts/greybox_e2e.sh` step 1 (`labctl.sh reset`) failed under
  podman-compose (`exit status 125`, "cannot remove … as it is running") and wedged the
  stack, blocking Part E. A **recurrence of BUG-0013**: that fix made `labctl.sh up`
  self-healing but left `reset` recreating containers with a bare `down -v` + `up` and no
  force-clean fallback. Factored the force-clean into one shared `_force_clean()` helper and
  routed every lifecycle path — `up` (keep-volume), `reset` (drop-volume), and `down`
  (keep-volume, from the sweep) — through it. Recurrence review +
  prior-PA-failure analysis (PA-0014 was scoped to the *trigger* env/profile change, the
  PA-0002 sweep inherited that framing, and PA-0003 wasn't applied so the self-heal was
  duplicated-by-omission) in `docs/bugs/BUG-0017-*`; new rule PA-0018 re-keys the self-heal to
  the *mechanism* and to all container-recreate paths. See CC-LAB-0013. Verified statically
  (mocked podman/compose; `up`/`reset` both branches exit 0). Suite 416 passed / 6 skipped.
- Fix (BUG-0016): `greybox-run`'s "new-code reward" was starved by a global coverage
  frontier (the benign baseline, sent first per point, consumed the novelty), so every
  attack showed `novel=0`, `newcode_reward` read 0, and a false "shim not installed?" NOTE
  contradicted the step-6 PASS. `run_greybox` now credits an attack's coverage as a
  **per-point differential** (attack vs its own baseline); the global frontier is kept only
  for the run-wide exploration total; the NOTE fires only when no coverage was captured. The
  Part F runbook exit was reframed (verify the bandit via posteriors; `requests_per_finding`
  can't show its oracle-probe savings) — same class. Recurrence review + prior-PA-0015
  analysis in the RCA; new rule PA-0017 (an exit metric must isolate the capability it
  claims). RCA `docs/bugs/BUG-0016-*`; see CC-FUZZ-0017. Suite 416 passed / 6 skipped.
- Fix (BUG-0015, on-host): `scripts/waf_evasion_e2e.sh` exited silently after step 1 because
  `labctl.sh up` returned non-zero on success when no profile was set — its `up)` case ended
  with `[ -n "$PFF_PROFILE" ] && echo ...`, a trailing `A && B` that fails (and, as the last
  command, sets the exit status) when the profile is empty, aborting the `set -e` caller. Now
  an `if`. Parts I and K passed on-host; this unblocks Part J. Recurrence review: shipped
  because on-host scripts can't be executed in the build sandbox (recurrence of BUG-0014),
  and a fail-loud self-test can't catch an abort before it runs — captured as PA-0016
  (static/shellcheck + exit-code checks on both branches; verify the script's own harness,
  strengthening PA-0015). RCA `docs/bugs/BUG-0015-*`; see CC-LAB-0012.
- Docs (BUG-0014): investigated and fixed the systemic inadequacy of the initial
  `docs/ON_HOST_RUNBOOK.md` — its `[build+run]` parts (E/I/J/K) documented unbuilt,
  unverified, and in places incorrect steps as followable (the WAF-disabling double
  `auto_prepend_file`, log-tailing DB faults, a non-working `up --profile`, an invalid
  duplicate-identical Content-Length exit). Root cause: operational docs written from design
  intent, never executed/verified against the real host, with a format that conflated "needs
  building" with "runnable". The recurrence review found this root cause produced BUG-0009 /
  BUG-0012 / BUG-0013 and the "no Compose provider" incident, each fixed piecemeal with no
  documentation-adequacy PA. Corrective: E/I/J/K are now verified one-command `[run]` flows;
  the Legend is corrected (all parts `[run]`; a `[design]` tag marks unbuilt steps that must
  not be written as followable). New rule PA-0015. RCA `docs/bugs/BUG-0014-*`.
- Fix (BUG-0012/BUG-0013, on-host scripts): `scripts/proxy_e2e.sh` step 5 gave a false FAIL
  because it asserted the parsed path rejects a duplicate-*identical* Content-Length, which
  is valid per RFC 7230 — now it sends *conflicting* values (0 and 5), matching the offline
  test (PA-0013). And `lab/labctl.sh up` is now self-healing under podman-compose (which
  can't recreate a running stack in place on an env/profile change): on failure it downs,
  force-clears wedged podman containers/pod/network, and retries — unblocking
  `waf_evasion_e2e.sh` / `h2_desync_e2e.sh`. BUG-0013's recurrence review found this is the
  same class as the earlier "no Compose provider" incident, which had been fixed in place
  without a PA; captured now as PA-0014. See CC-PROXY-0013, CC-LAB-0011. Suite 415 passed / 6 skipped.
- Process/governance: strengthened the bug protocol with a **recurrence-escalation** step.
  Before deciding a preventive action, the investigation must now review the other
  `docs/bugs/` logs and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence of the same bug
  or the same root cause; if one is found, it must first document **why the earlier
  preventive action did not prevent the recurrence** (too narrow / wrong layer / not
  followed / not enforced) and then choose a new PA that fixes that failure mode and
  strengthens or supersedes the prior one. Added the two new sections to the required
  contents + template in `docs/bugs/README.md` and to the bug workflow in `CLAUDE.md`
  (distinct from PA-0002's codebase sweep: this sweeps the bug history). Governance change
  — recorded here per the CLAUDE.md convention.
- Fix (BUG-0010/BUG-0011, on-host proxy): HTTPS interception failed on-host with "Missing
  Authority Key Identifier" and `scripts/proxy_e2e.sh` hung on shutdown. `LocalCA` now
  mints certs strict OpenSSL/browsers accept (CA SKI + keyCertSign; leaf SKI, AKI→CA,
  serverAuth EKU, IPAddress SAN for IP hosts; no deprecated `utcnow()`), and
  `AsyncProxyServer.stop()` cancels in-flight connection tasks + bounds `wait_closed()`
  (Python 3.12+ waits on live connections) so the proxy exits cleanly; the proxy CLI
  persists flows per-record (WAL) and the script bounds its shutdown. RCAs
  `docs/bugs/BUG-0010-*`, `BUG-0011-*`; rules PA-0011/PA-0012; see CC-PROXY-0012.
  Suite 415 passed / 6 skipped.
- Feature (Phase 8 mutation-vs-WAF on-host last mile): runbook Part J is now a one-command
  flow. Built `fuzzlab/mutation/livefilter.py::HttpFilter` (the mutation `Filter` seam
  backed by live WAF round-trips: 403 -> caught, with rule-id parsing) and
  `fuzzlab/mutation/run.py` + `fuzzlab mutate-run` (search a preserving bypass against the
  live WAF and record it to `payload_variant`, with optional Part E coverage gain).
  `scripts/waf_evasion_e2e.sh` enables the WAF, evades it, verifies base 403 / variant 200,
  and restores the WAF to OFF (even on error). See CC-MUT-0006. Suite 415 passed / 5 skipped.
- Feature (Phase 9 protocol on-host last mile): runbook Part K is now a one-command flow.
  Built `fuzzlab/proxy/h2transport.py::H2Transport` — the live h2c socket send/receive
  around the from-scratch `H2RawClient`: `request(...)` (well-behaved: preface+SETTINGS+
  HEADERS, ACK, read to END_STREAM, decode `:status`/body) and `send_raw(...)` (byte-exact
  malformed/length-desync/CRLF-in-header primitives). `labctl.sh` gained `PFF_PROFILE`
  (top-level `--profile`) so `PFF_PROFILE=desync ./labctl.sh up` starts the downgrade
  front-end. `scripts/h2_desync_e2e.sh` self-tests a normal request through the downgrade
  and emits the desync primitives. See CC-PROXY-0011, CC-LAB-0010. Suite 411 passed / 5 skipped.
- Feature (Phase 6 proxy on-host last mile): runbook Part I is now a one-command flow.
  Built `fuzzlab/proxy/socketsender.py::SocketSender` (real upstream `Sender`: byte-exact
  TCP/TLS forward + full HTTP/1 response read), CONNECT/TLS termination in
  `AsyncProxyServer` (CA-minted per-host leaves via new `LocalCA.leaf_cert_files`;
  server-side `loop.start_tls`), and a `fuzzlab proxy` CLI (`--export-ca` + the
  `--authorized` run path). `scripts/proxy_e2e.sh` proves the real upstream and the
  byte-exact duplicate-Content-Length exit against the live lab. See CC-PROXY-0010.
  Suite 408 passed / 5 skipped.
- Process/governance: added `CLAUDE.md` — an auto-loaded, session-start checklist that
  makes the engineering bookkeeping impossible to overlook: the preventive-action rules
  (mandatory), CHANGELOG + per-component change-control, the living `requirements.md` and
  `docs/ARCHITECTURE.md` specs, the error log, and the full bug protocol (ERROR_LOG ↔
  BUG-NNNN ↔ PA-NNNN + the PA-0002 sweep). Added a prominent "Engineering process" section
  to `README.md` and umbrella pointers from `CHANGELOG.md`, `ERROR_LOG.md`,
  `docs/PREVENTIVE_ACTIONS.md`, `docs/bugs/README.md`, and `docs/components/README.md` back
  to `CLAUDE.md`. Motivated by two process misses this session (a bug fixed with only an
  ERROR_LOG line; instrumentation not spec-tracked). Project-level governance change — no
  single component owner, so recorded here per the CLAUDE.md convention.
- Feature (Phase 3 live last mile, T3.2–T3.7): grey-box instrumentation is now runnable end
  to end. Built `greybox/coverage.py::FileCoverageSource` + `greybox/dbfault.py::
  FileDbFaultSource` (read the lab shim's per-request side channel — covered lines *and* a
  db_fault marker in one correlation-keyed file), `greybox/reset.py::ScriptLabControl`
  (labctl snapshot/restore), and `fuzzlab greybox-run` (`greybox/run.py` + `greybox_cli.py`)
  which sends correlated probes, shapes the reward (screening + coverage novelty + db_fault),
  and writes enriched `attempt` rows. Lab side: `lab/web.Dockerfile` adds pcov; new
  `puppy-fort-factory/includes/cov.php` shim + `includes/prepend.php` chain (fixes the
  single-valued `auto_prepend_file` — the old runbook prose would have silently disabled the
  WAF); `lab/compose.yaml` mounts the side channel; `lab/labctl.sh` gains `snapshot`/
  `restore`. One-command runner `scripts/greybox_e2e.sh` (build → self-test → snapshot →
  run → exit check). Runbook Part E rewritten from `[build+run]` to a single command.
  M10 stays advisory (oracle remains sole finding-writer). See CC-FUZZ-0016, CC-LAB-0009.
  Suite 405 passed / 4 skipped.
- Fix (BUG-0008, auth correctness): the session manager no longer treats the presence of
  a session cookie as proof of login. PHP's `session_start()` issues an anonymous
  `PHPSESSID` on the first GET, so the login fetcher's jar was non-empty even on a *failed*
  login and any credentials "authenticated" (the crawler logged "authenticated as admin"
  for a nonexistent user). `SessionManager._login` now fails loud when the login POST
  response is still a login page or is `401/403`, before inspecting cookies — a positive
  differential signal is required (`fuzzlab/session/manager.py`). This is a toolkit
  false-positive, not the lab's intended SQLi auth-bypass (plain wrong creds don't trigger
  that). Regression tests model the pre-login anonymous cookie. RCA
  `docs/bugs/BUG-0008-login-success-inferred-from-anonymous-cookie.md`; rule PA-0007; see
  CC-SESS-0008. Suite 394 passed / 4 skipped.
- Docs: expanded `docs/ON_HOST_RUNBOOK.md` — rewrote **Part E** (Phase 3 grey-box) into a
  concrete, followable implementation guide (pcov + coverage shim snippets, the reader
  seams to back, reset, M10 wiring, the exit query), and added **Parts F–L** for the
  Phase 4–10 exits that were missing: bandit-beats-fixed-order (F), detection classifier
  vs baselines (G), ranker + active learning (H), live-TLS proxy (I), mutation-vs-WAF (J),
  protocol depth (K), and plugins/anomaly/report/transfer (L). Each part is tagged `[run]`
  (built — run + read `run_metrics`) or `[build+run]` (needs an on-host last mile), with
  exact commands, expected results, and verify queries grounded in the real flags/keys.
- Fix (BUG-0007, on-host): credentials are now keyed by the **bare hostname** regardless
  of whether they were saved as `127.0.0.1`, `127.0.0.1:8080`, or a full URL
  (`core/credentials.py::_norm_host`), matching how the session layer looks them up
  (`urlparse(url).hostname`). Previously `set-credential --host 127.0.0.1:8080` stored a
  key the crawler's hostname lookup (`127.0.0.1`) missed. The `require` error now shows
  the exact `set-credential` command. Runbook corrected (Part C uses `--host 127.0.0.1`;
  added a working-directory note — run `fuzzlab` from the repo root). `contract.load` now
  raises a clear, actionable `ContractError` for a missing ground-truth dir (no raw
  traceback), and `fuzzlab auto` exits cleanly on it. +3 tests (392 passed / 4 skipped).
- Phase 10 (follow-up): wired the last plugin hook — `register_payload_source` — end to
  end. `mutation/payloads.py::PayloadPool` aggregates seed payloads per vuln class from
  built-ins + plugin payload sources (deduped, bad sources skipped); `PayloadPool.from_plugins`
  folds in `PluginManager.payload_sources()`, and `MutationSearch.search_pool` evolves each
  seed against the filter. All seven FR-PLUG-2 hooks now have a consumer. +5 tests
  (390 passed / 4 skipped). Change-control: CC-PLUG-0004.
- Phase 10 (T10.5): added the **multi-target evaluation harness**
  (`fuzzlab/harness/multitarget.py`). `run_targets` runs the pipeline against several
  `TargetSpec`s (base-url + ground-truth) via an injected `sender_for` seam;
  `transfer_summary` reports per-target scores + macro precision/recall + a `generalizes`
  verdict (real vulns on ≥ 2 scored targets); `format_transfer` renders it. Offline-
  testable; the live external-lab transfer run is the on-host T10.6 exit. +4 tests
  (385 passed / 4 skipped). Change-control: CC-LAB-0008.
- Phase 10 (T10.4): added the **reproducible evaluation report** (`fuzzlab/report/`).
  `build_report(store, run_id)` assembles a deterministic report from a stored run
  (run/config identity, target, counts, findings, `run_metrics`, deployed models, active
  plugins), stably sorted; `format_json` is canonical (sorted-key) JSON for diffing,
  `format_text` a human summary. Wired as a read-only `fuzzlab report [--run] [--json]`
  command. +6 tests (381 passed / 4 skipped). Change-control: CC-UI-0009.
- Phase 10 (T10.3): added the **anomaly-detection tripwire** (`fuzzlab/ml/anomaly.py`).
  `ECOD` — a parameter-free, pure-Python Empirical-CDF outlier detector (no numpy/sklearn,
  no labels); `flag_top` flags the top contamination fraction; `detect_anomalies` runs it
  over the run's candidate vectors and records `anomaly_flagged`; `augment` +
  `train_and_score(hybrid=True)` feed the anomaly score into the classifier (XGBOD-style).
  **Advisory only** — scores/flags/a feature, never labels. +8 tests (375 passed / 4
  skipped). Change-control: CC-ML-0008.
- Phase 10 (T10.2): wired the plugin hooks into the pipeline (all no-ops with zero
  plugins). `HttpClient` fires `on_request` (folded, may edit the request) + `on_response`
  (observe); `audit.evaluate` gains `register_rules` + `on_candidate`; `Oracle` gains
  `register_oracle` (the only plugin path to a finding-writer) + `on_finding`. `plugins`
  threads through `run_pipeline`/`run_auto`, which records the active set on the run;
  `fuzzlab auto --plugins` discovers entry-point plugins. The oracle/advisory split holds
  at the boundary (observation returns ignored). +7 tests (367 passed / 4 skipped).
  Change-control: CC-PLUG-0003.
- Phase 10 (T10.1): built the **plugin system** (`fuzzlab/plugins/`, D6). A `HookRegistry`
  with the seven FR-PLUG-2 hooks (mutation `on_request`; observation
  `on_response`/`on_candidate`/`on_finding`; registration `register_rules`/
  `register_payload_source`/`register_oracle`), per-plugin priority ordering, and
  contain-log-**disable** isolation (a failing plugin never aborts a run). Entry-point
  discovery via `importlib.metadata` (injectable for tests); `PluginManager` is the
  pipeline-facing surface and records the active set to migration 10's `run_plugin`
  (head → 10). The oracle/advisory split holds through plugins — observation returns are
  ignored, so only a `register_oracle` plugin reaches the finding-writer. **Zero plugins
  is a full no-op** (NFR-PLUG-optional). Wrote `docs/PHASE_10_PLAN.md`. +12 tests
  (360 passed / 4 skipped). Change-control: CC-PLUG-0002, CC-CORE-0016.
- Phase 9 (T9.5, D17): added the opt-in **h2→h1 downgrade front-end** to the lab — a
  self-owned desync research target. `lab/downgrade/nginx.conf` accepts HTTP/2 (h2c) and
  proxies HTTP/1.1 to the app (`http2 on;` + `proxy_http_version 1.1;`); a `frontend`
  compose service (nginx) is gated behind the **`desync` profile**, so a plain `up` never
  starts it and the default lab is unchanged (loopback-only, `PFF_DOWNGRADE_PORT`). +7
  tests (config-only, incl. a `docker compose config` profile-gating check; 348 passed /
  4 skipped). Change-control: CC-LAB-0007.
- Phase 9 (T9.2/T9.3): from-scratch **HTTP/2**. `proxy/h2frames.py` (byte-exact frame
  encode/decode, the preface, and a declared-length override = a length-desync primitive),
  `proxy/hpack.py` (minimal HPACK — integer/string primitives, static table, literal reps;
  passes arbitrary header bytes verbatim), and `proxy/h2client.py::H2RawClient` (assembles
  preface→SETTINGS→HEADERS→DATA, and arbitrary/malformed frame sequences via build_raw —
  the desync tool for the self-owned lab). Dependency-light; the parsed `h2` path is
  declared + skip-guarded. HPACK matches the RFC 7541 integer vectors. +13 tests
  (341 passed / 4 skipped). Change-control: CC-PROXY-0009.
- Phase 9 (T9.1): started **protocol depth** with a from-scratch, byte-exact WebSocket
  frame codec (`fuzzlab/proxy/ws.py`) — encode/decode, masking (self-inverse),
  7/16/64-bit lengths, fragmentation reassembly, control frames, and the RFC 6455
  handshake (`accept_key` matches the spec vector) reusing the HTTP/1.1 machinery. The
  proxy history now tags each flow's `protocol` (migration 9; `FlowRecord.protocol`
  defaults to `http/1.1`). Wrote `docs/PHASE_9_PLAN.md`; the raw path is dependency-light
  (stdlib), `wsproto` declared+skip-guarded for the parsed path. +11 tests
  (328 passed / 4 skipped). Change-control: CC-PROXY-0008, CC-CORE-0015.
- Phase 8 (T8.5/T8.6): variant write-back + gated LLM scaffold — completes the mutation
  engine's offline stack. `mutation/catalog.py` records accepted variants' provenance to
  the `payload_variant` table and enforces the **destructive gate** (`is_destructive`):
  destructive-looking variants are refused (never persisted or sent) unless
  `allow_destructive` is explicitly set (default off). `mutation/llm.py::LlmExpander` is
  the FR-MUT-5 scaffold — default off, never calls an external service, quarantines
  everything for human review. +7 tests (317 passed / 4 skipped). Change-control:
  CC-MUT-0005. Remaining: the on-host T8.7 exit (bypass the live WAF + reach new code).
- Phase 8 (T8.4): bandit-scheduled, coverage-guided mutation search
  (`mutation/search.py::MutationSearch`). Operators are chosen with the reused
  ThompsonBandit (reward = evasion + coverage novelty, zero for any meaning-changing
  variant), the search hill-climbs, reads coverage through an injected seam (fake offline,
  grey-box live), and is budget-bounded + reproducible under a fixed seed. +7 tests
  (310 passed / 4 skipped). Change-control: CC-MUT-0004.
- Phase 8 (T8.2/T8.3): context-typed XSS + filter learning. `mutation/xss.py` generates
  XSS candidates keyed on the auditor's sink context and drops ones the filter blocks
  (keeping working break-outs like `<svg onfocus=…>`); `mutation/filtermodel.py` mirrors
  the lab WAF from the shared `waf-rules.json` (block/sanitize/log) as the offline seam;
  `mutation/learn.py::FilterLearner` observes what the filter blocks/strips and does a
  bounded search for a semantics-preserving operator chain the filter doesn't catch
  (`learn_bypass`). Offline; the same learner runs live via canary round-trips later.
  +14 tests (303 passed / 4 skipped). Change-control: CC-MUT-0003.
- Phase 8 (T8.1): started the **mutation engine** (`fuzzlab/mutation/`).
  `operators.py` — typed, **semantics-preserving** operators (url-encode, whitespace
  alternates, SQL inline comments, case-toggle, and vetted-equivalent SQL rewrites),
  deterministic, class-scoped, composable via `apply_chain`. `semantics.py` — a validator
  that refutes meaning-changing mutations via canonicalization, with an `sqlglot`
  AST-equivalence path (skip-guarded where absent); vetted tautology swaps are trusted by
  provenance. Migration 8 adds the `payload_variant` provenance table (head → 8). Declared
  `sqlglot` and the previously-missing `h11` in `pyproject.toml` (PA-0005). Wrote
  `docs/PHASE_8_PLAN.md`. +11 tests, 1 skipped for absent sqlglot (289 passed / 4 skipped).
  Change-control: CC-MUT-0002, CC-CORE-0014.
- Lab (D16, Phase 8 prerequisite): added a **configurable lab WAF** — a deliberately
  naive request prefilter (`puppy-fort-factory/includes/waf.php` + `config/waf-rules.json`)
  wired globally via PHP `auto_prepend_file` (`web.Dockerfile`), with `PFF_WAF`/
  `PFF_WAF_MODE` env in `compose.yaml`/`.env.example`. Modes block/sanitize/log; signatures
  are bypassable on purpose (the mutation engine's target). **Default OFF** — a no-op
  unless enabled, so the app and all ground-truth labels are unchanged. +5 tests
  (PHP-CLI driven, skip without `php`; 278 passed / 3 skipped). Change-control: CC-LAB-0006.
- Phase 7 (T7.3): added **active learning** (`ml/active.py`): `uncertainty_sampling`
  (candidates nearest the 0.5 boundary, reusing the ranker's `rank_uncertainty`) and
  `query_by_committee` over a bootstrap `Committee` of rankers (highest score variance),
  with `propose_queries(store, run_id, budget, method)` returning the top-budget
  candidate ids to confirm next. Advisory only — it proposes what to confirm; the oracle
  alone confirms. +7 tests (273 passed / 3 skipped). Change-control: CC-ML-0007.
- Phase 7 (T7.2): implemented the **pointwise candidate ranker**. `ml/ranker.py::Ranker`
  augments the structural features with char n-gram TF-IDF and fits a logistic pointwise
  scorer with per-candidate explanations; `ml/rank_train.py::train_and_rank` runs OOF
  GroupKFold, reports NDCG@k/Precision@k vs a random-order baseline, writes advisory
  `candidate.rank_score`/`rank_uncertainty` (migration 7 — head → 7), persists a model +
  metrics, and falls back on thin data. Wired as `fuzzlab auto --rank`. Advisory-only
  (writes no findings); rank columns are separate from the Phase-5 `candidate.score`.
  +7 tests (266 passed / 3 skipped). Change-control: CC-ML-0006, CC-CORE-0013.
- Phase 7 (T7.1): started the **candidate ranker** (ML component A.2).
  `fuzzlab/ml/ranking.py` adds per-page ranking metrics (`ndcg_at_k`, `precision_at_k`,
  and grouped means over pages with a positive; ties break to input order so a constant
  scorer can't win); `fuzzlab/ml/text_features.py::CharNgramVectorizer` is a bounded,
  deterministic, L2-normalized pure-Python char n-gram TF-IDF with `candidate_text`
  (param/path/category/method). Wrote `docs/PHASE_7_PLAN.md`. Advisory-only; no store
  change yet. +11 tests (259 passed / 3 skipped). Change-control: CC-ML-0005.
- Phase 6 (T6.6): tied the proxy together. `server.py::ProxyEngine` is the sans-I/O
  flow pipeline (scope → match-and-replace → interception → byte-exact forward →
  history; out-of-scope traffic bypasses untouched/unrecorded); `parse_connect` +
  `target_from_request` handle CONNECT and rewrite absolute-form to origin-form;
  `AsyncProxyServer` is the asyncio socket layer (plain-HTTP path tested offline over
  loopback); `ca.py::LocalCA` is the local CA with a per-host leaf-cert cache behind an
  injectable minter (real X.509 minting is lazy `cryptography`). The **live** CONNECT +
  TLS serving and browser trust are the on-host last mile. This completes the
  offline-buildable proxy stack. +12 tests, 1 skipped for broken sandbox crypto (248
  passed / 3 skipped). Change-control: CC-PROXY-0007.
- Phase 6 (T6.4/T6.5): added the proxy's interactive tooling and the manual-login
  escape hatch. `intercept.py::Interceptor` models interception as an awaited
  `asyncio.Future` (hold → edit → release/drop; off = transparent pass-through);
  `repeater.py::Repeater` persists tabs to `repeater_tab` and replays byte-exact
  requests through an injected sender seam (optionally recording to history);
  `session_capture.py::SessionCapture` captures the session a human establishes with a
  **manual browser login** and `SessionManager.adopt` (new, FR-SESS-11) adopts it —
  the escape hatch for logins detection can't parse (MFA/CAPTCHA/multi-step/SPA), with
  secrets kept in memory only. +14 tests (237 passed / 2 skipped). Change-control:
  CC-PROXY-0005, CC-PROXY-0006, CC-SESS-0007.
- Phase 6 (T6.3): the proxy now records **flow history**. Migration 6 extends `flow`
  with `host`/`in_scope`/byte-exact raw request+response bytes (content-addressed via
  `body`), adds a `flow_fts` FTS5 index and a `repeater_tab` table (head → 6).
  `fuzzlab/proxy/history.py::HistoryWriter` batches writes into one transaction
  (non-blocking data path), content-addresses raw bytes + bodies, indexes head text for
  search, and **redacts secrets on write** (`fuzzlab/proxy/redact.py`) so credentials
  never hit the store or FTS index — while the wire path stays byte-exact. +7 tests
  (224 passed / 2 skipped). Change-control: CC-PROXY-0004, CC-CORE-0012.
- Phase 6 (T6.1/T6.2): started the **intercepting proxy** (`fuzzlab/proxy/`) with the
  offline-testable dual-path core (D4). `RawMessage` is a **byte-exact** container that
  round-trips received bytes and edits by byte surgery (untouched lines stay verbatim);
  `parser.py` is the `h11` parsed path; `scope.py` is a default-deny scope engine;
  `matchreplace.py` applies ordered byte-level rewrites. Proves the exit in miniature:
  a hand-edited duplicate/conflicting `Content-Length` is forwarded byte-for-byte on
  the raw path while the parsed path rejects it. Wrote `docs/PHASE_6_PLAN.md`. +21
  tests (217 passed / 2 skipped). Change-control: CC-PROXY-0003.
- Docs: refreshed `docs/ARCHITECTURE.md` to reflect the true build status — `core/`,
  the session manager, the fuzzing harness + oracle (M1–M7, M9), the bandit scheduler,
  the detection classifier (logistic + GBT + conformal, advisory), and the web control
  panel are marked **built**; grey-box (Phase 3) is **partial** (offline consumer layer
  built, live sources on-host); the intercepting proxy (Phase 6) is next. Rewrote the
  build-status snapshot (suite: 196 passed / 2 skipped) and per-subcomponent statuses.
- Phase 5 (T5.4): added a **gradient-boosted-trees** detection model
  (`fuzzlab/ml/gbt.py`) — a pure-Python logistic-loss GBT over shallow weighted
  regression trees (class-balanced, deterministic, no numpy/sklearn), behind the same
  `fit`/`predict_proba` interface. `train_and_score(model_kind="logistic"|"gbt"|"auto")`;
  `auto` out-of-fold-selects the better of logistic/GBT and deploys the winner
  (`fuzzlab auto --score` uses it). A test shows GBT beats logistic and both baselines on
  a non-linear boundary. Still advisory (scores, never labels). +4 tests (196 passed /
  2 skipped). Change-control: CC-ML-0004.
- Phase 5 (T5.2 + T5.3): the detection ML now trains on the store. `build_dataset`
  assembles examples from candidates (label = a matching oracle finding), grouped by
  endpoint, with a versioned feature vector; `train_and_score` runs honest out-of-fold
  GroupKFold (logistic vs prevalence + sigma baselines), calibrates a conformal gate,
  writes **advisory** `candidate.score` (never labels), persists a `model` row + the
  OOF metrics, and falls back to the prevalence baseline on thin data. Wired as
  `fuzzlab auto --score`; the web panel surfaces the top scored candidates with their
  flag/abstain/drop decision. +4 tests (192 passed / 2 skipped). Change-control:
  CC-ML-0003, CC-UI-0008.
- Phase 5 groundwork (T5.1): added `fuzzlab/ml/` — a dependency-light (pure-Python)
  detection-classifier + honest-evaluation core, strictly **advisory** (scores/triage,
  never `finding` labels). `metrics` (`pr_auc`, leakage-free `group_kfold`), `baselines`
  (prevalence, mean+kσ), `logistic` (standardized/L2/class-balanced), and `conformal`
  (flag/abstain/drop at a target error rate). A test proves the exit in miniature: the
  model beats **both** baselines on held-out GroupKFold PR-AUC and the conformal gate's
  error rates are bounded. Wrote `docs/PHASE_5_PLAN.md`; roadmap points to it.
  Store-training + persistence + optional GBT remain. +5 tests (188 passed / 2 skipped).
  Change-control: CC-ML-0002.
- Phase 4 (T4.4 + T4.5): **cost-normalized selection** and **hierarchical backoff** for
  the bandit. Each observation records a cost (the oracle passes the mechanism's probe
  count); with `cost_normalized`, ordering divides sampled reward by mean cost so a cheap
  informative mechanism beats an expensive one of equal reward (costs persist via
  migration 5). With `backoff`, a fresh (context, arm) is seeded from the first coarser
  context that has data (`context_parents`), so cold buckets borrow strength. Both are
  enabled on `fuzzlab auto --bandit`; defaults off elsewhere. +5 tests (183 passed / 2
  skipped). Change-control: CC-SCHED-0004, CC-CORE-0011.
- Phase 4 (T4.2 + T4.3): context buckets, priors, and the bandit wired into the confirm
  loop. Added `context_for` (bucket = `category:sink|location`), `arm_priors` (cost/
  reliability warm starts for oracle mechanisms), and a `references/`-derived
  `catalog_families`/`catalog_priors` reader (for the future payload-family bandit).
  `Oracle.confirm` now orders its applicable mechanisms via an optional scheduler and
  updates it per outcome, so the productive mechanism is front-loaded and its
  confirmation skips the expensive probes; threaded through `run_pipeline`/`run_auto`
  and `fuzzlab auto --bandit` (posteriors load/save around the run). A test shows a
  trained bandit reaches the confirming mechanism with fewer probes than a fresh one.
  Default (no scheduler) unchanged. +10 tests (179 passed / 2 skipped). Change-control:
  CC-SCHED-0003, CC-FUZZ-0015.
- Phase 4 groundwork: added `fuzzlab/scheduler/` — a `ThompsonBandit` (Beta-Bernoulli
  Thompson sampling per (context, arm), catalog priors, posteriors persisted in the
  reserved `bandit_posteriors` table) and a `UniformScheduler` control. Consumes the
  Phase 3 shaped reward; the RNG is injected so the method is stochastic but tests are
  deterministic — incl. a beat-uniform simulation (the bandit finds the paying arm and
  beats the control on hits). Wrote `docs/PHASE_4_PLAN.md`; roadmap points to it.
  Loop-wiring + cost-normalization + backoff + the on-lab exit remain. +7 tests (169
  passed / 2 skipped). Change-control: CC-SCHED-0002.
- Stored-XSS auto-wiring: `auto` now emits the stored-XSS observe point from the
  ground-truth *cases* (the enumerated points file lacks `source_url`), carrying the
  store endpoint via `InjectionPoint.store_url`/`store_param` (new) into the candidate;
  `StoredXssStrategy` plants at the store endpoint and observes the render page. With
  `--browser`, `profile.php` stored XSS (via `edit_profile.php`) is confirmed as
  `xss-stored` — closing the last DOM/stored detection gap. +2 tests (162 passed / 2
  skipped). Change-control: CC-FUZZ-0014, CC-AUD-0013.
- Web control panel (D11): built out `fuzzlab web` into a real dashboard. Added
  `fuzzlab/web/results.py` (store-backed `list_runs`/`run_detail`) and expanded the
  app with a **runs table**, **run-detail** views (`/runs/{id}` HTML + `/api/runs[/{id}]`)
  showing the score (TP/FP/FN/TN), target fingerprint, dataset counts (findings,
  negatives, candidates, attempts, pages), the findings table, and run metrics. Manual
  mode surfaces the selectable categories (D14). The panel is **read-only** over the
  store (never creates it, never sends traffic — no-auto-run and loopback-only
  preserved). +6 tests (160 passed / 2 skipped). Change-control: CC-UI-0007.
- Oracle vectors (M6): **browser execution for stored + DOM XSS**. Added an injected
  `BrowserExecutor` seam (`fuzzlab/oracle/browser.py`) with a `FakeBrowserExecutor` for
  offline tests and a live `PlaywrightBrowserExecutor` (`fuzzlab/tools/browserexec.py`,
  on-host). New `DomXssStrategy`/`StoredXssStrategy` confirm only when a tokened payload
  actually *fires* in the browser (execution, not reflection; fail-closed). Strategies
  are now scoped by `Candidate.category`, so the `xss` category fans out to reflected +
  DOM + stored. Threaded the browser through `Oracle`/`run_pipeline`/`run_auto` and
  `fuzzlab auto --browser`; `R-XSS-REFLECT` also nominates on `fragment`. With
  `--browser`, `auto` confirms `reviews.php#author` and `feedback.php?ref`; without it
  nothing changes. Stored-XSS auto-wiring (source_url) is a follow-up. +9 tests (154
  passed / 2 skipped). Change-control: CC-FUZZ-0013, CC-AUD-0012.
- Oracle vectors: added four more deterministic confirmers — **open redirect** (M9
  redirect-target-control), **SSTI** (M4 evaluation marker), **path traversal/LFI** (M7
  `/etc/passwd` content marker), and **command injection** (M1 differential timing) —
  taking the oracle from 2 classes to 6. Each is a fail-closed `ConfirmationStrategy`
  scoped to its vuln_class; the rising-delay timing logic is now shared by SQLi and
  command injection. Categories are scoped by the run plan (D14), so these cost nothing
  on the SQLi/XSS lab benchmark and run only when selected or present in a target's
  ground truth. `R-SSTI` now nominates on location (like XSS). +10 tests (145 passed /
  2 skipped). Change-control: CC-FUZZ-0012, CC-AUD-0011.
- Phase 2 build: **POST-body injection**. The oracle can now test POST body params, not
  just GET query — a backward-compatible `_send` helper threads `method`/`location`
  through, and `RequestsProbeSender`/`SeamProbeSender` issue a POST with a form-encoded
  body. The pipeline builds POST candidates from the evaluation evidence (now carrying
  method/location), and `auto`'s ground-truth benchmark audits the 16 POST points too
  (only client-only/DOM points remain, pending M6). Unlocks `login.php` auth-bypass
  SQLi and turns the POST controls into real negatives. POST probing is state-changing
  — reset the lab between runs. Change-control: CC-FUZZ-0011, CC-AUD-0010. Suite 135
  passed / 2 skipped.
- Bug fix (BUG-0006): automatic mode never nominated XSS — `R-XSS-REFLECT` required
  `sink_context`, a post-detection label the pipeline's discovery never sets, so no XSS
  candidate reached the oracle (the `test_pipeline` fixture masked it by hand-setting
  the label). Changed the rule to nominate on location (query/body); the oracle's M5
  types the context itself and confirms (fail-closed → no FP on escaped params).
  Preventive rule PA-0006. Change-control: CC-AUD-0009.
- Phase 2 build (T2.8): `fuzzlab auto` now runs a real **detection benchmark** — with
  `--ground-truth` it audits the enumerated contract points (not just crawl-discovered
  ones), decoupling detection from crawl coverage, and lists the points it can't yet
  test (POST-body injection, stored/DOM XSS needing M6) instead of silently missing
  them. `--points auto|crawl|ground-truth` selects the source. `run_pipeline` now
  counts oracle-rejected candidates as negatives too. Change-control: CC-FUZZ-0010.
- Phase 2 build (T2.8 live wiring): added **`fuzzlab auto`** — the automatic-mode
  entry point (`fuzzlab/harness/auto.py` + `auto_cli.py`). It builds injection points
  from a crawl consolidated into the store, resolves the run plan (D14 categories from
  ground truth + scored, or D15 fail-safe), wraps the real probe sender in a request
  counter, and runs `run_pipeline` — writing the `target` fingerprint, `evaluation`
  negatives, and oracle `finding` rows, and scoring TP/FP vs ground truth. Requires
  `--authorized`; runs authenticated with `--identity`. This is the runnable automatic
  path the manual tool chain lacked. +4 tests (130 passed / 2 skipped). Runbook Part D
  updated with the command; on-host step is the run + fewer-requests measurement.
  Change-control: CC-FUZZ-0009.
- Bug fix (BUG-0005): the headless encrypted-credential backend used `keyrings.alt`'s
  `EncryptedKeyring`, which needs PyCrypto/pycryptodome (undeclared, uninstalled) — so
  `fuzzlab session set-credential` crashed with `No module named 'Crypto'` on a fresh
  host, blocking every authenticated run. Reimplemented it on `cryptography` (Fernet +
  PBKDF2, `0600`, atomic, loud on wrong passphrase), declared `cryptography` as a
  dependency, and added real round-trip tests (skippable when the native lib is
  broken). The store's fake-backed tests never exercised the real path — preventive
  rule PA-0005. Change-control: CC-CORE-0010. Suite 126 passed / 2 skipped.
- Lab tooling: `labctl.sh` now probes for a *working* Compose provider
  (`docker compose` / `podman compose` / `docker-compose` / `podman-compose`) instead
  of assuming a `docker`/`podman` CLI implies one, and prints an install hint if none
  is found — fixes a "looking up compose provider failed" dump on a Fedora host with
  podman-docker but no compose package. Documented the prerequisite in the lab README
  and on-host runbook. Change-control: CC-LAB-0005.
- Docs: added `docs/ON_HOST_RUNBOOK.md` — step-by-step for running the toolkit on a
  host with a container daemon: bring up the lab and verify the DB fix, install the
  toolkit, Phase 1 authenticated per-identity crawl→audit→fuzz (+ two-lab), Phase 2
  automatic run + request-reduction measurement, and the Phase 3 grey-box live wiring.
  Delivers the parked Phase 1 runbook TODO; linked from `ON_HOST_TASKS.md`.
- Bug fix (BUG-0004): the lab app's `config.php` defaulted the DB user to `root`
  (empty password), which modern MariaDB authenticates over the unix socket and
  refuses over TCP — so any run without the PFF_DB_* env failed with "Access denied
  for user 'root'". Defaulted to the dedicated least-privilege `pff` user instead
  (matching `lab/.env.example`/compose); updated the app README manual setup to
  create `pff` and stop using root, and aligned the `schema.sql` import note to
  `sudo mysql`. Preventive rule PA-0004. Change-control: CC-LAB-0004.
- Phase 3 build (offline scaffolding): added `fuzzlab/greybox/` — the grey-box
  **consumer** layer behind injected-source seams, fully testable without a lab:
  `CoverageSource`/frontier + `app_lines` filtering, `DbFaultSource`, a multi-tier
  `shaped_reward` (screening / coverage-novelty / db_fault), a `LabControl` reset
  seam, the pure M10 confirmation decision, and `record_attempt_signals` filling the
  schema's already-reserved `attempt.coverage`/`attempt.db_fault`. +17 tests
  (125/125 green), including the "new code scores higher" exit property end-to-end.
  Remaining Phase 3 work is the live pcov/DB-fault/reset sources + M10 oracle wiring
  + exit measurement (on-host, `docs/ON_HOST_TASKS.md`). Change-control: CC-CORE-0009.
- Docs: added `docs/PHASE_3_PLAN.md` — the Phase 3 (grey-box instrumentation) plan:
  per-request pcov line coverage (app-filtered), a DB-fault signal, deterministic
  lab reset between iterations, coverage-novelty folded into `attempt.reward`, and
  the grey-box M10 mechanism into the oracle — all behind injected-source seams
  (offline-testable) with live capture on the host. Fills the schema's reserved
  `attempt.coverage`/`attempt.db_fault`; no ML this phase. Roadmap points to it.
- Docs: added `docs/ON_HOST_TASKS.md` — one place tracking the deferred **on-host**
  work that needs a real lab/browser/container daemon (Phase 1 live two-lab run +
  runbook; Phase 2 T2.8 live crawler/auditor wiring + request-reduction
  measurement). Phase 1/2 plans point to it — so the last-mile items are not lost.
- Phase 2 build (T2.8): **automatic-mode pipeline wired end-to-end** (library
  composition). Added `fuzzlab/harness/pipeline.py::run_pipeline` — one entry point
  that runs an automatic run: dedup by template cluster (T2.6) → fingerprint the
  target and record the `target` row (T2.5) → evaluate the rules engine scoped to the
  run's categories, logging negatives (T2.3/D14/D15) → confirm each candidate with the
  deterministic oracle (sole finding-writer) → score against ground truth only when
  the plan is scored (D15) → record request-efficiency metrics. Fully testable with an
  injected sender; the live crawler/auditor browser-fetch wiring is the remaining
  on-host last mile. +3 tests (108/108 green). Change-control: CC-FUZZ-0008.
- Bug fix (BUG-0003): the oracle stored `finding` URLs verbatim (full URLs) while
  ground truth and every other stored URL use **path form**, so a scored pipeline run
  counted every true finding as a false alarm (`tp=0, fp=3`). Centralized URL
  normalization in `fuzzlab/core/urls.py::to_path` (the single home of the convention)
  and call it at every finding writer; removed `store_adapter`'s duplicate helper.
  Preventive rule PA-0003. Change-control: CC-CORE-0008.
- Phase 2 build (T2.9/T2.10): **category selection + no-ground-truth fail-safe**
  decision logic. `core/runmode.py` `resolve_run` implements D14 (automatic against
  our lab auto-derives categories from ground truth and is scored; manual selects,
  defaulting to all) and D15 (automatic against a no-ground-truth target requires an
  explicit selection or fails loudly, and is unscored); it normalizes ground-truth
  vuln classes to categories and fails closed on unknown categories/modes.
  `audit.known_categories()` supplies the selectable set. +7 tests (105/105 green).
  Wiring into the launcher/harness rides with T2.8. Change-control: CC-CORE-0007,
  CC-AUD-0008.
- Phase 2 build (T2.3): **rules-as-data + full evaluation logging**. Added
  `fuzzlab/audit/` — an editable JSON rule set with a declarative `when` predicate,
  a loader, and an engine that records **every** rule evaluation (fired and
  not-fired → negatives) in a new `evaluation` table (migration 4), emitting
  candidates for fired ones; a `categories` filter is the D14/T2.9 hook. This gives
  the trainable-dataset-with-negatives half of the Phase 2 exit. Resolved the
  negatives to-confirm toward a dedicated `evaluation` table. +4 tests (98/98
  green). Change-control: CC-CORE-0006, CC-AUD-0007.
- Phase 2 build (T2.5/T2.6/T2.7 algorithms): added the fewer-requests building
  blocks as pure, tested `core/` modules — `fingerprint.py` (server/framework/DBMS/
  WAF from headers/cookies/errors), `dedup.py` (DOM-skeleton MinHash +
  `TemplateClusterer` so near-duplicate pages are audited once), and `hybrid.py`
  (`needs_browser` — static-first, browser-on-demand). +10 tests (94/94 green).
  Loop-wiring into the crawler/auditor and the live request-reduction measurement
  ride with T2.8. Change-control: CC-CRAWL-0005, CC-AUD-0006.
- Phase 2 build (T2.1 wiring): the **oracle is now the sole finding-writer**. Added
  `fuzzlab/tools/probesender.py` (authenticated + standalone probe senders adapting
  tool HTTP to the oracle's `Sender`); the fuzzer's `--store` path confirms its
  target via the oracle, which writes the `finding`. `store_adapter.import_fuzz_csv`
  writes attempts only — the provisional timing-only finding path is removed. Added
  an oracle→store→harness end-to-end test (findings scored; confidence is the
  mechanism, not `timing-only`). Suite 84/84 green. Change-control: CC-FUZZ-0007.
- Phase 2 build (T2.1/T2.2/T2.4): implemented the **deterministic oracle** —
  `fuzzlab/oracle/`: a class-pluggable `Oracle` + `ConfirmationStrategy` registry
  (sole finding-writer, fail-closed) with the current lab's mechanisms — M1
  differential timing (rising-delay on median/MAD baselines), M2 error signature,
  M3 boolean/response differential (SQLi), and M5 reflected-canary-in-context
  (reflected XSS); plus median/MAD robust baselines (T2.2) and sink-context typing
  (T2.4). Senders are injected, so it is unit-tested without a network; +10 tests
  (81/81 green), each mechanism with a fail-closed case. Next: route the
  fuzzer/harness through the oracle to replace the provisional timing-only findings.
  Change-control: CC-FUZZ-0006.
- Planning: added a **no-ground-truth fail-safe** for automatic runs (D15) — an
  automatic test against a validation lab / target whose vulnerabilities we don't
  know must not auto-select or test everything: it requires an explicit category
  selection, fails loudly if none is given, runs unscored (findings but no
  TP/FP/FN), and keeps all safety gates on (destructive off, scope-enforced,
  authorized). Recorded as D15 + a cross-cutting safety principle in
  `DECISIONS_AND_ROADMAP.md` and `ARCHITECTURE.md`, the UI spec (FR-UI-nogt), the
  oracle doc, and `PHASE_2_PLAN.md` (T2.10). Change-control: CC-UI-0006.
- Planning: added **injection-category selection by run mode** (D14) — automatic
  runs (against our lab) auto-select the categories from the lab's ground truth;
  manual runs let the user select which vulnerabilities/categories to test (launcher
  selector + a `--categories` flag). The selection scopes the auditor's rules,
  payload sources, and which oracle strategies run. Recorded in
  `DECISIONS_AND_ROADMAP.md` (D14), `architecture/oracle-confirmation.md`, the UI
  spec (FR-UI-categories), and `PHASE_2_PLAN.md` (T2.9). Change-control: CC-UI-0005.
- Planning: scoped the deterministic oracle as a **class-pluggable confirmer across
  attack vectors** (not time-based only), per direction to expand coverage. Reviewed
  the `references/` catalogs (63 categories) and wrote a secondary architecture doc
  `docs/architecture/oracle-confirmation.md` — a small set of confirmation
  mechanisms (M1–M10) and the full injection-class → mechanism mapping, sequenced by
  tier (black-box → browser → out-of-band → grey-box), with non-injection
  categories marked out of scope for the oracle. Updated the FUZZ spec (FR-FUZZ-3/4/5),
  `ARCHITECTURE.md` #7 + the splitting-rule index (first secondary doc), and
  `PHASE_2_PLAN.md` (T2.1 + exit criterion). Change-control: CC-FUZZ-0005.
- Planning: added `docs/PHASE_2_PLAN.md` — the deterministic-hardening (no-ML) task
  breakdown (T2.1–T2.8): a standalone deterministic oracle (differential timing +
  error signatures) as the sole finding-writer, median/MAD baselines, rules-as-data
  with full evaluation logging (negatives), canary reflection + sink-context typing,
  fingerprint-before-fuzz, template-cluster (MinHash) dedup, hybrid crawl, and a
  request-efficiency exit measurement. Referenced from the roadmap.
- Phase 1 build (T1.7): **non-secret session-state persistence**. Added migration 3
  (`session_state` table) + Store methods; the session manager persists non-secret
  metadata (host/identity/kind/validity/endpoints/token-exp) on login and logout,
  resumes it in a fresh manager, and the tools pass `--store` so runs persist.
  Secrets are never stored — a resume re-authenticates. +4 tests. Recorded a runbook
  TODO for the live two-lab validation in `PHASE_1_PLAN.md`. Change-control:
  CC-CORE-0005, CC-SESS-0006.
- Bug: BUG-0002 — a harness test still hardcoded the schema head (`== 2`),
  broken by migration 3 (recurrence of BUG-0001's class). Fixed to derive from the
  migration registry; added PA-0002 (sweep the codebase for a bug class when adding
  its preventive action, don't fix only the triggering instance). Suite 71/71 green.
- Phase 1 build (T1.10, part): **authenticated the Playwright/browser path** for
  the crawler and auditor. Added `fuzzlab/tools/browserauth.py`, which shapes a
  session into Playwright cookies / an extra bearer header and applies it to the
  browser context. The crawler gained `--identity` (injects at browser start); the
  auditor's browser path injects too (built via `make_auth`). With this, every tool
  code path (requests + browser) authenticates via the session manager; only the
  live two-lab run remains. +2 tests (67/67 green). Change-control: CC-CRAWL-0004,
  CC-AUD-0005.
- Phase 1 build (T1.10, part): migrated the **requests-based tools onto the auth
  seam** so they authenticate via the session manager. Added
  `fuzzlab/tools/authhttp.py` (build an authenticated `HttpClient` for a target +
  identity). The fuzzer gained `--identity` and a sender abstraction
  (`RequestsSender` standalone / `SeamSender` authenticated, timing-serialized);
  the auditor's static fetch gained `--identity`/`--base-url` and routes through the
  seam. Standalone behavior preserved; +5 tests (65/65 green). Remaining: the
  crawler/Playwright browser path (cookie injection) and the live two-lab run.
  Change-control: CC-FUZZ-0004, CC-AUD-0004.
- Phase 1 build: implemented the **session manager** (detection-only auth,
  per-host credentials) and the **per-host credential store**. `core/credentials.py`
  (T1.1) stores credentials keyed by `(host, identity)` in the OS keyring with an
  encrypted-file headless fallback and a gated lab-only env fallback; JWT `exp` is
  read without a crypto dependency. `fuzzlab/session/` (T1.2–T1.9) detects a host's
  login form (with fresh CSRF carry-through), detects the session credential
  (cookie / JSON-token+JWT / Basic), verifies success differentially, detects
  logout, re-authenticates single-flight, fails loudly on unparseable logins,
  excludes auth endpoints from fuzzing, and is a drop-in `core/` HTTP-seam addon;
  added a `fuzzlab session` CLI. Tests: session package 17, suite 60/60 green.
  Remaining (T1.10): route tool HTTP through the seam + live two-lab validation
  (needs a runnable lab). Change-control: CC-CORE-0004, CC-SESS-0005.
- Planning: recorded a **manual-login session capture** capability (post-Phase 6):
  once the proxy exists, a human logs in through it in a real browser, the proxy
  captures the established session (FR-PROXY-9), and the session manager adopts it
  (FR-SESS-11) — the escape hatch for logins detection can't crack (MFA, CAPTCHA,
  multi-step), still with no per-host config. Reflected in D13, the Phase 6
  roadmap, `ARCHITECTURE.md` (#3, #11), and both component specs. Change-control:
  CC-SESS-0004, CC-PROXY-0002.
- Planning: refined the session manager to **detection-only** auth with
  **per-host credentials** (revised D12/D13, per user direction), superseding the
  profile-first framing. The manager now detects each host's login/session
  mechanism dynamically (login form incl. fresh CSRF carry-through; cookie vs
  JSON-token/JWT vs Basic/Bearer; differential success; dynamic expiry) and passes
  credentials saved per host; there are no hand-written per-host profiles, and an
  unparseable login fails loudly (accepted trade-off for zero per-host config).
  Rewrote FR-SESS-1…10, D12/D13, `ARCHITECTURE.md` #3, and `PHASE_1_PLAN.md`.
  Change-control: CC-SESS-0003 (supersedes the profile/strategy-authoring parts of
  CC-SESS-0002; its credential-store backend resolution stands, now per-host).
- Planning: settled the session manager's **credential store** (D12 — OS keyring
  with an encrypted-file headless/CI fallback and a gated lab-only env fallback)
  and re-architected it for **multi-target auth** (D13 — pluggable `AuthStrategy`
  strategies: form+cookie, JSON+JWT, Basic, header key, scripted; per-target
  profiles as data) so it can log in and hold sessions across the external
  validation labs (D10), not just the Puppy Fort Factory. Expanded the
  session-manager spec (FR-SESS-6/9/10, NFR-portable/extensible), updated
  `ARCHITECTURE.md` (#3 + `core/` credential store) and `docs/PHASE_1_PLAN.md`
  (now T1.1–T1.10), and added the `keyring`/`keyrings.alt`/`pyjwt` dependencies.
  Change-control: CC-SESS-0002.
- Planning: added `docs/PHASE_1_PLAN.md` — the session-manager task breakdown
  (T1.1–T1.8) with acceptance checks, grounded in the lab's actual auth (PHP
  session cookies; no CSRF/JWT). Scope decision recorded: CSRF/JWT built to spec
  and fixture-tested now, live-validated later. Referenced from the roadmap.
- Process: adopted a **bug-investigation** requirement — every bug discovered in
  the code gets a root-cause-analysis document under `docs/bugs/` (description,
  where, what failed, what it was, RCA, corrective action, preventive action), and
  every preventive action is maintained in `docs/PREVENTIVE_ACTIONS.md`, a single
  context-free rule list to follow while working. Added `docs/bugs/README.md`, the
  first investigation `BUG-0001` (schema version hardcoded in tests, fixed in
  `30ea97d`/CC-CORE-0003), and `PREVENTIVE_ACTIONS.md` with PA-0001. Recorded as a
  cross-cutting principle in `docs/DECISIONS_AND_ROADMAP.md`.
- Process: added a **splitting rule** to `docs/ARCHITECTURE.md` — if it grows too
  complex, detailed material moves into secondary architecture documents under
  `docs/architecture/` referenced from the primary map. Recorded as a cross-cutting
  principle too.
- Docs: rewrote the root `README.md` to reflect the `fuzzlab` package layout, the
  CLI, the containerized lab, the launcher, and the lab-only/no-auto-run posture —
  the old README described only the standalone fuzzer.
- Phase 0 build (cont.): migrated the tools onto the unified store (T0.8) via a
  `store_adapter` and an opt-in `--store` flag on each tool. The crawler writes
  `page`/`endpoint`/`parameter`, the auditor writes `candidate`, and the fuzzer
  writes `attempt` rows plus `finding` rows for confirmed timing hits (flagged
  `timing-only` until the Phase 2 oracle). A synthetic end-to-end test shows a full
  run populating all six tables and the harness scoring the consolidated findings.
  Change-control: CC-CRAWL-0003, CC-AUD-0003, CC-FUZZ-0003.
- Phase 0 build (cont.): containerized the target lab (T0.2, D7) under `lab/` —
  `compose.yaml` (PHP/Apache + MariaDB), `web.Dockerfile`, `.env.example`,
  `labctl.sh` (up/down/reset), and a README. Web tier published on loopback only,
  DB not published; app bind-mounted, DB seeded from `schema.sql`. `docker compose
  config` validates; actual bring-up runs in an environment with a container
  daemon. Change-control: CC-LAB-0003.
- Phase 0 build (cont.): added the ground-truth label contract (T0.6) —
  `lab/ground-truth/{labels.json,injection-points.json,expectedresults.csv}` with
  JSON Schemas and a validating loader that cross-checks the files; the integration
  harness (T0.7) — a scorer (TP/FP/TN/FN, precision/recall/F1/MCC) and an
  assert-known-vulns run that reads oracle findings and records `run_metrics`; the
  minimal local web launcher (T0.9, D11) — loopback-only, offering automatic vs
  manual with no auto-run and an authorization gate; a `fuzzlab` CLI entry point;
  and migration 2 (self-describing findings). Tests: 28/28 green.
  Change-control: CC-LAB-0002, CC-CORE-0003, CC-UI-0004.
- Phase 0 build: created the `fuzzlab` Python package with a `core/` shared
  library and implemented the foundations — the SQLite project store with a
  numbered, idempotent migration runner and the core-contract tables (T0.3);
  layered config with a run hash + redaction, structured JSON logging, the request
  budget + per-host timing mutex, and a scope-enforcing session-aware HTTP seam
  (T0.4); and a versioned feature extractor with golden tests (T0.5). Moved the
  existing tools (spider/fetcher/fuzzer/build_sql_db) into `fuzzlab/tools/` so each
  imports `core/` and runs as a package module, with the indicator DB relocated to
  packaged data (T0.1). Added `pyproject.toml`. Foundation test suite: 12/12 green.
- Process: made explicit in `docs/components/README.md` that change-control logs
  are **append-only** — every change adds a new entry, all historical entries are
  kept, and a superseding change references the entry it supersedes rather than
  rewriting it (the living `requirements.md` specs are what get updated in place).
- Planning: decided the primary UI is a **local web application** (control panel +
  dashboard on localhost), not a `textual` TUI (new decision D11) — results and
  output are far easier to review in a browser and it composes with the planned
  Datasette. The no-auto-run launcher now lives on the web page; a plain CLI entry
  point per tool is kept for headless use; the web app binds to loopback only and
  is served separately from the vulnerable target. Reflected in
  `docs/DECISIONS_AND_ROADMAP.md` (D11, Phase 6 UI, deferred list),
  `docs/ARCHITECTURE.md` (component map + component #12), `docs/PHASE_0_PLAN.md`
  (T0.9), and the component #12 spec + change-control log (CC-UI-0003).
- Planning: added a **no-auto-run** requirement — bring-up presents a launcher
  offering automatic vs manual operation and never starts tools against the
  container on its own. Recorded in `docs/PHASE_0_PLAN.md` (Goal, T0.7, new T0.9,
  exit criterion), `docs/DECISIONS_AND_ROADMAP.md` (cross-cutting principle),
  `docs/ARCHITECTURE.md` (integration model, component #12, Security-and-safety),
  and the component #12 spec + change-control log (CC-UI-0002) — to keep the user
  in control of when the tools touch the target.
- Process: made it explicit that **both** logs are updated on every change — this
  high-level CHANGELOG and each affected component's change-control log — noted in
  this file's header and in `docs/components/README.md`.
- Planning: updated `docs/ARCHITECTURE.md` to reflect the settled decisions — a
  standing maintenance rule (keep the doc in sync whenever the architecture
  changes; each component now also has its own spec and change-control log),
  containerization/env-pinning of the lab (D7), and the manifest-driven generator
  (D8) — so the architecture document matches the decisions we made.
- Planning: added `docs/components/` — a requirement specification and a
  per-component change-control log for each of the 13 primary components, plus a
  `README.md` defining the change-control entry format (change, impact, risk +
  mitigation, deliverables with status, effectiveness). The component
  change-control logs are lower-level and per-component; the root CHANGELOG stays
  the high-level project history.
- Planning: added `docs/DECISIONS_AND_ROADMAP.md` (settled design decisions
  D1–D7, cross-cutting principles, and the phased build plan) and
  `docs/ARCHITECTURE.md` (component map, subcomponents, interactions, and
  dependencies) — to lock the project direction before building the next phase
  (lean foundations, then the session manager).
- Planning: committed the two research prompts under `docs/` and stripped their
  human-facing preambles so each `.md` is a raw prompt fed directly to an agent.
- Planning: after reviewing the lab-scaling research, recorded decisions D8–D10
  (manifest-driven lab generator as a track sequenced after the toolkit; a
  machine-readable out-of-band label contract now; the lab serving both detection
  and ML with cell/transform splits and a blind holdout), added env pinning to
  D7, added a parallel Lab track to the roadmap, and updated the ground-truth
  component and evaluation principle in the architecture and roadmap docs.
- Planning: added `docs/PHASE_0_PLAN.md` (foundations task breakdown) and chose a
  containerized lab environment for reproducibility and easy resets.

## 2026-09-20

- Project docs: added `CHANGELOG.md` (this file) and `ERROR_LOG.md` — to keep a
  durable record of why changes were made and how identified errors were fixed,
  so the project's history is legible as it grows.
- Planning: added `docs/ml-tooling-research-prompt.md` — a self-contained prompt
  to drive external research into ML techniques and the proxy/session-manager
  design before building the next phase.

## 2026-09-18

- `build_sql_db.py` / `php_indicators.db`: defined all 28 indicator types that
  the auditor implements (was 7) and added a `reference` column mapping each to a
  `references/` payload folder — to activate 21 rules that were dormant and let
  the audit summary point findings at the right payload catalog (commit `bc096b4`).
- `fetcher.py`: rewrote the auditor into a rule registry of 28 rules covering the
  `references/` taxonomy, parsed each page once via a `PageContext`, deduplicated
  findings with an occurrence count, and added a static-request fallback — to
  broaden coverage, cut duplicate rows, and stay robust when the browser refuses
  a response (commit `dabcf55`).
- `spider.py` / `fetcher.py`: reset the results table by default (with `--resume`
  to keep it), captured fetch/XHR endpoints, added a `source` column, and fixed
  discovery bugs — to make re-runs rebuild the map, reach JSON APIs that are
  never linked, and record how each URL was found (commit `1d18ce6`).
- `fetcher.py`: added an optional headless-browser engine — so the auditor
  inspects the rendered DOM and sees JavaScript-built forms and inputs
  (commit `7727ab8`).
- `spider.py`: added a headless-browser (Playwright) engine plus a `--engine`
  flag and richer storage — so the crawler can discover and parse
  JavaScript-rendered pages, not just static HTML (commit `36951eb`).
- Target app: expanded to 30 pages, 10 JavaScript-rendered — to give the crawler
  and auditor a realistic mix of server-rendered and client-rendered targets, and
  to exercise crawler-evasion handling (commit `8f121a9`).
- Target app: added the first JavaScript-rendered pages — to create content
  invisible to a static-HTML spider as a discovery test (commit `508d291`).
- `deploy.sh`: made the web root the default deploy destination — so the app is
  served at `http://localhost/` instead of a subdirectory (commit `5f87d80`).
- `deploy.sh`: added a deploy script that copies the app into the Apache web root
  with correct ownership/permissions and preserves an existing DB config — to
  make redeploying to the local lab repeatable and safe (commit `566c9f3`).

## 2026-09-17

- `tools/` and `references/`: added the crawler, auditor, indicator-DB builder,
  and payload-catalog taxonomy — to begin the discovery-and-audit pipeline that
  feeds the fuzzer (commit `25e512b`).
- `REFERENCES.md`: recorded the SQL injection and XSS payload catalogs the
  project draws on — to keep source references in one place (commit `40f404c`).
- Target app: added "Ryder's Puppy Fort Factory," a deliberately vulnerable
  PHP/MySQL app with a documented mix of vulnerable and secure pages — to serve
  as a local, authorized test target for the fuzzer (commit `b409603`).
- `blind_sqli_fuzzer.py`: added a time-based blind SQL injection detector and
  labeled-dataset builder — the project's starting tool, hardened from an initial
  draft (see `ERROR_LOG.md` for the fixes applied) (commit `814cdd7`).
