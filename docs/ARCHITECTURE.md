# Architecture Overview

High-level outline of the toolkit's components, their subcomponents, how they
interact, and their dependencies. Living document; keep it in sync with
`docs/DECISIONS_AND_ROADMAP.md`.

**Maintenance rule:** update this document whenever the project architecture
changes — a component added, removed, or split, or its responsibilities,
interfaces, or dependencies changed. Each primary component below also has its own
requirement specification and change-control log under `docs/components/`.

**Splitting rule:** if this document grows too complex as the project builds out,
move detailed material into **secondary architecture documents** under
`docs/architecture/` and reference them from here. This document then stays the
high-level map and index; each secondary document owns the depth for its area
(and is itself kept in sync under the maintenance rule).

Secondary architecture documents:
- `architecture/oracle-confirmation.md` — the class-pluggable oracle: confirmation
  mechanisms and the injection-class → mechanism mapping across the `references/`
  attack-vector catalogs (component #7).

*Last updated: 2026-09-21.*

Status legend: `[built]`, `[partial]`, `[planned]`. "Built" means implemented and
unit-tested offline (suite: 196 passed / 2 skipped); where a component's exit
criterion or validation must run against the live containerized lab, that is called
out inline and tracked in `docs/ON_HOST_TASKS.md`.

**Where the build is (2026-09-21).** Phases 0–2 are built (foundations, session
manager, deterministic wins). Phase 3 (grey-box) has its offline consumer layer
built; its live coverage/DB-fault sources are on-host. Phase 4 (bandit) and Phase 5
(detection classifier) have their learning cores built offline; their
beats-the-control exits run on the lab. Phase 6 (the intercepting proxy) has its full
**offline** stack built — byte-exact dual-path core, scope, match-and-replace, flow
history, repeater, interception, manual-login session capture, the flow engine, and the
local-CA leaf cache — leaving only live CONNECT/TLS socket serving and browser trust
on-host. Phase 7 (candidate ranker + active learning) is built offline — the pointwise
ranker (NDCG@k/Precision@k vs random), uncertainty sampling, and query-by-committee —
with the real-lab held-out exit on-host. Phase 8 (mutation engine) has begun: the lab
WAF (D16) is the filter-evasion target, and the semantics-preserving operator framework
+ validator are built; context-typed XSS, filter learning, and bandit/coverage search
remain. Phase 9 (protocol depth) is well underway — the from-scratch WebSocket codec and the
byte-exact HTTP/2 frame layer + minimal HPACK + raw-frame client are built; the parsed
`wsproto`/`h2` path, live ALPN/socket, and the opt-in h2→h1 desync lab front-end remain.
Phase 10 (polish + generalization) is complete offline — the plugin system (registry +
pipeline wiring), the ECOD anomaly detector, the reproducible evaluation report, and the
multi-target evaluation harness are built; only the live transfer run against a second
target is on-host. That leaves the accumulated on-host exits and the Lab-track manifest
generator as the remaining work.

## Integration model

The **shared SQLite project store is the integration bus** (decision D5). Each
tool runs independently and communicates by reading and writing tables in that
store, not by calling other tools' APIs. Shared concerns live in a `core/`
library that every tool imports (decision D6). The intercepting proxy is an
**optional observer**, never a mandatory pipeline. A deterministic **oracle** is
the only component allowed to write vulnerability labels; machine-learning
components only write scores and uncertainty (the oracle/advisory split). The
target lab runs in a container with pinned PHP/Apache/MySQL/libxml versions (D7),
so labels stay valid across upgrades and runs are reproducible.

**No auto-run:** bringing up the lab never starts tool traffic on its own. A
launcher (see component #12) presents a run-mode choice — **automatic** (the tools
run in sequence against the lab) or **manual** (the tools are made available for
hand-driven use) — and nothing is sent to the target until the user chooses
automatic mode or invokes a tool by hand.

## Component map

```
                     ┌───────────────────────── Diagnostics / UI ─────────────────────────┐
                     │  local web control panel + dashboard · Datasette over store · logs   │
                     └───────────────────────────────▲─────────────────────────────────────┘
                                                     │ reads
   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  ┌───────────┐
   │ crawler  │  │ auditor  │  │ scheduler│  │ fuzzer / │  │ mutation      │  │  proxy    │
   │ (spider) │  │(fetcher) │  │ (bandit) │  │ harness  │  │ engine        │  │(observer) │
   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬────────┘  └────┬──────┘
        │             │             │             │               │                │
        │             │             │        ┌────▼────┐          │                │
        │             │             │        │ oracle  │          │                │
        │             │             │        └────┬────┘          │                │
        └─────────────┴─────────────┴─────────────┼───────────────┴────────────────┘
                                                   │  reads/writes
                        ┌──────────────────────────▼──────────────────────────┐
                        │                     core/ (shared library)            │
                        │  http client · session manager · store (SQLite +      │
                        │  migrations) · features (versioned) · request budget  │
                        │  + concurrency mutex · logging · config · plugins     │
                        └──────────────────────────┬───────────────────────────┘
                                                   │
                                       ┌───────────▼───────────┐
                                       │     project store      │
                                       │  (SQLite; the contract)│
                                       └───────────┬───────────┘
                                                   │ targets / instruments
                        ┌──────────────────────────▼──────────────────────────┐
                        │  Target lab: Puppy Fort Factory (PHP/MySQL/Apache)    │
                        │  + ground-truth manifest  + grey-box instrumentation  │
                        │  (coverage, DB error hook, state snapshot/restore)    │
                        └───────────────────────────────────────────────────────┘

   ML components (classifier, ranker, anomaly detector, active learner) attach as
   plugins on core/ hooks; they read features and write scores/uncertainty only.
```

## Components and subcomponents

Throughout this section, **Depends on (components)** lists other project
components only. Python package dependencies (for example `h11`, `sqlglot`, or
LightGBM) are implementation details, mentioned within the subcomponents and
tracked in the requirements files, not here.

### 1. Target lab and ground truth `[built; generator is the single source (L-P3.3c-CUT done); grey-box offline layer built]`
- **The generated PHP lab** `[built]` (`L-P3.3c-CUT`, replacing the retired hand-built
  "Puppy Fort Factory" app): PHP/Laravel/MySQL/Apache app, generated by
  `fuzzlab.labgen.assemble` from `lab/manifests/*.yaml` via the `php_laravel` emitter;
  ~30 pages, ~10 JavaScript-rendered (Layer B, not reproduced by the generator — see
  D-open-1 below); documented mix of vulnerable and secure pages
  (`lab/VULNERABILITIES.md`, generated). Runs containerized with pinned
  PHP/Apache/MySQL/libxml versions (D7); brought up via `lab/labctl.sh` (probes for a
  working docker/podman compose provider).
- **Ground-truth labels** `[built contract; labels hand-authored]`: a
  machine-readable, out-of-band contract (`labels.json`, `expectedresults.csv`, and a
  separate `injection-points.json`), read from disk by the tools and the harness,
  never served by the target, with opaque case IDs (D9). The loader/consumer is built
  (`fuzzlab/labels/contract.py`) and drives the `fuzzlab auto --ground-truth` scoring.
  A case may additionally carry an optional per-case `stack` (`CC-LAB-0040`) naming its
  stack profile — inline, not a separate analysis file — which is the axis the
  fingerprint-independence gate tests for independence from `vuln_class`.
  Labels are hand-authored; `lab/VULNERABILITIES.md` is now the generated,
  human-facing artifact `fuzzlab.labgen.vuln_map` renders from them (`L-P3.3c-CUT`).
  The lab grows into two tiers (dense "range", realistic "shop") with
  annotated / blind / all-secure build profiles.
- **Lab WAF** `[built; default off]` (D16): a configurable, deliberately naive request
  prefilter, a Laravel middleware in the generated app since `L-P3.3c-CUT`
  (`app/Http/Middleware/FzlWaf.php`, backed by `app/Support/WafFilter.php`;
  ruleset `lab/waf-rules.json`), registered globally in `bootstrap/app.php`. Off by
  default (a no-op unless `PFF_WAF` is enabled), so existing labels stay valid; modes
  `block`/`sanitize`/`log`. It is the **Phase 8 filter-evasion target** the mutation
  engine learns to bypass — realistic but bypassable, not real protection.
- **h2→h1 downgrade front-end** `[built config; default off]` (D17, `lab/downgrade/`): an
  opt-in nginx front-end that terminates HTTP/2 and proxies HTTP/1.1 to the app — the
  **Phase 9 desync research target** for the raw-frame HTTP/2 client. Gated behind the
  `desync` compose profile (a plain `up` never starts it), loopback-only, lab-only.
- **Grey-box instrumentation** `[partial — offline consumer built; live sources on-host]`
  (D7): the consumer layer is built and unit-tested (`fuzzlab/greybox/`): coverage and
  DB-fault readers behind injected seams (`CoverageSource`/`InMemoryCoverageSource`,
  `DbFaultSource`/`InMemoryDbFaultSource`), the shaped multi-tier reward
  (`CoverageFrontier`, `shaped_reward`), the confirm hook, and state-reset call points.
  The **live sources** — Xdebug/pcov line coverage per request, the database error
  hook/query-log reader, and DB snapshot/restore — must run against the container and
  are on-host (`docs/ON_HOST_TASKS.md`).
- **Multi-target evaluation harness** `[built; live transfer on-host]` (Phase 10 T10.5,
  `fuzzlab/harness/multitarget.py`): runs the pipeline against several targets (each a
  base-url + ground-truth contract) and reports per-target + macro transfer metrics with a
  `generalizes` verdict — the generalization evidence. The live run against an external
  validation lab is on-host; the manifest-generated second target plugs in as a
  `TargetSpec`.
- **Manifest-driven generator** `[Phase 0 foundation built; Phase 3 multi-stack under way -- four emitters (php_current, python_fastapi, php_laravel, node_express) built to varying depth, plus a fifth (go_net_http, Phase A only) added by the category-4 second-target pilot; Layer-A real-page parity/coverage closed (CC-LAB-0062), cutover itself pending human sign-off]` (D8, target shape pinned by **D20**/
  `CR-LAB-0001`): the "lab as a compiler" — one manifest plus a safety matrix,
  seed, and env-profile generate the app, labels, docs, and oracle tests, with a
  **binary** verdict derived from `(transform, sink context)` (a partially
  neutralized case is VULNERABLE-but-harder, feeding a `difficulty` tier, not a
  third verdict value). The **existing hand-built PHP app above is migrated
  into the generator** at Phase 3 (not kept as a separate permanent fixture).
  A pattern-provenance corpus (`patterns/`, OSV/GHSA-sourced, informs scenarios
  in original words only — never inlined as code) lives under this component.
  Phase 0's foundation is built (`CC-LAB-0016`): `fuzzlab/labgen/` (manifest
  IR, the pure/versioned/snapshot-tested `verdict()`, sub-seed derivation +
  canonical serialization, the regenerate-and-diff and name-leak build gates)
  plus `lab/schemas/*.schema.json`, `lab/safety_matrix.yaml`, and a
  `lab/patterns/` scaffold (3 example cards, not the full corpus). A real
  covering-array resolver (`fuzzlab/labgen/resolver.py`, over `covertable`
  3.2.0, pairwise/mixed-strength/constrained) is built (`CC-LAB-0018`) and, as
  of Phase 1 (T-LAB2.1, `CC-LAB-0029`), wired into manifest loading: a
  manifest's optional `axis_ranges` block expands into concrete cells
  alongside today's explicit `cells` list, into the same `Cell` IR the
  emitter and verdict engine already consume. The per-stack module-composition
  emitter interface is built (`CC-LAB-0019`): `fuzzlab/labgen/emitter.py` (the
  `Emitter` ABC, `EmittedFiles` forward-compatible with multi-file/routed
  output), a composable `fuzzlab/labgen/modules/` Jinja2-template inventory
  (Addendum C), and the first (`php_current`) emitter — proven end to end for
  one illustrative vulnerable/secure SQLi pair via a real, byte-deterministic,
  `php -l`-checked render, then generalized to a small real sample of four
  actual pages (`product.php`, `blog_post.php`, `login.php`, `profile.php` —
  two vuln classes, three sink-context families — `CC-LAB-0022`), proving
  the module inventory isn't a one-cell special case; the remaining ~26 real
  pages remain a separate, later task. As of Phase 1 (L-P1.2b, `CC-LAB-0040`)
  the inventory also covers the corpus's **harder shapes**: three new
  sink-context families (`sql_identifier`, `sql_join_alias` — injection into a
  column identifier or JOIN alias rather than a literal value — and
  `url_javascript_scheme`, escaping-context-mismatch XSS), four new transform
  ops and eight new module fragments, all additive to `lab/safety_matrix.yaml`
  v1 with `verdict()` unchanged, exercised by
  `lab/manifests/phase1_harder_shapes_sample.yaml` (13 cells) — so the
  corpus is no longer only textbook value-position cells. A mechanical pull/index/scope/rank/cluster tool
  for the pattern-provenance corpus (`fuzzlab/tools/pattern_corpus_sourcing.py`,
  over `github/advisory-database` via git — `CC-LAB-0020`) produces a
  candidate list for human triage; it never authors a card and never writes
  `lab/patterns/cards/` or `provenance.yaml`, so the corpus itself is still
  only the 3 scaffold cards. A second, complementary build gate
  (`fuzzlab/labgen/secret_scanner.py`, `CC-LAB-0024`) wraps the Gitleaks
  binary against the generated output tree, separate from the name-leak
  scanner above — a `.gitleaks.toml` at the repo root allowlists explicitly
  `FAKE`/`EXAMPLE`/`PLACEHOLDER`-marked seeded credentials the generator may
  legitimately emit as vulnerable-code content, while an unmarked real-shaped
  secret still fails the build. A standalone, offline minimal-pair invariant
  checker (`fuzzlab/labgen/minimal_pair.py`, `CC-LAB-0025`, pulled forward from
  Phase 1) asserts a cell's vulnerable/secure twins differ only within their
  declared transform/sink region, emitter-agnostic via the module-composition
  provenance comment any such emitter writes; not yet wired into a build gate.
  A mandatory (once multi-stack, Phase 3) fingerprint-independence gate
  (`fuzzlab/labgen/fingerprint_gate.py`, `CC-LAB-0026`) chi-square-tests
  stack against vuln_class/verdict, schema-independent, so a stack can never
  become a de facto proxy for a class. It **is** now wired into `fuzzlab
  lab-generate --check` as a required step (`CC-LAB-0040`), conditional on the
  loaded manifest's cells actually spanning 2+ distinct `stack_profile` values;
  a single-stack manifest (every sample manifest today) skips it with an
  explicit printed reason, since the check is ill-defined for one stack rather
  than merely unhelpful. Per-case `stack` is also carried in the ground-truth
  `labels.json` contract (optional, inline) so the axis reaches the artifact
  downstream analysis reads, not just the manifest. The **metadata leakage
  gate** (`fuzzlab/labgen/leakage_probe.py`, `CC-LAB-0045`, plan §2.3) is the
  second required statistical `--check` step: a weak logistic model,
  cross-validated with `grouped_cv` (grouped by generating-rule ID), must not
  predict a cell's `vuln_class` from non-payload metadata alone, judged
  per-class against `min(that class's permutation null, its configured
  `PER_CLASS_AUC_THRESHOLDS` line)` — fail-closed, so a configured number can
  only tighten the gate. Every configured threshold currently ships as
  `provisional`, and the gate prints that status per class. Like the
  fingerprint gate it skips with an explicit printed reason when the corpus
  cannot support the measurement (`leakage_probe.insufficiency_reason`), which
  today it does on every sample manifest: a manifest carries only one of the
  seven allowlisted features (`path_depth`), the rest being live-response
  observations no build-time artifact records yet. Read-only corpus-analysis
  tooling (`fuzzlab/labgen/corpus_analysis.py`, `CC-LAB-0041`, plan §2.4) sits
  alongside those gates but is deliberately **not** one: a train/holdout
  split grouped by generating-rule ID (reusing `leakage_probe.grouped_cv`,
  the one shared `StratifiedGroupKFold` construction in the package) so
  near-duplicate cells cannot span a split; a near-duplicate rate over an
  explicit `(vuln_class, sink_context, transform-shape)` signature; and a
  class x transform x verdict diversity **artifact**, written by
  `fuzzlab lab-generate --corpus-report <path>` on a path independent of
  `--check` so it can never fail a build. A stack-agnostic tiered conformance suite
  (`fuzzlab/labgen/conformance/`, `CC-LAB-0027`) any emitter must pass: Tier
  0 (lint + minimal-pair diff) and Tier 3 (whole-lab regeneration) are real,
  fully exercised offline; `tier1.py`/`tier2.py` originally remained
  honestly-labeled `[design]` interfaces. As of `CC-LAB-0060`/`FR-LAB-57`
  (2026-09-22), `tier1.py`'s own public API (`build_tier1_case`/
  `run_tier1_case`/`evaluate_tier1_response`) is no longer design-only for
  every stack: it is run for real, through `LiveBootHarness` below, for
  `php_laravel` (`tests/test_labgen_conformance_tier1.py`'s
  `TestTier1RealLiveBoot`, skip-guarded, `pytest.mark.slow`) — proving a real
  SQLi differential and a real escaped-XSS negative through `tier1.py`'s own
  decision logic, not just a hand-written fake client. As of
  `CC-LAB-0061`/`FR-LAB-56` (2026-09-22), `tier2.py` gained the same
  treatment via a new `LiveBootTier2Oracle`, adding a real control/baseline
  differential on top of Tier 1's bare evidence-marker check (fails closed
  when the control itself can't distinguish vulnerable from not). A stack
  with no real `Tier1Client`/`Tier2Client` yet stays design-only for that
  tier. As of `CC-LAB-0054`/`FR-LAB-52`
  (2026-09-22), the live-boot on-host dependency Tier 1/2 needed is real for
  `php_laravel`: `fuzzlab/labgen/conformance/live_boot.py` assembles a real
  Laravel 13 skeleton (checked in, trimmed from a real `composer
  create-project`) with a manifest's real emitter output, runs a real
  `composer install`, boots a real `php artisan serve` against a seeded
  SQLite DB, and makes real HTTP requests — run via
  `tests/test_labgen_conformance_live_boot.py` (skip-guarded,
  `pytest.mark.slow`, not wired into `--check`), covering the escaped-echo
  form pages and the `product.php` numeric-SQLi vulnerable/secure twin (a
  real, observed payload differential). **Extended (`CC-LAB-0056`/`FR-LAB-54`,
  2026-09-22)** to the auth pages (`login.php`'s real SQLi auth-bypass twin,
  `register.php`'s real `INSERT`), the catalog/JSON-feed pages
  (`products.php`/`api/products.php`, including a real, parsed JSON
  response), and the stored-second-order pair (`edit_profile.php` ->
  `profile.php`, a real write-then-read round trip) — 5 of 6 real-page
  manifest groups live-boot-proven at that point; `search.php` remained
  unpinned pending `L-P3.3c-CUT`. **Resolved and extended
  (`CC-LAB-0058`/`FR-LAB-55`, 2026-09-22)**: `search.php`'s canonical-cell
  decision is made (`LABGEN-PL-RP-0001`, the LIKE-clause SQLi cell; the
  reflected-XSS case `PFF-0003` is a documented exemption instead — a real
  multi-sink page composition was judged out of scope) -- all 6 real-page
  manifest groups are now live-boot-proven. This change also added a real
  **MariaDB-backed** mode (`live_boot.MariaDbServer`, a real local `mariadbd`
  + the real `puppy-fort-factory/sql/schema.sql` imported verbatim), closing
  the gap the SQLite-only proof above always disclosed: every driven group is
  now also proven against the actual database engine `lab/compose.yaml`
  provisions, not only a test-harness substitute
  (`tests/test_labgen_conformance_live_boot_mariadb.py`, skip-guarded on a
  real local MariaDB). This surfaced two real, reported MySQL-vs-SQLite
  differences (a `TrimStrings`/`--`-comment dialect interaction, and a real
  schema/Eloquent-timestamps gap in the G4 write path) — see that test
  module's own docstring and `CC-LAB-0058` for the full detail; neither is
  fixed here (documented future work, out of this additive-only change's
  scope). **Capability-probe fix (`CC-LAB-0068`/`FR-LAB-60`, `BUG-0033`,
  2026-09-22):** `live_boot_available()`'s network-reachability check now
  runs a real, bounded `composer show -a` Packagist round trip through
  composer's own (proxy-aware) HTTP client, instead of a bare
  `socket.create_connection` — the raw-socket version could report
  "available" on a path a real, proxied `composer install` does not take,
  letting a gated test hang instead of pass/skip in an environment whose
  real HTTPS egress requires a configured proxy. Tier 2's real, dialect-correct, container-based oracle confirmation
  remains unbuilt (this MariaDB mode strengthens but does not replace it — it
  proves boot + observable behavior against the real engine, not an
  oracle-grade verdict). **`tier2.py` itself gains a real, synthetic-in-sandbox
  `Tier2Oracle` (`CC-LAB-0061`/`FR-LAB-56`, 2026-09-22, lane T2 of
  `docs/PARALLEL_LANE_BUILD_PLAN.md`)**: `LiveBootTier2Oracle`, built on the
  existing, unmodified `live_boot.LiveBootHarness` (never the real,
  loopback-only lab target, no `--authorized`), adds a real control/baseline
  differential over Tier 1's bare marker check and fails closed
  (`inconclusive`) rather than guessing when the control can't distinguish
  vulnerable from not — proven for real against `product.php`'s numeric-SQLi
  vulnerable/secure twins (a real positive and negative confirmation), plus 7
  offline tests. `tier2.py` is no longer purely `[design]`, but this remains a
  narrower, synthetic-in-sandbox claim than the production-grade, real-target
  oracle T-LAB0.7 describes, which stays
  `fuzzlab.labgen.identifier_sqli_assertion.IdentifierSqliTier2Oracle`'s (and
  any future real-target oracle's) job. A second
  Phase-3 stack emitter (`fuzzlab/labgen/emitters/python_fastapi/`, Tier-A
  depth per `CR-LAB-0001` Addendum C's stack-pacing decision, `CC-LAB-0029`)
  is built: FastAPI + SQLAlchemy + Jinja2, the same three value-context
  shapes `php_current` proves, via its own fully independent
  module-composition system (no cross-import with `php_current`/
  `fuzzlab.labgen.modules`); uses a one-time static discovery scaffold
  (`pkgutil.iter_modules()`/`importlib` over a `routers/` package) instead of
  a `route` accumulator, per Addendum D's FastAPI-specific research, and
  disables `/docs`/`/redoc`/`/openapi.json` in that scaffold (FastAPI serves
  them by default regardless of any debug flag); passes Tier 0/Tier 3 against
  its own sample manifest. A manifest reproducing today's real ~30-page PHP
  app byte-identically (`LAB_PHASE_0_PLAN.md`'s original, literal wording of
  the Phase 0 exit criterion) remains planned in that literal sense — no tool
  in this repo diffs generated source against `puppy-fort-factory/`'s actual
  file bytes, for either `php_current` or `php_laravel`. A **fourth stack
  emitter** (`fuzzlab/labgen/emitters/node_express/`, L-P3.1, Tier-A depth)
  is built: Express + `mysql2`, the same three value-context shapes
  `php_current`/`python_fastapi` prove, via its own fully independent
  module-composition system; a `route`-category accumulator method
  (`render_route_accumulator`, not part of the base `Emitter` ABC) builds
  the shared `app.js` route-registration file, fed by one fragment per
  supported cell sorted by cell ID. A **fifth stack emitter**
  (`fuzzlab/labgen/emitters/go_net_http/`, category 4 second-target pilot's
  `CC-LAB-0090`/`FR-LAB-64`, 2026-09-22) is this project's first Go stack —
  standard-library `net/http` only, Phase A depth (one illustrative
  shape: an HMAC-signature-verified webhook receiver, CWE-347, reusing
  `lab/safety_matrix.yaml`'s existing `webhook_signature_verification`
  family) with a real checked-in skeleton, a real `GoLiveBootHarness`
  (`fuzzlab/labgen/conformance/go_live_boot.py`, no separate
  install-dependencies step since `go build` resolves and compiles in one),
  and Tier 0 (`go vet`/`gofmt -l`)/Tier 3 conformance passing — the Go
  analogue of `ruby_rails`'s own Phase-A dispatch for category 1. Deferred
  to Phase B for this stack: a per-run database (this Phase A's one shape
  is stateless), CWE-918 (SSRF), and the richer Twitch EventSub message-ID/
  timestamp/replay-window checks. **Superseded for the
  Layer-A/cutover purpose by D-open-1** (`docs/LAB_IMPLEMENTATION_PLAN.md`
  §4.3.6.7, decided 2026-09-22): the operative exit bar for closing Phase 0 on
  the 16 `PFF-` real-page cases is functional **parity/coverage**, not a
  literal source-text diff (impossible in any case once the reproduction
  target is a Laravel reimplementation rather than raw PHP) — verified below.
  A **second, Laravel/Eloquent/Blade-idiom PHP emitter**
  (`fuzzlab/labgen/emitters/php_laravel/`, `CC-LAB-0029`, lane L-P3.3a) is now
  built as a **foundation only**: a `StackEnv` (`stack_env.py`) carrying a
  pinned `laravel/framework` version (13.32.0, resolved for real against
  Packagist), a digest-pinned `php:8.3-fpm-alpine` base image, and a
  generated `.env` with `APP_DEBUG=false`/`APP_ENV=production` forced (the
  Laravel-Ignition-debug-page correctness requirement D20 flags); a `route`
  accumulator module (`route_accumulator.py`) for `routes/web.php`, sorted
  by cell ID at render time per Addendum D's determinism rule; and
  `LaravelEmitter`, which lane **L-P3.3b** (`CC-LAB-0044`) has since taken to
  the **full module inventory** — every shape `php_current` supports, ported
  to Laravel/Eloquent/Blade idiom (`DB::select`/query-builder
  `whereRaw()`/`orderByRaw()` for the four SQL shapes; a per-cell **Blade
  view** for the three HTML shapes, making an HTML-sink cell a two-file
  `controller` + `view` cell on this stack), rendered by this emitter's own
  module registries (`emitters/php_laravel/modules.py` + its template tree),
  with nothing imported from or added to `fuzzlab.labgen.modules`. Laravel is
  the one stack the plan assigns full depth, since the Phase-1 hard-shape work
  is directly portable to a second PHP stack. Two cross-cutting contracts fell
  out of that port and now bind any future emitter on a shared checker: a
  stack's module *names* are the project's shared composition vocabulary
  (`fuzzlab.labgen.minimal_pair` classifies composition positions through
  `fuzzlab.labgen.modules`' registries and raises for a name it cannot find),
  and a sink never escapes anything itself (Blade sinks echo raw; the
  `html_entity_escape` transform applies `e()` in the controller). The widened
  `lab/manifests/phase3_php_laravel_sample.yaml` (20 cells) passes
  `fuzzlab lab-generate --check` end to end through the CLI's
  `EMITTER_REGISTRY`, which `php_laravel` is now registered in. Not carried: the `same_file_helper`/`cross_file` pass-through-helper depths
  (still refused, never flattened) -- `stored_second_order` is now carried, see
  below.
  The `puppy-fort-factory/` migration onto this emitter (lane L-P3.3c) landed
  **six page groups (G1-G6) plus a consolidation pass** in one combined
  change: `product.php`/`blog_post.php` (G1, `FR-LAB-44`),
  `products.php`/`api/products.php` and the JSON `view` module category (G2,
  `FR-LAB-45`), `login.php`/`register.php` and session/insert complexity tails
  (G3, `FR-LAB-46`), the stored second-order pair
  `edit_profile.php`->`profile.php` and this emitter's first **write**
  endpoint (`WRITES` module category; G4, `FR-LAB-47` -- `context_depth ==
  "stored_second_order"` is now rendered, `SUPPORTED_CONTEXT_DEPTHS`),
  `contact.php`/`newsletter.php` (G5, `CC-LAB-0050`/`FR-LAB-48`, merged
  earlier), and `search.php` plus the `html_attribute_quoted` shape (G6,
  `FR-LAB-49` -- **deliberately left with no canonical cell**, open for
  `L-P3.3c-CUT`). Because the six sub-lanes built five independent,
  incompatible URL-pinning mechanisms concurrently, a consolidation pass
  (`CC-LAB-0052`/`FR-LAB-50`) replaced all of them with **one**:
  `_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY` page-profile keys (generalizing G3's
  design -- canonical-cell-per-page, a `.php`-suffixed twin-URL convention for
  every other cell of that page, and a `None` canonical for a page whose cell
  choice is still an open policy question) plus one shared `served_url_for()`
  derivation and one `route_accumulator.fragment_for_cell(method=, action=)`
  signature, so every migrated page's real route keeps the app's exact
  `.php`-suffixed URL (T-LAB0.9's additive-only regression gate does not see
  those cases *relocate*) through a single mechanism rather than five.
  Per `D-open-1` (decided 2026-09-22), the cutover does not require
  reproducing the JS-rendered (Layer B) pages in general -- that case remains
  recorded in `lab/ground-truth/migration-exemptions.yaml`
  (`CC-LAB-0053`/`FR-LAB-51`, below). The atomic cutover itself that deletes
  the hand-built directory was unrelated to this consolidation and, at the
  time this consolidation landed, unscheduled pending human sign-off (plan
  §4.3.6.5) — it has since executed for real; see `L-P3.3c-CUT`,
  `CC-LAB-0067`/`FR-LAB-62`, below.

  **The DOM-XSS sink class, built (`L-P3.3c-DOM`, `CC-LAB-0066`/`FR-LAB-61`,
  2026-09-22).** `D-open-2` (decided 2026-09-22) formally put this shape out
  of the G1-G6 cutover's "full coverage" bar as deferred backlog, "to be
  picked up as its own lane whenever prioritized" -- it was then separately
  prioritized and built for real, not as part of `L-P3.3c-CUT`. A genuinely
  new `(vuln_class, sink_context.family)` pair, `("xss-dom",
  "dom_html_sink")`: the tainted value (a URL fragment/query-string
  parameter) is read *and* written entirely client-side and never reaches
  the server, so the new `dom_url_source` module renders no PHP variable
  read at all, and the new `dom_innerhtml_echo` Blade-view sink's `<script>`
  block does the client-side read and write itself, branching on
  `dom_write_prop` (`innerHTML` vulnerable / `textContent` secure, the new
  `dom_text_content` op). `reviews.php` (`PFF-0007`) and `feedback.php`
  (`PFF-0008`) are now real `php_laravel` pages
  (`lab/manifests/phase3_php_laravel_real_pages_dom.yaml`), each with an
  authored secure twin, served at their real `.php` URLs through the same
  unified mechanism as G1-G6, and live-booted for real
  (`fuzzlab.labgen.conformance.live_boot`) -- the one live-boot proof with no
  server round trip to differentiate on, only the served markup/script's
  `innerHTML`/`textContent` shape. `PFF-0007`/`PFF-0008` are **no longer**
  in `lab/ground-truth/migration-exemptions.yaml` (covered, not exempt).

  **The parity/cutover coverage gate** (`CC-LAB-0053`/`FR-LAB-51`,
  `fuzzlab/labgen/cutover_gate.py`, plan §4.3.6.6 point 3) is the precondition
  `L-P3.3c-CUT` needs before it can run, built ahead of and independent from
  the cutover itself: `assert_cutover_coverage()` asserts every `PFF-` case in
  `lab/ground-truth/labels.json` is reproduced by an emitted `php_laravel`
  cell (derived from `LaravelEmitter.supports()` over every manifest, never a
  hand-maintained literal, PA-0001/PA-0027) or named in the machine-readable
  `lab/ground-truth/migration-exemptions.yaml` (`{pff_case, reason}` entries,
  read by the gate itself). It is its own module rather than an addition to
  `regression_gate.py` (which diffs two loaded `GroundTruth` snapshots,
  independent of manifests/emitters by design), mirroring that module's
  `diff_*`/`assert_*` convention instead. `ground_truth_cases_for()` extends
  `php_laravel`'s existing page-profile metadata (`_GROUND_TRUTH_CASE_KEY`/
  `_CANONICAL_CELL_KEY`) with two more keys the coverage question needs:
  `ground_truth_case_by_family` (`search.php`'s one profile spanning
  `PFF-0002`/`PFF-0003`) and `secondary_ground_truth_cases` (`login.php`'s
  boilerplate `PFF-1008` password condition). Currently green: 14 of 16
  `PFF-` cases covered (`PFF-0007`/`PFF-0008` moved from exempted to covered
  once `L-P3.3c-DOM` landed, `CC-LAB-0066`), 2 exempted (`PFF-1002` --
  `track.php` has no sink at all; `PFF-0003` -- `search.php`'s
  simultaneously-true reflected-XSS case, downgraded per `CC-LAB-0058`), 0
  uncovered.

  **Layer A closed (`CC-LAB-0062`, Wave A2, 2026-09-22).** `docs/
  PARALLEL_LANE_BUILD_PLAN.md`'s Wave A2 lane re-ran this gate
  (`tests/test_labgen_cutover_gate.py`, all 16 tests including the two that
  exercise it against the live repo state) and confirmed the (then-)12/4/0
  split plus every `L-P3.3c-G1`..`G6` change-control entry
  (`CC-LAB-0046`..`CC-LAB-0051`) present and marked done — the "Checkable
  gate condition" `docs/PARALLEL_LANE_BUILD_PLAN.md`'s Wave A2 entry names.
  This closed Phase 0's exit criterion **as scoped to Layer A by D-open-1**
  first; the two DOM-XSS cases and the cutover itself (below) closed the
  rest.

  **`L-P3.3c-CUT`, the atomic cutover: done (`CC-LAB-0067`/`FR-LAB-62`,
  2026-09-22).** With the coverage gate green, the hand-built
  `puppy-fort-factory/` app is retired and the generator is the single
  source of the PHP target lab (D20 §7.2, closed). Layer-C assets re-homed:
  `config/waf-rules.json` -> `lab/waf-rules.json` (shared with
  `fuzzlab.mutation.filtermodel`); `includes/waf.php`/`includes/cov.php` ->
  Laravel middleware in the `php_laravel` skeleton (`app/Http/Middleware/
  FzlWaf.php`, backed by the framework-free `app/Support/WafFilter.php`;
  `FzlCoverage.php`), registered globally in `bootstrap/app.php`, same
  default-off/opt-in toggle semantics as the retired PHP shims;
  `sql/schema.sql` -> `lab/sql/schema.sql`; `VULNERABILITIES.md` ->
  **generated** (`fuzzlab.labgen.vuln_map`, rendered from `labels.json` +
  `migration-exemptions.yaml`, so it cannot drift from the cells it
  describes). `fuzzlab.labgen.assemble` is the new real-build entry point
  (generalizes `conformance.live_boot.LiveBootHarness._assemble` from one
  manifest to every `lab/manifests/*.yaml` cell the coverage gate already
  proved sufficient) — `lab/web.Dockerfile`'s new `gen` build stage and
  `deploy.sh` both call it. `lab/compose.yaml` no longer bind-mounts an app
  directory (the app is a build artifact, not hand-edited); `db`'s seed
  mount and `fuzzlab.mutation.filtermodel`'s WAF-rules path both re-point at
  `lab/`. `lab/ground-truth/labels.json`/`injection-points.json`'s `target`
  changed from `"puppy-fort-factory"` to `"php_laravel"` (metadata only, the
  coverage gate does not diff on it). Deliberate, decided gaps this lane
  does **not** close (D-open-1/D-open-2, both already decided): Layer B
  (the 10 JS-rendered pages) has no generator emitter and is not
  reproduced — a real, on-host live-crawler-discoverability loss,
  documented in `docs/ON_HOST_RUNBOOK.md`; `php_current` is **not**
  retired (it stays as the second stack `L-P3.4`'s fingerprint-independence
  gate needs).
  Security assertions are **independent third-party tools invoked headlessly**
  (sqlmap, commix, SSTImap, ZAP, and Nuclei — `fuzzlab/labgen/{oracle_wrapper,
  zap_oracle,nuclei_oracle}.py`, see `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`), not
  hand-authored exploit code, for every class with a mature oracle. One class,
  **identifier/alias/connector-position SQL injection**, has a real, documented
  tool-oracle gap instead: a spot-check against the real sqlmap binary
  (`CC-LAB-0029`) confirmed it does not reliably detect this shape, so
  `fuzzlab/labgen/identifier_sqli_oracle.py` is a fourth, custom
  differential-response prober (CASE-WHEN boolean differential, MySQL dialect
  implemented) filling that gap rather than a fifth wrapped third-party tool;
  `fuzzlab/labgen/identifier_sqli_assertion.py` (L-P1.2b, `CC-LAB-0040`) is the
  gate that drives it per manifest cell, failing closed unless the prober's
  outcome matches the cell's derived verdict — and it also carries this
  program's honest statement of what that prober still cannot confirm (a
  character-filtered identifier position needs an identifier-swap differential,
  not a CASE-WHEN one).
  The three classes without any oracle at all (IDOR/BOLA, business logic, race
  conditions) are **deferred indefinitely** and not in scope for now. Built as
  the parallel Lab track after the toolkit foundations; phase-level
  deliverables in `CR-LAB-0001` §8.
- **Depends on (components):** none (it is the system under test).
- **Consumed by:** crawler, auditor, fuzzer, proxy, and the reward path.

### 2. `core/` shared library `[built; plugin registry planned]`
- **HTTP client** `[built]`: one send helper behind an injectable seam; requires a
  session context; records raw bytes (`core/http.py`).
- **Store** `[built]`: SQLite access, schema, and numbered forward-only migrations
  (`core/store.py`, `core/migrations.py`; head = migration 5 — core, finding
  url/method/param, session_state, evaluation, bandit cost columns).
- **Features** `[built]`: one versioned extractor with golden-file tests
  (`core/features.py`, `features_json` + `feature_version`).
- **Request budget + concurrency** `[built]`: per-component caps, and a per-host mutex
  so timing measurements run at concurrency 1 (`core/budget.py`).
- **Logging** (structured, `core/obs.py`) and **config** (layered, hashed onto the
  run, `core/config.py`) `[built]`. Also `core/urls.py` (single home of path
  normalization), `core/dedup.py`, `core/fingerprint.py`, `core/hybrid.py`, and
  `core/runmode.py` (the D14/D15 run-mode + no-ground-truth fail-safe).
- **Credential store** `[built]`: keyring-abstracted, with an encrypted-file
  headless/CI fallback on `cryptography` Fernet (PBKDF2, 0600, atomic write; D12);
  secrets by reference only, never in the project store (`core/credentials.py`).
- **Plugin registry** `[planned]` (Phase 10): entry points plus hooks.
- **Depends on (components):** none (foundational layer; it manages the project store).
- **Consumed by:** every tool and ML component.

### 3. Session manager `[built; live validation pending]` (Phase 1)
- **Subcomponents:** a **login/session detector** (D13) — finds the login form
  (carrying hidden/CSRF fields fresh), detects the session credential from the
  response (cookie / JSON token+JWT / Basic-Bearer challenge), confirms success by
  differential behavior, and detects expiry (401/redirect/form-reappears/JWT
  `exp`); identity model **per host**; session state (cookies + headers/tokens);
  re-auth macro with single-flight lock; a **per-host credential vault** via the
  `core/` credential store (OS keyring + encrypted-file headless fallback, D12).
  Detection-only: no hand-written per-host profiles; unparseable logins fail loud.
- **Interface:** `prepare(request, identity)`, `observe(request, response,
  identity)`, `ensure(identity)`, resolved by the request's host. Internally the
  detected mechanism maps to an auth handler (cookie/form, JSON+token, Basic,
  header-key) — implementation detail, not user config. Post-Phase 6, logins
  detection can't crack are handled by **adopting a session the proxy captures
  from a manual browser login** (FR-SESS-11), still without per-host config.
- **Depends on (components):** `core/` (config, store, HTTP seam, credential
  store); crawler (discovered forms help locate the login); proxy (post-Phase 6,
  for manual-login session capture).
- **Consumed by:** crawler, auditor, fuzzer, and the proxy (as an addon). This is
  the most load-bearing dependency; everything authenticated flows through it, on
  every host — the Puppy Fort Factory and the external validation labs (D10).

### 4. Crawler / spider `[built; to harden]`
- **Subcomponents:** hybrid fetch (HTTP first, headless on demand), XHR/fetch
  capture, JS endpoint extraction, DOM-skeleton template dedup, state-aware
  navigation, URL normalization, crawl budget.
- **Depends on (components):** `core/`, session manager, target lab.
- **Writes:** `page`, `endpoint`, discovered `parameter` rows.

### 5. Auditor / fetcher `[built; to harden]`
- **Subcomponents:** rules-as-data registry (`audit/rules_data/default_rules.json`,
  category-scoped), candidate emission with full per-rule evaluation logging (every
  evaluation recorded, not just hits — the `evaluation` table feeds negatives),
  canary reflection probing with context typing, target fingerprinting
  (DBMS/framework/WAF).
- **Depends on (components):** `core/`, session manager, crawler, indicator DB & catalogs.
- **Writes:** `candidate` rows (rule evidence, features), fingerprint data.

### 6. Indicator database and payload catalogs `[built; to extend]`
- **Subcomponents:** `build_sql_db.py` + `php_indicators.db` (28 indicator types
  mapped to `references/` categories); the `references/` payload catalogs;
  payload metadata (family, DBMS, context prerequisites, destructive flag).
- **Depends on (components):** none (static data).
- **Consumed by:** auditor (indicators), scheduler and fuzzer (payloads/families).

### 7. Fuzzing harness and oracle `[built; grey-box/OOB mechanisms partial]`
- **Fuzzing harness** `[built]`: the generalized `template + injection_point +
  payload_source + oracle` pipeline (`harness/pipeline.py`, `harness/auto.py`,
  `harness/scoring.py`, `harness/integration.py`), so one harness serves multiple
  vulnerability classes. Driven end-to-end by `fuzzlab auto` (`harness/auto_cli.py`),
  which consolidates a crawl, runs scoped rules + oracle confirmation, and — with a
  ground-truth contract — scores TP/FP. The legacy `tools/blind_sqli_fuzzer.py`
  remains as the original single-class fuzzer.
- **Oracle** `[built; M10 wiring layer built, live sources on-host]`: a
  **class-pluggable** deterministic confirmer (`oracle/oracle.py`,
  `oracle/strategies.py`, `oracle/probe.py`) — the **only** writer of `finding`
  labels — over 7 vuln classes (sqli, reflected/DOM/stored XSS, open-redirect,
  SSTI, file-inclusion, command-injection). Built mechanisms: M1 differential
  timing, M2 error signature, M3 boolean/response differential, M4 SSTI
  evaluation marker, M5 reflected-canary-in-context, M6 browser execution
  (stored/DOM XSS via an injected `BrowserExecutor` — `oracle/browser.py`,
  `tools/browserexec.py`), M7 file-content marker (LFI/traversal), M8 out-of-band
  callback (blind command injection, via an injected, already-started
  `OobListener` — `oracle/oob.py`, a loopback-only local canary tracker;
  default-off, wired through `fuzzlab auto --oob`), M9 redirect-target control,
  and M10 grey-box confirmation (sql-injection/xss, via an injected
  `CoverageSource`/`DbFaultSource` — `greybox/coverage.py`, `greybox/dbfault.py` —
  consulting the pure `greybox/confirm.py::greybox_confirms()` decision through
  `GreyboxConfirmationStrategy`; default-off, wired through `fuzzlab auto
  --greybox-coverage-file`/`--greybox-dbfault-file`). **M10 caveat:** the wiring
  layer is built and fully unit-tested offline (`InMemoryCoverageSource`/
  `InMemoryDbFaultSource`); it is not yet live end-to-end — it additionally needs
  a correlating oracle probe sender (`send_correlated`, the contract
  `greybox/run.py`'s `RequestsCorrelatingSender` already establishes) that no
  shipped oracle sender implements yet, plus the on-host pcov/DB-fault side
  channel behind `FileCoverageSource`/`FileDbFaultSource` — both on-host last-mile
  work. Findings are written in path-normalized form via `core/urls.to_path`.
  Each injection class registers the mechanism(s) that prove it; full mechanism set
  and the injection-class → mechanism mapping (derived from `references/`):
  `architecture/oracle-confirmation.md`. M8/M10 (`CC-FUZZ-0023`/`0024`,
  `FR-FUZZ-10`/`11`) were merged in from the diverged branch
  `claude/trusting-noether-heon0n` (cherry-picked and renumbered; that branch's
  own `CC-FUZZ-0019`/`0020` and `FR-FUZZ-8`/`9` collided with numbers this
  branch's own C1/D0a/B0 lanes had already claimed for unrelated work — see the
  change-control entries' provenance notes).
- **Depends on (components):** `core/`, session manager, scheduler, oracle,
  indicator DB & catalogs; grey-box instrumentation for reward and labels. (The
  oracle itself depends on `core/` and the target lab, plus grey-box signals when
  available.)
- **Writes:** `attempt` rows (features, reward), `finding` rows (labels).

### 8. Payload scheduler (bandit) `[built; on-lab exit pending]` (Phase 4)
- **Subcomponents** `[built]`: `ThompsonBandit` (Beta-Bernoulli) over
  (context, arm) — context = `category:sink|location`, arm = `vuln_class:mechanism`
  (`scheduler/bandit.py`); discrete context buckets and catalog-derived priors
  (`scheduler/context.py`); hierarchical backoff and cost-normalized selection
  (reward per second, migration 5's `cost_sum`/`cost_n`); persisted posteriors
  (load/save); and a `UniformScheduler` control condition (`scheduler/uniform.py`).
  Ordered the oracle's applicable mechanisms in the confirm loop; wired as
  `fuzzlab auto --bandit`.
- **Depends on (components):** `core/`, auditor (candidates), fuzzing harness and
  oracle (rewards), grey-box instrumentation (coverage reward).
- **Reads/writes:** `bandit_posteriors`; chooses the next family per candidate.
- **Pending (on-host):** the beats-uniform-on-hits-per-1000-requests exit (T4.6).

### 9. Mutation engine `[partial — full offline stack built; live coverage exit on-host]` (Phase 8)
- **Operators + semantics validator** `[built]` (`fuzzlab/mutation/`): typed,
  meaning-preserving operators (`operators.py`) and a validator (`semantics.py`) that
  refutes meaning changes via canonicalization + an `sqlglot` AST path (skip-guarded).
- **Context-typed XSS + filter learning** `[built]`: `xss.py` (filter-aware, context-typed
  candidates), `filtermodel.py` (mirrors the D16 WAF from the shared ruleset — offline
  seam), `learn.py::FilterLearner` (learns block/strip behavior, finds semantics-
  preserving bypasses).
- **Bandit/coverage search + write-back** `[built]`: `search.py::MutationSearch`
  (ThompsonBandit operator selection + coverage-guided hill climbing against the grey-box
  seam, budget-bounded/seeded); `catalog.py` records variant provenance to
  `payload_variant` (migration 8) behind the **destructive gate** (NFR-MUT-safe);
  `llm.py::LlmExpander` is the gated, default-off, offline expansion scaffold.
  Write-back is now reachable from **two** callers (`CC-MUT-0009`/`CC-FUZZ-0019`,
  2026-09-22): the standalone `fuzzlab mutate-run` CLI's live WAF-evasion search, and
  the main grey-box harness's own attempt loop (`greybox/run.py::run_greybox`,
  opt-in `--mutation-variants`) — both call the same `catalog.record_variant`.
- **Exit** `[on-host]`: against the enabled D16 WAF, variants bypass the filter where the
  base is blocked **and** reach new code (grey-box coverage) vs the static catalog.
- **Depends on (components):** `core/`, indicator DB & catalogs, scheduler,
  oracle, grey-box instrumentation. (A lab WAF is a prerequisite decision, not a
  component dependency.)
- **Depended on by:** the fuzzing harness (component #7) — `greybox/run.py` calls
  this component's operators/validator/`catalog.record_variant` directly (opt-in).
- **Writes:** new payload candidates back into the catalog/attempts, from either
  `mutate-run` or `greybox-run`.

### 10. ML components `[built — classifier, ranker, active learner, anomaly detector; held-out exits on-host]` (Phases 5, 7, 10)
- **Detection classifier** (A.1) `[built; held-out exit on-host]`: the `fuzzlab/ml/`
  package (pure Python — no numpy/sklearn). Honest evaluation (`metrics.py`: PR-AUC +
  leakage-free GroupKFold), the baselines a model must beat (`baselines.py`:
  prevalence, mean+kσ), two models behind one `fit`/`predict_proba` interface
  (`logistic.py`; `gbt.py` — class-balanced gradient-boosted trees), split-conformal
  flag/abstain/drop (`conformal.py`), a store-trained dataset (`dataset.py`), and
  `train.py::train_and_score` (`model_kind` logistic/gbt/auto, OOF selection, advisory
  `candidate.score`, `model` row + OOF metrics, prevalence fallback on thin data).
  **Advisory only** — scores/uncertainty, never `finding` labels. Wired as
  `fuzzlab auto --score`; the panel surfaces the top scored candidates. The
  beats-both-baselines exit on the store's real dataset (T5.5) is on-host.
- **Candidate ranker** (A.2) `[built; held-out exit on-host]` (Phase 7): a pointwise
  learning-to-rank over candidate features augmented with char n-gram TF-IDF
  (`ranking.py`, `text_features.py`, `ranker.py`, `rank_train.py`). Reads candidate
  features, writes advisory `candidate.rank_score`/`rank_uncertainty` (migration 7; kept
  separate from the classifier's `candidate.score`) at **zero request cost**, with
  per-candidate explanations. Evaluated by NDCG@k/Precision@k vs a random-order baseline
  (GroupKFold); wired as `fuzzlab auto --rank`. The real-lab held-out exit (T7.4) is
  on-host.
- **Active learner** (A.6.5) `[built; live budget exit on-host]` (Phase 7): allocates
  oracle budget by uncertainty sampling (reusing `rank_uncertainty`) and query-by-
  committee (a bootstrap `Committee` of rankers) — `active.py::propose_queries` returns
  the candidates to confirm next. Advisory: it proposes; the oracle confirms.
- **Anomaly detector** (A.5) `[built; held-out flow eval on-host]` (Phase 10): a
  parameter-free, pure-Python **ECOD** tripwire (`ml/anomaly.py`) over the store's feature
  vectors — advisory scores/flags (`detect_anomalies` records `anomaly_flagged`), never
  labels — plus the **XGBOD-style hybrid** (`augment` / `train_and_score(hybrid=True)`)
  that feeds the anomaly score into the classifier.
- **Depends on (components):** `core/`, the oracle (labels), and the component
  that produces each model's inputs (auditor for the ranker, fuzzing harness for
  the classifier, proxy/flows for the anomaly detector).
- **Attach as:** plugins on `core/` hooks. Shipping without ML is a config change.

### 11. Intercepting proxy `[partial — full offline stack built; live TLS serving on-host]` (Phase 6)
- **Dual-path core** `[built]` (D4, `fuzzlab/proxy/`): the **raw byte path**
  (`message.py::RawMessage`) — byte-exact, round-trips received bytes and edits by byte
  surgery so untouched lines stay verbatim (NFR-PROXY-byte-exact) — and the **parsed
  path** over `h11` (`parser.py`). The exit criterion holds in miniature: a hand-edited
  conflicting duplicate `Content-Length` forwards byte-for-byte on the raw path while
  the parsed path rejects it.
- **WebSocket framing** `[built]` (Phase 9 T9.1, `ws.py`): a from-scratch, byte-exact RFC
  6455 frame codec (encode/decode, masking, fragmentation, control frames) + the handshake,
  recorded in history with a `protocol` tag (migration 9).
- **HTTP/2 raw path** `[built]` (Phase 9 T9.2/T9.3): from-scratch byte-exact frames
  (`h2frames.py`, with a declared-length-override desync primitive), a minimal HPACK
  (`hpack.py`, passes arbitrary header bytes), and the raw-frame client (`h2client.py` —
  preface→SETTINGS→HEADERS→DATA and arbitrary/malformed sequences), for authorized desync
  research against the self-owned lab. The parsed `wsproto`/`h2` path and live ALPN/socket
  are the rest of Phase 9 (on-host).
- **Scope + match-and-replace** `[built]`: a default-deny scope engine (`scope.py`,
  host + optional path regex) and ordered byte-level rewrites (`matchreplace.py`).
- **History, repeater, interception, session capture** `[built]`: `flow` history
  (`history.py` — FTS5, batched writes, content-addressed bodies + raw bytes, secret
  redaction on write; migration 6); repeater (`repeater.py` — DB-persisted tabs, replay
  via a sender seam); interception-as-awaited-`asyncio.Future` (`intercept.py`);
  manual-login **session capture** (`session_capture.py` → `SessionManager.adopt`,
  FR-PROXY-9/FR-SESS-11 — the escape hatch for logins detection can't crack: MFA,
  CAPTCHA, multi-step). For **live** interception the engine is hosted in the web app's
  event loop by `web/proxycontrol.py` (D19), since the intercept futures are not
  cross-process; the standalone `fuzzlab proxy` remains for record-and-forward.
  **Responses** are now optionally intercepted too (an awaited engine hook gated by
  `Interceptor.intercept_responses`, default off so the path stays byte-exact).
- **Flow engine + CONNECT/TLS** `[partial]`: `server.py::ProxyEngine` is the sans-I/O
  pipeline (scope → match-replace → intercept → byte-exact forward → history) and
  `AsyncProxyServer` the asyncio socket layer (plain-HTTP path tested offline over
  loopback); `ca.py::LocalCA` is the local CA with a per-host leaf-cert cache (real
  minting is lazy `cryptography`). **Live CONNECT + TLS socket serving and browser trust
  of the CA are the on-host last mile.**
- **Depends on (components):** `core/`, session manager (attached as an addon).
- **Role:** optional observer; other tools may route through it for unified
  history, but timing-sensitive traffic does not (D5).

### 12. Diagnostics and UI `[built control panel; revamp in progress (see docs/UI_REVAMP_PLAN.md)]`
- **Subcomponents:** a **local web application** (D11, `fuzzlab/web/`) `[built]` — a
  FastAPI control panel (loopback-only, read-only over the store, no auto-run) that
  hosts the **launcher with run-mode selection** (automatic vs manual; nothing is sent
  to the target until the user chooses) and a dashboard + run-detail view for live
  runs and results, surfacing oracle findings and the advisory model scores with their
  flag/abstain/drop decision (`web/app.py`, `web/results.py`). The `run_metrics` table
  and structured audit/debug logs are built.
- **Revamp (in progress, `docs/UI_REVAMP_PLAN.md`):** growing the read-only panel into a
  full control plane over a **tabbed shell** (Launcher / Proxy / Results / ML /
  Diagnostics; jinja2 templates + a `/static` asset pipeline). Phase 0 foundations built:
  a **command-spec registry** (`web/commandspec.py`) that derives per-tool flag forms from
  each tool's own `argparse` parser (every tool exposes `build_parser()`), **SSE plumbing**
  (`web/sse.py`), a **subprocess runner** (`web/runner.py`) with dry-run preview,
  authorized-gated execution, and live SSE output (`/api/launch*`; only declared flags reach
  argv, no shell), and a **unified serve mode** (`web/proxycontrol.py`, `fuzzlab web
  --with-proxy`) that runs the intercepting proxy in the panel's own event loop so live
  interception's futures work (D19; opt-in, `--authorized`-gated, loopback-only, separate
  port). Phase 1 built the **Activity Launcher UI**: per-tool forms rendered from each
  command spec, a dry-run preview, gated Run with live SSE output + Stop, a D14 category
  picker, and a plugins panel (verified end-to-end in a real browser). Phase 2.1 added the
  **Proxy tab's read-only flow History** (`web/proxyview.py`; `/api/proxy/flows[/{id}]`;
  cross-process store reads, DOM-safe rendering of untrusted flow fields). Phase 2.2 added
  **live Intercept** — request/response toggles, a polled pending queue, and edit / forward
  / drop over the in-process proxy (verified over real sockets). Phase 2.3 added the
  **Repeater** (`RepeaterController`; `/api/proxy/repeater/*`) — persisted replay tabs,
  byte-exact send (authorized-gated), and "→ Repeater" from a History flow. Phase 2.4 added
  **Scope + Match-Replace** management (`/api/proxy/scope`, `/api/proxy/matchreplace`),
  **completing the Proxy workbench** (History · Intercept · Repeater · Scope/Match-Replace).
- **Layout redesign (`docs/UI_LAYOUT_REDESIGN.md`, D-UI-shell):** the panel's five sections
  now live in a persistent **app shell** — a left-sidebar nav + a top context bar (target /
  scope / authorized / proxy chips) — over a **design-token** system (`web/static/tokens.css`:
  light / dark / system theme + compact density, persisted per-viewer, no-FOUC). Delivered as
  **R0** (`base.html` shell, retokenized `app.css`, `initShell()`; chrome-only, no behavior
  change, hash-based section switching preserved; CC-UI-0021, FR-UI-8). The **Launch view** was
  then rebuilt as the approved **master-detail** — a grouped, gate-tagged activity picker →
  the selected activity's command-spec form (`initLaunchNav()`; CC-UI-0022), brought forward
  from R1.
- **U0 — MPA routes + asset split (`docs/UI_IMPLEMENTATION_PLAN.md` §3, CC-UI-0025,
  2026-09-22, the enabling refactor every Wave-1 UI lane depends on):** retired the
  hash-based section switching from R0 in favor of **real per-section routes** —
  `GET /` (Launcher), `/proxy`, `/results`, `/ml`, `/diagnostics`, plus `/runs/{id}` — each
  independently deep-linkable, no-JS-renderable, and with server-computed sidebar active
  state (`aria-current="page"`) from one `NAV` source of truth in `web/app.py`. Split
  `templates/index.html` → `templates/sections/*.html`, `static/app.js` →
  `static/js/{shell,common,launcher,proxy}.js`, `static/app.css` →
  `static/css/{shell,launcher,proxy,results}.css` (D3: per-section modules/partials, no
  bundler) — making U1–U5's sections file-disjoint. The Proxy "send to Repeater" pivot now
  follows **POST/Redirect/GET with a 303** (R-07): a real `<form method="post">` to
  `POST /proxy/repeater/from-flow`, then a 303 to `/proxy?repeater_tab=<id>` — an opaque id
  only, never raw request bytes. Full-page MPA over HTMX per resolved R-01 (a loopback
  full-page GET is sub-millisecond, so HTMX's benefit doesn't apply here).
  Wave 1 (U1–U5) builds each section's real content on top of this split: an Overview
  dashboard, a Findings workbench, a Proxy rebuild, the ML tab, and Diagnostics + store
  explorer.
- **U2 — Findings workbench (`docs/UI_IMPLEMENTATION_PLAN.md` §3, CC-UI-0029,
  2026-09-22):** `GET /findings`/`/findings/{id}` — a faceted-filter sidebar (severity,
  vuln class, method, mechanism, endpoint; live per-group counts) + a quick-filter +
  applied-filter chips + a **saved-view** chip row over `finding`/`attempt`
  (`web/findingsview.py`, read-only), entirely client-side filter/sort over one bounded
  snapshot (D4/R-03). Saved views persist server-side in a new `saved_views` table
  (migration 12, `CC-CORE-0019`; `web/savedviews.py`;
  `GET/POST/PUT/DELETE /api/views?table=`) — the one write path this section owns
  (view definitions, not a result table). The detail view renders the multi-artifact
  ground-truth fields (`primary_endpoint`/`primary_role`/`related_endpoints`/
  `flow_variant`, CR-LAB-0001 Addendum B) when a finding's evidence carries them
  (additive/optional; no current writer attaches them yet). "Send to Repeater" reuses
  U0's PRG+303 pivot exactly (`POST /findings/repeater/from-finding` → 303 →
  `/proxy?repeater_tab=<id>`); since findings carry no raw bytes, the tab is a
  reconstruction from the finding's own `url`/`method`/`param` plus the oracle's
  recorded `evidence['payload']` when one was captured (`results.
  build_finding_raw_request`), against the finding's own run's target, explicitly
  labeled as a reconstruction rather than a byte-exact replay. Also shipped
  `static/js/datatable.js` — a standalone, hand-rolled
  ES module (native `<table>`, `textContent`-only rendering, scheme-checked pivot
  hrefs) meant for reuse by U1's recent-runs table and U5's store explorer (D4: no
  table dependency).
- **U4 — ML tab (`docs/UI_IMPLEMENTATION_PLAN.md` §3, CC-UI-0031/CC-ML-0010, 2026-09-22,
  Phase 3, Wave 1, built on U0):** filled in `/ml` with read-only, advisory panels over
  model internals already in the store — classifier PR curve + reliability/ECE, ranker
  nDCG@k/precision@k + score/uncertainty distributions, the conformal flag/abstain/drop
  split, the ECOD anomaly tripwire, active-learning committee disagreement, Thompson-
  bandit Beta posteriors, and mutation killed/survived variants — behind a persistent
  non-dismissible advisory banner, categorical bands, verb hygiene, and a neutral
  blue/amber palette (never the oracle's red/green), per resolved R-06. New read-only
  `fuzzlab/web/mlview.py` + `GET /api/ml/data`. Introduced this project's **charting
  layer** (D2, resolved R-02/R-12), shared with U5: vendored **uPlot 1.6.32** verbatim
  (`static/vendor/uplot/uPlot.esm.js` + `uPlot.min.css`, no bundler/CDN) behind
  `static/js/chart.js::createChart()` — full destroy()+recreate on theme/density change
  (canvas can't read CSS vars and uPlot bakes colors in at construction), a debounced
  `ResizeObserver` on the chart's parent cell + `requestAnimationFrame` coalescing, a
  `MutationObserver`/`matchMedia` retheme, `window.__charts` registry, and a
  visually-hidden `<table>` a11y fallback per chart. **Known gap** (see
  `docs/components/10-ml-components/requirements.md` FR-ML-9): the logistic
  classifier's trained weights are never persisted to the store, so the "logistic
  weights" panel R-06 calls for renders a documented not-available state rather than a
  value — closing it is a future ML-component change, out of this lane's read-only
  scope.
  U0/U1/U2/U3/U4/U6 and D0a/D0b have all landed.
- **U5 — Diagnostics tab + store explorer (`docs/UI_IMPLEMENTATION_PLAN.md` §3,
  CC-UI-0032, 2026-09-22, Phase 3/4, Wave 2, built on U0/U4/U2):** filled in
  `/diagnostics` (previously a stub) with a TensorBoard-like view over the
  `metric_series` time-series table (migration 11, `CC-CORE-0018`): cross-run
  trend charts over `run_metrics`, intra-run/cross-run step-series overlays with
  server-side LTTB downsampling (R-05) and client-side EMA smoothing applied
  after downsampling, plus snapshot panels (candidate-score histogram, bandit
  arm posteriors, model-registry timeline). Also shipped the read-only,
  Datasette-style **store explorer** (`FR-UI-2`/`FR-UI-14`): any store table,
  browsable via `GET /api/store/tables` + `GET /api/store/tables/{name}`, with
  the table name always re-validated against a live `sqlite_master` query before
  use — the actual injection-safety mechanism (`tests/test_web_diagnostics.py`
  covers this with parametrized injection-attempt cases). U5 was dispatched from
  a pre-Wave-2 base and, per PA-0031's merge protocol, independently built its
  own `static/js/chart.js`, `static/js/datatable.js`, and a second vendored copy
  of uPlot before U4's and U2's versions had landed; the integrator reconciled
  these by hand at merge time onto the already-landed versions rather than
  merging raw — U5's unique `ema()` client-side smoothing helper was merged into
  U4's `chart.js`, and `static/js/diagnostics.js` was adapted to call U2's
  landed `createDataTable()` API rather than landing a second `DataTable`
  implementation; U5's own `chart.js`/`datatable.js`/vendored uPlot copies were
  discarded. Known gap: the wall-clock/relative-time x-axis modes fall back to
  step order pending real per-point timestamps in the `metric_series_data` wire
  payload (a follow-up, not a regression — step order is still monotonic).
- **Reproducible evaluation report** `[built]` (Phase 10 T10.4, `fuzzlab/report/`): a
  deterministic report over a stored run (run/config identity, target, counts, findings,
  metrics, deployed models, active plugins), canonical JSON for diffing; read-only
  `fuzzlab report [--run] [--json]`.
- **Depends on (components):** `core/` (store and logging); in automatic mode the
  web app invokes the tools (crawler, auditor, fuzzer, harness).
- **Purpose:** the research-platform diagnostics from decision D2, made easy to
  review in a browser (D11), to verify functionality and locate bugs; and to keep
  the user in control of when the tools touch the target (the no-auto-run
  principle).
- **Safety:** the web app is bound to loopback, never exposed, and strictly
  separated from the vulnerable target (different origin/port; never in the
  target's web root), so the control plane is never itself an attack surface.

### 13. Plugin system `[built]` (Phase 10)
- **Registry + hooks** `[built]` (`fuzzlab/plugins/`): `importlib.metadata` entry-point
  discovery, a `HookRegistry` with the seven hooks (`on_request`, `on_response`,
  `on_candidate`, `on_finding`, `register_rules`, `register_payload_source`,
  `register_oracle`), per-plugin **priority** ordering, contain-log-**disable** isolation,
  and the oracle/advisory-split guard (observation returns ignored; only `register_oracle`
  reaches the finding-writer). `PluginManager` records the active set to `run_plugin`
  (migration 10). Zero plugins is a full no-op (D6).
- **Pipeline attachment** `[built]` (T10.2): `on_request`/`on_response` at the HTTP seam
  (`core/http.py`), `register_rules`/`on_candidate` in the auditor, `register_oracle`/
  `on_finding` in the oracle; `plugins` threads through `run_pipeline`/`run_auto`
  (`fuzzlab auto --plugins`). `register_payload_source` is consumed by the mutation
  engine's `PayloadPool` (`MutationSearch.search_pool`) — all seven hooks are wired.
- **Depends on (components):** `core/`.
- **Consumed by:** ML components, extra rules, and custom oracles.

## The store as the contract

Core tables and their principal readers/writers (see the roadmap for schema
detail):

| Table | Written by | Read by |
| --- | --- | --- |
| `run`, `schema_version` | core | everything |
| `target` (fingerprint) | auditor | scheduler, fuzzer |
| `page`, `endpoint`, `parameter` | crawler, auditor | auditor, ranker, fuzzer |
| `candidate` (rule evidence, features, score) | auditor, ranker | scheduler, fuzzer |
| `flow` (+ raw bytes) | proxy, http client | anomaly detector, UI, analysis |
| `attempt` (features, reward) | fuzzer | classifier, bandit, active learner |
| `finding` (labels, evidence) | oracle only | UI, ML training, reports |
| `bandit_posteriors` | scheduler | scheduler |
| `model` (versions, calibration) | ML training | ML inference |
| `request_budget` | all tools | budget manager, UI |
| coverage / fault signals | grey-box hooks | fuzzer, scheduler, mutation |
| `metric_series` (cross-run scalars: `run_id, source, key, step, ts, value`; migration 11) | per-step emitters via `core.store.log_scalar`/`MetricLogger`: coverage frontier (`greybox/run.py::run_greybox`, `source="coverage"`, landed `CC-FUZZ-0021`) landed; GBT/logistic, bandit loop, `MutationSearch`, stage timing still pending as later, separate lanes | diagnostics UI (U5) |

## Dependency ordering

From most foundational to most dependent. Nothing above a layer should import
from below it.

```
target lab + grey-box instrumentation      (system under test)
        ▲
core/  (store, http, features, budget, logging, config, plugins)
        ▲
session manager
        ▲
crawler → auditor → candidate queue
        ▲
scheduler (bandit) + oracle
        ▲
fuzzing harness  ──uses──►  scheduler, oracle, payload catalogs
        ▲
ML components (ranker, classifier, anomaly, active learner)   [plugins]
        ▲
proxy (optional observer)  ·  mutation engine  ·  diagnostics/UI
```

Key hard dependencies: everything depends on `core/` and the store; every
authenticated action depends on the session manager; every confirmed finding and
every training label depends on the oracle; the bandit's dense reward and the
mutation engine's hill climbing depend on grey-box signals.

## Key interaction flows

**1. The core discovery-to-label loop.**
crawler discovers pages/endpoints → auditor emits candidates with rule evidence →
ranker scores and orders them (0 requests) → scheduler picks a payload family per
candidate → fuzzing harness sends and extracts features → classifier screens
(flag/abstain/drop) → oracle confirms with differential timing (and coverage/DB
signals) → `finding` written with a label → that label becomes a training row and
a bandit reward.

**2. Session handling across tools.**
Each tool calls `session.prepare()` before sending and `session.observe()` after
receiving; `session.ensure()` re-authenticates via a single-flight lock when a
logout is detected. As a proxy addon, the same handling applies to hand-driven
browser traffic.

**3. Grey-box reward.**
A request executes against the instrumented lab → coverage and DB-fault signals
are collected per request → the oracle and the bandit read them as a dense reward
→ state is reset via snapshot/restore before the next iteration.

**4. Proxy as observer / manual testing.**
Browser or tools route through the proxy (non-timing traffic) → flows land in the
shared history with raw bytes → anomaly detector tags weird responses → repeater
replays and edits, including a raw byte path for malformed-traffic study.

## Cross-cutting concerns

- **Budget and concurrency:** one shared budget; timing traffic serialized per
  host by a mutex in the budget manager.
- **Logging and observability:** structured logs carrying `run_id`, `tool`,
  `identity`, `flow_id`; a metrics table; an audit log of every request for
  reproducibility.
- **Configuration:** layered (defaults → file → env → CLI), validated, hashed
  onto the `run` row; one config shared by all tools; secrets by reference only.
- **Testing:** protocol unit tests, `hypothesis` property tests for the parser,
  golden-file feature tests, deterministic ML-pipeline tests, an
  assert-N-known-vulns integration suite, and oracle precision tests.
- **Security and safety:** credentials in the OS keyring, redaction on write,
  automatic scope enforcement, a default-off destructive-payload gate, a lab-only
  posture throughout, **no auto-run** — bring-up presents a launcher and no
  tool sends traffic to the container until the user selects automatic mode or
  runs a tool by hand — and a **no-ground-truth fail-safe** (D15): an automatic run
  against a target we have no ground truth for requires an explicit category
  selection (never guesses or tests everything), runs unscored, keeps every safety
  gate on, and fails loudly if categories are not given.

## Build-status snapshot

Suite: 390 passed / 4 skipped (the skips need a native build unavailable in the sandbox:
2 credential-store tests, the proxy real-CA minting test, and the mutation engine's
`sqlglot` AST test). Everything below is offline-complete unless an on-host item is named.

- `[built]` (offline-complete, unit-tested):
  - **Foundations (Phase 0 + T1.1):** `core/` — unified store + forward-only
    migrations (head = 10), config, structured logging, request budget + per-host
    timing mutex, HTTP seam, versioned features (golden-file), path normalization,
    dedup, fingerprint, run-mode + D15 fail-safe, and the per-host credential store
    (`cryptography` Fernet fallback).
  - **Session manager (Phase 1):** detection-based login/session handling with
    per-identity state and non-secret state persistence (live two-lab validation
    pending, on-host).
  - **Discovery + audit:** crawler/spider, auditor (rules-as-data + full evaluation
    logging), indicator DB + payload catalogs, ground-truth label contract, and the
    integration harness.
  - **Deterministic wins (Phase 2):** the generalized fuzzing harness and the
    class-pluggable **oracle** (mechanisms M1–M9 across 7 vuln classes; the sole
    finding-writer), driven by `fuzzlab auto` with TP/FP scoring against ground truth.
  - **Bandit scheduler (Phase 4):** Thompson sampling with context buckets,
    catalog priors, cost-normalized selection, hierarchical backoff, persisted
    posteriors, and a uniform control (`fuzzlab auto --bandit`).
  - **Detection classifier (Phase 5):** the advisory `fuzzlab/ml/` core — honest
    eval, prevalence/sigma baselines, logistic + gradient-boosted-tree models,
    conformal flag/abstain/drop, store-trained dataset, train/score/persist
    (`fuzzlab auto --score`); scores only, never labels.
  - **Candidate ranker + active learning (Phase 7):** per-page ranking metrics
    (NDCG@k/Precision@k), char n-gram TF-IDF, a pointwise ranker with explanations
    writing advisory `candidate.rank_score` at zero request cost (`fuzzlab auto --rank`,
    migration 7), and active learning (uncertainty sampling + query-by-committee) to
    allocate the oracle budget; advisory only.
  - **Anomaly detector (Phase 10):** a pure-Python ECOD tripwire (`ml/anomaly.py`,
    advisory scores/flags) + the XGBOD-style hybrid feature for the classifier
    (`train_and_score(hybrid=True)`); never labels.
  - **Diagnostics/UI:** the loopback FastAPI control panel + dashboard/run-detail
    (findings + advisory scores), and the deterministic reproducible evaluation report
    (`fuzzlab report`, Phase 10 T10.4).
  - **Lab WAF (D16):** a configurable, default-off, deliberately bypassable request
    prefilter — the Phase 8 filter-evasion target.
  - **h2→h1 downgrade front-end (D17):** an opt-in, default-off (profile-gated) nginx
    front-end that downgrades HTTP/2 to HTTP/1.1 — the Phase 9 desync research target.
- `[partial]`:
  - **Grey-box (Phase 3):** offline consumer layer (coverage/DB-fault readers,
    shaped reward, reset call points) built; **live sources on-host** (Xdebug/pcov,
    DB error hook, snapshot/restore).
  - **Mutation engine (Phase 8):** the full offline stack is built — operators +
    semantics validator (canonical + `sqlglot` AST), context-typed filter-aware XSS, the
    filter model + bypass learner, the bandit/coverage-guided search, variant write-back
    to `payload_variant` (migration 8) behind the destructive gate, the gated
    default-off LLM scaffold, and (closing a previously untested wiring gap) the
    `payload_variant` -> scheduler candidate source -> `greybox-run --mutation-variants`
    read-back path; only the live filter-bypass + coverage exit (T8.7) remains.
  - **Protocol depth (Phase 9):** the from-scratch WebSocket frame codec + handshake, the
    `flow.protocol` tag (migration 9), and the byte-exact HTTP/2 frame layer + minimal
    HPACK + raw-frame client are built; the parsed `wsproto`/`h2` path, live ALPN/socket,
    and the opt-in h2→h1 desync lab front-end remain.
  - **Plugin system (Phase 10):** the `HookRegistry` (7 hooks, priority, contain-log-
    disable isolation, oracle/advisory-split guard), entry-point discovery, `PluginManager`,
    `run_plugin` recording (migration 10), and the pipeline wiring (T10.2 — HTTP seam,
    auditor, oracle; `fuzzlab auto --plugins`) and the `register_payload_source` consumer
    (mutation `PayloadPool`) are built — all seven hooks wired.
  - **Oracle mechanisms:** M8 (out-of-band, `oracle/oob.py` — blind command
    injection, via `fuzzlab auto --oob`) is built; M10 (grey-box,
    `GreyboxConfirmationStrategy` — sql-injection/xss, via `fuzzlab auto
    --greybox-coverage-file`/`--greybox-dbfault-file`) has its wiring layer built
    and unit-tested offline — the live correlating probe sender and the on-host
    pcov/DB-fault side channel it needs to confirm against a real target remain
    on-host last-mile work.
  - **Intercepting proxy (Phase 6):** the full offline stack is built — byte-exact
    dual-path core (`RawMessage` + `h11`), scope, match-and-replace, flow history
    (migration 6, FTS5), repeater, interception, manual-login session capture, the
    sans-I/O flow engine, and the local-CA leaf cache; only live CONNECT/TLS socket
    serving and browser trust remain (on-host).
- `[on-host]` (offline pieces done; the exit/validation runs on the live lab):
  Phase 3 live capture; Phase 4 beats-uniform exit (T4.6); Phase 5 held-out exit
  (T5.5); Phase 6 live CONNECT/TLS serving + browser trust; Phase 7 held-out
  NDCG@k/Precision@k exit + active-learning-budget-vs-random (T7.4); Phase 8
  variants-bypass-the-WAF-and-reach-new-code exit (T8.7); Phase 9 live WS/HTTP-2 + h2→h1
  desync exit (T9.6); Phase 10 live transfer run against a second/external target (T10.6);
  live `--browser`/`--bandit`/`--score`/`--rank` runs and stored-XSS session-to-browser
  wiring — all tracked in `docs/ON_HOST_TASKS.md`.
- `[planned]`: the manifest-driven lab generator (Lab track, the eventual option-C second
  target).
