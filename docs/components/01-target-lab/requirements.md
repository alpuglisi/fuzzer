# Target Lab and Ground Truth — Requirement Specification

Component code: **LAB** · Status: `[built; generator is the single source of the PHP lab since L-P3.3c-CUT (2026-09-22) -- the hand-built app is retired]`
· Last updated: 2026-09-23

Related: `ARCHITECTURE.md` #1; `DECISIONS_AND_ROADMAP.md` (D7, D8, D9, D10);
`./change-control.md`.

## 1. Purpose
Provide a deliberately vulnerable, locally hosted target with exact,
machine-readable ground truth, against which the toolkit's tools are exercised
and measured. Authorized, lab-only.

## 2. Scope
- **In:** the generated PHP target lab (`fuzzlab.labgen.assemble` over the
  `php_laravel` emitter — the single source of the PHP lab since `L-P3.3c-CUT`,
  2026-09-22, `CC-LAB-0067`/`FR-LAB-62`; the hand-built "Puppy Fort Factory" app it
  replaced is retired); ground-truth labels; grey-box instrumentation; the
  containerized environment; the manifest-driven generator, tiers, and build
  profiles.
- **Out:** the tools themselves; anything reachable from a non-loopback network.

## 3. Functional requirements
- **FR-LAB-1** Serve a deliberately vulnerable web app on localhost with a
  documented mix of vulnerable and secure pages. **Status (2026-09-22,
  `L-P3.3c-CUT`): the served app is now the generated `php_laravel` app** (built by
  `fuzzlab.labgen.assemble`, baked into `lab/web.Dockerfile`'s image), not the
  retired hand-built app — the requirement's substance (a deliberately vulnerable,
  documented, localhost-served app) is unchanged, only its referent.
- **FR-LAB-2** Emit machine-readable ground truth out-of-band (`labels.json`,
  `expectedresults.csv`, `injection-points.json`) with opaque case IDs, never
  served by the app. (D9)
- **FR-LAB-3** Provide grey-box signals: per-request line coverage, a DB
  error/fault signal, and state snapshot/restore for reset. (D7)
- **FR-LAB-4** Run in a container with pinned PHP/Apache/MySQL/libxml, with
  one-command up and reset. (D7)
- **FR-LAB-5** (Lab track) Generate app, labels, docs, and oracle tests from one
  manifest + safety matrix + seed + env-profile, with a **binary** verdict
  derived from `(transform, sink context)` — a partially neutralized case is
  VULNERABLE-but-harder (a `difficulty` tier), not a third verdict value. (D8, D20)
- **FR-LAB-6** (Lab track) Support build profiles: annotated, blind, all-secure.
- **FR-LAB-7** (Lab track) Support two tiers: dense range and realistic shop.
- **FR-LAB-8** (Lab track) Migrate the existing hand-built Puppy Fort Factory
  app's content into the generator (Phase 3) rather than keep it as a
  permanent separate fixture. (D20) **Status (2026-09-22, `L-P3.3c-CUT`,
  `CC-LAB-0067`/`FR-LAB-62`): satisfied.** The migration itself (server-side
  pages, `FR-LAB-44`..`50`), the parity/cutover coverage gate (`FR-LAB-51`,
  reporting 14 of 16 `PFF-` cases covered by an emitted `php_laravel` cell with the
  remaining 2 exempted in `lab/ground-truth/migration-exemptions.yaml`), and the
  atomic cutover itself are all now done: `puppy-fort-factory/` is deleted,
  `lab/compose.yaml`/`deploy.sh`/`fuzzlab/mutation/filtermodel.py`'s WAF-rules path
  are re-pointed at generator/`lab/`-owned locations, and the generator is the sole
  source of the PHP target lab.
- **FR-LAB-9** (Lab track) Own the pattern-provenance corpus (`patterns/`,
  OSV/GHSA-sourced pattern cards informing scenario briefs in original words
  only, never inlined as code) as a LAB subcomponent, not an IND catalog. (D20)
- **FR-LAB-10** (Lab track) For every vulnerability class with a mature,
  independently-authored exploitation tool (sqlmap, commix, et al.), the
  generator's security assertion is that tool invoked headlessly, not
  hand-authored exploit code. IDOR/BOLA, business-logic flaws, and
  race-condition classes (no mature automated oracle) are out of scope until
  further decided. (D20, `CR-LAB-0001` Addendum E)
- **FR-LAB-11** (Lab track) FR-LAB-10's "tool invoked headlessly" is a single
  reusable, importable wrapper (`fuzzlab.labgen.oracle_wrapper`, see
  `CC-LAB-0015`/`CC-LAB-0017`) shared by every seed's security assertion, not
  a per-seed ad-hoc CLI invocation. Covers sqlmap (SQL injection), commix
  (OS command injection), and SSTImap (server-side template injection) as of
  `CC-LAB-0017`; each gets its own request dataclass
  (`SqlInjectionOracleRequest`, `CommandInjectionOracleRequest`,
  `ServerSideTemplateInjectionOracleRequest`) and `run_*_oracle` function
  (plus a type-dispatching `run_oracle`), all sharing the contract below. Its
  contract: (a) plain, explicit parameters (target URL, method, injection
  parameter name/location, an optional session/token-refresh callback, and —
  only where the underlying tool needs it, e.g. sqlmap — an expected "secure"
  HTTP status code list) — independent of the manifest/cell schema, so it can
  be called before, during, or after that schema exists; (b) a
  bounded-timeout × bounded-attempt safety valve so a hung tool invocation
  can never block the caller indefinitely (encodes Spike 002's
  rotating-CSRF-token finding); (c) where the underlying tool special-cases
  an HTTP status code as an unrecoverable failure, a caller-supplied "secure"
  status code is translated automatically into the tool's own auth-bypass
  flag (sqlmap's `--ignore-code`, encoding Spike 001's finding) so the caller
  never needs the tool's flag syntax — SSTImap needs no such field, having no
  such special-casing (verified by reading its source, Spike 003);
  (d) every invocation is scoped to the one declared injection parameter,
  never a blind sweep of the target's other fields — via the tool's own
  parameter-selection flag where one exists (sqlmap's/commix's `-p`,
  Spike 002's parameter-sweep finding) or, where none exists, by building the
  tool's own injection-marker mechanism at exactly that parameter's value
  plus restricting its injection-point scope to that one location category
  (SSTImap's `-M`/`-P`, Spike 003); (e) the loopback-only safety check
  (`assert_loopback`) runs before every invocation and raises rather than
  silently proceeding on a non-loopback target; (f) the result is one of
  exactly three verdicts — `confirmed_vulnerable | confirmed_secure |
  inconclusive` — and a tool crash, timeout, or missing binary is always
  `inconclusive`, never guessed as secure (fail-closed, matching
  `NFR-LAB-label-accuracy`'s "labels derived, not hand-asserted" and this
  project's existing `fuzzlab.oracle` philosophy of never inferring a
  positive from the absence of a negative signal, PA-0007).
- **FR-LAB-12** (Lab track, Phase 0) The manifest schema represents a cell's
  `transform` as an ordered pipeline of ops (never a single enum) and its
  `sink_context` as a structured object — a family plus the set of concerns a
  pipeline must fully neutralize — never a bare string. Validated against
  `lab/schemas/manifest.schema.json`. (`CR-LAB-0001` §3, `CC-LAB-0016`)
- **FR-LAB-13** (Lab track, Phase 0) `fuzzlab.labgen.verdict.verdict()` is a
  pure function of `(pipeline, sink_context, safety_matrix)` implementing the
  D20 binary verdict: VULNERABLE or SECURE only, with a `partial` effect
  raising a `difficulty` tier rather than a third verdict value. The safety
  matrix (`lab/safety_matrix.yaml`) is an open, versioned, append-only
  registry of `(op, sink_family) -> effect` entries; a caller pins
  `safety_matrix_version` so a corpus generated under an older matrix stays
  re-derivable under that matrix's rules after later, additive changes.
  Verdict output for a fixed matrix version is snapshot-tested and must not
  silently drift. (D20, `CR-LAB-0001` §3/§5, `CC-LAB-0016`)
- **FR-LAB-14** (Lab track, Phase 0) A per-cell sub-seed is derived
  deterministically from `(root_seed, cell_id, transform, sink_context,
  stack_profile)`; canonical serialization of generated/label-contract-style
  output is byte-identical across repeated calls with equal input (no floats,
  sorted keys, no third-party formatter). A regenerate-and-diff build gate
  runs the generator twice from the same manifest+seed and fails the build on
  any byte difference. (NFR-LAB-reproducible, `CR-LAB-0001` §3, `CC-LAB-0016`)
- **FR-LAB-15** (Lab track, Phase 0) A name-leak scanner build gate fails the
  build if any generated artifact's URL, filename, or parameter name contains
  a vulnerability-class name, validated against a should-flag/should-not-flag
  fixture set (including known word-boundary collisions) so the scanner's
  no-false-negative property is established by testing, not code review; the
  scanner also fails the build on a crash, not just a hit. (NFR-LAB-no-leak,
  `CC-LAB-0016`)
- **FR-LAB-16** (Lab track) The `patterns/` provenance corpus
  (`lab/patterns/`) is a one-directional index (`cell_id -> [card_id, ...]`
  in `provenance.yaml`); a manifest cell never carries a card reference, and
  no card ID or `pattern://`-style string may appear in a manifest or in the
  verdict module's source — mechanically enforced. Each card validates
  against `lab/schemas/pattern_card.schema.json` and its `class` must exist
  in the versioned taxonomy. (`CR-LAB-0001` Addendum A, `CC-LAB-0016`)
- **FR-LAB-17** (Lab track, Phase 0/1 foundation) `fuzzlab.labgen.resolver.expand()`
  provides real covering-array expansion (pairwise by default, mixed
  strength via `sub_models`, declarative JSON-serializable `constraints`)
  over `covertable` 3.2.0, exact-pinned; its own kwargs to `covertable.make()`
  are validated against an explicit allowlist so an unrecognized/mistyped
  option raises rather than being silently ignored (`covertable.make()`'s
  own `**params` behavior), and its sorter is always pinned to
  `covertable.sorters.hash` rather than relying on the library's default.
  Deterministic across processes and `PYTHONHASHSEED` values. Also rejects a
  `strength` (top-level or per-`sub_models`-entry) exceeding the number of
  factors/fields it covers, since `covertable.make()` silently returns an
  empty array for that shape rather than raising (`BUG-0024`). Wired into
  manifest loading as of `FR-LAB-27`/`CC-LAB-0029` — superseded the "not yet
  wired" note below. (`CR-LAB-0001` §3, `docs/LAB_PHASE_0_PLAN.md` T-LAB0.3,
  `CC-LAB-0018`, `CC-LAB-0029`)
- **FR-LAB-18** (Lab track, Phase 0) An `Emitter` interface
  (`fuzzlab.labgen.emitter.Emitter`) turns a resolved `Cell` into one or more
  output files (`EmittedFiles`, never assumed to be exactly one — forward-
  compatible with a future routed, multi-file stack per `CR-LAB-0001`
  Addendum D), declaring supported `(vuln_class, sink_context)` pairs via
  `supports()` rather than erroring on an unsupported one. Implementations
  render via **module composition** — small, independently-authored and
  independently-testable source/transform/sink/complexity fragments
  (`fuzzlab.labgen.modules`) assembled per cell — never one monolithic
  template per `(class, sink_context)`, per `CR-LAB-0001` Addendum C. The
  first emitter, `php_current`, proves this end to end for one illustrative
  vulnerable/secure SQLi pair and generalizes to a small real sample of four
  actual `puppy-fort-factory/` pages (`product.php`, `blog_post.php`,
  `login.php`, `profile.php` — two vulnerability classes, three sink-context
  families: `sql_numeric_literal`, `sql_string_literal`, `html_body`),
  matching `lab/ground-truth/labels.json`'s `PFF-0001`/`PFF-0004`/`PFF-0005`/
  `PFF-0006`; reproducing the remaining ~26 real pages is separate, later
  scope. (`CR-LAB-0001` §3/Addenda C/D, `docs/LAB_PHASE_0_PLAN.md` T-LAB0.4,
  `CC-LAB-0019`, `CC-LAB-0022`)
- **FR-LAB-19** (Lab track, T-LAB0.8, mechanical tooling only) A pull/index/
  scope/rank/cluster pipeline (`fuzzlab/tools/pattern_corpus_sourcing.py`)
  produces a structured **candidate list** for human triage from
  `github/advisory-database` (git-clone pull, per
  `docs/LAB_PATTERN_CORPUS_SOURCING_PLAN.md` Revision 2 §2 — never the OSV/
  GHSA APIs), scoped by a versioned CWE/keyword crosswalk
  (`lab/patterns/sourcing/crosswalk.yaml`) covering the ten first-wave
  classes. This pipeline **never authors a card, never writes to
  `lab/patterns/cards/`, and never touches `provenance.yaml`** — card
  authoring (writing `root_cause`, judging licensing, deciding inclusion)
  stays separate, human-supervised work, per that plan's step 6. Idempotent:
  re-running against an unchanged upstream commit overwrites the current
  quarter's candidate/report files with identical content and does not
  duplicate a `lab/patterns/REFRESH_LOG.md` entry. (`CR-LAB-0001`, D20,
  `docs/LAB_PHASE_0_PLAN.md` T-LAB0.8, `CC-LAB-0020`)
- **FR-LAB-20** (Lab track) A separate, importable wrapper,
  `fuzzlab.labgen.zap_oracle` (kept out of `oracle_wrapper.py` deliberately —
  see `CC-LAB-0021`), covers the fourth tool-oracle class named in
  `CR-LAB-0001`'s tool-mapping table: **"Whole-app safety net → OWASP ZAP
  daemon mode / Automation Framework — Supplementary."** Unlike FR-LAB-11's
  per-parameter contract (sqlmap/commix/SSTImap), ZAP is a whole-app active
  scanner with no single declared parameter, so its contract is: (a) a
  `target_url` (the whole app, or a parameterized URL to seed the crawl) plus
  an optional `alert_name_pattern` that plays FR-LAB-11's "scope to the one
  thing under test" role at the *alert* level rather than the *parameter*
  level — leaving it unset opts into genuine unscoped whole-app "safety net"
  mode (any alert at/above `risk_threshold` counts), which is coarser and
  noisier by design and not the default a caller confirming one cell's class
  should reach for; (b) ZAP's own Automation Framework
  (`zap.sh -cmd -autorun <plan>`) is invoked as a **single bounded subprocess
  call** (never a `-daemon` + REST-API-polling design — see the spike for why
  that was rejected as unneeded complexity for this use case), reusing the
  same loopback-only enforcement, typed-error-not-raw-exception, and
  bounded-timeout×bounded-attempt safety valve as FR-LAB-11's tools;
  (c) the verdict is always derived from parsing the Automation Framework's
  own structured JSON report (`traditional-json-plus` template) against the
  caller's declared scope — **never from ZAP's own process exit code**, which
  reflects ZAP's opaque, unscoped policy and would conflate the class under
  test with routine header/info-disclosure noise present on almost any
  target; (d) each invocation gets its own isolated, temporary ZAP home/
  report directory (cleaned up afterward unless the caller supplies its own),
  so no invocation can be misled by another's stale state; (e) same
  fail-closed three-outcome verdict contract as FR-LAB-11
  (`confirmed_vulnerable | confirmed_secure | inconclusive`) — a timeout,
  crash, missing/unreadable report, or a stale pre-existing report file is
  always `inconclusive`, never guessed as secure. (`CR-LAB-0001`
  tool-mapping table, `docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md`,
  `CC-LAB-0021`)
- **FR-LAB-21** (Lab track, Phase 0/1 foundation; the measurement half — the gating half
  it originally deferred is now **FR-LAB-43**, `CC-LAB-0045`)
  `fuzzlab.labgen.leakage_probe.probe_leakage()` detects whether a
  corpus's non-payload metadata (status code, response length, header count, latency,
  param-name length, path depth, content-type — a closed allowlist) statistically leaks
  the vulnerability label, via a deliberately weak classifier, `StratifiedGroupKFold`
  grouped by generating-rule ID (never a random split), and a permutation-null AUC
  threshold (not a fixed constant). Per-class feature exclusions (e.g. `latency_ms` for
  time-based-blind-SQLi/race-condition classes, where timing *is* the signal) each carry
  a written justification and are always reported, never silently applied. Requires the
  optional `labgen` extras (`scikit-learn`, `numpy`); not imported eagerly by
  `fuzzlab.labgen.__init__`, so the rest of the package has no hard dependency on it.
  `probe_leakage()` itself still **never raises on a leaky result** — it measures and
  returns; the raising build gate built on top of it is `run_leakage_gate()`, specified
  by FR-LAB-43 (this supersedes this requirement's original "not wired into any build
  gate — full build-gating starts once real variation exists (Phase 1)", which was
  `docs/LAB_PHASE_0_PLAN.md` T-LAB0.11's Phase-1 condition and has now been met).
  (`docs/LAB_PHASE_0_PLAN.md`
  T-LAB0.11, `CC-LAB-0023`)
- **FR-LAB-22** (Lab track, Phase 0) A secret-scanner build gate, separate
  from and complementary to the FR-LAB-15 name-leak gate, runs **Gitleaks**
  (MIT, `--no-git`) against the generated lab output tree via
  `fuzzlab.labgen.secret_scanner.scan_tree_for_secrets`, using a project
  `.gitleaks.toml` (repo root) that extends Gitleaks' default ruleset with
  one allowlist for seeded fake/example credentials the generator may
  legitimately emit as vulnerable-code content (e.g. a hardcoded fake DB
  password demonstrating CWE-798) — such values must carry an explicit
  case-insensitive marker (`FAKE`/`EXAMPLE`/`PLACEHOLDER`/`NOTREAL`/
  `CHANGEME`) to be allowlisted; an unmarked secret is still caught. Not
  TruffleHog: its live-credential-verification differentiator is noise
  against seeded fake credentials and an unwanted outbound call from a
  loopback-only project's build. Validated against a should-flag/
  should-not-flag fixture corpus (real-shaped AWS/Stripe/PEM-key secrets vs.
  marked-fake and clean content) run against the real binary
  (skip-guarded to when it's on PATH, per PA-0005), plus injected-runner
  tests proving the gate fails the build on a scanner crash (an unexpected
  exit code, an exit-1-with-empty-report inconsistency, or a malformed
  report) — never silently treated as a clean pass, matching FR-LAB-15's own
  fail-on-crash rule. Should-flag fixtures assemble their secret literals from
  string fragments at test-run time rather than as one contiguous literal in
  the test source, so GitHub's own push-protection secret scanning does not
  reject a commit containing the fixture file (an earlier version did; see
  `ERROR_LOG.md`) — Gitleaks' own detection, which scans the fully-assembled
  bytes at test time, is unaffected. (NFR-LAB-no-secret-leak,
  `docs/LAB_PHASE_0_PLAN.md` T-LAB0.6, `CC-LAB-0024`)
- **FR-LAB-23** (Lab track, minimal-pair invariant pulled forward from Phase 1)
  `fuzzlab.labgen.minimal_pair.check_minimal_pair()` asserts a cell's rendered
  vulnerable/secure `EmittedFiles` differ only within the declared
  transform/sink region (`CR-LAB-0001` §3, `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`
  steps 5/6): it parses the `// Module composition: a -> b -> c` provenance
  comment a module-composition emitter writes, classifies each named position
  by its module's own registered category, and independently cross-checks the
  empirically differing content region via a longest-common-prefix/suffix
  trim — catching an unrelated identifier rename that leaves the composition
  comment unchanged (the Juliet-style failure mode the playbook itself cites),
  not just a declared-region mismatch. `check_identifier_stability()`
  separately asserts every declared function/handler name is byte-identical
  across twins. Raises `MinimalPairViolation` on an actual invariant
  violation or the base `MinimalPairError` when the check cannot be evaluated
  at all (no composition comment, or an unregistered module name) — never a
  silent pass. Standalone and offline: reads (never renders or modifies)
  `fuzzlab.labgen.emitter`'s types and `fuzzlab.labgen.modules`' registries.
  Not yet wired into a build gate/CLI. Explicitly out of scope: unequal-length
  composition sequences between twins and non-PHP identifier extraction — both
  documented limitations, not silently mishandled. (`CR-LAB-0001` §3,
  `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`, `CC-LAB-0025`)
- **FR-LAB-24** (Lab track, mandatory once multi-stack — Phase 3) The
  fingerprint-independence build gate, `fuzzlab.labgen.fingerprint_gate`,
  guards against a stack becoming a de facto proxy for a vulnerability class
  or verdict (`CR-LAB-0001` §3's "every Flask cell is SSTI" failure mode).
  Schema-independent — operates on plain `{stack, vuln_class, verdict}`
  mappings, never `fuzzlab.labgen.schema`. Two independent, both-mandatory
  checks: (1) deterministic coverage (`check_min_stacks_per_class`/
  `check_min_classes_per_stack`, canonical defaults: every class on >= 2
  stacks, every stack carrying >= 3 classes); (2) a chi-square test of
  independence (`scipy.stats.chi2_contingency`) between stack and
  vuln_class/verdict — required because coverage alone can pass on a corpus
  that is still strongly, statistically confounded. `run_fingerprint_gate()`
  raises one `FingerprintIndependenceError` listing every violation found, or
  returns a `FingerprintGateReport`. Requires the optional `labgen-stats`
  extra (`scipy`), imported lazily; a missing install raises a typed
  `MissingStatsDependencyError`, never a raw `ImportError`. Not yet wired
  into a build gate/CLI — there is no real multi-stack corpus to run it
  against until Phase 3. (`CR-LAB-0001` §3/§4, `CC-LAB-0026`)
- **FR-LAB-25** (Lab track, T-LAB0.7) A stack-agnostic, tiered conformance suite
  (`fuzzlab.labgen.conformance`) any emitter must pass for every `(class,
  sink_context)` it declares support for, structured fastest-first: **Tier 0**
  (lint + minimal-pair diff, fully offline) and **Tier 3** (whole-lab
  regeneration, byte-diffed across a full manifest, fully offline) are real,
  exercised checks; **Tier 1** (in-process functional/security assertion) and
  **Tier 2** (the full container-based oracle — the only tier that actually
  confirms a label) are honestly-labeled `[design]` interfaces requiring a
  real app/DB/oracle this offline session cannot provide, and both raise
  `OnHostRequiredError` rather than silently no-op-passing without one. A
  Tier-0/1 pass is never recorded as oracle confirmation — only a real Tier-2
  run is. Each `(vuln_class, sink_context.family)` shape also carries a
  `static_precheck: informative | uninformative` flag
  (`fuzzlab.labgen.conformance.static_precheck`, `CR-LAB-0001` Addendum C
  point 4) so a static/taint-style checker's clean scan on a shape it is
  structurally blind to (e.g. identifier-position SQL injection) is never
  mistaken for confirmation. (`docs/LAB_PHASE_0_PLAN.md` T-LAB0.7,
  `CR-LAB-0001` Addendum C, `CC-LAB-0027`)
- **FR-LAB-26** (Lab track, Addendum E, Spike 004) A second, independent tool-oracle
  wrapper, `fuzzlab.labgen.nuclei_oracle` (kept out of `oracle_wrapper.py` deliberately
  — see `CC-LAB-0028`), covers **Nuclei** for **path traversal / local file inclusion
  only**. Unlike FR-LAB-11's per-parameter contract (sqlmap/commix/SSTImap), Nuclei has
  no auto-detection against a declared parameter — it matches hand-authored YAML
  templates — so the oracle is the bundled template
  (`lab/nuclei-templates/path-traversal-etc-passwd.yaml`) plus this wrapper together.
  `run_path_traversal_oracle(PathTraversalOracleRequest(...))` scopes the template to a
  declared `(endpoint_path, param_name)` pair via Nuclei's own `-var` template-variable
  mechanism and returns the same fail-closed three-outcome verdict contract as FR-LAB-11
  (`confirmed_vulnerable | confirmed_secure | inconclusive`) as an independent type,
  reusing only `oracle_wrapper`'s generic `assert_loopback`/`locate_tool` safety
  primitives. Because Nuclei has no dedicated "not vulnerable" textual marker (unlike
  sqlmap/commix/SSTImap), a clean scan and a scan against an unreachable target are
  otherwise indistinguishable on stdout/exit-code alone — the wrapper independently
  checks Nuclei's own stderr diagnostics for a host-unreachable signal before ever
  returning `confirmed_secure`, and never passes `-silent` (which would suppress that
  signal). XXE, open redirect, and known-CVE templates remain unintegrated — a separate,
  larger undertaking. (`CR-LAB-0001` tool-mapping table,
  `docs/spikes/SPIKE-004-nuclei-vs-dvwa.md`, `CC-LAB-0028`)
- **FR-LAB-28** (Lab track, T-LAB0.9, `CR-LAB-0001` Addendum B) A permanent
  regression/additive-only build gate, `fuzzlab.labgen.regression_gate`, diffs a
  candidate ground-truth snapshot (normally the generator's freshly emitted output)
  against a baseline (normally the hand-authored `lab/ground-truth/`) by `case_id` and
  fails loud (`RegressionGateError`, naming every violation) if any case present in the
  baseline is missing from the candidate, or has changed page (`url`) or verdict
  (`expected_vulnerable`) — additive growth (new case IDs) always passes. This is the
  mechanical enforcement of "never reduce functionality"
  (`docs/LAB_IMPLEMENTATION_PLAN.md` section 1.1). It also required extending
  `fuzzlab.labels.contract.Case` with `primary_endpoint`/`primary_role`/
  `related_endpoints`/`flow_variant`, the multi-artifact (Juliet/SARIF-shaped)
  ground-truth fields Addendum B resolved: a cell whose vulnerability spans more than
  one endpoint stays one row/case, naming its primary location (where the untrusted
  value reaches the dangerous operation) plus any `related_endpoints`
  (`{endpoint, role}`, role one of `source | propagator | sanitizer | sink`) and a
  `flow_variant` (`direct | same_file_helper | cross_file | stored_second_order |
  cross_service`). All four fields are additive/defaulted (`flow_variant` defaults
  `"direct"`, the rest default empty/`None`) so every pre-existing single-location case
  is unaffected; a FUZZ-consumer sweep across `fuzzlab/harness/` and `fuzzlab/greybox/`
  (done as part of this same task, not deferred) confirmed no consumer assumes exactly
  one location per case in a way these fields would violate.
  (`docs/LAB_IMPLEMENTATION_PLAN.md` section 1.1, `CR-LAB-0001` Addendum B, `CC-LAB-0030`)
- **FR-LAB-27** (Lab track, Phase 2, `CR-LAB-0001` §8, L-P2.1) An identity/ownership
  graph, `lab/identities/identities.yaml` (schema `lab/schemas/identities.schema.json`),
  declares named test identities (`id`, `role`), the resources they own
  (`resource_id`, `owner`, `cell_ids`), and `authz_expectations` connecting an
  accessing identity to a target resource and a binary `expected_outcome`
  (`allowed | denied`, D20's binary-verdict convention) per manifest cell. Loaded by
  `fuzzlab.labgen.identity.load_identities(path) -> IdentityGraph` (frozen
  `Identity`/`Resource`/`AuthzExpectation` dataclasses plus lookup helpers), schema-
  validated the same way FR-LAB-1's manifest loader validates manifests, raising a
  typed `IdentityGraphError` for any schema violation, duplicate `identities[].id` /
  `resources[].resource_id`, or dangling reference (an `owner`, `accessing_identity`,
  or `target_resource` that does not resolve to a declared identity/resource) — never
  a raw `KeyError`/`jsonschema.ValidationError`. This is genuinely novel schema
  ground for the project (no external prior-art project declares static
  identity/ownership data this way; see `docs/LAB_IMPLEMENTATION_PLAN.md` §3.1).
  **Deliberately decoupled from the manifest/`Cell` IR the same way
  `lab/patterns/provenance.yaml` is decoupled from it (`CR-LAB-0001` Addendum A):**
  `fuzzlab.labgen.verdict` never imports `fuzzlab.labgen.identity` and carries no
  reference to this file's content — ownership/authz-expectation data is annotation
  feeding future test classes and audit tooling, not a verdict-engine input. Unlocks
  IDOR/BOLA *mechanically* only; the cells themselves stay deferred indefinitely per
  Addendum E. (`docs/LAB_IMPLEMENTATION_PLAN.md` §3.1, `CC-LAB-0029`)
- **FR-LAB-29** (Lab track, T-LAB2.1) *(Numbered `FR-LAB-29` rather than `FR-LAB-27` at
  merge time — this lane independently claimed `FR-LAB-27`, colliding with lane L-P2.1's
  identity/ownership requirement above; reconciled per this project's standing multi-lane
  policy: keep both entries' full content, renumber this later-landing one, fix its own
  `CC-LAB` cross-reference to `CC-LAB-0031` below.)* A manifest may declare an `axis_ranges` array
  (`lab/schemas/manifest.schema.json`'s `axis_range` shape) alongside, never instead of,
  its explicit `cells` array. Each block's `factors`/`strength`/`sub_models`/
  `constraints` are passed straight through to `fuzzlab.labgen.resolver.expand()`
  (FR-LAB-17); its `factors` keys are limited to a fixed, recognized axis-name set —
  `class`, `stack_profile`, `sink_context_family`, `transform`, `route_method`,
  `route_path` (`fuzzlab.labgen.schema.AXIS_RANGE_FACTOR_NAMES`, asserted in tests to
  match the schema's own allowlist one-for-one) — each placed into the matching `Cell`
  field of every generated row. Any `Cell` field not varied by a factor in a given block
  must be supplied as that block's own fixed value (`class`/`stack_profile`/`route`/
  `transform`/`sink_context`); a field with neither raises `ManifestError` rather than
  being silently defaulted. `sink_context_family`, when used as a factor, additionally
  requires the block's own `sink_context_neutralizations` map (family ->
  `required_neutralizations`), since that field is a function of the family, not an
  independent covering-array axis. Generated `cell_id`s are `<cell_id_prefix><4-digit
  1-based index>` in the resolver's own deterministic row order. `fuzzlab.labgen.schema.Manifest.from_dict()`
  expands every block (manifest order) and appends the results after any explicit
  `cells`, before the existing duplicate-`cell_id` check runs over the combined list. A
  manifest with no `axis_ranges` (today's format) loads byte-for-byte identically to
  before this requirement existed — regression-tested against both
  `lab/manifests/example_phase0_scaffold.yaml` and
  `lab/manifests/phase0_real_pages_sample.yaml`. No change to
  `fuzzlab.labgen.emitter`/`verdict` — both consume the same `Cell` IR regardless of
  which manifest path produced it. (`docs/LAB_IMPLEMENTATION_PLAN.md` §2.1, T-LAB2.1,
  `CC-LAB-0031`)
- **FR-LAB-30** (Lab track, §2.2, L-P1.2a) *(Numbered `FR-LAB-30` rather than `FR-LAB-27`
  at merge time — this lane independently claimed `FR-LAB-27`, colliding with lane
  L-P2.1's identity/ownership requirement above; reconciled per this project's standing
  multi-lane policy: keep both entries' full content, renumber this later-landing one,
  fix its own `CC-LAB` cross-references to `CC-LAB-0032` below.)* A third, independent
  oracle, `fuzzlab.labgen.identifier_sqli_oracle` (kept out of `oracle_wrapper.py`/
  `nuclei_oracle.py` deliberately — see `CC-LAB-0032`), covers
  **identifier/alias/connector-position SQL injection** (injection into a
  column/table identifier or JOIN alias, not an ordinary literal value) — a class a
  real sqlmap spot-check (documented in `CC-LAB-0029` and the module's own docstring)
  confirmed sqlmap does not reliably detect, since none of its payload templates
  express "substitute a different real identifier and diff the response," only
  "inject boolean/comparison syntax or a comment." `run_identifier_sqli_oracle
  (IdentifierSqliOracleRequest(...))` fires a healthy-baseline probe plus a
  boolean-differential TRUE/FALSE probe pair
  (`(CASE WHEN (<condition>) THEN <column_a> ELSE <column_b> END)` substituted whole
  into the declared parameter) and classifies by diffing either the response bodies
  (`DifferentialMode.RESPONSE_DIFF`, the default) or elapsed time
  (`DifferentialMode.TIMING_BLIND`, gating a `SLEEP()` call behind the same CASE-WHEN
  for endpoints whose body never reveals row-level differences), returning the same
  fail-closed three-outcome verdict contract as FR-LAB-11/FR-LAB-26
  (`confirmed_vulnerable | confirmed_secure | inconclusive`) as an independent
  `IdentifierSqliVerdict` type. DBMS phrasing is dialect-pluggable via a small
  `_DialectPhrasing` registry (`SqlDialect.MYSQL` implemented; `POSTGRESQL`/`SQLITE`
  named in the enum, raising `DialectNotImplementedError` rather than guessing their
  syntax, so adding either later is an additive registry entry, not a rewrite).
  Reuses only `oracle_wrapper.assert_loopback` directly — this oracle fires HTTP
  requests via an injected `HttpRunner`, never a subprocess, so it has no textual
  need for `locate_tool`/`ToolNotFoundError`. Extends PA-0025's fail-closed doctrine
  (verify the target was actually reached before ever inferring "secure" from an
  absence of difference) to this HTTP-direct oracle: a healthy baseline probe is
  required before any verdict, and two differential probes that error out
  identically (the real allowlist-rejection failure mode the spot-check produced)
  are `inconclusive`, never `confirmed_secure`. (`docs/LAB_IMPLEMENTATION_PLAN.md`
  §2.2, `CC-LAB-0032`)
- **FR-LAB-31** (Lab track, §3.2, lane L-P2.2) *(Numbered `FR-LAB-31` rather than
  `FR-LAB-27` at merge time — this lane independently claimed `FR-LAB-27`, colliding
  with lane L-P2.1's identity/ownership requirement above; reconciled per this
  project's standing multi-lane policy: keep both entries' full content, renumber this
  later-landing one, fix its own `CC-LAB` cross-reference to `CC-LAB-0033` below.)* A
  small LAB-owned session helper,
  `fuzzlab.labgen.identity_session.IdentitySessionStore`, holds one cookie jar per
  named test identity (from `identities.yaml` / `fuzzlab.labgen.identity`, FR-LAB-9's
  sibling identity-and-ownership schema — accepted duck-typed via a local
  `IdentityLike` fallback until that lane merges) so build-time oracle confirmation of
  stored/second-order cells (§3.3's `sink_endpoint`, a concurrent, not-yet-landed
lane) can submit a payload as
  one known identity and observe the sink under another. `login(identity_id) ->
  Session` logs in (replacing, never duplicating, that identity's jar entry on a
  second call); `refresh_session_for(identity_id)` returns a callable of exactly
  FR-LAB-11's `SessionRefresh` shape (`Callable[[], Mapping[str, str]]`), so it slots
  directly into any `oracle_wrapper.*OracleRequest.refresh_session` field, mirroring
  that convention rather than inventing a new one. Deliberately **not** the toolkit's
  separate Session-manager component (a different roadmap track built for adversarial
  tools against an unknown target, with re-auth-on-expiry, JWT handling, and
  auto-exclusion of auth endpoints): this helper only ever talks to identities the
  generator itself declared, and none of re-auth/JWT/auto-exclusion/unknown-target
  defenses are in scope here. (`CC-LAB-0033`)
- **FR-LAB-32** (Lab track, T-LAB0.10) *(Numbered `FR-LAB-32` rather than `FR-LAB-27`
  at merge time — this lane independently claimed `FR-LAB-27`, colliding with lane
  L-P2.1's identity/ownership requirement above; reconciled per this project's
  standing multi-lane policy: keep both entries' full content, renumber this
  later-landing one, fix its own `CC-LAB` cross-reference to `CC-LAB-0034` below.
  The resolver gap named below closed at merge time (transparent, no CLI change
  needed); the regression-gate gap remains genuinely open — see `CC-LAB-0034`'s
  updated Deliverables.)* A
  `fuzzlab lab-generate --manifest <path>
  --out <dir> [--emitter NAME] [--check]` CLI (`fuzzlab.labgen.cli`), dispatched
  from `fuzzlab/cli.py` following the same thin-subcommand-branch convention every
  other `fuzzlab <command>` already uses. Loads a manifest (`fuzzlab.labgen.schema
  .load_manifest`) and renders every cell the selected emitter declares support
  for; the emitter is looked up by name in a small registry
  (`EMITTER_REGISTRY: dict[str, type[Emitter]]`, default `"php_current"`) rather
  than hardcoded, so a future emitter (Phase 3) needs no CLI change to become
  selectable. `--check` runs the offline build-gate suite this component already
  built against the rendered output, collecting every failure rather than
  stopping at the first: the name-leak scanner (FR-LAB-15), the secret scanner
  (FR-LAB-22), a real-emitter regenerate-and-diff determinism check
  (`conformance.tier3.regenerate_and_diff_emitter`), the minimal-pair checker
  (FR-LAB-23) — paired generically against each cell's own transform-emptied twin
  (`dataclasses.replace(cell, transform=Pipeline(()))`), so it applies to any
  manifest, not only one that authors explicit vulnerable/secure twin cell pairs
  — and conformance Tier 0/Tier 3 (FR-LAB-25). Exits 1 and names every failing
  gate on a `--check` failure, 0 on a clean pass. Axis-range manifest expansion
  (`resolver.py`, FR-LAB-29) is transparent to this CLI — `Manifest.from_dict()`
  expands `axis_ranges` internally, so no separate resolver-wiring hook was ever
  needed here. Two things this CLI still does **not** do, flagged rather than
  silently built or dropped: it does not run the regression/additive-only gate
  (FR-LAB-28) — that needs a Cell-to-GroundTruth converter (deriving
  `labels.json`/`injection-points.json`/`expectedresults.csv`-shaped data from a
  rendered manifest) that does not exist yet, a genuine separate follow-up, left
  as a `# TODO(L-P0.9-integration)` in `run_checks()`. *(Updated to current truth: this
  requirement previously also said `fingerprint_gate.py` was deliberately not wired.
  Both statistical gates are now required `--check` steps — the
  fingerprint-independence gate as step 8 (FR-LAB-38, `CC-LAB-0040`) and the metadata
  leakage gate as step 9 (FR-LAB-43, `CC-LAB-0045`) — each skipping with an explicit
  printed reason on a corpus its check is ill-defined or unmeasurable for, rather than
  not being wired at all.)*
  (`docs/LAB_IMPLEMENTATION_PLAN.md` §1.2 T-LAB0.10, `CC-LAB-0034`)
- **FR-LAB-33** (Lab track, Phase 3, L-P3.1, Tier-A depth) *(Numbered `FR-LAB-33`
  rather than `FR-LAB-27` at merge time — this lane independently claimed
  `FR-LAB-27`, colliding with lane L-P2.1's identity/ownership requirement above;
  reconciled per this project's standing multi-lane policy: keep both entries'
  full content, renumber this later-landing one, fix its own `CC-LAB`
  cross-reference to `CC-LAB-0035` below.)* A second emitter,
  `fuzzlab.labgen.emitters.node_express`, implements
  `fuzzlab.labgen.emitter.Emitter` for Node/Express via its own,
  self-contained module-composition inventory
  (`fuzzlab.labgen.emitters.node_express.modules` — the same source/
  transform/sink/complexity category shape as `php_current`'s, ported to
  JS, not sharing `fuzzlab.labgen.modules`'s registries). Per the pacing
  decision in `docs/LAB_IMPLEMENTATION_PLAN.md` §4 ("stack 1 to full depth,
  stacks 2-3 to Tier-A-only depth"), it supports exactly the three
  well-documented, value-context shapes `php_current` also proves —
  `sqli`/`sql_numeric_literal`, `sqli`/`sql_string_literal`,
  `xss`/`html_body` — and declares every other `(vuln_class,
  sink_context.family)` pair unsupported via `supports()`, never raising.
  Introduces this component's first `StackEnv`
  (`fuzzlab.labgen.emitters.node_express.stack_env.NODE_EXPRESS_STACK_ENV`,
  `CR-LAB-0001` Addendum D's schema: `language`, `framework`,
  `framework_version`, a digest-pinned `base_image`, `workdir`,
  `entrypoint_cmd`, `is_multi_file`, `scaffold_files`, `accumulators`,
  `file_roles`) and this component's first `route`-category accumulator
  module: `NodeExpressEmitter.render_route_accumulator(cells)` builds
  `app.js`'s route-registration lines from the **whole** supported-cell set
  at once, sorted by `cell_id` at render time — never by append/iteration
  order — so adding one cell cannot reshuffle the file (the whole-lab
  regeneration determinism gate). This is deliberately **not** part of
  `Emitter.render(cell)` (the ABC's per-cell contract, unmodified): a
  routed, multi-file emitter's accumulator has a genuinely different
  cardinality (fed by every cell, not one), which a single `render(cell)`
  call cannot express — `render()` returns only the per-cell controller
  file, keeping `fuzzlab.labgen.conformance.tier3.render_whole_sample`'s
  "no two cells emit the same path" invariant meaningful. Any future routed
  emitter (e.g. Laravel's `routes/web.php`, L-P3.3a) is expected to follow
  the same split. Ships a real, npm-registry-resolved `package-lock.json`
  (`express@4.22.3`, `mysql2@3.24.4`) and a digest-pinned `Dockerfile`
  (Node 22 LTS "Jod", `NODE_ENV=production` set per the framework-debug-page
  research in `docs/LAB_IMPLEMENTATION_PLAN.md` §4) as per-stack
  `scaffold_files`. A CycloneDX SBOM was not generated — `syft` is not
  installed in this build environment; the intended command
  (`syft dir:fuzzlab/labgen/emitters/node_express/scaffold
  -o cyclonedx-json`) is documented as a follow-up rather than skipped
  silently. Proven against `lab/manifests/phase3_node_express_sample.yaml`
  via Tier 0 (`node --check`, skip-guarded when `node` isn't on the build
  host, mirroring FR-LAB-25's `php_available()`/`lint_php` convention) and
  Tier 3 (whole-manifest regenerate-and-diff, both per-cell controllers via
  the shared `conformance.tier3` module and the accumulator separately,
  since its cardinality doesn't fit that module's per-cell harness).
  (`CR-LAB-0001` Addendum D, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.1,
  `CC-LAB-0035`)
- **FR-LAB-34** (Lab track, Phase 3, Tier-A depth) *(Numbered `FR-LAB-34` rather
  than `FR-LAB-27` at merge time — this lane independently claimed `FR-LAB-27`,
  colliding with lane L-P2.1's identity/ownership requirement above; reconciled
  per this project's standing multi-lane policy: keep both entries' full
  content, renumber this later-landing one, fix its own `CC-LAB` cross-reference
  to `CC-LAB-0036` below and its own §5 interfaces bullet's self-reference.)* A
  second module-composition emitter, `fuzzlab.labgen.emitters.python_fastapi`
  (`PythonFastapiEmitter`),
  implements the `Emitter` ABC for FastAPI + SQLAlchemy + Jinja2, covering the
  same three Tier-A shapes `php_current` proves (`sql_numeric_literal`/
  `sql_string_literal` SQLi, `html_body` XSS) — deliberately not
  identifier/alias/connector-position SQLi or escaping-context-mismatch XSS
  (deferred per the Phase 3 stack-pacing decision, `CR-LAB-0001` Addendum C).
  Its own module-composition system (`SOURCES`/`TRANSFORMS`/`SINKS`/
  `COMPLEXITIES` registries + Jinja2 templates under
  `fuzzlab/labgen/emitters/python_fastapi/templates/`) is a fully independent
  implementation, not an extension of `fuzzlab.labgen.modules` — reuses only
  the stack-agnostic op-name vocabulary (`identity`/`param_bind`/
  `html_entity_escape`) `lab/safety_matrix.yaml` and `verdict()` already define,
  so no new safety-matrix entries were needed. Instead of a `route` accumulator
  module (`CR-LAB-0001` Addendum D's default multi-file-routing shape), this
  emitter uses a one-time **static discovery scaffold**
  (`app/main.py`, `pkgutil.iter_modules()`/`importlib` over a `routers/`
  package, sorted by module name) rendered once per build via
  `STACK_ENV.scaffold_files`/`render_scaffold_files()` — `render(cell)` itself
  returns exactly one per-cell router file. That same scaffold constructs
  `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`, a correctness
  requirement (not a follow-up): FastAPI serves `/docs`/`/redoc`/`/openapi.json`
  by default regardless of any debug flag, unlike Laravel/Express, which have a
  single "production mode" flag that also covers this. A package-local
  `StackEnv` dataclass (Addendum D's schema) carries a digest-pinned base image
  (`python:3.12-slim-bookworm@sha256:...`, fetched live against the Docker Hub
  registry API) and an exact-pinned `requirements.txt` lockfile for the
  generated app's own dependencies — `fuzzlab.labgen.schema` has no shared
  `StackEnv` yet (a future cross-cutting task once more Phase-3 stack lanes
  land and can agree a shared location; `schema.py` is treated as a
  "shared read-only file" no single stack lane edits unilaterally). Passes the
  Tier 0/Tier 3 conformance suite (FR-LAB-25) against
  `lab/manifests/phase3_python_fastapi_sample.yaml`; Tier 0's lint step gained a
  sibling to `lint_php`/`php_available` (`lint_python`/`python_available`,
  `python -m py_compile`, same skip-guarded convention), and its minimal-pair
  check uses `fuzzlab.labgen.minimal_pair`'s naive fallback directly rather than
  its real (PHP-comment-syntax-specific) checker, per that module's own
  documented, not-yet-attempted non-PHP extension point. (`CR-LAB-0001` Addenda
  C/D, `docs/LAB_IMPLEMENTATION_PLAN.md` Phase 3 §4.2/L-P3.2, `CC-LAB-0036`)
- **FR-LAB-35** (Lab track, `CR-LAB-0001` Addendum D, lane L-P3.3a — foundation only)
  *(Numbered `FR-LAB-35` rather than `FR-LAB-27` at merge time — this lane
  independently claimed `FR-LAB-27`, colliding with lane L-P2.1's
  identity/ownership requirement above; reconciled per this project's standing
  multi-lane policy: keep both entries' full content, renumber this
  later-landing one, fix its own `CC-LAB` cross-reference to `CC-LAB-0037`
  below.)* A second PHP emitter, `fuzzlab.labgen.emitters.php_laravel`, targeting
  Laravel/Eloquent/Blade idiom (distinct from `php_current`'s plain-PHP idiom;
  neither reuses the other's modules). Introduces `StackEnv`
  (`fuzzlab.labgen.emitters.php_laravel.stack_env`), the per-stack record
  Addendum D's multi-file-routing extension adds: `language`, `framework`,
  a pinned `framework_version`, a digest-pinned `base_image` (never a bare
  mutable tag), `is_multi_file`, `scaffold_files` (rendered once per build,
  never per cell), `accumulators`, and `file_roles`. The scaffold's generated
  `.env` **forces `APP_DEBUG=false`/`APP_ENV=production`** — a correctness
  requirement, not optional: Laravel's Ignition debug page discloses full
  stack traces plus every environment variable (DB/API credentials included)
  when debug mode is on, which would otherwise contaminate every cell's
  single, labeled vulnerability class with an unlabeled, unintended one.
  Also introduces the `route` module category Addendum D adds (cardinality
  `accumulator`, one fragment per cell merged into `routes/web.php`):
  `fuzzlab.labgen.emitters.php_laravel.route_accumulator.RouteAccumulator`
  **always sorts fragments by cell ID at render time**, never by
  append/iteration order, so adding one cell never reshuffles the file (the
  invariant Addendum D calls out as the concrete trap for this category).
  `LaravelEmitter` itself supports exactly one shape in this lane
  (`sqli`/`sql_numeric_literal`) — the full module inventory (harder
  identifier/alias/connector-position SQLi and escaping-context-mismatch
  XSS shapes, ported from `php_current`'s Phase-1 work) and the
  `puppy-fort-factory/` migration are explicitly out of scope here, tracked
  as lanes L-P3.3b and L-P3.3c respectively (§4.3 steps 2 and 6). Proven
  against a new, deliberately minimal `lab/manifests/phase3_php_laravel_sample.yaml`
  via the existing stack-agnostic conformance suite (FR-LAB-25): Tier 0
  (`php -l`) and Tier 3 (whole-lab regeneration via
  `fuzzlab.labgen.conformance.tier3.regenerate_and_diff_emitter`) both pass
  for real; the accumulator file itself is assembled and determinism-checked
  by this lane's own `assemble_routes_file()` rather than through Tier 3's
  shared `render_whole_sample` (which does not yet support more than one
  cell targeting the same output path — a documented, not silently
  worked-around, gap for a future accumulator-bearing stack lane to close).
  A real `composer.lock` (74 packages) was generated against Packagist for
  the stack's base dependency set; a CycloneDX SBOM via `syft` was not
  generated (`syft` unavailable on this build host — the intended command is
  documented in `fuzzlab/labgen/emitters/php_laravel/stack/README.md`).
  (`docs/LAB_IMPLEMENTATION_PLAN.md` §4.3 steps 1/3/4/5, `CR-LAB-0001`
  Addendum D, `CC-LAB-0037`)
- **FR-LAB-36** (Lab track, L-P2.3) *(Numbered `FR-LAB-36` rather than `FR-LAB-27` at
  merge time — this lane independently claimed `FR-LAB-27`, colliding with lane
  L-P2.1's identity/ownership requirement above; reconciled per this project's
  standing multi-lane policy: keep both entries' full content, renumber this
  later-landing one, fix its own `CC-LAB` cross-references to `CC-LAB-0038` below,
  and update its own "still requires a follow-up" sentence, closed at merge time —
  see `CC-LAB-0038`'s merge-time addendum.)* `fuzzlab.labgen.schema.Cell` carries an optional
  `sink_endpoint: Route | None = None`, distinct from `route` (the injection point),
  naming where a stored/second-order cell's payload actually reaches its sink and
  executes — e.g. a profile-bio write endpoint (`route`) whose payload executes on a
  separate profile-view page (`sink_endpoint`). `None` (the default) means
  same-endpoint, matching every cell in today's corpus unchanged. This is
  render/tracking metadata only, the same category as `identity.py`'s data —
  `fuzzlab.labgen.verdict.verdict()`'s derivation never reads it, and a cell's
  verdict depends only on `(transform, sink_context, safety_matrix)` as before
  (D20). `fuzzlab.labgen.emitters.php_current.PhpCurrentEmitter.render()` resolves
  its page profile (and its `// Real page:` comment) from `sink_endpoint` when set,
  falling back to `route` otherwise, since this emitter renders the sink side of a
  cell (the existing `read_stored_field` source module, FR-LAB-18 / `CC-LAB-0022`,
  already documented this "sink side only" scope before `sink_endpoint` existed to
  express it). `lab/schemas/manifest.schema.json` now declares `sink_endpoint` on
  the cell definition (added at merge time — see `CC-LAB-0038`'s merge-time
  addendum), mirroring `route`'s own `$ref` shape, so a manifest can declare it
  through the full validated `load_manifest()` path, not only via
  `Cell.from_dict`/`Manifest.from_dict(..., validate=False)`.
  (`docs/LAB_IMPLEMENTATION_PLAN.md` §3.3, `CC-LAB-0038`)
- **FR-LAB-37** (Lab track, §3.4, lane L-P2.4) *(Numbered `FR-LAB-37` rather than
  `FR-LAB-27` at merge time — this lane independently claimed `FR-LAB-27`, colliding
  with lane L-P2.1's identity/ownership requirement above; reconciled per this
  project's standing multi-lane policy: keep both entries' full content, renumber
  this later-landing one, fix its own `CC-LAB` cross-reference to `CC-LAB-0039`
  below.)* A parameter location/encoding axis:
  `fuzzlab.labgen.schema.ParamSpec` (`location` in `query | body | header | cookie |
  json`, `encoding` in `raw | url_encoded | double_url_encoded | base64`, both
  validated against `PARAM_LOCATIONS`/`PARAM_ENCODINGS`) as an optional `Cell.param`
  field, defaulting to `query`/`raw` so every cell omitting it (today's entire corpus)
  keeps its current meaning; `lab/schemas/manifest.schema.json` gained a matching
  optional `param` property on a manifest cell. Deliberately a `Cell`-level field, not
  folded into `SinkContext`: the axis never changes the `(transform, sink_context)`
  verdict-derivation contract `fuzzlab.labgen.verdict.verdict()` consumes — it changes
  only how a cell is rendered into a request and how the build-time oracle constructs
  its confirmation request — the same render/tracking-metadata category §3.3's
  (lane L-P2.3, not yet landed in this worktree at implementation time) proposed
  `sink_endpoint` field is framed as in the plan, i.e. not a verdict input. To
  exercise a non-`query`,
  non-`raw` cell against the FR-LAB-11 oracle contract, `fuzzlab.labgen.oracle_wrapper`
  gained: (1) `ParamLocation.COOKIE`/`.JSON` (query/body/header already existed) with
  new `_mark_cookie_param`/`_mark_json_param` marking helpers, since SSTImap's own `-P`
  sweep already supports a cookie category (`QBHC`) but the wrapper had no marker
  mechanism for it — JSON has no SSTImap-native `-P` category and shares `BODY`'s flag,
  marked via the JSON-aware helper instead of the pre-existing form-urlencoded one; (2)
  a new `Encoding` enum (`RAW | URL_ENCODED | DOUBLE_URL_ENCODED | BASE64`) and
  `_encode_marker()`, wired into `ServerSideTemplateInjectionOracleRequest`'s new
  `encoding` field and `_build_sstimap_argv`, which substitutes the *encoded* marker on
  the wire and tells SSTImap's `-M` to look for that same encoded form. Deliberately
  not added to `SqlInjectionOracleRequest`/`CommandInjectionOracleRequest`: those
  delegate parameter-selection to sqlmap's/commix's own `-p` flag rather than the
  wrapper's marker mechanism, so an `encoding` field there would be an unwired phantom
  axis value. Not yet wired as a `fuzzlab.labgen.resolver` axis (lane L-P1.1's
  per-cell axis-range/manifest mechanism had not landed in this worktree at
  implementation time) — a manifest lists `param.location`/`param.encoding` explicitly
  per cell today, same as every other Phase 0 axis before L-P1.1 lands. Not yet wired
  into `php_current`'s emitter (out of this task's scope; the emitter still renders
  every cell as if `param` were its `query`/`raw` default). (`docs/LAB_IMPLEMENTATION_PLAN.md`
  §3.4, `CC-LAB-0039`)
- **FR-LAB-38** (Lab track, §4.4, lane L-P3.4) The stack axis is carried end to end and
  the fingerprint-independence gate runs on every multi-stack build:
  1. **Ground-truth contract.** A `labels.json` case may carry an optional per-case
     `stack` string (`fuzzlab.labels.contract.Case.stack`, schema-validated,
     `minLength: 1` so an empty stack name fails closed) naming the stack profile its
     code belongs to — the same meaning as `fuzzlab.labgen.schema.Cell.stack_profile`
     / `CR-LAB-0001` §4's `stack_profile`. **Inline**, per the settled research decision
     in `docs/LAB_IMPLEMENTATION_PLAN.md` §4, not a separate analysis-only file. Optional
     and additive: a case omitting it loads as `None`, so the pre-multi-stack
     `lab/ground-truth/labels.json` round-trips unchanged and no scorer keys on it (it is
     analysis metadata, not part of `Case.key`). `Cell.stack_profile` itself already
     existed and is already required by `lab/schemas/manifest.schema.json`, populated by
     every sample manifest of all four emitters, usable as a covering-array factor axis
     (see the `axis_ranges` requirement above), and already an input to
     `fuzzlab.labgen.subseed`'s sub-seed derivation — so nothing was re-added there;
     §4.4's "add `stack` (or `stack_profile`) to `Cell`" instruction was already
     satisfied, and only the `labels.json` half was an actual gap.
  2. **Gate wiring.** `fuzzlab lab-generate --check` runs
     `fuzzlab.labgen.fingerprint_gate.run_fingerprint_gate` as a required step whenever —
     and only whenever — the loaded manifest's cells span at least
     `fuzzlab.labgen.cli.MIN_STACKS_FOR_FINGERPRINT_GATE` (2) distinct `stack_profile`
     values. `expected_classes`/`expected_stacks` are derived from that manifest's own
     cells (never placeholders); `min_stacks_per_class` is `CR-LAB-0001` §3/§4's canonical
     2; `min_classes_per_stack` is `min(3, <distinct classes in this corpus>)` — the
     canonical 3 as a *ceiling*, since a corpus whose whole class vocabulary is smaller
     cannot satisfy a flat 3 for any reason related to fingerprint leakage. For a
     single-stack manifest the step is skipped with an explicit printed reason (a
     one-stack corpus cannot place a class on two stacks and its chi-square contingency
     table is degenerate) — never a silent no-op and never a failure. The corpus records
     are built from **all** `manifest.cells`, not only the cells one emitter supports:
     fingerprint independence is a property of the authored corpus, and a multi-stack
     manifest is by construction not fully renderable by any single emitter. No `verdict`
     key is fed from the CLI, so the gate's stack↔verdict half is (per its own documented
     contract) skipped; deriving it needs the repo-relative safety matrix
     (`fuzzlab.labgen.verdict`), which no production code loads today — a known remaining
     deliverable, recorded in `CC-LAB-0040`, not an oversight.
     (`docs/LAB_IMPLEMENTATION_PLAN.md` §4.4, `CC-LAB-0040`)

- **FR-LAB-39** (Lab track, `docs/LAB_IMPLEMENTATION_PLAN.md` §2.4, lane L-P1.4)
  *(Numbered `FR-LAB-39` rather than `FR-LAB-38` at merge time — this lane independently
  claimed `FR-LAB-38`, colliding with lane L-P3.4's stack-axis requirement above;
  reconciled per this project's standing multi-lane policy: keep both entries' full
  content, renumber this later-landing one, fix its own `CC-LAB` cross-references to
  `CC-LAB-0041` below.)*
  Read-only corpus-analysis tooling over an already-built cell set,
  `fuzzlab.labgen.corpus_analysis` — three pieces sharing one concept, the
  *generating-rule group* a cell belongs to:
  1. **Near-duplicate definition + rate.** "Near-duplicate" for this corpus is an
     identical `DuplicateSignature` — `(vuln_class, sink_context.family,
     sorted(sink_context.required_neutralizations), transform-shape)` — **regardless
     of cell ID**, and also regardless of `route`, `sink_endpoint`, `param`, and
     `stack_profile`. `transform-shape` is the *ordered* op tuple, because
     `fuzzlab.labgen.verdict.verdict()` is order-sensitive over `Pipeline.ops`, so two
     cells whose pipelines differ only in order are genuinely different cells;
     `required_neutralizations` is order-*insensitive* (sorted) because it is a set of
     concerns, not a pipeline, and authoring order must not split one group in two.
     `duplication_report()` returns the signature count, the redundant-cell count, the
     rate, and every duplicate group's cell IDs. Informative: it raises nothing, and an
     empty corpus is a valid all-zero report.
  2. **Stratified, rule-grouped split.** `stratified_split()` returns a train/holdout
     `CorpusSplit` stratified by `vuln_class` and grouped by generating-rule ID, so no
     near-duplicate pair spans the split — true by construction, and re-checked as a
     post-condition that raises `CorpusSplitError` rather than being trusted. It
     **reuses** `fuzzlab.labgen.leakage_probe.grouped_cv()` (FR-LAB-8's own
     `StratifiedGroupKFold(shuffle=True)` construction, extracted into that one shared
     function for this purpose per PA-0003/PA-0021) rather than deriving a second
     grouping strategy. `fold` selects which of `n_splits` folds is the holdout, so the
     whole fold set is reachable (k-fold CV), not only one 1/k holdout. Fails loud with
     `CorpusSplitError` on fewer than two classes, on `n_splits` exceeding the
     generating-rule-group count, or on out-of-range `n_splits`/`fold`; with
     `MissingSplitDependencyError` (typed, never a raw `ImportError`) when scikit-learn
     is absent. Only this piece needs scikit-learn — (1) and (3) are pure Python.
  3. **Diversity report as a build ARTIFACT, never a gate.** `diversity_report()`
     returns class × transform × verdict counts plus class/transform/verdict/stack/
     sink-family marginals, and `corpus_report()`/`write_corpus_report()` bundle (1) and
     (3) into deterministic, key-sorted JSON (byte-stable, so the artifact itself cannot
     break NFR-LAB-reproducible). Explicitly distinct from FR-LAB-9's χ²-balance gate
     (`fingerprint_gate.py`): that gate asks "is stack↔class dependence significant —
     fail the build if so"; this only describes what is in the corpus. It carries no
     thresholds, states its own `gating` status in the artifact text, and never raises
     about the corpus's shape: a cell whose `(op, sink_family)` pair the safety matrix
     does not cover is recorded as `UNDERIVABLE_VERDICT` and **counted**
     (`n_underivable_verdicts`) rather than allowed to propagate `verdict()`'s
     by-design `SafetyMatrixError` into a build. The safety matrix is an explicit,
     optional argument — never loaded implicitly — so the report cannot silently derive
     verdicts under a different matrix than the corpus was built with; without one, the
     class × transform half is still fully usable.
  Generating-rule ID is derived from the signature (`generating_rule_id()`), because no
  `Cell` field records which rule produced a cell (`Cell` is deliberately untouched by
  this lane) and `cell_id` prefixes are per-manifest namespaces (`LABGEN-RP-`), too
  coarse to group by — every cell in a manifest would be one group, making a split
  impossible. Excluding `stack_profile` from the signature makes groups *larger*, which
  is the conservative direction for a split (it can only reduce train/holdout leakage);
  stack-vs-class balance remains FR-LAB-9's concern. If a future `Cell` gains a real
  `rule_id`, `generating_rule_id()` is the single place to change. Wired into
  `fuzzlab lab-generate` as `--corpus-report <path>`, on a code path independent of
  `--check` so an informative artifact can never fail a build.
  (`docs/LAB_IMPLEMENTATION_PLAN.md` §2.4, `CC-LAB-0041`)

- **FR-LAB-40** (Lab track, §3.5, lane L-P2.5) *(Numbered `FR-LAB-40` rather than the
  `FR-LAB-38` this lane claimed as "next free at authoring time" — by merge time, lanes
  L-P3.4 (`FR-LAB-38`) and L-P1.4 (`FR-LAB-39`) had already landed and taken the numbers
  this lane also reached for. Reconciled per this project's standing multi-lane policy:
  keep this entry's full content, renumber it, fix its own `CC-LAB` cross-reference to
  `CC-LAB-0042` below.)* A `context_depth` axis on the
  **generator-input** IR: `fuzzlab.labgen.schema.Cell.context_depth` (a validated
  string, one of `CONTEXT_DEPTHS = direct | same_file_helper | cross_file |
  stored_second_order`, default `direct`) declaring how far a cell's tainted value
  travels from the injection point to the sink — the counterpart of the ground-truth
  `Case.flow_variant` field (FR-LAB-28), which *records* after the fact what
  `context_depth` *declares* before generation. The two vocabularies are deliberately
  identical, so `fuzzlab.labgen.schema.flow_variant_for(cell) -> str` is the single
  shared mapping between them (PA-0003/PA-0021) rather than a per-caller re-derivation;
  a test asserts every `CONTEXT_DEPTHS` level is accepted by
  `fuzzlab/labels/schemas/labels.schema.json`'s own `flow_variant` enum (PA-0001).
  `flow_variant_for()` has no production caller yet, and deliberately so: no
  Cell-to-GroundTruth converter exists (FR-LAB-32 records that gap as
  `# TODO(L-P0.9-integration)` in `fuzzlab.labgen.cli.run_checks`), and building a
  ground-truth emission pipeline speculatively is out of §3.5's scope — the converter,
  when built, calls this function instead of re-deriving the label.
  Addendum B's fifth level, `cross_service`, is **not** reachable and is listed
  separately as `UNREACHABLE_CONTEXT_DEPTHS`: declaring it raises `ManifestError`
  naming why (real cross-service wiring, which several single-service stack emitters do
  not by themselves provide) and naming the four levels that are reachable, rather than
  silently rendering something meaningless; `lab/schemas/manifest.schema.json` omits it
  from the `context_depth` enum too, so it also fails at validation time.
  `context_depth` and `sink_endpoint` (FR-LAB-36) are kept **biconditionally**
  consistent rather than duplicating each other: `stored_second_order` is by definition
  exactly the case where the payload executes on a different endpoint than the one it
  was submitted to, so that depth requires a `sink_endpoint` distinct from `route`, and
  a cell carrying such a `sink_endpoint` may not declare any other depth —
  `Cell.from_dict` *derives* `stored_second_order` when `context_depth` is omitted and
  a distinct `sink_endpoint` is declared, so every pre-`context_depth` stored cell stays
  valid and unchanged in meaning. Not a verdict input: a depth hop is a pure
  pass-through that neutralizes nothing, so `fuzzlab.labgen.verdict` never reads the
  field and a cell's verdict stays a function of `(transform, sink_context,
  safety_matrix)` alone (D20) at every depth. Wired as a covering-array axis
  (`AXIS_RANGE_FACTOR_NAMES` + the manifest schema's `axis_range.factors`, FR-LAB-29),
  with an optional block-level fixed `sink_endpoint` for a `stored_second_order` level;
  a fixed `sink_endpoint` on a block no level uses is rejected rather than silently
  dropped (PA-0010). Rendered by `php_current` via a new `depth` module category
  (`fuzzlab/labgen/modules/depths/`, registry `DEPTHS`: `passthrough_helper`,
  `helper_call`, `cross_file_require`) — its own category, never a `transform` op, since
  `transform` op names are the verdict-relevant vocabulary `verdict()` walks:
  `direct` renders today's inline body byte-identically; `same_file_helper` routes the
  value through a pass-through helper defined in the same file; `cross_file` renders the
  identical flow with the helper in a second emitted file (`role="helper"`, pulled in by
  `require_once`), so the two differ only in file placement — exactly the distinction the
  axis exists to measure; `stored_second_order` needs no fragment, its depth being
  expressed structurally by `sink_endpoint` routing the emitter to the sink page, where
  the value is read from storage rather than from the request. Other emitters
  (`node_express`, `python_fastapi`, `php_laravel`) are untouched and still render every
  cell as if `context_depth` were `direct`. (`docs/LAB_IMPLEMENTATION_PLAN.md` §3.5,
  `CC-LAB-0042`)

- **FR-LAB-41** *(L-P1.2b; numbered `FR-LAB-41` rather than the `FR-LAB-38` this lane
  claimed at authoring time — by merge time, lanes L-P3.4 (`FR-LAB-38`), L-P1.4
  (`FR-LAB-39`), and L-P2.5 (`FR-LAB-40`) had already landed and taken the numbers this
  lane also reached for; reconciled per this project's standing multi-lane policy — this
  affects nothing but the cross-references.)* The corpus's **harder shapes**
  (`docs/LAB_IMPLEMENTATION_PLAN.md`
  §2.2), in four parts:
  1. **Three new `sink_context.family` values**, each with additive `lab/safety_matrix.yaml`
     rows under the existing `version: 1` (new `(op, sink_family)` pairs only — no existing
     pair's meaning changes, so a corpus generated before they landed re-derives
     identically, and `fuzzlab.labgen.verdict.verdict()`'s derivation logic is unchanged):
     - `sql_identifier` — the tainted value **is** a column/table identifier (e.g.
       `ORDER BY $sort`), not a literal value;
     - `sql_join_alias` — a JOIN alias (a connector position, substituted more than once
       in one statement);
     - `url_javascript_scheme` — the value is inside a `javascript:` URL, i.e. an HTML
       attribute whose content is JavaScript source.
     Two new concern IDs: `sql_identifier_substitution` (an attacker chooses *which*
     identifier the query names, needing no syntax break at all) and `js_context_break`.
     Four new transform ops: `identifier_charset_filter` (a bare-identifier character
     allowlist — `partial`: blocks every syntax-break character and none of the real
     defect), `identifier_allowlist` (membership in a fixed list of real identifiers —
     the only transform that closes an identifier position), `url_scheme_allowlist`, and
     `attr_value_allowlist` (which gives the pre-existing `html_attribute_unquoted`
     family its first expressible SECURE twin). Two rows carry the shapes' whole point:
     `(param_bind, sql_identifier|sql_join_alias) -> no_effect` (no SQL dialect can bind
     an identifier placeholder, so the textbook fix is *inapplicable*, not omitted) and
     `(html_entity_escape, url_javascript_scheme) -> partial` (correct escaping, wrong
     context — VULNERABLE-but-harder, per D20, never a third verdict value).
  2. **`php_current` renders all four harder shapes** — `(sqli, sql_identifier)`,
     `(sqli, sql_join_alias)`, `(xss, url_javascript_scheme)` and
     `(xss, html_attribute_unquoted)` (the last of which had a safety-matrix row since
     Phase 0 but no module set, leaving `LABGEN-EX-0003` permanently skipped) — via eight
     new `fuzzlab.labgen.modules` fragments, and each shape's `static_precheck` flag is
     registered as `uninformative`. A page profile may now set `source_override` to select
     a non-default source module, since one `(class, family)` shape can be reached by two
     taint origins (a request parameter on one page, an already-stored field on another);
     this is render-only metadata and does not fork the verdict-relevant shape vocabulary.
  3. **A manifest exercising them**, `lab/manifests/phase1_harder_shapes_sample.yaml` (13
     cells, each shape as a no-transform / plausible-but-wrong-fix / context-correct-fix
     triple), passing `fuzzlab lab-generate --check` end to end, including Tier 0 (`php -l`)
     and Tier 3 (whole-sample byte-identical regeneration). These are illustrative new lab
     pages, not reproductions of real `puppy-fort-factory/` pages, and carry no
     `lab/ground-truth/` label.
  4. **A build-time security assertion for the identifier shapes**,
     `fuzzlab.labgen.identifier_sqli_assertion` (see §5), which runs lane L-P1.2a's
     `run_identifier_sqli_oracle` against a cell and fails closed unless its outcome
     matches the cell's **derived** verdict. (`CC-LAB-0043`)
- **FR-LAB-43** (Lab track, generator-build-time, §2.3, lane L-P1.3) The metadata
  leakage probe (FR-LAB-8's `fuzzlab.labgen.leakage_probe`) is a **required**
  `fuzzlab lab-generate --check` step, judged with **per-class thresholds**:
  1. **`run_leakage_gate`** is the gating entry point; `probe_leakage` remains the
     non-raising measurement function (its pre-existing signature, fields and semantics
     are unchanged — `LeakageResult.leaks` still means "global AUC exceeded the global
     permutation null" and nothing else). The gate raises one `MetadataLeakageError`
     naming **every** violation, global and per-class.
  2. **Per-class thresholds.** `PER_CLASS_AUC_THRESHOLDS: dict[str, ClassThreshold]`
     (`auc_threshold`, `status` ∈ `THRESHOLD_STATUSES`, written `justification`), with
     `DEFAULT_CLASS_THRESHOLD` for unregistered classes. A class's **effective** pass
     line is `min(its own permutation-null percentile, its configured threshold)`. This
     one-directional, fail-closed composition is load-bearing, not an implementation
     detail: it delivers §2.3's per-class decision while preserving FR-LAB-8's standing
     constraint that no per-class knob may be usable to disable the gate for a class —
     a configured number can only tighten, and raising one above that class's null has
     no effect at all.
  3. **Provisional calibration is part of the contract.** Every threshold shipped in
     Phase 1 is `status="provisional"`, seeded from
     `PROVISIONAL_THRESHOLD_BAND = (0.55, 0.60)`, and `format_leakage_report` must print
     each class's number **with its status and rationale** plus a NOTE naming the classes
     whose verdict currently rests on an uncalibrated number. A threshold becomes
     `"calibrated"` only when its value has actually been derived from a properly-sized
     permutation-null distribution for that class.
  4. **Insufficient data is a skip, never a failure.** `insufficiency_reason()` returns
     the specific shortfall (empty corpus, fewer than two classes, fewer than
     `MIN_CELLS_FOR_GATE` cells, fewer than `MIN_GROUPS_FOR_GATE` generating-rule groups,
     a class below `MIN_CELLS_PER_CLASS_FOR_GATE`, or no in-scope feature with any
     variance) and `run_leakage_gate` raises the **separate** type
     `InsufficientCorpusError` for it, so a caller can skip with a printed reason rather
     than fail a build — mirroring FR-LAB-38's single-stack skip in the fingerprint gate.
  5. **Feature scope is narrow-only.** `probe_leakage(feature_scope=...)` may restrict
     the closed `FEATURE_ALLOWLIST` to the features a given corpus actually observes, and
     may never widen it. An in-scope feature absent from any cell is rejected, never
     imputed (PA-0006).
  6. **The CLI adapter.** `cli.leakage_probe_records_from_manifest(manifest)` is the one
     schema↔probe adapter, labelling by `vuln_class` and grouping by
     `corpus_analysis.generating_rule_id` — the same shared rule ID the de-duplication
     report and the stratified split use (PA-0003/PA-0021), never a second grouping.
  7. **Known scope limit (current truth, not a deferral).** Only
     `cli.MANIFEST_DERIVABLE_LEAKAGE_FEATURES = ("path_depth",)` of the seven allowlisted
     features is derivable from a manifest: five are live-response observations and
     `param_name_length` lives in an emitter's private per-route page profile, not in the
     `Cell` IR. Consequently the gate **skips on every sample manifest shipped today**.
     Making it bite on the real corpus requires observed per-cell response metadata
     recorded at build time; until that exists, this requirement's gating value is
     realized only for corpora that carry such metadata (which the tests exercise
     directly). (`CC-LAB-0045`)

- **FR-LAB-42** *(L-P3.3b, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3 step 2; number
  pre-assigned to this lane by the orchestrating session, so no post-merge renumbering was
  needed.)* The **`php_laravel` emitter carries the full module inventory** — every shape
  `php_current` supports, ported to Laravel/Eloquent/Blade idiom. Laravel is the one stack
  the plan assigns "full depth", because Phase 1's hard-shape work is directly portable to
  a second PHP stack:
  1. **Seven shapes**, each rendered by this emitter's *own* module registries
     (`fuzzlab.labgen.emitters.php_laravel.modules` — three sources, seven transform ops,
     seven sinks, two complexities, with their own Jinja2 template tree): `(sqli,
     sql_numeric_literal)` via `DB::select` raw-vs-bound; `(sqli, sql_string_literal)` via
     the query builder's `whereRaw()` vs. `where()`; `(sqli, sql_identifier)` via
     `orderByRaw()`; `(sqli, sql_join_alias)` (the alias substituted three times in one
     statement); and `(xss, html_body)`, `(xss, url_javascript_scheme)`,
     `(xss, html_attribute_unquoted)` as Blade views. Nothing is imported from or added to
     `fuzzlab.labgen.modules` (`php_current`'s plain-PHP/PDO idiom).
  2. **An HTML-sink cell is a two-file cell on this stack** — a controller (`role="controller"`)
     plus its own per-cell Blade view (`role="view"`,
     `resources/views/cells/<cell-slug>.blade.php`, a new `StackEnv.file_roles` entry),
     because a Laravel controller returns a view rather than echoing. Both files carry the
     `// Module composition: ...` provenance line, so the minimal-pair invariant is
     evaluated on each of them.
  3. **Two contracts this port establishes for any future second emitter on a shared
     checker.** (a) A stack's module *names* are the project's shared composition
     vocabulary, not per-stack names: `fuzzlab.labgen.minimal_pair` classifies each
     composition position through `fuzzlab.labgen.modules`' registries and raises for a
     name it cannot find, so a Laravel-only name would fail every cell's minimal-pair gate
     with a setup error rather than a finding. (b) A sink never escapes anything itself —
     in Blade terms the HTML sinks echo `{!! ... !!}` and the `html_entity_escape` transform
     applies Laravel's `e()` helper in the controller, keeping the security-relevant
     difference inside the declared transform region.
  4. **The widened `lab/manifests/phase3_php_laravel_sample.yaml`** (20 cells: a pair per
     value-context shape, a triple/quadruple per harder shape, verdicts always derived),
     passing `fuzzlab lab-generate --check` end to end — name-leak and secret scanners,
     determinism, minimal pair, Tier 0 `php -l` (run for real, all 28 emitted files) and
     Tier 3 whole-sample regeneration. `php_laravel` is registered in the CLI's
     `EMITTER_REGISTRY` (`--emitter php_laravel`), which is what makes that gate runnable.
  5. **The identifier-SQLi oracle reaches Laravel-rendered cells through a route-rewrite
     adapter only** (`fuzzlab.labgen.emitters.php_laravel.identifier_sqli`):
     `fuzzlab.labgen.identifier_sqli_assertion` is genuinely stack-agnostic apart from one
     assumption — that a cell is served at `cell.route.path`, true for filesystem-routed
     `php_current` but not for this router-dispatched stack, which serves each cell at its
     own cell-ID-derived `/cell/<slug>` URL so twins can coexist. The adapter rewrites the
     route and delegates; no verdict derivation, oracle call, comparison or fail-closed
     branch is re-implemented, and that shared module is unchanged.
  6. **`context_depth` other than `direct` is refused, not flattened.** The depth-hop
     fragments are not ported to Laravel yet, so `render()` raises rather than emitting a
     `same_file_helper`/`cross_file` cell as `direct` and mislabelling the depth its corpus
     record claims. Real `puppy-fort-factory/` page reproduction is §4.3 step 6
     (L-P3.3c), now under way per page group — see FR-LAB-48. (`CC-LAB-0044`)

- **FR-LAB-48** *(L-P3.3c-G5, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6 group G5; number
  pre-assigned to this lane by the orchestrating session, concurrently with G1–G4/G6, so no
  post-merge renumbering was needed.)* The two real **escaped-echo form pages** of
  `puppy-fort-factory/` are reproduced as `php_laravel` cells — a first, partial delivery of
  FR-LAB-8's migration, which lands per page group and completes at L-P3.3c-CUT:
  1. **Two secure-only cells** in `lab/manifests/phase3_laravel_real_pages_forms.yaml`:
     `LABGEN-PLRP-1005` (`contact.php`, POST `message`) and `LABGEN-PLRP-1006`
     (`newsletter.php`, POST `email`), reproducing ground-truth cases `PFF-1005` and
     `PFF-1006`. Both are `(xss, html_body)` cells whose single transform op is
     `html_entity_escape`, so `verdict()` derives SECURE — the label `lab/ground-truth/
     labels.json` already carries (`expected_vulnerable: false`, "reflected through
     htmlspecialchars" / "escaped echo; no DB write"). No new module, sink family, safety-
     matrix row or page-profile mechanism was needed beyond the URL pin below; the shape is
     rendered by L-P3.3b's existing inventory.
  2. **No vulnerable twin, by design.** §4.3.6.3's finding that secure-only cells are legal
     (`fuzzlab.labgen.minimal_pair` is a standalone offline checker over two rendered
     results, not a schema constraint): both real pages are labelled true negatives with
     `vuln_class: none`, so a twin would invent a vulnerability neither the real app nor any
     `PFF-` case has. The minimal-pair invariant is still *verified* for each cell against
     the same cell with its pipeline emptied (the `_weakened_twin` convention
     `fuzzlab.labgen.cli --check` uses), so §4.3.6.3a's inverted-default hazard is checked
     rather than assumed.
  3. **A migrated page's route keeps the real app's exact `.php`-suffixed URL**
     (§4.3.6.6a). A page profile may now **pin** the URL its cells are served at
     (`url_path`), so `routes/web.php` registers `Route::get('/contact.php', …)` rather than
     this stack's default cell-ID-derived `/cell/<slug>` URL. This is a correctness
     requirement, not a style choice: T-LAB0.9's additive-only gate
     (`fuzzlab.labgen.regression_gate`) fails a build that *relocates* an existing
     ground-truth case, and a test asserts exactly that against the real gate — the pinned
     URLs pass it and the idiomatic extension-less ones raise `RegressionGateError`. A
     pinned URL is owned by exactly one cell: a second cell claiming it raises, since a page
     needing a vulnerable cell *and* a secure twin cannot pin (both would register one
     path). Illustrative pages pin nothing and keep their previous behavior unchanged, and
     the identifier-SQLi route-rewrite adapter (FR-LAB-42.5) resolves the same pin, so an
     oracle always probes the URL the generated app really serves.
  4. **The whole-manifest conformance sweep is computed from `Emitter.supports()`**
     (§4.3.6.6 point 1, the BUG-0022/PA-0024 pattern, PA-0027(b)): Tier-3
     regenerate-and-diff, the unique-path check and Tier-0 `php -l` all run over every cell
     of every committed manifest this emitter supports — never a hand-maintained cell list —
     so a later page group's change that breaks an earlier group's page fails loudly, and a
     guard test asserts the derived set really spans more than this group's own manifest.
     `fuzzlab lab-generate --check` passes end to end on the new manifest. (`CC-LAB-0050`)

  *(Addendum, `FR-LAB-50`/`CC-LAB-0052`, 2026-09-22: point 3's `url_path` pin and
  single-claim guard were superseded by the unified `_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY`
  mechanism the consolidation pass introduced. `contact.php`/`newsletter.php` are that
  mechanism's trivial, single-cell case and are served exactly as described above; only the
  page-profile key names and the guard's location changed. See `FR-LAB-50`.)*

- **FR-LAB-44** *(L-P3.3c-G1, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6 group G1; number
  pre-assigned concurrently with G2–G4/G6.)* The two real numeric-literal-SQLi pages of
  `puppy-fort-factory/` (`product.php` -> `PFF-0001`, `blog_post.php` -> `PFF-0006`) are
  reproduced as `php_laravel` cells, each with an authored bound-parameter secure twin, in
  `lab/manifests/phase3_php_laravel_real_pages_numeric.yaml`. One module set (the existing
  `sql_numeric_literal` shape), two page profiles, no new modules — the pages' only
  documented difference (verbose vs. `@`-suppressed DB errors) is an observability axis, not
  a `(transform, sink_context)` fact, and is recorded but deliberately not modelled (the same
  omission `php_current`'s own real-pages sample makes for this pair). Contributed the naming
  finding that a case-ID-derived cell name would leak ground-truth provenance into generated
  files (FR-LAB-2), resolved by page-derived cell IDs (`LABGEN-RPL-<PAGE>`) and, in the
  unified mechanism (`FR-LAB-50`), by the always-popped `_GROUND_TRUTH_CASE_KEY` metadata
  field. Served via `served_url_for()`, the one shared URL derivation `FR-LAB-50`
  generalizes project-wide. (`CC-LAB-0046`)

- **FR-LAB-45** *(L-P3.3c-G2, §4.3.6 group G2; number pre-assigned concurrently.)* The real
  catalog listing (`products.php` -> `PFF-1001`) and its JSON feed (`api/products.php` ->
  `PFF-1003`), both secure-only, same SQL position, differing only in presentation. Added the
  `view` module category `CR-LAB-0001` Addendum D names (`fuzzlab.labgen.emitters
  .php_laravel.modules.VIEWS`, first member `json_view`): a Laravel Eloquent API Resource
  class rendering the page profile's declared, ordered `json_fields` (`(name, cast)` pairs
  against a closed `JSON_FIELD_CASTS` set — required and validated, never defaulted). A view
  module's name is recorded on its own `// View category: ...` provenance line, never in
  `// Module composition: ...`, for the same reason the `route` category never appears there
  (`minimal_pair` classifies every composition-line name through the shared registries and
  raises for one it cannot find). Orthogonal to the URL-pinning axis `FR-LAB-50` unifies — the
  `view` category is unaffected by, and unchanged since, the consolidation pass. (`CC-LAB-0047`)

- **FR-LAB-46** *(L-P3.3c-G3, §4.3.6 group G3; number pre-assigned concurrently.)* The real
  auth pages: `login.php` (`PFF-0004` vulnerable `username` + `PFF-1008` true-negative
  password condition, plus an authored secure twin) and `register.php` (`PFF-1004`,
  secure-only), in `lab/manifests/phase3_php_laravel_real_pages_auth.yaml`. The first
  two-cell (canonical + twin) real page in this emitter, and the source design the
  consolidation pass (`FR-LAB-50`) generalized project-wide: `real_page`/`canonical_cell_id`
  page-profile keys, the `.php`-suffixed twin-URL convention, and HTTP-method support on
  `route_accumulator.fragment_for_cell`. Two complexity-tail flags on the existing
  `single_statement` template, never new composition modules: `session_login` (session
  establishment + redirect) and `register_insert` (the prepared post-duplicate-check
  `INSERT`). New `emitters/php_laravel/auth_session.py`: a thin, offline-testable adapter
  over the LAB-owned `fuzzlab.labgen.identity_session.IdentitySessionStore` (L-P2.2) building
  a login POST from this stack's own page profile/URL, reinventing no session-holding logic
  (PA-0001/PA-0021). (`CC-LAB-0048`)

- **FR-LAB-47** *(L-P3.3c-G4, §4.3.6 group G4; number pre-assigned concurrently.)* The stored
  second-order pair `edit_profile.php` (write) -> `profile.php` (read/sink), reproducing the
  stored-XSS `bio` field (`PFF-0005` vulnerable / `PFF-1007` secure). The first
  `context_depth == "stored_second_order"` cells this emitter renders
  (`SUPPORTED_CONTEXT_DEPTHS = ("direct", "stored_second_order")`; `same_file_helper`/
  `cross_file` remain refused) and the first **write** endpoint any emitter in this project
  emits (`fuzzlab.labgen.emitters.php_laravel.modules.WRITES`, `stored_field_write.php.j2`):
  an Eloquent attribute assignment plus `save()`, persisting the tainted parameter verbatim
  (not itself the modelled defect — the vulnerability is decided at the read endpoint).
  `lab/identities/identities.yaml` gained the owning identity for the stored `bio`. Under the
  unified mechanism (`FR-LAB-50`), `/profile.php` and `/edit_profile.php` are two ordinary
  `real_page` profiles, each with its own `canonical_cell_id`, rather than this lane's
  original hand-authored `_REAL_URL_ROUTES` registry — every cell still answers both its read
  and write endpoints, via `_served_route_for()` applied once per endpoint. (`CC-LAB-0049`)

- **FR-LAB-49** *(L-P3.3c-G6, §4.3.6 group G6; number pre-assigned concurrently.)*
  `puppy-fort-factory/search.php` -- one `?q=` reaching three sinks (a `LIKE '%q%'` SQL
  string literal, an HTML body reflection, a quoted-attribute reflection) as six cells
  (three sink behaviors x vulnerable/secure), reproducing `PFF-0002`/`PFF-0003`. Added the
  `(raw_concat, html_attribute_quoted)` safety-matrix row and the `html_attribute_quoted`
  shape -- the first shape on which `php_laravel`'s inventory is a strict superset of
  `php_current`'s rather than equal to it (`test_laravel_carries_every_shape_php_current
  _supports` relaxed from equality to `>=`; `php_current`'s own shape map is untouched, it is
  not the migration target, §4.3.6.6b). New sinks `html_attribute_quoted_echo` and
  `sql_string_literal_like` (a second rendering of the existing `sql_string_literal` family,
  not a new one), registered in both emitters' sink vocabularies for `minimal_pair`, plus a
  `sink_override_by_family` page-profile key so one profile picks a different sink rendering
  per sink family sharing the page. **`search.php` is deliberately left with no canonical
  cell** -- its profile carries `real_page: True` but `canonical_cell_id: None`, the unified
  mechanism's (`FR-LAB-50`) legal, flagged-open state: Laravel cannot register six
  `GET /search.php` routes for six cells, and the canonical-cell choice (or a multi-sink page
  composition the `Cell` IR does not have today) is a policy decision left, explicitly, for
  `L-P3.3c-CUT`. Every cell is served at its plain illustrative `/cell/<slug>` URL until that
  decision lands. (`CC-LAB-0051`)

- **FR-LAB-50** *(L-P3.3c consolidation, all of §4.3.6's page groups; number assigned after
  `FR-LAB-49`, the highest pre-assigned migration-lane number.)* Six sub-lanes (G1..G6) built
  five independent, mutually-incompatible URL-pinning mechanisms concurrently against
  `emitters/php_laravel/__init__.py`/`route_accumulator.py` (see `FR-LAB-44`..`49`/`48` and
  `CC-LAB-0052` for the full list). This requirement is the **single, unified replacement**:
  1. **`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY`**, generalizing G3's design (`FR-LAB-46`) as the
     target shape (canonical-cell-per-page, HTTP-method support, an explicit twin-URL
     convention), of which G5's single-cell case (`FR-LAB-48`) is the trivial instance. A
     real page's profile names, via `canonical_cell_id`, the one cell served at the page's
     real URL/method; every other cell of that page is served at a distinct, still-
     `.php`-suffixed twin URL (`_twin_url_for()`); `canonical_cell_id: None` is the legal,
     explicitly-flagged "not yet decided" state G6's `search.php` (`FR-LAB-49`) needs.
  2. **One shared derivation** (`_served_route_for()`/`served_url_for()`, PA-0003/PA-0021),
     called by route registration, the identifier-SQLi probe adapter and the auth-session
     adapter alike — never re-derived — applied independently per endpoint, which is what
     let G4's read/write pair (`FR-LAB-47`) fold into the same mechanism without its own
     registry.
  3. **One `route_accumulator.fragment_for_cell(method=, action=)` signature**, reconciling
     G3's and G4's differing shapes, and a multi-line-aware `DuplicateRouteError` scan
     (G2's guard, `FR-LAB-45`, kept as the shared safety net) in `render_file()`.
  - **Design decision flagged for human review, not settled here:** the twin-URL suffix
    convention (embedding the non-canonical cell's slug before the real page's `.php`
    suffix, e.g. `/login.labgen-pla-0002.php`) was adopted from G3 unchanged, as an
    autonomous call made to unblock four lanes' merges rather than stall on a naming
    bikeshed. No alternative convention was evaluated against it. See §8.
  - **Not resolved by this requirement, and not this pass's to resolve:** `search.php`'s
    canonical-cell choice (`FR-LAB-49`, `L-P3.3c-CUT`'s to make). (`CC-LAB-0052`)

- **FR-LAB-51** *(L-P3.3c-CUT prep, plan §4.3.6.6 point 3; the parity/cutover coverage
  gate, built ahead of and independent from `L-P3.3c-CUT` itself, which remains
  unscheduled pending human sign-off.)* A coverage assertion that every `PFF-` case in
  `lab/ground-truth/labels.json` maps to at least one emitted `php_laravel` cell, or to a
  reviewed entry in an explicit exemption register — never a case silently uncovered.
  `fuzzlab.labgen.cutover_gate.assert_cutover_coverage()`/`diff_cutover_coverage()`
  classify every case as covered, exempted, or (gate-failing) uncovered:
  1. **Coverage is derived, never a hand-maintained literal** (PA-0001/PA-0027):
     `compute_php_laravel_coverage()` walks every `lab/manifests/*.yaml` cell through
     `LaravelEmitter.supports()` and the new
     `fuzzlab.labgen.emitters.php_laravel.ground_truth_cases_for(cell)`. A case gaining or
     losing a reproducing cell changes the gate's result with no second list to update.
  2. **`ground_truth_cases_for()` extends `FR-LAB-50`'s `_GROUND_TRUTH_CASE_KEY`/
     `_CANONICAL_CELL_KEY` page-profile convention**, rather than a second, competing
     mechanism, with two more page-profile keys for the two shapes that convention alone
     cannot express: `ground_truth_case_by_family` (`sink_context.family -> PFF- case
     id`, for a page whose one profile spans more than one case — `search.php`'s
     `PFF-0002`/`PFF-0003`, `FR-LAB-49`) and `secondary_ground_truth_cases` (extra case
     ids a page reproduces as a non-primary, boilerplate position identical across every
     cell of that page, rather than owned by one canonical cell — `login.php`'s
     already-hashed `PFF-1008` password condition, `FR-LAB-46`). Both are popped before
     any template renders, exactly like `_GROUND_TRUTH_CASE_KEY` (FR-LAB-2: no case ID
     leaks into a generated file).
  3. **The exemption register**, `lab/ground-truth/migration-exemptions.yaml`, is
     machine-readable (`{pff_case, reason}` entries) and read by the gate itself, never
     kept as prose — an uncovered case absent from it fails the gate loudly, and adding an
     entry is a diff a reviewer sees. `load_exemptions()` raises on a malformed or
     duplicate entry rather than silently treating the register as empty. Today's register
     lists `PFF-1002` (`track.php` performs no database query at all — no sink for any op
     the safety matrix models to apply to, per plan §4.3.6.6's own finding),
     `PFF-0007`/`PFF-0008` (DOM XSS, client-rendered, never reaches the server — exempted
     per the D-open-1/D-open-2 decisions, plan §4.3.6.7, both decided 2026-09-22: Layer B
     reproduction is not required for the cutover, and DOM XSS/`L-P3.3c-DOM` is out of the
     cutover's "full coverage" bar, deferred backlog instead), and (added by `CC-LAB-0058`)
     `PFF-0003` (`search.php`'s reflected-XSS case — real, but `/search.php`'s single
     `php_laravel` page profile can render only one canonical cell at that real URL, and
     `PFF-0002`, the co-located LIKE-clause SQLi, was chosen canonical; `PFF-0003`'s shape
     remains authored/tested as one of `FR-LAB-49`'s illustrative-URL cells). Status
     (`CC-LAB-0062`, 2026-09-22): live gate result is 12 covered / 4 exempted / 0
     uncovered — Layer A closed.
  4. **Deliberately its own module**, `fuzzlab.labgen.cutover_gate`, not an addition to
     `fuzzlab.labgen.regression_gate`: that gate diffs two already-loaded `GroundTruth`
     snapshots (schema-shaped, manifest-independent by design); this one walks manifest
     cells through an emitter's `supports()` — a different computation shape over
     different inputs — while mirroring that module's `diff_*` (non-raising) / `assert_*`
     (raising) two-function convention.
  - **Does not itself gate or perform `L-P3.3c-CUT`.** This requirement is the
    verification mechanism plan §4.3.6.6 describes as a precondition for the cutover; the
    cutover's own re-pointing work (`lab/compose.yaml`, `deploy.sh`,
    `fuzzlab/mutation/filtermodel.py`'s WAF-rules path, deleting `puppy-fort-factory/`) is
    untouched by it and stays blocked on human sign-off (`FR-LAB-8` remains **not**
    satisfied by this requirement — see that entry). (`CC-LAB-0053`)

- **FR-LAB-52** *(`docs/LAB_IMPLEMENTATION_PLAN.md` ~line 154's Tier 1/2 gap; the
  live-boot verification precondition for `L-P3.3c-CUT`, built ahead of and
  independent from the cutover itself, which remains unscheduled pending human
  sign-off.)* A `php_laravel`-emitted build must be provably not just
  syntactically valid PHP (`tier0`'s `php -l`) but a **genuinely bootable,
  responding application**: `fuzzlab.labgen.conformance.live_boot` assembles a
  real Laravel 13 project (the checked-in
  `fuzzlab/labgen/emitters/php_laravel/stack/skeleton/` skeleton — a real
  `composer create-project laravel/laravel` output, trimmed of dev-only
  tooling/front-end build pipeline — overlaid with a manifest's real
  `LaravelEmitter`-rendered controllers/views/routes), runs a real `composer
  install --no-dev`, seeds a real per-run SQLite database, boots a real `php
  artisan serve` process, and makes real HTTP requests against it via
  `LiveBootHarness`.
  1. **The skeleton/generated-content seam follows `StackEnv`'s own
     scaffold convention** (`stack_env.py`'s `scaffold_files`/
     `render_scaffold`), extended rather than forked: the skeleton directory is
     the "framework, rendered once, stack-wide" half; a manifest's
     `LaravelEmitter.render()`/`route_fragment_for()` output overlaid on top by
     `LiveBootHarness._assemble()` is the "generated per-manifest content"
     half — the same split `StackEnv.scaffold_files` already documents, now
     actually exercised end to end for the first time (no existing
     `fuzzlab.labgen.cli` path assembles scaffold + accumulated
     `routes/web.php` + per-cell files into one bootable tree; that assembly
     step is this requirement's own new code, not a pre-existing gap in
     already-shipped CLI behavior — see `route_accumulator.py`'s own
     docstring, which already named this as a future whole-manifest build
     driver's job).
  2. **SQLite is this harness's own, explicitly-scoped substitution for the
     production lab's MariaDB target** (`lab/sql/schema.sql`, read for shape
     only — never touched or moved). It is adequate for what this requirement
     proves (a real boot + a real, observable payload differential) and
     explicitly **not** claimed adequate for what Tier 2's real, dialect-
     sensitive oracle confirmation would need (identifier/alias-position SQLi
     verdicts, which `tier1.py`'s own docstring already flags as
     dialect-sensitive) — this requirement's own harness only drives manifests
     outside that shape class. A harness-only `.env` (`_harness_env_content`)
     is used instead of `StackEnv.env_file_content()` (which pins the real
     lab's own `DB_CONNECTION=mysql` production default) for exactly this
     reason: the two must not be conflated into one setting silently drifting
     production config.
  3. **Skip-guarded on a real capability probe**, `live_boot_available()`
     (composer + php on `PATH`, the checked-in skeleton present, and
     Packagist actually network-reachable) — never a bare tool-presence check
     mistaken for a working capability (PA-0005/PA-0009's "verify it is
     actually usable" rule). `tests/test_labgen_conformance_live_boot.py`
     applies this as a module-level `pytest.mark.skipif` and additionally
     tags both tests `@pytest.mark.slow` (a new marker, `pyproject.toml`'s
     `[tool.pytest.ini_options] markers`) — the project's first use of that
     convention, documented there for a future slow/network-dependent test to
     follow, selectable/deselectable via `pytest -m slow` / `pytest -m "not
     slow"` without needing to edit test code.
  4. **Proves a real vulnerable/secure payload differential**, not just two
     boot successes: `test_live_boot_numeric_manifest_sqli_twin_round_trips_a_payload`
     sends the same boolean-injection payload (`1 OR 1=1`) at
     `product.php`'s real, pinned vulnerable (`LABGEN-RPL-PRODUCT`) and secure
     (`LABGEN-RPL-PRODUCT-BOUND`) twins and asserts the raw-concatenation cell
     returns every seeded row while the bound-parameter cell does not — the
     actual, observable security property the safety matrix's derived
     verdicts claim, verified against a real response body rather than
     inferred from source text.
  - **Coverage actually proven in this session**: `lab/manifests/
    phase3_laravel_real_pages_forms.yaml` (`contact.php`/`newsletter.php`,
    escaped-echo POST forms, no DB) and `lab/manifests/
    phase3_php_laravel_real_pages_numeric.yaml` (`product.php`/`blog_post.php`
    numeric-literal SQLi vulnerable/secure twins, against the seeded SQLite
    `products`/`posts` tables) — 4 of the 6 `phase3_php_laravel_real_pages_*`/
    `phase3_laravel_real_pages_*` manifests. The other real-page manifests
    (auth/G2/G4/search) are **not yet driven by this harness** — they need
    additional seed data (a `users` table with a real bcrypt/md5-matching
    row for `login.php`, a stored-second-order write-then-read round trip for
    `edit_profile.php`/`profile.php`) that this requirement's scope did not
    extend to; `LiveBootHarness` itself does not preclude it, and a future
    change should extend `_SCHEMA_SQL`/`_SEED_SQL` and add their own test
    functions rather than a second harness. (`CC-LAB-0054`)

    *(Update, `FR-LAB-54`/`CC-LAB-0056`, 2026-09-22: the auth/G2/G4 manifests
    are now also driven — see `FR-LAB-54` below for the full statement. Only
    `search.php` remains undriven, deliberately, pending `L-P3.3c-CUT`.)*
  - **Does not itself confirm a Tier-2, oracle-grade vulnerable/secure
    verdict.** `fuzzlab.labgen.conformance.tier2`'s "the only tier that
    actually confirms a label" claim is unchanged by this requirement — a
    real, container-based, dialect-correct oracle (sqlmap/commix/ZAP-wrapped)
    remains genuinely unbuilt and out of scope here. This requirement narrows,
    but does not close, the gap `docs/LAB_IMPLEMENTATION_PLAN.md` ~line 154
    named; see that document's own updated text for the current, accurate
    status.

- **FR-LAB-53** *(`fuzzlab/labgen/minimal_pair.py`; lane L-P3.3c-G3's
  (`CC-LAB-0048`) finding, closed here; `CC-LAB-0055`, `docs/bugs/BUG-0027-*.md`.)*
  `check_minimal_pair()`'s two documented limitations are fixed:
  1. **Path-independent pairing.** `check_minimal_pair(vulnerable, secure, *,
     pair_by=None)` accepts an optional `EmittedFile -> Hashable` key
     function. `None` (the default) is the original, unchanged literal-path
     pairing — every existing caller (`fuzzlab.labgen.cli`, every
     `tests/test_labgen_*.py` lane) keeps its exact prior behavior. When
     given, files on each side are matched by `pair_by(file)` instead of
     path, so two independently-authored cells that render to two different
     paths (a manifest's own vulnerable/secure authoring convention, e.g.
     G3's `login.php`/its `.php`-suffixed secure-twin URL) can be checked
     directly against each other, rather than only each against its own
     transform-emptied self. A `pair_by` that maps more than one file on one
     side to the same key raises `MinimalPairError` (a setup problem, never
     silently resolved by picking one).
  2. **Content confinement independent of composition-name matching.** The
     "differ outside any declared transform/sink change" check previously
     ran *only* when the two variants' composition sequences were
     name-identical -- disabled for essentially every real vulnerable/secure
     pair, whose transform names legitimately differ. It is now derived
     independently from *each side's own* composition metadata: a
     `transform` module's self-identifying comment line (`// {name}
     transform: ...`, a convention every template in
     `fuzzlab.labgen.modules.transforms` follows) gives a structural lower
     bound on where the transform/sink region begins in the assembled file;
     content found to differ before that point is a `MinimalPairViolation`
     regardless of whether the two sides' composition names match. This was
     a genuine defect (`BUG-0027`), not merely an enhancement -- the checker
     silently passed an input its own docstring says it must reject. The
     symmetric trailing-region case (a rewrite inside a sink's own rendered
     output) remains unclosed, since no sink template self-identifies the
     way transform templates do and closing it would require re-rendering a
     module standalone -- a line this checker's docstring already refuses to
     cross; recorded as a residual, explicitly out-of-scope gap, the same
     way the pre-existing equal-composition-length restriction already is.

- **FR-LAB-54** *(extends `FR-LAB-52`'s live-boot scope; `CC-LAB-0056`,
  `docs/bugs/BUG-0028-*.md`.)* `fuzzlab.labgen.conformance.live_boot
  .LiveBootHarness`'s real, on-host proof extends from 2 to 5 of the 6
  `phase3_php_laravel_real_pages_*`/`phase3_laravel_real_pages_*` manifests:
  1. **`auth`** (`login.php`/`register.php`). A real seeded `users` row
     (`SEED_USER_ID`/`SEED_USERNAME`/`SEED_PASSWORD`, module-level constants
     on `live_boot.py`) whose password is stored **md5-hashed** — matching
     `login.php`'s own `password_hash_fn` (`php_laravel.__init__
     ._PAGE_PROFILES['/login.php']`), never bcrypt/`Hash::make`: the
     migrated login/register controllers go through `DB::table('users')`
     (the query builder), never Eloquent, so `App\Models\User`'s
     `'password' => 'hashed'` cast is never invoked for either page —
     confirmed directly against the skeleton's own `app/Models/User.php`
     before relying on it. `login.php`'s vulnerable/secure twin
     (`LABGEN-PLA-0001`/`0002`) is proven with a genuine, unauthenticated
     SQLi boolean-injection auth bypass: the vulnerable cell authenticates
     (a real `302`) with no correct password at all, while the bound-
     parameter secure twin rejects the identical payload with the real
     page's own `401`. (The naive `' OR '1'='1' -- ` textbook payload does
     **not** work against this specific rendered statement — it leaves
     Laravel's separately-bound `->where('password', ...)` clause's
     placeholder commented out of the final SQL text while PDO still tries
     to bind a value to it, a real `SQLSTATE[HY000]` `QueryException`
     rather than a bypass; the working payload keeps one placeholder of its
     own before the comment marker so the still-supplied binding lands on
     it instead. Recorded here because it is a genuine, observed fact about
     this exact query shape, not assumed from the textbook form.)
     `register.php` (`LABGEN-PLA-0003`) is proven with a real prepared
     `INSERT`, confirmed by reading the row back out of the same booted
     app's own SQLite database (`LiveBootHarness.query_db()`, new — a
     read-only introspection helper for observing a write a real HTTP
     request already made, never used to drive a request itself), plus the
     real duplicate-username `409` rejection.
  2. **`g2`** (`products.php`/`api/products.php`). Both cells are
     secure-only per the manifest itself — no vulnerable twin exists to
     differential against, confirmed by reading the manifest rather than
     assumed. `products.php` is proven with a real, category-filtered HTML
     result set against the seeded `products` table (reusing, not
     duplicating, `FR-LAB-52`'s existing product seed data);
     `api/products.php` is proven with a real, well-formed JSON array
     (parsed with `json.loads()` on the real response body, not merely
     "status 200") whose field set/types match the `json_view` Eloquent API
     Resource's own declared contract, plus both endpoints' real
     bound-parameter behavior against a string-literal-breakout payload.
  3. **`g4`** (`edit_profile.php` -> `profile.php`, `stored_second_order`).
     The one genuinely sequential-state case: a real POST to the write
     endpoint followed by a real GET of the read endpoint, both against the
     same seeded `users` row's `bio` field (the write/read endpoints' shared
     `?user=` owner default, `SEED_USER_ID` — no session/auth machinery
     needed to reach either endpoint, confirmed directly: neither the write
     nor the read route carries any auth middleware in the generated
     `routes/web.php`, so `FR-LAB-52`'s auth-session adapter is not a
     dependency here). Proven for both the vulnerable cell
     (`LABGEN-PLRP-0401`: a POSTed `<script>` marker survives unescaped at
     the read sink) and the secure twin (`LABGEN-PLRP-0402`: the same
     marker is HTML-entity-escaped, `&lt;script&gt;...`) — each cell's own
     read URL AND write URL (canonical or twin, per `FR-LAB-50`'s unified
     mechanism) derived from the emitter's own `route_fragment_for()`
     output rather than re-derived (PA-0001/PA-0021).
  - **`search.php` was explicitly not attempted at the time of this
    requirement.** `lab/manifests/phase3_php_laravel_real_pages_search.yaml`'s
    own header documented that all six of its cells were still without a
    canonical URL-owning cell pending the `L-P3.3c-CUT` policy decision
    (`CC-LAB-0052`/`0053`). *(Superseded by `FR-LAB-55`/`CC-LAB-0058`,
    2026-09-22: that decision is now made — `search.php` is driven too.)*
  - **`BUG-0028` (full bug protocol).** Extending coverage surfaced two real
    defects in `LiveBootHarness` itself (not in any emitted code), both
    invisible until a real redirect and a real Eloquent `->save()` were
    exercised for the first time: (a) `request()` silently followed a real
    `POST` `302` (`urllib`'s own documented default), masking a real login
    success as a `404`; (b) the seeded `users` schema lacked the
    `created_at`/`updated_at` columns `App\Models\User`'s default Eloquent
    timestamps need, breaking every G4 write with a real `500`. Both fixed
    (a non-redirect-following `urllib` opener; two new nullable schema
    columns) — see `docs/bugs/BUG-0028-*.md` and `PA-0030`.
  - Still, as `FR-LAB-52` already states, **not** a Tier-2, oracle-grade,
    dialect-correct verdict confirmation — this requirement only extends
    which real-page groups get a real boot + real, observable behavior,
    unchanged in kind from `FR-LAB-52`'s own scope statement.

- **FR-LAB-55** *(extends `FR-LAB-52`/`FR-LAB-54`'s live-boot scope with a
  real MariaDB backend, and resolves `search.php`'s open canonical-cell
  decision; `CC-LAB-0058`.)* Two additions, both real, both on-host, neither
  touching `lab/compose.yaml`/`deploy.sh`/`fuzzlab/mutation/filtermodel.py`/
  `puppy-fort-factory/`:
  1. **A real MariaDB-backed live-boot mode.** `fuzzlab.labgen.conformance
     .live_boot.MariaDbServer` starts a real local `mariadbd` (via the system
     `service` command, never a hand-rolled datadir invocation — reusing the
     sandbox's already-integrated init script), imports the REAL
     `puppy-fort-factory/sql/schema.sql` verbatim (`mariadb < schema.sql` —
     never a port or a synthetic equivalent, unlike `FR-LAB-52`'s own SQLite
     `_SCHEMA_SQL`), and provisions the least-privilege application identity
     matching `lab/compose.yaml`'s own default `PFF_DB_NAME`/`PFF_DB_USER`/
     `PFF_DB_PASS` values (`puppy_fort`/`pff`/`pff_lab_pw` — the lab's own
     already-public dev defaults, not a secret this requirement invents).
     `LiveBootHarness` gains an additive `mariadb_server` parameter (`None`
     keeps the original SQLite behavior byte-for-byte) that points the
     assembled app's `.env` at it (`DB_CONNECTION=mysql`) and skips the
     SQLite seed step (the real schema already seeds real rows). Cleanup is
     unconditional on every exit path (`PA-0012`): the test database/user are
     always dropped, and `mariadbd` is stopped again only if this run is the
     one that started it (a service already running before the test — e.g. a
     human's own session — is left exactly as found). `mariadb_available()`
     mirrors `live_boot_available()`'s own capability-probe convention
     (`PA-0005`/`PA-0008`): checks the real `mariadb`/`mariadb-admin`
     binaries, the `service` command, `/etc/init.d/mariadb`, and
     `puppy-fort-factory/sql/schema.sql` — never starts anything as a probe
     side effect. `tests/test_labgen_conformance_live_boot_mariadb.py`
     (skip-guarded, `pytest.mark.slow`) re-proves every group the SQLite
     harness drives — `forms`/`numeric`/`auth`/`g2`/`g4` — plus (2) below,
     against the real engine and the real seeded data (`admin`/`alice`/`bob`,
     ten real products, four real posts — never the SQLite harness's own
     synthetic seed).
  2. **`search.php`'s canonical-cell decision, resolved (Path B).** `PFF-0002`
     (the `LIKE`-clause SQLi) and `PFF-0003` (the reflected XSS, both
     `html_body` and `html_attribute_quoted`) are both real and
     simultaneously true at the same real `/search.php` URL. A real
     multi-sink page composition (one route genuinely exhibiting both) was
     evaluated and judged a disproportionate architecture change for this
     requirement's scope (it would fork the "one cell, one verdict-relevant
     shape" invariant every module-set/minimal-pair mechanism in
     `LaravelEmitter` depends on) — so `_PAGE_PROFILES['/search.php']` now
     names `LABGEN-PL-RP-0001` (the SQLi cell) `canonical_cell_id`, served at
     the real `/search.php` URL; every other cell of that manifest is a twin
     at its own `.php`-suffixed variant URL, unchanged mechanism. `PFF-0003`
     is a genuine, reviewed downgrade from covered to exempted
     (`lab/ground-truth/migration-exemptions.yaml`'s new `PFF-0003` entry) —
     `fuzzlab.labgen.cutover_gate.assert_cutover_coverage()` stays green (12
     covered, 4 exempted, 0 uncovered), never silently dropped.
  - **Real, observed MariaDB-vs-SQLite differences, reported per this
    requirement's own instruction rather than papered over** (see
    `tests/test_labgen_conformance_live_boot_mariadb.py`'s module docstring
    for the full detail): (a) the classic `-- ` (trailing-space) SQL comment
    used by `FR-LAB-54`'s own auth-bypass payload does not survive Laravel's
    `TrimStrings` middleware against real MySQL/MariaDB's stricter comment
    grammar (which requires the trailing whitespace `TrimStrings` removes) —
    SQLite's own `--` comment needs no such whitespace, so this is a genuine
    dialect difference, not a harness bug; the underlying SQLi auth bypass is
    still real against MariaDB with a dialect-appropriate payload (`#`,
    MySQL's bare to-end-of-line comment, immune to trimming). (b) The real
    schema has no `users.updated_at` column (only `created_at`, no `ON
    UPDATE` companion); `FR-LAB-54`'s G4 write leg goes through Eloquent
    (`$storedOwner->save()`, default `$timestamps = true`), so it genuinely
    500s against the real schema — a real compatibility gap in the
    `php_laravel` skeleton's default `User` model (framework-default
    timestamps vs. a real schema that never modeled `updated_at`), first
    surfaced by this real proof (the SQLite harness's own synthetic schema
    had silently added the missing column, per `FR-LAB-54`'s own `BUG-0028`
    fix, masking the gap). Left as documented future work, not fixed here:
    this requirement is additive-only in scope, and the fix belongs to
    whichever future change resolves G4's cutover-readiness, not to a
    conformance harness whose job is to observe and report a real gap, not
    silently patch around it.
  - Still, as `FR-LAB-52`/`FR-LAB-54` already state, **not** a Tier-2,
    oracle-grade, container-based, dialect-correct oracle confirmation of a
    label (see `FR-LAB-56` for `tier2.py`'s own, now real but still
    synthetic-in-sandbox, claim) — this requirement proves boot + real,
    observable behavior against the real engine and real schema, which is a
    stronger, but still narrower, claim than a full Tier-2 confirmation.

- **FR-LAB-56** *(wires `fuzzlab.labgen.conformance.tier2` — previously
  `"[design -- not exercised]"`, no working confirmation logic — against a
  real, synthetic, in-sandbox app, mirroring `FR-LAB-52`'s Tier-1 precedent;
  `CC-LAB-0061`.)* `tier2.py` gains a real `Tier2Oracle` implementation,
  `LiveBootTier2Oracle`, built on the existing, unmodified
  `fuzzlab.labgen.conformance.live_boot.LiveBootHarness` (never the real,
  loopback-only lab target; no `--authorized` needed, D11). It adds a real
  control/baseline differential on top of what a bare Tier-1 evidence-marker
  check can show: it sends the case's real payload request and a second
  real request for a caller-supplied inert control value at the same
  param/location, and reports `confirmed_vulnerable` only when the evidence
  marker is present in the payload response and genuinely absent from the
  control response — never guessing a verdict when the control itself
  cannot distinguish vulnerable from not (a real `inconclusive` detail is
  reported instead, fail-closed per `PA-0025`, matching
  `fuzzlab.labgen.identifier_sqli_assertion.IdentifierSqliTier2Oracle`'s own
  convention — a second, pre-existing, real `Tier2Oracle` this requirement
  does not change). New `Tier2Client` protocol names the minimal
  `.get()`/`.post()` shape it needs, satisfied structurally by
  `LiveBootHarness` without a new import dependency between the two
  conformance modules. Proven for real (not just offline) against
  `phase3_php_laravel_real_pages_numeric.yaml`'s `product.php` vulnerable
  (`LABGEN-RPL-PRODUCT`) / secure (`LABGEN-RPL-PRODUCT-BOUND`) twins — a
  real positive and a real negative confirmation for the same `1 OR 1=1`
  boolean-injection payload.
  - Still **not** the production-grade, dialect-sensitive, container-based,
    real-target oracle T-LAB0.7 describes as Tier 2's own bar — that remains
    `IdentifierSqliTier2Oracle`'s/a future real-target oracle's job, exactly
    as `FR-LAB-52`/`FR-LAB-54`/`FR-LAB-55` already state for the equivalent
    Tier-1 live-boot claim. `LiveBootTier2Oracle` narrows that gap (a real,
    in-sandbox confirmation mechanism now exists where none did before) but
    does not close it.

- **FR-LAB-57** *(`CC-LAB-0060`, 2026-09-22 — wires `fuzzlab.labgen.
  conformance.tier1`'s own public API against a real in-process app+DB, for
  whichever stacks already have a real `Tier1Client`; extends `FR-LAB-52`'s
  `LiveBootHarness` scope, does not change it.)* `tier1.py`'s
  `build_tier1_case`/`run_tier1_case`/`evaluate_tier1_response` must be
  provably exercisable against a real running app, not only a hand-written
  fake client — for any stack that already has a real, on-host-independent
  `Tier1Client` implementation. Today that is `php_laravel`, via
  `LiveBootHarness.fetch()` (`FR-LAB-52`'s existing harness, unmodified and
  reused as-is; this requirement adds no new harness code, only tests that
  drive the existing one through `tier1.py`'s own public functions instead
  of `LiveBootHarness.get()`/`.post()` directly).
  1. **Real Tier-1 cases, real differential.** `TestTier1RealLiveBoot` in
     `tests/test_labgen_conformance_tier1.py` builds real `Tier1Case`
     objects for `product.php`'s real vulnerable/secure twin
     (`LABGEN-RPL-PRODUCT`/`LABGEN-RPL-PRODUCT-BOUND`, `lab/manifests/
     phase3_php_laravel_real_pages_numeric.yaml`) and runs each through
     `run_tier1_case()` against a real `LiveBootHarness` — the same real
     boolean-injection differential `FR-LAB-52`'s own
     `test_live_boot_numeric_manifest_sqli_twin_round_trips_a_payload`
     proves by hand-inspecting `harness.get()` responses, now proven through
     `evaluate_tier1_response`'s own marker-in-body decision logic instead.
     Both twins' real `Tier1Outcome.matches_expectation` is asserted `True`.
  2. **Real Tier-1 negative.** The same test module runs `contact.php`/
     `newsletter.php` (`LABGEN-PLRP-1005`/`1006`, `lab/manifests/
     phase3_laravel_real_pages_forms.yaml`, secure-only escaped-echo forms)
     through `build_tier1_case()`/`run_tier1_case()` with a raw
     `<script>...</script>` payload and `expected_vulnerable=False`,
     asserting the real response never reflects it unescaped.
  3. **Skip-guarded and marked slow**, exactly matching `FR-LAB-52`'s own
     convention: `live_boot_available()` (composer + php on `PATH`, real
     Packagist reachability) gates the whole `TestTier1RealLiveBoot` class,
     and each test carries `@pytest.mark.slow` — a real `composer install`
     against Packagist, unchanged wall-clock-time profile from `FR-LAB-52`.
  4. **Still synthetic, in-sandbox, never the real target (D11).** Exactly
     like `FR-LAB-52`/`FR-LAB-54`/`FR-LAB-55`: `LiveBootHarness` assembles
     and boots its own throwaway build in a temp directory; nothing here
     sends traffic to the real, loopback-only Ryder's Puppy Fort Factory
     lab target, so no `--authorized` flag applies (D11 unchanged).
  5. **Stacks with no real `Tier1Client` yet remain design-only.** `tier1.py`
     itself is unmodified in behavior — only its module docstring is
     updated to state the current, stack-by-stack status accurately.
     `OnHostRequiredError` is still raised for any case run with `client=None`,
     and a Tier-1 pass is still never recorded as Tier-2 oracle confirmation
     (`tier2.py`'s own scope is untouched by this requirement).

- **FR-LAB-58** *(applies the site-architecture expansion corpus's
  `suggested_op`/`suggested_sink_family` proposals to `lab/safety_matrix.yaml`,
  per `CC-LAB-0063`.)* `lab/safety_matrix.yaml` grows from 25 to 102 entries,
  covering 20 new `sink_family` values and ~70 new transform `op`s, spanning
  every cell `docs/research/corpus-examples/` currently holds (the original
  6 — `access-control`, `auth-session`, `ecommerce-logic`, `file-handling`,
  `search-export`, `ugc-xss` — plus the 6 added by the same expansion's
  correction pass — `mass-assignment`, `ssrf`, `insecure-deserialization`,
  `ssti`, `header-injection`, `webhook-signature`). All additions are new
  `(op, sink_family)` pairs under the existing `version: 1` (this file's
  own append-only convention, same as `FR-LAB-41`'s harder-shapes rows): no
  existing pair's meaning changes, and a corpus generated under `v1` before
  this landed re-derives identically. 17 new concern IDs were added to the
  matrix file's header vocabulary comment (one informative name per new
  vulnerability class, e.g. `ownership_check_bypass`, `mass_assignment`,
  `ssrf_request_forgery`, `weak_signature_comparison`), following the
  existing `sql_syntax_break`/`html_tag_break` naming convention. `partial`
  (D20 — VULNERABLE-but-harder, never a third verdict value) was used,
  not `neutralises`, wherever a corpus entry's own `pattern`/`notes`/
  `cwe_rationale` documented a residual, well-known weaker-defense gap:
  `mime_type_check`/`filename_charset_sanitize` (file-handling — no
  content/magic-byte inspection), `path_prefix_check` (file-handling — a
  string-prefix check on an unresolved path is symlink/prefix-bypassable),
  `hostname_allowlist` (ssrf — DNS-rebinding gap, since the resolved IP
  isn't itself checked), `driver_escape_string` (search-export — manual
  driver-level escaping vs. this file's existing parameterization
  preference), and `naive_string_compare`/`loose_equality_compare`
  (webhook-signature — a comparison *is* performed, just timing-unsafe
  and, for PHP `==`, type-juggling-prone, a harder attack than the
  `no_signature_check`/`trust_post_data` total-bypass rows at the same
  family). Two corpus-proposed sink families with conceptual overlap
  (`template_render` from `ssti`, `template_render_pipeline` from
  `search-export`) were kept as separate, unmerged families — merging is a
  design decision left to a later change. This requirement is the
  safety-matrix registry only: **no emitter/module currently implements
  code generation for any of these 20 new sink families** — that is
  separate, unstarted future work (the module-template half of the
  site-architecture plan's own Step 8 handoff), not claimed done here.
  Verified: `jsonschema.validate()` against
  `lab/schemas/safety_matrix.schema.json` passes; no duplicate `(op,
  sink_family)` key across the 102 entries; `tests/test_labgen_verdict.py`
  (15 tests, pre-existing entries only) stays green, unchanged.

- **FR-LAB-59** *(implements code generation for `orm_entity_bulk_assign`
  in `php_current`'s shared module registry, per `CC-LAB-0064`, drafted and
  reviewed through this project's new pre-change review gate,
  `docs/components/README.md`, before implementation.)* First scoped
  increment of the module-template half `FR-LAB-58` left unstarted: 2 of
  the family's 10 `lab/safety_matrix.yaml` ops (`unfiltered_body_update`
  vulnerable, `runtime_field_allowlist` secure), in the shared
  `fuzzlab.labgen.modules` registry (`fuzzlab/labgen/modules/__init__.py`,
  `php_current`'s package) — not `php_laravel` directly, since
  `php_laravel`'s own module names must already exist in this shared
  registry for `fuzzlab.labgen.minimal_pair`'s composition-line classifier
  to pass (its `_MODULE_CATEGORY` dict is built only from this package's
  `SOURCES`/`TRANSFORMS`/`SINKS`/`COMPLEXITIES`, never from an individual
  emitter's own dicts); an earlier draft of `CC-LAB-0064` targeted
  `php_laravel`'s Eloquent `$fillable`/`$guarded` directly and was
  re-scoped away from that in review for exactly this reason, plus a
  second one — Eloquent's mass-assignment guard is a model-class property,
  not a value-expression rewrite, and neither registry has an existing
  module category for emitting a separate model file, while plain PDO has
  no such mismatch (every module here composes into one inline PHP
  fragment already). Four new modules: one source, `all_post_params`
  (publishes `value_expr = "$_POST"`, the whole array — `GetParamSource`/
  `PostParamSource` both extract exactly one named parameter, the wrong
  shape here); two transforms, `unfiltered_body_update` (passes
  `value_expr` through unchanged) and `runtime_field_allowlist` (rewrites
  it to `array_intersect_key($_POST, array_flip($allowed_fields))`,
  `allowed_fields` supplied by the emitter's own page profile — mirrors
  `IdentifierAllowlistTransform`'s `allowed_identifiers` convention
  exactly, including its "raise rather than invent a default allowlist"
  design); one sink, `orm_entity_bulk_assign` (builds and executes a
  parameterized `UPDATE ... SET ...` at runtime from whatever keys survive
  in `value_expr` — column *names* come from the array's keys, bound
  *values* are always parameters). Unlike every other sink here (each a
  single-line `value_expr` interpolation, since each handles one tainted
  scalar), this sink's template needs its own runtime PHP `foreach` to
  build both the SET-clause text and a positionally-matching bound-values
  array — real new implementation surface, not a reuse of
  `sql_identifier_order_by.php.j2`'s single-value-substitution pattern.
  `php_current`'s own `_MODULE_SET_BY_SHAPE`/`_PAGE_PARAMS` (a new
  `/account_settings.php` profile: `table: users`, `id_column: id`,
  `allowed_fields: (display_name, bio, avatar_url)`) and
  `fuzzlab/labgen/conformance/static_precheck.py`'s
  `STATIC_PRECHECK_BY_SHAPE[("mass_assignment", "orm_entity_bulk_assign")]
  = UNINFORMATIVE` (needed for `tests/test_labgen_mass_assignment.py`'s
  static-precheck test, which `static_precheck_status()` would otherwise
  `KeyError` on for an unregistered shape) — both discovered as real gaps
  during implementation, not anticipated by the reviewed change-control
  draft, and reflected back into it per the draft's own "a real divergence
  found during implementation gets reflected back into the entry" rule —
  were also added. New manifest `lab/manifests/mass_assignment_sample.yaml`
  (`class: mass_assignment`, a new `vuln_class` value; confirmed this is a
  plain open string in both `lab/schemas/manifest.schema.json` and
  `fuzzlab/labgen/schema.py`, not a closed enum) carries the vulnerable/
  secure minimal pair, both cells sharing the identical
  `sink_context.required_neutralizations: [mass_assignment]` (the static-
  per-sink-family convention every existing pair already follows).
  Explicit deferral, unchanged from the reviewed draft: the other 8
  `orm_entity_bulk_assign` ops (JS/GraphQL/Sequelize-shaped op names from
  the corpus's Node anchors that do not map naturally onto this registry's
  plain-PDO idiom), `php_laravel`/`python_fastapi`/`node_express` reusing
  these same registered names for their own native rendering, and the
  other 19 new sink families `FR-LAB-58` left registry-only. Verified:
  both cells render via `PhpCurrentEmitter`, `php -l` clean, `verdict()`
  derives `VULNERABLE`/`trivial` and `SECURE` respectively, 20 new tests in
  `tests/test_labgen_mass_assignment.py` pass; `lab-generate --check`
  against the new manifest fails only on this sandbox's two pre-existing,
  unrelated environment gaps (`gitleaks` not on `PATH`, `numpy` not
  installed — confirmed identical against `lab/manifests/
  phase1_harder_shapes_sample.yaml` run the same way), the same gates
  every other manifest in this repository currently fails on here.

- **FR-LAB-60** *(`live_boot.py`'s capability-probe accuracy; `CC-LAB-0068`,
  `BUG-0033`/`PA-0035`, 2026-09-22).* `live_boot_available()`'s network-
  reachability check must exercise the **actual operation path** it gates
  (a real `composer install`'s proxy-aware HTTPS/Packagist round trip
  through composer's own HTTP client), never a raw-socket or other proxy
  signal for it that can diverge from the real path in an environment
  whose real HTTPS egress requires a configured proxy a bare
  `socket.create_connection` bypasses:
  - `_composer_network_probe()` runs a real, minimal `composer show -a
    psr/log` query (no local `composer.json`/lockfile touched) as the
    network half of `live_boot_available()`, replacing the prior bare
    `socket.create_connection((host, 443))` check (`_network_reachable`,
    `FR-LAB-52`'s original probe — now removed as unsound per `BUG-0033`'s
    RCA).
  - The probe enforces its own bounded, explicit timeout
    (`NETWORK_PROBE_TIMEOUT_S`) and reports unavailable (`False`) — never
    raises, never hangs the caller — on a `subprocess.TimeoutExpired` or
    any `OSError` starting the process.
  - Every later real subprocess step of the live-boot pipeline (`composer
    install`, `artisan key:generate`, run through the shared `_run()`
    helper) also enforces its own explicit, bounded `timeout=`
    independently of this probe passing — a passing probe is never relied
    on alone to guarantee a later real step won't hang — and `_run()`
    turns a `subprocess.TimeoutExpired` from any of them into a clear
    `LiveBootError` naming the command and bound, rather than letting it
    propagate uncaught or hang.
  - This requirement generalizes to any future `*_available()`-style
    capability probe added to this component: it must test the real,
    actual dependent operation's path, not an easier-to-check stand-in for
    it (`PA-0034`).

- **FR-LAB-61** *(DOM-based XSS sink class, `php_laravel`; `CC-LAB-0066`,
  2026-09-22).* Lane `L-P3.3c-DOM`, explicitly deferred out of the
  `L-P3.3c-G1..G6` cutover's scope (D-open-2, decided 2026-09-22: "a new
  client-side sink class, not a migration"), now built for real as its own,
  separately-prioritized lane:
  - A genuinely new `(vuln_class, sink_context.family)` shape,
    `("xss-dom", "dom_html_sink")` — distinct from `xss`/`html_body` and
    every other HTML shape this component supports, because the tainted
    value is read **and** written entirely client-side by embedded
    JavaScript and never reaches the server at all (matching
    `lab/ground-truth/labels.json`'s own `vuln_class: "xss-dom"`,
    `sink_context: "dom"` for `PFF-0007`/`PFF-0008`). `lab/safety_matrix.yaml`
    gained one new sink family (`dom_html_sink`, required concern
    `html_tag_break`) and one new op (`dom_text_content` — the client-side
    write uses `Node.textContent` instead of `Element.innerHTML`; `raw_concat`
    is reused for the unescaped baseline), both additive under the existing
    `version: 1`.
  - New modules — `dom_url_source` (a no-op: no PHP variable is ever
    extracted), `dom_text_content` (a transform that flips the client-side
    write mechanism rather than wrapping a PHP expression) and
    `dom_innerhtml_echo` (a Blade-view sink whose `<script>` block does the
    client-side read *and* write itself) — registered in **both**
    `fuzzlab.labgen.modules` (`php_current`, unrendered — for the shared
    minimal-pair vocabulary only, the same discipline `CC-LAB-0051` set) and
    `fuzzlab.labgen.emitters.php_laravel.modules` (rendered, via a new
    `_MODULE_SET_BY_SHAPE` entry).
  - `puppy-fort-factory/reviews.php` (`PFF-0007`, `#author=` from
    `location.hash`) and `feedback.php` (`PFF-0008`, `?ref=` from
    `location.search`) are reproduced as real `php_laravel` pages
    (`lab/manifests/phase3_php_laravel_real_pages_dom.yaml`), each with an
    authored secure twin (`dom_text_content`), through the unified
    URL-pinning mechanism (`_REAL_PAGE_KEY`/`_CANONICAL_CELL_KEY`,
    `CC-LAB-0052`) — both real `.php`-suffixed URLs served exactly as
    `labels.json` labels them.
  - `lab/ground-truth/migration-exemptions.yaml`'s `PFF-0007`/`PFF-0008`
    entries are **removed** (no longer exempt — now covered for real), and
    `fuzzlab.labgen.cutover_gate`'s coverage gate reflects it
    (`test_the_exemption_register_names_exactly_the_expected_cases` updated
    to `{PFF-1002, PFF-0003}`).
  - `fuzzlab.labgen.conformance.static_precheck.STATIC_PRECHECK_BY_SHAPE`
    gained `("xss-dom", "dom_html_sink") -> UNINFORMATIVE`: a PHP taint
    checker has no PHP-observable flow to analyze at all for this shape (the
    value never touches a PHP variable), more sharply uninformative than
    every SQL/escaping-context-mismatch shape already in that registry.
  - `fuzzlab.labgen.conformance.live_boot.LiveBootHarness` live-boots this
    manifest too (`test_live_boot_dom_manifest_serves_reviews_and_feedback`,
    `tests/test_labgen_conformance_live_boot.py`): the one live-boot proof in
    this component with no server-side round trip to differentiate on at
    all — both real pinned URLs return 200 and embed the right client-side
    shape (`innerHTML` vs. `textContent`), never a JS-*execution* proof
    (headless, JS-executing crawling stays the documented D-open-1 gap).
- **FR-LAB-62** *(the atomic cutover itself, `L-P3.3c-CUT`; `CC-LAB-0067`,
  2026-09-22).* With the cutover coverage gate green (`FR-LAB-51`) and every
  `L-P3.3c-G1..G6`/`L-P3.3c-DOM` sub-lane merged, the hand-built
  `puppy-fort-factory/` app is retired and the generator becomes the single
  source of the PHP target lab (D20 §7.2, satisfying `FR-LAB-8`). Concrete
  change list (`docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.5):
  - Layer-C assets re-homed: `config/waf-rules.json` -> `lab/waf-rules.json`
    (shared with `fuzzlab.mutation.filtermodel`, unchanged consumer contract);
    `sql/schema.sql` -> `lab/sql/schema.sql`; `includes/waf.php`/
    `includes/cov.php` -> Laravel middleware in the `php_laravel` scaffold
    (`app/Http/Middleware/FzlWaf.php`, backed by the framework-free
    `app/Support/WafFilter.php` so `tests/test_lab_waf.py`'s offline driver
    keeps exercising the *real* filtering logic with no framework bootstrap;
    `app/Http/Middleware/FzlCoverage.php`), both registered globally in
    `bootstrap/app.php`, same default-off (`PFF_WAF`)/opt-in (`X-Fzl-Cov`)
    toggle semantics as the retired PHP shims; `VULNERABILITIES.md` ->
    **generated** (`fuzzlab.labgen.vuln_map`, rendered from `labels.json` +
    `migration-exemptions.yaml`, so the human-readable map cannot state
    anything the machine-readable ground truth does not itself state).
  - `fuzzlab.labgen.assemble` (new module): the real-build entry point that
    generalizes `conformance.live_boot.LiveBootHarness._assemble` from one
    manifest's cells to every `lab/manifests/*.yaml` cell the `php_laravel`
    emitter supports (the same derivation `cutover_gate.
    compute_php_laravel_coverage` already proved sufficient — PA-0001/
    PA-0027, one derived walk, not two). `lab/web.Dockerfile` gained a `gen`
    build stage that runs it; `deploy.sh` (the bare-metal/manual path) calls
    it directly.
  - Runtime wiring re-pointed: `lab/compose.yaml` no longer bind-mounts an
    app directory (the app is a build artifact of the generator, never
    hand-edited in place) and its `db` seed mount + `fuzzlab.mutation.
    filtermodel`'s WAF-rules path both point at `lab/`-owned locations;
    `lab/web.Dockerfile` is a two-stage build (`gen` then `php:8.3-apache` +
    `composer install` for Laravel's own dependencies, which the hand-built
    vendor-free app never needed).
  - Ground truth: `lab/ground-truth/labels.json`/`injection-points.json`'s
    `target` changed from `"puppy-fort-factory"` to `"php_laravel"`
    (metadata only — `tests/test_labels_contract.py` updated to match; the
    coverage gate does not diff on this field, per §4.3.6.6a).
  - Route paths keep the real app's exact `.php`-suffixed URLs (§4.3.6.6a);
    `php_current` is **not** retired (§4.3.6.6b — it remains the second
    stack `L-P3.4`'s fingerprint-independence gate needs).
  - Deliberate, decided gaps this lane does not close (D-open-1/D-open-2,
    both decided 2026-09-22, out of this lane's scope): Layer B (the 10
    JS-rendered pages) has no generator emitter and its live, on-host
    crawler-discoverability exercise is lost — documented in
    `docs/ON_HOST_RUNBOOK.md` as a known, deliberate gap, not a defect.
  - Landed as two commits per the plan's "kept separate and revertable"
    instruction: one doing all the re-pointing/re-homing with
    `puppy-fort-factory/` still present and every test green, a second doing
    only the `git rm -r puppy-fort-factory/` once the first commit's own
    full test run (fast suite + the live-boot slow suite) was green.
> **✅ Cross-branch bookkeeping-ID collision, resolved (originally flagged
> 2026-09-22 by the Category 1 (E-commerce) pilot session; correction note
> added 2026-09-23 by this branch's own session).** This branch's `django`
> emitter Phase A originally landed as `FR-LAB-64`/`FR-LAB-65`, which
> collided with `FR-LAB-64`/`FR-LAB-65` independently claimed on
> `claude/second-target-cat1-ecommerce` (its own `node_express` CWE-1321
> module / `ruby_rails` Phase A harness) — neither branch merged into
> `main` yet, so each session picked "next free" off its own stale copy of
> this file. A fix commit on this branch (`a04127f`) renumbered this
> branch's entries to `FR-LAB-72`/`FR-LAB-73`. **That fix commit's own
> warning text (the paragraph this note replaces) had a real, self-
> introduced bug**, found on a later re-read of this file: its find/replace
> renumbered every `64`/`65` it found, including inside the warning
> message's own prose — so the warning ended up asserting "`FR-LAB-72`/
> `FR-LAB-73` collide with cat1's own `FR-LAB-72`/`FR-LAB-73`," a
> self-contradictory claim (72/73 was the *target* of the renumbering, not
> a second collision). **Verified directly against a real fetch of
> `origin/claude/second-target-cat1-ecommerce`'s current
> `requirements.md`, 2026-09-23: its highest `FR-LAB-` number is
> `FR-LAB-69`** — `FR-LAB-72`/`FR-LAB-73` do not exist there and do not
> collide with anything on that branch's actual pushed state (the prior
> note's "cat1 is through `FR-LAB-71`" claim was also not quite matched by
> that branch's real file content at fetch time, though close). This
> branch's `FR-LAB-72`/`FR-LAB-73` are confirmed clear as of this check;
> a session merging either branch into `main` later should still re-verify
> at merge time, since both branches keep advancing independently.
- **FR-LAB-72** *(the `django` emitter exists, Phase A scope; `CC-LAB-0090`,
  2026-09-22).* A new `Emitter` implementation
  (`fuzzlab.labgen.emitters.django.DjangoEmitter`) for category 2's
  (Social/UGC platforms) new-stack pick — Instagram/Python-Django, per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9 and
  `docs/research/category2-social-ugc-functionality-and-cwe-research.md`.
  **Phase A scope only**: exactly one shape, `(sqli,
  sql_numeric_literal)` — the same first shape `php_laravel`'s own L-P3.3a
  foundation lane and `node_express`'s own Phase A plan both picked — with
  a real vulnerable twin (unparameterized string-concatenated
  `connection.cursor()` query) and a real secure twin (a parameterized
  `%s` placeholder on the same raw cursor, never the ORM on either twin —
  deliberately isolating the vulnerable/secure axis to string-concat-vs.
  -parameterized-placeholder, the same axis every other stack's first
  shape proves, rather than confounding it with "ORM vs. raw SQL").
  Module composition (`fuzzlab.labgen.emitters.django.modules`) follows
  `node_express.modules`' own Tier-A/Phase-A port of the shared
  source/transform/sink/complexity category shape (`CR-LAB-0001` Addendum
  C) — its own registries, no import from or registration into
  `fuzzlab.labgen.modules` or any sibling emitter's registry. A
  `route`-category accumulator (`fuzlab_django_lab/urls.py`, Addendum D)
  is fed one fragment per supported cell via
  `DjangoEmitter.render_route_accumulator()`, sorted by cell ID at render
  time (verified deterministic across two calls with reversed cell order —
  `tests/test_labgen_django_conformance.py`). Passes Tier 0 (`python -m
  py_compile` on every generated view + the accumulator) and Tier 3
  (whole-manifest regenerate-and-diff, byte-deterministic) —
  `lab/manifests/phase_a_django_sample.yaml`,
  `tests/test_labgen_django_conformance.py`. The full module-inventory
  depth (mirroring `node_express`'s own three Tier-A shapes, let alone
  `php_laravel`'s full nine) is explicitly out of scope — a separate,
  later Phase B.
- **FR-LAB-73** *(`DjangoLiveBootHarness` proves a real boot + real HTTP
  payload differential; `CC-LAB-0090`, 2026-09-22).*
  `fuzzlab.labgen.conformance.django_live_boot.DjangoLiveBootHarness`
  structurally mirrors `php_laravel`'s own `LiveBootHarness`
  (`build()`/`_assemble()`/`request()`/`get()`/`post()`/`query_db()`/
  `close()`/context-manager protocol, the same bounded-timeout-at-every-
  subprocess-step discipline via its own `_run()`, and reuses
  `live_boot.py`'s existing `_NoRedirectHttpErrorProcessor`/
  `_NO_REDIRECT_OPENER` directly rather than reimplementing it — `BUG-0028`'s
  fix, generic `urllib` plumbing with no Laravel-specific behavior). The
  actual boot mechanism is new and venv-based, never Docker/`composer`: a
  real `python -m venv` + `pip install django==5.2.17` + `manage.py
  migrate --no-input` + `manage.py runserver` boot, **forced to
  `127.0.0.1`** regardless of `DJANGO_STACK_ENV.entrypoint_cmd`'s nominal
  `0.0.0.0` string (`CLAUDE.md`'s non-negotiable Safety section — loopback-
  only, never exposed; the same real-vs-nominal-field distinction
  `LiveBootHarness.build()` already has for `php_laravel`, now stated
  explicitly here rather than left to silent analogy). A real capability
  probe, `django_boot_available()`, exercises the actual operation path
  (a real, bounded `pip download django==5.2.17 --no-deps` round trip
  through whatever proxy is configured — `PA-0035`, generalizing
  `BUG-0033`'s `composer` fix to `pip`), never a bare socket/DNS check.
  **`DEBUG = False`/`ALLOWED_HOSTS` are forced** in the generated
  `settings.py` (`fuzzlab.labgen.emitters.django.stack_env.
  settings_py_content()`) — a correctness requirement, not a follow-up
  (mirrors `php_laravel`'s own `APP_DEBUG=false`, D20): left on, Django's
  own debug page would leak a full traceback + `SECRET_KEY`-adjacent
  settings on exactly the unhandled-exception path the vulnerable twin's
  SQLi payload triggers, contaminating this cell's single labeled
  vulnerability class with an unlabeled full-disclosure secondary one —
  **verified against the real served HTTP response body, not merely
  `settings.py`'s source text**
  (`tests/test_labgen_django_live_boot_single_shape.py::
  test_django_live_boot_debug_false_no_traceback_leak`). Real, executed,
  skip-guarded (PA-0005) proof, observed directly this session: a real
  `GET` with a syntax-breaking payload (`1' OR '1'='1`) against the
  vulnerable twin returns a real `500` with **no** stack trace (Django's
  plain error page, confirming `DEBUG = False` is enforced in practice,
  not just asserted); the identical payload against the secure twin's
  parameterized query returns a real `404` (safely treated as a
  non-matching literal string, never executed as SQL) — the same
  syntax-break-vs.-safely-bound differential every other stack's first
  live-boot test proves.
- **FR-LAB-88** *(the `django` emitter widened to Tier-A depth; `CC-LAB-0091`,
  2026-09-23).* `fuzzlab.labgen.emitters.django.DjangoEmitter` widened from
  Phase A's one shape to the same three-shape Tier-A bar `node_express`
  already proves: `sqli`/`sql_string_literal` (a login-style lookup, POST
  body source, an MD5'd-password-boilerplate sink, parameterized `%s`
  placeholders vs. quoted-string concatenation) and `xss`/`html_body` (a
  stored value — a real, seeded `profiles` row, read via a small fixed
  `_read_stored_bio()` helper every generated view carries unconditionally
  — echoed raw into an `HttpResponse` body vs. escaped with
  `django.utils.html.escape()`). Any cell whose `route.method` is not
  `GET` renders with `@csrf_exempt` (gated on the cell's own route method,
  never on which complexity template renders it, so a future POST-shaped
  cell on a different complexity cannot silently ship undecorated —
  verified by a whole-collection regression check,
  `tests/test_labgen_django_conformance.py::
  test_every_non_get_cell_is_decorated_with_csrf_exempt`). Passes Tier 0/
  Tier 3 for the widened manifest
  (`lab/manifests/phase_b_django_widen_sample.yaml`). The full
  `php_laravel`-depth nine-shape inventory, and the researched,
  corpus-grounded Django-specific XSS footgun (`mark_safe()`/`|safe`/
  `{% autoescape off %}`, `docs/research/category2-social-ugc-
  functionality-and-cwe-research.md` §4) stay out of scope — the latter
  deliberately deferred to Phase C's own corpus-grounded page design.
- **FR-LAB-89** *(real live-boot proof for both widened shapes, including
  a `PA-0034` adversarial test; `CC-LAB-0091`, 2026-09-23).* Real, executed,
  skip-guarded (PA-0005) proof in `tests/test_labgen_django_live_boot_
  phase_b.py`: a real `POST /api/login` request with a classic SQLi
  login-bypass payload (`' OR 1=1 -- `) against the vulnerable twin's
  unparameterized query returns a real `200` (a genuine, observable
  authentication bypass — no correct password required), while the secure
  twin's parameterized query returns a real `404` (no bypass); a real
  `GET /api/profile` request against a `profiles` row seeded with a real
  `<script>` payload returns the vulnerable twin's raw, unescaped payload
  in the response body, and the secure twin's real `&lt;script&gt;`-escaped
  form. **A real `PA-0034` adversarial test** (an input orthogonal to the
  feature's own SQLi demonstration — a mismatched HTTP method, `GET`
  instead of `POST`, against the newly `@csrf_exempt`-decorated `/api/login`
  view) confirmed the CSRF exemption does not silently widen the attack
  surface — this test **found a real code defect** (`BUG-0037`/`PA-0039`:
  the vulnerable sink concatenated a possibly-`None` value without a
  `str()` cast, crashing with a real `500` instead of the expected `404`
  on a `GET` request), fixed before this entry landed, and now passing.
- **FR-LAB-95** *(PicTrail app identity + `/post` real page; `CC-LAB-0092`,
  2026-09-23).* Establishes **PicTrail** — the Instagram-style app
  identity for the `django` stack's Phase C content (category 2 pilot;
  page-set design in `docs/research/category2-social-ugc-functionality-
  and-cwe-research.md` §6) — and lands its first real,
  ground-truth-bearing page: `GET /post?id=` (a post-detail lookup,
  grounded in the real Instagram post-detail feature researched there).
  Reuses Phase A's proven `sqli`/`sql_numeric_literal` module verbatim —
  zero new sink/source/transform/complexity code; the value of this
  increment is the **app-identity/ground-truth pattern** standing up end
  to end for the first time on this stack, not a new vulnerability shape.
  A new `_REAL_PAGE_CELL_IDS`-based URL-pinning mechanism in
  `render_route_accumulator` serves a real-page cell at its own declared
  route path instead of the generic `generated/{slug}/` pattern every
  illustrative cell uses (`php_laravel`'s own "a real page keeps its own
  exact URL" convention, ported at a much smaller scale — one real-URL-
  owning cell, no twin/canonical-cell machinery). Passes Tier 0/Tier 3
  for the new manifest
  (`lab/manifests/phase_c_picktrail_post_detail.yaml`).
- **FR-LAB-96** *(real, independent ground truth authored and cross-
  checked against a real live-booted request, including a `PA-0034`
  adversarial test; `CC-LAB-0092`, 2026-09-23).* A brand-new, independent
  ground-truth directory, `lab/ground-truth-picktrail-django/` (D9's
  three-file contract: `labels.json`/`injection-points.json`/
  `expectedresults.csv`), never touching or merging into `php_laravel`'s
  own `lab/ground-truth/` — this project's first-ever second, independent
  ground-truth set. One case, `PT-0001` (a fresh, opaque case-ID prefix,
  never `PFF-`/`LABGEN-*`), loaded for real via
  `fuzzlab.labels.contract.load()` and cross-checked, independently of
  the emitter's own `_ROUTE_PARAMS`/`_REAL_PAGE_CELL_IDS` internals,
  against a real booted request at the exact URL/param/method the ground
  truth names (`tests/test_labgen_django_live_boot_picktrail.py::
  test_ground_truth_case_matches_the_real_served_page`) — a real 200 on a
  legitimate lookup, a real 500 on the ground truth's own claimed SQLi
  payload. **A real `PA-0034` adversarial test** (citing `BUG-0031` as
  the directly analogous precedent — `php_laravel`'s own first
  real-URL-serving mechanism silently hardcoded the wrong HTTP method,
  producing false ground truth): a mismatched-method `POST` against the
  pinned, `GET`-declared `/post` URL. The real, observed result (found by
  the test, not predicted in advance) is a clean `403` (Django's own
  `CsrfViewMiddleware`, since a `GET`-method cell is never decorated with
  `@csrf_exempt`) — safe, no crash, no widened attack surface. **Named,
  accepted limitations of this first slice** (not oversights): the
  `{"id", "name"}` JSON response shape (shared with every other cell using
  the `single_statement` complexity) is not a fully realistic post-detail
  response shape; `lab/ground-truth-picktrail-django/` is not wired into
  `fuzzlab.core.config`'s global `ground_truth_dir`-driven consumers (the
  web dashboard, `cutover_gate.py`, `regression_gate.py`) — reachable,
  this entry, only through its own bespoke test; the right home for a
  second, per-target ground-truth set is
  `fuzzlab.harness.multitarget.TargetSpec.ground_truth` (Phase E, not
  attempted here).
- **FR-LAB-102** *(PicTrail's second real page, `/post/comments`, and this
  emitter's first real Django template-engine round trip; `CC-LAB-0093`,
  2026-09-23).* Django's real `mark_safe()`/template-autoescaping-bypass
  footgun, deliberately deferred from Phase B (`CC-LAB-0091`) — a
  **deliberate narrowing** of the fuller researched shape (`docs/research/
  category2-social-ugc-functionality-and-cwe-research.md` §4 row 2's
  `@mention`/`#hashtag` auto-linking-specific footgun): this entry builds
  the simpler, generic `mark_safe()`-on-the-entire-raw-comment version,
  stated explicitly, not implied as full grounding — the auto-linking
  shape stays a real, later increment. New `_ROUTE_PARAMS["/post/
  comments"]`; a new `(xss, html_body_template)` shape in
  `_MODULE_SET_BY_SHAPE`, backed by a new `lab/safety_matrix.yaml` sink
  family, `html_body_template` — genuinely new, not a rendering of
  `html_body`, because this sink is **safe by default** (Django's own
  template auto-escaping) rather than dangerous by default: the
  vulnerable twin's `mark_safe_wrap` transform uses the matrix's
  `introduces` mechanic to add the `html_tag_break` concern only when
  applied, mirroring `verbose_error_leak`'s own use of that mechanic at a
  different family. `DjangoEmitter.render()` returns a **second
  `EmittedFile`** for this shape (this emitter's first two-file-per-cell
  render) — a companion `.html` template, emitted as a **fixed Python
  string constant, never a `.j2` file rendered through this emitter's own
  Jinja2 module-composition system**: that system's Jinja2 environments
  use the same `{{ }}` delimiter Django's own template engine does, so a
  `.j2` generation template containing literal Django syntax
  (`{{ comment }}`) would collide with generation-time rendering — the
  exact collision `php_laravel`'s own Blade views avoid via raw-echo
  `{!! $value !!}` syntax for the identical reason (this project's
  pre-change review caught this before it was built, not after). Since
  the template content is identical between twins, it needs no per-cell
  interpolation at generation time at all — a real generation-time test
  (`tests/test_labgen_django_conformance.py::
  test_comment_template_is_never_evaluated_by_this_projects_own_jinja2_
  pass`) confirms the emitted bytes are exactly `{{ comment }}`,
  untouched, and byte-identical between twins. Real `TEMPLATES[0]["DIRS"]`
  settings change (`fuzzlab.labgen.emitters.django.stack_env.
  settings_py_content()`). Passes Tier 0/Tier 3 for the new manifest
  (`lab/manifests/phase_c_picktrail_comments.yaml`).
- **FR-LAB-103** *(real live-boot proof through the real Django template
  engine, both directions of the differential, plus ground-truth
  extension; `CC-LAB-0093`, 2026-09-23).* Real, executed, skip-guarded
  (PA-0005) proof in `tests/test_labgen_django_live_boot_picktrail_
  comments.py`: a real seeded `comments` row carrying a
  `<script>alert(1)</script>` payload (`DjangoLiveBootHarness`'s
  `seed_comment` constructor parameter, mirroring `seed_bio`'s
  convention); the vulnerable twin's real response body contains the raw,
  unescaped payload (`mark_safe()` genuinely defeats Django's
  auto-escaping through the real engine); **and, proven separately, not
  merely inferred** — the secure twin's real response body contains the
  real HTML-entity-escaped form (`&lt;script&gt;`), confirming Django's
  own default template auto-escaping is genuinely still in effect when
  the transform does not opt out of it. Ground truth extended (not a new
  directory) with `PT-0002` in `lab/ground-truth-picktrail-django/`
  (`vuln_class: "xss-stored"`, `sink_context: "html"` — required, not
  cosmetic, since `fuzzlab.mutation.xss`/`fuzzlab.audit.rules` both key
  XSS payload/audit selection off this field — mirroring `lab/ground-
  truth/labels.json`'s own `PFF-0005` shape on both counts), loaded for
  real and cross-checked, independently of the emitter's own internals,
  against a real booted request at the exact URL/method it names, seeded
  with the same adversarial payload.
- **FR-LAB-105** *(PicTrail's third real page, `/upload/link-preview`,
  and this emitter's first server-side-HTTP-fetch (SSRF, CWE-918) sink
  category; `CC-LAB-0094`, 2026-09-23).* Ports the already-reviewed,
  corpus-grounded shape (`docs/research/corpus-examples/ssrf/python/
  {vulnerable,idiomatic}-oembed-unfurl-4.py`) almost verbatim, reusing
  `lab/safety_matrix.yaml`'s existing `server_side_http_fetch` sink
  family unchanged — no new safety-matrix design needed. New
  `_ROUTE_PARAMS["/upload/link-preview"]`; a new `(ssrf,
  server_side_http_fetch)` shape in `_MODULE_SET_BY_SHAPE`, rendered with
  `render_only` complexity (not `single_statement`, whose fixed
  `if row is None: ...` epilogue assumes a DB-row sink shape this one
  does not have — a real defect caught by compiling the generated view
  before this entry landed, not shipped). Two new transform modules:
  `unchecked_url_fetch` (the vulnerable twin, an explicit self-documenting
  no-op matching the matrix's own `no_effect` row, not an empty pipeline
  relying on `identity`) and `scheme_and_resolved_ip_allowlist` (the
  secure twin: scheme check, then the URL's *resolved* IP via
  `socket.gethostbyname()` + `ipaddress.ip_address(...).is_private/
  .is_loopback/.is_link_local`, closing the DNS-rebinding gap a
  hostname-only allowlist leaves open — `lab/safety_matrix.yaml`'s own
  `hostname_allowlist`/`partial` vs. `scheme_and_resolved_ip_allowlist`/
  `neutralises` distinction). One deliberate adaptation from the corpus
  example, stated explicitly: `ALLOWED_SCHEMES = {"http", "https"}` here
  (the corpus example is `https`-only), so the live-boot adversarial
  payload is blocked specifically by the resolved-IP check, not
  incidentally by the scheme check. One shared sink module,
  `http_fetch_json_sink` (`requests.get(url, timeout=5,
  allow_redirects=False)` — `allow_redirects=False` closes a
  redirect-based allowlist bypass; the sink module itself never differs
  between twins, mirroring `CC-LAB-0093`'s own "sink is neutral, the
  transform is what secures/breaks it" shape). Fail-closed on validation
  failure: the secure twin's transform raises `ValueError`, propagated as
  Django's own real exception-handling path (`DEBUG=False`-safe, no
  stack-trace leak, the same mechanism `CC-LAB-0090`'s own test already
  proved) rather than a hand-rolled `try/except` wrapper. Passes Tier
  0/Tier 3 for the new manifest (`lab/manifests/
  phase_c_picktrail_link_preview.yaml`).

  **Shared-schema dependency, landed as its own standalone, pre-requisite
  entry** (`CC-LAB-0094a`, same date): `fuzzlab/labels/schemas/
  labels.schema.json`'s `vuln_class`/`sink_context` enums widened to add
  `ssrf`/`network` (plus five other values from the same widening) —
  needed for this entry's own ground truth (below) but landed separately
  since the schema is shared across every active category branch;
  adopts category 3's own already-reviewed widening (`fa8207d` on
  `claude/category-3-build-iuu5k9`) byte-identically rather than
  inventing different values, verified via `diff` and via
  `fuzzlab.labels.contract.load()` against every existing ground-truth
  directory.
- **FR-LAB-106** *(real live-boot proof of the SSRF differential, both
  directions, plus the `PA-0034` adversarial-direction test and
  ground-truth extension; `CC-LAB-0094`, 2026-09-23).* Real, executed,
  skip-guarded (PA-0005) proof in `tests/
  test_labgen_django_live_boot_picktrail_link_preview.py`, against a new,
  real, stdlib-only "internal service" HTTP-server fixture
  (`fuzzlab.labgen.conformance.django_live_boot.InternalServiceFixture`,
  bound via `("127.0.0.1", 0)` so port allocation and bind are one atomic
  call — no separate find-free-port race to mitigate; torn down via
  `server.shutdown()` + `server.server_close()` + a bounded
  `thread.join(timeout=5)` on its `daemon=True` serving thread, a
  concrete mechanism, not a `PA-0012` citation — `PA-0012` is
  asyncio-specific and does not apply to this stdlib-threaded fixture):
  the vulnerable twin's real response genuinely relays the fixture's own
  secret marker back to the caller (a real SSRF, not just "no validation
  code is present" at a source-level glance); **and, proven separately**
  — the secure twin genuinely rejects the identical payload with a real
  Django 500, specifically via the resolved-IP check (both schemes are
  allowed, so only that check can be blocking it). Per `PA-0034`, a third
  test proves the allowlist doesn't fail closed on everything: a
  well-formed, real, public, JSON-returning URL must still succeed on
  the secure twin — skip-guarded by a new, dedicated capability probe,
  `django_live_boot.external_http_probe(url)`, pointed at that exact URL
  (per `PA-0035`: reusing `django_boot_available()`'s own PyPI-
  reachability probe here would only prove pip-install-time reachability,
  a different operation from an app-level `requests.get()` at test-run
  time — the same class of mistake `BUG-0033` was for `composer`, not
  repeated here). Ground truth extended (not a new directory) with
  `PT-0003` in `lab/ground-truth-picktrail-django/` (`vuln_class:
  "ssrf"`, `sink_context: "network"`), loaded for real and cross-checked,
  independently of the emitter's own internals, against a real booted
  request at the exact URL/method/param it names, pointed at the
  internal-service fixture.

- **FR-LAB-64** *(prototype pollution, CWE-1321, `node_express`; `CC-LAB-0070`,
  2026-09-22).* Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4a's
  decided Category-1 (e-commerce) Walmart/Node cell list, the `node_express`
  emitter gained a real, dedicated vulnerable/secure pair for CWE-1321 --
  distinct from the incidental `cwe_unique` mention already present in
  `docs/research/corpus-examples/insecure-deserialization/node/manifest.yaml`
  (a bracket-lookup gadget side effect, never an actual pollution
  mechanism):
  - A genuinely new `(vuln_class, sink_context.family)` shape,
    `("prototype_pollution", "object_property_bulk_set")`, at a BFF-style
    `POST /api/preferences` endpoint that deep-merges the whole JSON
    request body onto a live, in-memory preferences object.
    `lab/safety_matrix.yaml` gained one new sink family
    (`object_property_bulk_set`, required concern `proto_pollution` --
    reusing the concern-id vocabulary `lab/patterns/sourcing/crosswalk.yaml`
    already named for this class) and two new ops, both additive under the
    existing `version: 1`: `unguarded_deep_merge` (`no_effect` -- no
    `__proto__`/`constructor`/`prototype` key guard) and
    `proto_key_filtered_merge` (`neutralises`, `neutralizes:
    [proto_pollution]` -- those three keys are skipped before ever reaching
    the merge's own assignment).
  - New modules -- `post_body_json` (the whole-body source, vs. one named
    field), `unguarded_deep_merge`/`proto_key_filtered_merge` (the two
    merge transforms) and `object_property_bulk_set` (the sink, which never
    itself decides which keys are legitimate, matching every other sink's
    convention) -- registered in **both** `fuzzlab.labgen.modules`
    (vocabulary-only there; no PHP emitter renders this JS/Node-runtime-
    specific mechanism, since a PHP array has no `Object.prototype`-style
    shared prototype chain for CWE-1321 to affect at all) and
    `fuzzlab.labgen.emitters.node_express.modules` (rendered, via a new
    `_MODULE_SET_BY_SHAPE` entry) -- the same "registered in the shared
    vocabulary even where only one emitter renders it" discipline
    `L-P3.3c-DOM`'s `dom_url_source` established.
  - New sink family `object_property_bulk_set` is genuinely distinct from
    the existing `orm_entity_bulk_assign` (mass-assignment) family: that
    family writes a *persisted* entity through a SQL identifier-charset
    guard; this one writes directly onto a *live in-memory* JS object,
    where an attacker-chosen `__proto__`/`constructor`/`prototype` key can
    escape the target object entirely and land on the shared prototype
    chain -- a mechanism SQL has no equivalent for at all.
  - New manifest `lab/manifests/prototype_pollution_node_sample.yaml`: two
    cells (`LABGEN-PP-0001` vulnerable / `LABGEN-PP-0002` secure),
    `stack_profile: node_express` -- no sibling manifest for another stack,
    since this shape has no cross-stack equivalent (unlike
    `mass_assignment_sample.yaml`'s `php_laravel` twin).
  - `fuzzlab.labgen.conformance.static_precheck.STATIC_PRECHECK_BY_SHAPE`
    gained `("prototype_pollution", "object_property_bulk_set") ->
    UNINFORMATIVE` -- the conservative default; unlike some of this
    registry's other rows, no Node-oriented static tool has actually been
    spot-checked against this shape in this project yet, so the row makes
    no claim about what a real tool could or could not find.
  - Proved for real, not simulated: both twins are rendered and each
    executed as a real `node` subprocess (Node v22.22.2, confirmed on the
    build host) against a real `{"__proto__": {"polluted": true}}` payload,
    asserting `Object.prototype`'s own state afterward -- `true` for the
    vulnerable twin, `false` for the secure twin -- plus a third check that
    both twins still merge an ordinary, non-adversarial key correctly (not
    a stub that merely rejects the whole body). See
    `tests/test_labgen_prototype_pollution.py`.
  - CWE-1333 (ReDoS), the second Node cell §9.4a's Category-1 decision
    names, was explicitly deferred to a later, separate lane at the time
    this requirement was written (a different, timing-differential oracle
    mechanism) -- now built, see **FR-LAB-69** below.

- **FR-LAB-65** *(`ruby_rails` emitter Phase A: real skeleton + live-boot
  harness; `CC-LAB-0071`, 2026-09-22).* This project's first Ruby-on-Rails
  stack (category 1's Shopify pick,
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §2/§9.4a/§9.5), scoped to
  Phase A only -- the real bootable skeleton and live-boot harness, proven
  against one illustrative cell; the real Rails-idiom vulnerability modules
  (webhook-signature, CWE-915 mass assignment, CWE-502 deserialization) are
  a separate, later requirement/lane.
  - New `fuzzlab.labgen.emitters.ruby_rails.RailsEmitter` (an
    `Emitter` implementation): renders exactly one
    `(vuln_class, sink_context.family)` shape, `("xss", "html_body")` --
    a query-string parameter (`get_param`) reflected, unescaped
    (`html_body_echo`), into a controller action's rendered view
    (`render_only`) -- and one `Cell.context_depth`, `"direct"`. Reuses the
    shared `get_param`/`identity`/`html_entity_escape`/`html_body_echo`/
    `render_only` module-name vocabulary `php_current`/`php_laravel`
    already use (not yet wired into `fuzzlab.labgen.minimal_pair`'s
    category map, which is `php_current`-module-registry-sourced per the
    open question this component's own requirements already record for
    `php_laravel` -- widening it for a third stack is left to whichever
    lane needs it, same as that existing note says).
  - New `fuzzlab.labgen.emitters.ruby_rails.route_accumulator.
    RouteAccumulator`: the Rails `config/routes.rb` analogue of
    `php_laravel.route_accumulator`'s `CR-LAB-0001` Addendum D pattern
    (`get '<path>', to: '<controller>#<action>' # cell: <id>` fragments,
    always sorted by cell ID, duplicate-URL detection) -- adapted for
    Rails' own `to: "controller#action"` string convention rather than
    Laravel's `[Controller::class, 'action']` array form.
  - New checked-in skeleton
    `fuzzlab/labgen/emitters/ruby_rails/stack/skeleton/`: a real, trimmed
    `rails new --minimal` output, Rails `8.1.3.1` (the verified-current
    stable release on rubygems.org as of 2026-09-22, not a guessed `7.x`),
    with one real migration (`db/migrate/..._create_users.rb` + a `User`
    model) for the minimal per-run-database schema this requirement's own
    dispatch instructions call for at minimum, though no Phase A cell reads
    or writes it yet. Exact provenance/trim list in
    `fuzzlab/labgen/emitters/ruby_rails/stack/README.md`.
  - New `fuzzlab.labgen.conformance.rails_live_boot.RailsLiveBootHarness`
    (`rails_boot_available()`): the Rails port of
    `conformance.live_boot.LiveBootHarness`. Real `bundle install`, a real
    `bin/rails db:prepare` against a real per-run SQLite database, a real
    `bin/rails server` (Puma) boot, and real HTTP requests via the same
    `urllib.request`-based client pattern (never a new HTTP client
    abstraction). `rails_boot_available()`'s network probe
    (`_bundle_network_probe`) runs a real, bounded `bundle lock` (the
    actual dependency-resolution phase of `bundle install`, not a raw
    socket/DNS check) against a throwaway `Gemfile`, per PA-0035 -- applied
    correctly for this package manager from the start, not retrofitted
    after a `BUG-0033`-shaped defect. Implements `Tier1Client`. Every real
    subprocess step has its own bounded timeout, enforced at a shared
    `_run()` helper.
  - Proved for real, not simulated: `tests/test_labgen_ruby_rails_live_boot.py`
    (1 test, `@pytest.mark.slow`, skip-guarded on `rails_boot_available()`)
    assembles, real-`bundle install`s, real-migrates, real-boots, and sends
    a real HTTP request to one illustrative cell, asserting the real
    response body contains the unescaped payload it sent -- plus a real
    `200` from Rails' own `/up` health endpoint. Passed for real: 1 passed
    in ~4.9s.
  - A real code defect was found and fixed during this same change (Rails'
    `ActiveSupport::Inflector#underscore` does not round-trip a
    cell-ID-derived class name whose digits abut a letter, so the
    generated controller's bare `render :show` resolved the wrong view
    directory) -- `docs/bugs/BUG-0034-*.md`/`PA-0036`; fixed by rendering
    via an explicit `render template: "<path>"` literal instead.
  - Explicitly out of this requirement's scope (a later, separate lane):
    the Shopify-research-shortlisted vulnerability modules themselves,
    widening `SUPPORTED_CONTEXT_DEPTHS`/`_MODULE_SET_BY_SHAPE` to full
    depth, wiring this stack into `multitarget.py`/Tier 2, and touching
    `lab/safety_matrix.yaml` for this stack.
    **Now built -- see FR-LAB-66/67/68 below.**

- **FR-LAB-66** *(`ruby_rails` Phase B, webhook-signature verification;
  `CC-LAB-0072`/`CC-LAB-0075`, 2026-09-22).* First code-generation
  implementation, in any stack, of the existing
  `webhook_signature_verification` sink family (`lab/safety_matrix.yaml`)
  -- Shopify's own `X-Shopify-Hmac-SHA256` mechanism
  (`docs/research/site-architecture-survey-functionality-shopify.md` §1,
  plan §9.4a's "Decided" block, item 1).
  - New shape `("webhook_signature", "webhook_signature_verification")` in
    `RailsEmitter._MODULE_SET_BY_SHAPE`. New source
    `raw_request_body` (`request.body.read`) and new sink
    `webhook_signature_verification` (recomputes an HMAC-SHA256 over the
    raw body with a fixed lab secret and compares it to the
    `X-Shopify-Hmac-SHA256` header). Reuses the existing
    `naive_string_compare`/`constant_time_compare` op vocabulary verbatim
    (`lab/safety_matrix.yaml` already had these rows from an earlier,
    Node-only corpus pass; no new op minted).
  - New manifest `lab/manifests/webhook_signature_rails_sample.yaml`
    (`LABGEN-RR-0002` vulnerable/naive-`==`, `LABGEN-RR-0003` secure/
    `ActiveSupport::SecurityUtils.secure_compare`).
  - Proved for real, two ways
    (`tests/test_labgen_ruby_rails_webhook_signature_live_boot.py`): (1) a
    real HTTP round trip against both booted twins, forging a real valid
    HMAC and a tampered one, confirming both twins correctly accept/reject
    (the naive-vs-constant-time difference is a timing side channel, not a
    functional bypass, per `lab/safety_matrix.yaml`'s own `partial`/D20
    framing); (2) a real, isolated Ruby timing microbenchmark
    (`RailsLiveBootHarness.run_ruby`, new in this change -- see
    `CC-LAB-0075`) run inside the booted cell's own `bundle exec`,
    demonstrating that plain `String#==` is measurably timing-variable by
    early-vs-late mismatch position (~4.8x ratio measured) while the real
    `ActiveSupport::SecurityUtils.secure_compare` from this app's own
    resolved gem is not (~1.02x). Deliberately uses large (200,000-byte)
    synthetic strings to make the effect measurable within a bounded,
    non-flaky test, not this cell's own ~44-byte digest.

- **FR-LAB-67** *(`ruby_rails` Phase B, CWE-915 mass assignment;
  `CC-LAB-0073`/`CC-LAB-0075`, 2026-09-22).* First Ruby/Rails-idiomatic
  instance of the existing `orm_entity_bulk_assign` sink family
  (`lab/safety_matrix.yaml`, previously implemented only by `php_laravel`'s
  own `DB::table(...)->update()` twin) -- Rails' own unrestricted
  `permit!` vs an explicit `permit(:a, :b)` strong-parameters allowlist
  (plan §9.4a's "Decided" block, item 2).
  - New shape `("mass_assignment", "orm_entity_bulk_assign")` in
    `RailsEmitter._MODULE_SET_BY_SHAPE`. New source `all_params_nested`
    (`params.require(:user)`) and two new, Rails-strong-parameters-
    specific ops in `lab/safety_matrix.yaml`/`ruby_rails.modules`:
    `permit_bang_unrestricted` (`no_effect`) and
    `strong_params_explicit_allowlist` (`neutralises`,
    `[mass_assignment]`) -- genuinely new, since no other stack's op
    vocabulary already names Rails' own `permit!` escape hatch. New sink
    `orm_entity_bulk_assign` (Rails' own `ActiveRecord#update!` against
    the checked-in `users` table).
  - Extends the FR-LAB-65 skeleton with a new migration
    (`db/migrate/20260922000001_add_role_to_users.rb`) adding the one
    privilege-relevant column (`role`) the pair needs, seeding one real
    `shopper1` row via the migration's own `up` block (this stack's
    per-run-SQLite analogue of `php_laravel`'s `LiveBootHarness`-side
    `REAL_SCHEMA_SQL` seed).
  - New manifest `lab/manifests/mass_assignment_rails_sample.yaml`
    (`LABGEN-RR-0004` vulnerable, `LABGEN-RR-0005` secure).
  - Proved for real
    (`tests/test_labgen_ruby_rails_mass_assignment_live_boot.py`): a real
    HTTP PATCH against each booted twin with a `role` field alongside the
    legitimate `bio` field -- the vulnerable twin's real ActiveRecord write
    sets `role` to the attacker's value (`"admin"`), the secure twin's real
    write silently drops it (stays `"customer"`). Each twin gets its own
    fresh harness (and therefore its own fresh per-run database) so one
    twin's write cannot leak into the other's assertion.

- **FR-LAB-68** *(`ruby_rails` Phase B, CWE-502 insecure deserialization;
  `CC-LAB-0074`/`CC-LAB-0075`, 2026-09-22).* First Ruby/Psych instance of
  the existing `object_deserialization` sink family
  (`lab/safety_matrix.yaml`, not previously implemented by any emitter in
  code) -- `YAML.unsafe_load` vs `YAML.safe_load`, CVE-2013-0156's own
  mechanism applied directly rather than through Rails' historical XML-
  parameter-parser entry point (plan §9.4a's "Decided" block, item 3).
  - New shape `("insecure_deserialization", "object_deserialization")` in
    `RailsEmitter._MODULE_SET_BY_SHAPE`. New source `post_param`
    (reused shared-vocabulary name). Two new Psych-specific ops in
    `lab/safety_matrix.yaml`/`ruby_rails.modules`: `yaml_unsafe_load`
    (`no_effect`) and `yaml_safe_load` (`neutralises`,
    `[insecure_deserialization]`). New sink `object_deserialization`
    (reports the parsed value's real Ruby class, or the raised exception's
    class, as JSON).
  - `app/controllers/application_controller.rb` (the FR-LAB-65 skeleton)
    now `require "ostruct"` globally, so a `!ruby/object:OpenStruct` YAML
    tag is loadable at all -- required for both twins, since requiring a
    stdlib class is not itself the vulnerability.
  - New manifest `lab/manifests/insecure_deserialization_rails_sample.yaml`
    (`LABGEN-RR-0006` vulnerable, `LABGEN-RR-0007` secure).
  - Proved for real
    (`tests/test_labgen_ruby_rails_insecure_deserialization_live_boot.py`):
    a real HTTP POST carrying a `!ruby/object:OpenStruct` YAML payload --
    the vulnerable twin's real response reports `parsed_class: "OpenStruct"`
    (an attacker-chosen Ruby object was actually constructed server-side);
    the secure twin's real response reports
    `error: "Psych::DisallowedClass"` (rejected before construction). A
    third test confirms both twins still parse ordinary plain YAML
    identically (the minimal-pair invariant, proven over a real HTTP round
    trip).

- **CC-LAB-0075 cross-reference** *(shared Phase-B harness/tooling
  infrastructure the three requirements above depend on, 2026-09-22).*
  Not a new vulnerability shape itself: `RailsLiveBootHarness` gained
  `raw_body`/`headers` params on `request`/`post` (a webhook-signature
  check needs the exact raw bytes it signs, which `data`'s own
  `application/x-www-form-urlencoded` encoding would otherwise re-encode
  out from under a forged signature) and a `run_ruby` method (a real,
  isolated `bundle exec ruby` microbenchmark inside an already-installed
  cell's app directory). `fuzzlab.labgen.conformance.tier0` gained
  `ruby_available`/`lint_ruby`/`lint_ruby_emitted_files` (the Ruby analogue
  of `lint_php`/`lint_python`, this project's first). `ApplicationController`
  gained `skip_forgery_protection` (every Phase B cell is a non-GET write
  endpoint a real HTTP client hits directly, with no browser CSRF-token
  round trip of its own -- CSRF is orthogonal to every vulnerability class
  this lane builds). `fuzzlab.labgen.conformance.static_precheck` gained
  `UNINFORMATIVE` rows for the two genuinely new shapes (webhook-signature,
  insecure-deserialization); the mass-assignment shape reused its existing
  `CC-LAB-0063`/`0064` row (keyed on `(vuln_class, sink_family)` only, not
  `stack_profile`).

- **FR-LAB-69** *(ReDoS, CWE-1333, `node_express`; `CC-LAB-0076`,
  2026-09-22).* Per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`
  §9.4a's decided Category-1 (e-commerce) Walmart/Node cell list (the
  second Node cell, deferred by `FR-LAB-64` above until this shape's own
  timing-differential oracle mechanism existed -- see `FR-FUZZ-12`,
  `docs/components/07-fuzzing-harness-and-oracle/requirements.md`), the
  `node_express` emitter gained a real, dedicated vulnerable/secure pair
  for CWE-1333:
  - A genuinely new `(vuln_class, sink_context.family)` shape,
    `("redos", "regex_highlight_match")`, on a new `/api/search` route
    (`_ROUTE_PARAMS`): a search/highlight endpoint that builds a `RegExp`
    from a user-supplied search term and highlights matches inside fixed
    content.
  - Vulnerable: `unescaped_regex_construct` -- `new RegExp(term, 'gi')`
    with no escaping, so a pathological pattern (e.g. `(a+)+$`) causes
    catastrophic backtracking. Secure: `regex_escape_construct` -- escapes
    every regex metacharacter (a new `escapeRegExp` helper, included
    unconditionally in every generated controller) before constructing the
    pattern, so it can only ever match itself literally.
  - `content_literal` (the endpoint's fixed, searched content) is a
    calibrated 22-character run of `'a'` embedded in otherwise-ordinary
    product copy, chosen so the vulnerable twin's blowup against `(a+)+$`
    is a clear, reliably-reproducible tens-of-milliseconds event -- never
    an open-ended multi-second/multi-minute hang.
  - Registered in `node_express`'s own `_MODULE_SET_BY_SHAPE` and,
    vocabulary-only (the `L-P3.3c-DOM`/`FR-LAB-64` precedent), in the
    shared `fuzzlab.labgen.modules` registry.
  - New manifest `lab/manifests/redos_node_sample.yaml`
    (`LABGEN-RD-0001` VULNERABLE/trivial, `LABGEN-RD-0002` SECURE), two new
    `lab/safety_matrix.yaml` rows plus a new `redos` concern in the
    matrix's concern vocabulary, and a new `static_precheck.py` row
    (UNINFORMATIVE -- no Node-oriented static ReDoS tool has been
    exercised against this shape in this project).
  - Proved for real, not simulated: `tests/test_labgen_redos.py` renders
    both twins for real and runs each as a real Node.js subprocess, timed
    with `process.hrtime.bigint()` inside the subprocess (excluding Node
    startup and Python subprocess overhead) against a benign term and
    `(a+)+$`. Measured: vulnerable twin ~55-70ms on the evil term (vs. <1ms
    on a benign term on the same handler); secure twin <1ms on both.
    Repeated 5x with no observed flakiness.
  - Judgment call, stated explicitly: the test's confirmation thresholds
    (`_VULNERABLE_FLOOR_MS=20`, `_SECURE_CEILING_MS=5`) sit with wide
    margin on both sides of the measured ~55-70ms/<1ms gap specifically so
    ordinary CI scheduling jitter cannot flip the verdict, while staying
    tight enough that a regression removing the escaping (or the
    calibrated content run) would still fail the test.
  - Out of this requirement's scope: wiring this stack into
    `fuzzlab/harness/multitarget.py`; running the new oracle mechanism
    against a live target.

- **FR-LAB-81** *(Phase C: MeadowMart BFF app identity + coherent routes +
  ground truth, `node_express`; `CC-LAB-0077`, 2026-09-23).* Per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4/§9.4a/§9.5's Category
  1 (E-commerce) Walmart/Node pilot, the two existing real `node_express`
  cells (`FR-LAB-64` prototype pollution, `FR-LAB-69` ReDoS) are assembled
  into one small, coherent app identity, the **MeadowMart BFF** (a
  fictitious brand; its shape -- a Node/Express layer aggregating legacy
  services -- is grounded in `docs/research/site-architecture-survey-functionality-walmart.md`):
  - `_REAL_PAGE_CANONICAL`/`_twin_url_for`/`_served_url_for`
    (`fuzzlab/labgen/emitters/node_express/__init__.py`): the canonical
    (vulnerable) cell of each real-page pair is served at the real BFF URL
    (`/api/preferences`, `/api/search`); its secure twin at a deterministic
    `-twin-<cell-id>` URL — the same mechanism `php_laravel`'s
    `_served_route_for`/`_twin_url_for` already uses, for the identical
    reason (a twin pair must coexist as distinct live routes in one running
    process). Every other cell keeps the prior `/generated/<cell-id>` URL.
  - Three new, always-included, genuinely inert surrounding routes in
    `render_route_accumulator`'s `app.js` (`/api/products`,
    `/api/orders/:orderId`, `/api/cart`) — no request input read or
    reflected by any of them; added purely for app-identity coherence, no
    manifest cell or ground-truth case of their own.
  - New `lab/ground-truth-meadowmart/` (`labels.json`/`injection-points.json`/
    `expectedresults.csv`, D9's out-of-band contract): opaque `MMART-NNNN`
    case IDs (distinct from `PFF-*` and the concurrent Rails lane's
    `FCART-*`), `target: "node_express_meadowmart_bff"`, 2 positive/2
    negative cases (the canonical cell and its secure twin, for each real
    page). Loads and validates via `fuzzlab.labels.contract.load`.
  - `fuzzlab/labels/schemas/labels.schema.json`: additive enum widening --
    `vuln_class` gains `prototype_pollution`/`redos`, `sink_context` gains
    `object_property`/`regex` (neither class could be expressed in the
    ground-truth contract before this).
  - Deliberately not attempted (out of scope, per the dispatch brief):
    merging the generic Tier-A sample manifest's illustrative SQLi/XSS
    cells (`lab/manifests/phase3_node_express_sample.yaml`) into this app;
    it stays a separate, unrelated fixture.

- **FR-LAB-82** *(Phase D: whole-app live-boot conformance for the
  MeadowMart BFF; `CC-LAB-0078`, 2026-09-23).* Per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §5's standard, closes the
  real gap every prior `node_express` proof left open (isolated
  `require()`-and-fake-`req`/`res` per cell, never the whole assembled app
  booted together). New `tests/test_labgen_node_bff_app.py`: assembles the
  full app (all four cells of both real manifests + the three
  `FR-LAB-81` inert routes, one `app.js` built by
  `render_route_accumulator` over the full cell set at once), a real
  network-reachable `npm install`, a real `node app.js` boot on
  `127.0.0.1`, and real HTTP (`urllib.request`) against every route:
  - Every inert page answers correctly.
  - Both real pages are reachable at their coherent, canonical BFF URLs;
    both secure twins at their own twin URLs.
  - The ReDoS cell's real, directly-observable real-HTTP timing
    differential (vulnerable canonical route slow on `(a+)+$`, secure twin
    fast) holds over the fully assembled app, not just in isolation.
  - Both preference-endpoint twins still merge ordinary (non-adversarial)
    payloads correctly over real HTTP.
  - Explicitly not re-derived here (stated in the test module's own
    docstring): the prototype-pollution differential itself, since
    polluting `Object.prototype` has no in-band HTTP signal by its real
    nature -- that differential stays proven by `FR-LAB-64`'s real,
    executed Node-subprocess test; this requirement additionally confirms
    the route it lives at is reachable, real, and coherent inside the
    fully assembled app.

- **FR-LAB-83** *(Phase E: MeadowMart BFF `TargetSpec` wired into
  `multitarget.py`; `CC-LAB-0079`, 2026-09-23).* Per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6, this app's half only
  (the concurrent Rails/Shopify lane owns its own `TargetSpec`). New
  `tests/test_labgen_node_bff_multitarget.py`: a real
  `fuzzlab.harness.multitarget.TargetSpec` (`base_url` from the same real
  live-booted app `FR-LAB-82` assembles; `ground_truth` from
  `FR-LAB-81`'s `lab/ground-truth-meadowmart`), run for real through
  `run_targets`/`transfer_summary` using the existing, unmodified
  `fuzzlab.tools.probesender.RequestsProbeSender` — a real HTTP sender, not
  a hand-written fake (unlike `tests/test_multitarget.py`'s existing
  fake-sender coverage of the harness plumbing, which this does not
  replace). Produces a real, scored `ScoreReport` (tp=0, fn=2,
  precision=recall=0.0 — because neither raw vuln_class name is mapped by
  `fuzzlab.core.runmode._VULN_TO_CATEGORY` nor known to
  `fuzzlab.audit.rules.known_categories()`, so zero candidates are ever
  nominated for either, a documented, flagged gap, not a defect — see
  `tests/test_labgen_node_bff_multitarget.py`'s own docstring for the full
  explanation) and a `transfer_summary` correctly reporting
  `generalizes=False` for a single target. A second run against the same
  live target gets a distinct `run_id`. Deliberately out of scope: wiring
  the category mapping/an audit rule so `prototype_pollution`/`redos` (the
  latter already has a downstream oracle confirmer,
  `RegexDosStrategy`/`FR-FUZZ-12`, under a different category string,
  `regular-expression`) can actually be nominated and confirmed; running
  both this target and the Rails/Shopify target together in one
  `run_targets` call (left for a follow-on step once both `TargetSpec`s
  exist, per §6 step 2's own note).

- **FR-LAB-84** *(Phase C: ForgeCart app identity + coherent routes +
  ground truth, `ruby_rails`; `CC-LAB-0080`, 2026-09-23).* Per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4/§9.4a/§9.5's Category
  1 (E-commerce) Shopify/Rails pilot, the four existing real `ruby_rails`
  shapes (`FR-LAB-65` reflected XSS, `FR-LAB-66` webhook-signature,
  `FR-LAB-67` CWE-915 mass assignment, `FR-LAB-68` CWE-502 insecure
  deserialization) are assembled into one small, coherent app identity, the
  **ForgeCart storefront + admin** (a fictitious brand; its shape -- a
  Shopify-style merchant storefront + admin -- is grounded in
  `docs/research/site-architecture-survey-functionality-shopify.md`):
  - `_REAL_PAGE_URL_BY_CELL_ID` (`fuzzlab/labgen/emitters/ruby_rails/__init__.py`),
    checked first by `url_path_for`: five new real-page cell IDs
    (`LABGEN-RR-RP-0001`..`0005`) get a real, coherent app URL (`/search`;
    two real Shopify webhook topics, `/webhooks/orders/create` vulnerable
    and `/webhooks/customers/update` secure; `/admin/customers/update`;
    `/admin/products/import`). Every pre-existing cell (Phase A's
    illustrative shape, Phase B's three sample pairs, `LABGEN-RR-0001`..
    `0007`) is untouched and keeps its prior `/cell/<slug>` URL and passing
    tests unchanged.
  - Five new, always-included, genuinely inert surrounding routes
    (`route_accumulator._STATIC_APP_ROUTES`: `/`, `/products`, `/cart`,
    `/admin`, `/admin/orders`) with their own checked-in skeleton
    controllers (`StorefrontController`/`AdminController`) -- no request
    input read or reflected by any of them; added purely for app-identity
    coherence, no manifest cell or ground-truth case of their own.
  - New `lab/manifests/shopify_forgecart_real_pages.yaml`: the five
    real-page cells, each reusing an existing shape's existing modules (no
    new vulnerability module). Four vulnerable, one secure (a second,
    distinct real Shopify webhook topic) -- a genuine negative real-page
    case, not an all-positive set. Uses `POST`, not `PATCH`, for the
    mass-assignment real page specifically so
    `fuzzlab.harness.auto.points_from_ground_truth` (which only treats
    GET/POST ground-truth points as actively auditable) can audit it
    without any change to that shared CORE/FUZZ-layer code.
  - New `lab/ground-truth-forgecart/` (`labels.json`/`injection-points.json`/
    `expectedresults.csv`, D9's out-of-band contract): opaque `FCART-NNNN`
    case IDs (distinct from `PFF-*` and the concurrent Node lane's
    `MMART-*`), `target: "ruby_rails_forgecart"`, 4 positive/1 negative
    case. Loads and validates via `fuzzlab.labels.contract.load`.
  - `fuzzlab/labels/schemas/labels.schema.json`: additive enum widening --
    `vuln_class` gains `webhook_signature`/`mass_assignment`/
    `insecure_deserialization`, `sink_context` gains
    `webhook_signature`/`mass_assignment`/`deserialization` (none of the
    three classes could be expressed in the ground-truth contract before
    this).

- **FR-LAB-85** *(Phase D: whole-app live-boot conformance for ForgeCart,
  plus `BUG-0035` fix; `CC-LAB-0081`, 2026-09-23).* Per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §5's standard, closes
  the real gap every prior `ruby_rails` proof left open (one or two cells
  booted in isolation, never the whole assembled app). New `tests/
  test_labgen_ruby_rails_whole_app_live_boot.py`: assembles all 12 cells
  this stack has ever built (Phase A's illustrative shape, Phase B's three
  sample pairs, `FR-LAB-84`'s five real-page cells) onto one real, single
  `bin/rails server` boot, with real HTTP against every route (the five
  real vulnerability pages, the five inert surrounding pages, the health
  check, and the pre-existing `/cell/<slug>` endpoints) and no route
  collision. While building this, found and fixed a real, 100%-reproducible
  defect: the checked-in skeleton's `Gemfile` never pinned the `json` gem,
  so an unconstrained `bundle install` resolved `json 3.0.2`
  (`activesupport` 8.1.3.1's own gemspec declares only `json >= 0`), whose
  keyword-only `JSON.parse` broke `ActiveSupport::JSON.decode`'s own
  positional call on the read path of every encrypted session-cookie read
  -- 500'ing every second request of any session, invisible to Phase A/B's
  single-request-per-test suite. Full RCA: `docs/bugs/BUG-0035-rails-
  skeleton-json-gem-arity-breaks-second-request-in-a-session.md`;
  preventive action `docs/PREVENTIVE_ACTIONS.md` `PA-0037`. Fixed by
  pinning `gem "json", "~> 2.7"` and regenerating `Gemfile.lock` for real.

- **FR-LAB-86** *(Phase E: ForgeCart `TargetSpec` wired into
  `multitarget.py`; `CC-LAB-0082`, 2026-09-23).* Per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6, this app's half only
  (the concurrent Walmart/Node lane owns its own `TargetSpec`). New
  `tests/test_multitarget_ruby_rails_forgecart.py`: a real
  `fuzzlab.harness.multitarget.TargetSpec` (`base_url` from the same real
  live-booted app `FR-LAB-85` assembles; `ground_truth` from `FR-LAB-84`'s
  `lab/ground-truth-forgecart`), run for real through
  `run_targets`/`transfer_summary` using the existing, unmodified
  `fuzzlab.tools.probesender.RequestsProbeSender`. Produces a real, scored
  `ScoreReport` with `tp>=1` (the real `/search` reflected-XSS case is
  genuinely confirmed -- `xss` is a category `run_auto`'s existing
  detection machinery already knows how to confirm, unlike this app's
  three brand-new vuln classes, which score 0 recall for the same
  documented-gap reason the concurrent Node lane's own `FR-LAB-83` names
  for its two brand-new classes) and a `transfer_summary` correctly
  reporting the target in `found_on`. A second run against a fresh boot of
  the same app gets its own distinct `run_id`. Deliberately out of scope:
  building a confirmation oracle for `webhook_signature`/`mass_assignment`/
  `insecure_deserialization`; running both this target and the Node target
  together in one `run_targets` call (left for a follow-on step per §6 step
  2's own note, same as `FR-LAB-83`).
- **FR-LAB-87** *(§6 step 2: combine ForgeCart + MeadowMart `TargetSpec`s in
  one `run_targets` call; `CC-LAB-0083`, 2026-09-23).* Closes the follow-on
  both `FR-LAB-83` and `FR-LAB-86` left open. New
  `tests/test_multitarget_category1_combined.py`: boots both apps for real
  and simultaneously (`RailsLiveBootHarness` for ForgeCart, the same
  `node app.js` boot helper `FR-LAB-83`'s test uses for MeadowMart, inlined
  since both must be live at once rather than as independent fixtures),
  builds both real `TargetSpec`s, and calls
  `run_targets([forgecart_spec, meadowmart_spec], store, sender_for=...)`
  once. Asserts: both outcomes scored, each with its own distinct `run_id`;
  ForgeCart's real `/search` XSS confirmation (`tp>=1`) holds unchanged
  when run alongside a second live target; MeadowMart's honest `tp==0`
  (documented gap, unchanged) also holds; `transfer_summary` reports
  `targets=2`, both names appear via `format_transfer`, and `generalizes`
  is correctly `False` (only one of the two scored targets has recall > 0
  — `generalizes` requires >= 2). This is the actual toolkit-side Phase 10
  `T10.6`-style deliverable for category 1: `fuzzlab.harness.multitarget`
  genuinely running and scoring two real, independent second targets in
  one call. Does not attempt a true `generalizes=True` demonstration
  (needs the `fuzzlab.core.runmode._VULN_TO_CATEGORY`/audit-rule wiring
  both `FR-LAB-83` and `FR-LAB-86` already flagged as separate follow-on
  work) and does not modify `fuzzlab/harness/multitarget.py` itself. This
  closes Category 1 (E-commerce)'s full Phase A-E build.
- **FR-LAB-112** *(vuln-corpus Phase 3: real gVisor dynamic-validation
  sandbox; `CC-LAB-0084`, 2026-09-23).* New
  `fuzzlab/tools/corpus_validation_sandbox.py`:
  `run_in_sandbox(language, script_path, authorized=True, ...)` executes
  a `docs/research/corpus-examples/` fixture under gVisor (`runsc run`
  against a hand-built OCI bundle, no Docker/containerd) with a
  deliberately empty network namespace (no interface ever attached — an
  SSRF/exfil attempt fails at the kernel-facing boundary `runsc`
  intercepts, not an allow-list), an `-overlay2=all:memory` ephemeral
  write layer (every write vanishes with the container), real cgroup v1
  `memory`/`pids` limits (a genuine OOM-kill and a genuine fork-bomb cap,
  not `ulimit` approximations), a non-root (`nobody`, uid/gid 65534)
  process with an empty capability set and `noNewPrivileges`, and a
  wall-clock timeout. Refuses to run anything without explicit
  `authorized=True` and appends a JSONL audit-log entry for every call.
  Implements `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s "Validation execution
  sandbox" section, required before any collected/manufactured pair can
  be dynamically executed to earn `validated: true`. Two documented
  deviations from that section's literal spec (both because this
  environment's egress policy blocks the blob-serving CDN every
  container registry checked routes through, so no base image is
  pullable): the sandbox mounts the host's own already-installed PHP/
  Python/Node interpreters as the OCI root instead of a purpose-built
  minimal image, and `runsc` is invoked directly rather than via `docker
  run --runtime=runsc` — see `CC-LAB-0084`'s own entry for the full
  reasoning and the accepted-risk framing. Every containment property is
  verified for real (not asserted from the mechanism's existence alone)
  in `tests/test_corpus_validation_sandbox.py`: network unreachability,
  filesystem ephemerality, the memory cap, the pids cap, the wall-clock
  kill, the non-root uid, the opt-in gate, and the audit log. New pytest
  marker `sandbox`, skip-guarded on `sandbox_available()` (same
  convention as `slow`'s `live_boot_available()` guard) so this degrades
  to a clean skip, never a failure, wherever `runsc`/cgroup v1 are
  absent. Does not itself validate any real corpus entry or flip
  `validated: true` anywhere — that is separate, not-yet-started work.

- **FR-LAB-74** *(`spring_boot`: the fourth emitter, category 3's Atlassian
  pick, "TrackerNest"; `CC-LAB-0130`, 2026-09-22).* Per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` sec 9 (the 12-app
  category expansion) and its own functionality/CWE research
  (`docs/research/category3-saas-functionality-and-cwe-research.md`), a
  new Java/Kotlin+Spring Boot emitter (`fuzzlab.labgen.emitters.spring_boot`)
  supporting exactly one shape as of this entry:
  `(vuln_class="ssti", sink_context.family="template_render")`, TrackerNest's
  `/wiki/pages/render` OGNL-injection cell (real Confluence
  CVE-2021-26084/CVE-2022-26134 shape — an attacker-supplied string
  compiled/evaluated as an OGNL expression via the real `ognl:ognl:3.4.13`
  library, vs. the secure twin's fixed macro-name-only lookup). A real,
  checked-in, minimal Spring Boot project skeleton
  (`fuzzlab/labgen/emitters/spring_boot/stack/skeleton/`, hand-authored to
  the shape Spring Initializr would produce — `start.spring.io` itself is
  unreachable from this build sandbox, see the skeleton's own `README.md`),
  a real capability probe (`spring_boot_boot_available()`, a bounded real
  Maven Central round trip, `PA-0035`/`BUG-0033`), and a live-boot harness
  (`fuzzlab.labgen.conformance.live_boot_spring_boot.SpringBootLiveBootHarness`)
  that assembles, real-builds (`mvn package`), boots (`java -jar`), and
  proves one real HTTP payload differential per cell (one cell per harness
  instance — the twin pair shares a route, so they are never live-booted
  together, mirroring `mass_assignment_laravel_sample.yaml`'s own precedent).
  Tier 0 (`mvn compile`) and Tier 3 (`regenerate_and_diff_emitter`/
  `render_whole_sample`) conformance cover both cells.
  **Deliberately out of scope for this entry** (tracked for a follow-on
  `CC-LAB-009x`): the XXE (`/issues/{id}/import`) and insecure-
  deserialization (`/integrations/webhook-payload`) cells `docs/research/
  category3-saas-functionality-and-cwe-research.md` sec 6b also designs for
  TrackerNest; ground truth (`labels.json`/`injection-points.json`); wiring
  into `fuzzlab.harness.multitarget`. **Tier 1/2 status: `[design]`-only**
  beyond the one proven live-boot cell, matching `python_fastapi`/
  `node_express`'s own stated status for a newly-built stack.

- **FR-LAB-75** *(`spring_boot`: TrackerNest's second cell, XXE; `CC-LAB-0131`,
  2026-09-22).* Extends `FR-LAB-74`'s `spring_boot` emitter with a second
  supported shape, `(vuln_class="xxe", sink_context.family="xml_parse_input")`
  — `POST /issues/import`, a real Java `javax.xml.parsers.
  DocumentBuilderFactory` parse of the raw request body (CWE-611). The
  vulnerable twin (`xml_external_entities_enabled`, already in
  `lab/safety_matrix.yaml` since `CC-LAB-0063`) leaves external-entity/
  DOCTYPE resolution at its default-permissive setting; the secure twin
  uses a **new, additive** safety-matrix entry this requirement also adds,
  `xml_external_entities_disabled` (Xerces/JAXP's `disallow-doctype-decl`
  feature — the real, standard Java XXE fix), giving this sink family the
  secure counterpart it lacked since `CC-LAB-0063`. Also adds
  `SpringBootLiveBootHarness.post()` (a raw-body-capable POST — the SSTI
  cell only ever needed `get()`) and a per-HTTP-method mapping-annotation
  lookup in `SpringBootEmitter` (`GetMapping`/`PostMapping` — this is the
  stack's first POST cell). Live-boot-proven: the vulnerable twin resolves
  a DOCTYPE-declared external entity into a real, harness-owned fixture
  file's contents (never a real host path); the secure twin returns a real
  HTTP 400 rejecting any DOCTYPE while still correctly parsing an ordinary
  document. **Still deferred** (per `CC-LAB-0130`'s original "Out of scope"
  section, restated here rather than left ambiguous): TrackerNest's third
  designed cell, insecure deserialization; ground truth; `multitarget.py`
  wiring.

- **FR-LAB-80** *(`spring_boot`: TrackerNest's third and final cell, insecure
  deserialization; `CC-LAB-0132`, 2026-09-22).* Extends `FR-LAB-75`'s
  `spring_boot` emitter with a third supported shape,
  `(vuln_class="insecure_deserialization", sink_context.family="object_deserialization")`
  — `POST /integrations/webhook-payload`, a real Java
  `ObjectInputStream.readObject()` deserialization of the raw request body
  (CWE-502). Reuses two **existing** `lab/safety_matrix.yaml` ops (no new
  entry needed, unlike `FR-LAB-75`'s XXE addition):
  `function_executing_deserialize` (vulnerable — unrestricted, constructs
  any classpath-present `Serializable` type the stream names) and
  `handler_registry_lookup` (secure — a `resolveClass()`-override allowlist
  permitting exactly one expected class,
  `com.fuzzlab.trackernest.generated.WebhookEvent`). Two new, fixed skeleton
  support classes (`WebhookEvent`, `UnexpectedType` — an inert POJO
  standing in for a real gadget-chain class, no RCE-capable code anywhere
  on this classpath) and a test-only `SerializeFixtureTool` helper (a plain
  `main()`, never Spring-managed) that produces real fixture bytes for the
  live-boot proof, since Python cannot emit Java's serialization wire
  format directly. Also adds `SpringBootLiveBootHarness.app_dir` (a public
  property exposing the assembled app's real root directory, needed so the
  live-boot test can run the fixture helper against the harness's own
  compiled `target/classes`) and an explicit `<mainClass>` in `pom.xml`'s
  `spring-boot-maven-plugin` config (disambiguating the executable jar's
  entry point now that a second `main()` exists on the classpath).
  Live-boot-proven: the vulnerable twin constructs and reports
  `UnexpectedType` for bytes naming it; the secure twin returns a real HTTP
  400 rejecting the same bytes while still correctly accepting real
  `WebhookEvent` bytes. **This closes TrackerNest's full three-cell
  designed set** (`FR-LAB-74` SSTI, `FR-LAB-75` XXE, this entry insecure
  deserialization) per `docs/research/category3-saas-functionality-and-cwe-research.md`
  sec 6b. **Still out of scope:** ground truth
  (`labels.json`/`injection-points.json`); `multitarget.py` wiring; "Huddle
  Hub" (the Slack pick, reusing `php_laravel`, not yet started).

- **FR-LAB-115** *(Huddle Hub: webhook-signature-verification cell on
  `php_laravel`; `CC-LAB-0133`, 2026-09-23).* Category 3's Slack pick,
  "Huddle Hub," gets its first designed cell — built on the existing,
  shared `php_laravel` emitter, not a new one, per §9.2's ledger note.
  New shape: `(vuln_class="webhook_signature_bypass",
  sink_context.family="webhook_signature_verification")`,
  `required_neutralizations: [weak_signature_comparison]` — a Slack-style
  Events-API-style callback receiver (profile-keyed at `/webhooks/events`
  for template-context lookup; actually served at the illustrative
  `/cell/<slug>` URL, since Huddle Hub has no migrated real page to anchor
  a pinned URL to). Reuses two existing `lab/safety_matrix.yaml` ops —
  `loose_equality_compare` (vulnerable: PHP's `==`/`!=` "magic hash"
  type-juggling bug) and `constant_time_compare` (secure: `hash_equals()`)
  — no new safety-matrix entry needed. New source/sink/transform modules
  registered in **both** `php_laravel`'s own registries and the shared
  `fuzzlab.labgen.modules` registry (`php_current`'s package) — required by
  this stack's own module-composition convention (the shared
  `fuzzlab.labgen.minimal_pair` classifier looks every composition-line
  name up there), with `php_current` gaining matching, classifiable module
  names/templates only, not a working cell of its own (mirrors the
  `dom_url_source`/L-P3.3c-DOM and `html_attribute_quoted_echo`/
  L-P3.3c-G6 precedent exactly). Also adds an additive `headers` parameter
  to `LiveBootHarness.request()`/`post()` (previously no way to send a
  custom request header at all). Live-boot-proven (real
  `composer install`/`artisan serve` boot/HTTP) for ordinary functional
  correctness on both twins, and separately, real-`php`-executed-proven for
  the actual "magic hash" comparison-operator differential itself (a live
  HTTP test cannot force the server's own freshly-computed SHA-256 HMAC
  output to itself be magic-hash-shaped — see `CC-LAB-0133`'s own
  change-control entry for the full reasoning). **Still deferred:** Huddle
  Hub's other two designed cells (SSRF via link unfurling, header injection
  in outgoing-webhook delivery); ground truth; `multitarget.py` wiring.

- **FR-LAB-116** *(Huddle Hub: SSRF-via-link-unfurling cell on `php_laravel`;
  `CC-LAB-0134`, 2026-09-23).* Extends `FR-LAB-115`'s Huddle Hub app with a
  second designed cell, `(vuln_class="ssrf",
  sink_context.family="server_side_http_fetch")` — a Slack-style "link
  unfurling" feature (server fetches a user-pasted URL to generate a
  message preview), profile-keyed at `/messages/unfurl`. Reuses the
  existing `get_param` source. Reuses two existing `lab/safety_matrix.yaml`
  ops — `unchecked_url_fetch` (vulnerable: zero validation) and
  `scheme_and_resolved_ip_allowlist` (secure: validates scheme + the
  *resolved* IP against private/reserved ranges, closing the DNS-rebinding
  gap the matrix's own `hostname_allowlist` op — deliberately not modeled
  in this cell — leaves open) — no new safety-matrix entry needed. Both
  twins bound their fetch with an explicit stream-context timeout (PA-0035
  spirit: a generated cell's own server-side fetch must never hang
  indefinitely, independent of which op is vulnerable). New module names
  registered in both `php_laravel`'s own registries and the shared
  `fuzzlab.labgen.modules` registry, per `FR-LAB-115`'s own established
  precedent. Live-boot-proven against a real local marker HTTP server this
  test owns: the vulnerable twin reaches it via both an IP literal and a
  resolved hostname; the secure twin rejects both forms with a real HTTP
  400 (confirmed via the marker server's own hit counter staying at zero)
  while still accepting a real public URL. **Still deferred:** Huddle
  Hub's third designed cell (header injection in outgoing-webhook
  delivery); ground truth; `multitarget.py` wiring.

- **FR-LAB-107** *(Huddle Hub: outbound-header-injection cell on
  `php_laravel`; `CC-LAB-0135`, 2026-09-23).* Extends `FR-LAB-115`/
  `FR-LAB-116`'s Huddle Hub app with its third and final designed cell,
  `(vuln_class="outbound_header_injection",
  sink_context.family="outbound_http_request_header_value")`,
  `required_neutralizations: [outbound_header_injection]` — a Slack-style
  outgoing-webhook delivery feature (an admin-configured trigger word is
  embedded in a custom header on the outbound POST to the configured
  webhook URL), profile-keyed at `/integrations/outgoing-webhook`. A
  genuinely new sink_family/concern in `lab/safety_matrix.yaml`
  (additive, no version bump) with two new ops: `raw_header_concat`
  (vulnerable: the trigger word is concatenated directly into a raw
  `"Name: value\r\n"` header block for PHP's stream-context `header`
  string option — an embedded `\r\n` splices in an arbitrary extra
  header the destination actually receives) and
  `structured_http_client_headers` (secure: Laravel's `Http` facade,
  Guzzle-backed — Guzzle's real PSR-7 `Request` constructor rejects any
  CRLF-bearing header value outright, caught and turned into an HTTP
  400). Both twins bound the outbound call with an explicit 5s timeout
  (PA-0035 spirit, matching `FR-LAB-116`'s own precedent) and read the
  destination webhook URL from `env('HUDDLEHUB_WEBHOOK_URL', ...)` with
  an RFC-2606 `.invalid`-TLD fallback so an unset env var fails closed
  rather than reaching something real; the URL itself is not a tainted
  parameter (kept out of scope for this header-injection-only cell). New
  module names registered in both `php_laravel`'s own registries and the
  shared `fuzzlab.labgen.modules` registry, per `FR-LAB-115`/`FR-LAB-116`'s
  own established precedent. Live-boot-proven against a real local
  marker HTTP server: the vulnerable twin's crafted trigger word
  (`innocuous\r\nX-Injected: proof`) results in the marker server
  genuinely receiving a real, separate `X-Injected: proof` header
  alongside the intact original `X-Huddle-Trigger: innocuous` header,
  verified by inspecting the marker server's own actually-parsed
  headers; the secure twin rejects the identical value with a real HTTP
  400 and never reaches the marker server, while still accepting an
  ordinary trigger word. **This closes Huddle Hub's full three-cell
  designed set** — Huddle Hub's *cell design* is now complete, but the
  app itself is not yet usable end-to-end: ground truth
  (`labels.json`/`injection-points.json`) and `multitarget.py` wiring
  remain deferred for both Huddle Hub and TrackerNest as a whole (see
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4/§9.6).

- **FR-LAB-108** *(TrackerNest: Phase C ground truth; `CC-LAB-0136`,
  2026-09-23).* TrackerNest's own `lab/ground-truth-trackernest/`
  (`labels.json`/`injection-points.json`/`expectedresults.csv`, target
  `spring_boot`, case prefix `TNEST`), per
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4 step 2 — never a
  `PFF-*` case. Describes the app instantiated with its three vulnerable
  twins deployed (`LABGEN-SSTI-0001`/`LABGEN-XXE-0001`/
  `LABGEN-DESER-0001`) — the only combination of these three same-route
  twin pairs that is simultaneously real-bootable at all (two
  `@RestController`s on the identical `@GetMapping`/`@PostMapping` path
  is a real Spring Boot "Ambiguous mapping" boot failure). Three cases:
  `TNEST-0001` (SSTI, `/wiki/pages/render`, GET, `macroExpr` query,
  rendering `server` — plain-text `ResponseEntity`, not JSON);
  `TNEST-0002` (XXE, `/issues/import`, POST, `body` — whole raw body, no
  named field, matching category 4/Netflix's own established
  convention); `TNEST-0003` (insecure deserialization,
  `/integrations/webhook-payload`, POST, `body` — same whole-raw-body
  convention). `fuzzlab/labels/schemas/labels.schema.json`'s
  `vuln_class`/`sink_context` enums extended additively (no version
  bump) for this category's 6 new classes, shared with `FR-LAB-109`
  below (landed once, in the same commit). Verified: `fuzzlab.labels.
  contract.load()` loads and cross-checks all 3 files without error;
  every case's exactly-one-tainted-param claim confirmed by reading each
  cell's actual rendered controller output directly.

- **FR-LAB-109** *(Huddle Hub: Phase C ground truth; `CC-LAB-0137`,
  2026-09-23).* Huddle Hub's own `lab/ground-truth-huddlehub/`
  (target `php_laravel`, case prefix `HHUB`), same §4-step-2 contract as
  `FR-LAB-108` above — never a `PFF-*` case. Each cell already has its
  own unique `/cell/<slug>` URL (`served_url_for()`, keyed on `cell_id`),
  so no route-collision constraint applies here the way it does for
  TrackerNest, but this ground truth still records only the three
  vulnerable cells' own URLs (never a paired "none" row for a secure
  twin), matching category 5/Booking.com's own established convention.
  Three cases: `HHUB-0001` (webhook-signature bypass,
  `/cell/labgen-hhb-0001`, POST, `X-Signature` **header** — the
  attacker-controlled input this CWE-347 case concerns is the signature
  header value itself, not the body field the HMAC is computed over);
  `HHUB-0002` (SSRF, `/cell/labgen-hhb-0003`, GET, `url` query);
  `HHUB-0003` (outbound header injection, `/cell/labgen-hhb-0005`, GET,
  `triggerWord` query). Verified the same way as `FR-LAB-108`. Cross-
  branch enum-naming drift flagged, not silently left: category 4
  independently named its own webhook class `webhook_signature` (this
  project's `webhook_signature_bypass` is a distinct string, no actual
  collision) — a merge-time reconciliation note, not a blocker.

- **FR-LAB-110** *(TrackerNest: Phase E — wire into `multitarget.py`;
  `CC-LAB-0138`, 2026-09-23).* TrackerNest's own `TargetSpec`
  (`spring_boot_trackernest`), a real boot of all 3 vulnerable cells
  together, run through `fuzzlab.harness.multitarget.run_targets` for
  real, per `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6 steps
  1-2. `tests/test_labgen_spring_boot_trackernest_multitarget.py`.
  Recall is honestly 0 (`ssti`/`xxe`/`insecure_deserialization` unmapped
  in `_VULN_TO_CATEGORY`, real follow-on work, not attempted here).

- **FR-LAB-111** *(Huddle Hub: Phase E — wire into `multitarget.py`;
  `CC-LAB-0139`, 2026-09-23).* Huddle Hub's own `TargetSpec`
  (`php_laravel_huddlehub`), a real boot of all 3 vulnerable cells
  together via the existing multi-cell-capable `LiveBootHarness`, run
  through `run_targets` for real.
  `tests/test_labgen_php_laravel_huddlehub_multitarget.py`. Two flagged,
  unfixed gaps: recall 0 (same unmapped-vuln-class reason as
  `FR-LAB-110`), and `fuzzlab.harness.auto.points_from_ground_truth`
  having no `location="header"` branch (a real, pre-existing latent gap
  first exercised by this project's own ground truth, flagged not fixed).

- **FR-LAB-104** *(Category 3 §6 step 2: both apps run together;
  `CC-LAB-0140`, 2026-09-23).* `tests/test_multitarget_category3_combined.py`
  runs both `TargetSpec`s from `FR-LAB-110`/`FR-LAB-111` through one
  `run_targets` call for real — two independent real boots (Java/Spring
  Boot + PHP/Laravel), two distinct real `run_id`s, a real combined
  `transfer_summary` (`targets: 2`, `generalizes: False` — correctly, no
  scored target has recall > 0 yet). Closes the toolkit-side half of
  category 3's own Phase 10 `T10.6`-style proof, matching category 1's
  own established combined-run precedent.

- **FR-LAB-76** *(`go_net_http` Phase A: this project's first Go target-lab
  stack; `CC-LAB-0170`, 2026-09-22, category 4 pilot — Media/streaming,
  Twitch pick, `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4/§9.5).*
  The toolkit supports a Go/`net/http` target stack at Phase-A depth: one
  real, live-bootable illustrative shape, matching every other stack's own
  Phase-A bar (`ruby_rails`'s `FR-LAB-77` being the immediately preceding
  precedent for this exact scope level).
  - `fuzzlab.labgen.emitters.go_net_http.GoEmitter` renders exactly one
    shape — `("webhook_signature", "webhook_signature_verification")`, an
    EventSub-webhook-receiver-shaped handler comparing two HMAC-SHA256
    digests either with Go's `==` (vulnerable — CWE-347, data-dependent-time
    comparison) or `crypto/hmac.Equal` (secure — constant-time). Reuses
    `lab/safety_matrix.yaml`'s existing `webhook_signature_verification`
    sink family and its existing `naive_string_compare`/
    `constant_time_compare` ops verbatim (added by `CC-LAB-0063` for the
    corpus-examples research) — no new safety-matrix entry was needed.
  - A real, checked-in skeleton (`fuzzlab/labgen/emitters/go_net_http/
    stack/skeleton/`: a bare `go mod init` plus a hand-written `main.go`
    wiring `net/http.NewServeMux()`) and a real live-boot harness
    (`fuzzlab.labgen.conformance.go_live_boot.GoLiveBootHarness`) that
    assembles, runs a real `go build`, boots the compiled binary, and
    serves real HTTP requests — proven end to end by
    `tests/test_labgen_go_live_boot.py` (real signature accepted/rejected
    for both twins, `@pytest.mark.slow`, skip-guarded on
    `go_boot_available()`).
  - `go_boot_available()`'s network probe (`_go_module_proxy_probe`) runs a
    real, bounded `go list -m -versions` against the real Go module proxy —
    built correctly the first time per `PA-0035`, not a bare socket check
    (`BUG-0033`'s exact mistake, avoided here for a new package manager).
  - Tier 0 (`go vet`/`gofmt -l`, `tests/test_labgen_go_net_http.py`) and
    Tier 3 (whole-manifest regenerate-and-diff,
    `tests/test_labgen_go_net_http_conformance.py`) both pass for the one
    illustrative cell pair (`lab/manifests/webhook_signature_go_sample.yaml`).
  - **Explicit scope call: no per-run database in this Phase A.** The one
    illustrative shape is stateless (no read/write to persisted data),
    unlike every other stack's own Phase-A illustrative shape — deferred to
    Phase B, when a data-touching shape (the CWE-918 SSRF pick recorded in
    `docs/research/site-architecture-survey-functionality-twitch.md` §2) is
    added for this stack.
  - **Deliberately out of scope here** (Phase B, per the plan's own
    "richer stack-idiomatic modules are a separate, later lane" split): the
    real Twitch EventSub message-ID/timestamp concatenation and 10-minute
    replay-window check, CWE-918 (SSRF), and any SQLi/XSS shape for this
    stack (which would be the first shape needing the per-run database
    above).

- **FR-LAB-77** — **SUPERSEDED (2026-09-23, `CC-LAB-0173`, marked in
  place per this project's living-doc convention — history stays below
  for context, not deleted).** The `java_spring_boot` package this
  requirement described is retired; its one capability (a JVM/Java target
  stack supporting the Netflix CWE-502 Jackson-deserialization cell) is
  now met by `spring_boot` — see `FR-LAB-93`. *(`java_spring_boot` Phase A:
  this project's first JVM/Java
  target-lab stack; `CC-LAB-0171`, 2026-09-22, category 4 pilot — Media/
  streaming, Netflix pick, `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`
  §9.4/§9.5).* The toolkit supports a Spring Boot 3.4.1/Spring MVC target
  stack at Phase-A depth: one real, live-bootable illustrative shape,
  matching every other stack's own Phase-A bar (`go_net_http`'s
  `FR-LAB-76` being the immediately preceding precedent for this exact
  scope level, within the same category-4 pilot).
  - `fuzzlab.labgen.emitters.java_spring_boot.JavaEmitter` renders exactly
    one shape — `("insecure_deserialization", "object_deserialization")`,
    a `/api/playback/resume`-shaped `@RestController`/`@PostMapping`
    handler that Jackson-deserializes its request body either
    polymorphically (vulnerable — CWE-502, `activateDefaultTyping()`
    lets an attacker-supplied type hint in the JSON pick the concrete
    class Jackson instantiates) or into a single, fixed, concrete DTO
    class (secure — no polymorphism). Reuses `lab/safety_matrix.yaml`'s
    existing `object_deserialization` sink family (added by `CC-LAB-0063`)
    but adds two new ops to it — `jackson_default_typing_deserialize`/
    `jackson_typed_allowlist_deserialize` — since none of that family's
    existing node/php/python ops names this Java-specific idiom.
  - **No route accumulator, a genuine architectural difference from every
    other routed emitter (`node_express`/`ruby_rails`/`go_net_http`) —
    Spring Boot's component scanning auto-discovers every generated
    `@RestController` class on the classpath at boot**, rooted at
    `Application.java`'s package (`com.fuzzlab.lab`); every generated cell
    controller is hardcoded to the fixed subpackage
    `com.fuzzlab.lab.cells`, guaranteed by construction, never derived
    from anything manifest-supplied (`CC-LAB-0171`'s own adequacy-review
    correction made this package/file-layout guarantee explicit).
  - A real, checked-in skeleton (`fuzzlab/labgen/emitters/java_spring_boot/
    stack/skeleton/`: a `pom.xml` inheriting `spring-boot-starter-parent`
    3.4.1 with `spring-boot-starter-web`, resolved for real against Maven
    Central) and a real live-boot harness
    (`fuzzlab.labgen.conformance.java_live_boot.JavaLiveBootHarness`) that
    assembles, runs a real `mvn package`, boots the packaged jar, and
    serves real HTTP requests — proven end to end by
    `tests/test_labgen_java_live_boot.py` (a real, observable
    deserialization code-path differential: the vulnerable twin accepts a
    caller-chosen type hint the secure twin rejects, `@pytest.mark.slow`,
    skip-guarded on `java_boot_available()`). This is a **code-path**
    proof, not a working `ysoserial`-style RCE gadget chain (neither twin
    has one on its classpath) and not a timing-side-channel proof (CWE-502
    has no timing property to prove) — stated explicitly per this
    project's own honesty convention for non-exploit-chain illustrative
    cells.
  - `java_boot_available()`'s network probe (`_maven_central_probe`) runs
    a real, bounded `mvn dependency:go-offline` against the checked-in
    skeleton's own `pom.xml` — built correctly per `PA-0035` from the
    first commit (a raw, unauthenticated `curl` against Maven Central
    directly returned a real `429` during this dispatch's own research;
    the probe never uses anything but the real `mvn` client, which
    resolves the same dependency successfully), and every Maven/JVM
    subprocess call inherits the full process environment rather than a
    hand-picked subset (the exact bug `CC-LAB-0170`'s own `go` probe had
    and fixed, applied correctly here from the start).
  - Tier 0 (`mvn -q compile`, `tests/test_labgen_java_spring_boot.py` —
    necessarily network-coupled for this stack, since compiling against
    Spring Boot needs the same resolved dependencies the live-boot harness
    needs; acknowledged, not silently assumed) and Tier 3 (whole-manifest
    regenerate-and-diff, `tests/test_labgen_java_spring_boot_conformance.py`)
    both pass for the one illustrative cell pair
    (`lab/manifests/insecure_deserialization_java_sample.yaml`).
  - **Explicit scope call: no per-run database in this Phase A.** Like
    `go_net_http`'s Phase A, the one illustrative shape is stateless (no
    read/write to persisted data) — deferred to Phase B, when a
    data-touching shape (the CWE-862 GraphQL-field-authorization pick, or
    the eventual DGS/GraphQL-federation layer itself) is added for this
    stack.
  - **Deliberately out of scope here** (Phase B): the GraphQL/DGS
    federation layer (`spring-boot-starter-graphql`, `@DgsComponent`/
    `@DgsData` resolvers, a federation directive set) and CWE-862
    (GraphQL field authorization), per
    `docs/research/site-architecture-survey-functionality-netflix.md` §2's
    own Phase B note.

- **FR-LAB-92** *(`go_net_http` Phase B, first increment: a second
  illustrative shape, CWE-918/SSRF; `CC-LAB-0172`, 2026-09-23, category 4
  pilot's Twitch pick).* Given its own new FR number rather than widening
  `FR-LAB-76` in place — a distinct vuln class with a genuinely different
  module-composition shape deserves independent discoverability, per this
  entry's own change-control review (which also corrected a backwards
  precedent citation for the opposite choice; see `CC-LAB-0172`).
  - `fuzzlab.labgen.emitters.go_net_http.GoEmitter` renders a second
    shape — `("ssrf", "server_side_http_fetch")`, a clip-thumbnail-fetch
    proxy handler (`GET /api/clips/thumbnail?url=...`) that server-side-
    fetches the caller-supplied URL either with no validation at all
    (vulnerable — CWE-918, `unchecked_url_fetch`) or after rejecting any
    scheme but `https` and rejecting a resolved IP that is loopback/
    private/link-local/unspecified (secure —
    `scheme_and_resolved_ip_allowlist`, checked against the *resolved*
    address, closing the DNS-rebinding gap a hostname-string-only
    allowlist would leave open). Reuses `lab/safety_matrix.yaml`'s
    existing `server_side_http_fetch` family/ops verbatim (added by
    `CC-LAB-0063`) — no new safety-matrix entry needed.
  - **A deliberate module-composition divergence from the webhook-
    signature shape:** the vulnerable/secure difference here lives
    entirely in *which sink module renders* (the validation-then-fetch
    logic is one inseparable operation, not a value transform composed
    before a shared sink) — the manifest's one op names a **sink**
    directly. `GoEmitter`'s per-module import table
    (`_MODULE_IMPORTS`) is keyed per-module, not per-shape, for exactly
    this reason: the two sinks this shape can render need different Go
    standard-library packages (`unchecked_url_fetch` needs no `net`/
    `net/url`; `scheme_and_resolved_ip_allowlist` needs both), found and
    fixed during implementation after a shape-wide fixed import list
    failed `go build`/`gofmt` with an "imported and not used" error.
  - Both sinks use a bounded `http.Client{Timeout: 5 * time.Second}`,
    never a bare `http.Get` — this shape's entire point is a real
    outbound call, so an unbounded client would let either twin's
    *generated code* hang against a slow/unresponsive target, not just
    this dispatch's own test harness.
  - Proven end to end by
    `tests/test_labgen_go_live_boot.py`'s real live-boot test: two
    throwaway loopback listeners this test process itself starts (a
    plain-HTTP one and a self-signed-TLS HTTPS one) isolate the secure
    twin's scheme-check rejection from its resolved-IP-allowlist
    rejection specifically — a corrected test design after the first
    draft's plan (a single plain-HTTP listener) would have proven only
    the scheme check, not the IP-allowlist logic the shape's own name
    promises (`CC-LAB-0172`'s own adequacy-review correction). Neither
    listener is a real external or production host, per `CLAUDE.md`'s
    lab-only/authorized-only discipline; a "secure twin successfully
    fetches some real allowed external target" positive case is
    explicitly deferred (no real target allowlist exists yet for this
    stack), not silently omitted.
  - Tier 0 (`go vet`/`gofmt -l`, now exercised over both shapes together)
    and Tier 3 both pass for the combined cell set
    (`lab/manifests/ssrf_go_sample.yaml`, alongside the existing
    `webhook_signature_go_sample.yaml`).
  - **Per-run database: still deferred, not added by this increment.**
    This shape doesn't read/write persisted data either — `modernc.org/
    sqlite` (a pure-Go, cgo-free driver) was verified to resolve cleanly
    through this sandbox's proxy during this dispatch's own research, for
    whichever future increment adds a data-touching shape.
  - **Deliberately out of scope here:** the richer real Twitch EventSub
    message-ID/timestamp-concatenation/replay-window check for the
    existing webhook-signature cell (refines an already-proven shape
    rather than adding vuln-class breadth, which this project ranks
    lower) — deferred to a later increment, not dropped.

- **FR-LAB-93** *(§9.2a Java/Spring Boot consolidation: Netflix's cell now
  lives in `spring_boot`; `CC-LAB-0173`, 2026-09-23).* Supersedes
  `FR-LAB-77`'s capability without restating it: the CWE-502 Jackson
  polymorphic-deserialization cell (playback-resume shape) is ported out
  of the now-retired `java_spring_boot` package into category 3's
  `spring_boot` package (TrackerNest), as `(vuln_class=
  "insecure_deserialization", sink_context.family="object_deserialization")`
  with a new op pair (`jackson_default_typing_deserialize`/
  `jackson_typed_allowlist_deserialize`) that already existed in
  `lab/safety_matrix.yaml` from the original entry — no new safety-matrix
  work needed.
  - **Real Jackson major-version API break found and resolved.**
    `spring_boot`'s skeleton pins `spring-boot-starter-parent` 4.1.1,
    which resolves Jackson 3.1.5 (`tools.jackson.databind.*`), not the
    Jackson 2 (`com.fasterxml.jackson.databind.*`) the original cell used
    against Spring Boot 3.4.1. Verified directly via `javap` against the
    real resolved jar before writing any port code: Jackson 3's
    `ObjectMapper` has no instance `activateDefaultTyping` method (moved
    to `JsonMapper.builder()...build()`), and `LaissezFaireSubTypeValidator`
    is package-private in Jackson 3 (cannot be referenced from generated
    code) — the ported vulnerable sink instead defines a small local
    `PolymorphicTypeValidator.Base` subclass with the same "allow any
    subtype" semantics. Confirmed working end to end in a real, isolated
    Maven probe before any template code was written.
  - **A real minimal-pair-vocabulary dispatch refactor.**
    `SpringBootEmitter._MODULE_SET_BY_SHAPE` keys `(vuln_class,
    sink_context.family) -> (source, complexity)`, with the sink selected
    separately by `cell.transform.ops`. The pre-existing
    `(insecure_deserialization, object_deserialization)` entry's default
    source (`request_stream`, publishing the raw `HttpServletRequest`
    itself) doesn't fit the ported Jackson ops, which need to read the
    body into a `byte[]` instead. A new `_SOURCE_OVERRIDE_BY_OP` map lets
    an op override the shape-level default source; only the two Jackson
    ops are in it, every other op/shape keeps its existing dispatch
    unchanged (re-verified: the pre-existing 32-test suite stays green
    byte-for-byte). **Known, stated narrowing:** this overrides only the
    source, not `_ModuleSet.complexity` — sufficient today (every op for
    every shape uses `single_handler`) but would need widening for a
    future op needing a different complexity module on an already-
    supported shape.
  - **Cell/page identity, addressed explicitly (not left as a bare
    "cosmetic" note).** The ported class renders under
    `com.fuzzlab.trackernest.generated` (the same package every other
    `spring_boot` cell/DTO already lives in) — a **build/skeleton-level**
    sharing decision only, the same shape `node_express` already has
    precedent for (hosting Walmart's cells without merging app identity).
    This does not make Netflix's cell "a TrackerNest page": no
    TrackerNest ground truth or page/route design is touched, and the
    ported cell keeps its own `LABGEN-JV-` cell-ID prefix (distinct from
    TrackerNest's own `LABGEN-DESER-`/`LABGEN-SSTI-` prefixes) so
    provenance stays distinguishable at the manifest/ground-truth level.
    Category 4's own Phase C page design (not yet started for either
    Netflix or Twitch) is unaffected.
  - **Both twins share one literal route
    (`POST /api/playback/resume`) safely**, matching TrackerNest's own
    `LABGEN-DESER-0001`/`0002` twin-pair precedent: `spring_boot`'s own
    live-boot harness (`SpringBootLiveBootHarness`) boots exactly one cell
    per real Spring Boot instance, never both twins in one running app,
    so an identical route across twins is not the ambiguous-mapping
    hazard it would be under a multi-cell-per-boot harness (the shape
    `go_net_http`/`java_spring_boot` both needed cell-ID-derived paths to
    avoid) — confirmed by reading the harness's own constructor signature
    and by a real boot hitting exactly this "Ambiguous mapping" Spring
    Boot startup failure during this port's own initial manual
    verification, before the correct single-cell convention was applied.
  - Proven end to end by two real live-boot tests
    (`tests/test_labgen_spring_boot_deserialization_jackson_live_boot.py`),
    each its own separate `SpringBootLiveBootHarness` instance:
    (a) the vulnerable twin accepts a type-hint-wrapped body naming an
    arbitrary class; (b) the secure twin accepts its own well-formed
    plain-JSON body and rejects the same type-hint-wrapped body — the
    same three assertions the original, now-deleted
    `tests/test_labgen_java_live_boot.py` made (a coverage-diff check
    confirmed this before that file was deleted), adapted to
    `spring_boot`'s real HTTP contract.
  - **`java_spring_boot` retired in the same dispatch**: the package,
    its conformance harness (`fuzzlab.labgen.conformance.java_live_boot`),
    its manifest, and its 4 test files are deleted. `grep`-confirmed no
    other file (including `fuzzlab/harness/multitarget.py`) referenced it
    by name, so nothing else on this branch broke — the full non-slow
    suite was re-run after the deletion to confirm (no regression, same
    pre-existing `gitleaks`-related failures as before).

- **FR-LAB-97** *(Phase C ground truth for category 4's Netflix and Twitch
  apps, plus additive `labels.schema.json` widening; `CC-LAB-0174`,
  2026-09-23).* Adds real, out-of-band ground truth (D9's contract) for
  every vulnerable cell category 4 has built so far, each app in its own
  directory with its own opaque case-ID prefix, mirroring category 5's own
  already-reviewed precedent (`lab/ground-truth-booking-clone/`) for both
  the per-app-directory layout and the schema-widening mechanism.
  - `lab/ground-truth-netflix-clone/` (`target: "spring_boot"`, prefix
    `NFLX-`): one case, `NFLX-0001`, for `LABGEN-JV-0001`
    (`POST /api/playback/resume`, CWE-502 Jackson polymorphic
    deserialization, `FR-LAB-93`). The tainted value is the entire raw
    request body (Jackson deserializes it polymorphically), not one named
    field, so `param` is the literal string `"body"` with
    `location: "body"` — recorded explicitly as a judgment call, since the
    schema has no "whole body, no field name" concept and no existing case
    in this project's ground truth had this shape before.
  - `lab/ground-truth-twitch-clone/` (`target: "go_net_http"`, prefix
    `TWCH-`): two cases — `TWCH-0001` for `LABGEN-GO-0001`
    (`POST /generated/labgen-go-0001`, CWE-347 webhook-signature,
    `FR-LAB-76`), whose tainted value is a request **header**
    (`X-Signature-256`); `param` is set to the literal header name, the
    same convention a query-param case uses the literal query-string key
    — this project's first header-carried ground-truth case, recorded as
    a judgment call. `TWCH-0002` for `LABGEN-GO-0003`
    (`GET /generated/labgen-go-0003`, CWE-918 SSRF, `FR-LAB-92`), an
    ordinary query-param case (`param: "url"`, `location: "query"`).
  - **Additive widening of `fuzzlab/labels/schemas/labels.schema.json`**:
    append three `vuln_class` enum values (`webhook_signature`, `ssrf`,
    `insecure_deserialization`, matching `Cell.vuln_class`'s real string
    values verbatim) and three `sink_context` enum values (`webhook`,
    `network`, `deserialization`, deliberately coarser than the internal
    `SinkContext.family` strings, e.g.
    `webhook_signature_verification`/`server_side_http_fetch`/
    `object_deserialization`, matching this schema's own existing
    convention of a coarser sink-context vocabulary). Purely additive: no
    existing enum value changed or removed, so every already-valid
    ground-truth directory (including the default `lab/ground-truth/`)
    stays valid unchanged — re-verified directly
    (`tests/test_labels_contract.py` stays green).
  - New offline tests, `tests/test_labels_contract_category4.py`: asserts
    concrete content (case counts, IDs, `vuln_class`/`sink_context`/
    `url`/`method`/`param`/`location` per case, opaque-ID checks) for both
    new directories, not just that `contract.load()` doesn't raise, plus
    one test re-confirming the default `lab/ground-truth/`'s own contract
    still loads/validates after the schema widening.
  - **Deferred scope, explicitly**: this only completes §4 Phase C step 2
    (author ground truth for cells as-built). Step 1 — designing a
    coherent page/route set spanning each app's chosen vulnerability
    classes, rather than ground truth over the single illustrative
    route(s) Phase A/B happened to build — remains open, larger,
    not-yet-started work for both apps, exactly as category 5's own
    tracker entry records the same gap for Booking.com/Expedia ("Phase
    C's 'coherent page/route set' bar... not yet begun"). Recorded here
    rather than left to imply Phase C is now fully done for category 4.

- **FR-LAB-98** *(Phase D: real Tier 1/2 conformance for two of category
  4's three cells; `CC-LAB-0175`, 2026-09-23).* Real, executed Tier 1
  (`fuzzlab.labgen.conformance.tier1.run_tier1_case`) and Tier 2
  (`tier2.LiveBootTier2Oracle`/`run_tier2_case`) proof for the SSRF cell
  (`LABGEN-GO-0003`/`0004`, `go_net_http`) and the Jackson-deserialization
  cell (`LABGEN-JV-0001`/`0002`, `spring_boot`), reusing Phase A/B's own
  live-boot harnesses through small local `Tier1Client`/`Tier2Client`
  adapter classes — no change to either harness's existing, already-used
  `request`/`post` methods. Both cells' verdicts confirmed for real (Tier
  1 and Tier 2 alike) against a real `go build`/`mvn package` boot.
  - **Open question, not a todo: the webhook-signature cell
    (`LABGEN-GO-0001`/`0002`, CWE-347) is not Tier-1/2-confirmable as this
    module is currently designed.** Tier 1/2's model is a single-request
    marker/functional differential; both twins of this cell accept a
    correct signature and reject an incorrect one identically for any one
    request (`naive_string_compare` vs `hmac.Equal` diverge only in
    comparison *timing*, which no single-request oracle can observe --
    `tests/test_labgen_go_live_boot.py`'s own docstring already states
    this same honesty rule for this cell's Tier 0/3 proof). Confirming it
    would need a genuinely new timing-differential oracle (statistical,
    multi-request timing measurement against a real boot) -- a different
    kind of Tier-2 oracle than `LiveBootTier2Oracle`'s marker-differential
    one, not built here. This mirrors the project's own existing
    precedent for a class whose flaw is not a single-request functional
    difference (the `identifier_charset_filter` open question above: an
    *identifier-swap* differential mode, not yet built either).

- **FR-LAB-99** *(Phase E: both apps wired into
  `fuzzlab.harness.multitarget` for real; `CC-LAB-0176`, 2026-09-23).*
  `TargetSpec`s for both apps, booted for real (`GoLiveBootHarness`,
  `SpringBootLiveBootHarness` — each gained an additive `base_url`
  property), run through `run_targets`/`transfer_summary` in one call with
  the project's existing `RequestsProbeSender` (real HTTP, never a fake
  sender) — satisfies §6's actual ask (construct the spec, run it, confirm
  it produces metrics and a `generalizes` verdict).
  - **Open, explicitly recorded (not a defect in this wiring): real
    detection on these three vuln classes is a structural zero today, for
    two independent reasons.** No audit `Rule` exists for
    `webhook_signature`/`ssrf`/`insecure_deserialization`
    (`fuzzlab.core.runmode._VULN_TO_CATEGORY` only maps `sqli`/`xss-*`) —
    the same class of gap category 1's own Phase E entry flagged for its
    own new vuln classes and left unattempted. And two of the three
    ground-truth points don't fit the generic pipeline's point model: the
    header-located webhook case is skipped by
    `fuzzlab.harness.auto.points_from_ground_truth` (which has no
    header-location case at all, not just no vulnerability-class rule —
    it falls into the DOM/browser skip path, a small additional
    mislabeling worth a future fix even though the point is correctly
    excluded either way); the whole-body-JSON deserialization case is
    included as a point, but `RequestsProbeSender`'s body-location
    convention (`data={param: value}`, form-urlencoded) cannot send valid
    JSON, so no payload could ever succeed through it. Only the SSRF
    query-param case is genuinely probed as designed. Building a new
    audit-rule category, a header-location point type, or a
    whole-body-JSON sender convention are each real, sized follow-on work
    — not attempted in this increment.
- **FR-LAB-78** *(open-redirect shape, `php_laravel`; `CC-LAB-0210`,
  2026-09-22).* Category 5's (Travel/booking/marketplaces,
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5) Booking.com
  pilot's first increment. Note on numbering: `FR-LAB-63` is already spoken
  for (`CC-LAB-0069`'s title cites it, although no `requirements.md` heading
  for it exists — a pre-existing bookkeeping gap in that earlier entry, not
  this one's to fix); this entry is `FR-LAB-78` to avoid a real collision.
  - A genuinely new `(vuln_class, sink_context.family)` shape,
    `("open_redirect", "http_redirect_location")`: a server-issued HTTP
    redirect (Laravel's `redirect()` helper) whose target is a tainted
    query parameter, grounded in Booking.com's real "continue to partner/
    payment provider" post-checkout-continuation and affiliate-redirect
    behavior (`docs/research/category5-travel-functionality-and-cwe-
    research.md` §1.1/§2.1, CWE-601) — the first new vulnerability class
    this project has added since `L-P3.3c-DOM`'s DOM-XSS shape (`FR-LAB-61`)
    and the first that is not an XSS/SQLi/mass-assignment variant.
    `lab/safety_matrix.yaml` gained one new sink family
    (`http_redirect_location`) and one new concern (`open_redirect`), both
    additive under the existing `version: 1`: `raw_concat`/`no_effect` (the
    unvalidated baseline) and `redirect_target_allowlist`/`neutralises` (an
    explicit same-origin-relative-path allowlist — not a "starts with `/`"
    prefix check, which protocol-relative/backslash-prefixed bypasses would
    defeat; see the transform's own docstring for the concrete character
    class and PA-0026's allowlist-adapter discipline it follows).
  - New modules — `redirect_target_allowlist`, `http_redirect_return`
    (a sink whose own rendered code is the method's terminal statement, the
    first sink shape in this project with no row/value to hand back) and
    `terminal_response` (the first **third** complexity module any stack's
    module set has needed, since neither `single_statement` nor
    `render_only` fits a sink that is itself the terminal `return`;
    originally named `redirect_response`, **renamed to `terminal_response`
    by `FR-LAB-90`/`CC-LAB-0211`** once a second, unrelated sink family
    needed the identical, already sink-agnostic wrapper — this entry
    updated in place to the current name, per this file's own living-doc
    convention; `CC-LAB-0210`'s append-only change-control record keeps the
    original name, as the historical record of what that change actually
    shipped) — registered in **both** `fuzzlab.labgen.modules` (`php_current`,
    unrendered — for the shared minimal-pair vocabulary only, the same
    discipline `CC-LAB-0051`/`FR-LAB-61` set) and
    `fuzzlab.labgen.emitters.php_laravel.modules`/`__init__.py` (rendered,
    via a new `_MODULE_SET_BY_SHAPE` entry and page profile,
    `/booking/continue`, `return_to`).
  - `fuzzlab.labgen.conformance.static_precheck.STATIC_PRECHECK_BY_SHAPE`
    gained `("open_redirect", "http_redirect_location") ->
    StaticPrecheckStatus.INFORMATIVE`: the vulnerable cell has nothing
    between source and sink, a textbook static-analysis finding, the same
    reasoning as `("xss", "html_body")`.
  - New manifest `lab/manifests/booking_open_redirect_sample.yaml`
    (`LABGEN-BC-0001`/`LABGEN-BC-0002`, the vulnerable/secure twin pair).
    Deliberately narrow first increment: does not yet cover the rest of
    Booking.com's researched functionality (search, listing, checkout,
    Extranet) or the research doc's other shortlisted candidates
    (price-integrity duplicate, CWE-1236 CSV-export) — those are later,
    separate increments inside this category's reserved
    `CC-LAB-0210`-`0249` block, tracked in
    `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4.
  - Real live-boot proof
    (`tests/test_labgen_open_redirect.py::test_live_boot_redirect_manifest_blocks_the_bypass_shapes_the_allowlist_is_meant_to_catch`),
    matching this component's `CC-LAB-0069` evidentiary bar: a real HTTP GET
    against both twins with four adversarial `return_to` payloads
    (`//evil.example`, `/\evil.example`, `https://evil.example`,
    `javascript:alert(1)`) plus one benign in-origin payload, reading the
    real (unfollowed — `LiveBootHarness`'s existing `_NoRedirectHttpErrorProcessor`,
    `BUG-0028`) `Location:` header back for each: the vulnerable twin
    reflects every adversarial target verbatim, the secure twin collapses
    every one of them to `/`, and both twins pass the benign in-origin
    payload through unchanged. This is the first caller of `LiveBootHarness`
    that needs a response header rather than only status/body, so
    `HttpResponse` gained an additive `headers: dict[str, str]` field
    (default `{}`, every pre-existing construction unchanged) and
    `LiveBootHarness.request()` now populates it from the real response.
- **FR-LAB-79** *(second, independent ground-truth directory; `CC-LAB-0210`,
  2026-09-22).* The ground-truth label contract (`fuzzlab.labels.contract`)
  now has a real, tested precedent for more than one `ground_truth_dir`
  serving more than one distinct lab app sharing an emitter/stack:
  category 5's Booking.com app gets its own
  `lab/ground-truth-booking-clone/{labels,injection-points}.json` +
  `expectedresults.csv` (one case, `BKNG-0001`), with its own opaque
  `BKNG-` case-id prefix (D9's out-of-band ground-truth contract; never
  `PFF-*`) — kept wholly separate from `lab/ground-truth/`'s `PFF-` cases
  and outside `fuzzlab.labgen.cutover_gate`'s `PFF-`-scoped coverage gate
  (verified: `cutover_gate.DEFAULT_LABELS_DIR` is hardcoded to
  `lab/ground-truth`, and `ground_truth_cases_for()` returns nothing for a
  non-`real_page` profile, so the new directory's case is never walked by
  that gate). `fuzzlab/labels/schemas/labels.schema.json`'s `vuln_class`/
  `sink_context` enums gain `"open_redirect"`/`"redirect"` (additive;
  existing enum values, and therefore every existing `PFF-` case, are
  unchanged and re-validated by this change's own test run).
  `tests/test_labgen_open_redirect.py::test_the_new_ground_truth_directory_loads_independently_of_the_default_one`
  is the first test in this repository to load two ground-truth
  directories in the same process and confirm neither's `contract.load()`
  call is affected by the other's existence.
- **FR-LAB-90** *(CSV/report export formula-injection shape, `php_laravel`;
  `CC-LAB-0211`, 2026-09-22).* Category 5's Booking.com app, second
  increment (first: `FR-LAB-78`'s `open_redirect` shape).
  - A genuinely new `(vuln_class, sink_context.family)` shape,
    `("csv_formula_injection", "csv_cell_value")`: a CSV/report export
    response whose cell content is a tainted query parameter, grounded in
    Booking.com's real Extranet/partner-admin booking-list export view
    (`docs/research/category5-travel-functionality-and-cwe-research.md`
    §1.1/§2.1, CWE-1236). `lab/safety_matrix.yaml` gained one new sink
    family (`csv_cell_value`) and one new concern (`csv_formula_injection`),
    both additive under the existing `version: 1`: `raw_concat`/
    `no_effect` (the unvalidated baseline) and `csv_formula_neutralize`/
    `neutralises` (a single-quote prefix applied when the value's first
    *non-whitespace* character is one of the five OWASP-documented
    CSV-formula trigger characters — `=`, `+`, `-`, `@`, a tab, or a
    carriage return — not merely a "starts with a trigger character" check,
    which the adequacy review for this entry demanded be closed rather than
    described in prose; see the transform's own docstring, `PA-0026`).
    This mitigation's scope is documented explicitly, not claimed
    unqualified: the standard, most broadly effective client-side control
    (reliable in Excel/LibreOffice Calc's normal CSV import path), not a
    claim that every spreadsheet application's every import path behaves
    identically (Google Sheets' handling has varied) — the concern-
    vocabulary header in `lab/safety_matrix.yaml` states this bound.
  - New modules — `csv_formula_neutralize` (transform) and
    `csv_export_row` (sink, another sink whose own rendered code is the
    method's terminal statement) — registered in **both**
    `fuzzlab.labgen.modules` (`php_current`, unrendered — shared
    minimal-pair vocabulary only) and
    `fuzzlab.labgen.emitters.php_laravel.modules`/`__init__.py` (rendered,
    via a new `_MODULE_SET_BY_SHAPE` entry and page profile,
    `/extranet/export`, `label`). This second terminal-statement sink is
    what surfaced that `FR-LAB-78`'s `redirect_response` complexity module
    was already fully sink-agnostic in implementation (a bare
    method-signature wrapper, no redirect-specific code at all) — **renamed
    to `terminal_response`** and reused for both shapes, rather than
    minting a second, near-duplicate complexity module, matching this
    project's own `single_statement`/`render_only` convention of naming
    shared modules by structural shape and reusing them across unrelated
    vuln classes/sink families (caught during this entry's own accuracy
    review; `FR-LAB-78`'s text above is updated in place to the current
    name, per this file's own living-doc convention, while `CC-LAB-0210`'s
    append-only change-control entry keeps the original name as the
    historical record of what that change actually shipped). The rename
    touches
    `fuzzlab/labgen/modules/__init__.py`,
    `fuzzlab/labgen/emitters/php_laravel/modules.py`, both stacks' own
    `templates/complexities/{redirect_response.php.j2 ->
    terminal_response.php.j2}`, `fuzzlab/labgen/emitters/php_laravel/
    __init__.py`'s `open_redirect` `_ModuleSet` row, and
    `tests/test_labgen_modules.py`'s `_DETERMINISM_CTX_BY_MODULE` key —
    the template content itself is byte-identical to before, only the name
    changed.
  - `fuzzlab.labgen.conformance.static_precheck.STATIC_PRECHECK_BY_SHAPE`
    gained `("csv_formula_injection", "csv_cell_value") ->
    StaticPrecheckStatus.UNINFORMATIVE`: a PHP taint checker has no
    CSV/spreadsheet-application model to recognize a single-quote prefix as
    a real sanitizer against this specific downstream-interpretation risk.
  - New manifest `lab/manifests/booking_csv_export_sample.yaml`
    (`LABGEN-BC-0003`/`LABGEN-BC-0004`, the vulnerable/secure twin pair,
    continuing this app's own cell-ID sequence from `FR-LAB-78`'s
    `LABGEN-BC-0001`/`0002`).
  - Real live-boot proof
    (`tests/test_labgen_csv_export_injection.py::test_live_boot_csv_manifest_neutralizes_every_formula_trigger_shape`),
    matching this component's `CC-LAB-0069`/`FR-LAB-78` evidentiary bar: a
    real HTTP `GET` against both live-booted twins with real
    trigger-character payloads (`=cmd|'/c calc'!A1`, `+1+1`, `-2+3`,
    `@SUM(1,1)`) plus the leading-whitespace-bypass shape
    (`" =cmd|'/c calc'!A1"`), reading the real CSV response *body* back and
    asserting the whole differential (header row, trailing cell, and the
    leading-quote-or-not on the tainted cell), not only its first byte.
    **Real finding surfaced by this proof, not assumed:** the `php_laravel`
    skeleton's default Laravel middleware stack (never disabled by
    `bootstrap/app.php`) already strips leading/trailing whitespace from
    every request input (`TrimStrings`) before either twin's own code
    runs — confirmed because even the vulnerable twin (no transform at
    all) never observed the leading-whitespace payload's leading space.
    This does not make `csv_formula_neutralize`'s own whitespace handling
    dead code (a different ingestion path would not get this framework-
    level assist), so a second, framework-independent test
    (`test_the_neutralize_expression_itself_closes_the_leading_whitespace_bypass`)
    evaluates the transform's exact rendered PHP expression directly via
    `php -r` against a raw, untrimmed string, proving the neutralizer's own
    check is correct on its own terms, not merely coincidentally covered by
    Laravel's default middleware.
  - Deliberately narrow, matching `FR-LAB-78`'s own scoping: does not yet
    cover the rest of Booking.com's researched functionality or the
    research doc's remaining shortlisted candidate (the price-integrity
    duplicate) — a later increment inside this category's reserved
    `CC-LAB-0210`-`0249` block. After this increment: 2 of 5 originally
    shortlisted shapes landed, 2 pages, still short of Phase C's "coherent
    page/route set" bar.
- **FR-LAB-91** *(ground truth's second case in the existing directory;
  `CC-LAB-0211`, 2026-09-22).* `BKNG-0002` appended to the *same*
  `lab/ground-truth-booking-clone/` directory `FR-LAB-79` created (not a
  third directory) — verified against the real loader
  (`fuzzlab.labels.contract.load_labels()` parses `labels.json`'s `cases`
  array with no one-case-per-file restriction, and explicitly guards
  against a duplicate `case_id`) that this is fully supported, not an
  extrapolation from `FR-LAB-79`'s own single-case precedent. Every one of
  the shared ground-truth contract's three files updated together, per the
  adequacy review's explicit demand (a `labels.json`-only change would have
  broken `load()`'s `expectedresults.csv` cross-check for the *whole*
  directory, `BKNG-0001` included, not just left `BKNG-0002` unscored):
  `labels.json` (`BKNG-0002`), `expectedresults.csv` (matching row),
  `injection-points.json` (the `label`-parameter entry).
  `fuzzlab/labels/schemas/labels.schema.json`'s `vuln_class`/`sink_context`
  enums widened again, additively, with `"csv_formula_injection"`/`"csv"`
  (existing values, and every existing case across both ground-truth
  directories, unchanged and re-validated by this change's own test run).
- **FR-LAB-100** *(price-integrity/business-logic amount-trust shape,
  `php_laravel`; `CC-LAB-0212`, 2026-09-23).* Category 5's Booking.com app,
  third increment (first: `FR-LAB-78`'s `open_redirect`; second: `FR-LAB-90`'s
  `csv_formula_injection`).
  - Reuses the **already-existing** `price_integrity_bypass` concern and
    `payment_charge_amount` sink family in `lab/safety_matrix.yaml`
    (`client_trusted_amount`/`trust_client_price_input`, both `no_effect`;
    `server_recomputed_amount`/`hook_delegated_recompute`, both
    `neutralises` → `neutralizes: [price_integrity_bypass]` — added by
    `CC-LAB-0063`) — no safety-matrix change needed. Verified (grep, not
    assumed) that no emitter on any stack rendered this shape before this
    entry; `php_laravel` is the first. Grounded in Booking.com's real
    checkout total computation
    (`docs/research/category5-travel-functionality-and-cwe-research.md`
    §1.1/§2.1) and the real QloApps (a real open-source hotel-booking
    engine, OSL-3.0) `Cart::getOrderTotal()` pattern
    (`docs/research/corpus-examples/ecommerce-logic/php/manifest.yaml`) —
    explicitly the lowest-novelty pick of that research doc's shortlist (a
    duplicate concern flavor, not a new CWE class), kept for its strong
    real-site grounding.
  - **The secure twin recomputes, it does not merely discard.** The
    adequacy review for this entry demanded the fix genuinely match the
    `server_recomputed_amount` op's own name and the cited QloApps
    grounding (the real fix recomputes the total from cart/selection
    state, never returns a bare hardcoded constant): the new
    `ServerRecomputedAmountTransform` looks the charge up in a page-profile
    -supplied `room_type_rates` table (an ordered tuple of `(room_type,
    rate)` pairs, each validated as a bare identifier / `\d+\.\d{2}`
    literal, PA-0026-style — no default, fails loud) keyed by a
    *non-tainted* `room_type` request parameter, falling back to
    `default_room_type`'s own rate for any unrecognized selection — never
    to the tainted `amount`. New sink `PaymentChargeInsertSink`
    (`DB::table('bookings')->insert(...)`), which — like
    `OrmEntityBulkAssignSink` — sets `$rows` rather than returning
    directly, so the *existing* `single_statement` complexity's own tail
    closes the method; no new/`terminal_response`-shaped complexity needed
    this time. Source reuses the existing `post_param` module unchanged.
    Both new modules registered in **both** `fuzzlab.labgen.modules`
    (`php_current`, unrendered — shared vocabulary only) and
    `fuzzlab.labgen.emitters.php_laravel.modules`/`__init__.py` (rendered),
    including `tests/test_labgen_modules.py`'s `_DETERMINISM_CTX_BY_MODULE`
    entries for both, added *before* the whole-repo `pytest` run (`PA-0040`,
    applied proactively this time — see `CC-LAB-0212`'s own Effectiveness).
    New page profile `/booking/checkout` (`amount`,
    `room_type_rates: (("standard","89.00"),("deluxe","149.00"),
    ("suite","249.00"))`, `default_room_type: "standard"`), new
    `_MODULE_SET_BY_SHAPE` row.
    `fuzzlab.labgen.conformance.static_precheck.STATIC_PRECHECK_BY_SHAPE`
    gained `("price_integrity_bypass", "payment_charge_amount") ->
    UNINFORMATIVE`.
  - **A real `bookings` table was missing and had to be added** — the
    adequacy review caught, before implementation, that
    `fuzzlab.labgen.conformance.live_boot._SCHEMA_SQL` (the SQLite schema
    every `LiveBootHarness` build provisions) had no table this shape's
    sink could write to; a live-boot proof would have failed to boot
    entirely without it. Added additively (`products`/`posts`/`users`
    unchanged) — `bookings(id, room_type, total_amount)`, no seed rows
    (each test inserts its own row via a real HTTP request).
  - New manifest `lab/manifests/booking_price_integrity_sample.yaml`
    (`LABGEN-BC-0005`/`LABGEN-BC-0006`, continuing this app's own cell-ID
    sequence).
  - Real live-boot proof
    (`tests/test_labgen_price_integrity.py::test_live_boot_price_integrity_manifest_ignores_the_client_amount_on_the_secure_twin`):
    real HTTP `POST`s against both twins with an attacker-controlled
    `amount` (`0.01`), reading the real inserted `bookings.total_amount`
    row back via `LiveBootHarness.query_db` (the same DB-introspection
    mechanism `CC-LAB-0056`'s real `register.php` `INSERT` proof already
    established) immediately after each twin's own request (querying only
    after both would read the same latest row twice — a real sequencing
    mistake this test's own first run caught and fixed before landing, not
    a design flaw). The vulnerable twin's real stored row equals the
    attacker's own `0.01`; the secure twin's always equals its own
    rate-table lookup (`89.00` default, `149.00` for a real `room_type=
    deluxe` selection — proving the lookup is genuinely data-driven, not a
    disguised constant), never the attacker's amount.
  - Deliberately closes this app's shortlisted-shape roster on `php_laravel`
    (3 of 3 unblocked shapes now landed — the remaining two, CWE-502
    Jackson deserialization and Spring Data SpEL injection, are
    Expedia/Java-Spring-Boot). 3 pages, 3 ground-truth cases; still short of
    Phase C's "coherent page/route set" bar (search, listing, checkout-flow
    completion, Extranet browsing — not yet begun as real page/route
    coverage, only as illustrative injection-shape cells).
- **FR-LAB-101** *(ground truth's third case in the existing directory;
  `CC-LAB-0212`, 2026-09-23).* `BKNG-0003` appended to the same
  `lab/ground-truth-booking-clone/` directory `FR-LAB-79`/`FR-LAB-91`
  already grew — consistent with `fuzzlab.labels.contract`'s real,
  multi-case-per-directory-supporting loader. All three of the shared
  ground-truth directory's files updated together (`labels.json`,
  `expectedresults.csv`, `injection-points.json`), per `FR-LAB-91`'s own
  established precedent. `fuzzlab/labels/schemas/labels.schema.json`'s
  `vuln_class` enum widened again, additively, with
  `"price_integrity_bypass"` — `sink_context` reuses the existing `"sql"`
  value rather than minting a new one (the sink mechanism genuinely is a
  SQL `INSERT`, and the adequacy review preferred reuse over an
  under-specified new token) — no `sink_context` schema change needed.

- **FR-LAB-94** *(`spring_boot` emitter package ported onto this branch;
  `CC-LAB-0213`, 2026-09-23).* Category 5's Expedia app (Java/Spring Boot)
  needs the `spring_boot` stack per §9.2a's cross-category consolidation
  decision: reuse category 3's `spring_boot` package (built for TrackerNest,
  `CC-LAB-0130`/`0131`/`0132`, and already the host of category 4's ported
  Netflix Jackson-deserialization cell, `CC-LAB-0173`) rather than building a
  from-scratch Java/Spring Boot emitter for Expedia, since this repository's
  multi-branch model keeps each category's own package private to its
  branch until a PR merge. This requirement records the mechanical port: the
  self-contained `fuzzlab/labgen/emitters/spring_boot/` package (emitter,
  `modules.py`, Jinja templates, the checked-in Maven skeleton) and
  `fuzzlab/labgen/conformance/live_boot_spring_boot.py` (real `mvn package`
  + `java -jar` boot harness, no central-registry wiring needed — confirmed
  by inspection that no CLI/`EMITTER_REGISTRY`/`static_precheck`/
  `minimal_pair` file references `spring_boot` at all; the stack is
  self-contained via Spring's own classpath component-scan, the same shape
  `python_fastapi` already established) were copied unmodified from
  `origin/claude/category-4-build-t9uz3y` (the more current of the two
  source branches, since it already carries category 3's TrackerNest work
  plus the Netflix port). The package's own 8 non-live-boot/live-boot test
  files were ported alongside it (a 9th, category-4-specific
  `tests/test_labels_contract_category4.py`, was excluded — it exercises
  `lab/ground-truth-netflix-clone/`/`-twitch-clone/`, directories that don't
  exist on this branch and aren't this category's to carry).
  `lab/safety_matrix.yaml` gained two small, additive ports discovered
  missing by running the ported tests rather than assumed present: the
  `xml_external_entities_disabled`/`xml_parse_input` secure-counterpart row
  (originally category 3's `CC-LAB-0131`/`FR-LAB-75`) and the
  `jackson_default_typing_deserialize`/`jackson_typed_allowlist_deserialize`
  rows for `object_deserialization` (originally category 4's `CC-LAB-0171`,
  carried through the Netflix-cell port `CC-LAB-0173`) — both were present
  on the source branches but not yet on this one, since `safety_matrix.yaml`
  is a shared file each category branch edits independently until merge.
  All 41 ported tests (33 non-live-boot + 8 real live-boot, the latter
  proving a real Maven build/boot/HTTP round trip for TrackerNest's SSTI/
  XXE/deserialization cells and the ported Netflix Jackson cell) pass
  unmodified on this branch after the two safety-matrix additions. This
  requirement is scoped to the port only — Expedia's own two shortlisted
  shapes (CWE-502 Jackson deserialization, now already available via the
  ported Netflix cell with no Expedia-specific work needed beyond a new
  page profile/manifest reusing the existing ops; Spring Data SpEL/`@Query`
  injection, confirmed genuinely new — no safety-matrix rows, emitter
  modules, or corpus precedent exist anywhere in this repository for it)
  are separate, later requirements.

- **FR-LAB-113** *(`spel_injection` shape, CWE-917, `spring_boot`;
  `CC-LAB-0214`, 2026-09-23).* Expedia's first own shape (distinct from
  `FR-LAB-94`'s ported Netflix Jackson cell, which is TrackerNest/
  category-4 code reused, not built for Expedia). A hotel-search endpoint
  (`GET /api/hotels/search-sort`) accepts a `sortBy` query parameter,
  parsed and evaluated as a Spring Expression Language (SpEL) expression.
  - Grounded in real Spring CVEs: CVE-2018-1273 (Spring Data Commons,
    `MapDataBinder`'s unrestricted `StandardEvaluationContext` — the
    exact mechanism this shape models) and CVE-2022-22980/CVE-2026-41717
    (Spring Data MongoDB `@Query`/`@Aggregation` SpEL parameter-binding
    injection). New `lab/safety_matrix.yaml` concern `spel_injection`
    (CWE-917) and sink family `spel_expression_evaluate`:
    `standard_evaluation_context_unrestricted`/`no_effect` (vulnerable —
    `new StandardEvaluationContext()`, permits type references/method
    invocation/bean resolution) vs.
    `simple_evaluation_context_restricted`/`neutralises` (secure —
    `SimpleEvaluationContext.forReadOnlyDataBinding().build()`, Spring's
    own documented CVE-2018-1273 fix). Both twins call the *identical*
    `SpelExpressionParser().parseExpression(tainted).getValue(context)`
    sequence; only the `EvaluationContext` object differs.
  - Went through this component's pre-change review gate before
    implementation. The accuracy pass returned clean ACCURATE on all 10
    checked claims (including a real `mvn dependency:tree` run
    confirming `spring-expression` ships transitively, no new Maven
    dependency needed). The adequacy pass returned INADEQUATE, catching
    a real, blocking classification error: the draft's own SSTI-shape
    analogy for this shape's `static_precheck` flag was backwards — no
    spring_boot `STATIC_PRECHECK_BY_SHAPE` precedent exists at all, and
    the correct classification is UNINFORMATIVE (both twins share an
    identical call shape, unlike SSTI's genuinely different vulnerable/
    secure API calls) — plus a real omission (the draft hadn't flagged
    that `labels.schema.json`'s `sink_context` enum needed widening).
    Both fixed before implementation.
  - `docs/research/category5-travel-functionality-and-cwe-research.md`'s
    SpEL-injection shortlist entry corrected in the same change,
    pre-implementation: MITRE/NVD classify this mechanism under CWE-917,
    not the CWE-89 the doc had originally labeled it (CWE-89 describes
    CVE-2016-6652's specific JPQL/SQL *outcome*, a different real CVE in
    the same family) — corrected in place with a dated note.
  - New `spring_boot` modules:
    `StandardEvaluationContextUnrestrictedSink`/
    `SimpleEvaluationContextRestrictedSink`, reusing the existing
    `QueryParamSource`/`single_handler` modules — no new source or
    complexity module needed. New `_MODULE_SET_BY_SHAPE` row, new
    `_PAGE_PARAMS` route. `STATIC_PRECHECK_BY_SHAPE` gains
    `("spel_injection", "spel_expression_evaluate") -> UNINFORMATIVE`.
  - New manifest `lab/manifests/expedia_spel_injection_sample.yaml`
    (`LABGEN-EXP-0001`/`LABGEN-EXP-0002`, Expedia's first cell-ID
    prefix, checked for collision against every other active branch).
  - Real live-boot proof
    (`tests/test_labgen_spel_injection_live_boot.py`): both twins
    receive `sortBy=T(java.lang.Math).abs(-99)` — a safe, side-effect-
    free type-reference/method-invocation canary (not a
    `Runtime.exec`-shaped payload, even in this lab-only sandbox).
    Vulnerable twin: real HTTP 200 with `99` in the body. Secure twin:
    real HTTP 400 (rejected `T(...)` reference). A second, benign
    property-path expression (`'price'`) proves the secure twin still
    functions for legitimate input.

- **FR-LAB-114** *(Expedia's own ground-truth directory;
  `CC-LAB-0214`, 2026-09-23).* New `lab/ground-truth-expedia-clone/`
  directory (opaque `EXPD-` case-ID prefix, never `PFF-*`) — matches
  `lab/ground-truth-booking-clone/`'s established per-app-identity
  precedent (the adequacy review's resolution: TrackerNest's own
  spring_boot cells have no ground-truth cross-check at all, so there
  was no "reuse a shared dir" precedent to follow; Expedia is a new app
  identity, like Booking/Netflix/Twitch, so it gets its own dedicated
  directory). One case, `EXPD-0001`, cross-checked by
  `fuzzlab.labels.contract` and by this shape's own test suite.
  `fuzzlab/labels/schemas/labels.schema.json`'s `vuln_class` enum
  widened additively (`spel_injection`); `sink_context` enum widened
  additively (`spel` — a fresh, plain-word token matching Booking's own
  `redirect`/`csv` minting convention, not forced into an existing
  bucket, per the adequacy review).

- **FR-LAB-117** *(`run_targets()` gains `oob`/`coverage`/`dbfault`
  passthrough; `CC-LAB-0177`, 2026-09-23).* `fuzzlab.harness.multitarget.
  run_targets()` forwards `oob`/`coverage`/`dbfault` to `run_auto()`
  (previously silently dropped, though `run_auto()` already accepted
  them), the same `None`-defaulted keyword shape as its existing
  `browser`/`scheduler`/`plugins` passthrough. Needed so a
  `TargetSpec`-driven multitarget run can actually use `FR-FUZZ-14`'s new
  SSRF oracle strategies — found and fixed while wiring category 4's own
  Phase E test to that new capability. One shared instance across every
  target in a batch is safe: `run_targets()` loops sequentially, never
  concurrently, over `specs`.

- **FR-LAB-118** *(Twitch's third real page: access-control/IDOR;
  `CC-LAB-0178`, 2026-09-23).* `go_net_http` gains a third shape,
  `("access_control", "db_row_by_id_lookup")` — a per-channel analytics
  lookup (`GET /channels/analytics?channel_id=<id>`) requiring the
  caller's own identity (a fixed demo `X-Broadcaster-Id` header, modeling
  only the ownership-check-bypass mechanism in isolation, never a real
  session/auth system) to match the requested `channel_id`. Reuses
  `lab/safety_matrix.yaml`'s existing `no_ownership_check`/
  `identity_match_before_fetch` ops verbatim (added by `CC-LAB-0063`) — the
  first lab-generator instantiation of this mechanism on any stack, a
  cross-branch collision check performed and recorded finding none.
  - `fuzzlab.labgen.emitters.go_net_http.GoEmitter` renders it via
    convention 1 (the same transform-modifies-a-value-feeding-a-fixed-sink
    shape the webhook-signature shape already uses): a new source
    (`read_channel_id_and_broadcaster_header`, mirroring
    `read_webhook_signature`'s two-value-publish convention), two new
    transforms, one new sink.
  - Cells `LABGEN-GO-0005` (vulnerable)/`LABGEN-GO-0006` (secure), served
    at `/generated/labgen-go-0005`/`-0006` per this stack's own
    cell-ID-derived route convention.
  - Real live-boot proof (three assertions): the vulnerable twin leaks
    another channel's analytics on a mismatched `channel_id`; the secure
    twin rejects the same mismatch with a real HTTP 403; the secure twin
    still serves the legitimate, matching-identity request.
  - Ground truth: `TWCH-0003` in `lab/ground-truth-twitch-clone/`
    (`vuln_class="access_control"`, `sink_context="object_lookup"`,
    additive schema widening).
  - **Not itself detection capability**: no audit rule or oracle strategy
    is added for `access_control` — a real, buildable follow-on (the
    differential an attacker-chosen `channel_id` vs. the caller's own
    identity produces), tracked in §8, not attempted here.

- **FR-LAB-119** *(Netflix's second real page: partner content-metadata
  ingestion, XXE; `CC-LAB-0179`, 2026-09-23).* Reuses TrackerNest's own
  already-built XXE shape (`raw_body` source,
  `xml_external_entities_enabled`/`_disabled` sinks, `CC-LAB-0131`) at a
  new Netflix route, `POST /api/content/import` — zero new generator
  code, only a new `_PAGE_PARAMS` entry + manifest + ground truth. Real
  grounding: DDEX's ERN messages (the B2B media-metadata-exchange
  standard) are confirmed XSD-validated XML, and Netflix is a confirmed
  EIDR participant (both facts, cited); the endpoint design itself is
  labeled as this manifest's own illustrative inference. Cells
  `LABGEN-JV-0003`/`0004`; ground truth `NFLX-0002`
  (`vuln_class="xxe"`, `sink_context="xml"`, both pre-existing enum
  values). Real live-boot proof (vulnerable resolves an external entity,
  secure rejects any DOCTYPE with HTTP 400, both still parse legitimate
  documents). **Accepted, explicitly-stated risk**: the shared XXE
  modules are not forked between TrackerNest and Netflix, so a future
  template change to one could silently affect the other — mitigated by
  a new joint regression test rendering both apps' XXE cells together
  every run. **Not itself detection capability, and not covered by
  Phase E's multitarget wiring**: `SpringBootLiveBootHarness` takes
  exactly one cell per real server instance, so `NFLX-0002` needs its
  own separate `TargetSpec`/hand-rolled multi-cell fixture (the same
  real, sized follow-on category 3's own `CC-LAB-0138` needed for
  TrackerNest) — not built here.
- **FR-LAB-120** *(Twitch's fourth real page: JWT `alg:none` signature
  confusion; `CC-LAB-0180`, 2026-09-23).* Instantiates `lab/safety_
  matrix.yaml`'s existing `jwt_alg_none_default`/`jwt_none_alg_opt_in`
  mechanism (`jwt_signature_verification` family, `CC-LAB-0063`, never
  before built on any stack) on `go_net_http`: `GET /channels/settings`
  (served `/generated/labgen-go-0007`/`-0008`), a channel-owner-only
  settings endpoint, Bearer-JWT-protected. A hand-rolled JWT parser/
  verifier, Go stdlib only (no third-party library, matching this
  stack's zero-dependency `go.mod`), modeling the real `auth0/
  node-jsonwebtoken` vulnerability (GHSA-8cf7-32gw-wr33, cited in
  `docs/research/corpus-examples/auth-session/node/vulnerable-1.js`):
  the vulnerable twin honors an attacker-chosen `alg:none` header,
  skipping signature verification entirely; the secure twin requires the
  token's own header to explicitly claim the one pinned algorithm
  (`HS256`) before any further processing. `hmac.Equal` (constant-time)
  used explicitly; a malformed/empty signature fails closed by
  construction (length-mismatch-safe). Cells `LABGEN-GO-0007`/`0008`;
  ground truth `TWCH-0004` (`vuln_class="jwt_algorithm_confusion"`,
  `sink_context="jwt"`, both new enum values, additively widened). Real
  live-boot proof (3 assertions: `alg:none` honored on the vulnerable
  twin; a garbage `HS256` signature still correctly rejected on the same
  vulnerable twin; `alg:none` correctly rejected outright on the secure
  twin). A real Go "declared and not used" compile bug (the same class
  `CC-LAB-0178`'s `broadcasterID` bug was) found and fixed before
  landing. **Not itself detection capability**: no new audit rule or
  oracle strategy is added here — deliberately split from this page per
  the pre-change review's adequacy pass, landed as its own separately-
  scoped follow-on (a real, buildable single-request differential is
  recorded, not attempted in this entry).
- **FR-LAB-121** *(Twitch's fifth real page: predictable session token;
  `CC-LAB-0181`, 2026-09-23).* Instantiates `lab/safety_matrix.yaml`'s
  existing `predictable_token_source`/`csprng_token` mechanism
  (`session_token_generation` family, `CC-LAB-0063`, never before built
  on any stack) on `go_net_http`: `POST /sessions/refresh` (served
  `/generated/labgen-go-0009`/`-0010`), a session-token-refresh endpoint.
  **Genuinely no tainted request input at all** — a real, third module-
  composition convention (`NoOpTokenRequestSource`, documented explicitly
  as new, not conflated with the SSRF shape's own Convention 2, which
  still has a real source): the manifest's one op names a sink module
  directly, the same mechanic Convention 2 uses, just without a real
  source alongside it. Vulnerable twin: `token := fmt.Sprintf("%d",
  time.Now().UnixNano())` (CWE-330); secure twin: 32 bytes from
  `crypto/rand`, hex-encoded. Cells `LABGEN-GO-0009`/`0010`; ground truth
  `TWCH-0005` (`vuln_class="weak_token_entropy"`,
  `sink_context="session_token"`, both new enum values, additively
  widened; `param="body"`/`location="body"`, the whole-body-point
  convention for no-per-field-param cases, even though the body is
  unused). Real live-boot proof (two consecutive vulnerable-twin tokens
  parse as decimal integers whose difference tracks real measured
  elapsed time; two consecutive secure-twin tokens never parse as
  decimal integers). **Not itself detection capability**: no new audit
  rule or oracle strategy is added here — deliberately split from this
  page per the pre-change review's adequacy pass (the same split
  `FR-LAB-120` established), landed as its own separately-scoped
  follow-on.
- **FR-LAB-122** *(Twitch's sixth real page: channel-profile mass
  assignment; `CC-LAB-0182`, 2026-09-23).* Instantiates
  `lab/safety_matrix.yaml`'s existing `unfiltered_object_assign`/
  `typed_schema_allowlist` mechanism (`orm_entity_bulk_assign` family,
  `CC-LAB-0063`; already built on `php_current`/`ruby_rails`/
  `php_laravel`, never before on `go_net_http`) on `go_net_http`:
  `POST /channels/profile` (served `/generated/labgen-go-0011`/`-0012`).
  Go has no ORM bulk-assign call to misuse, so the shape reuses this
  stack's own Convention 2 (the manifest's one op names a sink module
  directly, like the SSRF/weak-token-entropy shapes): the vulnerable
  sink `json.Unmarshal`s the raw request body directly onto a channel
  struct that already declares every persisted field, including
  `is_partner` (never exposed by this endpoint's own intended form,
  CWE-915); the secure sink unmarshals into a narrow DTO struct with
  only `display_name`/`bio`, then copies exactly those two fields.
  Route method is `POST`, not the task's own suggested `PATCH`
  (`labels.schema.json`'s `method` enum is closed to `GET`/`POST`).
  Cells `LABGEN-GO-0011`/`0012`; ground truth `TWCH-0006`
  (`vuln_class="mass_assignment"`, `sink_context="mass_assignment"` --
  both pre-existing enum values, no schema widening needed;
  `param="body"` (the whole-body-point convention `weak_token_entropy`'s
  own `TWCH-0005` already uses, not `ruby_rails`'s own single-named-field
  `param="user[role]"` convention -- required so `fuzzlab.harness.auto.
  points_from_ground_truth` marks this point's content type as JSON),
  `location="body"`.
  Real live-boot proof: the vulnerable twin's response reflects
  `is_partner: true` when the request sets it; the secure twin's never
  does, for the identical request body. **Not itself detection
  capability**: no new audit rule or oracle strategy is added here --
  deliberately split from this page per this session's own established
  lab-then-detection pattern, landed as its own separately-scoped
  follow-on.
- **FR-LAB-123** *(Twitch's seventh real page: second access-control/IDOR
  instance, `/channels/subscribers`; `CC-LAB-0183`, 2026-09-23).* Reuses
  `CC-LAB-0178`'s already-built `access_control`/`db_row_by_id_lookup`
  module set (`ReadChannelIdAndBroadcasterHeaderSource`/
  `NoOwnershipCheckTransform`/`IdentityMatchBeforeFetchTransform`/
  `ObjectLookupAuthorizationCheckSink`) verbatim at a second, distinct
  real Twitch feature: `GET /channels/subscribers?channel_id=`, a
  per-channel subscriber-roster lookup -- the same textbook OWASP
  API1:2023 BOLA surface as `/channels/analytics` (`TWCH-0003`), reused
  at a genuinely different real page, not a renamed copy of the same one.
  **Zero new generator code**: only a new manifest
  (`lab/manifests/access_control_subscribers_go_sample.yaml`, cells
  `LABGEN-GO-0013`/`0014`) and one new
  `_ROUTE_PARAMS["/channels/subscribers"]` entry in
  `fuzzlab/labgen/emitters/go_net_http/__init__.py` -- no new module, op,
  or safety-matrix entry, mirroring `CC-LAB-0179`'s own reuse-at-a-new-
  route precedent. Ground truth `TWCH-0007`
  (`vuln_class="access_control"`, `sink_context="object_lookup"`, both
  pre-existing enum values from `TWCH-0003` -- no schema widening
  needed). Real live-boot proof (same three-assertion shape as
  `CC-LAB-0178`'s own live-boot test): the vulnerable twin leaks another
  channel's subscriber data on a mismatched `channel_id`; the secure twin
  rejects the same mismatch with a real HTTP 403; the secure twin still
  serves the legitimate, matching-identity request.
  **This is the detection-generalization proof itself, verified for
  real, not assumed from theory**: `AccessControlIdorStrategy`
  (`CC-FUZZ-0029`, already built for `TWCH-0003`) is keyed on
  `vuln_class` + sink shape, never per-route, so it needed zero new audit-
  rule or oracle-strategy code to confirm `TWCH-0007`'s new vulnerable
  twin and correctly fail closed on its new secure twin -- proven against
  a real `go build`/boot/HTTP round trip
  (`test_real_boot_proves_the_access_control_idor_strategy_generalizes_
  to_subscribers_route`) and against the real
  `fuzzlab.harness.multitarget.run_targets` pipeline end to end
  (`tests/test_multitarget_category4.py`), which shows Twitch's own real,
  scored recall moving from 5/6 to 6/7 with no strategy/rule change.
- **FR-LAB-124** *(Netflix's third real page: second insecure_
  deserialization instance, `/api/profiles/switch`; `CC-LAB-0184`,
  2026-09-23).* Reuses `LABGEN-JV-0001`/`0002`'s already-built
  Jackson-polymorphic-typing module set (`jackson_body` source via
  `_SOURCE_OVERRIDE_BY_OP`, `jackson_default_typing_deserialize`/
  `jackson_typed_allowlist_deserialize` sinks, `CC-LAB-0173`) verbatim at
  a second, distinct real Netflix feature: `POST /api/profiles/switch`, a
  multi-profile-switch payload (Netflix's own documented up-to-5-
  profiles-per-account feature, each with its own maturity-rating/
  autoplay/subtitle preferences -- distinct from `/api/playback/resume`'s
  own resume-position mutation, not a cosmetic rename of it), mirroring
  `CC-LAB-0179`'s and `CC-LAB-0183`'s own reuse-at-a-new-route precedent.
  **Zero new generator code**: only a new manifest
  (`lab/manifests/insecure_deserialization_netflix_profiles_sample.yaml`,
  cells `LABGEN-JV-0005`/`0006`) and one new
  `_PAGE_PARAMS["/api/profiles/switch"]` entry (`{}`, matching
  `/api/playback/resume`'s own whole-body-JSON convention) in
  `fuzzlab/labgen/emitters/spring_boot/__init__.py` -- no new module, op,
  or safety-matrix entry. Ground truth `NFLX-0003`
  (`vuln_class="insecure_deserialization"`, `sink_context="deserialization"`,
  both pre-existing enum values from `NFLX-0001` -- no schema widening
  needed; `param="body"`, the same whole-body-point convention
  `NFLX-0001`/`NFLX-0002` already use). Real live-boot proof (same
  three-assertion shape as the `LABGEN-JV-0001`/`0002` live-boot test):
  the vulnerable twin accepts an attacker-type-hinted body; the secure
  twin accepts its own well-formed plain body but rejects the same
  type-hinted one.
  **This is the detection-generalization proof itself, verified for
  real, not assumed from theory**: `InsecureDeserializationType
  ConfusionStrategy` (`CC-FUZZ-0030`, already built for `NFLX-0001`) is
  keyed on `vuln_class` + sink shape, never per-route, so it needed zero
  new audit-rule or oracle-strategy code to confirm `NFLX-0003`'s new
  vulnerable twin and correctly fail closed on its new secure twin --
  proven against a real `mvn package`/boot/HTTP round trip
  (`tests/test_labgen_spring_boot_deserialization_netflix_profiles_live_
  boot.py::test_real_boot_proves_the_insecure_deserialization_strategy_
  generalizes_to_profiles_route`) and against the real
  `fuzzlab.harness.multitarget.run_targets` pipeline end to end, via a
  hand-rolled multi-cell boot assembling all three of Netflix's own
  positives together (`tests/test_multitarget_category4.py::
  test_netflix_multi_cell_boot_confirms_all_positives`), which shows
  Netflix's own real, scored recall in that boot moving from 2/2 to 3/3
  (`tp=3, fp=0`) with no strategy/rule change. The single-cell
  `test_both_apps_run_through_multitarget_for_real` test (which boots
  only `LABGEN-JV-0001`, per `SpringBootLiveBootHarness`'s
  one-cell-per-boot constraint) has its own recall assertion updated for
  the ground-truth count change alone (1/2 -> 1/3, unrelated to whether
  detection generalizes -- `NFLX-0003`'s own vulnerable twin is simply
  not booted in that particular test).
  **Pre-change review gate, mechanism fidelity noted explicitly (same
  substitution as `CC-LAB-0182`/`CC-LAB-0183`'s own precedent wording):**
  the `Agent` tool for a two-independent-reviewer accuracy/adequacy pass
  was not present in this session's toolset (checked via `ToolSearch`
  before concluding this, not assumed absent) -- substituted with a
  documented, rigorous self-review (accuracy + adequacy), recorded in
  `CC-LAB-0184`.
- **FR-LAB-125** *(Twitch's eighth real page: second ssrf/
  server_side_http_fetch instance, `/clips/download`; `CC-LAB-0185`,
  2026-09-23).* Reuses `CC-LAB-0172`'s already-built `ssrf`/
  `server_side_http_fetch` module set (`ReadUrlQueryParamSource`,
  `UncheckedUrlFetchSink`/`SchemeAndResolvedIpAllowlistSink`) verbatim at
  a second, distinct real Twitch feature: `GET /clips/download?source_url=`,
  a clip-import/download endpoint that server-side-fetches an externally-
  hosted clip file -- genuinely distinct from `/api/clips/thumbnail`'s own
  thumbnail-fetch-and-render proxy (`TWCH-0002`), not a renamed copy of
  it. **Zero new generator code**: only a new manifest
  (`lab/manifests/ssrf_clips_download_go_sample.yaml`, cells
  `LABGEN-GO-0015`/`0016`) and one new
  `_ROUTE_PARAMS["/clips/download"]` entry in
  `fuzzlab/labgen/emitters/go_net_http/__init__.py` -- no new module, op,
  or safety-matrix entry, mirroring `CC-LAB-0183`'s own reuse-at-a-new-
  route precedent. Ground truth `TWCH-0008` (`vuln_class="ssrf"`,
  `sink_context="network"`, both pre-existing enum values from
  `TWCH-0002` -- no schema widening needed). Real live-boot proof (same
  differential shape as `CC-LAB-0172`'s own live-boot test): the
  vulnerable twin fetches an unvalidated plain-HTTP loopback target
  successfully; the secure twin rejects the same target (scheme check).
  **This is the detection-generalization proof itself, verified for
  real, not assumed from theory**: `SsrfInBandMarkerStrategy`/
  `SsrfOobStrategy` (`CC-FUZZ-0027`, already built for `TWCH-0002`) are
  keyed on `vuln_class` + sink shape, never per-route, so they needed
  zero new audit-rule or oracle-strategy code to confirm `TWCH-0008`'s
  new vulnerable twin and correctly fail closed on its new secure twin --
  proven against a real `go build`/boot/HTTP round trip, using a real,
  started `OobListener`
  (`tests/test_labgen_go_live_boot.py::
  test_real_boot_proves_the_ssrf_strategies_generalize_to_clips_download_route`)
  and against the real `fuzzlab.harness.multitarget.run_targets` pipeline
  end to end (`tests/test_multitarget_category4.py`), which shows
  Twitch's own real, scored recall moving from 6/7 to 7/8 (`tp=7, fp=0`)
  with no strategy/rule change.
  **Pre-change review gate, mechanism fidelity noted explicitly (same
  substitution as `CC-LAB-0182`/`CC-LAB-0183`/`CC-LAB-0184`'s own
  precedent wording):** the `Agent` tool for a two-independent-reviewer
  accuracy/adequacy pass was not present in this session's toolset
  (checked via `ToolSearch` before concluding this, not assumed absent)
  -- substituted with a documented, rigorous self-review (accuracy +
  adequacy), recorded in `CC-LAB-0185`.
- **FR-LAB-126** *(Twitch's ninth real page: first unrestricted-file-
  upload instance, `/channels/emotes/upload`; `CC-LAB-0186`,
  2026-09-23).* Instantiates `lab/safety_matrix.yaml`'s existing
  `fs_web_root_write` sink family and its `no_extension_check`/
  `extension_allowlist_mime_check` ops (`CC-LAB-0063`) on `go_net_http`
  for the FIRST time on any stack (confirmed absent by grep before
  starting) -- genuinely new breadth, not a cheap depth reuse like
  `FR-LAB-120`-`125`. A channel-emote upload endpoint. A new source,
  `ReadUploadedFileSource` (this stack's first real `multipart/form-data`
  parser, bounded at a fixed 5 MiB via `io.LimitReader`), publishes the
  caller-supplied filename/content/multipart-`Content-Type` a sink reads
  directly -- Convention 2 (the manifest's one op names a sink directly,
  like SSRF/mass-assignment). Go has no PHP-style "the web server
  executes an uploaded script" footgun, so the vulnerable twin
  (`no_extension_check`) models the real, well-documented CWE-434-to-XSS
  chain instead: it writes the upload to `static/emotes/<caller's own
  filename>` verbatim and serves it back with a `Content-Type` from
  `mime.TypeByExtension` on that same filename (falling back to the
  caller's own multipart `Content-Type` header) -- an uploaded `.html`
  file is served back same-origin as `text/html`. The secure twin
  (`extension_allowlist_mime_check`) allowlists real image extensions
  (`.png`/`.jpg`/`.jpeg`/`.gif`/`.webp`) AND sniffs the real bytes via
  `http.DetectContentType`, rejecting anything not really an image;
  writes under a fully server-chosen filename (`"emote"+ext`) and always
  serves the sniffed content type, never one derived from the extension
  or the caller's header. Cells `LABGEN-GO-0017`/`0018`; ground truth
  `TWCH-0009` (`vuln_class="unrestricted_file_upload"`,
  `sink_context="fs_web_root_write"`, both new enum values, additively
  widened; `param="file"`/`location="body"` -- the real multipart field
  name, deliberately not the `body`/`body` whole-body-point convention
  `weak_token_entropy`/`mass_assignment` use, since `file` genuinely is
  this shape's one tainted field and using `body` would incorrectly
  trigger `points_from_ground_truth`'s JSON-content-type auto-detection;
  `rendering="server"`, not this ground-truth directory's usual
  `"server-json"`, since the success response is raw bytes with a
  dynamic content type, never JSON). Real live-boot proof (4 assertions:
  the vulnerable twin serves an uploaded `.html` back as `text/html`
  with a marker intact; the secure twin rejects the same `.html` upload
  outright with HTTP 415; the secure twin also rejects a spoofed upload
  -- real HTML bytes under an allowlisted `.png` extension -- with HTTP
  415, proving content sniffing actually runs, not just the extension
  check; the secure twin accepts a real PNG-signature upload and serves
  it back as `image/png`). A real Go "declared and not used" compile bug
  (`clientContentType` unreferenced in the secure sink's first draft) was
  found and fixed before landing, the same defect class `FR-LAB-118`'s
  `broadcasterID` bug and `FR-LAB-120`'s JWT bug were. `GoLiveBootHarness.
  HttpResponse` (`fuzzlab/labgen/conformance/go_live_boot.py`) additively
  gained a `headers` field -- this stack's first shape whose vulnerable/
  secure difference is only observable in a response header
  (`Content-Type`), not the body or status; every existing construction
  site is unaffected (default empty dict), re-verified by re-running this
  stack's full pre-existing live-boot suite unmodified-in-assertion.
  Filesystem safety verified structurally, not just by test-author
  intent: the generated handler's upload directory (`static/emotes`) is
  a relative path, resolved against the booted process's own `cwd`,
  which `GoLiveBootHarness` already sets to a throwaway
  `tempfile.TemporaryDirectory` -- so the live-boot test's writes land in
  a throwaway directory with no extra plumbing, and the test's own probe
  payload is an inert `<!DOCTYPE html><p>` marker snippet, never an
  executing `<script>` tag. Twitch's own real, scored recall moves from
  7/8 to 7/9 -- a real missed positive (no rule/strategy exists yet for
  this class), not a false one. **Pre-change review gate, mechanism
  fidelity noted explicitly (same substitution as `CC-LAB-0182`-`0185`'s
  own precedent wording):** the `Agent` tool for a two-independent-
  reviewer accuracy/adequacy pass was not present in this session's
  toolset (checked via `ToolSearch`, not assumed absent) -- substituted
  with a documented, rigorous self-review (accuracy + adequacy),
  recorded in `CC-LAB-0186`. **Not itself detection capability**: no new
  audit rule or oracle strategy is added here -- deliberately split from
  this page per this session's own established lab-then-detection
  pattern (the same split `FR-LAB-120`/`FR-LAB-121` established), landed
  as its own separately-scoped follow-on.

## 4. Non-functional requirements
- **NFR-LAB-reproducible** Byte-identical regeneration; pinned env asserted at
  runtime.
- **NFR-LAB-safety** Lab-only; bound to localhost; destructive classes off by
  default; no outbound route.
- **NFR-LAB-no-leak** No vulnerability class name in any URL, filename, or
  parameter a tool can see.
- **NFR-LAB-no-secret-leak** No real credential/secret material in any
  generated artifact; a seeded fake/example credential is permitted only
  when it carries an explicit, recognizable fake-value marker.
- **NFR-LAB-label-accuracy** Labels derived, not hand-asserted; env settings that
  affect labels (e.g. `display_errors`, libxml entity handling, `open_basedir`)
  pinned and asserted.

## 5. Interfaces and data contracts
Serves HTTP to the tools. Publishes ground truth as out-of-band files (above),
plus `sitemap.xml`/OpenAPI later. Exposes grey-box coverage and fault signals for
the fuzzer, scheduler, and oracle. Does not write the SQLite store directly.
(Lab track, generator-build-time) `fuzzlab.labgen.oracle_wrapper` exposes a plain
Python function per validated class (`run_sql_injection_oracle`,
`run_command_injection_oracle`, `run_server_side_template_injection_oracle`,
plus a type-dispatching `run_oracle`) taking a
small request dataclass and returning an `OracleVerdict`
(`confirmed_vulnerable | confirmed_secure | inconclusive` + raw tool
output/exit info) — see FR-LAB-11. It takes no dependency on and is never
imported by `fuzzlab.oracle` (the unrelated runtime detection oracle, FUZZ
component #7); the two are separate tools with separate purposes that happen
to share the word "oracle".
(Lab track, generator-build-time) `fuzzlab.labgen.zap_oracle.run_zap_whole_app_scan`
takes a `ZapWholeAppScanRequest` (`target_url`, optional `alert_name_pattern`,
`risk_threshold`, timeouts) and returns a `ZapScanVerdict` — same three-outcome
contract as `OracleVerdict` above, plus the matching/all alert lists — see
FR-LAB-18. Kept in its own module rather than `oracle_wrapper.py` since ZAP's
whole-app, no-single-parameter shape doesn't fit that module's per-parameter
request contract; also unrelated to and never imported by `fuzzlab.oracle`.
(Lab track, generator-build-time) `fuzzlab.labgen.resolver.expand(raw_config)`
takes a `{factors, strength?, sub_models?, constraints?}` mapping and returns
a list of `{axis_name: level_value}` rows — see FR-LAB-17. Called from
`fuzzlab.labgen.schema.Manifest.from_dict()` (via `_expand_axis_range`/
`_expand_axis_ranges`) whenever a manifest's `axis_ranges` block is present —
see FR-LAB-29.
(Lab track, dev tooling, not runtime) `fuzzlab.tools.pattern_corpus_sourcing`
exposes `run_refresh()` (also `python -m fuzzlab.tools.pattern_corpus_sourcing
refresh`) which reads/writes only `lab/patterns/sourcing/` and
`lab/patterns/refresh/`/`REFRESH_LOG.md`; it takes no dependency on and does
not write `lab/patterns/cards/` or `lab/patterns/provenance.yaml` — see
FR-LAB-18.
(Lab track, generator-build-time) `fuzzlab.labgen.regression_gate.check_no_regression(
baseline_dir, candidate_dir, *, loader=fuzzlab.labels.contract.load)` loads both
directories (an injectable `loader`, so a future CLI can point it at a not-yet-written
generator output directory) and calls `assert_no_regression(baseline: GroundTruth,
candidate: GroundTruth) -> RegressionDiff`, which raises `RegressionGateError` — naming
every missing case ID / changed page / changed verdict found, not just the first — or
returns a `RegressionDiff` (also exposing `added_case_ids`, informational). See
FR-LAB-28. `fuzzlab.labels.contract.Case` gained `primary_endpoint`, `primary_role`,
`related_endpoints` (tuple of `{endpoint, role}` mappings), `flow_variant` (default
`"direct"`) — all additive/defaulted; `fuzzlab.labels.schemas.labels.schema.json`'s
`case` definition and `lab/ground-truth/expectedresults.csv` extended to match, see
FR-LAB-28.
(Lab track, generator-build-time) `fuzzlab.labgen.schema.flow_variant_for(cell) -> str`
is the one shared mapping from a `Cell.context_depth` (generator input) to the
ground-truth `Case.flow_variant` value a case generated at that depth must carry
(identity by construction — the two vocabularies are the same). No production caller
yet: the Cell-to-GroundTruth converter it exists for does not exist (see FR-LAB-32's
`# TODO(L-P0.9-integration)`). See FR-LAB-40.
(Lab track, generator-build-time) `fuzzlab.labgen.identity.load_identities(path) ->
IdentityGraph` reads `lab/identities/identities.yaml`, validated against
`lab/schemas/identities.schema.json` — see FR-LAB-27. Reads nothing the manifest
cells reference and is never imported by `fuzzlab.labgen.verdict` or
`fuzzlab.labgen.schema`.
(Lab track, generator-build-time) `fuzzlab.labgen.emitters.python_fastapi`
exposes `PythonFastapiEmitter` (the `Emitter` ABC), plus `STACK_ENV`
(a package-local `StackEnv`) and `render_scaffold_files()` for this stack's
one-time scaffold output (`app/main.py`, `app/db.py`, package `__init__.py`
files, `requirements.txt`, `Dockerfile`) — a build driver calls
`render_scaffold_files()` (or reads `STACK_ENV.scaffold_files`) exactly once
per build, separately from `render(cell)`, since `Emitter`'s ABC has no
per-stack-scaffold method yet — see FR-LAB-34.

(Lab track, generator-build-time) `fuzzlab.labgen.identifier_sqli_assertion` wires lane
L-P1.2a's identifier-SQLi differential prober in as a build gate — see FR-LAB-41:
`is_identifier_sqli_cell(cell) -> bool` (the `IDENTIFIER_SINK_FAMILIES` filter);
`build_identifier_sqli_request(cell, *, target_base_url, param_name, column_a, column_b,
...) -> IdentifierSqliOracleRequest`, which probes `cell.sink_endpoint` when present and
`cell.route` otherwise (mirroring `php_current.render()`'s own choice) and refuses — rather
than silently mis-probing — a non-identifier sink family or a `param` that is not
`query`/`raw`; `assert_identifier_sqli_cell(cell, matrix, *, runner=default_http_runner,
**request_kwargs) -> IdentifierSqliAssertionResult`, which derives the expected verdict with
`verdict()` (never a hand-asserted expectation) and raises `IdentifierSqliAssertionError`
on a mismatch **or** an `inconclusive` probe (fail-closed, PA-0025; there is deliberately no
"allow inconclusive" switch); and `IdentifierSqliTier2Oracle`, a structurally-typed
`conformance.tier2.Tier2Oracle` adapter (`confirm(case) -> (bool, str)`) that raises rather
than collapsing an inconclusive probe into `False`. The probe metadata it needs
(`param_name`, `column_a`, `column_b`) is supplied by the caller from the emitter's own page
profile, not read off the `Cell` — the same render-only/verdict-relevant split
`conformance.tier1.build_tier1_case` uses. Imports `identifier_sqli_oracle` and `verdict`
only; never `oracle_wrapper`'s sqlmap/commix/SSTImap code.

## 6. Dependencies (components)
None (it is the system under test).

## 7. Acceptance criteria
- App serves on localhost from the container; reset restores clean state.
- Ground-truth files validate against schema and match the served app.
- Runtime env self-check passes against the env-profile.
- (Lab track) generate-twice-and-diff is empty; the contamination sweep finds
  nothing undeclared.
- (Lab track, Phase 0 foundation — met) manifest and safety-matrix files
  validate against their JSON Schemas; `verdict()` matches its snapshot;
  `fuzzlab.labgen.gates.regenerate_and_diff()` passes for the example
  manifest; the name-leak scanner passes its should-flag/should-not-flag
  fixture set; every `patterns/` card validates and every `provenance.yaml`
  reference resolves. See `tests/test_labgen_*.py`.
- (Lab track, T-LAB0.9 — met) `fuzzlab.labgen.regression_gate.check_no_regression`
  passes the real `lab/ground-truth/` against itself and against an additive superset,
  and fails loud, naming the exact case ID and violation kind, on a deliberately
  shrunk or verdict-flipped ground-truth fixture. See
  `tests/test_labgen_regression_gate.py`.
- (Lab track, Phase 2, L-P2.1 — met) `identities.yaml` validates against its JSON
  Schema; every `resources[].owner` and `authz_expectations[].accessing_identity`/
  `target_resource` resolves to a declared identity/resource; `verdict.py` carries no
  reference to `fuzzlab.labgen.identity`. See `tests/test_labgen_identity.py`.
- (Lab track, Phase 1, L-P1.2b — met) every cell of
  `lab/manifests/phase1_harder_shapes_sample.yaml` derives its expected verdict against
  matrix v1, renders through `php_current`, and passes `lab-generate --check` (Tier 0
  `php -l` + Tier 3 regeneration included); every `php_current`-targeting cell of *every*
  manifest in `lab/manifests/` renders (the PA-0024 whole-collection guard); and the
  identifier-position cells' labels are confirmed by lane L-P1.2a's oracle through
  `identifier_sqli_assertion`, including four unmocked real-HTTP end-to-end assertions. See
  `tests/test_labgen_harder_shapes.py` and `tests/test_labgen_identifier_sqli_assertion.py`.

## 8. Open questions
- (`CC-LAB-0178`, 2026-09-23; **resolved** `CC-FUZZ-0029`/`CC-AUD-0017`,
  2026-09-23) **No audit rule/oracle strategy exists for `access_control`.**
  ~~Twitch's `TWCH-0003` ... is a real, buildable follow-on ... Not
  attempted in this entry.~~ Built: `R-ACCESS-CONTROL`
  (`fuzzlab/audit/rules_data/default_rules.json`, `FR-AUD-8`) +
  `AccessControlIdorStrategy` (`fuzzlab/oracle/strategies.py`,
  `FR-FUZZ-16`), verified live against Twitch's real booted `TWCH-0003`
  twins. Twitch's real, scored `multitarget` recall moves from 1/3 to 2/3.
- (`CC-LAB-0139`, 2026-09-23) **`fuzzlab.harness.auto.points_from_ground_truth` has no
  `location="header"` branch.** A ground-truth point with `location="header"` (Huddle
  Hub's `HHUB-0001`, the first such point in this project — see
  `lab/ground-truth-huddlehub/labels.json`) falls into that function's generic
  client-only/DOM `else` branch and is recorded `skipped` with the reason string
  `"client-only/DOM (needs browser execution, M6)"` — technically inaccurate for a
  header-location point, which needs a header-capable prober, not a browser. Two
  pieces of real, sized follow-on work, neither attempted here: (1) give
  `points_from_ground_truth` a real `location == "header"` branch with an accurate
  skip reason (or a way to actually drive it); (2) build a header-capable prober
  (`RequestsProbeSender.send()`'s own signature has no way to set an arbitrary
  request header for an injection point either — see `fuzzlab/tools/probesender.py`).
  Tracked here so this flagged gap is not lost; revisit when a header-location vuln
  class (webhook-signature-bypass or any future one) needs real automated detection
  coverage, not just wiring proof.
- (`CC-LAB-0176`/`FR-LAB-99`, category 4) **Three real gaps between
  category 4's cells and the generic detection pipeline, found while
  wiring Phase E.** (1) No audit `Rule` category exists for
  `webhook_signature`/`ssrf`/`insecure_deserialization` — same class of
  gap category 1's own Phase E flagged for its own new vuln classes. (2)
  `fuzzlab.harness.auto.points_from_ground_truth` has no header-location
  case at all (only `query`/`body`/DOM); a header-carried ground-truth
  point (e.g. `TWCH-0001`) is silently absorbed into the DOM/browser skip
  path with a misleading reason string, rather than its own, honestly
  labeled "header injection points aren't audited yet" skip reason. (3)
  `fuzzlab.tools.probesender.RequestsProbeSender`'s `location="body"`
  convention is single-form-field (`data={param: value}`); it has no way
  to express "substitute the payload into a whole raw JSON body," so a
  whole-body-JSON ground-truth point (e.g. `NFLX-0001`) can never be
  meaningfully probed through it. None of the three are attempted here —
  each is real, sized follow-on work.
- (`CC-LAB-0175`/`FR-LAB-98`, category 4) **The webhook-signature cell
  (`LABGEN-GO-0001`/`0002`, CWE-347) has no Tier 1/2 conformance path.**
  `naive_string_compare` vs `hmac.Equal` are functionally identical for any
  single request (both accept a correct signature, reject an incorrect
  one) — they diverge only in comparison timing, which
  `fuzzlab.labgen.conformance.tier1`/`tier2`'s marker/functional-
  differential model cannot observe. Same shape as the
  `identifier_charset_filter` open question below (a class whose flaw
  isn't a single-request functional difference): needs a genuinely new,
  statistical, multi-request timing-differential oracle, not attempted
  here.
- (L-P3.3b) **`fuzzlab.labgen.minimal_pair`'s module-category map is sourced from one
  emitter's registry.** It builds `_MODULE_CATEGORY` from `fuzzlab.labgen.modules`
  (`php_current`'s) alone, so *every* stack that wants the real (rather than the naive)
  minimal-pair checker must name its modules from that vocabulary — which `php_laravel`
  now does deliberately (FR-LAB-42.3a). The alternative is a pluggable category map, or a
  registry the checker can be handed: a small additive change to that shared module, not
  made here because it is a sibling lane's file and no second stack needs it yet
  (`node_express`/`python_fastapi` use the naive checker by their own Tier-0 convention).
  Worth revisiting when a third stack reaches full depth.
- (L-P3.3b) **`lab-generate` has no clean failure for an emitter/manifest stack
  mismatch.** Rendering a manifest whose cells target another stack, but whose
  `(class, family)` shapes the selected emitter supports, raises an uncaught `ValueError`
  from the page-profile lookup (a traceback) rather than a CLI-level message. Pre-existing
  and not specific to this stack (`--emitter php_current` on the Laravel manifest behaves
  the same, and did before this lane), so it is recorded rather than fixed inside a lane
  that does not own that surface. A `stack_profile`-aware skip, or a typed CLI error, is
  the obvious remedy.
- (L-P3.3b, narrowed by L-P3.3c-G4/`FR-LAB-47`) **`same_file_helper`/`cross_file` are still
  not ported to Laravel; `stored_second_order` now is.** `php_current` renders all three
  depths (`CC-LAB-0042`); `php_laravel` rendered none of them at L-P3.3b and now renders
  `stored_second_order` (`SUPPORTED_CONTEXT_DEPTHS`, `FR-LAB-47`) via a structural write
  endpoint rather than a ported depth *fragment* — `same_file_helper`/`cross_file` still need
  the pass-through-helper fragments `fuzzlab.labgen.modules.DEPTHS` carries, ported to
  Laravel idiom, which remains real remaining work for a cross-stack `context_depth` corpus.
- (L-P3.3c consolidation, `FR-LAB-50`) **The twin-URL naming convention is a judgment call a
  human reviewer may want to revisit.** `_twin_url_for()` embeds the non-canonical cell's
  slug before a real page's `.php` suffix (e.g. `/login.labgen-pla-0002.php`), adopted from
  lane G3 unchanged. This was an autonomous design choice made to unblock four lanes' merges
  rather than stall on a naming bikeshed (Auto Mode's "make the reasonable call" guidance),
  and no alternative (a query-string discriminator, a `/variants/<slug>/...` prefix, etc.)
  was evaluated against it. Revisiting it means changing one function; nothing else in the
  mechanism depends on the specific string shape.
- (L-P3.3c-G6/`FR-LAB-49`, still open) **`search.php` has no canonical cell.** Six cells
  (three sink behaviors x vulnerable/secure) share one real URL Laravel cannot register six
  routes for; which cell (if any single one) should own `/search.php`, or whether the `Cell`
  IR needs a multi-sink page composition, is a policy decision explicitly left for
  `L-P3.3c-CUT` (which owns emitting the candidate ground truth the regression gate runs
  against) — not resolved by lane G6 nor by the consolidation pass that followed it.
- (L-P1.2b) **The `identifier_charset_filter` cells cannot be oracle-confirmed yet.**
  L-P1.2a's prober always wraps the probe value in `CASE WHEN ... END`, which a
  bare-identifier character filter rejects (HTTP 400), so the oracle correctly returns
  `inconclusive` and the build assertion fails closed. Confirming them needs an
  *identifier-swap* differential mode (two bare, legal identifiers — e.g. `name` vs
  `secret` — diffed), which is precisely the strategy no sqlmap technique implements and a
  small additive `DifferentialMode` on `fuzzlab.labgen.identifier_sqli_oracle`. Not built
  here: that module is lane L-P1.2a's deliverable.
- (L-P1.2b) **Whether any existing oracle can confirm the escaping-context-mismatch XSS
  cells.** `oracle_wrapper` is SQLi/command-injection/SSTI and `nuclei_oracle` is
  path-traversal templates, so `zap_oracle`'s whole-app scan is the only candidate; whether
  ZAP's active scanner recognizes a `javascript:`-URL or unquoted-attribute context must be
  checked against the real binary (PA-0005) on-host before any new XSS oracle is written.
- (L-P1.2b) **Whether `verdict()`'s difficulty score should account for an inapplicable
  fix.** A `param_bind` pipeline at `sql_identifier` scores `trivial` (a `no_effect` op adds
  neither partial credit nor length beyond one op) although it is among the subtlest cells
  in the corpus — code that looks parameterized and is not. Changing it means changing
  `verdict()`'s derivation, deliberately out of L-P1.2b's scope.
- Database isolation strategy (per-run schema, dump reload, or rollback).
- Whether to expose source (annotated build only, if at all).
- Exact pinned versions and error-surfacing behavior, recorded in the
  env-profile.
