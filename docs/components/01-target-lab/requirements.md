# Target Lab and Ground Truth — Requirement Specification

Component code: **LAB** · Status: `[built app; generator Phase 0 foundation built (schema, verdict engine, determinism/name-leak gates, patterns/ scaffold, covering-array resolver, T-LAB0.8 mechanical sourcing tool); rest planned]`
· Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #1; `DECISIONS_AND_ROADMAP.md` (D7, D8, D9, D10);
`./change-control.md`.

## 1. Purpose
Provide a deliberately vulnerable, locally hosted target with exact,
machine-readable ground truth, against which the toolkit's tools are exercised
and measured. Authorized, lab-only.

## 2. Scope
- **In:** the Puppy Fort Factory app; ground-truth labels; grey-box
  instrumentation; the containerized environment; later the manifest-driven
  generator, tiers, and build profiles.
- **Out:** the tools themselves; anything reachable from a non-loopback network.

## 3. Functional requirements
- **FR-LAB-1** Serve a deliberately vulnerable web app on localhost with a
  documented mix of vulnerable and secure pages.
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
  permanent separate fixture. (D20)
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
- **FR-LAB-21** (Lab track, Phase 0/1 foundation, reference implementation — not
  build-gating yet) `fuzzlab.labgen.leakage_probe.probe_leakage()` detects whether a
  corpus's non-payload metadata (status code, response length, header count, latency,
  param-name length, path depth, content-type — a closed allowlist) statistically leaks
  the vulnerability label, via a deliberately weak classifier, `StratifiedGroupKFold`
  grouped by generating-rule ID (never a random split), and a permutation-null AUC
  threshold (not a fixed constant). Per-class feature exclusions (e.g. `latency_ms` for
  time-based-blind-SQLi/race-condition classes, where timing *is* the signal) each carry
  a written justification and are always reported, never silently applied. Requires the
  optional `labgen` extras (`scikit-learn`, `numpy`); not imported eagerly by
  `fuzzlab.labgen.__init__`, so the rest of the package has no hard dependency on it. Not
  wired into any build gate — full build-gating starts once real variation exists
  (Phase 1), per `docs/LAB_PHASE_0_PLAN.md` T-LAB0.11. (`docs/LAB_PHASE_0_PLAN.md`
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
  as a `# TODO(L-P0.9-integration)` in `run_checks()`; and `fingerprint_gate.py`
  is deliberately not wired (needs a real multi-stack corpus, Phase 3, to mean
  anything against a single-stack corpus).
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
     record claims. Real `puppy-fort-factory/` page reproduction remains §4.3 step 6
     (L-P3.3c). (`CC-LAB-0044`)

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
- (L-P3.3b) **The `context_depth` axis is not ported to Laravel.** `php_current` renders
  `same_file_helper`/`cross_file`/`stored_second_order` (`CC-LAB-0042`); `php_laravel`
  refuses them (FR-LAB-42.6). Porting the depth fragments to Laravel idiom (a helper class
  or trait, and a second route for a stored/second-order cell's injection point) is real
  remaining work, and a cross-stack `context_depth` corpus needs it.
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
