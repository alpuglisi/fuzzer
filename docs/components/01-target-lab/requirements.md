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
  Deterministic across processes and `PYTHONHASHSEED` values. Not yet wired
  into manifest loading — the Phase 0 manifest still lists cells explicitly,
  one axis level each. (`CR-LAB-0001` §3, `docs/LAB_PHASE_0_PLAN.md` T-LAB0.3,
  `CC-LAB-0018`)
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
- **FR-LAB-27** (Lab track, §2.2, L-P1.2a) A third, independent oracle,
  `fuzzlab.labgen.identifier_sqli_oracle` (kept out of `oracle_wrapper.py`/
  `nuclei_oracle.py` deliberately — see `CC-LAB-0029`), covers
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
  §2.2, `CC-LAB-0029`)

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
a list of `{axis_name: level_value}` rows — see FR-LAB-17. Not yet called
from `fuzzlab.labgen.schema`'s manifest loading.
(Lab track, dev tooling, not runtime) `fuzzlab.tools.pattern_corpus_sourcing`
exposes `run_refresh()` (also `python -m fuzzlab.tools.pattern_corpus_sourcing
refresh`) which reads/writes only `lab/patterns/sourcing/` and
`lab/patterns/refresh/`/`REFRESH_LOG.md`; it takes no dependency on and does
not write `lab/patterns/cards/` or `lab/patterns/provenance.yaml` — see
FR-LAB-18.

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

## 8. Open questions
- Database isolation strategy (per-run schema, dump reload, or rollback).
- Whether to expose source (annotated build only, if at all).
- Exact pinned versions and error-surfacing behavior, recorded in the
  env-profile.
