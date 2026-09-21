# Target Lab and Ground Truth — Requirement Specification

Component code: **LAB** · Status: `[built app; generator Phase 0 foundation built (schema, verdict engine, determinism/name-leak gates, patterns/ scaffold, covering-array resolver); rest planned]`
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
  vulnerable/secure SQLi pair; reproducing today's real PHP app is separate,
  later scope. (`CR-LAB-0001` §3/Addenda C/D, `docs/LAB_PHASE_0_PLAN.md`
  T-LAB0.4, `CC-LAB-0019`)
- **FR-LAB-19** (Lab track, Phase 0) A secret-scanner build gate, separate
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
  fail-on-crash rule. (NFR-LAB-no-secret-leak, `docs/LAB_PHASE_0_PLAN.md`
  T-LAB0.6, `CC-LAB-0020`)

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
(Lab track, generator-build-time) `fuzzlab.labgen.resolver.expand(raw_config)`
takes a `{factors, strength?, sub_models?, constraints?}` mapping and returns
a list of `{axis_name: level_value}` rows — see FR-LAB-17. Not yet called
from `fuzzlab.labgen.schema`'s manifest loading.

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
