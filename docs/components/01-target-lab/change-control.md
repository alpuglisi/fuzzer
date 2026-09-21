# Target Lab and Ground Truth — Change Control Log

Component code: **LAB**. Entry format and required fields: see
`../README.md`. Newest first.

### CC-LAB-0020 — T-LAB0.6: Gitleaks secret-scanner build gate (2026-09-21)
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
  ad hoc verification and in the test suite's real-binary-path tests.
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
  - [x] `requirements.md` — new `FR-LAB-19` + `NFR-LAB-no-secret-leak` — done
  - [ ] Wire into `fuzzlab lab-generate --check` (T-LAB0.10) — todo, blocked
    on that CLI existing
- Effectiveness (assessed 2026-09-21): met its intent — the gate correctly
  flags unmarked real-shaped secrets and passes marked-fake/clean content in
  the fixture corpus, and every injected-crash path raises rather than
  passing silently. Full suite: 665 passed, 2 pre-existing unrelated
  `test_mutation_operators.py` failures, 5 skipped (baseline before this
  change: 642 passed, same 2 failures, 5 skipped).

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
