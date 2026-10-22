# Preventive actions

The active rules to follow while working on this project. Each is a preventive
action from a bug investigation (`docs/bugs/`). No background here by design —
read this list and follow it. Consult it before and during changes.

**Following this list is mandatory, not advisory.** It is one step in the full
change process; see `CLAUDE.md` (the session-start checklist) for how it fits with the
changelog, change-control, error-log, and bug-report requirements.

Format: `PA-NNNN — <rule>. (from BUG-NNNN)`

Every entry ends with exactly one enforcement line, checked by
`tests/test_pa_enforcement.py` (each named test must exist; resolved by AST):

- `- Enforced by: tests/<file>.py::<test>[, tests/<file>.py::<test> …]` — the tests
  that fail when the rule is broken, or
- `- Enforced by: none — <reason>` — why no test enforces it (a process or conduct
  rule, on-host only, not yet built).

A new PA names its enforcement when it is written. Prefer a mechanical guard (an AST or
whole-package check proven on a synthetic offender, PA-0034(2)) to prose: the
retrospective of BUG-0110..BUG-0139 found every one of those 25 bugs happened while a
prose PA already applied. The test prints the share of PAs enforced by `none`.

- **PA-0001** — In tests, do not hardcode a value that a source-of-truth constant
  or registry in the code already defines (schema head version, `FEATURE_VERSION`,
  enum members, etc.); derive the expectation from that source. Reserve literal
  expected values for genuinely fixed external contracts. (from BUG-0001)
  - Enforced by: none — a test-writing convention; no check can tell a derived expectation from a hard-coded one, so it is applied in review
- **PA-0002** — When a bug investigation adds a preventive action, sweep the whole
  codebase for existing instances of that bug class and remediate them (or record
  why not) — do not fix only the instance that triggered the investigation. (from
  BUG-0002)
  - Enforced by: none — a process rule for bug investigations; the sweep and its result are recorded in each bug report, not checked by a test
- **PA-0003** — A storage or serialization convention that must hold across more
  than one writer lives in exactly one shared function that every writer calls at
  the write site — not as a per-writer private helper, and not as a convention
  stated only in prose. New writers of the same column/field go through that shared
  function (e.g. result URLs are stored in path form via `fuzzlab.core.urls.to_path`).
  (from BUG-0003)
  - Enforced by: tests/test_identifier_predicate.py::test_defined_once, tests/test_json_points.py::test_the_credential_change_rule_is_one_function_shared_with_forms, tests/test_session_browser_login.py::test_one_predicate_tells_credential_cookies_from_ambient_ones, tests/test_shared_primitives.py::test_every_owner_is_defined_once
- **PA-0004** — A committed default that selects an external identity, credential, or
  endpoint must be a value the target actually accepts **and** must match what the lab
  provisions (compose / `.env` / schema) — not a developer's local assumption. And
  when an incident is resolved only by an environment workaround (an `ERROR_LOG` entry
  marked `Environment`), still fix the repo default that caused it, so a fresh checkout
  does not reproduce it. (from BUG-0004)
  - Enforced by: none — no test compares committed defaults with what the lab provisions; checked when a default changes
- **PA-0005** — Every library imported at runtime — including one pulled in by a
  third-party backend the code instantiates — must be a **declared** dependency; never
  assume a different installed library satisfies another's requirement (e.g.
  `cryptography` does not provide PyCrypto's `Crypto`). And a real code path that test
  doubles bypass everywhere must still have at least one test exercising the real
  implementation (skippable when it needs an environment feature) or a documented
  on-host smoke check, so fresh-install / first-use failures are caught before a user
  hits them. (from BUG-0005)
  - Enforced by: none — no test compares runtime imports with the declared dependencies; the real-path half is applied per feature (PA-0065 adds the browser backstop)
- **PA-0006** — An integration/pipeline test must feed inputs shaped like what the
  real upstream produces; do not hand-populate a field the live path does not set at
  that stage (e.g. a post-detection label like `sink_context` on a freshly-discovered
  point) to make a downstream step succeed — that masks a wiring gap. A rule or step
  keys only on what is available at its stage; anything derived later belongs to the
  stage that derives it. (from BUG-0006)
  - Enforced by: none — a fixture-writing convention; no generic check can tell a hand-populated field from an upstream-shaped one
- **PA-0007** — Never infer authentication or authorization success from the mere
  presence of an *ambient* credential the server also issues to anonymous users (a
  session cookie set by `session_start()`, an ambient CSRF/anti-forgery token, etc.).
  Require a *positive differential* signal that the protected action actually succeeded
  — the login response left the login page behind, a page that is `401/403` when
  anonymous now returns `2xx`, or an identity-specific marker is present. Test fixtures
  for auth/detection code must reproduce the server's ambient state (e.g. a pre-login
  anonymous cookie), not only the happy path, or a broken success path looks healthy
  (a recurrence vector of PA-0006). (from BUG-0008)
  - Enforced by: tests/test_session_browser_login.py::test_one_predicate_tells_credential_cookies_from_ambient_ones
- **PA-0008** — Gate optional behavior on the **authoritative capability probe**, not on
  a fragile name string. To detect a native extension use `extension_loaded('x')` (not
  `function_exists('\x\fn')`, whose leading-backslash namespaced form is unreliable);
  likewise prefer the direct capability check over stringly-typed name lookups elsewhere.
  A misfiring guard silently degrades to "feature off / no signal", which is hard to spot.
  (from BUG-0009)
  - Enforced by: none — the PHP coverage shim's capability check runs on-host only; no test inspects how capability probes are spelled
- **PA-0009** — A build or deploy step that provisions a runtime capability (compiling/
  installing an extension, a package, a binary) must **verify it is actually usable in the
  same step** — e.g. `pecl install x && … && php -m | grep -qi '^x$'` — so a broken or
  cache-stale layer fails the build, not a later run. Install the toolchain the build
  needs (e.g. `$PHPIZE_DEPS` for PECL) rather than assuming it is present. (from BUG-0009)
  - Enforced by: none — a container build-step rule, verified by the on-host image build, not by a test
- **PA-0010** — When an API takes a filter/selector argument, confirm the expected
  **granularity** (file vs directory vs prefix vs glob) before passing it — a
  wrong-granularity argument commonly returns a silently-empty result rather than an
  error (e.g. handing pcov's file-list filter a directory). And verify the actual
  produced **signal** end to end, not just that the dependency is present: "loads ≠
  works" — a self-test that inspects the real output catches what a presence check
  cannot. (from BUG-0009)
  - Enforced by: none — a review rule (confirm an API filter's granularity, verify the produced signal); PA-0026 carries the adapter test that came from it
- **PA-0011** — X.509 certificates generated for TLS must carry the extensions strict
  verifiers (modern OpenSSL, browsers) require: a CA with a Subject Key Identifier and a
  keyCertSign KeyUsage; a leaf with a Subject Key Identifier, an Authority Key Identifier
  that references the issuer, a serverAuth Extended Key Usage, and a SAN of the correct
  type (IPAddress for IP hosts, DNSName otherwise). Assert the generated cert's extensions
  and verify it against a real chain check in a test — even one skip-guarded to the
  environment that has a working crypto backend. (from BUG-0010)
  - Enforced by: tests/test_proxy_live.py::test_leaf_cert_chains_to_ca_with_aki_ski
- **PA-0012** — Tearing down an `asyncio` server must be bounded and must not assume
  `wait_closed()` returns once the listener closes: on Python 3.12+ it also waits for
  active connections, which for a long-lived server may never end. Track and cancel
  in-flight connection tasks on stop and wrap the final wait in a timeout. Persist
  important state as it is produced (not only on graceful shutdown), so a forced/abrupt
  stop loses nothing. (from BUG-0011)
  - Enforced by: tests/test_oracle_oob.py::test_stop_returns_while_a_connection_sits_idle
- **PA-0013** — A self-test assertion must reflect the **true contract of the system under
  test**, not an intuitive-but-wrong premise (e.g. only *conflicting* Content-Length is
  invalid; duplicate-*identical* is valid per RFC 7230). An on-host / integration self-test
  must use the same construction the validated offline test proved — never a weaker or
  hand-rolled variant that asserts something the offline test did not establish. (from
  BUG-0012)
  - Enforced by: tests/test_proxy_message.py::test_duplicate_content_length_raw_exact_but_parsed_rejects
- **PA-0014** — Do not rely on compose behaviors that differ between `docker compose` and
  `podman-compose` — chiefly in-place recreate on a config/env change, which
  podman-compose cannot do. Orchestration that changes env/profile on a running stack must
  be self-healing: on failure, tear the stack down (keep data volumes), force-clear wedged
  containers/pod/network under podman, and retry. And when a provider/environment incident
  is fixed in place, still record a PA for the *class* — closing it as a one-off leaves the
  class unguarded and it recurs. (from BUG-0013)
  - Enforced by: none — compose and podman orchestration runs on-host only; no test exercises it
- **PA-0015** — Operational / runbook documentation must be written from an **executed,
  verified run**, not from design intent. A step whose on-host last-mile code is not yet
  built and self-tested is tagged `[design]` and must **not** be presented as a followable
  command sequence; it becomes `[run]` only once its code exists and a self-testing script
  (that fails loud) proves the exit. Commands and expected outputs in a `[run]` step must be
  ones actually produced, and any step that changes host state or sends traffic ships with
  such a script. If the build environment cannot execute the steps (no lab/host), say so and
  keep them `[design]` until validated on the host. (from BUG-0014)
  - Enforced by: none — a documentation rule ([design] vs [run] steps), applied in review
- **PA-0016** — Shell scripts under `set -e` must never end a function/case/script (or any
  branch whose status becomes the script's exit status) with a bare `A && B`: it returns
  non-zero when `A` is false (`B` is skipped), so the script exits non-zero on success and
  aborts `set -e` callers. Use an `if`, or append `|| true`. Because the build environment
  cannot run the on-host scripts, verify them statically: `shellcheck`, plus a targeted
  `bash -c` exit-code check on **both** relevant branches (e.g. an optional var set and
  unset), and assert the success path exits 0. This strengthens PA-0015 — a `[run]`
  script's own harness (control flow, exit codes on every path) must be verified, not just
  its exit assertion, since a fail-loud self-test cannot catch an abort that happens before
  it runs. (from BUG-0015)
  - Enforced by: none — on-host shell scripts are checked with shellcheck and branch exit-code runs by hand; no test runs them
- **PA-0017** — An exit criterion or self-test metric must **isolate and measure the
  specific capability it claims to prove**, via a controlled comparison (e.g. an
  attack-vs-its-own-baseline differential), not a proxy dominated by unrelated work (a
  global frontier the control fills first; a total-requests count dominated by discovery).
  A passing self-test is not sufficient if the metric doesn't reflect the capability, and a
  diagnostic/NOTE must key on the actual condition it names (e.g. "no coverage captured" ⇒
  coverage-seen == 0), not a derived artifact. (from BUG-0016)
  - Enforced by: none — a metric-design rule, judged per metric in review
- **PA-0018** — Container-lifecycle self-heal is a cross-path convention. Every
  orchestration path that creates, removes, or recreates containers on a possibly-running
  or wedged podman stack must route through the **one shared force-clean helper** (per
  PA-0003) — never reimplement it per subcommand and never leave a path without it. When a
  container-lifecycle fix is added, the PA-0002 sweep must enumerate call sites by the
  **operation** (recreate / remove / tear-down) — every relevant subcommand (`up`, `reset`,
  `down`, and any future one) — not by the **trigger** that first surfaced it (e.g. an
  env/profile change). This re-keys PA-0014 from the trigger to the mechanism
  (podman-compose cannot remove or recreate a running/wedged stack) so a sibling path with
  the same cause but a different trigger cannot slip through the sweep. (from BUG-0017)
  - Enforced by: none — on-host container-lifecycle code; no test enumerates its call sites
- **PA-0019** — When a turn's work produces a finding that matches an artifact's stated
  scope for what it records (e.g. `ERROR_LOG.md`'s "anything that broke and was fixed"),
  add that artifact's entry in the same turn, checked against the artifact's literal scope
  statement — never inferred from whether the finding *feels* bug-shaped, and never treated
  as satisfied merely because the finding is also written up elsewhere (a spike report, a
  design doc, a playbook). Before ending any turn that involved running something and
  hitting unexpected behavior, re-read the relevant bookkeeping artifacts' own scope lines
  as a checklist item, not as background context absorbed once at session start. (from
  BUG-0018)
  - Enforced by: none — a session-conduct rule; partly backed by the Stop hook .claude/hooks/check-error-log-bookkeeping.sh, which is not a test
- **PA-0020** — When a preventive action's root cause is my own missed or inconsistent
  self-check (rather than a defect in project code, tests, or a process document), a
  written rule alone does not count as prevention — it must also have an enforcement path
  that runs independent of my remembering to apply it (in this project, a Claude Code hook
  under `.claude/settings.json`/`.claude/hooks/` that inspects actual session state and
  blocks or warns mechanically). This strengthens/supersedes PA-0019, which was itself an
  instance of the gap it named: an advisory rule addressed to the same fallible process it
  targets. Concretely, `.claude/hooks/check-error-log-bookkeeping.sh` now runs as a Stop
  hook and blocks the session from ending when this turn's not-yet-pushed changes look
  incident-shaped (a new/modified `docs/spikes/` or `docs/bugs/` doc, or `fail`/`hang`/
  `workaround`/`killed`/`timed out`/`crash`/`broken`/`regress` added to the diff) but
  `ERROR_LOG.md` was not touched. (from BUG-0019)
  - Enforced by: none — enforced by the Stop hook .claude/hooks/check-error-log-bookkeeping.sh, not by a pytest test
- **PA-0021** — PA-0003's obligation (a storage/serialization convention shared by more than
  one writer or reader lives in exactly one shared function every participant calls) applies
  to **every** such convention in the codebase, not only the one it was originally written
  against. Before adding a second, independent derivation of a value another path already
  stores or parses (credential keys, cache keys, identifiers, normalized hosts/URLs/paths),
  check whether a shared normalization function already exists for it. And a validation
  module that raises a typed error for some failure modes must raise that same typed error
  for every foreseeable failure at its boundary (e.g. a missing file/directory) — never let
  the underlying OS/library exception propagate raw. (from BUG-0007)
  - Enforced by: tests/test_ml_persist.py::test_the_loader_boundary_types_every_extreme_failure, tests/test_shared_primitives.py::test_every_owner_is_defined_once
- **PA-0022** — Any keyword/substring match used as a mechanical heuristic (a hook, a lint
  rule, a build gate) must anchor on word boundaries (`\b`) unless a bare substring is
  specifically intended, and must be checked against the project's own routine vocabulary
  (changelog/commit-message conventions, common English words) for accidental collisions
  before being trusted to run unattended — e.g. grep the heuristic's own keyword list
  against a sample of ordinary, incident-free commit messages/diffs and confirm zero
  matches. (from BUG-0020)
  - Enforced by: tests/test_oracle_strategies_access_control.py::test_denial_marker_is_word_boundary_anchored, tests/test_ml_model_selection.py::test_guard_ignores_legitimate_model_queries
- **PA-0023** — Any object wrapping a `sqlite3` connection (or another thread-affine OS
  handle) that is held as shared state on an object reachable from more than one call path
  must not assume its calls always land on the same OS thread — either confine it to a
  component that is provably single-threaded by construction (state that invariant in the
  docstring), or make the cached handle per-thread (`threading.local()`), never a single
  shared instance attribute reused blindly. Do not copy a "cache one connection on `self`"
  pattern from one component into a new one without re-checking whether the single-thread
  assumption still holds for the new component's actual callers — e.g. an ASGI test client
  used without its context-manager form spins up a fresh thread per top-level call, which
  is enough to break it. (from BUG-0021)
  - Enforced by: none — no test drives a shared sqlite handle from two threads; the single-thread invariant is stated in docstrings
- **PA-0024** — Whenever an emitter's (or any capability-registry-driven component's)
  "supports this shape" declaration is widened to accept a new case, the same change must
  exercise **every** existing record (manifest cell, config entry, etc.) that could newly
  match that shape — not only the new record the change was written for — as a standing
  test, not a one-time manual check. A per-shape capability registry and a per-record
  metadata registry that must stay in lockstep is a recurring shape of this bug class:
  before landing such a widening, add or extend a whole-collection regression test (e.g. a
  "render every cell of every existing manifest" test) rather than relying on tests scoped
  to the new record alone. (from BUG-0022)
  - Enforced by: tests/test_labgen_harder_shapes.py::test_every_cell_of_every_manifest_that_targets_php_current_renders, tests/test_labgen_php_laravel_harder_shapes.py::test_every_cell_of_every_manifest_that_targets_php_laravel_renders
- **PA-0025** — A tool-oracle wrapper that classifies a "no positive finding" result as
  `confirmed_secure` must independently verify, from the tool's own diagnostic output,
  that the tool actually reached and exercised the target — never infer "secure" purely
  from the absence of a positive match plus a clean exit code, since a match-only-output
  tool (no dedicated "not vulnerable" marker, unlike sqlmap/commix) cannot otherwise
  distinguish "ran cleanly, found nothing" from "never ran at all." Run the tool at a
  verbosity that surfaces its own connectivity/health diagnostics (never suppress them
  for "cleaner" output) and check for them before returning `confirmed_secure`. Extends
  PA-0007's fail-closed doctrine from authentication-signal inference to tool-oracle-
  output inference generally. (from BUG-0023)
  - Enforced by: tests/test_labgen_identifier_sqli_oracle.py::test_inconclusive_when_both_true_and_false_probes_error_identically, tests/test_labgen_identifier_sqli_assertion.py::test_an_unreachable_target_never_passes_a_secure_cell
- **PA-0026** — Supersedes/strengthens PA-0010. When building an explicit-allowlist
  adapter around a third-party function specifically because it silently accepts and
  mishandles some input class, enumerate the value-shape preconditions the wrapped
  implementation assumes but does not itself validate — for **every** allowlisted
  parameter, not only the one input class that originally motivated writing the adapter
  (cardinality relationships between parameters, min/max counts, ordering assumptions,
  mutual exclusivity, etc.) — and add an explicit precondition check plus a test that
  first reproduces the library's own silent failure, for each one found. PA-0010 named
  the general instinct ("confirm granularity", "verify the signal") but gave no
  checklist step forcing every allowlisted parameter's preconditions to be enumerated,
  which is exactly how a PA-0010-citing adapter still shipped with an uncovered gap
  (`covertable.make()`'s `strength` silently producing `[]` when it exceeds the factor
  count, uncaught by an adapter that had already defended the kwarg-key and sorter-
  default surfaces). Applies to every existing PA-0010-motivated adapter, per PA-0002's
  sweep obligation. (from BUG-0024)
  - Enforced by: tests/test_labgen_resolver.py::test_strength_exceeding_factor_count_rejected_not_silently_empty
- **PA-0027** — Strengthens PA-0001 and complements PA-0024. A test's expectations **and
  its fault injection** must be functions of the specific record under test, never of the
  collection's cardinality or a record's iteration position. (a) A fixture that perturbs
  "every other"/"the second" invocation keys its counter on the identity of the thing it
  perturbs (a `cell_id`, a path, a request), never on a global per-record call counter
  whose parity depends on how many *other* records the run includes — that silently stops
  (or starts) injecting the fault when the collection or the component's supported set
  grows. (b) PA-0001 extends to **derived** sources of truth: when a predicate or registry
  in the code can compute the set a test asserts on (e.g. `Emitter.supports()` over a
  manifest's cells), the test computes it from that predicate rather than restating it as
  a literal — PA-0001's "value a constant or registry already defines" was read too
  narrowly to cover a set no constant states but a predicate computes, which is how a
  hand-maintained `SUPPORTED_CELL_IDS` literal survived alongside it. PA-0024 obliges a
  capability widening to exercise every newly-matching record; this rule covers the
  inverse direction — the *existing* tests must still test what they claim once the
  record count moves. (from BUG-0025)
  - Enforced by: tests/test_labgen_cutover_gate.py::test_coverage_is_derived_from_supports_never_a_hand_maintained_literal
- **PA-0028** — A semantics/equivalence validator that accepts a mutation by default
  (any fragment-level check — AST comparison, canonicalized-string comparison, or
  otherwise — that returns "equivalent") must enumerate the transform shapes its
  fragment-level checks are structurally blind to, i.e. any construct whose safety
  depends on context **outside** the compared fragment (a SQL `--`/unterminated-comment
  marker, whose effect is on whatever follows it in the real, concatenated statement),
  and refuse those unconditionally absent explicit trusted provenance — checked before
  the fragment-level checks run, not left to them. This is PA-0025's fail-closed
  doctrine's "unprovable from the compared unit" case, applied to semantics validators:
  the default posture for an unproven case is reject, not accept. (from BUG-0026)
  - Enforced by: tests/test_mutation_operators.py::test_untrusted_line_comment_introduction_is_rejected
- **PA-0029** — Generalizes PA-0028 beyond semantics validators. Any checker whose "no
  violation found" verdict is reached by a code path that **gates off entirely (rather
  than narrows)** part of its own stated invariant under some condition must have a test
  whose positive fixture exercises that gated-off branch with an **additional, unrelated**
  defect injected into it — never only a fixture where the gating condition happens not to
  trigger. A positive fixture that always takes the gated branch (e.g.
  `fuzzlab.labgen.minimal_pair`'s own real vulnerable/secure pair, whose composition names
  always legitimately differ) proves the gate does not false-positive; it proves nothing
  about whether anything still runs when the gate is open. Every future condition added to
  such a checker (a new module category folded into `DEFAULT_VARIABLE_CATEGORIES`, a new
  gating boolean anywhere else) needs its own "declared difference alone passes, declared
  difference *plus* an unrelated rewrite still fails" pair of tests, not one. (from
  BUG-0027)
  - Enforced by: tests/test_labgen_minimal_pair.py::test_content_confinement_runs_even_when_variable_categories_is_narrowed, tests/test_labgen_minimal_pair.py::test_unrelated_rewrite_before_the_transform_region_now_caught
- **PA-0030** — A harness that claims to report "the real app's response" must not
  silently apply a client **default** that transforms what the server actually sent
  before the caller sees it (redirect-following, retry-on-error, automatic
  decompression changing an observable byte count, etc.) unless that transformation
  is the literal thing under test. Before extending such a harness's coverage to a
  previously untested category of real behavior (a redirect, a write through a
  different persistence layer/ORM than the ones already exercised, an authenticated
  flow), enumerate what that behavior needs from BOTH the client library's own
  documented defaults and the framework/ORM's own default behaviors (timestamps,
  casts, soft deletes, etc.) that no existing case happened to trigger — extending
  PA-0026's "enumerate every precondition, not only the one that motivated the
  change" discipline from allowlist adapters to live HTTP+ORM conformance harnesses.
  (from BUG-0028)
  - Enforced by: none — superseded by PA-0046, which carries the enforcement
- **PA-0031** — Before dispatching a wave of concurrently-running agent lanes that will
  each add sequential bookkeeping IDs (`CC-<CODE>-NNNN`, `FR-<CODE>-N`, or a
  `BUG-NNNN`/`PA-NNNN` pair), pre-assign each lane its own reserved, non-overlapping
  number(s) in its dispatch prompt rather than instructing it to "claim the next free
  one." Branching from the same trunk tip, concurrent lanes computing "next free"
  independently almost always compute the *same* number, and every resulting collision
  costs a manual renumber-and-reconcile pass across `CHANGELOG.md` and the affected
  component's `change-control.md`/`requirements.md`. This is a process rule for the
  orchestrating session, not a fix for a code defect — see
  `docs/MULTI_AGENT_ORCHESTRATION.md` for the full rationale and the rejected
  alternatives (fragment files, batched reconciliation, fewer/larger lanes, a merge-queue
  bot).
  - Enforced by: none — an orchestration rule (pre-assigned numbers), not checkable in the repository
- **PA-0032** — Before ending a turn with any next-step question, offer, or "say the
  word" framing directed at the user, check that question against the standing
  instructions already given for the current task. If the user already authorized the
  action the question is about (a scope, a count, a condition like "until X" or "keep
  going until done"), do not ask again — proceed. Reserve an end-of-turn check-in for a
  genuine blocker: an actual decision only the user can make, a missing input, or an
  ambiguity the standing instructions do not resolve — never for a natural-feeling
  stopping point (a wave/phase/batch finishing) that the standing instructions already
  cover. This is a session-conduct rule, not a fix for a fuzzlab code defect — a
  different root cause from PA-0019's bookkeeping-recall gap (that one is about
  recalling *what to record*; this one is about recalling *what was already
  authorized*). (from BUG-0029) *(Amended by BUG-0141.)* Reporting a stall, an
  overrun or a cap is never the check-in this rule forbids (PA-0141..PA-0146).
  - Enforced by: none — a session-conduct rule; its exceptions are enforced by PA-0141..PA-0146
- **PA-0033** — Strengthens PA-0020's *scope of enforcement* (not its diagnosis, which
  PA-0033 reuses as-is): PA-0020 established that a bug whose root cause is "my own
  missed or inconsistent self-check" needs mechanical enforcement, not a clearer written
  rule — but its own enforcement artifact (`check-error-log-bookkeeping.sh`) only covers
  one instance of that class (`ERROR_LOG.md` bookkeeping). Every future explicit,
  quantitative "do more of X / don't stop at the minimum" instruction that produces a
  checkable artifact (a list, a count, a set of records) must get its **own** concrete,
  mechanical check at the time the instruction is first acted on — not a restatement of
  the instruction's own wording in a planning document, and not deferred on the
  assumption PA-0020's general principle already covers it by existing. Concrete
  instance: `.claude/hooks/check-corpus-cwe-coverage.sh`, which blocks the session from
  ending if a touched `docs/research/corpus-examples/*/*/manifest.yaml` entry has fewer
  than 2 `cwe_unique` CWEs, or if any `cwe_unique` ID is also claimed unique by another
  touched entry — a CWE relevant to more than one entry belongs in `cwe_shared` and does
  not count toward either entry's floor. (Initially built as a simpler length check on a
  flat `cwe:` field; tightened to the shared/unique split and cross-entry uniqueness
  check after the first version still allowed copy-pasting the same CWEs across sibling
  entries, which a direct follow-up instruction correctly identified as not meeting the
  actual intent.) (from BUG-0030)

  Extended again per this same principle when a follow-up direct instruction ("at least
  5 pairs, not one example per CWE") surfaced a second uncovered quantitative floor:
  `check-corpus-cwe-coverage.sh` now also aggregates every `manifest.yaml` under a
  touched cell directory (`docs/research/corpus-examples/<cell>/`) and blocks the
  session if that cell has fewer than 5 `role: vulnerable` entries. Same failure mode as
  the original PA-0033 gap — a quantitative "at least N" instruction was tracked only in
  prose (this plan doc's Status section) rather than mechanically enforced — caught
  before it recurred a second time by applying PA-0033's own rule proactively this time,
  rather than waiting for a review to catch it.
  - Enforced by: none — enforced by the Stop hook .claude/hooks/check-corpus-cwe-coverage.sh, not by a pytest test
- **PA-0034** — Two related rules, from a PR review that found real defects a
  same-session test suite and a 4-round change-control review both missed (from
  `BUG-0031`, code-generation, and `BUG-0032`, an enforcement hook — recurrence of the
  same root cause one layer apart):
  1. Any new code-generation sink/template that constructs a SQL statement (or other
     executable text) from a runtime-computed *identifier* (not just a bound value), or
     that combines a request-derived value with a request-derived HTTP verb/route/
     auth-context assumption for the first time in a given code path, needs at least one
     test that renders the actual code and executes it against an adversarial input
     *orthogonal* to the feature's own intended demonstration (a malformed identifier, a
     mismatched HTTP verb, an absent auth context) — not only assertions that prove the
     feature's own happy path. A feature's own tests passing proves it does what it was
     built to do; it does not prove it doesn't also do something else unsafe.
  2. Any mechanical check built to enforce a quantitative/structural floor (PA-0033's own
     class of artifact) must, before being trusted, be run against at least one synthetic
     fixture *constructed to be malformed in the specific way the check claims to catch*
     — not validated solely by confirming it flags the real corpus's/codebase's own
     currently-known problems, since self-authored data rarely reproduces the malformed
     shape a future author might actually produce. Strengthens PA-0033: building the
     check is necessary but not sufficient; the check needs its own adversarial
     self-check before "mechanical enforcement exists" can be trusted. (from BUG-0031,
     BUG-0032)
  - Enforced by: none — applied per guard (each guard carries its own synthetic-offender test); nothing checks that every guard has one
- **PA-0035** — A capability probe that gates whether a real, potentially slow or
  hanging operation runs (a `pytest.mark.skipif(not xxx_available(), ...)`-style guard,
  or any equivalent pre-flight check) must exercise the **actual operation path** —
  the same client/transport/binary the real, gated operation itself uses, doing the
  smallest real instance of the same real work — never a different, easier-to-check
  proxy for it (a raw `socket.create_connection` standing in for a real, proxy-aware
  HTTPS client's request; a version-string check standing in for actually invoking the
  tool; etc.). A raw TCP connect can succeed on a path (unproxied egress) the real
  operation does not take (a required HTTPS proxy), so it answers a related but
  different question than "will the real operation complete." This generalizes
  PA-0025's fail-closed doctrine ("a wrapper's status conclusion must be independently
  verified against what the real underlying thing actually did, never inferred from an
  easier-to-observe stand-in") from tool-oracle *output* classification to pre-flight
  *capability* probes specifically — a context PA-0025's own wording does not cover
  (see `BUG-0033`'s recurrence review for why this is a new rule rather than a
  stretching of PA-0025's stated scope). Every such probe must also enforce its **own**
  bounded, explicit timeout on that real operation and report unavailable (never raise,
  never hang) if it is exceeded — passing this probe is never, by itself, a guarantee
  that every later real step of the operation it gates is also bounded: each of those
  later steps (e.g. the real `composer install` a live-boot probe gates) must enforce
  its own timeout independently, at the shared helper that runs it, not left to each
  call site to remember. The PA-0002 sweep for this class checked every other
  `*_available()`-style probe in `fuzzlab/` (`php_available`/`python_available` in
  `tier0.py`, `sqlglot_available` in `mutation/semantics.py`, `mariadb_available` in
  `live_boot.py`): each of those already directly tests the actual capability it gates
  (a CLI binary on PATH, or an actual import-and-parse of the library in question), not
  a proxy signal for it — only `live_boot_available()`'s network half
  (`_network_reachable`, now `_composer_network_probe`) had this defect. (from
  BUG-0033)
  - Enforced by: tests/test_labgen_conformance_live_boot_probe.py::test_composer_network_probe_enforces_a_bounded_timeout, tests/test_labgen_conformance_live_boot_probe.py::test_composer_network_probe_returns_false_on_timeout_never_raises
- **PA-0036** — When code-generation names an entity by one convention (a file path, a
  route string) and separately derives a *related* name for it via a target
  framework's own naming/inflection convention (a class name, or a symbol the
  framework expands into a path at runtime), never assume the two are inverses of
  each other without checking. Prefer computing the framework-facing value from the
  same single source of truth (an explicit path/string, never re-derived through the
  framework's own inflector) over relying on the round trip generatively; where an
  inflected form must be relied upon anyway, execute the target framework's real
  name-conversion function once against representative "hard" inputs (e.g. a run of
  digits directly abutting a letter) before trusting it. Concrete instance: the
  `ruby_rails` emitter's generated controller called Rails' bare `render :show`,
  which resolves the view directory via `self.class.controller_path` — derived from
  the class name through `ActiveSupport::Inflector#underscore` at runtime, which does
  not insert an underscore before a digit run following a letter — so a class name
  like `CellLabgenRr0001Controller` (from a cell ID like `LABGEN-RR-0001`, this
  project's own convention) resolved to the wrong view directory and 500'd on every
  real request. Fixed by rendering via an explicit `render template: "<path>"`
  literal computed from the same string used to write the view file, never through
  the inflector. Distinct from PA-0034 (executed adversarial tests for sinks that
  construct executable text) and PA-0035 (a capability probe's fidelity to a real
  operation path) — this is about generated code's own naming consistency with a
  target framework's implicit conventions, a failure mode neither prior rule covers.
  (from BUG-0034)
  - Enforced by: none — no test runs the target framework's inflector against generated names
- **PA-0037** — Two related rules from a real, 100%-reproducible defect that shipped
  latent through two full build phases because no test's own scope ever took the
  request pattern that triggers it:
  1. **Pin every transitive dependency a checked-in stack skeleton's own direct
     dependency under-constrains, when that dependency has a documented history of
     breaking major-version changes** (a semver-major bump that changes a widely-used
     method's calling convention, e.g. positional-to-keyword-only parameters). A direct
     dependency's own gemspec/package manifest declaring an unbounded or overly wide
     range on a transitive dependency (e.g. `activesupport`'s `json >= 0`) is not
     evidence that dependency is actually safe at every resolvable version — an
     unconstrained `bundle install`/`npm install`/`composer install` can silently
     resolve a newer major line that breaks an internal call site the direct
     dependency's own maintainers have not yet reconciled. Pin it explicitly in the
     skeleton's own manifest (with a comment naming the incompatibility and this rule),
     verified by a real install + the specific multi-step interaction below — never
     assumed safe because "it's just a transitive dependency."
  2. **A live-boot/integration test suite built entirely from single-request,
     single-cell tests (each individually correct and sufficient for its own narrow
     purpose) can still, in aggregate, never exercise a realistic multi-step
     interaction a real deployment needs** — e.g. two requests sharing one session/
     cookie, a request that depends on state a prior request created. Any stack's
     live-boot conformance suite must include at least one test that sends **two or
     more sequential real requests within the same client session** against the fully
     assembled app (not a single cell in isolation) before that stack's whole-app
     conformance (this project's own Phase D standard) is considered proven — a
     single-request-per-test suite structurally cannot surface a defect reachable only
     on request #2+ (session/cookie handling, any stateful middleware), regardless of
     how many individually-passing single-request tests exist. Distinct from PA-0035
     (a capability *probe's* fidelity to the real operation path) and PA-0033/PA-0034
     (quantitative floors and adversarial inputs for code-generation sinks) — this is
     about a test *suite's* aggregate request-pattern coverage, a failure mode none of
     the prior rules cover. Concrete instance: the `ruby_rails` skeleton's unpinned
     `json` gem resolved to a version whose `JSON.parse` broke
     `ActiveSupport::JSON.decode`'s own internal call, 500'ing every session-cookie
     read on the second request of any session — invisible to two full build phases'
     worth of single-request tests, found only once a whole-app, multi-request test was
     built. (from BUG-0035)
  - Enforced by: none — no test pins the ruby_rails skeleton's transitive gems or requires a multi-request live test per stack

- **PA-0039 — a cross-language module port must re-verify every language-specific
  runtime-behavior assumption the source language's shape relied on, not just its
  syntax/structure.** Porting a proven module (source/transform/sink/complexity) from
  one emitter's language to another's (e.g. `node_express`'s JS to `django`'s Python)
  copies the module's shape correctly by construction if it renders the same
  composition — but a runtime behavior the source language happened to make safe (JS's
  `+`/PHP's `.` string-concatenation both coerce `null`/`undefined` to text rather than
  raising) does not automatically hold in the new language (Python's `+` raises
  `TypeError` concatenating `str` and `None`). A sink that concatenates a possibly-absent
  tainted value directly into a string must defensively cast it to that language's own
  string type first (`str(...)` in Python), matching whatever sibling sink in the same
  emitter already does this correctly — never assume the port is complete once it
  renders the intended composition; a value that is empty/absent at runtime, not just
  the composition's shape, must also be checked. The PA-0002 sweep for this class
  checked every other tainted-value concatenation site in the same emitter's own
  template directory (`grep -rn "value_expr\|password_var"` over
  `fuzzlab/labgen/emitters/django/templates/`) — only the one sink this bug was found
  in lacked the cast; its siblings (`sql_numeric_lookup.py.j2`, `html_body_echo.py.j2`)
  already had it. A future cross-language module port should run the same sweep before
  considering that class of module "ported," not just "renders the same shape." (from
  BUG-0037)
  - Enforced by: none — superseded in scope by PA-0053 and PA-0054, whose absent-input checks enforce it
- **PA-0040** — When a change registers a module (or any entry) in a **shared,
  cross-stack** registry consumed by more than one stack-specific module set or more
  than one test file's own completeness table (as opposed to a change confined to one
  stack's own emitter-local registry), run the whole-repo `pytest tests/` suite and
  confirm it is green **before** the change is pushed/considered complete — not only
  the test file(s) judged directly relevant to the change. Sharpens `CLAUDE.md`'s own
  Definition-of-Done step 2 ("run the suite; keep it green") for the specific case
  where "the suite" that matters is not obviously implied by which production file was
  edited: `fuzzlab.labgen.modules`' shared registries have their own, separate
  completeness table/guard test (`tests/test_labgen_modules.py`'s
  `_DETERMINISM_CTX_BY_MODULE`) from any single stack's own module-set tests, and a
  change that adds a shared-vocabulary-only registration (the `L-P3.3c-DOM`/
  `CC-LAB-0210` pattern) must satisfy both. (from BUG-0038; this ID was originally
  assigned `PA-0036` on `claude/category-5-build-6boejs`, which collided with this
  branch's own, unrelated `PA-0036` — renumbered on merge, not restated.)
  - Enforced by: none — a process rule on which suite to run; scripts/verify_change.py now always adds the whole-package guards, but nothing forces its use
- **PA-0038** — Before considering any new `lab/ground-truth-*/` directory
  complete: (a) confirm all three required files (`labels.json`,
  `injection-points.json`, `expectedresults.csv`) show as tracked/addable via
  `git status`/`git add -n` — `.gitignore`'s blanket `*.csv` rule requires its
  own `!lab/ground-truth-<app>/*.csv` negation per directory, so a file
  present on disk can still be silently ignored and never reach the commit;
  and (b) run that shape's own test module as its own explicit, separate
  `pytest` invocation (not just as part of a claimed whole-repo run) and quote
  its literal pass count in the change-control entry's Effectiveness section.
  An aggregate whole-repo pass count does not, on its own, prove any specific
  new test file was actually collected and exercised against the final
  committed tree — sharpens PA-0040's related but narrower finding (that a
  cross-cutting change needs the whole suite run, not just the files judged
  directly relevant) for the case where even a claimed whole-repo pass turns
  out inconsistent with the new file's own directory-completeness contract
  (a new `lab/ground-truth-*/` directory missing a required sibling file,
  e.g. `expectedresults.csv`, that `fuzzlab.labels.contract.load()` requires
  unconditionally, compounded here by that file also being unreachable via
  `git add` for lack of a `.gitignore` negation). (from BUG-0036)
  - Enforced by: none — a commit-time process check (git add -n, a separate run of the new file); no test checks it
- **PA-0041** — When a project maintains more than one implementation of the
  same seam/protocol (e.g. `fuzzlab.oracle.probe.Sender`: `SeamProbeSender`
  and `RequestsProbeSender`), a security-relevant transport setting adopted
  in one implementation (redirect-following, TLS verification, timeout
  behavior, etc.) must be applied to every other implementation of that same
  seam in the same change, not left to be discovered independently
  per-implementation the first time a vuln class that happens to exercise it
  is built. (from BUG-0039)
  - Enforced by: none — no test compares transport settings across a seam's implementations; PA-0046 pins the redirect setting per sender
- **PA-0042** — Before mapping a new vuln class into
  `fuzzlab.core.runmode._VULN_TO_CATEGORY` (wiring a real confirmation path
  for it), verify live, end to end, through `fuzzlab.harness.multitarget.
  run_targets`'s own real scoring — not just `ConfirmationStrategy.confirm()`
  in isolation — against real ground truth for that class, checking the
  resulting `ScoreReport.tp`/`fp` values, not only that a `Verdict` object
  was returned. A strategy can confirm correctly and still score as a false
  positive if its `vuln_class` attribute's spelling doesn't match the
  ground-truth convention — a gap `confirm()`'s own return value alone can
  never surface. (from BUG-0040)
  - Enforced by: none — a live end-to-end scoring check for each newly mapped class; the multitarget runs cover the classes mapped so far
- **PA-0043** — `fuzzlab.labels.contract`'s ground truth has two distinct
  shapes per app: the *point* (`injection-points.json`, "where to probe" —
  url/method/param/location/rendering) and the *case*
  (`labels.json`, "the scored ground truth" — adds `vuln_class`,
  `sink_context`, `expected_vulnerable`). They are not automatically kept
  in sync, and a function building an audit `InjectionPoint`/`Candidate`
  from ground truth (e.g. `fuzzlab.harness.auto.points_from_ground_truth`)
  only has direct access to the *point* shape's own fields. Before adding a
  new rule or strategy that keys on a ground-truth-sourced field (a new
  `when` predicate, a new `Candidate` attribute), check which shape that
  field actually lives on — if it's case-only (as `sink_context` was), the
  construction site must explicitly cross-reference the matching case (by
  `(url, method, param)` identity) and carry the value over; it will not
  appear "for free." Then prove the real value flows through with an
  end-to-end test exercising the actual construction function against a
  real or realistic ground-truth fixture — never only a hand-built
  `Candidate`/`InjectionPoint` fixture that pre-supplies the field directly,
  which looks like coverage but cannot catch a missing propagation step
  (the same masking failure mode `PA-0006` names for a different root
  cause — see `BUG-0039`'s own recurrence-review section for why these two
  bugs are siblings, not a recurrence of one another: `PA-0006` is about a
  value that doesn't exist yet at a pipeline stage; this is about a value
  that exists elsewhere but was never wired through). (from BUG-0039)
  - Enforced by: tests/test_auto.py::test_points_from_ground_truth_carries_sink_context_from_the_matching_case
- **PA-0044** — Before considering any change to a `lab/ground-truth-*/`
  directory's case *or point* count (a `Case`/`InjectionPoint` added,
  removed, or reshaped — e.g. a `param`/`location` correction that changes
  which points a derived filter matches — not just an unrelated field
  edited within an existing entry) complete, grep the **whole** test suite
  (not only obviously-related files) for every hardcoded fraction/count
  assertion that could depend on that directory's cardinality or shape
  (target-app `recall`/`tp ==`/`N/M` assertions in `tests/*multitarget*.py`
  and `tests/*labels_contract*.py`, but also point-count assertions
  elsewhere, e.g. `tests/test_auto.py`'s own hardcoded whole-body-JSON
  point count) and explicitly re-run every file such a grep surfaces —
  **regardless of whether that file carries `pytest.mark.slow`** and is
  therefore excluded from the routine `pytest -q -m "not slow"` pre-push
  check. That check is the correct fast-iteration gate and stays
  mandatory, but it is never sufficient on its own to certify a
  ground-truth-cardinality-or-shape change complete: a hardcoded assertion
  living in a `slow`-marked file is invisible to it by construction, and a
  commit that only touches ground truth (not the test file whose assertion
  depends on it) gets no other prompt to re-run that file either. A grep
  finds all such files at once; a full, unfiltered suite re-run after the
  fact (this bug's own third instance, `test_auto.py`, was found exactly
  this way) is a valid but strictly weaker substitute — prefer the grep.
  Sharpens `PA-0040`'s related but narrower "run the whole-repo suite, not
  just relevant files" finding (scoped there to shared cross-stack module
  registries) and `PA-0038`'s "run that shape's own test module" (scoped
  there to the *new* ground truth's own dedicated tests) for the case
  neither covers: a pre-existing, unrelated-looking, cross-cutting test
  file whose hardcoded assertion merely happens to depend on a
  ground-truth directory's total count or shape. (from BUG-0040)
  - Enforced by: none — a process rule (grep every cardinality assertion when ground truth changes)
- **PA-0045** — Sharpens `PA-0044` from file-level to match-level
  verification, after `PA-0044`'s own fix (`CC-LAB-0197`) missed a second,
  independent hardcoded fraction in the same file it had just edited and
  re-run: a file passing `pytest` after you fix ONE hardcoded ground-
  truth-cardinality assertion does not prove there is no SECOND,
  independent occurrence of the same pattern elsewhere in that file —
  `pytest` re-running green only proves the assertions it collected are
  internally consistent with each other and the code, not that you found
  every assertion that needed changing. Before considering such a fix
  complete, count how many times the target's own recall/`tp`/count
  pattern actually matches across the whole file (e.g. `grep -c` it, or
  visually confirm every occurrence), and confirm that exact number of
  assertions was edited — not just that the file as a whole now passes.
  Applies with specific, recurring force to
  `tests/test_multitarget_category4.py`'s own single-cell-boot +
  multi-cell-boot test-pairing convention (each target gets one assertion
  in each), where a single ground-truth-cardinality change routinely
  invalidates TWO independent assertions in that one file, not one — do
  not stop at the first one found. (from BUG-0043)
  - Enforced by: none — a process rule (count every occurrence of the assertion pattern)
- **PA-0046** — Supersedes/strengthens `PA-0030`. `PA-0030`'s rule (a
  component that claims to report "the real app's response" must not
  silently apply a client default — redirect-following, retry-on-error,
  automatic decompression, etc. — that transforms what the server
  actually sent, unless that transformation is the literal thing under
  test) is correct, but its own framing scoped it to conformance
  harnesses (`*LiveBootHarness` classes) extending coverage to a new
  behavior category. The rule's real scope is any component that builds a
  `Probe` (or any object a `ConfirmationStrategy`/timing oracle treats as
  "the real target's response") — this project had TWO more such
  components (`fuzzlab.tools.probesender.RequestsProbeSender`,
  `fuzzlab.greybox.run.RequestsCorrelatingSender`, plus a third,
  lower-severity timing instance, `fuzzlab.tools.blind_sqli_fuzzer.
  RequestsSender`) silently following `requests`' own default
  redirect-following behavior, undetected because each was tested in
  isolation against a fake session that never exercised a real redirect.
  Before adding or extending ANY sender that feeds a `ConfirmationStrategy`
  or timing oracle, explicitly set `allow_redirects=False` (mirroring
  `fuzzlab.core.http`'s own authenticated path, which already got this
  right) unless following a redirect is the literal thing that sender's
  own strategy needs to observe, and add a fake-session test asserting the
  kwarg was actually passed — not just that a fake response was returned
  correctly. A component whose job genuinely IS to follow redirects (a
  login-flow fetcher discovering an authenticated session, a crawler
  discovering pages) is not an instance of this rule; the discriminator is
  whether the caller is a `ConfirmationStrategy`/oracle that needs the
  UN-followed response, not blanket avoidance of `allow_redirects=True`
  everywhere. (from BUG-0044)
  - Enforced by: tests/test_probesender.py::test_requests_probe_sender_never_follows_redirects, tests/test_fuzzer_seam.py::test_requests_sender_unchanged_standalone_behavior
- **PA-0047** — When adding a `ConfirmationStrategy` (or the first ground-truth
  case for an existing one) whose category needs a `fuzzlab.core.
  runmode._VULN_TO_CATEGORY` entry (its category's hyphenated slug differs
  from ground truth's own underscored `vuln_class` spelling), do not trust
  `test_every_ruled_strategy_category_is_reachable_from_its_vuln_class`
  (`CC-FUZZ-0034`) alone to catch a missing entry: that guard only checks
  the oracle's own internal `_CATEGORY_TO_CLASS` dict for self-consistency,
  and stays silently blind whenever a strategy's own `vuln_class` field is
  ITSELF mis-spelled to already match its `category` (as
  `OpenRedirectStrategy.vuln_class` was, hyphenated instead of
  underscored) — the guard's own early-continue ("identical either way, no
  mapping needed") then fires on a value that was only "identical" because
  it was wrong. Two things follow, both now enforced: (1) run
  `tests/test_oracle.py::
  test_ground_truth_vuln_classes_with_a_ruled_hyphenated_twin_are_mapped`
  (or extend it), which checks the SAME invariant against every real
  `lab/ground-truth*/labels.json` file's own `vuln_class` strings, not the
  oracle's own internal dict — verify it live against a real, scored
  `run_targets`/multitarget pipeline run (not just the unit-test fake
  senders) before declaring the new class reachable, since a category gap
  and a `vuln_class`-spelling gap are independent defects that can each
  hide the other; (2) every new `ConfirmationStrategy.vuln_class` value
  must be underscored to match ground truth's own `labels.json`
  `vuln_class` enum spelling (never hyphenated to match its own
  `category` field, which is a DIFFERENT, deliberately hyphenated slug) —
  check this directly against the strategy's own field value, not by
  pattern-matching a naming convention that could itself miss a variant.
  Confirming a new page's detection with a hand-built `Candidate` alone is
  not sufficient proof it works end to end; a live, scored multitarget
  pipeline run is the only check that exercises category reachability AND
  the scoring key's exact vuln_class match together. (from BUG-0045)
  - Enforced by: tests/test_oracle.py::test_ground_truth_vuln_classes_with_a_ruled_hyphenated_twin_are_mapped
- **PA-0048** — When adding a `sink_context_in`-gated audit rule (the
  `R-INSECURE-DESERIALIZATION`/`R-HEADER-INJECTION` shape), do not assume
  `fuzzlab.harness.auto.points_from_ground_truth` hands the audited
  `InjectionPoint` the right `sink_context` just because the ground-truth
  `Case` itself has the right one: that function's own `(url, method,
  param) -> sink_context` lookup silently collapses to ONE value per key,
  which is WRONG whenever more than one `Case` shares that key with a
  DIFFERENT `sink_context` — a real, already-used pattern in this
  project's own data model (`fuzzlab.labels.contract`'s
  multi-vuln_class-per-endpoint support, e.g. `TWCH-0013`/`TWCH-0015`
  sharing one sink with `sink_context` `"header"` vs `"redirect"`
  respectively). Before declaring a new `sink_context_in`-gated rule
  reachable, check directly whether its target url/param is one that
  ground truth also labels with ANY other vuln_class, and if so, verify
  the fix in `points_from_ground_truth` (or its future equivalent) emits
  a point carrying every distinct `sink_context` at that key, not just
  confirm the strategy against a hand-built `Candidate` and assume the
  real pipeline agrees — the same "hand-built confirm succeeds but the
  real pipeline still misses it" symptom `BUG-0045`'s own regression
  discipline was built to catch, here from a different, independent root
  cause (a collapsed one-to-many point-building lookup, not a category-
  mapping/vuln_class-spelling mismatch). A duplicate `InjectionPoint`
  differing only in `sink_context` is safe to emit (`fuzzlab.harness.
  scoring.score`'s `detected_keys` is a set keyed on `(url, method,
  param, vuln_class)`, never `sink_context`, so it cannot double-count a
  TP/FP) — prefer emitting one point per distinct value over trying to
  merge/prioritize them. (from BUG-0046)
  - Enforced by: tests/test_multitarget_category4.py::test_both_apps_run_through_multitarget_for_real

- **PA-0049** — Every committed dependency lockfile must be resolved against the
  project's **pinned runtime**, not the build/developer host. Concretely: each
  distinct dependency root that ships a lockfile (here both
  `fuzzlab/labgen/emitters/php_laravel/stack/composer.json` **and** its
  `skeleton/composer.json`) must itself carry the platform pin that fixes the
  runtime version (`"config": {"platform": {"php": "<image PHP>"}}` to match
  `web.Dockerfile`'s pinned `php:8.3` base, per D7) — a pin on one root does not
  protect a sibling root. Regenerating a lock (`composer update`, `npm install`,
  etc.) on a newer host without that pin silently resolves to packages the
  pinned runtime cannot run, and nothing fails until a from-scratch image build.
  When adding or fixing such a pin, **sweep every lockfile in the repo for a
  missing runtime pin** (PA-0002) and confirm each lock has no dependency
  requiring a runtime newer than the pinned one. (from BUG-0047)
  - Enforced by: none — no test checks lockfile runtime pins; the from-scratch image build is the check

- **PA-0050** — A liveness/readiness probe must target a **known-served,
  modelled endpoint** and treat "the server answered at all" as up; it must not
  equate "up" with a 2xx/3xx status on an **incidental** path such as `/`.
  `curl -f "${BASE}/"` is a false-negative liveness signal against any target
  whose `/` is not a 200 route — the generated Laravel lab 404s on `/` by
  design. Probe something the target actually serves (e.g.
  `/product.php?id=1`, which also confirms DB), or accept any HTTP response as
  "up." This generalises `PA-0025` (which fixed the *audit oracle* inferring
  *secure* from an *unreachable* target) to **every** reachability/health check
  in any layer, on-host shell harnesses included, and covers the mirror
  direction (inferring *dead* from a reachable target's incidental 404). When a
  target-app cutover changes the served surface, re-audit every health/readiness
  probe that hard-codes a route. (from BUG-0048)
  - Enforced by: none — the health probes are in on-host shell harnesses; no test covers them

- **PA-0051** — When porting an **observation/interception mechanism** (a
  coverage/fault shim, a proxy hook, an error sniffer) across runtimes or
  frameworks, do not assume the control-flow it depends on carries over. In
  particular, "an unhandled exception propagates out to my outer `catch`" is
  **false** under frameworks that catch-and-render exceptions internally:
  Laravel's `Illuminate\Routing\Pipeline` renders a controller `QueryException`
  to a 500 `Response` at the router-dispatch boundary, so it never reaches a
  global middleware's `catch`. Use the framework's own surfacing hook instead
  (Laravel `withExceptions(...)->report(...)`), record into request-scoped state
  the observer reads, and **keep a capability self-test that fails loud when the
  signal is dead** (as `greybox_e2e.sh`'s step-3 self-test did here — the
  discipline from PA-0008/BUG-0009 is what caught this). Verify the ported
  mechanism live (fault present ⇒ flag set; benign ⇒ flag clear), never assume
  parity with the predecessor runtime. (from BUG-0049)
  - Enforced by: none — the ported shim is verified by greybox_e2e.sh's on-host self-test, not by a pytest test

- **PA-0052** — A tool's **scope / allowlist filter** must be derived from the
  operator-configured target (e.g. the start URL's own host, with loopback
  aliases and `www.` normalised), **never a hardcoded lab literal** such as
  `localhost`/`127.0.0.1`. The crawler's link-follow guard was a fixed loopback
  allowlist that doubled as its "don't escape to the open web" boundary, so once
  the target became any authorized external host the guard excluded the target
  itself and followed zero links (BUG-0050). Express the boundary as "stay on
  the configured target's host," and **exercise any lab-only-default guard with
  a test that uses a non-default (non-loopback, real-host) target** — a
  loopback-only test can never catch a filter that silently drops real targets.
  Generalises `PA-0050` (which fixed the same class — a lab-shape assumption
  baked into a *readiness* check) from reachability probes to every
  target-scoping filter. (from BUG-0050)
  - Enforced by: tests/test_spider_scope.py::test_external_start_follows_only_same_host, tests/test_spider_scope.py::test_external_host_was_the_bug_all_links_would_have_been_dropped

- **PA-0053** — Strengthens/supersedes `PA-0039`'s scope. Every request
  parameter a generated page reads must have a **defined absent-input
  behavior** — the real page's own default (in `php_laravel`, the per-profile
  `default_value` page-profile key) or a handled 4xx returned *before* any
  sink — in **every** emitter and for every route, not only when porting a
  module across languages. A type cast alone (`PA-0039`'s `str(...)`) does not
  satisfy this: PHP's `.` already coerces `null` to `''` and the page still
  fails at the SQL/redirect layer. When migrating a real page, reproduce its
  absent-input behavior (e.g. `$_GET['id'] ?? '1'`) as deliberately as its
  vulnerability. Enforced mechanically, not by memory (`PA-0020`/`PA-0033`):
  the live-boot navigability crawl (`tests/test_labgen_navigability_live_boot.py`)
  requests every link-reachable page bare and asserts the anonymous visitor's
  status; each Browsable Labs lane must extend that crawl to its own app
  before its pages count as converted, and a newly linked page must pass it.
  A known exception is pinned by an `xfail(strict=True)` test naming its
  follow-up, never by asserting the 500 as expected. (from BUG-0051)
  - Enforced by: tests/test_labgen_navigability_live_boot.py::test_crawl_from_root_discovers_every_ground_truth_url_with_anonymous_status

- **PA-0054** — Strengthens `PA-0053` (whose rule stands) on **enforcement
  scope**. `PA-0053`'s only mechanical check, a link-reachability crawl, cannot
  see a route that nothing links to yet, so a known absent-input crash sat in
  the un-crawled `django` emitter until its lane built a homepage. Therefore:
  (1) every emitter's route profile must **declare** each named request
  parameter's absent-input behavior (a real default, or a handled 4xx before
  any sink), checked **offline** over every route the emitter's manifests
  produce -- not left to whatever a crawl reaches; (2) every live navigability
  test must also send a bare request to **every route the build serves**,
  enumerated from the emitter's own served-URL derivation (e.g.
  `served_url_for`), in addition to the crawl; (3) a `PA-0002` sweep that finds
  this class in an emitter it does not fix must pin each known instance with
  an `xfail(strict=True)` or an offline failing check -- never a prose
  deferral to a future lane. (from BUG-0052)
  - Enforced by: tests/test_absent_input_declarations_cross_emitter.py::test_spring_boot_declares_absent_input_for_every_route, tests/test_absent_input_declarations_cross_emitter.py::test_django_declares_absent_input_for_every_get_param_route, tests/test_absent_input_declarations_cross_emitter.py::test_go_net_http_declares_absent_input_for_every_route

- **PA-0055** — Completes `PA-0054`'s named sweep for `go_net_http` (Browsable
  Labs Lane 3). No new rule: `PA-0054` already named `go_net_http` as a
  remaining stack needing its own route-enumerated sweep before its pages
  count as converted, and this lane's application of that exact mechanism
  (an offline per-route `absent_input` declaration check, plus a live bare-
  request sweep of every served route) found and fixed three instances
  (`/api/clips/thumbnail`, `/clips/download`, `/clips/export`) on the first
  attempt, with no residue needing an `xfail` pin. Recorded so the sweep's
  completion for this emitter is traceable the same way `PA-0054` itself
  is traceable to `BUG-0052`'s. Remaining stacks (`spring_boot`,
  `ruby_rails`, `node_express`, `python_fastapi`) still owe their own
  application of `PA-0054`, unchanged by this entry. (from BUG-0053)
  - Enforced by: tests/test_absent_input_declarations_cross_emitter.py::test_go_net_http_declares_absent_input_for_every_route

- **PA-0056** — Strengthens `PA-0054` (whose rule stands) on **enforcement
  precision**, after a `spring_boot` recurrence exposed three specific gaps in
  its wording rather than its intent: (1) `PA-0054`'s bare-request sweep must
  send the request using **that route's own declared HTTP method**, not only
  a bare `GET` -- a framework's own method-routing layer can answer a `GET`
  on a POST-only route with its own 4xx (e.g. Spring's `405`) before the
  handler, and therefore the source/sink code, ever runs, so a `GET`-only
  sweep is structurally blind to this whole crash class on a POST-heavy
  stack however long the defect has been present; (2) "declare each named
  request parameter's absent-input behavior" covers **every input channel** a
  route can read -- query, header, multipart part, or whole body -- not only
  a named query parameter; (3) a `PA-0002` sweep that names another emitter as
  still owing this class, rather than fixing it, must pin every named,
  un-fixed instance with a failing-by-design check (`xfail(strict=True)` or an
  offline declaration-coverage test) **in the same change that defers it** --
  a prose "Lane N must do this later" sentence with no enforcement is not a
  preventive action, and stating it a second time (as `PA-0054`'s own sweep
  note did) does not make it one. (from BUG-0054)
  - Enforced by: tests/test_labgen_spring_boot_absent_input_live_boot.py::test_bare_own_method_request_answers_the_declared_status, tests/test_labgen_spring_boot_absent_input_live_boot.py::test_every_route_declares_a_bare_status_in_this_contract

- **PA-0057** — Strengthens `PA-0039`'s scope (from module ports to a stack's
  skeleton/harness runtime configuration) and `PA-0054`'s live half. (1) Every
  stack's **served** build -- the real deployment path **and** every test-time
  live-boot launch -- runs with its framework's debug / exception-detail /
  source-annotating output disabled (Rails `consider_all_requests_local = false`
  and `annotate_rendered_view_with_filenames = false`, Laravel `APP_DEBUG=false`,
  Django `DEBUG = False`, Express `NODE_ENV=production`, FastAPI docs routes off,
  no Spring devtools/actuator, no Go `pprof`), enforced mechanically by
  `tests/test_labgen_debug_pages_disabled.py` -- one check per stack reading the
  governing setting where the running app takes it from; a new stack, harness,
  or launch site extends it in the same change (the requirement had lived only
  as prose, `docs/LAB_IMPLEMENTATION_PLAN.md:775`, and per-stack memory, so the
  `ruby_rails` port's development-mode harness shipped Rails' detailed exception
  pages, whose "Extracted source" revealed each twin's transform). (2) Every
  live navigability / bare-request sweep asserts each response's **declared**
  status, not a range, and that error-response **content** carries no debug or
  generated-source markers -- a status-only "< 500" sweep cannot tell a debug
  page from a static one, nor see an absent input a sink's catch-all rescue
  turned into a 200. The PA-0002 sweep found one more instance (the test-time
  `node app.js` launches, `node_express`), pinned by a strict xfail and
  flagged, per `PA-0054`(3). (from BUG-0055)
  - Enforced by: tests/test_labgen_debug_pages_disabled.py::test_ruby_rails_booted_environment_has_debug_pages_off, tests/test_labgen_debug_pages_disabled.py::test_php_laravel_deployment_and_harness_env_have_app_debug_false, tests/test_labgen_debug_pages_disabled.py::test_django_settings_have_debug_false, tests/test_labgen_debug_pages_disabled.py::test_every_test_time_node_launch_sets_production, tests/test_labgen_debug_pages_disabled.py::test_spring_boot_has_no_devtools_actuator_or_stacktraces, tests/test_labgen_debug_pages_disabled.py::test_go_net_http_serves_no_pprof_debug_handlers, tests/test_labgen_debug_pages_disabled.py::test_python_fastapi_has_no_debug_and_no_schema_routes

- **PA-0058** — Strengthens `PA-0054`. `PA-0055` and `PA-0056` (the
  concurrent Lanes 3 and 4) add each route's own request method, input
  channels, and pinning other emitters right away. PA-0058 adds only what
  none of those covers:
  1. **Assert the declared absent-input result on both twins, not just "no
     crash".** Every bare-request check (the sweep, or the offline render
     check) must assert the route's **declared** status exactly, and
     **identically on both twins**. A "< 500" assertion alone is not
     enough: an undeclared absent-input path that does not crash but
     differs between the twins passes it, and it hands a crawler or oracle
     a way to tell the twins apart at the baseline URL. MeadowMart's bare
     `/api/search` answered 200 on both twins, with different bodies
     (BUG-0056, D3).
  2. **Validate declarations against one closed value set.** An
     `absent_input` declaration counts only if its value comes from **one
     closed, cross-emitter value set** and is allowed for the route's
     source kind (e.g. `ABSENT_INPUT_BY_SOURCE` in `node_express` and
     `python_fastapi`). Checks must validate membership, not presence.
     Otherwise each lane invents its own spelling, and a cross-emitter
     check can neither read one emitter's valid declaration nor reject a
     misspelled one.
  Until the concurrent lanes' spellings (`default:<v>` vs `default_value`)
  are unified, and the shared S15 check validates membership, that
  reconciliation is flagged to Lane 7 (`CC-LAB-0247`). (from BUG-0056)
  - Enforced by: tests/test_labgen_node_express_browsable.py::test_every_node_express_route_declares_an_allowed_absent_input, tests/test_labgen_node_express_browsable.py::test_absent_input_lines_are_identical_on_both_twins

- **PA-0059** — Strengthens `PA-0018` (container-lifecycle self-heal must route through
  the one shared `_force_clean` helper). `PA-0018` fixed *where* self-heal must run but not
  *how its trigger is detected* or *how its own data stays current*, and both gaps let the
  same "self-heal must actually happen" bug class recur a third time (`BUG-0057`, a
  wedged `apps`-profile stack left running by `labctl.sh down`):
  1. **Never trust a wrapped compose command's own exit code as the sole failure signal.**
     `podman compose down` returned exit 0 while printing per-container/per-network
     removal errors and leaving the whole stack running. A container-lifecycle operation's
     self-heal must additionally check **real post-state** (e.g. `podman ps -a` for any
     leftover project container) before concluding it succeeded.
  2. **A shared self-heal helper's own resource-name data is a hand-maintained duplicate
     of `compose.yaml`'s service list and must be swept in the same change that adds or
     removes a compose service** (PA-0002 applied to data, not just logic) — flagged as a
     candidate to derive `_force_clean`'s container/network lists from `compose.yaml`
     directly the next time this file is touched for that reason, rather than continuing
     to hand-list them. (from BUG-0057)
  - Enforced by: none — _force_clean's post-state check and its service list are on-host shell code; no test compares the list with compose.yaml

- **PA-0060** — Every container base-image reference (`FROM`, `COPY --from=<image>`, a
  compose `image:` key) must be a **fully registry-qualified** name
  (`docker.io/library/<name>:<tag>`, or the appropriate non-Docker-Hub registry), never a
  bare short name. A short name resolves silently under `docker build`'s single implicit
  registry, but Podman's short-name resolution prompts interactively
  (`Please select an image:`) whenever more than one unqualified-search registry is
  configured, and that prompt hangs forever under a non-interactive `--build`/`up` run
  with no error and no timeout (`BUG-0058`). Since this project explicitly supports
  `docker compose`/`podman compose`/`podman-compose` as interchangeable (`lab/labctl.sh`'s
  own header), a Dockerfile or compose file is not done until every image reference in it
  is qualified this way — verify with
  `grep -nE '^\s*FROM |COPY --from=[a-zA-Z0-9]|image:' <file>` and check each match starts
  with a registry host, not a bare repository name (build-stage references like
  `--from=gen`/`--from=<stage-name>` are not images and are exempt). (from BUG-0058)
  - Enforced by: none — no test checks that image references are registry-qualified; a grep at review time

- **PA-0061** — Every bare `requests.Session()` this project creates to send traffic to a
  caller-supplied (possibly non-lab) target must set a realistic browser `User-Agent`
  (`fuzzlab.core.http.DEFAULT_USER_AGENT`), never rely on `requests`' own default
  (`python-requests/x.y`). Several real external targets serve reduced/interstitial
  content (still `200 OK`) to that default UA instead of real markup, which silently
  breaks link discovery, oracle confirmation, or coverage correlation with no error
  (`BUG-0059`) — the local lab never surfaces this since it doesn't discriminate by UA,
  so this class is only ever caught against a real external target. When adding a new
  tool that opens its own `requests.Session()`, set this header at construction, and when
  sweeping for this bug class, grep the **whole** `fuzzlab/` package for
  `requests\.Session\(\)`, not just the directory the original report came from — this
  bug's own first sweep pass wrongly asserted two files were already fixed without
  checking, then missed three more instances entirely until a full-package grep was
  actually run. (from BUG-0059)
  - Enforced by: none — no test checks bare requests.Session() call sites for a browser User-Agent

- **PA-0062** — Strengthens `PA-0061` (every bare `requests.Session()` must set a
  realistic `User-Agent`). A `User-Agent` header alone is not enough: `requests`' other
  defaults (`Accept: */*`, no `Accept-Language`) are internally inconsistent with a real
  browser regardless of what UA string sits on top of them, and several WAFs check for
  exactly that mismatch — fixing only the UA moved a real target's response from
  silently serving reduced content to an outright `403` (`BUG-0060`, a direct
  recurrence of `BUG-0059`'s root cause one layer deeper). Use the full
  `fuzzlab.core.http.DEFAULT_BROWSER_HEADERS` dict (UA + matching `Accept`/
  `Accept-Language`/`Sec-Fetch-*`/`Upgrade-Insecure-Requests`), not the UA string alone,
  at every bare-session call site — and when fixing a fingerprintability bug in an HTTP
  client, ask whether *every* header a real client of the claimed kind would set is
  internally consistent, not just the one header the original symptom pointed at. This
  class of fix (making this project's own traffic harder for a WAF to distinguish from a
  real browser) is dual-use and requires confirming with the operator that the target is
  theirs or one they are otherwise authorized to test (D11) before implementing it — done
  for this case, but re-confirm per target, not assumed from a prior confirmation.
  (from BUG-0060)
  - Enforced by: none — no test checks bare requests.Session() call sites for the full browser header set

- **PA-0063** — Strengthens `PA-0003`/`PA-0021`, which are worded around normalizing a
  *value* and fire only when someone *adds a derivation*. Three additions:
  1. **Row selection is a convention too.** Choosing "the current row" of a table that
     more than one producer writes (several model families, tools, or runs) lives in
     **one shared reader**. That reader is scoped by the producer and by whatever the row
     is current *for* (e.g. the run). It is never an inline `ORDER BY id DESC LIMIT 1`
     at a read site. If the table has no column for the producer or scope, record it
     where the reader can see it (here, the `model` row's calibration JSON carries
     `run_id`) rather than guessing "newest".
  2. **A new writer audits the existing readers.** A change that makes a new producer
     write rows into an existing table must, in the same change, grep every reader of
     that table (`FROM <table>`) and check each one for single-producer or single-run
     assumptions. A reader that was correct when written can break when a second
     producer appears.
  3. **Enforced, not remembered.** For `model`, every read goes through
     `fuzzlab.ml.model_registry.select_latest`. `tests/test_ml_model_selection.py::
     test_no_module_reads_model_as_newest_row_of_any_family` fails on any inline "newest
     row" read. Extend that guard, or add a sibling guard, when another shared
     multi-producer table gets a selection convention.

  Distinct from `PA-0048`, which is a one-to-many *lookup* collapsing at point-build
  time; this is many producers sharing one table at read time. (from BUG-0061)
  - Enforced by: tests/test_ml_model_selection.py::test_no_module_reads_model_as_newest_row_of_any_family, tests/test_ml_model_selection.py::test_guard_catches_the_buggy_shapes

- **PA-0064** — Strengthens `PA-0017` (a metric must measure what it claims) and extends
  `PA-0029` (a gated-off branch needs a test that enters it) from checkers to
  **evaluation machinery**: splitters, scorers, metrics, and anything that produces a
  number presented as held-out or as an exit criterion.
  1. **Fail empty, never fail wrong.** An evaluation helper that cannot satisfy its
     contract for some input returns no result or raises. It never returns a
     contract-violating stand-in, such as a train == test fold "so the caller still gets
     scores". Callers treat "no result" as thin data, through their documented fallback.
  2. **Held-out numbers come from a verified partition.** Out-of-fold or holdout numbers
     are computed only through a path that checks every row is held out exactly once
     (`fuzzlab.ml.metrics.oof_folds`). A number recomputed from in-sample scores is
     labelled in-sample wherever it is displayed. It is shown only beside the held-out
     numbers of the model that produced those scores.
  3. **Test the degenerate branch.** Every degenerate or fallback branch of an
     evaluation helper (too few groups, `k < 2`, one class, empty input) has a test that
     enters it and asserts the contract there, not only on typical inputs.
  4. **Sweep by mechanism, not by artifact type** (as `PA-0018` did for container
     operations). The `PA-0002` sweep for this class covers every place a held-out
     number is produced or displayed, not only the module where it was found. Enforced
     for `fuzzlab/ml/` by `tests/test_ml_oof.py::test_no_out_of_fold_scorer_bypasses_oof_folds`
     and that file's degenerate-branch tests. (from BUG-0062)
  - Enforced by: tests/test_ml_oof.py::test_no_out_of_fold_scorer_bypasses_oof_folds, tests/test_ml_oof.py::test_oof_folds_fails_closed, tests/test_ml_oof.py::test_trainers_fall_back_instead_of_raising_when_k_is_below_two

- **PA-0065** — Strengthens `PA-0005`, whose "skippable when it needs an environment
  feature" escape hatch had no backstop. It is extended to the web UI, where
  `TestClient` is the test double for the browser: it renders templates but never runs
  their JavaScript, applies the CSP, or draws a chart.
  1. **Every HTML page is smoked in a real browser.** `tests/test_web_pages_browser.py`
     walks `app.routes`, so a new page is covered automatically, and fails if it meets a
     page it cannot classify or fill. It asserts zero page errors, zero console errors
     and zero CSP violations, plus each page's key rendered output. Extend it whenever a
     page gains client-side behavior.
  2. **A skip must fail somewhere.** `FUZZLAB_REQUIRE_BROWSER=1` (`tests/_browser.py`)
     turns every browser-test skip (no web extra, no Playwright, no launchable
     Chromium) into a failure. A change touching `fuzzlab/web/templates/` or
     `fuzzlab/web/static/` is verified with it set. Its change-control effectiveness
     entry quotes the browser tests' **pass** count. "N skipped" is not verification.
  3. **"Renders" needs a browser.** An effectiveness claim that something renders or
     works in the UI requires a real-browser run. A payload or markup test supports only
     "the data is served".
  4. **Policy ↔ markup are tied mechanically.** No template may contain what the app's
     own CSP blocks (inline `<script>`, `<style>`, `style=`, `on*=`, `javascript:`).
     `tests/test_web_templates_csp.py` enforces this. A change that tightens a browser
     security policy is verified across every page in a real browser, not only by
     checking the response header.
  5. **Adapters pass vendored-library options in the exact shape the vendored source
     handles.** Read the source, e.g. uPlot's `class` → `classList.add(c)` takes one
     token. This extends `PA-0026`'s precondition enumeration to adapters such as
     `static/js/chart.js`. (from BUG-0063, BUG-0064)
  - Enforced by: tests/test_web_pages_browser.py::test_every_page_loads_without_errors_or_csp_violations, tests/test_web_templates_csp.py::test_no_template_contains_csp_blocked_markup, tests/test_web_templates_csp.py::test_guard_patterns_catch_the_blocked_constructs

- **PA-0066** — Strengthens `PA-0063`, which named only *row selection* from a
  multi-producer table, and whose sweep was keyed on the "newest row" query shape. It is
  extended to every multi-run read:
  1. **Run-keyed joins.** A lookup built from one per-run table and applied to rows of
     another (finding → candidate labels, evaluation → candidate counts, any feature
     join) is keyed by `run_id` plus the content key. Content such as `(path, param)`
     is unique only within one run, and across targets not even that.
  2. **Test the wide scope against the narrow one.** A function that can run at more
     than one scope (one run, or every run) has a test that seeds **at least two runs**
     and asserts the wide-scope result equals the concatenation of the per-run results.
     A single-run fixture cannot tell a scoped join from a leaking one. See
     `tests/test_ml_budget_and_scope.py::test_store_wide_dataset_takes_labels_and_counts_from_each_rows_own_run`.
  3. **Sweep by mechanism.** The `PA-0002` sweep for a scope bug greps every read of a
     per-run table that has no `run_id` filter or id join, not only the query shape
     that surfaced the bug (the `PA-0018` lesson). (from BUG-0065)
  - Enforced by: tests/test_ml_budget_and_scope.py::test_store_wide_dataset_takes_labels_and_counts_from_each_rows_own_run, tests/test_ml_budget_and_scope.py::test_store_wide_dataset_never_labels_across_targets

- **PA-0067** — Strengthens `PA-0063` / `PA-0066` in how a sweep **judges** a site, after
  the per-run report (`BUG-0066`) recurred in a line `BUG-0061`'s sweep had explicitly
  cleared as "per-family correct". `PA-0066` widened what to look for, but not how to
  judge what was found.
  1. **A sweep verdict names the reader's scope.** For each site, record what the reader
     is *for* (one run's page or report, one run's training, a store-wide view), and
     whether the query's scope matches it. "Correct per family / per name" is not a
     verdict for a per-run reader. A site cleared without naming its reader's scope
     counts as unswept.
  2. **Per-run readers of `model` go through the run-scoped readers** (`select_latest`,
     `latest_classifier`, `latest_ranker` with the run's `run_id`). The guard
     `tests/test_ml_model_selection.py::test_no_module_reads_model_as_newest_row_of_any_family`
     now also flags `MAX(version)` reads of `model` that have no name filter. It was
     proven to flag the old report query.
  3. **A recurrence in a site a prior sweep cleared triggers a re-sweep** of every site
     that sweep cleared, judged by rule 1. The re-sweep is recorded in the new bug
     report. (from BUG-0066)
  - Enforced by: tests/test_ml_model_selection.py::test_no_module_reads_model_as_newest_row_of_any_family, tests/test_ml_model_selection.py::test_each_run_page_uses_its_own_classifier

- **PA-0068** — Strengthens `PA-0064` (held-out numbers; in-sample labelled) from *numbers*
  to *every calibrated artefact*, after BUG-0067: out-of-fold conformal thresholds were
  applied to in-sample deploy scores, and PA-0064's sweep never looked at decisions.
  1. **An artefact judges only its own distribution.** A threshold, calibration map or
     held-out metric is applied only to scores from the distribution it was calibrated
     or computed on. With no such score the consumer says so ("n/a (…)"); it never
     substitutes another score.
  2. **Stored scores name their source.** A model row records `score_source`. A score
     distribution that must be kept gets its own column, never a mix in one column. One
     function decides which stored score a gate may judge (`fuzzlab.ml.train.gate_input`).
  3. **A writer owns its paired columns.** The writer of a score column writes or clears
     its paired columns (`score` / `score_oof`, `rank_score` / `rank_score_oof`) in the
     same pass, so a re-scored run never keeps another model's values.
  4. **Sweep by consumer.** The PA-0002 sweep for this class covers every consumer of a
     calibrated artefact (each `gate.decide`, each threshold comparison, each
     calibration applied), not only the producers. (from BUG-0067)
  - Enforced by: tests/test_ml_saved_and_decisions.py::test_legacy_run_mode_rows_are_never_gated_on_in_sample_scores, tests/test_ml_saved_and_decisions.py::test_rescoring_in_another_mode_clears_the_old_out_of_fold_scores

- **PA-0069** — Strengthens `PA-0064(3)/(4)` and `PA-0017` from *which data* an
  honest-evaluation artefact sees to *the statistic it computes*, after BUG-0070: the
  conformal gate's quantile index exceeded its stated α at lab sizes, and the anomaly
  tripwire's "fraction flagged" counted whole tie groups past its budget.
  1. **A stated guarantee is tested as stated.** An error bound, a coverage level or a
     "fraction flagged" gets a test that asserts it **as stated** (≤ α, ≤ k — not a
     loose tolerance), at the smallest sample size the toolkit accepts, ties included,
     plus a non-vacuity check that it is not merely conservative.
  2. **An order-statistic threshold states its whole rule, in one helper.** Its
     finite-sample rule (index), its comparison operator and its tie handling are
     derived and documented **together**, in one shared helper (PA-0003; e.g.
     `conformal.upper_index` / `lower_index`, `anomaly.flag_budget` / `flag_top`), with
     ranks computed exactly where α is fractional. The test asserts the claimed
     fraction or bound with ties.
  3. **Calibrate on what is compared.** A threshold is calibrated on the exact values
     its consumers compare it with, after any storage rounding.
  4. **Sweep every order-statistic threshold.** The PA-0002 sweep for this class covers
     every order-statistic threshold in the codebase (`sorted(…)[k]`, quantiles,
     fractions, contamination), not only the reported one. (from BUG-0070)
  - Enforced by: tests/test_conformal_bound.py::test_per_side_error_on_the_calibration_set_is_at_most_alpha_with_ties, tests/test_conformal_bound.py::test_distinct_scores_flag_exactly_k_and_ties_never_exceed_it, tests/test_conformal_bound.py::test_the_gate_is_calibrated_on_the_stored_rounded_scores

- **PA-0070** — Strengthens and generalises `PA-0065(3)` (verify in the real browser)
  and `PA-0035` (a probe exercises the real operation path), after BUG-0068: the built
  package shipped 87 of 485 data files while every test passed against the editable
  install. Each prior rule was scoped to one layer; this one covers any shipped
  artefact.
  1. **Shipped or installed behaviour is verified on the built artefact** (or the real
     runtime), never only on the development stand-in. For the package:
     `tests/test_packaging.py` builds it and compares the built file set with the tracked
     source.
  2. **Package-data rules are recursive** (`**`) and include dotfiles; exclusions are an
     explicit deny-list that is asserted never to match a tracked file. Hidden
     *directories* are not matched by `**/.*` — the equality test is the backstop.
  3. **The PA-0002 sweep for this class covers every build/ship path** (package data,
     scripts that copy files, container build COPY lists). (from BUG-0068)
  - Enforced by: tests/test_packaging.py::test_the_built_package_ships_every_tracked_file, tests/test_packaging.py::test_the_deny_list_matches_no_tracked_file

- **PA-0071** — A reader may depend only on what production writes, after BUG-0069: the
  report read `candidate.feature_version`, which nothing ever wrote, and its test passed
  because the fixture wrote the column by hand.
  1. **A contract column or key that a reader depends on must have a production writer;
     a test must not supply by hand a value production never writes.** If a reader
     needs such a column, build the writer, or stop presenting the column as a recorded
     fact.
  2. **Enforced mechanically:** `tests/test_contract_writers.py` takes the contract
     tables' columns from the migrated schema and asserts each has an INSERT/UPDATE
     writer in `fuzzlab/` or an allowlist entry with its reason; it is proven on a
     synthetic writer-less column, and a stale allowlist entry fails too.
  3. **The PA-0002 sweep for this class covers every writer-less column** (the
     allowlist records each one's reason). (from BUG-0069)
  - Enforced by: tests/test_contract_writers.py::test_every_contract_column_has_a_production_writer, tests/test_contract_writers.py::test_the_guard_catches_a_writer_less_column, tests/test_contract_writers.py::test_the_allowlist_has_no_stale_entries

- **PA-0072** — Strengthens `PA-0041` (one seam's implementations stay in step) from
  *transport settings on senders* to the seam's **signature and every wrapper**, after
  BUG-0071: `_CostCounter` (the bandit's cost wrapper) lacked `content_type`, so
  `--bandit` crashed on every content-typed probe.
  1. **Every implementation or wrapper of a project protocol accepts the protocol's full
     signature and forwards every argument it accepts.**
  2. **Enforced by discovery, not by a list.** `tests/test_sender_conformance.py` finds
     `Sender` implementations by shape (AST), checks each signature against the
     protocol, and calls each wrapper against a recording inner sender. It is proven on
     synthetic wrappers that lack or drop an argument. Add a sibling guard when another
     protocol gets wrappers.
  3. **A loop that writes per-row state first writes a non-label "pending" state and
     flushes what it has in a `finally`.** A crash must never leave a value a consumer
     reads as a label (here NULL `oracle_status` reads as "oracle-labelled"). (from
     BUG-0071)
  - Enforced by: tests/test_sender_conformance.py::test_every_seam_class_accepts_the_full_protocol_signature, tests/test_sender_conformance.py::test_every_wrapper_forwards_every_protocol_argument, tests/test_pipeline_invariants.py::test_a_crash_mid_loop_leaves_reached_rows_checked_and_the_rest_pending

- **PA-0073** — Strengthens `PA-0048` ("duplicate points are safe to emit") after
  BUG-0072: the duplicates were safe for scoring, but the unbudgeted oracle loop
  confirmed each one and wrote duplicate findings.
  1. **When a producer may emit duplicates "safely", name every consumer of the
     duplicated unit and check each one.** "Safe" is a claim about all of them.
  2. **Enforce the invariant in every mode.** Here, `oracle.confirm` calls == distinct
     confirmation keys and findings ≤ distinct keys, in unbudgeted, budgeted and fallback
     modes (`tests/test_pipeline_invariants.py`).
  3. **A golden that pins a count is re-derived, never regenerated blindly.** A golden
     change is listed with before/after and its cause. (from BUG-0072)
  - Enforced by: tests/test_pipeline_invariants.py::test_one_confirmation_and_at_most_one_finding_per_key

- **PA-0074** — Strengthens `PA-0069(2)/(4)` (tie handling of order-statistic
  thresholds) and `PA-0003`, after BUG-0073: the ML tab compared a per-page ranker metric
  with a global prevalence "baseline". The ranking metrics broke ties by input order, so a
  constant ranker could beat the random expectation.
  1. **A metric and its baseline are computed by the same function over the same rows**
     (here `rank_train.evaluate_vs_random`). A displayed baseline derived any other way
     is a defect.
  2. **Every score-ordered computation states its tie handling**: a threshold, a top-k
     metric, or a selection cut. Input order is never the tie-break for a metric or a
     guarantee. A constant scorer is tested to equal the random expectation.
  3. **The PA-0002 sweep for this class covers every score-ordered computation**, not
     only thresholds. (from BUG-0073)
  - Enforced by: tests/test_ml_ranking.py::test_a_constant_scorer_equals_the_exact_random_expectation, tests/test_web_ml.py::test_a_constant_ranker_shows_no_lift_over_its_baseline

- **PA-0075** — Strengthens `PA-0063(1)` and `PA-0067` (model-row scope, judged on the
  reader side) after BUG-0074: a store-wide model (scope NULL = "all runs") was cited for
  later runs it never scored.
  1. **A provenance claim about a run** ("this model scored / produced X for this run")
     **is backed by a recorded fact about that run.** It is never inferred from an
     open-ended scope (NULL = all, "newest", a maximum).
  2. **A writer whose scope is open-ended records the closed set it acted on** (here,
     `calibration.scored_run_ids`).
  3. **A reader of a legacy open-ended row falls back to a fact in the run's own data**
     (a stored score in the family's column, passed as `select_latest`'s required
     `score_column`), never to "covers everything". (from BUG-0074)
  - Enforced by: tests/test_ml_model_selection.py::test_a_store_wide_train_covers_exactly_the_runs_it_scored, tests/test_ml_model_selection.py::test_each_family_reader_backs_a_legacy_row_with_its_own_score_column

- **PA-0076** — Strengthens `PA-0066(1)` (cross-table lookups keyed by run + content)
  after BUG-0075: the label join keyed on `(run, path, param, category)` and ignored the
  HTTP method both tables record, so a POST-only finding labelled the GET candidate
  positive.
  1. **A join between two tables keys on every identity field both sides record.** A
     field is omitted only with a stated reason (e.g. "an endpoint is a path").
  2. **Both sides normalise through one helper** (PA-0003; here `dataset.method_key`).
  3. **When a new value of an identity field becomes possible** (a new method, location
     or content type), **sweep the joins keyed without it.** (from BUG-0075)
  - Enforced by: tests/test_ml_dataset_keys.py::test_a_post_only_finding_labels_only_the_post_candidate, tests/test_ml_dataset_keys.py::test_method_key_normalises_both_sides

- **PA-0077** — Plugin containment covers every per-plugin step, after BUG-0076: one
  entry point with `priority = "high"` raised inside `register()` and took every plugin
  down, the ML stages included.
  1. **Every per-plugin step is inside the containment boundary:** load, metadata,
     registration, hook lookup, hook call, and recording. The containment property is
     tested at each step, not only at hook invocation.
  2. **A contained failure is visible:** a rejection or disable carries its reason to the
     run record or CLI. (from BUG-0076)
  - Enforced by: tests/test_plugins.py::test_malformed_metadata_rejects_only_that_plugin, tests/test_plugins.py::test_a_raising_hook_attribute_disables_only_that_plugin, tests/test_plugins.py::test_record_writes_every_attached_plugin_and_marks_a_failed_one

- **PA-0078** — A displayed count reads the recorded counter, after BUG-0077: the bandit
  panel showed `α + β − 2` as pulls, which counted informed-prior mass as pulls.
  1. **Never reconstruct a count from parameters that also encode something else** (a
     prior, a smoothing term, a default).
  2. **A display test asserts the value a production writer records**, not a formula
     applied to a hand-seeded row (cf. PA-0071). (from BUG-0077)
  - Enforced by: tests/test_web_ml.py::test_bandit_panel_pulls_are_the_schedulers_counter

- **PA-0079** — Usage-level validation precedes every side effect, after BUG-0078: the
  D15 fail-safe exited 2 only after writing a run row (and importing the crawl). The same
  symptom had been fixed for plugin errors alone (CC-FUZZ-0050), with no rule and no
  sweep.
  1. **Every usage-level validation runs before any side effect** (store open, run row,
     import, network). The pure part of a resolution is one function that both the CLI
     and the library call (here `harness.auto.plan_run`).
  2. **A failure only the run can hit marks the run** (`Store.mark_aborted`: `notes =
     "aborted: …"`). It is never left looking like a finished empty run.
  3. **Tested per path:** each known usage-error path asserts that no run row (no store)
     is left behind. A sweep covers every `start_run` caller. (from BUG-0078)
  - Enforced by: tests/test_auto_cli_side_effects.py::test_usage_failures_exit_2_with_no_run_row, tests/test_auto_cli_side_effects.py::test_a_failure_after_the_run_starts_marks_it_aborted

- **PA-0080** — Untrusted input never becomes a filesystem path, and secrets are private
  from creation, after BUG-0079: a CONNECT host became a leaf-certificate filename (path
  traversal), and keys were written, then chmodded.
  1. **A value from the network that becomes part of a path is validated against a
     whitelist grammar**, and the resolved path is asserted inside its root.
  2. **Secret files are created 0600 with `O_NOFOLLOW`** (`core.secretfile.write_secret`,
     the one helper), never chmodded after the write. The PA-0002 sweep for this class
     covers every write-then-chmod. (from BUG-0079)
  - Enforced by: tests/test_proxy_ca_hardening.py::test_hostile_hosts_are_refused_and_nothing_is_written, tests/test_proxy_ca_hardening.py::test_keys_are_0600_from_creation_whatever_the_umask, tests/test_credentials.py::test_the_encrypted_keyring_file_is_private_from_creation

- **PA-0081** — Strengthens `PA-0003` for safety gates, after BUG-0080: the loopback
  check existed in three copies and the proxy CLI had none.
  1. **Every listener goes through `core.net.require_loopback`.**
  2. **Enforced by a guard test that finds listeners by call shape**
     (`tests/test_loopback_listeners.py`), proven on a synthetic offender. A new safety
     gate shared by several call sites gets the same treatment. (from BUG-0080)
  - Enforced by: tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated, tests/test_loopback_listeners.py::test_the_guard_flags_an_ungated_listener

- **PA-0082** — Strengthens `PA-0046` (no automatic redirects in senders) from the oracle
  seam to every client that sends credentials, after BUG-0081: the session manager
  POSTed credentials to any form action and let a 307 re-send them.
  1. **A credential is sent only to an origin the operator authorised:** the login
     page's own origin, an in-scope host, or an explicit allow-list. A URL derived from
     response content (a form action, a redirect, a link) is never trusted as a
     credential destination.
  2. **Every client that sends credentials disables automatic redirects** and follows
     them by hand under the same origin rule. A 307/308 is never followed with a body.
     (from BUG-0081)
  - Enforced by: tests/test_session_credential_destination.py::test_a_cross_origin_form_action_gets_no_credentials, tests/test_session_credential_destination.py::test_a_307_or_308_is_never_followed

- **PA-0083** — Safety claims are backed at the action, after BUG-0082 ("never … sent",
  but gated only at record time) and BUG-0084 ("redacts token query parameters",
  never implemented).
  1. **A safety gate sits at the action it guards** (sending, writing, binding), not at
     a later bookkeeping step.
  2. **Every "never / always" safety claim in a docstring is backed by a test that fails
     when the claim is broken**; for a send gate, the test counts sends. The PA-0002
     sweep for this class greps docstrings for such claims.
  3. **A gate on an obfuscatable signature matches the normalised form as well as the
     raw one** (normalising only adds refusals). (from BUG-0082, BUG-0084)
  - Enforced by: tests/test_destructive_send_gate.py::test_the_live_filter_refuses_at_the_send_itself, tests/test_destructive_send_gate.py::test_obfuscated_destructive_payloads_are_refused, tests/test_requirements_traceability.py::test_every_safety_nfr_is_traced_to_real_tests

- **PA-0084** — An oracle confirms by structural effect, after BUG-0083: reflected-XSS
  confirmed whenever a break-out substring appeared anywhere.
  1. **Confirmation is by the structural effect a break-out would have:** an element
     outside inert content, an injected attribute, a token in JS code state, or a scheme
     in scheme position. Never a substring appearing somewhere. A lexer or parser that
     cannot be sure gives no verdict (PA-0025).
  2. **Each strategy has a true-positive and an escaped-reflection false-positive
     fixture per context**, derived from the lab's own sink templates where they exist.
     (from BUG-0083)
  - Enforced by: tests/test_oracle_xss_structural.py::test_non_exploitable_reflections_never_confirm, tests/test_oracle_xss_structural.py::test_exploitable_reflections_confirm, tests/test_oracle_xss_structural.py::test_the_lab_sinks

- **PA-0085** — Redaction rules, after BUG-0084: proxy history kept URL tokens and body
  passwords.
  1. **Sensitivity is decided by one name-token predicate** (`core.redaction.
     is_sensitive_name`), never a local substring list, which over-redacts benign
     fields such as `author`.
  2. **A redaction test plants each promised class of secret and searches every
     persisted copy** (rows, body table, FTS, separately stored bodies), with a benign
     list asserting nothing over-redacts. (from BUG-0084)
  - Enforced by: tests/test_proxy_redaction.py::test_no_secret_reaches_any_persisted_copy, tests/test_proxy_redaction.py::test_logs_use_the_same_predicate, tests/test_proxy_redaction.py::test_benign_names

- **PA-0086** — Generalises `PA-0077` (plugin containment) to every per-unit boundary,
  after BUG-0085: one bad proxy rule broke every connection.
  1. **User-supplied rules are validated when created** (regexes, encodings, scope
     patterns), never first evaluated on live traffic.
  2. **Every per-unit handler contains its own failures and reports them** (per
     connection, per plugin, per run). (from BUG-0085)
  - Enforced by: tests/test_proxy_rules_and_scope.py::test_bad_match_replace_rules_are_refused_when_created, tests/test_proxy_rules_and_scope.py::test_an_engine_failure_answers_502_and_the_proxy_keeps_serving

- **PA-0087** — One policy decision, one parser, after BUG-0086: a port-specific exclude
  was overridden by a second, host-only check, and every authority split broke on
  IPv6.
  1. **A policy decision is evaluated in exactly one place, on the most specific key.** A
     fallback on a less specific key must never be able to turn a deny into an allow.
  2. **Authorities are parsed by one IPv6-aware helper** (`proxy.authority`), never by
     `partition(":")`. (from BUG-0086)
  - Enforced by: tests/test_proxy_rules_and_scope.py::test_a_port_specific_exclude_is_not_bypassed_by_a_host_wide_include, tests/test_proxy_rules_and_scope.py::test_ipv6_connect_and_host_headers_parse

- **PA-0088** — Atomic transitions and locked check-then-act on shared storage, after
  BUG-0087: migrations were not atomic and two first opens raced. `open_store`'s own
  docstring rule was not followed.
  1. **An all-or-nothing transition is tested by injecting a mid-way failure.**
  2. **A check-then-act on shared storage holds the write lock across the check**
     (`BEGIN IMMEDIATE`, then re-check inside). `executescript` is never used where
     atomicity matters.
  3. **A rule stated in the store contract's docstring is backed by a concurrency
     test.** (from BUG-0087)
  - Enforced by: tests/test_migrations_atomic.py::test_a_failing_migration_leaves_nothing_behind, tests/test_migrations_atomic.py::test_concurrent_first_opens_never_fail

- **PA-0089** — Strengthens `PA-0071` from columns to any state, after BUG-0088: bandit
  backoff read parent posteriors that only a test created.
  1. **A feature switch is tested by its observable effect through the production
     path.** A flag whose on and off runs are indistinguishable in a test is a defect.
  2. **A test never creates state its producer does not**, in memory as well as in
     columns, unless it also tests the producer. (from BUG-0088)
  - Enforced by: tests/test_spa_query.py::test_the_switch_turns_query_discovery_off, tests/test_proxy_redaction.py::test_the_redaction_opt_out_keeps_raw_bytes

- **PA-0090** — Extends `PA-0084`, after BUG-0089: in-band SSRF/XXE confirmed on a mere
  reflection of the callback URL, whose token was also the "proof".
  1. **A confirmation's proof must not be derivable from the probe that elicits it.** An
     OOB / in-band marker is a keyed function of the token (here an HMAC), never the
     token the request carries.
  2. **Each such strategy has a "reflects the request but does nothing"
     false-positive fixture.** (from BUG-0089)
  - Enforced by: tests/test_oracle_oob.py::test_a_page_reflecting_the_callback_url_is_not_an_ssrf, tests/test_oracle_oob.py::test_the_callback_serves_a_proof_absent_from_its_url

- **PA-0091** — Strengthens `PA-0085`, after BUG-0090: JSON lists and objects under a
  sensitive key (`tokens: [...]`, `credentials: {...}`) kept their secrets in history,
  because every planted test secret was a scalar.
  1. **A redaction test plants each name form × each value shape.** Name forms are
     singular, plural and qualified. Value shapes are scalar, list, object, nested, and
     list of objects. Each combination is searched in every persisted copy.
  2. **A sensitive key redacts its whole subtree.** A redactor never recurses into a
     sensitive container looking for a second sensitive name. (from BUG-0090)
  - Enforced by: tests/test_proxy_redaction.py::test_a_sensitive_key_redacts_its_whole_value_whatever_its_shape

- **PA-0092** — Strengthens `PA-0068`, after BUG-0091: sealed holdout labels moved
  public forward metrics and every later non-holdout model. The seal had been enforced
  at an enumerated set of readers, and a second producer (forward evaluation), as well
  as trainers called without `--holdout`, were outside it.
  1. **A sealed set is enforced at every producer of public label-derived numbers, by
     one predicate** (`ml.holdout.sealed_split` / `held_ids`). It is keyed on durable
     state (the target's recorded memberships), never on a per-call flag.
  2. **A seal test flips the sealed labels and asserts every public number and every
     trained artefact is unchanged**, with a control flip proving the check is live.
  3. **The sealing argument is required where it can be forgotten** (`metric_input`'s
     `held`), with an AST guard. (from BUG-0091)
  - Enforced by: tests/test_ml_holdout_seal.py::test_flipping_every_sealed_label_moves_no_public_number, tests/test_ml_holdout_seal.py::test_every_metric_input_call_says_whether_the_row_is_sealed, tests/test_ml_holdout_seal.py::test_the_guard_catches_an_offender

- **PA-0093** — Strengthens `PA-0082`, after BUG-0092: credentials could be sent over a
  downgrade from https to http. The allow-list had no deny, and the agreed "never a
  downgrade" constraint was waived in implementation as "moot".
  1. **In an allow-list, the deny rules (transport, scheme) are evaluated before any
     allow, and each is tested directly.** A test makes every allow path admit a
     destination that the deny then refuses.
  2. **A safety constraint from an agreed draft is never waived in implementation
     without going back to the reviewers.** A deviation is recorded as a reviewed
     change, never as an implementation note. (from BUG-0092)
  - Enforced by: tests/test_session_credential_destination.py::test_every_allow_path_is_overridden_by_the_deny

- **PA-0094** — Strengthens `PA-0084`, after BUG-0093: a reflection in a JSON /
  ld+json / `<template>` / `src` script was confirmed as XSS.
  1. **Structural evidence includes the container's executability under the platform's
     own rules** (script type, `src`, `nomodule`, inert ancestors), implemented as one
     predicate.
  2. **Each structural check has a fixture where the structure matches but the container
     is inert.** (from BUG-0093)
  - Enforced by: tests/test_oracle_xss_structural.py::test_script_executes_is_the_one_predicate, tests/test_oracle_xss_structural.py::test_a_reflection_in_a_script_that_never_runs_does_not_confirm

- **PA-0095** — New, after BUG-0094: `flag_top` counted tie groups by rescanning every
  score for each distinct value, which is O(n²).
  1. **A per-element loop over a collection, inside a loop over the same collection's
     values, is O(n²).** Count with `Counter` or a sort.
  2. **Any function on a per-candidate or per-flow path has a test bounding its
     operation count** at a size where the quadratic form would be visibly worse. (from
     BUG-0094)
  - Enforced by: tests/test_ml_anomaly.py::test_flag_top_does_linear_work_on_heavy_ties

- **PA-0096** — Strengthens `PA-0021`, after BUG-0095: a saved model with `10**1000`
  escaped the loader as a raw `OverflowError`, and sizes were unbounded.
  1. **A typed error boundary is tested with values at every numeric extreme** (huge
     integers, `1e400`, NaN, ±inf, `-0.0`, bools) **and with oversized inputs** (bytes,
     element counts, depth). Sizes are bounded before allocation.
  2. **Validation predicates are total:** they return False and never raise. (from
     BUG-0095)
  - Enforced by: tests/test_ml_persist.py::test_the_loader_boundary_types_every_extreme_failure, tests/test_ml_persist.py::test_is_num_is_total

- **PA-0097** — Strengthens `PA-0080`, and extends `PA-0088` from the store to files,
  after BUG-0096: one `os.write` left a truncated secret behind a normal return, and
  the keyring renamed it over the good file.
  1. **A file write is complete or raises:** loop on short writes, raise on no progress,
     and `fsync` before returning.
  2. **Replacing a file is atomic:** a unique temp file, fsync, rename, and a directory
     fsync. On failure the temp file is removed and the original is intact.
  3. **A file that must never be replaced silently (a trust root) is created with
     `O_EXCL`.**
  4. **Each is tested with an injected mid-write failure**, including a real kernel short
     write where the platform allows it. (from BUG-0096)
  - Enforced by: tests/test_secretfile.py::test_a_real_short_write_raises_instead_of_returning, tests/test_secretfile.py::test_a_failed_replace_leaves_the_original_intact_and_no_temp, tests/test_secretfile.py::test_create_never_replaces_and_a_failed_create_leaves_nothing

- **PA-0098** — Strengthens `PA-0082` and `PA-0093`, after BUG-0097: a login-page
  redirect to another origin made that origin the credential allow-list's anchor.
  1. **The trust anchor of an allow-list is operator input only** (base URL, scope,
     allow-lists). A URL a response supplies is checked against the anchor, never added
     to it.
  2. **Every navigation hop is authorised before it is fetched.**
  3. **A client that cannot refuse redirects must prove it followed none, or fail
     closed.** (from BUG-0097)
  - Enforced by: tests/test_session_transport_binding.py::test_the_destination_anchor_is_the_base_url_not_the_page, tests/test_session_transport_binding.py::test_a_redirect_to_another_origin_is_never_fetched_nor_trusted, tests/test_session_transport_binding.py::test_a_fetcher_that_cannot_refuse_redirects_fails_closed

- **PA-0099** — Strengthens `PA-0093`, after BUG-0098: an https-established session was
  reused over plain http.
  1. **A transport floor binds every credential-bearing artefact** (password, cookie,
     token, Basic header) **at every point it is sent**: cached or fresh, through any
     helper that hands it to another sender, and again after anything edits the
     request. (from BUG-0098)
  - Enforced by: tests/test_session_transport_binding.py::test_an_https_session_is_never_applied_over_http, tests/test_session_transport_binding.py::test_greybox_never_sends_an_https_cookie_over_http

- **PA-0100** — Generalises `PA-0092(1)` from evaluation numbers to persisted traffic,
  after BUG-0099: a second producer stored secrets unredacted.
  1. **Every producer of persisted traffic goes through the one storage boundary**
     (`core.redaction`). An AST guard enumerates the producers and is proven on a
     synthetic offender (PA-0034(2)). (from BUG-0099)
  - Enforced by: tests/test_storage_redaction.py::test_every_traffic_producer_goes_through_the_redaction_boundary, tests/test_storage_redaction.py::test_the_guard_catches_a_synthetic_producer

- **PA-0101** — Strengthens `PA-0091`, after BUG-0100: the JSON redactor kept bodies it
  could not parse.
  1. **A redactor fails closed.** A body it cannot prove clean is omitted, never stored
     as received.
  2. **It is tested with malformed, huge-number, deep, oversized, mislabelled, chunked
     and compressed bodies carrying secrets** (PA-0096's extremes, applied to
     redaction). (from BUG-0100)
  - Enforced by: tests/test_storage_redaction.py::test_an_unparseable_or_deep_json_body_with_a_secret_is_omitted, tests/test_proxy_redaction.py::test_chunked_and_compressed_bodies_with_a_secret_are_omitted

- **PA-0102** — Extends `PA-0095` to I/O, after BUG-0101: unbounded, re-copying,
  event-loop-blocking upstream reads.
  1. **A network read has a byte cap and an overall deadline**, not only an idle
     timeout.
  2. **Accumulation never re-copies the buffer inside the read loop.** `bytes(buf)` in
     a loop is a swept pattern.
  3. **Blocking I/O never runs on an event loop.** (from BUG-0101)
  - Enforced by: tests/test_proxy_upstream_and_flush.py::test_the_body_is_never_recopied_per_chunk, tests/test_proxy_upstream_and_flush.py::test_a_dripping_peer_hits_the_overall_deadline, tests/test_proxy_upstream_and_flush.py::test_a_slow_sender_does_not_block_the_event_loop

- **PA-0103** — Strengthens `PA-0084` and `PA-0094`, after BUG-0102: a regex literal
  after `return` was lexed as code.
  1. **A hand-written lexer is tested on every grammar ambiguity it resolves.**
  2. **Where the grammar alone cannot decide, the result is UNSURE, never "code".**
     (from BUG-0102)
  - Enforced by: tests/test_oracle_xss_structural.py::test_a_token_inside_a_regex_literal_is_not_code, tests/test_oracle_xss_structural.py::test_a_slash_after_a_closing_brace_is_unsure

- **PA-0104** — Strengthens `PA-0096`, after BUG-0103: finite parameters produced NaN.
  1. **A loaded model's intermediate values and outputs are validated (finite, in
     range) before use.** Operand validation alone does not prove closure. (from
     BUG-0103)
  - Enforced by: tests/test_ml_persist.py::test_a_finite_model_whose_arithmetic_overflows_is_refused_at_scoring

- **PA-0105** — Strengthens `PA-0092`, after BUG-0104: a falsy holdout record was read
  as "no seal".
  1. **Fail-closed state distinguishes absent from malformed**, and malformed is never
     read as absent.
  2. **Safety state lives in its own append-only table, not inside a mutable blob.** Any
     backfill runs in the migration, never on first use by a reader. (from BUG-0104)
  - Enforced by: tests/test_holdout_seal_table.py::test_a_present_but_malformed_record_is_unknown, tests/test_holdout_seal_table.py::test_upgrading_a_v18_store_backfills_every_legacy_seal

- **PA-0106** — Enforces `PA-0093(2)`, after BUG-0105: an agreed "no-op where
  unsupported" became "no-op on any error".
  1. **An error is swallowed only by an explicit, named list of conditions**, never by a
     bare `except OSError` / `except Exception`.
  2. **A swallow list is tested with one swallowed and one propagated error**, and
     guarded against bare swallows with a synthetic offender. (from BUG-0105)
  - Enforced by: tests/test_secretfile.py::test_swallow_lists_are_explicit, tests/test_secretfile.py::test_the_swallow_guard_catches_an_offender

- **PA-0107** — Generalises `PA-0088(1)`, after BUG-0106: a "one transaction" history
  flush was not atomic.
  1. **Every documented batch or transaction claim has an injected-failure test.**
  2. **A batch writer prepares before it writes, and rolls back to its own
     savepoint.** (from BUG-0106)
  - Enforced by: tests/test_proxy_upstream_and_flush.py::test_a_database_failure_mid_flush_rolls_back_and_a_retry_writes_once

- **PA-0108** — Generalises `PA-0096`, after BUG-0107: bad evidence crashed datasets or
  became a fabricated row.
  1. **Every reader of stored JSON validates shape and types at one parser.**
  2. **Malformed rows are quarantined and counted, never replaced by defaults that
     fabricate data.** (from BUG-0107)
  - Enforced by: tests/test_dataset_evidence.py::test_a_bad_row_is_quarantined_never_fabricated

- **PA-0109** — Generalises `PA-0088(2)` to files, after BUG-0108: concurrent keyring
  updates lost one.
  1. **A read-modify-write on any shared store, files included, holds an interprocess
     lock across the read, and has a two-writer test.** (from BUG-0108)
  - Enforced by: tests/test_secretfile.py::test_concurrent_processes_lose_no_update

- **PA-0110** — New, after BUG-0109: a failed delete reported success.
  1. **An operation reports success only when its effect is verified, or when the
     swallowed failure is exactly the documented no-op case.** (from BUG-0109)
  - Enforced by: tests/test_secretfile.py::test_a_failed_delete_is_reported_and_a_missing_one_is_not

- **PA-0111** — Strengthens `PA-0061` and `PA-0062`, after BUG-0110: the login detector
  serialised a form unlike a browser. PA-0062 checked emulated request headers only.
  1. **Code that emulates a browser or protocol behaviour (form submission, redirects,
     cookies, headers) implements the named algorithm rule by rule.** Its rules are
     listed in a rule table that cites the spec step for each (e.g.
     `fuzzlab.core.forms.RULES`).
  2. **A guard test fails if any listed rule has no fixture.**
  3. **At least one fixture is a captured third-party target's shape, not only our own
     lab's.** The lab never surfaces the divergence it was written around. (from
     BUG-0110)
  - Enforced by: tests/test_form_entries.py::test_every_rule_has_a_fixture, tests/test_form_entries.py::test_bwapp_login_form_posts_what_a_browser_posts

- **PA-0112** — Strengthens `PA-0083(2)` (related: `PA-0020`, `PA-0033`), after BUG-0111
  and BUG-0112: NFR-CRAWL-safe and NFR-FUZZ-safe were specified and never built, and
  nothing failed. PA-0083(2) covered docstring claims only, the wrong layer.
  1. **Every NFR is classified** as SAFETY or NOT_SAFETY (with a reason) in
     `tests/test_requirements_traceability.py`; an unclassified NFR fails.
  2. **Every SAFETY NFR is traced in its `requirements.md`.** `Enforced by:` lines name
     the enforcing code and `tests/<file>.py::<test_function>` (checked by AST to
     exist), and a clause not yet enforced says `Not yet enforced:` plainly. A safety
     clause is never presented as built without a test that fails when it is removed.
  3. **The guard is proven on synthetic offenders:** a missing line, a test that does
     not exist, an unclassified NFR. (from BUG-0111, BUG-0112)
  - Enforced by: tests/test_requirements_traceability.py::test_every_safety_nfr_is_traced_to_real_tests, tests/test_requirements_traceability.py::test_every_classified_nfr_still_exists, tests/test_requirements_traceability.py::test_the_guard_catches_each_kind_of_offender

- **PA-0113** — Strengthens `PA-0111`, after BUG-0113: authenticated tools truncated the
  operator's URL to its origin, so an app under a sub-path could not log in. PA-0111
  covered emulated algorithms, not deployment layout.
  1. **A base URL is never truncated to its origin.** It keeps its path for discovery
     and joins. Query and fragment are dropped when a URL becomes a discovery base.
     Stored absolute paths join to the origin.
  2. **A session cookie's scope is the origin root unless the server says otherwise.**
  3. **Every component that takes an operator URL has a test with the app under a
     sub-path (`/app/`).** Our own labs all serve at the root and cannot surface this.
     (from BUG-0113)
  - Enforced by: tests/test_subpath_apps.py::test_the_crawler_logs_in_from_its_start_url_not_the_bare_origin, tests/test_subpath_apps.py::test_crawl_points_join_absolute_paths_to_the_origin, tests/test_session_browser_login.py::test_a_spa_under_a_sub_path_logs_in

- **PA-0114** — Strengthens `PA-0112`, after BUG-0114: the destructive-URL rule missed
  bWAPP's `update.php` (it rebuilds the database on a GET).
  1. **Before any crawl of a newly adopted third-party lab, its destructive or
     state-rewriting endpoints are enumerated from its source.** Each is checked
     against `core.urls.destructive_reason` in a test.
  2. **An endpoint the rule cannot catch is listed with its compensating control, or as
     a stated residual,** never silently. (from BUG-0114)
  - Enforced by: tests/test_forms_phase1.py::test_bwapps_destructive_gets_are_refused, tests/test_forms_phase1.py::test_bwapps_uncaught_endpoints_are_known_and_covered_elsewhere

- **PA-0115** — Strengthens `PA-0041` and `PA-0072`, after BUG-0115: greybox sent header
  payloads in the query, and DOM XSS moved body payloads into the URL. Those rules
  covered a seam's transport settings and signature, not where a payload lands.
  1. **Refuse, never relocate.** A sender, strategy or executor that cannot place a
     payload at the point's location raises (`UnplaceableLocation`) or gives no verdict.
     It never sends it somewhere else.
  2. **Placement is enforced by discovery.** `tests/test_sender_conformance.py` sends a
     marked value at each placeable location through every concrete seam class (a new
     one must register a factory) and asserts it lands there only; it is proven on a
     synthetic relocating sender.
  3. **The sweep is by mechanism:** every location branch of every component that
     builds its own request. A known instance not fixed is pinned with a strict xfail
     in the same change (`PA-0054(3)`). (from BUG-0115)
  - Enforced by: tests/test_sender_conformance.py::test_every_sender_places_a_probe_where_the_point_says, tests/test_sender_conformance.py::test_the_placement_check_catches_a_relocating_sender, tests/test_sender_conformance.py::test_senders_refuse_an_unplaceable_location

- **PA-0117** — Strengthens `PA-0084(2)`, `PA-0090` and `PA-0094`, from the mechanisms
  they were written for to every confirmation strategy, after BUG-0117: the SQLi,
  file-inclusion, SSTI and SpEL strategies confirmed on a signature the benign page also
  showed, on one unreplicated sample, or on a number a page already contained.
  1. **A fixed signature or marker counts only when it is absent from a benign control
     of the same point.** The control has the probe's type, minus what the probe tests.
  2. **A response differential counts only when the baseline is shown stable around it
     and it replicates with fresh tokens.** Its noise bound is stated and tested as
     stated (PA-0069(1)).
  3. **Enforced by discovery:** every `default_strategies()` member of a category runs
     against payload-independent noise (constant, periodic, signature-always) and must
     not confirm. The guard is proven on synthetic offenders (PA-0034(2)).
  4. **The PA-0002 sweep covers every strategy with a fixed marker or a single sample,**
     not only the failing mechanism's own class. (from BUG-0117)
  - Enforced by: tests/test_oracle_sqli_string.py::test_payload_independent_noise_never_confirms_any_sqli_strategy, tests/test_oracle_sqli_string.py::test_noise_discovery_guard_flags_a_control_less_signature_strategy, tests/test_oracle_sqli_string.py::test_noise_discovery_guard_flags_a_single_sample_differential

- **PA-0122** — Strengthens `PA-0022` (related: BUG-0113, PA-0113), after BUG-0122: the
  session manager read any redirect containing "login" as a logout. PA-0022's
  anchoring rule was never enforced on session detection, and its `\b` remedy is too
  weak for URLs.
  1. **A rule that decides session or auth state, auth-endpoint membership or
     credential handling from a URL, a `Location` or a name compares canonical URL
     keys** (plus query parameters where a login is query-routed) **or whole path
     segments and tokens.** Never a substring, never `\b`.
  2. **Enforced by an AST guard** over the modules that hold such rules (session,
     probe senders, auth helpers, navigation, crawler, `core/urls`, `harness/auto`).
     The guard is proven on a synthetic offender (PA-0034(2)). The oracle's
     vulnerability detectors are out of scope.
  3. **The PA-0002 sweep is by mechanism.** It records the pattern used and a
     disposition per site (PA-0067(1)).
  4. **Each such rule is checked against the lab's own vocabulary** (the target app's
     page and field names, PA-0022's check made concrete), and that check is a test.
     (from BUG-0122)
  - Enforced by: tests/test_logout_redirect.py::test_no_substring_test_decides_session_or_auth_state, tests/test_logout_redirect.py::test_the_guard_catches_a_synthetic_offender, tests/test_logout_redirect.py::test_the_lab_vocabulary_has_one_login_url

- **PA-0123** — Strengthens `PA-0112` and `PA-0002` (related: BUG-0050, BUG-0111),
  after BUG-0123: the crawler's browser followed an open redirect to github.com (and,
  in two bWAPP crawls, to a public blog). Scope was enforced at the link queue only,
  the browser guard checked destructive URLs only, Playwright never routes a
  redirect's later hops, and PA-0112 traced NFRs, not each clause per sending layer.
  1. **Every outbound path is scope-checked where the request is made**, not where its
     URL was chosen: browser navigations, redirect hops, subresources, popups,
     WebSockets, and API-request clients (`context.request.*`,
     `pw.request.new_context().fetch`, which also pass `max_redirects=0`).
  2. **Scope is an origin** (scheme, host, port) decided by the one predicate
     (`core.urls.in_origin_scope`). A host-only scope is a stated exception
     (BUG-0050's external crawl), never a default; another loopback port is another
     service.
  3. **A browser is confined at two layers, each for what it actually sees:** the
     route (the whole context, redirect chains walked hop by hop, `in_scope` required
     and checked before every fetch, `allow` never lifting scope) is the only guard for
     routed requests, which the Playwright driver fetches; the launch arguments
     (`navguard.browser_launch_args`: no proxy, resolver rules per `host:port`) confine
     only what Chromium itself sends. A scope is fixed before the browser starts and
     never re-derived from a URL being fetched. Both are enforced by an AST guard over every launch, guard and
     API-request site, proven on synthetic offenders, and by real-browser tests that
     reach for another port and an off-host address and fail, never skip, under
     `FUZZLAB_REQUIRE_BROWSER=1`.
  4. **Each clause of a safety NFR is traced on its own, per sending layer** (queue,
     static redirects, browser, API requests). A clause traced at one layer is not
     traced at the others. (from BUG-0123)
  - Enforced by: tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped, tests/test_browser_scope.py::test_the_browser_guard_catches_synthetic_offenders, tests/test_redirect_scope_sweep.py::test_a_later_post_login_hop_out_of_scope_is_never_fetched, tests/test_requirements_traceability.py::test_every_safety_nfr_is_traced_to_real_tests

- **PA-0124** — Strengthens `PA-0002` (for classifiers) and `PA-0117` (for
  confirmers), after BUG-0124: Juice Shop's open redirect (`/redirect?to=`) was never
  a candidate (a name-only rule; the value-shape rules came from a per-lane sweep that
  mapped only that lane's shapes) and would not have confirmed (one canary form,
  refused by a containment allowlist).
  1. **A classifier whose outputs select categories maps every output in one table**
     (`audit/value_shape.SHAPE_CATEGORIES`), with deliberate exclusions recorded with a
     reason (`SHAPE_EXCLUSIONS`). A test fails on a shape without a row and on rules
     that differ from the table. A sweep over such a classifier is by output, never by
     the lane's own categories.
  2. **A confirmer that relies on one probe form states the server-side filters it
     cannot pass, or carries a stated second form** (here: a seeded canary for
     containment allowlists, sent only after the plain one fails). (from BUG-0124)
  - Enforced by: tests/test_open_redirect_seed.py::test_every_shape_has_a_row_and_the_rules_match_the_table, tests/test_open_redirect_seed.py::test_a_containment_allowlist_confirms_on_the_seeded_canary

- **PA-0125** — Strengthens `PA-0012` (teardown is bounded) and `PA-0035` (every
  subprocess step is bounded) from *bounded* to *complete*, after BUG-0125: 429 orphaned
  `php -S` servers (a stopped `artisan serve`'s child), `go run` binaries and a puma
  (~14 GB) OOM-killed the suite. Both rules were followed by the leaking code.
  1. **A process the toolkit or its tests start owns its whole process tree,
     grandchildren included:** started in its own session under a supervisor tied to
     its owner's life (`fuzzlab.procutil.start_server`; `run_bounded` for a tool that
     forks), stopped as a group, identity-checked (pidfd plus `/proc` start time),
     never killed by name or pattern.
  2. **A real-process test proves nothing survives `close()` or the owner's death** --
     the port refuses and no process remains in the server's group or session, and an
     owner SIGKILLed with a grandchild-forking server leaves nothing.
  3. **Enforced, not remembered:** `tests/test_procutil_guard.py` fails on any spawn
     outside `procutil` (AST, proven on synthetic offenders), and the session-end
     safety net (`tests/_leak_guard.py`) stops any registered server still live and
     fails the run, naming argv, pid and age.
  4. **A "bounded" stop is checked for completeness:** a timeout, `terminate()` or
     `kill()` on one pid is not a stop of a launcher (`artisan`, `go run`,
     `bundle exec`, `mvn`, `npm`).
  5. **An id is trusted only while its leader pid is held** (review round 1): a process
     group or session id may be signalled only while its leader pid is still held --
     alive, or a zombie this code has not yet reaped, with the recorded start time. Pids
     wrap within minutes (pid_max 32768 here). So a supervisor reaps its server only
     after its last `killpg`, an owner sweeps a supervisor's session before reaping it
     (never through a runtime that reaps for it, e.g. asyncio's child watcher), a group
     whose leader is gone is signalled only inside a still-held session, and an unknown
     start time (0) matches nothing. Each such kill path has a test that fakes a reused
     id and shows nothing is signalled. (from BUG-0125)
  - Enforced by: tests/test_procutil_guard.py::test_every_child_process_goes_through_procutil, tests/test_procutil_guard.py::test_guard_flags_synthetic_offenders, tests/test_procutil.py::test_owner_sigkill_takes_child_and_escaped_grandchild, tests/test_procutil.py::test_a_stale_record_whose_pid_was_reused_is_never_signalled

- **PA-0126** — Strengthens `PA-0035` (probe the real operation) and `PA-0123` (browser
  confinement), after BUG-0126: the M6 browser executor had never run against a real
  browser. It ignored the operator's Chromium (its launch configuration was a third
  copy), let a launch failure abort the whole run, and read the sentinel 300 ms after
  `load`, before an asynchronously rendered sink fired.
  1. **Every Chromium launch takes its whole configuration from one helper**
     (`navguard.chromium_launch_kwargs`: headless, scoped args, the operator's binary),
     enforced by the AST guard at every `chromium.launch`, proven on a synthetic
     offender. A second copy of launch settings is a defect.
  2. **A browser mechanism has a real-browser check against a page whose sink fires
     after `load`**, and waits by polling up to a stated window, never by a fixed sleep.
  3. **A browser that cannot start is "no verdict"** (`UnplaceableLocation`), remembered
     for the run: never a crash, never a negative. (from BUG-0126)
  - Enforced by: tests/test_browser_scope.py::test_the_launch_sites_are_the_four_known_ones, tests/test_browser_scope.py::test_the_m6_executor_uses_the_configured_chromium, tests/test_browser_scope.py::test_the_m6_executor_sees_a_sink_that_fires_after_load, tests/test_m6_navigation_failures.py::test_a_browser_that_cannot_start_stops_at_once

- **PA-0127** — Strengthens `PA-0094` and `PA-0084`(2) (a recurrence of BUG-0093's
  root cause one layer out), and the BUG-0072 rule, after BUG-0127: a reflection in
  Juice Shop's `application/json` error confirmed reflected XSS. PA-0094 judged
  containers inside a document; the response itself is the outermost container.
  1. **A confirmer states every precondition of its signal and checks each on the
     observed response.** A markup signal (an injected element, attribute or script
     state; a meta refresh) counts only in a response a browser renders as HTML: its
     content type, and not served as a download (`oracle/strategies._renders_as_html`).
  2. **Its tests include a response that breaks each precondition** (for a markup
     signal: a JSON, plain-text, script and attachment echo of the same payload),
     alongside PA-0084(2)'s per-context fixtures. (from BUG-0127)
  - Enforced by: tests/test_oracle_xss_structural.py::test_a_reflection_confirms_only_in_a_response_rendered_as_html

- **PA-0128** — Strengthens and generalises `PA-0012`, after BUG-0128: browser teardown
  (`navguard.release`) unrouted while a page was still navigating, and the driver
  sometimes never answered. PA-0012 named one API (`asyncio.Server.wait_closed`); the
  principle applies to every layer.
  1. **A teardown stops its sources of in-flight work first** (connections, pages,
     child tasks) **and only then makes a call that may wait on that work.** Where
     the wait cannot be bounded (a sync Playwright call), quiescing first is mandatory.
  2. **A teardown has a test that starts it with work still in flight**, and a race
     that shows up intermittently is measured over enough runs to tell (here 80)
     before it is called fixed. (from BUG-0128)
  - Enforced by: tests/test_browser_scope.py::test_release_closes_every_page_before_unrouting, tests/test_oracle_oob.py::test_stop_returns_while_a_connection_sits_idle

- **PA-0129** — Strengthens `PA-0117` at the executor layer, after BUG-0129: the M6
  browser executor counted any page dialog as the probe's hit, so an app's own `alert`
  confirmed DOM / stored XSS. PA-0117's noise guard ran strategies with fake executors,
  so the executor's own evidence channels were never fed noise.
  1. **An execution signal counts only when it carries the probe's own fresh token.** A
     channel that cannot carry it (dialogs, console messages, a generic navigation)
     is never evidence: it is handled (dismissed) and ignored.
  2. **Each executor evidence channel has a real-page test producing that channel's
     noise with an inert payload**, which must not confirm. (from BUG-0129)
  - Enforced by: tests/test_browser_scope.py::test_an_apps_own_dialog_is_never_a_hit

- **PA-0130** — Strengthens `PA-0081` (one loopback gate, guarded by call shape) from
  fuzzlab's own listener calls to **every server it or its tests launch**, after
  BUG-0130: Spring Boot test servers listened on 0.0.0.0 (port flag only) and Go/Node
  servers took `HOST` from the inherited environment. PA-0081's guard could not see a
  bind address that is another program's argv flag, env variable or framework default.
  1. **A launched server binds loopback explicitly at its launch site** -- an argv flag
     or an env value set there (`--server.address=127.0.0.1`, `HOST=127.0.0.1`, a host
     argument) -- never a framework default or an inherited variable, even one whose
     default is safe.
  2. **The real sockets are checked** (`PA-0035`): `procutil.listeners` reads the LISTEN
     sockets of the server's process tree from `/proc`; `stop_server` -- the choke point
     every site goes through -- fails on a non-loopback listener, and the harnesses also
     check right after boot.
  3. **Enforced in source over `fuzzlab/` and `tests/`:** the static pin rule
     (`tests/test_loopback_listeners.py::test_every_server_launched_through_procutil_pins_loopback`)
     and the listener guard (now over tests/ too), each proven on synthetic offenders
     (PA-0034(2)); a process launcher is not mistaken for a listener. (from BUG-0130)
  4. **The runtime check is authoritative; the source rules are lints** (BUG-0130
     follow-up). The rule is "checked after boot, and at stop while live". Every server
     site calls `procutil.assert_loopback_only` right after boot, and every stop
     re-checks while the server still runs. The static pin, boot-check and netns rules
     catch common mistakes early, but they can miss what another program does at
     runtime. They are never the proof that a server is not exposed.
     "Exposed" means a non-loopback listener in the **host's** network namespace.
     The stop's check is total: if the check itself fails, the stop still runs in
     full and the failure is raised afterwards (`ListenerCheckFailed`). A check
     never aborts a cleanup.
  5. **A test that must bind a wildcard address does it only in a private network
     namespace** (`tests/_netns.private_netns`: `unshare -rn`). It skips, or fails
     under `FUZZLAB_REQUIRE_NETNS=1`, and never falls back to a host bind. Detection
     is proven by injecting that namespace as the host's. Enforced by
     `test_no_test_binds_a_wildcard_address_outside_a_private_netns`.
  Stated limits of the lints (reviewer B, confirmation round): a launcher reached
  through `importlib.import_module(...)` or bound to a variable first
  (`f = procutil.start_server; f(...)`) is not seen by the static pin rule. The
  boot-check lint and the runtime check still cover such a site.
  - Enforced by: tests/test_loopback_listeners.py::test_every_server_launched_through_procutil_pins_loopback, tests/test_loopback_listeners.py::test_the_pin_rule_flags_synthetic_offenders, tests/test_loopback_listeners.py::test_every_server_site_checks_loopback_right_after_boot, tests/test_loopback_listeners.py::test_no_test_binds_a_wildcard_address_outside_a_private_netns

- **PA-0131** — Strengthens `PA-0083(3)` (a gate matches normalised forms as well as the
  raw one), after BUG-0131: four gates judged a label, control name, entry or option by
  embedding it in a URL (`destructive_reason("/?x=" + text)`), and a `#` in the text
  hid everything after it. PA-0083(3) covered adding forms of the input, not a lossy
  step that removes part of it before any rule runs.
  1. **A gate judges its whole input in the input's own grammar:** a text by the text
     rule (`core.urls.text_destructive_reason`), a URL by the URL rule. An input is
     never embedded in another grammar's container (a text in a URL, a value in a query)
     to reuse a rule.
  2. **A gate's tests feed inputs carrying the structural characters** of every grammar
     the input passes through (`#`, `?`, `&`, `%`, quotes) and assert the refusal.
  3. **Enforced by an AST guard** (`tests/test_forms_phase4.py::test_no_text_is_judged_through_a_url`):
     no URL-rule call in `fuzzlab/` takes an argument built with a `?`, except a listed,
     reasoned allowance; proven on synthetic offenders (PA-0034(2)). (from BUG-0131)
  - Enforced by: tests/test_forms_phase4.py::test_no_text_is_judged_through_a_url, tests/test_forms_phase4.py::test_a_hash_in_a_label_name_value_or_option_hides_nothing

- **PA-0132** — Strengthens `PA-0111` (browser behaviour emulated rule by rule) and
  `PA-0006` (fixtures shaped like the real upstream), after BUG-0132: a browser login
  handed the requests-based senders only the bearer from its login response, not the
  `token` cookie the app's own JS set, so Juice Shop's server-rendered pages were probed
  anonymously. PA-0111's enforcement covered form serialisation only, and the login was
  designed as "detection", so the rule was not seen to apply.
  1. **A session handed from one client to another carries all the session state the
     first client holds for the host:** its cookie jar, script-set cookies included,
     and any other state the second client can use. This holds for a browser login to
     the requests senders, a crawl to an API client, and a capture to the manager. It is
     filtered by the scope, transport (`secure`, FR-SESS-13) and secret rules. It is
     never a projection derived from one response, and one function does the carrying
     (here `manager._jar_cookies`, PA-0003).
  2. **A session feature's fixture models what the target's server reads, per
     consumer**, not only what its login writes. At least one endpoint authenticates
     only through the state the target's client code establishes (a JS-set cookie, a
     header the app builds from localStorage). A real-path test sends through each
     consumer to it (the browser crawl, the `core/` seam, `session print`; PA-0035).
  3. **The PA-0002 sweep for this class lists every handoff point** of a session
     between clients, with a disposition each. A gap not fixed is pinned by a strict
     xfail (`PA-0054(3)`). (from BUG-0132)
  - Enforced by: tests/test_session_browser_login.py::test_a_requests_send_reaches_a_page_that_reads_only_the_js_set_cookie, tests/test_session_browser_login.py::test_the_js_set_cookie_never_goes_to_another_host

- **PA-0133** — Strengthens `PA-0084(1)` and `PA-0127(1)`, and extends `PA-0117` to the
  true-positive side, after BUG-0133: M4 refused Juice Shop's evaluated SSTI because the
  literal echoed in the profile's edit field matched `expr in text`.
  1. **A confirmer's disqualifying rule is judged by the same structural standard as its
     signal:** by the parsed role of what it sees (where a probe's literal is echoed:
     `strategies._echo`, `context.split_form_control_values`), never by a raw substring
     anywhere. Enforced by an AST guard
     (`tests/test_evaluation_marker_echo.py::test_no_strategy_judges_its_literal_by_a_raw_substring`),
     proven on BUG-0133's own line (PA-0034(2)).
  2. **Every confirmer has a true-positive fixture in a realistic page:** the input echoed
     where real apps echo it (an edit form around the evaluated value), at least one a
     captured third-party shape, beside a false-positive fixture for each place a
     reflection disqualifies.
  3. **A disqualifier change is mutation-checked in both directions:** dropping it lets a
     reflection confirm; widening it refuses the edit form. (from BUG-0133)
  - Enforced by: tests/test_evaluation_marker_echo.py::test_no_strategy_judges_its_literal_by_a_raw_substring, tests/test_evaluation_marker_echo.py::test_the_literal_guard_catches_the_old_rule, tests/test_evaluation_marker_echo.py::test_the_prg_edit_form_confirms_like_juice_shops_profile


- **PA-0134** — Strengthens `PA-0123` (scope is an origin), `PA-0099` (a floor binds every
  credential-bearing artefact at every send point) and `PA-0132` (a session handed between
  clients), after BUG-0134: a session was sent to every port of its host (Juice Shop's
  cookie and bearer to bWAPP on another loopback port), and a request there could log in
  there. PA-0123 governed request scope only, and the host-level session rule survived it
  as a "stated exception" no test pinned.
  1. **Every secret-bearing artefact carries the origins it belongs to from creation**
     (a session's cookies, tokens and Basic header, a browser's jar and storage state, a
     captured session), and every send path checks membership through one predicate
     (`SessionState.origins`; `prepare`, `authorize`, `_navigate(session_origins=)`,
     `header_scope_for` / `cookie_scope`, greybox's `cookie_origins`). A storage key such
     as `(host, identity)` indexes; it never authorises a send. An artefact with no
     origins goes nowhere (fail closed).
  2. **A stated exception to where a secret may go is pinned by a test of its exact
     extent, and is re-reviewed in the same change whenever a PA narrows the same class**
     (as PA-0123 narrowed scope to an origin). A security exception is never deferred in
     prose only (`PA-0054(3)`, `PA-0056(3)`).
  3. **Enforced by an AST guard** over the session-carrying modules: no `==`/`!=` with a
     hostname (`.hostname`, `canonical_host(...)`) decides a send, except listed, reasoned
     allowances; proven on BUG-0134's own shapes (PA-0034(2))
     (`tests/test_session_origin_scope.py::test_no_session_send_decision_compares_hosts`).
     The guard is a lint: the real-server tests (B receives nothing) are the proof.
     *(Review round 1:)* it sees through `.lower()` / `.casefold()` / `str()`, follows
     names and `self.` attributes assigned from a host, and flags `in` / `not in`.
  4. *(Review round 1.)* **A browser context that holds a session never loads another
     origin's document or socket, and no other origin's response may read or write its
     jar**: in such a context a document or WebSocket off the session's origins is
     aborted, and any other request there goes through a separate cookie-less client
     whose `Set-Cookie` is dropped. Withholding a header is not enough when the client
     shares state (a cookie jar, `document.cookie`, `localStorage`) with the session.
     *(Review round 3:)* that separate client sends an explicit empty `Cookie` on every
     request, since its own jar fills from the answers it fetches, and it is made once
     per guard (concurrent handlers race on any lazy or retiring lifecycle).
  (from BUG-0134)
  - Enforced by: tests/test_session_origin_scope.py::test_no_session_send_decision_compares_hosts, tests/test_session_origin_scope.py::test_a_send_to_another_port_carries_no_session_and_never_logs_in_there

- **PA-0135** — Strengthens `PA-0095(2)` and replaces its scope, after BUG-0135: a
  `scan_routes` linearity test asserted `t_large < 3.5 * t_small` and failed under
  load on linear code, and the FR-CRAWL-17 scan test repeated the shape. PA-0095 named
  only per-candidate and per-flow paths, did not forbid a timing ratio, and nothing
  enforced it.
  1. **A complexity claim is tested on an operation count the code exposes, never on a
     wall-clock ratio.** This holds for any code that claims to be linear, bounded or
     at most doubling, whatever path it is on. A wall-clock bound is only a generous
     absolute smoke alarm.
  2. **Code with a complexity claim exposes its operation counts**, covering both its
     Python-level steps and the span of its C-level searches (here `spa.StepCounter`).
  3. **The oracle is proven on a deliberately quadratic variant** (`PA-0034(2)`).
  4. **Enforced:** `tests/test_no_wall_clock_ratio.py` fails on a test that compares
     two clock measurements scaled against each other, or their ratio. It is proven on
     BUG-0135's own lines. A timing property measured by the system under test (a
     side-channel test) is not a complexity claim and is out of scope. (from BUG-0135)
  - Enforced by: tests/test_no_wall_clock_ratio.py::test_no_test_asserts_a_wall_clock_ratio, tests/test_no_wall_clock_ratio.py::test_the_guard_catches_bug_0135_and_each_synthetic_offender

- **PA-0136** — Strengthens `PA-0003` / `PA-0087` (one policy decision, one place) for
  the browser guard, and generalises BUG-0134 T1 and the reveal window's choice, after
  BUG-0136: a refused navigation was aborted with Playwright's default code, so Chromium
  replaced the crawled page with its error page; only two branches used `"aborted"`.
  1. **How a request is refused is decided once, by the kind of request, never per
     reason:** every abort of a document request -- a navigation, top-level or frame,
     and each of its redirect hops -- uses `"aborted"` (ERR_ABORTED: the current
     document survives, and `goto` of that target still raises); a subresource keeps
     the default. One helper (`navguard._abort_code`), one `abort()` in the handler.
  2. **A browser guard's tests record what the browser is told, not only that it was
     refused:** fake routes keep the abort code, and the code is pinned per reason
     (`tests/test_navigation_aborts.py::test_every_abort_reason_keeps_the_document_for_a_navigation`).
  3. **A fix of one branch of a shared mechanism sweeps every sibling branch in the
     same change** (here, every abort site), whatever feature the first fix was filed
     under. (from BUG-0136)
  - Enforced by: tests/test_navigation_aborts.py::test_every_abort_reason_keeps_the_document_for_a_navigation, tests/test_shared_primitives.py::test_route_aborts_happen_only_in_navguard


- **PA-0137** — Strengthens `PA-0126(3)` (a browser that cannot start is no verdict) and
  generalises FR-FUZZ-45/47's "never a silent negative" to a mechanism's external
  failures, after BUG-0137: a page the M6 executor could not load raised out of the
  oracle and the pipeline, which ended confirmation for every remaining candidate.
  1. **A confirmation mechanism maps every expected failure of the external work it
     depends on to "no verdict" at its own boundary,** not only the failure first seen.
     For a browser this covers the start, the context, each navigation and the
     observation (a page that never loaded and showed nothing). It uses the oracle's
     no-verdict path (`UnplaceableLocation`, with a reason that carries no payload or
     URL), and only for the named error class (PA-0106); a defect still propagates.
     Evidence already gathered (a hit) still counts.
  2. **A wait is never for an event a refused action can cancel:** wait for what is
     certain (the commit), then bound the rest.
  3. **Enforced by a run, not only a unit:** a multi-candidate run in which an early
     candidate's mechanism fails and a later one must still be confirmed, plus one test
     per failure point that mutation-checks the mapping. (from BUG-0137)
  4. *(Review, D54.)* **The unit of "not observed" is the probe, not the mechanism or
     the candidate:** a probe that could not be observed ends only that probe; the
     mechanism goes on to its next probe within a stated bound. With no evidence and
     anything unobserved, the result is inconclusive, never a negative, so it never
     becomes a training negative.
  - Enforced by: tests/test_m6_navigation_failures.py::test_a_page_that_cannot_load_never_ends_the_pipeline, tests/test_m6_navigation_failures.py::test_a_playwright_error_is_no_verdict_and_names_no_url, tests/test_m6_navigation_failures.py::test_any_other_error_is_not_swallowed

- **PA-0138** — Strengthens `PA-0137(2)` from the M6 executor to the whole codebase,
  with enforcement, and widens `PA-0136(3)` / `PA-0002` for a rule about a shared
  primitive, after BUG-0138: a page whose script navigates to a refused URL while it is
  parsed never fires `domcontentloaded`. The crawl, its query windows, the auditor and
  the browser login each waited out their timeouts, because BUG-0137 applied PA-0137(2)
  on the oracle path only.
  1. **A guarded page is navigated, and a load state waited for, only through
     `navguard`'s helper** (`navigate`, `reload`, `wait_for_state`,
     `load_state_reached`). The helper waits for the commit, so a refused own target
     still raises. It then waits for the load state, bounded and suppressed, and cut
     short once a main-frame navigation fails. **Enforced by an AST guard**
     (`tests/test_guarded_navigation.py`): no other module of fuzzlab calls `goto`,
     `reload`, `go_back`, `go_forward`, `wait_for_navigation`, `expect_navigation`,
     `wait_for_load_state` or `wait_for_url`. It is proven on synthetic offenders.
  2. **A page whose load did not complete is read from what is there:**
     - the DOM, read without waiting for an element that may never come (no
       `inner_text('body')` wait);
     - the response the browser already received;
     - never a second request, and never a wait on content.
  3. **A rule about a shared primitive (a call every component makes) is swept across
     every caller of that primitive, not along the path its bug came from;** and a
     behavior change to a shared mechanism (here the abort code) is followed to every
     consumer that waits on what it changed. Each such rule gets a structural guard
     where one is possible. (from BUG-0138)
  4. *(Review, D58.)* **A cancellation signal counts only from the commit of what it
     cancels:** an earlier event (the previous page's navigation) never cuts this one's
     wait. **Content comes from the document the URL loaded:**
     - its received bytes, kept by the guard that fulfilled them, when its parsing
       stopped or another document replaced it;
     - its live DOM when it was merely slow;
     - never another document's.

     The guard also covers `set_content`, `wait_for_event` and `expect_event`.
  - Enforced by: tests/test_guarded_navigation.py::test_every_guarded_navigation_goes_through_the_one_helper, tests/test_guarded_navigation.py::test_the_navigation_guard_catches_synthetic_offenders

- **PA-0139** — Strengthens `PA-0124(2)` from the open redirect to every confirmer, after
  BUG-0139: every M6 payload called the sentinel with single quotes, so Juice Shop's
  track-result DOM XSS (its id evaluated in a single-quoted server-side string; 500 on a
  `'`) was a guaranteed false negative.
  1. **A confirmer's probe set never shares one quoting or encoding shape where the
     vulnerability does not require it.** Where the effect does not depend on a quote
     (calling a sentinel, computing a marker), at least one probe carries no quote
     character at all, and the probes span the quote kinds. The M6 set is pinned by
     `tests/test_m6_payload_quoting.py::test_the_sentinel_call_comes_in_three_quoting_shapes`.
  2. **A confirmer that keeps one shape states the upstream filter it cannot pass**
     (in its requirement and the bug sweep that found it): today Go-template SSTI
     (`"`), XXE (`"`) and CRLF (raw `\r\n`).
  3. **A confirmer's true positive is tested through a realistic data path**, not only
     a direct echo: at least one fixture puts a step between the input and the sink
     that rejects or breaks on a character the payloads might use. Every new payload
     shape is checked against the existing negatives (escaped render, JSON echo).
     (from BUG-0139)
  *(Review.)* Go-template SSTI now carries a second, raw-string form, so PA-0139(2)'s
  stated single-shape confirmers are XXE (`"`) and CRLF (raw `\r\n`).
  - Enforced by: tests/test_m6_payload_quoting.py::test_the_sentinel_call_comes_in_three_quoting_shapes, tests/test_m6_payload_quoting.py::test_a_sink_behind_a_single_quoted_evaluation_is_confirmed

- **PA-0141** — Supersedes `PA-0032` for one case: **progress, not activity, is what
  authorises continued autonomous work.**
  1. **Open a goal before dispatching.** Any session that dispatches agents opens a goal
     ledger first: `scripts/orchestration_guard.py goal open --text … --metric …
     --baseline N --evidence <run output>`. The metric is the user's own measure of
     success (e.g. confirmed findings per live run), measured, not estimated.
  2. **Checkpoint every 3 hours of unattended work.** Run a real measurement, record it
     with `checkpoint`, and send the user the `report` with PushNotification.
  3. **A stall is a defect.** If the metric has not improved for 6 hours and the user has
     not written, that is a stall: busy is not building. Stop feeding the stalled work.
     Open a process or measurement item to find out why the metric is not moving, fix
     that cause under the bug protocol (the process itself included), and report to the
     user. Don't wait to be asked. Reporting a stall is never the check-in PA-0032
     forbids.
  4. **The hooks enforce this.** During a stall, the dispatch gate lets through only an
     item of kind process or measurement opened after the stall began. The Stop hook
     refuses to end a turn with a checkpoint overdue or a stall unreported.
     (from BUG-0141)
  - Enforced by: tests/test_orchestration_guard.py::test_a_stalled_metric_denies_dispatch_until_the_user_writes, tests/test_orchestration_guard.py::test_during_a_stall_only_work_on_the_stall_itself_is_dispatched, tests/test_orchestration_guard.py::test_a_stall_needs_a_push_notification_before_the_turn_ends, tests/test_orchestration_guard.py::test_a_checkpoint_falls_due_after_three_unattended_hours, tests/test_orchestration_guard.py::test_dispatching_without_a_ledger_is_caught_at_the_stop, tests/test_orchestration_guard.py::test_replay_of_the_2026_10_14_incident_stops_six_hours_in

- **PA-0142** — **Review rounds are capped.**
  1. **At most 3 review requests per work item** between user contacts. A request is any
     dispatch to a registered reviewer, or one tagged `[review]`.
  2. **After the third round, ask the user.** Do not open a fourth. Report what the
     rounds keep finding and propose one of: ship with stated residuals, narrow the
     scope, or redesign.
  3. **Reviewers sort their findings** into must-fix (correctness, safety, the goal) and
     follow-up. Only must-fix items enter the next round. Follow-ups go to the ledger as
     self-originated items (PA-0143). (from BUG-0141)
  - Enforced by: tests/test_orchestration_guard.py::test_review_rounds_are_capped_and_counted_from_real_dispatches

- **PA-0143** — **Work the session opens itself waits for the user.** This covers a
  reviewer's suggestion, a hardening, a follow-up feature, or a known gap filed as a
  bug. Record it with `item add … --origin self`; it is not dispatched until the user
  has written after it was opened. List every such item in the next report. The one
  exception is a defect that blocks an active item (`--kind bug --blocks <item>`): fix
  it under the bug protocol. (from BUG-0141)
  - Enforced by: tests/test_orchestration_guard.py::test_work_the_session_opened_itself_waits_for_the_user

- **PA-0144** — **A fix that keeps spawning bugs is stopped, not fixed forward.**
  1. **Two bugs spawned by one item stop it.** When one item's fixes have spawned 2 bugs
     (`item add … --spawned-by <item>`), dispatch for that item and its bugs stops.
  2. **Measure, then redesign.** Measure the shared mechanism's real behaviour (`MULTI_AGENT_ORCHESTRATION.md`
     §7), write down a redesign, and take it to the user before the next fix. This
     extends the retrospective's chain C1 (7 bugs in the navigation guard) into a
     trigger. (from BUG-0141)
  - Enforced by: tests/test_orchestration_guard.py::test_a_fix_that_keeps_spawning_bugs_forces_a_stop

- **PA-0145** — **Every dispatched item has a time budget.** The default is 4 hours of
  wall clock; set it with `--budget-hours` when you know better. Past the budget,
  dispatch for that item stops until the user has seen the overrun and chosen:
  continue, cut scope, or drop it. A user message restarts the budget. (from BUG-0141)
  - Enforced by: tests/test_orchestration_guard.py::test_an_item_over_budget_is_held_and_others_are_not

- **PA-0146** — **Limit concurrent work and keep it apart.**
  1. **At most 3 active items** at a time.
  2. **No two active items change the same file** unless one is declared to follow the
     other (`--after`).
  3. **Checked at both ends.** Declared files are checked at `item add`. The active
     items' real branch diffs (`--branch`/`--base`) are compared at every Stop.

  This makes the harness lane's "no two lanes on one file without a planned merge order"
  (MULTI_AGENT_ORCHESTRATION §1) mechanical. (from BUG-0141)
  - Enforced by: tests/test_orchestration_guard.py::test_wip_limit_and_declared_file_overlap, tests/test_orchestration_guard.py::test_audit_finds_two_active_branches_changing_one_file

- **PA-0147** — **Report from the ledger, and re-ground after every compaction.**
  1. **Lead status answers with the report.** Every answer to a status or progress
     question, and every checkpoint notice, starts with the guard's `report`: metric
     history, last improvement, items, rounds, spawned bugs, triggers. Only then does it
     narrate.
  2. **A summary's pending list is not authorisation.** After a context compaction or
     resume, the "pending tasks / next step" list is a record, not authorisation. Compare
     progress with the goal before the next dispatch; the SessionStart hook prints the
     report for this. (from BUG-0141)
  - Enforced by: tests/test_orchestration_guard.py::test_after_a_compaction_the_session_is_shown_the_goal

- **PA-0148** — **Measure a slow step before you call it inherent; do invariant setup once.**
  1. **Install or probe invariant setup once and reuse it.** This covers anything
     derived only from a pinned input (a locked dependency install, a pinned
     environment, a capability probe). Reuse it under a lock, publish it atomically
     with a completion marker, and key it by everything it depends on. Never repeat it
     per test, per boot or per module.
  2. **Break a step that takes more than a few seconds down by phase** (one real boot,
     timed per subprocess) before anyone accepts it or plans around it. "Live boots are
     slow" was accepted for days; one measurement showed 51.6 s of a 52 s boot was a
     reinstall.
  3. **Keep a cache layer away from the logic its own tests drive.** BUG-0142's first
     attempt cached the probes and broke their tests: cache the availability check,
     not the probe.

  (from BUG-0142)
  - Enforced by: tests/test_live_boot_vendor_cache.py::test_the_harness_never_runs_a_per_boot_install, tests/test_live_boot_vendor_cache.py::test_the_django_harness_never_builds_a_per_boot_environment, tests/test_live_boot_vendor_cache.py::test_each_toolchain_check_runs_once_per_process_and_its_probe_stays_testable, tests/test_live_boot_vendor_cache.py::test_an_interrupted_build_is_rebuilt_not_trusted

- **PA-0149** — **A server is ready only when its own process listens on its port.**
  1. **Prove ownership.** Start servers through `procutil.start_server_on_free_port`,
     or wait with `procutil.wait_until_listening`. A bare connect is never a boot check:
     it also succeeds against another process that holds the port.
  2. **Reproduce a concurrency-only failure before setting it aside.** A failure seen
     only under concurrency or load is either reproduced deterministically, or tied to
     a specific shared resource (a port, a file, a process group). A WATCH note is not
     an outcome, and neither is a re-run.
  3. **"Start and wait for a server" is a shared primitive** (SP-31): one owner, one
     guard.

  This strengthens PA-0130, which checked a server's sockets but accepted their
  absence, and PA-0135. (from BUG-0143)
  - Enforced by: tests/test_server_port_ownership.py::test_every_started_server_is_checked_for_owning_its_port, tests/test_server_port_ownership.py::test_the_guard_catches_a_bare_connect_boot, tests/test_server_port_ownership.py::test_a_port_held_by_another_process_is_never_taken_for_the_server, tests/test_server_port_ownership.py::test_the_go_harness_never_boots_against_another_process, tests/test_loopback_listeners.py::test_a_free_port_launch_is_checked_like_any_other

- **PA-0150** — **Assert exact counts or orders only for actions the test alone performs.**
  When another legitimate actor can act on the same objects (a supervisor, a reaper, a
  server, the kernel), the test does one of two things:
  - it removes that actor, by modelling the function's documented use;
  - or it asserts the outcome (all gone, nothing else touched) instead of the count.

  This strengthens PA-0135 from wall-clock ratios to any scheduling-dependent oracle.
  (from BUG-0144)
  - Enforced by: tests/test_procutil.py::test_kill_process_group_kills_exactly_the_recorded_group

- **PA-0300** — Strengthens `PA-0113` (related: `PA-0067(1)/(3)`, `PA-0020`, `PA-0033`),
  after BUG-0300: ground-truth points doubled an operator sub-path (`…/bWAPP/` +
  `/bWAPP/x.php`). PA-0113(3) asked for a sub-path test of every component taking an
  operator URL, but nothing listed those components, and BUG-0113's sweep cleared
  `points_from_ground_truth` "by contract" with no written contract and no test.
  1. **Every function in `fuzzlab/` that takes an operator base URL is registered** in
     `tests/test_base_url_subpath_registry.py`. Functions are found by AST: a parameter
     whose name ends in `url` with a qualifier `base`/`start`/`target`/`root`/`app`/
     `site`/`entry`, or a bare `base`/`start`/`root` used as a URL. Each entry points
     to a test that drives the function with a sub-path base (checked by AST to exist
     and to contain a sub-path URL), or to a strict xfail naming its bug. A new such
     function without an entry fails, and so does a stale entry. Proven on synthetic
     offenders (`PA-0034(2)`).
  2. **A join states its convention.** A stored or observed path (`to_path`, a
     ground-truth url: the full request path) joins to the base's **origin**. An app's
     own route path (a generated cell's served path) joins to the base's **path**. A
     sweep verdict "by contract" names where the contract is written, or the site
     counts as unswept (`PA-0067(1)`).
  3. **A recurrence in a site a prior sweep cleared re-sweeps every site that sweep
     cleared** (`PA-0067(3)`), recorded in the bug report. (from BUG-0300)
  - Enforced by: tests/test_base_url_subpath_registry.py::test_the_registry_guard_catches_synthetic_offenders, tests/test_base_url_subpath_registry.py::test_identifier_sqli_route_paths_join_the_base_path

- **PA-0301** — Strengthens `PA-0114` and `PA-0022` (related: `PA-0122`), after
  BUG-0301: the destructive rule missed Juice Shop's `/dataerasure` (one token) and
  `GET /rest/user/change-password` (a verb-object pair). PA-0114's from-source
  enumeration found them, but it is a per-adoption check, so the rule had already
  shipped without them. PA-0022's vocabulary check covered collisions (false
  positives), never missed spellings.
  1. **A keyword deny rule is checked against the spellings it was not written for**:
     compound and concatenated tokens (`dataerasure`, `accountdelete`), noun forms of
     its verbs (`erasure`), and credential verb-object pairs in either order
     (`change-password`, `password_change`). This is a test:
     `tests/test_destructive_routes_external_labs.py::test_no_lab_route_hides_a_destructive_word_in_a_compound`
     scans every lab route, and each hit the rule does not refuse needs a written
     disposition. A stale disposition fails. Proven on synthetic offenders
     (`PA-0034(2)`). Stated limit: stems shorter than five letters (`wipe`, `drop`)
     are not scanned inside compounds; such a word is only caught standing alone.
  2. **The PA-0002 sweep for this class runs the rule over every lab's enumerated
     state-changing routes**: the generated labs' manifests and ground truth, and each
     adopted third-party lab's PA-0114 table. Each route the rule does not refuse is
     listed with its compensating control, or as a stated residual.
  3. **A table row records its gate's computed verdict** (`PA-0001`): the URL rule,
     the request/method gate, the body gate, the form gate or the SPA form gate,
     whichever must stop it. A residual's verdict is pinned to None, so the row is
     revisited when a rule starts refusing it. (from BUG-0301)
  - Enforced by: tests/test_destructive_routes_external_labs.py::test_the_generated_labs_state_changing_routes_are_enumerated_and_judged, tests/test_destructive_routes_external_labs.py::test_bug_0301_compensating_controls_hold_meanwhile

- **PA-0310** — Strengthens `PA-0025`, `PA-0059(1)` and `PA-0130` for container
  engines, after BUG-0310. The external labs' loopback checks refused only docker's
  `host` network mode, so podman's `ns:`/`slirp4netns`/`pasta` modes and an external
  network named `host` passed. They also read an engine error as "nothing running /
  nothing exposed".
  1. **A safety check over an external system's state is an allowlist** of the states
     known to be safe, not a list of known-bad ones. It is backed where possible by an
     engine-agnostic fact (for containers: compare the container's network namespace
     with the host's), whatever name the engine gives the mode.
  2. **Every inability to determine the state is a failure**, in the shell and in the
     API. That covers an engine error, a timeout, a missing engine, empty output from a
     failed query and an unexpected result shape. `$(cmd 2>/dev/null)` alone is never
     the answer: its exit status is checked.
  3. **The tests use offenders the check's own list was not written from**: another
     engine's vocabulary, a failing or raising engine, a zero-container answer. Each
     fail-closed branch is mutation-checked.
  4. **The PA-0002 sweep covers every safety check over that system's state**, shell and
     Python, and records any it could not fix in this change. (from BUG-0310)
  - Enforced by: tests/test_external_labs_static.py::test_the_exposure_check_allows_only_project_network_modes, tests/test_external_labs_static.py::test_a_container_in_the_host_netns_is_exposed_whatever_its_mode_says, tests/test_external_labs_static.py::test_check_exposure_fails_closed_on_engine_errors

- **PA-0311** — Strengthens `PA-0013` and carries `PA-0117(1)` to ground-truth labels,
  after BUG-0311. A bWAPP negative was "proven" from the escaped display path while the
  DB error path echoed the value raw. Two live checks could not detect the violation
  they tested for (a session cookie that is never updated; POST bodies in an access
  log), and a status filter listed the values it excluded.
  1. **A ground-truth negative is proven on every path the input reaches output by**,
     error handlers included (DB errors, exceptions, warnings). It is backed by a live
     probe that drives those paths, and its note cites each path checked.
  2. **A live or integration assertion of a premise names the observation that would
     differ if the premise were false, and confirms the observed channel can carry
     it**, with a positive control where one can be sent. An assertion on a channel
     that cannot carry the violation is replaced by one on a channel that can. A
     stand-in condition expected to imply the premise does not count. The predicate
     over the observed channel, control included, is a function unit-tested offline on
     a synthetic sample of that channel before any live run, and an allowlist where
     the system's own comparison is loose. The check is run live before it is called
     done.
  3. **A status or enum filter names the value it means**, imported from its defining
     module (`PA-0001`), never a list of values to exclude. (from BUG-0311)
  - Enforced by: tests/test_external_labs_static.py::test_the_level_log_check_flags_synthetic_offenders, tests/test_external_labs_static.py::test_the_bwapp_image_logs_each_requests_level_cookie

- **PA-0400** — Strengthens `PA-0026` (enumerate an adapter's input shapes) and `PA-0036`
  (never assume a round trip without checking), after BUG-0400: the launcher's argv builder
  inverted argparse for the shapes it had when written and mis-serialised `nargs='*'`,
  `const=""` and dash-leading values that other lanes' parsers added later.
  1. **Code that maps between argv and argparse values for the project's parsers**
     (introspection, serialisation, copying, forwarding) **states its contract as a round
     trip** — parse, build, parse, compare values — **tested over every action of every
     registered parser** (discovered, not listed), so a shape another lane adds later fails it.
  2. **A shape it cannot express fails closed (raises)**; it never emits a different argv.
  3. **Prefer forwarding the user's own argv verbatim** over re-serialising a parsed namespace.
  (from BUG-0400)
  - Enforced by: tests/test_cli_argv_roundtrip.py::test_discovery_reaches_every_registered_parser_and_the_broken_shapes, tests/test_cli_taxonomy.py::test_a_copy_parses_every_action_exactly_like_its_source

- **PA-0401** — Strengthens `PA-0400(3)` (forward verbatim) and `PA-0021` (one derivation
  per convention), after BUG-0401: `train run` printed and checked the resolved store while
  forwarding the user's raw `--store` (with `~`) to an engine that derives the path itself.
  1. **A value a wrapper resolves and acts on** (checks, prints, records) **is forwarded in
     its resolved form, in the position the downstream parser lets win** (last, for
     argparse) -- never the raw text the downstream would derive differently. Every other
     value is still forwarded verbatim.
  2. **Its test parses the forwarded argv with the downstream's own parser** and compares
     that value with the one the wrapper reported, over every spelling the user can give
     (`~`, `..`, `=`, an abbreviation). (from BUG-0401)
  - Enforced by: tests/test_train_cli.py::test_the_engine_opens_exactly_the_store_resolved_and_printed

- **PA-0402** — A test-suite guard that observes the filesystem is bounded to what the suite
  owns, after BUG-0402: the store guard walked the whole invocation cwd and reported tests'
  own temp stores.
  1. **It walks the repository tree only**, never a directory it does not own (the cwd, home,
     the temp area); for those it checks named files, never a walk.
  2. **It excludes the test framework's own scratch area** (pytest's basetemp).
  3. **Its tests run it from a cwd outside the repository and with the basetemp inside the
     walked tree.** (from BUG-0402)
  - Enforced by: tests/test_storepath.py::test_the_store_guard_never_walks_pytests_temp_base_nor_an_outside_cwd, tests/test_storepath.py::test_the_guard_watches_an_outside_cwd_and_excludes_pytests_basetemp

- **PA-0403** — Strengthens `PA-0040` and `PA-0044` (narrowed test sets miss cross-cutting
  checks) from per-trigger rules into a rule about the verification set, after BUG-0403: a
  new module imported `fuzzlab.ml` directly; the import-based list of affected test files
  never contained the path-scanning guard that judges it.
  1. **A change that adds or edits a module under `fuzzlab/` is verified against every
     path-scanning guard test** (tests that discover code by walking `fuzzlab/`/`tests/`:
     `grep -rlE --include="*.py" "rglob|ast.parse\(.*read_text" tests/`), not only the files that import the
     changed modules. An import-based list cannot find a guard that judges a *new* module.
  2. **When the full suite is the backstop, it runs before the push of the commit it
     certifies**, on the clean committed tree. (from BUG-0403)
  - Enforced by: tests/test_verify_change.py::test_a_module_change_selects_its_importers_and_every_guard, tests/test_verify_change.py::test_guards_are_always_selected_even_for_no_package_change

- **PA-0450** — Strengthens `PA-0075` (a provenance claim is backed by a recorded fact)
  from store rows to **file handoffs**, after BUG-0450: `fuzz` imported a previous run's
  CSV as its own attempts because the file existed at the default path.
  1. **A step imports, cites or attributes an artifact to the current run only on a
     fact from its producer that this run wrote it** (a return value, a this-run token
     or record) — never because the path exists.
  2. **A fixed default output path shared by every run in a directory is a provenance
     hazard.** A tool that writes one makes "wrote nothing" visible to its consumer; the
     web UI pins such paths per project (`web.projects.OPTION_CLASS`, FR-UI-456), and a
     new path option must be classified there (a discovery test fails otherwise).
  3. **Each such handoff has a test that runs the producer empty over a pre-existing
     file.** The PA-0002 sweep is by mechanism: every import of a file into the store,
     with a disposition per site (recorded in BUG-0450). (from BUG-0450)
  - Enforced by: tests/test_core_project.py::test_fuzz_never_imports_a_stale_csv_when_its_run_collected_nothing

- **PA-0451** — Strengthens `PA-0028` and `PA-0083(3)`, after BUG-0451: the untrusted
  project-file check was a denylist (`type IN ('trigger','view')`), and a trigger got past
  it twice — by sharing a table's name, then by being typed `TRIGGER`.
  1. **A safety gate over untrusted structured input admits only an allowlist derived from
     what this code itself creates or accepts** — exact identity, and an exact definition
     wherever the object can execute (here `core.project.reference_schema`, built by
     running the migrations). Never a denylist keyed on one field.
  2. **Its tests include the platform's own equivalent spellings** (case, comments, shared
     namespaces, direct schema writes) **and a non-vacuity fixture of every legitimate
     shape** (here fresh, legacy, `ANALYZE`d stores). (from BUG-0451)
  - Enforced by: tests/test_core_project.py::test_a_case_variant_trigger_never_fires_on_open, tests/test_web_projects.py::test_a_case_variant_trigger_never_fires_through_the_ui

- **PA-0452** — Strengthens `PA-0450`, after BUG-0452: tests created the UI's default
  store `./fuzzlab.db` in the repository.
  1. **A built-in default path is never written implicitly.** It counts as the operator's
     choice only if it already exists; otherwise it is offered (the start screen's "Use
     ./fuzzlab.db"), never used.
  2. **A session-wide guard fails any test run that leaves a default output in the working
     directory** (`tests/conftest.py::_no_default_store_in_the_working_directory`); a new
     default output path gets the same guard. The guard compares the default path's state
     (and its side files and project directory) before and after, so it stays armed when
     the file already exists (code review round 3). (from BUG-0452)
  3. **Stated exception:** an explicit operator flag that needs a store before any page
     is opened (`fuzzlab web --with-proxy`) binds and creates the default at start-up
     (`ProjectManager.adopt_default`, FR-UI-458). Any other exception is written here
     first. (code review round 3)
  - Enforced by: none — enforced by the session-wide fixtures `tests/conftest.py::_no_default_store_in_the_working_directory` and `tests/_store_guard.py::default_store_untouched`, which fail any test run that writes a default store (fixtures, not test functions)

- **PA-0453** — Strengthens `PA-0451`, after BUG-0453: the allowlist that replaced
  BUG-0451's denylist exempted tables from definition matching because `trusted_schema=OFF`
  was believed to make them inert; a generated column, `CHECK` or `DEFAULT` ran SQLite's
  own functions without bound on open, listing and migrate.
  1. **An allowlist over untrusted structure compares the full definition of every
     object.** No kind is exempted on the belief that a platform setting makes it inert;
     a claim that a setting protects something is backed by an attack fixture showing the
     protected case blocked and the unprotected case running.
  2. **Nothing of an untrusted structure is read before the definition that computes it is
     validated** (here `schema_version` before its rows), and a version this build cannot
     validate is refused before any other read. (from BUG-0453)
  - Enforced by: tests/test_core_project.py::test_an_allowed_table_with_a_changed_definition_is_refused_before_any_row_is_read

- **PA-0454** — Strengthens `PA-0108` and `PA-0101(2)`, after BUG-0454: a deeply nested or
  oddly typed value in a project file from someone else crashed the project pages.
  1. **Every value read from a store or file that can come from someone else is typed at
     one parser before use**: its storage type checked (SQLite does not enforce a declared
     column type), its size capped, JSON parsed with `RecursionError` handled; an odd value
     reads as missing or malformed — never fabricated, never an exception.
  2. **A fix for one parser-limit crash is swept across every parser of the same input
     source in the same change** (PA-0002 applied at fix time, not later). (from BUG-0454)
  - Enforced by: tests/test_core_project.py::test_deep_json_in_a_project_file_reads_as_malformed, tests/test_core_project.py::test_odd_types_in_a_project_file_are_never_a_crash

- **PA-0455** — Strengthens `PA-0101`, after BUG-0455: the record redactor truncated a
  value before stripping its URL userinfo, so a credential straddling the cut was kept.
  1. **A redactor never applies a lossy transformation (truncation, decoding, splitting)
     before the redaction that depends on the whole value**; bound the work with
     linear-time redaction first and cut last.
  2. **Every bound a redactor introduces is tested with a secret straddling it.** (from
     BUG-0455)
  - Enforced by: tests/test_core_project.py::test_a_credential_straddling_the_record_cut_is_still_removed

- **PA-0456** — Strengthens `PA-0131` and `PA-0453`, after BUG-0456: the definition check
  compared whitespace-normalised text (`str.split()`), and a definition SQLite reads
  differently (a U+00A0 inside an identifier, a moved `--` comment end) compared equal.
  1. **An equality or allowlist check over untrusted input compares the raw form, byte for
     byte,** unless a normalisation is the consumer's own (its tokenizer or parser) — never
     a convenience transform from another grammar.
  2. **Its tests include inputs that differ only in what the consumer treats as
     significant** (non-ASCII spaces, comment boundaries, quoting), each with a
     non-vacuity step proving the consumer reads them differently. (from BUG-0456)
  - Enforced by: tests/test_core_project.py::test_a_definition_that_only_normalises_equal_is_refused

- **PA-0500** — Strengthens `PA-0096` and generalises `PA-0131(2)` and `PA-0108(1)`, after
  BUG-0500: `canonical_origin` promised ``None`` for an unusable URL but raised on a
  malformed authority, and one stored target row took every origin reader down.
  1. **A function whose contract promises a sentinel for unusable input is total**, and
     its tests feed the malformed inputs of every grammar it parses (for a URL: a bad
     IPv6 bracket, an NFKC-invalid netloc, a bad port, a lone surrogate, control
     characters) and assert the sentinel.
  2. **A reader of stored data normalises each stored value through one total boundary**
     (here `core.runtarget.origin_of`): a malformed row reads "unreadable", never takes
     the reader down.
  3. **The PA-0002 sweep lists every caller of the non-total function with a
     disposition**; a known instance not fixed (here in a locked file) is pinned by a
     strict xfail (`PA-0054(3)`). (from BUG-0500)
  - Enforced by: tests/test_core_runtarget.py::test_origin_of_is_total, tests/test_web_sitetree.py::test_a_malformed_stored_base_url_is_an_unreadable_origin_not_a_crash

- **PA-0151** — **No pipe into a reader that can stop early, under `pipefail`.**
  1. **Avoid the pipe.** In a `set -o pipefail` script, never pipe into a reader that may
     exit before EOF (`grep -q`, `grep -m`, `head`, `sed …q`, a checker that may refuse).
     Capture the output, or use a here-string, a single self-quitting tool, or a file.
  2. **Test with a large input.** A test of such a script uses an input larger than a
     pipe buffer.

  Strengthens PA-0059(1), whose `pipefail` made a reader's normal early exit look like
  an error. (from BUG-0145)
  - Enforced by: tests/test_external_labs_extctl.py::test_the_preflight_never_dies_of_sigpipe_when_its_checker_stops_reading

- **PA-0152** — **A shared-contract change names its consumers from the code, and
  integration checks every lane's consumers against it.**
  - A change to a shared contract (a config key's possible values, a return shape, a
    table's reader) lists its consumers in its change-control Impact. Find them by
    searching the key or function across `fuzzlab/`, never from memory or by file.
  - Concurrent lanes are told of the change at dispatch.
  - The merged full suite runs before any push of an integration.

  Strengthens PA-0146, which covers shared files, not shared contracts. (from BUG-0146)
  - Enforced by: tests/test_web_projects.py::test_with_no_project_open_nothing_creates_a_file, tests/test_web_sitetree.py::test_site_tree_routes_are_read_only

- **PA-0153** — Strengthens `PA-0137` (a mechanism's external failure is no verdict) and
  `PA-0138(3)` (sweep a shared primitive across every caller), after BUG-0147: a probe
  that met a connection reset raised out of the oracle and ended the run for every
  target, because PA-0137 was applied to the browser only and never enforced beyond it.
  1. **A probe that gets no complete response is `ProbeUnobserved`,** classified in one
     place (`probesender._unobserved`, SP-34): a reset or abort, a cut-off or
     undecodable body. A refused, DNS, TLS or proxy failure is not one: it fails
     loudly. A timeout keeps its own rule. The oracle makes `ProbeUnobserved` no verdict
     from that mechanism -- never a negative, never the end of the run -- and an
     idempotent probe is re-sent once first. (The mechanism, not the probe, is the
     unit for HTTP: a recorded deviation from PA-0137(4), see BUG-0147.)
  2. **Every sender that issues HTTP itself is listed with its error contract;** an AST
     guard fails on a new one until it is listed and tested.
  3. **Every default mechanism is run against a sender that never answers and a stopped
     out-of-band listener;** none may raise or return a negative. A mechanism added
     later is covered by the same guard.
  4. **A hand-written HTTP response that closes its connection says
     `Connection: close`** in its own head (lab templates and the proxy).
  - Enforced by: tests/test_probe_unobserved.py::test_no_default_mechanism_turns_a_probe_without_response_into_a_negative, tests/test_probe_unobserved.py::test_a_point_with_no_response_never_ends_the_pipeline, tests/test_probe_unobserved.py::test_every_http_sender_maps_a_transport_failure, tests/test_probe_unobserved.py::test_every_hand_written_response_that_closes_says_so
- **PA-0501** — Strengthens `PA-0111(3)` and `PA-0006`, after BUG-0501: the disco
  explorer, validated only on its author's fixture, explored nothing on Juice Shop.
  PA-0111(3) named browser *emulation* only, and its guard covers `core.forms` alone.
  1. **A discovery or exploration mechanism is not reported as working until it has run
     against at least one application its author did not write**, with its own counters
     checked (states, actions, submissions, unrestorable, budget hit), not only its
     findings.
  2. **Every shape that broke it there joins its fixture as a standing test** (here: a
     one-time overlay, a dismissible notice, a hash router, state classes), and the
     fixture is shown to fail on the code before the fix.
  3. **A rule written for one mechanism class is re-read against a new mechanism of a
     neighbouring class** when it is built (explorer vs emulator), not only by name.
     (from BUG-0501)
  - Enforced by: tests/test_disco_e2e.py::test_the_hidden_api_surface_is_reached, tests/test_disco_synth.py::test_state_classes_never_change_a_signature, tests/test_disco_synth.py::test_segments_are_classified_and_slugs_need_siblings

- **PA-0502** — Strengthens `PA-0501(1)` and `PA-0110`, after BUG-0502: the disco
  explorer reported 75 submissions on Juice Shop when 2 forms' values were sent; its
  actions went to a header re-acted in every state. PA-0501(1) was met by reading the
  counters, PA-0110 had never been applied to report counters.
  1. **A discovery mechanism's effect counters count observed effects**, never its own
     intent: a submission is counted when the filled values reached a request, not when
     a submit click ran.
  2. **Each reported counter is reconciled with independent evidence** (the capture, the
     action log) before it is recorded in a change-control entry or reported.
  3. **Element identity carries no context of where the element was seen** (route, URL,
     state), and **markers a mechanism writes into a page are cleared before it reads
     them again**. (from BUG-0502)
  - Enforced by: tests/test_disco_e2e.py::test_a_search_box_is_submitted_by_enter_and_chrome_is_acted_on_once, tests/test_disco_synth.py::test_a_submission_is_sent_only_when_a_distinctive_filled_value_reaches_a_request, tests/test_disco_e2e.py::test_the_hidden_api_surface_is_reached

- **PA-0503** — New axis beside `PA-0112` / `PA-0123` (scope and destructive gates),
  after BUG-0503: the shared link extractor handed both crawlers a POST form's action,
  a ping and script strings as links to GET.
  1. **A source that feeds a crawl queue states its contract: every URL it returns is
     safe to GET**, and returns nothing whose evidence implies a write or an unknown
     method (a submission target, a beacon, a string in a script). Such URLs reach the
     target only through the gated paths that know their method (form submission,
     observed browser requests).
  2. **A coverage benchmark's score never decides a safety question**: a case the
     benchmark rewards that this project's write-safety forbids is left unmet, and the
     score is reported with it. (from BUG-0503)
  - Enforced by: tests/test_linkextract.py::test_a_submission_target_or_a_script_string_is_never_a_link, tests/test_spider_links.py::test_every_linked_resource_is_followed_and_the_gates_still_refuse

- **PA-0504** — Strengthens `PA-0128`, after BUG-0504: browser teardown closed the page
  and unrouted while a navigation the page had just started was paused at
  interception, so a refused URL was requested. PA-0128 was about liveness and its test
  checked call order on fakes.
  1. **A safety guard outlives the work it guards**: a teardown never removes a guard
     (routes, gates) while anything it guards can still be in flight; it adds a refusal
     instead, and lets the in-flight work reach the guard before ending its source.
  2. **Closing is not stopping**: a page (or any source of work) is frozen and drained
     before it is closed; a guarded page is closed only through `navguard.close_pages`.
  3. **A teardown's safety is tested with a refused request started at the moment of
     teardown**, in the real browser, and a race is measured under parallel load before
     it is called fixed. (from BUG-0504)
  - Enforced by: tests/test_navigation_aborts.py::test_a_navigation_started_at_teardown_is_refused_never_sent, tests/test_shared_primitives.py::test_a_guarded_page_is_closed_only_through_close_pages, tests/test_browser_scope.py::test_release_closes_every_page_before_unrouting

- **PA-0505** — Strengthens `PA-0502(3)` and `PA-0041`, after BUG-0505: the disco
  harvest explored Juice Shop a second time under `/sitemap.xml` (a catch-all answered
  with the app's shell) and scored a duplicate finding; and it never loaded a route the
  app's scripts declare, which the spider's scanner finds. PA-0502(3) named element
  identity only; PA-0041 named sender transport settings only and was not enforced.
  1. **A discovery mechanism identifies what it has seen by its content, never by the
     address it was reached at**: the same document under two addresses is one
     document unless it renders differently there (a history-mode route).
  2. **Two tools that discover the same surface share each kind of evidence's
     mechanism** (one owner in `docs/SHARED_PRIMITIVES.md`); a mechanism one has and
     the other lacks is added to the other in the same change or recorded as a known
     gap in its requirements. (from BUG-0505)
  - Enforced by: tests/test_disco_harvest.py::test_the_shell_under_another_path_of_a_hash_routed_app_is_an_alias, tests/test_disco_harvest.py::test_a_history_mode_route_from_the_same_shell_is_explored, tests/test_disco_harvest.py::test_both_crawlers_read_an_apps_routes_through_the_one_scanner, tests/test_disco_e2e.py::test_a_catch_all_document_is_an_alias_never_a_second_app, tests/test_disco_e2e.py::test_a_route_only_the_script_declares_is_loaded_with_its_query

- **PA-0506** — Extends `PA-0503`, after BUG-0506: with SPA form submission off (the
  safe default), the spider never saw a form's request, so Juice Shop's login SQL
  injection had no point; the reveal window blocked writes and discarded their shape.
  1. **A safety gate withholds an action's effect, not its discovery**: where a
     request's shape can be learnt without sending it (blocked in the browser and
     recorded), discovery does so by default; a gate that discards what it blocked is a
     defect.
  2. **A dry action leaves no trace**: nothing reaches the server, client state the
     app's own code changed during it is rolled back before the crawl goes on, and a
     session-bearing context is checked after it (fail closed). (from BUG-0506)
  - Enforced by: tests/test_spa_capture.py::test_dry_submission_records_each_forms_write_and_sends_nothing, tests/test_spa_capture.py::test_dry_submission_keeps_an_authenticated_crawls_session, tests/test_forms_phase4.py::test_a_write_the_reveal_window_blocks_is_recorded_never_sent

- **PA-0507** — Strengthens `PA-0501(1)` and `PA-0505(2)`, after BUG-0507: the path
  variation rule took Juice Shop's sibling API routes and a directory's files for
  parameters -- the defect `disco.synth` had fixed a day earlier (BUG-0501) -- because
  it was written as a second implementation of that decision and measured only on an
  app without sibling routes.
  1. **A rule that classifies names the evidence that separates its confusable
     alternative** (route or value, file or value), and is measured on an application
     where that alternative occurs before it ships.
  2. **Before a mechanism is registered as a new shared primitive, the codebase is
     searched for an existing implementation of the same decision** (docstrings, bug
     records); one found becomes the owner, or both decide through one owner, in the
     same change. (from BUG-0507)
  - Enforced by: tests/test_path_discovery.py::test_routes_the_code_names_are_not_values_and_placeholders_are_parameters, tests/test_path_discovery.py::test_the_streaming_values_are_data_its_code_never_names, tests/test_path_discovery.py::test_every_path_templating_rule_decides_variation_through_the_one_owner

- **PA-0509** — After BUG-0509: `LocalSpider._clone` copied the first worker's
  `__dict__` after its browser had started, including Playwright's cached
  bound-method listener wrappers, so every other worker's page events reached the
  first worker's handlers.
  1. **An object copied to make another worker copies only state the code owns.** A
     clone made by copying `__dict__` after the original was handed to a library (as a
     listener, route or callback) drops the library's per-object attributes.
  2. **A multi-worker test judges each worker's events by what that worker recorded
     itself** (PA-0511). (from BUG-0509)
  - Enforced by: tests/test_spider_trace.py::test_a_cloned_worker_never_inherits_playwrights_cached_listeners, tests/test_spider_trace.py::test_each_workers_page_events_reach_that_worker

- **PA-0510** — Strengthens `PA-0078` (no count reconstructed from parameters that also
  encode something else) from displayed counts to every evidence record, after
  BUG-0510: the trace took a PRG follow-up's observation for its send, and a run
  counter for an exchange's re-sends. Related: `PA-0083(1)`.
  1. **Evidence of an action is recorded where the action happens, by the code that
     performs it.** It is never reconstructed from a field that summarises the action's
     result for another consumer (an observation, a verdict input, a run counter). If
     the code performing the action keeps no such record, add one there; do not infer
     it.
  2. **An evidence producer is tested against an independent count of the actions**:
     the requests a loopback server received equal the recorded tries, end to end
     through the real pipeline, with a case for each way an action can miss its usual
     result (a re-send, a redirect that is no observation, no response). (from BUG-0510)
  - Enforced by: tests/test_trace_attempts.py::test_run_auto_records_every_try_and_changes_no_count_or_verdict, tests/test_trace_attempts.py::test_a_follow_up_that_was_no_observation_is_still_recorded, tests/test_trace_attempts.py::test_a_follow_ups_retry_is_parented_to_the_follow_up

- **PA-0511** — Strengthens `PA-0150`, after BUG-0511: two failed-load tests asserted
  that the server logged no tick after the fallback's request. Under load, ticks sent
  seconds before the mark arrived after it, and the auditor's test failed on correct
  code. PA-0150 covered exact counts, was enforced only by the test it fixed, and its
  sweep did not reach request order.
  1. **An absence claim about a concurrent actor is judged by a stamp the actor gave the
     event when it acted** (its clock, or a sequence it assigned), never by where an
     observer's log received it. Arrival order is send order only when nothing delays
     delivery.
  2. **The new oracle is proven on the defect it guards** (`PA-0034(2)`): here, with the
     document left alive. (from BUG-0511)
  - Enforced by: tests/test_no_arrival_order_oracle.py::test_no_test_judges_a_concurrent_actor_by_arrival_after_a_mark, tests/test_no_arrival_order_oracle.py::test_the_guard_catches_bug_0511_and_each_synthetic_offender, tests/test_navigation_aborts.py::test_the_send_time_oracle_sees_a_document_left_alive

- **PA-0512** — Strengthens `PA-0510(1)`, after BUG-0512: the disco importer composed an
  action's workflow id from its number and an assumed prefix, while disco names actions
  `act-`, `nav-` or `harvest-`. PA-0510's sweep listed the importer by event, not by
  each field it derives.
  1. **A correlation id or key is copied from what the producer wrote, never composed by
     the consumer.** When the producer does not write it, it is made to.
  2. **The test covers every id form the producer makes**, and that each correlated
     item shares its scope with what it correlates. (from BUG-0512)
  - Enforced by: tests/test_diagram_e2e.py::test_a_capture_gives_origins_auth_contexts_workflows_and_external_refs

- **PA-0513** — Strengthens `PA-0510(2)`, after BUG-0513: "every send" was instrumented
  at the run's own sender only; the cross-account check's peer and unauthenticated
  senders were never traced.
  1. **An "every X" instrumentation claim is verified against an independent count on a
     run that exercises every configuration creating an X.** (from BUG-0513)
  - Enforced by: tests/test_cross_account.py::test_run_auto_traces_the_peer_and_unauthenticated_replays

- **PA-0514** — Strengthens `PA-0507(2)` and `PA-0100`, after BUG-0514: the trace's URL
  redactor was chosen by analogy (the crawler's, query values only) while the project's
  record boundary already stripped userinfo, matrix parameters and token fragments.
  1. **A new sink of target-derived text uses the strongest existing redactor for each
     kind of value it stores** (searched for, not chosen by analogy).
  2. **It is tested against the full list of token shapes**: userinfo, a matrix
     parameter, a query-shaped fragment, a path token, a relative URL. (from BUG-0514)
  - Enforced by: tests/test_trace_model.py::test_safe_ref_withholds_every_token_shape, tests/test_trace_model.py::test_scrub_event_passes_relative_urls_under_url_keys

- **PA-0515** — After BUG-0515: the diagrams drew a failed load as a reply, blocked
  requests and spider loads as browser traffic, refused hosts as solid flows, groupings
  as observed, and counted other sends as executed.
  1. **Every drawn element and count names the event field that supports it.**
  2. **Each view has a negative fixture for each kind of non-traffic it can receive**
     (failed, blocked, refused, grouped, not a test's own send). (from BUG-0515)
  - Enforced by: tests/test_diagram_e2e.py::test_a_failed_spider_load_is_drawn_lost_never_as_a_reply, tests/test_diagram_e2e.py::test_the_data_flow_shows_the_application_and_keeps_testing_separate, tests/test_trace_model.py::test_executed_counts_a_tests_own_sends_on_its_interface

- **PA-0516** — After BUG-0516: the reducer's kind and capped attributes depended on event
  order, and the recorder's counters were written only at close.
  1. **An order- or batching-independence claim is tested on permutations and batch
     sizes that cross every boundary the code has** (a cap, a conflict, a flush), and
     against a rebuild.
  2. **A health counter the spec asks to expose is written while the run is live.**
     (from BUG-0516)
  - Enforced by: tests/test_trace_model.py::test_kind_and_capped_attributes_do_not_depend_on_order, tests/test_trace_model.py::test_the_counters_are_written_while_the_run_is_live

- **PA-0517** — After BUG-0517: the trace's `location` key held both where a value was
  injected and a response's redirect target.
  1. **An event body key has one meaning across every producer**; a new field is checked
     against the existing keys before it is named. (from BUG-0517)
  - Enforced by: tests/test_diagram_e2e.py::test_a_redirect_is_shown_with_its_target

- **PA-0518** — After BUG-0518: the diagrams page's origin list was built once from a
  filtered model, the application box had no evidence link, and a malformed scope gave
  a 500.
  1. **A UI requirement stated for every element or for "a change" is tested on each
     kind of element and on a change after the first load.**
  2. **A route's parameter that the view parses is validated in the view and refused
     with 400.** (from BUG-0518)
  - Enforced by: tests/test_web_diagrams.py::test_the_page_renders_labels_as_text_navigates_evidence_and_updates_live, tests/test_web_diagrams.py::test_exports_download_and_bad_requests_are_refused

- **PA-0519** — Strengthens `PA-0510(1)` and `PA-0512` from evidence producers and ids to
  every view reading the model, and widens `PA-0515`'s sweep, after BUG-0519: the data
  flow's finding filter re-derived "what finding F cites" from the capped `attrs.finding`
  and a fixed actor list, and disagreed with `finding_links` (the spider's flows after
  BUG-0515 split its actor; every finding past the 40th on an interface).
  1. **A view or filter takes a relation from the record that defines it** (the
     producer's event, or the model's links), never from a capped or summary attribute
     and never from an enumerated list of kinds or ids; a count shown to the operator
     comes from an exact source, never a capped attribute's length.
  2. **Two functions that derive one relation are held equal by a test on every record**
     of a real run and of a fixture past every cap (`PA-0516(1)`).
  3. **A change that adds or splits an entity kind or actor sweeps every enumeration of
     kinds or ids** in `report/diagram.py` and `static/js/diagrams.js`, filters and
     keep-sets included, not only drawn output. (from BUG-0519)
  - Enforced by: tests/test_diagram_e2e.py::test_the_finding_filter_draws_exactly_the_flows_finding_links_names, tests/test_diagram_e2e.py::test_a_finding_past_the_attribute_cap_keeps_its_interface_and_flows, tests/test_web_diagrams.py::test_the_page_never_counts_a_capped_attribute

- **PA-0520** — Strengthens `PA-0513`, after BUG-0520: the M6 browser's store and page
  requests reach the target through the Playwright driver and Chromium, never a sender,
  while the diagrams said M6 recorded its sends. PA-0513's sweep and count covered sender
  objects only, and nothing tied the count to the run's sending keywords.
  1. **A send is anything that makes the target receive a request on the tool's behalf**
     (a probe sender, the browser's route fetches, its API request context, Chromium
     itself). An "every send" claim is swept and counted by what the target receives, not
     by which objects send.
  2. **The independent count runs every sending keyword of the run's entry point
     (`run_auto`)**, and a guard classifies every parameter, checks each wrapped one is
     wrapped on every branch, and fails on an unclassified new keyword.
  3. **A step seen in a callback is recorded from the producer's own context**, with the
     callback's stamp; never emitted from a callback whose execution context is not
     established. (from BUG-0520)
  - Enforced by: tests/test_confirm_trace.py::test_every_send_of_a_run_is_counted_by_the_server, tests/test_confirm_trace.py::test_the_count_test_covers_every_sending_keyword_of_run_auto, tests/test_confirm_trace.py::test_the_keyword_guard_catches_a_synthetic_new_keyword, tests/test_confirm_trace.py::test_an_m6_visit_records_each_step_where_it_happens

- **PA-0521** — Strengthens `PA-0514(2)`, after BUG-0521: the trace's URL redactor judged a
  path segment whole, so a canary token followed by `)` or a backtick in a payload's
  preview was kept.
  1. **The token-shape list includes each shape embedded in text**, followed by the
     punctuation the tool's own payloads use; a redactor that judges whole segments also
     judges the identifier runs inside them. (from BUG-0521)
  - Enforced by: tests/test_trace_model.py::test_a_payload_preview_never_keeps_its_canary_token, tests/test_trace_model.py::test_safe_ref_withholds_every_token_shape

- **PA-0524** — Strengthens `PA-0513` and `PA-0520` from sends to every kind of evidence,
  after BUG-0524: refused hosts were read from the capture proxy only, while the browser
  guard, an earlier layer, refused every out-of-scope request first. PA-0513/0520 count
  sends by what the target receives; a refusal never reaches the target.
  1. **An observation claim ("every refused host", "every request the browser made")
     names each layer that can produce the observation, and its consumer reads all of
     them.**
  2. **It is tested against an independent count from each layer on a real run where an
     earlier layer acts first.** (from BUG-0524)
  - Enforced by: tests/test_disco_livetrace.py::test_a_real_capture_is_in_the_store_while_it_runs_and_unchanged, tests/test_disco_livetrace.py::test_both_refusal_layers_are_traced_under_their_own_keys

- **PA-0525** — Strengthens `PA-0450(1)` and `(3)`, after BUG-0525: `disco capture`
  refused an `--out` holding `capture.jsonl` only; the explorer appends to `actions.jsonl`
  and the importer reads four more files as the run's.
  1. **A producer whose output is several files a consumer reads as one run refuses an
     output location holding any of them, before any side effect** (a dry run included).
  2. **The list is one constant, and a test fails when a consumer reads a run file not in
     it.** (from BUG-0525)
  - Enforced by: tests/test_disco_cli.py::test_capture_refuses_a_directory_holding_any_file_the_trace_reads, tests/test_disco_cli.py::test_every_file_the_import_and_the_trace_read_is_refused_when_stale

- **PA-0526** — Strengthens `PA-0135(1)`, after BUG-0526: four tests bounded a whole
  browser-driven run (6.5-9.5 s) to show a step was not waited out; under the harness's
  load the Playwright driver's start alone took 4.5-7 s. PA-0135's guard caught ratios
  only.
  1. **A test that bounds how long a step takes times that step at its own call** (a
     wrapper on the step), never a span that also holds a process, driver or browser
     start; such a span keeps only a smoke bound of 30 s or more.
  2. **The step oracle is proven against the exact original defect** it guards
     (PA-0034(2)), not a look-alike. (from BUG-0526)
  - Enforced by: tests/test_no_startup_timing.py::test_no_test_bounds_a_span_that_holds_a_browser_start, tests/test_no_startup_timing.py::test_the_guard_catches_bug_0526_and_allows_a_step_or_a_smoke_bound
- **PA-0523** — Strengthens `PA-0115(1)` and `PA-0137(1)`, after BUG-0523: the browser
  executor returned its placement refusal as "not executed", which its only reader took as
  an observation, and the oracle let a mechanism that does not address a candidate make it
  a negative. PA-0115(1) allowed "raises or gives no verdict" and was checked at the
  producer; PA-0126(3)/PA-0137(1) mapped the browser's failures, not its refusals, and
  never checked the candidate's final status.
  1. **A refusal is raised, never returned as an observation;** "no verdict" is checked at
     the consumer, by the candidate's final status, not at the producer.
  2. **A candidate built for one mechanism is decided only by it, within its own
     category** (FR-AUD-30): another mechanism's placement may confirm it but never makes
     it a negative, and a strategy without an arm decides no such candidate. (from
     BUG-0523)
  - Enforced by: tests/test_unplaceable_confirmation.py::test_no_executor_returns_an_observation_for_a_refusal, tests/test_unplaceable_confirmation.py::test_run_auto_records_an_unplaceable_store_as_inconclusive_never_a_negative, tests/test_unplaceable_confirmation.py::test_a_stored_candidate_is_decided_only_by_the_mechanism_that_plants_it, tests/test_unplaceable_confirmation.py::test_decided_by_reaches_only_the_deciding_category, tests/test_unplaceable_confirmation.py::test_a_strategy_without_an_arm_decides_only_a_candidate_with_no_decider
- **PA-0522** — Strengthens `PA-0136(3)` and `PA-0138(3)`, after BUG-0522: a failed load's
  error page arrives late (Chromium commits it after `goto` has raised) and overtook the
  next navigation of every guarded browser. X1's cleanup had been proven against a refused
  load only, and the fix's first draft judged "the error page has come" by the page's
  current URL, so it missed consecutive failures.
  1. **A failed navigation is over only when the browser has finished what the failure
     starts**, judged by events seen since the navigation started, never by current
     state: SP-01 waits, bounded, with every expiry counted and logged, for the error page
     a network error starts and, when the navigation was overtaken by such a page, the
     overtaken navigation's late commit.
  2. **How a failed load ends its document is decided once** (`navguard.end_failed_load`,
     SP-01): no `about:blank` is navigated by hand in an `except` or `finally`, and any
     other `about:blank` navigation outside navguard is allow-listed by module and
     function, with its reason.
  3. **A cleanup that navigates is measured against every way the step before it can
     fail**, several in a row and mixed orders included; a suppressed navigation error is
     not "done" (a navigation reported as interrupted can still commit).
  4. **Classification reads only what the browser wrote** (the leading code, or the
     end-anchored error-page URL), never target-controlled text (PA-0022).
  - The guard's limits: it sees only a literal `"about:blank"` passed positionally or as
    `url=` to `navigate`/`goto`; not another spelling, a navigation by script
    (`page.evaluate`), `set_content`, or a new function given an allow-listed name in an
    allow-listed module. (from BUG-0522)
  - Enforced by: tests/test_shared_primitives.py::test_every_about_blank_navigation_is_a_reasoned_exception, tests/test_shared_primitives.py::test_the_about_blank_guard_catches_synthetic_offenders, tests/test_navigation_aborts.py::test_a_failed_navigation_returns_after_its_own_error_page, tests/test_navigation_aborts.py::test_only_the_leading_code_decides_a_wait_for_an_error_page
- **PA-0531** — Strengthens `PA-0115(2)`/`(3)` and `PA-0111`, after BUG-0531: each sender
  placed a query value its own way (an appended second pair; a `dict` rebuild that lost
  duplicates and rewrote siblings), and PA-0115's conformance check read the query as a
  `dict` on a query-less URL, so it could not see an occurrence.
  1. **A value placed in a URL's query goes through the one owner** (`core.urls`, SP-42):
     `place_query_param` for a standalone URL, `bind_query` for bound entries,
     `place_route_query_param` for an SPA hash route. An AST guard over `fuzzlab/` (the
     owner excluded) flags: `params` reaching a send (a keyword; a positional; a
     `"params"` key or `dict(params=…)` passed as `**`, directly or through a local;
     `.update`/`.setdefault` adding it to such a local); a subscript store into
     `"params"`; `dict(parse_qsl/parse_qs)` and `parse_qs`; a string build (`+`, `%`,
     `+=`, f-string, `.format`) holding a `?`/`&` constant and query material (a quoter,
     `.query`, `"&".join`, or a local name the same scope assigned from one), or holding
     a `[?&]name=` constant; `"&".join`/`"?".join`; `._replace(query=…|fragment=…)`;
     `SplitResult`/`ParseResult(...)`; a tuple `urlunsplit`/`urlunparse` rebuilding the
     query or fragment. Every finding outside the owner is on an allow-list with its
     count and its reason, compared exactly (a new builder and a stale entry both fail).
     The guard is proven on 50 synthetic offenders and 10 near-misses.
  2. **A placement check observes the raw request through the real client's own URL
     preparation, never a parsed `dict`,** on a probe URL that already carries the name,
     a missing `=`, an empty part and a raw escape. Senders that share a client are
     compared byte for byte, and the check is shown to fail on an appending and on a
     collapsing sender.
  3. **Senders on different clients (Chromium against `requests`) are compared under a
     relation measured on the real clients,** pinned by a real-browser test that fails
     when a client's rewriting changes, and proven not vacuous on pairs a server reads
     apart.
  4. **A known unfixed instance in another item's code is pinned in the same change by an
     offline strict xfail naming its owner** (`PA-0054(3)`), never a prose deferral.
  - The guard's limits: it does not see query material reaching a build through a
    parameter, an attribute or another function's name; a separator held in a variable,
    or a `"".join([...])` build; a `params` dict reaching `**` through an attribute or
    another function; session-level `Session.params`; or a new function given an
    allow-listed name in an allow-listed module. (from BUG-0531)
  - Enforced by: tests/test_query_placement.py::test_every_query_builder_goes_through_the_one_owner, tests/test_query_placement.py::test_the_query_builder_allow_list_has_no_stale_entry, tests/test_query_placement.py::test_the_query_builder_guard_catches_synthetic_offenders, tests/test_sender_conformance.py::test_every_sender_places_a_query_occurrence_in_place, tests/test_sender_conformance.py::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender, tests/test_query_placement.py::test_platform_clients_rewrite_only_escapes_they_disagree_on, tests/test_query_placement.py::test_the_equivalence_still_tells_apart_what_a_server_reads_apart
- **PA-0528** — Strengthens `PA-0025`, `PA-0311(2)` and `PA-0153`, after BUG-0528: the contract runner passed a cut, stalled or late 200, admitted it as the endpoint's baseline, and ignored state assertions it could not evaluate. An outcome that claims something held (a pass, a satisfied assertion, a baseline, a setup success) rests only on observations that were complete and evaluated.
  1. **An exchange is complete only when its status, its headers and its whole body arrived within its limits.** An incomplete one is judged only by what its incompleteness proves (a **read** timeout proves latency of at least the limit; a connect timeout proves nothing). It is never written to evidence, and the response is closed on every exit.
  2. **Every assertion is three-valued, with its reason.** A pass needs every mandatory one satisfied. Each unobserved branch has a fixture whose body would *satisfy* the assertion.
  3. **A new judge or oracle is built against (1) and (2),** with fixtures for a cut, stalled, late and connect-timed-out answer and an unobservable assertion. Not enforced by a test: a judge that does not exist yet has no stable shape to discover (verdict vocabularies differ: `pass`, `confirmed_secure`, `CHECKED`); it is applied in review. The line below enforces (1) and (2). (from BUG-0528)
  - Enforced by: tests/test_disco_runner_outcomes.py::test_an_incomplete_200_is_never_a_pass_nor_the_endpoints_baseline, tests/test_disco_runner_outcomes.py::test_an_unobserved_state_check_is_never_a_pass, tests/test_disco_runner_outcomes.py::test_every_state_check_must_be_evaluated_for_a_pass, tests/test_disco_runner_outcomes.py::test_the_response_is_closed_on_every_exit, tests/test_disco_runner_outcomes.py::test_an_incomplete_body_is_never_written_to_evidence, tests/test_disco_runner_outcomes.py::test_a_connect_timeout_never_proves_latency, tests/test_disco_runner_outcomes.py::test_a_real_200_cut_or_stalled_after_its_headers_is_an_error
- **PA-0529** — Strengthens `PA-0117(1)/(3)` and `PA-0137(4)`, and applies `PA-0507(2)`, after BUG-0529: a throttled, refused, blocked or gateway answer to a control, baseline, compared slot or replay confirmed findings or made negatives. A control, a baseline sample, a compared slot or a replay is evidence only when it is the application's own answer, decided by one classification (SP-56) from the answer and SP-16's credential and login facts.
  1. **Each strategy declares the classes each role admits,** with its reason. Any other answer gives no verdict: inconclusive, never a confirmation and never a negative.
  2. **Every response a mechanism reads is an observation or ends it:** a throttle or unavailable answer, an incomplete non-timing send, or a non-read timing timeout. A payload whose follow-up got no observation keeps its own response; a run that then decides nothing is inconclusive. A control's unobserved follow-up ends the mechanism only where the strategy needs it observed alike.
  3. **A request that submits a credential is never read as a session loss.** The credential a probe carried is a per-probe fact; an unknown one counts as carried.
  4. **Enforced by discovery:** every default strategy is classified; every send of a control reader is compared or is a declared literal mutation (AST, proven on a revert of `_compared`, an untagged control and a non-literal role); no status classification exists outside the owner but a reviewed allowance list. (from BUG-0529)
  - Enforced by: tests/test_oracle_comparable_controls.py::test_a_signature_absent_from_a_control_that_is_not_the_applications_never_confirms, tests/test_oracle_comparable_controls.py::test_a_differential_whose_baseline_and_variant_are_not_the_applications_never_confirms, tests/test_oracle_comparable_controls.py::test_a_credential_submissions_own_refusal_is_its_answer_and_still_confirms, tests/test_oracle_comparable_controls.py::test_every_default_strategy_says_how_it_reads_controls, tests/test_oracle_comparable_controls.py::test_every_send_of_a_control_reader_is_compared_or_a_declared_mutation, tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner, tests/test_disco_runner_outcomes.py::test_a_throttled_answer_is_never_judged_by_its_status_class
- **PA-0532** — Strengthens `PA-0020` and `PA-0033` for one rule, and supersedes the prose-only "one pytest at a time" (CLAUDE.md step 2, MULTI_AGENT_ORCHESTRATION §2), after BUG-0532. Only `scripts/verify_change.py` enforced that rule, with its own lock and a one-sided quiet-host check. Every ad-hoc pytest relied on an agent re-implementing a check-then-start from prose, and seven overlapped other runs in two days (F-092..F-104).
  1. **The session enforces it.** Every pytest session of `tests/` takes the host pytest lock (`tests/_pytest_lock.py`, `/tmp/fuzzlab-pytest.lock`) in the root conftest's `pytest_configure`, before anything else. It waits for the lock or refuses (exit 4, nothing run); a guard keeps that hook first. xdist workers (`config.workerinput`) skip the lock, and so do nested sessions that carry the holder's token, with the holder in their ancestry and confirmed as the kernel's holder.
  2. **A rule about how processes may run is enforced where every such process passes**, as a lock the process itself takes. It is not enforced by one tool that starts some of them, nor by a check-then-start in prose or a dispatch.
  3. **A process that starts a nested pytest passes its environment on.** A holder's descendant without the holder's token fails at once instead of deadlocking.
  4. **No routine bypass.** There is no off switch, and `FUZZLAB_PYTEST_LOCK_PATH` is honoured only inside a locked session (the lock's own tests). (from BUG-0532)
  - Enforced by: tests/test_pytest_lock_wiring.py::test_the_root_conftest_takes_the_lock_first, tests/test_pytest_lock_wiring.py::test_the_wiring_guard_catches_each_synthetic_offender, tests/test_pytest_lock_wiring.py::test_this_session_ran_the_hook, tests/test_pytest_lock.py::test_a_second_session_waits_for_the_first_and_then_runs, tests/test_pytest_lock.py::test_a_session_refuses_after_its_wait_and_runs_nothing, tests/test_pytest_lock.py::test_xdist_takes_the_lock_once_and_its_workers_skip_it, tests/test_pytest_lock.py::test_a_nested_session_with_the_holders_token_runs, tests/test_pytest_lock.py::test_a_holders_descendant_without_its_token_fails_at_once, tests/test_pytest_lock.py::test_a_token_without_ancestry_does_not_bypass_the_lock, tests/test_pytest_lock.py::test_a_private_lock_path_is_refused_outside_a_locked_session, tests/test_verify_change.py::test_the_child_pytest_waits_for_the_pytest_lock_as_long_as_the_run
- **PA-0537** — Strengthens `PA-0532`, after BUG-0537: `verify_change.py` kept its "zero other pytest processes" precondition after every session started queueing on the host pytest lock, so with agents queueing it starved and nothing could be verified.
  1. **When a serialisation mechanism replaces another, every tool that carried the old one drops it** (sweep by mechanism, PA-0002): a precondition that the new mechanism makes permanently false is a starvation bug, not extra safety. (from BUG-0537)
  - Enforced by: tests/test_verify_change.py::test_a_tree_whose_conftest_takes_the_pytest_lock_never_waits_for_a_quiet_host
- **PA-0536** — Strengthens `PA-0102`, `PA-0086(1)` and `PA-0096(1)`/`PA-0454(1)`, and closes `PA-0528`'s residual R6 for body bytes, after BUG-0536. Three reads of untrusted input checked their bound on the finished artefact, or never: a target body read whole (a `requests` timeout taken for a deadline, and cleared on that premise by BUG-0101's sweep), a JSONL line capped at its parser after the reader had buffered it, and a contract regex validated by compiling it and then run without bound. **A bound on untrusted input is enforced inside the loop that does the work** (each receive, each buffered chunk, each match), never only on the finished body, line or pattern.
  1. **Reading a target's HTTP body has one owner** (SP-60, `core.bodyread`).
     - It has a wire and a decoded ceiling, decodes incrementally under the ceiling, and checks a wall-clock deadline at every receive.
     - One watchdog holds that deadline where a library reads in one call (status line, headers, chunk lines) by shutting the socket.
     - Its requests advertise only the codings it can decode under its ceiling.
     - It returns a typed incomplete marker that no consumer takes for a body; SP-34 makes it "not observed".
     - **Every consumer keeps the marker typed.** A stand-in that only looks like a response (status 0, error text as its body) is not a type. No consumer scores, records, accepts or adopts as a baseline what the marker names.
     - Every `requests` session fuzzlab makes is bounded where it is made. An AST guard fails on a new unbounded `requests.Session()` or module-level `requests.<verb>()` outside a reasoned list, and is proven on synthetic offenders (`PA-0034(2)`).
  2. **A timeout argument is not a deadline.** A sweep verdict that a read is bounded in time cites a test against a dripping peer, never the presence of a timeout.
  3. **A line or record cap is enforced by the reader that buffers**, as soon as its buffer passes the cap. Accumulation is linear, with an exposed copy count (`PA-0135(2)`), and the count's oracle is proven on the quadratic form (`PA-0135(3)`).
  4. **A pattern from a contract, a generator or a target runs on target text only under a time bound that can stop it**: a killable worker, never a thread. A timeout is inconclusive, never a no-match. Compiling a pattern validates its syntax, not its cost.
  (from BUG-0536)
  - Enforced by: tests/test_bounded_reads.py::test_every_requests_session_fuzzlab_makes_is_bounded, tests/test_bounded_reads.py::test_the_session_guard_catches_synthetic_offenders, tests/test_bounded_reads.py::test_a_dripped_body_is_cut_at_its_deadline_and_never_taken_whole, tests/test_bounded_reads.py::test_a_gzip_bomb_stops_at_the_decoded_ceiling_and_is_never_taken_whole, tests/test_bounded_reads.py::test_an_unterminated_line_over_the_cap_is_quarantined_once_and_never_held, tests/test_bounded_reads.py::test_reading_a_long_line_in_small_pieces_copies_each_byte_a_bounded_number_of_times, tests/test_bounded_reads.py::test_the_copy_oracle_flags_a_quadratic_tail, tests/test_bounded_reads.py::test_a_catastrophic_pattern_is_an_error_never_a_hang_nor_a_no_match, tests/test_bounded_reads.py::test_the_matcher_never_runs_a_contract_pattern_in_the_runners_process, tests/test_bounded_reads.py::test_a_dripped_status_line_and_headers_are_cut_at_the_deadline, tests/test_bounded_reads.py::test_a_bounded_send_advertises_only_codings_it_can_bound, tests/test_bounded_reads.py::test_greybox_never_scores_records_or_adopts_an_incomplete_probe
- **PA-0541** — Strengthens `PA-0141`, `PA-0142`, `PA-0145` and `PA-0532`, after BUG-0541: the audit stalled 19 hours while every lane was busy: design gates before code, one audit item in work, and a serialised test host spent on per-item proof runs and unordered merges.
  1. **A defect with a concrete reproduction is implemented first**: the failing test, then the fix, then one implementation review (two only for sessions, the oracle, redaction or the store). A design draft or pre-change review is for a change to a store or wire contract, or on the owner's request.
  2. **A lane's test budget is fixed**: targeted test files first (one invocation); each new test proven once on the pre-fix code; then one harness run with `--base` at the lane's last green commit. Revert matrices and mutant suites only for a shared primitive's guard. A run already past its wait is never stopped.
  3. **Merges are planned around the one test host**: each lane's verified commit is pushed as soon as it is green, in an order that puts a suite-wide change (one that makes the harness select the whole suite) last, so that one full run serves it.
  4. **Slots carry the metric**: at most one of three concurrent items is work that does not move the owner's metric, and an eligible queued item is dispatched the moment a slot frees.
  5. **A gate is weighed against the goal's clock**: when an item passes its budget or review cap, the orchestrator stops sending it rounds and tells the owner the cost so far and the options (ship with residuals, narrow, drop), the same turn the trigger fires.
  - Enforced by: none — orchestration behaviour, not code; its check is the guard's stall, budget and review-cap triggers (`scripts/orchestration_guard.py report`, PA-0141..PA-0147) read at every checkpoint.
- **PA-0533** — Strengthens `PA-0007`, `PA-0113`, `PA-0122`, `PA-0134` and `PA-0529(3)`,
  after BUG-0533: a 403 logged the session in again. Each earlier rule constrained one
  signal, one reader or one send path; none constrained the state change, and PA-0134 bound
  a session's evidence to its origin only.
  1. **An identity's state changes only on evidence about that session.** SP-56
     classifies first: a throttle, gateway, 407 or incomplete answer never changes it, and
     is never recorded or matched as a resource's refusal. A loss shape, a credentialed
     policy block or a submission's loss shape triggers a check of the session's stable
     protected resource, and the resource's answer decides. Without a resource, only a
     non-submission loss shape counts, as an unconfirmed loss.
  2. **Evidence is bound to the session it is about:** to its origins (PA-0134), to its
     generation and the state object judged, and to the time it was taken (a verdict
     covers only the signals seen before its request was sent). Every write
     compare-and-sets on the current state and that generation, and is atomic with every
     install: the invalidation's row and every install's row are written under one lock.
  3. **Re-logins draw on a refilling budget.** With it spent, an identity with a resource
     waits within its bounds or goes sticky unknown; an identity without one carries on at
     once, never sleeping or aborting. An unknown identity pauses, then goes sticky; it
     never logs in or out on an inconclusive check.
  4. **Enforced at the actor.** `_mark_lost` is the only writer of `valid = False`, and
     `detect_logout` is the one loss predicate: a whole-package AST guard, proven on
     synthetic offenders. The loss decisions leave SP-56's allowance list.
  5. **An answer to a request sent on a session known to be lost is never evidence**
     (the owner's decision D′): the session layer marks the request, the sender carries
     the mark, and **every consumer reads it**: the oracle's layer 1, applied to every
     compared send whichever sender made it, reads any answer to it as not comparable,
     whatever its class; the live WAF filter never records it as an allow or a block; the
     blind-SQLi builder never takes it as a sample or a row. A consumer found not reading
     it is fixed in the same change, or pinned by a strict xfail naming its owner
     (`PA-0531(4)`). (from BUG-0533)
  - Enforced by: tests/test_session_forbidden_answers.py::test_a_forbidden_answer_never_logs_in_and_checks_at_most_once, tests/test_session_forbidden_answers.py::test_a_throttled_answer_never_triggers_anything, tests/test_session_forbidden_answers.py::test_a_throttle_is_never_a_resources_refusal_status_nor_a_loss, tests/test_session_forbidden_answers.py::test_health_verdict_never_matches_a_throttle_gateway_407_or_incomplete_answer, tests/test_session_forbidden_answers.py::test_detect_logout_keeps_its_loss_signals_and_never_reads_a_throttle, tests/test_session_forbidden_answers.py::test_a_suspected_loss_on_a_live_session_is_checked_once_and_never_logs_in, tests/test_session_forbidden_answers.py::test_a_credential_submissions_answer_is_checked_never_an_unconfirmed_loss, tests/test_session_forbidden_answers.py::test_a_late_answer_from_an_earlier_session_is_ignored, tests/test_session_forbidden_answers.py::test_a_pause_found_for_an_older_generation_never_pauses_the_new_one, tests/test_session_forbidden_answers.py::test_a_pause_of_a_replaced_generation_never_delays_its_replacement, tests/test_session_forbidden_answers.py::test_a_lost_verdict_for_a_replaced_session_tells_no_listener_and_writes_no_row, tests/test_session_forbidden_answers.py::test_a_loss_seen_while_a_check_is_in_flight_is_still_acted_on, tests/test_session_forbidden_answers.py::test_verify_live_asked_about_a_session_replaced_while_it_checked_answers_live, tests/test_session_forbidden_answers.py::test_mark_lost_on_a_replaced_state_changes_nothing_and_writes_no_row, tests/test_session_forbidden_answers.py::test_an_adopt_between_the_checks_compare_and_the_mark_tells_no_listener, tests/test_session_forbidden_answers.py::test_a_slow_row_write_never_leaves_a_replaced_sessions_row_last, tests/test_session_forbidden_answers.py::test_an_unknown_session_is_sticky_and_costs_nothing_after, tests/test_session_forbidden_answers.py::test_relogins_draw_on_a_refilling_budget, tests/test_session_forbidden_answers.py::test_a_no_resource_identity_whose_budget_is_spent_carries_on_at_once, tests/test_session_forbidden_answers.py::test_an_answer_on_a_session_known_lost_is_never_evidence, tests/test_session_forbidden_answers.py::test_a_resource_backed_identity_never_sends_on_a_lost_session, tests/test_session_forbidden_answers.py::test_layer_one_reads_any_answer_on_a_lost_session_as_not_comparable, tests/test_session_forbidden_answers.py::test_a_peer_replay_on_a_session_known_lost_is_never_evidence, tests/test_session_forbidden_answers.py::test_the_live_waf_filter_never_reads_an_answer_on_a_lost_session, tests/test_session_forbidden_answers.py::test_the_blind_sqli_builder_never_admits_an_answer_on_a_lost_session, tests/test_session_forbidden_answers.py::test_only_the_owner_decides_a_session_loss, tests/test_session_forbidden_answers.py::test_the_loss_decision_guard_catches_synthetic_offenders, tests/test_core_comparability.py::test_no_module_classifies_a_throttle_or_refusal_but_the_owner
- **PA-0534** — After BUG-0534: the store version was read from SQLite's file side effects, so a reader's close refreshed the page and a running scan's commits went unseen (a review fix for one case opened the other); a live refresh dropped focus from every control kind but the one tested, in either order of a user's page load and a refresh (BUG-0518's root cause recurring; PA-0518(1) neither swept nor enforced); and a version was marked seen before its refresh ran, so a failed refresh was never retried.
  1. **A change signal over state another engine manages is that engine's own documented change counter** (SQLite: `PRAGMA data_version` on one held connection) plus the identity of what it watches -- never inferred from the engine's storage side effects (file sizes, mtimes, journal headers). One owner: `web/sitetree.py::store_version` (SP-58).
  2. **Its never / always claims, correctness ones included, are tested against every engine operation that touches what it reads, with the writer in another process**: a commit (UPDATE-only, after a WAL restart, a held writer's burst, rollback mode), each checkpoint kind, a reader's and a writer's last close, a replace, a rename and a removal of the file. A fix for one case re-runs all of them.
  3. **A live view keeps the user's place across every refresh**: each focusable control it re-renders carries a focus key naming its identity, unique in its region, and is restored through the one helper (`static/js/livefocus.js`), verified where focus landed, falling back to a visible equivalent and ending at the region's pane, never the page body, never scrolling; work the user started that a refresh overlaps is delivered once, in either order, tested by holding each side's fetch. Every polling or streaming page script is registered with its real-browser focus tests -- each control kind tested across a change after the first load, with writes that sort before it as well as after, asserting identity (an id, an href, a label), synchronised on the page's own counters, never a sleep -- or a reasoned exemption. This is PA-0518(1) made mechanical and swept.
  4. **Amends PA-0023 with a third pattern**: a handle whose value is meaningful only on one connection (here `data_version`) may be one shared instance if every use is under one lock, it is opened for any thread, the invariant is in its docstring, and an AST guard plus a many-thread test pin it.
  5. **A live view marks a version seen only once its refresh of that version succeeded -- every fetch the refresh draws from** (each group's pages, the selection's summary, findings and contents), a non-200 answer being a failure, never an empty result: a failed refresh keeps what is shown, says so once, and is retried at the next poll; a test injects a failed fetch into each kind of fetch to prove it.
  - Enforced by: tests/test_web_sitetree.py::test_every_commit_of_a_held_writer_in_another_process_changes_the_version, tests/test_web_sitetree.py::test_no_read_close_or_checkpoint_changes_the_version, tests/test_web_sitetree.py::test_a_store_moved_under_the_watch_keeps_its_commits_and_spoils_no_other, tests/test_web_sitetree.py::test_no_module_fingerprints_the_store_from_its_files, tests/test_web_sitetree.py::test_the_store_fingerprint_guard_catches_synthetic_offenders, tests/test_web_sitetree.py::test_the_store_watch_is_used_only_under_its_lock, tests/test_web_sitetree.py::test_the_watch_lock_guard_catches_synthetic_offenders, tests/test_web_sitetree.py::test_concurrent_polls_from_many_threads_agree, tests/test_web_store_locks.py::test_a_projects_listing_never_drops_the_store_watchs_locks, tests/test_web_live_focus.py::test_every_live_view_is_registered_with_its_focus_test, tests/test_web_live_focus.py::test_the_live_view_registry_catches_synthetic_offenders, tests/test_web_live_focus.py::test_every_live_view_restores_focus_through_the_one_helper, tests/test_web_live_focus.py::test_no_registered_live_view_test_synchronises_by_sleeping, tests/test_web_live_focus.py::test_the_sleep_guard_catches_a_synthetic_offender, tests/test_web_sitetree_browser.py::test_a_refresh_during_a_show_more_load_still_delivers_that_page, tests/test_web_sitetree_browser.py::test_every_focusable_control_in_the_site_maps_live_regions_has_a_focus_key, tests/test_web_sitetree_browser.py::test_restore_focus_skips_every_candidate_that_refuses_focus_and_ends_at_the_pane, tests/test_web_sitetree_browser.py::test_a_refresh_whose_group_fetch_fails_is_retried_at_the_next_poll, tests/test_web_diagrams.py::test_every_focusable_control_in_the_diagrams_live_regions_has_a_focus_key, tests/test_web_sitetree_browser.py::test_a_refresh_whose_contents_fetch_fails_keeps_the_table_and_is_retried, tests/test_web_sitetree_browser.py::test_a_group_whose_refresh_fails_on_expand_is_retried_at_the_next_expand, tests/test_web_sitetree_browser.py::test_unkeyed_siblings_with_one_label_keep_distinct_identities_across_refreshes
- **PA-0535** — After BUG-0535: the Projects listing read a store's magic bytes with `open()` in the web process, whose close released the POSIX locks of every SQLite connection the process held; another process's close then deleted `-wal`/`-shm` under them (a corrupt project under `--with-proxy`, lost commits, wrong reads).
  1. **A process that holds, or may hold, SQLite connections never opens, reads, writes or copies a database's main file, `-wal` or `-shm` outside SQLite.** Whether a file is SQLite is asked of SQLite (`core.store.is_sqlite`); a read-only open goes through `core.store.open_read_only` (FR-CORE-508, SP-59); a copy uses the backup API.
  2. **Enforced by a computed scope, not a list, and at run time**: the static guard covers every module the web package imports, transitively (lazy imports and literal `import_module` included), whatever the module itself opens, and every library call that opens a file by name (`shutil`, `filecmp`, `tempfile`, `zipfile`, `tarfile`, Starlette's `FileResponse` and `StaticFiles`); each raw open there is a reviewed allowance with its count and its reason, and a stale one fails. A test-time audit hook (`tests/_store_audit.py`) fails any web test during which production code opened a store's file outside SQLite, whatever the call. Both are proven on synthetic offenders, a helper module's open included. What neither sees is stated with them (code outside the import graph that no web test runs, such as an entry-point plugin; C code; another process).
  3. **Store behaviour across connections is tested with the other connection in another process** (`tests/_xproc.py`): SQLite's locks, shared memory and WAL fold are per process, so a second connection of the test's own process cannot show a cross-process failure.
  - Enforced by: tests/test_web_store_locks.py::test_no_web_process_module_opens_a_store_file_except_through_sqlite, tests/test_web_store_locks.py::test_the_store_file_guard_catches_synthetic_offenders, tests/test_web_store_locks.py::test_the_store_open_audit_catches_synthetic_offenders, tests/test_web_store_locks.py::test_a_projects_listing_never_drops_the_in_process_proxys_store_locks, tests/test_web_store_locks.py::test_a_projects_listing_never_drops_a_request_readers_locks, tests/test_web_store_locks.py::test_opening_a_project_never_drops_a_held_connections_locks, tests/test_core_store_read_only.py::test_whether_a_file_is_sqlite_is_asked_of_sqlite_never_read_raw, tests/test_core_store_read_only.py::test_every_read_only_open_goes_through_the_opener
- **PA-0538** — Strengthens PA-0526 and PA-0135 (from product code to test helpers) and applies PA-0149(2), after BUG-0538: the site-map browser tests' `Tab.item` filtered nested tree items by a descendant (`has=`), one resolution cost ~1.9 s of a renderer core, and under the harness's parallel load fixed timeouts overran.
  1. **A browser test never filters a locator by a descendant over a nested structure**: it locates the descendant and steps up. Any `has=`/`has_not=` in a browser test is a reviewed allowance.
  2. **A failure seen only under the harness's load is reproduced under that load and measured with clocks the test does not distort** (page-side timestamps, per-process CPU, server timings), before it is attributed to the product or to the timeout; the test's own event timestamps are not evidence (Playwright's sync API delivers events only inside its calls).
  - Enforced by: tests/test_web_live_focus.py::test_no_browser_test_locates_by_a_descendant_filter, tests/test_web_live_focus.py::test_the_descendant_filter_guard_catches_synthetic_offenders
- **PA-0548** — Strengthens `PA-0102(3)` and `PA-0536(1)`, after BUG-0548: the disco capture proxy decoded, redacted and built every record in its mitmproxy hooks, on the loop that carries every browser request. A 1 MiB JSON answer held the loop for a median 104 ms. Its queue was bounded by record count and dropped when full. PA-0102(3) named only blocking I/O and was enforced on the native proxy only. PA-0536(1)'s sweep listed `requests` readers only, so mitmproxy's whole-body decode was missed.
  1. **An event-loop or callback path does no work whose cost grows with untrusted input:** decoding, decompression, redaction, parsing, serialisation, hashing or writing. It takes references and hands off, and the hand-off comes before the work. A claim that a hook does not block cites a measurement of the hook and of the loop.
  2. **Every proxy hook in the package is under a guard.** No per-flow hook of a `fuzzlab` mitmproxy addon reaches body or record work, followed through its class's `self` methods and the package's functions. A new addon module is enumerated automatically. The guard is proven on the pre-fix shape (`PA-0034(2)`).
  3. **A queue that carries work off a loop is bounded in the unit that costs: bytes, and records.** Past its bound it paces the producer without blocking the loop (an awaitable and an order-keeping line). A loss comes only after a bounded wait, and it is counted where the run's operator reads it. A consumer that waits for the drain (a stop's grace) waits longer than the drain (`PA-0138(3)`).
  4. **A target body that arrives through any library is decoded through SP-60, under a ceiling.** The requests that fetch it advertise only codings SP-60 can bound. `PA-0536(1)`'s sweep is by what is read (a target's body), not by the library it arrives through.
  (from BUG-0548)
  - Enforced by: tests/test_capture_hook_guard.py::test_no_proxy_hook_does_body_or_record_work_on_the_loop, tests/test_capture_hook_guard.py::test_the_hook_guard_catches_synthetic_offenders, tests/test_disco_capture.py::test_the_proxy_hook_takes_the_exchange_and_the_writer_does_all_the_work, tests/test_disco_capture.py::test_past_its_byte_budget_the_queue_holds_the_browser_back_and_loses_nothing, tests/test_disco_capture.py::test_an_exchange_still_without_room_after_its_wait_keeps_its_record_not_its_body, tests/test_disco_capture.py::test_the_line_moves_without_its_waiters_and_is_written_at_shutdown, tests/test_disco_capture.py::test_a_body_too_large_or_undecodable_is_never_held_whole_and_its_record_says_so, tests/test_disco_capture.py::test_a_proxy_stop_outlasts_the_recorders_drain, tests/test_disco_capture.py::test_the_target_is_asked_only_for_codings_the_writer_decodes_bounded
- **PA-0547** — Strengthens `PA-0076` (a join keys on every identity field) from joins to every step that drops work, and `PA-0507(1)` (a classifier is measured where its confusable alternative occurs) from routes to every similarity, after BUG-0547: the pipeline's DOM-template stage dropped every injection point on all but the first page of a template -- keyed on the page's tag skeleton, which holds no field of the request -- and every page without HTML was one template. Related: `PA-0073`, `PA-0456`.
  1. **A step that drops units of work as duplicates keys on everything the unit sends and observes**: every field of the unit, taken generically (a new field joins the key on its own), normalised only where the one owner that builds the request overwrites it (here SP-42's placement of a standalone query slot). A similarity (a template, a cluster, a shape) may narrow a fold, never decide it alone.
  2. **An absent or empty input is unknown, never a shared default**: it gets its own identity and folds with nothing but itself.
  3. **A fold reports how many it dropped and on what key**; a drop that is not provably the same work is a coverage reduction, reported as one.
  4. **Its tests change one field at a time over the unit's fields** (a guard over the dataclass, not a list) and include the confusable shape: one context, two different works. (from BUG-0547)
  - Enforced by: tests/test_dom_dedup_folding.py::test_every_field_of_a_point_is_in_its_wire_request_key, tests/test_dom_dedup_folding.py::test_a_shared_template_never_merges_two_attack_surfaces, tests/test_dom_dedup_folding.py::test_points_that_differ_in_any_request_field_both_survive, tests/test_dom_dedup_folding.py::test_absent_or_empty_html_is_unknown_never_a_duplicate, tests/test_dom_dedup_folding.py::test_true_duplicates_fold_and_the_count_and_key_are_reported
- **PA-0546** — Strengthens `PA-0505(1)` (identify what was seen by its content, never by its address) from documents and states to every deduplication key, after BUG-0546. The spider's capture writer keyed a captured request by method, path and top-level body keys, so a dispatcher's operations (GraphQL, JSON-RPC, `action`/`op`/`cmd`) and a later request's nested inputs were dropped as duplicates. PA-0505(1) was worded for documents, its sweep did not reach request signatures, and it was not enforced. Also strengthens `PA-0531(4)`/`PA-0054(3)` (pin, never defer in prose), which BUG-0546's first sweep broke because nothing checks a sweep's rows.
  1. **A deduplication key holds everything that can route the item to different code or give it different inputs**: for a request, the method, the canonical path, the media type and every operation selector, in the body at any depth or in the query. An item is a duplicate only when what is kept for its key already holds it exactly. One that adds anything (a key path or a type, at any depth) is always kept with its own evidence, and a cap on what is kept applies only to items that add nothing.
  2. **A rule that keeps or drops by such a key names the confusable alternative and what decides it, and errs towards keeping.** For a selector or a data field, the decider is the field's name, whatever its non-empty value. For a GraphQL document or search text, it is an executable document. A condition on the value may only add a selector, never turn one into data. A misjudged item costs a row, never an input. (The first version named "a token value" as the decider, which merged "Add to cart" with "Remove from cart".)
  3. **A merge or dedupe that feeds a consumer judging the whole item is checked against that consumer before it ships.** A body merged from two requests would have been refused by the importer for a field one of them carried, or for its leaf count (measured). The consumer's own identity is checked too: the importer's first-wins parameters bind a second operation's shared inputs to the first (pinned).
  4. **Every writer of `discovered_requests` keys its rows through `tools.apiop`** (`operation_key`, `request_shape`, `operation_schema`, `row_signature`). This is an AST guard proven on synthetic offenders, BUG-0546's writer among them.
  5. **Every row of a bug's PA-0002 sweep states its disposition:** fixed (here, or by a named bug), not an instance (with why), or pinned by an offline strict xfail that exists and names its owner. "Another lane's item" is not a disposition. For BUG-0546 this is a guard over its sweep rows, proven on synthetic offenders (the first version's two prose rows among them). The known instances are `record_form`, `disco.synth`, `store_adapter._store_request` and `core/dedup.py` via `pipeline._dedup`.
  - The guards' limits:
    - The writer guard checks that the four keying functions are called in the function that writes the table, not how their results flow into the signature. It covers `discovered_requests` only.
    - The sweep guard reads BUG-0546's sweep only (10 bug docs have such a section today), and it trusts a row that says "fixed" or "not an instance". (from BUG-0546)
  - Enforced by: tests/test_captured_operations.py::test_every_captured_request_writer_keys_through_the_operation, tests/test_captured_operations.py::test_the_operation_guard_catches_synthetic_offenders, tests/test_captured_operations.py::test_two_graphql_operations_on_one_endpoint_stay_two_operations, tests/test_captured_operations.py::test_two_json_bodies_differing_only_in_a_nested_key_keep_both, tests/test_captured_operations.py::test_json_rpc_methods_stay_apart, tests/test_captured_operations.py::test_contexts_are_capped_per_operation_and_a_new_input_never_is, tests/test_captured_operations.py::test_a_selector_value_with_whitespace_or_over_64_characters_keeps_operations_apart, tests/test_captured_operations.py::test_the_bug_0546_sweep_pins_every_instance_it_does_not_fix, tests/test_captured_operations.py::test_the_sweep_guard_catches_a_prose_deferral
- **PA-0543** — Strengthens `PA-0102(1)`, `PA-0528(1)`, `PA-0536(1)`/`(2)` and `PA-0087(2)`, after BUG-0543: the native proxy guessed where HTTP/1 messages ended (the listener read `Content-Length` only; the sender took a byte suffix, an idle receive or a close for the end), so chunked uploads lost their bodies and cut responses were relayed and recorded as whole. Its listener read clients without a body cap, a deadline or a connection cap, because BUG-0101's sweep cleared it on the stream reader's head limit.
  1. **A message is complete only at its framed end, decided by one framing owner.** Every HTTP/1 read the proxy makes goes through SP-63 (`proxy/framing.py`), requests and responses alike. A close, an idle receive or a byte pattern in the payload never ends a message. A read that stops first is typed incomplete (`UpstreamIncomplete`) and is never returned, recorded or relayed as a response. A message that cannot be framed is refused (400 / 502), never forwarded in part. The owner's own parse is the strict one: the head's end and its fields come from one parse of the same bytes (a bare CR or LF, obs-fold or a non-token field name is refused), never from a lenient view built for editing. An AST guard fails on hand framing outside the owner (`readuntil` / `readexactly`, a guessed last-chunk literal), proven on the pre-fix shapes.
  2. **A read bound covers both directions and every dimension, enforced while reading.** The proxy's inbound read has head, body and time bounds as its upstream read does, and the proxy listener has an admission cap whose refusals are counted. This admission and time clause is scoped to the proxy listener: other listeners (`oracle/oob.py`, the web UI's uvicorn) belong to other components and are recorded as residuals (BUG-0543 R9, R10), not claimed. A sweep that clears a reader names what each bound limits (head, body, time, count) and cites, for each, a test against an over-limit, dripping or flooding peer, never the presence of a limit. (from BUG-0543)
  - Enforced by: tests/test_proxy_framing.py::test_every_proxy_http1_read_goes_through_the_framing_owner, tests/test_proxy_framing.py::test_the_framing_guard_catches_synthetic_offenders, tests/test_proxy_framing.py::test_a_response_cut_before_its_framed_end_is_incomplete_never_returned, tests/test_proxy_framing.py::test_a_request_that_cannot_be_framed_is_answered_400_and_never_forwarded, tests/test_proxy_framing.py::test_a_response_head_that_does_not_parse_strictly_is_never_relayed, tests/test_proxy_framing.py::test_a_dripped_request_is_answered_408_at_its_deadline_and_never_forwarded, tests/test_proxy_framing.py::test_connections_over_the_cap_are_answered_503_and_counted
- **PA-0549** — Strengthens `PA-0148(1)`/`(2)` from build and harness setup to per-request runtime setup, generalises `PA-0134(4)`'s jar rule to every pooled client, and strengthens `PA-0510(1)` and `PA-0046` from senders to the layers beneath them, after BUG-0549: the core seam made an HTTP session per send and the proxy's sender a socket and a system-CA SSL context per call, because their interfaces carried neither the identity, the session generation nor exact framing, and nobody measured the cost (CC-CORE-0072 kept it "as before"). Its fix's review then found reuse and resend decided from the client's own bytes and exception classes: a CL.0 probe's kept connection absorbed another identity's request, the seam's transport re-sent below the sender that records tries, the proxy's sender replayed a request after part of its answer, and the Repeater was left on kept connections in prose.
  1. **Per-request setup a sender repeats is measured, and kept when it is invariant**: a connection, an HTTP session, an SSL context. "As before" is no reason to keep a per-send cost; a change that keeps one on a send path cites a measurement of it.
  2. **A kept connection is keyed by everything it must not be shared across** (origin, identity, session generation). It has an owner that retires it when the session changes and closes it at teardown or collection, never under a send in flight. It carries no identity state of its own: no cookie jar (credentials are explicit per send) and no connection-bound authentication.
  3. **A connection is reused only after an exchange proven exactly framed and bodiless**: one well-formed request with no body bytes, one fully framed keep-alive answer, nothing after it. A request with a body always gets a connection of its own, closed after it, whatever its framing: whether the peer read the body cannot be observed (CL.0), and a well-framed answer proves nothing about it. A framing header in any spelling a server may honour (`Transfer_Encoding`) counts as framing, and every deliberately malformed request gets a fresh connection too. A claim that a probe class "always gets a fresh connection" is pinned by a test whose peer leaves a body unread (`PA-0083(2)`).
  3a. *(Merge integration, from BUG-0549's merge-integration section.)* **Whether anything followed an answer is the framing owner's observation, not a second parse.** A keep decision reads SP-63's `leftover` and the socket's state when the answer ended. It never re-parses the bytes a reader returned: that return value changes shape when its owner changes. A residual that names a dependency on another lane's change in flight is a test that fails until the dependency is met, never prose (PA-0134(2)).
  3b. *(Review round 2, from BUG-0549's "Review round 2".)* **A keep decision a library makes for the code is the code's to verify.** Before relying on a library's connection reuse, measure what it observes at the end of an answer: its buffered reader, the TLS layer, the socket. Then make the decision where those are visible (for `requests`, SP-60's pools: `exact_end`). A test's peer sends bytes past an answer, plain and over TLS. A library's word ("drops a connection it finds closed") is not a sweep verdict (PA-0536(2), widened from timeouts to every safety claim a library makes).
  3c. *(Review round 2.)* **A defect a sweep finds in an unpushed change of the same batch is fixed in that batch**, never pinned as another owner's open instance. A strict xfail (PA-0531(4)) is for another item's code that this change does not own.
  4. **A transport never re-sends below the code that records the try**: a re-send is the evidence producer's to make and record, where it happens (`PA-0510(1)`, `PA-0046`). A raw sender beneath no evidence producer (the proxy's) re-sends a reused connection's request at most once, only for an idempotent method, and only when no byte of answer came, counted where the bytes are read, never inferred from an exception class; never after a timeout or a partial answer.
  5. **A sender used for deliberate, connection-sensitive experiments keeps fresh connections by construction** (the web Repeater: `keep_alive=False`), pinned by a test that counts upstream connections; such a switch is never left as a residual in prose (`PA-0134(2)`). (from BUG-0549)
  - Enforced by: tests/test_http_pooling.py::test_sends_of_one_identity_share_a_connection_sequentially_and_concurrently, tests/test_http_pooling.py::test_identities_and_generations_never_share_a_connection_or_a_cookie_jar, tests/test_http_pooling.py::test_a_generation_change_never_closes_a_send_still_in_flight, tests/test_http_pooling.py::test_a_reused_connection_closed_before_any_answer_is_never_resent_by_the_transport, tests/test_http_pooling.py::test_a_send_with_a_body_never_leaves_or_takes_a_pooled_connection, tests/test_http_pooling.py::test_closing_the_client_closes_its_pooled_connections, tests/test_socketsender_pooling.py::test_well_framed_keep_alive_exchanges_reuse_one_upstream_connection, tests/test_socketsender_pooling.py::test_an_exchange_that_is_not_exactly_framed_never_leaves_its_connection, tests/test_socketsender_pooling.py::test_a_stale_pooled_connection_is_retried_once_and_a_timeout_never, tests/test_socketsender_pooling.py::test_a_body_the_upstream_leaves_unread_never_reaches_the_next_request, tests/test_socketsender_pooling.py::test_a_kept_connection_reset_after_part_of_its_answer_is_never_resent, tests/test_socketsender_pooling.py::test_tls_upstream_connections_are_reused_and_the_context_built_once, tests/test_socketsender_pooling.py::test_concurrent_exchanges_each_get_their_own_answer_on_reused_connections, tests/test_socketsender_pooling.py::test_closing_the_sender_closes_its_idle_upstream_connections, tests/test_web_repeater.py::test_each_repeater_send_gets_a_fresh_upstream_connection, tests/test_trace_attempts.py::test_the_seams_default_transport_sends_exactly_the_tries_it_records, tests/test_socketsender_pooling.py::test_bytes_after_a_framed_answer_never_leave_its_connection_kept, tests/test_http_pooling.py::test_an_answer_followed_by_another_never_leaves_its_pooled_connection, tests/test_http_pooling.py::test_a_stray_answer_held_by_tls_never_leaves_its_pooled_connection
- **PA-0542** — Strengthens `PA-0111`, `PA-0531(4)` and `PA-0117(1)`, after BUG-0542. A path point's PRG follow-up was resolved against the placed URL, so `#top` or `edit` re-sent the payload by GET, and the oracle read that answer as the page the probe led to. Path placement (CC-FUZZ-0096) reassigned the variable the follow-up reads, five days after FR-FUZZ-49. The PRG rule table named the browser's base (the request's URL), and every rule fixture was a body point, where the probe's own URL and the placed URL are one. BUG-0531 had fixed the same defect for a bound query point, at its call site only, and pinned this one. The first fix refused only the template-relative spelling. It let the server's absolute spelling of the same request (`/p/<payload>/edit`) through, on an unverified claim that the strategies classify it, and its boundary test could not observe the misattribution.
  1. **An emulated rule whose result depends on where the payload sits is exercised at every location that places it differently.** The rows come from the list of placeable locations, and a table check fails when a location is added without a row. It is never exercised only where the difference is invisible. A rule that diverges from the emulated algorithm says so in the rule table, with its reason.
  2. **A follow-up, or any request derived from a probe, is derived from the probe's own request description, never from the placed request.** Where no payload-free target exists (a path point's own segment), it is refused before any send, never sent with the payload (`PA-0115(1)`). The refusal is decided on the resource the target names, however the target is spelled: relative to that resource, or an absolute path or URL holding the placed value, compared as written and decoded. One browser request gets one decision.
  3. **A change that reassigns or repurposes a value names every reader of it in its change-control entry.**
  4. **A carve-out justified by what a downstream consumer does is checked against every consumer of that output**, by reading each one or by a test per consumer. Otherwise it is not a carve-out.
  5. **A boundary or carve-out test makes the excluded outcome observable.** Its fixture answers the request that the rule refuses or allows with what would be misread (a page, not another redirect), so that the test fails when the rule is wrong.
  (3), (4) and (5) are applied in review. The tests below enforce (1) and (2). (from BUG-0542)
  - Enforced by: tests/test_query_placement.py::test_no_prg_follow_up_carries_the_payload_at_any_location, tests/test_query_placement.py::test_the_prg_location_table_covers_every_placeable_location, tests/test_query_placement.py::test_a_path_points_prg_follow_up_never_carries_the_payload, tests/test_query_placement.py::test_a_location_the_server_wrote_with_the_payload_is_refused, tests/test_prg_observation.py::test_every_prg_rule_has_a_fixture, tests/test_prg_observation.py::test_a_path_points_follow_up_that_would_re_send_the_payload_never_confirms
- **PA-0550** — Strengthens `PA-0102(3)`, `PA-0107` and `PA-0012`, and applies `PA-0516(2)`, `PA-0023` and `PA-0531(4)`, after BUG-0550: the proxy wrote its flow history on its event loop, so one slow or locked store write stalled every connection, in batches cut by count only. BUG-0101's sweep of PA-0102(3) listed network reads and kept the store write on the loop; its one test covered the sender; the only measurement was taken on an idle store. The fix's first version then lost every queued flow on SIGTERM, left its commit-failure claim untested and its web-stop drain on the loop as prose (review round 1).
  1. **Blocking work on an event loop includes store and disk work** (SQLite statements and commits, file writes) **and work that grows with a message** (redaction, hashing, parsing a body), not only network reads. A loop path does bounded work per message and hands the rest to a thread it owns; a thread-affine store connection is owned by one writer thread, never moved into `to_thread`.
  2. **A writer that buffers bounds what it holds by count, bytes and age, and states its overflow policy:** backpressure, or drops counted, logged and written to the store while the run is live. A batch that cannot be written is retried a bounded number of times and counted; a failed write leaves nothing behind, its commit included; `close` drains within a stated timeout and counts what it could not.
  3. **Work kept on a loop because it is believed short cites a measurement against a slow and a busy dependency**, not only an idle one.
  4. **A deferred non-functional requirement of any class carries an `Enforced by:` or a `Not yet enforced:` line** in its `requirements.md`, not only a SAFETY one (PA-0112).
  5. **A change that moves a write behind a queue re-checks every way its process stops** (strengthens PA-0012): each requested stop the process's owners send (Ctrl-C; SIGTERM from `kill`, a supervisor or a service manager; a web lifespan's stop) drains the queue; a test stops the real process with that signal after work was answered and finds it all stored; the durability statement names what a hard kill loses (up to the queue bound), never the synchronous bound it replaced.
  6. **A claim that a failed write leaves nothing behind is tested with the failure injected at each statement it covers, the commit included** (strengthens PA-0107(1)).
  7. **Every instance a sweep finds is fixed or pinned by a strict xfail in the same change** (PA-0531(4)), never left as a stated residual; a blocking close, flush, record or search of a history writer inside an `async def` anywhere in `fuzzlab/` is caught by a whole-package AST guard. (3) and (4) are applied in review, not by a test; the line below enforces (1), (2), (5), (6), (7), (8) and (9). (from BUG-0550)
  8. *(Merge integration and its review round 2, from BUG-0543's integration and round-2 sections.)* **A side channel that only observes a flow (history, trace) never changes the flow's answer.** **Every caller** that hands a flow to it after the upstream answered (the engine and the Repeater today) contains the hand-over and counts any failure where its operator reads the result: `ProxyEngine.history_failures`, printed at stop, and the web Repeater's `history_error` / `history_failures` beside the response. Each such caller has a test that injects a raising side channel there. Fixing the failing write behind the hand-over (a store error, BUG-0550 item 3) does not fix the hand-over itself. A sweep instance in the lane's own component is fixed in the same change, not pinned.
  9. *(Review round 2, from BUG-0550's "Review round 2".)* **A resource joins a teardown or exit registry only once it holds what the teardown acts on** (a started thread, an open handle). **A teardown over many owners contains each owner's failure, reports it, and goes on.** A test makes one owner's start fail and another owner's close fail.
  - Enforced by: tests/test_proxy_history_writer_thread.py::test_a_blocked_store_write_never_stalls_proxied_traffic, tests/test_proxy_history_writer_thread.py::test_the_loop_parses_only_each_messages_first_line, tests/test_proxy_history_writer_thread.py::test_the_proxy_loop_never_calls_store_or_redaction_work, tests/test_proxy_history_writer_thread.py::test_the_loop_work_guard_catches_synthetic_offenders, tests/test_proxy_history_writer_thread.py::test_a_full_queue_drops_are_counted_reported_and_written_live, tests/test_proxy_history_writer_thread.py::test_a_failing_write_is_retried_then_counted_and_later_flows_still_write, tests/test_proxy_history_writer_thread.py::test_a_failed_commit_is_rolled_back_and_the_retry_writes_once, tests/test_proxy_history_writer_thread.py::test_close_writes_every_pending_flow_in_submission_order, tests/test_proxy_history_writer_thread.py::test_a_sigterm_stops_the_recording_proxy_like_ctrl_c_and_writes_every_answered_flow, tests/test_proxy_history_writer_thread.py::test_stopping_the_web_proxy_drains_its_history_off_the_web_loop, tests/test_proxy_history_writer_thread.py::test_no_event_loop_path_blocks_on_a_history_writer, tests/test_proxy_history_writer_thread.py::test_the_history_loop_guard_on_synthetic_code, tests/test_proxy_rules_and_scope.py::test_a_history_failure_never_changes_the_clients_answer, tests/test_proxy_repeater.py::test_a_history_failure_never_loses_the_repeaters_response, tests/test_web_repeater.py::test_a_history_failure_answers_the_repeaters_response_and_says_so, tests/test_proxy_history_writer_thread.py::test_a_writer_thread_that_cannot_start_never_stops_the_exit_drain, tests/test_proxy_history_writer_thread.py::test_a_stop_whose_writer_thread_cannot_start_still_writes_what_it_buffered
- **PA-0554** — Strengthens `PA-0500(1)` (a total function's tests feed a lone surrogate), `PA-0086(2)` (a per-unit handler contains and reports its failures) and `PA-0546(3)` (check a change against its consumer before it ships), after BUG-0554: the spider's capture writer bound `ensure_ascii=False` JSON text into SQLite and digested target text with a strict encode, so a captured body holding a lone surrogate raised; the exception went to navguard's observer catch, which only logs, and the request was lost uncounted. The importer failed the whole import on such a row. PA-0500(1) was worded for functions that promise a sentinel and enforced on URL parsers only; PA-0086(2) never said that "reports" means a count; BUG-0546's round 1 made one digest total and swept no further.
  1. **Text decoded from a target's JSON may hold a lone surrogate.** A writer that binds such text into SQLite writes each surrogate as its JSON escape (`tools.apiop.storable_json`; never `ensure_ascii=False` text into a bind), and a digest or key of such text encodes with `surrogatepass`, never a strict `.encode("utf-8")`. A totality claim over target text is tested with a lone surrogate in each position its grammar has (a key, a value, a selector value, nested, a GraphQL document over the token cap).
  2. **A writer of target-derived rows never raises to its caller.** What it cannot store comes back as a reason that its caller counts where the run's operator reads it. An exception guard that only logs is containment, not the report PA-0086(2) asks for.
  3. **A fix that lets new rows into a table is run through every reader of that table on those rows before it ships.** A reader that cannot hold them refuses and counts them; it never fails on them.
  4. **Enforced mechanically:** a whole-package AST guard (no SQLite `execute`/`executemany` parameter holds `ensure_ascii=False` text or a strict encode, directly, through a local name, or through a function returning one; reviewed allowances with reasons), a keying guard (no strict encode in `tools/apiop.py` or the capture writer), both proven on synthetic offenders including BUG-0554's writer, `row_signature` and the `encode_entries` shape, and a guard over BUG-0554's sweep rows (`PA-0546(5)`).
  - The guards' limits: the bind guard follows one level of functions, by name, and names assigned in the same function; it cannot see unsafe text carried in through an attribute, a container built elsewhere, or a deeper call chain. The keying guard covers `tools/apiop.py` and the writer only. The sweep guard reads BUG-0554's sweep only. (from BUG-0554)
  - Enforced by: tests/test_capture_surrogates.py::test_a_body_holding_a_lone_surrogate_is_stored_losslessly, tests/test_capture_surrogates.py::test_the_operation_keys_and_digests_are_total_on_lone_surrogates, tests/test_capture_surrogates.py::test_a_marker_next_to_a_lone_surrogate_is_still_scrubbed, tests/test_capture_surrogates.py::test_a_write_the_store_refuses_is_counted_never_raised, tests/test_capture_surrogates.py::test_the_spider_import_refuses_and_counts_a_captured_lone_surrogate, tests/test_capture_surrogates.py::test_the_disco_import_refuses_and_counts_a_lone_surrogate_instead_of_failing, tests/test_capture_surrogates.py::test_no_sqlite_bind_takes_text_a_lone_surrogate_makes_raise, tests/test_capture_surrogates.py::test_the_capture_keying_never_encodes_strictly, tests/test_capture_surrogates.py::test_the_guards_catch_synthetic_offenders, tests/test_capture_surrogates.py::test_the_bug_0554_sweep_settles_or_pins_every_row
- **PA-0539** — Strengthens `PA-0028`, `PA-0029`, `PA-0110` and `PA-0502`, after BUG-0539: the disco explorer took a folded layout hash for a state's identity, a route-scoped key for an action's work (written before the action ran), and a subset of a state's controls for the state, then shrank the state to match. Each was a fix that saved work, judged by the work it saved.
  1. **An identity or acceptance decision rests on an exact key or on recorded evidence of equivalence** ("visited", "done", "the same step", "this is the recorded state"). A similarity key (folded, a set, a layout) may order or bound work, never decide sameness; every bound it applies is reported as a coverage exclusion.
  2. **A work item is consumed only by its observed success or an explicit refusal.** "Done" is written after the effect was read, never before; a failure, an unreadable result included, leaves it retryable within a stated bound, then failed and reported.
  3. **An acceptance check never rewrites its contract from what it observed, and refuses both ways:** a proper subset and a superset. A feature is optional only when declared so with evidence that holds independent of the state being judged (a fresh load of the entry document showed it gone), never from one observation of a click, and a declaration never excuses what the judged state's own step added. A step is acted on, and attributed to a state, only on a page that passed that state's check.
  4. **A recorded action is repeated (a replay, a restore) only on recorded evidence that it is safe to repeat** (no non-idempotent request observed); otherwise its result is used where it was reached, or reported unresolved.
  5. **A fold, skip, declaration or acceptance that saves work ships with a test of what it must not merge or accept** (two states, a second-stage step, a subset, a superset, a declared difference plus a missing mandatory element (PA-0029's pair), a failed attempt), proven on the pre-fix code -- including each one the fix itself introduces; the structural key's sites are fixed by an AST guard proven on synthetic offenders (`PA-0034(2)`). (from BUG-0539)
  - Enforced by: tests/test_disco_state_identity.py::test_the_structural_key_never_decides_a_visited_state, tests/test_disco_state_identity.py::test_the_structural_key_guard_catches_synthetic_offenders, tests/test_disco_state_identity.py::test_a_recorded_core_is_never_accepted_by_a_proper_subset_nor_shrunk, tests/test_disco_state_identity.py::test_a_failed_attempt_never_consumes_the_work_and_is_retried_then_failed, tests/test_disco_state_identity.py::test_a_path_that_sent_a_non_idempotent_request_is_never_replayed, tests/test_disco_state_identity_browser.py::test_a_wizard_step_with_the_same_layout_is_explored_to_its_end, tests/test_disco_state_identity_browser.py::test_a_dialogs_second_stage_takes_the_same_next_again, tests/test_disco_state_identity_browser.py::test_a_restore_that_lost_a_core_control_is_unresolved_and_its_contract_kept, tests/test_disco_state_identity.py::test_a_superset_of_the_contract_is_never_the_recorded_state, tests/test_disco_state_identity.py::test_a_declared_optional_feature_never_excuses_a_missing_mandatory_one, tests/test_disco_state_identity.py::test_an_action_whose_result_could_not_be_read_is_retried_and_its_successor_recorded, tests/test_disco_state_identity_browser.py::test_a_modal_closed_by_its_own_control_that_does_not_reopen_is_unresolved, tests/test_disco_state_identity_browser.py::test_a_restore_that_lands_on_a_later_stage_is_unresolved_never_that_stage

- **PA-0551** — Strengthens `PA-0501(2)`, `PA-0502(1)`, `PA-0502(3)` and `PA-0505(2)`, after BUG-0551:
  both crawlers read only the top document's light tree, so controls in shadow roots
  and frames, and delegated actions, were never candidates, and nothing said so.
  PA-0501(2) grows a fixture only from shapes a measured lab broke. PA-0502(3)'s
  marker clear was done in the light tree. PA-0505(2) was never applied to enumeration.
  The fix's review round found four more defects in the fix itself. It walked to a
  container with `parentElement`, put a heuristic's candidates into state identity,
  counted any request in a time window as a trial's effect, and wrote its closed-root
  gap down as a residual. So (2) to (5) below go further. They strengthen `PA-0502(1)`:
  an effect must be one the action caused. They strengthen `PA-0502(3)`: identity covers
  which elements make up a state, not only each element's signature.
  1. **A crawler page script that discovers or locates UI reads the composed tree
     through the one owner** (SP-70, `tools/composed.py::COMPOSED_JS`). That covers
     every open shadow root, and each frame by its own read in its own realm. A
     light-tree-only DOM query in a page script is a reviewed allowance with its count
     and its reason.
  2. **A discovery mechanism's fixture covers each way the platform presents UI**, not
     only the shapes a measured lab had: open and closed shadow roots; same-origin,
     cross-origin and out-of-scope frames; delegated handlers. It also covers **the
     variants each mechanism's code branches on**: a container element or none; a
     static page and one whose text changes under a document listener; a quiet network
     and a polling one; a host that renders nothing and one that slots its children.
     Each has a real-browser test judged by what the server received.
  3. **What a read cannot reach, or a bound leaves out, is counted in the run report,
     never claimed.** It is met only by a complete count, or by a counted remainder
     (`budget.*`), never by a residual paragraph.
  4. **An ancestor walk in a composed page script continues past the top of a shadow
     tree**, to the shadow root or its host (`composedParent`), wherever it looks for a
     container or a context. `parentElement` ends there.
  5. **A heuristic candidate is kept only on evidence its own action caused**, compared
     with a control observation made without that action. **Its presence, its verdict and
     its flags never enter state identity.** (from BUG-0551 and its review round)
  - Enforced by: tests/test_composed_tree_guard.py::test_every_crawler_page_script_reads_the_composed_tree, tests/test_composed_tree_guard.py::test_the_composed_tree_guard_catches_synthetic_offenders, tests/test_composed_tree_guard.py::test_discos_reads_and_the_spiders_form_read_are_built_on_the_owner, tests/test_disco_compose.py::test_a_form_in_an_open_shadow_root_is_found_filled_and_sent, tests/test_disco_compose.py::test_a_same_origin_frames_controls_are_explored_and_replayed_through_the_frame, tests/test_disco_compose.py::test_a_document_delegated_action_is_kept_and_an_inert_candidate_dropped, tests/test_disco_compose.py::test_what_was_not_read_is_counted_never_claimed, tests/test_disco_compose.py::test_the_census_counts_every_closed_root_of_the_documents_read, tests/test_disco_compose.py::test_a_formless_widget_at_a_shadow_roots_top_is_filled_and_sent, tests/test_disco_compose.py::test_the_spiders_form_read_finds_a_formless_widget_at_a_shadow_roots_top, tests/test_disco_compose.py::test_a_click_that_only_swaps_static_text_keeps_the_state, tests/test_disco_compose.py::test_a_delegated_candidate_is_no_part_of_a_states_identity, tests/test_disco_compose.py::test_a_delegated_candidate_is_no_part_of_the_execution_key_or_a_contract, tests/test_disco_compose.py::test_a_background_poll_never_makes_an_inert_candidate_live

- **PA-0552** — Strengthens `PA-0533` (rules 1, 2, 4 and 5 and its sweep) and `PA-0128` / `PA-0504` (a replaced context), after BUG-0552 and its review round 1: disco's explorer held a session without the session manager, decided its loss from the page's URL alone, re-installed the snapshot it started with, and left each replaced context open; BUG-0533's sweep had listed it as no consumer because it called no session owner. The first fix then published a generation's loss only by installing its replacement (a second worker kept acting on it), gave the CLI's storage-state path no protected check (a role-gated 401 ended every run), read only the first sign of a window, and missed two consumers of the mark its own rule 4 named.
  1. **A component that holds a session outside the session manager is a session consumer** (a browser context made from a storage state or a provider, a client with a captured credential). It decides that session's loss only through the session layer's owners: SP-56 classes each answer it got (with SP-16's facts: a credential submission's refusal and an intermediary's 407 are no sign), SP-16's login-form rule reads a rendered page (read whatever the answers were: one sign never hides another), and SP-61 decides for the generation it holds. A URL or a page shape never decides alone.
  2. **A lost session is replaced only by a fresh one from the session provider, revalidated by a protected check before anything is sent on it**, never by the snapshot the work started from. A loss nothing resolves ends that identity's work with a reported reason.
  3. **A replaced browser context is released (SP-38) and closed before its replacement exists**, and a test counts the open contexts across repeated replacements.
  4. **The answers recorded in a known-lost window are marked where they are recorded** (for a capture: the action ids its requests went out under) and **read through one reader** (`disco.capture.lost_action_ids`, SP-71). Every consumer that takes answers as evidence reads the mark, or is pinned by a strict xfail naming its owner (`PA-0531(4)`) -- **enforced by a whole-package guard over the readers of the records, not by a hand-written list**: a reader that neither reads the mark nor is listed with its pin or reason fails it.
  5. **A PA-0002 sweep for a rule about a session enumerates the components that hold a session**, not only the callers of the rule's owner; a sweep for a rule about consumers enumerates them from the call graph (who reads the records), not from what each module is described as doing.
  6. **A holder of a session generation shared by several workers publishes its loss to every one of them at the verdict, before any recovery** (as the manager's `_mark_lost` does, PA-0533(2)), under the lock the recovery takes, so the others wait for that decision and adopt its session or stop. **No worker acts, restores or loads on a generation known gone**: the check is made before each such step, not only at a state boundary, and every window sent on a gone generation is marked, a clean-looking one included, up to the context's release.
  7. **A session holder without a manager establishes a protected resource of its own before falling back to `PA-0533(1)`'s unconfirmed loss**: a resource its credential gets a live answer from and no credential is refused by, both read by SP-61's public `health_verdict`, its checks sent outside the recorded traffic. Only with none is a loss shape an unconfirmed loss.
  8. **A coarse sign is counted only where it is a change or where a check decides it**: with no known login form, a password form is a sign where the page was known without one (the URL before an action, the state restored, the start page) and, elsewhere, only when a protected check will decide it; a narrowing that drops one of those places is a defect of its own. (from BUG-0552)
  - Enforced by: tests/test_disco_session_loss.py::test_an_api_401_on_an_unchanged_route_is_confirmed_and_a_fresh_session_installed, tests/test_disco_session_loss.py::test_a_login_form_rendered_in_place_is_a_lost_session, tests/test_disco_session_loss.py::test_repeated_losses_never_leave_an_old_context_open, tests/test_disco_session_loss.py::test_without_a_provider_a_lost_session_ends_authenticated_exploration, tests/test_disco_session_loss.py::test_without_a_provider_a_login_form_rendered_on_a_restore_is_a_lost_session, tests/test_disco_session_loss.py::test_without_a_provider_a_login_form_at_the_seed_ends_before_anything_is_explored, tests/test_disco_session_loss.py::test_without_a_provider_a_role_gated_401_on_a_live_session_is_a_denial, tests/test_disco_session_loss.py::test_a_401_whose_script_drops_the_session_and_goes_to_login_reinstalls_it, tests/test_disco_session_loss.py::test_a_policy_block_on_a_live_session_is_an_authorization_denial, tests/test_disco_session_loss.py::test_an_answer_that_is_not_this_sessions_refusal_is_never_a_suspicion, tests/test_disco_session_loss.py::test_a_credentialed_401_is_checked_for_the_contexts_generation, tests/test_disco_session_loss.py::test_a_login_page_after_a_401_on_a_live_session_reinstalls_it, tests/test_disco_session_loss.py::test_a_loss_another_worker_finds_mid_action_is_never_this_workers_coverage, tests/test_disco_session_loss.py::test_no_worker_acts_on_a_generation_another_worker_found_lost, tests/test_disco_session_loss.py::test_a_newer_session_never_drops_a_pending_window_unmarked, tests/test_disco_session_loss.py::test_ede_never_replays_or_tests_an_answer_from_a_lost_window, tests/test_disco_session_loss.py::test_an_answer_in_a_lost_window_is_never_in_the_inventory, tests/test_disco_session_loss.py::test_import_disco_never_takes_a_lost_windows_answer_as_evidence, tests/test_lost_window_mark.py::test_every_capture_reader_reads_the_lost_window_mark, tests/test_lost_window_mark.py::test_the_capture_reader_guard_catches_synthetic_offenders

- **PA-0545** — Strengthens `PA-0132(3)`, `PA-0134(1)`, `PA-0536(1)`, `PA-0528`, `PA-0123(1)` and `PA-0503(1)`, and carries `PA-0112` from safety NFRs to a crawl's bounds, after BUG-0545: the legacy spider's static engine sent anonymously in an authenticated crawl, its handler filed a timeout, a reset, SP-60's incomplete body or a 503 as a visited page, its queue admitted every URL a target returned, and each page row waited on a commit; and, in the fix's review, a resumed crawl loaded stored rows around the scope and destructive rules, a host the session manager does not serve was sent to without the session, and three tests failed on the old code for another test's reason; in its second review, the browser engine loaded a loopback alias of the start without the session (its cookie host-only for the start's host, while the route's origin rule folded the alias in) and a fourth test failed on the old code for the first test's reason. PA-0132/0134's sweeps listed where a session must not go, never a send path that silently drops it; PA-0536(1) was enforced on greybox only and its sweep did not follow `BodyIncomplete` into the spider's handler; NFR-CRAWL-bounded was NOT_SAFETY and never built; PA-0123(1) was enforced for the browser and redirect hops, never the static engine's first hop, so scope held only while every producer remembered it; PA-0503(1) did not name a store as a source that feeds the queue; PA-0134(1)'s one origin predicate is not how a browser's cookie jar carries a session (by host), and round 1 patched R6 in one engine's send path and took the other's disposition from its rule.
  1. **An authenticated tool's every send path carries the identity or refuses, loudly, before the send.** The PA-0002 sweep of an identity feature lists every send path (each engine, each fallback, each submission, each redirect hop) with "carries it through the session manager" or "refuses with an error"; "sends anonymously" is never a disposition, nor a residual left to another component. Each disposition is measured -- what the target received, for each host the tool's scope admits (a loopback alias of the start included) -- never read from the path's rule. A send the session layer would make without the identity (none applied, nothing decided) is refused before the transport, never sent and then withheld. A path's test asserts what the target received on each request, that nothing reached a refused one, and a test with an identity the path cannot carry asserts the refusal and that nothing was sent. An answer the session layer sent without the identity (withheld) is never taken as the identity's.
  2. **A record that later work trusts as final is written only for a final outcome.** A load that did not answer, answered with a throttle, gateway, incomplete or server error, or whose extraction did not finish is recorded unresolved, retried within a bound when it may pass, reported and resumed; it never takes the final record's place. SP-60's and SP-56's markers are followed into every handler that writes a record.
  3. **A queue that grows from what a target returns has an admission budget:** a key reserved at admission, and bounds on total, pending, per origin and per route shape (values never counted), each refusal counted and reported as partial coverage. A specified bound (an NFR) is built and tested, or marked not yet enforced, whatever its safety class.
  4. **A record on a crawl's hot path never waits on a commit:** rows are batched by count, bytes and age by one writer, flushed at close, with a bounded backlog and a failed write raised.
  5. **Every load passes the crawl's scope and destructive rules at the one point every load passes -- where the request is made -- whatever queued it.** A store read back by a resumed run is a producer like any other; a new producer is never a reason to skip the check, and a producer's own check never replaces it. Each refusal is counted and reported. The test resumes a store holding an out-of-scope row and a destructive row and asserts that neither target received a request.
  6. **A regression test's pre-fix proof is on its own assertion.** Its fixture gives the pre-fix path what the test needs to reach the behaviour it names (an anonymous crawl sees the same links and forms), the proof records the failing assertion of every test in the file -- not only those a review named -- and a bug doc's claim of what the old code did cites that record.
  7. **A load goes only where the session's carrier in that engine reaches, decided at the one gate every load passes.** The gate compares the host the load goes to with the hosts the carrier reaches -- the session manager's own decision for a seam send, the cookie jar's domain match for a browser -- before any navigation or send; never an origin rule alone (it folds aliases a host-only cookie never reaches) and never a list of aliases. A refused load is unresolved, counted and reported, never visited. Its test runs the real browser and asserts that the unreached host received nothing. (from BUG-0545)
  - Enforced by: tests/test_spider_static_identity.py::test_a_static_crawl_carries_the_identity_through_the_session_manager, tests/test_spider_static_identity.py::test_a_session_lost_on_a_send_is_never_extracted_and_the_page_is_retried, tests/test_spider_static_identity.py::test_an_identity_the_static_engine_cannot_carry_is_refused_never_crawled_anonymously, tests/test_spider_static_identity.py::test_a_failed_login_stops_the_crawl_and_nothing_is_crawled_anonymously, tests/test_spider_static_identity.py::test_a_redirect_to_another_origin_is_never_followed_with_or_without_the_session, tests/test_spider_static_identity.py::test_a_selector_form_is_submitted_with_the_session, tests/test_spider_static_identity.py::test_a_host_the_session_manager_does_not_serve_is_never_sent_without_the_session, tests/test_spider_static_identity.py::test_a_browser_load_the_session_cookie_does_not_reach_is_refused_never_sent, tests/test_spider_frontier.py::test_a_destination_many_parents_link_is_queued_once, tests/test_spider_frontier.py::test_a_fan_out_trap_is_bounded_by_the_route_budget_and_reported, tests/test_spider_frontier.py::test_the_frontier_admits_each_key_once_and_counts_every_budget, tests/test_spider_frontier.py::test_a_transient_failure_is_retried_and_never_recorded_visited, tests/test_spider_frontier.py::test_an_incomplete_body_is_retried_never_taken_for_a_page, tests/test_spider_frontier.py::test_a_page_that_keeps_failing_is_unresolved_reported_and_resumed, tests/test_spider_frontier.py::test_a_resumed_crawl_never_loads_a_stored_row_out_of_its_scope_or_destructive, tests/test_spider_frontier.py::test_recording_a_page_never_waits_for_the_stores_lock, tests/test_spider_frontier.py::test_page_rows_are_committed_by_count_bytes_and_age_and_flushed_at_close

- **PA-0530** — Strengthens `PA-0073` and `PA-0076(3)`, after BUG-0530: four layers (importer, point builder, pipeline, ML join) each decided "which rows are one test" with a hand-written tuple that omitted fields of the request, so distinct requests were tested once and the rest were marked checked and labelled. PA-0076 covered joins between two tables, not dedup keys inside one; PA-0073's invariant varied only url and param.
  1. **Whether two units are one request, test or label** (a dedup set, a lookup key, a confirmation key, a join) **is decided by the one versioned identity owner** (SP-57, `core.reqctx`), never a hand-written tuple.
  2. **Every field a sender, strategy or executor can read from a candidate is in that identity or in its exclusion table with a reason.** A guard fails on an unclassified field (proven on a synthetic offender); every identity field is shown to move the id and no excluded one to.
  3. **A row is marked done only by its own unit's work.**
  4. **A stated residual that merges distinct inputs ("first wins") is a defect,** pinned with a strict xfail naming its owner, never a residual.
  5. **When a producer's output changes shape or cardinality, the sweep covers every caller of that producer** (grep its name), not only the keys of the mechanism changed; a caller that projects the output away from the identity deduplicates on what it actually sends, with a test (review round 1: greybox was missed). (from BUG-0530)
  - Enforced by: tests/test_request_contexts.py::test_every_candidate_field_is_in_the_identity_or_excluded, tests/test_request_contexts.py::test_the_field_guard_catches_a_synthetic_offender, tests/test_request_contexts.py::test_every_identity_field_moves_the_context, tests/test_request_contexts.py::test_no_excluded_field_moves_the_context, tests/test_request_contexts.py::test_the_seed_categories_are_the_strategies_that_read_the_original_value, tests/test_request_contexts.py::test_the_seed_guard_catches_a_synthetic_offender, tests/test_request_contexts.py::test_the_pipeline_tests_a_context_that_only_its_siblings_reach, tests/test_request_contexts.py::test_greybox_sends_each_of_its_requests_once
- **PA-0544** — Complements `PA-0100`, after BUG-0544: redacted evidence (a blanked CSRF token, a blanked identifier, a loopback stand-in for an app's host) was sent as the request's own values, so token-protected forms were refused before their handler and read as negatives. Review round 1 found the first fix treated the binding as a value problem only: the fetch is itself a request and the recipe itself a stored value. Review round 2 found items 5 and 7 applied too narrowly: the route checked only when the fetch chose it, the loopback predicate failing closed on the authority but deny-listing the tail. Review round 3 found them followed in name only: "proves" was written as "no recogniser of a host fires" (a deny-list of the shapes its lists know), and the send was checked against the route, not the session, with the gap stated as a residual.
  1. **A persisted value is evidence, never replay material.** A value redaction blanked or a stand-in replaced is recorded as a placeholder (by name, never by value) where it is stored, and is never sent as the request's own.
  2. **Before a send that needs it, the value is re-obtained by an authorized setup step on the probe's own session route** and bound in memory only (D12).
  3. **A send whose prerequisites cannot be rebuilt is not made:** the test is inconclusive with the reason, never a negative. Every send of the request that needs them is bound or refused, whatever its shape.
  4. **A wrapper of the sender protocol reports and forwards every optional capability its inner sender has** (`fetch_capable` like `prg_capable`), proven on a synthetic wrapper that hides it.
  5. **A setup request is a request:** it passes every gate a probe or a PRG follow-up passes, judged on its own URL (send gate, auth endpoints, isolated paths), and is made on the session the bound send carries -- same origin, no session note, and any cookie it receives either carried into that one send or the test is unbound. The route it actually went out on is recorded and the send that uses its result is checked against it **at the send** (the route can change during or after the setup request); another route or identity makes the test unbound (review round 2). What is recorded and checked is the **session**, not only the route: its route, identity and generation, and a loss the session layer saw on the setup request's own answer. A loss known before the send refuses it before anything is sent; a generation that changed inside the send makes its answer unread. A gap in this check is never a stated residual: it is a false-negative source, fixed or pinned (PA-0530(4)) (review round 3).
  6. **State a setup request leaves for one send is bound to that send** (a token the send carries), never a sender-wide flag; every other send discards it.
  7. **A recipe is a stored value:** what it records passes the strongest existing redactor, and anything the redactor would change is not stored at all. **A safety predicate that admits a value (loopback) fails closed** against every reader's parse, proven on the bypass shapes: it admits only what it proves for every part of the value (authority and tail), never by denying the shapes found so far, and its test covers each bypass class with more than the reported spelling (review round 2). "Proves" means **an allow-list of a stated grammar**: the predicate asks whether every part is in the grammar it states, never whether a part reads as the forbidden thing (no recogniser, classifier, closed list or parser of the forbidden thing decides admission); it is enforced by a guard that the predicate reads no recogniser and by a generated sweep of each bypass class, not a list of reported spellings (review round 3). (from BUG-0544)
  - Enforced by: tests/test_replay_bindings.py::test_a_blanked_csrf_token_is_bound_fresh_before_each_send, tests/test_replay_bindings.py::test_a_token_that_cannot_be_fetched_is_inconclusive_never_negative, tests/test_replay_bindings.py::test_no_fresh_value_reaches_the_store, tests/test_replay_bindings.py::test_a_sibling_naming_a_host_is_sent_as_given_on_loopback_and_never_off_it, tests/test_sender_conformance.py::test_every_wrapper_reports_and_forwards_its_inner_senders_fetch, tests/test_sender_conformance.py::test_the_fetch_guard_catches_a_wrapper_that_hides_it, tests/test_replay_bindings.py::test_the_seam_never_fetches_a_login_page_with_the_runs_session, tests/test_replay_bindings.py::test_a_source_page_on_another_origin_is_never_bound, tests/test_replay_bindings.py::test_the_pages_session_is_carried_into_the_bound_send_only_or_the_test_is_unbound, tests/test_replay_bindings.py::test_a_refused_binding_never_lends_its_pages_cookie_to_another_probe, tests/test_replay_bindings.py::test_a_source_page_holding_a_secret_or_an_identifier_is_never_stored, tests/test_replay_bindings.py::test_a_value_that_names_a_host_beyond_loopback_to_any_reader_is_outside_the_lab, tests/test_replay_bindings.py::test_the_binder_refuses_a_raw_or_built_send_to_its_own_request, tests/test_replay_bindings.py::test_the_binder_never_binds_a_fresh_value_that_names_a_host_beyond_loopback, tests/test_replay_bindings.py::test_a_bound_send_never_leaves_on_another_route_than_its_pages_fetch, tests/test_replay_bindings.py::test_every_spelling_of_the_generated_sweep_is_outside_the_lab, tests/test_replay_bindings.py::test_the_tail_rule_is_an_allow_list_never_a_recogniser_of_hosts, tests/test_replay_bindings.py::test_a_page_whose_own_answer_lost_the_session_is_never_bound_on_the_next_login, tests/test_replay_bindings.py::test_a_bound_send_on_a_session_relogged_in_after_its_fetch_is_unbound, tests/test_replay_bindings.py::test_a_bound_send_on_a_copy_relogged_in_after_its_fetch_is_unbound_and_verified

- **PA-0555** — Strengthens `PA-0544(7)` and `PA-0545(6)`, after BUG-0555: FR-AUD-20's lab predicate (SP-73) returned early, before BUG-0544's allow-list, whenever `neutral_value`'s recogniser of hosts did not flag a value, so a loopback authority it missed kept an outside tail and a bare outside host with an unlisted TLD or a short-form IPv4 address was sent (BUG-0544's pinned residual N-R3-1). PA-0544(7)'s guard read one helper (`_tail_in_grammar`) and its sweep varied only the tail, so the gate in front of the proof was never checked. The fix's review then found that its rewrite, derived from one reader's reading, dropped what the old gate held (`://` after a prefix, an unbracketed IPv6 literal), kept an unproven early return for JSON numbers, measured its cost per value and on some sources only (a lab's expected-vulnerable answer-key point was refused), and recorded a guard's pre-fix failure on another assertion. Its second review found the round-1 rules written as closed lists of spellings -- authority marks `://`, `:\`, `:/\` but not a special scheme's `:` or `:/`, an IPv6 literal ended at `/ ? # \ ;` or whitespace but not at `=`, `,`, a quote or `|`, and judged only on WHATWG's texts, which drop the tab a shell splits at -- and swept over the same lists.
  1. **A safety predicate's guard reads everything the predicate reaches**, from its public entry through each function of its module it calls (a transitive walk, not one helper), and fails on any recogniser, classifier, closed list or parser of the forbidden thing; it is proven on a synthetic offender at the entry (an early return) and one several calls down. The one list FR-AUD-20's predicate may read is IANA's root-zone TLD list, bundled verbatim and dated (FR-AUD-32), for a bare token only, because it is the definition of the names a public resolver answers; a test proves the decision is the file's, label for label.
  2. **The shape decision is a part.** Which values are subject to the proof is itself decided fail closed: syntactically, on every text every reader of the value parses (WHATWG's preprocessing with and without `http://`, an application's trim and percent-decoding, a C reader's NUL, an address parser such as `getaddrinfo`), for every value type that reaches the predicate (a JSON number by its text), and a value of uncertain shape is subject to the proof. A carve-out that admits without proof (a pure word, a small number, a type) is a stated residual with its measurement and its measured flip cost. Soundness is measured against more than one reader.
  3. **An admitted host is an explicit set of spellings every reader reads alike**, never "a reader reads it as loopback"; other spellings of the same address are outside, as stated false positives.
  4. **A generated sweep varies every part of the value** -- the authority's spelling in every form (bracketed and bare), the delimiter after it, the prefix before it, and the tail -- and is checked against the real readers at design time, with the measured readings embedded in the test. A sweep whose fixed parts pass a gate cannot test the gate. A delimiter or prefix varies over every character (printable ASCII, whitespace with tab, LF and CR, NUL, non-ASCII), never over the list the rule itself uses.
  5. **A rewrite of a safety predicate keeps what the predicate it replaces held**, proven by a non-regression corpus generated from the old rule's coverage with its expectation written out, or states each loss with its measured cost; "none the other way" is a measurement in both directions.
  6. **A predicate's cost is measured per point on every source of points** -- recorded stores, every lab answer key's leaves, the external labs' sources -- against the base and the previous version, and a guard keeps every lab's expected-vulnerable answer-key point unrefused (an allowance only with a stated reason).
  7. **A guard asserts its stated reason first**, and its pre-fix record names what it found (PA-0545(6) for guards); a guard of a guard is never counted as a reproduction.
  8. **A token's boundary is the complement of its alphabet, and a mark is the reader's whole rule.** A rule that reads a literal from a value (an address, a scheme) ends it at any character outside the literal's alphabet, never at a closed list of delimiters; a mark a reader accepts in several spellings (a special scheme followed by `//`, `/`, `\` or nothing) is held by the reader's rule, not by a list of the spellings at hand; and a rule written for a reader is applied to the text that reader parses (the raw value for an address parser, a shell or a splitting application). (from BUG-0555 and its review rounds 1 and 2)
  - Enforced by: tests/test_replay_bindings.py::test_the_lab_predicate_reaches_no_recogniser_of_hosts, tests/test_replay_bindings.py::test_the_recogniser_guard_catches_a_synthetic_offender, tests/test_replay_bindings.py::test_every_authority_spelling_outside_the_lab_set_is_outside_the_lab, tests/test_replay_bindings.py::test_the_binder_never_binds_an_authority_spelling_outside_the_lab_set, tests/test_replay_bindings.py::test_a_value_a_reader_takes_for_a_host_beyond_the_lab_set_is_outside, tests/test_replay_bindings.py::test_a_loopback_authority_the_recogniser_misses_is_still_outside_the_lab, tests/test_replay_bindings.py::test_every_value_the_old_scheme_anywhere_rule_put_outside_is_still_outside, tests/test_replay_bindings.py::test_a_value_holding_an_authority_mark_anywhere_is_outside_the_lab, tests/test_replay_bindings.py::test_a_bare_ipv6_literal_is_outside_the_lab, tests/test_replay_bindings.py::test_a_json_number_leaf_is_judged_by_its_json_text, tests/test_replay_bindings.py::test_no_expected_vulnerable_answer_key_point_is_unbound_by_the_lab_predicate, tests/test_replay_bindings.py::test_the_bare_token_rule_reads_ianas_root_zone_and_nothing_else, tests/test_replay_bindings.py::test_a_special_scheme_after_a_non_scheme_character_is_outside_the_lab, tests/test_replay_bindings.py::test_an_ipv6_literal_ends_at_any_character_outside_its_alphabet

- **PA-0557** — Strengthens `PA-0544(5)` and `PA-0533(2)`, after BUG-0557: the seam's bound send was checked against its page fetch's route, identity, generation and loss, but a LIVE health check adopts a rotated session cookie in place, in the same generation, so the send carried the old cookie's token on the new cookie and its 403 was read as a negative; a re-login's bound send was refused only after it had gone out (a stated residual). PA-0544(5) named the generation as the session, and its sweep listed the changers of the generation, not the writers of the material; PA-0533(2) bound evidence to the generation and the state object, which stay the same while the material changes.
  1. **A value obtained on a session is bound to the session's material, never to a name or a counter of it.** The material is every cookie and header the session layer applies, names and values, with its generation. Any change between the setup request and the send that uses its result -- a re-login, an isolated copy's re-login, a cookie a health check adopted in place, any future writer -- refuses the send (unbound, never a negative).
  2. **The check is made where the material is applied, before it is applied:** the session layer's `prepare`, told what the send must carry (SP-75, `material_frame(expect=...)`), so nothing goes on the wire. A check after the send is a fallback for a session addon that cannot be told, never a stated residual.
  3. **A sweep of a "same session" check lists every writer of the session's material** (every assignment to an installed state's cookies or headers), not only the events that renumber it; and the material is identified without holding a value (a keyed digest). (from BUG-0557)
  - Enforced by: tests/test_replay_bindings.py::test_a_live_health_check_that_adopts_a_rotated_cookie_after_the_fetch_unbinds_the_send, tests/test_replay_bindings.py::test_another_sends_policy_block_whose_check_adopts_a_rotation_unbinds_the_bound_send, tests/test_replay_bindings.py::test_a_pauses_live_recheck_that_adopts_a_rotation_unbinds_the_bound_send, tests/test_replay_bindings.py::test_a_bound_send_on_a_real_copy_relogged_in_after_its_fetch_is_never_sent, tests/test_replay_bindings.py::test_a_bound_send_on_a_session_relogged_in_after_its_fetch_is_unbound, tests/test_session_material.py::test_a_send_bound_to_its_fetchs_material_is_refused_after_a_live_check_rotates_it, tests/test_session_material.py::test_a_new_generation_with_the_same_cookies_is_other_material, tests/test_session_material.py::test_the_material_is_a_keyed_digest_never_a_value

- **PA-0558** — Strengthens `PA-0536(1)`, `PA-0549(3b)` and `PA-0545`'s consumer rule, after BUG-0558: the session manager's login fetcher was a plain `requests.Session()` under a guard allowance that deferred it to its owner, whose merge then bounded the health fetcher beside it and left it; BUG-0549's round-2 sweep counted it "fixed by construction"; and login discovery took an incomplete or failed page for "no login form here", charged to the re-auth cap. So a login read unbounded, a stray answer after the login page could become the credentials POST's answer, and an identity could be capped by answers never read whole. In the fix's review (round 1), letting the transport error propagate changed what `ensure` and `prepare` raise for every login caller, swept on the seam only: the seam's logins went uncapped, disco's recovery escaped its worker, the static crawl went on page by page, both CLIs ended in a traceback, and one cut candidate hid the others and the browser fallback.
  1. **The login handshake is a target exchange:** every fetcher the session layer makes is SP-60-bounded where it is made (ceilings, deadline, exact-framing pools); a send with a body takes a connection of its own (`PA-0549(3)`); an incomplete or failed answer is a failed fetch -- never a login answer, never "no form here", never charged to a re-auth cap -- and it reaches the caller as the session layer's own typed failure (`LoginFetchFailed`, a `SessionAuthError`), after every other candidate and the browser fallback had their turn, with its own cap of consecutive failures, so every caller's existing handler applies and a page that keeps failing ends loudly.
  2. **An allowance in a whole-package guard is a property of the code, not a deferral.** A site deferred to another owner is a strict xfail on its behaviour (`PA-0531(4)`) that the allowance names, and the owner's next change or merge touching that file fixes it or re-justifies it in its change-control entry.
  3. **A sweep verdict for a site cites the guard's finding for that site**, never the guard's general claim: a site on an allowance list is not "fixed by construction".
  4. **A change to what a function raises is swept by that function's callers, not by the consumers of the marker it carries** (strengthens `PA-0002` and CLAUDE.md item 7 for a function in no shared-primitive row): every caller is listed with its disposition, each measured by a test that drives that caller -- a seam, a recovery, a crawl, each CLI -- in the same change. (from BUG-0558 and its review round 1)
  - Enforced by: tests/test_bounded_reads.py::test_every_requests_session_fuzzlab_makes_is_bounded, tests/test_bounded_reads.py::test_the_session_managers_login_fetch_is_bounded, tests/test_bounded_reads.py::test_an_incomplete_login_page_is_a_failed_fetch_never_a_login_answer, tests/test_bounded_reads.py::test_a_stray_answer_after_the_login_page_never_reaches_the_credentials_post, tests/test_login_fetch_failed.py::test_a_seams_cut_login_page_costs_a_bounded_number_of_logins_then_stops_loudly, tests/test_login_fetch_failed.py::test_a_disco_recovery_whose_login_page_is_cut_ends_authenticated_exploration, tests/test_login_fetch_failed.py::test_a_static_crawls_relogin_on_a_cut_login_page_stops_the_crawl, tests/test_login_fetch_failed.py::test_greybox_reports_a_cut_login_page_as_an_authentication_failure, tests/test_login_fetch_failed.py::test_session_print_reports_a_cut_login_page_as_a_failed_login, tests/test_login_fetch_failed.py::test_a_cut_login_candidate_never_hides_a_form_at_another, tests/test_login_fetch_failed.py::test_a_cut_credentials_post_is_a_failed_fetch_never_a_rejected_login

- **PA-0559** — Strengthens `PA-0545(1)` and `(7)`, `PA-0134(1)`, `PA-0138(3)` (with SHARED_PRIMITIVES rule 2), in its review round 1 `PA-0123(3)`, and in its review round 2 `PA-0002` and its own items (6) and (7), and in its review round 3 its own items (7), (8) and (9), and after the owner's final round its own item (12), `PA-0536(1)` and `PA-0548(4)`, after BUG-0559: an identity browser crawl sent a load's redirect hop, a selector form's submission and the page's own `location` / meta-refresh jumps to a loopback alias its session cookie (host-only) does not reach, and filed the anonymous landing as the identity's page; the auditor's fetcher and disco's explorer did the same. BUG-0545 round 2 had checked the cookie's reach only where a load starts, with a predicate private to the spider, and merged the measured hop and form as residual R8; the guard every request passes decided by origin, which folds the aliases.
  1. **Where a session goes is decided per request, at the one owner every request of its carrier passes, never per load or per tool.** For a browser that is navguard's route, its WebSocket handler and `checked_api_request`: every navigation, redirect hop, subresource, socket and API request of a context that carries a session is checked there; a tool's load gate may refuse early, never instead.
  2. **A carrier is judged by its own rule.** A cookie reaches a host by RFC 6265's domain match (host-only: that host; a dotted domain: the names under it, never an IP), measured in the real browser; an origin rule that folds aliases decides scope and where the route's own headers go, never where a cookie goes.
  3. **A decision two tools must agree on is born in the owner, with a SHARED_PRIMITIVES row and a guard,** never as a private helper of the consumer that met the bug first; its PA-0002 sweep lists every caller of the owner (every guarded context that adopts a session, every API request with a storage state) with a measured disposition, and an AST guard holds the wiring for new callers.
  4. **A measured send of the bug's own class on a neighbouring path of the same carrier is never a residual.** It is fixed in the owner in the same item, or the item stops and the orchestrator decides; a brief's file scope does not override `PA-0545(1)`.
  5. **Each such path has a real-browser test on loopback** asserting that the unreached host received no request of any kind and that no anonymous landing was stored: a redirect hop, a form submission, a script's `location`, a meta refresh, a subresource -- for every tool that adopts a session.
  6. *(Review round 1, BA-3; strengthens PA-0123(3).)* **A guard that claims every request of a carrier passes it lists, by measurement, what the carrier sends without asking it** -- for a browser, what a page can make Chromium send on its own (speculation-rules prefetch and prerender, `<link rel=prefetch>`, preconnect), on each binary a tool may run (the full browser and the headless shell) -- and either confines each by every rule the guard applies (scope, the destructive rule, the session's reach), or proves it is never triggered, with a real-browser test that the target received nothing. A layer's coverage is never taken from its rule ("the launch arguments confine Chromium's own traffic" is a scope rule only), and a guard's docs never claim "every request" beyond what was measured. The consumers check what a load committed before they read it, as defence in depth behind the route.
  7. *(Review round 1, BA-1, BA-2.)* **A reach predicate's inputs are enumerated from the carrier, not from the bug's shapes:** every form the carrier holds a value in (a cookie by URL, by bare and dotted domain, an IPv6 literal with its brackets), every spelling the scope folds (all loopback aliases), and material that is not a credential (an ambient cookie a storage state holds for another host) -- each measured in the real browser and tested; and a caller that cannot name a session's credentials derives them from where the session starts, never "every adopted value is a credential" when one extra value refuses the session's own host.
  8. *(Review round 2, BB-3; strengthens item 6.)* **A guard against what the browser decides and sends itself sits at the browser's own egress, not where the page is read.** Every launch names the enforcer (`navguard.browser_launch_args`, SP-04): what Chromium sends past the route is refused, and the guard's exceptions are tickets issued only where the guard already checked that request (`admit_socket` in the socket handler, `admit_landing` at the route's redirect fulfil). Layers that read the page (its text, its DOM, an init script) are defence in depth only: the parser decodes a character reference and builds a closed shadow root after they looked, and a new spelling is never the fix. A measured send of the class that the chosen layer cannot see means the layer is wrong (item 4), not that a residual is stated.
  9. *(Review round 2, BB-2, BB-4(2); strengthens PA-0002 and item 3.)* **A sweep's "every X in `fuzzlab/`" is a search over the package, and an AST guard over the package holds it**, proven on a synthetic offender, with any exception named in the guard with its reason (`test_no_cookie_domain_is_compared_with_a_host_outside_the_owner`: one comparison of a cookie's domain with a host, `navguard.cookie_reaches`; `test_no_module_reads_a_response_body_as_strict_utf8`: one decoder, `navguard.decoded_text` -- a handler that must answer every request never decodes in a way that can raise). A sweep listed from the modules a lane has read is not a sweep.
  10. *(Review round 2, BB-1; strengthens item 7.)* **A credential set derived from material is tested at its boundary** -- material none of which is a credential (a state whose session lives in browser storage) -- as well as its cases; the empty set never stands for "all".
  11. *(Review round 3, the https redirect regression and tunnel reuse; strengthens item 8.)* **An exception a guard grants (a ticket) is measured against every way the browser uses what it admits** -- a certificate error's retry (a second connection), the keep-alive pool (a later request on the admitted connection), multiplexing (HTTP/2) -- on every scheme the tools carry, against a local server of that scheme when no lab has one: "not measured, no lab" is never a flag for a guard's own exception. The admission is bound to what it was granted for (one exchange of one landing), enforced where the browser sends, without weakening anything the browser verifies (no TLS termination, no certificate switch).
  12. *(Review round 3, BB-4; strengthens items 7 and 9.)* **Code fed a value the target writes is tested over the whole domain the library accepts for it**, generated (every codec name Python's registry knows, as a header and a `<meta>` label), through the real path (a real page through the route), and catches what that domain can raise; a guard against a hazardous call bans the class, not the instance found (every strict decode of a Playwright body: `.text()`, `.post_data`, `.post_data_json`), proven on synthetic offenders.
  13. *(After the owner's final round, the decoder regression; strengthens item 12, `PA-0536(1)` and `PA-0548(4)`.)* **When a value the target writes selects an implementation (a codec, a parser, a format), the selection is an allow-list of what the browser -- or the protocol's reference -- does, each entry measured, never what the library accepts minus what has failed; and its tests generate the hazard's whole input -- the selector and the data it runs on, at a size that shows a super-linear cost -- with a time budget, through the real path** (round 3 generated every label on small bodies: it bounded what can raise, not what can take time, and CPython's `punycode` decoder held the route past its timeout).
  14. *(At the gaps merge, the label parser; strengthens items 12 and 13 and `PA-0549(3c)`.)* **A pattern that reads a value the target writes runs in time linear in that value.** Two quantifiers that can take the same characters never sit side by side (`\s*["']?\s*` splits one whitespace run every way, and a lazy group before a trailing `\s*$` retries the run at every length); one character class takes the run. Its test feeds a long run of each repeated class to a child process under a time bound. The PA-0002 sweep for this class searches `fuzzlab/` for adjacent quantifiers over overlapping classes and measures each hit; a pre-existing instance outside the item is pinned by a strict xfail for its owner (BUG-0559, "The label parser").
  15. *(At the gaps merge's verification and its review; strengthens `PA-0403(1)` and `PA-0040`; from BUG-0559 and BUG-0555, sections "At the gaps merge's verification".)* **No commit is checked by a hand-picked list of test files** (CLAUDE.md step 2): a lane round's one pytest invocation and a coordinator's commit at a merge are `scripts/verify_change.py --base <the commit's parent>`, whose selection always holds every whole-package guard (`--list-only` prints it), and a brief that asks for a targeted run names that selection, never a list of the changed modules' importers. PA-0403(1) named the right set but was applied only at the push gate: five times (F-157, F-164, F-198, F-244, F-245) a commit checked by its own tests failed a whole-package guard at the next harness run, a full cycle each. **A helper a fix needs is first looked for in the owner, and reused only where its inputs and contract match** (the session manager's `_host_url` is not `parse_auth_origins`' `as_url`: a `host:port` is a usage error there and a host to match here). The selection is enforced by the test named below; its use at each commit is a process rule no test can see (the push gate finds a miss only afterwards).
  - Enforced by: tests/test_browser_session_reach.py::test_every_context_that_adopts_a_session_hands_its_cookies_to_the_guard, tests/test_browser_session_reach.py::test_the_reach_guard_catches_synthetic_offenders, tests/test_browser_session_reach.py::test_a_cookie_reaches_its_own_host_or_a_name_under_its_dotted_domain_never_an_ip, tests/test_browser_session_reach.py::test_the_route_refuses_every_request_and_hop_to_an_unreached_host_before_it_is_sent, tests/test_browser_session_reach.py::test_a_redirect_hop_to_a_host_the_cookie_does_not_reach_is_never_sent, tests/test_browser_session_reach.py::test_a_selector_form_whose_action_the_cookie_does_not_reach_is_never_submitted, tests/test_browser_session_reach.py::test_a_page_navigating_itself_to_a_host_the_cookie_does_not_reach_stays_its_own, tests/test_browser_session_reach.py::test_the_auditors_browser_fetcher_never_audits_an_unreached_host_as_the_identity, tests/test_browser_session_reach.py::test_disco_never_explores_an_unreached_host_as_the_storage_states_session, tests/test_browser_session_reach.py::test_no_speculation_rules_preload_leaves_a_guarded_context, tests/test_browser_session_reach.py::test_every_guarded_context_neutralises_preloads_before_its_pages_run, tests/test_browser_session_reach.py::test_the_route_gives_no_speculation_rule_set, tests/test_browser_session_reach.py::test_the_auditors_fetcher_and_the_spider_never_preload_the_alias, tests/test_browser_session_reach.py::test_a_preload_past_the_guard_is_never_read_as_the_identitys_page, tests/test_browser_session_reach.py::test_disco_never_reads_a_state_or_a_protected_resource_on_an_unreached_host, tests/test_browser_session_reach.py::test_an_ipv6_cookie_as_chromium_holds_it_reaches_its_own_host_and_no_other, tests/test_browser_session_reach.py::test_a_storage_states_ambient_cookie_on_another_host_never_refuses_its_start_host, tests/test_browser_session_reach.py::test_disco_explores_its_start_host_with_a_storage_state_that_holds_an_alias_cookie, tests/test_browser_session_reach.py::test_no_preload_a_page_hides_from_the_guard_leaves_the_browser, tests/test_browser_session_reach.py::test_the_enforcer_refuses_what_the_browser_sends_itself_and_tunnels_admitted_sockets, tests/test_browser_scope.py::test_the_launch_args_alone_confine_an_unrouted_page_to_the_origin, tests/test_browser_session_reach.py::test_no_cookie_domain_is_compared_with_a_host_outside_the_owner, tests/test_browser_session_reach.py::test_no_module_reads_a_response_body_as_strict_utf8, tests/test_browser_session_reach.py::test_a_storage_state_profile_sends_the_cookies_a_browser_would_send, tests/test_browser_session_reach.py::test_a_storage_state_is_adopted_by_where_its_cookies_reach_the_scope, tests/test_browser_session_reach.py::test_a_guarded_page_loads_a_document_in_a_legacy_charset, tests/test_browser_session_reach.py::test_a_storage_state_whose_session_no_cookie_carries_never_refuses_its_start_host, tests/test_browser_session_reach.py::test_disco_explores_its_start_host_with_a_local_storage_session_and_an_alias_cookie, tests/test_browser_session_reach.py::test_no_charset_label_a_target_writes_makes_the_decoder_raise, tests/test_browser_session_reach.py::test_a_guarded_page_loads_a_document_whatever_charset_it_names, tests/test_browser_session_reach.py::test_a_legacy_charset_forms_submission_is_seen_carrying_its_value, tests/test_browser_session_reach.py::test_an_https_landing_and_socket_load_from_a_self_signed_target, tests/test_browser_session_reach.py::test_no_request_rides_an_https_landings_tunnel_after_its_exchange, tests/test_browser_session_reach.py::test_the_enforcer_holds_an_https_tunnel_to_its_ticket, tests/test_browser_session_reach.py::test_a_charset_label_decodes_only_by_an_encoding_a_browser_defines, tests/test_browser_session_reach.py::test_a_request_body_is_read_whatever_charset_it_names_within_its_budget, tests/test_browser_session_reach.py::test_a_charset_label_after_a_long_whitespace_run_is_parsed_in_linear_time, tests/test_verify_change.py::test_guards_are_always_selected_even_for_no_package_change

- **PA-0560** — Strengthens `PA-0511` and `PA-0150`, after BUG-0560. A writer-thread test waited until the history writer's rows were visible, then read its counter at once. The writer moves the counter only after the rows' commit and the trace events' commit, so a 0.3 s delay between them failed the test 5 of 5 times. The test's poll helper cited PA-0511, which covers absence claims only. PA-0150 was enforced only by the test it fixed. PA-0550 never stated the order in which the writer publishes.
  1. **A wait on a concurrent actor proves only the value it polled, and what the actor published before that value.** A test that reads several of an actor's results waits on the one the actor publishes last, or on the actor's own drain or close, and only then reads the others. A read that the wait did not cover is a race, however short its window, and is never called "flaky".
  2. **When an actor publishes one unit of work in several steps, the steps are written down in order next to a guard over its tests.** The guard flags a read of a later step after a wait on an earlier one. It is proven on the bug's own lines and on synthetic offenders (`PA-0034(2)`). The proxy history writer's order is rows, trace events, `stats`, `run_metrics` (`_PUBLISHED`). Its guard covers every test module that drives `HistoryWriter` or `ProxyController`.
  3. **The sweep goes by the actor's publications, not by the failing assertion** (this strengthens `PA-0002` for test oracles). It reads every value of the actor that a test reads after a wait. (from BUG-0560)
  - Enforced by: tests/test_proxy_history_writer_thread.py::test_no_history_test_reads_a_later_publication_than_it_waited_for, tests/test_proxy_history_writer_thread.py::test_the_read_after_visible_guard_on_synthetic_code, tests/test_proxy_history_writer_thread.py::test_a_batch_is_cut_by_age

- **PA-0556** — Strengthens `PA-0514(2)` / `PA-0521(1)` (from the trace's redactor to the owner every sink calls), `PA-0544(7)` (a recipe's "strongest redactor" is itself tested), `PA-0085(2)` / `PA-0091(1)` (from names and shapes to positions), in its review round 1 `PA-0002` (a sweep measured per caller) and `PA-0544(1)/(3)` (a redacted endpoint query is replay material), and in its review round 2 `PA-0530(5)`, `PA-0545(6)` and `PA-0135(3)` (followed by mechanism, not by the named spelling, test or caller), and after the owner's final round its own item 7 (a fix proven forward only), and in r4 its own item 8 (a differential over inputs its author chose), and in r5 its own items 8-9 (a differential against the batch's own history, never the pushed tree), and in r6 its own items 8-10 (a differential's enumeration of what the replaced code did, which no round could prove complete), and in its r6 review **narrows `PA-0549(3c)`** to its owner's reading (the owner's rule for this batch and F-226's correction: "a defect a sweep finds in an unpushed change of the same batch" is a regression against the pushed tree; a leak the pushed tree also has is pinned, whichever unpushed revision redacted it), after BUG-0556: the URL and sibling redactors judged a query value as one flat token and a query as one level of `&` pairs, so a token nested in a URL or query string inside a value (raw or percent-encoded), behind a `;`, or in a middle segment's `;jsessionid=` reached `page.url`, `parameter.example`, `form.entries`, a replay recipe's `source_page` and, by name, proxy history. BUG-0514/0521 had fixed the same flat model inside `core.trace` only; `parameter.example`'s raw values were a reserved bug (BUG-0120) asserted in a test as "still needed".
  1. **A redactor models a value as possibly structured.** Wherever a value can sit in a URL (a query pair, `&` or `;` separated; a path parameter; a query-shaped fragment) the owner walks it as a nested URL, a query string or a percent-encoded layer, to a stated depth and size bound, and redacts the whole top-level value past the bound or on any failure.
  2. **A redaction test is generated over position as well as name and shape:** nesting depth, encoding (raw, single and double percent-encoding, `+`), separator (`&`, `;`, mixed) and path parameters; each case is searched for every secret run in every stored copy and in every decoding, and a benign list is asserted byte-identical.
  3. **A redaction gap found in one sink is fixed in the owner** (SP-17 rule 1), and its sweep lists every writer of that kind of value with its disposition. A writer storing a value outside the owner's rule is a defect; a known one is pinned by a strict xfail, never asserted as "by design".
  4. **A sweep of an owner's callers is measured, not read** *(review round 1)*. Each caller's disposition cites a test that drives a secret through that caller and searches what it stored or sent. A caller that decides *whether* the owner runs (a `"?" in target` gate, a branch handling part of the value itself, a writer of the same kind of value that calls no owner) is part of the owner's coverage: the sweep lists every writer of the kind of value, not every call of the owner.
  5. **A generated redaction sweep includes what real encoders produce, measured** *(review round 1)*: Python's `quote()` default `safe="/"`, `quote(safe="/:")`, a framework's redirect helper. Its positions include every place the owner's other boundaries already treat as a credential (a URL's userinfo).
  6. **A redaction that changes what a request sends is a replay change** *(review round 1)*. The sweep records, per writer, whether its stored value is sent as the request's own. A value redaction replaces there is recorded as a placeholder by name and its test refused (`UNBOUND`), never sent blank (PA-0544(1)/(3)). Each test's pre-fix proof is on its own assertion (PA-0545(6)), and a complexity oracle is proven on a deliberately quadratic variant (PA-0135(3)), before a round is reported.
  7. **A fix is made to the mechanism, not the spelling** *(review round 2, after a third pass at the same class: every round-1 fix held for its repro while the same mechanism stayed open next to it)*. Before a round is reported, the fix's neighbouring paths are enumerated by mechanism and each gets a test that fails on the pre-fix code: every piece the walk reads (an authority, a path segment, a fragment route, a pair list holding a URL); every place a URL can start inside a value, as the real parser reads it (measured: WHATWG's `https:///`, backslashes, a leading space), and every place the owner's other rules already call a credential; every caller of a producer whose output changed, by grep of its name (PA-0530(5)); every value of a repeated field (a duplicate header) and every field of the kind (every URL-bearing header); every split a caller makes before the owner sees the value (whitespace, a single-space request line); every way a writer quotes a value (a substring, judged on the whole value, never a list of cut lengths). PA-0545(6)'s proof covers every test of the file, run on the pre-fix code with its failure type recorded, and a complexity oracle counts the C-level work of every call (decodes, encodes, splits, pattern searches) on an input per part of the code, its offenders never reporting their own work. (from BUG-0556 and its review rounds 1-2)
  8. **A fix is proven not to remove what the code did before** *(after the owner's final round: round 2's item-7 tests all asserted that more was redacted, and none compared its walk with f939778's, so a regex class that stopped at whitespace, a replacement moved before the split and two value shapes routed elsewhere kept secrets f939778 redacted; the fix check found one, a generated differential 6 313 cases in four classes)*. Before a round is reported, the changed owner's output is diffed against the pre-fix revision's by a generated differential over every consumer (each redactor, the clean-page test, the stored-value rule, the record and proxy callers): a case clean before and kept after is a regression of the batch, fixed in it (PA-0549(3c)), each class with a test that fails on the round's own pre-fix revision; a benign differential shows clean inputs unchanged. A test that changes a shared fixture or helper re-runs the PA-0545(6) sweep over the whole file afterwards (round 2's last commit changed `_audit_store` after its sweep and masked three tests again). (from BUG-0556, after the final round) *(Amended at the merge, owner-approved; F-226, F-248.)* **The regression bar is the pushed tree:** a case the pushed tree redacted and the change keeps is the batch's regression, fixed in it; a case a pre-fix revision of the batch redacted and the change keeps is information, reported with its family, never a bar (what the pushed tree also keeps is pinned, item 11).
  9. **A differential's inputs are derived from the change, not chosen** *(r4: r3 followed item 8, and its differential of 90 720 + 12 600 URLs "regressed none", but its prefixes were the author's list and held no value led by `\\` or `\/` -- the very leads r3's change kept URL-shaped while reading no authority in them, so `next=%5C%5Cx%26password%3D<word>` was kept by every URL consumer, where f939778 had redacted it; a skeptic found it, and the same sweep extended with those leads counts 5 607 regressed cases)*. The differential item 8 requires drives, for every condition the change adds or alters (each literal a changed predicate tests: a prefix, a character class, a separator, a branch), at least one input on each side of it, in every encoding and position the sweep has, and the round's report lists those conditions with the inputs that cover them. A claim that a listed spelling "was redacted before" is measured on the pre-fix revision per spelling, never inferred from its group (r3 listed three spellings f939778 kept as regressions). (from BUG-0556, r4)
  10. **A differential's baseline is the pushed tree, and its inputs drive the pushed code's own parsing** *(r5: items 8 and 9 were followed against f939778 and 20cd466, the batch's own revisions, which already held the walk the first commit put in place of the pushed tree's `redact_query` and `urlsplit`; so a reading the batch dropped on its first day -- an `&` part holding a `;` read as one pair, a tab, CR or LF removed before a name is read -- was on both sides of every comparison: 4 366 URLs of a 214 352-URL differential were kept by 290fcfb and redacted by 7393c90)*. Every round's differential also runs against the pushed tree (the last revision users have), whatever its own pre-fix revision is, and reports the leaks at the revision that the pushed tree redacted (fixed in the batch, PA-0549(3c)), the leaks at both (each assigned to a family and pinned by a strict xfail, or stated with its reason) and the fixed. Its corpus drives the pushed code's own parsing as well as the change's conditions (item 9): each library parse the replaced code called (`urlsplit`: tabs, CRs and LFs removed; scheme and netloc rules) and each separator it split on (`&` only), on both sides of each. (from BUG-0556, r5)
  11. **A redactor's fix is layered on the pushed redactor** *(r6: items 8-10 each extended a differential's enumeration of what the replaced code did, and each round the next behaviour left out regressed: r5 followed item 10 and measured 0, and an independent check of 144d234 found 2 104 URLs it kept that 7393c90 redacted, in five behaviours no corpus had driven -- `safe_ref`'s order of steps, the record redactor's whitespace split, `Refresh`'s every `url=` run, a raise its callers read as "withhold", a duplicate header's collapse)*. A change to a redactor users already have never replaces it: the pushed code is kept, frozen verbatim in a module nobody edits (its text pinned to the pushed commit's), every consumer runs it first on its input as received and the change only on its output, so no secret the pushed code redacted can leak, by construction, whatever behaviour of it nobody enumerated. Where the pushed code raised, the consumer raises and each caller does what it did then (the proxy history writer stores the flow with its bodies omitted and its URL cut at the first `?`, so a path parameter before it is kept: family (d), pinned); a caller the change added withholds the value itself (its own marker) and should not fail its batch (`import_audit` withholds every text of a page `urlsplit` rejects, with or without a `?`, since the merge's follow-up; it judges the page by `urlparse` as well as by the floor). What the change cannot see in the pushed code's output (information that output lost), when the pushed code leaks it too, is pinned by a strict xfail with its candidate rule stated, never another design round; the differential of items 8-10 still runs, to report the gains and the pins' families. *(r6 review: the floor's guards missed a decorator, a re-binding after the `def`, a text parameter the registry did not name and every use that was not a call by an imported name; `import_audit` raised on a page the pushed import read; a raise was counted as redacted while the history writer's fallback stored the URL before its `?`.)* The floor's guards model the bindings and references listed here -- a definition's decorators are part of its frozen text; a layered consumer is bound once, undecorated, never re-bound, and reads none of its text parameters (every positional one) after its floor except as a predicate's argument; any reference to the walk or the floor, by any import form or a literal `getattr`, is a use -- state what they cannot see -- a same-name rebinding in another scope, a rebinding of a trusted predicate name, star imports, keyword-only text parameters, literal-name reflection, a shadow package replacing the floor module, a name computed at run time (FR-CORE-537; stated at the merge) -- instead of claiming it, and are proven on an offender of each kind. Where the floor raises, each caller's fallback is measured for what it stores, never counted as redacted; and the round's sweep drives every URL a caller the batch changed reads (each `import_audit` text and page) through that caller. (from BUG-0556, r6 and its review)
  - Enforced by: tests/test_redaction_floor.py::test_the_floor_is_the_pushed_trees_code_verbatim, tests/test_redaction_floor.py::test_the_frozen_check_flags_an_edited_floor, tests/test_redaction_floor.py::test_every_url_redaction_consumer_runs_its_floor_first, tests/test_redaction_floor.py::test_the_layering_check_flags_a_consumer_that_skips_its_floor, tests/test_redaction_floor.py::test_no_function_runs_the_walk_or_the_floor_unregistered, tests/test_redaction_floor.py::test_the_registry_scan_flags_an_unregistered_walk_or_floor_call, tests/test_redaction_nested.py::test_every_nested_spelling_of_a_secret_is_redacted_and_the_url_stays_a_url, tests/test_redaction_nested.py::test_no_generated_spelling_reaches_the_store_through_import_spider, tests/test_redaction_nested.py::test_no_generated_spelling_reaches_the_store_through_import_disco, tests/test_redaction_nested.py::test_proxy_history_and_the_http_recorder_store_no_nested_credential, tests/test_redaction_nested.py::test_ordinary_nested_values_are_left_byte_identical, tests/test_redaction_nested.py::test_a_layer_left_encoded_behind_a_raw_slash_is_decoded_wherever_it_is_read, tests/test_redaction_nested.py::test_a_nested_urls_userinfo_is_a_credential_in_both_redactors, tests/test_redaction_nested.py::test_import_audit_stores_the_spiders_endpoint_and_no_secret, tests/test_redaction_nested.py::test_proxy_history_redacts_a_path_parameter_in_a_message_with_no_query, tests/test_redaction_nested.py::test_a_project_record_redacts_a_credential_nested_in_a_route_fragment, tests/test_redaction_nested.py::test_an_endpoint_query_redaction_changed_is_never_sent, tests/test_redaction_nested.py::test_the_linearity_oracle_flags_a_quadratic_walk, tests/test_redaction_nested.py::test_a_review_round_2_spelling_is_redacted_by_every_url_redactor, tests/test_redaction_nested.py::test_the_review_round_2_spellings_store_no_secret_through_import_spider, tests/test_redaction_nested.py::test_proxy_history_redacts_every_url_bearing_header_and_any_request_line, tests/test_redaction_nested.py::test_a_project_record_walks_a_url_holding_a_raw_space_whole, tests/test_redaction_nested.py::test_import_audit_redacts_a_quoted_substring_of_a_secret_value, tests/test_redaction_nested.py::test_import_audit_stores_a_page_as_the_spider_does_when_the_first_finding_is_off_origin, tests/test_redaction_nested.py::test_greybox_never_sends_a_point_the_builder_refused_or_a_placeholder, tests/test_redaction_nested.py::test_an_in_batch_regression_spelling_is_redacted_by_every_url_consumer, tests/test_redaction_nested.py::test_an_in_batch_regression_spelling_stores_no_secret_through_import_spider, tests/test_redaction_nested.py::test_a_raw_single_backslash_pair_list_is_redacted_by_every_url_redactor, tests/test_redaction_nested.py::test_a_project_record_strips_a_top_level_userinfo_holding_a_space, tests/test_redaction_nested.py::test_a_backslash_led_authoritys_pair_list_is_redacted_by_every_url_consumer, tests/test_redaction_nested.py::test_a_backslash_led_authoritys_pair_list_stores_no_secret_through_import_spider, tests/test_redaction_nested.py::test_a_clean_backslash_led_value_is_left_byte_identical, tests/test_redaction_nested.py::test_a_secret_the_pushed_tree_redacted_is_redacted_by_every_url_consumer, tests/test_redaction_nested.py::test_an_identifier_the_pushed_tree_read_whole_is_redacted_by_every_identifier_consumer, tests/test_redaction_nested.py::test_the_amp_reading_never_replaces_the_semicolon_reading, tests/test_redaction_nested.py::test_a_clean_semicolon_part_or_tab_is_left_byte_identical, tests/test_redaction_nested.py::test_r6_review_d1_import_audit_imports_a_page_no_origin_reads_as_the_pushed_tree_did, tests/test_redaction_nested.py::test_r6_review_r4_import_audit_withholds_the_texts_of_a_page_its_floor_rejects
