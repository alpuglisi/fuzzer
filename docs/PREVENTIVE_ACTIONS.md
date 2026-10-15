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

- **PA-0402** — A test-suite guard that observes the filesystem is bounded to what the suite
  owns, after BUG-0402: the store guard walked the whole invocation cwd and reported tests'
  own temp stores.
  1. **It walks the repository tree only**, never a directory it does not own (the cwd, home,
     the temp area); for those it checks named files, never a walk.
  2. **It excludes the test framework's own scratch area** (pytest's basetemp).
  3. **Its tests run it from a cwd outside the repository and with the basetemp inside the
     walked tree.** (from BUG-0402)

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

- **PA-0454** — Strengthens `PA-0108` and `PA-0101(2)`, after BUG-0454: a deeply nested or
  oddly typed value in a project file from someone else crashed the project pages.
  1. **Every value read from a store or file that can come from someone else is typed at
     one parser before use**: its storage type checked (SQLite does not enforce a declared
     column type), its size capped, JSON parsed with `RecursionError` handled; an odd value
     reads as missing or malformed — never fabricated, never an exception.
  2. **A fix for one parser-limit crash is swept across every parser of the same input
     source in the same change** (PA-0002 applied at fix time, not later). (from BUG-0454)

- **PA-0455** — Strengthens `PA-0101`, after BUG-0455: the record redactor truncated a
  value before stripping its URL userinfo, so a credential straddling the cut was kept.
  1. **A redactor never applies a lossy transformation (truncation, decoding, splitting)
     before the redaction that depends on the whole value**; bound the work with
     linear-time redaction first and cut last.
  2. **Every bound a redactor introduces is tested with a secret straddling it.** (from
     BUG-0455)

- **PA-0456** — Strengthens `PA-0131` and `PA-0453`, after BUG-0456: the definition check
  compared whitespace-normalised text (`str.split()`), and a definition SQLite reads
  differently (a U+00A0 inside an identifier, a moved `--` comment end) compared equal.
  1. **An equality or allowlist check over untrusted input compares the raw form, byte for
     byte,** unless a normalisation is the consumer's own (its tokenizer or parser) — never
     a convenience transform from another grammar.
  2. **Its tests include inputs that differ only in what the consumer treats as
     significant** (non-ASCII spaces, comment boundaries, quoting), each with a
     non-vacuity step proving the consumer reads them differently. (from BUG-0456)
