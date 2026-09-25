# Preventive actions

The active rules to follow while working on this project. Each is a preventive
action from a bug investigation (`docs/bugs/`). No background here by design —
read this list and follow it. Consult it before and during changes.

**Following this list is mandatory, not advisory.** It is one step in the full
change process; see `CLAUDE.md` (the session-start checklist) for how it fits with the
changelog, change-control, error-log, and bug-report requirements.

Format: `PA-NNNN — <rule>. (from BUG-NNNN)`

- **PA-0001** — In tests, do not hardcode a value that a source-of-truth constant
  or registry in the code already defines (schema head version, `FEATURE_VERSION`,
  enum members, etc.); derive the expectation from that source. Reserve literal
  expected values for genuinely fixed external contracts. (from BUG-0001)
- **PA-0002** — When a bug investigation adds a preventive action, sweep the whole
  codebase for existing instances of that bug class and remediate them (or record
  why not) — do not fix only the instance that triggered the investigation. (from
  BUG-0002)
- **PA-0003** — A storage or serialization convention that must hold across more
  than one writer lives in exactly one shared function that every writer calls at
  the write site — not as a per-writer private helper, and not as a convention
  stated only in prose. New writers of the same column/field go through that shared
  function (e.g. result URLs are stored in path form via `fuzzlab.core.urls.to_path`).
  (from BUG-0003)
- **PA-0004** — A committed default that selects an external identity, credential, or
  endpoint must be a value the target actually accepts **and** must match what the lab
  provisions (compose / `.env` / schema) — not a developer's local assumption. And
  when an incident is resolved only by an environment workaround (an `ERROR_LOG` entry
  marked `Environment`), still fix the repo default that caused it, so a fresh checkout
  does not reproduce it. (from BUG-0004)
- **PA-0005** — Every library imported at runtime — including one pulled in by a
  third-party backend the code instantiates — must be a **declared** dependency; never
  assume a different installed library satisfies another's requirement (e.g.
  `cryptography` does not provide PyCrypto's `Crypto`). And a real code path that test
  doubles bypass everywhere must still have at least one test exercising the real
  implementation (skippable when it needs an environment feature) or a documented
  on-host smoke check, so fresh-install / first-use failures are caught before a user
  hits them. (from BUG-0005)
- **PA-0006** — An integration/pipeline test must feed inputs shaped like what the
  real upstream produces; do not hand-populate a field the live path does not set at
  that stage (e.g. a post-detection label like `sink_context` on a freshly-discovered
  point) to make a downstream step succeed — that masks a wiring gap. A rule or step
  keys only on what is available at its stage; anything derived later belongs to the
  stage that derives it. (from BUG-0006)
- **PA-0007** — Never infer authentication or authorization success from the mere
  presence of an *ambient* credential the server also issues to anonymous users (a
  session cookie set by `session_start()`, an ambient CSRF/anti-forgery token, etc.).
  Require a *positive differential* signal that the protected action actually succeeded
  — the login response left the login page behind, a page that is `401/403` when
  anonymous now returns `2xx`, or an identity-specific marker is present. Test fixtures
  for auth/detection code must reproduce the server's ambient state (e.g. a pre-login
  anonymous cookie), not only the happy path, or a broken success path looks healthy
  (a recurrence vector of PA-0006). (from BUG-0008)
- **PA-0008** — Gate optional behavior on the **authoritative capability probe**, not on
  a fragile name string. To detect a native extension use `extension_loaded('x')` (not
  `function_exists('\x\fn')`, whose leading-backslash namespaced form is unreliable);
  likewise prefer the direct capability check over stringly-typed name lookups elsewhere.
  A misfiring guard silently degrades to "feature off / no signal", which is hard to spot.
  (from BUG-0009)
- **PA-0009** — A build or deploy step that provisions a runtime capability (compiling/
  installing an extension, a package, a binary) must **verify it is actually usable in the
  same step** — e.g. `pecl install x && … && php -m | grep -qi '^x$'` — so a broken or
  cache-stale layer fails the build, not a later run. Install the toolchain the build
  needs (e.g. `$PHPIZE_DEPS` for PECL) rather than assuming it is present. (from BUG-0009)
- **PA-0010** — When an API takes a filter/selector argument, confirm the expected
  **granularity** (file vs directory vs prefix vs glob) before passing it — a
  wrong-granularity argument commonly returns a silently-empty result rather than an
  error (e.g. handing pcov's file-list filter a directory). And verify the actual
  produced **signal** end to end, not just that the dependency is present: "loads ≠
  works" — a self-test that inspects the real output catches what a presence check
  cannot. (from BUG-0009)
- **PA-0011** — X.509 certificates generated for TLS must carry the extensions strict
  verifiers (modern OpenSSL, browsers) require: a CA with a Subject Key Identifier and a
  keyCertSign KeyUsage; a leaf with a Subject Key Identifier, an Authority Key Identifier
  that references the issuer, a serverAuth Extended Key Usage, and a SAN of the correct
  type (IPAddress for IP hosts, DNSName otherwise). Assert the generated cert's extensions
  and verify it against a real chain check in a test — even one skip-guarded to the
  environment that has a working crypto backend. (from BUG-0010)
- **PA-0012** — Tearing down an `asyncio` server must be bounded and must not assume
  `wait_closed()` returns once the listener closes: on Python 3.12+ it also waits for
  active connections, which for a long-lived server may never end. Track and cancel
  in-flight connection tasks on stop and wrap the final wait in a timeout. Persist
  important state as it is produced (not only on graceful shutdown), so a forced/abrupt
  stop loses nothing. (from BUG-0011)
- **PA-0013** — A self-test assertion must reflect the **true contract of the system under
  test**, not an intuitive-but-wrong premise (e.g. only *conflicting* Content-Length is
  invalid; duplicate-*identical* is valid per RFC 7230). An on-host / integration self-test
  must use the same construction the validated offline test proved — never a weaker or
  hand-rolled variant that asserts something the offline test did not establish. (from
  BUG-0012)
- **PA-0014** — Do not rely on compose behaviors that differ between `docker compose` and
  `podman-compose` — chiefly in-place recreate on a config/env change, which
  podman-compose cannot do. Orchestration that changes env/profile on a running stack must
  be self-healing: on failure, tear the stack down (keep data volumes), force-clear wedged
  containers/pod/network under podman, and retry. And when a provider/environment incident
  is fixed in place, still record a PA for the *class* — closing it as a one-off leaves the
  class unguarded and it recurs. (from BUG-0013)
- **PA-0015** — Operational / runbook documentation must be written from an **executed,
  verified run**, not from design intent. A step whose on-host last-mile code is not yet
  built and self-tested is tagged `[design]` and must **not** be presented as a followable
  command sequence; it becomes `[run]` only once its code exists and a self-testing script
  (that fails loud) proves the exit. Commands and expected outputs in a `[run]` step must be
  ones actually produced, and any step that changes host state or sends traffic ships with
  such a script. If the build environment cannot execute the steps (no lab/host), say so and
  keep them `[design]` until validated on the host. (from BUG-0014)
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
- **PA-0017** — An exit criterion or self-test metric must **isolate and measure the
  specific capability it claims to prove**, via a controlled comparison (e.g. an
  attack-vs-its-own-baseline differential), not a proxy dominated by unrelated work (a
  global frontier the control fills first; a total-requests count dominated by discovery).
  A passing self-test is not sufficient if the metric doesn't reflect the capability, and a
  diagnostic/NOTE must key on the actual condition it names (e.g. "no coverage captured" ⇒
  coverage-seen == 0), not a derived artifact. (from BUG-0016)
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
- **PA-0019** — When a turn's work produces a finding that matches an artifact's stated
  scope for what it records (e.g. `ERROR_LOG.md`'s "anything that broke and was fixed"),
  add that artifact's entry in the same turn, checked against the artifact's literal scope
  statement — never inferred from whether the finding *feels* bug-shaped, and never treated
  as satisfied merely because the finding is also written up elsewhere (a spike report, a
  design doc, a playbook). Before ending any turn that involved running something and
  hitting unexpected behavior, re-read the relevant bookkeeping artifacts' own scope lines
  as a checklist item, not as background context absorbed once at session start. (from
  BUG-0018)
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
- **PA-0021** — PA-0003's obligation (a storage/serialization convention shared by more than
  one writer or reader lives in exactly one shared function every participant calls) applies
  to **every** such convention in the codebase, not only the one it was originally written
  against. Before adding a second, independent derivation of a value another path already
  stores or parses (credential keys, cache keys, identifiers, normalized hosts/URLs/paths),
  check whether a shared normalization function already exists for it. And a validation
  module that raises a typed error for some failure modes must raise that same typed error
  for every foreseeable failure at its boundary (e.g. a missing file/directory) — never let
  the underlying OS/library exception propagate raw. (from BUG-0007)
- **PA-0022** — Any keyword/substring match used as a mechanical heuristic (a hook, a lint
  rule, a build gate) must anchor on word boundaries (`\b`) unless a bare substring is
  specifically intended, and must be checked against the project's own routine vocabulary
  (changelog/commit-message conventions, common English words) for accidental collisions
  before being trusted to run unattended — e.g. grep the heuristic's own keyword list
  against a sample of ordinary, incident-free commit messages/diffs and confirm zero
  matches. (from BUG-0020)
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
- **PA-0024** — Whenever an emitter's (or any capability-registry-driven component's)
  "supports this shape" declaration is widened to accept a new case, the same change must
  exercise **every** existing record (manifest cell, config entry, etc.) that could newly
  match that shape — not only the new record the change was written for — as a standing
  test, not a one-time manual check. A per-shape capability registry and a per-record
  metadata registry that must stay in lockstep is a recurring shape of this bug class:
  before landing such a widening, add or extend a whole-collection regression test (e.g. a
  "render every cell of every existing manifest" test) rather than relying on tests scoped
  to the new record alone. (from BUG-0022)
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
  authorized*). (from BUG-0029)
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
- **PA-0041** — When a project maintains more than one implementation of the
  same seam/protocol (e.g. `fuzzlab.oracle.probe.Sender`: `SeamProbeSender`
  and `RequestsProbeSender`), a security-relevant transport setting adopted
  in one implementation (redirect-following, TLS verification, timeout
  behavior, etc.) must be applied to every other implementation of that same
  seam in the same change, not left to be discovered independently
  per-implementation the first time a vuln class that happens to exercise it
  is built. (from BUG-0039)
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
