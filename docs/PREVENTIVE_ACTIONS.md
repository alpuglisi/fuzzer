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
