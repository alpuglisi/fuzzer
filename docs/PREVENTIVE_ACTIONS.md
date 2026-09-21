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
