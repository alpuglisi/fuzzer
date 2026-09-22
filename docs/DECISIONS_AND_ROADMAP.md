# Decisions and Roadmap

Living document. It records the settled design decisions for the toolkit and the
phased plan to build it. Update it when a decision changes; do not silently
diverge from it.

*Last updated: 2026-09-21.*

**Related documents:** `docs/ARCHITECTURE.md` (component map and dependencies),
`docs/ml-tooling-research-prompt.md` and `docs/app-scaling-research-prompt.md`
(research prompts), the external ML & tooling research report that informed these
decisions, `CHANGELOG.md`, and `ERROR_LOG.md`.

## Purpose and scope

A modular, Python security-testing toolkit run locally against our own
deliberately vulnerable lab application ("Ryder's Puppy Fort Factory"). This is
authorized, educational security research on infrastructure we own. Everything
runs against localhost. The toolkit is **lab-only** and is not intended to be
pointed at third-party systems.

## Settled decisions

### D1 — Purpose: a sharp toolkit and learning platform for our own lab

We optimize for finding our lab's known (and planted-unknown) vulnerabilities
efficiently and for learning, not for a general black-box scanner that must work
on unseen apps.

- **Consequences:** grey-box instrumentation is in scope (see D7); evaluation
  means "did it find the planted bugs in fewer requests"; overfitting to the lab
  is acceptable for now; generalization is deferred to a later validation against
  a second, differently-built target app.

### D2 — Posture: research platform first, evolving into a tool

Start with the instrumentation, versioned data, and controls of a research
platform, then grow usable-tool ergonomics on top. The diagnostics are needed to
verify functionality and locate bugs.

- **Consequences:** the first work is foundations (shared store, versioned
  features, request-budget meter, structured logging, an integration test
  harness), not the flashy components. Keep that layer lean so it does not become
  a project of its own.

### D3 — Build order: session manager first, then the proxy

The session manager is small, everything downstream depends on it, and a silent
session expiry poisons every dataset. The proxy is a multi-week build nothing
else strictly requires.

- **Consequences:** after foundations, build the session manager; the proxy comes
  later in the sequence.

### D4 — Proxy build: hybrid now, full-from-scratch reconsidered later

Build our own proxy architecture on sans-I/O protocol state machines (`h11`,
`h2`, `wsproto`) for the parsed path, with a hand-rolled raw byte path for
malformed/smuggling traffic. Revisit a fully hand-written parser after the rest
of the toolkit works and depending on how things are going.

- **Consequences:** correctness comes from mature state machines; the byte-exact
  control we care about lives in the raw path.

### D5 — Integration architecture: shared store as the bus, proxy optional

Each tool reads and writes a shared SQLite project store. The proxy is an
optional observer, not a mandatory central bus.

- **Consequences:** every tool stays independently runnable; the proxy's latency
  stays out of timing features; the database schema is the integration contract.
  Timing-sensitive traffic does **not** route through the proxy.

### D6 — Repo structure: refactor into a package with a `core/` shared library

Move the loose scripts into a package with a `core/` library (HTTP client,
session, store, features, budget, logging, config) that the tools import.

- **Consequences:** shared concerns live in one place; retrofitting later would be
  more painful than starting with it now.

### D7 — Grey-box is committed: instrument the lab

Because we own the target, we will instrument it: line coverage (Xdebug or
pcov), a database error hook, and database snapshot/restore for state reset
between iterations.

- **Consequences:** the fuzzer, bandit reward, and mutation engine get a dense,
  causal signal instead of noisy timing. The store schema reserves a place for
  coverage data. This overlaps the app-scaling work, since both touch how the lab
  is built and reset. It does not have to be built first, but it is a first-class
  workstream. The lab environment (PHP/Apache/MySQL/libxml) is pinned in a
  container and asserted at runtime, because several labels depend on it (for
  example, error-based versus blind SQLi depends on `display_errors`).

### D8 — Lab scaling via a manifest-driven generator, sequenced after the toolkit

Adopt the "lab as a compiler" model from the scaling research: one manifest plus
a versioned safety matrix plus a seed and an environment profile, run through a
pure generator, emits the app (one file per case), the labels, the docs, and the
oracle tests. The vulnerable/secure verdict is **derived** from
`(transform, sink context)`, never hand-asserted. Run it as a **parallel lab
track that starts after the toolkit foundations**, not before.

- **Consequences:** stop hand-adding pages to the lab in the meantime;
  `VULNERABILITIES.md` becomes a generated artifact (see D9); the lab gains, over
  time, two tiers (a dense "range" tier for detection measurement and the
  realistic "shop" tier) and build profiles (annotated / blind / all-secure).

### D9 — Machine-readable, out-of-band ground-truth labels, starting now

Introduce a machine-readable label contract now: `labels.json` (rich: flow,
transform, sink context), a Benchmark-style `expectedresults.csv`, and a separate
`injection-points.json` (parameter-discovery ground truth, distinct from
vulnerability labels). Hand-author it for the current pages and have the tools and
the test harness consume it **out-of-band** (read from disk, never served by the
target). Use opaque case IDs; no class name in any URL, filename, or parameter a
tool can see.

- **Consequences:** the integration harness and tools consume the label files,
  not the prose doc; `VULNERABILITIES.md` stays human-facing and later becomes
  generated.

### D10 — The lab serves both detection benchmarking and ML training, with discipline

Use the lab for both purposes, but keep measurement honest: split by generator
cell and by transform (not by page), keep a permanent blind holdout never used
for tuning, report Matthews correlation and precision at fixed recall, and
validate periodically against an external target we did not build (WAVSEP, which
the ZAP team maintains; Juice Shop for the realism tier).

- **Consequences:** this upgrades the earlier "group by endpoint" rule to "group
  by cell/transform," and the deferred second-target decision is partly satisfied
  by these external validation targets.

### D11 — UI: a local web application, not a terminal TUI

The primary interface is a **local web application** — a control panel to launch
and steer runs and a dashboard to review output and results — served on localhost
only. It replaces the `textual` TUI as the primary UI. This is also where the
no-auto-run launcher lives: bring-up opens the web page with the automatic/manual
choice and touches the target only when the user acts.

- **Why:** output and results are far easier to review in a browser than in a
  terminal, and this composes with the already-planned Datasette (itself a web
  view over the store) rather than duplicating it in a TUI.
- **Safety (non-negotiable):** the web app is bound to loopback, never exposed,
  and strictly separated from the vulnerable target — a different origin/port, and
  never deployed into the target's web root — so the control plane is never itself
  an attack surface nor confused with the system under test.
- **Keep a headless path:** each tool retains a plain CLI entry point for
  automation, scripting, and power use; the web app orchestrates, but the tools
  still write their own results to the store.
- **Consequences:** supersedes the TUI in component #12 and in Phase 6's "TUI +
  Datasette"; the earlier "no full web UI before a TUI" deferral is replaced by
  "a lean localhost-only web app now; a heavyweight or multi-user web platform
  stays deferred." Stack (e.g. FastAPI or Flask + a light frontend, Datasette
  embedded/linked) is a to-confirm-during-build detail.

### D12 — Credential store: per-host, OS keyring with an encrypted-file headless fallback

Credentials are **saved associated to the corresponding host** (keyed by host,
then identity) and obtained through a `core/` credential-store abstraction over the
`keyring` library, never stored in the project store or the repo. When the session
manager needs to authenticate to a host, it looks up that host's credentials and
passes them — no per-host auth config file, just the vault entry. Backend
resolution, auto-selected and config-overridable:

1. **OS Secret Service** (gnome-keyring/KWallet) when present and unlocked — the
   interactive-desktop path.
2. **Encrypted-file backend** (`keyrings.alt` AES `EncryptedKeyring`) for headless
   boxes, CI, and containers — unlocked by a passphrase from
   `FUZZLAB_KEYRING_PASSPHRASE` (or an interactive prompt), with the encrypted
   store at a configured, repo-external path (`$FUZZLAB_KEYRING_PATH`, default
   `~/.config/fuzzlab/credentials.enc`). Only the passphrase ever lives in the
   environment; the credentials stay encrypted at rest.
3. **Gated, lab-only env fallback** (default off) for ephemeral CI: per-host
   `FUZZLAB_CRED_<HOST>_<IDENTITY>`, honored only when `allow_env_credentials` is
   set **and** the target scope is loopback/lab, with a loud warning. Never for a
   non-lab target.

The vault key is `(host, identity)`; the config holds no secrets. Redaction on
write applies everywhere. This makes the session manager usable on desktops,
headless hosts, containers, and CI alike, with credentials attached to the host
they belong to.

### D13 — Multi-target auth: dynamic detection, no per-host profiles

The session manager must log in and hold sessions across **many** hosts without
hand-written per-lab configuration. It **detects each host's login/session
mechanism dynamically** and handles it, passing that host's saved credentials
(D12) — detection-only, no per-host auth profile or override:

- **Login detection.** Find the login (a form containing a password field; carry
  its hidden fields — e.g. a CSRF `user_token` — through by re-fetching the form
  before submit), map the username/password fields, and submit the host's
  credentials.
- **Session-credential detection.** Read what the login response establishes and
  reuse it: `Set-Cookie` → session cookie; a token/JWT in a JSON body →
  `Authorization: Bearer`; a `WWW-Authenticate` challenge → Basic/Bearer. Session
  state generalizes to cookies **and** headers/tokens per `(host, identity)`.
- **Success/expiry detection.** Confirm login by differential behavior (a
  protected probe stops redirecting to login); detect expiry dynamically (401/403,
  redirect to the detected login, the login form reappearing, JWT `exp`) and
  re-authenticate under a single-flight lock.
- **Detection-only, fail loud.** The detector handles the common shapes
  (form→cookie, JSON→token/JWT, Basic/Bearer). A login it cannot parse
  (multi-step, CAPTCHA, exotic SPA) **fails loudly with diagnostics** rather than
  falling back to a hand-written profile; the remedy is to improve detection. This
  trade-off is accepted deliberately to keep the toolkit zero-config per host.
- **Manual-capture escape hatch (post-Phase 6).** Once the proxy exists, the
  fail-loud cases are handled without per-host config by letting a human log in
  through the proxy in a real browser; the proxy captures the established session
  and the session manager adopts it (FR-PROXY-9 / FR-SESS-11). This covers MFA,
  CAPTCHA, and multi-step logins that automated detection cannot.

Internally the detected mechanism maps to an auth handler (cookie/form,
JSON+token, Basic, header-key); these are implementation detail selected by
detection, not user-authored profiles.

### D14 — Injection-category selection by run mode

Which injection categories are tested depends on the launcher run mode (D11):

- **Automatic** (the benchmark against our lab): categories are **auto-selected
  from the lab's ground truth** (`labels.json` vuln classes / `injection-points`) —
  the run tests exactly what the lab is known to contain, so it stays a clean
  detection benchmark.
- **Manual** (hand-driven tool use): the user **selects which vulnerabilities /
  categories to test**, via a category selector in the launcher and a
  `--categories` flag on the tools. Nothing is tested for a category the user did
  not select.

Category selection scopes the auditor's active rules, the payload sources, and
which oracle `ConfirmationStrategy` classes run. (An automatic run against a target
without ground truth cannot auto-derive; there the categories must be given, i.e.
the manual-style selection applies.) This does not weaken no-auto-run (D11): the
user still chooses automatic mode before anything runs.

### D15 — No-ground-truth fail-safe for automatic runs

An automatic run against a target with **no ground-truth contract** (an external
validation lab, or any target whose vulnerabilities we do not know) must fail
safe — it never guesses and never blasts everything:

- **No auto-derivation, no "test everything" default.** With no ground truth there
  is nothing to auto-select from, so the run **requires an explicit category
  selection** (launcher selection / `--categories`). If none is given it **fails
  loudly** with a clear message rather than silently doing nothing or testing all
  categories.
- **Unscored (exploration) posture.** Without ground truth the integration harness
  cannot compute TP/FP/TN/FN, so it **reports findings without a benchmark score**
  and marks the run "no ground truth — unscored." It never fabricates a score.
- **All safety gates stay on.** Destructive-payload classes remain off by default,
  scope is enforced (lab-only, in-scope hosts only), and `--authorized` is still
  required. No-auto-run (D11) is unchanged.

This is the counterpart to D14: D14 covers the known-lab and manual cases; D15
covers the unknown-target automatic case.

### D16 — Configurable lab WAF (Phase 8 filter-evasion target)

Resolves the deferred "WAF in the lab" question: the Puppy Fort Factory ships a
**configurable, deliberately naive request prefilter** ("lab WAF") so the Phase 8
mutation engine's filter-transformation learning (FR-MUT-3) and its
defeat-the-filter exit have a real, controllable target.

- **In-app prefilter, wired globally, default OFF.** `includes/waf.php` runs via PHP
  `auto_prepend_file` (set in `web.Dockerfile`), so no page is edited. It is a **no-op
  unless `PFF_WAF` is enabled**, so the default app — and every existing ground-truth
  label — is unchanged; the filter is turned on only for filter-evasion experiments.
- **Configurable at runtime (no rebuild).** `PFF_WAF=on|off`, `PFF_WAF_MODE=block|
  sanitize|log`, and a machine-readable ruleset (`config/waf-rules.json`). `block`
  returns 403; `sanitize` strips the matched fragment (the transformation the engine
  learns); `log` observes only.
- **Deliberately bypassable.** The signatures are naive on purpose (e.g. `union select`
  but not `union/**/select`; `<script>` but not `<svg onfocus=>`) — a realistic target
  to learn to evade, not real protection. The ruleset is shared so the toolkit can model
  the filter offline.
- **Not a WAF-bypass-as-defense claim.** It exists to *exercise* evasion in the lab,
  under the same lab-only, loopback-only, no-auto-run posture as the rest of the target.

Because it is off by default, D7 reproducibility and all prior phases are unaffected.

### D17 — Opt-in h2→h1 downgrade front-end (Phase 9 desync target)

The lab ships an **opt-in, default-off** front-end reverse proxy that terminates HTTP/2
(cleartext h2c, prior knowledge) and forwards **HTTP/1.1** to the Puppy Fort Factory app
— the classic topology where HTTP/2-to-HTTP/1.1 desync/smuggling primitives live — as a
**legitimate, self-owned research target** for the toolkit's raw-frame HTTP/2 client.

- **Default off, profile-gated.** A `frontend` service (nginx, pinned) under the
  `desync` compose profile; a plain `docker compose up` never starts it, so the default
  lab is unchanged. Enable only for protocol-desync experiments
  (`docker compose --profile desync up`).
- **Config only, no app change.** nginx does `http2 on;` at the front and
  `proxy_http_version 1.1;` to `web:80` — the downgrade. The app and all ground-truth
  labels are untouched.
- **Lab-only posture.** Loopback-only (`127.0.0.1`), never exposed; it exists to
  *exercise* desync in the lab, on infrastructure we run ourselves — never a technique
  aimed at third parties. This is the counterpart, for protocol depth, of the D16 WAF.

### D18 — The web launcher runs tools as gated subprocesses (UI revamp Phase 0.3)

The control panel launches each activity as its **own child process**
(`python -m fuzzlab.cli <name> …`), not in the web process. Rationale: the tools keep
writing their own results (the UI still writes none — NFR-UI-read-only), a run is
cleanly cancellable, and a crashing tool can't take down the panel. Safety is built in:
argv is assembled **only from flags the command spec declares** (unknown form fields are
ignored — no arbitrary-argument injection) and **without a shell** (`create_subprocess_exec`
with an argv list). A run sends nothing until an explicit, `authorized`-gated
`POST /api/launch`, and a **dry run** previews the exact command first (FR-UI-5), so
no-auto-run (D11) is preserved. See `docs/UI_REVAMP_PLAN.md`; realized in `web/runner.py`.

### D19 — Live interception runs the proxy in the web app's event loop (UI revamp Phase 0.4)

The Proxy tab's live pause/edit/drop/forward is backed by `proxy/intercept.py`, which
holds `asyncio.Future` objects — **not shareable across processes**. So when the panel
hosts live interception it runs `AsyncProxyServer` **in its own uvicorn event loop**
(`fuzzlab web --with-proxy`, via `web/proxycontrol.py`), rather than as the separate
`fuzzlab proxy` process. The proxy stays **opt-in and `--authorized`-gated** (it forwards
to upstreams), loopback-only, and on a **separate port** from the panel; flow **history**
remains readable cross-process from the store. Without `--with-proxy` the tab is dormant
and the panel is unchanged. See `docs/UI_REVAMP_PLAN.md`.

### D-UI-shell — The web UI is a left-nav app shell over a design-token system (layout redesign R0)

The panel's layout is a persistent **app shell**: a left-**sidebar** navigation (grouped
Workbench / Analysis sections) plus a **top context bar** (target, scope, authorization,
proxy status), framing a scrolling content area — replacing the earlier top hash-tab
masthead (Phase 0.2, CC-UI-0012), whose hash-based section switching it keeps. All color,
elevation, and density live in one **design-token** stylesheet (`tokens.css`): **light /
dark / system** theme (system by default, explicit override wins) and a **compact density**,
each persisted per-viewer in `localStorage` and applied before first paint. Rationale:
scalability (a sidebar grows to many sections where a tab row does not), a consistent frame
across pages, and a single retheme point — matching the app-shell + severity-token patterns
of the VM/DAST tools reviewed in `docs/UI_LAYOUT_REDESIGN.md`. The shell is **chrome only**:
it preserves no-auto-run (D11), loopback-only, the `authorized` gate, NFR-UI-read-only, and
redaction; the invariant-bearing markup is unchanged. R0 is the first step of the R0→R3
migration in `docs/UI_LAYOUT_REDESIGN.md` (R1 deep-linkable per-section routes + Overview,
R2 Findings workbench, R3 Proxy rebuild). Realizes FR-UI-8; see CC-UI-0021.

### D20 — Manifest-driven generator: binary verdict, migrate the hand-built app, `patterns/` under LAB

Per `CR-LAB-0001` (approved 2026-09-21), the manifest-driven lab generator (D8) is
realized as: a **binary verdict** model (a `partial`-neutralization case is
VULNERABLE-but-harder, feeding a `difficulty` tier, rather than a third
`hardened` verdict value) — simpler, and keeps existing binary-detector scoring
intact; the **existing hand-built PHP app is migrated** into the generator at
Phase 3.6, rather than kept permanently as a separate Tier-0 fixture, consistent
with D8's original "stop hand-adding pages" consequence; and the **pattern-
provenance corpus (`patterns/`) lives under LAB** (`01-target-lab/`), since it is
generator-design provenance, not a runtime payload catalog for IND. The three
classes with no mature automated security-assertion oracle (IDOR/BOLA,
business-logic flaws, race conditions; see `CR-LAB-0001` Addendum E) are
**deferred indefinitely** — no paid expert consultation for now; the generator
ships without them. This keeps D8 itself intact (the "why") while D20 pins the
"what," per `CR-LAB-0001` §6/§7.

**Migrate confirmed, conflicting draft corrected (2026-09-21):** an earlier
draft of `docs/LAB_PHASE_0_PLAN.md` had read a separate "additive-only, never
reduce functionality or capability" instruction as applying to the hand-built
app itself (concluding it should be kept forever, never migrated) — a
misreading. That instruction is about the **toolkit's own capabilities,
robustness, and stack breadth never regressing**, not about any one hand-built
artifact's continued existence once the generator can reproduce and supersede
it. Confirmed: the hand-built `puppy-fort-factory/` app is retired once Phase
0/1 prove byte-identical reproduction and the Phase 3 PHP/Laravel emitter
lands — the generator becomes the single source of the PHP lab, not an
additional target alongside a permanently-kept original. `LAB_PHASE_0_PLAN.md`
corrected to match; nothing about Phase 0's own exit criterion changes (it
still just proves reproduction, not cutover).

### D21 — Storage layout: per-project SQLite files plus a small global config DB

Closes out a Phase-0 loose end noticed during a 2026-09-22 change-control
audit: this had been sitting in "Deferred decisions" as "decide at Phase 0"
since early in the project, but Phase 0 has been `[built]` for a long time and
already ships this exact shape. Formalized as settled, no code change: each
project gets its own SQLite store file; a small separate global database holds
cross-project config. See the (now-struck-through) entry under "Deferred
decisions" below for the original framing.

### Deferred decisions (revisit at the noted point)

- **Classifier false-positive tolerance (conformal α)** — decide at the
  classifier phase (Phase 5); a value judgment, leaning to a high abstain rate
  and low false-flag rate.
- **Second target app** — decide when generalization becomes a goal, after the
  core toolkit works.
- **Full from-scratch HTTP parser** — reconsider after the toolkit works end to
  end (per D4).
- ~~**One DB file per project vs one global DB** — decide at Phase 0; leaning
  per-project files plus a small global config database.~~ **Decided (D21,
  2026-09-22, closing out a Phase-0 loose end noticed during a change-control
  audit — Phase 0 has been `[built]` since early in the project and already
  ships this shape):** per-project SQLite files plus a small global config
  database, as originally leaned. No code change; this only formalizes the
  already-shipped architecture as a settled decision rather than leaving it
  perpetually "deferred."

## Cross-cutting principles (apply to every component)

- **Oracle/advisory split.** ML components only write scores and uncertainty; a
  deterministic oracle is the only thing that writes a `label`. Every oracle
  confirmation produces a training row, so the system self-labels over time.
- **Differential-timing confirmation.** Confirm time-based findings by probing an
  endpoint at several requested delays and requiring latency to rise with the
  delay, not by trusting one slow response.
- **Evaluation honesty.** Split by generator cell and by transform (not by
  page/endpoint), keep a permanent blind holdout never used for tuning, report
  Matthews correlation and precision at fixed recall (plus PR-AUC), always compare
  against a dumb baseline (fixed threshold and mean + k·σ), and validate
  periodically against an external target we did not build.
- **Request budget is a first-class resource.** Every component checks requests
  out of a shared budget; timing measurements run at concurrency 1 per host,
  enforced by the budget manager rather than by convention.
- **Feature-store discipline.** One versioned feature extractor writes
  `features_json` with a `feature_version`, so the whole dataset can be recomputed
  when features change.
- **No label leakage.** Never build features from the payload string; deduplicate
  positives by `(endpoint, payload_family)` before splitting.
- **Security hygiene even in the lab.** Credentials in the OS keyring, redaction
  on write to the store, automatic scope enforcement, and a default-off gate on
  destructive payloads. The habits outlive the lab.
- **No auto-run against the target.** Bringing up the environment never starts
  tool traffic on its own. A launcher presents a run-mode choice — automatic (the
  tools run in sequence) or manual (the tools are made available for hand-driven
  use) — and nothing is sent to the target until the user chooses automatic mode
  or invokes a tool by hand.
- **Fail safe without ground truth.** An automatic run against a target with no
  ground-truth contract requires an explicit category selection (never
  auto-guesses or tests everything), runs unscored, and keeps every safety gate on
  (destructive off, scope-enforced, authorized). It fails loudly if categories are
  not specified. (D15)
- **Bug investigation + preventive actions.** Every bug discovered in the code
  gets a bug investigation document under `docs/bugs/` (description, where
  encountered, what failed, what the bug was, a root-cause analysis, the
  corrective action, and a preventive action derived from the root cause). Every
  preventive action is also added to `docs/PREVENTIVE_ACTIONS.md` — a single,
  context-free rule list that is consulted and followed while working. See
  `docs/bugs/README.md`.
- **Documentation stays legible.** The architecture document is kept in sync with
  the build (its maintenance rule); if it grows too complex, detail moves into
  secondary architecture documents under `docs/architecture/` referenced from it
  (its splitting rule).

## Roadmap (phased)

Ordered by (value × certainty) / effort. Each phase produces something usable.
Status legend: `[built]`, `[partial]`, `[planned]`.

### Phase 0 — Foundations (lean) `[planned]`
Goal: one command runs the existing tools against the lab, all writing to one
store.
- Unified SQLite store with WAL, single-writer, content-addressed bodies, and
  numbered migrations.
- `core/` shared library: HTTP send helper, config loading, structured logging,
  request-budget manager (with the per-host timing mutex).
- Versioned `features.py` with golden-file tests.
- Integration harness: docker-compose lab plus an assert-N-known-vulns test.
- **Exit:** existing tools run from one entry point and share one database.

### Phase 1 — Session manager `[planned]`
Goal: tools stay authenticated through a full run. Task breakdown in
`docs/PHASE_1_PLAN.md`.
- Cookie jar, identity model, `prepare` / `observe` / `ensure`, single-flight
  re-auth.
- CSRF token extraction from the preceding response; JWT `exp` handling.
- Multiple identities (`anonymous`, `user`, `admin`).
- Auto-exclusion of auth endpoints from fuzzing scope.
- Keyring-backed credentials and redaction on write.
- **Exit:** crawler and fuzzer stay authenticated for a whole run, with results
  per identity.

### Phase 2 — Deterministic wins (no ML) `[planned]`
Goal: fewer requests for the same findings, and a trainable dataset with
negatives. Task breakdown in `docs/PHASE_2_PLAN.md`.
- Differential-timing oracle.
- Median/MAD rolling baselines replacing mean/σ.
- Template-cluster dedup via DOM-skeleton MinHash.
- Hybrid crawl (HTTP first, headless on demand).
- Canary reflection probing with context typing.
- Fingerprint-before-fuzz.
- Rules-as-data with full evaluation logging (record every rule evaluation, not
  just hits).
- **Exit:** measurably fewer requests, and a `candidate` table containing
  negatives.

### Phase 3 — Grey-box instrumentation `[planned]`
Goal: a dense, causal reward signal. Task breakdown in `docs/PHASE_3_PLAN.md`.
- Xdebug/pcov line coverage read per request, filtered to app files.
- Database-level fault signal (query log or a proxy/DB error hook).
- Lab state reset (DB snapshot/restore) between iterations.
- Wire coverage into `attempt.reward`.
- **Exit:** a request reaching new application code produces a distinguishable
  reward.

### Phase 4 — Bandit scheduler `[planned]`
Goal: find the known vulnerabilities in fewer requests than uniform selection. Task
breakdown in `docs/PHASE_4_PLAN.md` (learning core built; loop-wiring + on-lab exit
remain).
- Payload-family arms and discrete context buckets.
- Hierarchical Thompson sampling with backoff and catalog-derived priors.
- Shaped multi-tier reward including Phase 3 coverage.
- Cost-normalized selection (reward per second).
- Persisted posteriors and a `UniformScheduler` control condition.
- **Exit:** a plot showing the bandit beats uniform on hits-per-1000-requests on
  held-out pages.

### Phase 5 — Detection classifier + conformal `[planned]`
Goal: beat the dumb baselines on held-out endpoints with calibrated abstention. Task
breakdown in `docs/PHASE_5_PLAN.md` (honest-eval + models core built; store-training
and the real-data exit remain).
- Logistic-regression and mean + 7σ baselines, honestly evaluated with
  GroupKFold.
- Gradient-boosted trees with class-balanced loss and calibration.
- Split-conformal wrapper producing flag / abstain / drop.
- Dedup positives before splitting; a fallback path when the model is absent.
- **Exit:** held-out PR-AUC beats both baselines; the conformal abstain rate is
  calibrated.

### Phase 6 — Intercepting proxy, HTTP/1.1 `[planned]`
Goal: browse the lab through it and inspect exact bytes on the wire.
- asyncio + `h11` sans-I/O core; interception as an awaited future.
- CONNECT plus TLS interception with a local CA and cached per-host leaf certs.
- Dual-path design: parsed path plus a raw byte path with single-use
  connections and byte-exact capture.
- History in the shared store with FTS5 and batched writes.
- Repeater with DB-persisted tabs and connection-reuse control.
- Match-and-replace and scope rule engines.
- Local web control panel and dashboard (D11), with Datasette for deep store
  exploration.
- Session manager as a proxy addon.
- Capture the session from a manual browser login and hand it to the session
  manager to adopt (FR-PROXY-9 / FR-SESS-11) — the escape hatch for logins
  detection can't crack (MFA, CAPTCHA, multi-step), no per-host config.
- Property-test the parser with `hypothesis`.
- **Exit:** browse the lab, hand-edit a request with a duplicate
  `Content-Length`, and see the exact bytes sent.

### Phase 7 — Candidate ranker + active learning `[planned]`
- Char n-gram TF-IDF plus structural features; a pointwise ranker.
- NDCG@k / Precision@k evaluation per page, with explanations.
- Uncertainty sampling and query-by-committee to allocate oracle budget.
- A separate, uniformly-sampled evaluation set.

### Phase 8 — Mutation engine `[planned]`
- `sqlglot`-based AST parsing with typed, semantics-preserving operators.
- Context-typed XSS generator keyed on reflection context.
- Filter-transformation learning from canary probes.
- Bandit-scheduled operator selection; coverage-guided hill climbing.
- (Optional) offline LLM catalog expansion behind the AST/semantics gate.
- Prerequisite: decide on a lab WAF — **done (D16):** a configurable, default-off,
  deliberately bypassable prefilter now ships in the lab as the filter-evasion target.

### Phase 9 — Protocol depth `[planned]`
- WebSockets via `wsproto` in the proxy.
- An HTTP/2 raw-frame client with arbitrary header bytes and ALPN override.
- Lab topology extension: a front-end proxy doing HTTP/2 to HTTP/1.1 downgrade,
  as a legitimate desync research target.

### Phase 10 — Polish and generalization `[planned]`
- Anomaly-detection tripwire (ECOD) and XGBOD-style hybrid features.
- Plugin entry-point system.
- A second lab target to test transfer.
- Documentation and reproducible evaluation scripts.

### Near-term focus
Phase 0 (lean foundations), then Phase 1 (session manager).

### Explicitly deferred indefinitely
Autonomous LLM agent loops, deep reinforcement learning, HTTP/3, deep-learning
anomaly detection, any distributed architecture, and a heavyweight or multi-user
web platform (the near-term UI is a lean, localhost-only web app — D11).

## Lab track (parallel to the toolkit roadmap)

Per D8, the lab grows via a manifest-driven generator, as its own track that
starts after the toolkit foundations (Phases 0–1 above). Per **D20**, the
authoritative phase-level deliverable breakdown is `CR-LAB-0001` §8 (Phase 0
foundation → Phase 1 variation-on-existing-stack → Phase 2 identity/depth →
Phase 3 multi-stack, incl. migrating the existing hand-built app per §7.2 →
Phase 4 realism tier and beyond) — read it there rather than here, so this
summary and that phase list don't drift apart again. Notable per D20: Phase 2's
`authz_expectations` groundwork unlocks IDOR/BOLA *mechanically*, but building
actual IDOR/BOLA cells on top of it is one of the three gap classes deferred
indefinitely (no automated oracle, no paid consult for now) — the groundwork is
still worth building since Phase 2 needs it for other things (stored/
second-order cases), IDOR/BOLA cells themselves just don't get scheduled.

The two tracks share the label contract (D9) and the pinned environment, so the
toolkit can consume lab labels from the first lab phase onward.

## Already built (starting point)

`[built]` the target lab app; the JavaScript-rendering crawler (`spider.py`); the
injection-point auditor (`fetcher.py`, 28-rule registry); the indicator database
builder (`build_sql_db.py`) and `php_indicators.db`; the time-based blind SQLi
fuzzer (`blind_sqli_fuzzer.py`); the `references/` payload catalogs; the deploy
script; and the project logs and research/planning docs. These are consolidated
and hardened during Phases 0–2.
