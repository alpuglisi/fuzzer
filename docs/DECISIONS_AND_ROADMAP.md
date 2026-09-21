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

### Deferred decisions (revisit at the noted point)

- **WAF in the lab** — decide before the mutation engine (Phase 8); without one,
  the WAF-bypass line has no target.
- **Classifier false-positive tolerance (conformal α)** — decide at the
  classifier phase (Phase 5); a value judgment, leaning to a high abstain rate
  and low false-flag rate.
- **Second target app** — decide when generalization becomes a goal, after the
  core toolkit works.
- **Full from-scratch HTTP parser** — reconsider after the toolkit works end to
  end (per D4).
- **One DB file per project vs one global DB** — decide at Phase 0; leaning
  per-project files plus a small global config database.

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
Goal: tools stay authenticated through a full run.
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
negatives.
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
Goal: a dense, causal reward signal.
- Xdebug/pcov line coverage read per request, filtered to app files.
- Database-level fault signal (query log or a proxy/DB error hook).
- Lab state reset (DB snapshot/restore) between iterations.
- Wire coverage into `attempt.reward`.
- **Exit:** a request reaching new application code produces a distinguishable
  reward.

### Phase 4 — Bandit scheduler `[planned]`
Goal: find the known vulnerabilities in fewer requests than uniform selection.
- Payload-family arms and discrete context buckets.
- Hierarchical Thompson sampling with backoff and catalog-derived priors.
- Shaped multi-tier reward including Phase 3 coverage.
- Cost-normalized selection (reward per second).
- Persisted posteriors and a `UniformScheduler` control condition.
- **Exit:** a plot showing the bandit beats uniform on hits-per-1000-requests on
  held-out pages.

### Phase 5 — Detection classifier + conformal `[planned]`
Goal: beat the dumb baselines on held-out endpoints with calibrated abstention.
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
- Prerequisite: decide on a lab WAF.

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
starts after the toolkit foundations (Phases 0–1 above). High-level phases,
adapted from the scaling research:

- **Lab Phase 0 — Schema and import (no new pages).** JSON Schema for the
  manifest and an initial safety matrix covering only the transforms and sink
  contexts the current pages use; write manifest entries for the existing pages;
  make the generator reproduce today's app; diff generated docs against the
  hand-written map and explain every discrepancy; pin the environment.
- **Lab Phase 1 — Oracles and label pipeline (still no new pages).** Positive,
  negative (paired-secure), and contamination oracles; a Psalm taint backstop;
  environment assertions; a byte-identical regeneration gate; emit
  `labels.json`, `expectedresults.csv`, `injection-points.json`, `sitemap.xml`;
  a loopback-only database reset.
- **Lab Phase 2 — Scale within known classes.** Expand cells for SQLi and XSS
  with hard caps per cell and surface-feature variation; add difficulty tiers;
  generate the benign corpus (including apostrophe-rich, safely-reflected, and
  slow-but-benign true negatives); add the `blind` and `all-secure` build
  profiles.
- **Lab Phase 3 — Realism.** Auth states and roles; IDOR/BOLA; multi-step, stored,
  and second-order cases; a REST surface with generated OpenAPI.
- **Lab Phase 4+ — Class breadth (cheapest oracle first).** Open redirect, path
  traversal/LFI, SSTI, CSRF, XXE, then SSRF (loopback canary only); command
  injection and deserialization last, behind a disabled-by-default profile.

The two tracks share the label contract (D9) and the pinned environment, so the
toolkit can consume lab labels from the first lab phase onward.

## Already built (starting point)

`[built]` the target lab app; the JavaScript-rendering crawler (`spider.py`); the
injection-point auditor (`fetcher.py`, 28-rule registry); the indicator database
builder (`build_sql_db.py`) and `php_indicators.db`; the time-based blind SQLi
fuzzer (`blind_sqli_fuzzer.py`); the `references/` payload catalogs; the deploy
script; and the project logs and research/planning docs. These are consolidated
and hardened during Phases 0–2.
