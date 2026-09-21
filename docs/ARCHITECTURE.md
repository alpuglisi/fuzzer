# Architecture Overview

High-level outline of the toolkit's components, their subcomponents, how they
interact, and their dependencies. Living document; keep it in sync with
`docs/DECISIONS_AND_ROADMAP.md`.

**Maintenance rule:** update this document whenever the project architecture
changes — a component added, removed, or split, or its responsibilities,
interfaces, or dependencies changed. Each primary component below also has its own
requirement specification and change-control log under `docs/components/`.

**Splitting rule:** if this document grows too complex as the project builds out,
move detailed material into **secondary architecture documents** under
`docs/architecture/` and reference them from here. This document then stays the
high-level map and index; each secondary document owns the depth for its area
(and is itself kept in sync under the maintenance rule). None exist yet.

*Last updated: 2026-09-21.*

Status legend: `[built]`, `[partial]`, `[planned]`.

## Integration model

The **shared SQLite project store is the integration bus** (decision D5). Each
tool runs independently and communicates by reading and writing tables in that
store, not by calling other tools' APIs. Shared concerns live in a `core/`
library that every tool imports (decision D6). The intercepting proxy is an
**optional observer**, never a mandatory pipeline. A deterministic **oracle** is
the only component allowed to write vulnerability labels; machine-learning
components only write scores and uncertainty (the oracle/advisory split). The
target lab runs in a container with pinned PHP/Apache/MySQL/libxml versions (D7),
so labels stay valid across upgrades and runs are reproducible.

**No auto-run:** bringing up the lab never starts tool traffic on its own. A
launcher (see component #12) presents a run-mode choice — **automatic** (the tools
run in sequence against the lab) or **manual** (the tools are made available for
hand-driven use) — and nothing is sent to the target until the user chooses
automatic mode or invokes a tool by hand.

## Component map

```
                     ┌───────────────────────── Diagnostics / UI ─────────────────────────┐
                     │  local web control panel + dashboard · Datasette over store · logs   │
                     └───────────────────────────────▲─────────────────────────────────────┘
                                                     │ reads
   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  ┌───────────┐
   │ crawler  │  │ auditor  │  │ scheduler│  │ fuzzer / │  │ mutation      │  │  proxy    │
   │ (spider) │  │(fetcher) │  │ (bandit) │  │ harness  │  │ engine        │  │(observer) │
   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬────────┘  └────┬──────┘
        │             │             │             │               │                │
        │             │             │        ┌────▼────┐          │                │
        │             │             │        │ oracle  │          │                │
        │             │             │        └────┬────┘          │                │
        └─────────────┴─────────────┴─────────────┼───────────────┴────────────────┘
                                                   │  reads/writes
                        ┌──────────────────────────▼──────────────────────────┐
                        │                     core/ (shared library)            │
                        │  http client · session manager · store (SQLite +      │
                        │  migrations) · features (versioned) · request budget  │
                        │  + concurrency mutex · logging · config · plugins     │
                        └──────────────────────────┬───────────────────────────┘
                                                   │
                                       ┌───────────▼───────────┐
                                       │     project store      │
                                       │  (SQLite; the contract)│
                                       └───────────┬───────────┘
                                                   │ targets / instruments
                        ┌──────────────────────────▼──────────────────────────┐
                        │  Target lab: Puppy Fort Factory (PHP/MySQL/Apache)    │
                        │  + ground-truth manifest  + grey-box instrumentation  │
                        │  (coverage, DB error hook, state snapshot/restore)    │
                        └───────────────────────────────────────────────────────┘

   ML components (classifier, ranker, anomaly detector, active learner) attach as
   plugins on core/ hooks; they read features and write scores/uncertainty only.
```

## Components and subcomponents

Throughout this section, **Depends on (components)** lists other project
components only. Python package dependencies (for example `h11`, `sqlglot`, or
LightGBM) are implementation details, mentioned within the subcomponents and
tracked in the requirements files, not here.

### 1. Target lab and ground truth `[built app; planned instrumentation]`
- **Puppy Fort Factory** `[built app]`: PHP/MySQL/Apache app; ~30 pages, ~10
  JavaScript-rendered; documented mix of vulnerable and secure pages. Runs
  containerized with pinned PHP/Apache/MySQL/libxml versions (D7).
- **Ground-truth labels** `[partial]`: a machine-readable, out-of-band contract
  (`labels.json`, `expectedresults.csv`, and a separate `injection-points.json`),
  read from disk by the tools and the harness, never served by the target, with
  opaque case IDs (D9). Hand-authored initially; later emitted by the
  manifest-driven lab generator (D8), at which point `VULNERABILITIES.md` becomes
  a generated, human-facing artifact. The lab grows into two tiers (dense "range",
  realistic "shop") with annotated / blind / all-secure build profiles.
- **Grey-box instrumentation** `[planned]` (D7): line coverage (Xdebug/pcov), a
  database error hook, and snapshot/restore for state reset.
- **Manifest-driven generator** `[planned]` (D8): the "lab as a compiler" — one
  manifest plus a safety matrix, seed, and env-profile generate the app, labels,
  docs, and oracle tests, with verdicts derived from `(transform, sink context)`.
  Built as the parallel Lab track after the toolkit foundations.
- **Depends on (components):** none (it is the system under test).
- **Consumed by:** crawler, auditor, fuzzer, proxy, and the reward path.

### 2. `core/` shared library `[planned]`
- **HTTP client**: one send helper; requires a session context; records raw
  bytes.
- **Store**: SQLite access, schema, and numbered migrations.
- **Features**: one versioned extractor (`extract_vN`), `features_json` +
  `feature_version`.
- **Request budget + concurrency**: per-component caps, and a per-host mutex so
  timing measurements run at concurrency 1.
- **Logging** (structured) and **config** (layered, hashed onto the run).
- **Credential store**: keyring-abstracted, with OS Secret Service and an
  encrypted-file headless/CI fallback (D12); secrets by reference only, never in
  the project store.
- **Plugin registry**: entry points plus hooks.
- **Depends on (components):** none (foundational layer; it manages the project store).
- **Consumed by:** every tool and ML component.

### 3. Session manager `[built; live validation pending]` (Phase 1)
- **Subcomponents:** a **login/session detector** (D13) — finds the login form
  (carrying hidden/CSRF fields fresh), detects the session credential from the
  response (cookie / JSON token+JWT / Basic-Bearer challenge), confirms success by
  differential behavior, and detects expiry (401/redirect/form-reappears/JWT
  `exp`); identity model **per host**; session state (cookies + headers/tokens);
  re-auth macro with single-flight lock; a **per-host credential vault** via the
  `core/` credential store (OS keyring + encrypted-file headless fallback, D12).
  Detection-only: no hand-written per-host profiles; unparseable logins fail loud.
- **Interface:** `prepare(request, identity)`, `observe(request, response,
  identity)`, `ensure(identity)`, resolved by the request's host. Internally the
  detected mechanism maps to an auth handler (cookie/form, JSON+token, Basic,
  header-key) — implementation detail, not user config. Post-Phase 6, logins
  detection can't crack are handled by **adopting a session the proxy captures
  from a manual browser login** (FR-SESS-11), still without per-host config.
- **Depends on (components):** `core/` (config, store, HTTP seam, credential
  store); crawler (discovered forms help locate the login); proxy (post-Phase 6,
  for manual-login session capture).
- **Consumed by:** crawler, auditor, fuzzer, and the proxy (as an addon). This is
  the most load-bearing dependency; everything authenticated flows through it, on
  every host — the Puppy Fort Factory and the external validation labs (D10).

### 4. Crawler / spider `[built; to harden]`
- **Subcomponents:** hybrid fetch (HTTP first, headless on demand), XHR/fetch
  capture, JS endpoint extraction, DOM-skeleton template dedup, state-aware
  navigation, URL normalization, crawl budget.
- **Depends on (components):** `core/`, session manager, target lab.
- **Writes:** `page`, `endpoint`, discovered `parameter` rows.

### 5. Auditor / fetcher `[built; to harden]`
- **Subcomponents:** rule registry (moving to rules-as-data), candidate emission
  with full per-rule evaluation logging, canary reflection probing with context
  typing, target fingerprinting (DBMS/framework/WAF).
- **Depends on (components):** `core/`, session manager, crawler, indicator DB & catalogs.
- **Writes:** `candidate` rows (rule evidence, features), fingerprint data.

### 6. Indicator database and payload catalogs `[built; to extend]`
- **Subcomponents:** `build_sql_db.py` + `php_indicators.db` (28 indicator types
  mapped to `references/` categories); the `references/` payload catalogs;
  payload metadata (family, DBMS, context prerequisites, destructive flag).
- **Depends on (components):** none (static data).
- **Consumed by:** auditor (indicators), scheduler and fuzzer (payloads/families).

### 7. Fuzzing harness and oracle `[built fuzzer; harness+oracle planned]`
- **Fuzzing harness** `[partial]`: generalize `blind_sqli_fuzzer.py` toward
  `template + injection_point + payload_source + oracle`, so one harness serves
  multiple vulnerability classes.
- **Oracle** `[planned]`: deterministic confirmation (differential timing,
  error-signature checks, and coverage/DB-fault signals when grey-box is on). The
  **only** writer of `finding` labels.
- **Depends on (components):** `core/`, session manager, scheduler, oracle,
  indicator DB & catalogs; grey-box instrumentation for reward and labels. (The
  oracle itself depends on `core/` and the target lab, plus grey-box signals when
  available.)
- **Writes:** `attempt` rows (features, reward), `finding` rows (labels).

### 8. Payload scheduler (bandit) `[planned]` (Phase 4)
- **Subcomponents:** payload-family arms, discrete context buckets, hierarchical
  Thompson sampling with backoff, catalog-derived priors, cost-normalized
  selection, persisted posteriors, and a uniform-selection control.
- **Depends on (components):** `core/`, auditor (candidates), fuzzing harness and
  oracle (rewards), grey-box instrumentation (coverage reward).
- **Reads/writes:** `bandit_posteriors`; chooses the next family per candidate.

### 9. Mutation engine `[planned]` (Phase 8)
- **Subcomponents:** `sqlglot` AST parsing, typed semantics-preserving operators,
  context-typed XSS generation, filter-transformation learning from canaries,
  bandit-scheduled operator selection, coverage-guided hill climbing, optional
  gated offline LLM catalog expansion.
- **Depends on (components):** `core/`, indicator DB & catalogs, scheduler,
  oracle, grey-box instrumentation. (A lab WAF is a prerequisite decision, not a
  component dependency.)
- **Writes:** new payload candidates back into the catalog/attempts.

### 10. ML components `[planned]` (Phases 5, 7, 10)
- **Detection classifier** (A.1): gradient-boosted trees + calibration +
  conformal flag/abstain/drop; reads `attempt.features_json`, writes scores.
- **Candidate ranker** (A.2): learning-to-rank over parameters/forms; reads
  candidate features, writes `candidate.score`; costs zero requests.
- **Anomaly detector** (A.5): ECOD/Isolation Forest tripwire, later XGBOD-style
  hybrid features.
- **Active learner** (A.6.5): allocates oracle budget by uncertainty and
  committee disagreement.
- **Depends on (components):** `core/`, the oracle (labels), and the component
  that produces each model's inputs (auditor for the ranker, fuzzing harness for
  the classifier, proxy/flows for the anomaly detector).
- **Attach as:** plugins on `core/` hooks. Shipping without ML is a config change.

### 11. Intercepting proxy `[planned]` (Phase 6)
- **Subcomponents:** asyncio core; parsed path (`h11`/`h2`/`wsproto`) and a raw
  byte path (byte-exact, single-use connections); CONNECT + TLS interception with
  a local CA and cached leaf certs; history (FTS5, batched writes, content-
  addressed bodies); repeater (DB-persisted tabs); match-and-replace; scope
  engine; interception-as-awaited-future workflow; manual-login **session
  capture** (hand the session established by a human browser login to the session
  manager to adopt — FR-PROXY-9 — the escape hatch for logins detection can't
  crack: MFA, CAPTCHA, multi-step).
- **Depends on (components):** `core/`, session manager (attached as an addon).
- **Role:** optional observer; other tools may route through it for unified
  history, but timing-sensitive traffic does not (D5).

### 12. Diagnostics and UI `[planned]`
- **Subcomponents:** a **local web application** (D11) — a control panel that hosts
  the **launcher with run-mode selection** (automatic vs manual; no auto-run —
  nothing is sent to the target until the user chooses) and a dashboard for live
  runs, interception, and results; Datasette over the store for deep exploration; a
  `run_metrics` table; structured audit and debug logs; a `--dry-run` mode; and a
  plain CLI entry point per tool for headless/automation use.
- **Depends on (components):** `core/` (store and logging); in automatic mode the
  web app invokes the tools (crawler, auditor, fuzzer, harness).
- **Purpose:** the research-platform diagnostics from decision D2, made easy to
  review in a browser (D11), to verify functionality and locate bugs; and to keep
  the user in control of when the tools touch the target (the no-auto-run
  principle).
- **Safety:** the web app is bound to loopback, never exposed, and strictly
  separated from the vulnerable target (different origin/port; never in the
  target's web root), so the control plane is never itself an attack surface.

### 13. Plugin system `[planned]` (Phase 10)
- **Subcomponents:** `importlib.metadata` entry points; a hook registry
  (`on_request`, `on_response`, `on_candidate`, `on_finding`, `register_rules`,
  `register_payload_source`, `register_oracle`); per-plugin isolation and
  priority.
- **Depends on (components):** `core/`.
- **Consumed by:** ML components, extra rules, and custom oracles.

## The store as the contract

Core tables and their principal readers/writers (see the roadmap for schema
detail):

| Table | Written by | Read by |
| --- | --- | --- |
| `run`, `schema_version` | core | everything |
| `target` (fingerprint) | auditor | scheduler, fuzzer |
| `page`, `endpoint`, `parameter` | crawler, auditor | auditor, ranker, fuzzer |
| `candidate` (rule evidence, features, score) | auditor, ranker | scheduler, fuzzer |
| `flow` (+ raw bytes) | proxy, http client | anomaly detector, UI, analysis |
| `attempt` (features, reward) | fuzzer | classifier, bandit, active learner |
| `finding` (labels, evidence) | oracle only | UI, ML training, reports |
| `bandit_posteriors` | scheduler | scheduler |
| `model` (versions, calibration) | ML training | ML inference |
| `request_budget` | all tools | budget manager, UI |
| coverage / fault signals | grey-box hooks | fuzzer, scheduler, mutation |

## Dependency ordering

From most foundational to most dependent. Nothing above a layer should import
from below it.

```
target lab + grey-box instrumentation      (system under test)
        ▲
core/  (store, http, features, budget, logging, config, plugins)
        ▲
session manager
        ▲
crawler → auditor → candidate queue
        ▲
scheduler (bandit) + oracle
        ▲
fuzzing harness  ──uses──►  scheduler, oracle, payload catalogs
        ▲
ML components (ranker, classifier, anomaly, active learner)   [plugins]
        ▲
proxy (optional observer)  ·  mutation engine  ·  diagnostics/UI
```

Key hard dependencies: everything depends on `core/` and the store; every
authenticated action depends on the session manager; every confirmed finding and
every training label depends on the oracle; the bandit's dense reward and the
mutation engine's hill climbing depend on grey-box signals.

## Key interaction flows

**1. The core discovery-to-label loop.**
crawler discovers pages/endpoints → auditor emits candidates with rule evidence →
ranker scores and orders them (0 requests) → scheduler picks a payload family per
candidate → fuzzing harness sends and extracts features → classifier screens
(flag/abstain/drop) → oracle confirms with differential timing (and coverage/DB
signals) → `finding` written with a label → that label becomes a training row and
a bandit reward.

**2. Session handling across tools.**
Each tool calls `session.prepare()` before sending and `session.observe()` after
receiving; `session.ensure()` re-authenticates via a single-flight lock when a
logout is detected. As a proxy addon, the same handling applies to hand-driven
browser traffic.

**3. Grey-box reward.**
A request executes against the instrumented lab → coverage and DB-fault signals
are collected per request → the oracle and the bandit read them as a dense reward
→ state is reset via snapshot/restore before the next iteration.

**4. Proxy as observer / manual testing.**
Browser or tools route through the proxy (non-timing traffic) → flows land in the
shared history with raw bytes → anomaly detector tags weird responses → repeater
replays and edits, including a raw byte path for malformed-traffic study.

## Cross-cutting concerns

- **Budget and concurrency:** one shared budget; timing traffic serialized per
  host by a mutex in the budget manager.
- **Logging and observability:** structured logs carrying `run_id`, `tool`,
  `identity`, `flow_id`; a metrics table; an audit log of every request for
  reproducibility.
- **Configuration:** layered (defaults → file → env → CLI), validated, hashed
  onto the `run` row; one config shared by all tools; secrets by reference only.
- **Testing:** protocol unit tests, `hypothesis` property tests for the parser,
  golden-file feature tests, deterministic ML-pipeline tests, an
  assert-N-known-vulns integration suite, and oracle precision tests.
- **Security and safety:** credentials in the OS keyring, redaction on write,
  automatic scope enforcement, a default-off destructive-payload gate, a lab-only
  posture throughout, and **no auto-run** — bring-up presents a launcher and no
  tool sends traffic to the container until the user selects automatic mode or
  runs a tool by hand.

## Build-status snapshot

- `[built]`: target lab (app + containerized), crawler, auditor, indicator DB +
  catalogs, blind SQLi fuzzer, deploy script, logs, planning docs; `core/` + unified
  store + migrations + config/logging/budget/HTTP-seam/features + per-host
  credential store (Phase 0 + T1.1); ground-truth label contract; integration
  harness; local web launcher; the session manager (Phase 1, unit-tested — live
  two-lab validation pending).
- `[planned, near-term]`: deterministic hardening (Phase 2), grey-box
  instrumentation (Phase 3); migrate tool HTTP onto the seam + session for live
  per-identity runs (T1.10).
- `[planned, later]`: bandit, classifier, proxy, ranker/active learning, mutation
  engine, protocol depth, plugin system, second target.
