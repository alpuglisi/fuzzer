# Architecture Overview

High-level outline of the toolkit's components, their subcomponents, how they
interact, and their dependencies. Living document; keep it in sync with
`docs/DECISIONS_AND_ROADMAP.md`.

*Last updated: 2026-09-21.*

Status legend: `[built]`, `[partial]`, `[planned]`.

## Integration model

The **shared SQLite project store is the integration bus** (decision D5). Each
tool runs independently and communicates by reading and writing tables in that
store, not by calling other tools' APIs. Shared concerns live in a `core/`
library that every tool imports (decision D6). The intercepting proxy is an
**optional observer**, never a mandatory pipeline. A deterministic **oracle** is
the only component allowed to write vulnerability labels; machine-learning
components only write scores and uncertainty (the oracle/advisory split).

## Component map

```
                     ┌───────────────────────── Diagnostics / UI ─────────────────────────┐
                     │   TUI (textual)   ·   Datasette over the store   ·   metrics/logs    │
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

### 1. Target lab and ground truth `[built app; planned instrumentation]`
- **Puppy Fort Factory** `[built]`: PHP/MySQL/Apache app; ~30 pages, ~10
  JavaScript-rendered; documented mix of vulnerable and secure pages.
- **Ground-truth manifest** `[partial]`: `VULNERABILITIES.md` today; to become a
  machine-readable label source that tools can join against (overlaps the
  app-scaling work).
- **Grey-box instrumentation** `[planned]` (D7): line coverage (Xdebug/pcov), a
  database error hook, and snapshot/restore for state reset.
- **Depends on:** nothing (it is the system under test).
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
- **Plugin registry**: entry points plus hooks.
- **Depends on:** the store.
- **Consumed by:** every tool and ML component.

### 3. Session manager `[planned]` (Phase 1)
- **Subcomponents:** identity model, cookie jar, token extractors (CSRF, JWT,
  custom), validity checker, re-auth macro with single-flight lock, credential
  access via OS keyring.
- **Interface:** `prepare(request, identity)`, `observe(request, response,
  identity)`, `ensure(identity)`.
- **Depends on:** `core/` (store, http client, config).
- **Consumed by:** crawler, auditor, fuzzer, and the proxy (as an addon). This is
  the most load-bearing dependency; everything authenticated flows through it.

### 4. Crawler / spider `[built; to harden]`
- **Subcomponents:** hybrid fetch (HTTP first, headless on demand), XHR/fetch
  capture, JS endpoint extraction, DOM-skeleton template dedup, state-aware
  navigation, URL normalization, crawl budget.
- **Depends on:** `core/`, session manager, the target lab.
- **Writes:** `page`, `endpoint`, discovered `parameter` rows.

### 5. Auditor / fetcher `[built; to harden]`
- **Subcomponents:** rule registry (moving to rules-as-data), candidate emission
  with full per-rule evaluation logging, canary reflection probing with context
  typing, target fingerprinting (DBMS/framework/WAF).
- **Depends on:** `core/`, session manager, crawler output, the indicator DB.
- **Writes:** `candidate` rows (rule evidence, features), fingerprint data.

### 6. Indicator database and payload catalogs `[built; to extend]`
- **Subcomponents:** `build_sql_db.py` + `php_indicators.db` (28 indicator types
  mapped to `references/` categories); the `references/` payload catalogs;
  payload metadata (family, DBMS, context prerequisites, destructive flag).
- **Depends on:** nothing at runtime (data).
- **Consumed by:** auditor (indicators), scheduler and fuzzer (payloads/families).

### 7. Fuzzing harness and oracle `[built fuzzer; harness+oracle planned]`
- **Fuzzing harness** `[partial]`: generalize `blind_sqli_fuzzer.py` toward
  `template + injection_point + payload_source + oracle`, so one harness serves
  multiple vulnerability classes.
- **Oracle** `[planned]`: deterministic confirmation (differential timing,
  error-signature checks, and coverage/DB-fault signals when grey-box is on). The
  **only** writer of `finding` labels.
- **Depends on:** `core/`, session manager, scheduler, payload catalogs, and (for
  reward/labels) grey-box instrumentation.
- **Writes:** `attempt` rows (features, reward), `finding` rows (labels).

### 8. Payload scheduler (bandit) `[planned]` (Phase 4)
- **Subcomponents:** payload-family arms, discrete context buckets, hierarchical
  Thompson sampling with backoff, catalog-derived priors, cost-normalized
  selection, persisted posteriors, and a uniform-selection control.
- **Depends on:** `core/`, the candidate queue, reward signals from the
  fuzzer/oracle and (ideally) coverage.
- **Reads/writes:** `bandit_posteriors`; chooses the next family per candidate.

### 9. Mutation engine `[planned]` (Phase 8)
- **Subcomponents:** `sqlglot` AST parsing, typed semantics-preserving operators,
  context-typed XSS generation, filter-transformation learning from canaries,
  bandit-scheduled operator selection, coverage-guided hill climbing, optional
  gated offline LLM catalog expansion.
- **Depends on:** payload catalogs, scheduler, oracle/coverage feedback, and a
  lab WAF decision.
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
- **Depends on:** `core/` (features, store) and the oracle for labels.
- **Attach as:** plugins on `core/` hooks. Shipping without ML is a config change.

### 11. Intercepting proxy `[planned]` (Phase 6)
- **Subcomponents:** asyncio core; parsed path (`h11`/`h2`/`wsproto`) and a raw
  byte path (byte-exact, single-use connections); CONNECT + TLS interception with
  a local CA and cached leaf certs; history (FTS5, batched writes, content-
  addressed bodies); repeater (DB-persisted tabs); match-and-replace; scope
  engine; interception-as-awaited-future workflow.
- **Depends on:** `core/` (store, logging), session manager (as an addon).
- **Role:** optional observer; other tools may route through it for unified
  history, but timing-sensitive traffic does not (D5).

### 12. Diagnostics and UI `[planned]`
- **Subcomponents:** a `textual` TUI for live interception and runs; Datasette
  over the store for exploration; a `run_metrics` table; structured audit and
  debug logs; a `--dry-run` mode.
- **Depends on:** the store and `core/` logging.
- **Purpose:** the research-platform diagnostics from decision D2, to verify
  functionality and locate bugs.

### 13. Plugin system `[planned]` (Phase 10)
- **Subcomponents:** `importlib.metadata` entry points; a hook registry
  (`on_request`, `on_response`, `on_candidate`, `on_finding`, `register_rules`,
  `register_payload_source`, `register_oracle`); per-plugin isolation and
  priority.
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
  automatic scope enforcement, a default-off destructive-payload gate, and a
  lab-only posture throughout.

## Build-status snapshot

- `[built]`: target lab, crawler, auditor, indicator DB + catalogs, blind SQLi
  fuzzer, deploy script, logs, planning docs.
- `[planned, near-term]`: `core/` + unified store (Phase 0), session manager
  (Phase 1), deterministic hardening (Phase 2), grey-box instrumentation
  (Phase 3).
- `[planned, later]`: bandit, classifier, proxy, ranker/active learning, mutation
  engine, protocol depth, plugin system, second target.
