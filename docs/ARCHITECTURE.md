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
(and is itself kept in sync under the maintenance rule).

Secondary architecture documents:
- `architecture/oracle-confirmation.md` — the class-pluggable oracle: confirmation
  mechanisms and the injection-class → mechanism mapping across the `references/`
  attack-vector catalogs (component #7).

*Last updated: 2026-09-21.*

Status legend: `[built]`, `[partial]`, `[planned]`. "Built" means implemented and
unit-tested offline (suite: 196 passed / 2 skipped); where a component's exit
criterion or validation must run against the live containerized lab, that is called
out inline and tracked in `docs/ON_HOST_TASKS.md`.

**Where the build is (2026-09-21).** Phases 0–2 are built (foundations, session
manager, deterministic wins). Phase 3 (grey-box) has its offline consumer layer
built; its live coverage/DB-fault sources are on-host. Phase 4 (bandit) and Phase 5
(detection classifier) have their learning cores built offline; their
beats-the-control exits run on the lab. Phase 6 (the intercepting proxy) has its full
**offline** stack built — byte-exact dual-path core, scope, match-and-replace, flow
history, repeater, interception, manual-login session capture, the flow engine, and the
local-CA leaf cache — leaving only live CONNECT/TLS socket serving and browser trust
on-host. Phase 7 (candidate ranker + active learning) is built offline — the pointwise
ranker (NDCG@k/Precision@k vs random), uncertainty sampling, and query-by-committee —
with the real-lab held-out exit on-host. Phase 8 (mutation engine) has begun: the lab
WAF (D16) is the filter-evasion target, and the semantics-preserving operator framework
+ validator are built; context-typed XSS, filter learning, and bandit/coverage search
remain. Phase 9 (protocol depth) is well underway — the from-scratch WebSocket codec and the
byte-exact HTTP/2 frame layer + minimal HPACK + raw-frame client are built; the parsed
`wsproto`/`h2` path, live ALPN/socket, and the opt-in h2→h1 desync lab front-end remain.
Phase 10 (polish + generalization) is complete offline — the plugin system (registry +
pipeline wiring), the ECOD anomaly detector, the reproducible evaluation report, and the
multi-target evaluation harness are built; only the live transfer run against a second
target is on-host. That leaves the accumulated on-host exits and the Lab-track manifest
generator as the remaining work.

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

### 1. Target lab and ground truth `[built app; grey-box offline layer built; generator planned]`
- **Puppy Fort Factory** `[built app]`: PHP/MySQL/Apache app; ~30 pages, ~10
  JavaScript-rendered; documented mix of vulnerable and secure pages. Runs
  containerized with pinned PHP/Apache/MySQL/libxml versions (D7); brought up via
  `lab/labctl.sh` (probes for a working docker/podman compose provider).
- **Ground-truth labels** `[built contract; labels hand-authored]`: a
  machine-readable, out-of-band contract (`labels.json`, `expectedresults.csv`, and a
  separate `injection-points.json`), read from disk by the tools and the harness,
  never served by the target, with opaque case IDs (D9). The loader/consumer is built
  (`fuzzlab/labels/contract.py`) and drives the `fuzzlab auto --ground-truth` scoring.
  Labels are hand-authored initially; later emitted by the manifest-driven lab
  generator (D8), at which point `VULNERABILITIES.md` becomes a generated, human-facing
  artifact. The lab grows into two tiers (dense "range", realistic "shop") with
  annotated / blind / all-secure build profiles.
- **Lab WAF** `[built; default off]` (D16): a configurable, deliberately naive request
  prefilter (`includes/waf.php`, `config/waf-rules.json`) wired globally via PHP
  `auto_prepend_file`. Off by default (a no-op unless `PFF_WAF` is enabled), so existing
  labels stay valid; modes `block`/`sanitize`/`log`. It is the **Phase 8 filter-evasion
  target** the mutation engine learns to bypass — realistic but bypassable, not real
  protection.
- **h2→h1 downgrade front-end** `[built config; default off]` (D17, `lab/downgrade/`): an
  opt-in nginx front-end that terminates HTTP/2 and proxies HTTP/1.1 to the app — the
  **Phase 9 desync research target** for the raw-frame HTTP/2 client. Gated behind the
  `desync` compose profile (a plain `up` never starts it), loopback-only, lab-only.
- **Grey-box instrumentation** `[partial — offline consumer built; live sources on-host]`
  (D7): the consumer layer is built and unit-tested (`fuzzlab/greybox/`): coverage and
  DB-fault readers behind injected seams (`CoverageSource`/`InMemoryCoverageSource`,
  `DbFaultSource`/`InMemoryDbFaultSource`), the shaped multi-tier reward
  (`CoverageFrontier`, `shaped_reward`), the confirm hook, and state-reset call points.
  The **live sources** — Xdebug/pcov line coverage per request, the database error
  hook/query-log reader, and DB snapshot/restore — must run against the container and
  are on-host (`docs/ON_HOST_TASKS.md`).
- **Multi-target evaluation harness** `[built; live transfer on-host]` (Phase 10 T10.5,
  `fuzzlab/harness/multitarget.py`): runs the pipeline against several targets (each a
  base-url + ground-truth contract) and reports per-target + macro transfer metrics with a
  `generalizes` verdict — the generalization evidence. The live run against an external
  validation lab is on-host; the manifest-generated second target plugs in as a
  `TargetSpec`.
- **Manifest-driven generator** `[planned]` (D8): the "lab as a compiler" — one
  manifest plus a safety matrix, seed, and env-profile generate the app, labels,
  docs, and oracle tests, with verdicts derived from `(transform, sink context)`.
  Built as the parallel Lab track after the toolkit foundations.
- **Depends on (components):** none (it is the system under test).
- **Consumed by:** crawler, auditor, fuzzer, proxy, and the reward path.

### 2. `core/` shared library `[built; plugin registry planned]`
- **HTTP client** `[built]`: one send helper behind an injectable seam; requires a
  session context; records raw bytes (`core/http.py`).
- **Store** `[built]`: SQLite access, schema, and numbered forward-only migrations
  (`core/store.py`, `core/migrations.py`; head = migration 5 — core, finding
  url/method/param, session_state, evaluation, bandit cost columns).
- **Features** `[built]`: one versioned extractor with golden-file tests
  (`core/features.py`, `features_json` + `feature_version`).
- **Request budget + concurrency** `[built]`: per-component caps, and a per-host mutex
  so timing measurements run at concurrency 1 (`core/budget.py`).
- **Logging** (structured, `core/obs.py`) and **config** (layered, hashed onto the
  run, `core/config.py`) `[built]`. Also `core/urls.py` (single home of path
  normalization), `core/dedup.py`, `core/fingerprint.py`, `core/hybrid.py`, and
  `core/runmode.py` (the D14/D15 run-mode + no-ground-truth fail-safe).
- **Credential store** `[built]`: keyring-abstracted, with an encrypted-file
  headless/CI fallback on `cryptography` Fernet (PBKDF2, 0600, atomic write; D12);
  secrets by reference only, never in the project store (`core/credentials.py`).
- **Plugin registry** `[planned]` (Phase 10): entry points plus hooks.
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
- **Subcomponents:** rules-as-data registry (`audit/rules_data/default_rules.json`,
  category-scoped), candidate emission with full per-rule evaluation logging (every
  evaluation recorded, not just hits — the `evaluation` table feeds negatives),
  canary reflection probing with context typing, target fingerprinting
  (DBMS/framework/WAF).
- **Depends on (components):** `core/`, session manager, crawler, indicator DB & catalogs.
- **Writes:** `candidate` rows (rule evidence, features), fingerprint data.

### 6. Indicator database and payload catalogs `[built; to extend]`
- **Subcomponents:** `build_sql_db.py` + `php_indicators.db` (28 indicator types
  mapped to `references/` categories); the `references/` payload catalogs;
  payload metadata (family, DBMS, context prerequisites, destructive flag).
- **Depends on (components):** none (static data).
- **Consumed by:** auditor (indicators), scheduler and fuzzer (payloads/families).

### 7. Fuzzing harness and oracle `[built; grey-box/OOB mechanisms partial]`
- **Fuzzing harness** `[built]`: the generalized `template + injection_point +
  payload_source + oracle` pipeline (`harness/pipeline.py`, `harness/auto.py`,
  `harness/scoring.py`, `harness/integration.py`), so one harness serves multiple
  vulnerability classes. Driven end-to-end by `fuzzlab auto` (`harness/auto_cli.py`),
  which consolidates a crawl, runs scoped rules + oracle confirmation, and — with a
  ground-truth contract — scores TP/FP. The legacy `tools/blind_sqli_fuzzer.py`
  remains as the original single-class fuzzer.
- **Oracle** `[built; M8/M10 pending]`: a **class-pluggable** deterministic confirmer
  (`oracle/oracle.py`, `oracle/strategies.py`, `oracle/probe.py`) — the **only**
  writer of `finding` labels — over 7 vuln classes (sqli, reflected/DOM/stored XSS,
  open-redirect, SSTI, file-inclusion, command-injection). Built mechanisms:
  M1 differential timing, M2 error signature, M3 boolean/response differential,
  M4 SSTI evaluation marker, M5 reflected-canary-in-context, M6 browser execution
  (stored/DOM XSS via an injected `BrowserExecutor` — `oracle/browser.py`,
  `tools/browserexec.py`), M7 file-content marker (LFI/traversal), and M9
  redirect-target control. **Pending:** M8 out-of-band callback and M10 grey-box
  (the grey-box reward hook is wired via `greybox/confirm.py`; its live signal is
  on-host). Findings are written in path-normalized form via `core/urls.to_path`.
  Each injection class registers the mechanism(s) that prove it; full mechanism set
  and the injection-class → mechanism mapping (derived from `references/`):
  `architecture/oracle-confirmation.md`.
- **Depends on (components):** `core/`, session manager, scheduler, oracle,
  indicator DB & catalogs; grey-box instrumentation for reward and labels. (The
  oracle itself depends on `core/` and the target lab, plus grey-box signals when
  available.)
- **Writes:** `attempt` rows (features, reward), `finding` rows (labels).

### 8. Payload scheduler (bandit) `[built; on-lab exit pending]` (Phase 4)
- **Subcomponents** `[built]`: `ThompsonBandit` (Beta-Bernoulli) over
  (context, arm) — context = `category:sink|location`, arm = `vuln_class:mechanism`
  (`scheduler/bandit.py`); discrete context buckets and catalog-derived priors
  (`scheduler/context.py`); hierarchical backoff and cost-normalized selection
  (reward per second, migration 5's `cost_sum`/`cost_n`); persisted posteriors
  (load/save); and a `UniformScheduler` control condition (`scheduler/uniform.py`).
  Ordered the oracle's applicable mechanisms in the confirm loop; wired as
  `fuzzlab auto --bandit`.
- **Depends on (components):** `core/`, auditor (candidates), fuzzing harness and
  oracle (rewards), grey-box instrumentation (coverage reward).
- **Reads/writes:** `bandit_posteriors`; chooses the next family per candidate.
- **Pending (on-host):** the beats-uniform-on-hits-per-1000-requests exit (T4.6).

### 9. Mutation engine `[partial — full offline stack built; live coverage exit on-host]` (Phase 8)
- **Operators + semantics validator** `[built]` (`fuzzlab/mutation/`): typed,
  meaning-preserving operators (`operators.py`) and a validator (`semantics.py`) that
  refutes meaning changes via canonicalization + an `sqlglot` AST path (skip-guarded).
- **Context-typed XSS + filter learning** `[built]`: `xss.py` (filter-aware, context-typed
  candidates), `filtermodel.py` (mirrors the D16 WAF from the shared ruleset — offline
  seam), `learn.py::FilterLearner` (learns block/strip behavior, finds semantics-
  preserving bypasses).
- **Bandit/coverage search + write-back** `[built]`: `search.py::MutationSearch`
  (ThompsonBandit operator selection + coverage-guided hill climbing against the grey-box
  seam, budget-bounded/seeded); `catalog.py` records variant provenance to
  `payload_variant` (migration 8) behind the **destructive gate** (NFR-MUT-safe);
  `llm.py::LlmExpander` is the gated, default-off, offline expansion scaffold.
- **Exit** `[on-host]`: against the enabled D16 WAF, variants bypass the filter where the
  base is blocked **and** reach new code (grey-box coverage) vs the static catalog.
- **Depends on (components):** `core/`, indicator DB & catalogs, scheduler,
  oracle, grey-box instrumentation. (A lab WAF is a prerequisite decision, not a
  component dependency.)
- **Writes:** new payload candidates back into the catalog/attempts.

### 10. ML components `[built — classifier, ranker, active learner, anomaly detector; held-out exits on-host]` (Phases 5, 7, 10)
- **Detection classifier** (A.1) `[built; held-out exit on-host]`: the `fuzzlab/ml/`
  package (pure Python — no numpy/sklearn). Honest evaluation (`metrics.py`: PR-AUC +
  leakage-free GroupKFold), the baselines a model must beat (`baselines.py`:
  prevalence, mean+kσ), two models behind one `fit`/`predict_proba` interface
  (`logistic.py`; `gbt.py` — class-balanced gradient-boosted trees), split-conformal
  flag/abstain/drop (`conformal.py`), a store-trained dataset (`dataset.py`), and
  `train.py::train_and_score` (`model_kind` logistic/gbt/auto, OOF selection, advisory
  `candidate.score`, `model` row + OOF metrics, prevalence fallback on thin data).
  **Advisory only** — scores/uncertainty, never `finding` labels. Wired as
  `fuzzlab auto --score`; the panel surfaces the top scored candidates. The
  beats-both-baselines exit on the store's real dataset (T5.5) is on-host.
- **Candidate ranker** (A.2) `[built; held-out exit on-host]` (Phase 7): a pointwise
  learning-to-rank over candidate features augmented with char n-gram TF-IDF
  (`ranking.py`, `text_features.py`, `ranker.py`, `rank_train.py`). Reads candidate
  features, writes advisory `candidate.rank_score`/`rank_uncertainty` (migration 7; kept
  separate from the classifier's `candidate.score`) at **zero request cost**, with
  per-candidate explanations. Evaluated by NDCG@k/Precision@k vs a random-order baseline
  (GroupKFold); wired as `fuzzlab auto --rank`. The real-lab held-out exit (T7.4) is
  on-host.
- **Active learner** (A.6.5) `[built; live budget exit on-host]` (Phase 7): allocates
  oracle budget by uncertainty sampling (reusing `rank_uncertainty`) and query-by-
  committee (a bootstrap `Committee` of rankers) — `active.py::propose_queries` returns
  the candidates to confirm next. Advisory: it proposes; the oracle confirms.
- **Anomaly detector** (A.5) `[built; held-out flow eval on-host]` (Phase 10): a
  parameter-free, pure-Python **ECOD** tripwire (`ml/anomaly.py`) over the store's feature
  vectors — advisory scores/flags (`detect_anomalies` records `anomaly_flagged`), never
  labels — plus the **XGBOD-style hybrid** (`augment` / `train_and_score(hybrid=True)`)
  that feeds the anomaly score into the classifier.
- **Depends on (components):** `core/`, the oracle (labels), and the component
  that produces each model's inputs (auditor for the ranker, fuzzing harness for
  the classifier, proxy/flows for the anomaly detector).
- **Attach as:** plugins on `core/` hooks. Shipping without ML is a config change.

### 11. Intercepting proxy `[partial — full offline stack built; live TLS serving on-host]` (Phase 6)
- **Dual-path core** `[built]` (D4, `fuzzlab/proxy/`): the **raw byte path**
  (`message.py::RawMessage`) — byte-exact, round-trips received bytes and edits by byte
  surgery so untouched lines stay verbatim (NFR-PROXY-byte-exact) — and the **parsed
  path** over `h11` (`parser.py`). The exit criterion holds in miniature: a hand-edited
  conflicting duplicate `Content-Length` forwards byte-for-byte on the raw path while
  the parsed path rejects it.
- **WebSocket framing** `[built]` (Phase 9 T9.1, `ws.py`): a from-scratch, byte-exact RFC
  6455 frame codec (encode/decode, masking, fragmentation, control frames) + the handshake,
  recorded in history with a `protocol` tag (migration 9).
- **HTTP/2 raw path** `[built]` (Phase 9 T9.2/T9.3): from-scratch byte-exact frames
  (`h2frames.py`, with a declared-length-override desync primitive), a minimal HPACK
  (`hpack.py`, passes arbitrary header bytes), and the raw-frame client (`h2client.py` —
  preface→SETTINGS→HEADERS→DATA and arbitrary/malformed sequences), for authorized desync
  research against the self-owned lab. The parsed `wsproto`/`h2` path and live ALPN/socket
  are the rest of Phase 9 (on-host).
- **Scope + match-and-replace** `[built]`: a default-deny scope engine (`scope.py`,
  host + optional path regex) and ordered byte-level rewrites (`matchreplace.py`).
- **History, repeater, interception, session capture** `[built]`: `flow` history
  (`history.py` — FTS5, batched writes, content-addressed bodies + raw bytes, secret
  redaction on write; migration 6); repeater (`repeater.py` — DB-persisted tabs, replay
  via a sender seam); interception-as-awaited-`asyncio.Future` (`intercept.py`);
  manual-login **session capture** (`session_capture.py` → `SessionManager.adopt`,
  FR-PROXY-9/FR-SESS-11 — the escape hatch for logins detection can't crack: MFA,
  CAPTCHA, multi-step). For **live** interception the engine is hosted in the web app's
  event loop by `web/proxycontrol.py` (D19), since the intercept futures are not
  cross-process; the standalone `fuzzlab proxy` remains for record-and-forward.
  **Responses** are now optionally intercepted too (an awaited engine hook gated by
  `Interceptor.intercept_responses`, default off so the path stays byte-exact).
- **Flow engine + CONNECT/TLS** `[partial]`: `server.py::ProxyEngine` is the sans-I/O
  pipeline (scope → match-replace → intercept → byte-exact forward → history) and
  `AsyncProxyServer` the asyncio socket layer (plain-HTTP path tested offline over
  loopback); `ca.py::LocalCA` is the local CA with a per-host leaf-cert cache (real
  minting is lazy `cryptography`). **Live CONNECT + TLS socket serving and browser trust
  of the CA are the on-host last mile.**
- **Depends on (components):** `core/`, session manager (attached as an addon).
- **Role:** optional observer; other tools may route through it for unified
  history, but timing-sensitive traffic does not (D5).

### 12. Diagnostics and UI `[built control panel; revamp in progress (see docs/UI_REVAMP_PLAN.md)]`
- **Subcomponents:** a **local web application** (D11, `fuzzlab/web/`) `[built]` — a
  FastAPI control panel (loopback-only, read-only over the store, no auto-run) that
  hosts the **launcher with run-mode selection** (automatic vs manual; nothing is sent
  to the target until the user chooses) and a dashboard + run-detail view for live
  runs and results, surfacing oracle findings and the advisory model scores with their
  flag/abstain/drop decision (`web/app.py`, `web/results.py`). The `run_metrics` table
  and structured audit/debug logs are built.
- **Revamp (in progress, `docs/UI_REVAMP_PLAN.md`):** growing the read-only panel into a
  full control plane over a **tabbed shell** (Launcher / Proxy / Results / ML /
  Diagnostics; jinja2 templates + a `/static` asset pipeline). Phase 0 foundations built:
  a **command-spec registry** (`web/commandspec.py`) that derives per-tool flag forms from
  each tool's own `argparse` parser (every tool exposes `build_parser()`), **SSE plumbing**
  (`web/sse.py`), a **subprocess runner** (`web/runner.py`) with dry-run preview,
  authorized-gated execution, and live SSE output (`/api/launch*`; only declared flags reach
  argv, no shell), and a **unified serve mode** (`web/proxycontrol.py`, `fuzzlab web
  --with-proxy`) that runs the intercepting proxy in the panel's own event loop so live
  interception's futures work (D19; opt-in, `--authorized`-gated, loopback-only, separate
  port). Phase 1 built the **Activity Launcher UI**: per-tool forms rendered from each
  command spec, a dry-run preview, gated Run with live SSE output + Stop, a D14 category
  picker, and a plugins panel (verified end-to-end in a real browser). Phase 2.1 added the
  **Proxy tab's read-only flow History** (`web/proxyview.py`; `/api/proxy/flows[/{id}]`;
  cross-process store reads, DOM-safe rendering of untrusted flow fields). Phase 2.2 added
  **live Intercept** — request/response toggles, a polled pending queue, and edit / forward
  / drop over the in-process proxy (verified over real sockets). Phase 2.3 added the
  **Repeater** (`RepeaterController`; `/api/proxy/repeater/*`) — persisted replay tabs,
  byte-exact send (authorized-gated), and "→ Repeater" from a History flow. Phase 2.4 added
  **Scope + Match-Replace** management (`/api/proxy/scope`, `/api/proxy/matchreplace`),
  **completing the Proxy workbench** (History · Intercept · Repeater · Scope/Match-Replace).
- **Layout redesign (`docs/UI_LAYOUT_REDESIGN.md`, D-UI-shell):** the panel's five sections
  now live in a persistent **app shell** — a left-sidebar nav + a top context bar (target /
  scope / authorized / proxy chips) — over a **design-token** system (`web/static/tokens.css`:
  light / dark / system theme + compact density, persisted per-viewer, no-FOUC). Delivered as
  **R0** (`base.html` shell, retokenized `app.css`, `initShell()`; chrome-only, no behavior
  change, hash-based section switching preserved; CC-UI-0021, FR-UI-8). The **Launch view** was
  then rebuilt as the approved **master-detail** — a grouped, gate-tagged activity picker →
  the selected activity's command-spec form (`initLaunchNav()`; CC-UI-0022), brought forward
  from R1. R1 still adds deep-linkable per-section routes + an Overview dashboard, R2 a Findings
  workbench, R3 a Proxy rebuild.
  **Pending:** the ML tab (Phase 3), the TensorBoard-like diagnostics tab + a
  `metric_series` time-series table (Phase 4), Datasette-style store exploration, a
  `--dry-run` mode, and a plain CLI entry point per tool for headless use
  (`fuzzlab auto` exists today).
- **Reproducible evaluation report** `[built]` (Phase 10 T10.4, `fuzzlab/report/`): a
  deterministic report over a stored run (run/config identity, target, counts, findings,
  metrics, deployed models, active plugins), canonical JSON for diffing; read-only
  `fuzzlab report [--run] [--json]`.
- **Depends on (components):** `core/` (store and logging); in automatic mode the
  web app invokes the tools (crawler, auditor, fuzzer, harness).
- **Purpose:** the research-platform diagnostics from decision D2, made easy to
  review in a browser (D11), to verify functionality and locate bugs; and to keep
  the user in control of when the tools touch the target (the no-auto-run
  principle).
- **Safety:** the web app is bound to loopback, never exposed, and strictly
  separated from the vulnerable target (different origin/port; never in the
  target's web root), so the control plane is never itself an attack surface.

### 13. Plugin system `[built]` (Phase 10)
- **Registry + hooks** `[built]` (`fuzzlab/plugins/`): `importlib.metadata` entry-point
  discovery, a `HookRegistry` with the seven hooks (`on_request`, `on_response`,
  `on_candidate`, `on_finding`, `register_rules`, `register_payload_source`,
  `register_oracle`), per-plugin **priority** ordering, contain-log-**disable** isolation,
  and the oracle/advisory-split guard (observation returns ignored; only `register_oracle`
  reaches the finding-writer). `PluginManager` records the active set to `run_plugin`
  (migration 10). Zero plugins is a full no-op (D6).
- **Pipeline attachment** `[built]` (T10.2): `on_request`/`on_response` at the HTTP seam
  (`core/http.py`), `register_rules`/`on_candidate` in the auditor, `register_oracle`/
  `on_finding` in the oracle; `plugins` threads through `run_pipeline`/`run_auto`
  (`fuzzlab auto --plugins`). `register_payload_source` is consumed by the mutation
  engine's `PayloadPool` (`MutationSearch.search_pool`) — all seven hooks are wired.
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
  posture throughout, **no auto-run** — bring-up presents a launcher and no
  tool sends traffic to the container until the user selects automatic mode or
  runs a tool by hand — and a **no-ground-truth fail-safe** (D15): an automatic run
  against a target we have no ground truth for requires an explicit category
  selection (never guesses or tests everything), runs unscored, keeps every safety
  gate on, and fails loudly if categories are not given.

## Build-status snapshot

Suite: 390 passed / 4 skipped (the skips need a native build unavailable in the sandbox:
2 credential-store tests, the proxy real-CA minting test, and the mutation engine's
`sqlglot` AST test). Everything below is offline-complete unless an on-host item is named.

- `[built]` (offline-complete, unit-tested):
  - **Foundations (Phase 0 + T1.1):** `core/` — unified store + forward-only
    migrations (head = 10), config, structured logging, request budget + per-host
    timing mutex, HTTP seam, versioned features (golden-file), path normalization,
    dedup, fingerprint, run-mode + D15 fail-safe, and the per-host credential store
    (`cryptography` Fernet fallback).
  - **Session manager (Phase 1):** detection-based login/session handling with
    per-identity state and non-secret state persistence (live two-lab validation
    pending, on-host).
  - **Discovery + audit:** crawler/spider, auditor (rules-as-data + full evaluation
    logging), indicator DB + payload catalogs, ground-truth label contract, and the
    integration harness.
  - **Deterministic wins (Phase 2):** the generalized fuzzing harness and the
    class-pluggable **oracle** (mechanisms M1–M7 + M9 across 7 vuln classes; the sole
    finding-writer), driven by `fuzzlab auto` with TP/FP scoring against ground truth.
  - **Bandit scheduler (Phase 4):** Thompson sampling with context buckets,
    catalog priors, cost-normalized selection, hierarchical backoff, persisted
    posteriors, and a uniform control (`fuzzlab auto --bandit`).
  - **Detection classifier (Phase 5):** the advisory `fuzzlab/ml/` core — honest
    eval, prevalence/sigma baselines, logistic + gradient-boosted-tree models,
    conformal flag/abstain/drop, store-trained dataset, train/score/persist
    (`fuzzlab auto --score`); scores only, never labels.
  - **Candidate ranker + active learning (Phase 7):** per-page ranking metrics
    (NDCG@k/Precision@k), char n-gram TF-IDF, a pointwise ranker with explanations
    writing advisory `candidate.rank_score` at zero request cost (`fuzzlab auto --rank`,
    migration 7), and active learning (uncertainty sampling + query-by-committee) to
    allocate the oracle budget; advisory only.
  - **Anomaly detector (Phase 10):** a pure-Python ECOD tripwire (`ml/anomaly.py`,
    advisory scores/flags) + the XGBOD-style hybrid feature for the classifier
    (`train_and_score(hybrid=True)`); never labels.
  - **Diagnostics/UI:** the loopback FastAPI control panel + dashboard/run-detail
    (findings + advisory scores), and the deterministic reproducible evaluation report
    (`fuzzlab report`, Phase 10 T10.4).
  - **Lab WAF (D16):** a configurable, default-off, deliberately bypassable request
    prefilter — the Phase 8 filter-evasion target.
  - **h2→h1 downgrade front-end (D17):** an opt-in, default-off (profile-gated) nginx
    front-end that downgrades HTTP/2 to HTTP/1.1 — the Phase 9 desync research target.
- `[partial]`:
  - **Grey-box (Phase 3):** offline consumer layer (coverage/DB-fault readers,
    shaped reward, reset call points) built; **live sources on-host** (Xdebug/pcov,
    DB error hook, snapshot/restore).
  - **Mutation engine (Phase 8):** the full offline stack is built — operators +
    semantics validator (canonical + `sqlglot` AST), context-typed filter-aware XSS, the
    filter model + bypass learner, the bandit/coverage-guided search, variant write-back
    to `payload_variant` (migration 8) behind the destructive gate, and the gated
    default-off LLM scaffold; only the live filter-bypass + coverage exit (T8.7) remains.
  - **Protocol depth (Phase 9):** the from-scratch WebSocket frame codec + handshake, the
    `flow.protocol` tag (migration 9), and the byte-exact HTTP/2 frame layer + minimal
    HPACK + raw-frame client are built; the parsed `wsproto`/`h2` path, live ALPN/socket,
    and the opt-in h2→h1 desync lab front-end remain.
  - **Plugin system (Phase 10):** the `HookRegistry` (7 hooks, priority, contain-log-
    disable isolation, oracle/advisory-split guard), entry-point discovery, `PluginManager`,
    `run_plugin` recording (migration 10), and the pipeline wiring (T10.2 — HTTP seam,
    auditor, oracle; `fuzzlab auto --plugins`) and the `register_payload_source` consumer
    (mutation `PayloadPool`) are built — all seven hooks wired.
  - **Oracle mechanisms:** M8 (out-of-band) and M10 (grey-box) still to build.
  - **Intercepting proxy (Phase 6):** the full offline stack is built — byte-exact
    dual-path core (`RawMessage` + `h11`), scope, match-and-replace, flow history
    (migration 6, FTS5), repeater, interception, manual-login session capture, the
    sans-I/O flow engine, and the local-CA leaf cache; only live CONNECT/TLS socket
    serving and browser trust remain (on-host).
- `[on-host]` (offline pieces done; the exit/validation runs on the live lab):
  Phase 3 live capture; Phase 4 beats-uniform exit (T4.6); Phase 5 held-out exit
  (T5.5); Phase 6 live CONNECT/TLS serving + browser trust; Phase 7 held-out
  NDCG@k/Precision@k exit + active-learning-budget-vs-random (T7.4); Phase 8
  variants-bypass-the-WAF-and-reach-new-code exit (T8.7); Phase 9 live WS/HTTP-2 + h2→h1
  desync exit (T9.6); Phase 10 live transfer run against a second/external target (T10.6);
  live `--browser`/`--bandit`/`--score`/`--rank` runs and stored-XSS session-to-browser
  wiring — all tracked in `docs/ON_HOST_TASKS.md`.
- `[planned]`: the manifest-driven lab generator (Lab track, the eventual option-C second
  target).
