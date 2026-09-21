# Web UI Revamp — Implementation Plan

Component: **UI** (#12, `fuzzlab/web/`) · Status: `[proposed]` · Last updated: 2026-09-21

Related: `ARCHITECTURE.md` #11 (proxy), #12 (diagnostics/UI), #13 (plugins);
`DECISIONS_AND_ROADMAP.md` (D2, D5, D11, D14, D15); `components/12-diagnostics-and-ui/`.

## 1. Motivation

The web application is not robust enough. Today `fuzzlab/web/` is a small FastAPI app
that renders HTML from Python f-strings — no JS, no template engine, no live updates, no
charts — and it is **strictly read-only over the store**. Its three "modes" are
*automatic* (a stub; the real pipeline seam is unwired and it points the user at
`fuzzlab auto`), *manual* (prints copy-paste command strings + the category list — no
actual controls), and *review* (browse past runs/findings).

The goal is to turn this read-only viewer into a full **local control plane** with:

1. A full suite of controls to **launch each activity** and adjust its flags/options.
2. A **proxy workbench** to review, edit, drop, forward, and repeat intercepted traffic.
3. A dedicated **ML tab**, separate from the primary application.
4. A **TensorBoard-like diagnostics tab** for performance review and deep troubleshooting.

## 2. Terminology (so the plan matches the code)

In fuzzlab, **"plugins" (the PLUG component, #13) is an internal hook system**
(`on_request`, `register_rules`, …) — not a launch-a-thing. The things a user *launches*
are the **CLI activities/tools**: `crawl`, `audit`, `fuzz`, `auto`, `greybox-run`,
`proxy`, `mutate-run`, `report`, `session`. This plan reads "launch each plugin and adjust
flags" as **"launch each activity"**, and gives the hook-plugin system a smaller
treatment (show the active set, toggle `--plugins`).

## 3. Non-negotiable invariants (must survive the revamp)

Baked into the component's requirements/decisions (D11, D14, D15, NFR-UI-*):

1. **No auto-run** — nothing touches the target except by an explicit user action.
2. **Loopback-only** — the control plane binds `127.0.0.1`, never the target's origin.
3. **Authorized gate** — every traffic-sending action stays gated (`authorized: true`
   config + `--authorized` on the tool).
4. **UI does not write result tables** — tools write their own results; the UI
   orchestrates and reads. New time-series metrics are emitted *by the components*, not
   the UI.
5. **Secrets never render** — redaction on write already exists; the UI shows redacted
   values only.

## 4. Target information architecture (tabs)

| Tab | Purpose | Ask |
|---|---|---|
| **Launcher** | Status + run-mode + a form-driven card per activity (all flags), dry-run preview, Run/Stop, live output | #1 |
| **Proxy** | History · Intercept (edit/drop/forward) · Repeater · Scope/Match-Replace | #2 |
| **Results** | The existing runs dashboard + run detail (findings, score, metrics) — kept, polished | — |
| **ML** | Classifier / ranker / conformal / anomaly / active-learning / bandit / mutation | #3 |
| **Diagnostics** | Cross-run trends, intra-run series, learning curves, timings, log tail, store explorer | #4 |

## 5. What already exists (survey result)

Most of the hard backend machinery is built and just not surfaced:

- **Proxy** (`fuzzlab/proxy/`): `intercept.py` (`Interceptor` — pause/edit/drop/forward as
  awaited `asyncio.Future`s), `repeater.py` (`Repeater` — DB-persisted replay tabs,
  byte-exact send via an injected `Sender`), `history.py` (`HistoryWriter` — SQLite flows +
  raw bytes, FTS5 search, secret redaction on write), `matchreplace.py`, `scope.py`,
  `message.py::RawMessage` (byte-exact edit target). The interception **seam is live** at
  `server.py:109-113`.
- **ML** (`fuzzlab/ml/`, `fuzzlab/scheduler/`, `fuzzlab/mutation/`): classifier
  (`ml_pr_auc*`, calibration, logistic weights, GBT), ranker (`rank_ndcg/precision`,
  `explain()`), conformal gate, anomaly (ECOD), active learning, Thompson bandit
  (`bandit_posteriors`), mutation search (`payload_variant`).
- **Store** (`fuzzlab/core/migrations.py`): `run_metrics` (EAV, no timestamp), `attempt`
  (reward/coverage/db_fault/features_json, `created_at`), `flow` (elapsed_ms, protocol,
  `created_at`), `candidate` (score/rank_score/rank_uncertainty), `bandit_posteriors`,
  `model`, `payload_variant`, `repeater_tab`, `run_plugin`.
- **CLI**: all `argparse`, dispatched from `fuzzlab/cli.py`; every traffic command hard-
  gates on `--authorized`; `mutate-run` also gates destructive variants on
  `--allow-destructive`.

## 6. Phase 0 — Foundations (prerequisite for everything)

**Frontend stack (dependency-light, offline, no build step).** Activate **jinja2**
(already a declared `web` dep, currently unused) + a `fuzzlab/web/static/` dir with
**vanilla JS modules**, a small CSS file, and **one vendored charting lib committed to the
repo** (recommend **uPlot**, ~40 KB, time-series-focused) — no CDN, works air-gapped.
Live updates via **SSE** (`EventSource`); actions go back over `fetch`+POST.

**Command-spec registry (backbone of #1).** Rather than hand-mirroring every flag into
HTML (which rots, and violates PA-0001/PA-0003 — don't duplicate a source of truth),
**extract a `build_parser()` from each tool's `main()`** and add
`fuzzlab/web/commandspec.py` that introspects `parser._actions` to emit a JSON form schema
(name, type, default, choices, required, help, sends-traffic, needs-authorized,
destructive). `store_true`→checkbox, `choices`→dropdown, `int/float`→number,
`append`→repeatable, `required`→required. New flags then appear in the UI automatically.

**Execution engine.** `fuzzlab/web/runner.py` launches an activity as a **subprocess**
(`python -m fuzzlab.tools.X …`), tracks it (start/stop/exit), and streams stdout/stderr
over SSE. Subprocess (not in-process) keeps result-writing on the tools' side of the
boundary and makes cancellation clean. `--authorized` is appended **only** when the user
has toggled authorization; **`--dry-run` (FR-UI-5, currently unbuilt) is the default front
door** — it shows the exact argv and sends nothing until the user confirms.

**Unified serve mode for live proxy.** `intercept.py` holds live `asyncio.Future`s, which
are **not cross-process**; today the web app and `fuzzlab proxy` are separate processes
sharing only SQLite. Live edit/drop/forward therefore requires the proxy engine to run
**in the web app's own event loop**. Add an opt-in `fuzzlab web --with-proxy` (or a "Start
proxy" button) that starts `AsyncProxyServer` as an asyncio task inside the FastAPI
process, wired with an `Interceptor` + `MatchReplaceEngine` (the CLI omits both today —
`server.py:79-80`), so routes can call `interceptor.pending()/forward()/drop()`. History
stays cross-process-readable from the store.

*Decisions to record:* "UI launches tools as gated subprocesses (dry-run first,
authorized-gated)" and "unified serve hosts an in-process proxy for live interception."
*Size: L.*

## 7. Phase 1 — Activity Launcher (ask #1)

- Auto-generated form card per activity from the command spec, grouped by "sends traffic /
  read-only."
- **Dry-run preview** of the exact command → **Run** (gated) → **live output** (SSE) →
  exit status; **Stop** cancels the subprocess.
- Category selector (D14) wired for `auto`/`greybox-run`; the D15 no-ground-truth
  fail-safe enforced in the form (require categories, mark unscored).
- Small **Plugins** panel: list `PluginManager.active()` (name/version/priority), toggle
  `--plugins`.
- *Size: M.*

## 8. Phase 2 — Proxy Workbench (ask #2)

Backend primitives already exist; this is largely wiring + UI.

- **History** — flow list + FTS search (`HistoryWriter.search`), raw req/resp viewer
  (`raw_request/raw_response`). *Exists; read-only; cross-process.* **S–M.**
- **Intercept** — pending queue (`interceptor.pending()`); **edit** (re-serialize a
  `RawMessage`), **drop** (`.drop`), **forward** (`.forward(edited)`), enable/disable
  toggle. *Seam exists; needs unified serve + routes.* **M.**
- **Repeater** — list/create tabs (`repeater_tab`), edit + **send** (`Repeater.send`),
  view response. *Exists; needs UI.* **S–M.**
- **Scope / Match-Replace** — manage `Scope` hosts and ordered `MatchReplaceEngine`
  rewrites. **S.**
- **Two engineering gaps to close honestly:** (a) **response editing** isn't implemented —
  the engine only intercepts requests and the `sender` call at `server.py:115` is
  synchronous; add an awaited response-intercept hook (small `ProxyEngine` change,
  CC-PROXY). (b) **replay must use live in-memory bytes, not stored history** — persisted
  flow bytes are *redacted*, so "repeat from history" loses secrets; the UI replays via
  repeater tabs/live messages and labels redacted stored copies.
- *Size: L.*

## 9. Phase 3 — ML tab (ask #3)

Read-only over the store + on-demand model internals; the data already exists,
`web/results.py` just doesn't surface it yet:

- Classifier: `ml_pr_auc(+prevalence/sigma)`, calibration, logistic weights /
  `Ranker.explain()` contributions.
- Ranker: `rank_ndcg/precision(+_random)`, `candidate.rank_score/rank_uncertainty`
  distributions.
- Conformal triage: flag/abstain/drop breakdown (thresholds from `model.calibration`).
- Anomaly (`anomaly_flagged`), active-learning disagreement, **bandit posteriors** (Beta
  mean = α/(α+β), pulls ≈ α+β−2, mean cost), **mutation variants** (`payload_variant`).
- *Size: M.*

## 10. Phase 4 — Diagnostics / TensorBoard-like tab (ask #4)

**Chartable today (no new emitters):**
- Cross-run trend lines over `run_metrics` (pipeline_requests, requests_per_finding,
  tp/fp/precision/recall/f1/mcc, ml_*, rank_*, greybox_*).
- Intra-run series via `created_at`: `attempt.reward`/coverage, `flow.elapsed_ms`.
- Distributions/snapshots: candidate scores, bandit arm state, model registry timeline.
- Store explorer (FR-UI-2): a lightweight built-in table browser (+ optional Datasette
  link).

**Needs new instrumentation (cannot be charted yet — be upfront):**
- **A `metric_series(run_id, source, key, step, ts, value)` table** (additive migration) —
  the backbone, because `run_metrics` has no timestamp/step.
- Emit per-step points from: GBT boosting-round loss / logistic convergence (**training
  curves**), the bandit loop (**posterior / regret-vs-uniform trajectory**), the coverage
  frontier (**growth curve**), `MutationSearch` (**per-step reward/novelty**), and stage
  wall-clock/throughput timings.
- Optional: a queryable **log sink** so the structured `core/obs.py` JSON logs
  (currently stderr-only) can power a live event/log-tail view.
- *Size: L (the tab shell + "now" charts is M; the emitters are the long tail and can land
  incrementally).*

## 11. Security & invariant preservation

- Launcher runs tools **only on explicit click**, **dry-run first**, `--authorized`
  appended only when authorized → no-auto-run intact.
- Proxy interception is **opt-in**, in-process, loopback-bound; the target is never
  same-origin.
- The UI still **writes no result tables**; time-series come from component emitters.
- Redaction preserved; replay avoids leaking via redacted history.
- Everything stays offline (vendored assets, no CDN).

## 12. Process / bookkeeping (per CLAUDE.md)

Each phase ships with: updated `components/12-diagnostics-and-ui/requirements.md` (new
FR-UI-*) and `11-intercepting-proxy` (response-intercept); `ARCHITECTURE.md` #12/#11
edits; `DECISIONS_AND_ROADMAP.md` entries for the two Phase-0 decisions; per-component
change-control entries (CC-UI-*, CC-PROXY-*, CC-CORE-* for the migration); `CHANGELOG.md`;
and tests (route tests, command-spec introspection, dry-run-sends-nothing,
loopback-refusal, redaction).

## 13. Sequencing

**0 → 1 → 2 → 3 → 4.** Phase 0 unlocks the rest; Phases 1–2 deliver the most-requested
control. Phase 4's "chartable now" slice can ship early (read-only) with the
instrumentation emitters trickling in behind it. Phases 3 and 4-now are low-risk
(read-only) and could be parallelized with 1–2.

## 14. Open questions

- Store explorer: built-in table browser vs. embedded/linked Datasette (FR-UI-2 named
  Datasette; a built-in browser avoids a new heavy dep — confirm at build time).
- Charting lib: uPlot (recommended) vs. hand-rolled SVG for the simplest series.
- Whether the live event/log-tail view is worth a persistent log sink now or later.
