# fuzzlab

A modular, **lab-only** injection security-testing toolkit and research platform,
exercised against a self-hosted, deliberately vulnerable web app (Ryder's Puppy
Fort Factory). Crawler, auditor, and a time-based blind SQLi fuzzer share one
SQLite store; an integration harness scores runs against a machine-readable
ground-truth contract; a local web launcher drives it all.

## Authorized use only

Run this **only** against systems you own or have explicit permission to test.
The whole project is **lab-only**: the target app is served on loopback and must
never be exposed, tools that send traffic require an explicit `--authorized`
flag, and **nothing runs against the target until you ask it to** (no auto-run,
decision D11).

## Engineering process (required reading before you change anything)

This project keeps a deliberate paper trail, and **following it is part of every change,
not optional cleanup.** Start with **[`CLAUDE.md`](CLAUDE.md)** — the mandatory,
session-start checklist that every contributor (human or AI agent) follows. In short,
every change:

- follows **`docs/QUALITY_POLICY.md`**. It states the outcome, classifies the risk, and
  takes the review and verification for that class. It applies the affected control
  families; `docs/quality/CONTROL_INDEX.md` lists the historical
  `docs/PREVENTIVE_ACTIONS.md` rules under each family, with their current requirement;
- adds a line to **`CHANGELOG.md`** and a controlled entry to the primary component's
  **`docs/components/<n>-*/change-control.md`** (append-only);
- keeps the **living specs** current: the affected component's
  **`docs/components/<n>-*/requirements.md`** (edited in place) and, when structure or
  contracts change, **`docs/ARCHITECTURE.md`**;
- and, if it fixes a defect, records it in **`ERROR_LOG.md`**. A significant, recurring
  or systemic defect, a security event or a failed control is formal CAPA: a
  **`docs/bugs/BUG-NNNN-*.md`** investigation that corrects the existing control.

The canonical detail lives in `CLAUDE.md`, `docs/QUALITY_POLICY.md`,
`docs/components/README.md`, and `docs/bugs/README.md`.

## Layout

```
fuzzlab/            the package
  core/             shared library: store + migrations, config, logging,
                    request budget + timing mutex, HTTP seam, versioned features
  tools/            crawler (spider), auditor (fetcher), blind SQLi fuzzer,
                    indicator-DB builder, and the unified-store adapter
  labels/           ground-truth label contract loader + JSON schemas
  harness/          integration harness: scoring + assert-known-vulns
  web/              local web control panel / launcher (loopback only)
lab/                containerized target (compose, Dockerfile, labctl.sh)
lab/ground-truth/   labels.json, injection-points.json, expectedresults.csv
lab/VULNERABILITIES.md  the lab's generated vulnerability map (do not hand-edit)
docs/               architecture, decisions/roadmap, per-component specs + logs
```

The target lab (PHP/MySQL, deliberately vulnerable) is entirely generated —
`fuzzlab.labgen.assemble` renders it from `lab/manifests/*.yaml` and
`fuzzlab/labgen/emitters/php_laravel/` at build time (`lab/web.Dockerfile` / `deploy.sh`).
The hand-built `puppy-fort-factory/` app this replaced was retired by the atomic
cutover (`L-P3.3c-CUT`, `docs/LAB_IMPLEMENTATION_PLAN.md` §4.3.6.5); `lab/ground-truth/`
is unchanged by that cutover.

## Install

```bash
pip install -e ".[web,dev]"      # add ",browser" for JavaScript-rendered crawling
```

## Run (Phase 0)

Bring up the containerized lab (needs Docker or Podman):

```bash
cd lab && cp .env.example .env && ./labctl.sh up     # serves http://127.0.0.1:8080/
```

Open the launcher (loopback only) and choose automatic or manual — it sends
nothing to the target until you do:

```bash
fuzzlab web                                           # http://127.0.0.1:8787/
```

The panel reads the shared store only. Besides the launcher it has an Overview,
Findings, Runs, Proxy, ML and Diagnostics views and a **Site map**
(`/sitetree`): what the tools recorded, browsable by origin (loopback aliases are
one host) → URL path → single-page-app `#/route` → endpoint → parameter →
findings and candidates. Every node shows its findings by severity and its
candidates by oracle status, filters by run, category, severity, status and path,
loads lazily, and refreshes when the store changes. It never shows a stored query
string or any recorded value (parameter examples, evidence); each finding links
to its own page.

Or run the tools directly (manual mode), consolidating into the shared store:

```bash
fuzzlab crawl --start http://127.0.0.1:8080 --store fuzzlab.db
fuzzlab audit --store fuzzlab.db
fuzzlab fuzz  --url http://127.0.0.1:8080/product.php --param id --authorized --store fuzzlab.db
```

Each tool is also runnable as `python -m fuzzlab.tools.<name>`.

`--store` is optional in `report`, `train …`, `mutate-run`, `reveal-holdout`,
`flow-anomaly` and `proxy --record`. (`auto` and `greybox-run` still take it explicitly
for now; for `crawl`, `audit` and `fuzz` it is opt-in consolidation.) A command uses the
first of these that is set:
1. `--store PATH`;
2. `$FUZZLAB_STORE`;
3. `$FUZZLAB_STORE_PATH`;
4. `./fuzzlab.db` in the current directory.

The web UI uses the same rule. Every summary names the store it used:

```bash
fuzzlab report                 # the latest run in ./fuzzlab.db  (stderr: store: …/fuzzlab.db (default))
fuzzlab train models           # the saved models, label-free (the model registry)
```

`fuzzlab --help` groups the commands into four groups:
- **working runs:** fuzzlab used as a tool against a lab target;
- **training and benchmark** (`fuzzlab train …`): ground truth, scored runs, model
  training, holdouts, calibration, the model registry;
- **lab;**
- **other.**

A training or benchmark run is `fuzzlab train run <url>`. It takes the same flags as
`auto`, and needs `--authorized` plus at least one training or benchmark choice that
takes effect, for example:

```bash
# [design] -- the command's parsing and store handling are tested; not yet run here against the lab
fuzzlab train run http://127.0.0.1:8080 --ground-truth lab/ground-truth --score --authorized
```

Give benchmark and training runs their own `--store` when reproducibility matters: bandit
posteriors, holdout reveals and earlier-run training pools are store-wide. The older names
`mutate-run`, `reveal-holdout` and `flow-anomaly` still work; they are now
`fuzzlab train mutate`, `train reveal-holdout` and `train flow-anomaly`.

## The blind SQLi fuzzer

Sends a small payload catalog to one parameter, measures latency against a
per-target baseline, and records observations. Detection is derived purely from
timing, so the ground-truth signal is independent of the payload's own label —
usable for training/evaluating a classifier without label leakage. Benign
payloads are controls; if they are ever flagged, raise `--sigma`/`--min-delay`.

## Tests

```bash
pytest        # 30 tests: store/migrations, config, budget, features, labels,
              # harness scoring, store consolidation, and the web launcher
```

## Documentation

- `CLAUDE.md` — **start here**: the mandatory engineering-process checklist (bookkeeping,
  bug protocol, preventive-action rules) for every change, human or AI agent.
- `docs/ARCHITECTURE.md` — components, the store-as-contract, dependencies.
- `docs/DECISIONS_AND_ROADMAP.md` — settled decisions (D1–D11) and the phased plan.
- `docs/PHASE_0_PLAN.md` — the foundations plan and current status.
- `docs/components/` — a requirement spec and an append-only change-control log
  per component.
- `docs/QUALITY_POLICY.md` — the operating quality policy (risk route, defects vs CAPA,
  twelve control families); `docs/quality/` — the PA-to-family map and its generated index.
- `docs/bugs/` — formal CAPA investigation documents (root-cause analysis).
- `docs/PREVENTIVE_ACTIONS.md` — the immutable history of preventive actions, read through
  the control families.
- `lab/VULNERABILITIES.md` — the lab's vulnerability map, **generated** from
  `lab/ground-truth/labels.json` (`python3 -m fuzzlab.labgen.vuln_map`) — do not hand-edit.
