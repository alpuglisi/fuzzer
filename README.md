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
puppy-fort-factory/ the deliberately vulnerable PHP/MySQL app
docs/               architecture, decisions/roadmap, per-component specs + logs
```

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

Or run the tools directly (manual mode), consolidating into the shared store:

```bash
fuzzlab crawl --start http://127.0.0.1:8080 --store fuzzlab.db
fuzzlab audit --store fuzzlab.db
fuzzlab fuzz  --url http://127.0.0.1:8080/product.php --param id --authorized --store fuzzlab.db
```

Each tool is also runnable as `python -m fuzzlab.tools.<name>`.

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

- `docs/ARCHITECTURE.md` — components, the store-as-contract, dependencies.
- `docs/DECISIONS_AND_ROADMAP.md` — settled decisions (D1–D11) and the phased plan.
- `docs/PHASE_0_PLAN.md` — the foundations plan and current status.
- `docs/components/` — a requirement spec and an append-only change-control log
  per component.
- `docs/bugs/` — bug investigation documents (root-cause analysis per bug).
- `docs/PREVENTIVE_ACTIONS.md` — the context-free rule list to follow while
  working (every rule derives from a bug investigation).
- `puppy-fort-factory/VULNERABILITIES.md` — the lab's vulnerability map.
