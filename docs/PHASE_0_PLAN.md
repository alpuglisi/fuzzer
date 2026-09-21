# Phase 0 — Foundations (plan)

The lean foundations that every later phase depends on. Producing zero new
vulnerabilities is expected and correct; this phase is about the platform, not
the payloads.

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (D1–D11) and
`ARCHITECTURE.md`.*

## Status (2026-09-21)

Phase 0 is **built and unit-tested** (30 tests green). Implemented in the
`fuzzlab` package:

- **T0.1** package layout + `pyproject.toml`; tools moved to `fuzzlab/tools/` — done.
- **T0.2** containerized lab under `lab/` — files done; `docker compose config`
  validates. **Bring-up + smoke test must be run in an environment with a
  container daemon** (this sandbox has the docker CLI but no daemon).
- **T0.3** store + numbered idempotent migrations (head = v2) — done.
- **T0.4** config (hash/redaction), logging, budget + timing mutex, HTTP seam — done.
- **T0.5** versioned features + golden tests — done.
- **T0.6** ground-truth label contract (schemas, loader, cross-check) — done.
- **T0.7** integration harness (scoring + assert-known-vulns + `run_metrics`) — done.
- **T0.8** tools consolidate into the unified store via `--store` — done (adapter-based).
- **T0.9** minimal local web launcher (loopback-only, no auto-run) + CLI — done.

Remaining to close Phase 0 end-to-end (needs a running container daemon, i.e. the
user's Fedora/Podman host): bring the lab up with `lab/labctl.sh up`, run
`crawler → auditor → fuzzer --store fuzzlab.db` against it (or automatic mode from
the launcher once the pipeline is wired), and confirm the harness reports the
known vulnerabilities from live data. The deterministic oracle (currently
timing-only findings) lands in Phase 2.

## Goal

One command brings up a pinned, containerized lab and then **presents a user
interface that lets the user choose how to proceed** — it never starts running
tools against the container on its own. The two modes are: **automatic**, which
runs the existing tools in sequence (all writing to a single SQLite store) and an
integration harness that confirms the lab's known vulnerabilities from a
machine-readable label contract; and **manual**, which leaves the lab running and
makes the tools available for hand-driven use, sending nothing to the target until
the user invokes a tool. Runs are reproducible and record the exact config and
environment they ran under.

## Environment approach: containerized (decided)

The lab runs in a container (Podman on Fedora; Docker-compatible), not on the
bare host. Pin PHP + extensions, Apache, MariaDB, and libxml; bind-mount the app
directory into the web root so edits are live; bake in the SELinux, php-fpm, and
database-user setup so it is reproducible; provide one-command up and reset. Build
the image so grey-box coverage (Xdebug/pcov, Phase 3) can be enabled later
without reworking it.

## Tasks

Ordered; each lists a deliverable and an acceptance check.

### T0.1 — Package layout and repo restructure
Create a Python package with a `core/` subpackage; move the existing scripts to a
`tools/` layer that imports `core/`; keep each tool independently runnable; add a
`pyproject.toml` and pinned requirements.
- **Accept:** each existing tool runs from the package and imports `core/`.

### T0.2 — Containerized lab
A `compose` definition and image pinning PHP (+ `mysqli`, room for Xdebug/pcov),
Apache, MariaDB, and libxml; app bind-mounted to the web root; DB seeded from the
schema with a dedicated app user; SELinux-friendly bind mounts; one-command up and
a clean reset.
- **Accept:** a single command serves the app on a local URL with a fresh DB, and
  a reset command restores clean state.

### T0.3 — Project store and migrations
One SQLite database with WAL, `synchronous=NORMAL`, `busy_timeout`, foreign keys,
content-addressed bodies, the core tables from `ARCHITECTURE.md` (reserving
coverage columns), and a numbered, forward-only migration runner.
- **Accept:** a fresh database is created by the migration runner; re-running is
  idempotent.

### T0.4 — `core/` shared library
Layered config (defaults → file → env → CLI) hashed onto the `run` row;
structured logging carrying `run_id`/`tool`/`identity`; the request-budget manager
with a per-host timing mutex; a session-aware HTTP send seam (the real session
manager arrives in Phase 1).
- **Accept:** a run records its config hash; budget checkouts are enforced; the
  timing mutex serializes requests per host.

### T0.5 — Versioned features
`features.py` with `extract_vN(request, response, baseline) -> dict` and a
`feature_version`, plus golden-file tests over fixed (request, response, baseline)
triples.
- **Accept:** golden tests pass; adding a feature bumps the version and can
  recompute historical rows.

### T0.6 — Ground-truth label contract (D9)
Schemas and hand-authored files for the current lab pages: `labels.json` (flow,
transform, sink context), `expectedresults.csv` (Benchmark-style), and
`injection-points.json` (parameter-discovery ground truth). Opaque case IDs; read
out-of-band by the tools and harness; never served by the target.
- **Accept:** a loader validates the files against their schemas and the harness
  consumes them.

### T0.7 — Integration harness
The **automatic mode's** run, invoked from the launcher (T0.9), not on bring-up:
an assert-known-vulns run that runs crawler → auditor → fuzzer, compares results
against `expectedresults.csv`, and reports TP/FP/TN/FN. Deterministic where
feasible; time-based checks quarantined.
- **Accept:** when the user selects automatic mode, the harness confirms the known
  vulnerabilities; it does not run until that mode is selected.

### T0.8 — Migrate tools onto the store
Crawler and auditor write to the unified store; the fuzzer reads candidates and
writes attempts and findings. Tools remain standalone-runnable.
- **Accept:** a full run populates `page`, `endpoint`, `parameter`, `candidate`,
  `attempt`, and `finding`.

### T0.9 — Launcher with run-mode selection (no auto-run)
After the container is up, open a **local web control panel** (localhost-only,
D11) that offers the two run modes and does nothing to the target until the user
acts. Phase 0 ships a minimal panel; the full web dashboard is component #12,
elaborated later. A plain CLI entry point exists alongside it for headless use.
- **Automatic:** run the discovery → fuzz pipeline and the integration harness
  (T0.7) against the lab, and show results.
- **Manual:** leave the lab running and make the tools available for hand-driven
  use — from the panel (and/or as ready-to-run commands with the right
  target/store already wired) — and send nothing to the container until the user
  runs a tool.
- **Safety:** the panel binds to loopback only, is never exposed, and is served
  separately from the vulnerable target (different origin/port; never in the
  target's web root).
- **Accept:** bringing up the environment stops at the launcher; no request
  reaches the lab until the user selects automatic mode or manually runs a tool;
  the panel is reachable only on localhost.

## Exit criterion

One command brings up the containerized, pinned lab and stops at a launcher that
never auto-runs tools; **automatic** mode runs the tools against the lab (all
writing to one store) and the harness confirms the known vulnerabilities from the
machine-readable labels; **manual** mode leaves the lab up with the tools ready to
invoke by hand and sends nothing until asked; each run records its config hash and
environment; and the golden/determinism tests pass.

## Out of scope for Phase 0 (deferred)

Session manager (Phase 1), grey-box coverage collection (Phase 3; only reserve
schema now), any ML, the proxy, and the manifest-driven lab generator (Lab
track).

## To confirm during the build

- The package name.
- Per-project database files plus a small global config database, versus one
  global database (leaning per-project).
- Podman versus Docker (Podman is the Fedora-native default; keep the compose
  file compatible with both).

## Known risks

- SELinux with bind mounts needs the `:Z`/`:z` relabel option; document it.
- Rootless Podman networking between the app and DB containers; use a shared pod
  or compose network.
- Running the lab in a container adds a little latency overhead to timing-based
  detection; keep it constant by always measuring against the container, and note
  it in run metadata.
