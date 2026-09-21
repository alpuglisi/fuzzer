# Phase 0 — Foundations (plan)

The lean foundations that every later phase depends on. Producing zero new
vulnerabilities is expected and correct; this phase is about the platform, not
the payloads.

*Last updated: 2026-09-21. See `DECISIONS_AND_ROADMAP.md` (D1–D10) and
`ARCHITECTURE.md`.*

## Goal

One command brings up a pinned, containerized lab and runs the existing tools
against it, all writing to a single SQLite store, and an integration harness
confirms the lab's known vulnerabilities from a machine-readable label contract.
Runs are reproducible and record the exact config and environment they ran under.

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
An assert-known-vulns run that brings up the container, runs crawler → auditor →
fuzzer, compares results against `expectedresults.csv`, and reports
TP/FP/TN/FN. One command; deterministic where feasible; time-based checks
quarantined.
- **Accept:** the harness confirms the known vulnerabilities and runs from one
  command.

### T0.8 — Migrate tools onto the store
Crawler and auditor write to the unified store; the fuzzer reads candidates and
writes attempts and findings. Tools remain standalone-runnable.
- **Accept:** a full run populates `page`, `endpoint`, `parameter`, `candidate`,
  `attempt`, and `finding`.

## Exit criterion

One command runs the tools against the containerized, pinned lab, all writing to
one store; the harness confirms the known vulnerabilities from the machine-
readable labels; each run records its config hash and environment; and the
golden/determinism tests pass.

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
