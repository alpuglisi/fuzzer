# Target Lab and Ground Truth — Change Control Log

Component code: **LAB**. Entry format and required fields: see
`../README.md`. Newest first.

### CC-LAB-0005 — `labctl.sh` probes for a working Compose provider (2026-09-21)
- Change: `labctl.sh` no longer assumes a `docker`/`podman` CLI implies a Compose
  provider. It probes `docker compose`, `podman compose`, `docker-compose`, and
  `podman-compose` (in that order) via `<cand> version` and uses the first that runs;
  if none works it exits with an install hint (`sudo dnf install -y podman-compose`
  or `docker-compose-plugin`) instead of the raw "looking up compose provider failed"
  dump. Lab README and `docs/ON_HOST_RUNBOOK.md` note the provider prerequisite.
- Impact (other components / project): fixes a confusing bring-up failure on a Fedora
  host that had podman-docker but no compose provider; unblocks the on-host lab. No
  change to the compose stack itself.
- Risk (level; mitigation): low — a shell provider-detection change only. Applies
  PA-0004 (fix the repo, not just the environment, after an environment-only
  incident). Verified by inspection here (this sandbox has no compose provider to run
  it against); to be exercised on the host.
- Deliverables:
  - [x] Provider probing + clear install hint in `labctl.sh` — done.
  - [x] Prerequisite documented (lab README, on-host runbook) — done.
  - [ ] Confirmed `up`/`status`/`reset` on the host with a provider installed — on-host.
- Effectiveness (assessed 2026-09-21): expected effective — the script now selects an
  available provider and gives an actionable message when none exists; live bring-up
  pending on the host.

### CC-LAB-0004 — App DB defaults to the `pff` user, not `root` (BUG-0004) (2026-09-21)
- Change: `puppy-fort-factory/config/config.php` now defaults `DB_USER`/`DB_PASS` to
  the dedicated lab application user (`pff` / `pff_lab_pw`) instead of `root` / empty.
  Updated the app README manual-setup steps to create the least-privilege `pff` user
  (with the exact SQL) and to stop pointing the app at `root`; aligned the
  `schema.sql` import comment to `sudo mysql` (socket auth). No change to the
  containerized path's behavior (compose already supplies `PFF_DB_USER=pff`).
- Impact (other components / project): fixes BUG-0004 — the shipped default targeted
  the DB `root` account, which modern MariaDB authenticates over the unix socket and
  refuses over TCP (`Access denied for user 'root'`), so any run where the PFF_DB_*
  env was not supplied (a manual LAMP setup, or env not propagated) failed to
  connect. The repo default now matches what the lab actually provisions. Unblocks
  the on-host Phase 1/2/3 activities. `config.php` lints clean (`php -l`).
- Risk (level; mitigation): low — a defaults-only change; env vars still override and
  the container path is unchanged. Lab-only throwaway credentials (already present in
  `lab/.env.example`); the DB is never published and the web tier is loopback-only.
- Deliverables:
  - [x] `config.php` defaults → `pff` (never root); explanatory comment — done.
  - [x] App README manual setup creates `pff`, drops root; schema.sql import note — done.
  - [x] `php -l` clean; sole `root` literal removed — done.
  - [ ] Live connect verified on the host (container `labctl.sh up` and/or manual) — on-host.
- Effectiveness (assessed 2026-09-21): expected effective — the only `root` literal in
  the app is removed and the default now matches the provisioned `pff` user; live DB
  connection to be confirmed on the host.

### CC-LAB-0003 — Containerized lab (2026-09-21)
- Change: added `lab/` — a `compose.yaml` (PHP/Apache `web` + `mariadb:11.4` `db`),
  `web.Dockerfile` (`php:8.3-apache` + `mysqli`, room for pcov/Xdebug later), a
  `.env.example`, a `labctl.sh` (up/down/reset/status/logs/pin), and a README.
  The app is bind-mounted (live edits); the DB is seeded on first start from
  `schema.sql`. Realizes Phase 0 T0.2 and decision D7.
- Impact (other components / project): gives every tool a reproducible, pinned
  target and one-command up/reset; the integration harness (T0.7) will run against
  it in automatic mode. No code change to the app; it reads `PFF_DB_*` from the
  environment, which compose supplies.
- Risk (level; mitigation): medium — a deliberately vulnerable app must never be
  exposed. Mitigated by publishing the web tier on `127.0.0.1` only and not
  publishing the DB at all; local-only lab credentials in `.env` (real secrets
  stay in the keyring); SELinux `:Z` bind-mount options documented for Fedora.
  Reproducibility risk (floating tags) mitigated by a documented digest-pin step
  (`labctl.sh pin`), to be locked during build.
- Deliverables:
  - [x] `compose.yaml`, `web.Dockerfile`, `.env.example`, `labctl.sh`, README — done.
  - [x] `docker compose config` validates (syntax + env interpolation) — done.
  - [ ] Actual bring-up + `curl` smoke test — todo (run in the user's Fedora/Podman
    environment; this sandbox has the docker CLI but no daemon).
  - [ ] Pin base images to digests — todo (build-time, `labctl.sh pin`).
  - [ ] Grey-box coverage (pcov/Xdebug) in the image — todo (Phase 3).
- Effectiveness (assessed 2026-09-21): partially verified — the compose file
  validates and the init ordering was checked against `schema.sql` (fresh install
  seeds everything incl. `posts`). End-to-end bring-up is pending in an environment
  with a running container daemon.

### CC-LAB-0002 — Ground-truth label contract implemented (2026-09-21)
- Change: authored the machine-readable, out-of-band ground-truth contract for the
  current lab under `lab/ground-truth/` — `labels.json` (8 vulnerable cases + true
  negatives, opaque `PFF-NNNN` case IDs), `injection-points.json` (parameter-
  discovery ground truth incl. client-only fragment/query points), and
  `expectedresults.csv` (Benchmark-style mirror). Added JSON Schemas
  (`fuzzlab/labels/schemas/`) and a validating loader (`fuzzlab/labels/contract.py`)
  that cross-checks labels.json against expectedresults.csv so they cannot drift.
  Realizes Phase 0 T0.6 and decision D9.
- Impact (other components / project): gives the integration harness (T0.7) a
  scored source of truth and the ML track (D10) its labels; the crawler/auditor
  discovery can be measured against `injection-points.json`. No change to the app
  itself; the files are read from disk and never served by the target.
- Risk (level; mitigation): medium — wrong labels silently corrupt every downstream
  metric. Mitigated by schema validation, the labels/CSV cross-check (a flipped
  verdict is caught), opaque case IDs (no class leaks into the ID a tool sees), and
  authoring directly from `VULNERABILITIES.md`. Labels are hand-authored for now;
  the generator (D8) will emit them later.
- Deliverables:
  - [x] JSON Schemas for labels + injection points — done.
  - [x] `labels.json`, `injection-points.json`, `expectedresults.csv` — done.
  - [x] Validating loader + cross-check; 5 tests — done.
  - [ ] Grey-box instrumentation signals (Phase 3) — todo.
  - [ ] Generator-emitted labels (D8, Lab track) — todo.
- Effectiveness (assessed 2026-09-21): effective — the loader validates and loads
  the real contract (8 positives, negatives present) and catches an injected
  labels/CSV drift; opaque-ID and client-only-point assertions pass.

### CC-LAB-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — the Puppy Fort Factory app
  (~30 pages, ~10 JavaScript-rendered) with a hand-written `VULNERABILITIES.md`,
  deployed by copy-to-webroot on a bare Fedora host.
- Impact (other components / project): the crawler, auditor, and fuzzer target
  this app; ground truth is currently prose, which the integration harness cannot
  consume, so automated scoring is not yet possible.
- Risk (level; mitigation): low. Hand-maintained labels can drift from the app;
  mitigated going forward by the machine-readable label contract (D9) and the
  manifest-driven generator (D8), and by pinning the environment (D7).
- Deliverables:
  - [x] Vulnerable app built and deployed — done.
  - [x] Human-readable vulnerability map — done.
  - [ ] Machine-readable label contract — todo (Phase 0 T0.6).
  - [ ] Containerize with pinned versions — todo (Phase 0 T0.2).
  - [ ] Grey-box instrumentation — todo (Phase 3).
  - [ ] Manifest-driven generator — todo (Lab track).
- Effectiveness (assessed or pending): pending — this is the baseline record.
