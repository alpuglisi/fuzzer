# Target Lab and Ground Truth — Change Control Log

Component code: **LAB**. Entry format and required fields: see
`../README.md`. Newest first.

### CC-LAB-0009 — Grey-box instrumentation: pcov + cov.php shim, prepend chain, DB snapshot (Phase 3 T3.1/T3.5) (2026-09-21)
- Change: instrumented the lab image for grey-box runs. `lab/web.Dockerfile` installs pcov
  (`pcov.enabled=1`, `pcov.directory=/var/www/html`). New `puppy-fort-factory/includes/
  cov.php` is a no-op unless a request carries `X-Fzl-Cov`; when present it writes one JSON
  side-channel file per request (`/tmp/fzl-cov/<id>`) with covered app lines **and** a
  per-request `db_fault`/`db_error` marker (from PHP's error state). Because
  `auto_prepend_file` is single-valued, the WAF and the shim are chained through new
  `includes/prepend.php` (the Dockerfile now prepends that, not `waf.php` directly) — this
  also **fixes** the double-`auto_prepend_file` mistake the old runbook prose would have
  produced (the last line silently wins, disabling the WAF). `lab/compose.yaml` bind-mounts
  the host `${FZL_COV_DIR:-/tmp/fzl-cov}` and sets `FZL_COV_DIR`. `lab/labctl.sh` gains
  `snapshot`/`restore` (fast `mariadb-dump`/restore for deterministic resets, T3.5).
  `scripts/greybox_e2e.sh` orchestrates the whole Part E flow (build → health → curl
  self-test → snapshot → `fuzzlab greybox-run` → exit check). `lab/.snapshots/` is gitignored.
- Impact (other components / project): backs the grey-box readers/driver (CC-FUZZ-0016)
  with live sources, making Part E a one-command run. Both instrumentation paths self-gate,
  so the default app and **every ground-truth label are unchanged** (WAF off unless
  `PFF_WAF=on`; coverage a no-op unless `X-Fzl-Cov` is sent). Loopback-only; lab-only.
- Risk (level; mitigation): low–medium — enabling pcov globally adds per-request overhead
  and the prepend chain touches the WAF wiring. Mitigated by: the shim self-gating on the
  header (no cost on ordinary traffic beyond pcov idle), the chain preserving WAF ordering
  (WAF first, may block/exit; coverage second), the side-channel file being written under
  a dedicated `/tmp/fzl-cov` mount, and `scripts/greybox_e2e.sh` self-testing both signals
  before the run. Container-side, so not covered by the Python suite; validated on-host by
  the script's curl self-test.
- Deliverables:
  - [x] pcov in the image; `cov.php` coverage + per-request db_fault shim — done.
  - [x] `prepend.php` chain (fixes single-valued `auto_prepend_file`) — done.
  - [x] compose side-channel mount + `FZL_COV_DIR`; `labctl.sh snapshot/restore` — done.
  - [x] `scripts/greybox_e2e.sh` orchestration; `.gitignore` for snapshots — done.
- Effectiveness (assessed 2026-09-21): pending live confirmation on the host — the script's
  step-3 self-test asserts coverage is recorded and an error-based SQLi sets db_fault
  before the run proceeds. Offline, the readers/driver are covered by CC-FUZZ-0016's tests.

### CC-LAB-0008 — Multi-target evaluation harness (Phase 10 T10.5) (2026-09-21)
- Change: `fuzzlab/harness/multitarget.py` runs the full pipeline against several targets
  — each a `TargetSpec` (name, base-url, optional ground-truth contract) — one `run_auto`
  per target, and produces a **transfer summary**: per-target scores (tp/fp/fn,
  precision/recall from the existing scoring), macro precision/recall over the scored
  targets, a `found_on` list, and a `generalizes` verdict (real vulnerabilities — recall
  > 0 — on ≥ 2 scored targets). The network is injected via `sender_for(spec)` so it is
  offline-testable; `format_transfer` renders a deterministic summary.
- Impact (other components / project): the generalization/transfer capability for
  Phase 10 — evidence the toolkit isn't overfit to the Puppy Fort Factory. The live run
  against an external validation lab (Juice Shop/WAVSEP, D10) is the on-host T10.6 exit;
  the eventual manifest-generated second target (option C) plugs in as just another
  `TargetSpec`. No schema change; reuses `run_auto` + `ScoreReport`.
- Risk (level; mitigation): low — a thin orchestration over the existing pipeline, behind
  an injected sender seam. Mitigated by 4 tests (`tests/test_multitarget.py`): two scored
  targets both confirm SQLi and `generalizes` is True with macro metrics; a mixed
  scored/unscored run summarizes correctly and does not over-claim generalization;
  `format_transfer` text; empty target list. Suite 385 passed / 4 skipped.
- Deliverables:
  - [x] `run_targets` + `transfer_summary` + `format_transfer` (T10.5) — done.
  - [ ] Live transfer run against an external lab (T10.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the harness runs multiple
  targets and reports per-target + macro transfer metrics with a generalization verdict;
  the live external-lab transfer is on-host.

### CC-LAB-0007 — Opt-in h2→h1 downgrade front-end (Phase 9 T9.5, D17) (2026-09-21)
- Change: added a **default-off** front-end reverse proxy to the lab as a desync research
  target. `lab/downgrade/nginx.conf` accepts HTTP/2 (h2c) and proxies **HTTP/1.1** to
  `web:80` (`http2 on;` + `proxy_http_version 1.1;`) — the h2→h1 downgrade topology. A new
  `frontend` compose service (nginx 1.27) is gated behind the **`desync` compose profile**,
  so a plain `up` never starts it and the default lab is unchanged; loopback-only host
  port (`PFF_DOWNGRADE_PORT`, default 8081). Recorded as decision **D17**.
- Impact (other components / project): gives the PROXY component's raw-frame HTTP/2 client
  (T9.3) a self-owned target for the Phase 9 desync exit (T9.6). Off by default → D7
  reproducibility and all prior phases unaffected. Lab-only, never exposed.
- Risk (level; mitigation): medium (a desync target is security-sensitive) — mitigated by
  default-off profile gating, loopback-only binding, lab-only posture, and it being
  infrastructure we own. Mitigated for correctness by 7 tests (`tests/test_lab_downgrade.py`,
  incl. a `docker compose config` profile-gating check when the CLI is present): the
  frontend is profile-gated, loopback-only, mounts the config, depends on web; the default
  services are unchanged; the nginx config does the h2→h1 downgrade; `.env.example`
  documents the port. Suite 348 passed / 4 skipped.
- Deliverables:
  - [x] nginx h2→h1 config + profile-gated compose service + env (T9.5) — done.
  - [ ] Bring it up on-host and demonstrate an h2→h1 desync primitive (T9.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the front-end is off by
  default and, when the `desync` profile is enabled, downgrades HTTP/2 to HTTP/1.1 to the
  app; the live desync demonstration is on-host.

### CC-LAB-0006 — Configurable lab WAF (Phase 8 prerequisite, D16) (2026-09-21)
- Change: added a **configurable, deliberately naive request prefilter** to the lab
  (`puppy-fort-factory/includes/waf.php` + `config/waf-rules.json`), wired globally via
  PHP `auto_prepend_file` (a conf.d ini in `web.Dockerfile`), with `PFF_WAF`/
  `PFF_WAF_MODE` env passthrough in `compose.yaml`/`.env.example`. Modes: `block` (403),
  `sanitize` (strip the matched fragment), `log` (observe). The signatures are naive on
  purpose (e.g. `union select` but not `union/**/select`; `<script>` but not
  `<svg onfocus=>`) — a realistic-but-bypassable filter. **Default OFF:** the file is a
  no-op unless `PFF_WAF` is enabled, so the app and all existing ground-truth labels are
  unchanged (D7 reproducibility preserved). Recorded as decision **D16**.
- Impact (other components / project): resolves the deferred "WAF in the lab" question
  and gives the Phase 8 mutation engine (MUT) a real target for filter-transformation
  learning (FR-MUT-3) and its defeat-the-filter exit. Shared ruleset lets the toolkit
  model the filter offline. No change to the app's behavior while off.
- Risk (level; mitigation): low — off by default and factored so the meaning-bearing
  logic (`pff_waf_check_value`) is pure and testable. Mitigated by 5 tests
  (`tests/test_lab_waf.py`, PHP-CLI driven, skip if `php` absent): ruleset well-formed +
  unique ids; default-off wiring; naive payloads caught; classic bypasses evade;
  benign passes and `sanitize` strips the match. Suite 278 passed / 3 skipped.
- Deliverables:
  - [x] `waf.php` prefilter (block/sanitize/log) + `waf-rules.json` — done.
  - [x] Global wiring via `auto_prepend_file`; env config; default off — done.
  - [x] Offline PHP-driven tests + ruleset validation — done.
  - [ ] Enable on-host and confirm block/sanitize behavior against the live lab — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the filter catches the naive
  payloads and lets the classic bypasses through, exactly the target Phase 8 needs; live
  block/sanitize verification is on-host.

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
