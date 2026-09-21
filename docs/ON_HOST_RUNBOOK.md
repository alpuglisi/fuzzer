# On-host runbook

Step-by-step for running the toolkit against the containerized lab on your own host
(the sandbox that builds this repo has no container daemon or live target, so these
steps are done here). Pairs with `docs/ON_HOST_TASKS.md` (the checklist of deferred
live work) and the phase plans.

> **Lab-only.** The target app is deliberately vulnerable. Keep the web tier on
> `127.0.0.1`, never publish the database, and never point the tools at anything you
> are not authorized to test. The fuzzer requires `--authorized`.

---

## Part A — Bring up the lab and verify the DB fix

1. **Pull the latest branch.**
   ```bash
   git pull            # main, includes the config.php pff-user fix (BUG-0004)
   ```

2. **Start the containerized lab** (Docker or Podman). A Compose **provider** must be
   installed — the `docker`/`podman` CLI alone is not enough. On Fedora
   (podman-docker):
   ```bash
   sudo dnf install -y podman-compose        # or, on Docker Engine: docker-compose-plugin
   ```
   Then:
   ```bash
   cd lab
   cp .env.example .env          # local lab credentials (not real secrets)
   ./labctl.sh up                # build + start; serves http://127.0.0.1:8080/
   ./labctl.sh status            # wait for the db healthcheck to report healthy
   ```
   (`labctl.sh` auto-selects `docker compose` / `podman compose` / `docker-compose` /
   `podman-compose` — the first that works — and prints an install hint if none is
   found.)

3. **Verify the DB connection** (this is what BUG-0004 fixed — the app connects as the
   least-privilege `pff` user, not `root`):
   ```bash
   curl -s http://127.0.0.1:8080/product.php?id=1 | head -20
   ```
   You should get the product page HTML, **not** `Database connection failed: Access
   denied for user 'root'`. If you see a DB error, check `./labctl.sh logs` and that
   `.env` was copied.

   *Manual (bare LAMP) alternative:* follow `puppy-fort-factory/README.md` — it now
   creates the `pff` user (never root) and `config/config.php` defaults to it.

4. **Reset to a clean DB** whenever you want a fresh run:
   ```bash
   ./labctl.sh reset
   ```

## Part B — Install the toolkit

From the repo root, in a Python 3.11+ venv:
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[browser,web]"     # core + JS-crawl (Playwright) + web launcher
playwright install chromium         # headless browser for JS-rendered pages
```
`fuzzlab <command>` is then on your PATH (or use `python -m fuzzlab <command>`).
Nothing runs against the target until you ask it to (no auto-run, D11).

## Part C — Phase 1: authenticated per-identity run

The lab's test accounts are `admin/admin123`, `alice/password1`, `bob/letmein`.

1. **Save credentials per host+identity** (stored in the OS keyring, D12 — never in the
   repo or the project store; the password is prompted):
   ```bash
   fuzzlab session set-credential --host 127.0.0.1:8080 --identity admin --username admin
   ```

2. **Confirm login detection** prints a usable session header:
   ```bash
   fuzzlab session print --host 127.0.0.1:8080 --identity admin \
     --base-url http://127.0.0.1:8080/
   ```

3. **Run crawl → audit → fuzz for that identity**, all writing to one shared store
   (`--store`), authenticated via `--identity`:
   ```bash
   fuzzlab crawl  --start http://127.0.0.1:8080 --store run.db --identity admin
   fuzzlab audit  --spider-db spider_results.db --store run.db \
                  --identity admin --base-url http://127.0.0.1:8080/
   fuzzlab fuzz   --url http://127.0.0.1:8080/product.php --param id \
                  --store run.db --identity admin --authorized
   ```
   Re-run per identity (`anonymous`, `alice`, …) to get results per identity. Expect
   `product.php?id` and `search.php?q` to be confirmed and the secure pages to stay
   clean (`puppy-fort-factory/VULNERABILITIES.md` is the map).

4. **Two-lab validation:** repeat Part C against a second lab (e.g. an external
   JWT-auth app) using `--host <that-host>` and its own saved credentials, to confirm
   dynamic login detection and per-host credentials across mechanisms (cookie vs JWT).

## Part D — Phase 2: automatic run + request-reduction measurement

Automatic mode is wired as `fuzzlab auto` — it consolidates a crawl, resolves the
plan (D14/D15), and runs the deterministic pipeline (scoped rules eval with
negatives → oracle confirm → target fingerprint → score → request metrics).

1. **Crawl once** (feeds the pipeline), then run the automatic **scored** pass against
   our lab (categories auto-derived from ground truth, D14; scored, D15):
   ```bash
   fuzzlab crawl --start http://127.0.0.1:8080 --db spider_results.db
   fuzzlab auto  --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
                 --store auto.db --ground-truth lab/ground-truth --authorized
   ```
   The summary prints the plan, candidates/negatives, oracle findings,
   `tp/fp/fn/tn` vs ground truth, and the request cost. Add `--identity admin` to run
   authenticated.
2. **Fail-safe check (D15):** point automatic mode at a target with **no**
   `--ground-truth` and no `--categories` — it must refuse loudly:
   ```bash
   fuzzlab auto --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
                --store t.db --authorized            # → error: requires --categories
   fuzzlab auto --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
                --store t.db --categories sql-injection --authorized   # unscored run
   ```
3. **Measure:** compare the auto run's `pipeline_requests` /
   `pipeline_requests_per_finding` in `run_metrics` against a Phase-1 baseline (the
   standalone `fuzz` run's request count) for the same findings — the Phase 2 exit is
   *measurably fewer requests*. Confirm negatives are present:
   ```bash
   sqlite3 auto.db "SELECT key,value FROM run_metrics WHERE key LIKE 'pipeline_%';"
   sqlite3 auto.db "SELECT fired, COUNT(*) FROM evaluation GROUP BY fired;"  -- 0 = negatives
   sqlite3 auto.db "SELECT dbms, framework FROM target;"                     -- fingerprint
   ```

## Part E — Phase 3: grey-box instrumentation

The consumer layer (`fuzzlab/greybox/`) is built and unit-tested behind injected
seams. The on-host work backs those seams with live sources (see
`docs/PHASE_3_PLAN.md` and the Phase 3 checklist in `docs/ON_HOST_TASKS.md`):

1. **Instrument the image (T3.1):** add pcov to `lab/web.Dockerfile` and a
   request-scoped coverage shim (`auto_prepend_file`/`auto_append_file`) that writes
   app-filtered covered lines to a **loopback-only** side channel keyed by a
   per-request correlation-id header the tools set. Rebuild: `./labctl.sh reset`.
2. **Back the readers:** implement the live `CoverageSource` (reads the T3.1 channel)
   and `DbFaultSource` (tails MariaDB's error/general log or a DB error hook); feed
   `app_lines` → `CoverageFrontier` → `shaped_reward` and `record_attempt_signals`
   (already built).
3. **Deterministic reset (T3.5):** add DB snapshot/restore to `labctl.sh` behind the
   `LabControl` seam; call `reset()` between iterations for state-changing payloads.
4. **Wire M10 (T3.6):** have `Oracle.confirm` consult `greybox_confirms` with the
   injected sources and the sink's file/line, so grey-box confirms where a black-box
   mechanism abstains (oracle stays the sole, fail-closed finding-writer).
5. **Exit measurement (T3.7):** on the running instrumented lab, confirm a request
   reaching **new application code** yields a distinguishable (higher) `attempt.reward`
   and that error-based SQLi separates from benign traffic via `attempt.db_fault`.

## Safety checklist (every run)

- Web tier on `127.0.0.1` only; DB never published; app never exposed publicly.
- Fuzzer only with `--authorized`; destructive payload classes stay off by default.
- Credentials live in the OS keyring (D12) — never commit real secrets; `.env` holds
  lab-only throwaway credentials.
- Automatic runs against a target with **no** ground truth fail safe (D15): explicit
  `--categories` required, run unscored, all gates on.
