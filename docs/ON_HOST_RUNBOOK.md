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

> **Working directory.** Run `./labctl.sh` from `lab/`, but run the **`fuzzlab`
> commands from the repo root** (`cd ..` out of `lab/`). The examples below use paths
> like `lab/ground-truth`, which resolve from the repo root; from inside `lab/` you
> would instead pass `ground-truth`. When in doubt, an absolute path always works.

## Part C — Phase 1: authenticated per-identity run

The lab's test accounts are `admin/admin123`, `alice/password1`, `bob/letmein`.

1. **Save credentials per host+identity** (stored in the OS keyring, D12 — never in the
   repo or the project store; the password is prompted). The **host is the hostname,
   without a port** (`127.0.0.1`, not `127.0.0.1:8080`) — the session layer looks
   credentials up by hostname; the store normalizes either form to the hostname:
   ```bash
   fuzzlab session set-credential --host 127.0.0.1 --identity admin --username admin
   ```

2. **Confirm login detection** prints a usable session header:
   ```bash
   fuzzlab session print --host 127.0.0.1 --identity admin \
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

1. **Detection benchmark (default with `--ground-truth`).** With a contract, `auto`
   audits the **enumerated ground-truth points** (not only what the crawl reached), so
   the score measures the oracle's true detection rather than crawl coverage:
   ```bash
   fuzzlab crawl --start http://127.0.0.1:8080 --db spider_results.db
   fuzzlab auto  --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
                 --store auto.db --ground-truth lab/ground-truth --authorized
   ```
   The summary prints the plan, points source, candidates/negatives, oracle findings,
   `tp/fp/fn/tn`, request cost, and a **"not audited"** list. It now audits the GET/query
   **and POST-body** points; only the client-only/DOM points (`reviews.php#author`,
   `feedback.php?ref`) are skipped, pending browser execution (M6). Expect `fp=0` on all
   secure controls (the key correctness signal) and `tp≈4–5`: the GET SQLi + reflected
   XSS (`product.php?id`, `blog_post.php?id`, `search.php?q` SQLi + XSS), and possibly
   `login.php` POST auth-bypass SQLi if it confirms via the quoted timing payloads. The
   remaining `fn` are the stored/DOM-XSS points (M6). Add `--identity admin` to run
   authenticated.

   **Note:** POST probing is state-changing on some endpoints (register/checkout/
   add_to_cart), so `./labctl.sh reset` between benchmark runs for clean, comparable
   results. For a **discovery run** (measures the whole tool incl. crawl coverage) use
   `--points crawl`.

   **DOM/stored XSS (M6):** add `--browser` to also audit the client-only/DOM points
   via a real headless browser (Playwright):
   ```bash
   fuzzlab auto --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
                --store auto.db --ground-truth lab/ground-truth --browser --authorized
   ```
   This confirms `reviews.php#author` and `feedback.php?ref` (xss-dom); the "not
   audited" list should then be empty. (Stored XSS on `profile.php` still needs the
   point→case store-endpoint wiring — a follow-up.)
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

## Legend — what kind of step each part is

- **[run]** — the code is built; you run commands and read results. Do these first.
- **[build+run]** — needs an on-host last-mile implementation (live source/socket/lib the
  sandbox can't provide) before the exit runs. Concrete steps are given; ping me and I can
  implement the fuzzlab-side code for you to validate.

The quickest wins are **Parts F, G, H, L** (all `[run]`): same lab, extra flags, read
`run_metrics`. Parts E, I, J, K are `[build+run]`.

---

## Part E — Phase 3: grey-box instrumentation `[build+run]`

Goal: a request reaching **new application code** produces a higher `attempt.reward`, and
error-based SQLi is distinguishable via `attempt.db_fault`. The consumer layer
(`fuzzlab/greybox/`) is built and unit-tested behind injected seams; here you back those
seams with live sources. Do the steps in order.

1. **Add line coverage to the image (T3.1).** Edit `lab/web.Dockerfile` to install pcov
   and point it at the app, then add a request-scoped coverage shim:
   ```dockerfile
   # after the mysqli install:
   RUN pecl install pcov && docker-php-ext-enable pcov
   RUN printf 'pcov.enabled=1\npcov.directory=/var/www/html\n' \
       > /usr/local/etc/php/conf.d/zz-pcov.ini
   RUN printf 'auto_prepend_file=/var/www/html/includes/cov.php\n' \
       >> /usr/local/etc/php/conf.d/zz-pff-waf.ini   # reuse the prepend ini
   ```
   Create `puppy-fort-factory/includes/cov.php` — a **loopback-only** shim that, when a
   per-request correlation header is present, starts pcov and on shutdown writes the
   app-filtered covered lines to a side-channel file keyed by that id:
   ```php
   <?php
   // Grey-box coverage shim (lab-only). No-op unless the tool sets X-Fzl-Cov.
   $cid = $_SERVER['HTTP_X_FZL_COV'] ?? '';
   if ($cid !== '' && function_exists('\pcov\start')) {
       \pcov\start();
       register_shutdown_function(function () use ($cid) {
           \pcov\stop();
           $cov = \pcov\collect(\pcov\inclusive, ['/var/www/html']);
           $out = [];
           foreach ($cov as $file => $lines) { $out[$file] = array_keys($lines); }
           @file_put_contents("/tmp/fzl-cov/" . preg_replace('/[^A-Za-z0-9_.-]/','',$cid),
                              json_encode($out));
       });
   }
   ```
   Bind-mount a writable `/tmp/fzl-cov` for the side channel in `lab/compose.yaml` (a
   named volume or a host bind), then rebuild: `cd lab && ./labctl.sh reset`.

2. **Back the readers (fuzzlab side).** Implement a live `CoverageSource` that reads the
   side channel written in step 1 (keyed by the correlation id the tools send as
   `X-Fzl-Cov`) and a live `DbFaultSource` that tails MariaDB's error/general log (enable
   `log_error`/`general_log` on the `db` service). Feed them through the **already-built**
   `app_lines` → `CoverageFrontier` → `shaped_reward` and `record_attempt_signals`. The
   seam interfaces are `fuzzlab/greybox/coverage.py::CoverageSource` and
   `dbfault.py::DbFaultSource` — the fakes there show the exact contract. *(This is
   fuzzlab code, not container config — say the word and I'll write these against the
   seams so you only have to run them.)*

3. **Deterministic reset (T3.5).** Add DB snapshot/restore to `lab/labctl.sh` (e.g.
   `mariadb-dump` before a run, restore between iterations) so state-changing payloads
   start from a clean DB. Call it between iterations for POST/stored-payload endpoints.

4. **Wire M10 (T3.6).** With the live sources injected, `Oracle.confirm` consults the
   grey-box confirm hook (`greybox/confirm.py`) with the sink's file/line, so grey-box
   confirms where a black-box mechanism abstains — the oracle stays the sole, fail-closed
   finding-writer.

5. **Exit (T3.7).** Run the fuzzer against the instrumented lab, then check that new-code
   requests scored higher and error-based SQLi set the fault bit:
   ```bash
   sqlite3 run.db "SELECT id, round(reward,3), db_fault FROM attempt ORDER BY id DESC LIMIT 10;"
   ```
   Expect a request reaching new app lines to show a higher `reward`, and an error-based
   SQLi attempt to show `db_fault=1` while benign traffic shows `0`.

## Part F — Phase 4: bandit beats the fixed order (T4.6) `[run]`

The bandit orders the oracle's confirmation mechanisms per context; the exit is **fewer
requests per finding** than the fixed cheapest-first order. There is no `--uniform` flag —
the control is simply a run **without** `--bandit`.

1. **Control (fixed order):**
   ```bash
   fuzzlab auto --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
                --store base.db --ground-truth lab/ground-truth --authorized
   sqlite3 base.db "SELECT value FROM run_metrics WHERE key='pipeline_requests_per_finding';"
   ```
2. **Bandit (repeat into ONE store so posteriors accumulate and improve):**
   ```bash
   for i in 1 2 3 4 5; do
     ( cd lab && ./labctl.sh reset )          # POST probes are state-changing
     fuzzlab auto --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
                  --store bandit.db --ground-truth lab/ground-truth --bandit --authorized
   done
   sqlite3 bandit.db "SELECT id,value FROM run_metrics \
     WHERE key='pipeline_requests_per_finding' ORDER BY id;"
   ```
   **Exit:** the bandit's `requests_per_finding` is lower than the control and trends down
   across the repeated runs. Inspect what it learned:
   ```bash
   sqlite3 bandit.db "SELECT context, arm, round(alpha/(alpha+beta),3) AS mean, cost_n \
     FROM bandit_posteriors ORDER BY mean DESC LIMIT 10;"
   ```

## Part G — Phase 5: detection classifier beats baselines (T5.5) `[run]`

Add `--score` to train the detection classifier over the store and write advisory
candidate scores (never labels):
```bash
fuzzlab auto --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
             --store auto.db --ground-truth lab/ground-truth --score --authorized
sqlite3 auto.db "SELECT key, value FROM run_metrics WHERE key LIKE 'ml_pr_auc%';"
```
**Exit:** `ml_pr_auc` > both `ml_pr_auc_prevalence` and `ml_pr_auc_sigma`. The advisory
scores land on candidates:
```bash
sqlite3 auto.db "SELECT id, round(score,3) FROM candidate \
  WHERE run_id=(SELECT MAX(id) FROM run) AND score IS NOT NULL ORDER BY score DESC LIMIT 10;"
```
**Thin-data note:** one PFF run may not have enough confirmed positives to train — then
the model reports `model='prevalence-fallback'` and skips PR-AUC. Accumulate several runs
into the **same** `--store` (crawl → auto repeatedly) to build up candidates/findings
before expecting a strong PR-AUC.

## Part H — Phase 7: ranker + active learning (T7.4) `[run]`

Add `--rank` to train the pointwise ranker (zero extra requests) and score ordering vs a
random baseline:
```bash
fuzzlab auto --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
             --store auto.db --ground-truth lab/ground-truth --rank --authorized
sqlite3 auto.db "SELECT key, value FROM run_metrics WHERE key LIKE 'rank_%';"
```
**Exit:** `rank_ndcg` > `rank_ndcg_random` (and `rank_precision` ≥ `rank_precision_random`).
The advisory rank scores + uncertainty land on candidates:
```bash
sqlite3 auto.db "SELECT id, round(rank_score,3), round(rank_uncertainty,3) FROM candidate \
  WHERE run_id=(SELECT MAX(id) FROM run) AND rank_score IS NOT NULL \
  ORDER BY rank_score DESC LIMIT 10;"
```
**Active learning** (library, no CLI flag) — pick the most informative candidates to
confirm next:
```bash
python - <<'PY'
from fuzzlab.core.store import Store
from fuzzlab.ml.active import propose_queries
with Store("auto.db") as s:
    rid = s.conn.execute("SELECT MAX(id) FROM run").fetchone()[0]
    print("uncertainty:", propose_queries(s, rid, budget=5, method="uncertainty"))
    print("committee:  ", propose_queries(s, rid, budget=5, method="committee"))
PY
```

## Part I — Phase 6: intercepting proxy, live TLS `[build+run]`

The whole offline stack is built (`fuzzlab/proxy/`): byte-exact `RawMessage`, the `h11`
parsed path, scope, match-and-replace, flow history, repeater, interception, the local CA
cache, and the async server (plain-HTTP path). The on-host last mile:

1. **Real upstream + CONNECT/TLS.** Implement the socket `Sender` (connect/send/recv to
   the upstream) and TLS-terminate CONNECT with `LocalCA` leaf certs (mint on first
   CONNECT, cache per host). `AsyncProxyServer` currently returns 501 for CONNECT.
2. **Verify real CA minting** on-host: `pytest tests/test_proxy_server.py::test_real_ca_mints_signed_leaf`
   should pass here (it skips in the sandbox for lack of a working `cryptography`).
3. **Trust the CA** in the browser/OS store used to browse the lab (install
   `fuzzlab-ca.crt`; never distribute the CA key — it stays 0600 on the host).
4. **Exit:** browse the lab through the proxy, intercept a request, hand-edit it to carry
   a **duplicate `Content-Length`**, forward it, and confirm the **exact bytes** go on the
   wire (the raw path) while the parsed path would have rejected it.

## Part J — Phase 8: mutation engine vs the lab WAF (T8.7) `[build+run]`

The engine is built (`fuzzlab/mutation/`): semantics-preserving operators + validator,
context-typed XSS, the filter model + bypass learner, the bandit/coverage search, and the
variant write-back behind the destructive gate. `sqlglot` (SQL-AST operators) installs
cleanly on-host: `pip install "sqlglot>=20,<30"`.

1. **Enable the WAF** (D16, default off): edit `lab/.env` → `PFF_WAF=on`,
   `PFF_WAF_MODE=block` (or `sanitize`), then `( cd lab && ./labctl.sh up )` to restart.
2. **Confirm the filter is live:** a naive payload should be blocked, a classic bypass
   should pass:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" \
     "http://127.0.0.1:8080/search.php?q=1%20union%20select%201"        # 403 (blocked)
   curl -s -o /dev/null -w "%{http_code}\n" \
     "http://127.0.0.1:8080/search.php?q=1%20union/**/select%201"        # 200 (bypass)
   ```
3. **Learn + evade against the live WAF.** Point `FilterLearner` at real canary
   round-trips (an HTTP sender) instead of the offline `FilterModel`, and run
   `MutationSearch` — confirm it finds a semantics-preserving variant the live WAF lets
   through where the base is blocked, and that the variant then confirms via the oracle
   (recorded in `payload_variant`). *(Wiring the live-sender adapter for `FilterLearner`
   is the small last-mile bit — I can add it.)*
4. **Exit:** variants bypass the filter where the base payload is blocked **and** reach
   new code (needs Part E's live coverage).

## Part K — Phase 9: protocol depth `[build+run]`

The WebSocket codec, HTTP/2 frame layer + minimal HPACK, and the raw-frame client are
built (`fuzzlab/proxy/ws.py`, `h2frames.py`, `hpack.py`, `h2client.py`). On-host:
```bash
pip install "wsproto>=1.2,<2" "h2>=4,<5"     # the parsed-path libraries
pytest tests/test_proxy_h2.py                 # all pass on-host (incl. the h2/HPACK paths)
```
1. **Bring up the h2→h1 desync front-end** (D17, opt-in):
   ```bash
   ( cd lab && docker compose --profile desync up -d )   # nginx h2c on 127.0.0.1:8081
   ```
2. **Send a raw HTTP/2 request** with the `H2RawClient` over an h2c socket to
   `127.0.0.1:8081` (the client builds the bytes; the socket send is the last-mile).
   Confirm a normal request is served through the downgrade, and a **byte-exact/arbitrary**
   request (e.g. a header value with CRLF, or a length-desync frame) goes on the wire as
   built.
3. **Exit:** demonstrate an h2→h1 desync primitive against the front-end — lab-only, on
   your own infrastructure.

## Part L — Phase 10: plugins, anomaly, report, transfer `[run]`

1. **Plugins** — a sample plugin extends the toolkit with no core change. Install any
   package that exposes a `fuzzlab.plugins` entry point, then:
   ```bash
   fuzzlab auto --base-url http://127.0.0.1:8080 --spider-db spider_results.db \
                --store auto.db --ground-truth lab/ground-truth --plugins --authorized
   sqlite3 auto.db "SELECT name, version, priority FROM run_plugin \
     WHERE run_id=(SELECT MAX(id) FROM run);"
   ```
   The active set is recorded per run; a failing plugin is contained, not fatal.
2. **Anomaly tripwire** (ECOD, advisory) over the run's candidates:
   ```bash
   python - <<'PY'
   from fuzzlab.core.store import Store
   from fuzzlab.ml.anomaly import detect_anomalies
   with Store("auto.db") as s:
       rid = s.conn.execute("SELECT MAX(id) FROM run").fetchone()[0]
       print(detect_anomalies(s, rid, contamination=0.1))
   PY
   ```
3. **Reproducible report** for any run (read-only; save it alongside your numbers):
   ```bash
   fuzzlab report --store auto.db            # human summary
   fuzzlab report --store auto.db --json     # canonical JSON for diffing
   ```
4. **Transfer to a second target (T10.6).** Stand up an external validation lab (OWASP
   Juice Shop / WAVSEP, per D10) with a ground-truth contract, then run the multi-target
   harness over both:
   ```bash
   python - <<'PY'
   from fuzzlab.core.store import Store
   from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary, format_transfer
   from fuzzlab.labels import contract
   from fuzzlab.tools.probesender import make_probe_sender
   specs = [
       TargetSpec("pff", "http://127.0.0.1:8080",
                  ground_truth=contract.load("lab/ground-truth"), points_source="ground-truth"),
       TargetSpec("juice", "http://127.0.0.1:3000",
                  ground_truth=contract.load("path/to/juice-ground-truth"), points_source="ground-truth"),
   ]
   with Store("transfer.db") as s:
       outs = run_targets(specs, s, sender_for=lambda spec: make_probe_sender(spec.base_url, None))
       print(format_transfer(transfer_summary(outs)))
   PY
   ```
   **Exit:** non-trivial recall on the second target (`generalizes=True`).

## Safety checklist (every run)

- Web tier on `127.0.0.1` only; DB never published; app never exposed publicly.
- Fuzzer only with `--authorized`; destructive payload classes stay off by default.
- Credentials live in the OS keyring (D12) — never commit real secrets; `.env` holds
  lab-only throwaway credentials.
- Automatic runs against a target with **no** ground truth fail safe (D15): explicit
  `--categories` required, run unscored, all gates on.
