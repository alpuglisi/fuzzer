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

## Part E — Phase 3: grey-box instrumentation `[run]`

Goal: a request reaching **new application code** produces a higher `attempt.reward`, and
error-based SQLi is distinguishable via `attempt.db_fault`. The whole live last mile now
ships in the repo — the instrumentation (pcov + the `cov.php` shim), the file-backed
readers, the DB snapshot/restore, the `fuzzlab greybox-run` driver, and the exit check —
so this part is a single command.

### E.1 One command

From the repo root, with the lab prerequisites installed (Part A) and the toolkit
installed (Part B):

```bash
scripts/greybox_e2e.sh
```

It runs, in order (T3.1–T3.7):

1. **Rebuild the instrumented lab** — `cd lab && ./labctl.sh reset` builds the image with
   pcov and the coverage/db-fault shim and re-seeds a clean DB.
2. **Wait for health** at `http://127.0.0.1:${PFF_WEB_PORT:-8080}/`.
3. **Self-test the side channel** with two `curl`s (a benign request records covered
   lines; an error-based SQLi on `login.php`'s username sets `db_fault`). It fails loud
   with a specific hint if either is missing.
4. **Snapshot the DB baseline** (`./labctl.sh snapshot baseline`) for deterministic resets.
5. **Run the live grey-box pass** (`fuzzlab greybox-run … --reset --authorized`).
6. **Print the exit check** (see E.4).

Knobs (all optional env vars): `PFF_WEB_PORT`, `FZL_COV_DIR` (default `/tmp/fzl-cov`),
`GB_STORE` (default `greybox.db`), `GB_POINTS` (`ground-truth` | `crawl` | `auto`),
`GB_SPIDER_DB`, `GB_GROUND_TRUTH`, `GB_SETTLE`.

**If step 3 says pcov is not loaded** (an empty coverage file), a stale image layer is
the usual cause. Force a clean rebuild of the web image, then re-run the script:
```bash
( cd lab && ./labctl.sh down && podman-compose build --no-cache web && ./labctl.sh up )
```
(`web.Dockerfile` installs pcov with `$PHPIZE_DEPS` and asserts `php -m | grep pcov` at
build time, so a genuinely broken build now fails loudly instead of at run time.)

### E.2 What was built (so you can trust/inspect it)

- **Image (T3.1)** — `lab/web.Dockerfile` installs pcov (`pcov.enabled=1`,
  `pcov.directory=/var/www/html`). `auto_prepend_file` is **single-valued**, so the WAF
  and the coverage shim are chained through `puppy-fort-factory/includes/prepend.php`
  (do **not** add a second `auto_prepend_file` line — the last one silently wins). Both
  self-gate, so the default app and every ground-truth label are unchanged.
- **Shim (T3.1/T3.4)** — `puppy-fort-factory/includes/cov.php` is a no-op unless a request
  carries `X-Fzl-Cov`. When present it writes one JSON file per request to
  `/tmp/fzl-cov/<id>`: `{"files": {path: [lines]}, "db_fault": bool, "db_error": "…"}`.
  `db_fault` is captured **per request** from PHP's error state (PHP 8's default mysqli
  throws on a SQL error → a fatal in `error_get_last()`), so there is no racy DB-log
  tailing — the coverage and the fault share one correlation-keyed file.
- **Side channel** — `lab/compose.yaml` bind-mounts the host `${FZL_COV_DIR:-/tmp/fzl-cov}`
  into the container so fuzzlab reads back what the shim writes.
- **Readers (T3.2/T3.4)** — `greybox/coverage.py::FileCoverageSource` and
  `greybox/dbfault.py::FileDbFaultSource` read that side channel; they feed the
  already-built `app_lines` → `CoverageFrontier` → `shaped_reward` and
  `record_attempt_signals`.
- **Deterministic reset (T3.5)** — `lab/labctl.sh snapshot|restore [name]` (fast
  `mariadb-dump`/restore, not a rebuild), driven live by
  `greybox/reset.py::ScriptLabControl`. `greybox-run --reset` restores the baseline
  between stateful (non-GET) points.
- **Driver (T3.6/T3.7)** — `fuzzlab greybox-run` (`greybox/run.py` + `greybox_cli.py`)
  sends a benign baseline plus SQLi/XSS probes per point (each with a fresh `X-Fzl-Cov`
  id), reads coverage novelty + db_fault, writes a shaped-reward `attempt` row, and
  records grey-box `run_metrics`.

### E.3 M10 (grey-box confirmation) — status

`greybox-run` computes M10 **advisorily** and reports `M10 would-confirm` (the sink file
executed, plus a DB fault for SQLi) using the pure decision in `greybox/confirm.py`. The
oracle remains the **sole, fail-closed finding-writer**; folding M10 into `Oracle.confirm`
with a per-candidate sink file/line is the remaining deepening (the contract carries
`vuln_class`/`sink_context` but not a sink line, so that step needs a sink map). Nothing
in Part E writes findings.

### E.4 Exit (T3.7)

The script prints the exit automatically. To re-check by hand:

```bash
sqlite3 greybox.db "SELECT id, payload_family, round(reward,3) AS reward, db_fault
                    FROM attempt WHERE run_id=(SELECT MAX(id) FROM run WHERE tool='greybox')
                    ORDER BY reward DESC LIMIT 10;"
```

Expect payload requests that reach **new app lines** to show a **higher `reward`** than
the benign baseline, and error-based SQLi to show **`db_fault=1`** while benign traffic
shows `0`. (If new-code reward does not exceed baseline, the shim/side-channel is not
wired — the self-test in step 3 catches this first.)

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

## Part I — Phase 6: intercepting proxy, live TLS `[run]`

The offline stack was already built (`fuzzlab/proxy/`): byte-exact `RawMessage`, the
`h11` parsed path, scope, match-and-replace, flow history, repeater, interception, the
local CA cache, and the async server (plain-HTTP path). The live last mile now ships too
— the real upstream `SocketSender`, CONNECT/TLS termination with CA-minted leaves, and a
`fuzzlab proxy` CLI — so this part is a script plus (for HTTPS) importing the CA.

### I.1 One command

```bash
scripts/proxy_e2e.sh
```

It runs, in order: ensure the lab is up → export the local CA → start `fuzzlab proxy`
(recording flows to a store) → fetch the lab **through** the proxy (proves the real
`SocketSender`, HTTP 200) → send a **duplicate-`Content-Length`** request through the
proxy and read it back from the store to prove it went on the wire **byte-exact** while
the parsed path rejects it (the Part I exit) → print how to trust the CA and browse.

Knobs (env): `PFF_WEB_PORT`, `PROXY_PORT` (default 8888), `PROXY_STORE`
(default `proxy_flows.db`), `CA_DIR` (default `~/.fuzzlab/ca`).

### I.2 What was built

- **Real upstream (T6.x)** — `fuzzlab/proxy/socketsender.py::SocketSender`: the injected
  `Sender` seam, now a real TCP/TLS client that forwards the request **byte-exact** and
  reads the whole response back byte-exact (Content-Length, chunked, or close-delimited).
- **CONNECT/TLS (T6.x)** — `AsyncProxyServer(ca=LocalCA(...))` replies `200 Connection
  Established`, TLS-terminates the client with a CA-minted per-host leaf
  (`LocalCA.leaf_cert_files`), and forwards tunnelled requests through the same engine to
  the HTTPS upstream. Without a CA, CONNECT still answers 501 (offline default).
- **CLI** — `fuzzlab proxy` (`fuzzlab/proxy/cli.py`): `--export-ca` writes/prints
  `fuzzlab-ca.crt` (sends nothing, needs no `--authorized`); running the proxy needs
  `--authorized`. Flags: `--host --port --scope (repeatable) --ca-dir --store --identity
  --no-verify-tls --no-tls`.

### I.3 Trust the CA + browse (interactive)

For HTTPS interception, import the CA once and point your browser at the proxy:

```bash
fuzzlab proxy --export-ca --ca-dir ~/.fuzzlab/ca        # prints the .crt path
# import ~/.fuzzlab/ca/fuzzlab-ca.crt into your browser/OS trust store
fuzzlab proxy --scope 127.0.0.1 --ca-dir ~/.fuzzlab/ca --store proxy_flows.db --authorized
# set the browser HTTP/HTTPS proxy to 127.0.0.1:8888, then browse http://127.0.0.1:8080/
```

The CA private key never leaves the host (0600). On-host you can also confirm the real
X.509 paths that skip in the sandbox:

```bash
pytest tests/test_proxy_server.py::test_real_ca_mints_signed_leaf \
       tests/test_proxy_live.py::test_connect_tls_tunnel_forwards_byte_exact
```

### I.4 Exit (byte-exact malformed forwarding)

The script proves it automatically (step 5). By hand: with the proxy running, intercept a
request, hand-edit it to carry a **duplicate `Content-Length`**, forward it, and confirm
the recorded flow's raw request has both headers verbatim while
`fuzzlab.proxy.parser.is_valid_request` returns `False` — the raw path forwards what the
parsed path would reject.

## Part J — Phase 8: mutation engine vs the lab WAF (T8.7) `[run]`

The engine was already built (`fuzzlab/mutation/`): semantics-preserving operators +
validator, context-typed XSS, the filter model + bypass learner, the bandit/coverage
search, and the destructive-gated variant write-back. The live last mile now ships too —
`HttpFilter` (the `Filter` seam backed by real WAF round-trips) and a `fuzzlab mutate-run`
driver — so this part is one command. (`sqlglot` for the SQL-AST operators installs
cleanly on-host: `pip install "sqlglot>=20,<30"`; without it the validator falls back to
canonicalization.)

### J.1 One command

```bash
scripts/waf_evasion_e2e.sh
```

It: enables the WAF (D16) and restarts → confirms the filter is live (naive payload 403,
classic bypass 200) → runs `fuzzlab mutate-run` to learn a **semantics-preserving** variant
the live WAF lets through and record it to `payload_variant` → verifies the recorded
variant live (base 403, variant 200) → **restores the WAF to OFF** (leaves the lab in its
default state, even on error). If the Part E side channel (`/tmp/fzl-cov`) exists, it also
measures the variant's coverage gain.

Knobs (env): `PFF_WEB_PORT`, `WAF_MODE` (block|sanitize), `MUT_STORE`
(default `waf_variants.db`), `FZL_COV_DIR`.

### J.2 What was built

- **Live filter (T8.x)** — `fuzzlab/mutation/livefilter.py::HttpFilter` implements the
  mutation `Filter` seam (`caught`/`evaluate`) against the live WAF: it sends the payload
  through a probe sender and maps the block status (HTTP 403) to "caught", parsing the
  matched rule ids from the block page. Drop-in for `FilterLearner`/`MutationSearch` where
  offline tests used `FilterModel.from_lab()`.
- **Driver + CLI (T8.7)** — `fuzzlab/mutation/run.py::run_mutation` + `fuzzlab mutate-run`
  (`fuzzlab/mutation/cli.py`): per base payload, search for a preserving evader; when the
  base is blocked and a variant evades, record it via the destructive-gated
  `record_search_result` (`payload_variant`). `--cov-dir` wires a coverage function over
  the Part E side channel so `coverage_gain` (new app lines the variant reaches) is real.

### J.3 Exit

Variants bypass the filter where the base is blocked (step 4 proves it live: base 403,
variant 200) **and** reach new code. For the coverage half, run Part E first so the shim /
side channel is live, then pass `--cov-dir /tmp/fzl-cov` (the script does this
automatically when the dir exists); the recorded `payload_variant.coverage_gain` is the new
app lines the accepted variant executed that the blocked base could not. Manual check:

```bash
sqlite3 waf_variants.db "SELECT base_payload, variant, operators, bypassed_rule, coverage_gain
                         FROM payload_variant
                         WHERE run_id=(SELECT MAX(id) FROM run WHERE tool='mutate');"
```

## Part K — Phase 9: protocol depth `[run]`

The WebSocket codec, HTTP/2 frame layer + minimal HPACK, and the raw-frame client were
already built (`fuzzlab/proxy/ws.py`, `h2frames.py`, `hpack.py`, `h2client.py`). The
missing socket send/receive now ships as `fuzzlab/proxy/h2transport.py::H2Transport`, so
this part is one command.

### K.1 One command

```bash
scripts/h2_desync_e2e.sh
```

It brings up the opt-in h2→h1 downgrade front-end (compose `desync` profile), waits for
the h2c listener, then: sends a **real HTTP/2 request over an h2c socket** with the raw
client and confirms the front-end serves a response through the downgrade (the self-test:
a HEADERS frame + non-empty body on our stream); and emits the **desync primitives**
byte-exact — a CRLF-in-header-value request and a length-desync frame — reporting how the
front-end handles them.

### K.2 What was built

- **Live h2c transport** — `H2Transport` opens a plaintext TCP socket to the front-end
  (nginx `http2 on;` accepts the HTTP/2 preface with **prior knowledge** — no TLS/ALPN, no
  Upgrade dance). `request(...)` runs a well-behaved exchange (send preface+SETTINGS+HEADERS,
  ACK the server SETTINGS, read to END_STREAM, decode the response — `:status` decodes when
  static-indexed; the body is never HPACK-compressed). `send_raw(...)` writes **exactly**
  the bytes from `H2RawClient.build_raw(...)` for full-control / malformed frames.
- **labctl profile** — `PFF_PROFILE=desync ./labctl.sh up` now brings up the front-end
  (the `--profile` flag is a top-level compose flag, so it is passed before the subcommand).

### K.3 The parsed convenience path (optional, on-host)

The from-scratch modules need no third-party libs and their tests always run. The optional
`h2`/`wsproto` parsed path is separate:

```bash
pip install "wsproto>=1.2,<2" "h2>=4,<5"
pytest tests/test_proxy_h2.py tests/test_proxy_h2_transport.py
```

### K.4 Exit (h2→h1 desync primitive)

The raw client emits the desync primitives on the wire byte-exact (step 4). A **patched
nginx (1.27) correctly rejects** CRLF-in-header-value and length-desync frames — that is
the right defensive behavior, so the demonstration is the *emission* of the primitive and
observing the front-end's handling, not a successful smuggle against a hardened target.
Everything stays loopback, on infrastructure you own.

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
