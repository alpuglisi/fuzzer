# Error log

A record of identified errors (bugs, deployment failures, environment issues) and
**how they were remediated**. Newest entries at the top. Add an entry whenever
something breaks and is fixed, so the same problem is easy to recognize and
resolve next time.

A **code** defect also needs a full bug report (`docs/bugs/BUG-NNNN-*.md`) and one or
more preventive-action rules (`docs/PREVENTIVE_ACTIONS.md`) — this log alone is not
enough. See `CLAUDE.md` for the full change process.

Format per entry:
- **Date / component**
- **Symptom:** what was observed
- **Root cause:** why it happened
- **Remediation:** what fixed it
- **Status:** Fixed / Open / Environment (fixed outside the repo)

---

## 2026-09-21 — ON_HOST_RUNBOOK documented unbuilt/unverified steps as followable (BUG-0014)

- **Symptom:** the initial runbook's `[build+run]` parts (E, I, J, K) could not be followed —
  they referenced last-mile code that didn't exist and commands/outputs never run, and
  contained concrete errors (a second `auto_prepend_file` line that would silently disable
  the WAF; per-request DB fault via log-tailing; `up --profile desync` that didn't work; a
  duplicate-*identical* Content-Length "exit" that is valid HTTP).
- **Root cause:** operational docs were authored from design intent and never executed/
  verified against the real host, and the format didn't distinguish verified-runnable from
  unbuilt/aspirational steps (`[build+run]` conflated "needs building" with "runnable").
- **Recurrence:** the same root cause recurred across Parts E/I/J/K and produced BUG-0009
  (double auto_prepend), BUG-0012 (dup-CL), BUG-0013 (up --profile) + the "no Compose
  provider" incident; each was fixed piecemeal with no PA about documentation adequacy, so
  the class stayed unguarded (same failure mode as BUG-0013).
- **Remediation:** Parts E/I/J/K rebuilt into verified one-command `[run]` flows backed by
  tested code + self-testing scripts; the concrete errors fixed (BUG-0009/0012/0013); the
  runbook Legend corrected (all parts `[run]`; a `[design]` tag now marks any unbuilt/
  unverified step, which must not be written as followable). Full RCA + recurrence/prior-PA
  analysis in `docs/bugs/BUG-0014-*`; rule PA-0015.
- **Status:** Fixed (this commit). Suite 415 passed / 6 skipped.

## 2026-09-21 — On-host script defects: proxy self-test premise (BUG-0012) + compose recreate (BUG-0013)

- **Symptom (1):** `scripts/proxy_e2e.sh` step 5 reported `FAIL: the parsed path did not
  reject the duplicate Content-Length`, even though the proxy forwarded byte-exact correctly.
- **Root cause (1):** the self-test used two *identical* `Content-Length: 0` headers;
  duplicate-identical CL is valid per RFC 7230 (h11 accepts it) — only *conflicting* values
  are rejected. The script diverged from the offline unit test, which used 5/6.
- **Remediation (1):** the script now sends conflicting values (0 and 5); runbook Part I.4
  clarified. RCA `docs/bugs/BUG-0012-*`; rule PA-0013.
- **Symptom (2):** `scripts/waf_evasion_e2e.sh` / `h2_desync_e2e.sh` step 1 failed under
  podman-compose (`container name ... already in use ... use --replace`; dependent-container
  errors) and left the stack wedged.
- **Root cause (2):** the orchestration assumed `compose up` recreates a running stack in
  place on an env/profile change (a docker-compose behavior); podman-compose cannot. Same
  *class* as the earlier "no Compose provider" entry (assuming a compose capability podman
  lacks) — which was fixed in place and never captured as a PA, so the class recurred.
- **Remediation (2):** `lab/labctl.sh up` is now self-healing — on failure it `down`s (keeps
  the DB volume), force-clears wedged podman containers/pod/network, and retries `up`. Full
  RCA + recurrence/prior-PA-failure analysis in `docs/bugs/BUG-0013-*`; rule PA-0014.
- **Status:** Fixed (this commit). See CC-PROXY-0013, CC-LAB-0011. Suite 415 passed / 6 skipped.

## 2026-09-21 — Proxy on-host: leaf cert rejected (BUG-0010) + shutdown hang (BUG-0011)

- **Symptom (1):** on the host, `pytest ...test_connect_tls_tunnel_forwards_byte_exact`
  failed the TLS handshake with `ssl.SSLCertVerificationError: ... Missing Authority Key
  Identifier`. **Symptom (2):** `scripts/proxy_e2e.sh` hung at 5/6 (stopping the proxy).
- **Root cause (1):** `LocalCA` minted CA/leaf certs without SKI/AKI (and KeyUsage/EKU, and
  a DNSName SAN for IP hosts); strict OpenSSL (Fedora, Py 3.13) rejects a leaf with no AKI.
  **Root cause (2):** `AsyncProxyServer.stop()` awaited `Server.wait_closed()` unbounded,
  which on Python 3.12+ waits for active connections — a lingering connection blocked
  shutdown forever, so the proxy never exited and the script's `wait` hung.
- **Remediation (1):** `_mint_ca` adds SKI + keyCertSign KeyUsage; `_mint_leaf` adds SKI, an
  AKI from the CA public key, serverAuth EKU, a leaf KeyUsage, and an IPAddress SAN for IP
  hosts; dropped deprecated `utcnow()`. Added a skip-guarded extension-assertion test.
  **Remediation (2):** `AsyncProxyServer` tracks + cancels connection tasks and bounds
  `wait_closed()` with a 3s timeout; the proxy CLI persists flow history per-record
  (`batch_size=1`, WAL); `proxy_e2e.sh` bounds its `kill -INT` wait with a `-KILL` fallback.
- **Status:** Fixed (this commit). Full RCAs in `docs/bugs/BUG-0010-*` and `BUG-0011-*`;
  rules PA-0011, PA-0012. See CC-PROXY-0012. Suite 415 passed / 6 skipped.

## 2026-09-21 — Grey-box self-test: coverage file written but empty (pcov not collecting)

- **Symptom:** `scripts/greybox_e2e.sh` step 3 failed with "benign request recorded no
  covered lines — is pcov installed/enabled?" The side-channel file *was* written (the
  shim ran and the host↔container mount worked), but its `files` map was empty.
- **Root cause:** three independent causes, each producing empty coverage, fixed in
  sequence (the step-3 self-test caught each). (1) The `cov.php` shim gated pcov on
  `function_exists('\pcov\start')`, whose leading-backslash string form is unreliable —
  it can be false even when pcov is loaded, so the shim never called `\pcov\start()`/
  `collect()`. (2) `lab/web.Dockerfile` ran `pecl install pcov` without `$PHPIZE_DEPS`
  (autoconf/gcc/make); on a rebuild the PECL build can no-op/fail so pcov never loads,
  and a stale cached layer hid it. (3) **Decisive:** even with pcov loaded, the shim
  called `\pcov\collect(\pcov\inclusive, ['/var/www/html'])` — but pcov's inclusive
  filter is a list of *files*, not directories, so a directory matched nothing and
  `collect()` returned empty.
- **Remediation:** the shim now gates on `extension_loaded('pcov')` (unambiguous) and
  calls `\pcov\collect()` (no directory filter), keeping app files by path prefix; the
  Dockerfile installs `$PHPIZE_DEPS` before `pecl install pcov` and asserts
  `php -m | grep -qi pcov` at build time so a broken layer fails the build (and the
  changed RUN line invalidates the suspect cache). `labctl.sh exec` was added and the
  script now checks pcov is loaded in the container before the curl self-test, printing
  the exact `build --no-cache web` command if not. (cov.php is bind-mounted, so this last
  fix needs no image rebuild — just re-run the script.)
- **Remediation (sweep, PA-0002):** the `mysqli` install now carries the same build-time
  load check; no other fragile `function_exists('\ns\fn')` guards or unverified extension
  installs remain.
- **Status:** Fixed (this commit); live re-run on the host to confirm. Full RCA in
  `docs/bugs/BUG-0009-greybox-coverage-empty-fragile-pcov-guard.md`; rules PA-0008,
  PA-0009. See CC-LAB-0009 update.

## 2026-09-21 — Any credentials "authenticated" (BUG-0008): login success inferred from an anonymous cookie

- **Symptom:** `fuzzlab session print`/`crawl --identity admin` reported a `PHPSESSID`
  cookie and "authenticated as admin (1 cookie(s))" for *any* username/password —
  including a nonexistent user and mismatched identities (`broken_auth.txt`).
- **Root cause:** `SessionManager._login` treated the presence of a session cookie as
  proof of login. PHP's `session_start()` sets an anonymous `PHPSESSID` on the first
  GET (before login), so the jar was non-empty even on a *failed* login; and
  `_verify_authenticated` only checked that `base_url` (the public homepage) was "not a
  login page", which is always true. So auth success was inferred from an *ambient*
  credential the server hands to anonymous users too — a toolkit false-positive, **not**
  the lab's intended (SQLi-based) auth bypass, which plain wrong creds do not trigger.
- **Remediation:** `_login` now fails loud when the login POST response is still a login
  page (`is_login_page`) or is `401/403`, before inspecting cookies — a positive
  differential signal is required. On the lab, wrong creds now error (form re-rendered)
  and correct creds still succeed (redirect to `profile.php`). Regression tests model
  `session_start()`'s pre-login cookie (`AnonCookieLoginFetcher`). Full RCA in
  `docs/bugs/BUG-0008-login-success-inferred-from-anonymous-cookie.md`; rule PA-0007.
- **Status:** Fixed (this commit). See CC-SESS-0008. Suite 394 passed / 4 skipped.

## 2026-09-21 — Credential host-key mismatch (BUG-0007) + ground-truth path traceback

- **Symptom (1):** `fuzzlab crawl --identity admin` failed with `CredentialError: no
  credentials for identity 'admin' on host '127.0.0.1'`, even though the runbook's
  `set-credential --host 127.0.0.1:8080` had been (or would be) used.
- **Root cause (1):** the credential store keyed by the exact `--host` string
  (`127.0.0.1:8080`), but the session/browser-auth path looks credentials up by
  `urlparse(base_url).hostname` (`127.0.0.1`, no port) — the two never matched.
- **Remediation (1):** `credentials.py` normalizes the host to its bare hostname
  (`_norm_host`) on set/get/require/delete, so `127.0.0.1`, `127.0.0.1:8080`, and a full
  URL all key the same; the `require` error now prints the exact `set-credential` command.
  Runbook Part C corrected to `--host 127.0.0.1`.
- **Symptom (2):** `fuzzlab auto --ground-truth lab/ground-truth` (run from inside `lab/`)
  raised a raw `FileNotFoundError` for `lab/ground-truth/labels.json`.
- **Root cause (2):** cwd was `lab/`, so the relative path resolved to `lab/lab/...`; the
  toolkit commands assume the repo root.
- **Remediation (2):** `contract.load` raises an actionable `ContractError` (naming the
  expected path and the repo-root/absolute-path options) and `fuzzlab auto` exits cleanly
  on it; the runbook now states to run `fuzzlab` from the repo root.
- **Status:** Fixed.

## 2026-09-21 — Automatic mode never nominated XSS (rule keyed on a post-detection label)

- **Symptom:** the live `fuzzlab auto` scored run missed every reflected/DOM XSS case
  (e.g. `search.php?q`) as a false negative, though the oracle can confirm reflected XSS.
- **Root cause:** `R-XSS-REFLECT` fired only when `sink_context` was set, but that is a
  label discovery never sets on a fresh point, so no XSS candidate was ever nominated
  for the oracle. `test_pipeline` masked it by hand-setting `sink_context="html"`.
- **Remediation:** `R-XSS-REFLECT` now nominates on location (query/body); the oracle's
  M5 types the reflection context itself and confirms (fail-closed → no FP). Pipeline
  now counts oracle-rejected candidates as negatives. Full RCA in
  `docs/bugs/BUG-0006-xss-never-nominated-in-automatic-mode.md`; rule PA-0006.
- **Status:** Fixed (this commit). See CC-AUD-0009, CC-FUZZ-0010.

## 2026-09-21 — Headless credential store crashed (`No module named 'Crypto'`)

- **Symptom:** `fuzzlab session set-credential` with `FUZZLAB_KEYRING_PATH`/
  `FUZZLAB_KEYRING_PASSPHRASE` set crashed with
  `ModuleNotFoundError: No module named 'Crypto'` (after trying `Cryptodome`).
- **Root cause:** the encrypted-file backend used `keyrings.alt`'s `EncryptedKeyring`,
  which needs PyCrypto/pycryptodome — an undeclared, uninstalled dependency. The
  intended library, `cryptography` (already installed), was never actually wired up;
  the store's tests inject a fake backend, so the real path was never exercised.
- **Remediation:** reimplemented the backend on `cryptography` (Fernet + PBKDF2),
  declared `cryptography` as a dependency, added real round-trip tests (skip when the
  native lib is broken). Full RCA in
  `docs/bugs/BUG-0005-headless-keyring-depended-on-pycrypto.md`; rule PA-0005.
- **Status:** Fixed (this commit; verified on the host after `pip install -e .`).

## 2026-09-21 — `labctl.sh up` failed: no Compose provider

- **Symptom:** on a Fedora host, `./labctl.sh up` dumped
  `Error: looking up compose provider failed / 7 errors occurred: ... docker-compose
  ... podman-compose ... executable file not found`.
- **Root cause:** the host had the `docker`/`podman` CLI (podman-docker) but no
  Compose provider package installed; `labctl.sh` assumed `docker` existing implied
  `docker compose` worked, so it invoked a provider that was not present.
- **Remediation (environment):** install a provider —
  `sudo dnf install -y podman-compose` (or `docker-compose-plugin`).
- **Remediation (repo hardening, PA-0004):** `labctl.sh` now probes each candidate
  (`docker compose`, `podman compose`, `docker-compose`, `podman-compose`) and uses
  the first that runs, and prints an install hint if none is found instead of the raw
  provider dump. Lab README + on-host runbook note the prerequisite.
- **Status:** Environment (install a provider); repo hardened. See CC-LAB-0005.

## 2026-09-21 — App DB config defaulted to `root` (repo default fixed)

- **Symptom:** `config.php` defaulted the DB user to `root`/empty; with no PFF_DB_*
  env, `mysqli_connect` died with `Access denied for user 'root'@'localhost'`. Same
  failure as the 2026-09-18 "Environment" entry below, but this is the repo default.
- **Root cause:** the committed default selected `root`, which modern MariaDB
  authenticates over the unix socket (TCP login refused), and which also disagreed
  with the lab's own dedicated `pff` user (compose/.env). The earlier incident was
  worked around only in the environment, so the repo default stayed broken.
- **Remediation:** defaulted `config.php` to the `pff` app user (never root); updated
  the app README manual setup to create `pff` and the schema import note. Full RCA in
  `docs/bugs/BUG-0004-config-defaults-to-db-root.md`; rule PA-0004.
- **Status:** Fixed (this commit; live DB connect to be confirmed on the host).

## 2026-09-21 — Oracle stored findings with full URLs (path-form mismatch)

- **Symptom:** the T2.8 scored pipeline reported `tp=0, fp=3` — every genuine,
  oracle-confirmed vulnerability counted as a false alarm.
- **Root cause:** `Oracle._write_finding` stored `candidate.url` verbatim
  (`http://localhost/product.php`) while ground truth and every other stored URL
  use path form (`/product.php`); the normalization convention lived only as a
  private helper in `store_adapter`, invisible to the oracle.
- **Remediation:** added `fuzzlab/core/urls.py::to_path` as the single home of the
  convention; the oracle and `store_adapter` both call it. Full RCA in
  `docs/bugs/BUG-0003-oracle-stored-full-urls-not-path-form.md`; rule PA-0003.
- **Status:** Fixed (this commit).

## 2026-09-18 — `build_sql_db.py` / auditor coverage

- **Symptom:** the auditor implemented 28 rules but only ever ran 7; all findings
  were grouped as `references/(unmapped)/`.
- **Root cause:** the indicator database defined only the original 7 indicator
  types and had no `reference` column, so 21 rules had no matching row and never
  executed.
- **Remediation:** updated `build_sql_db.py` to define all 28 indicator types
  (matching the rule registry one-to-one) and a `reference` column mapping each to
  its `references/` folder; regenerated `php_indicators.db`. Verified every rule
  runs with no unhandled or failed rules.
- **Status:** Fixed (commit `bc096b4`).

## 2026-09-18 — `spider.py` / `fetcher.py` browser navigation

- **Symptom:** navigating a headless-browser page to an error-status or
  non-navigable endpoint (e.g. `api/products.php` returning 500) raised
  `ERR_HTTP_RESPONSE_CODE_FAILURE` and the URL was dropped.
- **Root cause:** Chromium refuses to render some responses; the code treated any
  `goto` failure as a lost page.
- **Remediation:** wrapped the render in a try/except that falls back to a plain
  HTTP request, so the URL is still recorded and audited.
- **Status:** Fixed.

## 2026-09-18 — `spider.py` local-scope check

- **Symptom:** the crawler recorded only the start page and never followed any
  links when crawling a site on a non-default port (e.g. `:8080`).
- **Root cause:** `_is_local` compared `urlparse(url).netloc`, which includes the
  port, against bare hostnames, so every link was judged non-local and skipped.
- **Remediation:** compare `urlparse(url).hostname` instead, which excludes the
  port.
- **Status:** Fixed.

## 2026-09-18 — Playwright install (dev environment)

- **Symptom:** `pip install playwright` failed to find any distribution; later the
  browser launch failed with "Executable doesn't exist" for a build the managed
  version expected.
- **Root cause:** the package index host was excluded from the proxy, so pip could
  not reach it; and the installed Playwright version expected a browser build that
  did not match the one already present.
- **Remediation:** forced pip through the agent proxy to install the package, then
  either ran `playwright install chromium` or pointed the launcher at an existing
  browser via a `PLAYWRIGHT_CHROMIUM_EXECUTABLE` override.
- **Status:** Environment.

## 2026-09-18 — Live site returned HTTP 500 (Fedora deployment)

- **Symptom:** `http://localhost/puppy-fort-factory/` returned "500 Internal
  Server Error"; the Apache error log did not show the cause.
- **Root cause:** on Fedora, PHP runs under PHP-FPM, so the fatal error was logged
  in the PHP-FPM log, not the Apache log. The underlying failure was the database
  connection (see the two entries below), not a PHP parse error.
- **Remediation:** read the PHP-FPM log to get the real error, then fixed the
  database connection issues below.
- **Status:** Environment.

## 2026-09-18 — Database connection "Permission denied" (SELinux)

- **Symptom:** PHP-FPM logged `mysqli_sql_exception: Permission denied` when the
  app tried to connect to the database.
- **Root cause:** SELinux (enforcing on Fedora) blocks the web server from opening
  a network connection to the database by default.
- **Remediation:** enabled the boolean with
  `sudo setsebool -P httpd_can_network_connect_db on`.
- **Status:** Environment.

## 2026-09-18 — Database connection "Access denied for user 'root'"

- **Symptom:** after the SELinux fix, PHP-FPM logged
  `Access denied for user 'root'@'localhost'`.
- **Root cause:** on Fedora, MariaDB's `root` account uses socket authentication,
  so it cannot be reached over TCP with a password regardless of the value set.
- **Remediation:** created a dedicated application user
  (`CREATE USER 'pff'@'127.0.0.1' ... GRANT ALL ON puppy_fort.*`) and pointed the
  app's `config/config.php` at it; imported the schema.
- **Status:** Environment.

## 2026-09-18 — Web root returned a 403 (directory index)

- **Symptom:** browsing `http://localhost/` returned an Apache autoindex 403
  (`AH01276: ... No matching DirectoryIndex`).
- **Root cause:** the web root had no index page and directory listing is
  disabled; the app was in a subdirectory.
- **Remediation:** changed `deploy.sh` to deploy the app to the web root by
  default, so `index.php` sits at `/`. (Harmless before that, since the app was
  reached via its subdirectory URL.)
- **Status:** Fixed (commit `5f87d80`).

## 2026-09-17 — `blind_sqli_fuzzer.py` circular labeling

- **Symptom:** the generated training label was not an independent signal; it was
  effectively derived from the payload's own class.
- **Root cause:** the original draft set the "vulnerable" label from the
  is-malicious flag plus timing, so the label leaked the feature it was meant to
  predict.
- **Remediation:** detection is now computed from measured timing alone (median of
  repeats vs baseline), and the payload label is recorded as a separate column, so
  features and ground truth stay independent.
- **Status:** Fixed (commit `814cdd7`).

## 2026-09-17 — `blind_sqli_fuzzer.py` missing import

- **Symptom:** the original draft would crash immediately with a `NameError`.
- **Root cause:** it used the `requests` library throughout but never imported it.
- **Remediation:** added `import requests` with a friendly guard if the package is
  missing, and required an explicit target plus an `--authorized` flag.
- **Status:** Fixed (commit `814cdd7`).

---

## Open / low priority

- `fetcher.py` `--append` occurrence counter: repeated `--append` runs recompute
  `occurrences` as the current row count (1 after de-duplication) before the new
  audit bumps it, so cumulative counts across runs are not preserved. The default
  (fresh) run is unaffected. **Status:** Open (low priority).
