# Error log

A record of identified errors (bugs, deployment failures, environment issues) and
**how they were remediated**. Newest entries at the top. Add an entry whenever
something breaks and is fixed, so the same problem is easy to recognize and
resolve next time.

Format per entry:
- **Date / component**
- **Symptom:** what was observed
- **Root cause:** why it happened
- **Remediation:** what fixed it
- **Status:** Fixed / Open / Environment (fixed outside the repo)

---

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
