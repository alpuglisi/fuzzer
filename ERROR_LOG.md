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

## 2026-09-21 — `test_web_repeater.py` flakes with a cross-thread SQLite error

- **Symptom:** found incidentally while verifying an unrelated lab-generator lane's full-suite
  run: `tests/test_web_repeater.py::test_routes_list_create_and_send_gate` and
  `::test_route_send_reaches_upstream_when_authorized` intermittently fail with
  `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same
  thread` (a different one of the two failing each time). Reproduced twice independently
  (each time with different specific test(s) failing, consistent with a genuine race rather
  than one bad test); not reliably reproducible on demand afterward — order/timing-dependent.
- **Root cause:** not yet investigated. The error itself points at `fuzzlab/proxy/repeater.py`
  (or its `SocketSender`/store-adapter path) obtaining a SQLite connection/cursor on one
  thread and using it from another — Python's `sqlite3` module rejects this by default. Full
  RCA not yet done.
- **Remediation:** not yet fixed. Unrelated to the lab-generator (LAB component) work in
  progress this session; owned by PROXY/UI. Tracked as follow-up work (a full
  `docs/bugs/BUG-NNNN` investigation + fix is still owed per this log's own scope note —
  logging the finding now, in the turn it was found, rather than only once it's fixed).
- **Status:** Open.

## 2026-09-21 — sqlmap/commix exit non-zero on a legitimate negative finding, not only on a crash

- **Symptom:** while building `fuzzlab/labgen/oracle_wrapper.py` (`CC-LAB-0015`), an initial
  draft gated a verdict on the tool's subprocess exit code being `0` before trusting its
  textual output — the two skip-guarded integration tests against real cloned `sqlmap`/
  `commix` binaries failed immediately, because both tools exit non-zero on a clean "not
  injectable" finding, not only on a crash.
- **Root cause:** an untested assumption about a third-party tool's exit-code contract,
  carried over from a more typical CLI convention (0 = success/negative, non-zero = error)
  that doesn't hold for these two tools.
- **Remediation:** verdicts are now derived from the tool's own textual output via
  configurable regex markers, tuned against real tool output; a non-zero exit code is only
  consulted to add detail when neither marker matched (never as the primary signal). Caught
  by the real-binary integration test before the assumption ever shipped in a commit — no
  `docs/bugs/BUG-NNNN` opened, matching this project's own precedent (`docs/bugs/BUG-0018`'s
  scope note): this is a fact caught and fixed within the same session's authoring work,
  never landed as a defect in committed code, same as the two prior sqlmap/commix
  tool-behavior findings below.
- **Status:** Fixed (this commit). See CC-LAB-0015.

## 2026-09-21 — ERROR_LOG hook's keyword regex false-positives on "change" (BUG-0020)

- **Symptom:** the first real use of `.claude/hooks/check-error-log-bookkeeping.sh` (added
  in BUG-0019) after an incident-free, decision-only commit (D20/`CR-LAB-0001` approval)
  fired a false positive, blocking the stop.
- **Root cause:** the keyword regex matched `hang` as an unanchored substring, and `hang`
  is a substring of `change`/`changed`/`changes` — words this changelog-heavy project's
  own conventions use in nearly every commit. Full RCA in `docs/bugs/BUG-0020-*`.
- **Remediation:** anchored every keyword with `\b` word boundaries and explicit inflection
  groups; verified the real false-positive diff now passes, a synthetic true positive still
  blocks, and a synthetic change/changed/changes-only diff no longer matches on keywords.
  Rule PA-0022 (check a keyword heuristic against the project's own routine vocabulary
  before trusting it unattended).
- **Status:** Fixed (this commit).

## 2026-09-21 — PA-0019 was advisory-only, not mechanically enforced (BUG-0019)

- **Symptom:** asked to make PA-0019 (BUG-0018's fix) actually prevent recurrence rather
  than just document the expectation, inspection showed PA-0019 has no enforcement path
  other than my own end-of-turn recall of `docs/PREVENTIVE_ACTIONS.md` — the same recall
  step BUG-0018 showed already fails silently.
- **Root cause:** a preventive action whose root cause is my own missed/inconsistent
  self-check cannot be fixed by a written rule addressed to that same self-check; it needs
  an enforcement path independent of my remembering to apply it. Full RCA in
  `docs/bugs/BUG-0019-*`.
- **Remediation:** added `.claude/hooks/check-error-log-bookkeeping.sh`, wired as a Stop
  hook in `.claude/settings.json`. It inspects this turn's not-yet-pushed changes (working
  tree + unpushed commits) and blocks the session from stopping (once per stop cycle, via
  the same `stop_hook_active` recursion guard as `~/.claude/stop-hook-git-check.sh`) when
  they look incident-shaped (a new/modified `docs/spikes/`/`docs/bugs/` doc, or `fail`/
  `hang`/`workaround`/`killed`/`timed out`/`crash`/`broken`/`regress` added to the diff) but
  this log wasn't touched. Pipe-tested against four synthetic scenarios; committed to the
  repo so it applies in future sessions/clones, not just this container. Added PA-0020
  (strengthens/supersedes PA-0019).
- **Status:** Fixed

## 2026-09-21 — oracle-spike break/fix findings not logged to ERROR_LOG until prompted (BUG-0018)

- **Symptom:** the sqlmap 401/403-handling finding (Spike 001) and the commix ambient-
  defense/field-sweep hang (Spike 002) were each fully written up inside their spike
  documents and folded into `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`, but neither was added to
  this log at the time. Both were only logged after the user explicitly asked, in a
  following turn, to "record those both in a bug log."
- **Root cause:** reliance on a finding's narrative framing/salience to decide whether the
  `CLAUDE.md` bookkeeping checklist applied, rather than mechanically checking new findings
  against this log's own stated scope ("anything that broke and was fixed") regardless of
  how the finding was phrased or where else it was written up. Full RCA in
  `docs/bugs/BUG-0018-*`.
- **Remediation:** added the two findings to this log (previous entries below) with
  cross-references to their spike docs; added PA-0019 (re-check a turn's findings against
  each bookkeeping artifact's literal scope before ending the turn, not by how bug-shaped
  the finding feels); swept this session's own conduct per PA-0002 and found one more
  un-logged instance (the Docker Hub egress-policy block during Spike 001 — logged below).
- **Status:** Fixed (this commit).

## 2026-09-21 — Docker Hub image pulls blocked by egress policy during Spike 001 (found via BUG-0018's PA-0002 sweep)

- **Symptom:** `docker compose up -d --build` against a cloned `vAPI` repo (Spike 001)
  failed pulling `mysql:8.0`/`phpmyadmin/phpmyadmin` with a 403 from
  `production.cloudfront.docker.com`, reported by this session's agent proxy as a policy
  denial, not a transient failure.
- **Root cause:** this execution environment's egress policy blocks Docker Hub image pulls
  outright; per this environment's own guidance, a policy denial is reported, not retried
  or routed around.
- **Remediation:** ran the spike's target application natively instead (PHP built-in
  server + a local MariaDB install via `apt`), loopback-only, rather than in containers.
  Fully described in `docs/spikes/SPIKE-001-sqlmap-vs-vapi.md`, but not given its own log
  line until the BUG-0018 sweep found it. **Forward-looking implication:** Phase 3's
  containerized per-stack emitters (`CR-LAB-0001` Addendum D's `StackEnv.base_image`)
  should not assume Docker Hub is reachable in every execution context this project might
  run in; worth a documented fallback when that work actually starts.
- **Status:** Environment (worked around outside the repo; no repo change needed unless
  Phase 3 implementation later needs a documented fallback).

## 2026-09-21 — commix oracle hangs on ambient defenses and non-target form fields (Spike 002)

- **Symptom:** during `docs/spikes/SPIKE-002-commix-vs-dvwa.md` (validating commix as an
  independent security-assertion oracle for the lab generator, per `CR-LAB-0001` Addendum
  E), a headless `commix --batch` run against a properly-secured target (DVWA's
  `impossible.php`) first hung indefinitely against the real `ip` parameter because its
  anti-CSRF token rotates every page load and a captured token was stale by the second
  request; after that was worked around, commix moved on to sweep the irrelevant static
  `Submit` form field and entered a runaway false-positive-verification retry loop that
  never concluded on its own and had to be killed manually.
- **Root cause:** no fuzzlab code exists yet for this — this is a design gap, not a code
  defect. Nothing in the (not-yet-built) oracle wrapper scopes a tool invocation to the
  cell's declared injection parameter, and nothing accounts for a target's ambient defenses
  (rotating CSRF tokens, rate limiting) that are unrelated to the vulnerability class
  actually under test.
- **Remediation:** for the spike itself, the CSRF check was disabled in a local, reverted
  copy of `impossible.php` to isolate the command-injection defense from the unrelated CSRF
  defense, and the runaway `Submit`-field sweep was stopped by killing the process once the
  real parameter's clean result was already captured. The actual fix — scoping oracle
  invocations to the cell's declared parameter and giving the wrapper session/token-refresh
  awareness (or scoping each security assertion to just the transform under test) — is
  recorded as a requirement in `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`, not yet implemented.
- **Status:** Open (design requirement recorded; no oracle-wrapper code exists yet to fix).

## 2026-09-21 — sqlmap oracle refuses to test past a 401/403 "secure" response (Spike 001)

- **Symptom:** during `docs/spikes/SPIKE-001-sqlmap-vs-vapi.md` (validating sqlmap as an
  independent security-assertion oracle for the lab generator, per `CR-LAB-0001` Addendum
  E), a headless `sqlmap --batch` run against vAPI's properly-parameterized secure endpoint
  aborted immediately with `[CRITICAL] not authorized` instead of testing and reporting a
  clean negative, because the endpoint's "wrong credentials" response is `HTTP 401`, which
  sqlmap treats as an authentication failure by default.
- **Root cause:** no fuzzlab code exists yet for this — this is a design gap, not a code
  defect. The generator's planned oracle wrapper (`CR-LAB-0001` Addendum E) does not yet
  exist, so nothing reads a cell's declared "secure" HTTP status and passes it to sqlmap as
  `--ignore-code`.
- **Remediation:** re-ran manually with `--ignore-code=401`, which let sqlmap test both
  parameters and correctly report "does not seem to be injectable" with no false positive.
  The actual fix — the oracle wrapper reading the cell's expected secure-response status
  from the manifest and passing the matching `--ignore-code` automatically — is recorded as
  a requirement in `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`, not yet implemented.
- **Status:** Open (design requirement recorded; no oracle-wrapper code exists yet to fix).

---

## 2026-09-21 — `labctl.sh reset` not self-healing under podman-compose (BUG-0017, recurrence of BUG-0013)

- **Symptom:** `scripts/greybox_e2e.sh` step 1 (`labctl.sh reset`) failed on the host with
  `executing /usr/bin/podman-compose up -d --build: exit status 125` and "cannot remove
  container … as it is running" / "container state improper" — the stack was wedged and
  Part E could not start.
- **Root cause:** `reset` recreated containers with a bare `compose down -v` + `up` and no
  force-clean fallback. podman-compose cannot remove/recreate a running/wedged stack — the
  exact limitation fixed in BUG-0013, but that fix (CC-LAB-0011) was applied only to the
  `up` subcommand. A **recurrence of BUG-0013**: PA-0014 was scoped to the *trigger*
  (env/profile change) not the *mechanism*, the PA-0002 sweep inherited that narrow framing
  and missed the sibling recreate path, and the self-heal was inlined in `up` instead of a
  shared helper (PA-0003 not applied).
- **Remediation:** factored the force-clean sequence into one shared `_force_clean()` helper
  and routed **both** `up` (keep-volume, on failure) and `reset` (drop-volume, before +
  after with retry) through it. Full RCA incl. recurrence + prior-PA-failure analysis in
  `docs/bugs/BUG-0017-*`; new rule PA-0018 (re-keys the self-heal to the mechanism and to
  all container-recreate paths). See CC-LAB-0013.
- **Status:** Fixed (this commit). labctl `up`/`reset` exit-code paths verified statically
  (mocked podman/compose, both success and fallback branches exit 0); suite 416 passed /
  6 skipped.

## 2026-09-21 — Grey-box "new-code reward" starved by the global frontier (BUG-0016)

- **Symptom:** `greybox-run` step 5 reported `new-code max: 0.000` + a NOTE "is the cov.php
  shim installed?" while step 6 said PASS and 338 novel lines were captured — a
  self-contradiction. The coverage-reward property (T3.7) wasn't actually demonstrated
  (payloads scored higher only via db_fault).
- **Root cause:** novelty was measured against a single **global** frontier and the benign
  baseline ran first per point, consuming that point's coverage — so every attack showed
  `novel=0`, `newcode_reward` was ~always 0, the baseline earned a novelty-only reward, and
  the NOTE inferred "shim broken" from that artifact.
- **Recurrence:** same class as the Part F metric (`requests_per_finding` can't show the
  bandit's oracle-probe savings) and BUG-0014 — a metric/self-test that passes/fires
  without measuring the capability. PA-0015 didn't prevent it (a self-test can pass while
  measuring the wrong thing).
- **Remediation:** `run_greybox` now uses a **per-point differential** (attack coverage vs
  its own baseline) for the reward novelty and `newcode_reward`; the global frontier is kept
  only for the run-wide exploration total; the NOTE fires only when `coverage_lines_seen==0`.
  Part F's runbook exit reframed to verify via posteriors with a metric caveat. Full RCA +
  recurrence/prior-PA analysis in `docs/bugs/BUG-0016-*`; rule PA-0017. See CC-FUZZ-0017.
- **Status:** Fixed (this commit). Suite 416 passed / 6 skipped.

## 2026-09-21 — `labctl.sh up` exits non-zero on success without a profile (BUG-0015)

- **Symptom:** `scripts/waf_evasion_e2e.sh` printed step 1 "lab up" then exited silently
  with no steps 2–5 (its EXIT trap quietly turned the WAF back off). `h2_desync_e2e.sh`
  (which sets `PFF_PROFILE=desync`) was unaffected.
- **Root cause:** the `up)` case ended with `[ -n "${PFF_PROFILE:-}" ] && echo ...`; with no
  profile, `[ -n "" ]` returns 1 and — being the last command — `labctl.sh up` exits 1
  despite success, so the caller under `set -e` aborts. A shell trailing-`A && B` exit-status
  pitfall introduced by the profile support (CC-LAB-0010). It shipped because the on-host
  scripts can't be executed in the build sandbox (recurrence of BUG-0014's root cause), and a
  fail-loud self-test can't catch an abort that precedes it.
- **Remediation:** the profile notice now uses an `if` (returns 0 with or without a profile);
  verified `up`'s no-profile tail exits 0. Swept the other `&&` sites (safe). Full RCA +
  recurrence + prior-PA-failure analysis in `docs/bugs/BUG-0015-*`; rule PA-0016. See
  CC-LAB-0012.
- **Status:** Fixed (this commit). Parts I and K passed on-host; Part J unblocked.

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
- **Status:** Fixed. Full RCA (backfilled during a bookkeeping reconciliation pass — this
  entry and CC-CORE-0017 existed but the investigation doc and PA did not) in
  `docs/bugs/BUG-0007-credential-host-key-mismatch-and-ground-truth-path-traceback.md`;
  rule PA-0021 (recurrence of the BUG-0003/PA-0003 class on a different field). See
  CC-CORE-0017.

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

## 2026-09-21 — Schema-version assertion hardcoded, recurrence (BUG-0002)

- **Symptom:** `tests/test_harness.py::test_score_from_store_and_metrics` failed
  (`assert 3 == 2`) after adding migration 3 (T1.7) — a correct, intended schema change
  turned green tests red.
- **Root cause:** another test hardcoded the schema head version instead of deriving it
  from the migration registry — the same class BUG-0001 fixed, but BUG-0001's fix only
  touched the tests failing at the time and never swept for other instances, leaving this
  one latent until migration 3 tripped it.
- **Remediation:** derived the assertion from `migrations.MIGRATIONS`
  (`max(v for v, _ in migrations.MIGRATIONS)`); swept `tests/` for other hardcoded
  schema-version literals (none remained). Full RCA in
  `docs/bugs/BUG-0002-schema-version-hardcoded-recurrence.md`; rule PA-0002 (sweep the
  codebase for a bug class's other instances whenever a preventive action is added).
- **Status:** Fixed (commit `30ea97d`+ range). Suite 71/71 passed.

## 2026-09-21 — Schema-version assertions hardcoded in tests (BUG-0001)

- **Symptom:** `tests/test_core_foundations.py::test_migrations_are_idempotent` and
  `test_store_run_and_body_roundtrip` failed (`assert 2 == 1`) after adding migration 2
  (self-describing findings, T0.7) — a correct, intended schema change turned green tests
  red.
- **Root cause:** both tests asserted the schema head version as the literal `1` instead of
  deriving it from the `MIGRATIONS` registry, the value's actual source of truth.
- **Remediation:** both assertions now derive the head from the registry. Full RCA in
  `docs/bugs/BUG-0001-schema-version-hardcoded-in-tests.md`; rule PA-0001 (don't hardcode a
  value a source-of-truth constant/registry already defines).
- **Status:** Fixed (commit `30ea97d`, CC-CORE-0003). Suite 30/30 passed.

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
