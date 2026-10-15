# Error log

A record of identified errors (bugs, deployment failures, environment issues) and
**how they were remediated**. Newest entries at the top. Add an entry whenever
something breaks and is fixed, so the same problem is easy to recognize and
resolve next time.

For an ordinary defect this entry is the record: the reproduction, the correction, the
regression check and the scope. A significant, recurring or systemic defect, a security
or data-integrity event, or a failed control is formal CAPA. It also needs a
`docs/bugs/BUG-NNNN-*.md` report, and its control is corrected through
`docs/quality/pa_control_map.tsv` (`docs/QUALITY_POLICY.md` §4, `CLAUDE.md`).

Format per entry:
- **Date / component**
- **Symptom:** what was observed
- **Root cause:** why it happened
- **Remediation:** what fixed it
- **Status:** Fixed / Open / Environment (fixed outside the repo)

---

## 2026-10-15 — Process controls: the progress guard and two Stop hooks enforced proxies (fixed, BUG-0156, BUG-0157)
- **Symptom:** three failures, all reproduced:
  - Any user message, "status?" included, cleared every progress-guard hold. It restarted the stall and budget clocks and zeroed the review-round count. Two parallel reviewers counted as two rounds (lean QC review, synthetic replay).
  - The bookkeeping Stop hook exited 2 on the README line "The timeout setting is 15 seconds." (reproduced in a throwaway repository).
  - The corpus hook rejected independent examples that share one accurate CWE, and passed silently when `python3` lacked PyYAML.
- **Root cause:** each control checked a proxy instead of the property it governs:
  - contact instead of a decision scoped to one hold;
  - a word in the diff instead of a declared defect;
  - a count of unique labels instead of an accurate mapping.

  None had been qualified on a legitimate case.
- **Remediation:**
  - `scripts/orchestration_guard.py`:
    - `decide`, which quotes the user and names one hold; allowances add up and nothing resets;
    - cumulative spend across reopen and rename (`--continues`);
    - a round = the requests between two work dispatches;
    - `item disposition` for the bug chain and for exhausted experiments (R1).
  - `.claude/hooks/check_bookkeeping.py` replaces the keyword hook: `Change-Type:`/`Risk:` trailers, and a structural `ERROR_LOG.md` check.
  - The CWE hook drops the uniqueness quota, keeps the owner's pairs floor, and fails visibly without PyYAML.
  - Tests: `tests/test_orchestration_guard.py`, `tests/test_stop_hooks.py`.
- **Status:** Fixed. CAPA effectiveness is provisional.

## 2026-10-15 — Oracle: a connection reset from the target ended the whole confirmation run (fixed, BUG-0147, PA-0153)
- **Symptom:** `test_multitarget_category4::test_both_apps_run_through_multitarget_for_real` failed intermittently under the full parallel suite with `ConnectionResetError` on the template-injection confirmer's redirect follow-up to the Go Twitch clone (`GET /channels/$%7B603*129%7D`).
- **Root cause:**
  - The Go response-splitting twin hand-wrote a 302 without `Connection: close`, then closed. `requests` reused the connection, and under load the follow-up arrived before the close, so the close sent a reset.
  - The probe senders had no defined outcome for "no response": `RequestsProbeSender` caught timeouts only, so the reset ended the run for both targets. PA-0137 had made such failures "no verdict" for the browser only.
  - Reproduced deterministically without load. On the real Go app, the missing `Connection: close` and the close after one response are confirmed; the reset ordering there is inferred.
- **Remediation:** `ProbeUnobserved`, classified in one place (`probesender._unobserved`); an idempotent probe is re-sent once; the oracle makes it inconclusive, never a negative or the end of the run; OOB mechanisms still wait for their callback; a dead target still fails loudly. The Go twin and the proxy's 501 send `Connection: close`. Guards: every default mechanism against a dead sender and a stopped listener (named exemptions), every HTTP sender, every hand-written response (CC-FUZZ-0088, CC-LAB-0259, CC-PROXY-0024, CC-UI-0056).
- **Status:** Fixed.

## 2026-10-15 — Integration of the five session lanes: cross-lane defects found by the merged full suite (fixed, BUG-0145/0146, PA-0151/0152)
- **Symptom:** merging the five lane branches onto the dev branch gave 14 failures in the full suite.
- **Root cause:** each lane was built against the 10-14 base and was green there. Merged:
  - options added by the dev branch were unclassified in the CLI taxonomy and the UI option table;
  - the labs lane's base-URL registry did not list 7 origin-scope and run-target functions;
  - two of its tests predated origin-scoped sessions (a session without origins; a 3-value unpack of a now 4-value return);
  - the project-files lane read the `target` table outside the site-tree lane's one reader;
  - the site tree assumed a store with no project open, and fell back to the implicit default (BUG-0146);
  - one intermittent exit 141: `pipefail` SIGPIPE (BUG-0145, reproduced deterministically).
- **Remediation:**
  - classifications moved out of `PENDING`;
  - registry entries, each with a direct sub-path test;
  - the stale test doubles brought up to the current contract;
  - `core/project.py` reads through `core.runtarget`;
  - the site tree is wired to the open project only;
  - the four early-exit pipes removed.
  - See BUG-0145 and BUG-0146.
- **Status:** Fixed (merged full suite re-run before push).

## 2026-10-15 — Test harness: a live boot accepted another process on its port as its own server (fixed, BUG-0143/PA-0149)
- **Symptom:** run in parallel, `test_multitarget_category4::test_both_apps_run_through_multitarget_for_real` failed with `ConnectionResetError` probing the Twitch clone. It had failed the same way twice on 10-14 and was parked as a WATCH item. **Correction:** that test's resets recurred with this fix in place, so they are not explained by it (open as BUG-0147); the hazard fixed here was reproduced on its own.
- **Root cause:** all 5 live-boot harnesses and 11 test-side server starts picked a free port, released it, then accepted any successful connect as "booted". Reproduced deterministically: with a stand-in server on the port, the Go harness booted "successfully" and its URL answered the stand-in.
- **Remediation:** `procutil.port_owner`, `wait_until_listening` and `start_server_on_free_port` check ownership through the server tree's own sockets and retry a taken port. All 16 sites were converted. An AST guard flags the 16 pre-fix sites; the BUG-0130 loopback guards now also see the new launcher. See `docs/bugs/BUG-0143-a-booted-server-was-never-checked-to-own-its-port.md`.
- **Status:** Fixed.

## 2026-10-15 — Tests: the group-kill test's exact count raced the supervisor (fixed, BUG-0144/PA-0150)
- **Symptom:** `test_kill_process_group_kills_exactly_the_recorded_group`: `assert 1 == 3`, 11 of 30 runs under CPU load.
- **Root cause:** the group ran under the supervisor, which kills the group's remaining members when the leader dies. The function was correct; the count raced.
- **Remediation:** the test uses a caller-owned group (the documented use) plus a bystander that must survive; 30 of 30 runs under load. See `docs/bugs/BUG-0144-group-kill-test-raced-the-supervisor.md`.
- **Status:** Fixed.

## 2026-10-15 — Test suite: live boots reinstalled pinned dependencies on every boot (fixed, BUG-0142/PA-0148)
- **Symptom:** the full suite took about 68 min (serial pass 61 min 28 s).
- **Root cause:** measured on one boot: `composer install` took 51.6 s of a 52 s Laravel boot; Django built a venv and pip-installed per boot (about 8 s of 10 s). The 5 toolchain network probes re-ran in every importing module (121 s to collect the Laravel files).
- **Remediation:** a per-host Laravel `vendor/` and Django venv cache (locked, atomic, keyed by the lock file and interpreter), a per-app autoloader, and the availability checks cached per process. Serial pass: 61:28 to 38:45; warm Laravel boot 3.05 s; Django test file 57 s to 8.7 s; collection 121 s to 10 s. A first attempt that cached the probes broke two probe tests; my consumer search had been cut off by `head`. Fixed. See `docs/bugs/BUG-0142-live-boot-tests-reinstall-dependencies-every-boot.md`.
- **Status:** Fixed.

## 2026-10-15 — Orchestration: about 15 hours of autonomous work without progress on the goal and without telling the user (fixed, BUG-0141/PA-0141..0147)
- **Symptom:** from 2026-10-14 17:57 to 2026-10-15 09:01 UTC, the orchestrating session dispatched review rounds, follow-ups and merge fixes:
  - 39 commits, 42 review requests, 82 review-fix items and 6 bug numbers;
  - confirmed Juice Shop findings per run stayed at 6 (7 distinct);
  - no progress report or notification reached the user until they asked.
- **Root cause:** the session treated activity as progress. It never measured the work against the goal. When the stall was visible (01:32) it did not investigate or fix it. Nothing mechanical caught either failure: no goal metric, checkpoint, stall trigger, review-round cap, scope gate, fix-chain trigger or time budget.
- **Remediation:**
  - `scripts/orchestration_guard.py` with PreToolUse, Stop and SessionStart hooks: a goal ledger; checkpoints every 3 h; a 6 h stall is treated as a defect (only work investigating and fixing it is dispatched; the user is notified); at most 3 review rounds per item; self-opened work waits for the user; 2 spawned bugs stop an item; a 4 h item budget; a WIP limit of 3 and no file overlap.
  - PA-0141..0147; PA-0032 and the overnight plan amended; MULTI_AGENT_ORCHESTRATION §8.
  - See `docs/bugs/BUG-0141-orchestration-ran-without-progress-or-escalation.md`.
- **Status:** Fixed (hooks take effect when a session loads them; residuals in the bug doc).

## 2026-10-15 — Oracle/M6: a DOM XSS behind a quote-sensitive data path was never confirmed (fixed, BUG-0139/PA-0139)
- **Symptom:** live on Juice Shop, the crawl seeded `#/track-result?id=` and M6 loaded it with every payload, but the candidate was "checked", never confirmed. A true-positive DOM XSS was missed.
- **Root cause:** every M6 payload called `__fzlbHit('TOKEN')` with single quotes. `GET /rest/track-order/:id` evaluates the id inside a single-quoted server-side string, so a `'` answers 500 and nothing is echoed or rendered: a guaranteed miss for that sink. The confirmer had one quoting shape and no stated limit (PA-0124(2) was applied to the open redirect only).
- **Remediation:** CC-FUZZ-0084 adds two payloads: the sentinel call with backticks, and one with no quote, slash or whitespace in the call (`__fzlbHit(String.fromCharCode(...))`, which replaced the review-rejected `/TOKEN/.source` form); payloads ordered by reach, with one last quote-free try after the not-observed stop. That makes 6 payloads; the token is unchanged (fresh, hex, checked by the binding) and must be alphanumeric. See `docs/bugs/BUG-0139-m6-payloads-all-single-quoted.md` and PA-0139.
- **Status:** Fixed (offline, on a loopback fixture of that data path; the live re-run is the coordinator's).

## 2026-10-15 — Crawler, auditor, browser login: a page whose script navigates to a refused URL while it is parsed was waited out (fixed, BUG-0138/PA-0138)
- **Symptom:** on the merged tree (spa-query + origin-scope), a page whose head script runs `location.href = '/logout'`:
  - the crawl waited out its `timeout_ms` ("Timeout 4000ms exceeded", 4.95 s), then fell back to a static request, so the lab saw `GET /` twice;
  - a query probe or seed load timed out and kept nothing;
  - the auditor's rendered fetch and the browser login waited out their timeouts too.
- **Root cause:** each caller navigated with `goto(wait_until="domcontentloaded")` and the full timeout. Since BUG-0136 the refused navigation is aborted with ERR_ABORTED, which keeps the document but stops its loading, so `domcontentloaded` never comes. BUG-0137 applied PA-0137(2) ("never wait for an event a refused action can cancel") to the M6 executor only; its sweep stopped at the oracle path. A second wait of the same kind, `inner_text('body')` on a document with no body, cost a further 30 s once the first was fixed.
- **Remediation:**
  - CC-CRAWL-0030, CC-AUD-0043, CC-SESS-0024 and the CC-FUZZ-0083 amendment move every navigation onto one helper, `navguard.navigate` / `reload`: wait for the commit (a refused own target still raises), then wait for the load state, bounded and cut short 300 ms after a main-frame navigation fails.
  - A page whose load did not complete is read from the response the browser already received, never with a second request.
  - The body text is read without waiting.
  - An AST guard holds every module to the helper.
  - See `docs/bugs/BUG-0138-a-page-that-navigates-away-while-parsed-was-waited-out.md` and PA-0138.
- **Status:** Fixed.

## 2026-10-14 — Oracle/M6: a page the browser executor could not load ended the confirmation run (fixed, BUG-0137/PA-0137)
- **Symptom:** one DOM/stored XSS candidate whose page timed out, crashed or had its own redirect refused raised out of `oracle.confirm` and `pipeline._confirm`; every later candidate stayed `pending`. After BUG-0136, a page that navigates by script to a refused URL before `load` also cost 8 s, then raised.
- **Root cause:** `PlaywrightBrowserExecutor.run` mapped only a launch failure to "no verdict" (BUG-0126); a Playwright error of its context, plant or observe navigation escaped, and no layer above contains a mechanism's raw errors.
- **Remediation:** CC-FUZZ-0083: the observe navigation waits for the commit, then for `load` for at most 3 s (suppressed). A Playwright error, or a page that never loaded, with no hit is `UnplaceableLocation` with a URL-free reason; a hit at any point counts. Only Playwright errors are caught. See `docs/bugs/BUG-0137-an-m6-page-failure-ended-the-confirmation-run.md`, PA-0137.
- **Status:** Fixed.

## 2026-10-14 — Crawler: a refused script navigation replaced the page with Chromium's error page (fixed, BUG-0136/PA-0136)
- **Symptom:** a page whose script navigated after load to an out-of-scope host or a destructive URL was stored with Chromium's error page as its content; its links were never crawled.
- **Root cause:** `navguard`'s route aborted refused navigations with the default error code (Chromium then commits its error page); only the reveal window and BUG-0134's withheld branch used `"aborted"`.
- **Remediation:** one rule: every abort of a document request uses `"aborted"`, a subresource the default (`navguard._abort_code`). CC-CRAWL-0028. `docs/bugs/BUG-0136-a-refused-navigation-replaced-the-page-with-an-error-page.md`.
- **Status:** Fixed (real Chromium; mutation-checked)

## 2026-10-14 — Crawler tests: a wall-clock ratio decided a linearity test (fixed, BUG-0135/PA-0135)
- **Symptom:** `tests/test_spa_routes.py::test_the_scan_is_linear_on_adversarial_5mb_bodies`
  failed once in the FR-CRAWL-17 lane's related run and once under concurrent lane load
  (`t_large < 3.5 * t_small` broken), then passed when re-run; `scan_routes` had not changed.
- **Root cause:** a linearity claim tested by a wall-clock ratio, which machine load
  decides; PA-0095(2) asked for operation counts but only for per-candidate paths, and
  nothing enforced it. The new FR-CRAWL-17 scan test repeated it.
- **Remediation:** the scanners expose operation counts (`spa.StepCounter`); both
  tests assert `ops(2n) <= 2 * ops(n) + slack`, proven on deliberately quadratic
  variants; a wall-clock bound stays only as an absolute smoke alarm; the AST guard
  `tests/test_no_wall_clock_ratio.py` (PA-0135) (CC-CRAWL-0027 review amendment).
- **Status:** Fixed.

## 2026-10-14 — BUG-0134's first fix still leaked in the browser and the login (fixed in review round 1, BUG-0134/PA-0134)
- **Symptom:** reviewer A, live in real Chromium: a redirected navigation landing on another port was answered under A's URL, so B's script read A's `document.cookie` / `localStorage`; `route.fetch` stored B's `Set-Cookie` in the shared jar (replacing A's `sid`); the login still accepted an in-scope host on any port (and an https upgrade to any port).
- **Root cause:** the first fix withheld request headers only, while the browser shares a jar and storage with every document it loads; the login's anchor kept FR-SESS-12's host-level clause.
- **Remediation:** other-origin documents and WebSockets aborted; other-origin subresources fetched through a cookie-less request context with `Set-Cookie` stripped; login anchors are origins (`--auth-origin` added). See BUG-0134's "Review round 1" section.
- **Status:** Fixed (real Chromium and real loopback servers; mutation-checked)

## 2026-10-14 — Session manager: a session was sent to every port of its host (fixed, BUG-0134/PA-0134)
- **Symptom:** on a loopback lab, Juice Shop's session cookie and bearer (`127.0.0.1:3000`) were attached to requests to bWAPP (`:8090`) and any other port of `127.0.0.1` the crawl or a probe reached; a request there could log in there with the host's credential; another app's login page logged the session out; greybox and an any-port browser crawl did the same (BUG-0132 review, reviewer A S2).
- **Root cause:** the session's send scope was its storage key's host, decided by hostname comparisons at each carrier (`prepare`, `ensure`, `authorize`, `observe`, `_navigate(session_host=)`, `header_scope_for`, greybox, the breakers' listeners, `is_auth_endpoint`), kept as a "stated exception" after PA-0123 made scope an origin.
- **Remediation:** `SessionState.origins` (base, login page, credential destination, `auth_origins`; in memory only); every carrier checks origin membership; another origin goes out anonymously, never logs in there, is counted and stamped `anonymous (out of origin)`; the browser route withholds the port-agnostic jar from another origin. CC-SESS-0023, CC-CRAWL-0026, CC-FUZZ-0080, CC-PROXY-0023. `docs/bugs/BUG-0134-session-sent-to-another-port-of-the-host.md`.
- **Status:** Fixed (real loopback servers on two ports and real Chromium; residuals in the bug's sweep table)

## 2026-10-15 — Cloud container: 14 `lab-generate --check` tests failed because gitleaks was missing (environment)
- **Symptom:** the clean-tree full-suite run for CC-LAB-0300 (`-m "not slow"`, at
  64d69a2) failed 14 labgen tests (`test_cli_check_passes_end_to_end*`,
  `test_lab_generate_check_passes_on_the_clean_example_manifest`,
  `test_run_checks_generic_weakened_twin_pairing_passes_for_an_arbitrary_cell`), each
  with `secret scanner: 'gitleaks' executable not found on PATH`.
- **Root cause:** environment. The session's container has no `gitleaks`, and the
  `--check` secret-scanner gate correctly fails closed without it
  (NFR-LAB-no-secret-leak). The same 14 failed identically at the base commit cdde39f,
  before this change.
- **Remediation:** `apt-get install gitleaks` (8.16.0) in the session container. The 14
  then passed at 64d69a2, and the full suite was rerun with it present (CC-LAB-0300
  "Effectiveness, final").
- **Status:** Environment (fixed outside the repo)

## 2026-10-15 — External lab fixtures: an external-lab negative and three live checks rested on premises nobody had observed (fixed, BUG-0311 / PA-0311, CC-LAB-0300)
- **Symptom:** code review found that BWAPP-0047 (sqli_17 `User-Agent`, reflected XSS)
  was labelled a negative although a quote-breaking value comes back raw in the MySQL
  error. Of the live test's two security-level checks, one could not fail and one failed
  on a harmless GET. The "checked candidate" filter also counted undecided statuses.
- **Root cause:** a negative proven only on the display path, never the error path, and
  live assertions on channels that cannot carry the violation they test for. The session
  adopts no response cookies, and access logs hold no POST bodies. The status filter was
  hand-written instead of using `oracle_status.CHECKED`.
- **Remediation:** BWAPP-0047 is now a positive, plus BWAPP-0057/0058 (the same echo),
  all verified live. The level checks became "no probe of the level parameters" plus a
  stated structural reason. The filter uses `CHECKED` (commit e74fba8). That
  replacement was wrong too: live run 3 showed the crawl pass probing the login form's
  `security_level` field through the isolated client. It now reads a per-request log of
  the level cookie that the fixture writes, through an allowlist predicate that is
  unit-tested offline, with level-1 controls before and after the passes (code review
  rounds 2-3; the first version's control could never pass). Full RCA in
  `docs/bugs/BUG-0311-*`, rule PA-0311.
- **Status:** Fixed (revised check verified live: live run 5 at 859bcfd, 4 passed)

## 2026-10-15 — External lab fixtures: the loopback exposure checks failed open (fixed, BUG-0310 / PA-0310, CC-LAB-0300, CC-CORE-0300)
- **Symptom:** code review found that the pre-flight and post-boot checks passed podman's
  `ns:/proc/1/ns/net`, `slirp4netns:allow_host_loopback=true` and `pasta`, and an
  external network named `host`. Engine errors read as "nothing left" (`down` exit 0)
  or "not running", and a non-loopback binding seen only in `NetworkSettings.Ports` was
  never judged.
- **Root cause:** the checks were a denylist of docker's bad modes, and "the engine
  could not answer" defaulted to "safe".
- **Remediation:** allowlists in the pre-flight and the post-check, a comparison of each
  container's network namespace with the host's, both inspect port sources combined,
  and every engine error treated as a failure (commit e74fba8). Full RCA in
  `docs/bugs/BUG-0310-*`, rule PA-0310.
- **Status:** Fixed

## 2026-10-15 — External lab fixtures: build-time failures met while making bWAPP / Juice Shop permanent (fixed, CC-LAB-0300; environment)
- **Symptom:** (1) no Docker daemon in the cloud build container (`docker info`: no
  `/var/run/docker.sock`); (2) the first bWAPP image prototype served every page as binary
  garbage with a 200; (3) the official Juice Shop image did not evaluate the SSTI the
  brief lists as confirmed (`#{7*191}` came back literal); (4) the first live
  `bootstrap` reported bWAPP's portal "does not require a login" and Juice Shop's
  `whoami` "does not name the account"; (5) the bWAPP ground-truth-points run could not
  log in (origin base) and the crawl-points run was refused for its request budget.
- **Root cause:** (1) environment: `dockerd` not started; (2) PHP 5.6's `PharData`
  extracted this zip's entries still deflated (the php:5.6 base has no `unzip` and no zip
  extension); (3) the image's `safetyMode: auto` disables Docker-tagged challenges inside a
  container (`challenges.yml` `disabledEnv`; the brief's run was a source build); (4) in the
  new, uncommitted bootstrap: bWAPP's relative `Location: login.php` was resolved against
  the origin root, and `whoami` reads the `token` cookie, not the bearer; (5) login
  discovery looks at the base page (bWAPP is under `/bWAPP/`; the ground-truth join doubles
  a sub-path base, BUG-0300), and header points over ~150 pages need ~9700 requests.
- **Remediation:** (1) `dockerd` started in the session (pid recorded, stopped at the
  end); (2) a pinned busybox fetch stage does `sha256sum -c` + `unzip`; (3) the fixture
  sets `NODE_ENV=unsafe` (Juice Shop's own `config/unsafe.yml`), asserted by a static test
  and by bootstrap; (4) redirects resolved against the request URL, `whoami`/`/profile`
  checked with the cookie (both caught before commit, by the first live run, and covered
  by unit tests); (5) the fixture's own Apache config redirects `/` to
  `/bWAPP/portal.php`, and the crawl pass sets `FUZZLAB_BUDGET_TOTAL=30000`.
- **Status:** Fixed (2)-(5) in CC-LAB-0300; (1) Environment. None was a defect in
  committed code (no BUG report); the locked-file defects found alongside are BUG-0300
  and BUG-0301.
## 2026-10-15 — core/urls: the destructive rule misses Juice Shop's GET password change and `/dataerasure` (open, deferred, BUG-0301/PA-0301)
- **Symptom:** the PA-0114 enumeration of Juice Shop's routes (before adopting it as a permanent fixture) found `destructive_reason` and `transaction_reason` both None for `GET /rest/user/change-password?current=a&new=b&repeat=b` (changes the bearer's password; `current` is optional) and `/dataerasure` (GET and POST; files an erasure request and clears the token cookie). The send gate lets both through, and the real `dataErasureForm.hbs` form passes `form_skip_reason`, so the POST would be imported and fuzzed. Latent: neither is captured by a crawl today.
- **Root cause:** the rule matches whole tokens and listed pairs only, and is validated only against the spellings it was written for: `dataerasure` is one token (`erasure` is not `erase`), and `(change, password)` is not a listed pair. A recurrence of BUG-0114's class.
- **Remediation:** none to the rule yet: `fuzzlab/core/urls.py` is locked by another session, so the corrective action is deferred to its owner (CC-CORE-0301). Pinned by strict xfails, a computed Juice Shop / bWAPP PA-0114 table, and the PA-0301 compound-spelling scan over every lab's routes (`tests/test_destructive_routes_external_labs.py`). `docs/bugs/BUG-0301-destructive-rule-missed-juice-password-change-and-data-erasure.md`.
- **Status:** Open (deferred to the `core/urls.py` lock owner; compensating controls stated in BUG-0301)

## 2026-10-15 — Harness: ground-truth points double an operator base URL's sub-path (open, deferred, BUG-0300/PA-0300)
- **Symptom:** `points_from_ground_truth(gt, "http://127.0.0.1:8092/bWAPP/")` with a ground-truth url `/bWAPP/sqli_1.php` builds `http://127.0.0.1:8092/bWAPP/bWAPP/sqli_1.php` (every branch: server, DOM and stored-XSS points); greybox's `points_with_classes` inherits it and keys its class lookup the same way. A ground-truth run against a sub-path base would probe 404s and score every case as missed.
- **Root cause:** the join is `base_url.rstrip("/") + path`, treating a ground-truth url as app-relative, while findings (and so the scored keys) are full request paths (`to_path`). The convention was never written down, every generated lab serves at `/`, and BUG-0113's sweep cleared this function "by contract" without a sub-path test: PA-0113(3) had no enforcement.
- **Remediation:** none to the code yet: `fuzzlab/harness/auto.py` and `fuzzlab/greybox/run.py` are locked by another session, so the corrective action is deferred to their owner (CC-FUZZ-0300). Operators pass the origin as `--base-url` for ground-truth runs meanwhile. Pinned by strict xfails, and PA-0300's registry (`tests/test_base_url_subpath_registry.py`) now lists every function that takes an operator base URL with its sub-path test or its bug. `docs/bugs/BUG-0300-ground-truth-points-doubled-an-operator-sub-path.md`.
- **Status:** Open (deferred to the `harness/auto.py` lock owner)

## 2026-10-15 — CLI: `train models` imported `fuzzlab.ml` outside the optional-ML seam (fixed, BUG-0403/PA-0403)
- **Symptom:** the clean-tree suite of `31b5013` failed `tests/test_ml_import_guard.py` on `fuzzlab/train_cli.py`; a no-ML build would crash on `fuzzlab train models`.
- **Root cause:** a direct `from fuzzlab.ml.model_registry import …` in a new non-ML module; the pre-push verification set was derived from imports only, which never lists the repository's path-scanning guard tests, and the push preceded the full run.
- **Remediation:** `import_ml("fuzzlab.ml.model_registry")` with the standard exit-2 message; a no-ML exit test. PA-0403: path-scanning guards are always in the verification set, and the full suite runs before the push it certifies. CC-FUZZ-0401. `docs/bugs/BUG-0403-train-models-imported-ml-outside-the-seam.md`.
- **Status:** Fixed

## 2026-10-15 — CLI: `train run` printed and checked one store, the engine opened another (fixed, BUG-0401/PA-0401)
- **Symptom:** `fuzzlab train run URL --store=~/x.db --score --authorized` printed `store: <HOME>/x.db` but the engine opened `./~/x.db` (an sqlite error, or a file under a directory named `~`).
- **Root cause:** the wrapper resolved the store (expanding `~`) for its check and its printed line, but forwarded the user's raw `--store` verbatim (PA-0400(3)); the engine derives the path itself without expansion -- two derivations of one value.
- **Remediation:** `train_cli.forward()` always appends the resolved `--store` last (argparse keeps the last); tested by parsing the forwarded argv with the engine's own parser for 9 spellings, plus a forwarding round trip over every engine action. CC-FUZZ-0401. `docs/bugs/BUG-0401-train-run-printed-one-store-and-opened-another.md`.
- **Status:** Fixed

## 2026-10-15 — Tests: the store guard walked directories it does not own (fixed, BUG-0402/PA-0402)
- **Symptom:** run from outside the repository, `tests/_store_guard.py` walked the whole cwd (all of `$HOME`, or `/`), and reported every test's own `tmp_path/fuzzlab.db` as a leaked default store when pytest's temp base lay under that cwd.
- **Root cause:** the cwd was treated as a recursive walk root like the repository, and pytest's basetemp was not excluded; the guard's tests never ran from a cwd outside the repository.
- **Remediation:** walk only the repository (minus the basetemp); stat only the outside cwd's own `fuzzlab.db*`; clear the store variables in `pytest_configure`. CC-CORE-0401. `docs/bugs/BUG-0402-store-guard-walked-beyond-its-roots.md`.
- **Status:** Fixed

## 2026-10-15 — Web launcher / CLI dry-run: argv builder mis-serialises four argparse shapes (open, BUG-0400/PA-0400)
- **Symptom:** `cli_dryrun.report('crawl', …)` printed `--submit-spa-forms []` and dropped a bare `--follow-selector-forms`; `--identity=-bob` was shown as `--identity -bob`, which argparse rejects. The same `web/runner.build_flags` builds the web launcher's real child argv.
- **Root cause:** `build_flags` inverts argparse from `OptionSpec.type`/`multiple` only (`nargs`/`const` are not introspected) and was never tested as a round trip over every action of every registered parser; new shapes arrived later via other lanes' parsers.
- **Remediation:** pinned with strict xfails (`tests/test_cli_argv_roundtrip.py`); this lane's `train run` forwards argv verbatim (no new instance). The fix is the UI lane's (`fuzzlab/web/` is out of this lane's scope). `docs/bugs/BUG-0400-launcher-argv-builder-mis-serialises-flags.md`.
- **Status:** Open (pinned; handed to the UI session)

## 2026-10-15 — project files (unmerged): code review round 4 — a definition that only normalised equal passed the schema check (fixed, BUG-0456/PA-0456)
- **Symptom:** security reviewer: replacing the space before `argv` in `launch`'s stored definition with U+00A0 (or moving the newline that ends a `--` comment in `page`) passed `inspect` and `summary`; SQLite then had no `argv` column and `/project` was a 500.
- **Root cause:** the definition check compared text after Python's `str.split()` whitespace normalisation, which is not SQLite's grammar.
- **Remediation:** definitions compared byte for byte (`_exact_sql`), verified against fresh, analysed, downgraded and historical stores; regression test with non-vacuity steps; mutation-checked.
- **Status:** Fixed (re-reviewed: both reviewers APPROVE, code review round 5 on 4f6c46b)

## 2026-10-15 — project files (unmerged): code review round 3 — crafted table definitions ran SQL on open; crafted values crashed the project pages; a straddling credential was recorded (fixed, BUG-0453/PA-0453, BUG-0454/PA-0454, BUG-0455/PA-0455)
- **Symptom:** security reviewer: a project file whose `project` table definition gained a generated column built from `printf`/`replace` held `inspect` for 38 s (and `summary` hung the start screen); a 200 000-deep `targets` JSON or a BLOB `started_at` made `/projects/open` and `/project` 500s; both reviewers: `http://admin:<4 KB>@host` was recorded with the password.
- **Root cause:** the allowlist exempted tables from definition matching on a false belief about `trusted_schema=OFF`, and read `schema_version` before checking it; readers assumed fuzzlab-written types and shallow JSON; the record redactor cut values before stripping userinfo.
- **Remediation:** every definition compared, `schema_version` checked first, newer files read no further, length limits; `_text`/`_int` typing and `RecursionError` handled at both parsers; userinfo stripped from the whole value, cut last. Regression tests with non-vacuity steps; mutation-checked.
- **Status:** Fixed (re-reviewed: both reviewers APPROVE, code review round 5 on 4f6c46b)

## 2026-10-15 — project files (unmerged): a trigger passed the untrusted-file check again; tests created ./fuzzlab.db (fixed, BUG-0451/PA-0451, BUG-0452/PA-0452)
- **Symptom:** code review round 2 (reviewer B): a `sqlite_master` row typed `TRIGGER` passed `core.project.inspect` and fired during the UI's open; layout review (reviewer C): `/home/user/fuzzer/fuzzlab.db` (+ `fuzzlab.db.d/`) had been created in the repo by this branch's web tests.
- **Root cause:** the schema check was a case-sensitive denylist (its round-1 fix patched one spelling); the UI bound the built-in default store and a pinned launch from a default-config test created it.
- **Remediation:** an allowlist of exactly the objects fuzzlab's migrations create (`reference_schema`); the default store counts only if it exists, else the start screen offers it; default-config tests use private stores; a session guard fails a run that creates `./fuzzlab.db`; the stray files were removed.
- **Status:** Fixed (re-reviewed: both reviewers APPROVE, code review round 5 on 4f6c46b)

## 2026-10-15 — project files (unmerged, branch claude/new-session-dwzrhb): code review round 1 found defects in 9f1536e (fixed in the follow-up commit; CC-UI-0450, CC-CORE-0450)
- **Symptom:** two independent reviewers of the pushed, unmerged project-files commit found: a trigger named like a table passed the untrusted-file refusal (it deleted findings once opened); `redact_for_record` kept part of a password containing `@`; New / Save as adopted or deleted a stale `<name>.fuzzlab.d`; a planted symlink at a pinned intermediate let a tool write outside the project; opening an older/newer file while a project was open was silent; plus non-blocking gaps (dropped discard reports, broad exception lists, an uncapped `recent.json` read, an unrecorded `stopped` at shutdown, …). While testing the fix, a test that planted a FIFO as `recent.json` hung the run: opening a FIFO read-only blocks — the page itself would have hung the same way.
- **Root cause:** in-change defects of a not-yet-merged feature, caught by the review gate the process requires; the FIFO hang was an `os.open` without `O_NONBLOCK` on an attacker-placeable path.
- **Remediation:** every finding fixed and given a regression test (listed in the CC-UI-0450 / CC-CORE-0450 review notes); `recent.json` opened `O_NOFOLLOW | O_NONBLOCK` and refused unless a regular file. Recorded under the change's own CC entries (as BUG-0125's review rounds were, CC-CORE-0050) rather than as separate BUG-NNNN, since no defect reached a merged branch.
- **Status:** Fixed (re-reviewed: both reviewers APPROVE, code review round 5 on 4f6c46b)

## 2026-10-15 — fuzzer: an empty run imported the previous run's CSV (fixed, BUG-0450/PA-0450)
- **Symptom:** found in design review of project files (CC-UI-0450): `fuzzlab fuzz --store S` with a run that collected no rows still imported `--output` (default `blind_sqli_dataset.csv` in the working directory) — an earlier run's, possibly another target's or project's — as its own attempts; with no such file it crashed with `FileNotFoundError` before the oracle confirmation.
- **Root cause:** provenance inferred from presence: `save_dataset` wrote nothing for an empty run and returned no fact, and `main` imported the path unconditionally (a recurrence of PA-0075's root cause at the file layer).
- **Remediation:** `save_dataset` returns whether it wrote the file and `main` imports only then (CC-FUZZ-0450); the web UI pins `--output` to the project's own directory (FR-UI-456); PA-0450 and its sweep.
- **Status:** Fixed (offline test; mutation-checked)

## 2026-10-15 — core: `canonical_origin` raised on a malformed authority; one stored target row broke every origin reader (fixed at the reader boundary, BUG-0500/PA-0500)
- **Symptom:** in the site tree's code review, a `target` row with `base_url = 'http://[::1'` made every `/api/sitetree/*` request return 500; ML's holdout origin reader fails the same way on such a store.
- **Root cause:** `core.urls.canonical_origin` documents ``None`` for an unusable URL but calls `urlsplit` unguarded, which raises `ValueError` on a malformed IPv6 bracket or an NFKC-invalid netloc; stored-data readers called it directly.
- **Remediation:** `core.runtarget.origin_of` turns that `ValueError` into ``None`` ("origin unreadable"); `run_origins` (and so ML) and the site tree go through it; a node key with such an origin is a 400 (CC-CORE-0501, CC-UI-0503). The source fix in `core/urls.py` (locked) is pinned by a strict xfail.
- **Status:** Fixed at the reader boundary; source fix open (follow-up for the `core/urls.py` owner)

## 2026-10-14 — Oracle M4: an edit form's echo of the input hid an evaluated SSTI (fixed, BUG-0133/PA-0133)
- **Symptom:** on the live Juice Shop check of FR-FUZZ-49, `POST /profile username=#{728*889}` → 302 → `GET /profile` showed `647192`, yet `SstiStrategy` returned None.
- **Root cause:** M4's "evaluated, not just reflected" rule (`expr in text`) judged the probe's literal as a raw substring anywhere; the profile's edit field (`<input value="#{728*889}">`) echoes it. No fixture showed the input back in an edit form; the confirmer PAs covered only false positives.
- **Remediation:** the literal disqualifies only when echoed outside a form control's value (parsed: input `value`, textarea, selected option), and the number must then appear outside every form control; same for SpEL, the SQL evaluation marker and the Go template marker (which also missed HTML-escaped echoes). CC-FUZZ-0079. `docs/bugs/BUG-0133-an-edit-form-echo-hid-an-evaluated-ssti.md`.
- **Status:** Fixed (offline fixtures; the live Juice Shop re-check is the coordinator's)

## 2026-10-14 — Session manager: a browser login's senders lacked the cookie the SPA's JS set (fixed, BUG-0132/PA-0132)
- **Symptom:** live on Juice Shop, `fuzzlab auto --identity juice-user` probed `/profile` (SSTI) and `/profile/image/url` (SSRF) effectively unauthenticated: 0 candidates, 0 attempts. `/profile` answers 500 with the bearer alone and 200 with the `token` cookie alone; the crawl (full browser state) did reach it.
- **Root cause:** `_browser_login_state` built the session from the login response's detected credential only (the bearer); the `token` cookie the app's JS sets afterwards is in the browser's jar, never in a response, and was not carried into `SessionState.cookies`. The fixture's endpoints read only the bearer.
- **Remediation:** the jar's in-scope cookies (password-cleaned, host-matched, unexpired, `secure` only for an https-only session) join the session's cookies; the corrupted-credential arm corrupts the cookie copy of the bearer too; `session print` prints every header; the crawler checks credential cookies only. CC-SESS-0022, CC-CRAWL-0025. `docs/bugs/BUG-0132-browser-login-dropped-the-js-set-session-cookie.md`.
- **Status:** Fixed (verified offline on a fixture page that reads only the JS-set cookie; the live Juice Shop re-run is the coordinator's)

## 2026-10-14 — Crawler/importer: a `#` in a label, control name, entry or option hid the destructive word (fixed, BUG-0131/PA-0131)
- **Symptom:** while building forms phase 4's label gate: `spa.form_refusal` let a button labelled `#1 Delete` through (plain `Delete` was refused); `store_adapter.entries_refusal`, `formnav.option_refusal` and control names behaved the same.
- **Root cause:** each gate judged a text by embedding it in a URL (`destructive_reason("/?x=" + text)`); `urlsplit` moves everything after `#` into the fragment, which the URL rule never reads. Tests used only texts without URL-structural characters.
- **Remediation:** `core.urls.text_destructive_reason` (the same tokens over the whole text); the four sites use it; SPA fragments are also judged as texts; an AST guard forbids splicing a text into a URL for a URL rule. CC-CORE-0052, CC-CRAWL-0024, CC-AUD-0039. `docs/bugs/BUG-0131-a-hash-in-a-label-hid-the-destructive-word.md`.
- **Status:** Fixed
- **Follow-up (same day):** the one residual of the sweep, `harness.auto._crawl_url_refusal` (it re-joined a SPA route's path and query into a URL), now judges the fragment as a text too; PA-0131's AST guard has no exception left. CC-FUZZ-0077.

## 2026-10-14 — Lab servers launched by harnesses/tests not pinned to loopback (fixed, BUG-0130/PA-0130)
- **Symptom:** the integration full suite (p3-int + bug-0125 at 83650d6) failed `tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`: it read the five harnesses' `procutil.start_server` calls (and `run_bounded`'s) as `asyncio.start_server`. Checking what those launched servers bind found real exposure: Spring Boot (harness + 4 tests) started with `--server.port` only, i.e. on 0.0.0.0; Go and Node servers took `HOST` from the inherited environment.
- **Root cause:** loopback-only was enforced at fuzzlab's own Python listener calls (PA-0081) and the compose port binds, never at the real sockets of servers launched as other programs; launch sites left the bind address to framework defaults and inherited env.
- **Remediation:** every launch site pins loopback explicitly (`--server.address=127.0.0.1`, `HOST=127.0.0.1`, host in argv); `procutil.listeners` reads the tree's real LISTEN sockets from /proc and `stop_server` (every site) raises `NonLoopbackListener`, the harnesses also check right after boot; the listener guard exempts procutil launches and scans tests/ too; a static pin rule over fuzzlab/ and tests/. CC-LAB-0255, CC-CORE-0051. `docs/bugs/BUG-0130-lab-servers-not-pinned-to-loopback.md`.
- **Status:** Fixed (Spring/Node/Rails/Django pins verified statically only: no network installs here)
- **Follow-up (same day, review):** the stop's listener check could abort the stop on an exception (now total: recorded, stop/sweep/collect always run, `ListenerCheckFailed` raised after); exposure masked a lost server (`ExposedAndLost`); exposure tests now bind wildcards only in a private netns. BUG-0130 "Follow-up", PA-0130 items 4-5.

## 2026-10-14 — Fuzzer: any page dialog confirmed browser XSS (fixed, BUG-0129/PA-0129)
- **Symptom:** in code review (reviewers A and B), and reproduced on a real browser: a page that shows its own `alert` on load, with an inert reflection, was reported as executing the DOM-XSS payload.
- **Root cause:** the M6 executor recorded the probe's token on any dialog; the payloads never open one (they call the tokened sentinel). PA-0117's noise guard never reached the executor's own channels.
- **Remediation:** dialogs are dismissed and never counted; the tokened sentinel binding is the only evidence. CC-FUZZ-0074. `docs/bugs/BUG-0129-any-dialog-confirmed-browser-xss.md`.
- **Status:** Fixed

## 2026-10-14 — Crawler/auditor/fuzzer: browser teardown hung while a page navigated (fixed, BUG-0128/PA-0128)
- **Symptom:** a real-browser M6 test whose page navigates right after the payload fires hung in about 1 run in 9; a call trace showed `BrowserContext.unroute_all` never returning.
- **Root cause:** `navguard.release` unrouted before the context's pages were closed, so a navigation's paused requests were still in flight and the driver never answered the interception change. All browser teardowns use `release`.
- **Remediation:** `release` closes every page first, then unroutes. 80 runs with no hang (was 1 in 9). CC-CRAWL-0020. `docs/bugs/BUG-0128-browser-teardown-hangs-while-a-page-navigates.md`.
- **Status:** Fixed

## 2026-10-14 — Fuzzer: reflected XSS confirmed in a JSON response (fixed, BUG-0127/PA-0127)
- **Symptom:** the live Juice Shop run confirmed `xss-reflected` on `/api/Challenges/?sort=`, whose `application/json` error echoes the value; no browser runs it.
- **Root cause:** `ReflectedXssStrategy` parsed every response as HTML; the content type was an unstated precondition no fixture broke. The open-redirect meta-refresh check had the same gap.
- **Remediation:** both confirm only in a response a browser renders as HTML (`text/html`, `application/xhtml+xml`, or untyped); tests with JSON/text/script echoes. CC-FUZZ-0072. `docs/bugs/BUG-0127-reflected-xss-confirmed-in-json.md`.
- **Status:** Fixed

## 2026-10-14 — Fuzzer: `auto --browser` aborted; DOM XSS missed (fixed, BUG-0126/PA-0126)
- **Symptom:** the first live `fuzzlab auto --browser` run on Juice Shop exited `rc=1` at the first browser check (`Executable doesn't exist at …/chrome-headless-shell`); with the binary given, the `#/search?q=` DOM XSS was not confirmed.
- **Root cause:** the M6 executor had its own copy of the Chromium launch settings without the operator's binary, did not contain a launch failure, and read its sentinel 300 ms after `load` (Juice Shop's sink fires at about 1 s). Its tests were all fakes.
- **Remediation:** one launch helper (`navguard.chromium_launch_kwargs`) at all three launch sites, AST-guarded; a failed launch is "no verdict" for the run; the sentinel is polled for up to 4 s. Verified live (the DOM XSS confirms in 2.1 s). CC-FUZZ-0071, CC-CRAWL-0018, CC-AUD-0037. `docs/bugs/BUG-0126-browser-executor-never-worked-live.md`.

## 2026-10-14 — Test infrastructure: leaked lab servers OOM-killed the suite (fixed, BUG-0125/PA-0125)
- **Symptom:** full-suite runs were OOM-killed (memory cgroup; Chrome and pytest killed). 429 orphaned `php8.3 -S 127.0.0.1:<port> /tmp/fuzzlab-php-laravel-live-boot-*/…/server.php` processes (ages 1–10 h), ~15 orphaned `/tmp/go-build…/exe/main` and a `puma`, parent PID 1, held ~14 GB. One passing run of `tests/test_labgen_php_laravel_access_control_live_boot.py` left 3 new orphans.
- **Root cause:** `LiveBootHarness` started `php artisan serve`, whose child `php -S` survived `close()` (it terminated only `artisan`); `go run`, `bundle exec`/puma and `mvn` have the same launcher shape; nothing tied any test-launched server to its owner's life, a forking tool's `subprocess.run` timeout killed only the direct child, and a harness whose build failed after the server started never closed it.
- **Remediation:** the orchestrator stopped the orphans by PID (each command line read first; the operator's bWAPP and Juice Shop labs untouched), freeing 12.7 GB. Fix: `fuzzlab/procutil.py` — a supervisor per server (own session, PDEATHSIG + subreaper, group stop, identity-checked by pidfd and start time, never by pattern), `run_bounded` for forking tools; all five harnesses, the test servers, the web runner and the sweep sites use it; Laravel runs `php -S` directly; a session-end safety net fails any run that leaks a server; an AST guard. CC-CORE-0048, CC-LAB-0254, CC-UI-0053. `docs/bugs/BUG-0125-test-lab-servers-leaked.md`.
- **Status:** Fixed

## 2026-10-14 — Fuzzer: Juice Shop's allowlist-gated open redirect never detected (fixed, BUG-0124/PA-0124)
- **Symptom:** `fuzzlab auto` over all categories missed Juice Shop's open redirect (`/redirect?to=` redirects when the target contains an allowlisted URL).
- **Root cause:** the open-redirect rule selected by parameter name only (`to` is not in it); the value-shape rules mapped only the categories one lane needed; the confirmer sent one plain canary, which a containment allowlist refuses.
- **Remediation:** one shape → categories table with `R-OPEN-REDIRECT-VALUE` / `R-SSRF-VALUE`; a redirect seed (http/https, no query, no identifier-like host or path piece) sent only in a second `.example` canary after the plain one fails, a stated FR-AUD-20 exception the operator approved; host-based confirmation. CC-AUD-0034, CC-FUZZ-0067, CC-ML-0029. `docs/bugs/BUG-0124-allowlist-gated-open-redirect-missed.md`.
- **Status:** Fixed

## 2026-10-14 — Crawler/auditor/M6 browser: requests left the target origin (fixed, BUG-0123/PA-0123)
- **Symptom:** the first Juice Shop crawl's browser followed `/redirect?to=https://github.com/...` and rendered github.com; the forms phase 1/2 bWAPP crawls likewise rendered `itsecgames.blogspot.com` through `http_response_splitting.php?url=`. No cookie or credential left the lab.
- **Root cause:** scope was enforced at the link queue only; `navguard.guard_page` checked destructive URLs only, Playwright never routes a redirect's later hops, launches did not confine name resolution, API-request clients were unchecked, and a loopback start admitted every loopback port.
- **Remediation:** one origin predicate (`core.urls.in_origin_scope`); a context-wide route that checks scope then destructive tokens and walks redirect chains hop by hop; WebSocket routing; `browser_launch_args` (no proxy, resolver rules per `host:port`, background networking off); scope-checked API requests with `max_redirects=0`; a loopback crawl scoped to its exact origin. AST guard plus real-browser tests. The sweep fixed the session's post-login redirect chain and the labgen identifier-SQLi runner (both followed redirects unchecked). CC-CORE-0044, CC-CRAWL-0015, CC-AUD-0033, CC-FUZZ-0066, CC-SESS-0020, CC-LAB-0253. `docs/bugs/BUG-0123-browser-left-the-target-origin.md`.
- **Status:** Fixed

## 2026-10-14 — Session: any redirect containing "login" read as a logout (fixed, BUG-0122/PA-0122)
- **Symptom:** in the live bWAPP phase 2 run, `ba_insecure_login.php` → `302 ba_insecure_login_1.php` re-logged the run in, and the header breaker falsely stopped header probing ("session bound to a probed header").
- **Root cause:** `detect_logout`'s redirect rule was a substring test. PA-0022 (anchor keyword heuristics) was never enforced on session detection, and its `\b` remedy is too weak for URLs.
- **Remediation:** `redirect_is_logout`, which matches the session's own login URL (key, scheme upgrade, query-routed) or an anchored login segment or token. An AST guard bans substring auth-state tests in the session, auth and navigation modules. CC-SESS-0019. `docs/bugs/BUG-0122-logout-redirect-substring-rule.md`.
- **Status:** Fixed

## 2026-10-14 — Fuzzer: a probe meant for one location was sent at another (fixed, BUG-0115/PA-0115)
- **Symptom:** found in design (forms phase 2): greybox sent ground-truth header payloads as query parameters; with `--browser`, DOM XSS loaded POST-body (and would load header) payloads as URL query parameters, so a hit would be recorded against the wrong input.
- **Root cause:** each component that builds its own request fell through to "query" for a location it did not handle; the seam conformance checks covered signatures, not placement.
- **Remediation:** greybox header branch and `UnplaceableLocation`; DOM XSS only for query/fragment points; the browser executor refuses unplaceable locations; the pipeline's fingerprint probe goes through a query (else body) point with its siblings, never a header point (review follow-up); a placement conformance check by discovery. The probe senders' unknown-location fallback is pinned by a strict xfail (needs a scored ground-truth run). CC-FUZZ-0063. `docs/bugs/BUG-0115-probe-location-relocated.md`.
- **Status:** Fixed (one instance pinned, flagged)

## 2026-10-14 — Oracle: SQLi, file-inclusion, SSTI and SpEL strategies confirmed on evidence the probe did not cause (fixed, BUG-0117/PA-0117)
- **Symptom:** these pages were all "confirmed" (tests T7/T7b/T8/T12/T27 fail on `ad352db`):
  - a page that always prints a MySQL warning;
  - a strict INT column that errors on any non-numeric input;
  - a page alternating A, A, B;
  - a page that always shows `root:x:0:0:`;
  - a page full of numbers.
- **Root cause:** the "control or replicate" rule (PA-0084/0090/0094) was enforced per mechanism by fixtures, never across a category by discovery, so the older strategies were never swept.
- **Remediation:**
  - controls for SqliError and PathTraversal;
  - a bracketed, replicated differential engine for SqliBoolean (bound 1/1458 per family, proven exactly);
  - two-sample cross-checks for SSTI and SpEL;
  - a noise-discovery guard, proven on offenders.

  CC-FUZZ-0065. `docs/bugs/BUG-0117-sqli-evidence-not-caused-by-the-probe.md`.
- **Status:** Fixed

## 2026-10-13 — Crawler/fuzzer: the destructive-URL rule missed `update` / `insert` (fixed, BUG-0114/PA-0114)
- **Symptom:** bWAPP's `update.php` rebuilds its database on a plain GET, and the deny rule allowed it (latent: nothing linked to it yet).
- **Root cause:** BUG-0111's token list was never checked against the target's own destructive endpoints.
- **Remediation:** an `insert` token and `update`-as-a-script-name pairs; a from-source test of bWAPP's destructive GETs. CC-CORE-0039. `docs/bugs/BUG-0114-destructive-list-missed-update-and-insert.md`.
- **Status:** Fixed

## 2026-10-13 — Session/crawler: an app under a sub-path could not log in; crawl points doubled the path (fixed, BUG-0113/PA-0113)
- **Symptom:** `fuzzlab crawl --start http://127.0.0.1:8090/bWAPP/portal.php --identity user`: "no login form found from http://127.0.0.1:8090".
- **Root cause:** the spider and `SessionManager.prepare` truncated the operator's URL to its origin; `injection_points_from_store` joined absolute paths to the base's path. Our labs all serve at `/`.
- **Remediation:** discovery from the operator's URL (remembered for re-login), a directory fallback without query, operator-only destructive exemption, origin-root cookies, pre-login in the auditor and fuzz, origin joins. CC-SESS-0016, CC-CRAWL-0012, CC-AUD-0030, CC-FUZZ-0061. `docs/bugs/BUG-0113-base-url-truncated-to-origin.md`.
- **Status:** Fixed

## 2026-10-13 — Fuzzing: auth endpoints probed with the session; destructive crawl points fuzzed (fixed, BUG-0112/PA-0112)
- **Symptom:** `is_auth_endpoint` had no caller; an authenticated crawl-sourced run would probe login.php/logout.php with the session.
- **Root cause:** NFR-FUZZ-safe's exclusion was recorded but never consumed at the send; nothing traced the NFR to a test.
- **Remediation:** `check_send_url` in every probe sender (explicit ground-truth allowance, AST guard); destructive crawl points skipped and reported; auth endpoints probed anonymously; no cookie carried between probes. CC-FUZZ-0060, CC-CORE-0038. `docs/bugs/BUG-0112-auth-endpoints-fuzzed-with-the-session.md`.
- **Status:** Fixed

## 2026-10-13 — Crawler: no destructive-link deny-list; would GET bWAPP's reset.php (DROP DATABASE) and logout.php (fixed, BUG-0111/PA-0112)
- **Symptom:** found before an authenticated crawl of the loopback bWAPP: every same-host link, redirect, script fetch and subresource was followed, and the auditor re-fetched them.
- **Root cause:** NFR-CRAWL-safe was specified and never built; safety NFRs were not traced to tests.
- **Remediation:** `core.urls.destructive_reason`; queue filter, hand-followed redirects and a browser route guard in the spider; auditor and M6 guarded; discovery hops checked. PA-0112's traceability guard over every NFR. CC-CORE-0038, CC-CRAWL-0011, CC-AUD-0029, CC-SESS-0015. `docs/bugs/BUG-0111-crawler-followed-destructive-links.md`.
- **Status:** Fixed

## 2026-10-13 — Session: login to a real third-party target rejected with right credentials (fixed, BUG-0110/PA-0111)
- **Symptom:** `fuzzlab session print` against a loopback bWAPP: "login for user@127.0.0.1 was rejected (status 200)".
- **Root cause:** the login detector read each control's `value` attribute: no submit-button `form=submit`, and the `<select>` sent `""`.
- **Remediation:** `core.forms.form_entries` builds the HTML entry list, rule by rule; a submitter override is refused. CC-CORE-0037, CC-SESS-0014, CC-AUD-0028. `docs/bugs/BUG-0110-login-form-not-serialised-like-a-browser.md`.
- **Status:** Fixed

## 2026-10-13 — Credentials: a failed credential delete reported success (fixed, BUG-0109/PA-0110)
- **Symptom:** a backend PermissionError on delete returned normally; the credential stayed usable.
- **Root cause:** `except Exception: pass` around the backend delete.
- **Remediation:** delete verifies the entry is gone, else CredentialError with the cause. CC-CORE-0036. `docs/bugs/BUG-0109-credential-delete-reported-false-success.md`.
- **Status:** Fixed

## 2026-10-13 — Credentials: concurrent keyring updates lost one (fixed, BUG-0108/PA-0109)
- **Symptom:** three writer processes kept 6 of 18 credentials.
- **Root cause:** an unlocked load-modify-replace.
- **Remediation:** a thread lock plus a flock on a stable <keyring>.lock, held across load → save. CC-CORE-0036. `docs/bugs/BUG-0108-keyring-lost-update.md`.
- **Status:** Fixed

## 2026-10-13 — ML: unreadable evidence crashed datasets or fabricated a training row (fixed, BUG-0107/PA-0108)
- **Symptom:** `[]` evidence → AttributeError; `{not json` → a fake negative row on `/`.
- **Root cause:** no shape validation; `{}` default.
- **Remediation:** one parser (`core.evidence`); quarantine, count and record; refuse past 5% or on possible label loss. CC-ML-0025, CC-FUZZ-0059. `docs/bugs/BUG-0107-bad-evidence-crashed-or-fabricated-rows.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy: a failed history flush left a partial transaction; retry duplicated rows (fixed, BUG-0106/PA-0107)
- **Symptom:** an open transaction with one row visible; a retry wrote it twice.
- **Root cause:** interleaved redact/insert with no savepoint or rollback.
- **Remediation:** prepare first, then write in a savepoint, roll back on error, commit only an owned transaction. CC-PROXY-0021. `docs/bugs/BUG-0106-history-flush-not-atomic.md`.
- **Status:** Fixed

## 2026-10-13 — Storage: directory-fsync failures were swallowed after a secret replace (fixed, BUG-0105/PA-0106)
- **Symptom:** an injected EIO returned normally.
- **Root cause:** a bare `except OSError` (agreed only for unsupported platforms).
- **Remediation:** skip only EINVAL/ENOTSUP/EOPNOTSUPP or no O_DIRECTORY; else DurabilityUnknown. CC-CORE-0036. `docs/bugs/BUG-0105-directory-fsync-errors-swallowed.md`.
- **Status:** Fixed

## 2026-10-13 — ML: malformed holdout metadata removed the seal (fixed, BUG-0104/PA-0105)
- **Symptom:** `holdout: {}`/None/False/unparseable read as unsealed.
- **Root cause:** truthiness for presence; the seal only in mutable JSON.
- **Remediation:** present-but-malformed → UNKNOWN; migration 19 `holdout_seal` with an in-migration backfill; guard allow-list. CC-ML-0025, CC-CORE-0036, CC-PLUG-0009. `docs/bugs/BUG-0104-malformed-holdout-record-removed-seal.md`.
- **Status:** Fixed

## 2026-10-13 — ML: a finite saved model predicted NaN (fixed, BUG-0103/PA-0104)
- **Symptom:** std=5e-324 → predict_proba [nan].
- **Root cause:** operands validated, arithmetic not.
- **Remediation:** std ≥ 1e-12 (trainer floors too); z, logit and outputs checked before return. CC-ML-0025. `docs/bugs/BUG-0103-finite-model-predicts-nan.md`.
- **Status:** Fixed

## 2026-10-13 — Oracle: a regex literal was lexed as code (false XSS) (fixed, BUG-0102/PA-0103)
- **Symptom:** `return /TOK/` with escaped slashes → CONFIRMED.
- **Root cause:** a one-character regex/division look-behind.
- **Remediation:** token-aware context (keywords, paren heads), `}/` → UNSURE. CC-FUZZ-0059. `docs/bugs/BUG-0102-regex-literal-lexed-as-code.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy: upstream reads were unbounded, quadratic and blocked the loop (fixed, BUG-0101/PA-0102)
- **Symptom:** 541 MB copied for an 8 MiB body; a slow upstream stalled others.
- **Root cause:** bytes(body) per chunk, no caps, sync sender in a coroutine.
- **Remediation:** one bytearray, header/body caps and a deadline, sender in a thread. CC-PROXY-0021. `docs/bugs/BUG-0101-unbounded-upstream-read.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy/core: JSON redaction failed open; deep input crashed (fixed, BUG-0100/PA-0101)
- **Symptom:** a huge int, trailing comma or unquoted key kept the password; 1,100-deep raised.
- **Root cause:** `except ValueError: return body`; no bounds; type-only dispatch.
- **Remediation:** fail closed: a whole-body token scan, size and depth bounds, sniffing, framed bodies decoded or omitted. CC-CORE-0036, CC-PROXY-0021. `docs/bugs/BUG-0100-redaction-failed-open.md`.
- **Status:** Fixed

## 2026-10-13 — Core: the HTTP client's recorder stored secrets (fixed, BUG-0099/PA-0100)
- **Symptom:** URL token, request password and response token persisted in flow/body.
- **Root cause:** a second producer outside the proxy's redaction.
- **Remediation:** one storage boundary in core.redaction used by both producers; an AST producer guard. CC-CORE-0036. `docs/bugs/BUG-0099-http-client-recorder-stored-secrets.md`.
- **Status:** Fixed

## 2026-10-13 — Session: an https session was reused over plain http (fixed, BUG-0098/PA-0099)
- **Symptom:** cookie and bearer applied to http://; greybox sent the cookie unchecked.
- **Root cause:** the floor bound only the login POST.
- **Remediation:** SessionState.secure_only checked by prepare, authorize (after plugins), session_header and greybox. CC-SESS-0013, CC-CORE-0036. `docs/bugs/BUG-0098-https-session-reused-over-http.md`.
- **Status:** Fixed

## 2026-10-13 — Session: a redirected login page became a trusted credential origin (fixed, BUG-0097/PA-0098)
- **Symptom:** the password was POSTed to attacker.example/collect.
- **Root cause:** BUG-0092 made the response-derived final URL the allow-list anchor.
- **Remediation:** hops walked by hand and authorised before fetching; the anchor is operator input only. CC-SESS-0013. `docs/bugs/BUG-0097-redirected-login-page-trusted-as-credential-origin.md`.
- **Status:** Fixed

## 2026-10-13 — Storage: a short write left a truncated secret file and reported success (fixed, BUG-0096/PA-0097)
- **Symptom:** under a real file-size limit, `write_secret` returned normally with 4 of 11 bytes on disk; the keyring would rename such a temp over the good keyring.
- **Root cause:** a single `os.write` with its count ignored; no fsync; a non-atomic replace.
- **Remediation:** complete-or-raise writes with fsync; atomic `replace_secret` and `O_EXCL` `create_secret`; the keyring and the CA use them, and the CA pair is checked on load. CC-CORE-0035, CC-PROXY-0020. `docs/bugs/BUG-0096-short-write-truncates-secret-file.md`.
- **Status:** Fixed

## 2026-10-13 — ML: a huge JSON integer escaped the model loader's typed refusal (fixed, BUG-0095/PA-0096)
- **Symptom:** `rate = 10**1000` with a valid sha raised a raw `OverflowError`; sizes were unbounded.
- **Root cause:** `_is_num` could raise, and the boundary enumerated exception classes.
- **Remediation:** a total `_is_num`; `OverflowError` / `MemoryError` wrapped; byte, element, tree and depth limits on dump and load. CC-ML-0024. `docs/bugs/BUG-0095-huge-json-int-escapes-model-loader.md`.
- **Status:** Fixed

## 2026-10-13 — ML: `flag_top` counted tie groups quadratically (fixed, BUG-0094/PA-0095)
- **Symptom:** 1.6 M comparisons at n=4000; 3.9 s at 40k scores.
- **Root cause:** a full rescan per distinct score.
- **Remediation:** one `Counter` pass with an operation-count test; NaN raises. CC-ML-0024. `docs/bugs/BUG-0094-flag-top-quadratic-tie-counting.md`.
- **Status:** Fixed

## 2026-10-13 — Oracle: a reflection in a script that never runs was confirmed as XSS (fixed, BUG-0093/PA-0094)
- **Symptom:** CONFIRMED for JSON, ld+json, `<template>` and `src` scripts.
- **Root cause:** any `<script>` was treated as JavaScript.
- **Remediation:** `script_executes` per the HTML standard's type rules; inert scripts are text in a raw-text element. CC-FUZZ-0058. `docs/bugs/BUG-0093-inert-script-confirmed-as-xss.md`.
- **Status:** Fixed

## 2026-10-13 — Session: credentials could be sent over a downgrade from https to http (fixed, BUG-0092/PA-0093)
- **Symptom:** an https login page allowed an http same-host or in-scope-port destination.
- **Root cause:** allow rules OR-ed with no prior deny; the agreed "never a downgrade" was waived as "moot".
- **Remediation:** a transport deny before every allow, with an https floor from `base_url`, discovery hops, the page and redirects. CC-SESS-0012. `docs/bugs/BUG-0092-credentials-sent-over-https-downgrade.md`.
- **Status:** Fixed

## 2026-10-13 — ML: sealed holdout labels moved public forward metrics (fixed, BUG-0091/PA-0092)
- **Symptom:** flipping 9 held-out labels moved the public forward PR-AUC from 0.668 to 0.761, with no reveal recorded.
- **Root cause:** the seal was per model and per enumerated reader; forward evaluation and non-holdout trainers were outside it.
- **Remediation:** per-target sealing: every trainer gets an implied holdout, forward evaluations and ML-tab panels read public rows only, and an unknown membership fails closed. CC-ML-0024, CC-UI-0050. `docs/bugs/BUG-0091-sealed-holdout-labels-move-public-metrics.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy: sensitive JSON containers kept their secrets in history (fixed, BUG-0090/PA-0091)
- **Symptom:** `{"tokens":[...],"credentials":{...}}` was persisted unchanged.
- **Root cause:** only scalar values of a sensitive key were replaced; plurals were not sensitive.
- **Remediation:** a sensitive key's whole value is replaced; plural fold in `core.redaction`. CC-PROXY-0020, CC-CORE-0035. `docs/bugs/BUG-0090-json-container-secrets-in-proxy-history.md`.
- **Status:** Fixed

## 2026-10-13 — Oracle: in-band SSRF/XXE confirmed on a reflection of the callback URL (fixed, BUG-0089/PA-0090)
- **Symptom:** a page that only echoed the submitted callback URL confirmed SSRF / XXE in-band.
- **Root cause:** the listener served the token as its body, and the token is in the URL.
- **Remediation:** the listener serves an HMAC proof of the token, and the strategies require it. CC-FUZZ-0057. `docs/bugs/BUG-0089-oob-in-band-confirms-url-reflection.md`.
- **Status:** Fixed

## 2026-10-13 — Scheduler: bandit backoff never took effect (fixed, BUG-0088/PA-0089)
- **Symptom:** with backoff on, a cold sibling context still started at the flat prior.
- **Root cause:** `_seed` reads parent posteriors, but `update` never wrote them.
- **Remediation:** parent contexts pool their leaves' pulls; the panels label them "(pooled)". CC-SCHED-0006, CC-UI-0049. `docs/bugs/BUG-0088-bandit-backoff-never-takes-effect.md`.
- **Status:** Fixed

## 2026-10-13 — Store: migrations not atomic; concurrent first opens failed 13 of 20 (fixed, BUG-0087/PA-0088)
- **Symptom:** duplicate-column / table-exists / locked errors on concurrent first opens; a failed migration left partial state.
- **Root cause:** `executescript` commits and runs in autocommit, and the version was not re-read under a lock; the WAL switch bypasses the busy handler.
- **Remediation:** `BEGIN IMMEDIATE` per migration with an in-lock re-check, statement-by-statement execution, ROLLBACK on error, and a WAL-switch retry. CC-CORE-0034. `docs/bugs/BUG-0087-migrations-not-atomic-first-open-race.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy: a port-specific scope exclude was bypassed; IPv6 authorities were misparsed (fixed, BUG-0086/PA-0087)
- **Symptom:** flows of an excluded `host:port` were recorded; `CONNECT [::1]:8443` parsed as host `[`.
- **Root cause:** a second, host-only scope check; `partition(":")` in five places.
- **Remediation:** one scope decision on the authority; one IPv6-aware `proxy.authority` parser. CC-PROXY-0019. `docs/bugs/BUG-0086-scope-exclude-bypass-and-ipv6-authority.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy: one bad match/replace or scope rule broke every connection (fixed, BUG-0085/PA-0086)
- **Symptom:** after adding a non-latin-1 or bad-regex rule, every request got an empty reply.
- **Root cause:** rules were not validated at creation, and `_on_client` contained only `CancelledError`.
- **Remediation:** validation at creation (API 400); per-connection containment (502 if nothing was written yet). CC-PROXY-0019, CC-UI-0049. `docs/bugs/BUG-0085-proxy-rule-errors-crash-connections.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy: history persisted URL tokens, body passwords and redirect tokens (fixed, BUG-0084/PA-0085)
- **Symptom:** `flow.url`, stored raw messages and FTS contained `access_token`, `password` and `session` values.
- **Root cause:** only headers were redacted, despite the docstring.
- **Remediation:** name-token redaction of query parameters, URL headers and form / JSON / multipart bodies in every persisted copy; one shared predicate with obs. CC-PROXY-0019, CC-CORE-0034. `docs/bugs/BUG-0084-proxy-history-persists-secrets.md`.
- **Status:** Fixed

## 2026-10-13 — Oracle: reflected-XSS confirmed non-exploitable reflections (fixed, BUG-0083/PA-0084)
- **Symptom:** an escaped value mid-URL and a json_encode'd JS string were confirmed as XSS.
- **Root cause:** confirmation by substring presence, with a fixed break-out per context.
- **Remediation:** structural confirmation (element, injected attribute, JS code state, scheme position) with a fail-closed JS lexer; tests derived from the 4 lab sink templates. CC-FUZZ-0057. `docs/bugs/BUG-0083-reflected-xss-oracle-false-positives.md`.
- **Status:** Fixed

## 2026-10-13 — Mutation/greybox: destructive payloads were sent without `--allow-destructive` (fixed, BUG-0082/PA-0083)
- **Symptom:** `mutate-run` sent 10 of 10 `DROP TABLE` variants with the flag off.
- **Root cause:** the gate existed only at record time, on raw strings.
- **Remediation:** a send-time gate on raw and normalised payloads; a destructive base is skipped entirely; greybox is gated too. CC-MUT-0012, CC-FUZZ-0057. `docs/bugs/BUG-0082-destructive-payloads-sent-without-flag.md`.
- **Status:** Fixed

## 2026-10-13 — Session: credentials POSTed to any form action and re-sent on redirects (fixed, BUG-0081/PA-0082)
- **Symptom:** a form `action` on another host received the stored username and password; a 307 re-sent them; Basic logins never worked.
- **Root cause:** the action URL from the page was trusted, and the client followed redirects.
- **Remediation:** an origin rule (login origin / https upgrade / in scope / `auth_origins`), redirects followed by hand (307/308 never), Basic at discovery. CC-SESS-0011. `docs/bugs/BUG-0081-session-credentials-to-any-form-action.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy: `fuzzlab proxy --host 0.0.0.0` bound every interface (fixed, BUG-0080/PA-0081)
- **Symptom:** the CLI bound a non-loopback host.
- **Root cause:** three copies of the loopback check, none in the proxy CLI or server.
- **Remediation:** one `core.net` gate at every listener, with an AST guard finding listeners by call shape. CC-PROXY-0019, CC-CORE-0034, CC-UI-0049. `docs/bugs/BUG-0080-proxy-cli-binds-non-loopback.md`.
- **Status:** Fixed

## 2026-10-13 — Proxy CA: CONNECT host path traversal; keys briefly world-readable (fixed, BUG-0079/PA-0080)
- **Symptom:** `CONNECT ../../outside/evil:443` wrote a cert and key outside the CA directory.
- **Root cause:** the raw CONNECT host was used as a filename; keys were written, then chmodded (the keyring file too).
- **Remediation:** host grammar validation, a path backstop, and 0600-from-creation `write_secret` with `O_NOFOLLOW` (CA and keyring). CC-PROXY-0019, CC-CORE-0034. `docs/bugs/BUG-0079-proxy-ca-leaf-path-traversal.md`.
- **Status:** Fixed

## 2026-10-13 — `fuzzlab auto`: the D15 fail-safe exit left an orphan run row (fixed, BUG-0078/PA-0079)
- **Symptom:** a usage error (no categories, `--points ground-truth` without a contract)
  exited 2 but left an empty run behind, which `fuzzlab report` then defaulted to.
  `greybox-run` (no crawl points) and `run_targets` (a bad spec after earlier targets
  had started) did the same.
- **Root cause:** usage validation ran after `start_run`. An earlier fix of the same
  symptom (plugins, CC-FUZZ-0050) left no rule and no sweep.
- **Remediation:**
  - a shared pure `plan_run`, run before the store;
  - environment prechecks (`--browser`, greybox paths);
  - `Store.mark_aborted` marks a run that fails after it starts.

  CC-FUZZ-0056, CC-CORE-0033; `docs/bugs/BUG-0078-d15-exit-leaves-orphan-run.md`.
- **Status:** Fixed

## 2026-10-13 — ML tab: bandit pull counts counted prior mass (fixed, BUG-0077/PA-0078)
- **Symptom:** after one pull, the panel showed 3 and 1 pulls on two arms.
- **Root cause:** pulls were shown as `α + β − 2`, which assumes a Beta(1,1) prior;
  arms carry informed priors.
- **Remediation:** pulls read the stored `cost_n` counter. CC-UI-0048;
  `docs/bugs/BUG-0077-bandit-panel-pull-counts.md`.
- **Status:** Fixed

## 2026-10-13 — Plugins: one malformed plugin crashed every plugin's registration (fixed, BUG-0076/PA-0077)
- **Symptom:** an entry point with `priority = "high"` made
  `PluginManager.from_entry_points` raise, losing every plugin, the ML stages included.
- **Root cause:** metadata reading in `register()`, and hook lookup, were outside the
  containment boundary.
- **Remediation:** every exception from `plugin_info` rejects only that plugin, with
  its reason; a bool priority is rejected; hook lookup is contained. CC-PLUG-0008;
  `docs/bugs/BUG-0076-plugin-registration-not-contained.md`.
- **Status:** Fixed

## 2026-10-13 — ML dataset: labels ignored the HTTP method (fixed, latent, BUG-0075/PA-0076)
- **Symptom:** a finding confirmed only on POST labelled the GET candidate at the same
  path and param positive.
- **Root cause:** the label and seen-key joins omitted the method, which both tables
  record.
- **Remediation:** a shared `dataset.method_key` on both sides; a method-less finding
  still matches any method. CC-ML-0023;
  `docs/bugs/BUG-0075-dataset-labels-ignore-http-method.md`.
- **Status:** Fixed

## 2026-10-13 — Report/run page: a store-wide model cited for runs it never scored (fixed, BUG-0074/PA-0075)
- **Symptom:** after a store-wide train, a later unscored run reported that model.
- **Root cause:** a NULL model scope was read as "covers every run".
- **Remediation:** store-wide trains record `scored_run_ids`; legacy rows cover only
  runs holding that family's stored score (`select_latest(score_column=…)`). CC-ML-0023;
  `docs/bugs/BUG-0074-store-wide-model-cited-for-unscored-runs.md`.
- **Status:** Fixed

## 2026-10-13 — ML tab: ranker baseline not comparable; ties broken by input order (fixed, BUG-0073/PA-0074)
- **Symptom:** a no-signal ranker showed precision@k 0.5 against a "random baseline" of
  0.1. A constant ranker scored nDCG 1.0 when the input listed positives first.
- **Root cause:** the panel's baseline was a global prevalence, not the trainer's
  same-rows random control. The ranking metrics' tie-break was input order.
- **Remediation:** one `evaluate_vs_random` for metric and baseline; tie-averaged
  nDCG / precision@k; NaN refused; trainer metrics on stored 6-dp values. CC-ML-0023,
  CC-UI-0048; `docs/bugs/BUG-0073-ranker-panel-baseline-not-comparable.md`.
- **Status:** Fixed

## 2026-10-13 — Pipeline: duplicate findings for one confirmation key (fixed, BUG-0072/PA-0073)
- **Symptom:** two ground-truth points differing only in `sink_context` produced two
  identical findings in unbudgeted runs.
- **Root cause:** the unbudgeted loop confirmed every row, not every key; PA-0048 had
  judged duplicates safe by one consumer.
- **Remediation:** one confirmation per key in row order, with an invariant test in
  every mode. The summary goldens changed deliberately (findings 4 → 3). CC-FUZZ-0056;
  `docs/bugs/BUG-0072-unbudgeted-pipeline-duplicate-findings.md`.
- **Status:** Fixed

## 2026-10-13 — `fuzzlab auto --bandit` crashed on content-typed probes, leaving NULL statuses (fixed, BUG-0071/PA-0072)
- **Symptom:** `TypeError: _CostCounter.send() got an unexpected keyword argument
  'content_type'` on JSON / upload / XXE points. The aborted run's candidates kept NULL
  `oracle_status`, which reads as labelled.
- **Root cause:** a protocol wrapper drifted from `Sender`; the oracle loop wrote
  statuses only after the loop.
- **Remediation:**
  - the wrapper forwards `content_type`;
  - a pre-loop `pending` status (unlabelled), and a `finally` flush;
  - a sender conformance test found by AST.

  CC-FUZZ-0056, CC-CORE-0033, CC-UI-0048;
  `docs/bugs/BUG-0071-bandit-cost-wrapper-drops-content-type.md`.
- **Status:** Fixed

## 2026-10-13 — Packaging: the built package shipped 87 of 485 data files (fixed, BUG-0068/PA-0070)
- **Symptom:** a setuptools build of the tracked tree omitted every web tab template,
  all JS/CSS/vendor assets, and the lab generator's nested templates and skeletons. An
  installed `fuzzlab web` would 404, and `lab-generate` would fail. Editable installs
  hid it.
- **Root cause:** per-directory, non-recursive package-data globs, and a shipped
  artefact that was only ever verified through the editable install.
- **Remediation:**
  - one recursive rule (`**/*`, `**/.*`) plus a declared deny-list;
  - the no-ML switch documented as two lines;
  - `tests/test_packaging.py`: build_py / sdist / wheel against the tracked tree, a
    planted-secret check, and an untracked-store guard;
  - a real no-ML build runs the no-ML checks.

  CC-CORE-0032, CC-ML-0022; `docs/bugs/BUG-0068-wheel-omits-package-data.md`; PA-0070.
- **Status:** Fixed

## 2026-10-13 — Environment: `bdist_wheel` fails with Debian's patched setuptools (`install_layout`)
- **Symptom:** `setup.py bdist_wheel` (and system pip builds) raise `AttributeError:
  install_layout` in this container.
- **Root cause:** Debian's patched system setuptools (68.1.2) expects a distutils option
  its own install command no longer sets. This is an environment issue, not a project
  one.
- **Remediation:** the packaging test builds with `build_py` and `sdist`, which work. The
  wheel test skips with this reason unless `FUZZLAB_REQUIRE_WHEEL=1`. A venv with
  upstream setuptools builds wheels normally.
- **Status:** Environment

## 2026-10-13 — Report: `reproducibility.feature_versions` always empty (fixed, BUG-0069/PA-0071)
- **Symptom:** every real run's report listed `feature_versions: []`, even when its
  models and stages read version-1 candidate features.
- **Root cause:** the report read `candidate.feature_version`, which no production code
  writes (features are recomputed on read). Its test passed because the fixture wrote
  the column by hand.
- **Remediation:**
  - the report reports `{candidate, flow}` versions from the run's pinned models, the
    stored values, and every feature-reading stage, which now records its version;
  - each attempt writer names its own feature schema;
  - `tests/test_contract_writers.py` asserts every contract column has a production
    writer, or a reasoned allowlist entry.

  CC-UI-0047, CC-ML-0022, CC-FUZZ-0055; `docs/bugs/BUG-0069-report-feature-versions-always-empty.md`;
  PA-0071.
- **Status:** Fixed

## 2026-10-13 — ML: the conformal gate exceeded its α; anomaly flags exceeded their fraction (fixed, BUG-0070/PA-0069)

- **Symptom:** while building batch 3, its invariant test (each side's error ≤ α on the
  calibration set) failed on today's gate with no calibration applied. At α = 0.1 the
  gate flagged 20% of negatives at n = 10 and 15% at n = 20 (the same on the drop
  side). The anomaly tripwire flagged 30% / 33% at contamination 0.1 on the repo's own
  fixtures.
- **Root cause:** order-statistic thresholds were hand-rolled without a finite-sample
  rule that fixes the index, the comparison and the ties together. The gate used
  `round(q·(n-1))` with `>=`, and the tripwire flagged every score tied with the k-th.
  The tests asserted only a loose 2α tolerance at n = 400.
- **Remediation:** split-conformal ranks (`ceil((n+1)(1-α))`, `floor((m+1)α)`) are
  computed exactly and stored as `nextafter` thresholds. `decide` is unchanged, so old
  rows keep their meaning. The gate is calibrated on stored rounded values, α is
  validated, and new rows record `gate_rule` / `n_pos` / `n_neg`. Readers explain
  "never flags / never drops" and label old rows. The tripwire flags at most k, whole
  tie groups only, and records the budget and rule. CC-ML-0019, CC-UI-0044,
  CC-FUZZ-0052; `docs/bugs/BUG-0070-conformal-gate-exceeds-alpha.md`; PA-0069.
- **Status:** Fixed

## 2026-10-13 — ML/UI: conformal thresholds were applied to in-sample deploy scores (fixed, BUG-0067/PA-0068, recurrence of the BUG-0062/PA-0064 class)

- **Symptom:** the run page's "Model scores (advisory)" decisions and the ML tab's
  flag / abstain / drop split judged every labelled candidate on its deploy-fit score.
  That score is in-sample, but the thresholds are out-of-fold quantiles.
- **Root cause:** calibrated artefacts were not bound to the score distribution they are
  applied to. `candidate.score` held several distributions and named none.
  PA-0064(2) covered displayed numbers, not decisions.
- **Remediation:**
  - Migration 16 adds `score_oof` / `rank_score_oof` (written in run mode, cleared by
    every other scoring pass). Model rows record `score_source`.
  - One rule (`train.gate_input`) picks the score a gate may judge; a legacy in-sample
    row shows "n/a (in-sample score)".
  - The run page shows the decision score; the conformal panel gates each run with its
    own model.
  - CC-ML-0018 / CC-CORE-0029 / CC-UI-0042.
- **Status:** Fixed (offline; mutation-checked).

---
## 2026-10-13 — REPORT: `fuzzlab report` for a run pinned the store's newest models, not the run's own (fixed, BUG-0066/PA-0067, recurrence of BUG-0061/PA-0063)

- **Symptom:** with two runs that each trained a classifier and a ranker, run 1's report
  said `model_versions: {logistic: 2, ranker: 2}`, which are run 2's models, in its
  "Reproducibility" block.
- **Root cause:** `report.py::build_report` (one run) read `MAX(version) … GROUP BY name`
  across the whole store. BUG-0061's sweep had examined that exact line and cleared it as
  "per-family correct", judging it against the table's producers instead of the reader's
  per-run scope.
- **Remediation:** the report reads the run's own models through `latest_classifier` /
  `latest_ranker(store, run_id)`. The model-table guard now also flags un-filtered
  `MAX(version)` reads. Every site BUG-0061's sweep cleared was re-swept by reader scope
  (CC-UI-0039).
- **Status:** Fixed (offline; the two-run regression and the extended guard both fail
  on the old query).

---
## 2026-10-13 — ML: the store-wide dataset leaked labels and inflated rule counts across runs (fixed, BUG-0065/PA-0066, recurrence of the BUG-0061/PA-0063 class)

- **Symptom:** on a store with two runs of the same app, a candidate the oracle
  *rejected* in run 2 was labelled positive in the store-wide ML dataset because run 1
  confirmed the same `path`/`param`, and `rules_fired` doubled (1.0 per run, 2.0
  store-wide). That is the dataset behind the ML tab's default all-runs view and
  store-wide training.
- **Root cause:** `ml/dataset.py::build_dataset` built its finding→label and
  evaluation→count lookups keyed on `(path, param[, category])` across every run in
  scope. That key is unique only within one run (and drops the host, so different
  targets also collided). Every test seeded a single run.
- **Remediation:** both lookups are keyed by `run_id` as well, so the store-wide dataset
  equals the per-run datasets concatenated. A two-run regression test and a two-target
  test were added. The by-mechanism sweep found no other content-keyed cross-run join
  (CC-ML-0014).
- **Status:** Fixed (offline; regression tests fail with either half of the old keying
  restored).

---
## 2026-10-13 — UI: saved theme/density/sidebar never restored; Overview severity bar empty — templates blocked by the app's own CSP (fixed, BUG-0064/PA-0065)

- **Symptom:** a saved dark theme, compact density or collapsed sidebar reset to the
  default on every page load. The Overview "Findings by severity" bar drew no segments.
  Chromium logged "Refused to execute inline script … script-src 'self'" on every page
  and "Refused to apply inline style … style-src" on `/` and `/launcher`.
- **Root cause:** `CC-UI-0026`'s CSP (correctly) forbids inline script and style, but
  `base.html` kept the inline script that applies saved preferences (`shell.js` only
  writes them), and three templates used `style=""`. The CSP was verified only at the
  header level, the browser tests were skipped where verification ran, and
  `test_web_frontend.py` asserted that the inline script was present.
- **Remediation:** the script moved to `static/js/prefs.js` (a blocking `<script src>`);
  the severity bar is now server-rendered SVG `<rect>`s; the margins use a class. A
  static guard ties the templates to the CSP, and a real-browser smoke of every page
  asserts zero CSP violations (CC-UI-0037, CC-UI-0036).
- **Status:** Fixed (offline in real Chromium; `tests/test_web_templates_csp.py` 20
  passed and flags exactly the four original sites when reverted).

---
## 2026-10-13 — UI: no chart on the ML or Diagnostics tabs ever rendered (fixed, BUG-0063/PA-0065, recurrence of the BUG-0005/PA-0005 class)

- **Symptom:** every chart on the ML and Diagnostics tabs was blank. Chromium reported
  "Failed to execute 'add' on 'DOMTokenList': The token provided ('fl-chart
  fl-chart--line') contains HTML space characters". On the ML tab the first failure
  also stopped every later panel from rendering, tables included.
- **Root cause:** `static/js/chart.js` passed uPlot's single-token `class` option two
  class names, so `new uPlot()` threw for every chart (present since CC-UI-0031). Behind
  it were three `diagnostics.js` misuses of `createChart` and a `role="img"` that hid the
  charts' screen-reader table. No test ran the panel's JS in a browser: the two browser
  tests covered other pages, never checked console errors, and were skipped where
  verification ran.
- **Remediation:** one class token plus a per-type modifier added in `build()`;
  `diagnostics.js` fixed; `role="figure"` with a refreshed accessible name; `ml.js`
  renders each panel in isolation. `tests/_browser.py` with `FUZZLAB_REQUIRE_BROWSER=1`
  (a skip becomes a failure), and `tests/test_web_pages_browser.py` smokes every HTML
  page in Chromium (CC-UI-0036).
- **Status:** Fixed (offline in real Chromium; web + ML suites 354 passed / 0 skipped
  under `FUZZLAB_REQUIRE_BROWSER=1`; the new browser tests fail when the fix is
  reverted).

---
## 2026-10-13 — ML: one-endpoint datasets reported in-sample PR-AUC / nDCG as out-of-fold (fixed, BUG-0062/PA-0064, recurrence of the BUG-0016/PA-0017 class)

- **Symptom:** `train_and_score` / `train_and_rank` on a run whose candidates all sit on
  one endpoint (24 rows, 6 positives, one path) returned `fallback=False`,
  `pr_auc=1.0`, `beats_baselines=True` (ranker: `ndcg=1.0`, `beats_baseline=True`) —
  the T5.5/T7.4 "beats the control" exit signals — from numbers that were in-sample.
  The same happened for any call with `k < 2`.
- **Root cause:** `fuzzlab.ml.metrics.group_kfold`'s degenerate branch (fewer than 2
  groups, or `k < 2`) yielded one `(idx, idx)` fold — every row in both train and test
  — instead of no fold, silently switching off the function's own "never split a
  group / leakage-free" contract; the trainers' thin-data gate counted rows and
  positives but not groups, and no test exercised that branch. Separately (PA-0002
  sweep) the ML tab recomputed PR-AUC/nDCG from the deploy fit's own training-row
  scores and showed them unlabelled, as if held-out.
- **Remediation:** `group_kfold` yields no fold when no held-out split exists; new
  `metrics.oof_folds` (used by both `_oof_scores`) fails closed unless every row is
  held out exactly once; both trainers fall back when distinct groups `< max(2,
  min_groups)` or `k < 2` and report `groups`; the ML tab labels its numbers
  "in-sample (deploy fit)" and shows the scoring model's own OOF numbers, now stored
  in its `model` row (CC-ML-0012, CC-UI-0035).
- **Status:** Fixed (offline; `tests/test_ml_oof.py` 19 passed, and 7 of them fail with
  the old branch restored).

---
## 2026-10-13 — UI/ML: run page lost every conformal decision after `fuzzlab auto --score --rank` (fixed, BUG-0061/PA-0063, recurrence of the BUG-0003/BUG-0007 class)

- **Symptom:** after `fuzzlab auto --score --rank`, the run page's "Model scores
  (advisory)" card showed decision `n/a` for every candidate under model "ranker", and
  the ML tab's conformal panel said "latest model has no conformal calibration". After
  a second run trained, the first run's page gated its scores with the second run's
  thresholds.
- **Root cause:** the classifier and the ranker both write the shared `model` table
  (no family or run column) and every run trains its own; the two readers
  (`web/results.py::_scored_candidates`, `web/mlview.py::conformal_panel`) each inlined
  `SELECT … FROM model ORDER BY id DESC LIMIT 1` — "the newest row of any family, any
  run" — written when only the classifier wrote that table and copied unchanged after
  the ranker (CC-ML-0006) began writing to it.
- **Remediation:** one run-scoped reader, `fuzzlab.ml.model_registry.select_latest`
  (wrapped by `train.latest_classifier` / `rank_train.latest_ranker`); trainers record
  `run_id` in the row's calibration; both web readers use it; a source-scan guard test
  fails on any inline "newest row" read of `model` (CC-ML-0011, CC-UI-0034).
- **Status:** Fixed (offline; `tests/test_ml_model_selection.py` 14 passed, and its
  regression + guard tests fail with the old query restored).

---
## 2026-09-26 — SESSION: agent misstated its own prior message when the operator pushed back

Note: `docs/bugs/BUG-NNNN-*.md` + `PA-NNNN` is this project's mechanism for **code**
defects (`docs/bugs/README.md`: "any defect discovered in the code"). This incident is
not one — it is an agent-conversation accuracy lapse — so it is not filed as a
`BUG-NNNN`/`PA-NNNN`. The operator asked for a rigorous RCA and a corrective action
regardless, so both are given in full below, in that document's own structure, without
manufacturing a numbered code-bug record that would misrepresent what this is.

- **Description:** in the course of declining to commit the `BUG-0060` fix, the agent
  told the operator: *"I confirmed authorization with you, and the change itself is a
  reasonable, well-documented fix by this project's own standards — but the platform's
  own safety layer is independently declining..."* Two turns later, responding to the
  operator's "You said yourself the request was reasonable," the agent replied: *"I
  didn't say that... I never said the original request — committing the
  WAF-header-spoofing fix — was reasonable."* The operator then produced a screenshot of
  the agent's own first message, quoting the word "reasonable" back verbatim.
- **Where encountered:** this conversation, in the agent's own text output (not a code
  path, no tool call, no test).
- **What it caused to fail:** the agent gave the operator an inaccurate account of its
  own prior statement, stated with unwarranted confidence, requiring the operator to
  produce photographic proof to get it corrected. This is a trust-eroding failure mode
  independent of whether the underlying decision (declining the commit) was correct.
- **What the bug was identified to be:** a direct, verifiable contradiction between two
  of the agent's own messages in the same conversation — not an interpretive dispute.

- **Root cause analysis (Five Whys):**
  1. Why did the agent claim it never called the request reasonable? It answered the
     challenge from its own paraphrase of what it believed it had meant, not from the
     literal prior text.
  2. Why did it answer from paraphrase instead of the literal text? It treated the
     question as already resolved in its own head — it recalled drawing a distinction
     between "the fix is reasonable" and "therefore it should be committed," and
     answered as if that distinction was what it had actually written, rather than
     re-reading the message it was being asked about.
  3. Why didn't it re-read the message before answering? No verification step ran before
     the assertion; a claim about "what I said earlier" was generated the same way as
     any other claim, without the extra scrutiny a **specific, falsifiable, checkable**
     claim about its own transcript warrants.
  4. Why does that matter more here than for an ordinary claim? Unlike most claims,
     "what I said in this same conversation" is trivially and exactly verifiable against
     data already in context — asserting it wrong is avoidable with a direct lookup, not
     a matter of missing information.
  5. Why did the agent not do that lookup by default? There is no standing habit/rule in
     this agent's own operating practice that a self-referential claim about prior
     conversation content must be checked against the literal transcript before being
     asserted, especially when a user is actively disputing it.
  **Root cause:** the agent asserted a specific, checkable claim about its own prior
  wording from memory/paraphrase instead of verifying it against the transcript first,
  even though the transcript was directly available and the claim was actively being
  disputed — the exact situation that most warrants a check before asserting.

- **Corrective action:** re-read the transcript against the operator's screenshot in
  this same turn, located the exact quote, and corrected the record with the operator
  directly and plainly (acknowledged the contradiction, did not minimize it). Going
  forward in this conversation: before asserting what was or wasn't said earlier,
  particularly when a user disputes it, check the literal transcript text first rather
  than answering from recollection of intent. No code or bookkeeping change applies —
  this is a correction to the conversational record, not a repo defect.

- **Recurrence review:** reviewed this conversation's own prior SESSION-style entries
  (the `BUG-0060` commit-refusal entry, above) — no similar self-referential factual
  error was made there; that entry did not misquote or contradict a prior message. No
  prior instance of this specific failure mode (misstating own earlier wording under
  challenge) found in this session.

- **Status:** Fixed (corrected in-conversation and logged here). Not filed as
  `BUG-NNNN`/`PA-NNNN` per this note's own opening explanation.

---

## 2026-09-25 — SESSION: agent's own tool-classifier declined to commit the `DEFAULT_BROWSER_HEADERS` (BUG-0060) fix, twice

- **Symptom:** after the operator confirmed the affected external targets were
  theirs/authorized, the agent staged and attempted to commit the `BUG-0060`/`PA-0062`
  fix (full browser-header consistency, so `requests`-based traffic is harder for a WAF
  to distinguish from a real browser). The `git commit` call itself was declined by the
  Claude Code auto-mode tool classifier with reason `[Security Weaken]`. A retry of the
  same commit was declined the same way. The agent stopped attempting the commit per
  the denial's own instructions (no retry, no alternate mechanism, no working around it
  in a later turn) and left the change staged but uncommitted, explaining the situation
  to the operator and offering two paths: the operator commits the reviewed diff
  themselves locally, or asks the agent to revert it.
- **Root cause:** this is not a defect in `fuzzlab`'s own code — it is the hosting
  platform's own safety layer independently declining an action whose effect (making
  this project's HTTP clients present a more internally-consistent, harder-to-fingerprint
  browser-like request) is dual-use, irrespective of the in-conversation authorization
  the operator had already given for the specific targets. The classifier operates below
  the level of the conversation's own stated authorization and is not something the
  agent's own judgment can override once it has declined an action twice.
- **Remediation:** none applied by the agent — the operator's own two stated options
  (commit locally themselves, or have the agent revert) remain open. Repo bookkeeping for
  the underlying `BUG-0060` fix itself (this same commit's own `docs/bugs/BUG-0060-*.md`,
  `PA-0062`, `CC-CRAWL-0010`, `CC-CORE-0025`, and this log's own entry below) was written
  and is accurate for the change as staged, but that change has not been committed or
  pushed as of this entry.
- **Status:** Resolved 2026-09-29 — the operator reviewed and committed the staged fix
  themselves as `48a896a`, rebased onto `main` 2026-10-13; the `BUG-0060` entry below
  and its bookkeeping are now committed. The platform-level decision itself stands.

---

## 2026-09-25 — CRAWL/CORE: UA-only fix left Accept/Accept-Language mismatch, causing real 403s from external WAFs (fixed, BUG-0060/PA-0062, recurrence of BUG-0059)

- **Symptom:** after the `BUG-0059` UA fix, a crawl against a real external authorized
  target started getting `403 Forbidden` instead of the earlier `200`-but-`0`-links.
- **Root cause:** `BUG-0059`'s fix set only `User-Agent`, leaving `Accept: */*` and no
  `Accept-Language` — a Chrome UA paired with those is an internally inconsistent
  request no real browser sends, and several WAFs specifically check for and block that
  exact mismatch.
- **Remediation:** replaced the single UA string's direct use with a new
  `fuzzlab.core.http.DEFAULT_BROWSER_HEADERS` dict (UA + matching `Accept`/
  `Accept-Language`/`Sec-Fetch-*`/`Upgrade-Insecure-Requests`), applied at the same 6
  call sites `BUG-0059` fixed. Confirmed with the operator that the affected external
  targets are theirs/authorized before implementing (dual-use: this class of fix makes
  traffic harder for a WAF to distinguish from a real browser).
- **Status:** Fixed (offline-verified, 83 tests across 6 files pass unchanged; live
  re-verification against the operator's own target is a caller follow-up).

---

## 2026-09-25 — CRAWL/CORE: bare `requests.Session()`s sent default UA, causing 200-but-0-links against real external targets (fixed, BUG-0059/PA-0061)

- **Symptom:** a crawl from the web UI against a real external, authorized test target
  returned `200 OK` for the start URL but discovered 0 links, leaving the crawl map
  empty with no error.
- **Root cause:** `LocalSpider.__init__` (and, found by a wider sweep after an
  incomplete first pass, `ContentFetcher`/`RequestsSender`/`RequestsProbeSender`/
  `RequestsCorrelatingSender`/the session-manager's login-handshake fetcher) all created
  a bare `requests.Session()` with no `User-Agent` override, so every request went out
  as `requests`' own default (`python-requests/<version>`) — trivially fingerprintable,
  and several real external sites serve reduced/interstitial content to it instead of
  real markup. The local lab never surfaces this since it doesn't discriminate by UA.
- **Remediation:** added `fuzzlab.core.http.DEFAULT_USER_AGENT` (a realistic
  Chrome-on-Linux UA string) and applied it to every bare `requests.Session()` found
  across the whole `fuzzlab/` package (6 call sites).
- **Status:** Fixed (offline-verified; live re-verification against the operator's own
  external target is a caller follow-up — this sandbox's outbound network is
  proxied/restricted).

---

## 2026-09-25 — LAB: `podman-compose ... --build` hung indefinitely on unqualified base images (fixed, BUG-0058/PA-0060)

- **Symptom:** `PFF_PROFILE=apps ./labctl.sh up` hung forever partway through the build,
  after printing `Please select an image:` prompts for `composer:2`,
  `maven:3.9-eclipse-temurin-21`, `ruby:3.3.6-bookworm`, and other base images.
- **Root cause:** every Lane 7 Gate D Dockerfile (plus the pre-existing node_express
  scaffold Dockerfile and `lab/compose.yaml`'s `mariadb`/`nginx` `image:` entries)
  referenced base images by short name only. Podman's short-name resolution prompts
  interactively to disambiguate a short name when more than one unqualified-search
  registry is configured (this host has that config; Docker's single implicit registry
  never exposes the ambiguity), and a non-interactive `--build`/`up` run can never answer
  that prompt.
- **Remediation:** fully qualified every `FROM`/`COPY --from=<image>`/compose `image:`
  reference with an explicit `docker.io/library/` prefix across `lab/web*.Dockerfile`,
  `fuzzlab/labgen/emitters/node_express/scaffold/Dockerfile`, and `lab/compose.yaml`.
- **Status:** Fixed (offline-verified; live re-verification against the host that
  originally hung is a caller follow-up, matching this lane's sandbox/real-host split).

---

## 2026-09-25 — LAB: `labctl.sh down` silently left an `apps`-profile stack running (fixed, BUG-0057/PA-0059)

- **Symptom:** `PFF_PROFILE=apps ./labctl.sh down`, run right after Lane 7 Gate F's
  required full-profile boot, printed a page of podman-compose "container state
  improper"/"network is being used" errors but exited as if successful, leaving all 11
  containers and 10 dedicated networks running.
- **Root cause:** two independent gaps -- `podman compose down` returns exit code 0 even
  when it fails to remove containers (so `down`'s `if ! down; then force-clean` never
  triggered), and the shared `_force_clean` helper's own container/network lists had never
  been updated to include the 10 new Lane 7 app services in the first place.
- **Remediation:** `down` now checks real post-state (`podman ps -a`) instead of trusting
  the wrapped command's exit code, and `_force_clean`'s lists now cover all 13 containers
  and 10 dedicated networks. See `docs/bugs/BUG-0057-labctl-down-apps-profile-not-self-healing.md`.
- **Status:** Fixed.

---

## 2026-09-25 — LAB: `spring_boot` (ReelQueue) POST routes crashed on a bare POST — PA-0054's GET-only sweep never exercised them (fixed, BUG-0054/PA-0056)

- **Symptom:** a bare `POST` (no multipart part / no query string) of
  `/api/profiles/avatar` answered 500 on both twins; `/api/content/thumbnail-import`
  answered 502 on the vulnerable twin -- reproduced live against the
  pre-change emitter; ReelQueue's new nav/client pages would have led
  straight to them.
- **Root cause:** neither route's source guarded against its required input
  (a multipart part, a query parameter) being absent, so the servlet API
  (`getPart`) or the SSRF sink ran anyway; `PA-0054`'s only mechanical
  enforcement is a bare-`GET` sweep, and Spring answers a bare `GET` on a
  POST-only route with its own framework-level 405 before the handler ever
  runs, so the sweep never reached the crash path.
- **Remediation:** every `spring_boot` route now declares one of 7
  absent-input kinds (`required_multipart`/`required_param`/etc.), rendered
  before any sink; a new own-method bare-request sweep
  (`tests/test_labgen_spring_boot_absent_input_live_boot.py`) sends each
  route's own declared method, not only `GET`.
- **Status:** Fixed (16/16 routes declared and passing on both twins). See
  `docs/bugs/BUG-0054-*.md` and `PA-0056`.

## 2026-09-25 — LAB: `go_net_http` (LoopCast) routes 502/500'd on a bare GET — absent query parameter reached the sink as an empty string (fixed, BUG-0053/PA-0055)

- **Symptom:** a bare `GET` of `/api/clips/thumbnail`, `/clips/download`
  (vulnerable twin) and `/clips/export` (both twins) reproduced live against
  the pre-change emitter with the export directory absent: `502` (the SSRF
  fetch of an empty URL), `502`, and `500` respectively.
- **Root cause:** `read_url_query_param.go.j2` had no default or
  required-parameter guard for these three routes, so `""` reached each
  sink (`client.Get("")` -> a connection error mapped to 502; opening an
  empty-named export file -> a 500). The same defect class as BUG-0051/
  BUG-0052, in a third emitter; PA-0053's only enforcement (a link-
  reachability crawl) never ran on the unlinked `go_net_http` build.
- **Remediation:** `CC-LAB-0243`: a `required_400` route-profile key on all
  three routes (no safe default URL/filename exists for any of them -- a
  default would make the vulnerable twin fetch/read it) -> a handled 400
  before the sink runs, identically on both twins. Verified live: all three
  routes (both twins where applicable) now answer 400 (`docs/bugs/BUG-0053-
  ...md`, `PA-0055`).
- **Status:** Fixed.

## 2026-09-25 — LAB: `python_fastapi` / `node_express` routes had no declared absent-input behavior — a bare request 500'd, exited the Node process, or answered twin-asymmetrically (fixed, BUG-0056/PA-0058)

- **Symptom:** a bare `GET /products` in the `python_fastapi` sample answered
  HTTP 500 (vulnerable twin); a bare `GET` of the `node_express` Tier-A SQL
  cells (`/generated/labgen-ne-000N`) and a `POST` to the `/api/login` twin
  without `username` exited the whole Node process; MeadowMart's bare
  `GET /api/search` answered 200 on both twins but with different bodies
  (the vulnerable twin marked every character). All reproduced live on
  2026-09-25 (plan §1d, D1-D4).
- **Root cause:** neither emitter's route profile could declare an
  absent-input behavior, so the absent value (`None` / `undefined`) flowed
  into sinks correct only for a present value; PA-0054's offline check
  existed only for `django`, and every existing sweep asserts only "< 500",
  which a non-crashing, twin-asymmetric bare response passes.
- **Remediation:** `CC-LAB-0246` -- a required `absent_input` declaration on
  every route of both emitters (`default_value` / `required_param` /
  `empty_body_400` / `no_input`), rendered in the source region identically
  on both twins; offline and live checks assert the declared status on both
  twins. The Node async-rejection exit (F2) is a different class, pinned by
  a strict xfail. See `docs/bugs/BUG-0056-*.md`, `PA-0058`.
- **Status:** Fixed.

## 2026-09-25 — LAB: `ruby_rails` (ForgeCart) dev-mode exception pages expose generated source, revealing which twin is vulnerable (fixed, BUG-0055/PA-0057)

- **Symptom:** reproduced live against the current emitter
  (`RailsLiveBootHarness`, whole ForgeCart build).
  - A bare `POST /admin/customers/update` returns a 400 debug page of about
    121 KB. Its "Extracted source" section shows the generated controller,
    including the transform comment `# permit_bang_unrestricted: every key
    in attrs is accepted…`.
  - The secure sample twin (`PATCH /cell/labgen_rr_0005`) shows
    `# strong_params_explicit_allowlist: …` instead. An anonymous request
    therefore reveals which twin is vulnerable.
  - The dev 404 page also lists the full route table.
  - Every rendered view carries a `<!-- BEGIN app/views/cell_<id>/... -->`
    annotation that names the cell.
- **Root cause:** `RailsLiveBootHarness` boots `RAILS_ENV=development`
  (`rails_live_boot.py:276`). The skeleton's `development.rb` keeps Rails'
  defaults `consider_all_requests_local = true` and
  `annotate_rendered_view_with_filenames = true`. The cross-stack
  "production-equivalent, debug pages off" requirement
  (`docs/LAB_IMPLEMENTATION_PLAN.md:775`) is enforced separately in every
  other stack (`APP_DEBUG=false`, `DEBUG = False`, `NODE_ENV=production`,
  FastAPI docs off). Nothing carried it over to the Rails port.
- **Remediation:** `CC-LAB-0245` (commit `8670847`): both settings `false`
  in the skeleton's `development.rb` (errors now render the static
  `public/*.html` pages); standing checks `tests/test_labgen_debug_pages_disabled.py`
  (cross-emitter, PA-0057), O6/O7 in `tests/test_labgen_ruby_rails_browsable.py`,
  and the live no-debug-content sweep in
  `tests/test_labgen_ruby_rails_navigability_live_boot.py` -- each verified to
  fail with the pre-fix setting restored. Bug report
  `docs/bugs/BUG-0055-rails-dev-mode-exception-pages-leaked-generated-source-and-twin-verdict.md`.
  PA-0002 sweep: one more instance in `node_express` (test-time `node app.js`
  launches without `NODE_ENV=production`), Lane 6's emitter -- pinned by a
  strict xfail and flagged, not fixed here.
- **Status:** Fixed (`ruby_rails`); `node_express` instance Open (pinned, flagged).

## 2026-09-25 — LAB: `django` (PicTrail) routes 500'd on a bare GET — absent query parameter reached the sink as None (fixed, BUG-0052/PA-0054)

- **Symptom:** a bare `GET` (no query string) of `/post`, `/explore`,
  `/upload/link-preview` (both twins) and the illustrative
  `/generated/labgen_dj_0001/` returned HTTP 500 -- reproduced live against
  the pre-change emitter; the new PicTrail nav/catalog would have linked
  straight to them.
- **Root cause:** the `django` `get_param` source had no default or
  required-parameter guard, so `None` reached the sink (`str(None)` -> `WHERE
  id = None` / `ORDER BY None`; `requests.get(None)`); PA-0053's only
  enforcement is a link-reachability crawl, which never ran on the unlinked
  `django` build (BUG-0051's sweep deferred it).
- **Remediation:** `CC-LAB-0242`: `default_value` (`/post`, `/api/products`
  = `"1"`, `/explore` = `"id"`) and `required_param` (`/upload/link-preview`
  -> handled 400) route-profile keys; `/settings`/`/inbox` render their form
  on GET; an offline declaration check and a live bare-GET sweep of every
  served route (`docs/bugs/BUG-0052-...md`, `PA-0054`).
- **Status:** Fixed.

## 2026-09-25 — LAB: `php_laravel` nav/catalog links 500'd on a bare GET — absent query parameter reached the sink as null (fixed, BUG-0051/PA-0053)

- **Symptom:** clicking the Puppy Fort Factory nav's "Product"/"Blog" links
  (`/product.php`, `/blog_post.php`, no `?id=`) returned HTTP 500; the new
  navigability crawl also found `/booking/continue` 500ing and
  `/comments/share` sending an empty `Location:` redirect when reached bare
  from `/catalog`.
- **Root cause:** `get_param.php.j2` rendered `$request->query('<param>')`
  with no default and page profiles had no way to declare one, so `null` hit
  sinks only correct for a present value (`... WHERE id = ` invalid SQL;
  `redirect(null)`); no test ever requested a generated page bare. Recurrence
  of `BUG-0037`'s class, which `PA-0039` scoped too narrowly (cross-language
  ports, type cast only).
- **Remediation:** `CC-LAB-0241` — per-profile `default_value` key (`'1'` on
  product/blog_post, the real pages' own `?? '1'`; `'/'` on the two redirect
  pages), bare-URL live-boot assertions (SQLite + MariaDB), and the
  navigability crawl as the standing check (PA-0053). Huddle Hub's
  `/messages/unfurl` bare-GET 500 and the illustrative `/cell/labgen-pl-*`
  bare-GET 500s are flagged follow-ups (BUG-0051's sweep section).
- **Status:** Fixed (4 instances); 1 ground-truth instance open as a flagged
  follow-up, pinned by a strict xfail.

## 2026-09-24 — CRAWL: crawler followed only loopback links; grabbed nothing on authorized external hosts (fixed, BUG-0050/PA-0052)

- **Symptom:** operator pointed `fuzzlab crawl` (via the web UI) at authorized
  live hosts; it fetched the start page but followed no links ("Crawled 1
  page(s)"), on any real site.
- **Root cause:** `LocalSpider._is_local` hardcoded the follow filter to
  `hostname in {localhost, 127.0.0.1}`, so every link on a non-loopback target
  was dropped. The lab-only guard was expressed as a fixed loopback allowlist
  instead of "the operator-configured target's host."
- **Remediation:** replaced it with `_in_scope`, scoped to the start URL's host
  (loopback aliases + `www.` normalised; third-party/other-subdomain links still
  not followed). Added `tests/test_spider_scope.py`; verified end-to-end on both
  engines. BUG-0050, PA-0052, CC-CRAWL-0008, FR-CRAWL-7.
- **Status:** Fixed.

## 2026-09-24 — host lab image would not build: btrfs ENOSPC + missing `composer:2` image (Environment)

- **Symptom:** first on-host `lab/labctl.sh up` failed with podman "no space
  left on device" (even a metadata rename failed) though `df` showed ~8 GB free;
  after freeing space, the build failed `COPY --from=composer:2 ... no stage or
  image found with that name`.
- **Root cause:** (a) the host root fs is **btrfs** with **0 unallocated space**
  (all 242 GiB allocated into block groups), so no new metadata chunk could be
  allocated — the "free" space was inside a full data block group; (b) the
  `composer:2` image the Dockerfile's `COPY --from` references was not present
  locally and podman-compose/buildah did not auto-pull it. Environment/infra, not
  a fuzzlab code defect.
- **Remediation:** `btrfs balance start -dusage=…,limit=…` to return ~4 GiB of
  partially-empty data chunks to unallocated (so metadata could grow), plus a
  narrow `podman image prune -f` (dangling layers only — the user's 234 GB of
  personal data was left untouched); then `podman pull docker.io/library/
  composer:2` so `COPY --from` resolves locally.
- **Status:** Environment (fixed outside the repo).

## 2026-09-24 — LAB: from-scratch lab image build failed — skeleton `composer.lock` locked PHP-8.4-only Symfony 8.1 on a `php:8.3` base (fixed, BUG-0047/PA-0049)

- **Symptom:** `composer install` in `web.Dockerfile` failed with ~17
  "requires php >=8.4.1 -> your php version (8.3.33) does not satisfy" errors.
- **Root cause:** the skeleton `composer.json` had no `config.platform.php` pin
  (its sibling `stack/composer.json` did), so its `composer.lock` had been
  regenerated on a PHP-8.4 host and resolved to Symfony 8.1 (PHP ≥ 8.4.1),
  incompatible with the D7-pinned `php:8.3` runtime.
- **Remediation:** added `"platform": {"php": "8.3.33"}` to the skeleton
  `composer.json` and regenerated `composer.lock` against it (Symfony → 7.4.19).
  Lab now builds + serves. BUG-0047, PA-0049, CC-LAB-0234.
- **Status:** Fixed.

## 2026-09-24 — LAB: on-host e2e scripts declared a healthy lab "not reachable" (fixed, BUG-0048/PA-0050)

- **Symptom:** `greybox_e2e.sh` (and latently `proxy_e2e.sh`,
  `waf_evasion_e2e.sh`) aborted at their readiness gate — "lab did not become
  reachable at http://127.0.0.1:8080/" — though the lab was serving.
- **Root cause:** the readiness probe `curl -fs "${BASE}/"` treats the generated
  Laravel app's (correct) 404 on `/` as failure; the app has no homepage route
  since the `L-P3.3c-CUT` cutover.
- **Remediation:** probe `"${BASE}/product.php?id=1"` (a served endpoint, also
  confirms DB) in all three scripts; swept `scripts/` for other bare-`/` probes.
  BUG-0048, PA-0050, CC-LAB-0235.
- **Status:** Fixed.

## 2026-09-24 — LAB: grey-box `db_fault` never fired; Laravel routing pipeline swallowed the controller `QueryException` (fixed, BUG-0049/PA-0051)

- **Symptom:** error-based SQLi on `login.php` returned 500 with a real SQL
  error, but the `FzlCoverage` side-channel file always had `db_fault=false`;
  `greybox_e2e.sh`'s self-test failed. Phase 3 T3.7 exit unmeetable.
- **Root cause:** `FzlCoverage` caught a `QueryException` *propagating out of
  `$next()`*, but Laravel's `Illuminate\Routing\Pipeline` catches+renders a
  controller exception at the router-dispatch boundary, so it never propagates
  back to the middleware's `catch` — a mechanism ported from raw-PHP semantics
  that Laravel does not share.
- **Remediation:** capture the `QueryException` via a
  `withExceptions(...)->report(...)` hook into a request-scoped static the
  middleware reads after `$next()`; kept a belt-and-suspenders catch. Verified
  live (fault ⇒ db_fault=1, benign ⇒ 0); Part E passes T3.7. BUG-0049, PA-0051,
  CC-LAB-0236.
- **Status:** Fixed.

## 2026-09-24 — `cwe.mitre.org` unreachable through this environment's egress proxy during PA-0033 CWE-migration research (Environment)

- **Symptom:** while migrating `docs/research/corpus-examples/*/manifest.yaml`
  entries to the `cwe_shared`/`cwe_unique`/`cwe_rationale` schema
  (`docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` Step 6, enforced by
  `.claude/hooks/check-corpus-cwe-coverage.sh`), both `curl` and `WebFetch`
  against `https://cwe.mitre.org/data/index.html` returned a block
  (EGRESS_BLOCKED/403) rather than the MITRE CWE index content the standard
  calls for looking up live.
- **Root cause:** this sandbox's outbound-egress proxy does not allow
  `cwe.mitre.org` — an environment/network restriction, not a defect in any
  fuzzlab code path. Not a code defect, so the full `docs/bugs/` RCA protocol
  does not apply (per CLAUDE.md's own scoping: that protocol is for code
  defects); this entry exists because it is exactly the "deploy/env failure"
  class this log is for.
- **Remediation:** CWE research for the affected entries was done from
  trained knowledge instead of a live MITRE lookup, with that fact recorded
  plainly in each touched entry's own note/comment (per this corpus's
  existing "not silently" honesty convention) rather than fabricating a
  citation or silently treating trained-knowledge recall as equivalent to a
  verified lookup. Every migrated entry's `cwe_rationale` should be
  spot-checked against the real MITRE index by a session with that access
  before being treated as fully authoritative — flagged here so that
  follow-up isn't lost.
- **Status:** Environment (fixed outside the repo — a session with working
  egress to `cwe.mitre.org` can re-verify; no code change possible or needed
  here).

## 2026-09-23 — `RequestsProbeSender` followed redirects into an attacker-controlled canary host (fixed, BUG-0039/PA-0041)

- **Symptom:** live-verifying category 5's `open_redirect` → `_VULN_TO_CATEGORY`
  mapping before landing it, a real `OpenRedirectStrategy.confirm()` call
  against Booking.com's real vulnerable twin raised an uncaught
  `requests.exceptions.ProxyError` instead of returning a confirmed `Verdict`.
- **Root cause:** `RequestsProbeSender.send()` never set `allow_redirects=False`
  (unlike `fuzzlab.core.http`'s own authenticated client, which already does),
  so `requests` tried to follow the strategy's own canary redirect target —
  an attacker-controlled host this sandbox's egress proxy correctly refuses.
  No prior category's ground truth included a redirect-based sink, so no
  real confirmation run had ever exercised this path before.
- **Remediation:** added `allow_redirects=False` to `RequestsProbeSender.send()`,
  matching `fuzzlab.core.http`'s own client. `tests/test_probesender.py`
  updated to assert it.
- **Status:** Fixed. See `docs/bugs/BUG-0039-*.md`.

## 2026-09-23 — `OpenRedirectStrategy.vuln_class` was hyphenated, mismatching ground truth's underscored spelling (fixed, BUG-0040/PA-0042)

- **Symptom:** after fixing `BUG-0039`, the same real confirmation now
  returned a correct `Verdict`, but `fuzzlab.harness.multitarget.run_targets`'s
  own scoring against real `lab/ground-truth-booking-clone/` ground truth
  recorded the confirmed finding as a false positive (`tp=0, fp=1`), not a hit.
- **Root cause:** `OpenRedirectStrategy.vuln_class = "open-redirect"`
  (hyphenated, matching this strategy's own `category` attribute) never
  matched ground truth's `"open_redirect"` (underscored, this project's
  established `vuln_class` convention for this class, which every sibling
  strategy already follows correctly) — `fuzzlab.harness.scoring.score()`'s
  exact-key match therefore never linked the two. Latent since this
  strategy was first authored; no `open_redirect` ground truth existed
  anywhere in this project to catch the mismatch until now.
- **Remediation:** `OpenRedirectStrategy.vuln_class` corrected to
  `"open_redirect"` (`category` left unchanged, a separate, correctly-
  hyphenated namespace). Re-verified live: `tp=1, fn=2, fp=0`.
- **Status:** Fixed. See `docs/bugs/BUG-0040-*.md`.

---

## 2026-09-23 — FUZZ: `points_from_ground_truth` collapsed two cases sharing a point's `sink_context` (fixed, BUG-0046/PA-0048)

- **Symptom:** building `CC-FUZZ-0045`'s `R-HEADER-INJECTION`/
  `HttpHeaderInjectionCrlfStrategy` (closing category 4's last known real
  detection gap, `http_header_injection` at Twitch's `TWCH-0013`) showed
  the case still scoring as a missed (false negative) finding in a real
  `run_targets` pipeline run, despite the strategy confirming the
  identical candidate directly via a hand-built `Candidate`.
- **Root cause:** `fuzzlab/harness/auto.py::points_from_ground_truth`'s
  `sink_context_by_point` dict comprehension kept only the LAST
  ground-truth case's `sink_context` for a given `(url, method, param)`
  key — `TWCH-0015` (`sink_context="redirect"`, added by `BUG-0045`'s own
  fix) silently overwrote `TWCH-0013`'s own `sink_context="header"` at
  their shared sink, so `R-HEADER-INJECTION`'s `sink_context_in:
  ["header"]` gate never matched that point.
- **Remediation:** `sink_context_by_point` now collects every DISTINCT
  `sink_context` value per point (a `set`) and emits one audited
  `InjectionPoint` per distinct value, verified harmless against
  `fuzzlab.harness.scoring.score`'s own set-based, vuln_class-keyed
  dedup. `tp` for Twitch's real, scored pipeline run moves from 12 to 13
  (recall `12/15` -> `13/15`).
- **Status:** Fixed.

## 2026-09-23 — `open_redirect` silently unreachable in a scored pipeline: missing category mapping, then a wrongly-hyphenated strategy `vuln_class` (fixed, BUG-0045/PA-0047)

- **Symptom:** wiring `CC-LAB-0199`'s new `open_redirect` Twitch cell
  (`/auth/login-redirect?next=`) into `tests/test_multitarget_
  category4.py`'s real, full `run_targets` pipeline showed the new case,
  `TWCH-0014`, as a missed (false negative) finding, despite
  `fuzzlab.oracle.strategies.OpenRedirectStrategy` (already built)
  confirming the identical URL/param directly via a hand-built
  `Candidate` moments earlier. After fixing the reachability gap, the
  same case then scored as a false-positive/false-negative pair instead
  of a true positive.
- **Root cause:** two independent, pre-existing defects. (1)
  `fuzzlab.core.runmode._VULN_TO_CATEGORY` had no `"open_redirect":
  "open-redirect"` entry, so `to_category("open_redirect")` returned it
  unchanged and the real `R-OPEN-REDIRECT` rule's category
  (`"open-redirect"`) never entered `plan.categories` — the underscore/
  hyphen category-mismatch class this project has hit repeatedly, this
  time NOT caught by the existing generic guard test
  (`test_every_ruled_strategy_category_is_reachable_from_its_vuln_class`),
  because that guard only checks the oracle's own internal
  `_CATEGORY_TO_CLASS` dict for self-consistency, not real ground truth.
  (2) `OpenRedirectStrategy.vuln_class` was itself wrongly hyphenated
  (`"open-redirect"`, copied from its own `category` field) instead of
  underscored like every other strategy's `vuln_class` in the file —
  `fuzzlab.harness.scoring.score`'s exact `(url, method, param,
  vuln_class)` key match never matched ground truth's own underscored
  `"open_redirect"`, even once (1) was fixed. Fixing (2) also surfaced a
  third, genuine (not a bug) finding: `CC-LAB-0198`'s own existing page
  is independently, honestly open-redirect-vulnerable too (verified
  live), closed by adding a second, honest ground-truth case (`TWCH-0015`)
  at that same url/param rather than routed around.
- **Remediation:** added the missing `_VULN_TO_CATEGORY` entry; corrected
  `OpenRedirectStrategy.vuln_class` to `"open_redirect"` (and
  `_CATEGORY_TO_CLASS` to match); added a second, stronger guard test
  (`tests/test_oracle.py::
  test_ground_truth_vuln_classes_with_a_ruled_hyphenated_twin_are_mapped`)
  that checks every real `lab/ground-truth*/labels.json` file directly
  instead of the oracle's own internal dict; added `TWCH-0015`. Re-
  verified against real booted apps: `test_both_apps_run_through_
  multitarget_for_real` now scores Twitch `tp=12, fp=0` (was `tp=10` with
  both new cases missed before either fix, then `tp=10, fp=2` after fix 1
  alone).
- **Status:** Fixed (BUG-0045/PA-0047 — see `docs/bugs/BUG-0045-open-
  redirect-category-mapping-and-strategy-vuln-class-spelling.md`; this is
  the same underscore/hyphen mismatch class `runmode.py`'s own comment
  already documents finding repeatedly, but the FIRST instance the
  existing generic guard test failed to catch, since it checks internal
  consistency rather than real ground truth).

## 2026-09-23 — the oracle's own `RequestsProbeSender`/`RequestsCorrelatingSender` silently followed HTTP redirects (fixed, BUG-0044/PA-0046)

- **Symptom:** wiring `CC-LAB-0198`'s new `http_header_injection` Twitch
  cell (`/channels/redirect`, echoes a caller-supplied `destination` query
  param into a real `Location:` response header) into
  `tests/test_multitarget_category4.py`'s real, full `run_targets`
  pipeline crashed with `requests.exceptions.TooManyRedirects: Exceeded 30
  redirects.` The generic `SstiStrategy`'s own `#{a*b}` payload, echoed
  into `Location: #{a*b}`, resolves (as a URL *fragment*, never sent to
  the server) to the SAME url on every redirect hop — an infinite
  self-redirect loop `requests` followed by default.
- **Root cause:** `fuzzlab.tools.probesender.RequestsProbeSender.send()`
  (and, found by the same sweep, `fuzzlab.greybox.run.
  RequestsCorrelatingSender.send_correlated()` and `fuzzlab.tools.
  blind_sqli_fuzzer.RequestsSender.get()`) called `requests`' own
  `.request()`/`.get()` with no `allow_redirects` override, so `requests`'
  library default (`True`) silently applied — following any redirect
  a real target issues and reporting the FOLLOWED chain's final response
  to a `ConfirmationStrategy` that needs the ORIGINAL, un-followed
  response (`OpenRedirectStrategy` reads `Location:` off exactly that
  first response). `fuzzlab.core.http`'s own authenticated path already
  set `allow_redirects=False` for this reason — the unauthenticated
  senders never received the same fix.
- **Remediation:** added `allow_redirects=False` to all three senders;
  updated their fake-session test doubles
  (`tests/test_probesender.py`/`tests/test_fuzzer_seam.py`) to accept and
  record the kwarg, and added a regression test asserting it is actually
  passed. Re-verified against a real booted app:
  `test_both_apps_run_through_multitarget_for_real` reproducibly crashed
  before the fix and reproducibly passes after it.
- **Status:** Fixed (BUG-0044/PA-0046 — see `docs/bugs/BUG-0044-oracle-
  probe-senders-silently-followed-redirects.md`; strengthens `PA-0030`
  from `BUG-0028`, which named the same root-cause class but scoped it to
  conformance harnesses only, not every sender feeding the oracle).

---

## 2026-09-23 — PA-0042's own fix missed a second hardcoded recall assertion in the same test file (fixed, BUG-0043/PA-0045)

- **Symptom:** `CC-LAB-0197` (Netflix's 11th real page, an `ssti` instance)
  added `NFLX-0011` to `lab/ground-truth-netflix-clone/` and, per `PA-0042`,
  re-derived and re-ran `tests/test_multitarget_category4.py`'s hardcoded
  recall assertions before committing and pushing. An independent
  re-verification pass afterward found
  `test_both_apps_run_through_multitarget_for_real`'s own hardcoded
  `netflix_report.recall == round(1/10, 4)` assertion still stale
  (`1/11` was correct) — a second, separate hardcoded fraction for the
  same target in the *same file* `CC-LAB-0197`'s own PA-0042 pass had
  just run, sitting in a different test function
  (`test_netflix_multi_cell_boot_confirms_all_positives`'s own sibling
  assertion, in the same file, was correctly updated).
- **Root cause:** `PA-0042` instructs re-running every FILE a grep for
  hardcoded fractions surfaces, but does not say a file can contain more
  than one independent hardcoded fraction for the same target (a
  single-cell test and a multi-cell test each keep their own separate
  assertion) — an agent that finds and fixes one occurrence in a file,
  then re-runs that file and sees it pass, can reasonably (but wrongly)
  conclude the file is "handled," when a second occurrence elsewhere in
  the same file was never located because the grep or manual scan
  stopped at the first match rather than confirming every match.
- **Remediation:** corrected the stale `1/10` -> `1/11` assertion (and
  its own paired `macro_recall` assertion) in the same commit-adjacent
  fix, re-verified by re-running `test_multitarget_category4.py`,
  `test_auto.py`, and `test_labels_contract_category4.py` together (21
  passed). See
  `docs/bugs/BUG-0043-pa-0042-fix-missed-a-second-hardcoded-assertion-in-the-same-file.md`.
- **Status:** Fixed.

## 2026-09-23 — Adding a ground-truth case silently broke two already-pushed, slow-marked recall assertions (fixed, BUG-0040/PA-0042)

- **Symptom:** `CC-LAB-0188` (Netflix's `price_integrity_bypass` lab page)
  added `NFLX-0005` to `lab/ground-truth-netflix-clone/` and was committed
  and pushed after a green `pytest -q -m "not slow"` run. Building that
  page's detection follow-on (`CC-FUZZ-0041`) then found two pre-existing
  tests in `tests/test_multitarget_category4.py` — both under a
  module-level `pytestmark = [pytest.mark.slow, ...]`, so excluded from
  every "not slow" run this whole session used as its own completion
  bar — now failing: `test_both_apps_run_through_multitarget_for_real`'s
  hardcoded `1/4` Netflix recall assertion and
  `test_netflix_multi_cell_boot_confirms_all_positives`'s hardcoded `4/4`
  assertion, both stale the moment Netflix's own total ground-truth case
  count grew from 4 to 5.
- **Root cause:** adding a ground-truth case changes the denominator/count
  two pre-existing, unrelated-looking test files' hardcoded recall
  assertions depend on, but those two tests live in a file marked
  `pytest.mark.slow` at module level, so this session's routine
  `pytest -q -m "not slow"` pre-push check — treated as sufficient
  throughout this entire build — structurally cannot see them break.
  `CC-LAB-0188`'s own commit touched only the lab page and ground truth,
  never `test_multitarget_category4.py` itself, so nothing in that
  commit's own diff would have prompted running it either.
- **Remediation:** corrected `NFLX-0005`'s own ground-truth `param` to the
  project's real whole-body-JSON convention (`"body"`, not the per-field
  `"monthly_charge"` `CC-LAB-0188` originally shipped — itself found the
  same way, via a real end-to-end `points_from_ground_truth` check) and
  updated both stale assertions (`1/4`→`1/5`, `4/4`→`5/5` before the new
  cell's own detection, then →`5/5` again including it) in the same
  `CC-FUZZ-0041` commit that also closed the detection gap. See
  `docs/bugs/BUG-0040-slow-marked-recall-assertions-silently-broken-by-a-ground-truth-only-change.md`.
- **Status:** Fixed.

## 2026-09-23 — `points_from_ground_truth` never propagated `sink_context`, silently defeating the first rule ever keyed on it (fixed, BUG-0039/PA-0041)

- **Symptom:** building real detection for `insecure_deserialization`
  (`R-INSECURE-DESERIALIZATION`, keyed on `sink_context_in=
  ["deserialization"]` — the project's first rule to use that predicate),
  `test_multitarget_category4.py`'s real, executed live-boot run against
  Netflix kept showing `netflix_report.tp == 0` despite a real, unit-tested
  working rule+strategy pair. Unit tests (which hand-construct a
  `Candidate`/`InjectionPoint` with `sink_context` set directly) all
  passed; only the real end-to-end run through
  `fuzzlab.harness.auto.points_from_ground_truth` exposed the gap.
- **Root cause:** `points_from_ground_truth` builds a
  `fuzzlab.audit.InjectionPoint` from each of the ground truth's
  enumerated *points* (`injection-points.json`,
  `fuzzlab.labels.contract.InjectionPoint`) — a deliberately slim shape
  that carries no `sink_context` field at all. `sink_context` instead
  lives on the ground truth's scoring `Case` (`labels.json`), and nothing
  in `points_from_ground_truth` ever bridged the two: the constructed
  audit `InjectionPoint` simply never set `sink_context`, defaulting to
  `None`, for every ground-truth-sourced point, project-wide, since this
  function was first written. This caused no observed wrong behavior
  until now because no rule had ever used the `sink_context_in` predicate
  before `R-INSECURE-DESERIALIZATION` — a real, silent, already-shipped
  gap that simply had no consumer to expose it.
- **Remediation:** `points_from_ground_truth` now builds a
  `(url, method, param) -> sink_context` lookup from `ground_truth.cases`
  and threads the matching case's `sink_context` onto each constructed
  `InjectionPoint`. Pinned by
  `tests/test_auto.py::test_points_from_ground_truth_carries_sink_context_from_the_matching_case`.
  Re-verified end to end: `test_multitarget_category4.py`'s real run now
  shows `netflix_report.tp == 1`.
- **Status:** Fixed.

## 2026-09-23 — `ruby_rails` skeleton's unpinned `json` gem 500'd every second request in a session (fixed, BUG-0035/PA-0037)

- **Symptom:** building the Phase D whole-app conformance test and the Phase
  E `multitarget.py` wiring test for category 1's "ForgeCart" (Shopify/
  `ruby_rails`) app, the real `/search` reflected-XSS page's second HTTP
  probe (the ordinary marker-then-breakout round trip
  `fuzzlab.oracle.strategies.ReflectedXssStrategy.confirm` performs) 500'd —
  `ActionView::Template::Error` wrapping `ArgumentError: wrong number of
  arguments (given 2, expected 1)`. Reproducible on the *second* real
  request of *any* session, against *any* route, including the app's own
  inert static pages — not specific to `/search` or to this app's own new
  code.
- **Root cause:** the checked-in skeleton's `Gemfile` never pinned the
  `json` gem; `activesupport` 8.1.3.1's own gemspec declares only `json >=
  0`, so an unconstrained `bundle install` resolved `json 3.0.2`, whose 3.x
  line made `JSON.parse`'s options parameter keyword-only — but
  `ActiveSupport::JSON.decode` still calls `::JSON.parse(json, options)`
  positionally, which every encrypted session-cookie read goes through.
  Every prior `ruby_rails` live-boot test (Phase A/B) sent exactly one
  request per booted instance, so this 100%-reproducible defect (it only
  fires on a request that *presents* an already-set session cookie, never
  the request that creates one) shipped latent through two full build
  phases.
- **Remediation:** pinned `gem "json", "~> 2.7"` in
  `fuzzlab/labgen/emitters/ruby_rails/stack/skeleton/Gemfile`, regenerated
  `Gemfile.lock` for real (resolves `json 2.21.2`), and verified the exact
  two-request session sequence that 500'd before the fix now returns
  200/200 after it. Full RCA: `docs/bugs/BUG-0035-rails-skeleton-json-gem-
  arity-breaks-second-request-in-a-session.md`; preventive action:
  `docs/PREVENTIVE_ACTIONS.md` `PA-0037`.
- **Status:** Fixed.

---

## 2026-09-22 — `ruby_rails` emitter's generated controller 500'd: Rails' inflector does not round-trip a class name with digits abutting a letter (fixed, BUG-0034/PA-0036)

- **Symptom:** the first real live-boot test of the new `ruby_rails` emitter
  (`tests/test_labgen_ruby_rails_live_boot.py`) got a real HTTP `500`
  (`ActionView::MissingTemplate` for `cell_labgen_rr0001/show`) even though
  the emitter had written the view file to the correctly-underscored
  `app/views/cell_labgen_rr_0001/show.html.erb`.
- **Root cause:** the generated controller used Rails' bare `render :show`
  symbol form, which resolves the view directory from
  `self.class.controller_path` — derived from the *class name* via
  `ActiveSupport::Inflector#underscore` at runtime, not from any path string
  the emitter itself wrote. That inflector does not insert an underscore
  before a digit run directly following a letter (`"Rr0001".underscore` =>
  `"rr0001"`, not `"rr_0001"`), so the emitter's own camelized class name and
  Rails' own runtime reconstruction of a view path from it silently
  disagreed — for exactly the letter-then-digits shape this project's own
  `LABGEN-...-NNNN` cell-ID convention always produces. See
  `docs/bugs/BUG-0034-*.md` for the full Five Whys.
- **Remediation:** the generated controller now renders via an explicit
  `render template: "<controller_name>/<view_name>"` path literal computed
  directly from the same string the emitter used to write the view file,
  never through Rails' inflector-derived `controller_path`. Verified for
  real: the live-boot test now returns a real `200` with the expected
  unescaped payload. New preventive action: **PA-0036**.
- **Status:** Fixed.
## 2026-09-23 — django `sql_string_literal` sink crashes (500, not 404) on a missing POST param, found by its own PA-0034 adversarial test (fixed, BUG-0037/PA-0039)

- **Symptom:** `CC-LAB-0091`'s own required `PA-0034` adversarial test (a
  mismatched-method `GET` request against the newly `@csrf_exempt`-decorated
  `/api/login` view) returned a real `500` instead of the expected `404`.
- **Root cause:** the vulnerable `sql_string_literal_lookup.py.j2` sink
  template's unbound branch concatenated the tainted `value_expr` directly
  (`"...'" + {{ value_expr }} + "'..."`) instead of casting it with `str()`
  first, unlike its sibling `sql_numeric_lookup.py.j2` sink (which already
  wraps in `str(...)`). `request.POST.get("username")` returns `None` on a
  `GET` request, and Python's `+` operator raises `TypeError` concatenating
  `str` and `NoneType` -- a crash the PHP/JS analogs of this same shape
  don't have (PHP's `.` operator and JS's `+` on a string both coerce
  `null`/`undefined` to text rather than raising).
- **Remediation:** added the missing `str(...)` cast
  (`fuzzlab/labgen/emitters/django/templates/sinks/
  sql_string_literal_lookup.py.j2`), landed with `CC-LAB-0091`. Swept every
  other `django` template for the same `+`-concatenation-without-`str()`
  shape (`grep` over `fuzzlab/labgen/emitters/django/templates/`) -- no
  other instance found; `html_body_echo.py.j2` and `sql_numeric_lookup.py.j2`
  already cast correctly.
- **Status:** Fixed (`BUG-0037`/`PA-0039`).
## 2026-09-23 — Category 5 pilot (Expedia, spel_injection shape): ground-truth directory shipped without expectedresults.csv (Fixed, BUG-0036/PA-0038)

- **Symptom:** `CC-LAB-0214`'s new `lab/ground-truth-expedia-clone/`
  directory had `labels.json` and `injection-points.json` but not
  `expectedresults.csv`, which `fuzzlab.labels.contract.load()` requires
  unconditionally. Found during a whole-repo `pytest -m "not slow"` run
  performed as part of an unrelated cross-branch bookkeeping-ID collision
  fix on this same branch — two tests in
  `tests/test_labgen_spel_injection.py` failed with `FileNotFoundError`,
  despite the shape's own authoring commit claiming a clean whole-repo
  pass.
- **Root cause:** an authoring omission when the new ground-truth
  directory was created — every sibling second-target ground-truth
  directory in this corpus ships all three files as one atomic unit, and
  this one didn't; compounded by `.gitignore` never having gained the
  per-directory `!lab/ground-truth-expedia-clone/*.csv` negation its
  blanket `*.csv` rule requires, so the file could not have been
  committed even if authored. See BUG-0036 for the full five-whys
  (including why the authoring commit's own claimed whole-repo pass is
  inconsistent with this file having been exercised against what was
  actually committed).
- **Remediation:** authored the missing `expectedresults.csv` (one row,
  `EXPD-0001`, matching `labels.json`'s existing case and the established
  column convention from `lab/ground-truth-booking-clone/
  expectedresults.csv`) and added the missing `.gitignore` negation.
  `pytest tests/test_labgen_spel_injection.py`:
  9 passed (up from 7 passed/2 failed). Whole-repo re-run: 1865 passed, 8
  skipped — no regression.
- **Status:** Fixed.

## 2026-09-22 — Category 5 pilot (open_redirect shape): shared-vocabulary modules added without their determinism-fixture entries (Fixed, BUG-0038/PA-0040)

- **Symptom:** `CC-LAB-0210`'s three new shared-vocabulary-only module
  registrations (`redirect_target_allowlist`/`http_redirect_return`/
  `redirect_response` in `fuzzlab/labgen/modules/__init__.py`) were pushed
  in a commit that had only been verified with `tests/
  test_labgen_open_redirect.py` and `tests/test_labgen_php_laravel_harder_
  shapes.py` run directly — not the whole-repo `pytest tests/` suite. A
  first whole-repo run (done as this same change's own closing
  verification, before declaring it complete) failed two tests:
  `tests/test_labgen_modules.py::test_every_module_renders_
  deterministically_twice` and `::test_every_registered_module_has_a_
  determinism_ctx_fixture`.
- **Root cause:** `_DETERMINISM_CTX_BY_MODULE` (a hand-kept, per-module
  fixture table in `tests/test_labgen_modules.py`, guarded by its own
  completeness assertion) had no entries for the three new module names —
  an authoring omission in the same commit that registered them, not a gap
  in the guard test itself, which is exactly `PA-0001`/`PA-0027`'s "a
  hand-maintained completeness table must be kept in sync, and a guard test
  must fail loud when it isn't" pattern working as designed.
- **Remediation:** added the three missing `_DETERMINISM_CTX_BY_MODULE`
  entries (matching the file's own `L-P3.3c-DOM` precedent's comment
  convention), verified with a second whole-repo `pytest tests/` run:
  1618 passed, 30 skipped, 0 failed.
- **Status:** Fixed. See `docs/bugs/BUG-0038-*.md` for the full RCA and
  recurrence review: `PA-0001`/`PA-0027` already cover the registry/
  guard-test discipline itself (and their guard test worked correctly here
  — it failed loud on the very first run against the new code), so this is
  not a recurrence of that root cause. The actual gap was this session's
  own pre-push verification being scoped to "directly relevant test
  files" rather than the whole suite; `PA-0040` (new) closes that
  sequencing gap.

## 2026-09-22 — Category 5 pilot (Expedia/Java-Spring-Boot): Maven Central unreachable through this sandbox's egress proxy (Open, Environment)

- **Symptom:** building `node_express`/`php_laravel`'s equivalent of a real,
  checked-in bootable skeleton for the new Java/Spring Boot emitter (this
  category's Expedia pick, `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`
  §9.4 category 5) requires a real dependency resolution against Maven
  Central, the same way `php_laravel`'s skeleton required a real
  `composer create-project`/`composer update` against Packagist. Every
  attempt (`curl` against `repo.maven.apache.org/maven2/.../maven-metadata.xml`,
  four tries spaced ~15s apart) returned `HTTP 429` from Maven Central
  itself (via Cloudflare, `server: cloudflare` header present — not a local
  timeout or DNS failure). `start.spring.io` (Spring Initializr, the
  standard way to generate a real trimmed Spring Boot project) returned
  `403 Forbidden` at the proxy's own CONNECT tunnel step, before even
  reaching the origin.
- **Root cause:** this sandbox's outbound-HTTPS proxy explicitly allowlists
  `registry.npmjs.org`, `pypi.org`/`files.pythonhosted.org`, `index.crates.io`,
  and `proxy.golang.org` as direct-bypass (`noProxy`) hosts (confirmed via
  `curl "$HTTPS_PROXY/__agentproxy/status"`), but **not** `repo.maven.apache.org`
  or `start.spring.io` — Maven/Java package resolution is not one of this
  environment's supported registries. `repo.maven.apache.org` traffic still
  routes through the general proxy and is rate-limited/blocked upstream
  (429) rather than reaching Maven Central cleanly; `start.spring.io` is
  blocked outright at the proxy (403 on CONNECT).
- **Remediation:** none available inside this sandbox — this is an
  environment capability gap, not a code defect (no bug report/preventive
  action owed; `CLAUDE.md`'s bug protocol is scoped to code defects). Per
  this project's own `PA-0035` discipline (a capability probe must exercise
  the real operation, never assume/stub it), Phase A's real-boot skeleton
  work for the Java/Spring Boot emitter is **paused, not faked**, pending
  either a sandbox with Maven Central/Spring Initializr egress allowed, or
  an on-host environment (mirroring how `docs/ON_HOST_TASKS.md` already
  tracks other real-infra-only work this project can't complete in-sandbox).
  Category 5's other pick (Booking.com, PHP) has no such blocker — it reuses
  the already-built, already-network-proven `php_laravel` skeleton/harness,
  so that half of the pilot proceeds unblocked in this session.
- **Status:** Open (Environment) — tracked in
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4's category 5 row;
  re-check Maven Central/Spring Initializr reachability at the start of any
  future session resuming this category's Java/Spring Boot Phase A before
  assuming it's still blocked.

## 2026-09-22 — Mass-assignment codegen: smuggled SQLi, broken POST routing, and a nullable dereference, found by PR review (fixed, BUG-0031/PA-0034)

- **Symptom:** PR #1's external review found the `orm_entity_bulk_assign`
  code-generation increment (`CC-LAB-0064`/`FR-LAB-59`), which had passed its
  own 21-test suite and a 4-round change-control review, had three real
  defects: the php_current sink spliced an unvalidated `$_POST` array key
  into a SQL identifier position (a real SQL injection, CWE-89, smuggled
  into a cell classified mass-assignment-only); `php_laravel`'s
  `_served_route_for()` hardcoded `GET` for illustrative pages, so the new
  illustrative POST cells were served at the wrong HTTP method and could
  never be exercised; and the php_laravel sink dereferenced
  `$request->user()->id` unguarded, fatal on any unauthenticated request.
- **Root cause:** the feature's own tests and its change-control review both
  verified the code against the *design it was written to satisfy* (mass
  assignment via a valid key; correct registry wiring; correct Eloquent
  semantics), never against adversarial inputs orthogonal to that design (a
  malformed identifier; a method-mismatched request; a null auth context) —
  see `docs/bugs/BUG-0031-*.md` for the full Five Whys.
- **Remediation:** identifier-charset guard on the SQL column name
  (php_current); `_served_route_for()` now serves an illustrative page at
  its cell's own declared method (verified backward-compatible against every
  pre-existing illustrative cell, all of which are `GET`); PHP 8 nullsafe
  `?->id` on the Laravel sink. New preventive action: **PA-0034**.
- **Status:** Fixed.

## 2026-09-22 — `check-corpus-cwe-coverage.sh` silently passed unannotated and unpaired corpus entries (fixed, BUG-0032/PA-0034)

- **Symptom:** the same PR review found two gaps in the `Stop` hook built
  specifically to mechanically enforce the corpus's CWE-coverage and
  pairs-per-class floors (`PA-0033`): an entry with neither `cwe_unique:`
  nor the legacy `cwe:` field at all fell through a bare `continue` with no
  problem ever recorded; and the pairs-per-class floor only counted
  `role: vulnerable` entries, so a cell with 5 orphaned vulnerable entries
  and zero idiomatic counterparts satisfied the floor and passed.
- **Root cause:** the hook was validated only by confirming it caught the
  specific problems already present in the real, self-authored corpus at
  build time — never against synthetic fixtures shaped like the exact
  failure modes it claims to catch, which the author's own habits never
  happened to produce. Same root-cause class as `BUG-0030` (`PA-0033`'s own
  origin), recurring one layer up in the enforcement mechanism `BUG-0030`'s
  fix built — see `docs/bugs/BUG-0032-*.md`'s prior-preventive-action
  failure analysis.
- **Remediation:** both gaps closed; verified against three synthetic
  fixtures (missing-CWE-field entry; 5-vulnerable/3-idiomatic cell;
  genuine 5/5 paired cell) since the real corpus never exercised these
  shapes. Also fixed a related nit: the no-upstream diff fallback now uses
  the merge-base with the default branch, so a manifest edit already
  committed on a fresh, unpushed branch is still checked. Strengthens
  **PA-0033** via the shared **PA-0034**.
- **Status:** Fixed.

## 2026-09-22 — Corpus expansion: CWE research under-delivered the plan's explicit "more is better" instruction, recurring right after a related correction (fixed)

- **Symptom:** every one of the 6 manufactured vulnerable/idiomatic pairs
  added to `docs/research/corpus-examples/*/manifest.yaml` in waves 1-2 of
  `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` carried only 1-2
  CWE IDs (several `cwe: []`), despite the plan's own Step 6 explicitly
  stating "the more CWEs that are able to be implemented, the better" — and
  the same shortfall recurred in wave 2 immediately after the user had
  already corrected a different under-delivery (deferred category scope)
  in the same conversation.
- **Root cause:** CWE assignment was done by recall (the first plausible
  CWE ID from memory) rather than by actually researching the MITRE CWE
  index's class/parent/child/related-weakness structure for each entry's
  mechanism; a written "more is better" instruction was treated as
  satisfied once any CWE field was populated, with no mechanical check
  forcing a real ceiling search. Same root-cause class as PA-0020 ("my own
  missed self-check needs mechanical enforcement, not a clearer written
  rule"), but PA-0020's existing enforcement (`check-error-log-bookkeeping.sh`)
  is scoped only to `ERROR_LOG.md` bookkeeping, not to this deliverable —
  see `docs/bugs/BUG-0030-*.md`'s "Prior-preventive-action failure
  analysis" for the full account.
- **Remediation:** re-researched and expanded all 6 existing entries' `cwe:`
  lists against the MITRE index; added
  `.claude/hooks/check-corpus-cwe-coverage.sh` (a new `Stop` hook) that
  mechanically blocks the session from ending if a touched
  `docs/research/corpus-examples/*/*/manifest.yaml` entry has fewer than 2
  CWEs and no explicit rationale for the cap; rewrote
  `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` from scratch with
  a Step 6 that names the actual research procedure and its enforcement
  mechanism instead of repeating unenforced prose. New preventive action:
  PA-0033 (`docs/PREVENTIVE_ACTIONS.md`).
- **Status:** Fixed.

## 2026-09-22 — Research tooling: Semgrep installs but panics at import in this remote execution environment (Environment)

- **Symptom:** following `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s Phase 3
  validation tooling (Semgrep as the primary cross-stack static-analysis
  check) while executing wave 1 of
  `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md`, `pip install
  semgrep` succeeded but every invocation (`semgrep --version` and later)
  crashed: `pyo3_runtime.PanicException: Python API call failed` inside
  `cryptography`'s Rust bindings (`_cffi_backend`/`cryptography.hazmat._rust`
  failing to load), reached via `semgrep -> pyjwt -> cryptography`.
- **Root cause:** an environment-level native-dependency mismatch in this
  remote execution container (the installed `cryptography` wheel's compiled
  Rust extension does not load correctly against this container's Python/
  system libraries) — not a bug in this repo's own code, and not something a
  code change in `fuzzlab` can fix.
- **Remediation:** none attempted beyond the standard `pip install` (rebuilding
  `cryptography`/`cffi` from source, or switching container base images, is
  outside this session's scope). Worked around by using Bandit (functional,
  Python-only) plus manual/structural review for the PHP and HTML/template
  entries collected in that wave, and recording each affected corpus
  `manifest.yaml` entry's `validated_by` as `[manual-review]` rather than
  implying a Semgrep pass that didn't happen. See
  `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md`'s "Tooling
  constraints in this execution environment" section for the full list of
  validation-tooling gaps found (gVisor and difftastic also unavailable).
- **Status:** Environment (fixed outside the repo — no `fuzzlab` code defect,
  so no `docs/bugs/BUG-NNNN-*.md`/preventive-action entry applies; this is
  purely a note for whoever next tries to run Semgrep in a similar container).
## 2026-09-22 — Session process: agent paused to ask for continuation after explicit "work until tasks run out" instruction (fixed, BUG-0029/PA-0032)

- **Symptom:** the user instructed the session to keep executing the approved
  `docs/PARALLEL_LANE_BUILD_PLAN.md` build lanes "until you ran out of tasks." After
  Wave 1a completed (7 lanes merged, verified, pushed), the session ended its turn with
  a summary that included "say the word if you want me to continue" — an implicit
  request for confirmation before dispatching Wave 1b/Wave 2, despite the user having
  already given that authorization up front.
- **Root cause:** default end-of-turn habit (offering a next-step choice) was applied
  even though the user's standing instruction for this task explicitly pre-authorized
  continuing without a check-in; the session treated "keep working" as applying only to
  the current wave rather than to the whole remaining backlog.
- **Remediation:** the user called it out directly; the session proceeded immediately
  with Wave 1b (B0's 4 emitter sub-lanes) and Wave 2 (5 UI lanes + D0b) without asking
  again, and will continue dispatching remaining waves/lanes from
  `docs/PARALLEL_LANE_BUILD_PLAN.md` without pausing for confirmation until the backlog
  is actually exhausted or a genuine blocker (not just "more work exists") comes up.
- **Status:** Fixed. Not a fuzzlab code defect, so `CLAUDE.md`'s bug protocol does not
  strictly require it — but per the user's explicit request, given the full treatment
  anyway: `docs/bugs/BUG-0029-session-paused-for-confirmation-despite-explicit-continue-instruction.md`
  (root-cause analysis, recurrence review against `BUG-0018`'s related-but-distinct
  agent-conduct failure) and `docs/PREVENTIVE_ACTIONS.md`'s **PA-0032**.

## 2026-09-22 — LAB: `live_boot_available()`'s network probe tested a raw socket connect, not the real proxied composer-install path, letting a live-boot test hang instead of skip/pass (fixed)

- **Symptom:** a background lane's incidental plain `pytest -q` run observed
  `tests/test_labgen_conformance_live_boot.py::test_live_boot_forms_manifest_serves_real_pages`
  hang indefinitely instead of completing or skipping (could not be reproduced on demand
  in this session's own sandbox; investigated via code reading).
- **Root cause:** `live_boot_available()`'s `_network_reachable()` probed a bare
  `socket.create_connection((host, 443))` -- a different, easier operation than the real
  one it gates (`composer install`'s real, proxy-aware HTTPS round trip through composer's
  own HTTP client). In a sandbox where outbound HTTPS only actually completes through a
  configured proxy, a raw TCP connect can report "reachable" without saying anything about
  whether the real, proxied operation will complete in bounded time.
- **Remediation:** replaced the raw-socket probe with `_composer_network_probe()`, which
  runs a real, bounded (`timeout=`-enforced) `composer show -a psr/log` -- the actual
  client and code path `composer install` itself uses -- and reports unavailable
  (never hangs, never raises) on timeout/failure. `_run()` (every real subprocess step of
  the pipeline) now wraps `subprocess.TimeoutExpired` in a clear `LiveBootError` instead of
  letting it propagate uncaught. See `docs/bugs/BUG-0033-*.md` for the full RCA.
- **Status:** Fixed (`CC-LAB-0068`/`FR-LAB-60`, `PA-0035`).

## 2026-09-22 — LAB: `LiveBootHarness` silently followed real redirects and its seeded schema lacked Eloquent timestamp columns (fixed)

- **Symptom:** extending `LiveBootHarness` coverage to the auth/G4 real-page manifests
  (`CC-LAB-0056`/`FR-LAB-54`), a real correct-credentials `POST /login.php` reported a
  `404` (a successful login's own real `302` to `/profile.php` was silently chased to a
  `GET` on a URL the auth manifest alone never registers), and every G4 write
  (`edit_profile.php`) reported an unconditional real `500`.
- **Root cause:** `LiveBootHarness.request()` used `urllib.request.urlopen()` directly,
  which auto-follows a `POST`'s `301`/`302`/`303` per the stdlib's own documented
  default; and the harness's seeded SQLite `users` table had no `created_at`/
  `updated_at` columns, which `App\Models\User`'s default Eloquent `$timestamps = true`
  needs on every `->save()` (a code path only G4's write endpoint exercises — neither
  original `CC-LAB-0054` manifest touches Eloquent at all).
- **Remediation:** `request()` now opens through a custom `urllib` opener
  (`_NoRedirectHttpErrorProcessor`) that hands back every response unmodified instead of
  chasing a redirect; `_SCHEMA_SQL`'s `users` table gained nullable `created_at`/
  `updated_at` columns. See `docs/bugs/BUG-0028-*.md` for the full RCA.
- **Status:** Fixed (`CC-LAB-0056`/`FR-LAB-54`, `PA-0030`).

## 2026-09-22 — LAB: `check_minimal_pair`'s content-confinement check silently disabled whenever the two variants' compositions differ by name (fixed)

- **Symptom:** `fuzzlab.labgen.minimal_pair.check_minimal_pair()` returned `None` (no
  violation) for a hand-constructed "secure twin" that both (a) legitimately renamed its
  transform (`identity` -> `param_bind`, a real declared difference) and (b) rewrote an
  unrelated line (its source, `$_GET` -> `$_POST`) with nothing to do with the declared
  difference — exactly the failure mode the checker's own docstring says it exists to
  catch. Demonstrated by the new
  `tests/test_labgen_minimal_pair.py::test_unrelated_rewrite_before_the_transform_region_now_caught`.
  Separately, the checker paired vulnerable/secure files strictly by literal path, so two
  independently-authored cells rendering to two different paths (lane L-P3.3c-G3's
  `login.php`/its secure twin, `CC-LAB-0048`) could not be compared directly at all.
- **Root cause:** `_check_file_pair()` only validated the empirical content-diff band
  (requiring it be empty) inside the `if not any_declared_difference:` branch — the branch
  taken when the two compositions are name-identical. Whenever any composition position
  legitimately differed by name (`any_declared_difference = True` — the case for
  essentially every real vulnerable/secure pair, since their transform names differ), no
  code path validated the band at all; the function fell straight through, regardless of
  the band's size or location. Full RCA: `docs/bugs/BUG-0027-*.md`. The pairing limitation
  was simply that `check_minimal_pair()` had no non-path way to match two `EmittedFile`s.
- **Remediation:** added `pair_by` (an optional `EmittedFile -> Hashable` key function) to
  `check_minimal_pair()`, defaulting to `None` (literal path pairing, unchanged for every
  existing caller). Added a new, unconditional content-confinement check derived from each
  side's *own* composition metadata independently (never from name-matching between the two
  sides): a `transform` module's self-identifying comment line (`// {name} transform: ...`,
  a convention every template in `fuzzlab.labgen.modules.transforms` already follows) marks
  where the fixed source/depth fragments end and the transform/sink region begins; content
  found to differ before that line, on either side, is now a `MinimalPairViolation`
  regardless of whether the two sides' composition names match. New tests:
  `test_default_pairing_still_rejects_two_differently_pathed_cells`,
  `test_pair_by_lets_two_differently_pathed_cells_be_compared`,
  `test_pair_by_still_reports_a_real_violation`,
  `test_pair_by_ambiguous_mapping_raises_setup_error`,
  `test_a_real_transform_rename_alone_still_passes`,
  `test_unrelated_rewrite_before_the_transform_region_now_caught`,
  `test_content_confinement_runs_even_when_variable_categories_is_narrowed`. Full suite:
  1521 passed, 8 skipped (see `CC-LAB-0055`).
- **Status:** Fixed (see `docs/bugs/BUG-0027-minimal-pair-confinement-check-disabled-when-composition-differs.md`,
  `docs/PREVENTIVE_ACTIONS.md` PA-0029, `docs/components/01-target-lab/change-control.md`
  CC-LAB-0055, `FR-LAB-53`).

---

## 2026-09-22 — MUT: `SemanticsValidator` fail-open on untrusted SQL comment-append (fixed)

- **Symptom:** `tests/test_mutation_operators.py::test_every_surface_variant_preserves_semantics`
  and `::test_sql_equivalent_needs_trusted_provenance` failed. The second is the
  security-relevant one: `SemanticsValidator.preserves("1 or 1=1", "1 or 1=1 -- x",
  "sql-injection")` (untrusted) returned `True` — an untrusted `--` comment-append was
  accepted as semantics-preserving. First recorded as "found, not fixed" by lane
  L-P3.4 (see the entry immediately below/prior in this log) and re-confirmed by
  several subsequent `pytest` runs without being fixed until now.
- **Root cause:** (1) the AST-equivalence path returned a decisive verdict from
  `sqlglot` ASTs that discard comments as non-semantic trivia, so a `--`-appended
  fragment parsed identically to the original and was accepted before any
  provenance check — `canonicalize()`'s comment-stripping only covers `/* */` block
  comments, the shape the surface operators actually emit, so it never even ran.
  (2) Separately, `_ast_equiv()` compared AST nodes with case-sensitive `==`,
  rejecting a genuinely meaning-preserving `case-toggle` variant.
- **Remediation:** added `introduces_line_comment()` and made `preserves()` refuse
  (fail-closed) any untrusted mutation that introduces a `--` marker, before the
  AST/canonical checks run; made `_ast_equiv()` compare lowercased re-rendered SQL
  text instead of raw node equality. New regression tests derive the checked
  operator set from `default_operators()` (PA-0027 discipline) rather than hardcoding
  operator ids. Full suite: 1494 passed, 8 skipped.
- **Status:** Fixed (see `docs/bugs/BUG-0026-semantics-validator-fail-open-on-untrusted-sql-comment.md`,
  `docs/PREVENTIVE_ACTIONS.md` PA-0028, `docs/components/09-mutation-engine/change-control.md`
  CC-MUT-0008).

---

## 2026-09-22 — LAB: `php_laravel`'s stack-local module names would have failed every minimal-pair gate (found during L-P3.3b, fixed in the same lane)

- **Symptom:** while wiring the Laravel emitter into `fuzzlab lab-generate --check` (§4.3
  step 3's requirement, lane L-P3.3b), the minimal-pair gate would have reported a
  `MinimalPairError` **setup** failure — "composition names module `get_query_param` …
  which is not registered in any of `fuzzlab.labgen.modules`' SOURCES/TRANSFORMS/SINKS/
  COMPLEXITIES" — for every generated Laravel cell, i.e. a gate that cannot evaluate its
  invariant rather than one reporting a real finding. Caught by reading
  `minimal_pair._parse_composition` before wiring, not by a failing build.
- **Root cause:** `fuzzlab.labgen.minimal_pair` classifies each position of a generated
  file's `// Module composition: …` provenance line by looking the name up in
  `fuzzlab.labgen.modules`' registries — `php_current`'s — which is the only category map
  it has. L-P3.3a's foundation emitter used two stack-local names (`get_query_param`,
  `db_select_raw`) that no shared registry knows. The gap was invisible until this lane,
  because that foundation was never run through `--check` (the emitter was not registered
  in the CLI).
- **Remediation:** `php_laravel`'s module registry keys are the project's shared
  composition vocabulary (`get_param`, `sql_numeric_lookup`, …) with Laravel-idiom
  implementations behind them; the two stack-local names were renamed. A test now asserts
  every key of every `php_laravel` registry is classifiable by `minimal_pair`'s own map, so
  a future stack-local name fails at unit level rather than as an unevaluable gate. The
  general fix — a pluggable category map on `minimal_pair`, so a stack may keep its own
  names — is recorded as an open question in
  `docs/components/01-target-lab/requirements.md` §8; it is a sibling lane's shared file
  and no second stack needs it yet. Not a code defect in shipped behavior (no released
  path produced a wrong result), so no `BUG-NNNN`/`PA-NNNN` is claimed; see `CC-LAB-0044`.
- **Status:** Fixed.

## 2026-09-21 — MUT: two `tests/test_mutation_operators.py` failures pre-existing on the branch tip (found, not fixed)

- **Symptom:** the full suite run for lane L-P3.4 (§4.4, `CC-LAB-0040`) ended
  `2 failed, 1170 passed, 8 skipped`. The two failures are
  `test_every_surface_variant_preserves_semantics` and
  `test_sql_equivalent_needs_trusted_provenance`: `SemanticsValidator.preserves()`
  returns `False` for a surface-only case-toggle variant of a SQLi payload that it
  should accept, and `True` for an unvetted `-- x` comment append that it should refuse
  (a fail-*open* direction, so the more serious of the two).
- **Root cause:** not yet diagnosed here — outside this lane's component (MUT,
  `fuzzlab/mutation/semantics.py`) and outside its scope. Recorded because it was
  observed, per `ERROR_LOG.md`'s own scope line and PA-0019: both failures reproduce on
  a **pristine detached worktree of this branch's tip (`HEAD`, no L-P3.4 changes
  applied)**, so they are pre-existing on `claude/trusting-noether-heon0n` and not
  caused by this lane's change — verified explicitly rather than assumed.
- **Remediation:** none by this lane (deliberately: fixing another in-flight lane's
  component mid-merge would collide). Flagged to the orchestrating session in this
  lane's hand-off report so it can be routed to whoever owns MUT; a code defect, so it
  needs the full `docs/bugs/BUG-NNNN` + `PA-NNNN` protocol from that owner, not just
  this line.
- **Status:** Open (not caused by, and not remediated by, `CC-LAB-0040`).

## 2026-09-21 — `lab-generate --check` gate tests stopped exercising their gate when an emitter's supported shapes were widened

- **Symptom:** while landing lane L-P1.2b (the harder SQLi/XSS shapes, which widen
  `php_current`'s supported shapes by four and therefore make the example manifest's
  long-skipped `LABGEN-EX-0003` renderable),
  `tests/test_labgen_cli.py::test_check_fails_loud_on_nondeterministic_render` failed:
  `--check` still exited 1, but the *determinism* gate it exists to exercise no longer
  tripped at all.
- **Root cause:** that test (and its minimal-pair sibling) injected its fault on the
  parity of a **global** counter incremented once per rendered cell, so which parity a
  given cell's render lands on depends on how many *other* supported cells precede it —
  at an even supported-cell count the corruption applied to both whole-tree renders
  identically and the regenerate-and-diff comparison saw no difference. The same file
  also hardcoded the supported-cell set that `PhpCurrentEmitter.supports()` computes.
- **Remediation:** both fault injections now count renders per `cell_id` (invariant under
  cell count), and `SUPPORTED_CELL_IDS` is derived from `supports()`. PA-0002 sweep done
  across `tests/`: the whole-tree counters in `test_labgen_gates.py` /
  `test_labgen_conformance_tier3.py` are at the correct granularity and left as-is. Full
  RCA: `docs/bugs/BUG-0025-check-gate-fault-injection-coupled-to-supported-cell-count.md`;
  rule: PA-0027.
- **Status:** Fixed (`CC-LAB-0043`).

## 2026-09-21 — Covering-array resolver silently returns zero cells when `strength` exceeds the factor count

- **Symptom:** while wiring `fuzzlab.labgen.resolver.expand()` into manifest loading
  (T-LAB2.1), an `axis_ranges` block with a single-axis `factors` mapping and the
  default `strength: 2` validated cleanly and expanded to an **empty** cell list — no
  error, no cells, nothing to catch it short of noticing the count.
- **Root cause:** `covertable.make()` does not raise when `strength` exceeds the number
  of factors (or a `sub_models` entry's own `strength` exceeds its own field count) — it
  silently returns `[]`, a t-way covering array being undefined for fewer than t factors.
  `fuzzlab.labgen.resolver.validate_covering_array_config()` already defends against two
  other silent-covertable-failure shapes (an unrecognized kwarg, an unpinned sorter
  default — both PA-0010) but had no check for this third shape.
- **Remediation:** `validate_covering_array_config()` now rejects `strength >
  len(factors)` and, per `sub_models` entry, `strength > len(fields)`, both before ever
  calling `covertable.make()`. Full RCA: `docs/bugs/BUG-0024-covering-array-strength-exceeds-factor-count.md`.
- **Status:** Fixed (`CC-LAB-0029`).

## 2026-09-21 — Nuclei oracle draft would misclassify an unreachable target as `confirmed_secure`

- **Symptom:** while validating `nuclei` as a tool-oracle (Spike 004), a first-draft
  classifier for `fuzzlab.labgen.nuclei_oracle` treated "exit 0, zero JSONL matches" as
  `confirmed_secure` — but `nuclei` also exits 0 with zero matches when it never reached
  the target at all (a closed port), so a torn-down/misconfigured secure twin would be
  recorded as confirmed secure.
- **Root cause:** unlike sqlmap/commix, Nuclei has no dedicated "not vulnerable" textual
  marker; a clean scan and an unreachable-target scan are both silent on stdout with exit
  code 0, distinguishable only via a stderr health-check line Nuclei prints unless
  `-silent` is passed.
- **Remediation:** `_classify()` checks `stderr` for Nuclei's own host-unreachable
  signal before ever returning `confirmed_secure`, downgrading to `inconclusive`
  instead; the wrapper never passes `-silent`. Caught and fixed during development,
  before shipping. Full RCA:
  `docs/bugs/BUG-0023-nuclei-oracle-unreachable-target-false-secure.md`; preventive
  action `PA-0025`.
- **Status:** Fixed.

## 2026-09-21 — `php_current.supports()` accepted a shape whose illustrative-manifest cell had no page profile

- **Symptom:** `PhpCurrentEmitter.render()` raised `ValueError` for
  `lab/manifests/example_phase0_scaffold.yaml`'s `LABGEN-EX-0004` cell
  (`xss`/`html_body`, route `/example/profile.php`), even though
  `PhpCurrentEmitter.supports()` returned `True` for that shape — violating
  the `Emitter` interface's own documented supports-then-render contract.
- **Root cause:** `CC-LAB-0022`'s real-page extension widened
  `PhpCurrentEmitter._MODULE_SET_BY_SHAPE` to accept `(xss, html_body)` (for
  the real `/profile.php` page) without adding a matching `_PAGE_PARAMS`
  entry for the pre-existing illustrative manifest's cell of the same shape
  — no test exercised a whole manifest's cell list through the now-widened
  `supports()`/`render()` pair, only individually hand-picked cells.
- **Remediation:** added the missing `_PAGE_PARAMS["/example/profile.php"]`
  entry; new whole-manifest Tier-3 regeneration tests
  (`tests/test_labgen_conformance_tier3.py`) now render every cell of both
  existing Phase-0 manifests, not a hand-picked subset. Full RCA:
  `docs/bugs/BUG-0022-php-current-supports-true-render-crashes-missing-page-profile.md`;
  preventive action `PA-0024`.
- **Status:** Fixed.

## 2026-09-21 — LAB lane worktree created from a stale/unrelated branch lineage

- **Symptom:** on session start for the T-LAB0.6 (Gitleaks secret-scanner) lane,
  `git log --oneline -5` showed only unrelated UI-redesign commits (a master-detail
  Launch view rebuild, app-shell/design tokens, Proxy Scope/Match-Replace) with no
  mention of "LAB"/"CC-LAB-00"/"labgen"/"D20", and `fuzzlab/labgen/` did not exist
  anywhere in the checkout at all (no `denylist.py`, `gates.py`, `resolver.py`, etc.).
  A sibling lane (`CC-LAB-0019`) hit the identical symptom independently.
- **Root cause:** a worktree-creation quirk in this session's harness — the worktree
  was materialized from a stale/unrelated branch lineage instead of the actual current
  trunk, even though the correct branch (holding the merged Phase 0 LAB lanes) was
  fully present in the shared git object store the whole time. Not a missing-history
  problem and not something either lane did wrong.
- **Remediation:** stopped and reported the discrepancy instead of working around it
  (e.g. manually re-importing files), per this project's explicit guidance for this
  exact failure mode. Confirmed via a fresh worktree that `claude/trusting-noether-heon0n`
  was reachable as a local branch and `git reset --hard claude/trusting-noether-heon0n`
  (working tree was clean, so no destructive-command safeguard was overridden) recovered
  the correct tree in one step — `git log` then showed the expected LAB merge-lane
  history and `fuzzlab/labgen/` existed with all expected modules.
- **Status:** Environment (fixed outside the repo — no repo-level change needed; the
  underlying worktree-provisioning quirk is a harness/session-infrastructure issue, not
  a defect in this codebase). See `docs/components/01-target-lab/change-control.md`
  `CC-LAB-0019`'s and `CC-LAB-0020`'s notes for the per-lane detail.

## 2026-09-21 — `test_web_repeater.py` flakes with a cross-thread SQLite error

- **Symptom:** found incidentally while verifying an unrelated lab-generator lane's full-suite
  run: `tests/test_web_repeater.py::test_routes_list_create_and_send_gate` and
  `::test_route_send_reaches_upstream_when_authorized` intermittently fail with
  `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same
  thread` (a different one of the two failing each time). Reproduced twice independently
  (each time with different specific test(s) failing, consistent with a genuine race rather
  than one bad test); not reliably reproducible on demand afterward — order/timing-dependent.
- **Root cause:** `fuzzlab/web/proxycontrol.py::RepeaterController` (not `Repeater`/
  `SocketSender` themselves) cached one persistent `Store`/`sqlite3` connection as shared
  instance state (`self._store`/`self._rep`) and reused it for every request regardless of
  which OS thread was calling. `fastapi.testclient.TestClient`, when not used as a context
  manager, spins up a fresh `anyio` portal thread per top-level `client.get()`/`client.post()`
  call; whether the bug fires depends on whether Linux happens to reuse the same low-level
  thread id for the next ephemeral thread, which is why it was order/timing-dependent rather
  than deterministic. Full RCA in `docs/bugs/BUG-0021-repeater-controller-cross-thread-sqlite.md`.
- **Remediation:** `RepeaterController` now keeps its `Store`/`Repeater` per calling thread
  (`threading.local()`) instead of as one shared attribute, while still sharing a single
  `repeater` run row across threads (`self._run_id` under a lock). See `CC-PROXY-0016`.
  Reproduced reliably under thread-churn stress testing (100s of failures per few hundred
  iterations) before the fix, 0 failures across 600+ iterations after; full suite green
  (642 passed / 5 skipped; the 2 `test_mutation_operators.py` failures are pre-existing and
  unrelated).
- **Status:** Fixed.

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
