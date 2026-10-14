# Session Manager — Change Control Log

Component code: **SESS**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-SESS-0018 — Isolated session copies for in-app login forms (forms phase 2, lane B) (2026-10-14)
- Change:
  - **`SessionManager.isolated_copy(identity, *, ordinal, max_logins=3)`.** A throwaway
    manager:
    - **built through `__init__`**, never `copy.copy`, so its states, auth endpoints,
      locks, failures, login attempts, copies and logout listeners start empty;
    - **shared, read-only:** the credential store and the fetch factory (one fresh
      fetcher, with its own jar, per login);
    - **copied:** scope, authorised auth origins, the operator's bases and operator
      bases, so a (re-)login uses the operator's URL and the same
      credential-destination anchors;
    - **`store=None`:** never persisted, so it cannot overwrite the run's
      `(host, identity)` row;
    - **label:** answers only to `<identity>#isolated:<n>` in `prepare`, `authorize`
      and `observe`; refuses every other identity, the bare one and `anonymous`
      included; `adopt` refuses.
  - **Registry.** `_copies`, the main manager's live copies; `release_copy`.
  - **`max_logins`** (new `__init__` keyword, default None = unlimited, as before):
    counts login attempts in `ensure`; over the cap → `LoginCapReached`.
  - **Distinctness.** After every copy login, `_check_isolated` compares the new state
    with the run's and with every other live copy's (`distinctness_problem`):
    - Basic is distinct (no server-side session);
    - otherwise a credential must exist and at least one value must differ;
    - an equal cookie or header value is an identifier when its name is sensitive,
      `core.redaction.looks_like_identifier` holds (shared, CC-CORE-0040), or it is at
      least `DISTINCT_MIN_LEN` = 16 characters (local policy);
    - a failure raises `SessionIsolationError`, naming credentials, never values.
  - **Errors.** `IsolatedLoginFailed(SessionAuthError)`, with `SessionIsolationError`
    and `LoginCapReached` under it. A copy wraps any login failure, credential error
    included, in it; a run's manager is unchanged.
  - **`verify_live(host, identity, base_url)`.** One walk of the operator's base with a
    fresh fetcher carrying the session's cookies and headers; false on 401/403 or this
    session's login form, and then the state is marked invalid and persisted (listeners
    are not told; the caller decides).
- Impact:
  - **Callers:** `tools.probesender.SeamProbeSender` (CC-FUZZ-0064). Existing callers
    are unaffected (new keyword defaults; a run's manager has no label).
  - **Shared code used as delivered:** `add_logout_listener` (CC-SESS-0017) and
    `looks_like_identifier` (CC-CORE-0040), unmodified.
- Risk: low to medium (a second login per login-form path). Bounded by the copy's
  login cap and the sender's caps and breakers (CC-FUZZ-0064).
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_login_form_isolation.py`: no shared mutable state, built via
        `__init__`, label-only identity, a copy's logout never told to the main
        listener, never persisted, distinct from the run's and every live copy's,
        by-value rule wired to the shared predicate, no values in messages, login cap,
        `verify_live` carries the cookie and marks a dead session) — done
  - [x] FR-SESS-17; NFR-SESS-redaction `Enforced by:` — done
- Review: reviewers A and B, lane B draft v1 → v2 → v2.1 → v2.2 → v2.3 (AGREED, both).
  Carried conditions: built through `__init__`, a copy's logout not passed to the main
  listener (test), T22's wiring patches `fuzzlab.session.manager.looks_like_identifier`.
- Effectiveness: verified offline (mutation check 32/32 over lane B's new logic); live
  bWAPP pending (orchestrator).

### CC-SESS-0017 — Logout listeners (`add_logout_listener`) for forms phase 2's breakers (2026-10-14)
- Change:
  - **`SessionManager.add_logout_listener(listener)`.**
    - **When it fires:** `observe` calls `listener(host, identity)` when it sees a
      *valid* session of this manager logged out.
    - **Where it runs:** after the state is marked invalid, inside the send that
      observed the logout.
    - **Errors:** a listener's error propagates (PA-0106).
    - **Registration:** adding the same listener again does nothing.
    - **Once per logout:** the valid→invalid check-and-set runs under a small guard
      lock, released before `_persist` and the listeners. Concurrent sends that see
      the same logout therefore tell a listener once.
  - **Why:**
    - forms phase 2 lane A stops header probing when a probed header logs the session
      out;
    - lane B stops session isolation when a copy's login logs the main session out.
  - **Why not count logins:** reviewers A and B found that counting logins through
    the shared fetch factory also counts lane B's copy logins.
- Impact:
  - **New API, no callers yet.**
  - **Behaviour:** with no listener, `observe` behaves as before.
  - **Scope:** an isolated copy is its own manager, so its logouts never reach the main
    manager's listeners.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (`tests/test_logout_listener.py`): told once per logout with host and
        identity, deduplicated, not told for another manager, errors propagate after
        the state is invalid, 8 concurrent observers tell it once — done
  - [x] FR-SESS-16 — done
- Review:
  - **Origin:** reviewers A and B (lane B's v2.1/v2.2 hook; lane A v2 must-fix M1).
    The hook was moved into the shared commit so both lanes build on it.
  - **Shared-commit gate:** AGREED by A and B.
  - **B's should-fix, adopted:** the "once" claim needed an atomic check-and-set,
    since `observe` holds no per-key lock.

### CC-SESS-0016 — Discovery base is the operator's URL, never its origin (BUG-0113) (2026-10-13)
- Change:
  - `ensure(host, identity, base_url, *, operator=False)`. An operator base is
    remembered in `_bases` and recorded in `_operator_bases`, which are the only bases
    exempt from `_navigation_ok`'s destructive check.
  - `prepare` re-ensures with the remembered base, else `_directory(request.url)`:
    the path to its last `/`, with no query or fragment. `_base_url` (origin-only) is
    removed.
  - `session_header(..., operator=)` passes through.
  - A Basic session records `login_url=None`.
  - `session/cli.py`, greybox and `browserauth` pass `operator=True`.
  - **"Logged out" means *this* login form.** `detect.shows_login_form` (a password
    form posting to the session's login action, or with exactly the login form's
    entry names, `SessionState.login_fields`, in memory) replaces "any password input" in the
    login-response check, the verification probe and `detect_logout`; `observe`
    passes the page URL. Found live: start pages with their own password form failed
    verification, and `password_change.php` read as a logout. Basic sessions
    (`content_check=False`) log out by 401/403 only, and are verified by status
    only.
- Impact:
  - **Behaviour:** sub-path apps log in. Re-logins use the operator's base. A probe URL
    is never a discovery base. A Basic session's logout detection is 401/403 only.
  - **CRAWL, AUD, FUZZ:** they pass operator URLs (their own entries).
  - **Test doubles:** `test_browserauth` expects origin-root cookie URLs.
- Risk: low-medium, since the login path changed. The credential-destination anchor is
  unchanged (origin, in-scope hosts, `auth_origins`), and the session suites pass.
- Deliverables:
  - [x] code — done
  - [x] `tests/test_subpath_apps.py` — done
  - [x] FR-SESS-15 — done
- Review: reviewers A and B, draft v1 (changes required) → v2 (AGREED, both).
  - **Adopted:** A1 (cookie path), A2 / B-M1 (directory fallback, no query;
    operator-only exemption), A3 (limitation stated), A's nit (`operator=False` by
    default, fail-closed), B-S1 (pre-login), B-S2 (Basic `login_url`), and B's nit (a
    destructive derived-base test).
  Implementation round: both AGREED. Their nits were adopted:
  - **B:** an operator call on a cached session still records the base (test added);
  - **A:** a `SeamProbeSender` built without a base never marks a probe URL as
    operator input (test added).

  The login-form refinement was found in the live run after both AGREED, and went back
  to them (PA-0093(2)). Both AGREED, requiring:
  - an entry-name signal, so an in-place re-render is still a logout (A, B1);
  - status-only Basic verification (B2).

  Both are adopted. The mutation check killed 23/23.
- Known limitation: sessions and bases are per `(host, identity)` (D12), so use
  distinct identities for two apps on one host:port.
- Effectiveness: verified live. The authenticated bWAPP crawl logs in.

### CC-SESS-0015 — Login discovery never follows a destructive hop (BUG-0111); traceability (PA-0112) (2026-10-13)
- Change: `_navigation_ok` refuses a URL `destructive_reason` flags, other than the base
  URL itself. `requirements.md` gains traceability lines for NFR-SESS-redaction
  (partly; the logger path is untested and `login_url` is not redacted).
- Impact: a login whose discovery redirects through `logout` / `reset` now fails loudly
  instead of fetching it.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] test — done
  - [x] FR-SESS-13 note — done
- Review: reviewer A nit 2, on draft v2.
- Effectiveness: verified by test.

### CC-SESS-0014 — Login forms submitted as a browser would (BUG-0110) (2026-10-13)
- Change:
  - `detect.find_login_form` builds `LoginForm.fields` with `core.forms.form_entries`.
    It now includes the submitter's `name=value` and a select's default option, and
    leaves out unchecked boxes, disabled controls and file inputs;
  - username and password detection read the form's owned, enabled inputs;
  - `LoginForm.fill` returns the entry list with the credentials replaced in place;
  - `LoginForm.submitter_overrides` is set, and `SessionManager` refuses such a form
    before any credential request;
  - the `Fetcher.post` data annotation is a sequence of pairs.
- Impact:
  - **Behaviour change:** login POST bodies gain the submitter's field and select
    defaults, and lose unchecked and disabled controls;
  - **Test doubles:** they receive a `FormEntries` (a list with `.get`), so the
    existing `data.get` doubles work unchanged;
  - **Credential destinations:** unchanged (`form.action` through
    `_credential_destination_ok`);
  - **PROXY / FUZZ:** not affected.
- Risk: low-medium. A login that relied on the old body (sending a disabled or unchecked
  field) would change. That is browser-incorrect, and no lab target relies on it (the
  session suites pass).
- Deliverables:
  - [x] detector and manager — done
  - [x] tests: the bWAPP-shaped end-to-end login; overrides refused with no request — done
  - [x] FR-SESS-3 amended, FR-SESS-14 added — done
- Review: as CC-CORE-0037 (A and B AGREED with required changes, all adopted).
- Effectiveness: verified live against the loopback bWAPP (`PHPSESSID` and
  `security_level=0`).

### CC-SESS-0013 — Login navigation anchored to operator input (BUG-0097); sessions bound to their transport floor (BUG-0098) (2026-10-13)
- Change:
  - **Discovery (BUG-0097):**
    - `_discover_login_form` walks redirects by hand (`_navigate`, `MAX_LOGIN_HOPS` = 5,
      `_get_no_redirects`), authorising every hop **before** fetching it, with the
      transport deny first;
    - a fetcher that cannot refuse redirects must report the URL asked for, or
      discovery refuses (A3);
    - `_credential_destination_ok(target, base_url, ...)` is anchored to the base URL,
      its https upgrade, in-scope hosts and `auth_origins`; the page exemption is
      removed;
    - the post-login probe walks hops the same way;
    - the default fetcher's `get` takes `allow_redirects`.
  - **Sessions (BUG-0098):**
    - `SessionState.secure_only` is derived from the login's floor or an https
      `login_url`, persisted as metadata, and derived failing closed for legacy
      records (`secure_only_of`);
    - `_check_transport` runs in `prepare` and `session_header`;
    - the new `authorize(request, identity, prepared_host)` is used after plugin
      retargets;
    - `SessionCapture` marks https or `Secure` captures;
    - greybox's sender refuses an https cookie over http.
- Impact (other components / project):
  - **CORE** (CC-CORE-0036): `HttpClient` calls `authorize`.
  - **FUZZ:** the greybox sender gains `cookie_secure_only`.
  - **PROXY:** session capture.
  - **Behaviour change:** an https session is refused over http, and a discovery hop
    outside scope / `auth_origins` is refused loudly.
  - **Test doubles:** their `get` declares `allow_redirects`.
- Risk: medium. A stricter login path: every allow path is tested, and in-scope
  multi-hop and SSO logins still work.
- Deliverables:
  - [x] anchored, hop-by-hop discovery — done
  - [x] `secure_only` on every send path — done
  - [x] tests: `test_session_transport_binding` (new); the redirect tests rewritten in
        `test_session_credential_destination` — done
  - [x] FR-SESS-12 amended, FR-SESS-13 added — done
- Implementation divergence: the post-login verification probe also walks hops. It
  previously let the fetcher follow redirects; found while testing, and in scope of
  PA-0098(2).
- Review: the review-9 draft (all 13 findings reproduced first on `1619932`) went v1 → v4 through both reviewers. A: 2 must-fix, 6 should-fix and 4 nits on v1, then 1 must-fix and 1 nit on v2. B: 2 must-fix, 7 should-fix and 5 nits on v1, then 1 must-fix on v2, and S9 on v3. AGREED 3/3 on v3. S9, a narrowing, was adopted as v4 with A's confirmation.
- Effectiveness (assessed 2026-10-13): effective offline. All 13 findings were reproduced on `1619932` (`scratchpad/ext2/f01..f13`). Each now has a test that fails there (or cannot import there, its repro script showing the old behaviour), and the repros show the fixed behaviour on the new tree. Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 47 mutants across the 13 fixes. 45 were killed on the first pass. The 2 survivors each showed a test gap, and both gaps were closed: the in-scope path of the event-loop test, and the thread lock without `fcntl`. Result: 47/47. Full non-labgen suite (150 files, `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 2003 passed, 13 skipped, 2 xfailed. The 1 error was `test_no_ml`'s real build, which builds from git-tracked files; it passes once the new files are staged (the no-ML and packaging files: 17 passed, 1 known environmental skip). The two gap-closing test files, re-run after the suite: 55 passed. The labgen half was not re-run, since no labgen code changed.

### CC-SESS-0012 — Credentials never over a downgrade from https to http: deny before allow (BUG-0092) (2026-10-13)
- Change:
  - `SessionManager._transport_ok(target, floor_https)` is the transport deny, checked
    **first** in `_credential_destination_ok` and never overridden: the scheme must be
    http or https, and https whenever the floor is.
  - **The floor** is https when any of these was https:
    - the operator's `base_url`;
    - any hop of the discovery redirect chain;
    - the login page itself;
    - the URL a POST redirect comes from.
  - **The login page reached by discovery** is checked before any POST. Its final URL
    is used as the login page URL.
  - **The manual 301/302/303 follow** uses the same predicate.
  - **`FetchResponse` gains `url` and `history_schemes`.** The default fetcher fills
    them from `requests`. A double without them falls back to `base_url`'s scheme.
- Impact (other components / project):
  - The interface addition is backward compatible: the new fields have defaults.
  - **Behaviour change, listed:** an https login can no longer send credentials to an
    http in-scope host or `auth_origins` entry.
  - Host scope is unchanged (host-level, any port, same or upgraded scheme).
- Risk: low. This is a stricter rule. Every allow path is tested against the deny, and
  the same and upgraded transports are tested as still allowed.
- Deliverables:
  - [x] deny-first predicate, floor from base, hops, page and redirects — done
  - [x] `FetchResponse.url` / `.history_schemes` — done
  - [x] tests: `test_session_credential_destination` (7 new tests, 14 cases; 10 fail on `5eb4be9`) — done
  - [x] FR-SESS-12 amended — done
- Implementation divergence: none. BUG-0081's "moot" note is superseded by this entry
  and BUG-0092.
- Review: the review-8 draft (all seven findings reproduced first) went v1 → v4 through both reviewers. v1→v2: B, 4 should-fix + 4 nits. v2→v3: A, 1 must-fix + 4 should-fix + 3 nits. v3→v4: A and B, the same must-fix (an implied holdout for every trainer). v4 was AGREED 3/3, and the final optional nits (A: store-wide trains skip, not refuse, an unknown target; B: the prioritizer raises, never returns None) were adopted.
- Effectiveness (assessed 2026-10-13): effective offline. Every finding's reproduction is now a test that fails on `5eb4be9` (counts in each bug doc). Mutation check (a copy of the working tree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` set to the copy): 38 mutants across the seven fixes, 35 killed on the first pass. The 3 survivors each showed a test gap (the plural fold of `pass`, the loader boundary's `OverflowError` catch, the discovery-hop https floor), and each gap was closed with a new test, after which 3/3 were killed (38/38). Full non-labgen suite (145 files, `FUZZLAB_REQUIRE_BROWSER=1`): 1869 passed, 13 skipped, 2 xfailed, 0 failed. The review-8 test files, re-run after the gap tests: 327 passed, and `test_secretfile` 13/13 with the reviewers' self-healing test. The labgen half was not re-run, since no labgen code changed.

### CC-SESS-0011 — Credentials only to authorised origins, never on redirects; HTTP Basic at discovery (BUG-0081) (2026-10-13)
- Change:
  - **`_credential_destination_ok`.** Allowed destinations are the login page's
    canonical origin, that host upgraded to https, an in-scope host (by host or
    `host:port`), or an origin in the new `SessionManager(auth_origins=[...])`.
    Otherwise `SessionAuthError` names the option, and no POST is made.
  - **No redirect following on the credential POST.** `Fetcher.post(...,
    allow_redirects=False)` is a new keyword, which old doubles without it are called
    without. 301/302/303 are followed by hand as a GET, only to an allowed origin.
    307/308 are never followed.
  - **HTTP Basic.** `_discover_login_form` reports a `401 + WWW-Authenticate: Basic`
    on the base URL, and `_basic_login` verifies the `Authorization` header against
    that base URL only. A POST answering 401 Basic switches to it too.
- Impact (other components / project): CLI callers (`auto`, `greybox`) pass no
  `auth_origins`. In-scope hosts already cover the lab's own services, and a CLI flag is
  a stated follow-up.
- Risk: low-medium. Legitimate same-origin, relative, https-upgrade and in-scope
  cross-port logins are all tested as allowed.
- Deliverables:
  - [x] origin rule; manual redirects; Basic at discovery — done
  - [x] `tests/test_session_credential_destination.py` — done
  - [x] FR-SESS-12 added — done
- Implementation divergence: the draft's "never a downgrade" is moot. The authenticated
  host is always in scope (`ensure` requires it), so a same-host http action is allowed
  by the in-scope rule. The vacuous downgrade test was replaced by an
  out-of-scope-host test, and this is stated in BUG-0081.
- Review: the review-7 draft v1 got AGREE-with-changes from both reviewers (A: 2 must-fix, 7 should-fix, 3 nits; B: 6 should-fix, 4 nits), all adopted; v2 was agreed 3/3, with the final nits adopted.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Mutation check** (a copy of the worktree, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH` verified to resolve to the copy): **40 of 40** review-7 mutants killed. Six first survivors were killed after adding tests for: the leaf cache refusing directly; 0600 with `chmod` disabled; the path backstop alone; a same-origin 307; a line-comment-split `INSERT … INTO`; a JS string open at a newline.
  - **Suites:** **non-labgen suite** (143 files, real browser and lint required; ): **1730 passed, 13 skipped, 2 xfailed, 0 failed**. The live multitarget category-3 / category-4 runs pass with no concurrent load. Packaging / no-ML / contract writers / lint: 22 passed, 1 skipped (the wheel, the known Debian setuptools issue). The labgen suites are untouched by this batch; the last full run (review 6) failed only the 33 known environmental tests (no scipy, scikit-learn or gitleaks).

### CC-SESS-0010 — Lint: unused `dataclasses.field` import in `session/manager.py` (2026-10-13)
- Change: removed the unused import (pyflakes). No behaviour change.
- Impact: none.
- Risk: none.
- Deliverables:
  - [x] fix — done
  - [x] `tests/test_lint.py` keeps it clean — done
- Review: covered by the batch-5 3/3 pre-change review (A5). Pre-assigned number.
- Effectiveness (assessed 2026-10-13): effective offline.
  - **Related suites** (95 files: ML, auto, web incl. real-browser, plugins, report,
    no-ML incl. the real no-ML build, harness, multitarget, pipeline, diagnostics, core,
    CLI, store, migrations, packaging, lint, contract writers, on-host script, greybox,
    store adapter, session, labgen CLI, mutation, oracle;
    `FUZZLAB_REQUIRE_BROWSER=1 FUZZLAB_REQUIRE_LINT=1`): 1249 passed, 3 skipped,
    11 failed.
    - 10 failures are `test_labgen_cli.py` tests, among the 33 known environmental
      failures (no scipy, sklearn or gitleaks).
    - The 11th, the multitarget live-boot test, failed with a connection reset from its
      locally booted server while two other suites held the CPU. It passes alone
      (2 passed).
  - **Mutation check** (a staged git copy, bytecode caches cleared): all 21 batch-5
    mutants are killed. Three were first mis-anchored by shell expansion in the
    mutation script and were re-run correctly. Killed:
    - old per-directory globs; no dotfiles;
    - deny-list missing pem / env; an over-broad deny pattern; a one-line no-ML switch;
    - report union missing models / stage metrics / flow;
    - the anomaly version on the read-only path, or missing;
    - flow-version duplicates; prioritizer / pipeline version missing;
    - CSV / greybox schema missing;
    - `_check_sql` never failing; the reveal not opt-in; a literal 5 in the budget check;
    - a lint regression; the dropped `Probe` import.

### CC-SESS-0009 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/session/cli.py` now factors its argparse setup (including the
  `set-credential`/`print` subparsers) into `build_parser()`; `main()` delegates parsing.
  Behavior-preserving — same subcommands, flags, and prompts.
- Impact: lets the web launcher introspect the session subcommands (CC-UI-0011; the registry
  recurses one level into subparsers). No CLI behavior change; the password prompt is
  unchanged (the launcher will treat `session` specially). No traffic on build; no schema
  change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests (subparser recursion covered).
- Deliverables:
  - [x] `build_parser()` (with subparsers); `main()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry surfaces both session
  subcommands from this parser.

### CC-SESS-0008 — Fix (BUG-0008): require a positive login-success signal, not an ambient cookie (2026-09-21)
- Change: `SessionManager._login` now fails loud when the login POST response is still a
  login page (`detect.is_login_page`) or is `401/403`, **before** inspecting cookies. The
  mere presence of a session cookie is no longer treated as proof of authentication —
  PHP's `session_start()` hands an anonymous `PHPSESSID` to everyone on the first GET, so
  the jar is non-empty even on a failed login. `_verify_authenticated`'s docstring is
  corrected to describe it as a secondary sanity check (it probes `base_url`, often
  public); the primary success decision is the POST-response check.
- Impact (other components / project): closes a high-severity auth-correctness hole where
  any credentials "authenticated" and tools ran anonymously while logging
  "authenticated as <id>". The crawler (`spider.py`) and auditor (`fetcher.py`) obtain
  sessions via `manager.ensure(...)`, so both now inherit the fail-loud behavior with no
  change of their own. Not the lab's intended (SQLi) auth bypass — a toolkit false
  positive that would also mis-fire against a secure app. Restores the FR-SESS-6
  "fail loud, never a silent unauthenticated run" contract for the wrong-credentials case.
- Risk (level; mitigation): low — the change only *adds* a rejection path; the correct-
  credentials path is unchanged (the lab redirects to `profile.php`, not a login page).
  Mitigated by two regression tests (`AnonCookieLoginFetcher` models the pre-login anon
  cookie: wrong creds fail loud despite the cookie, correct creds still authenticate) and
  the existing wrong-creds/bearer/basic tests. Suite 394 passed / 4 skipped.
- Deliverables:
  - [x] POST-response login-rejection check in `_login` (BUG-0008) — done.
  - [x] Corrected `_verify_authenticated` docstring — done.
  - [x] Regression tests for the pre-login anonymous cookie — done.
  - [x] RCA (`docs/bugs/BUG-0008-*`), PA-0007, ERROR_LOG entry — done.
- Effectiveness (assessed 2026-09-21): effective in tests — a wrong password no longer
  authenticates when an anonymous cookie is present, and a correct password still does.
  Live re-run on the host (wrong creds should now error; `admin`/`admin123` should still
  authenticate) pending user confirmation.

### CC-SESS-0007 — Adopt proxy-captured manual sessions (FR-SESS-11) (Phase 6 T6.5) (2026-09-21)
- Change: implemented `SessionManager.adopt(state)` — the session manager can now take
  a `SessionState` captured by the proxy from a **manual browser login**
  (`fuzzlab/proxy/session_capture.py`, FR-PROXY-9) and adopt it: mark it valid, bring
  its host into scope, cache it for `prepare`/`apply`, and persist only NON-SECRET
  metadata. Realizes the CC-SESS-0004 spec.
- Impact (other components / project): the escape hatch for logins the detector cannot
  parse (MFA, CAPTCHA, multi-step, exotic SPA), with no per-host config file — the
  toolkit stays authenticated on hosts Phase-1 detection can't crack. Secrets remain
  in memory only (D12); the store contract is unchanged.
- Risk (level; mitigation): low — reuses the existing non-secret persistence path;
  adds no new store columns. Mitigated by `tests/test_proxy_session_capture.py`
  (adoption authenticates `prepare` without a login handshake; only non-secret metadata
  is persisted). Suite 237 passed / 2 skipped.
- Deliverables:
  - [x] `SessionManager.adopt` (FR-SESS-11) — done.
- Effectiveness (assessed 2026-09-21): effective in tests — an adopted session
  authenticates requests with no login handshake and leaks no secret to the store.

### CC-SESS-0006 — Non-secret session-state persistence (T1.7) (2026-09-21)
- Change: the `SessionManager` now accepts a `store` and persists **non-secret**
  session state (via `SessionState.non_secret_state()`) on login success and on
  logout detection; `persisted_state(host, identity)` reads it back, and a fresh
  manager preloads known sessions on init. The auth builders (`authhttp`) open the
  store when `--store` is given, and the crawler/auditor/fuzzer pass their `--store`
  path so persistence happens in real authenticated runs. Realizes T1.7.
- Impact (other components / project): adds an audit/continuity trail in the store
  (CC-CORE-0005 `session_state`); no interface change for callers. Secrets are never
  persisted, so a resumed run still re-authenticates to obtain a live cookie/token —
  persistence is metadata, not a secret cache (as designed).
- Risk (level; mitigation): low — writes non-secret metadata only; a test asserts no
  cookie/token value appears in the row. Two connections to the same SQLite file
  (manager + tool consolidation) are safe under WAL.
- Deliverables:
  - [x] `store` param; persist on login/logout; `persisted_state`; preload — done.
  - [x] `authhttp`/tools pass `--store` so runs persist — done.
  - [x] 4 persistence tests (non-secret-only, resume, logout-flips-valid, no-store) — done.
- Effectiveness (assessed 2026-09-21): effective — state round-trips per host, a
  fresh manager resumes the known non-secret state, logout flips persisted validity,
  and no secret is written. Suite 71/71 green.

### CC-SESS-0005 — Session manager implemented (Phase 1) (2026-09-21)
- Change: built `fuzzlab/session/` — `state.py` (SessionState: cookies + tokens per
  host/identity; redaction; JWT-time expiry), `detect.py` (dynamic login-form
  detection with fresh hidden/CSRF carry-through; session-credential detection for
  cookie / JSON-token+JWT / Basic challenge; success + logout detection; base64url
  JWT `exp`), and `manager.py` (`prepare`/`observe`/`ensure`, identities per host,
  single-flight re-auth, fail-loud on unparseable logins, auth-endpoint exclusion,
  standalone `session_header`). Added a `fuzzlab session` CLI (set-credential /
  print). Drop-in addon for the `core/` HTTP seam. Realizes T1.2–T1.9.
- Impact (other components / project): the crawler/auditor/fuzzer can authenticate
  by routing HTTP through the seam with this addon; depends on the credential store
  (CC-CORE-0004). Detection-only per D13; no per-host profiles. No store-schema
  change (non-secret session-state persistence method exists but is not yet wired
  to a table — deferred, see below).
- Risk (level; mitigation): medium–high (auth correctness). Mitigated by: fail-loud
  with diagnostics (never a silent unauthenticated run), differential success
  verification, multi-signal logout detection, single-flight re-auth with a cap,
  auth-endpoint exclusion, secret redaction, and 17 unit tests (cookie + JWT login,
  wrong-creds/no-form/missing-creds/out-of-scope failures, single-flight one-login,
  auth-endpoint exclusion, observe→re-auth, standalone header, seam integration).
- Deliverables:
  - [x] SessionState + detection + manager (T1.2–T1.6, T1.8) — done.
  - [x] Fail-loud on unparseable logins (FR-SESS-6) — done.
  - [x] Standalone `session_header` + `fuzzlab session` CLI (T1.9) — done.
  - [x] Redaction of secrets in logs/repr (T1.7 redaction) — done.
  - [ ] Persist non-secret session state to a store table (T1.7 resume) — todo.
  - [ ] Migrate tool HTTP onto the seam + live two-lab validation (T1.10) — todo (needs a runnable lab; cookie path validated on PFF, JWT path on an external lab).
- Effectiveness (assessed 2026-09-21): effective in unit tests (17/17 for the
  session package; 60/60 suite) — cookie and JWT logins detected and handled,
  single-flight confirmed, unparseable logins fail loud. Live end-to-end on the
  containerized lab and an external JWT lab is pending an environment with a
  container daemon / network to those labs.

### CC-SESS-0004 — Planned: adopt proxy-captured manual sessions (spec) (2026-09-21)
- Change: added FR-SESS-11 `[planned, post-Phase 6]` — for logins detection can't
  parse (the FR-SESS-6 fail-loud cases: MFA, CAPTCHA, multi-step, exotic SPA), the
  session manager adopts a session captured by the proxy from a manual browser
  login (FR-PROXY-9) as the live session state for `(host, identity)`, still with
  no per-host config; interactive-login expiry prompts for re-capture. Resolves the
  MFA/SPA open questions as "handled post-Phase 6." Spec only — no code.
- Impact (other components / project): closes the accepted detection-only gap
  without reintroducing per-host profiles. Adds a post-Phase 6 dependency on the
  proxy (component #11, FR-PROXY-9). Recorded in D13 and the Phase 6 roadmap;
  `ARCHITECTURE.md` #3 updated.
- Risk (level; mitigation): low (planning). When built, captured cookies/tokens are
  secrets — mitigated by the existing redaction and no-cleartext-persistence rules
  (NFR-SESS-redaction, FR-SESS-9). Interactive re-auth can't be automated; mitigated
  by prompting for re-capture rather than silently failing.
- Deliverables:
  - [x] FR-SESS-11 recorded; open questions resolved to post-Phase 6 — done.
  - [ ] Implement session adoption from a proxy capture — todo (post-Phase 6).
- Effectiveness (assessed or pending): pending — depends on the proxy (Phase 6).

### CC-SESS-0003 — Detection-only auth + per-host credentials (spec) (2026-09-21)
- Change: per user direction, superseded the profile-first framing of CC-SESS-0002.
  Auth is now **detection-only** (D13, revised): the session manager detects each
  host's login, session credential, success, and expiry dynamically and handles
  them, with **no hand-written per-host profiles or overrides**; a login detection
  cannot parse **fails loudly**. Credentials are **saved per host** (D12, revised:
  vault keyed by `(host, identity)`) and passed to the host they belong to. The
  auth handlers (cookie/form, JSON+token, Basic, header-key) remain internally but
  are selected by detection, not authored by the user. Rewrote FR-SESS-1…10 around
  detection + per-host credentials; NFR-SESS-extensible → NFR-SESS-zero-config.
  Spec/plan only — no code.
- Impact (other components / project): removes the per-lab profile authoring the
  previous entry introduced; the only per-host input is credentials in the vault.
  The crawler is now a (soft) dependency — discovered forms help locate the login.
  Updated D12/D13 in `DECISIONS_AND_ROADMAP.md`, `ARCHITECTURE.md` #3, and
  `PHASE_1_PLAN.md`. Supersedes CC-SESS-0002's profile/strategy-authoring parts;
  the credential-store backend resolution from CC-SESS-0002 stands (now per-host).
- Risk (level; mitigation): medium–high. Detection-only is less predictable than
  declared profiles — a login it cannot parse fails (accepted trade-off, chosen for
  zero per-host config). Mitigated by fail-loud with diagnostics (never a silent
  unauthenticated run), differential success/expiry checks, single-flight re-auth,
  auth-endpoint exclusion, credential-store redaction, and validating first on the
  known cookie lab then a JWT lab. The accepted limitation (complex logins fail
  until detection improves) is documented in D13 and the spec.
- Deliverables:
  - [x] Spec rewritten for detection-only + per-host credentials — done.
  - [x] D12/D13 revised; `ARCHITECTURE.md` #3 + `PHASE_1_PLAN.md` updated — done.
  - [ ] Implement the login/session detector (FR-SESS-3…6) — todo (Phase 1).
  - [ ] Per-host credential vault + lookup by host (D12) — todo (Phase 1).
  - [ ] Fail-loud diagnostics for unparseable logins — todo (Phase 1).
- Effectiveness (assessed or pending): pending — spec-level. Judged in Phase 1 by
  authenticated runs on a cookie lab and a JWT lab with only saved credentials
  (no per-host config), and a clear failure on a deliberately unparseable login.

### CC-SESS-0002 — Multi-target auth + settled credential store (spec) (2026-09-21)
- Change: expanded the requirement spec before building, in response to the need to
  validate on several other lab environments (D10). Made the component
  **target-profile-driven** and **auth-scheme-pluggable** (new FR-SESS-9/10;
  generalized FR-SESS-1/3/4/7/8; new NFR-SESS-portable/extensible) and settled the
  **credential store** as an OS-keyring abstraction with an encrypted-file headless
  fallback and a gated lab-only env fallback (FR-SESS-6). Recorded as decisions D12
  (credential store) and D13 (multi-target auth). No code yet — spec/plan only.
- Impact (other components / project): the session manager can now log in and hold
  sessions across many labs (cookie/form, JSON+JWT, Basic, header key, scripted),
  which unblocks D10 external validation (WAVSEP, Juice Shop, …). Adds two
  extension points (auth strategies, target profiles) that the plugin system
  (component #13) will later expose; `core/` gains a credential-store abstraction
  (D12). `ARCHITECTURE.md` component #3 and `PHASE_1_PLAN.md` updated to match.
- Risk (level; mitigation): medium — a broader surface (multiple schemes, profiles,
  a pluggable interface) is more to get right, and mis-scoped auth silently
  corrupts data across tools. Mitigated by keeping per-target quirks in data
  (profiles) not code, one narrow `AuthStrategy` interface, the single-flight lock,
  auth-endpoint exclusion, credential-store redaction, and validating first on the
  known lab (cookie) then one external JWT lab before trusting broadly.
- Deliverables:
  - [x] Spec: target profiles, pluggable strategies, credential store (FR-SESS-6/9/10) — done.
  - [x] Decisions D12/D13 recorded; `ARCHITECTURE.md` #3 + `PHASE_1_PLAN.md` updated — done.
  - [ ] Implement the credential store (D12) — todo (Phase 1 T1.x).
  - [ ] Implement `AuthStrategy` + built-in strategies + profiles — todo (Phase 1).
  - [ ] Ship profiles for the chosen validation labs — todo (pending the lab list).
- Effectiveness (assessed or pending): pending — spec-level change. Judged in
  Phase 1 by authenticated runs across ≥2 auth schemes/labs and a headless/CI run.

### CC-SESS-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented; tools
  currently run unauthenticated or with ad-hoc handling.
- Impact (other components / project): once built, the crawler, auditor, fuzzer,
  and proxy all route auth through it; it is a hard dependency for any
  authenticated testing and for authorization (IDOR/BOLA) work later.
- Risk (level; mitigation): medium — silent session failure corrupts data across
  every tool. Mitigated by building it early (Phase 1, before most tools rely on
  auth), the single-flight lock, capped re-auth, and auto-excluding auth
  endpoints from fuzzing.
- Deliverables:
  - [ ] Identity model + cookie jar — todo (Phase 1).
  - [ ] `prepare`/`observe`/`ensure` + single-flight re-auth — todo (Phase 1).
  - [ ] CSRF extraction + JWT `exp` handling — todo (Phase 1).
  - [ ] Keyring credentials + redaction — todo (Phase 1).
- Effectiveness (assessed or pending): pending — not yet built.
