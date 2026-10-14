# Crawler / Spider — Change Control Log

Component code: **CRAWL**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CRAWL-0013 — Selector-form navigation; landing URLs and forms recorded (forms phase 1) (2026-10-13)
- Change: `tools/spider.py` and new `tools/formnav.py`.
  - **Navigation.** `--follow-selector-forms [names]`, off by default.
    - GET selector forms are enumerated. POST ones are enumerated only for
      operator-named selects.
    - Never submitted: a form with a settings-named control, or a destructive or
      out-of-scope action. Skipped: an option with a settings word or destructive
      value/label.
    - Enumeration stops on a non-3xx response, a cookie, or a destructive or
      out-of-scope `Location`. Self-redirects are skipped, and five in a row stop the
      form.
    - Submissions go through an isolated client (a throwaway session, or a Playwright
      `APIRequestContext` seeded from cookies). A response cookie never reaches the
      crawler.
  - **Recording.** The landing URL of a redirect is recorded with its query
    (`redact_url`). Every form is recorded in `discovered_forms` (redacted).
- Impact:
  - **Behaviour:** the crawler POSTs for the first time, only under the flag.
    NFR-CRAWL-safe's text and `Enforced by:` lines are updated.
  - **Spider DB:** a new table.
- Risk: medium (state change by submission), mitigated by the gate before any
  submission, which reviewers A and B required, and the fail-safes.
- Residuals:
  - a named settings picker could change state, so the operator names deliberately;
  - a visit to bWAPP's `restrict_folder_access.php` deletes its `.htaccess`.
- Deliverables:
  - [x] code — done
  - [x] tests — done
  - [x] FR-CRAWL-8 and FR-CRAWL-9; NFR-CRAWL-safe — done
- Review: as CC-CORE-0039. Reviewer A's optional nit was declined: A suggested that a
  destructive or out-of-scope `Location` *skip* that option rather than stop the form.
  Stopping is the v2 rule reviewer B required (a menu leading somewhere destructive is
  not trusted further). It costs coverage only.
- Effectiveness: live. From `portal.php` alone, 159 pages and 304 forms; the
  security-level picker was never submitted.

### CC-CRAWL-0012 — The crawler logs in from its start URL (BUG-0113) (2026-10-13)
- Change: `LocalSpider._auth_base_url = start_url`, not its origin. `playwright_auth`
  marks it as operator input and scopes the injected cookies to the origin root.
- Impact: authenticated crawls of sub-path apps work, and pages outside the start
  page's directory receive the cookie.
- Risk: low.
- Deliverables:
  - [x] code — done
  - [x] tests (unit, plus a real-browser sibling-cookie test) — done
- Review: as CC-SESS-0016.
- Effectiveness: verified live (bWAPP).

### CC-CRAWL-0011 — NFR-CRAWL-safe built: no destructive link queued, redirected to, or requested by the browser (BUG-0111) (2026-10-13)
- Change: `tools/spider.py`:
  - destructive links and XHR URLs are not queued (`_destructive`, logged and counted
    in `skipped_destructive`);
  - the static engine follows redirects by hand (`navguard.get_checked`), each hop in
    scope and not destructive;
  - the rendered engine installs `navguard.guard_page`, which aborts destructive
    navigations, fetch/XHR and subresources;
  - the start URL is exempt in both modes;
  - pages open with `service_workers="block"`, because a worker's fetches bypass
    `page.route` (reviewer B). WebSockets are not routed, a stated gap.

  New `tools/navguard.py`.
- Impact:
  - **Behaviour change:** fewer pages crawled where links are destructive, and the
    static engine no longer auto-follows redirects;
  - **AUD:** the auditor shares `navguard`.
- Risk: low. It adds refusals only, and a real-browser test covers the route.
- Deliverables:
  - [x] spider and navguard — done
  - [x] tests: static (link, 302) and a real-browser crawl — done
  - [x] NFR-CRAWL-safe amended, with traceability — done
- Review: as CC-CORE-0038 (A1 and B1/B2 adopted).
- Effectiveness: verified, including under `FUZZLAB_REQUIRE_BROWSER=1`.

### CC-CRAWL-0010 — Full browser header set (not UA alone), so a real external WAF stops 403ing a UA/Accept mismatch (2026-09-25, BUG-0060/PA-0062, recurrence of CC-CRAWL-0009)
- **Change:** `LocalSpider.__init__`'s `requests.Session()` now applies
  `fuzzlab.core.http.DEFAULT_BROWSER_HEADERS` (UA + `Accept`/`Accept-Language`/
  `Sec-Fetch-*`/`Upgrade-Insecure-Requests`) instead of `DEFAULT_USER_AGENT` alone.
- **Why:** live-reported by the operator running the crawler against a real external,
  authorized test target — `403 Forbidden`, one layer past `CC-CRAWL-0009`'s own fix. A
  Chrome `User-Agent` paired with `requests`' own `Accept: */*` and no
  `Accept-Language` is an internally inconsistent request several WAFs specifically
  detect and reject; `CC-CRAWL-0009` fixed the UA alone, which surfaced this deeper
  layer of the same gap instead of closing it. Full RCA:
  `docs/bugs/BUG-0060-ua-header-mismatch-403-external-waf.md`. Preventive action:
  `PA-0062` (supersedes `PA-0061`). Confirmed with the operator that the affected
  targets are theirs/authorized before implementing, since this class of fix is
  dual-use (it makes traffic harder for a WAF to distinguish from a real browser).
- **Verification:** offline — inspected the prepared request headers from a
  `DEFAULT_BROWSER_HEADERS`-configured session directly; `tests/test_spider_scope.py`'s
  12 tests pass unchanged. Live re-verification against the operator's own target that
  returned the `403` is the operator's own follow-up.
- **Scope:** no interface/contract change (`requirements.md` unaffected).

### CC-CRAWL-0009 — Default browser User-Agent, so real external targets don't silently serve 0-link content (2026-09-25, BUG-0059/PA-0061)
- **Change:** `LocalSpider.__init__`'s `requests.Session()` now sets a realistic
  Chrome-on-Linux `User-Agent` (`fuzzlab.core.http.DEFAULT_USER_AGENT`, a new shared
  constant) instead of leaving `requests`' own default (`python-requests/x.y`). The
  Playwright/rendered engine is unaffected (a real headless Chromium already sends an
  authentic browser UA).
- **Why:** live-reported running a crawl from the web UI against a real external,
  authorized test target — `200 OK` on the start URL, 0 links discovered. Root cause: the
  default UA is trivially fingerprintable, and several real external sites serve
  reduced/interstitial content to it instead of real markup; the local lab never
  surfaces this since it doesn't discriminate by UA. Full RCA:
  `docs/bugs/BUG-0059-spider-default-ua-zero-links-external-targets.md`. Preventive
  action: `PA-0061`. The same sweep found and fixed 5 other bare, UA-unset
  `requests.Session()` instances across the codebase (`fetcher.py`,
  `blind_sqli_fuzzer.py`, `probesender.py`, `greybox/run.py`, `session/manager.py`) —
  see the CORE component's own log for the shared constant this entry and those all
  route through.
- **Verification:** offline — `tests/test_spider_scope.py`'s 12 tests pass unchanged.
  Live re-verification against the operator's own external target that originally
  showed 0 links is the operator's own follow-up (this sandbox's outbound network is
  proxied/restricted and cannot reach arbitrary external hosts).
- **Scope:** no interface/contract change (`requirements.md` unaffected) — an HTTP
  client fidelity fix, not a behavior/scope change to what the crawler follows.

### CC-CRAWL-0008 — Scope link-following to the start URL's host, not a hardcoded loopback allowlist (2026-09-24, BUG-0050/PA-0052)
- Change: `fuzzlab/tools/spider.py` — replaced `LocalSpider._is_local(url)` (which
  followed a link only if its hostname was `localhost`/`127.0.0.1`) with
  `_in_scope(url)`, scoped to the start URL's own host (`self._scope_host`,
  computed in `__init__` via the new `_norm_host` helper). Loopback aliases
  (`localhost`/`127.0.0.1`/`::1`) are treated as one host and `www.` is
  normalised, so apex/`www` and cross-alias lab links still match; third-party
  and other-subdomain links are still not followed (the "don't escape to the open
  web" intent is preserved). Both enqueue call sites (link + XHR) updated. Applies
  to both engines and, via the CLI, to the web-UI crawl.
- Why: pointed at any authorized non-loopback host, the old guard dropped **every**
  discovered link, so the crawler fetched only the start page and found nothing —
  reported by the operator crawling authorized live hosts via the web UI. See
  BUG-0050.
- Verification: new `tests/test_spider_scope.py` (12 cases: external same-host /
  subdomain / third-party / `www` / no-host / loopback aliases) — all pass.
  End-to-end: a 3-page same-host site is fully discovered on both the `requests`
  and `playwright` engines, while an embedded third-party link is correctly not
  followed. Full non-slow suite unaffected.
- Scope: `fuzzlab/tools/spider.py`, `tests/test_spider_scope.py` (new); requirement
  FR-CRAWL-7 added. See BUG-0050, PA-0052.

### CC-CRAWL-0007 — `--dry-run` CLI flag (lane D0a) (2026-09-22)
- Change: `fuzzlab/tools/spider.py::build_parser()` gained `--dry-run` (via the new
  shared `fuzzlab/cli_dryrun.add_dry_run_flag()`). The module's `__main__` block now
  checks `args.dry_run` first: if set, it calls `fuzzlab/cli_dryrun.report("crawl",
  args)` — which plans and prints the exact argv/display command via the web
  launcher's existing pure functions (`fuzzlab/web/commandspec.spec()` +
  `fuzzlab/web/runner.build_argv()`/`display_command()`, CC-UI-0013/0015) — and exits
  0 before `LocalSpider` is ever constructed. No crawl request is made. When
  `--dry-run` is absent, behavior is unchanged.
- Impact (other components / project): CRAWL only, plus an incidental UI effect — see
  CC-UI-0027 (the web launcher's per-tool option list is introspected straight from
  `build_parser()`, so the new `--dry-run` checkbox shows up there automatically, with
  no code change to `fuzzlab/web/app.py`). No schema/store change; the dry-run path
  never touches the spider DB or the store.
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect. Mitigated by `tests/test_cli_dry_run.py` (crawl cases: flag present, report
  printed, `LocalSpider.__init__`/`.crawl` patched to raise if called — confirming
  nothing executes) and the unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `crawl`'s parser — done.
  - [x] Short-circuit in `__main__` calling the shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab crawl --dry-run` prints
  the planned argv/command and exits 0 without constructing `LocalSpider` or making
  any request; verified directly and via the new tests.

### CC-CRAWL-0006 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/tools/spider.py` now factors its argparse setup into `build_parser()`
  (returns the `ArgumentParser`); `parse_args()` delegates to it. Added `prog="fuzzlab
  crawl"` for accurate usage. Behavior-preserving — same flags, defaults, and parsing.
- Impact: lets the web launcher introspect the crawler's flags (CC-UI-0011). No CLI
  behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()`; `parse_args()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds the crawler's spec
  from this parser.

### CC-CRAWL-0005 — Template dedup + hybrid-crawl decision (algorithms) (2026-09-21)
- Change: built two Phase 2 crawler algorithms as pure, tested `core/` modules.
  `core/dedup.py` (T2.6): DOM-skeleton MinHash + `TemplateClusterer` — near-duplicate
  pages (same structure, different data) get the same `template_cluster_id` so they
  are audited once. `core/hybrid.py` (T2.7): `needs_browser(html)` — decides whether
  a statically fetched page is client-rendered and must escalate to Playwright
  (conservative: escalate on doubt).
- Impact (other components / project): these reduce requests when wired into the
  crawl loop (audit-once-per-cluster; static-first, browser-on-demand). The
  algorithms are in `core/` (shared, dependency-light). Wiring into `spider.py`'s
  fetch loop — computing `template_cluster_id` from the fetched HTML and switching
  engines per page — is the next step (needs the live browser/lab to validate, and
  is measured by T2.8).
- Risk (level; mitigation): low (pure functions, tested). Dedup hiding a distinct
  page mitigated by clustering on skeleton (not content) with a tunable threshold;
  hybrid mis-classifying a JS page mitigated by conservative escalation. 6 unit
  tests (same-template clusters together; different templates separate; SPA/noscript
  escalate; static page does not).
- Deliverables:
  - [x] `dedup.py` (MinHash + clusterer) + tests (T2.6) — done.
  - [x] `hybrid.py` (`needs_browser`) + tests (T2.7) — done.
  - [ ] Wire into `spider.py` fetch loop (cluster id from HTML; engine switch) — todo (with T2.8).
- Effectiveness (assessed 2026-09-21): effective in unit tests — 5 same-template
  pages collapse to one cluster; SPA/noscript shells escalate while a text-rich page
  does not. Live request reduction measured in T2.8.

### CC-CRAWL-0004 — Authenticated Playwright crawl (cookie injection) (2026-09-21)
- Change: the crawler's Playwright engine now authenticates by injecting the
  session into the browser context. `LocalSpider` gained `session_manager`/
  `identity`; `_start_browser` ensures the session and injects cookies
  (`add_cookies`) or a bearer header (`set_extra_http_headers`) via a shared
  `fuzzlab/tools/browserauth.py`. Added a `--identity` flag (base URL derived from
  `--start`). Anonymous crawl unchanged. Completes the crawler side of Phase 0/1
  Option A (both static and browser paths now authenticate).
- Impact (other components / project): JS-rendered pages and the Discover-nav
  links are now crawled as an identity, so authenticated-only surface is
  discovered; depends on the session manager (#3) and credential store.
- Risk (level; mitigation): low–medium — injection runs once at browser start; a
  failed login fails loud through `ensure`. `browserauth` is Playwright-free and
  unit-tested (cookie → add_cookies, bearer → extra header); the live browser wiring
  is thin glue validated on a host with a browser + lab.
- Deliverables:
  - [x] `browserauth` helper; `_start_browser` injection; `--identity` — done.
  - [x] Unit tests for cookie/bearer injection — done.
  - [ ] Live authenticated crawl against the lab (T1.10) — todo (needs a browser + lab).
- Effectiveness (assessed 2026-09-21): effective in unit tests — the session is
  shaped and applied to a (fake) context for both schemes. Live crawl pending.

### CC-CRAWL-0003 — Consolidates into the unified store (2026-09-21)
- Change: added `--store PATH` to the crawler; after a crawl it consolidates its
  native `discovered_pages` output into the unified store via
  `fuzzlab/tools/store_adapter.import_spider`, writing `page`, `endpoint`, and
  `parameter` rows (URLs normalized to path form; query params captured). Native
  standalone output is unchanged when `--store` is omitted. Phase 0 T0.8.
- Impact (other components / project): the crawler now feeds the integration bus
  (D5); its pages/params are readable by the auditor, harness, and (later) ranker.
  Adapter-based for now; a future phase can make the crawl write directly.
- Risk (level; mitigation): low — opt-in and additive; covered by the
  consolidation end-to-end test (synthetic spider DB → page/endpoint/parameter).
- Deliverables:
  - [x] `--store` + `import_spider` (page/endpoint/parameter) (T0.8) — done.
  - [ ] Direct-to-store writes (drop the native DB) — todo (later).
- Effectiveness (assessed 2026-09-21): effective — a synthetic crawl of 5 pages
  populates 5 pages and 4 parameters in the unified store (test green).

### CC-CRAWL-0002 — Moved into the `fuzzlab` package (2026-09-21)
- Change: `spider.py` moved to `fuzzlab/tools/spider.py` and now imports `core/`
  (`get_logger`), emitting a structured startup line. Still writes its own SQLite
  file for now (T0.8 migrates it to the shared store). Part of Phase 0 T0.1.
- Impact (other components / project): the crawler is now a package module
  (`python -m fuzzlab.tools.spider`) importing the shared library; no behavior or
  output-format change yet.
- Risk (level; mitigation): low — a move plus one import; verified the module
  imports and `--help` runs.
- Deliverables:
  - [x] Move into package; import `core/` (T0.1) — done.
  - [ ] Write to the shared store (T0.8) — todo.
- Effectiveness (assessed 2026-09-21): effective — imports cleanly and runs as a
  package module.

### CC-CRAWL-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `spider.py` renders
  JavaScript via Playwright, captures fetch/XHR endpoints, resets/reuses its own
  SQLite results, and fixes the earlier port-scope bug. Standalone; not yet on the
  shared store or session manager.
- Impact (other components / project): feeds the auditor and fuzzer; currently
  writes its own database rather than the shared store, and crawls unauthenticated.
- Risk (level; mitigation): low. Present gaps (no shared store, no auth, no
  template dedup) are addressed in Phase 0 (store migration) and Phase 2
  (hardening); no current risk to other components beyond its own DB format.
- Deliverables:
  - [x] JavaScript rendering + XHR capture — done.
  - [x] Reset-by-default and `--resume`; port-scope fix — done.
  - [ ] Migrate to the shared store — todo (Phase 0 T0.8).
  - [ ] Session-manager integration + per-identity crawl — todo (Phase 1).
  - [ ] Template dedup, hybrid crawl, state-machine — todo (Phase 2).
- Effectiveness (assessed or pending): effective for JS discovery — verified that
  the Playwright engine finds all 10 JS pages the static engine missed. Remaining
  items pending.
