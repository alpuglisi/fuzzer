# Crawler / Spider — Change Control Log

Component code: **CRAWL**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-CRAWL-0007 — Wire template dedup + hybrid engine into the fetch loop (2026-09-22)
- Change: `fuzzlab/tools/spider.py` now wires the two Phase 2 algorithms from
  CC-CRAWL-0005 into the live crawl loop, completing that entry's deferred
  "wire into spider.py fetch loop" deliverable (T2.8). Every fetcher
  (`_fetch_static`, `_goto_and_parse`, `_fetch_rendered`) now returns a 7th
  tuple element, `raw_html` (the unparsed HTML, `None` for non-HTML
  responses); `crawl()` feeds it through a per-crawl `TemplateClusterer`
  (`self._clusterer`) and persists the resulting `template_cluster_id` via a
  new `discovered_pages` column (added by `StorageManager._init_db()`'s
  existing ALTER-TABLE upgrade path, so older result databases pick it up
  automatically). Added a new opt-in `--engine hybrid`: fetches static first,
  and only escalates a specific page to a lazily-started Playwright browser
  when `core.hybrid.needs_browser()` says the static HTML looks
  client-rendered; the existing `auto`/`playwright`/`requests` engines are
  behavior-unchanged (same fetch path, same `rendered` flag semantics). The
  `finally` block's browser-teardown condition changed from `engine ==
  "playwright"` to `self._pw is not None` so a hybrid crawl that never
  escalated closes cleanly, and one that did still tears its browser down.
- Impact (other components / project): crawls now cluster near-duplicate
  pages (a future auditor pass can read `template_cluster_id` to audit one
  representative per cluster instead of every page) and `--engine hybrid`
  gives a cheaper default than always launching a browser, without touching
  callers of the existing engines or `store_adapter.import_spider` (which
  only reads `url`/`status_code`/`source`, unaffected by the new column).
- Risk (level; mitigation): low — purely additive (new column, new opt-in
  engine value); the three existing engines take the same code paths as
  before, just returning one more tuple element they already had access to
  internally. Mitigated by `tests/test_spider.py` (new; no prior coverage of
  this file): `StorageManager` persists/upgrades `template_cluster_id`
  (including an old-schema DB missing the column); `_fetch_static` captures
  raw HTML; same-skeleton pages cluster together across a crawl while a
  structurally different page does not; the hybrid engine escalates only the
  page that needs it, never starts a browser when nothing needs one, and
  never escalates when Playwright isn't installed; `requests`/`playwright`
  regression checks confirm the `rendered` flag is unchanged.
- Deliverables:
  - [x] `template_cluster_id` column + `StorageManager` read/write — done.
  - [x] `raw_html` threaded through all three fetchers — done.
  - [x] `--engine hybrid` (static-first, lazy browser escalation) — done.
  - [x] `tests/test_spider.py` (10 tests) — done.
- Effectiveness (assessed 2026-09-22): effective in unit tests — clustering
  and hybrid escalation behave as designed against synthetic HTML; live
  request-reduction measurement against the lab is still open (needs a
  browser + lab, consistent with CC-CRAWL-0005's own note).

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
