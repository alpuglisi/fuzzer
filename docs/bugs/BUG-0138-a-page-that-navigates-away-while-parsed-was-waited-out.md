# BUG-0138 — A page whose script navigates to a refused URL while it is parsed was waited out

- Date: 2026-10-15
- Status: fixed (CC-CRAWL-0030, CC-AUD-0043, CC-SESS-0024; CC-FUZZ-0083 amendment)
- Severity: medium. Coverage and cost: a page's content was read only through a second
  request, or not at all, after the full navigation timeout. There was no safety impact:
  the refused URL was never requested. A regression from BUG-0136 on the merged tree;
  never pushed.

## Description
Since BUG-0136 a navigation the guard refuses is aborted with `"aborted"`
(ERR_ABORTED), which keeps the current document. When a page's script navigates to a
refused URL **while the page is being parsed** (a head script setting
`location.href = '/logout'`), Chromium starts that navigation and stops the document's
loading. The refused navigation is aborted, so the document stays, but its parsing
never resumes: `domcontentloaded` and `load` never fire, and `document.body` stays null.
A real-Chromium probe confirmed each point: `requestfailed` for the main-frame
navigation 40 ms after the commit, `domcontentloaded` never reached, `readyState`
"complete", no body.

Every caller waited for those events, with the whole timeout:
- **the crawl:** `spider._goto_and_parse` used `page.goto(..., wait_until="domcontentloaded")`.
  It waited out `timeout_ms`, then the static fallback sent the page a second time (the
  SPA lane's repro: "blocked destructive … /logout" at 0.98 s, "Timeout 4000ms exceeded
  … falling back to a static request" at 4.95 s, `GET /` twice);
- **query windows:** a probe load timed out and kept nothing; a seed load failed and
  became a write seed;
- **the auditor:** `ContentFetcher.fetch` waited out its timeout too;
- **the browser login:** it waited out its own;
- **the rest of the spider:** the reveal window's restore, the re-adoption page, the
  anonymous submission, and the reloads all waited the same way.

Once the first wait was fixed, a second wait of the same kind showed:
`page.inner_text('body')` waits for a `body` element, and a document stopped in its
head never has one, so it cost Playwright's default 30 s.

## Where encountered
The SPA lane, on the merged tree (b5bf8c5: spa-query + origin-scope), with a loopback
`_Lab` whose head runs `location.href = '/logout'` and `timeout_ms=4000`.

## What it caused to fail
- **FR-CRAWL coverage and cost:** each such page cost `timeout_ms`, and then the
  static fallback sent it again (two requests where one was made).
- **FR-CRAWL-17:** a probe of such a route kept nothing, and a seed failed (a write
  seed, never a point).
- **FR-AUD-18:** the auditor waited out its timeout, then re-fetched the page.
- **FR-SESS-19:** the browser login waited out its timeout before failing.

## What the bug was identified to be
The wait for a navigation's load state was written separately at each call site,
always for the whole timeout, and with no notion that a refused navigation can cancel
the event being waited for.

## Root cause analysis
Five Whys:
1. *Why did the crawl take the whole timeout?* `goto(wait_until="domcontentloaded")`
   waited for an event that never came.
2. *Why did it never come?* The page's script navigated, while the page was parsed, to
   a URL the guard refuses. Starting that navigation stopped the document's loading,
   and ERR_ABORTED (BUG-0136) kept that stopped document instead of committing an
   error page.
3. *Why was the wait not bounded?* Every caller wrote its own `goto` or `reload` with
   the full timeout. PA-0137(2) ("never wait for an event a refused action can cancel:
   wait for what is certain, the commit, then bound the rest") was applied in
   `browserexec` only.
4. *Why only there?* BUG-0137's PA-0002 sweep was scoped to "every executor or browser
   call reachable from `oracle.confirm`", the path its symptom came from. The same wait
   existed at every other navigation in fuzzlab (the table below): in the crawler, the
   auditor and the browser login.
5. *Why did no test or guard catch it?* BUG-0136's real-browser tests made the script
   navigation after `load` (a timer), never during parsing. Nothing in the codebase
   enforced PA-0137(2).

**Root cause:** navigating a guarded page, and waiting for its load state, had no single
implementation. A rule about that wait (PA-0137(2)) was written generally, but swept
and enforced only on the path whose bug produced it.

## Corrective action
- **`tools/navguard.py`, one helper (CC-CRAWL-0030):**
  - `navigate(page, url, *, timeout_ms, wait_until, wait_ms)` and `reload(...)` wait for
    the **commit** only, so a refused or failed own target still raises (BUG-0136).
  - Then the load state is waited for in 100 ms steps: at most `wait_ms` (default
    `timeout_ms`, so a slow page is still waited for), suppressed, and no longer than
    `SUPERSEDED_GRACE_MS` (300 ms) after a main-frame navigation of the page fails
    (`requestfailed`). The result is a `Navigation(response, reached, superseded,
    committed_at)`.
  - `wait_for_state` applies the same rule to `networkidle`, and `load_state_reached`
    is a check, not a wait. `response_html(response)` returns the HTML the browser
    already received.
- **Callers:**
  - **spider (CC-CRAWL-0030):** every `goto` and `reload`, including the `about:blank`
    leaves. `_goto_and_parse` waits for `networkidle` only after a completed load, and
    reads the body text with `evaluate`, never by waiting for a `body`.
    - A page whose load did not complete is read from `response_html`. Its title, text
      and links are parsed as the static engine parses a page and merged with the DOM's
      links, and `_last_html` is that HTML. There is no second request.
    - `_rendered_ok` is set only for a completed load, so reveals never act on a
      stopped document.
    - Query probes and seeds use the same path.
  - **auditor (CC-AUD-0043):** `ContentFetcher.fetch` likewise, and returns the
    response's HTML for a load that did not complete.
  - **browser login (CC-SESS-0024):** the base page and the login routes. A page that
    navigates away while it is parsed has no form, so the login fails loudly ("no
    login form was found"), and fast.
  - **M6 executor (CC-FUZZ-0083 amendment):** the plant and the observe navigation use
    `navigate(..., wait_until="load", wait_ms=LOAD_WAIT_MS)`, and the load check uses
    `load_state_reached`. Its semantics are unchanged, except that a superseded load
    ends 300 ms after the refusal instead of at `LOAD_WAIT_MS`.
- **Enforcement:** `tests/test_guarded_navigation.py::test_every_guarded_navigation_goes_through_the_one_helper`
  is an AST guard. Outside `tools/navguard.py`, no module of fuzzlab calls `goto`,
  `reload`, `go_back`, `go_forward`, `wait_for_navigation`, `expect_navigation`,
  `wait_for_load_state` or `wait_for_url` on anything but the `navguard` module. It is
  proven on seven synthetic offenders.
- **Tests (real Chromium, `tests/test_guarded_navigation.py`):**
  - the crawl reads the head-script page in about 2 s (timeout 8 s), with `GET /`
    once, its content and its `/next` link kept, and the refusal recorded;
  - a slow page (a 2.5 s script) is still read whole;
  - a query lab's `/trap` seed and its probe each load once, quickly, and the seed's
    content and link are kept;
  - the auditor returns quickly with the page's HTML from one request;
  - the browser login fails loudly in about 2 s (its timeout is 10 s).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0137 / PA-0137(2)**, "a wait is never for an event a refused action can
  cancel: wait for what is certain, the commit, then bound the rest". **A recurrence**:
  the same defect class, in the callers BUG-0137 did not sweep.
- **BUG-0136 / PA-0136.** The trigger: ERR_ABORTED keeps the document, and a document
  stopped while parsing never loads. BUG-0136's own review measured the M6 side
  (CC-FUZZ-0082) but tested only after-`load` navigations elsewhere. Not a recurrence
  of BUG-0136's defect (the abort code is right); its consequence was not followed to
  every waiter.
- **BUG-0128** (teardown hangs while a page navigates). The same navigation lifecycle,
  but a different wait (`unroute_all`), already bounded. Not a recurrence.

## Prior-preventive-action failure analysis
- **PA-0137(2)** did not prevent this because:
  1. **Too narrow in application.** Its text is general, but BUG-0137's PA-0002 sweep
     was scoped to the oracle path, so the rule was applied only to `browserexec`. The
     crawler, the auditor and the browser login, which make the same wait, were never
     examined.
  2. **Not enforced.** Nothing in the codebase checked the rule; it relied on each
     author remembering it at each `goto`.
- **PA-0136(3)** ("a fix of one branch of a shared mechanism sweeps every sibling
  branch") did not prevent it either: its notion of a sibling was the branches of the
  one mechanism (the route handler's abort sites), not the other consumers of the
  behavior it changed.

PA-0138 makes the rule structural: one helper, with an AST guard. It also states that
the sweep for a rule about a primitive (here `goto` and its waits) covers every caller
of that primitive, not the path its bug came from.

## Preventive action
**PA-0138** (strengthens PA-0137(2) to a codebase-wide, enforced rule; widens PA-0136(3)
and PA-0002 for rules about a shared primitive), in `docs/PREVENTIVE_ACTIONS.md`.

### PA-0002 sweep (every navigation and load-state wait in fuzzlab)
| Site | Before | Disposition |
| --- | --- | --- |
| `spider._goto_and_parse` (crawl pages; query seeds through `_fetch_rendered`; probes) | `goto(domcontentloaded)`, full timeout; then `networkidle`, full timeout; then `inner_text('body')`, 30 s default | **fixed**: `navigate`; `networkidle` via `wait_for_state` after a completed load only; body text read without waiting; the response's HTML when not loaded |
| `spider._fetch_rendered` failure path | `goto("about:blank")` | `navigate` (instant) |
| `spider._window` close failure | `goto("about:blank")` | `navigate` |
| `spider._restore` (reveal window) | `goto` + `reload(domcontentloaded)` | **fixed**: `navigate` + `navguard.reload` |
| `spider._leave` (seed/probe window exit) | `goto("about:blank")` | `navigate` |
| crawl loop, query load start | `goto("about:blank")` | `navigate` |
| `spider._after_query_window` re-adoption page | `goto(domcontentloaded)` | **fixed**: `navigate` |
| `spider._submit_anonymously` | `goto(domcontentloaded)` | **fixed**: `navigate` |
| reveal clean reload; `_readopt_session` reload | `reload(domcontentloaded)` | **fixed**: `navguard.reload` |
| `fetcher.ContentFetcher.fetch` | `goto(domcontentloaded)` + `networkidle` | **fixed**: `navigate`; `wait_for_state`; the response's HTML when not loaded |
| `fetcher` failure path | `goto("about:blank")` | `navigate` |
| `browserlogin._drive` base page; login routes | `goto(domcontentloaded)` | **fixed**: `navigate` |
| `browserexec` plant and observe | commit + `wait_for_load_state(load, LOAD_WAIT_MS)` (BUG-0137) | the one helper (`navigate(wait_until="load", wait_ms=LOAD_WAIT_MS)`), ended 300 ms after a refusal |
| `browserexec._loaded` | `wait_for_load_state(load, 1 ms)` | `navguard.load_state_reached` |
| clicks (`spa.click_vetted`, `page.click`) | Playwright waits for a click's navigation to start, not to load | not this class |
| selector waits after a navigation | `inner_text('body')` (above); `browserlogin._pick_form`'s `is_enabled` runs only on a control the form scan found | the first fixed; the second not this class |
| `tests/` | tests drive Playwright directly | outside the guard (test code) |

## Residuals
- A page whose `domcontentloaded` really takes longer than `timeout_ms` (not
  superseded) is now read from its response's HTML instead of a second, static request.
  That is no less content and one request fewer, but it is a behavior change, stated in
  CC-CRAWL-0030 and CC-AUD-0043.
- A failed main-frame navigation of the **previous** page that is reported during a new
  navigation's wait would cut that wait to 300 ms. The page is then read from its
  response's HTML, so content is not lost. A failed load already leaves for
  `about:blank` (BUG-0136 X1), and a query load starts there; this has not been seen.

## Review of the fix (added in review)
Reviewer A agreed, after verifying live that reading the response HTML cannot hang.
Reviewer B agreed with changes (D58). Q1, Q2 and Q4 are done here. Q3, a hash seed
whose bare-route load did not reach, waits for the SPA lane's merge.
- **Q1, which failures count.** The first cut counted every main-frame navigation
  failure from the start of `goto`. A previous page's pending navigation, cancelled by
  this one and reported before its commit, could cut a normal load to 300 ms. Now only
  failures reported at or after the commit count: the helper arms itself when
  `goto(commit)` returns. In 40 of 40 real-Chromium runs a head script's refusal was
  reported after that return.
- **Q2, which content.** The first cut read every not-completed load from the
  response. That lost a slow page's JS-rendered text, and when an allowed script
  navigation had committed another document it mixed that document's title, links and
  URL into this URL's row. Now there are three cases: superseded (the received HTML
  with the DOM's links), merely slow (the live DOM), and another document (this URL's
  received HTML alone).
  - **Found while building it:** Chromium drops the replaced document's response body
    before `goto(commit)` returns, so `response.text()` is already gone. The body
    therefore comes from the guard, which fetched and fulfilled it
    (`_note_received`).
- **Q4:**
  - the reveal restore leaves for `about:blank` when its reload did not complete;
  - the AST guard also forbids `set_content`, `wait_for_event` and `expect_event`.

Residual added in review (A-N2): **a script that starts a download while the page is
parsed** was not measured. The download's navigation may or may not be reported as a
failed main-frame navigation. Either way the wait is bounded by the caller's timeout,
and the page is read from what it has: superseded, its received HTML; otherwise, its
live DOM.

### Review of 8350ab1 (added in review)
Both reviewers agreed. Three small fixes (CC-CRAWL-0030 and CC-AUD-0043 amendments):
- **The document key (reviewer A).** `url_key` drops the query, so a head script that
  navigated `/p?a=1` to `/p?a=2` looked like the same document, and `/p?a=2`'s title,
  links and final URL filled `/p?a=1`'s row. `core.urls.document_key` (origin, path,
  query) is now the one key for the spider's own-reload check and the guard's document
  checks.
- **Arming (reviewer B).** The failure watch arms on the main frame's own commit
  (`framenavigated`), with `goto`'s return as a fallback. So it no longer relies on a
  refusal being reported after `goto` returns: in 20 of 20 real-Chromium runs the
  commit armed it first.
- **The fetcher's empty body (reviewer B).** When a merely slow page has no body yet,
  the fetcher returns the received HTML, as the spider does.
