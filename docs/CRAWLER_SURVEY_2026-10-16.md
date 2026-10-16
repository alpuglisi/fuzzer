# Crawler survey: what six open-source crawlers do about discovery (2026-10-16)

Owner's request: six agents each chose a different open-source crawler on GitHub, then
studied how it crawls and discovers. This is the synthesis for the owner, who decides
which options are viable. Nothing here is built yet.

Ledger item `CRAWLER-SURVEY`. Each agent only read code: nothing was built, installed or
run against anything. The clones are scratch and are not in this repository.

## The six codebases

| # | Crawler | Commit read | Language | License | What we may take |
| - | --- | --- | --- | --- | --- |
| 1 | projectdiscovery/katana | 3e65064 | Go | MIT | ideas; code with notice (DevTools helpers are BSD) |
| 2 | apify/crawlee | 02899241 | TypeScript | Apache-2.0 | ideas; code with notice |
| 3 | zaproxy/zap-extensions (Client, classic, AJAX spiders) | 5ba9c672 | Java | Apache-2.0 | ideas; code with notice |
| 4 | SecuringWeb/BlackWidow | 19d813c | Python + JS | none (all rights reserved); JS is GPLv3 | **ideas only** |
| 5 | wapiti-scanner/wapiti | 1e816981 | Python | GPL-2.0+ | **ideas only** |
| 6 | Qianlitp/crawlergo | 38b6364 | Go | GPL-3.0 | **ideas only** |

fuzzlab is proprietary (pyproject). The recommendation for every option below is a
clean-room reimplementation from a written description; nothing is ported.

## The measured losses the survey was aimed at

From the baseline runs (CHANGELOG 2026-10-16; generic command line, rules on):

1. **No SPA form is submitted** on Juice Shop. 9 of the 15 answer-key cases are POST
   bodies. The crawl revealed 0 forms; SPA forms are submitted only on routes named with
   `--submit-spa-forms`, which a generic command line does not name.
2. **bWAPP picker navigation.** The crawl reached 5 pages. Its pages are behind a
   "choose your bug" POST picker; `formnav` enumerates options only with
   `--follow-selector-forms <select>`, and only through cookie-less 3xx answers.
3. **Realtime noise demotes query seeds.** Juice Shop's crawl log: "0 request(s) blocked
   by their window; 6 seed(s) kept as pages, never points". Each of the 6 demoted seeds
   (`#/search?q=` among them) had exactly 4 WebSocket messages dropped in its window, and
   no HTTP write. 75 WebSocket messages were dropped in the run.

### What the evidence settles about problem 3

All six agents independently pointed at the same fuzzlab code, and five guessed the
cause was socket.io *polling POSTs*. The run log says otherwise: it was **WebSocket
messages**.
- `_note_ws_drop` (`tools/spider.py:763`) counts each held WebSocket message as a write
  with method `WS` (`_count_query_write`, `spider.py:778`).
- That write is exempt only if `("WS", url)` is in the route's baseline. The baseline
  gets a WebSocket key only when a message happens to be sent while the bare route is
  loading (`_note_ws_send`, `spider.py:772`; `_goto_recording`, `spider.py:1308-1320`).
- `_count_query_write` never consults `spa.is_transport_url` (`tools/spa.py:265`), which
  `_observe` does use.

*Inferred, not measured:* socket.io's pings are periodic, so whether one lands inside
the baseline load is timing. This is the R2 premise to test in the regression.

## Ranked options

Ranking: evidence that it moves a measured loss first, then effort and risk. "Agents"
lists who proposed it. Effort: S = hours, M = a day or two, L = more.

### 1. Transport-aware write counting (problem 3) — S, evidence-backed
- **What:** in `spider._count_query_write`, an untainted write to a transport URL
  (`spa.is_transport_url`: socket.io / engine.io, including the WebSocket) is counted
  as a baseline write wherever and whenever it occurs, not only if the bare-route load
  happened to see it. It is still blocked (W3 unchanged). A write that carries the
  load's own query values (taint rule B2) still counts and still demotes.
- **Agents:** katana, Crawlee, ZAP, Wapiti, crawlergo (5 of 6). ZAP's principle is the
  general one: background traffic never cancels a discovery.
- **Expected effect:** the 6 demoted Juice Shop seeds become points (`#/search?q=` is
  one); measure the metric afterwards, do not assume it.
- **Acceptance (R3):** the diagnostic regression from the recorded Juice Shop trace,
  plus independently authored variants: a socket.io app with only polling, one with only
  WebSocket, and a tainted transport message that must still demote.
- **Policy:** no rule is loosened (nothing more is sent). Low risk to the write gate,
  but it touches the window's U1/B2 logic, so CRAWL review.

### 2. Readiness that ignores transports (cost, all problems) — S
- **What:** `_track`/`_settle` (`spider.py:972-994`) count every in-flight request, so a
  long-poll or a transport request holds a settle to its 5 s budget. Leave transport
  URLs (and WebSocket/EventSource) out of the in-flight count, as ZAP's adaptive wait
  counts in-scope requests only; optionally add katana's URL-change poll.
- **Agents:** katana, ZAP, Wapiti (inferred cost), Crawlee (its own wait has the bug).
- **Expected effect:** shorter crawls, fewer settles that time out; it does not by
  itself add a point. Measure crawl time and settle timeouts before and after.

### 3. Record refused writes as "discovered, unsent" requests (problems 1 and 2) — S–M
- **What:** when the window aborts a write (an XHR/fetch, or a non-GET navigation such
  as a picker POST), record the request in full — method, URL, content type, nested body
  — through `StorageManager.record_request` with a new source (e.g. `blocked`). Today it
  is counted and its URL kept, but its body is lost (`spider.py:691-754`).
  `store_adapter`'s import rules (`request_refusal`, credential and transaction rules)
  then decide whether it may become a point. Nothing extra is sent.
- **Agents:** Crawlee (capture-and-abort), crawlergo (POST navigation recorded), ZAP and
  Wapiti (full capture at the proxy).
- **Expected effect:** JSON endpoints and form bodies that the crawl now discards become
  candidates. Whether they reach the answer key's POST cases is the measurement.
- **Policy:** the import side must keep D71's rules. A recorded-but-unsent request is
  new data in the store, so it needs a store-contract note (ARCHITECTURE) and the
  redaction boundary (PA-0100) applied to bodies.

### 4. Picker handling for a generic command line (problem 2) — M, owner decision
- **What, in two parts:**
  - (a) when a picker's submission answers 200 with HTML instead of a redirect, parse the
    answer as a page in the isolated client instead of stopping (`formnav.py:155-157`);
    ZAP, Black Widow, Wapiti and crawlergo all follow the resulting page.
  - (b) let a generic run enumerate POST pickers without naming the select, behind the
    existing settings-word, destructive and cookie gates.
- **Agents:** ZAP, Black Widow, Wapiti, crawlergo. No surveyed crawler enumerates every
  option; fuzzlab already does, so only the gating differs.
- **Unverified premise:** whether bWAPP's `portal.php` answers 3xx or 200, and whether
  it sets a cookie. Check this on the lab before building (R2).
- **Policy:** (b) changes a send gate (FR-CRAWL-8 was gated on purpose by reviewers A/B).
  The owner decides; if yes, it becomes a D71-style switch or a new default.

### 5. Nested-body dedup signature and non-secret headers (capture fidelity) — M
- **What:** `record_request`'s signature uses top-level JSON keys only
  (`spider.py:170-171`), so two bodies with different nested shapes collapse. Use sorted
  leaf paths. Optionally store an allowlist of non-secret request headers (full
  Content-Type, X-Requested-With, custom API headers), never credential values.
- **Agents:** ZAP, Wapiti, crawlergo (value-type marks), Crawlee (method+payload key).
- **Policy:** headers touch the redaction boundary (PA-0100) and D12.

### 6. More SPA form candidates (problem 1) — M
- **What, in two parts:**
  - (a) an init script records which elements get `click`/`submit`/`keydown` listeners
    (hooked `addEventListener` and `on*` setters), feeding `FORMS_JS` and reveal
    candidates;
  - (b) a container with typed controls but no button is submitted by Enter in its last
    field, behind `form_refusal`, the window and the caps.
- **Agents:** crawlergo and Black Widow (listener hooks; both GPL/unlicensed, so written
  from scratch), Black Widow (Enter submit). katana has the hooks but never turns them on.
- **Caveat:** problem 1 on Juice Shop is, first, the generic command line: SPA forms are
  submitted only on named routes. These candidates matter once SPA form submission runs
  without naming routes — which is itself an owner decision about a send gate (same
  kind as 4b).

### Lower priority (no measured loss behind them yet)
- **Retry when a control becomes enabled** (ZAP) — a "no enabled button" result
  (`spider.py:1817`) re-reads the form after the fill. M.
- **Path replay / state graph** to reach forms shown only after earlier steps (katana,
  Black Widow, ZAP). M–L.
- **DOM-stable (MutationObserver) quiet window** in `_settle` (katana's own TODO). S–M.
- **URL fingerprint and pattern caps** against ID explosion (katana trie, Wapiti pattern
  caps, crawlergo type marks). S each.
- **Soft-404 / catch-all probe per directory** for history-mode SPAs (Wapiti). S–M.
- **Value-based source/sink attribution** with minted markers (Black Widow) — stored
  injection sinks. M.

## What none of them should be copied for

Every surveyed crawler is less careful than fuzzlab on safety. Not to adopt, by
consensus:
- auto-accepting `confirm()`/dialogs (katana, Black Widow);
- `--disable-web-security` (Black Widow, crawlergo);
- letting every XHR through, blind clicking, filling every input on the page, random
  values (Crawlee, ZAP AJAX, Wapiti, crawlergo);
- substring or regex logout lists as the only gate;
- pass-through scope for off-host requests (ZAP default);
- URL-only or length-only dedup (katana, Crawlee, Wapiti);
- rewriting `setInterval` or speeding timers (crawlergo, katana), which changes the app
  under test;
- cookie-only sessions (Wapiti), which miss Juice Shop's localStorage token;
- replaying a `fetch` POST as a GET (katana's hybrid engine, crawlergo's fetch hook bug).

## Side findings from the same run log (not from the survey)
- Every Juice Shop page's reveal refused the language menu (`aria-label settings-like
  ('language')`). That is the intended settings rule.
- `#/saved-payment-methods` refused a reveal on the account word `new`. That may be too
  broad for a credential rule; worth checking under D71's later reconciliation.

## Open questions the owner may want answered before choosing
- bWAPP `portal.php`: 3xx or 200, and does it set a cookie? (decides option 4a)
- With option 1 in place, how many of the 6 demoted seeds become confirmed findings?
- Whether SPA forms and POST pickers should run under a generic command line at all
  (options 4b and 6 change send gates).

## Correction (2026-10-16, after the options were built and measured)

The problem-3 mechanism above was wrong (F-063). A traced Juice Shop crawl read the
WebSocket messages that demoted the six query seeds. Every one was Juice Shop's
`42["verifyLocalXssChallenge","<the seed's own value>"]`: the app sends the query
value to its server. Rule B2 counts such a write, as designed, whatever the baseline.
Timing had nothing to do with it.

- Option 1, as narrowed by the review, exempts only engine.io control packets, and it
  never fired on Juice Shop (`spa_query_baseline_writes` = 0).
- Whether a seed whose app reports the query value to its own server should stay a
  "write seed" is a policy question for the owner. Today it does: loading it outside a
  window sends that value to the server.

Measured at 49e0768 (generic command line, rules on), against the baseline at f69e3c7:

| Lab | Confirmed | Reached | Crawled pages |
| --- | --- | --- | --- |
| Juice Shop | 5/15 (was 4) | 7/15 (was 6) | 87 (was 61) |
| bWAPP | 0/55 (unchanged) | 0/55 | unchanged |

- The new Juice Shop case is JUICE-0004 (DOM XSS, `#/search` `q`). It came through a
  crawled `#/search?q=` link, not through a seed.
- Its likely source is option 6's listener-found reveal targets: 60 reveal clicks
  instead of 12, and 23 navigations captured instead of 4. Which click produced the link
  is not traced.

**Repeat (388d073):** Juice Shop confirmed 4/15, and no `#/search?q=` link was crawled
(42 reveal clicks, against 60). The 5/15 above did not repeat, so no effect on the
metric is established (F-064).


## Why the metric is not moving (stall diagnosis, STALL-0016, 2026-10-16)

The goal metric is Juice Shop positives confirmed by one generic command line. It has
stayed at 4/15 for 11 h. The causes, measured today:

| Loss | Cases | Cause | Blocked on |
| --- | --- | --- | --- |
| Search-style pages discarded | `q`-style fragment cases | Juice Shop sends `verifyLocalXssChallenge` with the query value, and rule B2 counts it as a write | owner decision (question 2: keep, flag, or allow) |
| SPA forms never submitted | 9 POST-body cases | SPA forms are submitted only on routes named with `--submit-spa-forms`, which a generic run does not name | owner decision (option 4b / 6 send gate) |
| bWAPP pages unreached | 55/55 | the "choose your bug" POST picker is enumerated only for a named select | owner decision (option 4b) |
| Run-to-run variance | JUICE-0004 | reveal discovery differs between runs (42-60 clicks), so a case reached through a reveal comes and goes | engineering, possible without a decision: make reveal order and caps deterministic |

The survey options built today (1, 2, 3, 5, 6) are safe and verified. Measured on
Juice Shop, none moves a confirmed case reliably; the gains left need the decisions
above. Separately, an existing safety escape in M6 (a refused navigation after a hit,
under load) needs a formal CAPA (ERROR_LOG, open).
