# BUG-0152 — JSON API probes went out with a top-level navigation's headers

- Date: 2026-10-15
- Status: fixed (CC-CORE-0061, CC-FUZZ-0090); combined design and code review pending
- Severity: medium. An app that negotiates its error representation on `Accept`
  answered a JSON API probe with a generic HTML page, and the oracle never saw the
  error detail its own client receives. No lost finding on a real run is attributed to
  this defect (see "What it caused to fail").

## Description
The requests-based probe senders open a `requests.Session` whose default headers are
`core.http.DEFAULT_BROWSER_HEADERS`. That set is what a browser sends for a top-level
**navigation**:
- `Accept: text/html,application/xhtml+xml,…`;
- `Sec-Fetch-Dest: document`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-User: ?1`;
- `Upgrade-Insecure-Requests: 1`.

It went on every probe, JSON-body API probes included. A browser never sends a JSON
body that way: an HTML form can submit only urlencoded, multipart or text/plain bodies
(HTML §4.10.21.7), so a JSON body always comes from a script's `fetch()` or XHR, with
the fetch header set.

## Where encountered
- Recorded as a residual in BUG-0119's review round 1 (reviewer A, S5) on the unmerged
  branch `bug-0118-v3`, and not followed up (`docs/claude_juicelab_failures.md`
  F-043).
- The JSON-SEND design (session scratchpad, `json-send/design.md`) reports a by-hand
  observation on the Juice Shop development lab: with `Accept: application/json`, the
  login SQLi payload's response carries the database error; with the navigation set,
  a generic HTML 500. That observation was not repeated here, and no lab was contacted
  for this fix.

## What it caused to fail
- **Every JSON-body probe** through `RequestsProbeSender` carried the navigation set.
  That covers JSON-leaf points (`location == "json"`, FR-CORE-36) and whole-body points
  declared `application/json` or `+json`. It is the unauthenticated `auto` path and
  every multitarget run.
- **Hidden evidence.** A framework that negotiates on `Accept` (RFC 9110 §12.5.1)
  answers a navigation with its HTML error view. `tests/test_browser_header_profiles.py`
  builds four such apps from their frameworks' documentation (table below). Under the
  navigation set, all four answer the JSON probe with the generic page:
  `test_the_navigation_set_hides_the_json_evidence`.
- **End to end:** at a JSON-body point of a Spring-style app, M2 (`SqliErrorStrategy`)
  confirms only with the fetch set and does not confirm with the navigation set
  (`test_the_sqli_oracle_confirms_a_json_point_only_with_the_fetch_set`).
- **Not established:** that this caused JUICE-0003's loss. F-018 records that the
  2026-10-15 baseline never sent that probe (the BUG-0118 gate refused it). This bug is
  a general defect, not that loss's cause.
- **Not affected on this branch:** `SeamProbeSender` (the authenticated path).
  `HttpClient.send` adds no browser set here (BUG-0119 is unmerged), so its probes
  carry `requests`' own defaults (`Accept: */*`).

## What the bug was identified to be
There was one browser header set, and it described one kind of request. The senders
had no notion of which kind of request a probe is. A JSON API probe was presented as
a document navigation: a request no browser makes.

## Measurement (CLAUDE.md #8)
**Method.** Real Chromium 141.0.7390.37 drove a loopback recorder
(`ThreadingHTTPServer` on 127.0.0.1, port 0) that logs each request's header lines in
wire order. It was run with both the full build
(`/opt/pw-browsers/chromium-1194/chrome-linux/chrome`) and the headless shell, through
Playwright with `PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers`. The page performed:
- a same-origin `fetch()` POST with `Content-Type: application/json`;
- a `fetch()` GET;
- an `XMLHttpRequest` POST of JSON;
- a typed navigation (`page.goto`);
- a link click;
- a form POST.

The script is `json-send/measure/measure.py` in the session scratchpad. The raw
results are `chrome.json` and `shell.json` beside it.

**Same-origin `fetch()` POST of JSON** (XHR POST: identical):
```
Content-Type: application/json
Accept: */*
Origin: http://127.0.0.1:<port>
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:<port>/start
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-US,en;q=0.9          (full build; the headless shell sends none)
User-Agent: Mozilla/5.0 (X11; Linux x86_64) … HeadlessChrome/141.0.0.0 Safari/537.36
sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform
```
There is no `Sec-Fetch-User` and no `Upgrade-Insecure-Requests`. A `fetch()` GET
sends the same set without `Origin` and `Content-Type`.

**Top-level navigation** (typed):
```
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding / Accept-Language / User-Agent / sec-ch-ua*  (as above)
```
A link click or form POST has the same set with `Sec-Fetch-Site: same-origin` and a
`Referer`. A form POST also carries `Origin`, `Cache-Control: max-age=0` and its own
`Content-Type`.

**The fetch profile built from this** (`core.http.FETCH_HEADERS`):
- `Accept: */*`, `Sec-Fetch-Dest: empty`, `Sec-Fetch-Mode: cors`,
  `Sec-Fetch-Site: same-origin`;
- the navigation set's User-Agent and Accept-Language, so the two profiles present one
  client.

**Measured differences not adopted** (residuals; changing the navigation set was out
of this change's scope, and PA-0062 makes such a change an operator decision):
- the set's `Chrome/124` User-Agent against the measured `141`;
- no `sec-ch-ua*` client hints;
- `image/apng` and `signed-exchange` are absent from the navigation `Accept`;
- `Sec-Fetch-Site: none` (a typed URL) even where a browser would send `same-origin`
  (a link or a form);
- no `Origin` or `Referer` on either profile.

## Design correction (an error in the JSON-SEND design)
The design gave the fetch profile `Accept: application/json, text/plain, */*` "as
Chromium sends them". That is wrong. It is the default of the axios and Angular
HttpClient libraries, which an app's own client code sets. The browser's own
`fetch()`/XHR sends `Accept: */*` (measured above, and the Fetch standard's default
for an empty destination). The value was written from memory, not measured. The
measurement step required by CLAUDE.md #8 caught it before implementation.

The coordinator decided (2026-10-15) to use the measured value, not the design's.

## What the measured profile reveals: the negotiation table
Each row follows its framework's documentation, as modelled in
`tests/test_browser_header_profiles.py`:

| Style | Documented rule | `*/*` (fetch, measured) | navigation | `application/json` |
|---|---|---|---|---|
| Spring Boot `BasicErrorController` | "handle `text/html` specifically and provide a fallback for everything else" (JSON for machine clients) | **JSON** | HTML | JSON |
| Django REST Framework renderers | with `*/*` "select the first renderer in the list" (`JSONRenderer` by default); more specific types win | **JSON** | HTML | JSON |
| Express `res.format` (html first, as in Express's `examples/error-pages`) | with `*/*` "the response will be" the first handler's | HTML | HTML | JSON |
| Rails `respond_to` (html first, as in the jbuilder scaffold) | `negotiate_mime` returns `order.first` for `*/*`; a list containing `, */*` is "browser-like" and gets HTML unless the request is an XHR | HTML | HTML | JSON |

So the fix reveals the JSON detail for Spring- and DRF-style apps. For html-first
Express- and Rails-style apps, the browser's own `Accept` does not reveal it. Only the
app's own client `Accept` does, and that is per app, not per browser.
- Those two rows are **strict xfails** in `test_a_json_probe_gets_the_json_evidence`.
- `test_the_apps_own_accept_reveals_the_evidence_in_every_style` shows that a caller's
  `Accept` wins and reveals the detail in all four styles. That is the hook the
  follow-on uses.

The design's value would not have served Rails either: Rails treats
`application/json, text/plain, */*` as browser-like and answers HTML
(`test_the_designs_accept_is_a_browser_accept_to_rails`).

**Named follow-on:** replay the app's captured `Accept` per endpoint (DISC-CAPTURE).
- The crawler's request capture records what the app's own client sent.
- Passing it as the probe's header wins over the profile (`with_browser_headers`).
- It needs the captured header carried to the point and the sender, which is
  `fuzzlab/harness/*` and DISC-CAPTURE's work, not this change's.
- Plumbing a request `kind` from discovery (XHR-observed endpoints) is a second
  follow-on.

## Root cause analysis
**Method: Five Whys.**
1. Why did a negotiating app hide the JSON error detail? Because the probe's `Accept`
   preferred `text/html`, and its `Sec-Fetch-*` declared a document navigation.
2. Why did a JSON probe carry that? Because the senders' sessions carried one browser
   set, `DEFAULT_BROWSER_HEADERS`, as defaults for every request.
3. Why only one set? Because BUG-0059/BUG-0060 (PA-0061/PA-0062) introduced the set to
   make crawler traffic look like a browser. A crawler's requests are navigations, so
   one navigation set fitted, and the rule spread to every `requests.Session()`,
   probe senders included.
4. Why did the rule not ask which kind of request each send is? PA-0062 asks whether
   "every header a real client **of the claimed kind** would set is internally
   consistent". It took the kind as given, one per client. PA-0111's rule-by-rule
   emulation, with a rule table, was enforced for form serialisation only, never for
   headers. Nothing tested the header set against a browser's per-request behaviour.
5. Why was the gap not closed when it was seen? BUG-0119 recorded it as a residual in
   prose, with no pinned test and no work item (F-043).

**Root cause:** browser emulation of request headers was a single per-client constant,
not a per-request decision. No rule or test tied a request's headers to the kind of
request a browser makes for it, and the header values were never measured from a
real browser.

## Corrective action
Delivered by CC-CORE-0061 and CC-FUZZ-0090 (FR-CORE-44, FR-FUZZ-53, SP-38).
- **`core/http.py`** (the one owner, SP-38):
  - `NAVIGATION_HEADERS`: the old set, unchanged. `DEFAULT_BROWSER_HEADERS` is now the
    same dict.
  - `FETCH_HEADERS`: as measured.
  - `request_kind(headers, location)`: fetch for a JSON body (`is_json_media_type`:
    `application/json` or a `+json` suffix, RFC 6839) or `location == "json"`, else
    navigation.
  - `browser_headers(kind)`.
  - `with_browser_headers(headers, kind=)`: the caller's headers win,
    case-insensitively, each sent once.
  - `requests_browser_headers(headers, kind=)`: also sets each other-profile header
    the kind does not send to `None`. `requests` documents this as omitting a
    session-level key, so a navigation-default session sends exactly the fetch set.
  - `BROWSER_HEADER_RULES`: each emulated rule with its spec step or measurement
    (PA-0111).
- **Senders**:
  - `RequestsProbeSender` passes every send through `requests_browser_headers` with
    the probe's kind. A PRG follow-up keeps that kind: a browser follows a fetch's
    redirect in the same fetch.
  - `greybox.RequestsCorrelatingSender` and `blind_sqli_fuzzer.RequestsSender` do the
    same. Neither builds JSON today, so both send the navigation set.
  - `tools/fetcher.py` and `lab_fixtures/external.py` set their navigation session
    defaults through `browser_headers("navigation")`.
- **Tests**: `tests/test_browser_header_profiles.py` (new):
  - wire-level sets for a JSON, form, query, header and `+json` probe;
  - a navigation-default session that still sends only the fetch set;
  - the PRG kind;
  - a probed `Accept` that wins and is sent once;
  - the merge rules;
  - the four negotiating styles, with the html-first two as strict xfails;
  - the end-to-end M2 differential;
  - the rule-fixture guard;
  - the AST guard with its synthetic offenders.

  `tests/test_probesender.py` and `tests/test_fuzzer_seam.py` were updated: two exact
  header dicts became the probe's header plus its kind's profile, and one fake `get`
  now accepts `headers=`.

## Recurrence review
Checked `docs/bugs/` (including the BUG-0119 doc on `bug-0118-v3`) and
`docs/PREVENTIVE_ACTIONS.md` for browser header emulation, fingerprintable clients,
browser-behaviour emulation and parked residuals.
- **BUG-0059 / PA-0061, BUG-0060 / PA-0062:** these introduced the one navigation set
  for every bare `requests.Session()`. The root cause is the same: header emulation
  as one per-client constant. **A recurrence**, analysed below.
- **BUG-0119 / PA-0119** (branch `bug-0118-v3`, unmerged): it applies the navigation
  set to every seam send (`with_browser_headers` in `HttpClient.send`). Its review
  recorded this exact defect as a residual (S5) and did not fix it. **The same defect,
  known and parked.** Analysed below.
- **BUG-0110 / PA-0111:** browser behaviour is emulated rule by rule, with a rule table
  and a fixture per rule. It was enforced for form serialisation only. **The same root
  cause at another layer** (headers): analysed below.
- **BUG-0127 / PA-0127:** a confirmer must check its signal's preconditions on the
  observed response's content type. A related class (JSON and HTML responses read
  differently), on the response side. Not this root cause.
- **BUG-0039 / PA-0041, PA-0072:** one seam's implementations stay in step. This fix
  is applied to every requests-based sender at once, through one owner, which keeps
  them in step.
- **PA-0054(3) / PA-0056(3):** a known instance not fixed is pinned by a strict xfail.
  BUG-0119's S5 residual was not pinned. Analysed below.

## Prior-preventive-action failure analysis
- **PA-0062** (from BUG-0060; strengthens PA-0061):
  - **Too narrow, wrong layer.** It made one set internally consistent ("the claimed
    kind" of client) and assumed each client makes one kind of request. A probe sender
    makes both navigations (forms, links) and script requests (JSON APIs).
  - **Not enforced** (`Enforced by: none`).
  - **Its values were never measured.** The set was written from knowledge of a
    browser, not recorded from one.
- **PA-0111** (from BUG-0110): "code that emulates a browser … (form submission,
  redirects, cookies, headers) implements the named algorithm rule by rule".
  - **Not followed for headers.** It names headers, but its rule table and guard were
    built for form serialisation only (`core.forms.RULES`). The header set never had a
    rule table, so nothing asked which Fetch rules decide a request's headers.
  - **Not enforced for headers.** Its guard tests list form rules only.
- **PA-0119** (BUG-0119, unmerged): it is about which clients carry the set, not which
  set. Its review saw this defect and left it as prose.
  - **Not followed:** PA-0054(3) and PA-0056(3) require a known, unfixed instance to be
    pinned by a failing-by-design check in the same change that defers it. BUG-0119
    pinned nothing for S5.
- **CLAUDE.md #8 (measure before design)** held this time: the measurement caught the
  design's remembered `Accept` value before it shipped.

## Preventive action
**PA-0158** (`docs/PREVENTIVE_ACTIONS.md`). It strengthens PA-0062 and PA-0111, and
supersedes PA-0062's one-set wording:
1. A client that emulates a browser sends, **per request**, the header set of the kind
   of request a browser makes for it (navigation or fetch). The kind is decided by one
   owner from observable facts of the request (`core.http.request_kind`: its body's
   content type, its point's location), never from the app's source, and never one set
   for every request.
2. Each emulated header value is **measured** from a real browser and cited, with its
   spec step, in the owner's rule table (`BROWSER_HEADER_RULES`). Each rule has a
   fixture. A library's default (axios, Angular) is not a browser's.
3. Every requests-based sender takes its per-request headers from the owner, with its
   kind stated from `request_kind`. This is enforced by an AST guard over `fuzzlab/`,
   proven on synthetic offenders:
   - exceptions are listed with reasons, and a stale one fails;
   - a module naming a profile constant fails;
   - a kind-less merge fails, which catches BUG-0119's seam merge if it lands as
     written.
4. A known emulation gap is pinned by a strict xfail in the change that records it
   (PA-0054(3) applied to this class). Here: the html-first framework styles.

**PA-0002 sweep, by primitive (CLAUDE.md #7).** Searched `fuzzlab/` for
`DEFAULT_BROWSER_HEADERS`, `headers.update(`, `requests.Session(` and every
`<session>.request|get|post|…(` call.

| Caller | Traffic | Disposition |
|---|---|---|
| `tools/probesender.py::RequestsProbeSender` (`send`, `_request`, `_follow`) | probes: query, form, header, JSON, whole body | **fixed**: per-request `requests_browser_headers(kind=request_kind(...))`; PRG keeps the kind |
| `greybox/run.py::RequestsCorrelatingSender.send_correlated` | probes: query, form, header (JSON refused) | **fixed**: same call; navigation in practice |
| `tools/blind_sqli_fuzzer.py::RequestsSender.get` and `main` | GET query probes | **fixed**: same call; session defaults via `browser_headers` |
| `tools/fetcher.py::ContentFetcher` | page GETs (documents) | **converted**: `browser_headers("navigation")` defaults; navigation is correct |
| `lab_fixtures/external.py::_default_session`, `_LabClient.request` | lab setup forms | **converted** defaults; send **allowed** with a reason (navigations) |
| `lab_fixtures/external.py::_fetch_locked` | bWAPP archive download | **allowed**: not target traffic |
| `session/manager.py::_requests_fetch_factory` (`get`, `post`) | login pages and forms | **not edited** (the BUG-0148 lane's file). Allowed: form logins are navigations. **Change needed there**: a JSON-API login POST should pass `requests_browser_headers(headers, kind=request_kind(headers))`. |
| `tools/spider.py` (session defaults; `_isolated_submit`'s session copy) | crawl navigations | **not edited** (the DISC-CAPTURE lane's file). Allowed: navigations. A JSON-body isolated submit would need the same call. |
| `tools/navguard.py::get_checked` | static page GET | **not edited** (locked). Allowed: a document fetch is a navigation. |
| `core/http.py::HttpClient` / `SeamProbeSender` | authenticated probes | **not affected here**: no browser set on this branch. When BUG-0119 lands, its `with_browser_headers(request.headers)` must take `kind=request_kind(request.headers)`. The guard fails until it does. |
| `labgen/conformance/*live_boot*.py` (`req_headers.update`), `labgen/identifier_sqli_oracle.py` | generated-lab harnesses (urllib / `requests.get`) | **not clients of the browser set**: they check the toolkit's own generated labs |
