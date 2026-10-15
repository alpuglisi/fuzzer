# BUG-0119 — authenticated probes went out with python-requests' default headers, not the browser set the login used

- Date: 2026-10-15
- Status: fixed in the core seam (CC-CORE-0059). It was ported from the dropped branch
  `bug-0118-v3` on the owner's decision D69. The spider's API submit is pending at
  integration, and the M6 plant was not ported (see "Port"). The combined design and
  code review is pending.
- Severity: medium. Every authenticated probe looked like a different client from the
  one that logged in. An app that binds its session to the client, or a WAF that
  checks header consistency (BUG-0060), could log the probe out or block it. Probes
  then run without the session, or end it, and findings behind the login are missed.
  No failure on a real target is recorded; the defect was found in design review.

## Port (D69, 2026-10-15)
The owner decided D69: "We are maintaining the use of real browser headers for every
request" (relayed by the coordinator; not yet recorded in
`docs/DECISIONS_AND_ROADMAP.md` on this branch). This fix was first built on branch
`bug-0118-v3` (commits d0c6e5d and f078bbb), beside the BUG-0118 SQLi send gate. The
owner dropped that gate (D68), and the branch was not merged.

The JSON-SEND lane ported the BUG-0119 parts only. Nothing of the gate came with them
(`oracle/sqlsafety.py`, `oracle._sqli_gated`, D65/D66, `allow_unsafe_sqli`).

**Ported:**
- `core.http.with_browser_headers`;
- `HttpClient.send` applying it;
- `tests/test_seam_browser_headers.py` with its AST guard and allowances (the labgen
  runner and the generated-lab conformance harnesses as lab-harness exceptions;
  `_fetch_locked`);
- the `_probed_ua` updates of `tests/test_forms_phase2.py` and
  `tests/test_prg_observation.py`;
- this document, CC-CORE-0059, FR-CORE-42, PA-0119 and SP-36.

**Differences from the branch, for the current code:**
- **Two profiles (BUG-0152, SP-38).** `with_browser_headers(headers, kind=)` merges the
  navigation set or the measured fetch set. `HttpClient.send` passes
  `with_browser_headers(request.headers, kind=request_kind(request.headers))`, so a
  seam send with a JSON body carries the fetch set (`Accept: */*`,
  `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`) and every other send carries the
  navigation set. This closes the residual of review round 1, reviewer A S5 (below).
- **The spider's API form submit is not changed here.** `tools/spider.py` belongs to the
  DISC-CAPTURE lane. The change, to be applied at integration, is this. In
  `LocalSpider._isolated_submit`, add
  `from fuzzlab.core.http import request_kind, with_browser_headers` and replace
  `extra_http_headers=headers` with
  `extra_http_headers=with_browser_headers(headers, kind=request_kind(None, "body"))`.
  The submit is a urlencoded form, so it takes the navigation set. Until then the site
  is listed in the guard's `_PENDING` and pinned by two strict xfails
  (`test_the_spiders_api_form_submit_sends_the_browser_header_set`,
  `test_no_pending_http_client_remains`).
- **The M6 stored plant (`tools/browserexec.py`, review round 1) was not ported.** It is
  outside the port's listed parts. It is listed in `_PENDING` and pinned by
  `test_the_m6_stored_plant_sends_the_browser_set_with_the_contexts_own_agent`
  (strict xfail), and flagged to the coordinator. The branch's change was:
  `headers=with_browser_headers({"User-Agent": ua} if isinstance(ua, str) and ua else None)`
  on its `context.request.post`, with `ua = page.evaluate("() => navigator.userAgent")`.
  With SP-38 it also needs `kind=request_kind(None, "body")` (a form plant).
- **The guard** accepts every owner call that returns a set (`with_browser_headers`,
  `requests_browser_headers`, `browser_headers`) and both profile constants. It is
  marked as a whole-package guard.
- **CC-CRAWL-0031 and CC-LAB-0260** were not ported. The spider change is pending, and
  the labgen runner is unchanged (as on the branch after its review round 2).

## Description
Three HTTP clients sent `requests`' or Playwright's own default headers instead of
`fuzzlab.core.http.DEFAULT_BROWSER_HEADERS`:

1. **The core seam** (`core/http.py`). `HttpClient.send` handed the request's own
   headers to `_requests_transport`, which calls `requests.request(...)`. `requests`
   then added its defaults: `User-Agent: python-requests/x.y`, `Accept: */*`, no
   `Accept-Language`. The session manager logs in through a `requests.Session` that
   carries `DEFAULT_BROWSER_HEADERS` (`session/manager.py`). So the login came from a
   browser and every probe after it from python-requests.
2. **The spider's API form submit** (`LocalSpider._isolated_submit`). Its Playwright
   API request context got only the session's headers, so Playwright's API-client
   defaults filled the rest.
3. **The labgen identifier-SQLi runner** (`labgen/identifier_sqli_oracle.default_http_runner`).
   `requests.get(url, headers=...)` with the caller's headers only.

## Where encountered
Forms phase 2 design review: lane A's report, §6.2 item 1, recorded in the
orchestrator's defect list beside BUG-0118. It was held for the operator, because
PA-0062 requires operator confirmation for this dual-use class of fix. On 2026-10-15
the operator decided to apply PA-0062, and the fix was built in the BUG-0118 lane.

## What it caused to fail
- **Authenticated probes** through the seam: `SeamProbeSender` (`fuzzlab auto
  --identity`), and the `--identity` paths of the auditor (`tools/fetcher.py`) and of
  `fuzz` (`tools/blind_sqli_fuzzer.py`), which reach `HttpClient` through
  `tools/authhttp.make_auth`.
- **An app that binds a session to its client** saw a different User-Agent on every
  probe. `tests/test_seam_browser_headers.py` builds such an app: its `/api/me`
  answers 200 only with a live session and the User-Agent the login came from. (The
  unfixed seam was not run against it in this step.)
- **A WAF that checks the headers** for a browser UA without browser `Accept` headers
  (BUG-0060) could answer 403.
- **The spider's isolated form submit** and the **labgen runner** were
  fingerprintable as non-browser clients.

## What the bug was identified to be
The rule "send the full browser header set" was applied by setting a session's default
headers (`session.headers.update(DEFAULT_BROWSER_HEADERS)`). A client that keeps no
session defaults (a module-level `requests.request`, a Playwright API request context)
had no place where the set was added. There was no shared merge function, so each
such client would have needed its own copy.

## Root cause analysis
**Method: change analysis.** Compare the clients that sent the browser set with those
that did not, and find the difference.

| Client | Browser set? | How it is built |
|---|---|---|
| spider, auditor, `fuzz`, `RequestsProbeSender`, greybox, session manager, `lab_fixtures._default_session` | yes | `requests.Session()` + `.headers.update(DEFAULT_BROWSER_HEADERS)` |
| spider's `_isolated_submit` fallback (`requests.Session`) | yes | copies the spider session's headers |
| core seam `_requests_transport` | **no** | `requests.request(...)`, no session |
| spider's `_isolated_submit` (Playwright) | **no** | `pw.request.new_context(extra_http_headers=<session headers>)` |
| labgen `default_http_runner` | **no** | `requests.get(...)`, no session |

The difference is the API shape: every client built as a `requests.Session()` got the
set, and every other client did not. That matches the wording of PA-0061 and PA-0062
("every bare `requests.Session()`") and PA-0061's sweep ("grep for
`requests\.Session\(\)`"). The rule followed the API it named, not the traffic.

**Root cause:** the browser-header rule was written and swept as a property of
`requests.Session()` construction, and nothing checked it. HTTP clients of other shapes
were outside its wording, its sweep and any guard, so they kept their library defaults.

## Corrective action
Delivered with CC-CORE-0059, CC-CRAWL-0031 and CC-LAB-0260 (FR-CORE-42, SP-36):
- **`core.http.with_browser_headers(headers)`**: `DEFAULT_BROWSER_HEADERS` under the
  caller's headers. Every header the caller set wins, matched case-insensitively, so a
  header point's own value, a content type or a session's `Cookie` is never overridden
  and never sent twice. It returns a new dict and does not change the request. This is
  the one place the merge is made (PA-0003).
- **`HttpClient.send`** passes `with_browser_headers(request.headers)` to the
  transport, so every seam send carries the set. *(Port, D69: with
  `kind=request_kind(request.headers)`, BUG-0152.)*
- **`LocalSpider._isolated_submit`** gives its Playwright API context
  `extra_http_headers=with_browser_headers(headers)`. *(Port, D69: pending at
  integration; see "Port".)*
- **`labgen.identifier_sqli_oracle.default_http_runner`** is unchanged and listed in
  the guard as a lab-harness exception. Round 1 changed it to send
  `with_browser_headers(all_headers)`, but `fuzzlab.labgen` may not import
  `fuzzlab.core.http` (the labgen import guard), and the full suite on f078bbb failed
  on it; review round 2 reverted the change. The runner probes the toolkit's own
  generated lab at generation time; it is not target traffic.
- **Tests:** `tests/test_seam_browser_headers.py` (new):
  - real loopback servers that record the headers on the wire;
  - a UA-bound app;
  - a header point's value wins and is sent once; a JSON probe keeps its content type;
  - the merge is case-insensitive and does not mutate the request;
  - the spider's API submit sends the set; the labgen runner is a listed exception;
  - an AST guard over `fuzzlab/`, proven on synthetic offenders.

  `tests/test_forms_phase2.py` and `tests/test_prg_observation.py` were updated. Their
  fakes treated any `User-Agent` as a header probe; every send now carries the
  browser's, so they look for a User-Agent other than `DEFAULT_USER_AGENT`
  (`_probed_ua`).
- **Integration:** the guard allows one more client, added when this work was replayed
  onto the current branch: `fuzzlab/lab_fixtures/external.py::_fetch_locked`. It
  downloads the pinned bWAPP archive for lab setup (https only, sha256-checked) and
  never sends traffic to a target. Called without a session (as `fetch_bwapp()` is at
  line 863), it opens a bare `requests.Session()`, so this public download keeps
  `requests`' default headers. That is accepted: it is not target traffic.

## Review round 1 (2026-10-15)
Reviewer B (B3, S7) and reviewer A (S5) found, and this change corrects or records:
- **PA-0119 repeated its own failure mode** (B3): it listed API shapes, and its sweep
  missed two more. Fixed:
  - the **`urllib.request` clients** that send to generated loopback labs
    (`labgen/conformance/live_boot.py`, `rails_live_boot.py`,
    `live_boot_spring_boot.py`, `go_live_boot.py`, `django_live_boot.py` `request`,
    and `django_live_boot.external_http_probe`) are now seen by the guard and
    **allow-listed with a reason**: they are conformance harnesses checking the
    toolkit's own generated lab (or a reachability probe), not target traffic, and the
    browser set's `Accept` would renegotiate the very responses their tests assert;
  - the **Playwright `context.request.post`** of the M6 stored plant
    (`tools/browserexec.py`) now sends `with_browser_headers(...)`, with the browser
    context's own User-Agent winning so the plant and the observe navigation present
    one client *(Port, D69: not ported; pending, see "Port")*;
  - the guard: `_is_browser_set` no longer accepts any `<x>.headers` -- only a session
    whose headers were updated with the set; a `requests.Session()` counts only when
    the name it is bound to is updated; it also checks `urllib.request.Request` /
    `urlopen` and `context.request.<verb>`; its limits are stated (PA-0130(4));
  - PA-0119(1) now names the class (a non-browser client sending target traffic), with
    the shapes as today's guard coverage, not the rule.
- **Residual, not fixed (S7): the browser-login User-Agent.** When the session manager
  falls back to the browser login (`session/browserlogin.py`), the login comes from
  Chromium with its own User-Agent, and every seam probe after it sends
  `DEFAULT_USER_AGENT`. An app that binds the session to its client sees two clients.
  FR-CORE-42's "the same browser header set the login sent" was an overclaim and is
  corrected to "the requests-based login's set".
- **Residual, not fixed (A S5): navigation headers on JSON / API sends.** The seam now
  sends a navigation's set (`Accept: text/html,…`, `Sec-Fetch-Mode: navigate`,
  `Sec-Fetch-Dest: document`) on every send, a JSON body or an API path included. An
  app or framework that negotiates content on `Accept` (or on `Sec-Fetch-*`) may answer
  such a probe with HTML, a redirect or an error page instead of the JSON its own XHR
  client gets, which can hide a JSON-only signal from an oracle. No code change here
  (coordinator's decision); an XHR-style set for JSON sends is the candidate fix.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for fingerprintable client
headers and browser emulation.
- **BUG-0059 / PA-0061:** the spider sent python-requests' default User-Agent to
  external targets. PA-0061: a realistic UA on every bare `requests.Session()`, and a
  whole-package grep for `requests\.Session\(\)`. **Same root cause.**
- **BUG-0060 / PA-0062:** the UA alone was inconsistent with requests' other defaults,
  and a WAF answered 403. PA-0062 (supersedes PA-0061): the full
  `DEFAULT_BROWSER_HEADERS` at every bare-session call site. **Same root cause; a
  recurrence. Prior-PA analysis below.**
- **BUG-0110 / PA-0111:** the login detector serialised a form unlike a browser.
  PA-0111 strengthened PA-0061/PA-0062 for emulated *algorithms* (form submission,
  redirects, cookies). A related class at another layer; it did not reach clients
  outside `requests.Session()` either.
- **BUG-0132 / PA-0132** (missed in the first review; added in review round 1, S7): a
  session handed from one client to another must carry all the state the first client
  holds. A browser login handed to the requests senders is such a handoff; its client
  identity (the User-Agent) is part of what the app may bind the session to, and is
  not carried today (the residual above). A related class, not this root cause.
- **BUG-0080 / PA-0081 and BUG-0130 / PA-0130(4)** (cited in review round 1, B3): a
  shared safety rule is enforced by a guard that finds sites by **call shape**, and
  "the runtime check is authoritative; the source rules are lints" with stated limits.
  PA-0119's first version found sites by call shape but scoped its shapes too narrowly
  and stated no limits; the amended PA-0119(3) states them.

## Prior-preventive-action failure analysis
**PA-0062** was written by the operator (alpuglisi, commit f1906d8, 2026-09-29) from
BUG-0060. It requires:
- the full `DEFAULT_BROWSER_HEADERS` (not the UA alone) at every bare-session call
  site;
- when fixing a fingerprintability bug, checking that every header a real client would
  set is consistent;
- because this class of fix is dual-use, confirming with the operator that the target
  is theirs or one they are authorized to test (D11), re-confirmed per target.

Why it did not prevent BUG-0119:
- **Too narrow.** "Every bare-session call site" and PA-0061's grep pattern match
  `requests.Session()` only. The seam's `requests.request` call, a Playwright API
  request context and a module-level `requests.get` are HTTP clients of other shapes.
  None was in scope of the wording or the sweep.
- **Not enforced.** PA-0061 and PA-0062 both said "Enforced by: none". No test failed
  when a new client went out with library defaults.
- **Followed where it applied.** Every `requests.Session()` in `fuzzlab/` that sends
  target traffic carries the set (checked in the sweep below). The one bare session
  is the bWAPP setup download, which is not target traffic. The failure is the rule's
  scope, not compliance.

PA-0062's confirmation clause was followed: the fix waited for the operator's decision
(D63), and the operator decided to apply PA-0062 here (2026-10-15).

## Preventive action
**PA-0119** (`docs/PREVENTIVE_ACTIONS.md`), strengthening PA-0062 (and through it
PA-0061):
1. Every non-browser HTTP client in `fuzzlab/` that sends target traffic sends the
   full browser header set, whatever its API shape (the class, not a list of shapes;
   amended in review round 1).
2. The merge is made in one place, `core.http.with_browser_headers` (SP-36). The
   caller's headers win, case-insensitively.
3. An AST guard over `fuzzlab/` fails on a client without the set. An exception is
   listed with its reason, and a stale exception fails. A `<x>.headers` counts only
   for a session updated with the set; the guard's blind spots are stated.
4. PA-0062's dual-use rule stands: confirm with the operator before changing how the
   toolkit's traffic presents itself.

**PA-0002 sweep.** Every `requests.Session(`, `requests.<verb>(`, `requests.request(`
and `<x>.request.new_context(` in `fuzzlab/` was checked; review round 1 added every
`urllib.request.Request(`, `urlopen(` and `<x>.request.<verb>(`:
- **Fixed:** `core/http.py::_requests_transport` (through `HttpClient.send`),
  `tools/spider.py::_isolated_submit` (Playwright), and
  `labgen/identifier_sqli_oracle.py::default_http_runner` (two calls); in review round
  1, `tools/browserexec.py` (the M6 stored plant's `context.request.post`). *(Port,
  D69: of these, only `_requests_transport` through `HttpClient.send` landed. The
  spider is pending at integration, the plant is not ported, and the labgen runner
  was reverted to a listed exception in round 2. See "Port".)*
- **Already correct** (a session with `DEFAULT_BROWSER_HEADERS`):
  - `session/manager.py`, `greybox/run.py`, `tools/blind_sqli_fuzzer.py`,
    `tools/spider.py` (its session), `tools/fetcher.py`, `tools/probesender.py`,
    `lab_fixtures/external.py::_default_session`;
  - the spider's `requests` fallback in `_isolated_submit`, which copies the spider
    session's headers.
- **Allowed, with reasons, in the guard:**
  - `tools/spider.py::_isolated_request`, which forwards the routed browser request's
    own headers;
  - `lab_fixtures/external.py::_fetch_locked`, the bWAPP setup download. Its bare
    session is used when no session is passed, which is how `fetch_bwapp()` is called;
  - the generated-lab conformance harnesses' `request` in
    `labgen/conformance/live_boot.py`, `rails_live_boot.py`,
    `live_boot_spring_boot.py`, `go_live_boot.py` and `django_live_boot.py`, and
    `django_live_boot.external_http_probe` (review round 1; reasons above).
- **Not clients:** mentions in comments and docstrings, and the Django lab template's
  own server-side `requests.get()`.

## Port addendum: recurrence (2026-10-15)
BUG-0152 found the S5 residual above in the requests-based senders too, where it
predated this bug. That bug's recurrence review names this one: the S5 gap was recorded
in prose, with no pinned test (PA-0054(3)). Its PA-0158 strengthens PA-0119 with the
per-request kind.
