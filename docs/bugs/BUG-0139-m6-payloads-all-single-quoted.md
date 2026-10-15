# BUG-0139 — Every M6 payload was single-quoted, so a quote-sensitive sink was a guaranteed miss

- Date: 2026-10-15
- Status: fixed (CC-FUZZ-0084), offline; the live re-run on Juice Shop is the
  coordinator's
- Severity: medium (a false negative on a true-positive DOM XSS; no false positive, no
  safety impact)

## Description
The M6 browser strategies (`DomXssStrategy`, `StoredXssStrategy`) send the payloads
of `oracle/strategies._xss_exec_payloads`, each of which calls the sentinel binding
with the probe's token. All four called it as `__fzlbHit('TOKEN')`, with single
quotes.

Juice Shop's `#/track-result?id=` route fetches `GET /rest/track-order/:id`. The server
evaluates the id inside a **single-quoted** string (a MongoDB-style `$where`). Any `'`
in the id ends that string early: the evaluation throws (`SyntaxError: Unexpected
identifier`), the API answers 500, and nothing is echoed or rendered. Every M6 payload
carried a `'`, so the sink never received a payload it could render. The candidate was
"checked" (a negative), although the route is a real DOM XSS: with backticks,
`<img src=x onerror="window.__hit=`a1`">` is echoed, rendered through
`bypassSecurityTrustHtml`, and executes.

## Where encountered
Live on Juice Shop, after FR-CRAWL-17 started seeding `#/track-result?id=`. The
coordinator verified it with a diagnostic script (`scratchpad/diag/track_diag.py`).

## What it caused to fail
- **FR-FUZZ-48 / M6:** a guaranteed false negative for any sink whose data path breaks
  on a single quote: a server-side string evaluation, a SQL or NoSQL query built by
  concatenation that errors, or a filter that rejects `'`.
- **ML labels:** the miss was recorded as "checked", a negative, so it also taught the
  model that such sinks are safe.

## What the bug was identified to be
The confirmer's payload set had a single quoting shape, a property no test or rule
looked at. Its four payloads varied the **HTML** context (an element, an attribute
break-out, `<svg>`, `<script>`) but never how the sentinel call itself was quoted.

## Root cause analysis
Five Whys:
1. *Why was the track-result XSS not confirmed?* No payload reached the page: each
   one's `'` made the API answer 500.
2. *Why did every payload contain a `'`?* All four built the same sentinel call,
   `SENTINEL('TOKEN')`; only the HTML wrapper varied.
3. *Why was the call's quoting never varied?* The payloads were designed against the
   browser side (does it execute?). The data path before the sink, which may reject or
   break on a character, was never part of their model.
4. *Why did no rule catch a single-shape payload set?* PA-0124(2) ("a confirmer that
   relies on one probe form states the server-side filters it cannot pass, or carries a
   stated second form") was written for the open redirect's canary and applied there
   only. No sweep or test asked the question of the other confirmers.
5. *Why did no test show it?* The M6 fixtures echo the value straight into the page;
   none put a quote-sensitive step between the input and the sink.

**Root cause:** a confirmer's probe set shared one quoting shape. The rule that a
single probe form must state its limits, or carry a second form, existed (PA-0124(2))
but was neither swept across confirmers nor enforced.

## Corrective action
CC-FUZZ-0084:
- **`oracle/strategies._xss_exec_payloads`:** the four payloads are kept, unchanged and
  first. Two more call the sentinel without a single quote:
  - `<img src=x onerror="__fzlbHit(`TOKEN`)">` (backticks);
  - `<img src=x onerror=__fzlbHit(/TOKEN/.source)>`, with **no quote character at
    all**: a regular-expression literal's `.source` is the token, in an unquoted
    attribute value.
- **The token is unchanged:** fresh per candidate (`_token`, 8 hex characters),
  random, and checked by the binding exactly as before. The function now refuses a
  token that is not alphanumeric, since the token is placed in JS strings of every
  quote and in a regex literal.
- **Cost:** 6 payloads, up from 4. An unconfirmed DOM candidate costs 6 browser loads,
  about 24 s at the default `SETTLE_MS` (it was 16 s). A page that cannot be observed
  still costs at most `MAX_NOT_OBSERVED` (2) loads (BUG-0137). A confirmation stops at
  the first hit.
- **Tests** (`tests/test_m6_payload_quoting.py`, real Chromium, loopback):
  - the fixture is a hash-route page that fetches `/rest/track-order/<id>`; the server
    answers 500 on a `'` in the id, else echoes it as JSON; the page writes it with
    `innerHTML`;
  - `DomXssStrategy` now confirms it, with a payload that has no `'`;
  - each payload alone against that path: the four quoted ones never execute, and both
    quote-free ones do;
  - the negatives hold for all six: the same path written with `textContent`, and a
    JSON document echoing the value, are never confirmed;
  - unit pins: the three quoting shapes, the first four payloads unchanged, and the
    token rule.
  - **Mutation:** with the old four-payload list, the confirmation test, the
    per-payload test and the shape pin fail.
  - `test_m6_navigation_failures.py`'s all-observed pin now counts the payload set
    instead of a literal 4.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for payload-shape and encoding
defects:
- **BUG-0124 / PA-0124(2)** (the open redirect: one canary form, refused by a
  containment allowlist). **A recurrence of its class:** a confirmer with one probe
  form and no stated limit, here in the quoting dimension.
- **BUG-0083 / PA-0084, BUG-0093 / PA-0094, BUG-0127 / PA-0127** (reflected XSS:
  break-out substrings, inert containers, a JSON response). These are false
  **positives** from a weak structural judgement, not payload-shape misses. Not
  recurrences; their negatives must still hold for the new payloads, and they do (the
  escaped-render and JSON-echo tests).
- **BUG-0133 / PA-0133** (SSTI refused on an edit-form echo). A false negative from the
  judging rule, not the payload set. Not a recurrence, but the same lesson: test the
  true-positive side through a realistic data path.
- **BUG-0115 / PA-0115** (a payload relocated). It concerns where a payload goes, not
  its shape. Not a recurrence.

## Prior-preventive-action failure analysis
**PA-0124(2)** did not prevent this because:
1. **Too narrow in application.** It was written as a rule for every confirmer, but
   BUG-0124's sweep (PA-0002) ran over the classifier's outputs (PA-0124(1)), not over
   the confirmers' probe forms. M6 was never asked "what upstream filter can't you
   pass?".
2. **Not enforced.** Nothing records a confirmer's probe shapes or tests that it
   carries a second one, so a single-shape payload set looks like any other.

PA-0139 sweeps every confirmer's payload set (the table below). It also pins the M6
shapes in a test, and requires every remaining single-shape set to be stated.

## Preventive action
**PA-0139** (strengthens PA-0124(2) from one confirmer to all of them, with a sweep
and an enforcing test for M6), in `docs/PREVENTIVE_ACTIONS.md`.

### PA-0002 sweep (every confirmer's payload shapes; quote- or encoding-sensitive upstream paths)
| Confirmer | Payload shapes | A quote- or encoding-sensitive path makes it a guaranteed miss? | Disposition |
| --- | --- | --- | --- |
| M6 `DomXssStrategy`, `StoredXssStrategy` | 4 HTML contexts, one single-quoted call | **yes**: any `'`-sensitive path | **fixed**: + backtick and quote-free calls (6) |
| M5 `ReflectedXssStrategy` | quote-free marker `zqxm<tok>`; break-outs per context: element `<tok>` (quote-free); attribute uses the attribute's own quote; JS uses the string's own quote | no: the reflection probe and the element break-out are quote-free; an attribute or JS break-out needs that context's quote by definition | not this class |
| M4 `SstiStrategy` | `${a*b}`, `{{a*b}}`, `<%= a*b %>`, `#{a*b}`, `${{a*b}}` | no quote; five delimiter shapes | not this class |
| `GoTemplateSstiStrategy` | `{{ len "AAA…" }}`: one shape, **double-quoted** | **yes** for a `"`-sensitive path (Go's backtick raw string `{{ len `AAA…` }}` would pass) | **flagged, not built**: a second form changes that mechanism's two-probe design and cost; stated here (PA-0139(2)) |
| `SpelInjectionStrategy` | `T(java.lang.Math).abs(-n)` | no quote | not this class |
| `OpenRedirectStrategy` | `https://oracle<tok>.example/cb`, plus the seeded form (BUG-0124) | no quote; two forms | not this class |
| `HttpHeaderInjectionCrlfStrategy` | raw `\r\n` + one injected header | encoding: a path that strips CR or needs another encoding misses; one shape | stated residual (PA-0139(2)); not this bug's quoting class |
| `SqliError` / `Boolean` / `Timing` / `EvaluationMarker` | numeric and quoted families (`1 AND …`, `1' AND …`) | no: a quote-free numeric family exists | not this class |
| `CommandInjection` (timing, OOB) | separators `;`, `|`, `&&`, `$()`, backticks | no quote; several shapes (a shell-quoted context is a break-out question, not this one) | not this class |
| `SsrfOob`, `SsrfInBandMarker`, `CommandInjectionOob` | the canary URL | no quote | not this class |
| `XxeInBandMarker`, `XxeOob` | `<!ENTITY xxe SYSTEM "url">`: one shape, double-quoted (XML allows `'…'`) | in principle for a `"`-sensitive path to an XML body | stated residual (PA-0139(2)) |
| `PathTraversal*`, `RegexDos`, `CsvFormulaInjection` | traversal / regex / trigger shapes | no quote | not this class |
| greybox probes | `1' OR '1'='1' -- -` (sqli), `<fzlgbx>` (xss) | the sqli probe's quote is its purpose; the xss probe is quote-free | not this class |
| access control, mass assignment, JWT, upload, price, deserialization | not payload-string confirmers | — | not this class |

## Residuals
- **`GoTemplateSstiStrategy`** has one double-quoted probe shape; flagged for a decision
  (above).
- **XXE** has one double-quoted `SYSTEM` literal, and **CRLF** one raw `\r\n` encoding.
  Both are stated, not changed.
- The M6 HTML wrappers are fixed strings. A sink that needs a different context (for
  example inside a JS string) is still a miss for M6. That is not a quoting question,
  and it is unchanged.

## Sweep follow-up: Go-template SSTI (added in review)
The coordinator decided to build the flagged row. `GoTemplateSstiStrategy` now runs a
second two-probe round with Go's raw string, `{{ len `AAA…` }}`, when the
interpreted-string round did not confirm. It is just as strict: fresh lengths, both
evaluated, no cross-bleed, BUG-0133's echo rules. The cost is 2 requests to confirm by
`"` (as before), and 4 to confirm by the raw string or to give no verdict. The sweep
row "`GoTemplateSstiStrategy` … flagged, not built" is now **fixed** (CC-FUZZ-0084
amendment, FR-FUZZ-28). XXE (`"`) and CRLF (raw `\r\n`) remain stated residuals.

## Review of the fix (added in review)
Reviewers A and B agreed, with should-fixes (D62):
- **The regex form could be cut (A-S1).** `/TOKEN/.source` carries a `/`. A sink that
  takes the value as **one path segment** (a client building `'/rest/…/' + id`
  unencoded, an Express `:id`) split it there, so the "no quote at all" payload was
  itself shape-sensitive. It is replaced by `String.fromCharCode(...)` of the token:
  no quote, no `/` and no whitespace in the call. The fixture's API now matches one
  segment, and a stricter variant (backticks refused too) is reached only by this
  form.
- **Order by reach (A-S2):** the quoted `<img>`, then backtick, then `fromCharCode`,
  then the three other quoted wrappers.
- **The last quote-free try (B-S1):** a path that fails on a quote can make the quoted
  payloads' **loads** fail (not observed), so `MAX_NOT_OBSERVED` could stop the loop
  before a quote-free payload ran. One more load of the first untried fully
  quote-free payload is now always made (at most 1 extra).
- **A query point (B):** both quote-free payloads also execute through the
  quote-sensitive path when placed in the query (`+`, `%2F`, `%60` decoded by the
  page).
- **Cost (V5):** stated in FR-FUZZ-48.

Residual added in review (V6): **values in URL path segments are sensitive to `/`,
`#` and `?`.** The `fromCharCode` form avoids `/` and every quote. A sink that splits
on `#` or `?` (a client that concatenates them unencoded) still needs the app to
encode, and the payloads carry none of the three in that form. The HTML wrappers' own
spaces remain: HTML separates attributes only by whitespace or `/`, and a space in a
path segment is percent-encoded.
