# BUG-0127 — Reflected XSS confirmed in a response no browser renders as HTML

- Date: 2026-10-14
- Status: fixed (CC-FUZZ-0072)
- Severity: medium. A confirmed false positive: a finding the operator would act on, and
  a positive training label for the ML stages.

## Description
The first live `fuzzlab auto` run on Juice Shop (forms phase 3 integration) confirmed
`xss-reflected` on `GET /api/Challenges/?sort=`. The endpoint answers an unknown sort
column with an `application/json` error that echoes the value. The break-out
`<zqxb…>` appeared in the error string, and `ReflectedXssStrategy` parsed the body as
HTML, found an injected element in "text" context and confirmed. A browser shows a JSON
response as text (and Juice Shop sends `X-Content-Type-Options: nosniff`): nothing runs.

## Where encountered
The forms phase 3 live run on the operator's loopback Juice Shop lab (127.0.0.1:3000),
`$S/juice-p3c/run.db`.

## What it caused to fail
The precision of M5 (structural reflected-XSS confirmation, FR-FUZZ-39) on any target
with JSON or plain-text endpoints that echo input: every REST API.

## What the bug was identified to be
The confirmer judged the **text** of a response as if it were an HTML document, without
asking whether a browser would treat it as one. Its sound structural rules (BUG-0083,
BUG-0093, BUG-0102) all assume an HTML parse.

## Root cause analysis
1. *Why a confirmation?* The break-out produced an element in the parsed body.
2. *Why was the body parsed as HTML?* `ReflectedXssStrategy` parses every response with
   the HTML parser; the content type is never read.
3. *Why was that never caught?* Every lab sink and test fixture returns HTML; no fixture
   echoes input in a JSON, text or script response.
4. *Why did the lab not cover it?* The lab's XSS templates are HTML pages; a REST echo
   is not an XSS sink there, so it never needed a negative.

**Root cause:** the confirmation rule had an unstated precondition (the response is
rendered as HTML) that the code never checked, and no fixture violated it.

## Corrective action
- `oracle/strategies._renders_as_html(probe)`: `text/html`, `application/xhtml+xml`,
  or no Content-Type (a browser may sniff one). `ReflectedXssStrategy` confirms only
  when the break-out's structural check passes **and** the response renders as HTML.
- Sweep instance fixed: `OpenRedirectStrategy` read a meta refresh in any body; it now
  reads one only in such a response (a `Location` header is unaffected).
- Tests: `tests/test_oracle_xss_structural.py::test_a_reflection_confirms_only_in_a_response_rendered_as_html`
  (JSON, text, script: no; HTML, XHTML, none: yes);
  `tests/test_open_redirect_seed.py::test_a_meta_refresh_in_a_non_html_response_never_confirms`.
  Both fail with the gates removed (mutation check: 4 failures).

## Recurrence review
- **BUG-0083 / BUG-0093 / BUG-0102** (M5 structural confirmation): each tightened what
  counts as execution *inside* an HTML document; none asked whether the response is one.
  Same component, different root cause (parse rules, not the document type).
- **BUG-0072** (one confirmation per key; the context always observed): the strategy
  was told to observe the context rather than trust the auditor's label; the content
  type is part of that context and was not observed. Same family: a precondition of
  the confirming observation that was assumed instead of observed.
- No earlier bug confirmed a finding from a non-HTML response.

## Prior-preventive-action failure analysis
PA-0035 ("probe the real operation") and the BUG-0072 rule (observe, never assume, the
context) were applied to the reflection's *position* in the document, but not to the
document type: the rule was too narrow (it named the sink context, not the response).

## Preventive action
**PA-0127** (strengthens the BUG-0072 rule and PA-0035): a confirmer states every
precondition of its signal — here, that a browser renders the response as HTML — and
checks it on the observed response; a test feeds it a response that breaks each
precondition (a JSON, text or script echo for a markup signal).

## PA-0002 sweep
| Site | Content-type sensitive? | Disposition |
|---|---|---|
| `ReflectedXssStrategy` (M5) | yes: markup in the body | fixed |
| `OpenRedirectStrategy` meta refresh (M9) | yes: markup in the body | fixed |
| `OpenRedirectStrategy` `Location` header | no: a header | cleared |
| DOM / stored XSS (M6, `_BrowserXssStrategy`) | no: a real browser executes or not | cleared |
| greybox M10 (`greybox/confirm.py`, `xss*`) | sink coverage on an instrumented lab app | cleared (the lab's sink is its HTML render) |
| SQLi error / boolean / timing, SSTI evaluation, path traversal markers | no: server-side effects, any body type | cleared |
| Header injection (CRLF) | no: response headers | cleared |
| Auditor passive reflection (candidates only) | produces candidates, never findings | cleared |

## Residuals
- A response with no Content-Type still confirms (a browser may sniff HTML). A
  `nosniff` response without a type would not render; not handled (rare; stated).
- `text/xml` and `image/svg+xml` can run script in a browser and are not confirmed by
  M5 (false negatives, stated; the M6 browser path decides them when available).
