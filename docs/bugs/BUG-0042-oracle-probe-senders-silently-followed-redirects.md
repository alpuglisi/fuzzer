# BUG-0042 — the oracle's own `RequestsProbeSender`/`RequestsCorrelatingSender` silently followed HTTP redirects, crashing on a self-referencing `Location` value and undermining `OpenRedirectStrategy`'s own contract

- Date: 2026-09-23
- Status: fixed
- Severity: medium (a real target's response is silently transformed before a confirmation strategy sees it, and — for at least one real, realistic payload shape — the pipeline crashes outright rather than reporting a wrong-but-harmless verdict)

## Description

Building `CC-LAB-0198` (this project's first `http_header_injection`/
`http_response_header_value` instance on any stack, `go_net_http`'s
`/channels/redirect` endpoint) and wiring its manifest cells into
`tests/test_multitarget_category4.py::_twitch_cells()` — the same real,
full `run_targets`/`RequestsProbeSender` pipeline every other Twitch cell
already runs through — surfaced that `fuzzlab.tools.probesender.
RequestsProbeSender.send()` calls `self._session.request(...)` with no
`allow_redirects` override, so `requests`' own default (`True`) applies.
The generic `SstiStrategy` (unrelated to this new cell's own `http_header_
injection` class — it is tried against every GET/query candidate
regardless of vuln class, since the oracle's own `applies()` gating is by
category/vuln_class and the black-box pipeline does not know a candidate's
true class in advance) sent its `#{a*b}` payload as the new endpoint's
`destination` query param. The vulnerable twin echoed it verbatim into a
raw `Location: #{a*b}` response header (CWE-113, this cell's own point).
Because a bare `#`-prefixed value is a URL *fragment*, not a path segment,
`requests`' own redirect resolution (`urljoin(current_url, "#{a*b}")`)
produced the SAME url (path+query unchanged, only the fragment differs —
which is never sent to the server), so the server issued the identical
`302` again on the next hop, forever: `requests.exceptions.
TooManyRedirects: Exceeded 30 redirects.`, an uncaught exception that
crashed the whole `run_targets` call for both apps in that test.

Separately, and independently of the crash: `OpenRedirectStrategy` (`fuzzlab/
oracle/strategies.py`) inspects `probe.headers.get("location")` — it needs
the FIRST, un-followed response's own `Location:` header. With `requests`
silently following redirects by default, `probe.headers` would instead
reflect whatever the LAST response in a followed chain happened to
contain (which, for the real canary domain `OpenRedirectStrategy` sends,
`https://oracle<token>.example/cb`, is unresolvable — `.example` is a
reserved, non-resolving TLD — so a real target would raise a
`requests.exceptions.ConnectionError` too, uncaught by
`RequestsProbeSender`, the same crash class from a different angle). This
means `OpenRedirectStrategy` was never actually functional against a real
target through this sender, even though its own unit tests (`tests/
test_oracle_vectors.py`) pass, because those tests use hand-rolled fake
`Sender`s that hand back the un-followed 302's headers directly — the real
sender's own redirect-following default was never exercised until a real
cell finally echoed a caller-controlled value into a real `Location`
header and ran through the real pipeline for the first time.

## Where encountered

`tests/test_multitarget_category4.py::
test_both_apps_run_through_multitarget_for_real`, immediately after
wiring `lab/manifests/http_header_injection_redirect_go_sample.yaml`'s
cells into `_twitch_cells()` for `CC-LAB-0198`. Reproduced directly and
minimally with a standalone script booting the real generated app and
sending `SstiStrategy`'s own five payload strings via a real
`requests.Session()` against `/generated/labgen-go-0025` — `#{a*b}` alone
reproduces `TooManyRedirects` (the other four payloads resolve to
different — if still 404 — paths and complete in a single hop).

## What it caused to fail

- A real, reproducible `requests.exceptions.TooManyRedirects` crash of the
  entire `run_targets()` call in `test_both_apps_run_through_multitarget_
  for_real`, the moment `CC-LAB-0198`'s vulnerable twin was included —
  not a flake, not specific to test ordering.
- Independently (not exercised by this specific crash, but a real latent
  defect this investigation surfaced along the way): `OpenRedirectStrategy`
  cannot function correctly against a real target through
  `RequestsProbeSender` at all — it would either observe the wrong
  (post-redirect) response headers, or crash on the unresolvable canary
  domain — for as long as this project has had an `open_redirect` concern
  (`CC-LAB-0210`) with no dedicated live-boot test running it through this
  exact sender to notice.
- The same defect exists, independently, in `fuzzlab.greybox.run.
  RequestsCorrelatingSender.send_correlated()` (identical
  `self._session.request(...)` call with no `allow_redirects` override,
  feeding a `Probe` a `ConfirmationStrategy` inspects the same way) and,
  in a lower-severity form (timing skew rather than a wrong header/crash),
  in `fuzzlab.tools.blind_sqli_fuzzer.RequestsSender.get()`.

## What the bug was identified to be

Three real senders that build a `Probe`/timing measurement a
`ConfirmationStrategy` (or a timing oracle) treats as "the real server's
response" call `requests`' own `.request()`/`.get()` with no
`allow_redirects` override, so `requests`' library default (`True`)
silently applies — following any redirect the target issues and reporting
the FOLLOWED chain's final response instead of the actual response to the
request the strategy asked for, and crashing outright on a
self-referencing redirect target (a real, realistic payload shape for any
endpoint that echoes a caller-controlled value into a real `Location`
header).

## Root cause analysis

Five Whys:
1. Why did `test_both_apps_run_through_multitarget_for_real` crash on
   `CC-LAB-0198`'s vulnerable twin? `requests` followed the vulnerable
   twin's own genuinely-vulnerable `Location: #{a*b}` response into an
   infinite self-redirect loop (a `#`-prefixed fragment value resolves to
   the identical URL on every hop).
2. Why did `requests` follow that redirect at all? `RequestsProbeSender.
   send()` never set `allow_redirects=False` — `requests`' own default
   (`True`) applied silently.
3. Why wasn't this caught before a header-injection/redirect-shaped cell
   existed? No prior Twitch/Netflix cell ever echoed a caller-controlled
   value into a real `Location:` header and was run through this exact
   real sender — `open_redirect` (`CC-LAB-0210`) exists on a different
   stack/app pairing with no dedicated real-pipeline test exercising
   `OpenRedirectStrategy` against it through `RequestsProbeSender`
   specifically, so the sender's own redirect-following default had never
   been exercised by a redirect-issuing endpoint before now.
4. Why didn't `OpenRedirectStrategy`'s own existing unit tests catch that
   this sender can never make it work correctly? Those tests
   (`tests/test_oracle_vectors.py`) use hand-rolled fake `Sender`s that
   directly hand back the un-followed 302's own headers — by
   construction, they cannot exercise what a REAL `requests.Session`
   actually does with a real redirect, so the strategy's own logic was
   verified while the sender wiring it depends on in production never was.
5. Why does this matter as a real defect rather than a test-fixture gap?
   `fuzzlab.core.http` (the authenticated `SeamProbeSender` path) already
   sets `allow_redirects=False` for exactly this reason — this project
   already knew, and had already implemented, the correct behavior in one
   sender. `RequestsProbeSender`/`RequestsCorrelatingSender` are the
   unauthenticated equivalents of the same "hand a `ConfirmationStrategy`
   the real response" contract, and simply never received the same fix.

**Root cause:** two (arguably three, counting the timing-sender) of this
project's own real, live-target-facing senders never applied the
`allow_redirects=False` discipline `fuzzlab.core.http`'s authenticated
path already correctly applies, because nothing enforces that discipline
consistently across every component making this same "I report the real
server response" claim — each sender was written and tested in isolation
against fake sessions that never exposed the gap.

## Corrective action

- `fuzzlab/tools/probesender.py::RequestsProbeSender.send()` — added
  `allow_redirects=False` to every request this sender makes.
- `fuzzlab/greybox/run.py::RequestsCorrelatingSender.send_correlated()` —
  same fix, same reasoning (PA-0002's sweep).
- `fuzzlab/tools/blind_sqli_fuzzer.py::RequestsSender.get()` — same fix
  (a followed redirect also silently adds an unrelated round trip into
  this sender's own timing measurement, itself a `PA-0030`-shaped
  concern, lower severity but the same root cause).
- Updated `tests/test_probesender.py`'s `_FakeSession.request()` and
  `tests/test_fuzzer_seam.py`'s `FakeSession.get()` to accept and record
  `allow_redirects`, and added `test_requests_probe_sender_never_follows_
  redirects` (`tests/test_probesender.py`) plus a same-file assertion in
  `test_requests_sender_unchanged_standalone_behavior` (`tests/
  test_fuzzer_seam.py`), each asserting `allow_redirects is False`/`False`
  was actually passed through — a regression test for this exact defect,
  not just a re-run of the pre-existing suite.
- Re-verified live: `tests/test_labgen_go_live_boot.py::
  test_real_boot_proves_the_http_header_injection_differential_for_both_
  twins` and `tests/test_multitarget_category4.py::
  test_both_apps_run_through_multitarget_for_real` both pass against the
  real booted apps after the fix (the latter reproducibly crashed before
  it, and reproducibly passes after).
- `fuzzlab.session.manager`'s own `_RequestsFetcher` (`allow_redirects=
  True`, explicit and deliberate — login-flow discovery genuinely needs
  to follow a login redirect) and `fuzzlab.tools.spider`/`fuzzlab.tools.
  fetcher` (crawling components whose job is discovering pages through
  redirects) were reviewed and left unchanged — their redirect-following
  is the correct, intentional behavior for what they do, not an instance
  of this bug class.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior
occurrence of the same bug, or a different bug with the same root cause.

**Found a direct match: `BUG-0028`/`PA-0030`.** `BUG-0028` is the exact
same bug CLASS — an HTTP client silently applying a default
(redirect-following) that transforms what the server actually sent before
the code that claims to report "the real response" ever sees it — first
found in `fuzzlab.labgen.conformance.live_boot.LiveBootHarness`.

## Prior-preventive-action failure analysis

`PA-0030` (written from `BUG-0028`) states the rule in general terms — "A
harness that claims to report 'the real app's response' must not silently
apply a client default that transforms what the server actually sent
before the caller sees it (redirect-following, ...) unless that
transformation is the literal thing under test" — but its own worked
example and its own enumeration instruction ("enumerate what that
behavior needs from BOTH the client library's own documented defaults and
the framework/ORM's own default behaviors... that no existing case
happened to trigger") is framed entirely around *conformance harnesses*
(`*LiveBootHarness` classes) extending coverage to a new behavior
category. It was never applied as a sweep across every OTHER component in
this codebase making the same "I report the real response" claim —
`fuzzlab.tools.probesender.RequestsProbeSender`, `fuzzlab.greybox.run.
RequestsCorrelatingSender`, and `fuzzlab.tools.blind_sqli_fuzzer.
RequestsSender` are not conformance harnesses, they are oracle-facing
senders, and PA-0030's own wording gave no signal that they were in scope
too — even though `fuzzlab.core.http`'s own `allow_redirects=False` shows
this project's authors clearly already understood the authenticated path
needed the same fix; it just never propagated to the sibling
unauthenticated senders. This is the "too narrow" failure mode named in
CLAUDE.md's own bug-workflow: `PA-0030`'s rule was correct and, where
applied, effective, but its own scope framing (harnesses extending
coverage) did not name the class of component (any sender whose output
feeds a `ConfirmationStrategy`/oracle) the rule's own underlying principle
actually covers.

## Preventive action

See `PA-0044` (`docs/PREVENTIVE_ACTIONS.md`): supersedes/strengthens
`PA-0030` by widening its scope explicitly from "a harness extending
coverage to a new behavior category" to **every component that builds a
`Probe` (or any object a `ConfirmationStrategy`/timing oracle inspects as
"the real target's response")** — not only `*LiveBootHarness` classes.
Same sweep discipline (`PA-0002`) already applied here: `RequestsProbeSender`,
`RequestsCorrelatingSender`, and `RequestsSender` were all found and fixed
in this same change; `fuzzlab.session.manager`'s login-flow fetcher and
the crawling tools (`spider`/`fetcher`) were reviewed and correctly left
alone since redirect-following is their own deliberate, correct behavior,
not an instance of this defect.
