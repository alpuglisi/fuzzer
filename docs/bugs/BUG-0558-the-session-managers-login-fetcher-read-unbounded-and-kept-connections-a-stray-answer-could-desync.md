# BUG-0558 — The session manager's login fetcher read unbounded and kept connections a stray answer could desync

- Date: 2026-10-22
- Status: fixed
- Severity: high

## Description
The login handshake's fetcher (`fuzzlab/session/manager.py::_requests_fetch_factory`)
was a plain `requests.Session()`: no SP-60 bound (no wire or decoded ceiling, no
deadline, `r.text` taken whole) and urllib3's own pools, which keep a connection after an
answer even when more bytes followed it. One login's GETs and its credentials POST share
that session, so a stray answer after the login page could be read as the credentials
POST's answer, and a page that never finished (a decompression bomb, a drip) was read
whole or for as long as it lasted. Login discovery then took any failed candidate for
"no login form here", so an incomplete page ended the login as "no login form found",
charged to the re-auth cap.

It was BUG-0536's residual R2, pinned by a strict xfail
(`tests/test_bounded_reads.py::test_the_session_managers_login_fetch_is_bounded`) and
allowed by SP-60's guard ("AU-SESS403's file") for the session manager's owner; this lane
is that owner's follow-up (gap 4, item GAP-SESS).

## Where encountered
- BUG-0536's sweep (R2) and BUG-0549 review round 2 (SP-60's `exact_end` pools), at
  7393c90: `_requests_fetch_factory` (`sess = requests.Session()`), the one
  `UNBOUNDED_ALLOWED` entry for `fuzzlab/session/manager.py` in
  `tests/test_bounded_reads.py`, and `SessionManager._discover_login_form`'s
  `except Exception: continue`.
- Reproduced by the tests below against loopback peers.

## What it caused to fail
- **A stray answer became the login's answer.** A login page followed in the same
  segment by a second answer (a desynchronised upstream): urllib3 dropped the extra bytes
  with http.client's reader and kept the connection; the credentials POST rode it, and the
  upstream's next stray answer (a 302 setting `sid=evil`) was read as the POST's own. On
  7393c90 the login then landed on the login page with `sid=evil` and failed ("login
  ... was rejected"); a stray that set a cookie and landed elsewhere would have been
  adopted as the session
  (`test_a_stray_answer_after_the_login_page_never_reaches_the_credentials_post`).
- **An unbounded read.** A gzip page decoding to 40 MiB was decoded whole, five times
  (once per discovery candidate), in the process that holds the run's sessions
  (`test_the_session_managers_login_fetch_is_bounded`, GET and POST).
- **An incomplete page was a conclusion.** Discovery caught the failure as "a bad
  candidate", tried the next path, and raised `SessionAuthError("could not detect a
  login ... no login form found")`, which counts toward `max_reauth`: an identity could be
  capped for good by answers that were never read whole
  (`test_an_incomplete_login_page_is_a_failed_fetch_never_a_login_answer`).
- The credentials POST also shared the session's pooled connection (PA-0549(3): a body
  never shares a connection).

## What the bug was identified to be
The login fetcher's session was made outside SP-60 (allowed by the guard's reasoned
list), so neither the bounded read nor the exact-framing keep decision applied to it, and
discovery's catch-all turned a transport failure into a login answer.

## Root cause analysis
Five Whys:
1. *Why could a stray answer reach the credentials POST?* The fetcher's urllib3 pool kept
   the login page's connection although bytes followed the answer.
2. *Why was it not SP-60's pool, which closes such a connection?* The fetcher's session
   was `requests.Session()`, not `bodyread.bound(requests.Session())`; SP-60's guard
   allowed it by name.
3. *Why was it allowed?* BUG-0536's sweep found it (R2) in a file another lane
   (AU-SESS403) held, and pinned it for that owner: an allow-list entry plus a strict
   xfail. The merge of AU-SESS403 onto AU-BOUNDED (47a7053) then made the health fetcher
   AU-SESS403 had added beside it (`_plain_fetch_factory`) read bounded, in the same
   file, and left the pinned login fetcher as it was: nothing in that merge's checklist
   or harness asked for the open pins in the files it touched (the xfail kept xfailing,
   so the run stayed green).
4. *Why did BUG-0549's round 2 not catch it?* Its sweep table recorded "the session
   manager's login fetch" among the sessions "fixed by construction: the same pools",
   citing the guard's general claim ("every target session is bounded"), not the guard's
   finding for that file -- which was its allowance.
5. *Why did discovery turn a failed read into "no login form"?* `_discover_login_form`
   caught `Exception` per candidate ("a bad candidate URL is not fatal"), written before
   SP-60 had a typed incomplete marker; BUG-0536's sweep followed `BodyIncomplete` into
   the probe senders, greybox and the spider, not into the session layer it had pinned.

**Root cause:** a pinned exception to a whole-package rule lived on in a file its owner
then changed, and a later sweep counted the guard's general claim as covering it; with the
fetcher outside SP-60, the login's own catch-all made transport failures into login
answers.

## Corrective action
CC-SESS-0030 (this lane's commit on `lane/SESSROT`; FR-SESS-3 amended in place):
- `_requests_fetch_factory`: the login's session is `bodyread.bound(requests.Session())`
  -- wire and decoded ceilings, a deadline of four 15 s timeouts held by the watchdog,
  and SP-60's pools, which keep a connection only after an exactly framed answer
  (`exact_end`). An incomplete body raises `bodyread.BodyIncomplete`. The credentials POST
  goes on a one-shot bounded session that shares the login's jar and headers: a
  connection of its own, closed after it (PA-0549(3)).
- `_discover_login_form`: a transport failure (`requests.RequestException`, so
  `BodyIncomplete` too) propagates: a failed fetch, never "no login form", never charged
  to the re-auth cap; the seam maps it to "not observed" (SP-34).
- `tests/test_bounded_reads.py`: the session manager's `UNBOUNDED_ALLOWED` entry is
  removed, so the AST guard covers `fuzzlab/session/`; the pin is a plain test (GET and
  POST); two new loopback tests (an incomplete login page; a stray answer after the login
  page).
- The sweep of `fuzzlab/session/`: `_plain_fetch_factory` (the health GET) was already
  bounded, one fresh session per hop; `browserlogin.py`, `detect.py`, `state.py` and
  `cli.py` make no `requests` session. The guard now reports none outside the remaining
  reasoned entries (disco's watched runner, `tools/fetcher.py`, two lab-provisioning
  modules).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for unbounded target reads, kept
connections after a stray answer, and pinned residuals left by their owners:
- **BUG-0536 / PA-0536(1):** "every `requests` session fuzzlab makes is bounded where it
  is made", with an AST guard outside a reasoned list. The same defect: this fetcher was
  its R2.
- **BUG-0549 / PA-0549(3b):** "a keep decision a library makes for the code is the
  code's to verify"; its round-2 table listed this fetcher as covered.
- **BUG-0545 / PA-0545:** SP-60's incomplete marker followed into the spider's handler
  (a failed load is never a visited page); the same consumer rule, not applied to the
  login.
- **BUG-0528 / PA-0528:** an outcome that claims something held rests only on complete
  observations ("no login form" is such a claim).
Result: a recurrence of BUG-0536 (PA-0536(1)), with BUG-0549's sweep (PA-0549(3b)) and
PA-0545's consumer rule not reaching the session layer.

## Prior-preventive-action failure analysis
- **PA-0536(1) (BUG-0536) -- not followed through, and its guard's allowance had no
  end.** The rule is whole-package and its guard is exact, but the guard admitted this
  file by a reason that was a deferral ("AU-SESS403's file: pinned by ..."), not a
  property of the code. When the owner's merge changed the file (47a7053, which bounded
  the health fetcher beside it), nothing failed: the allowance and the xfail held, and no
  step asked for the pins in the files it touched.
- **PA-0549(3b) (BUG-0549 round 2) -- its sweep verdict was taken from the guard's
  claim.** Its table counted "the session manager's login fetch" as one of the sessions
  "fixed by construction" because the guard keeps every target session on SP-60's pools;
  the guard's allowance for that very file said the opposite.
- **PA-0545 / PA-0528 -- the consumer rule was swept by component, not by owner.**
  BUG-0545 followed `BodyIncomplete` into the spider; the session layer's discovery loop,
  which turned it into "no login form", was not on any sweep list because its fetcher was
  not yet bounded.

## Preventive action
**PA-0558** (strengthens PA-0536(1), PA-0549(3b) and PA-0545's consumer rule):
1. **The login handshake is a target exchange:** every fetcher the session layer makes is
   SP-60-bounded where it is made (ceilings, deadline, exact-framing pools), a send with a
   body takes a connection of its own (PA-0549(3)), and an incomplete or failed answer is
   a failed fetch -- never a login answer, never "no form here", never charged to a
   re-auth cap.
2. **An allowance in a whole-package guard is a property of the code, not a deferral.** A
   site deferred to another owner is a strict xfail on its behaviour (PA-0531(4)), and the
   guard's allowance for it names that xfail; the owner's next change to the file fixes
   it or re-justifies it in its change-control entry.
3. **A sweep verdict for a site cites the guard's finding for that site**, never the
   guard's general claim: a site on an allowance list is not "fixed by construction".
- Enforced by: tests/test_bounded_reads.py::test_every_requests_session_fuzzlab_makes_is_bounded, tests/test_bounded_reads.py::test_the_session_managers_login_fetch_is_bounded, tests/test_bounded_reads.py::test_an_incomplete_login_page_is_a_failed_fetch_never_a_login_answer, tests/test_bounded_reads.py::test_a_stray_answer_after_the_login_page_never_reaches_the_credentials_post

## Review round 1 (2026-10-22, on ffac4fa; SESSROT-B1, B4)

Two confirmed findings on this fix (CC-SESS-0030's and CC-FUZZ-0115's "Review round
1"; branch `lane/SESSROT-r1`). The sections above stand as written; where this section
corrects them, it says so.

### What each was
- **B1, the fix broke every login caller's contract.** The corrective action's
  `_discover_login_form` change let a transport failure (`requests.RequestException`,
  `BodyIncomplete` included) escape `ensure` and `prepare`, where a failed login had
  always been a `SessionAuthError` -- counted toward `max_reauth` and handled by every
  caller. The fix checked only the seam (its Impact line: "the seam: 'not observed'").
  Measured by the reviewer on a peer that cuts every GET (`Content-Length: 100`, ten
  bytes), six `SeamProbeSender.send` calls on the real manager: on 7393c90 three
  `SessionAuthError` ("no login form") then three "re-auth cap (3) reached"; on
  ffac4fa six `ProbeUnobserved`, `_failures` empty, `_attempts` 6, one login GET per
  send -- never capped, every candidate inconclusive. By reading the code, the same
  change made disco's `_recover_session` (which catches `SessionUnavailable` and
  `SessionAuthError`) escape its worker (`stop='error'`, the run re-raised), sent the
  spider's `_seam_send` into its per-page handler (each page failed and retried the
  login instead of `IdentityUnavailable` stopping the crawl), ended `greybox-run
  --identity` and `session print` in a traceback, and let one cut candidate
  (`/login`) end discovery before a form at `/signin` or the browser fallback
  (FR-SESS-19) was tried. Already open on 7393c90: a transport failure of the
  credentials POST or of the follow-up check escaped `_log_in_locked` uncaught.
- **B4, the incomplete-login-page test did not reach the behaviour it names on the old
  code.** Its fixture was the bomb, which the old plain `requests.Session()` decoded
  whole (40 MiB, five candidates, no error): no candidate failed, discovery's
  `except Exception: continue` never ran, and the test failed on 7393c90 for the
  unbounded read -- the bounded-fetch test's reason (the lane's own record,
  `prefix_proof.log`, ~lines 276-335; the skeptic's re-run). So "What it caused to
  fail" bullet 3 ("Discovery caught the failure as 'a bad candidate'...", citing that
  test) had no record behind it and contradicted bullet 2 ("decoded whole, five
  times"); CC-SESS-0030's Effectiveness line gave its pre-fix reason as "the unbounded
  read".

**Corrections.** Bullet 3 of "What it caused to fail" is replaced by: *a login page cut
short (a short body, a reset) -- which the old plain session raises on
(`ChunkedEncodingError`) -- was caught by discovery as "a bad candidate"; every
candidate was tried and the login raised `SessionAuthError("could not detect a login
... no login form found")`, which counts toward `max_reauth`* -- recorded on 7393c90 by
the test's new `cut` fixture (below). The corrective action's `_discover_login_form`
bullet ("a transport failure ... propagates ...; the seam maps it to 'not observed'")
is superseded by the corrective action of this round.

### Root cause analysis (Five Whys, across the two)
1. *Why did B1 reach review?* The fix changed what `SessionManager.ensure` and
   `prepare` raise, and its sweep and tests covered one caller: the seam, the path the
   residual came from.
2. *Why one caller?* The sweep followed SP-60's marker (`BodyIncomplete`) to its
   consumers -- the rule PA-0545(2) states ("SP-60's markers are followed into every
   handler") -- and SP-34 already maps it on the seam. It did not list the callers of
   the function whose raise contract changed; a propagated `RequestException` reads as
   "the typed marker reaching its caller", while to every other caller it is a type
   they never caught.
3. *Why was no rule asking for the callers?* PA-0558(1) as drafted said what a failed
   fetch is not ("never a login answer, never 'no form here', never charged to a
   re-auth cap") and not what it is to the caller. CLAUDE.md item 7 (sweep every caller
   of an owner) is written for shared primitives, and `ensure`'s raise contract is in
   no SP row.
4. *Why did B4's test fail on 7393c90 for another reason?* It was written against the
   new code's path (the bounded fetcher raising on the bomb), and its pre-fix run was
   read as "it failed" rather than at which assertion -- PA-0545(6), not followed.
5. *Why did the bug doc then claim the catch-all?* The doc's claim was written from the
   code's reading (the catch-all exists) and attached to the test that was meant to
   show it, without reading the record that showed it never ran.

**Root cause:** a change to what a widely called function raises was swept by the
consumers of the marker it carries, not by the function's callers; and a pre-fix proof
was taken from "failed" instead of from its own assertion.

### Prior-preventive-action failure analysis
- **PA-0545(6) (BUG-0545) -- not followed.** The record existed (`prefix_proof.log`)
  and showed the unbounded read; the claim was written from the code.
- **PA-0002 / CLAUDE.md item 7 -- too narrow for this change.** "Sweep every caller of
  the owner" is attached to the shared-primitive table; a raise-contract change of a
  function in no row was swept by symptom (the seam), the failure mode PA-0002 names.
- **PA-0558(1) (this bug, as first drafted) -- incomplete.** It forbade the old
  outcomes without saying what a caller receives, so "propagate the transport error"
  satisfied it while breaking the callers.

### Corrective action (round 1)
CC-SESS-0030 and CC-FUZZ-0115, "Review round 1" (FR-SESS-3 and FR-FUZZ-50 edited in
place):
- `fuzzlab/session/manager.py`: **`LoginFetchFailed`** (a `SessionAuthError`). Discovery
  records a candidate whose page was not read (`unread`, a required argument) and tries
  the others; `_login` tries the browser fallback first and raises `LoginFetchFailed`
  only when none yields a login, chained to the first unread page's transport error
  and naming only its class; `_log_in_locked` turns a transport error anywhere else in
  the login (the credentials POST, the follow-up check: the sweep of 7393c90's open
  paths) into one too. It is never charged to `max_reauth`; its own cap,
  `max_login_fetch_failures` (default 3) consecutive per (host, identity), reset by a
  login that succeeds, refuses the next login with a plain `SessionAuthError` before
  anything is fetched. An isolated copy raises it as is and inherits the cap.
- `fuzzlab/tools/probesender.py::_unobserved` (SP-34's owner): a `LoginFetchFailed` is
  classified by its transport cause (cut, reset or incomplete: "not observed"; an
  unreachable page or a timeout: loud), so the seam's probe is "not observed" only
  under the cap.
- The sweep, every caller of `ensure`/`prepare` with its disposition: the seam
  (`SeamProbeSender.send`, `fetch`, `_dispatch`, `_create_copy`: SP-34 by cause; a
  copy's cut login is a failed copy login as before); disco's `_recover_session`
  (`_end_authenticated`); the spider's `_seam_send` and `_session_host_refusal`'s
  `prepare` (`IdentityUnavailable`: the crawl stops); `greybox-run`'s `_cookie_for` (`p.error`);
  `session print` ("login failed", 1); and, loud as any `SessionAuthError` as on
  7393c90: `browserauth._ensure` (disco's start, the spider's browser engine,
  `tools/fetcher.py`'s browser start), the `ensure` of `blind_sqli_fuzzer` and
  `tools/fetcher.py`'s CLIs, and blind-SQLi's `SeamSender` (which maps a timeout only).
- Tests, `tests/test_login_fetch_failed.py`, one per caller on a loopback app that cuts
  the login page: the seam (three sends "not observed", every candidate once each, then
  the cap's loud `SessionAuthError` with no request), disco's recovery, the spider's
  static crawl, `greybox-run`, `session print`; and the login itself: a cut `/login`
  never hides a form at `/signin`, and a cut credentials POST is `LoginFetchFailed`.
  `tests/test_bounded_reads.py::test_an_incomplete_login_page_is_a_failed_fetch_never_a_login_answer`
  runs on a `cut` page (B4) and asserts the new contract.
- Pre-fix records. **On ffac4fa** (one pytest invocation with ffac4fa's `manager.py` and
  `probesender.py` swapped in -- `manager.py` also carrying BUG-0557's round-1 revert in
  three frame functions none of these tests reaches; the same eight failed the same way
  on the unmodified ffac4fa files in a plain-Python check -- record
  `scratchpad/lanes/SESSROT/r1_prefix_proof.log`), each of the eight fails at its own
  assertion: the seam gives five "not observed" where three and then two cap errors are
  wanted; disco's recovery lets `ChunkedEncodingError` escape; the static crawl returns
  without `IdentityUnavailable` (its log: `/expiring` and `/secret` each "unresolved
  after 3 load(s)", every load a login retry); `greybox-run` raises
  `ChunkedEncodingError`, not `SystemExit(2)`; `session print` the same, not 1; the cut
  `/login` ends the login before `/signin`; the cut credentials POST is a
  `ChunkedEncodingError`, not a `SessionAuthError`; and the incomplete-login-page test
  gets a `ChunkedEncodingError`, not a `SessionAuthError`. **On 7393c90** (this round's
  `test_bounded_reads.py` on 7393c90's `fuzzlab/`, the test function called with a real
  `_Peer("cut")` in plain Python, record `scratchpad/lanes/SESSROT/r1_b4_7393c90.log`),
  the incomplete-login-page test fails at its first assertion: `could not detect a
  login for alice@127.0.0.1: no login form found ...` -- discovery's catch-all took the
  cut candidates for pages without a form (the corrected bullet 3).

### Preventive action
**PA-0558** is amended before its merge (its text in the lane's `doc_texts.md`): item 1
now says what the caller receives (the layer's own typed failure, `LoginFetchFailed`,
after every candidate and the browser fallback, with its own cap), and a new item 4
makes a change to what a function raises a sweep of that function's callers, each
caller's disposition measured by a test that drives it. Its Enforced-by line adds the
seven tests above.
