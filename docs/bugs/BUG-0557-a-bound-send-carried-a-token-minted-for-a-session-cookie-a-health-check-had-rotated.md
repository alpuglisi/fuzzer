# BUG-0557 — A bound send carried a token minted for a session cookie a health check had rotated

- Date: 2026-10-22
- Status: fixed
- Severity: high

## Description
FR-FUZZ-67's binder fetches a form's page on the probe's own session and binds the
page's fresh values (a CSRF token) into the one send that carries the fetch's token
(`_FetchRoute`). That token compared the route, the identity label, the session
**generation** and a loss seen on the page's own answer. But the session manager
changes a session's cookies *inside* a generation: a health check that answers LIVE
adopts a rotated session id in place (`SessionManager._health_get` ->
`_adopt_rotation`, FR-SESS-23). So between the page fetch and the bound send, any LIVE
health check on a rotating app changed the cookie the bound send carried while every
check of the token still passed. The send carried the token minted for the old id on
the new id, the app refused it before its handler (403), and the oracle read that as a
negative. A re-login between the fetch and the send was caught, but only after the send
had gone out (its answer was left unread, a stated residual).

This is BUG-0544's residual N-R3-2, recorded after AU-REQID78's final round and pinned
by a strict xfail (`tests/test_replay_bindings.py::test_a_live_health_check_that_adopts_a_rotated_cookie_after_the_fetch_unbinds_the_send`);
this lane is the owner's follow-up (gap 2, item GAP-SESS).

## Where encountered
- The final-round check of AU-REQID78 (8fee220 and 3959dfc, plain Python on `git
  archive` exports, the real `SessionManager`, `HttpClient`, `SeamProbeSender`,
  `Oracle`), recorded as N-R3-2 in BUG-0544's "Residuals after the final round" and in
  `scratchpad/reqid78/residuals_r3.md`.
- Code at 7393c90: `fuzzlab/session/manager.py::_adopt_rotation` (writes
  `state.cookies[name] = value` in place, no new generation), called by `_health_get`
  for every LIVE check (`check_health`, so `verify_live`, `observe`'s policy-block and
  loss-shape checks, `_wait_out_pause`'s re-check in `prepare`) and by `_spa_probe`;
  `fuzzlab/tools/probesender.py::_FetchRoute` (`client`, `identity`, `generation`,
  `lost`) and `SeamProbeSender._send_on`, which compared `req.session_generation` with
  the fetch's **after** `self._dispatch(...)` had sent the request.

## What it caused to fail
On a PHP-like loopback app whose CSRF token is tied to the session id and which rotates
its id once on a logged-in `GET /` (the old id stays valid; its tokens do not move):
- **N2 (`verify_live`, which `_verify_main` runs after any copy login or re-login):**
  `[GET /form s2] [GET / s2 -> Set-Cookie s6, adopted] [POST /do sid=s6 csrf=tok(s2) ->
  403]`, verdict None, inconclusive None: a negative. The pinned test fails on 7393c90 at
  `('POST', '/do', 's6')` on the wire.
- **N1 (another send's policy block):** `[GET /form s2] [GET /waf s2 403] [GET / s2,
  rotated] [POST /do s8 tok(s2) -> 403]`: a negative.
- **N3 (a pause's LIVE re-check inside the bound send's own `prepare`):** `[GET /form s2]
  [GET /waf 403] [GET / 503] [GET / 200, rotated] [POST /do s8 tok(s2) -> 403]`: a
  negative. FR-FUZZ-67 claimed the pause re-check was covered; it was only when the
  re-check found a loss.
- **A re-login (the run's, or an isolated copy's) between the fetch and the send:** the
  POST went out on the new session with the old session's token (to the lab), and only
  its answer was left unread -- the residual FR-FUZZ-67 stated.

Every reflected-XSS / SQLi test of a token-protected form on such an app could come out
as a false negative.

## What the bug was identified to be
The bound send was checked against an identifier of the session (its generation), not
against the session material it carried. The manager has two kinds of material change --
an install (a login, an `adopt`: a new generation) and an in-place rotation adoption (the
same generation) -- and the check saw only the first. And the check ran after the send:
the material a send carries is decided inside the client's send (`prepare`), and the
sender only read what `prepare` recorded once the request had gone out.

## Root cause analysis
Five Whys:
1. *Why was the 403 read as a negative?* The bound send's token checks all passed: same
   route, same identity, same generation, no loss on the page's answer.
2. *Why did they pass when the cookie had changed?* `_adopt_rotation` changes
   `state.cookies` in place without a new generation, and nothing else in the token
   reflects the cookie values.
3. *Why did the token not reflect the cookie values?* PA-0544(5) (review round 3) defined
   "the session" to be checked as "its route, identity and generation, and a loss": the
   generation was taken for the identity of the session's material. FR-SESS-23
   (CC-SESS-0029) defines a generation as "each login and adopt", and the same change
   designed the in-place rotation adoption ("a check never kills its own session"). The
   round-3 sweep listed the changers of the generation (re-logins, copy re-logins), not
   the writers of the material.
4. *Why did a re-login still put a request on the wire?* The check was placed in the
   sender after `client.send`, because `prepare` runs inside the client's send and only
   records what it applied; the session layer had no way to be told what a send must
   carry before it applied anything. The round-3 fix accepted that as a stated residual.
5. *Why was no owner of "what material a send carries" in place?* Two components (SESS,
   which writes the material, and FUZZ, which binds values to it) each held half of the
   decision: FUZZ compared a number SESS publishes for another purpose (FR-SESS-23's
   signal staleness and FR-CORE-509's pool key), and no shared primitive said what a
   send's session material is or where it is compared.

**Root cause:** the identity of a session's material was approximated by a counter that
one of the material's two writers does not advance, and it was compared outside the
session layer after the send, because there was no one-owner mechanism for "the session
material this send carries", checked where the material is applied.

## Corrective action
CC-SESS-0030 and CC-FUZZ-0115 (this lane's commit on `lane/SESSROT`; FR-SESS-24 new,
FR-FUZZ-67 amended in place; SP-75 new):
- `fuzzlab/session/manager.py`: **`material_frame(*, expect=...)`** (SP-75's owner), a
  per-thread frame around one `client.send`. Inside it the first `prepare` of any
  `SessionManager` (the run's or an isolated copy's) records **`AppliedMaterial`** -- the
  state's generation and an HMAC-SHA256 under a per-process random key over every cookie
  and header name and value, never a value -- or None when it applies no session
  (anonymous, out of origin). Given an expectation, `prepare` compares the material it
  would apply, after any login, pause re-check or rotation its own way took, and raises
  **`SessionMaterialChanged`** before applying anything. One snapshot of the cookies and
  headers is digested and applied, so a rotation another thread adopts meanwhile is the
  next send's. `_adopt_rotation` replaces `state.cookies` in one assignment.
- `fuzzlab/tools/probesender.py`: the fetch opens a record-only frame and stores
  `carried.applied` in `_FetchRoute.material`; the bound send's `_send_on` dispatches
  inside `material_frame(expect=fetched.material)` and turns `SessionMaterialChanged`
  into `PrerequisiteUnavailable` (UNBOUND, never a negative). The after-send generation
  check stays for a session addon that keeps no frame (a test double).
- What changes for a generation: nothing. Its meaning (an install) and its consumers
  (FR-CORE-509's pool key, disco's execution key, PRG, isolation) are untouched.

Tests (each fails on 7393c90 and passes now): the N-R3-2 pin turned into a plain test
(`test_a_live_health_check_that_adopts_a_rotated_cookie_after_the_fetch_unbinds_the_send`,
now also asserting no POST); `test_another_sends_policy_block_whose_check_adopts_a_rotation_unbinds_the_bound_send`
(N1); `test_a_pauses_live_recheck_that_adopts_a_rotation_unbinds_the_bound_send` (N3);
`test_a_bound_send_on_a_real_copy_relogged_in_after_its_fetch_is_never_sent` (a real
isolated copy's re-login); `test_a_bound_send_on_a_session_relogged_in_after_its_fetch_is_unbound`
(amended: no POST goes out, where 7393c90 asserted the residual's one POST); and
`tests/test_session_material.py` (five tests of the frame on the real manager: a
rotation, a new generation with identical values, no session, the digest holding no
value, one frame per send).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a bound value checked against
the wrong notion of its session, and for in-place session changes missed by a consumer:
- **BUG-0544 / PA-0544(5)** (review rounds 2 and 3): the same bug. Round 2 checked the
  route, not the session; round 3 checked the generation, not the material, and left the
  sent request as a residual. N-R3-2 is this bug.
- **BUG-0533 / PA-0533(2):** "evidence is bound to the session it is about: to its
  origins, to its generation and the state object judged". Same root (a generation
  standing for the session), from the evidence side; the rotation adoption was designed
  there.
- **BUG-0552 / PA-0552:** disco re-installed a stale session; it publishes a
  generation's loss. A related consumer of "which session", but its material is a
  browser context's, not this send path's.
- **BUG-0549 / PA-0549(2):** a kept connection keyed by the session generation. Keying a
  pool by generation is correct (no connection-bound authentication, no jar); not this
  defect.
Result: a recurrence of BUG-0544 (PA-0544(5)) with the same root cause as PA-0533(2)'s
definition.

## Prior-preventive-action failure analysis
- **PA-0544(5) (BUG-0544 round 3) -- too narrow, and it accepted a residual its own text
  forbids.** It required "what is recorded and checked is the session, not only the
  route: its route, identity and generation, and a loss". The list was written from the
  round's repro (a re-login), so the generation stood in for the session material. The
  sweep enumerated the changers of the generation, not the writers of the material;
  `_adopt_rotation` writes the material in place and was not on the list. The same item
  also said "a generation that changed inside the send makes its answer unread", which
  made a request on the wire with another session's token an accepted outcome, beside
  its own sentence that "a gap in this check is never a stated residual".
- **PA-0533(2) (BUG-0533) -- wrong layer for this consumer.** It binds evidence to the
  generation and the state object; it never said that a state object's material can
  change while both stay the same, so a consumer reading "generation" as "material" had
  no rule against it.
- **Neither was enforced at the material.** PA-0544(5)'s tests drove re-logins only; no
  test drove a LIVE check with a rotating app between a fetch and its send until the
  final-round check did.

## Preventive action
**PA-0557** (strengthens PA-0544(5) and PA-0533(2)):
1. **A value obtained on a session is bound to the session's material, not to a name or
   a counter of it.** The material is every cookie and header the session layer applies
   (names and values) together with its generation. Any change between the setup request
   and the send that uses its result -- a re-login, an isolated copy's re-login, a
   cookie a health check adopted in place, any future writer -- refuses the send.
2. **The check is made where the material is applied, before it is applied**: the
   session layer's `prepare`, told what the send must carry (SP-75's
   `material_frame(expect=...)`), so nothing goes on the wire; a check after the send is
   only a fallback for an addon that cannot be told, never a stated residual.
3. **A sweep of a "same session" check lists every writer of the session's material**
   (every assignment to a state's cookies or headers after it is installed), not only
   the events that renumber it.
- Enforced by: tests/test_replay_bindings.py::test_a_live_health_check_that_adopts_a_rotated_cookie_after_the_fetch_unbinds_the_send, tests/test_replay_bindings.py::test_another_sends_policy_block_whose_check_adopts_a_rotation_unbinds_the_bound_send, tests/test_replay_bindings.py::test_a_pauses_live_recheck_that_adopts_a_rotation_unbinds_the_bound_send, tests/test_replay_bindings.py::test_a_bound_send_on_a_real_copy_relogged_in_after_its_fetch_is_never_sent, tests/test_replay_bindings.py::test_a_bound_send_on_a_session_relogged_in_after_its_fetch_is_unbound, tests/test_session_material.py::test_a_send_bound_to_its_fetchs_material_is_refused_after_a_live_check_rotates_it, tests/test_session_material.py::test_a_new_generation_with_the_same_cookies_is_other_material, tests/test_session_material.py::test_the_material_is_a_keyed_digest_never_a_value

**Sweep (PA-0002, by primitive).** Every writer of a state's material after install:
`_adopt_rotation` (from `_health_get`: every `check_health`, `verify_live`, `observe`'s
checks, the pause re-check in `prepare`; and `_spa_probe`, on a state not yet installed).
`SessionState.update_cookies` has no caller. `state.headers["Authorization"]` is written
only inside `_login`, before install. Every send that binds a value read on an earlier
send of the same session: the seam's binder (fixed here); `RequestsProbeSender` carries
the page's own cookies in its one-time token (no session manager, no rotation); the
legacy spider's selector-form submission (`tools/spider.py::_seam_submit`, CRAWL) sends a
form read from a page fetched on the static seam and is not bound to that page's
material: a rotation adopted by a check another worker's send triggers between the two
costs the crawl that submission's state (a coverage loss, not a test verdict). It is
outside this lane's files and stated for its owner (CRAWL), not fixed here. Consumers that
hold their own copy of the material (a disco browser context, the spider's browser
context, greybox's header) are not told of an adopted rotation; none of them binds a page
value through the seam.
