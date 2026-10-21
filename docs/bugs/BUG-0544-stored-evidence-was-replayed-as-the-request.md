# BUG-0544 — Stored evidence was replayed as the request

- Date: 2026-10-21
- Status: fixed (CC-FUZZ-0111, CC-AUD-0056, CC-CORE-0073)
- Severity: high (CRITICAL in the owner's audit, defect 7)

## Description

A stored sibling set is evidence: redaction (PA-0100) blanks a CSRF token, any sensitive
name and an identifier-like value, and the point builder replaced a host-shaped default
with loopback (FR-AUD-20). The pipeline then sent those stored values as the request's
own: `csrf_token=""`, `id=""`, `ref=http://127.0.0.1/`. A one-time token's form was
rejected before its handler ran, a blanked object key reached another code path, and the
result read as a negative (or as session loss).

## Where encountered

Owner-supplied adversarial audit at 6552276, defect 7 (`core/forms.py` `form_record`,
`tools/store_adapter.py` `redact_sibling`, `harness/auto.py` `_send_value` and the
builder's entries). Reproduced in `tests/test_replay_bindings.py` on c483dc1:
`csrf_token=one-time` is stored blank and sent blank on every probe.

## What it caused to fail

- Every fuzzed POST of a form with a one-time or session-bound token was refused before
  the vulnerable handler; the candidate was marked `checked`: a false negative (FR-FUZZ-42
  even listed "forms needing a fresh CSRF token do not confirm" as a residual).
- A link or captured body whose identifier sibling was blanked exercised a different
  handler path.
- A request carrying a loopback stand-in for the app's own host value was a request the
  app never made; header points' queries did the same.

## What the bug was identified to be

The stored entry list served two roles: persisted evidence (which must be redacted) and
runtime replay material (which must be the app's real request). Nothing recorded which
stored values were placeholders, nothing re-obtained them before a send, and nothing
refused a send that could not be rebuilt.

## Root cause analysis (Five Whys)

1. Why was `csrf_token` sent blank? The binder sent the stored entry list as is.
2. Why was the stored value blank? Redaction blanks a token before storage (PA-0100,
   correct for evidence).
3. Why did the binder not obtain a real one? Nothing told it the value was a placeholder,
   and no sender could fetch a page on the probe's session route.
4. Why was a send that could not be rebuilt still made? A missing prerequisite had no
   outcome other than "send what we have": the oracle's only no-verdict outcomes were
   unplaceable, unobserved and not comparable.
5. **Root cause:** persisted evidence was used as the replay template. The redaction
   boundary had no counterpart that separates "what may be stored" from "what must be
   sent", so every redaction or substitution silently became part of the request.

## Corrective action

- The importer records each sibling set's replay recipe (migration 25: `form.source_page`,
  `form.fresh`): the page it came from and the names of the placeholders; names and a page
  only (CC-AUD-0056, CC-CORE-0073).
- Before each send the oracle's binder fetches that page through the new sender `fetch`
  on the probe's own route and binds the placeholders' current values in memory
  (`core.forms.page_template_entries`); otherwise `PrerequisiteUnavailable`, and the
  candidate is inconclusive (`UNBOUND`) with the reason (CC-FUZZ-0111).
- A sibling naming a host outside the lab is never sent and never replaced: its point
  carries a `replay_refusal`; a loopback value is sent as given (FR-AUD-20 amended,
  `value_shape.names_outside_lab`).
- The fingerprint baseline, header points and the M6 browser never send a placeholder.
- Tests: `tests/test_replay_bindings.py` (the reproduction, the inconclusive paths, D12,
  a real-socket session jar), the fetch guards in `tests/test_sender_conformance.py`;
  amended with before/after: `test_forms_phase2` (three), `test_json_points` (one, split
  in two).

## Review round 1 (85e7ab2): what the first fix missed

Two reviewers and a skeptic reproduced seven blocking defects in the first fix (the
eighth review finding is BUG-0530's). Each is fixed in the revision, with a test that
fails on 85e7ab2 (`tests/test_replay_bindings.py`):

1. **The recipe stored a value (B1, R2-B2).** `form.source_page` kept the page's raw
   query: a disco Referer (`?api_key=…&ref=<uuid>`) and a crawl's `found_from`
   (`?t=<hex32>`) reached the store and candidate evidence, and the binder fetched a URL
   holding a redaction placeholder. Fix: `core.redaction.page_url_is_clean` (the strongest
   URL redactor leaves it unchanged, no placeholder, no empty query value); an unclean
   page is never stored (no page: unbound) and the binder never fetches one.
   Tests: `test_a_source_page_holding_a_secret_or_an_identifier_is_never_stored`,
   `test_a_page_whose_url_holds_a_redacted_value_is_never_fetched`.
2. **The anonymous sender's carried cookie was a sticky flag (B2, R2-B4).** A refused
   binding left the page's cookie for the next unrelated probe (BUG-0112). Fix: the page's
   cookies are held in memory under a one-time token (`probe.carry`) and loaded only into
   the send whose bound entries carry that token; every send discards them first. Test:
   `test_a_refused_binding_never_lends_its_pages_cookie_to_another_probe`.
3. **The loopback test was bypassable (B3).** `127.0.0.1:80@evil.example/`,
   `localhost:1@evil.example` and `http://evil.example\@127.0.0.1/` passed as loopback.
   Fix: `names_outside_lab` fails closed (`_names_only_lab`: no `@`, `\`, `%` or control
   character; http(s) only; the whole authority loopback with a numeric port under a
   manual split and `urlsplit`; no other host or URL in the tail). Test:
   `test_a_value_that_names_a_host_beyond_loopback_to_any_reader_is_outside_the_lab`.
4. **Sends outside the binder went out unbound (B4).** A JSON or raw-body send to the
   candidate's own request skipped the binder (NoSqlOperatorStrategy), sending a fake leaf
   and recording a negative. Fix: every send to the candidate's own (url, method) while it
   needs fresh values is bound or refused; a JSON candidate needing one is unbound before
   any strategy runs. Tests: `test_a_json_point_needing_a_fresh_leaf_sends_nothing_and_is_unbound`,
   `test_the_binder_refuses_a_raw_or_built_send_to_its_own_request`.
5. **The seam fetched a login page with the run's session (B5).** Its gates read the
   probe's route, not the page. Fix: the page's own auth-endpoint and isolated-path gates,
   as a PRG follow-up's. Test: `test_the_seam_never_fetches_a_login_page_with_the_runs_session`.
6. **A source page on another origin was bound (B6).** Fix: the builder keeps a page only
   on the point's own origin; the binder refuses another origin and a page fetched without
   the probe's session (a session note). Test: `test_a_source_page_on_another_origin_is_never_bound`.
7. **The seam carries no response cookie on any route (R2-B1).** A token tied to a cookie
   the page set was bound into a send without that cookie: rejected, read as a negative.
   Fix: the seam's fetch refuses a page that sets a cookie (unbound). Test:
   `test_the_pages_session_is_carried_into_the_bound_send_only_or_the_test_is_unbound[seam]`.

**Why the first fix missed them.** It treated the binding as a value problem only. The
fetch is itself a request -- with its own URL, session, origin, cookies and send gates --
and the recipe is itself a stored value; neither was put through the rules every other
request and every other stored value already follow (PA-0100, PA-0514(1), PA-0134,
FR-FUZZ-40/44, BUG-0112). PA-0544 is strengthened accordingly (items 5-7).

## Review round 2 (0703688): what round 1 still missed

An adversarial check of the round-1 commit reproduced every round-1 repro as fixed, and
found two neighbouring paths of the same defects still open (a skeptic reproduced both on
a `git archive` export of 0703688). Each is fixed with a test that fails on 0703688
(`tests/test_replay_bindings.py`):

1. **The loopback test failed closed on the authority but not on the tail (R2-1).**
   `_names_only_lab` cut the path, query and fragment on a fixed separator list without
   `:` and counted a token as a host only when `value_shape` read it as a URL, IP or host
   name. So a loopback URL whose tail named a host as host:port, or as a scheme and `:`
   without `//`, still counted as the lab and was sent as given:
   - `http://127.0.0.1/?next=evil.example:8080`;
   - `?next=8.8.8.8:53`;
   - `?next=https:evil.example` (`https://evil.example/` to WHATWG, measured in node 22);
   - `127.0.0.1/go?to=evil.example:443`;
   - `localhost:3000/r?u=evil.example:80/x`;
   - `#evil.example:8080`.

   The binder's fresh-value check reads the same predicate, so `_bind_fresh` bound the
   same shapes. This is a weakening against dcc7091, which replaced each of them with
   loopback.

   Fix: the tail is cut at every character a host, port, scheme or IPv6 literal is not
   spelled with. A value is the lab only when no run reads as a host to any reader
   (`_reads_as_host`):
   - `value_shape`'s URL, IP or host name, one trailing dot off;
   - a dotted quad in any radix;
   - a scheme and `:`, with or without `//`;
   - a host and a port (dotted, numeric or bracketed).

   A loopback host in the tail now counts too, and non-ASCII is refused like `%`.
   Measured in node 22, with `http://` put before the token: host:port, hex quads,
   underscore labels and fullwidth letters each read as a host.

   Tests:
   - `test_a_value_that_names_a_host_beyond_loopback_to_any_reader_is_outside_the_lab`
     (every spelling above, the four of round 1 and six more of the class);
   - `test_the_binder_never_binds_a_fresh_value_that_names_a_host_beyond_loopback`
     (the same spellings, and the loopback values, through the binder);
   - `test_a_value_naming_only_loopback_is_the_lab`.
2. **The bound send could leave on another route than its page's fetch (R2-2).** Round 1
   chose the fetch's route from the probe's URL and checked the page's own gates. It never
   checked that the bound send took that same route. On the N3 path:
   - the fetch went out on the isolated copy, whose re-login on that fetch logged the
     run's session out;
   - `_on_copy`'s verify tripped the single-session breaker;
   - the page (fetched with the copy's cookie) set no cookie, so the token was bound;
   - the bound send was routed anonymously and carried a token tied to a cookie it
     never sent.

   The app answered 403 before its handler, and `ReflectedXssStrategy` read that as a
   negative.

   Fix: the seam's fetch records the route its GET actually went out on (`_FetchRoute`:
   client and identity label) as the fetch's carry token, and the seam refuses the send
   carrying it when that send would leave on another route or identity
   (`PrerequisiteUnavailable`: the row is `UNBOUND`). The refusal also covers the copy
   failing to log in again for the send.

   Test: `test_a_bound_send_never_leaves_on_another_route_than_its_pages_fetch`. It uses a
   loopback app whose token is tied to the cookie, the real seam, binder, oracle and
   strategy, and fakes only the copy's session and `verify_live`. The control round
   confirms on the copy's route. After the trip, the GET is the only request: no POST.

**Why round 1 missed them; why PA-0544(5) and (7) did not prevent it.**
- *Item 7 was not followed for the tail.* It required the predicate to fail closed
  against every reader's parse, proven on the bypass shapes. Round 1 proved it on the
  four shapes the reviewer gave and kept a deny-list for the tail. A deny-list fails
  open on the next spelling of the same class.
- *Item 5 was too narrow, and checked at the wrong time.* It said the fetch is made on
  the session the bound send carries, but round 1 checked that only when the fetch chose
  its route. A route can change during the fetch (a copy's verify trips the breaker) or
  between the fetch and the send. Only the send can compare them.

PA-0544 items 5 and 7 are strengthened in place (marked *Review round 2*). No new PA:
same bug, same rules, made exact.

Residuals (stated in FR-FUZZ-67 and CC-FUZZ-0111):
- The route check compares the route and identity, not the session's generation, so a
  re-login of the same route between the fetch and the send is not caught.
- A standalone `https:evil.example` sibling (no loopback authority) is not a value
  `neutral_value` replaces, so FR-AUD-20 does not reach it. That is unchanged from
  dcc7091 and out of this round's scope.

## Review round 3 (3959dfc): the final round, on the owner's chosen design

A third adversarial check (`review_round3.md`; plain Python on `git archive` exports of
3959dfc, dcc7091 and 0703688, WHATWG measured in node 22) found every round-2 repro fixed
and one neighbouring path of each finding still open. The owner then chose the design
(2026-10-21, "final round, allow-list"): a loopback value keeps its path, query and
fragment only when no tail token holds a `.` or a `:` or is a number (any radix, any
length); anything else is replaced by plain loopback as at dcc7091; false positives
(`?page=2`) are accepted; nothing may leave the lab. The bound send is also refused when
the session changed after the page fetch. There is no round after this one. Each fix has
a test that fails on 3959dfc for its stated reason (one invocation on 3959dfc's product
files: 45 failed, 71 passed; `tests/test_replay_bindings.py`):

1. **The tail rule was still a recogniser of hosts (R3-1).** Round 2's `_reads_as_host`
   flagged a portless token only when `value_shape` read it as a URL, IP or host name,
   or `_ipv4_like` read four dotted parts. `value_shape`'s host name needs a two-letter
   TLD or one in the closed `GENERIC_TLDS` set, so a real gTLD outside it passed, and so
   did a one- to three-part or integer IPv4 address. Each of these was sent verbatim and
   bound fresh at 3959dfc (dcc7091 replaced every one with `http://127.0.0.1/`):
   - `http://127.0.0.1/?next=evil.top`, `?next=evil.shop`, `?next=attacker.tech/x`,
     `?next=evil.mov`, `/go/evil.top`, `127.0.0.1/?u=evil.store`,
     `localhost:3000/r?u=evil.live`, `#evil.zip` (a `filename` to `value_shape`);
   - `?next=134744072`, `8.8.2056`, `8.526344`, `0x8080808`, `0x08.0x08.0x0808` (each
     8.8.8.8 to `new URL("http://" + t)` in node 22).

   Fix: the tail rule is an allow-list of a stated grammar, never a recogniser
   (`value_shape._tail_in_grammar`; FR-AUD-20 states the grammar): the separators
   `/ ? # & =` (never `//`) between words of ASCII letters, digits, `_`, `-`, `~` whose
   first character is not a digit. `_tail_tokens`, `_ipv4_like` and `_reads_as_host`
   are gone. The binder's fresh values pass through the same predicate.

   Tests:
   - the thirteen spellings above (`_OUTSIDE_LAB_R3`) in
     `test_a_value_that_names_a_host_beyond_loopback_to_any_reader_is_outside_the_lab`
     and `test_the_binder_never_binds_a_fresh_value_that_names_a_host_beyond_loopback`,
     with the round-1 and round-2 spellings kept;
   - `test_every_spelling_of_the_generated_sweep_is_outside_the_lab`: 1,414 values, every
     token in seven tail positions (path, query, fragment; `http://127.0.0.1`,
     `127.0.0.1`, `localhost:3000`, `http://[::1]:8080`, `https://localhost`). The
     tokens: gTLDs not in `GENERIC_TLDS` (bare, nested, trailing dot, with a path); every
     one- to four-part decimal, `0x`, `0X` and octal spelling of 8.8.8.8, 1.2.3.4 and
     127.0.0.1; scheme-colon; host:port; bracketed literals; `//`; `%`; fullwidth and
     other non-ASCII spellings;
   - `test_the_tail_rule_is_an_allow_list_never_a_recogniser_of_hosts` (AST: the tail
     predicate names no shape classifier, TLD or extension list or address parser);
   - `test_a_value_naming_only_loopback_is_the_lab`: the loopback controls still keep
     their tail (`http://127.0.0.1/`, `http://127.0.0.1:3000/login?next=/account`,
     localhost paths of plain word segments, `[::1]`, `~alice`).

   Accepted false positives (asserted as outside): `?page=2&sort=name`, `app.js?v=1.2.3`,
   `?a=1`, `?at=10:30`, `?q=a+b`, `/2fa`, `/a;b`, `?ids=a,b`. Stated residual: a dotless
   word (`?next=intranet`) is in the grammar; only a resolver completing it from a search
   list reads it as a host.
2. **The route check did not compare the session (R3-2).** Round 2 recorded the fetch's
   client and identity label and refused the bound send only on another route or
   identity, and stated the rest as a residual. On the real `SessionManager` (requests
   login, credentials in memory) with a PHP-like app that keeps a logged-out id and shows
   the login box next to the form:
   - the session was logged out server-side;
   - the page fetch went out on it (`sid=s2`), and its answer showed the login box, so
     `observe` marked the session lost (its listeners were told), while `prepare`'s own
     `session_lost` on the fetch was still False;
   - the bound send's `prepare` logged in again (`GET /`, `POST /login`, `GET /`: `s7`)
     and posted `s2`'s token on `s7`: 403, and the row was a negative.

   0703688 behaved the same: round 2 had not touched this path.

   Fix (`tools/probesender.py`): `_FetchRoute` also records the session generation the
   fetch's `prepare` applied (`Request.session_generation`, read, never recomputed) and
   `lost`: the run's manager or the copy's told a loss of the identity while the fetch's
   GET was in flight (`_on_session_loss`, a FR-SESS-16 listener counting losses), or
   `prepare` flagged the session lost. Then:
   - `_FetchRoute.refusal` refuses the bound send before anything is sent when it would
     leave on another route or identity, or when the page's own answer lost the session;
   - `_send_on` refuses the bound send's answer when its `prepare` applied another
     generation than the fetch's (a re-login in between that no listener was told of:
     a time expiry, a loss found while a pause was waited out, another send's loss);
   - `_on_copy` still verifies a copy's re-login when the send is refused.
   Each raises `PrerequisiteUnavailable`, so the row is `UNBOUND`, never a negative.
   Nothing in the session layer or `core.http` changed.

   Tests:
   - `test_a_page_whose_own_answer_lost_the_session_is_never_bound_on_the_next_login`
     (the checker's path, real manager: after the page, no re-login and no POST);
   - `test_a_bound_send_on_a_session_relogged_in_after_its_fetch_is_unbound` (real
     manager; another send sees the loss after the fetch);
   - `test_a_bound_send_on_a_copy_relogged_in_after_its_fetch_is_unbound_and_verified`
     (an isolated copy logged out after the fetch; the single-session breaker still
     trips).

   Stated residual: `prepare` runs inside the client's send, so a bound send whose own
   `prepare` logged in again has gone out (to the lab, on the new session, with the old
   token) before its generation is known. Its answer is never read.

**Why round 2 missed them; why PA-0544(5) and (7) did not prevent it (recurrence).**
- *Item 7 was followed in name, not in substance.* It said the predicate admits only
  what it proves, "never by denying the shapes found so far". Round 2 wrote "proves" as
  "no recogniser of a host fires on the tail", which is a deny-list of the shapes its
  recognisers know: `GENERIC_TLDS` and four-part quads. The rule did not say what proof
  is, and its test covered named spellings, not a generated class.
- *Item 5 stopped at the route.* It required the send to be checked against the setup
  request's route at the send, but a route is not a session: one route can carry two
  sessions in a row. Round 2 saw the gap and wrote it down as a residual, which hid a
  false-negative source (PA-0530(4) names that failure mode for merged inputs).

PA-0544 items 5 and 7 are strengthened in place (marked *Review round 3*). There is no
new PA: same bug, same rules, made exact.

## Recurrence review

Checked `docs/bugs/` and `PREVENTIVE_ACTIONS.md` for a stored or redacted value reused as
a live value, or a substitution sent as the app's value:
- BUG-0099 / PA-0100 (the storage boundary): the cause of the placeholders, correct for
  evidence; it says nothing about replay.
- BUG-0124 (the redirect seed, FR-AUD-21's exception): about sending an app's host, not
  about placeholders.
- BUG-0110 / PA-0111 (form serialisation like a browser): the entry list's *shape*, not
  its values' provenance.
- FR-FUZZ-42's stated residual "forms needing a fresh CSRF token do not confirm".

No prior bug with this root cause. Related rule gap: a stated residual hid a false-negative
source (the same failure mode as BUG-0530's "first wins" residuals).

## Prior-preventive-action failure analysis

Not required (no same-root-cause match). PA-0100 is not weakened: storage stays redacted.

## Preventive action

**PA-0544** (complements PA-0100):
1. A persisted value is evidence, never replay material. A value redaction blanked or a
   stand-in replaced is recorded as a placeholder (by name, never by value) where it is
   stored, and is never sent as the request's own.
2. Before a send that needs it, the value is re-obtained by an authorized setup step on
   the probe's own session route and bound in memory only (D12).
3. A send whose prerequisites cannot be rebuilt is not made: the test is inconclusive
   with the reason, never a negative.
4. A wrapper of the sender protocol reports and forwards every optional capability its
   inner sender has (`fetch_capable` like `prg_capable`), proven on a synthetic wrapper
   that hides it.
5. *(Review round 1.)* **A setup request is a request**: it passes every gate a probe or
   a PRG follow-up passes, judged on its own URL (send gate, auth endpoints, isolated
   paths), and is made on the session the bound send carries -- same origin, no session
   note, and any cookie it receives either carried into that one send or the test is
   unbound. *(Review round 2:)* the route the setup request actually went out on is
   recorded, and the send that uses its result is checked against it **at the send**
   (the route can change during or after the setup request); a different route or
   identity makes the test unbound. *(Review round 3:)* what is recorded and checked is
   the **session**, not only the route: its route, identity and generation, and a loss
   the session layer saw on the setup request's own answer. A loss known before the send
   refuses it before anything is sent; a generation that changed inside the send makes
   its answer unread. A gap in this check is never a stated residual: it is a
   false-negative source, fixed or pinned (PA-0530(4)).
6. *(Review round 1.)* **State a setup request leaves for one send is bound to that send**
   (a token the send carries), never a sender-wide flag; every other send discards it.
7. *(Review round 1.)* **A recipe is a stored value**: what it records passes the strongest
   existing redactor, and anything the redactor would change is not stored at all; a
   safety predicate that admits a value (loopback) fails closed against every reader's
   parse, proven on the bypass shapes. *(Review round 2:)* it admits only what it proves
   for **every part** of the value (authority and tail), never by denying the shapes
   found so far; its test covers each bypass class with more than the reported spelling.
   *(Review round 3:)* "proves" means **an allow-list of a stated grammar**: the
   predicate asks whether every part is in the grammar it states, never whether a part
   reads as the forbidden thing (no recogniser, classifier, closed list or parser of the
   forbidden thing decides admission). It is enforced by a guard that the predicate
   reads no recogniser, and by a generated sweep of each bypass class, not a list of
   reported spellings.

- Enforced by: tests/test_replay_bindings.py::test_a_blanked_csrf_token_is_bound_fresh_before_each_send, tests/test_replay_bindings.py::test_a_token_that_cannot_be_fetched_is_inconclusive_never_negative, tests/test_replay_bindings.py::test_no_fresh_value_reaches_the_store, tests/test_replay_bindings.py::test_a_sibling_naming_a_host_is_sent_as_given_on_loopback_and_never_off_it, tests/test_sender_conformance.py::test_every_wrapper_reports_and_forwards_its_inner_senders_fetch, tests/test_sender_conformance.py::test_the_fetch_guard_catches_a_wrapper_that_hides_it, tests/test_replay_bindings.py::test_the_seam_never_fetches_a_login_page_with_the_runs_session, tests/test_replay_bindings.py::test_a_source_page_on_another_origin_is_never_bound, tests/test_replay_bindings.py::test_the_pages_session_is_carried_into_the_bound_send_only_or_the_test_is_unbound, tests/test_replay_bindings.py::test_a_refused_binding_never_lends_its_pages_cookie_to_another_probe, tests/test_replay_bindings.py::test_a_source_page_holding_a_secret_or_an_identifier_is_never_stored, tests/test_replay_bindings.py::test_a_value_that_names_a_host_beyond_loopback_to_any_reader_is_outside_the_lab, tests/test_replay_bindings.py::test_the_binder_refuses_a_raw_or_built_send_to_its_own_request, tests/test_replay_bindings.py::test_the_binder_never_binds_a_fresh_value_that_names_a_host_beyond_loopback, tests/test_replay_bindings.py::test_a_bound_send_never_leaves_on_another_route_than_its_pages_fetch, tests/test_replay_bindings.py::test_every_spelling_of_the_generated_sweep_is_outside_the_lab, tests/test_replay_bindings.py::test_the_tail_rule_is_an_allow_list_never_a_recogniser_of_hosts, tests/test_replay_bindings.py::test_a_page_whose_own_answer_lost_the_session_is_never_bound_on_the_next_login, tests/test_replay_bindings.py::test_a_bound_send_on_a_session_relogged_in_after_its_fetch_is_unbound, tests/test_replay_bindings.py::test_a_bound_send_on_a_copy_relogged_in_after_its_fetch_is_unbound_and_verified

PA-0002 sweep (by mechanism: every path that sends stored siblings): the oracle binder
(every strategy, the PRG restore, the access-control peer replay, which now binds in the
peer's own session), the fingerprint baseline, header points' representative query, the
M6 DOM executor (refuses), ground-truth JSON and store bodies (the host rule; 15 leaves
measured, none affected). Not swept here: greybox points carry no siblings
(FR-FUZZ-8); the blind-SQLi fuzzer sends an operator URL (no stored siblings).

## Residuals after the final round (8fee220; recorded at the merge)

A check of the round-3 commit (plain Python on a `git archive` export, the real
`SessionManager` and `HttpClient`; WHATWG measured in node 22) found R3-1 and R3-2 fixed
at their own repros, and one neighbouring path of each still open. The owner ruled out a
further fix round. Per PA-0530(4) and PA-0531(4) neither is a stated residual alone: each
is pinned by a strict xfail that reproduces it with real code and names its follow-up
owner. No product change was made for them.

- **N-R3-1 (FR-AUD-20, SP-73; owner AUD).** `names_outside_lab` returns False early when
  `neutral_value(value) == value`, and `neutral_value` recognises a loopback authority
  with a recogniser: `_host_prefix` cuts only at `/` or `:`, and `value_shape` must read
  the prefix as an IP or hostname. So a loopback value with no `/` before `?` or `#`
  (`127.0.0.1?next=evil.top`, `localhost?next=evil.example`,
  `127.0.0.1#evil.example:8080`, `localhost?u=134744072`,
  `127.0.0.1?next=https:evil.example`, `127.0.0.1?next=//evil.top/x`,
  `LOCALHOST?next=8.8.8.8:53`), or a loopback authority spelled so the recogniser misses
  it (`127.0.0.1./?next=evil.top`, `localhost./?next=evil.example`,
  `127.1/?next=evil.top`, `2130706433/?next=evil.top`,
  `0x7f000001/?next=evil.example:8080`), never reaches the authority proof or the
  `_tail_in_grammar` allow-list. Each is sent verbatim by `harness.auto._send_value` and
  `_outside_lab`, and bound by `oracle._FormBoundSender._bind_fresh`, although WHATWG
  reads the host as loopback and the tail as naming evil.top, evil.example or 8.8.8.8.
  The same values are sent verbatim at dcc7091 (older than the amendment, not a
  regression), but they are this bug's class, and they contradict the owner's rule that
  a loopback value keeps its tail only when no tail token holds a `.` or `:` or is a
  number. Pins: `tests/test_replay_bindings.py::test_a_loopback_authority_the_recogniser_misses_is_still_outside_the_lab`
  and `::test_the_binder_never_binds_a_loopback_authority_the_recogniser_misses` (12
  spellings each). Suggested follow-up: run the authority and tail proof whenever the
  value could carry a host, not only when `neutral_value` would change it; at least cut
  the authority at `?` and `#` too and treat a value whose leading run WHATWG reads as
  loopback as a loopback value subject to `_tail_in_grammar`. A broader gap with the same
  root cause (a top-level outside value `value_shape` misses: `evil.top`, `134744072`)
  is sent verbatim at both commits too.
- **N-R3-2 (FR-FUZZ-67, SP-20; owner FUZZ with SESS).** `SessionManager._health_get`
  adopts a rotated session cookie in place when a health check answers LIVE
  (`_adopt_rotation`), without a new generation. `_FetchRoute` compares only the client,
  identity, generation and loss, so a LIVE check between the page fetch and the bound
  send changes the cookie the bound send carries while every check still passes. The
  bound send then carries a token minted for the old cookie on the new one, and its 403
  is read as a negative, not unbound. It happens through `verify_live` (which
  `_verify_main` runs after any copy login or re-login), a policy block's
  `check_health`, and a pause's LIVE re-check in `prepare`; it is identical at 3959dfc.
  Measured on a PHP-like loopback app that rotates its id once on `GET /`: `[GET /form
  s2] [GET / s2, rotated to s6] [POST /do s6 tok5 -> 403]`, verdict None, inconclusive
  None. Pin: `tests/test_replay_bindings.py::test_a_live_health_check_that_adopts_a_rotated_cookie_after_the_fetch_unbinds_the_send`.
  Suggested follow-up: record the session material the fetch's `prepare` applied (a
  digest of the Cookie and Authorization headers, or a counter `_adopt_rotation`
  increments) in `_FetchRoute` and refuse, or leave unread, a bound send whose material
  differs; or have `_adopt_rotation` start a new generation.

Recorded as stated gaps in FR-AUD-20 and FR-FUZZ-67, in SP-73's row, and as sub-bullets
of CC-AUD-0056 and CC-FUZZ-0111.
