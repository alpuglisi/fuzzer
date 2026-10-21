# BUG-0542 — A path point's PRG follow-up re-sent the payload

- Date: 2026-10-21
- Status: fixed (CC-FUZZ-0113, FR-FUZZ-69; branch `lane/PRGPATH`; review round 1,
  PRGPATH-R1: branch `lane/PRGPATH-r1`)
- Severity: medium. The follow-up of a path point's probe was a second request carrying
  the payload, and the oracle read its answer as the page the probe's own request led
  to. It broke the NFR-FUZZ-safe clause "a post/redirect/get follow-up is one plain GET,
  never a re-sent body or payload", and it could confirm a finding through a request the
  probe never made: a page that renders its own URL was read as the POST's stored
  result. Exposure in the scored labs was not measured (a live run needs the owner's
  authorisation, D11): any path point whose application answers a PRG redirect with a
  `Location` relative to the payload's resource (`#top`, `edit`, `?x`) was exposed.

## Description
After a probe whose payload is a path segment (FR-FUZZ-57: `/p/{id}/view` sent as
`/p/<payload>/view`), both probe senders resolved a PRG redirect's `Location`
(FR-FUZZ-49) against the **placed** URL. A fragment-only `Location: #top` re-requested
`/p/<payload>/view`, and a relative `Location: edit` requested `/p/<payload>/edit`: the
payload again, by GET. The answer became `probe.followed`, which every opt-in strategy
reads as the observed page (`strategies._observed`).

## Where encountered
BUG-0531's PA-0002 sweep of the M6 PRG fix (AU-REQID14, CC-FUZZ-0106) found it and
pinned it: `tests/test_query_placement.py::test_a_path_points_prg_follow_up_never_carries_the_payload`,
a strict xfail naming AU-PRGPATH over `#top` and `edit` for both probe senders
(DRAFT-AU-REQID14 item 9). This lane (AU-PRGPATH) reproduced it on `c483dc1` against a
loopback echo server and a loopback PRG app the tests start (no lab contacted).

## What it caused to fail
- **Safety (NFR-FUZZ-safe, PRG clause).** The follow-up re-sent the payload: one more
  payload request per path probe, by GET, to a URL the operator never named
  (`/p/<payload>/edit`).
- **Attribution (FR-FUZZ-49 P5/P6).** The oracle took that request's answer for the page
  the probe led to. Measured on `c483dc1` (`tests/test_prg_observation.py::test_a_path_points_follow_up_that_would_re_send_the_payload_never_confirms`):
  `POST /p/<payload>/view` -> `303 edit`, where `GET /p/<seg>/edit` evaluates its own
  segment. M4 (SSTI) confirmed the path point with `observation: "prg"`, although no
  POST stored anything that page showed.
- **The rule table (PA-0111).** `PRG_RULES['no-body-no-payload']` says the follow-up
  carries no payload parameter; it held for every fixture because every fixture was a
  body point.

## What the bug was identified to be
`SeamProbeSender.send` and `RequestsProbeSender.send` both reassigned `url` to the placed
URL (`url = _path_url(url, param, value)`) before the PRG follow-up, which reads `url`
as its resolution base (`prg_target(probe, url, ...)`). `url` had two readers with two
meanings: the request the probe sent (routing, isolation, the header breaker's
attribution) and the probe's own URL (the base the follow-up is resolved against).

## Root cause analysis
Five Whys.
1. **Why did the follow-up carry the payload?** `prg_target` resolved `Location`
   against the placed URL.
2. **Why the placed URL?** Path placement (CC-FUZZ-0096, `926efe7`, 2026-10-19)
   reassigned `url` in both `send`s. The PRG follow-up (CC-FUZZ-0078, 2026-10-14) was
   five days older and reads the same variable; the path change did not list it as a
   reader, and no test asked a path point for a follow-up.
3. **Why did no PRG check catch it?** `probesender.PRG_RULES` names the browser's base
   ("Location is parsed relative to the request's URL"), which for a path point *is* the
   placed URL. The divergence the no-payload rule needs (the probe's own URL) was not a
   rule. It was prose in FR-FUZZ-64 for query points only, fixed at one call site by
   BUG-0531 with a local `wire`. Every rule fixture was a body point, where the probe's
   own URL and the request's URL are the same string, so the guard "every rule has a
   fixture" could not see the difference.
4. **Why was the path case not simply resolved against the probe's own URL?** A path
   point has no payload-free URL: its own URL is a template (`/p/{id}/view`), which no
   one can request. What to do with a target that keeps the segment needed a decision
   (refuse it), and nobody took it when FR-FUZZ-57 met FR-FUZZ-49.
5. **Why did they meet unexamined?** The PRG work and the path work were separate changes,
   and each tested its own locations: PRG on body points, path points without PRG.

**Root cause:** the follow-up's resolution base was not a rule of the PRG emulation at
every location. The one rule table stated the browser's base, and its fixtures covered
only the location where the probe's own URL and the placed URL coincide. So a later
change that repointed the shared variable at the placed URL broke nothing visible, and
the one location with no payload-free URL had no decided behaviour.

## Corrective action
CC-FUZZ-0113 (FR-FUZZ-69), in `fuzzlab/tools/probesender.py` only (the PRG follow-up):
- **Decision: resolve against the unplaced request URL**, as a query point's follow-up is
  (FR-FUZZ-64). Both senders keep `own`, the probe's own URL (a path point's template),
  and hand it to `prg_target`; the placed `url` still routes and attributes the
  follow-up (the seam's isolated copy, the header breaker), as it did the probe.
- `prg_target(..., own_segment=)` refuses a target that keeps the path point's own
  segment (`{id}`): it names the resource the payload is in, and the only request for it
  carries the payload (`#top`, `edit`, `?tab=2`, `./`). `Probe.prg` is
  `skipped: the follow-up would re-send the payload`; nothing is sent, nothing counted.
  A target that leaves the segment (`../list`, an absolute path or URL without the
  placed value) is fetched where a browser goes: resolution is structural, so the
  template and the placed URL give the same target.
- **Not "unobserved":** `PRG_UNOBSERVED` means a follow-up went out and gave no
  observation, and `Probe.prg_sends` counts it as a request (FR-FUZZ-49 P8). Nothing is
  sent here, so the refusal is a gate's `skipped:`, like another-origin or login-page
  targets.
- **A target the server wrote with the payload in its path is refused the same way**
  (review round 1, PRGPATH-R1): `prg_target(..., own_value=)` also refuses a target whose
  path holds the placed value as whole segments, as written or percent-decoded
  (`_re_sends`). `Location: /p/<payload>/edit`, as an absolute path or URL the server
  built from the request, is the same browser request as `edit`, so it gets the same
  decision. The round-0 text here called that target "taken as written: the payload
  rode the redirect, which the strategies classify (`strategies._rode_the_redirect`)".
  That was wrong: only M5 XSS reads `_rode_the_redirect`, and M4 confirmed through such
  a follow-up with `observation: "prg"` (see the review round below). A payload the
  server wrote only into the target's query is not the point's resource; it still
  rode the redirect and is taken as written, as at every location (FR-FUZZ-49 P6).
- `PRG_RULES` states both divergences: `location-relative` (the probe's own URL, never
  the placed one) and the new `own-segment-never-refetched`, with its fixture.
- Tests: the pin is a passing test over `#top`, `edit`, `?tab=2`, `./`, `../list`, an
  absolute path and an absolute URL, POST and GET, both senders; a whole-location guard
  (`test_no_prg_follow_up_carries_the_payload_at_any_location`, its table checked against
  `test_sender_conformance.PLACEABLE` plus the path); the server-written target (taken
  as written in round 0, refused since review round 1); an oracle-level test (M4
  never confirms through such a follow-up) with its control (a path point redirected
  to a page that shows the stored value still confirms).

## Recurrence review
Checked `docs/bugs/` (every report naming PRG, a follow-up, or the placed URL) and
`docs/PREVENTIVE_ACTIONS.md`:

| Prior | Rule | What it covered | Match |
|---|---|---|---|
| BUG-0531 | PA-0531 | query placement through one owner; its table row "bound query point with a PRG follow-up: handed `_follow` the placed URL, so the follow-up re-sent the payload" | **same bug** (the follow-up resolved against the placed URL), another location |
| BUG-0110 | PA-0111 | an emulated browser behaviour implemented rule by rule, each rule with a fixture | same root cause: a rule table whose fixtures could not see the case |
| BUG-0115 | PA-0115 | refuse, never relocate | related: the corrective action refuses |
| BUG-0510 | PA-0510 | the trace took a follow-up's observation for its send | related (follow-up bookkeeping), different defect |
| BUG-0117 | PA-0117 | a signature counts only when caused by the probe | related: attribution of a follow-up's answer |

Result: a recurrence of BUG-0531's PRG instance at the path location, with BUG-0110's
root cause (a rule table whose fixtures sat where the divergence is invisible).

## Prior-preventive-action failure analysis
- **PA-0531 (BUG-0531): fixed the instance, not the rule.** BUG-0531's corrective action
  gave the anonymous sender a separate `wire` local for the bound query branch, so the
  follow-up kept the probe's own URL there. That was a call-site fix: the resolution base
  stayed an implicit reading of a variable that other branches reassign. PA-0531's rules
  are about query placement (one owner, raw observation, client relations, pinning);
  none says the follow-up is derived from the probe's own URL at every location, so the
  path branch, found in the same sweep, was pinned (PA-0531(4), correctly) but nothing
  made the class impossible.
- **PA-0111 (BUG-0110): too narrow in its fixtures, wrong rule text.** PA-0111(2) checks
  that every rule has a fixture, not that a rule whose result depends on the location
  is exercised where the locations differ. FR-FUZZ-49's fixtures are all body points.
  And the `location-relative` rule described the emulated algorithm's base (the
  request's URL) without the divergence fuzzlab needs, so the table itself prescribed
  the defect for any location whose payload is in the URL.
- **PA-0115(1) (BUG-0115) was not applied to follow-ups:** refusing what cannot be sent
  as asked was the rule for probes; a follow-up that cannot be made without the payload
  had no such rule.

## Preventive action
**PA-0542** strengthens PA-0111 and PA-0531(4) (text in `docs/PREVENTIVE_ACTIONS.md`):
1. An emulated rule whose result depends on where the payload sits is exercised at every
   location that places it differently, from the list of placeable locations (a table
   check fails when a location is added without a row), never only where the
   difference is invisible. A rule that diverges from the emulated algorithm says so in
   the rule table, with its reason.
2. A follow-up (or any request derived from a probe) is derived from the probe's own
   request description, never from the placed request; where no payload-free target
   exists, it is refused before any send, never sent with the payload (PA-0115(1)).
3. A change that reassigns or repurposes a value names every reader of it in its
   change-control entry (here `url` in both `send`s: the send, the isolation key, the
   follow-up). Applied in review; (1) and (2) are enforced by the tests named in PA-0542.

**The PA-0002 sweep, by mechanism** (every place a request is derived from a probe's
answer):
- The PRG follow-up has one target rule, `probesender.prg_target`, and two callers, the
  two probe senders (`prg_capable` is declared nowhere else; `Sender.prg_capable` is
  False). Both are fixed and covered at every location by the whole-location guard.
- Every other location already resolved against the probe's own URL on `c483dc1`: body,
  header and JSON (the URL is never placed), a standalone and a bound query (BUG-0531's
  `wire`; the seam places in `_send_on`). The guard proves it for both senders.
- The PRG restore (P9) sends a benign value and is not for a path point
  (`Oracle._restore`), so it re-sends no payload.
- Other `urljoin(..., Location)` sites (`session/manager.py`, `tools/navguard.py`,
  `tools/formnav.py`, `labgen/identifier_sqli_oracle.py`) follow a login, a crawl or a
  generator's own navigation, never a probe's payload request.
- **Outside the class, reported:** `SqliErrorStrategy` (M2) labels any confirmation seen
  only through a follow-up `second_order: true`, including one whose `Location` the
  server wrote with the payload (the payload rode the redirect, FR-FUZZ-49 P6, which only
  M5 distinguishes). That is a classification of a server-written target in
  `oracle/strategies.py`, evidence-only (the class stays `sqli`), and the same for
  query points; it is reported to the coordinator, not pinned here, because the sender
  never re-sent anything there.

## Review round 1 (PRGPATH-R1, 2026-10-21)
**Finding (confirmed by the reviewer with a loopback reproduction on `9d0e819`).** The
round-0 fix refused a path point's follow-up only when its target, resolved against the
template, kept `{id}`. A `Location` the server wrote as an absolute path or URL holding
the placed segment (`/p/<payload>/edit`, `http://host/p/<payload>/edit`) passed every
gate and was fetched with the payload. A browser resolves `edit` to the same request, so
the two spellings got opposite decisions. The scope's invariant ("the oracle must never
treat a follow-up that re-sends the payload as the PRG observation of the original
request", tested for `#top`, relative `edit`, absolute-path and absolute-URL Locations)
did not hold for two of its four forms, on both senders.

**What it caused to fail.** This is the Attribution failure listed above, through
another spelling. The reviewer's script
(`scratchpad/prgpath_review/repro_abs.py`) ran
`Oracle(strategies=[SstiStrategy()]).confirm` on `POST /p/{id}/view` -> `303
/p/<seg>/edit` (built from the request's own segment), where `GET /p/<seg>/<any>`
evaluates its own segment and nothing is stored. On `9d0e819` that gave `CONFIRMED` with
`observation: "prg"`, for both senders and both absolute spellings. Every follow-up GET
carried the payload (`/p/%24%7B346%2A504%7D/edit`, ...). The relative `edit` gave no
verdict and no GET.

**What the defect was.** `prg_target` compared the target's path segments with the
template's placeholder only (`own_segment in urlsplit(target).path.split("/")`). It
never compared them with the value the probe placed, so a target the server wrote whole
could hold the payload unseen. The docstring, FR-FUZZ-69 and this report called that
deliberate ("taken as written: the payload rode the redirect, classified by the
strategies, `strategies._rode_the_redirect`").

**Root cause analysis (Five Whys).**
1. *Why was `/p/<payload>/edit` fetched?* The refusal looked for `{id}`, which only a
   target resolved against the template can keep.
2. *Why only `{id}`?* The lane framed the defect as "which base is the `Location`
   resolved against" (the root cause of round 0). It fixed the base, and treated a
   target that carries the payload without the base's help as another case: "the
   payload rode the redirect".
3. *Why was that case thought safe?* The lane justified it by a consumer's behaviour
   (`_rode_the_redirect` classifies such a follow-up) without reading which consumers
   apply it. Only M5 XSS calls it (`strategies.py:762`). M4, SpEL, M2 and the passwd
   markers set `observation: "prg"` whenever a response came through a follow-up
   (FR-FUZZ-49 P6 says so: "other strategies add `observation: "prg"`").
4. *Why did the lane's own tests not show it?* The boundary test
   (`test_a_location_the_server_wrote_with_the_payload_is_fetched_as_written`) used
   `_Echo`, which answers every request carrying the mark with another 302. So the
   follow-up was always `PRG_UNOBSERVED`, and the question the rule protects (is this
   answer read as the POST's observation?) was never asked. The `PATH_PRG` absolute
   rows (`/p/list`, `{base}/p/list`) were payload-free, and the oracle-level test had
   only relative rows.
5. *Why were those fixtures accepted?* Nothing required a boundary or carve-out test
   to make the excluded request observable, or a carve-out justified by downstream
   handling to be checked against every consumer.

**Root cause:** the refusal was keyed to one spelling of the resource (the template's
placeholder), not to the resource itself (the point's segment holding the placed value,
however written). The carve-out for the other spellings rested on an unverified claim
about every strategy, and its test could not observe the misattribution it allowed.

**Corrective action (this round, CC-FUZZ-0113 round 1, branch `lane/PRGPATH-r1`).**
- `probesender._re_sends(path, own_segment, own_value)`: a path point's target re-sends
  the payload when its path keeps `{param}`, or holds the placed value as whole segments
  as written or percent-decoded. So `%2A` against `*` is caught, and so is a value with a
  `/` written raw. `prg_target(..., own_value=)` refuses with the same `Probe.prg`
  (`skipped: the follow-up would re-send the payload`), before any send. Both senders
  pass `_placed_value(location, value)` (the value for a path point, None elsewhere)
  next to `_own_segment`. Every other location is unchanged.
- `PRG_RULES['own-segment-never-refetched']`, the `prg_target` docstring and FR-FUZZ-69
  state it. The "taken as written" text is replaced. A payload written only into the
  target's query stays the P6 "rode the redirect" case, as at every location.
- Tests (each fails on `9d0e819`):
  - `tests/test_query_placement.py::test_a_location_the_server_wrote_with_the_payload_is_refused`
    (renamed from `..._is_fetched_as_written`): the echo now answers only the probe
    with a redirect (`_Echo.redirect_limit`), so a sent follow-up would be observed.
    It asserts `probe.followed is None`, `probe.prg == RESENDS` and no second target,
    for both senders and both absolute spellings.
  - `tests/test_query_placement.py::test_a_path_points_prg_follow_up_never_carries_the_payload`:
    new rows `absolute-path-with-the-payload` and `absolute-url-with-the-payload` (POST
    and GET, both senders).
  - `tests/test_prg_observation.py::test_a_path_points_follow_up_that_would_re_send_the_payload_never_confirms`:
    now covers both senders, with new rows `/p/{seg}/edit`, `{base}/p/{seg}/edit` and a
    re-encoded `/p/{pchar}/edit`. `PrgSite` builds them from the request's own segment.
    These are the reviewer's reproduction as a test.
  - The rule fixture `_fx_own_segment` adds the server-written spelling.

**Recurrence review.** The same bug as round 0 (a path point's follow-up re-sends the
payload and is read as the POST's observation), through a spelling the round-0 fix
left open. Checked again: BUG-0531/PA-0531, BUG-0110/PA-0111, BUG-0115/PA-0115,
BUG-0117/PA-0117 (above), and PA-0542 as drafted in round 0 (handed to the coordinator,
not yet merged). The new element is the carve-out's justification. BUG-0117/PA-0117
("a signature counts only when caused by the probe") is the nearest prior rule about
attribution. It constrains each strategy's own reading, not a sender's choice of what
to hand the strategies as the observation.

**Prior-preventive-action failure analysis.**
- **PA-0542 round-0 draft, rule (2), was applied to one spelling.** It says that where
  no payload-free target exists, the follow-up is refused, never sent with the payload.
  The lane implemented "the target keeps `{id}`", a property of how the target was
  resolved, not of what it requests. So the rule held for every relative `Location`
  and failed for the absolute ones naming the same resource. The rule text did not say
  "however the target is spelled", and its enforcing tests had no payload-holding
  absolute row.
- **PA-0542 round-0 draft, rule (1), was satisfied vacuously for the boundary.** It
  requires exercising every location, and the lane did. But the boundary test's fixture
  answered the follow-up with a redirect, so the observation the rule protects could
  not occur in it.
- **PA-0117(1) (BUG-0117)** binds strategies to signatures the probe caused. It was
  correct but sits at the wrong layer for this case: the sender decided which response
  the strategies read as the probe's, and no rule bound that decision.

**Preventive action.** PA-0542 is strengthened before it merges (text in the lane's
`doc_texts.md`). Rule (2) now reads "however the target is spelled (relative to the
resource, or an absolute path or URL holding the placed value), compared as written and
decoded". Two rules are new:
- **(4)** A carve-out justified by what a downstream consumer does is checked against
  every consumer of that output, by reading their code or by a test per consumer, and
  is otherwise not a carve-out.
- **(5)** A boundary or carve-out test makes the excluded outcome observable. Its
  fixture answers the request the rule refuses or allows with what would be misread (a
  page, not another redirect), so the test fails if the rule is wrong.

(4) and (5) are applied in review. The tests above enforce (2) for both senders.

**PA-0002 sweep (by mechanism).** `prg_target` is the one target rule, and both callers
pass the placed value. No other code derives a request from a probe's `Location`; the
round-0 list above still holds. Outside this finding, reported and not changed here:
at a body or query point, a `Location` the server wrote with the payload is still
followed (FR-FUZZ-49 P6, by design). Every strategy but M5 XSS then reads it as
`observation: "prg"` without asking whether the payload rode the redirect (M4, SpEL
and Go-template SSTI `strategies.py:894`, `:949`, `:1219`; M2 `:554`; the path
traversal markers `:1255`, `:1342`; line numbers at `9d0e819`). That is
the same misattribution at the other locations. It belongs to `oracle/strategies.py`
(classification) and to FR-FUZZ-49 P6's owner, and is handed to the coordinator as a
residual.
