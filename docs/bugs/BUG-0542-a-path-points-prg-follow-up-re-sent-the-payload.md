# BUG-0542 — A path point's PRG follow-up re-sent the payload

- Date: 2026-10-21
- Status: fixed (CC-FUZZ-0113, FR-FUZZ-69; branch `lane/PRGPATH`)
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
  A target that leaves the segment (`../list`, an absolute path or URL) is fetched where
  a browser goes: resolution is structural, so the template and the placed URL give the
  same target.
- **Not "unobserved":** `PRG_UNOBSERVED` means a follow-up went out and gave no
  observation, and `Probe.prg_sends` counts it as a request (FR-FUZZ-49 P8). Nothing is
  sent here, so the refusal is a gate's `skipped:`, like another-origin or login-page
  targets.
- **The boundary, unchanged:** a `Location` the server wrote whole, a payload in it
  included (`/p/<payload>/edit` as an absolute path), is taken as written: the payload
  rode the redirect, which the strategies classify (FR-FUZZ-49 P6,
  `strategies._rode_the_redirect`). The sender never adds the payload itself.
- `PRG_RULES` states both divergences: `location-relative` (the probe's own URL, never
  the placed one) and the new `own-segment-never-refetched`, with its fixture.
- Tests: the pin is a passing test over `#top`, `edit`, `?tab=2`, `./`, `../list`, an
  absolute path and an absolute URL, POST and GET, both senders; a whole-location guard
  (`test_no_prg_follow_up_carries_the_payload_at_any_location`, its table checked against
  `test_sender_conformance.PLACEABLE` plus the path); the server-written boundary; an
  oracle-level test (M4 never confirms through such a follow-up) with its control (a
  path point redirected to a page that shows the stored value still confirms).

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
