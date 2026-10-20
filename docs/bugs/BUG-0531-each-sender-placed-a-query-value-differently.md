# BUG-0531 — Each sender placed a query value differently

- Date: 2026-10-20
- Status: fixed for every sender (CC-FUZZ-0106, CC-CORE-0068). The M6 executor's
  DOM-point siblings (`ExecRequest.entries`) land in CC-FUZZ-0106's second part, after
  AU-OUTCOME merges; until then that case is pinned by a strict xfail.
- Severity: medium. One injection point sent a different request depending on which
  sender carried it. A server that reads the first value of a repeated name never saw
  the anonymous senders' payload. The authenticated path lost duplicate siblings and
  rewrote untouched pairs. Scored ground truth was not exposed: 0 of its 157 rows carry a
  query.

## Description
The owner's adversarial audit of `6552276` (defect 14) found that a probe's query was
built by each sender in its own way, so one point produced different requests:

| Sender | What it did to `?id=1&tag=a&tag=b` for point `id` |
|---|---|
| `RequestsProbeSender`, greybox `RequestsCorrelatingSender`, blind-sqli `RequestsSender` | appended a second pair through `requests`' `params=`: `id=1&tag=a&tag=b&id=M` |
| `SeamProbeSender` (every session route), blind-sqli `SeamSender` | rebuilt the query through `dict(parse_qsl(...))` (`tools/authhttp.with_query_param`): `id=M&tag=b`. It also turned `%20` into `+`, dropped empty parts and turned `%E9` into `%EF%BF%BD` |
| M6 `PlaywrightBrowserExecutor` (observe navigation, GET store step) | appended (`_with_query`) |
| M6, for an SPA hash route that already carries the name | appended a second pair (`_with_fragment`) |
| `RequestsProbeSender`, bound query point with a PRG follow-up | handed `_follow` the placed URL, so the follow-up re-sent the payload |

## Where encountered
Audit defect 14 (AU-REQID14). Reproduced on `8100959` by
`tests/test_query_placement.py`: every sender sends to a loopback echo server the test
starts, which records the raw request target; M6 runs in real Chromium
141.0.7390.37 (Playwright build 1194).
- 45 of 48 sender × case combinations failed (the three that held were the seam family's
  blank-value case), and all 8 M6 cases failed.
- The anonymous and the authenticated sender put different bytes on the wire for the same
  point, although both go through `requests`.

## What it caused to fail
- **Detection.** Against a first-value server (most frameworks), the anonymous senders'
  payload was never read; the original value was. The seam family dropped every
  duplicate sibling, so a server that needs `tag=a&tag=b` saw a different request.
- **Consistency.** FR-FUZZ-47 (one point, one request, whichever sender), PA-0115(2)
  (placement enforced by discovery), PA-0111 (a browser-like serialisation).
- **PRG.** FR-FUZZ-49: a bound query point's follow-up re-sent the payload instead of a
  plain GET of the redirect target.

## What the bug was identified to be
No owner for "place a value in a URL's query". Five call sites built it themselves
(`params=`, a `dict` rebuild, string appends), and one passed the placed URL where the
probe's own URL was meant. The conformance check meant to keep the senders in step could
not observe an occurrence: `tests/test_sender_conformance.py::_Wire` parsed the query
into a `dict`, and its probe URL had no query.

## Root cause analysis
Five Whys.
1. **Why did a first-value server never see the anonymous payload?** `requests` appended a
   second `id` (`params=`).
2. **Why did the authenticated path lose `tag=a` and rewrite untouched pairs?**
   `tools/authhttp.with_query_param` rebuilt the query through `dict(parse_qsl(...))`.
3. **Why do the senders differ?** Each built the query itself: the two probe senders,
   greybox, blind-sqli and the M6 executor. Nothing owned "place a value in a query";
   SP-42 owned only the path segment.
4. **Why did PA-0115's conformance check not catch it?** It checks placement per
   *location*, not per occurrence. Its wire collapsed the query into a `dict`, and its
   probe URL had no query, so a duplicate, an order change or a rewritten sibling could
   not be seen (PA-0311(2): a check on a channel that cannot carry the violation).
5. **Why was there no owner?** SP-42 was created for the path segment (FR-FUZZ-57) and
   its sweep was by symptom path; query placement was older code, copied per sender.

**Root cause:** query placement was not a shared primitive, and the check meant to keep
the senders in step observed through a channel that could not carry the violation.

## Corrective action
CC-CORE-0068 and CC-FUZZ-0106 (AU-REQID14, branch `worktree-agent-aef1371774d69f3f5`).
- **One owner, SP-42 extended** (`fuzzlab/core/urls.py`): `QueryEntries` (the ordered raw
  parts of a query), `encode_query_value` (`quote_plus`, `safe=""`), `place_query_param`
  (the standalone rule: the first occurrence in place, every other raw part kept),
  `bind_query` (the bound rule: `FormEntries.replace`, every occurrence, as the oracle's
  binder does), `with_query` (moved from `tools/authhttp.py`) and
  `place_route_query_param` (inside an SPA hash route's query).
- **Every sender places through it:** both probe senders (every session route), greybox,
  both blind-sqli senders, M6's observe navigation, its GET store step (always
  `place_query_param`: a `StoreStep` has no entries) and its hash-route placement.
  `tools/authhttp.with_query_param` and `with_query` are removed.
- **PRG:** `RequestsProbeSender` sends to a separate `wire` and resolves the follow-up
  against the probe's own URL.
- **Unchanged:** the oracle's binder (`_FormBoundSender`), `harness/pipeline._baseline`,
  form bodies, the `Sender` protocol.
- **The DOM point's siblings** (`ExecRequest.entries` from `DomXssStrategy`) are
  CC-FUZZ-0106's second part, held until AU-OUTCOME merges (`oracle/strategies.py` is
  its file); pinned until then.
- **Checks:** `tests/test_sender_conformance.py` now reads the URL `requests` prepares
  (byte for byte) and checks every sender's occurrence; `tests/test_query_placement.py`
  checks every sender end to end and holds the AST guard.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for the same bug (a sender placing
a value differently from its siblings) and the same root cause (one seam's
implementations not kept in step; a check that cannot observe the violation):

| Prior bug | Rule | What it kept in step | Match |
|---|---|---|---|
| BUG-0039 | PA-0041 | a transport setting across a seam's implementations | same root cause |
| BUG-0044 | PA-0046 | redirects, per sender | same root cause |
| BUG-0071 | PA-0072 | the seam's signature and every wrapper | same root cause |
| BUG-0115 | PA-0115 | where a payload lands, by location | **same bug class**, one level up |
| BUG-0110 | PA-0111 | form serialisation, rule by rule | related: browser-like serialisation |
| BUG-0311 | PA-0311(2) | a check on a channel that cannot carry the violation | same failure of the check |

Result: a recurrence of BUG-0115's class (a sender places a payload unlike the point
says), with BUG-0039/BUG-0071's root cause (one seam's implementations not in step).

## Prior-preventive-action failure analysis
- **PA-0115 (BUG-0115): too coarse, and enforced on the wrong channel.** PA-0115(2)
  checks placement by discovery, but at *location* granularity: a marked value must land
  in the query, not the header. Its wire (`_Wire`) parsed the query into a `dict` and its
  probe URL had no query, so the check could not observe an occurrence, a duplicate, an
  order change or a raw-text rewrite. Every sender passed it while sending different
  bytes. PA-0115(3)'s sweep was by location branch, not by the mechanism that builds the
  query, so `with_query_param` and `params=` were never compared.
- **PA-0041 / PA-0072 (BUG-0039, BUG-0071): the wrong layer.** They keep transport
  settings and signatures in step, not the request a sender builds.
- **PA-0111 (BUG-0110): too narrow.** Its rule table covers `core.forms` serialisation;
  a URL query mutation is a different code path with no rule.
- **PA-0311(2) was not applied** to the conformance check itself: the check's channel
  (a `dict` of the query) could not carry the violation it existed to catch.

## Preventive action
**PA-0531** strengthens PA-0115(2)/(3) and PA-0111 (text in `docs/PREVENTIVE_ACTIONS.md`):
1. A value placed in a URL's query goes through the one owner (SP-42). An AST guard over
   `fuzzlab/` (the owner excluded) flags seven builder shapes (S1–S7), with an exact,
   reasoned allow-list that fails when stale, proven on 50 synthetic offenders and 10
   near-misses; its limits are stated.
2. A placement check observes the raw request through the real client's own URL
   preparation, never a parsed `dict`; senders that share a client are compared byte for
   byte, and the check is shown to fail on an appending and on a collapsing sender.
3. Senders on different clients (Chromium against `requests`) are compared under a
   relation measured on the real clients, pinned by a real-browser test, and proven not
   vacuous.
4. A known unfixed instance in another item's code is pinned by an offline strict xfail
   naming its owner (PA-0054(3)), never a prose deferral.

**The PA-0002 sweep, by mechanism** (the guard's own output, 57 findings on `8100959`):
12 fixed here (11 keys: `authhttp.with_query_param`/`with_query`, both probe senders'
`params` stores, greybox's two, blind-sqli's `params=`, `browserexec._with_query`/
`_with_fragment`, `harness.auto.header_points_from_store`); 45 allow-listed with reasons
(43 keys). The known instances owned elsewhere are pinned by strict xfails naming their
owner:
- `disco/runner.py:262`, the contract runner appends (AU-OUTCOME);
- `tools/spa.py` `query_url`, the SPA seed builder appends unencoded pairs (CRAWL, to be
  registered);
- `store_adapter.query_pairs` drops empty parts and a missing `=` (AU-REQID8);
- `store_adapter.py:274`, a disco form body's repeated name collapses (AU-REQID8);
- `labgen/oracle_wrapper._mark_query_param` re-encodes untouched pairs (LAB);
- found while sweeping M6: both probe senders' **path** branch hands `_follow` the placed
  path, so a relative `Location` (`#top`, `edit`) re-requests `/t/zqmark/…` (AU-PRGPATH,
  its own bug item).

## Update (2026-10-20): part 2 landed
Appended, not edited (this log is append-only).
- **The M6 DOM point's siblings:** CC-FUZZ-0106 part 2, after AU-OUTCOME merged.
  `ExecRequest.entries` carries a query point's link set from `DomXssStrategy._observe`,
  and the executor binds it with `core.urls.bind_query`, as the HTTP senders do.
  `test_a_dom_query_point_is_loaded_with_its_siblings` is no longer pinned, and a real
  Chromium test compares the browser's and the bound HTTP sender's query for a repeated
  name. The status above now reads: fixed for every sender, the M6 executor included.
- **`tools/spa.query_url`:** fixed in this bug's sweep under CC-CRAWL-0053 (not a
  separate item: same class). The seed builder places its route query through
  `core.urls.place_route_query_pairs`; its encoder keeps `/`, so a redirect-type name's
  same-origin path stays `/` (FR-CRAWL-17's safety test unchanged). Its strict xfail is
  now a positive test.
- **`disco/runner.py:262`:** fixed by AU-OUTCOME (CC-FUZZ-0105); its pin is positive.
- **Still pinned to their owners:** `store_adapter.query_pairs` and
  `store_adapter.py:274` (AU-REQID8), `labgen/oracle_wrapper` (LAB), the path point's
  PRG follow-up (AU-PRGPATH), the bound duplicate name (AU-REQID8).
- **Correction:** the corrective action above says a `StoreStep` has no entries. It has
  `entries`, but they are a JSON store body's leaves; it carries no query siblings,
  which is why the GET store step takes the standalone rule.
- **The guard's count:** 43 allow-listed findings under 41 keys (the runner's and
  `spa.query_url`'s entries are gone).
