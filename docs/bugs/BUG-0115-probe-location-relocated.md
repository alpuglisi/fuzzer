# BUG-0115 — A probe meant for one location was sent at another

- Date: 2026-10-14
- Status: fixed for the reachable instances (CC-FUZZ-0063); one instance pinned by a
  strict xfail (see the sweep)
- Severity: medium. Wrong evidence: a probe measured or "confirmed" something at a
  different input than the one recorded in the finding.

## Description
Several components place a payload "at the point's location" through their own branch
per location, and fall through to the URL query for anything they do not handle:
- **greybox `RequestsCorrelatingSender.send_correlated`** had no `header` branch. A
  ground-truth header point (`X-Signature`, `Authorization`, …) was sent as
  `?X-Signature=<payload>`, so `greybox-run` measured coverage for the wrong input.
- **`DomXssStrategy._observe`** rewrote any location other than query/fragment to
  `query`. With `--browser`, a Phase-1 POST form field (`location="body"`) was loaded as
  `GET ?field=<payload>`; a DOM hit would be recorded against the POST body field.
- **The browser executor's store step** planted any non-`body` store location as a GET
  query.

## Where encountered
Designing forms phase 2's header points (lane A draft v1, §6.1): header points would
have gone through the same paths.

## What it caused to fail
FR-FUZZ-19 (header-carried points) under `greybox-run`; FR-FUZZ-42 form points under
`--browser` (mislabelled DOM XSS); a browser load wasted per probe for a header point.

## What the bug was identified to be
A permissive fall-through ("unknown location → query") instead of a refusal, in each
component that builds its own request.

## Root cause analysis (Five Whys)
1. *Why did greybox send a header payload in the query?* Its location branches were
   `body` and "everything else"; header was never added when ground truth gained header
   points (CC-FUZZ-0032 added it to the two probe senders only).
2. *Why did DomXss relocate?* It was written for query/fragment points and "made safe"
   for others by rewriting them, rather than declining them.
3. *Why did no test catch either?* The seam conformance checks (PA-0041/PA-0072) verify
   signatures and argument forwarding, never **where** a payload lands.
4. *Why not?* Placement was assumed to follow from forwarding `location`.
5. *Why does that matter?* A forwarded `location` that the implementation then ignores is
   indistinguishable, to a signature check, from one it honours.

**Root cause:** location placement had no enforced contract; each implementation's
fall-through silently relocated what it could not place.

## Corrective action
CC-FUZZ-0063:
- greybox places header probes in headers (behind `check_send_header`) and raises
  `UnplaceableLocation` for any location it cannot place;
- `DomXssStrategy.applies` requires a query or fragment point, and `_observe` refuses
  anything else;
- the browser executor refuses an unplaceable observe or store location before starting
  a browser;
- `tests/test_sender_conformance.py` gains a placement check: every concrete seam
  class (found by shape; a new one must register a factory) and the greybox sender are
  sent a marked value at `query`, `body` and `header`, which must arrive there and
  nowhere else. It is proven on a synthetic relocating sender.

## Sweep (by mechanism: every location branch of every sender, strategy or executor that builds its own request)
| # | Site | Disposition |
|---|---|---|
| 1 | `greybox/run.py` `send_correlated` | fixed |
| 2 | `oracle/strategies.py` `DomXssStrategy` | fixed |
| 3 | `tools/browserexec.py` store step (and observe location) | fixed |
| 4 | `tools/probesender.py` Seam/Requests final branch (e.g. `fragment` → query) | **pinned, not fixed**: `tests/test_sender_conformance.py::test_senders_refuse_an_unplaceable_location` is `xfail(strict=True)`. Refusing there can change scored ground-truth results (R-XSS-REFLECT allows `fragment`), which needs a live, scored multitarget run (PA-0042/0047) that this offline lane cannot do. Flagged to the orchestrator. |
| 6 | `harness/pipeline.run_pipeline` fingerprint probe: `sender.send(points[0].url, points[0].param, "1")` sent any first point's parameter as a GET query (a header or POST field included), without siblings | fixed in the review follow-up: the first query (else form-body) point, at its own method and with its siblings; never a header point. `tests/test_forms_phase2.py::test_the_fingerprint_probe_goes_where_its_point_says` (found by reviewer A) |
| 5 | `harness/auto.points_from_ground_truth` DOM rewrite | unreachable today (no ground-truth DOM point has another location); pinned by `tests/test_forms_phase2.py::test_no_ground_truth_dom_point_has_another_location` (PA-0054(3)) |
| — | `tools/blind_sqli_fuzzer.py` senders | cleared: query-only by design (the operator's `--url` query parameter); no location argument exists, so nothing can be relocated (PA-0067(1): reader scope named) |

## Recurrence review
- **PA-0041** (BUG-0039) kept the seam's implementations in step for *transport
  settings* (redirects, TLS, timeouts).
- **PA-0072** (BUG-0071) made the protocol's *signature and forwarding* mechanical, by
  discovery.
- Neither is a recurrence of this root cause, but both are the nearest rules, and both
  were **too narrow**: they enumerate what a seam implementation must accept and
  forward, not what it must do with `location`. The guard PA-0072 built passes a sender
  that forwards `location` and then ignores it.

## Prior-preventive-action failure analysis
PA-0041 and PA-0072 named the right seam but the wrong layer (configuration and
signature, not behaviour). PA-0115 extends the same discovery-based enforcement to
placement.

## Preventive action
**PA-0115** (strengthens PA-0041 and PA-0072): refuse, never relocate; placement is
checked by discovery. See `docs/PREVENTIVE_ACTIONS.md`.
