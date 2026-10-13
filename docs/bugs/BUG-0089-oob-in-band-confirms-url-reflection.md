# BUG-0089 — In-band SSRF/XXE confirmation accepted a mere reflection of the callback URL

- Date: 2026-10-13
- Status: fixed (CC-FUZZ-0057)
- Severity: high (false findings). Found by BUG-0083's PA-0084 sweep, not by the review
  agent.

## Description
`SsrfInBandMarkerStrategy` and `XxeInBandMarkerStrategy` sent the OOB listener's
callback URL (`…/cb/<token>`) and confirmed when the response contained `<token>`. The
listener served the token itself as its body. But the token is **in the URL being
sent**, so a page that never fetched anything and merely reflected the submitted value
(e.g. `could not fetch http://127.0.0.1:…/cb/<token>`) confirmed SSRF / XXE.

## Where encountered
The PA-0084 sweep in this batch (substring-presence confirmers), while writing
BUG-0083.

## What it caused to fail
FR-FUZZ-5: false confirmed findings on any endpoint that echoes a URL parameter or an
XML body in an error message.

## What the bug was identified to be
The proof of a fetch was a value the request already carried.

## Root cause analysis
1. *Why confirm?* The token appeared in the reflected URL.
2. *Why was the token the proof?* The listener echoed the token, to support in-band
   confirmation simply.
3. *Why not caught?* The test doubles either really fetched the URL or returned fixed
   text; none merely reflected it.
4. *Why does this matter structurally?* A proof must be something only the event
   (the fetch) can produce. This is the same principle as BUG-0083.

**Root cause:** the confirmation signal was derivable from the probe itself
(substring presence, BUG-0083's class).

## Corrective action
In CC-FUZZ-0057:
- **The listener serves a proof.** `OobListener.proof(token)` is an HMAC-SHA256 of the
  token under a per-listener random secret (`fzlproof…`), and the callback now serves
  that instead of the token. It appears nowhere in the URL.
- **Both strategies check for it:** the in-band SSRF and XXE strategies require
  `listener.proof(token)` in the response. OOB-hit strategies (`wait_for`) are
  unaffected.
- **Tests** (`tests/test_oracle_oob.py`):
  - a URL-reflecting sender confirms neither SSRF nor XXE in-band;
  - a real fetch still confirms;
  - the callback body is the proof, absent from the URL, and keyed per listener;
  - the live multitarget SSRF/XXE labs still confirm (category-4 / category-3 runs:
    passed).

## Recurrence review
**BUG-0083 / PA-0084** (this batch): the same class, confirmation by substring
presence.

**Result:** a recurrence found by that PA's own sweep, before release. PA-0084 is new
in this batch, so there is no prior failure to analyse, and its sweep worked as
intended.

## Preventive action
**PA-0090** (extends PA-0084):
1. A confirmation's proof must not be derivable from the probe that elicits it. An
   OOB / in-band marker is a keyed function of the token (here an HMAC), never the
   token the request carries.
2. Each such strategy has a "reflects the request but does nothing" false-positive
   fixture.

**Sweep (PA-0002)** — strategies whose proof could appear in the request:
- **SSRF / XXE in-band:** fixed.
- **Open redirect:** the canary must be in `Location`'s **start**. A reflection in the
  body does not count.
- **SSTI:** the product must appear **and** the expression must not, so a reflection of
  the expression cannot pass.
- **Command-injection OOB / XXE OOB / SSRF OOB:** confirmed by an actual listener hit,
  which needs a real request.
- **SQLi error / boolean / timing:** differential or error-signature, which a
  reflection cannot fake.
