# BUG-0092 — Credentials could be sent over a downgrade from https to http

- Date: 2026-10-13
- Status: fixed (CC-SESS-0012)
- Severity: high. A login page served over https could have the stored username and
  password POSTed in cleartext, to the same host or to any in-scope port.

## Description
With the login page `https://lab.example/login` and scope `{lab.example}`,
`SessionManager._credential_destination_ok` returned True for
`http://lab.example/login` and `http://lab.example:9999/login`. Its allow rules are:
- the same origin;
- `auth_origins`;
- an http→https upgrade;
- **any in-scope host**.

They were OR-ed with no prior deny, so the in-scope rule admitted a downgrade. An
`auth_origins` entry over http admitted one too, and so did a discovery redirect from an
https base URL to an http login page.

## Where encountered
A third-party review of head `5eb4be9` (finding #3). Reproduced with
`scratchpad/ext/f3_downgrade.py`.

## What it caused to fail
FR-SESS-12 and PA-0082(1). BUG-0081's agreed design said credentials go "never over a
downgrade".

## What the bug was identified to be
The function had allow rules only. The "never a downgrade" constraint of BUG-0081's
agreed draft was **waived in implementation** as "moot". The reasoning covered one
configuration, a same-host http action on an http base. The BUG-0081 doc records the
waiver, and its test of the downgrade was replaced.

## Root cause analysis
1. *Why were credentials allowed over http?* The in-scope rule matched, and nothing
   denied the scheme.
2. *Why no deny?* The constraint was judged "moot" during implementation and never
   coded.
3. *Why judged moot?* The reasoning considered the authenticated host on an http base
   only, not an https login page.
4. *Why not caught?* The waiver was not taken back to the reviewers, and the test that
   would have exercised the downgrade was replaced by one that could not fail.

**Root cause:** an agreed safety constraint was dropped in implementation without
review, and an allow-list had no deny-first structure that would have made the
omission visible.

## Corrective action
- **Deny first (CC-SESS-0012).** `_transport_ok(target, floor_https)` runs before any
  allow, and nothing overrides it:
  - the scheme must be `http` or `https`;
  - if the floor is https, the target must be https.

  The floor is https when any of these was https:
  - the operator's `base_url`;
  - any hop of the discovery redirect chain;
  - the login page itself;
  - the URL a POST redirect comes from.
- **The login page's final URL is checked too.** `FetchResponse.url` and
  `.history_schemes` are new: the default fetcher reports the final URL and every hop's
  scheme. An old test double without them falls back to `base_url`'s scheme. A login
  page reached by a downgrade is refused before any POST.
- **The same predicate governs the manual 301/302/303 follow** after the POST.
  `auth_origins` cannot override a downgrade.
- **Ports:** host scope stays host-level by design. An in-scope other port over the
  **same or an upgraded** scheme stays allowed. This is stated in FR-SESS-12, with
  `auth_origins` named as the origin-precise alternative.
- **Tests** (`tests/test_session_credential_destination.py`):
  - an https login → http same host, other port, two `auth_origins` forms and `ftp:`,
    each refused with no POST;
  - every allow path (same origin, in scope, `auth_origins`) admits a destination the
    deny then refuses;
  - an https → http discovery redirect is refused;
  - an http → https → http discovery chain is refused;
  - an https → http POST redirect is not followed;
  - same or upgraded transport is still allowed (four cases);
  - the default fetcher reports its hops.

  10 of the new cases fail on `5eb4be9`.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0081 / PA-0082:** this exact function and constraint. A **recurrence**.

## Prior-preventive-action failure analysis
**PA-0082 was not followed, and it was not enforced.**
- PA-0082(1) lists the authorised origins. The implementation evaluated them as an OR
  with no deny.
- The draft's "never a downgrade" was part of the agreed design. Implementation waived
  it ("moot") from reasoning about one configuration, without going back to the
  reviewers. That is a process failure, not a gap in the rule's wording.
- No test exercised the deny, so nothing could catch the waiver.

## Preventive action
- **PA-0093** (strengthens PA-0082):
  1. **In an allow-list, the deny rules (transport, scheme) are evaluated before any
     allow**, and each is tested directly. A test makes every allow path admit a
     destination that the deny then refuses.
  2. **A safety constraint from an agreed draft is never waived in implementation
     without going back to the reviewers.** Any deviation is recorded in the bug doc as
     a reviewed change, never as an implementation note.

**Sweep (PA-0002):** other places that send credentials or session material:
- **`_basic_login`:** sends the header only to the operator's `base_url`. No derived
  destination.
- **`_verify_authenticated`:** probes `base_url`.
- **The core HTTP seam's `prepare`:** adds session headers to in-scope requests the
  operator's tools build. Not a response-derived destination.
- **The proxy:** forwards what the browser sends; it never originates credentials.
- **Oracle senders:** carry no stored credentials, and never follow redirects (PA-0046).
