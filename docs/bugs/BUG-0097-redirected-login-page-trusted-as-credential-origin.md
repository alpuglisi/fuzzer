# BUG-0097 — A redirected login page became a trusted credential destination

- Date: 2026-10-13
- Status: fixed (CC-SESS-0013)
- Severity: high. The stored username and password could be POSTed to an origin the
  operator never approved, over HTTPS too.

## Description
An in-scope login page `https://lab.example/login` that redirected to
`https://attacker.example/login` made the attacker's page the anchor of the credential
allow-list. Its form's relative `action="/collect"` resolved to
`https://attacker.example/collect`, whose origin equalled the "login page's own
origin", so the POST went there and the session was reported authenticated. A
deliberately vulnerable lab app with an open redirect on its login page would trigger
exactly this.

## Where encountered
A third-party audit of `main` at `1619932` (finding #1), reproduced with
`scratchpad/ext2/f01_redirect.py`. On `5eb4be9` the same scenario posted to the
in-scope `lab.example/collect`, so this is a **regression introduced by my BUG-0092
fix**.

## What it caused to fail
FR-SESS-12 and PA-0082(1) ("a URL derived from response content is never trusted as a
credential destination"); D11 (discovery GETs could leave scope).

## What the bug was identified to be
To enforce BUG-0092's transport floor, `_discover_login_form` started using the
fetcher's **final URL** as the login page URL. `_credential_destination_ok` then
allowed any destination with the same origin as that page, and the default fetcher
followed discovery redirects automatically.

## Root cause analysis
1. *Why did the password reach the attacker?* The destination matched the "same
   origin as the login page" rule.
2. *Why was that page the attacker's?* The page URL came from the redirect chain, a
   response-derived value.
3. *Why was a response-derived value trusted?* BUG-0092 needed the final URL's scheme
   for the transport floor, and I reused it as the trust anchor without separating the
   two roles.
4. *Why not caught?* BUG-0092's redirect tests covered same-host downgrades only, not
   a cross-origin redirect.

**Root cause:** the allow-list's anchor was response-derived; operator input was not
the only source of trust.

## Corrective action
- **Discovery never lets the fetcher follow redirects** (`_get_no_redirects`). It walks
  them by hand (`_navigate`, at most `MAX_LOGIN_HOPS` = 5), authorising **every hop
  before it is fetched** with the same predicate as credential destinations, the
  transport deny first. So no discovery request leaves the approved origins.
- **A fetcher that cannot refuse redirects fails closed** (A3): it must report a final
  URL equal to the one asked for.
- **`_credential_destination_ok(target, base_url, ...)` is anchored to operator input
  only:** the base URL's origin, its https upgrade, an in-scope host (any port, D12),
  or `auth_origins`. The "same origin as the page" exemption is removed.
- **The post-login verification probe** walks redirects the same way, carrying the
  session's headers.
- **Tests** (`tests/test_session_transport_binding.py`):
  - the audit's repro: refused, and the attacker origin is never fetched;
  - an in-scope multi-hop login still works;
  - an `auth_origins` SSO hop works;
  - too many hops → refused;
  - a fetcher that cannot refuse redirects → refused;
  - the anchor cases.

  The two BUG-0092 redirect tests are rewritten with real 302 hops.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0081 / PA-0082:** credential destinations. A recurrence of the class.
- **BUG-0092 / PA-0093:** my own fix, which introduced this.

## Prior-preventive-action failure analysis
- **PA-0082(1) was not followed.** It says a response-derived URL is never trusted as a
  credential destination, and my BUG-0092 change made one the anchor of the
  allow-list.
- **PA-0093 was followed but was not enough.** It puts the deny before every allow,
  but it says nothing about where the allow set comes from, so a poisoned allow set
  passed straight through.

## Preventive action
- **PA-0098** (strengthens PA-0082 and PA-0093):
  1. The trust anchor of an allow-list is **operator input only**. A URL from a
     response is checked against the anchor, never added to it.
  2. Every navigation hop is authorised **before** it is fetched.
  3. A client that cannot refuse redirects must prove it followed none, or the call
     fails closed.

**Sweep (PA-0002):**
- the post-login verification probe: now walks hops the same way;
- `_post_credentials`: already manual, now anchored to `base_url`;
- `_basic_login`: sends only to `base_url`;
- oracle and probe senders: never follow redirects (PA-0046);
- the proxy: forwards the browser's traffic and originates no credentials.
