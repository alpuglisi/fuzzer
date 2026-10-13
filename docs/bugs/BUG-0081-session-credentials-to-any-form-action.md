# BUG-0081 — The session manager POSTed stored credentials to any form action, and followed redirects with them

- Date: 2026-10-13
- Status: fixed (CC-SESS-0011)
- Severity: high. Stored lab credentials could leave the lab, sent to whatever origin a
  page's form or redirect named.

## Description
`SessionManager._login` discovered a login form and POSTed `form.fill(username,
password)` to `form.action_url`, with no origin check: a page with `action=
"http://attacker.example/c"` received the credentials. The default fetcher also POSTed
with `allow_redirects=True`, so a 307/308 from the real login endpoint re-sent the body
to any `Location`. Separately, HTTP Basic logins could never succeed:
- a Basic site serves no form, so discovery failed before any POST;
- `_login` rejected every 401 before reaching `detect_session_credential`'s Basic branch.

## Where encountered
The error-review phase (`scratchpad/review7/r6_session_leak.py`). Reviewer A found the
redirect path; reviewers A and B found the discovery gap for Basic.

## What it caused to fail
D12 (credentials stay with their owner) and the lab-only rule. HTTP Basic labs could
not authenticate at all.

## What the bug was identified to be
A URL taken from response content was trusted as a credential destination. The HTTP
client was allowed to re-send credentials on redirects.

## Root cause analysis
1. *Why did credentials go off-lab?* The POST target came from the page, unchecked.
2. *Why unchecked?* `ensure` checks the *host being authenticated* against scope, and
   the form was assumed to post back to it.
3. *Why the redirect leak?* The requests default follows redirects, and 307/308 keep
   the method and body.
4. *Why was Basic unreachable?* Discovery required a form; the POST-401 check
   preceded the Basic branch.
5. *Why no test?* The fakes always posted to the same host and never redirected.

**Root cause:** response-derived URLs were trusted as credential destinations, and
redirect following was left to the client library.

## Corrective action
In CC-SESS-0011:
- **`_credential_destination_ok(target, login_page_url)` allows** only:
  - the login page's canonical origin;
  - that same host upgraded http→https;
  - an in-scope host (the manager's `scope_hosts`, by host or `host:port`);
  - an origin listed in the new `SessionManager(auth_origins=[...])`.

  Otherwise `SessionAuthError` names the option and **no POST is made**.
- **The POST never follows redirects.** `allow_redirects=False` is a new `Fetcher.post`
  keyword, which old test doubles without it are called without.
  - A 301/302/303 is followed by hand as a GET, only to an allowed origin.
  - A 307/308 is **never** followed: the 3xx itself is judged.
- **HTTP Basic** is detected at discovery: the base URL answering `401` with
  `WWW-Authenticate: Basic` (no form). The POST-401-Basic case is a secondary path. The
  `Authorization` header goes only to that in-scope base URL, and a wrong password
  fails loudly.
- **Tests** (`tests/test_session_credential_destination.py`):
  - three cross-origin actions → no POST;
  - five allowed destinations (relative, absolute same-origin, https upgrade, in-scope
    other port, `auth_origins`);
  - an out-of-scope host → refused;
  - 307/308 to another origin and to the same origin → not followed;
  - a 302 → followed only when allowed;
  - Basic at discovery, a wrong Basic password, POST-401 → Basic, and a 401 without a
    challenge → rejected.

**Implementation note:** "never a downgrade" from the draft is moot. The authenticated
host is always in scope (`ensure` requires it), so a same-host http action is allowed
by the in-scope rule. That is stated rather than special-cased.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0039 / BUG-0044 / PA-0046** (senders must not follow redirects). **Same class:**
  redirect following by a client library. PA-0046 covered the oracle's probe
  senders (`allow_redirects=False`), not the session manager's login fetcher.
- **BUG-0008** (login success judged on a positive signal): same function, different
  defect.

**Result:** a recurrence of PA-0046's redirect class in a sender it did not name.

## Prior-preventive-action failure analysis
**PA-0046 was too narrow.** It was worded around "every `Sender`" (the oracle seam), and
the session manager's `Fetcher` is a different seam that also sends, with credentials
at that. The sweep never looked at it.

## Preventive action
**PA-0082** (strengthens PA-0046):
1. A credential is sent only to an origin the operator authorised: the login page's own
   origin, an in-scope host, or an explicit allow-list. A URL derived from response
   content (a form action, a redirect, a link) is never trusted as a credential
   destination.
2. Every HTTP client that sends credentials disables automatic redirects and follows
   them by hand under the same origin rule. A 307/308 is never followed with a body.

**Sweep (PA-0002):**
- **Session-manager POST:** fixed.
- **Session-manager GETs** (`_discover_login_form`, `_verify_authenticated`): they
  carry cookies or a header only to `base_url`, which is in scope. They follow
  redirects with no body, and cookies are domain-scoped by requests: accepted.
- **Oracle senders:** `allow_redirects=False` already (PA-0046).
- **`proxy/session_capture`:** it captures, and sends nothing.
- **`core/http` seam:** it sets `allow_redirects=False` (BUG-0039).
