# BUG-0098 — An https-established session was reused over plain http

- Date: 2026-10-13
- Status: fixed (CC-SESS-0013, CC-CORE-0036)
- Severity: medium-high. The audit rated it High. Session cookies and bearer or Basic
  headers obtained over https could be sent in cleartext to the same host.

## Description
`SessionManager.prepare` applied a cached `(host, identity)` session to any request
for that hostname. A session obtained over https was applied to
`http://lab.example/x`. `session_header()` handed the cookie to greybox, which put it
on every request with no transport check. A plugin that retargeted a prepared request
kept the attached credentials.

## Where encountered
A third-party audit of `1619932` (finding #2), reproduced with
`scratchpad/ext2/f02_cached.py`. Reviewer B (M1) found the greybox path.

## What it caused to fail
FR-SESS-12's https floor (BUG-0092) for session material; NFR-SESS-redaction's intent.

## What the bug was identified to be
The transport floor was enforced at the credential POST only. Cookies and tokens are
credentials too, and their send paths (`prepare`, `session_header` → greybox, plugin
retargets) never consulted it. **Partly by design:** sessions are keyed per host (D12),
so another port of the same host is intended. That part is unchanged, and it is now
stated in FR-SESS-13.

## Root cause analysis
1. *Why was the cookie sent over http?* `prepare` applied it unconditionally.
2. *Why unconditionally?* The session carried no record of how it was established.
3. *Why no record?* BUG-0092 framed the downgrade as a login-time property.
4. *Why not caught?* Its tests covered the POST only.

**Root cause:** the transport floor bound one artefact (the password POST), not every
credential-bearing artefact.

## Corrective action
- **`SessionState.secure_only`:**
  - it is set from the login's floor;
  - for a captured session, it is set by any https URL or `Secure` cookie;
  - when not given, it is derived from an https `login_url`;
  - it is persisted as metadata;
  - legacy persisted records derive it from `login_url`, and an unknown one fails
    closed (`secure_only_of`).
- **Every send path checks it before any secret:**
  - `prepare` (`_check_transport`);
  - `session_header` (refuses an http `base_url`);
  - `authorize`, called by `HttpClient.send` after a plugin changed the URL. It refuses
    another host or plain http;
  - greybox's `RequestsCorrelatingSender` (`cookie_secure_only`).
- **Stated residuals:**
  - a cookie's Path is not enforced, since sending it to another path of the same
    origin reveals nothing to another party;
  - other ports of the same host are allowed (D12).
- **Tests** (`tests/test_session_transport_binding.py`):
  - the repro;
  - another port allowed;
  - http-on-http allowed;
  - a login sets `secure_only`;
  - `session_header`;
  - a plugin retarget to http and to another host → nothing sent;
  - captured sessions;
  - legacy records (5 cases);
  - greybox.

## Recurrence review
- **BUG-0092 / PA-0093:** the same floor. A recurrence of the class: the floor existed,
  but not on these paths.

## Prior-preventive-action failure analysis
**PA-0093 was too narrow.** It required deny-before-allow at the credential POST.
Session material is a credential too, and its send paths were outside the rule.

## Preventive action
- **PA-0099:** a transport floor binds **every credential-bearing artefact** (password,
  cookie, token, Basic header) at **every point it is sent**: cached or fresh, through
  any helper that hands it to another sender, and again after anything edits the
  request.

**Sweep (PA-0002):** every consumer of `session_header` and `state.apply`:
- `HttpClient` (prepare, then authorize);
- greybox (fixed);
- `session/cli.py` (prints operator text and calls `session_header`, so the refusal
  applies).
