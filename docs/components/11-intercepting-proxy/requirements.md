# Intercepting Proxy — Requirement Specification

Component code: **PROXY** · Status: `[built — offline stack + live upstream SocketSender, CONNECT/TLS termination, and the fuzzlab proxy CLI; live HTTPS interception verified on-host]` (Phase 6) · Last updated: 2026-09-21 · see CC-PROXY-0010

Related: `ARCHITECTURE.md` #11; `DECISIONS_AND_ROADMAP.md` (D3, D4, D5);
`./change-control.md`.

## 1. Purpose
Provide a Burp-style intercepting proxy for inspecting, editing, and replaying
traffic — built from scratch for full control (D4) — as an **optional observer**
that shares the store, never a mandatory pipeline (D5).

## 2. Scope
- **In:** async proxy core, a parsed protocol path and a byte-exact raw path,
  TLS interception, shared history, repeater, match-and-replace, scope engine,
  interactive interception.
- **Out:** deciding what is vulnerable (auditor/oracle) and staying authenticated
  (session manager, attached as an addon).

## 3. Functional requirements
- **FR-PROXY-1** Async core with two paths: a **parsed** path (`h11`/`h2`/
  `wsproto`) for normal traffic and a **raw byte** path (byte-exact, single-use
  connections) for malformed-traffic study — the hybrid of D4.
- **FR-PROXY-2** CONNECT + TLS interception with a local CA and cached leaf certs.
- **FR-PROXY-3** Persist history to the store (FTS5 search, batched writes,
  content-addressed bodies) as `flow` rows with raw bytes.
- **FR-PROXY-4** Repeater with DB-persisted tabs; edit and replay, including via
  the raw path.
- **FR-PROXY-5** Match-and-replace rules and a scope engine (only in-scope hosts
  are intercepted/recorded).
- **FR-PROXY-6** Interactive interception modeled as an awaited future (hold,
  edit, release).
- **FR-PROXY-7** Attach the session manager as an addon so hand-driven browser
  traffic gets the same auth handling.
- **FR-PROXY-8** Remain optional: tools may route through it for unified history,
  but timing-sensitive traffic bypasses it (D5).
- **FR-PROXY-9 (session capture)** Capture the authenticated session from a
  **manual browser login** performed through the proxy — extract the established
  cookies/tokens for the `(host, identity)` and hand them to the session manager to
  adopt. This is the path for logins the session manager's detection can't parse
  (MFA, CAPTCHA, multi-step, exotic SPA), keeping the toolkit authenticated without
  a per-host config file. Captured secrets are redacted on write and never
  persisted in cleartext.

## 4. Non-functional requirements
- **NFR-PROXY-byte-exact** The raw path preserves bytes exactly (no reserializing).
- **NFR-PROXY-safe** Scope-enforced and lab-only; the local CA never leaves the
  host; credentials/tokens redacted on write.
- **NFR-PROXY-nonblocking** History writes are batched and must not stall the data
  path.
- **NFR-PROXY-optional** Nothing in the core pipeline requires the proxy to run.

## 5. Interfaces and data contracts
Writes `flow` rows (+ raw bytes) to the store, read by the anomaly detector, UI,
and analysis. Uses the session manager as an addon. Shares `core/` config, budget,
and logging.

## 6. Dependencies (components)
`core/`, session manager (attached as an addon).

## 7. Acceptance criteria
- Intercepts and replays HTTP/1.1, HTTP/2, and WebSocket traffic against the lab.
- Raw path reproduces byte-exact requests the parsed path would normalize.
- Flows land in shared history with raw bytes and are searchable; scope is
  enforced; timing-sensitive tool traffic can bypass the proxy.

## 8. Open questions
- TLS trust-store handling for the browser under test.
- History retention/rotation policy for large captures.
- HTTP/2 and WebSocket edge cases in the raw path.
