# Phase 6 — Intercepting proxy (HTTP/1.1) (plan)

A Burp-style intercepting proxy, **built from scratch** for full control (D4), as an
**optional observer** on the shared store (D5) — never in the timing path. The
defining feature is the **dual path**: a *parsed* path (`h11`) for normal traffic and
a *byte-exact raw* path for malformed-traffic study and hand-editing.

*Last updated: 2026-09-21. Component **PROXY** (#11). Requirements:
`docs/components/11-intercepting-proxy/requirements.md` (FR-PROXY-1..9). See D3/D4/D5
in `DECISIONS_AND_ROADMAP.md`.*

## Goal

Browse the lab through the proxy and inspect/edit exact bytes on the wire, with all
traffic landing in searchable shared history — while the core pipeline still runs
with the proxy off (it is optional, and timing-sensitive fuzzing bypasses it).

## Exit criterion

**Browse the lab, hand-edit a request with a duplicate `Content-Length`, and see the
exact bytes sent** — the parsed path (`h11`) would reject or normalize that request;
the raw path forwards it byte-for-byte.

## Principles (this phase)

- **Dual path (D4).** The parsed path validates/normalizes for convenience; the raw
  path is the source of truth for what goes on the wire and never reserializes
  (NFR-PROXY-byte-exact). Editing is byte surgery on the head, leaving untouched
  lines verbatim.
- **Optional observer (D5).** Nothing in the core pipeline requires the proxy; timing
  traffic bypasses it. Attaching it only adds `flow` history and manual tooling.
- **Offline-testable seams first.** The message model, parsers, scope, match-and-
  replace, history, interception queue, repeater, and session capture are built and
  unit-tested here with injected fakes; the live CONNECT/TLS socket serving and real
  browser trust are the **on-host** last mile (`docs/ON_HOST_TASKS.md`), like Phase 3.
- **Safe (NFR-PROXY-safe).** Scope-enforced, lab-only; the local CA never leaves the
  host; captured cookies/tokens are redacted on write and never persisted in cleartext.

## Tasks

- **T6.1 — Dual-path message model + parsers `[done, offline]`.**
  `fuzzlab/proxy/message.py::RawMessage` — byte-exact container (round-trips received
  bytes unchanged) with head/body split, duplicate-preserving header views, and
  byte-surgery edits (`with_appended_header`, `with_request_line`, `with_body`,
  header replace/remove) that keep untouched lines verbatim.
  `fuzzlab/proxy/parser.py` wraps `h11` for the parsed path (validate/normalize;
  duplicate `Content-Length` → rejected) alongside the raw path. A test proves the
  exit in miniature: a hand-edited duplicate-`Content-Length` request is byte-exact on
  the raw path and rejected on the parsed path.
- **T6.2 — Scope engine + match-and-replace `[done, offline]`.**
  `fuzzlab/proxy/scope.py::Scope` (include/exclude by host + optional path regex;
  default-deny; exclude overrides include) decides what is intercepted/recorded.
  `fuzzlab/proxy/matchreplace.py::MatchReplaceEngine` applies ordered byte-level
  rules to the request line / a header / the body (literal or regex).
- **T6.3 — Flow history `[done, offline]`.** Migration 6 extends `flow` with raw
  request/response bytes (content-addressed via `body`), `host`/`in_scope` columns, and
  an FTS5 index; adds `repeater_tab`. `fuzzlab/proxy/history.py::HistoryWriter` batches
  non-blocking writes into one transaction, content-addresses bodies + raw bytes,
  redacts secrets on write (`redact.py`, NFR-PROXY-safe), and offers punctuation-safe
  FTS search + byte-exact raw retrieval.
- **T6.4 — Interception (awaited future) + repeater `[done, offline]`.**
  `fuzzlab/proxy/intercept.py` models interactive interception as an `asyncio.Future`
  (hold → edit → release/drop). `fuzzlab/proxy/repeater.py` persists tabs to
  `repeater_tab` and replays edited requests through an injected sender seam
  (including the raw path).
- **T6.5 — Session capture (FR-PROXY-9) + session-manager addon `[done, offline]`.**
  `fuzzlab/proxy/session_capture.py` observes flows from a **manual browser login**,
  extracts the established cookies/tokens for `(host, identity)` (reusing the session
  detector), and hands a `SessionState` to the `SessionManager` to adopt — the escape
  hatch for logins detection can't parse (MFA/CAPTCHA/multi-step), no per-host config.
  Secrets redacted on write.
- **T6.6 — Local CA + async server wiring `[done offline; live serving on-host]`.**
  `fuzzlab/proxy/ca.py::LocalCA` — local CA + per-host leaf-cert cache behind an
  injectable minter seam (real X.509 minting is lazy `cryptography`, on-host).
  `fuzzlab/proxy/server.py`: `ProxyEngine` (the sans-I/O scope → match-replace →
  intercept → byte-exact forward → history pipeline), `parse_connect` +
  `target_from_request` (absolute↔origin rewrite), and `AsyncProxyServer` (the asyncio
  socket layer; its plain-HTTP path is tested offline over loopback). **Live CONNECT +
  TLS socket serving and browser trust of the CA are on-host.**

## Non-goals for Phase 6 (deferred)

- HTTP/2 and WebSocket parsing in the raw path (`h2`/`wsproto`) — Phase 9.
- Deciding what is vulnerable (auditor/oracle) — the proxy only observes/edits.
- A rich interception UI beyond the existing control panel — later.
- `hypothesis` property tests for the parser — deferred (not installed in the sandbox;
  the parser is covered by explicit byte-exact + round-trip unit tests instead).

## Component mapping

- **PROXY (11)** — the `fuzzlab/proxy/` package.
- **CORE (02)** — migration 6 (`flow` raw bytes + FTS5, `repeater_tab`); the shared
  store, budget, logging.
- **SESS (03)** — attached as an addon; adopts captured sessions (FR-SESS-11).
- **UI (12)** — the panel later surfaces flows/interception (kept minimal this phase).
