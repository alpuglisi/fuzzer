# Intercepting Proxy — Change Control Log

Component code: **PROXY**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-PROXY-0006 — Manual-login session capture + manager adoption (T6.5) (2026-09-21)
- Change: implemented FR-PROXY-9. `fuzzlab/proxy/session_capture.py::SessionCapture`
  watches the flows of a **manual browser login** through the proxy
  (`observe_request`/`observe_response`), accumulates the established cookies (from
  Set-Cookie and the browser's Cookie header) and any bearer token (with JWT `exp`,
  reusing `session/detect.py`), and builds a `SessionState`; `adopt_into(manager)` hands
  it to the session manager. Added `SessionManager.adopt(state)` (FR-SESS-11): marks the
  session valid, brings its host into scope, caches it for `prepare`/`apply`, and
  persists only NON-SECRET metadata. No per-host config file.
- Impact (other components / project): gives the session manager (#3) a way to stay
  authenticated on logins detection can't parse (MFA/CAPTCHA/multi-step/SPA) — the
  escape hatch D13 promised. Secrets live only in memory and are never written to the
  store (the `session_state` table has no secret columns), consistent with the D12
  secret model. Realizes CC-SESS-0004's spec (see CC-SESS-0007).
- Risk (level; mitigation): low — pure observation + in-memory handoff; adoption reuses
  the existing persistence path (non-secret only). Mitigated by 5 tests
  (`tests/test_proxy_session_capture.py`): cookie capture, bearer+exp capture, adoption
  authenticating `prepare` with no login handshake, and non-secret-only persistence.
  Suite 237 passed / 2 skipped.
- Deliverables:
  - [x] `SessionCapture` (cookie/token capture from flows) — done.
  - [x] `SessionManager.adopt` (FR-SESS-11) — done.
  - [ ] Live capture while browsing the lab through the running proxy — on-host (T6.6).
- Effectiveness (assessed 2026-09-21): effective in tests — a captured session
  authenticates the manager without a login handshake and no secret is persisted; the
  live browser capture is on-host.

### CC-PROXY-0005 — Interception (awaited future) + repeater (T6.4) (2026-09-21)
- Change: `fuzzlab/proxy/intercept.py::Interceptor` models interactive interception as
  an `asyncio.Future` (FR-PROXY-6): when enabled, the data path `await`s a per-message
  decision; `pending()`/`forward(id, edited?)`/`drop(id)` release it (edited via
  `RawMessage`), and disabling releases everything unedited — off means transparent
  pass-through (D5). `fuzzlab/proxy/repeater.py::Repeater` (FR-PROXY-4) persists tabs to
  `repeater_tab` (a saved raw request + target) and replays them through an injected
  **sender seam**, sending the exact bytes (raw path) and optionally recording the
  exchange to history.
- Impact (other components / project): the manual-testing surface — hold/edit/release
  and edit/replay — over the byte-exact core. The sender seam keeps it offline-testable
  (fake sender) while the on-host server supplies a real socket sender (T6.6).
- Risk (level; mitigation): low — sans-I/O logic behind seams; optional (D5). Mitigated
  by 9 tests (`tests/test_proxy_intercept.py`): disabled pass-through, forward-with-edit,
  forward-unedited, drop→None, disable-releases-held; tab persistence, byte-exact send,
  edited-raw replay persisting + sending exact bytes, and history recording.
- Deliverables:
  - [x] `Interceptor` awaited-future model (T6.4) — done.
  - [x] `Repeater` DB-persisted tabs + raw-path replay (T6.4) — done.
  - [ ] Wire both into the async server (T6.6) — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — held flows release edited or
  dropped, and the repeater replays byte-exact requests through the seam.

### CC-PROXY-0004 — Flow history: migration 6 + batched writer + FTS5 (T6.3) (2026-09-21)
- Change: added the proxy's shared history. **Migration 6** extends `flow` with a
  `host`, an `in_scope` flag, and byte-exact `req_raw_sha`/`resp_raw_sha` (raw wire
  bytes content-addressed via `body`, like decoded bodies), adds a standalone `flow_fts`
  FTS5 index, and a `repeater_tab` table (registry head → 6).
  `fuzzlab/proxy/history.py::HistoryWriter` buffers `FlowRecord`s and flushes them in
  **one transaction** (batched, non-blocking data path — NFR-PROXY-nonblocking),
  content-addressing raw bytes + bodies, indexing the head text for search, and
  offering `search()` (FTS5, punctuation-safe phrase queries) and byte-exact
  `raw_request`/`raw_response` retrieval. Persisted bytes are **redacted** first
  (`fuzzlab/proxy/redact.py`) so secrets never land in the store or the FTS index
  (NFR-PROXY-safe); the wire path stays byte-exact.
- Impact (other components / project): realizes FR-PROXY-3 — flows land in searchable
  shared history with raw bytes the anomaly detector, UI, and analysis read (D5). Adds
  the store columns/tables the proxy contract needs without touching existing rows
  (append-only migration). `repeater_tab` is the persistence for T6.4's repeater.
- Risk (level; mitigation): low — additive schema, batched writes, redaction on write.
  Mitigated by 7 tests (`tests/test_proxy_history.py`): migration-6 schema; batching
  defers then auto-flushes; byte-exact raw round-trip when no secrets; secret
  redaction (not stored, not searchable); FTS search by url/host/header; content-
  addressed dedup of identical raw. Suite 224 passed / 2 skipped.
- Deliverables:
  - [x] Migration 6 (flow raw bytes + FTS5 + `repeater_tab`) — done.
  - [x] Batched `HistoryWriter` + redaction + FTS search (T6.3) — done.
  - [ ] Interception + repeater (T6.4); session capture (T6.5); CA + server (T6.6) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — flows persist with
  byte-exact raw bytes, secrets are redacted, and history is searchable; the live
  capture-while-browsing path is on-host.

### CC-PROXY-0003 — Dual-path core: message model, parsers, scope, match-and-replace (T6.1/T6.2) (2026-09-21)
- Change: began Phase 6 with the offline-testable heart of the proxy — the **dual
  path** (D4). `fuzzlab/proxy/message.py::RawMessage` is a byte-exact container: it
  round-trips received bytes unchanged, exposes head/body and duplicate-preserving
  header views, and edits by **byte surgery** (`with_appended_header`, `with_header`,
  `without_header`, `with_request_line`, `with_body`) that leave untouched lines
  verbatim (NFR-PROXY-byte-exact). `fuzzlab/proxy/parser.py` is the parsed path over
  `h11` (`parse_request`/`parse_response`/`is_valid_request`) that validates and
  normalizes. `fuzzlab/proxy/scope.py::Scope` is a **default-deny** include/exclude
  engine (host + optional path regex; subdomain-suffix and port-less matching).
  `fuzzlab/proxy/matchreplace.py` applies ordered byte-level rewrites to the
  request/status line, a named header, or the body. Wrote `docs/PHASE_6_PLAN.md`.
- Impact (other components / project): delivers the phase's exit criterion in
  miniature — a hand-edited request with a conflicting duplicate `Content-Length` is
  forwarded byte-for-byte on the raw path while the parsed path rejects the ambiguous
  framing — establishing the byte-exact substrate the history, repeater, interception,
  and session-capture tasks build on. No store change yet (that is T6.3, migration 6).
  `h11` is a declared dependency (already installed); no new runtime dep this task.
- Risk (level; mitigation): low — pure, dependency-light byte logic; the proxy is
  optional (D5) and untouched by the core pipeline. Mitigated by 21 tests
  (`tests/test_proxy_message.py`): byte-exact round-trip, LF-only preservation,
  duplicate-header order, the duplicate-`Content-Length` raw-exact-but-parsed-rejects
  case (+ CL/TE smuggling primitive), all edit helpers, parser happy paths, and the
  scope + match-and-replace engines. Suite 217 passed / 2 skipped.
- Deliverables:
  - [x] `RawMessage` byte-exact model + edits (T6.1) — done.
  - [x] `h11` parsed path (T6.1) — done.
  - [x] Scope engine + match-and-replace (T6.2) — done.
  - [ ] Flow history + migration 6 (T6.3); interception + repeater (T6.4); session
        capture (T6.5); CA + async server wiring (T6.6, live on-host) — next.
- Effectiveness (assessed 2026-09-21): effective in tests — the raw path preserves
  malformed framing the parsed path rejects, which is the crux of the dual-path design;
  the live browse-and-forward exit is on-host.

### CC-PROXY-0002 — Planned: manual-login session capture (spec) (2026-09-21)
- Change: added FR-PROXY-9 — capture the authenticated session (cookies/tokens)
  from a **manual browser login** performed through the proxy and hand it to the
  session manager to adopt (FR-SESS-11). This is the escape hatch for logins the
  session manager's detection can't parse (MFA, CAPTCHA, multi-step, exotic SPA),
  with no per-host config. Spec only — no code (proxy is Phase 6).
- Impact (other components / project): gives the session manager (component #3) a
  way to stay authenticated on hosts detection can't handle; recorded in D13 and
  the Phase 6 roadmap; `ARCHITECTURE.md` #11 updated. No change to the store
  contract beyond the flows the proxy already records.
- Risk (level; mitigation): low (planning). Captured secrets are sensitive;
  mitigated by the proxy's existing redaction-on-write and lab-only/scope rules
  (NFR-PROXY-safe) and by not persisting them in cleartext.
- Deliverables:
  - [x] FR-PROXY-9 recorded — done.
  - [ ] Implement session capture + handoff to the session manager — todo (Phase 6).
- Effectiveness (assessed or pending): pending — built in Phase 6.

### CC-PROXY-0001 — Baseline (2026-09-21)
- Change: specify the component (requirements written). Not yet implemented.
  Decision D4 sets the build-from-scratch hybrid (sans-I/O parsed path + raw byte
  path); decision D5 fixes it as an optional observer on the shared store.
- Impact (other components / project): once built, it writes `flow` rows the
  anomaly detector, UI, and analysis read; it attaches the session manager as an
  addon so manual traffic is authenticated. Because it is optional (D5), no other
  component gains a hard dependency on it, and timing-sensitive fuzzing must be
  able to bypass it. Adds `flow` (+ raw bytes) to the store contract.
- Risk (level; mitigation): medium — a proxy in the data path can distort timing
  and is a security-sensitive component (TLS MITM, stored raw traffic). Mitigated
  by keeping it optional and out of the timing path (D5), a local-only CA, scope
  enforcement, redaction on write, and batched non-blocking history. The raw path
  isolates byte-exact study from the parsed path.
- Risk justification (accepted): building from scratch instead of adopting
  mitmproxy is accepted for the flexibility it buys (D4) — the byte-exact raw path
  and full control over interception — at the cost of more implementation work,
  sequenced after the session manager (Phase 6).
- Deliverables:
  - [ ] Async core; parsed (`h11`/`h2`/`wsproto`) + raw byte paths — todo (Phase 6).
  - [ ] CONNECT + TLS interception (local CA, cached leaf certs) — todo (Phase 6).
  - [ ] History: `flow` rows, FTS5, batched writes, content-addressed bodies — todo (Phase 6).
  - [ ] Repeater (DB-persisted tabs) + match-and-replace + scope engine — todo (Phase 6).
  - [ ] Interception-as-awaited-future workflow — todo (Phase 6).
  - [ ] Session-manager addon integration — todo (Phase 6).
- Effectiveness (assessed or pending): pending — not yet built. Will be judged by
  byte-exact replay, searchable shared history, and zero impact on timing-sensitive
  runs (which bypass it).
