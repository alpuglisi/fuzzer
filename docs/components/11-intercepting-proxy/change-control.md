# Intercepting Proxy — Change Control Log

Component code: **PROXY**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-PROXY-0014 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/proxy/cli.py` now factors its argparse setup into `build_parser()`;
  `main()` keeps the `p` reference (so `p.error(...)` on `--export-ca`/`--authorized` still
  works) and delegates parsing. Behavior-preserving — same flags, defaults, and gates.
- Impact: lets the web launcher introspect the proxy's flags (CC-UI-0011). Independent of
  the Phase-2 proxy-workbench wiring. No CLI behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()`; `main()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds the proxy's spec
  from this parser.

### CC-PROXY-0013 — Fix (BUG-0012): proxy_e2e.sh self-test uses conflicting Content-Length (2026-09-21)
- Change: `scripts/proxy_e2e.sh` step 5 now sends **conflicting** Content-Length values
  (`0` and `5`) instead of two identical `0`s. Duplicate-*identical* Content-Length is
  valid per RFC 7230 (h11 accepts it), so the old assertion (`is_valid_request` is False)
  produced a false FAIL even though the proxy forwarded byte-exact correctly. Runbook
  Part I.4 clarified to use conflicting values.
- Impact (other components / project): the Part I exit self-test now matches the validated
  offline unit test (which already used 5/6) and passes on-host. No product-code change —
  the proxy's raw byte-exact forwarding was already correct.
- Risk (level; mitigation): low — test/script-only. The offline
  `test_async_server_forwards_duplicate_content_length_byte_exact` already covers the
  correct (conflicting) case. Suite 415 passed / 6 skipped.
- Deliverables:
  - [x] Conflicting-CL request in `proxy_e2e.sh`; runbook wording — done.
  - [x] RCA `docs/bugs/BUG-0012-*`; rule PA-0013; ERROR_LOG — done.
- Effectiveness (assessed 2026-09-21): the on-host Part I run's exit check now reflects the
  true HTTP contract (only conflicting CL is rejected) and passes.

### CC-PROXY-0012 — Fix (BUG-0010/BUG-0011): leaf-cert AKI/SKI + bounded async shutdown (2026-09-21)
- Change: fixed two on-host proxy defects found running Part I. (BUG-0010) `LocalCA` now
  mints certs strict verifiers accept — CA with SKI + keyCertSign KeyUsage; leaf with SKI,
  an AKI referencing the CA, serverAuth EKU, a leaf KeyUsage, and an IPAddress SAN for IP
  hosts; dropped deprecated `datetime.utcnow()`. (BUG-0011) `AsyncProxyServer` tracks and
  cancels its per-connection tasks and bounds `wait_closed()` with a 3s timeout so stop()
  can't hang on live connections (a Python 3.12+ behavior); the proxy CLI persists flow
  history per-record (`batch_size=1`, WAL) and `scripts/proxy_e2e.sh` bounds its shutdown
  with a `-KILL` fallback.
- Impact (other components / project): HTTPS interception now actually works on-host (the
  minted leaf verifies and a browser will trust it), and `fuzzlab proxy` /
  `scripts/proxy_e2e.sh` exit cleanly instead of hanging. No interface change; the flow
  store is written incrementally now (WAL-safe concurrent reads).
- Risk (level; mitigation): low — additive cert extensions + a more careful teardown.
  Mitigated by a skip-guarded extension-assertion test (leaf AKI matches CA SKI, serverAuth
  EKU, IP SAN) plus the existing on-host tunnel test that reproduced BUG-0010 and now
  passes; the offline connection tests still pass with the new stop(). Suite 415 passed /
  6 skipped.
- Deliverables:
  - [x] SKI/AKI/EKU/KeyUsage + IP SAN in `LocalCA`; non-deprecated UTC (BUG-0010) — done.
  - [x] Tracked+cancelled conns and bounded `wait_closed()`; per-record history; bounded
        script shutdown (BUG-0011) — done.
  - [x] RCAs `docs/bugs/BUG-0010-*`, `BUG-0011-*`; PA-0011/PA-0012; ERROR_LOG — done.
- Effectiveness (assessed 2026-09-21): offline suite green; the on-host CONNECT/TLS tunnel
  test that failed with "Missing Authority Key Identifier" now has the extensions it needs,
  and shutdown is bounded so the Part I script can no longer hang.

### CC-PROXY-0011 — Live h2c socket transport for the raw HTTP/2 client (Phase 9 on-host, T9.x) (2026-09-21)
- Change: built the Phase 9 on-host last mile so runbook Part K is a one-command flow. New
  `fuzzlab/proxy/h2transport.py::H2Transport` is the socket send/receive around the
  already-built `H2RawClient`/`h2frames`/`hpack`: `request(...)` opens a plaintext TCP
  socket to an h2c (prior-knowledge) endpoint, sends preface+SETTINGS+HEADERS, ACKs the
  server SETTINGS, reads to END_STREAM, and decodes an `H2Response` (`:status` when
  static-indexed; reassembled DATA body); `send_raw(...)` writes exactly the bytes from
  `build_raw(...)` for malformed/length-desync/CRLF-in-header primitives. Orchestration
  `scripts/h2_desync_e2e.sh`.
- Impact (other components / project): the from-scratch HTTP/2 client can now talk to the
  lab's opt-in h2→h1 downgrade front-end over a real socket — no TLS/ALPN/Upgrade needed
  (nginx `http2 on;` prior knowledge). Depends on the LAB desync profile (CC-LAB-0010 adds
  `PFF_PROFILE` to `labctl.sh`). No change to the byte-building modules. Dual-use protocol
  tooling; loopback + opt-in profile only.
- Risk (level; mitigation): low–medium — a real socket to a smuggling research target.
  Mitigated by: loopback-only, the front-end being opt-in (`desync` profile, default off),
  the transport reading with bounded timeouts, and tests (`tests/test_proxy_h2_transport.py`)
  that exercise the real socket path against a one-shot loopback server: a normal request
  decodes `:status`/body, `send_raw` puts a length-desync frame on the wire byte-exact, and
  a CRLF-in-header value is carried verbatim. The desync exit is framed as emitting the
  primitive (a patched nginx correctly rejects it), not a successful smuggle. Suite 411
  passed / 5 skipped.
- Deliverables:
  - [x] `H2Transport.request` / `send_raw` (live h2c socket) + tests — done.
  - [x] `scripts/h2_desync_e2e.sh`; runbook Part K rewritten to one command — done.
  - [ ] Live smuggle against a deliberately-mishandling front-end — out of scope (nginx is patched).
- Effectiveness (assessed 2026-09-21): effective offline — the transport round-trips a real
  h2 response and emits both desync primitives byte-exact over a socket. The live front-end
  exchange is driven by `scripts/h2_desync_e2e.sh`.

### CC-PROXY-0010 — Live upstream SocketSender + CONNECT/TLS termination + `fuzzlab proxy` CLI (Phase 6 on-host, T6.x) (2026-09-21)
- Change: built the Phase 6 on-host last mile so runbook Part I is a one-command flow.
  New `fuzzlab/proxy/socketsender.py::SocketSender` is a real upstream `Sender`
  (`(host,port,use_tls,raw)->bytes`): TCP/TLS-connect, send byte-exact, read the whole
  HTTP/1 response (Content-Length / chunked / close-delimited). `AsyncProxyServer` gained
  a `ca` param and a `_handle_connect` that replies `200 Connection Established`,
  TLS-terminates the client with a CA-minted per-host leaf (new
  `LocalCA.leaf_cert_files` materializes the leaf to 0600 files; server-side upgrade via
  `loop.start_tls`), and forwards tunnelled requests through the same engine to the HTTPS
  upstream; without a CA, CONNECT still answers 501. New `fuzzlab/proxy/cli.py`
  (`fuzzlab proxy`, dispatched in `cli.py`): `--export-ca` (no `--authorized`; sends
  nothing) and the run path (requires `--authorized`), with scope/store/ca-dir flags.
  Orchestration `scripts/proxy_e2e.sh`.
- Impact (other components / project): the proxy can now intercept live traffic against
  the lab and record flows to the store; HTTPS interception works once the CA is trusted.
  Reuses the existing sans-I/O engine/repeater seam unchanged (the sender is injected), so
  no change to match-replace/history/scope/intercept. Per D5 the proxy stays optional and
  out of the timing path. Depends on `cryptography` on-host for minting + the handshake.
- Risk (level; mitigation): medium — real sockets + a server-side `loop.start_tls`
  upgrade (an internal-ish streams idiom) and MITM TLS. Mitigated by: byte-exact
  forwarding (no reserialization), full upstream TLS verification by default
  (`--no-verify-tls` opt-in for self-signed lab origins), the CA key staying 0600 and
  never distributed, `--authorized` gating the run, loopback defaults, and tests —
  `tests/test_proxy_live.py`: SocketSender Content-Length + close-delimited reads, the
  byte-exact duplicate-Content-Length forward through the async server (parsed path
  rejects it), and a skip-guarded on-host CONNECT+TLS tunnel that forwards byte-exact.
  Suite 408 passed / 5 skipped.
- Deliverables:
  - [x] `SocketSender` (real upstream, byte-exact) + tests — done.
  - [x] CONNECT/TLS termination in `AsyncProxyServer` + `LocalCA.leaf_cert_files` — done.
  - [x] `fuzzlab proxy` CLI (+ `--export-ca`) and dispatch — done.
  - [x] `scripts/proxy_e2e.sh`; runbook Part I rewritten to one command — done.
  - [ ] Live browser-trust + HTTPS interception walk-through — on-host (script prints steps).
- Effectiveness (assessed 2026-09-21): effective offline — the real sender round-trips and
  the duplicate-Content-Length request forwards byte-exact while the parsed path rejects
  it. The CONNECT+TLS tunnel and CA minting are covered by skip-guarded tests that run
  on-host, and `scripts/proxy_e2e.sh` drives the live lab exit.

### CC-PROXY-0009 — HTTP/2 frames + minimal HPACK + raw-frame client (T9.2/T9.3) (2026-09-21)
- Change: from-scratch, byte-exact HTTP/2 for the raw path. `fuzzlab/proxy/h2frames.py`
  encodes/decodes the frame types (DATA/HEADERS/SETTINGS/WINDOW_UPDATE/RST_STREAM/PING/
  GOAWAY/…), the connection preface, and lets the caller **override the declared length**
  independent of the payload (a length-desync primitive). `fuzzlab/proxy/hpack.py` is a
  minimal HPACK (integer/string primitives, the static table, literal representations,
  decode of static-indexed + literal; dynamic table + Huffman-encode out of scope) that
  passes **arbitrary header bytes** through unchanged. `fuzzlab/proxy/h2client.py::H2RawClient`
  assembles a request (preface → SETTINGS → HEADERS → optional DATA) and, via `build_raw`,
  arbitrary/malformed frame sequences — the desync/smuggling tool for the **self-owned
  lab** (the T9.5 h2→h1 front-end). Dependency-light; the parsed `h2` path is declared +
  skip-guarded (on-host).
- Impact (other components / project): realizes the HTTP/2 half of protocol depth — raw
  frame construction with arbitrary bytes for authorized desync research, offline-testable.
  The live socket + TLS + ALPN override and sending to a real h2 endpoint are on-host
  (T9.4/T9.6). Lab-only posture unchanged; no store change.
- Risk (level; mitigation): medium (dual-use tooling) — mitigated structurally by scope
  enforcement, loopback/lab-only, no-auto-run, and the target being infrastructure we run
  ourselves; the raw client only *builds bytes* here (no network). Correctness mitigated
  by 13 tests (`tests/test_proxy_h2.py`): HPACK integer RFC vectors, header round-trip
  incl. arbitrary CRLF, static-indexed decode, Huffman-decode raises; frame round-trip +
  flags, the length-override desync primitive, all builders, multi/partial-tail decode,
  truncation errors; client request structure, body DATA frame + odd/incrementing stream
  ids, arbitrary-header passthrough, and arbitrary-frame `build_raw`. Suite 341 passed / 4 skipped.
- Deliverables:
  - [x] HTTP/2 frame layer (T9.2) — done.
  - [x] Minimal HPACK (T9.2) — done.
  - [x] HTTP/2 raw-frame client (T9.3, offline builder) — done.
  - [ ] Parsed `wsproto`/`h2` path (T9.4); lab h2→h1 front-end (T9.5); exit (T9.6) — next/on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — HPACK matches the RFC integer
  vectors and preserves arbitrary bytes, frames round-trip byte-exact with a working
  length-desync primitive, and the client builds valid and deliberately-malformed requests;
  live ALPN/socket + the desync exit are on-host.

### CC-PROXY-0008 — WebSocket framing + flow.protocol (Phase 9 T9.1) (2026-09-21)
- Change: began protocol depth. `fuzzlab/proxy/ws.py` is a from-scratch, byte-exact RFC
  6455 WebSocket frame codec — `encode_frame`/`decode_frame`/`decode_frames` (FIN/RSV/
  opcode, MASK, 7/16/64-bit lengths, masking key), `apply_mask` (self-inverse),
  `reassemble` (fragmented data frames → messages), control-frame handling, and the
  handshake (`accept_key`, `is_upgrade_request`/`is_upgrade_response`) reusing the
  HTTP/1.1 machinery. The Phase 6 history now tags each flow's protocol: `FlowRecord`
  gains `protocol` (default `http/1.1`) and the writer persists it (migration 9's
  `flow.protocol`). Dependency-light (stdlib); the `wsproto` parsed path is declared and
  skip-guarded (on-host).
- Impact (other components / project): the raw WebSocket path — inspect/edit/replay
  frames (including masked/malformed) without a library normalizing them — recorded and
  searchable in the existing history and replayable via the existing repeater (encoded
  frames are raw bytes). Sets up HTTP/2 (T9.2/T9.3) and the parsed-path integration
  (T9.4). No behavior change to HTTP/1.1 flows (protocol defaults to `http/1.1`).
- Risk (level; mitigation): low — pure, dependency-light byte logic; optional (D5).
  Mitigated by 11 tests (`tests/test_proxy_ws.py`): migration-9 schema; the RFC handshake
  vector; upgrade detection; byte-exact unmasked frame; masking hides payload + round-trips
  + self-inverse; 16/64-bit lengths; control frames; fragmentation reassembly; multi-frame
  + partial-tail decode; truncated-frame errors; history records the protocol tag. Suite
  328 passed / 4 skipped.
- Deliverables:
  - [x] WebSocket frame codec + handshake + history protocol tag (T9.1) — done.
  - [ ] HTTP/2 frames + HPACK (T9.2); raw-frame client (T9.3); parsed-path wsproto/h2
        (T9.4); lab downgrade front-end (T9.5); exit (T9.6) — next/on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — frames round-trip byte-exact
  (masked and unmasked), the handshake matches the RFC vector, and flows carry a protocol
  tag; live WS interception through the running proxy is on-host.

### CC-PROXY-0007 — Local CA, flow engine, and async server wiring (T6.6) (2026-09-21)
- Change: tied the proxy together. `fuzzlab/proxy/server.py::ProxyEngine` is the
  **sans-I/O** flow pipeline — scope check → match-and-replace → interception →
  byte-exact forward (via an injected upstream sender seam) → history — where
  FR-PROXY-1/3/5/6 meet; out-of-scope traffic is forwarded untouched and unrecorded.
  `parse_connect`/`target_from_request` handle CONNECT and rewrite absolute-form
  requests to origin-form. `AsyncProxyServer` is the asyncio socket layer; its
  **plain-HTTP** path is exercised offline over loopback. `fuzzlab/proxy/ca.py::LocalCA`
  is the local CA (FR-PROXY-2) with a per-host **leaf-cert cache** behind an injectable
  minter seam; the real X.509 minting is lazy `cryptography` (on-host).
- Impact (other components / project): completes the offline-buildable proxy stack — the
  engine, CONNECT/target parsing, the async plumbing, and the CA cache are all in place
  and tested. The **live last mile** is on-host: CONNECT + TLS socket serving and
  browser trust of the CA (the sandbox has no working `cryptography`/TLS), tracked in
  `docs/ON_HOST_TASKS.md`. Optional per D5; timing traffic bypasses it.
- Risk (level; mitigation): low offline (seam-isolated, pure pipeline); the security-
  sensitive TLS MITM is on-host with a local-only CA, scope enforcement, and redaction.
  Mitigated by 12 tests (`tests/test_proxy_server.py`, 1 skipped for broken sandbox
  crypto): CONNECT + absolute/origin/https target parsing; leaf-cache mints once per
  hostname (port-independent) + a skip-guarded real-minting test; engine forwards +
  records in scope, bypasses out-of-scope untouched/unrecorded, applies match-replace,
  and drops/edits via the interceptor; and the async server round-trips a plain-HTTP
  request over loopback (absolute→origin rewrite) and returns 501 for CONNECT offline.
  Suite 248 passed / 3 skipped.
- Deliverables:
  - [x] `ProxyEngine` sans-I/O pipeline (scope/match-replace/intercept/forward/log) — done.
  - [x] `parse_connect` + `target_from_request` (absolute↔origin) — done.
  - [x] `AsyncProxyServer` plain-HTTP path (offline loopback) — done.
  - [x] `LocalCA` leaf-cert cache + lazy `cryptography` minting — done.
  - [ ] Live CONNECT + TLS serving + browser trust of the CA — on-host.
  - [ ] Exit: browse the lab, hand-edit a duplicate `Content-Length`, see exact bytes — on-host.
- Effectiveness (assessed 2026-09-21): effective in tests — the engine enforces scope,
  forwards byte-exact, intercepts, and records; the CA caches leaves per host; the async
  server round-trips plain HTTP. The live TLS browse-and-edit exit is on-host.

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
