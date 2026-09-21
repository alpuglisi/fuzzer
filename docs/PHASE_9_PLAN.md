# Phase 9 — Protocol depth (plan, for review)

Extend the intercepting proxy beyond HTTP/1.1 to **WebSockets** and **HTTP/2**, with a
**raw-frame** path that can put arbitrary bytes on the wire, and add an opt-in lab
topology (an HTTP/2 → HTTP/1.1 downgrade front-end) as a **legitimate, self-owned desync
research target**. Same posture as the rest of the toolkit: **lab-only, loopback-only,
on infrastructure we own** — never third parties.

*Draft for review — nothing built yet. Components **PROXY** (#11) and **LAB** (#1).
See `DECISIONS_AND_ROADMAP.md` (D4, Phase 9) and the proxy requirements (HTTP/2 +
WebSocket acceptance criteria and raw-path open questions).*

## Goal

Browse, intercept, and replay **WebSocket** and **HTTP/2** traffic through the proxy
against the lab; put a **byte-exact / arbitrary** HTTP/2 request on the wire that the
parsed path would normalize; and study **HTTP/2 → HTTP/1.1 desync** against an opt-in
downgrade front-end we run ourselves — all in the containerized lab.

## Exit criterion

Against the lab: the proxy intercepts and replays a WebSocket conversation and an HTTP/2
request; the raw-frame client sends an HTTP/2 request with header bytes the parsed path
(`h2`/HPACK) would reject or normalize, and we see the exact frames sent; and a
documented h2→h1 desync primitive is demonstrated against the opt-in front-end —
lab-only, on our own infrastructure.

## Principles (this phase)

- **Raw-frame first (D4).** The value is putting *arbitrary bytes* on the wire, so the
  core is from-scratch, dependency-light **frame codecs** — WebSocket framing and HTTP/2
  frames + a minimal HPACK — byte-exact and fully offline-testable. The parsed path
  (`wsproto`/`h2`) is a convenience for normal traffic, declared and **skip-guarded**
  where the build is unavailable (like `cryptography`/`sqlglot`), exercised on-host.
- **Offline-testable seams.** Codecs, frame assembly, masking, fragmentation, and the
  raw HTTP/2 request builder are unit-tested here with fakes. Live ALPN/TLS, sending to a
  real h2 server, the parsed libraries, and the desync topology are **on-host**, like
  Phases 3/6/8.
- **Reuse the proxy.** WebSocket/HTTP-2 flows record to the existing Phase 6 history
  (`flow`/`flow_fts`) and replay through the existing repeater; the WS handshake reuses
  the HTTP/1.1 machinery.
- **Safety and ethics.** Desync/smuggling primitives are dual-use; here they target a
  front-end **we deploy in our own loopback lab** for research. Scope enforcement,
  lab-only, no-auto-run, and the destructive gate all still apply. Nothing is aimed at
  systems we do not own.

## Design decisions to confirm (review points)

1. **Dependency-light, raw-first.** Build WebSocket framing and the HTTP/2 frame layer +
   HPACK **from scratch** (byte-exact); declare `wsproto`/`h2` for the parsed path and
   skip-guard their tests. *Proceeding this way unless you object.*
2. **HPACK scope.** Implement a **minimal HPACK** — the static table + literal
   header-field representations (with/without incremental indexing) and the integer/string
   primitives — enough to encode/decode arbitrary header bytes for the raw client. Full
   dynamic-table indexing/eviction is out of scope (not needed to emit arbitrary headers).
   *Confirm.*
3. **Lab topology front-end.** Add an **opt-in, default-off** front-end reverse proxy to
   the lab that terminates HTTP/2 and forwards HTTP/1.1 to the PHP app — the h2→h1
   downgrade desync target. Proposed: **nginx** (`http2` + `proxy_pass`), a new compose
   service gated behind a profile/flag so the default lab is unchanged (existing labels
   stay valid, like the D16 WAF). *Confirm front-end (nginx) + default-off.*
4. **Flow history for new protocols. `[decided]`** Add a `flow.protocol` column
   (`http/1.1` | `h2` | `ws`) via **migration 9** so history distinguishes them; the Phase
   6 `HistoryWriter`/`FlowRecord` gain a `protocol` field (default `http/1.1`, so existing
   behavior is unchanged).
5. **Safety framing.** Keep the desync/smuggling work explicitly lab-only and self-owned;
   the raw-frame "arbitrary bytes" client is a research tool for the authorized lab. *No
   change to posture; confirming it stays front-and-center.*

## Tasks

- **T9.1 — WebSocket frame codec + proxy handling `[done, offline]`.** From-scratch WS framing
  (`fuzzlab/proxy/ws.py`): encode/decode frames (opcode, FIN, mask/unmask, 7/16/64-bit
  lengths), fragmentation/continuation, and control frames (ping/pong/close). Reuse the
  HTTP/1.1 Upgrade handshake; record WS messages to history; replay via the repeater.
  Parsed path via `wsproto` (declared, skip-guarded).
- **T9.2 — HTTP/2 frame layer + minimal HPACK `[done, offline]`.** `fuzzlab/proxy/h2frames.py`
  — byte-exact encode/decode of the HTTP/2 frame types (DATA, HEADERS, SETTINGS,
  WINDOW_UPDATE, RST_STREAM, PING, GOAWAY, …), the connection preface, and
  `fuzzlab/proxy/hpack.py` — a minimal HPACK (static table + literal reps + int/string
  primitives) sufficient for arbitrary header bytes.
- **T9.3 — HTTP/2 raw-frame client `[done, offline builder; live on-host]`.**
  `fuzzlab/proxy/h2client.py` — assemble a request from frames (preface → SETTINGS →
  HEADERS → DATA), allowing **arbitrary/malformed** frames and header bytes for desync
  study. Frame assembly is offline-tested; the socket + TLS + ALPN override is on-host.
- **T9.4 — Parsed-path integration `[planned, mostly on-host]`.** Wire the `wsproto`/`h2`
  convenience path through the proxy so it intercepts/replays normal WS and HTTP/2
  (acceptance criteria); declared deps, skip-guarded offline, validated live.
- **T9.5 — Lab downgrade front-end `[done — config; live on-host]`.** Add the opt-in, default-off
  h2→h1 front-end (nginx) to `lab/compose.yaml` behind a profile, documented as the
  self-owned desync research target; recorded as a decision.
- **T9.6 — Exit `[on-host]`.** Intercept/replay WS + HTTP/2 through the proxy; send a
  byte-exact arbitrary HTTP/2 request; demonstrate an h2→h1 desync primitive against the
  front-end — lab-only.

## Component mapping

- **PROXY (11)** — `ws.py`, `h2frames.py`, `hpack.py`, `h2client.py`, and the parsed-path
  wiring; flows reuse the Phase 6 history + repeater.
- **LAB (1)** — the opt-in h2→h1 downgrade front-end (compose service + config).
- **CORE (2)** — migration 9 adds `flow.protocol` (decision 4).

## Out of scope for Phase 9 (deferred)

- A full, spec-complete HTTP/2 stack (flow control, priority, full dynamic-table HPACK) —
  only what the raw client and normal-traffic interception need.
- HTTP/3 / QUIC.
- Attacking anything outside the self-owned loopback lab (never).
- New detection/oracle mechanisms for protocol-specific bugs (later, if pursued).
