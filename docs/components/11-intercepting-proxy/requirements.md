# Intercepting Proxy — Requirement Specification

Component code: **PROXY** · Status: `[built — offline stack + live upstream SocketSender, CONNECT/TLS termination, the fuzzlab proxy CLI, and the live h2c H2Transport; HTTPS interception + h2c send verified on-host]` (Phase 6 + Phase 9) · Last updated: 2026-09-21 · see CC-PROXY-0010, CC-PROXY-0011

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
  are intercepted/recorded). *(Amended CC-PROXY-0019, BUG-0085 / BUG-0086:)*
  - **Rules are validated when created.** A match / replace that is not latin-1, or a
    regex or scope path regex that doesn't compile, raises `ValueError` (the API
    answers 400).
  - **One connection's failure is contained:** `502` when nothing was written yet,
    otherwise close; the server keeps serving.
  - **Scope is decided once, on the authority.** A port-less rule matches any port,
    and a port-specific exclude always wins.
  - **Authorities are parsed by `proxy.authority`** (IPv6 `[v6]:port` included).
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

- **FR-PROXY-10 (CA leaf hygiene, CC-PROXY-0019, BUG-0079)** A leaf is minted only
  for a valid host: an IP literal, or an IDNA, lower-cased `[a-z0-9_-]` label
  hostname, at most 253 characters. The leaf file lives directly in `<ca_dir>/leaves/`
  (IPv6 as `ip6-<hex>`, with a resolved-path backstop). Every key (leaf and CA) is
  created 0600 with `O_NOFOLLOW`, and the CA directories are 0700. *(CC-PROXY-0020,
  BUG-0096:)*
  - **The CA key** is created with `O_EXCL` (`core.secretfile.create_secret`), so a
    trust root is never silently replaced. It is written key first, then the
    certificate (atomically).
  - **On load**, the key must match the certificate, and a half CA is refused. Both
    raise `CAError`, naming the fix.
  - **Leaf key and cert** are replaced atomically and in full
    (`core.secretfile.replace_secret`). `fuzzlab proxy` and `AsyncProxyServer` bind loopback only
  (`core.net.require_loopback`, BUG-0080).
- **FR-PROXY-11 (persisted-copy redaction, CC-PROXY-0019, BUG-0084)** Before history is
  written, these are redacted:
  - sensitively named headers;
  - query parameters of the request target and of `Location` / `Content-Location` /
    `Refresh`;
  - form, JSON (any depth) and multipart (non-file) request and response bodies. *(CC-PROXY-0020,
    BUG-0090:)* a sensitive JSON key's **whole value** is replaced, whatever its type
    (scalar, list, object or nested), and plural names are sensitive
    (`core.redaction`). *(CC-PROXY-0021, BUG-0100:)* it fails closed through the shared
    boundary (FR-CORE-25). Chunked or compressed bodies are decoded with bounds
    (gzip / deflate): a clean one is stored byte-exact; one with a secret, or
    undecodable with a redactable type, is replaced by the marker, with
    `Transfer-Encoding` / `Content-Encoding` dropped and `Content-Length` set. The
    former residual is closed. `HistoryWriter.flush` is all-or-nothing (a savepoint;
    it commits only a transaction it owns), and a record whose redaction fails is
    stored with omitted bodies (BUG-0106);
  - `flow.url` and the separately stored bodies.

  Sensitivity is by name token (`core.redaction.is_sensitive_name`). Benign messages
  stay byte-identical, and Content-Length follows a changed body. Chunked or compressed
  bodies are stored as received (a residual). Trade-off: a Repeater tab seeded from
  history carries placeholders, and `HistoryWriter(redact_secrets=False)` is the
  lab-local opt-out.
- **FR-PROXY-12 (bounded upstream reads, CC-PROXY-0021, BUG-0101)**
  - `recv_http_response` accumulates in one buffer, never re-copied.
  - **Bounds:** headers ≤ 64 KiB; the body ≤ `max_body` (default 64 MiB); an overall
    deadline (default the idle timeout × 4). Breaching any of them raises
    `UpstreamResponseError`, and the connection is answered with a 502.
  - **Configurable:** `SocketSender(max_body=, deadline=)` and `fuzzlab proxy
    --max-response-bytes / --response-deadline`. They cut off long-lived streams and
    very large downloads, by design.
  - **Off the event loop:** the engine runs the (stateless) sender with
    `asyncio.to_thread`, with at most min(32, CPUs + 4) concurrent upstream calls.
    History is recorded on the loop thread.
- **FR-PROXY-400** *(`--record`; `CC-PROXY-0400`, 2026-10-15).* Flow recording stays
  opt-in.
  - `--record` records into the resolved store (FR-CORE-400).
  - `--store PATH` records there, as before; with both, `--store` wins.
  - The `--authorized` and loopback gates run before any store work.
  - `--export-ca` comes before any store resolution.
  - An explicit `--store ""` is now a usage error. It used to mean "do not record".

## 4. Non-functional requirements
- **NFR-PROXY-byte-exact** The raw path preserves bytes exactly (no reserializing).
- **NFR-PROXY-safe** Scope-enforced and lab-only; the local CA never leaves the
  host; credentials/tokens redacted on write.
  - Enforced by: `proxy.scope`, `core.net.require_loopback`, `proxy.ca`, `proxy.history` redaction — `tests/test_proxy_server.py::test_engine_bypasses_out_of_scope_untouched`, `tests/test_proxy_rules_and_scope.py::test_scope_matches_authorities`, `tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`, `tests/test_loopback_listeners.py::test_the_proxy_server_itself_refuses_a_non_loopback_bind`, `tests/test_proxy_ca_hardening.py::test_the_real_ca_key_is_0600_from_creation`, `tests/test_proxy_ca_hardening.py::test_the_path_backstop_holds_if_validation_were_bypassed`, `tests/test_proxy_redaction.py::test_no_secret_reaches_any_persisted_copy`, `tests/test_proxy_history.py::test_secrets_redacted_on_write`
  - Not yet enforced: `Repeater.send` has no scope check; out-of-scope traffic is forwarded to any upstream (scope governs interception and recording only). (BUG-0111 sweep.)
- **NFR-PROXY-nonblocking** History writes are batched and must not stall the data
  path.
- **NFR-PROXY-optional** Nothing in the core pipeline requires the proxy to run.
- **NFR-PROXY-dry-run** `fuzzlab proxy` accepts `--dry-run`: plans and prints the
  exact argv/command it would run and sends nothing (no listener is started, no
  upstream traffic), for headless use outside the web UI. Distinct from
  `--export-ca` (which also sends no traffic but actually writes the CA file);
  `--dry-run` takes priority and performs neither action. Reuses the web
  launcher's dry-run plan/report logic (`fuzzlab/web/commandspec.py` +
  `fuzzlab/web/runner.py`) via the shared `fuzzlab/cli_dryrun.py` helper.
  - Enforced by: `cli_dryrun` — `tests/test_cli_dry_run.py::test_proxy_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_proxy_dry_run_reports_plan_and_sends_nothing`
  - Not yet enforced (exact argv display; BUG-0400, open, the UI lane's fix): the shared display `web/runner.build_flags` mis-serialises `nargs='*'` lists, a bare `const=""` flag and dash-leading values, so for those the printed plan is not the exact argv. Pinned by strict xfails in `tests/test_cli_argv_roundtrip.py`.
  - Not yet enforced: `--dry-run` taking priority over `--export-ca` holds by branch order but is untested. (BUG-0111 sweep.)

## 5. Interfaces and data contracts
Writes `flow` rows (+ raw bytes) to the store, read by the anomaly detector, UI,
and analysis. Uses the session manager as an addon. Shares `core/` config, budget,
and logging. *(Note, U3/CC-PROXY-0018, 2026-09-22: the web UI's Proxy section was
re-laid on a shared message-editor component and resizable panes — see
`docs/components/12-diagnostics-and-ui/requirements.md`'s FR-UI-9 — purely a
client-side presentation change against these same unchanged `/api/proxy/*`
routes and `flow`/repeater-tab contracts; no interface or data-contract change
here.)*

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
