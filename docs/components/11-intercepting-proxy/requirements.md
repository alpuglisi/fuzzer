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
  created 0600 with `O_NOFOLLOW` (`core.secretfile.write_secret`), and the CA
  directories are 0700. `fuzzlab proxy` and `AsyncProxyServer` bind loopback only
  (`core.net.require_loopback`, BUG-0080).
- **FR-PROXY-11 (persisted-copy redaction, CC-PROXY-0019, BUG-0084)** Before history is
  written, these are redacted:
  - sensitively named headers;
  - query parameters of the request target and of `Location` / `Content-Location` /
    `Refresh`;
  - form, JSON (any depth) and multipart (non-file) request and response bodies;
  - `flow.url` and the separately stored bodies.

  Sensitivity is by name token (`core.redaction.is_sensitive_name`). Benign messages
  stay byte-identical, and Content-Length follows a changed body. Chunked or compressed
  bodies are stored as received (a residual). Trade-off: a Repeater tab seeded from
  history carries placeholders, and `HistoryWriter(redact_secrets=False)` is the
  lab-local opt-out.
## 4. Non-functional requirements
- **NFR-PROXY-byte-exact** The raw path preserves bytes exactly (no reserializing).
- **NFR-PROXY-safe** Scope-enforced and lab-only; the local CA never leaves the
  host; credentials/tokens redacted on write.
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
