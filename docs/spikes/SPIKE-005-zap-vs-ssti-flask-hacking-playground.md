# Spike 005 — OWASP ZAP as a whole-app safety-net oracle

**Date:** 2026-09-21 · **Status: succeeded.** Fifth executed action in the
lab-generator program (numbered 005 per the coordinator's assignment — a
separate, concurrent lane covers Nuclei as Spike 004, not documented here).
Extends Spikes 001–003 (sqlmap, commix, SSTImap) to the last tool named in
`docs/LAB_SEED_AUTHORING_PLAYBOOK.md`'s "SSTImap/Nuclei/ZAP remain
unintegrated" line and `CR-LAB-0001`'s tool-mapping table: **"Whole-app
safety net → OWASP ZAP daemon mode / Automation Framework — Supplementary"**
(the same table also lists "ZAP active scan or Nuclei" as an alternative
confirmation path for reflected/stored XSS — this spike incidentally
validates that path too, see "Results" below).

## What was done

1. **Tool.** Downloaded the official `zaproxy/zaproxy` release tarball
   (`ZAP_2.16.1_Linux.tar.gz`, ~234 MB, via `github.com/.../releases/download/...`
   → `release-assets.githubusercontent.com`, both reachable through this
   environment's egress proxy — Docker Hub is blocked per Spikes 001/002/003,
   but this plain HTTPS download was not) into the session scratchpad, not
   this repository. ZAP itself is Apache-2.0; used purely as an external
   oracle tool, same posture as the other three (their oracle tools are
   GPL-3.0 and cite-only). Confirmed Java is present (`openjdk 21`, already
   in this environment) since ZAP is a JVM application, unlike the three
   Python-based tools.
2. **Target app.** Reused Spike 003's target (`filipkarc/ssti-flask-hacking-playground`,
   Apache-2.0, and the secure twin authored for that spike) rather than
   cloning a new app, per this task's explicit permission to reuse an
   existing spike target when that's simpler — a small app with a real
   vulnerable/secure pair was already validated and available, and ZAP's own
   active-scan rule set covers far more than just SSTI (see "Results"),
   so a single-route app was still enough to validate multiple classes at
   once (SSTI plus reflected XSS, plus a spread of header/info-disclosure
   findings common to almost any target).
3. **Ran ZAP in plain `-daemon` mode first**, to understand its headless
   startup behavior before committing to an invocation shape — this is where
   the real gotchas surfaced (see "Findings" below). Confirmed the REST API
   comes up and answers `JSON/core/view/version/` once started successfully.
4. **Switched to ZAP's own "Automation Framework"** (`zap.sh -cmd -autorun
   <plan.yaml>`) instead of a `-daemon` + REST-API-polling design, once it
   became clear this single-shot mode already gives this wrapper the same
   "one bounded subprocess call" shape the other three tools use — see
   "Findings" for why this was the right call, not just the easy one.
   Generated ZAP's own maximal automation-plan template
   (`zap.sh -cmd -autogenmax`) to read the real job/parameter schema instead
   of guessing at YAML shapes from documentation alone.
5. **Built a plan** with jobs `spider` → `passiveScan-wait` → `activeScan` →
   `report` (template `traditional-json-plus`, which writes a structured
   JSON alert list, exactly what a wrapper needs to parse programmatically
   — as opposed to `risk-confidence-html`, meant for a human reader). Ran it
   headlessly (`-cmd`, no `-daemon`, exits when the plan completes) against:
   - **Vulnerable endpoint** (`http://127.0.0.1:8089/?user=test`, Spike 003's
     SSTI app).
   - **Secure twin** (`http://127.0.0.1:8090/?user=test`, Spike 003's
     hand-authored secure variant).

## Results

- **Vulnerable endpoint:** ZAP's active scanner correctly raised a
  **"Server Side Template Injection"** alert at **High risk / High
  confidence** on the `user` parameter — ZAP has a dedicated SSTI active-scan
  rule, not just a generic anomaly detector. It also separately raised
  **"Cross Site Scripting (Reflected)"** (High risk / Medium confidence) on
  the same parameter — expected, since the vulnerable route concatenates
  `user` directly into the template *source* (Spike 003), so unescaped
  HTML/JS in the payload reaches the response exactly as unescaped template
  syntax does. **This incidentally validates `CR-LAB-0001`'s "ZAP active
  scan ... for reflected/stored XSS" alternative confirmation path** as well
  as the whole-app-safety-net mapping, using the same target and no extra
  work. Whole scan (spider + passive wait + active scan + report) completed
  in **under 14 seconds**.
- **Secure twin:** ZAP raised **no** SSTI or XSS alert — only routine,
  target-independent noise (missing `Content-Security-Policy` header,
  missing anti-clickjacking header, a version-disclosure header, missing
  `X-Content-Type-Options`, and an informational "sensitive info in URL"
  note about the `user` query parameter itself). All Medium risk or lower,
  none naming SSTI or XSS. Completed in under 14 seconds; **exit code 0**
  ("Automation plan succeeded!") vs. **exit code 1** on the vulnerable run
  (an `exitStatus` job with `errorLevel: High` was included for this manual
  validation only — see "Findings" for why the wrapper itself does not rely
  on this exit code for its verdict).

## Findings that matter for the wrapper implementation

- **ZAP is a whole-app scanner, not a per-parameter tool — the request/
  verdict shape has to be different from sqlmap/commix/SSTImap's, and that
  is intentional, not a shortcut.** There is no `-p`/marker-style "test only
  this parameter" concept: ZAP crawls everything reachable from a seed URL
  and attacks every URL/parameter it finds with its whole active-scan rule
  set at once. The wrapper's request type therefore has no
  `param_name`/`param_location` — it takes `target_url` (the whole app, or a
  parameterized URL to seed the crawl with) and an `alert_name_pattern` that
  plays the same "scope to the one thing under test" role the other three
  tools' parameter-scoping does, just at the *alert* level instead of the
  *parameter* level (see next finding for why this still matters).
- **A ZAP scan without an explicit alert-name scope is not a specific
  security assertion — it is genuinely "supplementary," matching
  `CR-LAB-0001`'s own word for it.** The secure twin still raised five
  distinct alert types (all header/info-disclosure noise, real on almost any
  target). A caller that treated "any ZAP alert at all" as "vulnerable" would
  flag *every* target, including secure ones, on noise unrelated to the
  class actually under test. **Design implication: the wrapper defaults to
  requiring an `alert_name_pattern`-scoped classification** (matching a
  cell's declared class, e.g. `r"Server Side Template Injection"` or
  `r"Cross Site Scripting"`), and offers the unscoped "any alert at/above a
  risk threshold" mode as an explicitly separate, clearly-labeled
  "whole-app safety-net" mode for genuinely supplementary spot-checks — not
  the default, and not something a caller should mistake for a per-class
  security assertion.
- **ZAP's own process exit code is not a reliable verdict signal for this
  wrapper's purposes, for the same reason sqlmap's/commix's exit codes
  weren't (the `CC-LAB-0016`/`CC-LAB-0017` lesson, generalized): it reflects
  ZAP's own opaque, unscoped policy** (an `exitStatus` job's `errorLevel`
  threshold applies to *any* alert on the whole app, exactly the
  unscoped-noise problem above), **not the one class the caller declared.**
  The wrapper never adds an `exitStatus` job to the generated plan and never
  inspects the subprocess return code for the verdict; it always parses the
  JSON report itself and classifies against the caller's own
  `alert_name_pattern`/`risk_threshold`, the same "the tool's own opaque
  exit status is not trusted; the tool's own detailed output is" discipline
  already applied to sqlmap and commix.
- **`-daemon` + REST-API-polling was seriously considered and rejected as
  unnecessary complexity for this wrapper's use case.** ZAP's REST API
  (`JSON/core/view/version/`, spider/ascan status endpoints, etc.) works
  fine once the daemon is up, and would support a more interactive workflow
  (submit a scan, poll for completion, cancel a hung one directly). But the
  Automation Framework's single `-cmd -autorun` invocation already: (a) runs
  to completion and exits on its own — no manual poll-until-done loop
  needed; (b) writes a structured, parseable report as its terminal action;
  (c) fits the exact same "one bounded subprocess call under an injected
  Runner, with a timeout and a bounded retry count" shape `oracle_wrapper`
  already established for the other three tools. Building a daemon-lifecycle
  manager (start, wait for the API to come up, submit jobs, poll queues,
  tear down, and handle a hang at *any* of those steps) would have
  duplicated most of what the Automation Framework already does atomically,
  for no benefit this wrapper's callers need. **If a future need arises for
  genuinely interactive control (e.g. incrementally feeding more URLs into a
  long-lived scan), the daemon+API path remains available — this decision is
  about what best serves a bounded, one-shot "is this cell vulnerable"
  check, not a general verdict on ZAP's API.**
- **Two non-fatal startup quirks, real "gotchas" worth documenting, not
  wrapper-blocking bugs:**
  1. **Firefox is not installed in this environment**, and ZAP logs an
     `ERROR ... Cannot find firefox binary in PATH` from its Client/AJAX
     Spider browser-integration extension on every startup. This is
     harmless for the traditional `spider`/`activeScan` jobs this wrapper
     uses (they don't need a browser) — confirmed by the scans above
     completing correctly despite the error — but a future caller adding a
     `spiderAjax` job (for a JS-heavy app) would need a headless browser
     available. Documented here, not worked around, since this wrapper
     doesn't use the AJAX spider.
  2. **ZAP's telemetry "call home" step fails with `403 Forbidden`** in this
     environment (blocked by the egress proxy, the same class of thing
     Spikes 001–003 already noted for Docker Hub) and logs an `ERROR`-level
     stack trace on every run. Also harmless — it's fire-and-forget
     telemetry, not on ZAP's critical path — but a naive "any ERROR-level
     line in stderr means a failed run" heuristic would misfire on every
     single invocation in this environment. **The wrapper does not treat any
     stderr content as a failure signal by itself** — only the actual
     report file's contents and the subprocess timeout/crash status matter,
     precisely to avoid this trap.
- **One genuine hang risk found and designed around, not hit in this spike:
  a stale bind on ZAP's own daemon port.** An unrelated leftover process
  (a `secure_app.py` Flask instance from Spike 003, still running from an
  earlier command in this same session) was squatting on port 8090 the first
  time `-daemon` mode was tried, causing ZAP to log `BindException: Address
  already in use` and terminate immediately — a fast, clean failure in this
  case, but the general risk (ZAP silently trying to talk to something else
  already on that port, or hanging waiting for a port that never frees) is
  real for a heavier, longer-lived daemon than the other three tools spawn.
  The Automation Framework's `-cmd -autorun` invocation still binds ZAP's
  own local proxy port for the crawl/scan machinery internally, so this
  wrapper still faces the same port-collision class — mitigated by giving
  each invocation its own fresh `-dir` (ZAP's home/state directory, isolated
  per call via `tempfile.mkdtemp()` unless the caller overrides it) so no
  invocation can inherit another's stale state, plus the same bounded
  subprocess timeout that would catch an actual hang regardless of cause
  (the same fail-closed principle Spike 002's CSRF-rotation finding already
  established for commix).
- **Startup and scan time is real but bounded and predictable for a small
  target: ~14 seconds total** for a fresh JVM start, extension
  initialization, a 1-URL spider, a 1-minute-capped passive-scan wait
  (which returned as soon as the passive scanner's queue actually drained,
  not after the full cap), and a 2-minute-capped active scan (same — it
  returned once the active scanner's queue drained, not after the cap) —
  meaningfully heavier than sqlmap/commix/SSTImap's sub-2-second runs
  against the same tiny app, but nowhere near the multi-minute range that
  would make the default `timeout_s` need to be unusually large. A larger,
  multi-page real target would take longer proportional to its crawl
  surface and rule-set breadth; this wrapper's `timeout_s`/`max_attempts`
  remain the caller's dial for that, same as the other three tools.

## What this does and doesn't prove

**Proves:** ZAP's Automation Framework, run completely headlessly via a
single bounded subprocess call, correctly confirms a real vulnerability
(SSTI, and incidentally reflected XSS) on a known-vulnerable endpoint and
correctly clears a known-secure twin, extending the validated tool-oracle
set to a fourth, structurally different (whole-app rather than
per-parameter) tool — completing this project's playbook's named
integration list (SSTImap done in `CC-LAB-0016`/`CC-LAB-0017`; Nuclei is a
separate, concurrent lane's Spike 004; ZAP is this spike). Also proves the
Automation Framework's single-shot mode is sufficient for this wrapper's
purposes without a daemon/polling design.

**Doesn't prove:** anything about ZAP's authenticated-scan support (context
`authentication`/`sessionManagement` blocks exist in the plan schema but
were not exercised here — this app has no login), its AJAX/client spider for
JS-heavy apps (not needed here, and firefox isn't installed in this
environment regardless), or its behavior against a much larger multi-page
app where crawl/scan time would be substantially longer. Nuclei remains a
separate lane's concern, not documented here.

## Cleanup

Everything from this spike lived under the session scratchpad
(`/tmp/.../scratchpad/zap/`, `.../zap_home/`), not this repository. Both
Flask dev server instances (reused from Spike 003) were stopped. Nothing
from ZAP's own distribution was copied into this repository.
