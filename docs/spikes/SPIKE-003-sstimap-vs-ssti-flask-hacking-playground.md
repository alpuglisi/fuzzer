# Spike 003 — SSTImap as an independent oracle against a Flask/Jinja2 SSTI app

**Date:** 2026-09-21 · **Status: succeeded.** Third executed action in the
lab-generator program, extending Spike 001 (sqlmap) and Spike 002 (commix) to
the third independent-tool-oracle-validated class named in
`docs/LAB_SEED_AUTHORING_PLAYBOOK.md`'s "SSTImap/Nuclei/ZAP remain
unintegrated" line and `CR-LAB-0001`'s tool-mapping table ("SSTI / code
injection → SSTImap (not tplmap — self-declared unmaintained)").

## What was done

1. **Tool.** Cloned `vladko312/SSTImap` (a maintained fork/continuation of
   `epinna/tplmap`, per the same `CR-LAB-0001` guidance that named the
   original `tplmap` unmaintained) into the session scratchpad — not into
   this repository. **License confirmed by reading `LICENSE.md` directly:
   GPL-3.0**, the same posture as sqlmap (Spike 001) and commix (Spike 002):
   used purely as an external oracle tool, cite-only, nothing vendored.
2. **Target app.** Cloned `filipkarc/ssti-flask-hacking-playground` — a small,
   dedicated, single-route Flask/Jinja2 SSTI demo app. **License confirmed by
   reading `LICENSE.txt` directly: Apache-2.0.** Ran it natively (`python3
   __init__.py`, stdlib Flask dev server), loopback-only (`127.0.0.1:8089`),
   same rationale as Spikes 001/002 (this environment's egress policy blocks
   Docker Hub pulls, and the app needs nothing beyond `pip install flask`
   once a Debian-packaged `blinker` conflict was worked around with
   `--ignore-installed`). Used purely as a live test target; nothing copied
   into this repository.
3. **Vulnerable code, read directly:** the app's single route
   (`__init__.py::home`) takes `?user=...` and does
   `template = template + "<h1>Hi {}</h1>...".format(user)` **before**
   calling `render_template_string(template)` — the classic SSTI shape
   (user input concatenated into the template *source*, not passed as a
   template *variable*, so Jinja2 compiles and executes whatever the
   attacker supplies).
4. **No secure twin ships with the app** (it is a single-vulnerability demo,
   unlike vAPI/DVWA which had one built in) — the same situation Spike 002
   handled by editing a copy of the vulnerable file. Authored a minimal
   secure twin, `secure_app.py` (kept in the session scratchpad, not
   committed): identical route/shape/response text, differing **only** in
   the one transform that matters — `user` is passed as a Jinja2 **context
   variable** (`render_template_string(template, user=user)`) and referenced
   in the template via `{{ user }}`, instead of being `.format()`-ed into
   the template source before compilation. This is exactly this project's
   own minimal-pair convention (vulnerable and secure twins differ only in
   the transform) applied to a case the demo app didn't already provide.
5. **Confirmed both endpoints manually with curl before ever touching the
   tool** (mirroring Spikes 001/002's discipline):
   - Vulnerable: `?user={{7*7}}` → page renders `Hi 49` (Jinja2 evaluated the
     expression server-side).
   - Secure twin: `?user={{7*7}}` → page renders `Hi {{7*7}}` literally (the
     value is escaped/output as data, never compiled as template source).
6. **Ran `sstimap.py` headlessly** (no `-i`/`--interactive` flag — SSTImap's
   default mode, with only `-u` given, is already a non-interactive, one-shot
   detect-and-report run; there is no separate "batch" flag to pass) against
   both, with the injection point marked explicitly in the URL
   (`-u "http://127.0.0.1:8089/?user=*"`) rather than left to SSTImap's
   default un-marked, multi-location (`-P` default `QBHC`) sweep — see
   "Findings" below for why this matters for the wrapper design even though
   it did not cause a runaway in this app.

## Results

- **Vulnerable endpoint:** SSTImap correctly identified the `user` query
  parameter as injectable via the **Jinja2** engine, rendered technique, in
  well under a second, with full exploitation capabilities reported (shell
  command execution, file read/write, code evaluation) — no human confirming
  or writing anything, and no interactive prompts encountered.
- **Secure twin:** SSTImap correctly reported **"Tested parameters appear to
  be not injectable"** after exhausting every engine/technique combination it
  tries (Java, PHP, Python, JavaScript, Ruby, and several generic engines,
  in addition to Jinja2) — a clean negative, no false positive, completing in
  under 2 seconds.

## Findings that matter for the wrapper implementation

- **SSTImap has no `-p`-style "test only this parameter" flag** (unlike
  sqlmap and commix). Scoping instead works through **the marker mechanism**:
  placing SSTImap's marker character (`*` by default, or a custom one via
  `-M`) directly at the parameter's value in the URL/`--data`/`--header`/
  `--cookie`, combined with `-P` restricted to the one location category
  (`Q`/`B`/`H`/`C`) matching where the parameter actually lives. Verified
  directly: `-u ".../?user=*&submit=Login"` tested only `user` and never
  touched `submit`, in under half a second — **the equivalent scoping
  mechanism to sqlmap's/commix's `-p`, just spelled differently** (a marker
  placed at the exact injection site, rather than a parameter name passed
  separately). **Design implication: the wrapper must build the target
  URL/data/header/cookie with the marker substituted at the declared
  parameter's value**, not just pass the parameter's name, or SSTImap has
  nothing telling it where the one parameter under test actually is.
- **SSTImap's own reflection/stability pre-check already resists a naive
  field sweep, unlike commix.** Run with no marker at all and every query
  parameter present with a real (non-marker) value, SSTImap still tested
  only the one parameter (`user`) that actually reflects into the response
  and skipped the static `submit` field — it did **not** reproduce Spike
  002's commix runaway-on-an-irrelevant-static-field problem, in this app.
  This is a real, useful negative finding, not an assumption: **do not treat
  it as proof the same failure mode is impossible in general** (a
  differently-shaped app, a slower reflection check, or a field whose value
  *does* vary per-request could still trigger a sweep) — the wrapper scopes
  explicitly via the marker mechanism above regardless, both for correctness
  and so this project's oracle wrapper does not depend on every future
  target app happening to have SSTImap's specific heuristic save it.
- **No sqlmap-style 401/403 auth-abort behavior found.** Read `core/
  matcher.py` directly: SSTImap uses the HTTP status code only as one of
  several signals it compares for the boolean-error-based-blind technique
  (`--bool-match`'s default list includes `code` alongside header/cookie
  counts, body length, timing, etc.) — there is no special-cased "treat
  401/403 as an unrecoverable auth failure and abort" logic anywhere in the
  codebase, and no `--ignore-code`-equivalent flag exists (there is nothing
  to ignore). **This is a genuine negative finding, checked by reading the
  source, not merely "didn't happen to hit it"**: SSTImap does not need the
  Spike-001-style status-code workaround, so the wrapper's SSTI request type
  has no `secure_status_codes`/`--ignore-code`-equivalent field, unlike the
  SQLi request type.
- **No CSRF/session-rotation reproduction was possible with this app** (it
  has none) — this spike does not confirm or refute whether a rotating
  token would defeat SSTImap the way it defeated commix in Spike 002. The
  wrapper's SSTI request type still gets the same `refresh_session` callback
  and bounded `timeout_s` × `max_attempts` safety valve as the SQLi/command-
  injection request types, for architectural consistency and defense in
  depth, not because this spike proved it necessary for SSTImap specifically.
- **No hang, hard timeout, or hard-to-diagnose failure of any kind was
  observed** in either direction, at any point. Both runs completed in
  under two seconds. Nothing here needed working around, so nothing was
  logged to `ERROR_LOG.md` for this spike itself (contrast Spikes 001/002,
  which each surfaced a real workaround-worthy defect in the *approach*
  being validated).
- **Environment friction, not a tool finding:** the target app's pinned
  `requirements.txt` (`Flask==2.2.2`, `MarkupSafe==2.1.1`, …) failed to
  build from source in this environment (`MarkupSafe`'s C extension wheel
  build failed under the installed toolchain). Installed unpinned `flask`
  instead (`pip install --ignore-installed flask`, to work around a
  Debian-packaged `blinker` `RECORD`-file conflict) — the app's one route
  is trivial enough that the exact pinned versions didn't matter for this
  spike's purpose. Not a repo change; nothing in this project depends on
  those pins.

## What this does and doesn't prove

**Proves:** SSTImap, like sqlmap (Spike 001) and commix (Spike 002), works as
an independent oracle for its class — correct positive, correct negative,
zero original exploit code written by anyone — extending the validated set
of classes from {SQL injection, OS command injection} to {SQL injection, OS
command injection, server-side template injection}. Also proves the wrapper's
existing bounded-timeout/max-attempts/refresh-session design (built for
sqlmap/commix) needs no new architecture to accommodate a third tool — only a
class-appropriate way to build the scoped invocation (the marker mechanism
above).

**Doesn't prove:** anything about Nuclei or ZAP (still unintegrated per the
playbook), anything about SSTImap against a non-Jinja2 engine (Twig, Smarty,
Freemarker, …), and — since this app has no auth/CSRF layer — nothing about
how SSTImap behaves against a target with an ambient defense unrelated to the
SSTI class under test (the concern Spike 002 raised for commix). The three
gap classes (IDOR/BOLA, business logic, race conditions) remain out of scope
per the existing D20 decision.

## Cleanup

Everything from this spike lived under the session scratchpad
(`/tmp/.../scratchpad/{sstimap_check,ssti_playground,ssti_secure_twin}/`),
not this repository. Both Flask dev server instances were stopped. Nothing
from SSTImap's or the playground app's source was copied into this
repository; the secure twin (`secure_app.py`) was authored fresh for this
spike and also lives only in the scratchpad.
