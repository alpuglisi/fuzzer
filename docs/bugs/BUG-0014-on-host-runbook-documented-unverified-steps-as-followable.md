# BUG-0014 — ON_HOST_RUNBOOK.md documented unbuilt/unverified steps as followable

- Date: 2026-09-21
- Status: fixed
- Severity: medium (operators could not follow the runbook; one error would silently
  invalidate experiments)

## Description
The initial `docs/ON_HOST_RUNBOOK.md` presented the on-host `[build+run]` activities
(Parts E, I, J, K — and the pre-rewrite Part E) as followable procedures, but they were:
- **incomplete** — they referenced last-mile code that did not exist ("the socket send is
  the last-mile", "wiring the live-sender adapter … is the small last-mile bit — I can
  add it", "tail MariaDB's error/general log"), so the documented exit could not be run;
- **factually wrong in places** — a second `auto_prepend_file` line (PHP's directive is
  single-valued, so it would have *silently disabled the WAF*); a per-request DB-fault
  signal via log-tailing (no per-request correlation); `./labctl.sh up --profile desync`
  (the flag was never forwarded); and a "duplicate `Content-Length`" exit using identical
  values (valid per RFC 7230, so it does not demonstrate rejection);
- **asserted but never executed** — commands and expected outputs were written from design
  intent, not from a run against the real host/provider.

## Where encountered
Across this session the operator repeatedly hit the gap: "Part E … is not detailed enough
to follow"; then Parts I/J/K needed their last-mile code built to be runnable at all; and
several concrete errors surfaced only when finally run on the host (see the bugs below).

## What it caused to fail
The operator could not follow the runbook to completion; multiple steps failed on-host; and
the double-`auto_prepend_file` instruction, if followed, would have disabled the lab WAF —
silently invalidating any filter-evasion experiment while appearing to work.

## What the bug was identified to be
Operational documentation authored **ahead of, and untested against, the implementation and
the real host** — "documentation as aspiration." The `[build+run]` tag conflated "needs
building" with "runnable" and there was no rule forcing a distinction between a
verified-runnable step and an unbuilt/aspirational one.

## Root cause analysis
Five Whys:
1. Why couldn't the runbook be followed? Steps referenced last-mile code that didn't exist
   and commands/outputs that had never been run.
2. Why were unbuilt steps written as followable? The `[build+run]` parts were authored from
   design intent, not from an executed run.
3. Why author from intent? The build sandbox has no lab (no container daemon / working
   `cryptography`), so on-host steps could not be executed here and were written
   speculatively.
4. Why speculative-as-followable, not clearly marked unverified? No rule distinguished
   "designed/aspirational" from "executed/verified"; `[build+run]` was treated as runnable.
5. Why did concrete errors persist (double auto_prepend, log-tailing, up --profile,
   identical-CL)? The steps were never dry-run against the real PHP/provider/HTTP stack, so
   platform- and protocol-specific mistakes weren't caught until the operator ran them.

**Root cause:** on-host operational documentation was written from design intent and never
executed/verified against the real host, and the format did not force a distinction between
verified-runnable steps and unbuilt/aspirational ones — so unverified, sometimes-incorrect
instructions were presented as followable.

## Recurrence review
Reviewed `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`. **Reoccurrence found — the same
root cause recurred across Parts E, I, J, K** and directly produced concrete defects that
were logged and fixed piecemeal:
- BUG-0009 (grey-box) — included the double-`auto_prepend_file` instruction that would
  disable the WAF (a runbook error).
- BUG-0012 — the duplicate-identical `Content-Length` exit premise (a runbook/self-test
  error).
- BUG-0013 — `up --profile desync` / relying on compose behaviors the provider lacks (a
  runbook instruction that never worked).
- The ERROR_LOG "no Compose provider" incident — same family (documented/assumed host
  behavior that didn't hold).
No prior PA targeted **documentation adequacy / verification**, so nothing prevented the
pattern from repeating part after part.

## Prior-preventive-action failure analysis
Prevention did not hold because each earlier instance was closed as an isolated fix (the
Part E rewrite; the double-`auto_prepend_file` correction in CC-LAB-0009; the `--profile`
fix in CC-LAB-0010/CC-LAB-0011; the conflicting-CL fix in CC-PROXY-0013) **without ever
distilling a rule about documentation being verified before it is presented as
followable**. This is the same failure mode PA-0014 named for provider/environment
incidents ("fixed in place, class left unguarded"): the systemic cause — runbook steps
written from intent, not from an executed+verified run — was never captured, so it recurred
in each new part. The individual fixes were necessary but not preventive.

## Corrective action
- Parts E, I, J, K were rebuilt into verified, one-command `[run]` flows backed by real,
  tested code and self-testing scripts that fail loud: `scripts/greybox_e2e.sh`,
  `scripts/proxy_e2e.sh`, `scripts/waf_evasion_e2e.sh`, `scripts/h2_desync_e2e.sh`
  (CC-FUZZ-0016, CC-PROXY-0010/0011/0012/0013, CC-MUT-0006, CC-LAB-0009/0010/0011).
- The concrete errors were fixed (BUG-0009, BUG-0012, BUG-0013) and the DB-fault design
  moved from log-tailing to a per-request side channel.
- The runbook Legend was corrected: the stale "Parts E, I, J, K are `[build+run]`" claim is
  gone; all parts are `[run]`, and a `[design]` tag now marks any not-yet-built/verified
  step that must **not** be written as a followable command sequence.

## Preventive action
PA-0015 (see `docs/PREVENTIVE_ACTIONS.md`): operational/runbook documentation must be
written from an **executed, verified run**, not from design intent. A step whose on-host
last-mile code is not yet built and self-tested is tagged `[design]` and must not be
presented as a followable command sequence; it becomes `[run]` only once its code exists
and a self-testing script (that fails loud) proves the exit. Commands and expected outputs
in a `[run]` step must be ones actually produced, and any step that changes host state or
sends traffic ships with such a script. When the build environment cannot execute the steps
(no lab/host), that limitation is stated and the steps stay `[design]` until validated on
the host.
