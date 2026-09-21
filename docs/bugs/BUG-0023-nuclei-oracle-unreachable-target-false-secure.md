# BUG-0023 — Nuclei oracle would misclassify an unreachable target as `confirmed_secure`

- Date: 2026-09-21
- Status: fixed (caught during development, before the naive version was ever committed or shipped)
- Severity: high (security-relevant: a fail-open behavior in a security oracle)

## Description

While validating `nuclei` as an independent tool-oracle for the lab generator
(Spike 004, `docs/spikes/SPIKE-004-nuclei-vs-dvwa.md`), the first draft
classification logic for `fuzzlab.labgen.nuclei_oracle` treated "the tool
exited 0 and produced zero JSONL matches" as `confirmed_secure`. Testing that
draft against a deliberately unreachable target (a closed port, simulating a
misconfigured or torn-down secure-twin server) showed `nuclei` **also** exits
`0` with zero matches when it never actually reached the target at all —
indistinguishable, on stdout and exit code alone, from a target that was
reached and found not vulnerable.

## Where encountered

`fuzzlab/labgen/nuclei_oracle.py`, during interactive spike testing (not yet
committed) against `http://127.0.0.1:9999` (nothing listening) as a stand-in
for "secure target unreachable for an unrelated reason" — see Spike 004.

## What it caused to fail

Nothing shipped or ran in production against this defect — it was caught
during the module's own development, before any test or real invocation
depended on the naive classifier. Had it shipped, it would have caused: any
generator-build-time oracle check against a secure twin that failed to start,
had the wrong port, or was network-unreachable for any reason would be
recorded as `confirmed_secure` — a false-negative security verdict — silently
poisoning the corpus's ground truth (exactly the failure mode `oracle_wrapper`
and `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`'s fail-closed contract exist to
prevent, per `CLAUDE.md`'s safety posture).

## What the bug was identified to be

`nuclei`'s own health-check subsystem detects a target that refuses every
connection, prints `Skipped <host> from target list as found unresponsive
permanently` to **stderr** (only when `-silent` is not passed), and then
still completes the scan with `No results found` and exit code `0`. The
naive classifier looked only at exit code + stdout JSONL, so it had no way to
distinguish "reached the target, template did not match" from "never reached
the target at all."

## Root cause analysis

Five whys:

1. Why did an unreachable target get classified `confirmed_secure`? Because
   the classifier's only negative-evidence check was "zero JSONL matches +
   exit code 0."
2. Why was that the only check? Because `nuclei`, unlike `sqlmap`/`commix`,
   has no dedicated "not vulnerable" textual marker to also look for — a
   clean scan and an unreachable target both print *nothing* to stdout.
3. Why wasn't the possibility of "the tool never actually exercised the
   target" considered up front? Because the design was drafted by analogy to
   `oracle_wrapper`'s sqlmap/commix classifier, which distinguishes vulnerable
   vs. secure via two *independent* positive markers (Spike 001/002) — that
   design has no "did the tool even connect" gap to close, since sqlmap/commix
   each print an explicit secure marker only after actually probing the
   target. Nuclei's absence of any secure-side marker was a structurally new
   failure mode this project's process for validating an oracle
   (`docs/LAB_SEED_AUTHORING_PLAYBOOK.md` step 7, "run it against both
   twins") hadn't been exercised against yet for a match-based (not
   marker-based) tool.
4. Why did testing catch it before it shipped? Because Spike 004's own
   validation procedure (per the playbook: confirm manually first, then run
   the tool against both a real vulnerable and a real secure case) included
   a deliberate "what if the secure side is actually broken" check as a third
   case beyond the two the playbook literally asks for, precisely because the
   two-case check alone cannot surface this gap (both a real secure server
   and a dead server produce identical tool output under the naive
   classifier).
5. Why wasn't a "target unreachable" case already a standard third case in
   the playbook's oracle-validation step? Because `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`
   step 7 and both prior spikes' methodology only ever exercised "confirm
   against the vulnerable variant" and "confirm against the secure twin" —
   neither considered "confirm the tool can tell 'secure' apart from
   'un-testable'" as a distinct required case, because sqlmap/commix's marker
   design made that distinction implicit (an inconclusive sqlmap/commix run
   produces neither marker, which the existing `_classify` already treats as
   `inconclusive`, never `confirmed_secure`).

**Root cause:** the classification design assumed every independent
tool-oracle signals "confirmed secure" through some positive evidence of
having actually run against the target (a marker, in sqlmap/commix's case).
Nuclei's match-only output model has no such positive evidence for the
secure path — "ran cleanly and found nothing" and "never ran at all" are both
silence — so a classifier for a match-based tool must independently verify
the tool's own diagnostic stream for evidence that it reached the target, not
assume "no positive match + exit 0" already implies that.

## Corrective action

`_classify()` in `fuzzlab/labgen/nuclei_oracle.py` checks `run.stderr` against
`_HOST_UNREACHABLE_RE` (matching nuclei's own "unresponsive permanently" /
"could not connect" / "connection refused" / "no such host" / "context
deadline exceeded" / "no address associated" phrasings) **before** treating a
zero-match, exit-0 run as `confirmed_secure`, downgrading it to
`inconclusive` instead. `_build_nuclei_argv()` deliberately never passes
`-silent`, since that flag suppresses the exact stderr line this check
depends on. Verified against a real unreachable target
(`http://127.0.0.1:9999`, nothing listening) in the same interactive session
that found the bug: the corrected wrapper returns `inconclusive` with a
reason naming the unreachable-host signal, not `confirmed_secure`. See
`docs/spikes/SPIKE-004-nuclei-vs-dvwa.md` for the full three-case validation
(vulnerable / secure / unreachable) and `CC-LAB-0028` (`docs/components/01-target-lab/change-control.md`) for the
change record.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence
of the same bug, or a different bug with the same root cause. No identical
prior `BUG-NNNN` found (this is the first tool-oracle wrapper built against a
match-only, no-secure-marker tool). The closest prior art, related but not
identical in root cause:

- **PA-0007** (`BUG-0008`): "never infer success from the mere presence of an
  ambient signal; require a positive differential signal." Same *family* of
  mistake (treating an always-possible negative/absent signal as proof of the
  specific condition being tested) but a different mechanism and layer (HTTP
  auth-state inference vs. subprocess-output classification for an
  independent CLI tool) — not the same root cause, so no prior-PA-failure
  analysis is required per `docs/bugs/README.md` step 8's "same bug or a
  different bug with the same root cause" test. Recorded here as related
  prior art rather than a recurrence.
- `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`'s existing "ambient defenses" lesson
  (from Spikes 001/002: sqlmap's `--ignore-code`, commix's CSRF-token
  staleness) is the same *spirit* — a tool-oracle under-testing or
  mis-testing for a reason unrelated to the class under test — but was never
  turned into a `PA-NNNN` rule, only prose in the playbook. That gap is
  itself worth closing (see preventive action below), but it is a documentation
  gap, not a prior bug repeating, so again not a step-8 "prior-preventive-action
  failure" in the strict sense.

*(Numbered `BUG-0023`/`PA-0025`/`CC-LAB-0028` rather than this task's own
worktree numbers `BUG-0018`/`PA-0019`/`CC-LAB-0017` at merge time — this
lane's worktree diverged onto a stale, unrelated branch lineage before
starting (an environment quirk, self-diagnosed and recovered from via a
documented sync commit) and was based on a point predating several later
Phase 0 merges, all of which had already independently claimed those same
numbers for unrelated bugs/changes by the time this branch was reconciled
into trunk. No content changed; purely a numbering fix, applied consistently
across this doc, `ERROR_LOG.md`, `docs/PREVENTIVE_ACTIONS.md`,
`docs/spikes/SPIKE-004-nuclei-vs-dvwa.md`, and the two Nuclei test files'
in-code references.)*

## Preventive action

**PA-0025** — added to `docs/PREVENTIVE_ACTIONS.md`: a tool-oracle wrapper
that classifies a "no positive finding" result as `confirmed_secure` must
independently verify, from the tool's own diagnostic output, that the tool
actually reached and exercised the target — never infer "secure" purely from
the absence of a positive match plus a clean exit code, since a
match-only-output tool cannot otherwise distinguish "ran cleanly, found
nothing" from "never ran." Concretely: run the tool at a verbosity that
surfaces its own connectivity/health diagnostics (never suppress them for a
"cleaner" wrapper), and check for them before returning `confirmed_secure`.
This generalizes the Addendum-E/Spike-001/002 "ambient defenses" lesson
(previously prose-only in `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`) into an
enforceable rule, and extends PA-0007's fail-closed doctrine from
authentication-signal inference to tool-oracle-output inference generally.
**Sweep performed (PA-0002):** `fuzzlab.labgen.oracle_wrapper` (sqlmap/commix)
was re-read for the same gap. It does not have it: both `sqlmap` and `commix`
print an explicit textual marker (`does not seem to be injectable`) only
after actually probing the declared parameter, so a run that never reached
the target produces neither marker and is already classified `inconclusive`
by the existing `_classify()` — the marker-based design was already immune to
this bug class by construction, not by an explicit unreachable-host check.
No change needed there; noted in `oracle_wrapper.py`'s neighbourhood for the
next contributor via this bug report's cross-reference, per PA-0002's "or
record why not."
