# BUG-0018 — oracle-spike break/fix findings not logged to ERROR_LOG until prompted

- Date: 2026-09-21
- Status: fixed
- Severity: low (no incorrect deliverable resulted — the findings were captured in
  `docs/spikes/SPIKE-001-*`/`SPIKE-002-*` and the playbook — but the project's own
  bookkeeping process was not followed without being asked, which is exactly the failure
  mode `CLAUDE.md` opens by warning against)

## Description
While validating the lab generator's planned tool-oracle architecture, two spikes
(`docs/spikes/SPIKE-001-sqlmap-vs-vapi.md`, `docs/spikes/SPIKE-002-commix-vs-dvwa.md`) each
hit a real "something broke and was worked around" event: sqlmap refused to test past a
401 response and had to be re-run with `--ignore-code`; commix hung on an ambient rotating
CSRF token and then on a runaway false-positive loop against an irrelevant field, and had to
be manually killed. Both were written up, in full, inside the spike documents and folded
into `docs/LAB_SEED_AUTHORING_PLAYBOOK.md` as design lessons — but neither was added to
`ERROR_LOG.md` at the time. They were only logged after the user explicitly asked, in a
following turn, to "record those both in a bug log."

## Where encountered
This session, across the turns that produced Spike 001, Spike 002, and their immediate
synthesis into playbook updates — i.e., in my own end-of-turn conduct, not in project code.

## What it caused to fail
`CLAUDE.md`'s own opening instruction: "Do not skip the bookkeeping in this file — it is
part of every change, not optional cleanup... it has been overlooked before." `ERROR_LOG.md`
states its scope plainly: "Add an entry whenever something breaks and is fixed." Both spike
findings meet that scope exactly (a tool behaved unexpectedly against a real target; a
workaround was applied). For one full turn, the canonical record of "something broke and
how it was handled" did not contain either event — they existed only as prose inside larger
narrative documents, discoverable only by reading those documents in full, and the gap was
closed only because the user caught it and asked.

## What the bug was identified to be
I treated the spike write-ups themselves as satisfying the project's bookkeeping
requirement for "something broke and was fixed," without separately adding the specific,
canonical entry the project's own process names for that (`ERROR_LOG.md`) — even though nothing
about the process exempts a finding just because it's also described in a longer document.

## Root cause analysis
Five Whys:
1. Why weren't the findings added to `ERROR_LOG.md` at the time they were found? I moved
   directly from "the spike surfaced this finding" to "fold the finding into the design
   docs (spike write-up + playbook)," without a separate step asking "does this also need
   the ERROR_LOG entry the project's process names for this."
2. Why did folding it into the spike/playbook feel sufficient? Earlier in this session, the
   established pattern for planning work was "write a new document, that document is the
   record" (research prompts, CR addenda). I extended that same pattern to the spike
   findings without checking it against the *specific* rule that applies once something has
   actually broken during execution, which is different from — and in addition to — writing
   up the finding in prose.
3. Why wasn't that distinction checked? I was running a fast "spike → synthesize findings
   into the next design artifact" loop across two consecutive spikes, and did not pause at
   the end of either one to run `CLAUDE.md`'s definition-of-done checklist explicitly; I
   had been doing that reflexively for larger, single design decisions (e.g. the CR
   addenda), but not for facts that surfaced as smaller, embedded observations inside a
   spike's narrative rather than announcing themselves as "a bug."
4. Why does how a finding is phrased change whether the checklist fires? I don't have a
   mechanical, wording-independent trigger for "does this turn's output describe something
   that broke" — I rely on the finding's presentation matching my own sense of what "a bug"
   looks like (a crash, a wrong result, a red test), and a finding framed as "a design
   lesson learned during a spike" doesn't pattern-match as saliently, even though
   `ERROR_LOG.md`'s actual scope ("anything that broke and was fixed") already covers it
   without qualification.
5. Why did that gap survive two consecutive spikes rather than being caught after the
   first? Nothing in my own process re-derives the bookkeeping checklist from the *content*
   of what just happened; it's re-derived from *recognizing the moment as bug-shaped*, and
   the same recognition failure repeated identically on Spike 002 because nothing about
   Spike 001 changed the underlying trigger mechanism.

**Root cause:** I rely on a finding's narrative framing/salience to decide whether the
`CLAUDE.md` bookkeeping checklist applies, rather than mechanically checking new findings
against each artifact's actual stated scope (here, `ERROR_LOG.md`'s "anything that broke and
was fixed") independent of how the finding is phrased or where else it's written up. This is
a gap in my own end-of-turn self-check, not a gap in the project's process design — the
process already named the right home for this; I did not consult it at the right moment —
and not a misunderstanding of scope, since the entries I added once prompted were correctly
scoped on the first attempt.

## Corrective action
Added both findings to `ERROR_LOG.md` (sqlmap 401/403 handling; commix ambient-defense/
field-sweep hang), each cross-referenced to its spike document and to the fix requirement
already tracked in `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`, plus the corresponding `CHANGELOG.md`
line (commit `2baf3a9`).

## Recurrence review
Reviewed `docs/PREVENTIVE_ACTIONS.md` and `docs/bugs/` for a prior occurrence of this bug or
the same root cause. The closest match, BUG-0014 ("`ON_HOST_RUNBOOK.md` documented unbuilt/
unverified steps as followable"), is also a documentation-process bug, but its root cause is
different in kind: BUG-0014 is about writing operational steps from *design intent* rather
than from an *executed, verified run* (a forward-looking accuracy failure — presenting
something unverified as though it were verified). This bug is about a *backward-looking
recall* failure — an event that already happened and was already correctly understood, but
was not mechanically checked against the bookkeeping artifact the project's process names
for it. No other `docs/bugs/` entry or `PA-NNNN` targets "a correctly-identified finding not
propagated to the specific log the process requires for it." **No prior occurrence found for
this specific root cause.**

Per PA-0002, swept this session's own conduct for other instances of the same class —
"something broke or required a workaround, fully described in a narrative document, but
never given its own `ERROR_LOG.md` entry":

- **Found and remediated (this commit):** during Spike 001, Docker Hub image pulls failed
  with a 403 policy denial (`production.cloudfront.docker.com`), which was worked around by
  running the target natively instead of in containers. This is exactly the same class —
  described fully in `SPIKE-001-sqlmap-vs-vapi.md`'s prose, never given its own `ERROR_LOG.md`
  line. Added as a new entry (below), since it's an environment constraint relevant beyond
  this one spike (Phase 3's containerized emitters will need to account for it).
- **Considered, not added:** Spike 001 also involved extensive PHP-8.4/Laravel vendor
  compatibility patching (nullable-parameter deprecations, a Carbon behavior change) to get
  a throwaway third-party test target running. This is fully captured in `SPIKE-001`'s own
  "friction" section with its own remediation and forward-looking implication (pin the
  `StackEnv` PHP version correctly, per Addendum D), and it's friction internal to one
  disposable spike environment rather than a fact about this project's own deliverables or
  a risk that recurs independently of that spike. Judged not to need a separate `ERROR_LOG`
  line; recorded here so the triage decision itself is visible rather than silently skipped.

## Preventive action
**PA-0019** (see `docs/PREVENTIVE_ACTIONS.md`): when a turn's work produces a finding that
matches an artifact's stated scope for what it records (e.g. `ERROR_LOG.md`'s "anything
that broke and was fixed"), add that artifact's entry in the same turn, checked against the
artifact's literal scope statement — never inferred from whether the finding *feels*
bug-shaped, and never treated as satisfied merely because the finding is also written up
elsewhere (a spike report, a design doc, a playbook). Before ending any turn that involved
running something and hitting unexpected behavior, explicitly re-read the relevant
bookkeeping artifacts' own scope lines (`ERROR_LOG.md`'s "add an entry whenever something
breaks and is fixed" chief among them) as a checklist item, not as background context
absorbed once at session start.
