# REPORT-0001 — Trend analysis across the full bug log (BUG-0001…BUG-0028)

- Date: 2026-09-22
- Type: retrospective / cross-bug trend investigation (not a single-code-defect bug report)
- Scope: every document in `docs/bugs/` as of this date (28 investigations), cross-referenced
  against every rule in `docs/PREVENTIVE_ACTIONS.md` (PA-0001…PA-0031)
- Author note: this report is the required artifact for a project-wide retrospective; it is
  not itself a `BUG-NNNN` (no single new code defect was found by exercising code — the
  investigation is over the *existing, already-fixed* corpus, looking for a repeating cause
  spanning independent bugs). Where the investigation below identifies a trend not fully
  covered by any existing rule, new preventive actions are added to `docs/PREVENTIVE_ACTIONS.md`
  directly, following the precedent set by PA-0031 (a preventive action can originate from a
  process/retrospective finding, not only from a single `BUG-NNNN`).

## Why this report exists

`CLAUDE.md`'s bug workflow requires each individual investigation to check for a *prior*
occurrence of the same bug or root cause (step 7, "recurrence review") before deciding that
bug's own preventive action. That check is local: each bug report only looks backward at the
bugs before it. Nothing in the existing process periodically looks at the *whole* corpus at
once and asks whether one underlying cause is responsible for a disproportionate share of all
bugs, independent of which individual PA each one produced. This report is that pass — a
topical read of each bug summary would not surface it; the trend below is only visible once
every root-cause paragraph, every corrective action, and every recurrence-review section is
read in full and cross-tabulated.

## Method

1. Read all 28 `docs/bugs/BUG-NNNN-*.md` documents in full (not summaries), plus
   `docs/bugs/README.md` and the complete `docs/PREVENTIVE_ACTIONS.md` (PA-0001…PA-0031).
2. Extracted, per bug: the stated root cause, the corrective action, any tool/library/runtime
   named as implicated, the activity being conducted when the bug surfaced (writing a test,
   running an on-host script, extending an adapter, authoring documentation, etc.), and whether
   the bug's own recurrence-review section names it as a repeat of a prior bug or root cause.
3. Grouped bugs by root-cause *shape* (not by component or by which PA number they produced),
   allowing a bug to belong to more than one shape where its own RCA names more than one
   mechanism (several bugs, e.g. BUG-0009, are explicitly multi-defect).
4. Counted "on-host / this session" occurrence explicitly, since the project's own bug docs
   repeatedly self-diagnose "the sandbox cannot execute this, so it was never caught until the
   host" as a contributing factor — a first-class trend in its own right, not just background
   color.
5. Cross-checked each recurrence chain (a bug whose own doc names a prior `BUG-NNNN`/`PA-NNNN`
   as the same root-cause class) against the *stated reason prevention failed*, since several
   of those reasons are themselves the same shape, independent of the underlying code defect.

## Trend table (root-cause shape → occurrence count → bugs)

| # | Shape | Count | Bugs |
|---|---|---|---|
| 1 | **A test/fixture/self-test/harness does not reproduce what the real upstream, environment, or library actually produces**, so a real defect is invisible until a live/on-host/whole-corpus run exercises it | **14 / 28 (50%)** | BUG-0005, 0006, 0008, 0010, 0011, 0012, 0014, 0015, 0016, 0021, 0022, 0025, 0027, 0028 |
| 2 | **The defect was structurally unobservable in the build sandbox** (no container daemon, no working `cryptography` build, no podman, no lab) and surfaced only on the real host | 8 / 28 (29%) | BUG-0005, 0009, 0010, 0011, 0013, 0014, 0015, 0017 |
| 3 | **A cross-cutting convention (a stored/derived value, or a self-heal routine) was implemented at one write/call site instead of one shared function every participant goes through** | 4 / 28 (14%) | BUG-0003, 0007, 0017, 0021 |
| 4 | **A check inferred "success"/"secure"/"equivalent" from the mere *absence* of negative evidence, instead of requiring a positive, differential proof** (fail-open) | 5 / 28 (18%) | BUG-0008, 0009 (pcov "loads≠works" facet), 0023, 0026, 0027 |
| 5 | **A third-party library/API silently mishandled an out-of-range or wrong-granularity input instead of raising**, and the project's own adapter did not enumerate every precondition the library assumes | 2 / 28 (7%) | BUG-0009, 0024 |
| 6 | **A prior preventive action existed but did not prevent recurrence because it was worded around the triggering *symptom* rather than the underlying *mechanism*, so a sibling path/case with a different trigger slipped through** | 6 distinct chains touching 9 bugs (32%) | BUG-0001→0002, BUG-0001→0025, BUG-0003→0007, BUG-0009→0024, BUG-0013→0017, BUG-0018→0019 |
| 7 | **My own end-of-turn bookkeeping/self-check, not a code defect** | 3 / 28 (11%) | BUG-0018, 0019, 0020 |

(Rows are not mutually exclusive — e.g. BUG-0021 is both shape 1 and shape 3; BUG-0009 is
shapes 1, 2, 4, and 5 at once, being a three-defect investigation.)

## Libraries / tools / runtimes named as implicated

No single external library or tool recurs as the root-cause *carrier* across more than two
bugs (`podman-compose`: BUG-0013, BUG-0017 — already a direct, documented recurrence chain;
crypto tooling appears twice but for different reasons — PyCrypto/`keyrings.alt` in BUG-0005,
X.509 extension omission in BUG-0010). This project's bugs are **not** concentrated in one
troublesome dependency; the concentration is in the two *shapes* above (rows 1 and 2), which
recur across unrelated libraries, components, and phases: `sqlite3` (BUG-0021), `asyncio`
(BUG-0011), `pcov`/PHP extensions (BUG-0009), `covertable` (BUG-0024), `sqlglot` (BUG-0026),
`urllib.request` + Eloquent ORM defaults (BUG-0028), `nuclei` (BUG-0023), MariaDB auth
(BUG-0004), `h11`/HTTP framing (BUG-0012), X.509/TLS (BUG-0010), shell `set -e` semantics
(BUG-0015). Each is a different technology; the recurring element is never the library — it is
**how its real behavior was (or wasn't) verified** before being relied on.

## Activities being conducted when the bug surfaced

- **Running an on-host / live script or runbook step** (the first real execution against the
  actual lab/host/provider): BUG-0007, 0009, 0010, 0011, 0012, 0013, 0014, 0015, 0016, 0017 —
  **10 / 28 (36%)**. This is the single largest "activity" bucket by far, and it is the
  concrete mechanism behind trend-table row 2: the sandbox this project is largely built in
  cannot run the lab, so an entire class of defects is deferred to the first on-host run,
  arriving in a cluster once on-host work began (BUG-0007 through BUG-0017 are contiguous).
- **Writing or extending a test/fixture for a pipeline, adapter, or conformance harness**:
  BUG-0001, 0002, 0006, 0008, 0021, 0022, 0024, 0025, 0026, 0027, 0028 — 11 / 28 (39%).
- **Authoring or correcting operational documentation** (the runbook): BUG-0012 (self-test text
  diverged from validated test), BUG-0014 (the umbrella bug for this activity).
- **Fixing my own end-of-turn process** (bookkeeping, a hook): BUG-0018, 0019, 0020.

Rows 1/2 of the trend table and the "on-host" and "test/fixture" activity buckets are largely
the same population viewed from two angles: a test/fixture/harness was built against an
*assumed* shape of the real world, and the assumption broke either as soon as a live run
happened (on-host) or as soon as coverage was extended to a case the assumption hadn't been
checked against (a wider manifest, a wider registry, a new endpoint category).

## The dominant trend, stated plainly

**Half of every bug this project has recorded (14/28) has the same root-cause shape: a test,
fixture, self-test, or harness stood in for the real thing — a real upstream producer, a real
library call, a real server, a real on-host environment — without being checked against what
that real thing actually does, and the gap was invisible until something exercised the real
path.** This is not a new observation invented by this report; it is *already* the subject of
more individual preventive actions than any other cause in this project's history — PA-0006,
PA-0008, PA-0009 (the "loads ≠ works" clause), PA-0010, PA-0011, PA-0013, PA-0015, PA-0016,
PA-0017, PA-0024, PA-0026, PA-0027, PA-0029, and PA-0030 are *all*, independently, one
mechanism-specific instance of this same shape (a fixture that hand-sets a field the real
pipeline never sets; a cert-verifying test the sandbox skip-guards away; a self-test that
diverges from the validated construction; a metric proxy that isn't the capability; a registry
widening not re-run against the whole existing corpus; a client/ORM default nobody enumerated).
Fourteen rules is not fourteen *different* lessons — it is the same lesson landing fourteen
times in fourteen different subsystems, each time narrow enough (correctly, for that instance)
that it didn't generalize to the next one.

The second-largest trend (row 6: a **prior PA existed and still didn't prevent recurrence**,
9 bugs across 6 chains) is a trend *about the project's own preventive-action process itself*:
in every one of those six chains, the bug doc's own "prior-preventive-action failure analysis"
section gives the same diagnosis in different words — the earlier rule was written narrowly
enough (scoped to the literal value it was first written against, or to the trigger that first
surfaced it, or to the layer where it was easiest to state) that a sibling case with a
different trigger or a different literal value, but the identical underlying mechanism, was
read as out of scope. PA-0018 already re-derived this once, narrowly, for container-lifecycle
self-heal ("re-key from the trigger to the mechanism"); this report generalizes it, because it
has now happened five other times under five other rules (PA-0001, PA-0003, PA-0010, PA-0014,
PA-0019) with the identical diagnosis.

Both trends point at the same actionable gap: this project is good at fixing the *instance* of
a verification gap or a narrowly-scoped rule, and has never had a standing rule that names
either shape as the recurring, dominant failure mode in its own right — every existing PA
treats its own instance as the lesson, correctly, but nothing forces the next author (human or
AI) to recognize a *new* instance of either shape *before* it becomes bug #15 or recurrence #7.

## New preventive actions

**PA-0032** — Verification-fidelity is this project's single most common root-cause shape (14
of the first 28 recorded bugs; see `docs/reports/REPORT-0001-bug-log-trend-analysis.md`).
Whenever a test, fixture, self-test, or harness is authored **or extended to a new case**
(a wider input, a new manifest, a new environment, a new library/runtime version, a new
endpoint or code path), it must be built from, or checked against, a **real, captured instance**
of what the upstream producer, library, or environment actually does — a real library call's
actual return value, a real on-host run's actual output, a real server's actual response —
never a hand-authored approximation of what it is assumed to do. This check is not a one-time
authoring-time step: it is repeated at every point coverage is *extended*, because that is
where nearly every instance of this class in this project's history actually surfaced (a
widened registry, a new manifest, a new endpoint category, a newer runtime). This rule
generalizes and cross-references PA-0006, PA-0008, PA-0009, PA-0010, PA-0011, PA-0013, PA-0015,
PA-0016, PA-0017, PA-0024, PA-0026, PA-0027, PA-0029, and PA-0030, each of which is a
mechanism-specific instance of it; none of those rules is superseded (each still names its own
concrete mechanism precisely, which this rule does not restate), but a new instance of this
*shape*, in a subsystem none of those rules already names, is still a violation of this rule
even before it has its own bug report.

**PA-0033** — A preventive action must be worded at the level of the **underlying mechanism**
that produced the bug, never at the level of the specific **trigger or symptom** that first
surfaced it, and its PA-0002 sweep must enumerate every call site/subcommand/path that shares
that mechanism — not only the ones that share the original trigger. Before considering a new
preventive action finished, its author states explicitly what the *mechanism* is (as distinct
from the trigger) and checks at least one plausible sibling path against that mechanism, even
if that sibling path is not currently failing. This generalizes PA-0018 (which re-scoped
PA-0014 from "env/profile change" to "any container recreate/remove operation" for one case)
into a standing rule for every future preventive action: the same failure mode — a rule that
reads as in-scope only for its original trigger — recurred independently under PA-0001 (→
BUG-0002, BUG-0025), PA-0003 (→ BUG-0007), PA-0010 (→ BUG-0024), PA-0014 (→ BUG-0017), and
PA-0019 (→ BUG-0019), five more times after PA-0018 first named the shape, because PA-0018
itself was scoped only to container lifecycle rather than stated as a rule about how *all*
preventive actions must be worded. (from `docs/reports/REPORT-0001-bug-log-trend-analysis.md`)

## What this report deliberately does not do

- It does not re-litigate or supersede any individual PA — each of the fourteen (row 1) and
  five (row 6) instances was, on its own terms, correctly diagnosed and correctly fixed for the
  bug that produced it. The finding here is only that, taken together, they are one repeating
  shape apiece, not fourteen/five unrelated ones.
- It does not open new `BUG-NNNN` entries for the trend itself — no new code defect was found
  by exercising code in the course of this review; the corpus was read, not re-run.
- It does not recommend structural changes to the bug/PA process (e.g. a mandatory periodic
  retrospective) — that is a process-design decision for the project maintainer, out of scope
  for a single retrospective's findings; it is left as an implication of this report, not a
  proposal within it.
