# Seed authoring playbook — from a vulnerability report to a generated cell

**Status: consolidation of already-decided rules, not a new decision.**
Everything below is already settled across `CR-LAB-0001` Addenda B/C/D and
`LAB_PHASE_0_PLAN.md`; this document exists because those rules were never
written down as one executable sequence, and answers the question "how,
concretely, do we turn a real disclosure into a generated lab cell." **This
playbook has never been exercised on a real seed.** Its own recommended
first action (§8) is to fix that before trusting anything else in it.

## The pipeline, end to end

```
OSV/GHSA disclosure
      │  (human triage, LAB_PATTERN_CORPUS_SOURCING_PLAN.md)
      ▼
pattern card (2-4 sentences, original words, provenance ONLY)
      │  informs the SCENARIO, never the code
      ▼
scenario brief (human-written; must NOT name the vulnerability
                or the required mitigation — SecCodePLT rule, Addendum D)
      │
      ▼
SEED  — one (class, sink_context) pair, on stack 1, human-authored:
   • safety-matrix entry: (op, sink_context) -> effect
   • vulnerable module fragment(s), by file_role
   • secure twin (identical identifiers, differs ONLY in the transform)
   • TWO oracle assertions: functional, security
   • TWO Semgrep "shape" rules: sink present, transform present
      │
      ├──► PORT / VARIANT (LLM may draft; never the seed itself):
      │       - port the seed's shape to another stack's idiom
      │       - vary the sink context within the same class
      │       - vary nuisance-axis surface detail
      │     Input: the structured tuple + framework docs.
      │     NEVER the pattern card. NEVER writes the oracle or matrix entry.
      │
      ▼
GATES (tiered, LAB_PHASE_0_PLAN T-LAB0.7):
   Tier 0  lint + minimal-pair diff (whole file set) + Semgrep shape rules
   Tier 1  in-process functional + security test (where valid — never for
           SQLi/race cells; app in-process, DB in a long-lived container)
   Tier 2  full container oracle — the ONLY tier that confirms a label
   Tier 3  whole-lab regeneration + determinism + leakage probe + name-leak
      │
      ▼
provenance.yaml: cell_id -> [card_id]     (never inside the manifest —
                                            Addendum A's structural separation)
      │
      ▼
labels.json / expectedresults.csv / injection-points.json
```

## Step by step: adding one `(class, sink_context)` to the lab

1. **Identify the gap.** Pick a `(class, sink_context)` from the first-wave
   scope (`CR-LAB-0001` §5 / `LAB_PATTERN_CORPUS_SOURCING_PLAN.md` §5) not
   yet covered on the target stack.
2. **Pull the relevant pattern card(s).** Read the card's `root_cause` for
   the mechanism shape and its `source_url` for context. **Do not open the
   advisory's linked patch diff or PoC while authoring** — the card's
   paraphrase is what's licensed for this use; the diff is not.
3. **Write the scenario brief**, deriving it from the card the way
   SecCodePLT derives seeds from CVE analysis: describe the *coding
   scenario* (e.g. "a listing endpoint accepts a sort column from the
   client"), never the *vulnerability* (never "this is missing an
   allowlist on the sort column"). If the brief would give away the answer,
   rewrite it.
4. **Write the safety-matrix entry.** For every `(op, sink_context)` pair
   this seed touches, declare its effect: `neutralises | partial |
   no_effect | introduces` (`lab/safety_matrix.yaml`, T-LAB0.2). This is
   what makes `verdict()` derive the label — never write `vulnerable: true`
   anywhere.
5. **Author the secure twin first**, then produce the vulnerable variant as
   a *minimal removal* of one transform step — closer to how real flaws
   arise than adding a flaw to a blank page, and it's what keeps the
   minimal-pair diff small and mechanically checkable. Assign each module a
   `file_role` (`source | transform | sink | view | route`, Addendum D) and
   route it through the stack's `StackEnv.file_roles` map.
6. **Enforce identifier discipline.** Per-cell identifiers derive from the
   cell ID; the vulnerable and secure twins must emit **identical**
   identifiers. (Juliet's own documented defect: generic helper names made
   false positives unattributable to the right variant — don't repeat it.)
7. **Write two oracle assertions, by hand.** One functional ("the route
   works and returns the expected shape"), one security ("the vulnerable
   variant is exploitable; the secure twin is not"). **This step is never
   delegated to an LLM** — if the model writes both the code and the test
   that judges the code, a confidently-wrong pair passes silently.
8. **Write two Semgrep shape rules.** One asserting the vulnerable module
   contains the intended sink pattern, one asserting the secure module
   contains the intended transform. Mark the pair's
   `static_precheck: informative` unless the class is one a taint tool is
   structurally blind to (identifier/alias/connector-position injection,
   escaping-context mismatch, mass assignment, header-trust bypass — mark
   those `uninformative` and skip the check rather than trusting a clean
   scan, per `CR-LAB-0001` Addendum C §4).
9. **Record provenance**, never inline. Add `cell_id -> [card_id]` to
   `lab/patterns/provenance.yaml`. The manifest cell itself carries no
   reference to the card.
10. **Run the gates in order** (Tier 0 → 1 → 2). Fix and re-run on any
    failure; a Tier-1 pass is never recorded as label confirmation. Only a
    Tier-2 pass makes the cell real.
11. **To port to another stack:** hand the LLM the structured tuple +
    pinned framework version + a relevant doc excerpt — not the pattern
    card, not the seed's oracle or matrix entry as something to imitate
    unsupervised. Run the same gates. A human reviews anything that fails a
    gate twice, or that belongs to a Tier-B (deliberately hard) class.
12. **Log the hours spent** against (class tier × stack × seed-vs-port),
    tagged in the same place effort is tracked for §8 below. This is how
    the current ±40% effort estimate (`CR-LAB-0001` Addendum C §4) gets
    replaced with a real number instead of staying a guess forever.

## Non-negotiable rules (consolidated)

- The pattern card informs the *scenario*; it never appears in code, in an
  LLM's code-drafting context, or inside the manifest.
- A human authors every seed's oracle assertions and safety-matrix entry.
  An LLM may only draft/port *modules*.
- The scenario brief never names the vulnerability class or its required
  mitigation.
- Vulnerable and secure twins differ *only* in the transform, are diffed
  across their whole file set (not one file), and emit identical
  identifiers.
- A clean static-analysis scan is never treated as confirmation for a class
  marked `static_precheck: uninformative`.
- Only a Tier-2 (full container) oracle pass confirms a label. Nothing
  earlier in the pipeline is allowed to be recorded as confirmation.
- Never substitute an in-memory database for the real engine when
  fast-testing a SQL-related cell — dialect differences produce false
  passes that look like flaky tests, not methodology errors.

## What this playbook does not yet resolve

- **It has never been run.** No seed exists yet on any stack.
- **The module schema's `view`/`route`/`StackEnv` additions (Addendum D)
  are unvalidated** on a real framework — Phase 0's PHP reproduction target
  doesn't exercise them (filesystem-routed, no accumulator needed).
- **The 5–20% expected LLM-draft error rate** (Addendum C §2.2) has no
  measurement yet specific to framework-idiomatic web code, only adjacent
  analogues from other artifact types.

## Recommended next action

Before trusting this playbook's effort estimate or its untested schema
pieces any further: **author three real seeds with a stopwatch** — one
Tier-A (textbook-shaped), one Tier-B (deliberately hard, e.g. an
identifier-position SQLi case), and one cross-stack port — on the current
PHP stack or a minimal FastAPI/Express spike, whichever is faster to stand
up a throwaway harness for. This is the cheapest way to convert this
document from "a plan" into "a validated process," and it's the same
recommendation the underlying research made independently. It does not
require Phase 0 to be finished first, but it does require your go-ahead,
since it means writing actual (original, non-copied) vulnerable code for
the first time in this program.
