# BUG-0157 — The Stop hooks enforced proxies (incident words, a unique-CWE quota) instead of the property they guard

- Date: 2026-10-15
- Status: fixed (CAPA status: provisional)
- Severity: medium (failed controls: false blocks on routine work; one quota that
  induced inaccurate labels)
- Class: formal CAPA, failed control (`docs/QUALITY_POLICY.md` §4)

## Description
Two Stop hooks guarded bookkeeping with a proxy for the property they meant to check.

1. **`.claude/hooks/check-error-log-bookkeeping.sh`** (BUG-0018/0019, PA-0019/PA-0020)
   scanned the not-yet-pushed diff for "incident-shaped" words: fail, hang, workaround,
   killed, timed out, timeout, crash, broken, regress. Any match blocked the turn unless
   `ERROR_LOG.md` had been touched.
2. **`.claude/hooks/check-corpus-cwe-coverage.sh`** (BUG-0030, PA-0033) required every
   corpus manifest entry to carry at least two CWEs that no other touched entry claimed
   as unique.

## Where encountered
The lean quality-control review (`docs/quality/LEAN_QC_PROPOSAL_REV3.md`, "Bookkeeping
Stop-hook negative control" and "Requirements that should not survive unchanged",
PA-0033). Reproduced here on 2026-10-15:
- **Steps:** a throwaway repository with a pushed base; a commit adding the README
  line `The timeout setting is 15 seconds.`
- **Result:** the old hook printed "incident-shaped language ... added to the diff" and
  exited **2**.

## What it caused to fail
- **Keyword hook:**
  - It blocked benign documentation of timeouts, failures, crashes and regressions,
    which is the vocabulary of a fuzzing project's docs.
  - It was satisfied by *any* edit to `ERROR_LOG.md`, whatever that edit said.
  - It did not know whether a change was a defect at all.
- **CWE quota:**
  - Independent examples that correctly share one root weakness could not pass.
  - Acceptance depended on which other entries happened to be touched.
  - It pushed authors to add "unique" CWEs that fit poorly. Today's corpus shows the
    pattern: many entries carry two "unique" CWEs whose fit to the code is doubtful
    (for example CWE-665/CWE-710 on a fixed-template Handlebars example).
- **Silent pass:** the CWE hook passed silently (exit 0) when `python3` could not import
  PyYAML. In a container without it, the control did nothing.

## What the bug was identified to be
Both controls checked a measurable surrogate (a word in the diff; a count of unique
labels) instead of the requirement:
- for the keyword hook, "a defect fixed in this change has its error-log record";
- for the CWE hook, "each entry's weakness is mapped accurately".

## Root cause analysis
Five whys:
1. Why did a timeout sentence block a turn? The hook treated a word as evidence of an
   incident.
2. Why a word? The change carried no declared type, so the hook had to guess.
3. Why no declared type? The change record had no field for it; type and risk were
   never recorded anywhere machine-readable.
4. Why the CWE count? BUG-0030's under-delivery ("too few CWEs researched") was
   converted into a minimum count with a uniqueness rule, so that "more" became
   checkable.
5. Why did that seem adequate? A count is mechanical. Neither control was qualified on
   a legitimate case (a benign sentence; examples sharing a CWE), only on offenders.

**Root cause:** the controls were designed against an offender example only, with no
legitimate-case control (L10), and they substituted proxies because the change record
did not declare what the checks needed.

## Corrective action
This change (CHANGELOG 2026-10-15, "lean quality policy"):
- **`.claude/hooks/check_bookkeeping.py`** replaces the keyword hook (`.claude/settings.json`
  rewired; the old script removed).
  - Every unpushed commit declares `Change-Type:` (defect, feature, safety, process,
    docs, refactor, test) and `Risk:` (low, medium, high) trailers.
  - A `Change-Type: defect` commit needs an `ERROR_LOG.md` change in the same unpushed
    range or working tree.
  - A changed `docs/bugs/BUG-*.md` or `docs/spikes/*.md` needs one too.
  - There is no keyword scan.
- **`.claude/hooks/check-corpus-cwe-coverage.sh`**:
  - The per-entry two-unique-CWE quota and the cross-entry uniqueness rule are removed.
  - An entry needs at least one well-formed `CWE-<n>` mapping, with no duplicate within
    a field.
  - The owner-requested floor (at least 5 vulnerable and 5 idiomatic entries per cell,
    with real pairs) is unchanged.
  - A missing PyYAML now blocks with a message instead of passing silently.
- **Tests** (`tests/test_stop_hooks.py`, run for real against throwaway repositories):
  - the review's negative control (`test_a_benign_sentence_with_an_incident_word_is_not_an_incident`);
  - missing or invalid trailers;
  - a declared defect, and a bug record, each without and then with `ERROR_LOG.md`;
  - the loop guard;
  - entries sharing one CWE now pass;
  - a missing, malformed or duplicated mapping fails;
  - the pairs floor still fails at four;
  - the settings wiring.

## Recurrence review
Searched `docs/bugs/` and `docs/quality/CONTROL_INDEX.md` (L01, L07, L10):
- BUG-0018/BUG-0019 created the keyword hook (PA-0019/PA-0020).
- BUG-0030 created the CWE quota (PA-0033).
- BUG-0156 (this change) is the same mechanism in another control: a proxy (contact)
  enforced instead of the property (a decision).

## Prior-preventive-action failure analysis
- **PA-0020** ("enforce mechanically, not by prose") was right in principle but was
  implemented with a lexical proxy. It also never had a legitimate-case control, which
  PA-0034 asks guards to have; PA-0034 was applied to offenders only.
- **PA-0033** turned a research-quality instruction ("the more substantiated CWEs, the
  better") into a uniqueness quota. MITRE's mapping guidance does not support that, and
  the quota can reward inaccurate labels.

In both cases the failure was the *wrong measure*, not a lack of enforcement.

## Systemic action
- PA-0020 is corrected (declared fields, structural check), PA-0019 archived and PA-0033
  replaced, through their rows in `docs/quality/pa_control_map.tsv`.
- L10 in `docs/QUALITY_POLICY.md` requires both an offender control and a legitimate
  control for every guard.
- No new PA.

## Owner, due date and effectiveness
- Owner: verification owner.
- Due: the next five changes.
- Effectiveness criterion:
  - over the next five changes, the bookkeeping hook raises no block on a
    correctly declared non-defect change;
  - every declared defect lands with its error-log entry;
  - no corpus change is blocked for sharing an accurate CWE.
- Status: provisional.

## Residuals
- The trailers are self-declared. A defect declared as `docs` passes the hook; review
  (§2) remains the check on the classification.
- Corpus labels assigned under the old quota are not re-reviewed by this change.
  Re-mapping them to the precise weaknesses is open corpus work: a data change, and the
  owner's to schedule.
