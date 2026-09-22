# BUG-0030 — Site-architecture corpus expansion under-delivered the plan's
own explicit "as many substantiated CWEs as possible" instruction, and this
recurred even immediately after a first correction for a related but
distinct under-delivery (deferring research scope)

- Date: 2026-09-22
- Status: fixed
- Severity: medium (no code defect in `fuzzlab` itself, but a real quality
  defect in a deliverable the user explicitly, repeatedly corrected — this
  is the agent-execution-fidelity bug class `docs/MULTI_AGENT_ORCHESTRATION.md`
  and `CLAUDE.md`'s "confirm which mechanism it actually used" guidance name
  directly, and it cost the user two full correction cycles)

## Description

`docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` Step 6 states, in the
user's own original wording carried into the plan: *"Additional research
will be done to identify cwe's specific to the code's architecture/function/
tech stack. **The more cwe's that are able to be implemented, the better.**"*

Executing wave 1 and wave 2 of that plan, every one of the 6 manufactured
vulnerable/idiomatic pairs this session added to `docs/research/
corpus-examples/*/manifest.yaml` was given only 1-2 CWE IDs (often 0 on the
idiomatic side, an empty `cwe: []`), picked as "the first CWE that
plausibly matched the described pattern" rather than researched against the
MITRE CWE index's own class/parent/child relationships and related-weakness
data for genuinely additional, substantiated CWEs. This happened across two
separate work sessions in the same conversation, the second of which
immediately followed the user explicitly correcting a *different* instance
of the same underlying failure (see "Where encountered" and the root cause
below) — meaning the correction that did land did not generalize to the
sibling instruction it should have caught in the same pass.

## Where encountered

- Wave 1 (first execution pass): `woocommerce-cart-hook` (CWE-840, CWE-20)
  and `django-contrib-comments` (CWE-79 only, idiomatic side `cwe: []`)
  entries added to `docs/research/corpus-examples/ecommerce-logic/php/
  manifest.yaml` and `docs/research/corpus-examples/ugc-xss/python/
  manifest.yaml`.
- Between wave 1 and wave 2, the user corrected a **related but distinct**
  under-delivery: this session's stated wave-1 scope had deferred Steps 2-7
  for 4 of the plan's 6 categories, and the user instructed "No, do not
  defer, do the research." That correction was acted on faithfully — all 6
  categories got their architecture write-ups and one real
  architecture/function pair each in wave 2.
- Wave 2 (immediately after that correction): the 4 new pairs
  (`wekan-board-membership`, `peertube-video-upload`, `qloapps-booking`,
  `firefly-blocked-account-gate`) repeated the **exact same** CWE-research
  shortfall as wave 1 — 1-2 CWEs each, several `cwe: []` idiomatic sides —
  despite Step 6's "more is better" instruction being no less explicit for
  these 4 categories than for the first 2, and despite having just been
  corrected, in the same conversation, for a scope-completeness failure one
  step earlier in the same plan.

## What it caused to fail

- The delivered corpus does not reflect what Step 6 actually asked for: a
  deliberately maximized, substantiated CWE mapping per entry (base plan
  precedent, and this extension's own Step 6, both frame this as a
  research-depth requirement, not a "assign whatever CWE first comes to
  mind" checkbox).
- The user had to notice and call this out explicitly a second time, after
  already having corrected the sibling deferral problem once in the same
  conversation — the cost `CLAUDE.md`'s Definition of Done and
  `docs/MULTI_AGENT_ORCHESTRATION.md`'s delegation-fidelity guidance both
  exist specifically to avoid.

## What the bug was identified to be

Executing Step 6 for each new manifest entry, the actual behavior was: read
the manufactured pattern description, recall (from training, not from
consulting the MITRE CWE index's actual class/base/variant hierarchy or its
"CanPrecede"/"related weaknesses" data for that entry's mechanism) the one
or two most obvious CWE IDs, and record those as the entry's `cwe:` list —
then move on, treating "a cwe field is populated" as satisfying Step 6,
rather than treating Step 6 as its own bounded research task (enumerate the
MITRE index's relevant weakness class, its parent(s), any sibling/child
CWEs the same code shape also legitimately contributes to, and record each
with a one-line justification) the way Steps 3-4 (source search + validate)
and Step 7 (build + validate the vulnerable pair) were each actually treated
as their own bounded task with real work product to show.

## Root cause analysis

Five whys:

1. **Why did each entry get only 1-2 CWEs instead of "as many as can be
   substantiated"?** Because CWE assignment was done by recall (pattern
   match against memorized common CWE IDs — CWE-79 for an XSS shape,
   CWE-840 for a business-logic price shape) rather than by an actual
   research step against the MITRE index the plan itself names as the
   source for this step.
2. **Why was recall treated as sufficient when Steps 3-4 (real GitHub
   source, license-verified, commit-pinned) and Step 7 (a manufactured pair,
   explicitly validated) were both held to a real, checkable standard in the
   same entries?** Because Steps 3-4 and 7 each produce an artifact whose
   absence is immediately, mechanically obvious (no source file, no commit
   SHA, no `validated: true`) — there is no equivalent friction for Step 6:
   a `cwe: [CWE-79]` field looks exactly as "done" as a `cwe: [CWE-79,
   CWE-116, CWE-838]` field on casual inspection, so nothing forced a check
   of whether the list was actually researched to its stated ceiling versus
   just populated.
3. **Why did the intervening correction (don't defer categories 3-6) not
   also catch this?** Because that correction was read and applied
   narrowly — as "cover all 6 categories" — without re-auditing the
   *already-corrected* mental model against every other explicit
   instruction in the same plan document (Step 6's "more is better" is a
   sibling instruction, not a subset of the deferral instruction), so
   fixing the named gap did not trigger a check of the plan's other
   explicit, easy-to-under-deliver requirements.
4. **Why does this project not already catch this mechanically, the way it
   catches other "did I actually do the thing" gaps?** Because no
   corpus-specific check exists at all — `docs/research/corpus-examples/`
   has never had a mechanical gate, only prose conventions in
   `docs/VULN_CORPUS_EXPANSION_PLAN.md` that a human/agent is trusted to
   read and follow.
5. **Root cause:** an explicit, quantitative "do more of X, don't stop at
   the minimum" instruction was executed as a **satisfied-when-populated**
   checkbox rather than a **bounded research task with its own success
   criterion**, and — per this project's own established PA-0020 finding
   below — a bug whose root cause is "my own missed or inconsistent
   self-check" does not get fixed by writing the rule down more clearly; it
   needs a mechanical check that runs independent of remembering to apply
   the rule, which did not exist for this step.

## Recurrence review

Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a prior occurrence
of the same bug or a bug with the same root cause. Found one directly
on-point: **PA-0020** (from `BUG-0019`/`BUG-0020`) already establishes the
general rule this bug is an instance of: *"When a preventive action's root
cause is my own missed or inconsistent self-check (rather than a defect in
project code, tests, or a process document), a written rule alone does not
count as prevention — it must also have an enforcement path that runs
independent of my remembering to apply it."* This bug's root cause (step 5
above) is exactly that failure mode, applied to a different deliverable
(corpus CWE-research depth instead of `ERROR_LOG.md` bookkeeping).

## Prior-preventive-action failure analysis

PA-0020 correctly diagnosed the general failure mode and correctly
prescribed "mechanical enforcement, not a written rule" as the fix — but its
own enforcement mechanism (`.claude/hooks/check-error-log-bookkeeping.sh`,
wired as a `Stop` hook) is scoped narrowly to one specific instance of the
class: detecting incident-shaped language in a diff and checking whether
`ERROR_LOG.md` was touched. It does not generalize to *other* instances of
"my own missed self-check" — including, as this bug shows, under-delivering
an explicit quantitative research instruction in a different document
family (`docs/research/corpus-examples/*/manifest.yaml`) entirely outside
`ERROR_LOG.md`'s domain. PA-0020 was, in other words, correct but too
narrow in its *scope of enforcement* (one hook, one deliverable), even
though its *diagnosis* (self-check bugs need mechanical enforcement) was
right and is being reused, not revised, here. This mirrors PA-0029's own
framing relative to PA-0028: the general principle was sound, but each new
concrete instance of the class still needs its own concrete enforcement
artifact, not just an appeal to the already-written general rule.

## Corrective action

1. **Remediated the 6 existing manifest entries this bug describes**
   (PA-0002's sweep-and-remediate obligation, applied retroactively to
   already-committed work rather than only prospectively): re-researched
   each entry's applicable CWEs against the MITRE CWE index's actual
   class/parent/child/related-weakness structure (not recall), and expanded
   every entry's `cwe:` list to every substantiated ID found, with a
   one-line justification per ID. See the corpus-CWE-expansion commit that
   follows this bug report for the specific IDs added per entry.
2. **Added `.claude/hooks/check-corpus-cwe-coverage.sh`**, wired as an
   additional `Stop` hook in `.claude/settings.json` (alongside, not
   replacing, `check-error-log-bookkeeping.sh`): mechanically parses every
   `docs/research/corpus-examples/*/*/manifest.yaml` entry touched by the
   turn's not-yet-pushed changes and blocks the session from ending if any
   touched entry has fewer than 2 CWE IDs in its `cwe:` list and no
   `cwe_count_rationale:` field explaining why more weren't substantiated
   (a real gap — e.g. a narrowly-scoped snippet with genuinely one
   applicable weakness — is a legitimate, recordable outcome; a silently
   thin list is not).
3. **Rewrote `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` from
   scratch** (per the user's explicit instruction), including a
   restructured Step 6 that names the concrete research procedure (walk the
   MITRE index's class hierarchy and related-weakness data for the entry's
   actual mechanism, not recall a single obvious ID) and ties directly to
   the new hook as its own stated enforcement mechanism, rather than
   repeating "more is better" as unenforced prose a second time.

## Preventive action

**PA-0033** (strengthens/supersedes PA-0020's enforcement scope, does not
revise its diagnosis): every future explicit, quantitative "do more of X /
don't stop at the minimum" instruction that produces a checkable artifact
(a list, a count, a set of records) must get its own concrete, mechanical
enforcement artifact at the time the instruction is first acted on — not a
restatement of the instruction's own wording in a planning document, and
not deferred on the assumption that PA-0020's general principle already
covers it. `docs/PREVENTIVE_ACTIONS.md` records the rule; this document
records the first concrete instance of applying it
(`check-corpus-cwe-coverage.sh`) as the worked example future instances
should follow: identify the specific artifact the instruction bears on,
build a script that mechanically inspects that artifact for the
instruction's literal success criterion, and wire it into the Stop-hook
chain in the same change that fixes the immediate instance.
