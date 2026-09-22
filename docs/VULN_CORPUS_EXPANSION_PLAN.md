# Vulnerability corpus expansion — research plan

Working plan for broadening `fuzzlab`'s generated lab beyond the current 16
`puppy-fort-factory` ground-truth cases and the SQLi/XSS classes already
modeled in `lab/safety_matrix.yaml`. This is the research phase only — it
produces lists and a code corpus for humans/agents to design against next,
not new emitter code itself.

## Why

Discussed 2026-09-22, following the completion of the `php_laravel` real-page
migration (`L-P3.3c`) and its live-boot verification. Two ways to broaden the
generated corpus were identified:

- **Track A — broaden vulnerability classes** (new `op`/`sink_family` rows in
  `lab/safety_matrix.yaml`, new per-stack module templates): cheap, additive,
  doesn't require new fixture pages.
- **Track B — broaden real-page count**: capped by `puppy-fort-factory`'s own
  16 ground-truth cases; needs either extending that fixture or adding a
  second one.

This plan is the front end of Track A: before designing new vulnerability
classes and module templates, build a grounded reference base so new classes
are modeled on real code shapes, not invented from memory (the same instinct
already used for the existing matrix — see `lab/safety_matrix.yaml`'s header
citing `puppy-fort-factory/VULNERABILITIES.md` line numbers, and L-P1.2a's
sqlmap spot-check before building the SQLi oracle prober).

## Phase 1 — feature/functionality survey (in progress)

Two research angles, run in parallel:

1. **What features are actually common in real web applications?** A broad
   catalog of functionality categories seen across typical sites/apps —
   authentication, search, file upload/download, user profiles, comments/
   reviews, checkout/payment, admin panels, APIs/webhooks, messaging,
   notifications, third-party integrations, reporting/exports, etc.
2. **Which of those features are disproportionately associated with real
   exploitation?** Cross-referenced against OWASP Top 10 / OWASP WSTG
   categories, CWE prevalence data, and documented real-world breach/bug-
   bounty patterns — not just theoretical risk.

**Output:** a single documented list (this file, "Candidate feature/
vulnerability list" section below, filled in once research lands) of
feature areas worth targeting, each annotated with the vulnerability
class(es) it's known to be susceptible to and why.

## Phase 2 — real source-code collection (not started)

For each feature on the Phase 1 list: search GitHub for real, published
example implementations of that feature — vulnerable and/or idiomatic
implementations both count as reference material — collecting several
examples per feature. Where a feature appears in multiple languages/stacks,
collect examples per language separately.

**Organization:** by feature, then by language, e.g.:

```
docs/research/corpus-examples/
  file-upload/
    php/
    node/
    python/
  search/
    php/
    node/
    python/
  ...
```

Each collected example notes: source repo (owner/name), file path, license,
and a one-line note on why it was picked (what shape/pattern it demonstrates).

**Output:** an organized reference corpus of real code, per feature, per
language — input to Phase 3.

## Phase 3 — CWE mapping (deferred, not started)

Once Phase 2's corpus exists: identify the CWE(s) each collected example is
associated with, to ground the eventual `safety_matrix.yaml` vocabulary
(new `op`/`sink_family`/concern-ID rows) in a recognized taxonomy rather than
ad hoc naming. **Explicitly deferred** — do not start this until Phase 2's
corpus is in hand.

## Candidate feature/vulnerability list

*(To be filled in once Phase 1 research lands.)*

## Status

- [ ] Phase 1 dispatched
- [ ] Phase 1 complete, list documented above
- [ ] Phase 2 dispatched
- [ ] Phase 2 complete, corpus collected
- [ ] Phase 3 (deferred)
