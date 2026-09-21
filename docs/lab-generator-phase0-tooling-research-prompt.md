You are a senior software-test-infrastructure engineer and applied-ML
researcher. I need a rigorous, cited research report to de-risk the next
implementation phase of a manifest-driven vulnerable-lab generator, before any
code is written. Use web search extensively. Prefer authoritative, recent
sources (the last 18–24 months for anything you call "current"), cite every
non-obvious claim with a URL and its publication date, and clearly separate
established practice from experimental ideas. Where you can find and cite an
actual working example, prior-art project, or library, do so rather than
describing the idea abstractly.

## Context (read before researching)

I'm building `fuzzlab`, a modular security-testing toolkit, and its target
lab, "Puppy Fort Factory," is moving from one hand-authored PHP app to a
manifest-driven generator. Two prior research passes already shaped the
design (attached/referenced for context, don't re-derive their conclusions):

- A generator design report recommended: a pipeline-valued transform model
  over a structured, versioned safety matrix (verdict is *derived*, never
  asserted); pairwise/mixed-strength **covering-array** cell generation
  instead of full cross-product enumeration (this is the report's single
  highest-leverage recommendation); a **leakage probe** as a build gate — a
  deliberately weak classifier trained on response *metadata only* (status
  code, response length, headers, latency, param-name length, content type,
  path depth — never the response body or payload) that must not exceed
  ~0.55–0.60 AUC, or the corpus has a shortcut and the build fails; split
  determinism (byte-identical **source** emission, CI-gated; digest-pinned +
  SBOM-recorded **containers**, not bit-identical images); and a name-leak
  scanner that greps every served artifact against a denylist before a build
  ships.
- A follow-on report validating the corpus-sourcing plan found (among other
  things) that provenance/documentation data must be structurally separated
  from the manifest the verdict engine reads — the same invariant SLSA/
  in-toto provenance formats enforce (an artifact must be unchanged by
  whether provenance for it exists).

Both are settled design decisions; **don't re-litigate them.** What I need now
is tooling- and methodology-level research to actually build the first
implementation phase, which: reproduces the current PHP lab byte-for-byte
through the new pipeline (proving the generator core works before any new
tech stack is added); stands up the covering-array machinery (even though
Phase 0's own manifest lists cells explicitly, with no real variation yet);
stands up the determinism CI gate and the name-leak/secret-scan build gates;
and lays groundwork for the leakage probe and multi-artifact labeling that
later phases depend on. This is a solo, local, authorized security-research
project (same posture as DVWA/Juice Shop — loopback-only, lab-only,
defensive-research-oriented). Keep the report focused on how to build this
well, not on offensive technique.

## Research areas

### 1. Combinatorial / covering-array test-design tooling in Python

The design calls for pairwise (t=2) covering arrays with mixed strength on a
specific sub-tuple of parameters, and constraint support (excluding invalid
combinations, e.g. "stack X can never pair with class Y"). NIST's ACTS tool
implements the reference IPOG algorithm but is a Java desktop/CLI tool.
Research: is there a maintained, actively-developed **Python** library that
does mixed-strength, constrained covering-array generation well enough to
avoid shelling out to ACTS or hand-rolling IPOG? Compare options (e.g.
`allpairspy`, `combinatorial-testing`/PICT-derived tools, anything wrapping
ACTS programmatically, or a from-scratch IPOG implementation) on: constraint-
expression power, mixed-strength support, array-size efficiency versus ACTS's
published figures, maintenance status, and how easy it is to unit-test
deterministically (same seed/inputs → same array, forever). Recommend one
approach with a fallback, and note the effort to hand-roll IPOG if nothing
adequate exists.

### 2. Deterministic, multi-language code generation and CI-gating recipes

Research concrete recipes for **byte-identical source regeneration** as a CI
gate, validated separately per language family the generator will eventually
target (PHP now; Node/TypeScript and Python later — per the design's
polyglot-emitter architecture): canonical serialization libraries for
JSON/YAML/CSV (sorted keys, fixed float formatting, LF line endings) in
Python; templating/codegen approaches that don't introduce nondeterminism
(Jinja2 vs. a custom emitter; risks specific to JS codegen involving a
formatter or bundler, which the design's own open questions flag as the most
likely first place a spurious diff appears); how to pin and verify formatter
versions (prettier, black, php-cs-fixer) since formatter output changes
between minor versions; and practical use of `SOURCE_DATE_EPOCH` for any
embedded timestamps. Separately, research the current state of **Docker/
OCI image reproducibility** for a "digest-pinned inputs + recorded SBOM"
approach (not bit-identical images) — concrete SBOM tooling (Syft or
equivalent) and how to record it alongside generator output so an old build
stays explicable years later.

### 3. Name-leak and secret-scanning for generated, multi-file trees

The design requires a build gate that scans every *served* generated
artifact (routes, filenames, params, cookie/header names, HTML comments, JS
bundles and sourcemaps, OpenAPI/GraphQL schema text, error strings/stack
traces, framework-exposed endpoints, container/image labels) against a
denylist of vulnerability-class names, synonyms, and CWE IDs, failing the
build on any hit — plus a separate secret scanner over emitted config so a
generated tree never accidentally ships a real-looking credential. Research:
concrete, actively-maintained tools for each half (a generic secret scanner
— e.g. gitleaks or a comparable current alternative — and how others
structure a custom denylist/content-policy scanner for generated code
specifically, if any prior art exists for that narrower problem). Recommend
a concrete configuration approach and how to keep the denylist itself
versioned and testable (a scanner with silent false negatives is worse than
no scanner).

### 4. Leakage-probe design and per-class threshold setting

The leakage probe (train a weak classifier on response metadata only; fail
the build if it beats a low AUC ceiling) was flagged by prior research as
"experimental, no published prior art in this exact form for benchmark/test-
corpus construction" — check whether that's still true, and separately,
research the closest adjacent literatures that do solve "does my labeled
dataset have a shortcut/spurious-correlation feature": dataset-shortcut and
spurious-correlation detection methods from the broader ML-fairness/
robustness literature (e.g. work on shortcut learning, spurious correlation
benchmarks, dataset audits), and anything specific to security/vulnerability
datasets (the "sudden style change" artifact problem in synthetic-
vulnerability-injection benchmarks is a known instance — is there follow-on
work proposing a standard mitigation or detection method?). From this,
recommend: a concrete minimal reference implementation (feature set, model
choice — logistic regression vs. gradient boosting, held-out/stratified
evaluation setup) and a defensible method for setting the AUC threshold
**per class** rather than one global number, given that some classes (e.g.
time-based blind SQLi) have an irreducible, legitimate metadata signal (the
timing *is* the vulnerability) that shouldn't be flagged as a leak.

### 5. Prior art for ground truth spanning two artifacts

Some cells are only meaningfully "vulnerable" as a pair — a write endpoint
and a read endpoint (stored/second-order XSS; a signing key set in one place
and trusted in another). Research how existing test-case/benchmark
generation systems (Juliet/SARD's flow-based CWE test cases, or any other
labeled-vulnerability-corpus methodology you can find) represent a ground-
truth verdict that depends on a *pair or sequence* of locations rather than
a single one — do they use a synthetic pair ID, attach the label to one
designated "sink" location, or something else — and what tradeoffs each
approach has for a system (like mine) where the label contract is consumed
by downstream detection/scoring tools that currently assume one row per
finding.

## Output format

Produce a structured report: a short executive summary, then one clearly
headed section per research area above. In each, give the recommended
approach and alternatives with tradeoffs, concrete libraries/tools/citations,
pitfalls, and a maturity rating (established / experimental / not worth it at
this scale). Close with: (a) a concrete recommended tool/library choice for
each of areas 1–4, with version and licensing noted; (b) a short worked
example or pseudocode sketch for the leakage-probe reference implementation
in area 4; (c) a recommendation for area 5 with tradeoffs stated plainly
enough that I can decide; and (d) open questions or gaps you couldn't
resolve. Cite sources inline with URLs and dates, add a final reference list,
and flag anything that is hype or not worth the effort for a solo, local
security-research project.
