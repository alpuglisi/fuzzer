You are a senior software-security researcher with hands-on experience
building vulnerability benchmarks and test corpora. I need a rigorous, cited
research report that answers a question my own planning has left open: given
that our only "real-world" input is abstract, provenance-only pattern-card
text (never actual vulnerable code, per a strict no-verbatim-code/licensing
constraint), can we actually produce correct, idiomatic, verifiably-vulnerable
(and verifiably-secure) source code from it, at the volume this project
needs, without either an unreasonable amount of manual effort or an
unacceptable error rate? Use web search extensively. Prefer authoritative,
recent sources (the last 18–24 months for anything you call "current"), cite
every non-obvious claim with a URL and its publication date, and clearly
separate established practice from experimental ideas.

## Context (read before researching)

I'm building a manifest-driven generator for a deliberately vulnerable local
security-testing lab (`fuzzlab`/"Puppy Fort Factory" — same posture as DVWA/
Juice Shop/WebGoat: authorized, defensive/educational, loopback-only,
lab-only). The generator's design is settled (don't re-argue it): a
manifest describes "cells," each a `(vulnerability class, sink context,
transform pipeline, stack)` tuple; a pure `verdict()` function derives
vulnerable/secure from the pipeline and sink context (never asserted); and
per-stack **emitters** (Jinja2-templated) render each cell's actual
application code — a vulnerable variant and a minimal-pair secure variant
that differ only in the transform. An **oracle/emitter-conformance suite**
then confirms, by actually exercising the generated app, that the vulnerable
variant is exploitable and the secure variant isn't.

Separately, a small provenance corpus ("pattern cards") is being built from
real, disclosed vulnerabilities (OSV/GHSA-sourced), but **cards are abstract,
original-language descriptions of a root-cause mechanism only — 2 to 4
sentences — never code, never a patch diff.** They exist purely as citable
justification for why a cell's shape reflects something real; they are never
read by the verdict engine and never used as a code source.

**The gap I need researched:** nothing has validated that we can reliably go
from "here is an abstract 2–4 sentence description of a root-cause shape"
to "here is a correct, idiomatic, framework-appropriate Jinja2 template that
renders genuinely vulnerable code in Node/Express, Python/FastAPI, or
PHP/Laravel, with a secure twin that differs only in the transform" — at the
volume needed (current plan: ~18 vulnerability classes, several sink
contexts each, 3–4 target stacks — so potentially 100+ distinct template
pairs by the time all planned stacks are built). I need to know: how hard is
this really, how have comparable projects solved it, what tooling would help,
and what will go wrong if we just start hand-writing templates without a
plan.

## Research areas

### 1. How existing vulnerability benchmarks actually generated their code

Every benchmark project that maps an abstract weakness (a CWE, a class) to
concrete runnable code has solved exactly this problem before. Research, for
each of the following, **specifically how the vulnerable (and, where
applicable, paired secure/patched) code was produced** — hand-authored by
experts, template/mutation-based from real code, LLM-generated and then
verified, or some hybrid — and what that cost in effort or tooling: the
OWASP Benchmark project (~2,740 synthetic Java servlets), NIST SARD/Juliet
(64k+ C/C++ cases, 28k+ Java cases), and the more recent LLM-era benchmarks
CASTLE, SecCodePLT, CWEval, SEC-bench, SafeGenBench (558 prompts / 44 CWEs /
12 languages), RealSec-bench, and SecureAgentBench. For each, also determine
**its license** and whether its actual code/templates could be legally
reused or adapted as a starting skeleton for our generator's templates
(versus only its *methodology* being reusable) — this matters because a
permissively-licensed existing template set could be a legitimate shortcut
for stacks/classes it already covers, distinct from copying a real-world
disclosure's code (which our constraint forbids).

### 2. LLM-assisted code authoring: reliability data and a safe workflow

Several of the benchmarks above (CASTLE, SecCodePLT, SafeGenBench in
particular) reportedly used LLMs to generate benchmark code and then
validated it (Semgrep rules, an LLM judge, or execution-based oracles).
Research what pass/validation rates they actually reported — how often
LLM-generated "vulnerable" code was confirmed genuinely vulnerable by an
independent check, how often a "secure" variant was confirmed genuinely
secure, and what kinds of authoring mistakes recurred (e.g. accidentally
non-functional code, accidentally secure code labeled vulnerable, or
vulnerable code that doesn't compile/run in the target framework version).
From this, and from any published guidance on LLM-assisted secure-code or
vulnerable-code generation more broadly, propose a concrete, safe workflow
for us: can an LLM draft a *candidate template* (original code implementing
an abstract pattern, not copying a disclosure) for a human or an automated
oracle to verify before it ships, analogous to how our pattern-card pipeline
already restricts an LLM to labeling and forbids it from authoring the final
provenance text? Flag maturity honestly — is this established practice
anywhere, or are we still in "reasonable but unvalidated transfer" territory?

### 3. Automated secondary verification tooling per target stack

Before a newly authored template pair reaches the full dynamic oracle (which
likely requires a running container), research whether a fast, in-process
static check could catch authoring mistakes earlier and cheaper: for
Node/TypeScript, ESLint security plugins and/or Semgrep's JS/TS rule packs;
for Python, Bandit and/or Semgrep's Python rules; for PHP, since GitHub
CodeQL does not support PHP, research what does (Psalm's taint-analysis
mode, Phan, Progpilot, RIPS, or others) and its actual maturity/coverage for
our target classes (SQLi via Eloquent raw queries, mass assignment via
missing `$fillable`, SSTI-adjacent Blade misuse, etc.). For each tool/stack
pair, assess: does it actually flag our *intended* vulnerable pattern (true
positive) and correctly pass our *intended* secure pattern (true negative),
or is coverage too shallow to be useful as a pre-check? Recommend which of
these are worth wiring in as a cheap "sanity check before the real oracle
runs" step versus which aren't worth the integration cost.

### 4. Realistic effort estimate

Using whatever effort/scale data the projects in area 1 report (team size,
time spent, number of cases produced), and your own judgment calibrated to
those data points, estimate: **how many person-hours (or LLM-assisted
person-hours) per template pair** is realistic for a solo developer working
with AI assistance, for (a) a straightforward class/sink-context combination
similar to something well-documented, versus (b) a genuinely novel or
tricky one (e.g. the "correct parameterization but injection is in the
identifier/alias/connector position" cases this project specifically wants,
which are harder than textbook cases by design). Extrapolate to the current
first-wave scope (roughly 18 classes, several sink contexts each, starting
with 1 stack in Phase 1 and growing to 3–4 in Phase 3) and give an honest
total-effort range, flagging where the estimate is measured/analogous versus
a guess.

### 5. Fast-feedback iteration loop, to avoid a slow authoring cycle

If confirming a template pair's vulnerable/secure status requires booting a
full container stack every time, authoring 100+ templates will be extremely
slow. Research lightweight, in-process functional-testing approaches for
each target framework that can exercise a single generated route directly
without Docker — e.g. Laravel's built-in HTTP testing helpers, FastAPI's
`TestClient`/`httpx` in-process client, Express with `supertest` — and
whether any of these can drive the actual vulnerability check (e.g. a
time-based SQLi still needs real timing, which may need a real DB
connection, but a header-trust authorization bypass or a template-injection
case might not need a full container at all). Recommend which classes can
be checked at the fast, in-process layer during authoring, reserving full
container boots for periodic whole-stack confirmation, and note where the
speedup is illusory (i.e. where a fast check could give a false pass that
the real container-based oracle would catch).

## Output format

Produce a structured report: a short executive summary that directly answers
the framing question (can we actually do this, at what cost, with what
workflow), then one clearly headed section per research area above. In each,
give the recommended approach and alternatives with tradeoffs, concrete
tools/libraries/citations (including license terms where reuse is discussed),
pitfalls, and a maturity rating (established / experimental / not worth it).
Close with: (a) a concrete recommended authoring workflow combining areas 2
and 3 (draft → fast in-process check → full oracle confirm); (b) the effort
estimate from area 4 as a table (class-difficulty tier × stack × estimated
hours); and (c) open questions or gaps you couldn't resolve. Cite sources
inline with URLs and dates, add a final reference list, and flag anything
that is hype or not worth the effort for a solo, local security-research
project.
