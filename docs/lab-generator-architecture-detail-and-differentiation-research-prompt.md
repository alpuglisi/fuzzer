You are a senior software architect with experience in both vulnerability-
benchmark construction and open-source license compliance. I need a
rigorous, cited research report with two goals: (1) fill in architectural
detail our planning is currently missing for the *restrictively-licensed*
vulnerability-benchmark/lab projects we've only characterized shallowly so
far, specifically so we can document how our own design is independently
architected rather than assume it; and (2) close a specific, flagged unknown
in the one MIT-licensed reference architecture we're already building from.
Use web search extensively, and read source code/documentation directly
where you can access it (clone repos if useful, the way a prior research
pass in this project cloned NIST's VTSG). Cite every non-obvious claim with a
URL and its publication date. Where you find and read actual source, say so
explicitly (mark it "measured, read directly") versus relying on a
project's own docs/README (mark it "per project documentation") versus a
third-party description (mark it "per secondary source") — this distinction
matters a lot for the licensing half of this report.

## Context (read before researching)

I'm building a manifest-driven generator for a deliberately vulnerable local
security-testing lab (`fuzzlab`/"Puppy Fort Factory" — authorized,
educational, loopback-only, same posture as the projects discussed below).
The generator's core design is settled and derives a vulnerable/secure
verdict from a `(transform pipeline, sink context)` pair — never asserted —
and composes generated code from small reusable modules (source/transform/
sink/complexity fragments), a pattern adapted from NIST's Vulnerability Test
Suite Generator (VTSG, NISTIR 8493, MIT-licensed, `usnistgov/VTSG`), which we
have already cloned and inspected in detail. Our project's README and
planning docs also cite, as general "spirit" precedent for what a lab-only
deliberately-vulnerable target looks like, several other projects: **OWASP
Benchmark** (GPL-2.0, ~2,740 synthetic Java servlets), **DVWA**, **Mutillidae
II**, **WebGoat**, **bWAPP**, **XVWA**, and **Google Gruyere**. For all of
these except VTSG, our current documentation only records a one-line
characterization (case count, rough approach, license) — not their actual
internal architecture. We have never copied code from any of them and never
will (that constraint is fixed), but before scaling up implementation I want
to actually understand their architectures well enough to (a) write an
explicit, evidenced differentiation record — not an assumption — showing how
our generator's design differs structurally, and (b) learn anything
legitimately useful from their approaches (methods and ideas aren't
copyrighted; only their literal code/text is, and under GPL-2.0/GPL-3.0
specifically, copying or closely deriving code creates copyleft obligations
we want to avoid entirely, not just attribution obligations).

Separately, our design has one specific, already-flagged unknown: VTSG
composes a vulnerable case into a **single generated file** (its own `TODO`
notes it has no concept of matched pairs, and its file-composition model
doesn't address multi-file output at all). Our cells are **full framework
routes** — a controller, a model/ORM call, a view/template, sometimes
middleware — spread across multiple files in a real web-framework project
structure (Laravel, FastAPI, Express). Nothing in our research so far has
confirmed whether VTSG's module-composition idea actually extends cleanly to
that multi-file, routed shape, or whether it needs real rework.

## Research areas

### 1. OWASP Benchmark's actual architecture (GPL-2.0 — read for differentiation, not reuse)

Investigate, from the actual `OWASP-Benchmark` GitHub organization and its
generator tooling (not just the project's marketing page): how are the
~2,740 test cases actually produced — is there a generator/templating tool
at all, or is each vulnerability category more hand-authored with
parameterized variants? What's the code organization (one Java class per
case? A shared base with category-specific subclasses? Something else)? How
does it express "this case is vulnerable" vs. "this case is safe" — is there
anything resembling a decision table, a manifest, or is the label simply
implicit in which method was called? Does it have any concept of minimal
pairs (a vulnerable/secure twin differing only in the fix)? Report exactly
what you can confirm by reading the repository directly versus what's only
described in secondary sources. This is explicitly to compare architectures,
not to adapt any of its code or templates.

### 2. Architectural detail on the other cited "spirit" precedents

For DVWA, Mutillidae II, WebGoat, bWAPP, XVWA, and Google Gruyere: confirm
each project's actual current license (don't assume it's still what it was
years ago), and get enough real architectural detail to characterize how
each actually produces its vulnerable/secure pages — hand-authored PHP/Java
files with a difficulty-level toggle (DVWA's known pattern), a lesson-plugin
architecture (WebGoat), or something else. For any that are copyleft
(GPL-2.0/GPL-3.0 or similar), flag it clearly and note the same
read-for-differentiation-only posture. For any that are permissively
licensed (MIT/Apache-2.0/BSD), note whether there's anything actually worth
adapting (schema or methodology, never literal code) the way VTSG's schema
was adaptable. Prioritize depth on DVWA and WebGoat, since they're the most
architecturally distinct from VTSG (WebGoat's plugin-lesson model in
particular is a different shape worth understanding).

### 3. VTSG's flagged unknown: does module composition survive real framework routing?

This is the most important area in this report. VTSG composes a vulnerable
case into one file from `inputs.xml`/`filters.xml`/`sinks.xml`/
`complexities.xml`. Our cells need controller + model + view (+ middleware)
across multiple files in a real framework's directory structure. Research
whether **any** benchmark-generation or vulnerable-app-generation project —
academic or open-source, in any language — has actually solved multi-file,
framework-routed composition from reusable modules, not just single-file
composition. Look specifically at: any published follow-up or extension to
VTSG/SARD that addresses web-framework routing; any of the newer LLM-era
benchmarks (CASTLE, SecCodePLT, SafeGenBench, RealSec-bench,
SecureAgentBench — already partially surveyed in prior research for this
project) that generate code with a routing/controller layer rather than
bare functions, and how they structure that; and any general software-
engineering literature on "scaffold + fill" or "skeleton + fragment"
code-generation approaches for multi-file web application scaffolding
(this doesn't have to be security-specific — Rails/Laravel/Django
scaffolding generators solve a structurally similar "compose a routed
feature from a template + fragments across multiple files" problem, and are
worth investigating as a *non-security* architectural analogy). If you find
nothing that solves this directly, say so plainly, and give your own
reasoned proposal for how a `(source, transform, sink, complexity)` module
set could map onto a `route + controller + model-call + view-fragment`
structure — e.g., does "sink module" become "controller code," does
"complexity" become "how many layers of helper/service the call passes
through," does the view/template become a fifth module category VTSG
doesn't have at all?

### 4. Juliet's and SecCodePLT's hand-authoring specifics

For the ~20–30% of Juliet flaw types that had to be hand-written rather than
generated by its template engine (already known from prior research), find
whatever detail exists on *how* those were authored differently — was there
still a lighter-weight template, or fully bespoke code per case? For
SecCodePLT, whose 153 seed tasks are function-level (not framework-routed),
research whether its authors documented anything about the difficulty or
process of authoring a *seed* specifically (as opposed to the LLM-mutation
step, already covered by prior research) — team composition, time spent, or
any stated lessons about what makes a good seed. This directly informs how
we should structure our own Tier-B (hand-written, deliberately-hard class)
authoring process.

## Output format

Produce a structured report: a short executive summary, then one clearly
headed section per research area above. Areas 1 and 2 should each end with
an explicit comparison table: **their architecture** vs. **our architecture**
on the axes that matter for differentiation (verdict model: asserted vs.
derived; code organization: hand-authored vs. templated vs. modular
composition; pairing: none vs. minimal-pair; labeling: implicit vs.
out-of-band machine-readable contract; license). Area 3 should end with a
concrete recommendation for how our module schema should be extended (or
confirmed unchanged) to handle multi-file framework routing, stated
precisely enough that it could go directly into an update to our emitter
design. Close with: (a) the differentiation tables consolidated into one
place; (b) the routing-composition recommendation from area 3; (c) anything
from area 4 worth adopting for our Tier-B authoring process; and (d) open
questions or gaps you couldn't resolve. Cite sources inline with URLs and
dates — and be explicit throughout about measured (read directly) vs. cited
(secondary source) confidence, since that distinction is the point of the
licensing-related areas.
