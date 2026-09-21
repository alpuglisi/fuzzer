You are a senior application-security engineer and security test-lab architect. I
need a rigorous, cited research report on how to efficiently grow a deliberately
vulnerable web application used as a local test target. Use web search
extensively. Prefer authoritative, recent sources, cite every non-obvious claim
with a URL and its publication date, and clearly separate established practice
from experimental ideas.

## Context (read before researching)

I maintain a deliberately vulnerable web application as a local, isolated test
target for my own security tooling. This is authorized, educational security
research on infrastructure I own, in the same spirit as DVWA, Mutillidae, and
OWASP Juice Shop. Keep the report architecture- and defense-research-oriented:
focus on how to build and scale a safe, well-documented test lab, not on
operational instructions for attacking third parties.

Current state of the app ("Puppy Fort Factory"):
- Stack: PHP + MySQL/MariaDB served by Apache on localhost. Deployed by a script
  that copies files into the web root.
- Size: ~30 pages, about 10 of them JavaScript-rendered. A typical e-commerce
  feature set (catalog, cart, accounts, blog, search, etc.).
- It contains a deliberate mix of vulnerable and secure pages. Vulnerabilities
  present include SQL injection (error/UNION/time-based and blind), reflected and
  stored XSS, and DOM-based XSS. "Secure" here means free of those classes.
- Ground truth is documented by hand in a VULNERABILITIES.md map (per-page:
  vulnerable vs secure, class, parameter, example payloads). A payload-category
  taxonomy lives in a references/ folder.
- The app is the target for my own tools: a JavaScript-rendering crawler, an
  injection-point auditor, and a blind-SQLi fuzzer. Those tools rely on the
  ground-truth labels to measure detection accuracy and to train ML models.

Goal: efficiently increase both the SCALE (many more pages) and the COMPLEXITY
(more vulnerability classes, more instances, and graduated difficulty) of the
app, adding BOTH more non-vulnerable pages (realistic true negatives) and more
vulnerable pages (true positives), without hand-writing and hand-documenting each
one. "Efficiently" is the key word: I want to multiply coverage with minimal
per-page effort while keeping the lab coherent, reproducible, and accurately
labeled.

## Research areas

For EACH area, research optimal implementation approaches, pitfalls to avoid,
architectural considerations, optimizations, and how to maximize robustness,
scalability, and modularity. Compare relevant prior art and cite it.

1. Generating many pages with little per-page effort. Templating, scaffolding,
   data-driven page definitions, and code generation. How to define a page (its
   content, parameters, data source, and behavior) as data and render many pages
   from a few templates. Approaches for generating realistic benign content
   (products, posts, users, orders) at volume.

2. Scaling vulnerability coverage WITH ground truth. Techniques for
   parameterized or synthetic generation of vulnerable and secure endpoints from
   a specification, so each generated endpoint carries a known label. Study how
   large labeled vulnerability corpora are produced: OWASP Benchmark, NIST SARD
   and the Juliet test suites, and how intentionally vulnerable apps organize
   many cases (DVWA difficulty levels, Mutillidae, OWASP Juice Shop challenge
   model, WebGoat, bWAPP, XVWA, Google Gruyere). Extract the patterns that let
   them scale case count while keeping ground truth exact.

3. Increasing realism and complexity, not just count. Authentication states and
   roles, REST and GraphQL APIs, multi-step flows, stored/second-order and blind
   variants, and chained vulnerabilities. Graduated difficulty tiers per class
   (e.g. easy/medium/hard/secure) and how to express them without duplicating
   whole pages. Broadening beyond SQLi/XSS to more classes (SSRF, IDOR, file
   inclusion, command injection, SSTI, XXE, open redirect, CSRF, deserialization,
   etc.).

4. Keeping ground truth and documentation correct at scale. The risk that a
   generator introduces accidental vulnerabilities into "secure" pages, or drifts
   from the documented labels. Research single-source-of-truth designs where one
   machine-readable manifest generates the app, the label map, and the docs
   together; plus a verification/self-test harness that confirms each page's
   actual vuln/secure status matches its label. Reproducibility and determinism
   of generation.

5. Stack and integration decision. Whether to stay with plain PHP/MySQL, add a
   lightweight router or templating layer, or adopt a framework (e.g. Laravel or
   Symfony), weighed against the cost of rewriting. How the chosen approach keeps
   the app compatible with an Apache-on-localhost deploy and with external tools
   that crawl, audit, and fuzz it, and how to expose the ground-truth labels in a
   machine-readable form those tools can consume.

## Output format

Produce a structured report with a short executive summary, then one clearly
headed section per research area. In each, give the recommended approach and
1-2 alternatives with tradeoffs, concrete techniques/libraries/patterns, a
prior-art comparison where relevant, specific pitfalls, optimizations, and
robustness/scalability/modularity notes. Then provide: (a) a recommended overall
architecture for an efficient, label-accurate app generator; (b) a prioritized,
phased plan to grow the app in both benign and vulnerable coverage; and (c) open
questions and decisions I still need to make. Cite sources inline with URLs and
dates, add a final reference list, and flag anything that is hype or not worth
the effort at solo/local scale.
