You are a senior application-security researcher and security test-lab
architect. I need a rigorous, cited research report to inform the design of the
next phase of a manifest-driven vulnerable-lab generator. Use web search
extensively. Prefer authoritative, recent sources (roughly the last 18–24
months for anything you call "current"), cite every non-obvious claim with a
URL and its publication date, and clearly separate established practice from
experimental ideas. Where evidence conflicts or is thin, say so.

## Context (read before researching)

I maintain `fuzzlab`, a modular injection security-testing toolkit, exercised
against a self-hosted, deliberately vulnerable local web app I call "Puppy Fort
Factory" (in the same spirit as DVWA, Mutillidae, OWASP Juice Shop, WebGoat).
This is authorized, educational security research on infrastructure I own —
loopback-only, never exposed, and traffic-sending tools require an explicit
`--authorized` flag. Keep the report defense/research-oriented: how to build a
realistic, safe, well-labeled training/benchmark lab, not operational
instructions for attacking third parties. Do not reproduce verbatim vulnerable
source code from any proprietary or copyrighted codebase — describe root-cause
patterns abstractly enough that I can reimplement them as original code.

**Current state.** The app is a hand-authored PHP 8.3 (Apache) + MariaDB
monolith, ~30 pages, classic e-commerce feature set (catalog, cart, accounts,
blog, search). It has a documented, hand-labeled mix of vulnerable/secure pages
(mostly classic SQL injection — error/UNION/time-based/blind — and reflected/
stored/DOM XSS), plus a `references/` catalog of 64 vulnerability-class payload
folders (SSRF, SSTI, XXE, IDOR, JWT, GraphQL injection, NoSQL injection,
prototype pollution, deserialization, mass assignment, open redirect, request
smuggling, CSRF, race conditions, business-logic errors, etc. — most of these
classes are cataloged but not yet built into the lab). Ground truth is a
machine-readable, out-of-band contract (`labels.json`, `expectedresults.csv`,
`injection-points.json`) with opaque case IDs never served by the app; the
vulnerable/secure verdict is meant to be *derived* from `(transform, sink
context)`, never hand-asserted. A prior research pass (captured in this repo as
`docs/app-scaling-research-prompt.md`) already produced the decision to grow
the lab via a **manifest-driven generator** ("lab as a compiler": one manifest
+ a versioned safety matrix + a seed + an environment profile → a pure
generator emits the app, the labels, the docs, and the oracle tests) with two
planned tiers (a dense "range" tier for detection measurement, a realistic
"shop" tier) and build profiles (annotated / blind / all-secure). That decision
is settled; **do not re-litigate whether to build a generator** — this report
is about what should go INTO it next.

**The gap I want this report to close.** The lab is currently one hand-built
stack with textbook-style vulnerabilities. I want to push the generator design
so that it can emit a much larger, much more *varied*, and much more
*realistic* set of labeled training cases:

1. **Realism** — vulnerability instances that reflect patterns actually
   observed in current, real-world applications and disclosed incidents, not
   just canonical textbook payloads.
2. **Currency** — modern backend stacks, frameworks, ORMs, templating engines,
   and coding conventions (not only vanilla PHP + raw `mysqli` calls), since a
   detector trained only against one legacy stack will not generalize.
3. **Variation** — the generator should be able to produce many distinct,
   independently-labeled lab instances/cells that differ along real axes
   (stack, sink, framework idiom, data shape, difficulty), maximizing the
   diversity of the resulting training dataset rather than producing many
   near-duplicate cases.

## Research areas

For EACH area, research optimal approaches, concrete techniques/libraries/
sources, prior art, pitfalls, and how to maximize realism, variation, and
labeling accuracy at scale. Rate maturity (established / experimental / likely
overkill for a solo local project).

1. **Real-world vulnerability corpus mining.** Identify good, legally/ethically
   usable sources of *current* real-world vulnerability patterns to ground the
   lab's cells in reality rather than textbook payloads: CVE/NVD entries,
   GitHub Security Advisories, disclosed HackerOne/Bugcrowd report write-ups,
   conference talks and vendor blog post-mortems (2023–2026), the current OWASP
   Top 10 (Web), OWASP API Security Top 10, and the latest CWE Top 25. For a
   representative sample spanning our existing `references/` category list
   (SQL injection, XSS, SSRF, SSTI, XXE, IDOR/BOLA, JWT, GraphQL injection,
   NoSQL injection, prototype pollution, insecure deserialization, mass
   assignment, open redirect, CORS misconfiguration, request smuggling, CSRF,
   race conditions, business-logic errors), find 2–3 recent, well-documented
   real instances each, note the tech stack and the exact code-level root-cause
   pattern (not full exploit chains), and describe how that pattern could be
   turned into a manifest-safe, labeled lab cell. Flag which classes have rich
   recent public write-ups versus which are hard to source realistically.

2. **Modern tech-stack and framework coverage.** Using current developer/
   framework popularity data (Stack Overflow Developer Survey, State of JS/
   State of Backend-style surveys, RedMonk language rankings, GitHub Octoverse,
   or similar — cite the specific recent edition), identify which backend
   stacks are most representative of what real applications run today. For
   strong candidates (e.g. Node.js/Express, Next.js/React SSR, Python Flask/
   Django/FastAPI, Ruby on Rails, Java Spring Boot, Go with a common router,
   PHP with Laravel/Symfony, .NET/ASP.NET Core), catalog per stack: the
   idiomatic *unsafe* vs. *safe* sink APIs for each major vulnerability class
   (raw string-built SQL vs. parameterized/ORM query builders — Prisma,
   TypeORM, Sequelize, SQLAlchemy, ActiveRecord, Hibernate/JPA, Eloquent, GORM,
   Entity Framework), templating engines and their default auto-escaping /
   SSTI-prone constructs (Jinja2, EJS, Handlebars, ERB, Thymeleaf, Blade,
   Razor), common auth/session conventions (JWT library defaults and known
   misconfigurations, OAuth2/OIDC flows, cookie/session handling), and typical
   REST/GraphQL API shapes (JSON bodies, OpenAPI, GraphQL resolvers). Recommend
   which 3–5 stacks give the best realism/variation return per engineering
   effort for a generator to target next, and which to explicitly defer.

3. **Maximizing generated variation without inflating noise.** Research how to
   structure a manifest + safety-matrix so one generator run can emit a large
   number of *distinct, independently and correctly labeled* cells by combining
   orthogonal axes — vulnerability class × sink context × stack/framework ×
   ORM/templating idiom × data/parameter shape (name, location, encoding) ×
   difficulty/obfuscation tier × a paired secure counterpart — while avoiding a
   combinatorial explosion of near-duplicate, no-added-signal cases. Study how
   existing large labeled benchmarks and vulnerability datasets control this:
   OWASP Benchmark, NIST SARD/Juliet test suites, and recent (2023–2026)
   ML-for-appsec datasets and papers on synthetic vulnerable-code or fuzzing-
   training-data generation (e.g. CVEfixes, Big-Vul, DiverseVul, and follow-ups
   to VulDeePecker-style work). Extract what variation axes they use, how they
   avoid superficial features that let a model "shortcut" instead of learning
   the real vulnerability signal, and how they measure or report dataset
   diversity/coverage.

4. **Realistic surface and business-logic depth.** Beyond single-endpoint
   injection points, research what real modern applications add that produces
   genuinely different training signal: authenticated multi-step flows,
   stored/second-order and blind variants, IDOR/BOLA on REST/GraphQL resource
   endpoints, JSON API bodies vs. form encoding, webhook/callback endpoints
   (for realistic SSRF), third-party integration patterns (payment, search,
   notification webhooks), and business-logic/rate-limit flaws. Cite how
   existing modern intentionally-vulnerable projects structure this realism
   (crAPI, OWASP Juice Shop, VAmPI, NodeGoat, RailsGoat, WrongSecrets, iGoat) so
   the "shop" realism tier can add depth without unbounded scope creep.

5. **Determinism, labeling, and safety at higher variation.** More stacks and
   frameworks likely mean more runtimes/containers. Research how to preserve
   the existing pinned-environment/byte-identical-regeneration guarantee and
   the out-of-band, opaque-ID label contract when the generator targets
   multiple language runtimes (one polyglot generator emitting per-stack
   containers that still share one ground-truth contract? separate generator
   backends per stack sharing a schema?). Note how to keep the lab's existing
   safety invariants (loopback-only, no traffic without explicit
   authorization, no vulnerability-class name leaking into any URL/filename/
   parameter) intact as the number of generated stacks and cells grows by an
   order of magnitude or more.

## Output format

Produce a structured report with a short executive summary, then one clearly
headed section per research area above. In each, give the recommended approach
and 1–2 alternatives with tradeoffs, concrete techniques/libraries/sources,
prior-art comparison, specific pitfalls, and a maturity rating. Then provide:
(a) a recommended extension to the manifest/safety-matrix schema that adds
stack/framework and real-world-pattern axes without breaking the existing
`(transform, sink context)` verdict-derivation model; (b) a prioritized,
phased plan for folding this into the existing Lab Phase 0–4 track; (c) a
curated table of real-world example → adapted-lab-cell mappings for a first
wave of classes and stacks (source URL + date, stack, root-cause pattern,
proposed cell shape); and (d) open questions and decisions I still need to
make. Cite sources inline with URLs and dates, add a final reference list, and
flag anything that is hype or not worth the effort at solo/local scale.
