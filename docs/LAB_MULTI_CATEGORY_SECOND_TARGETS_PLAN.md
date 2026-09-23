# Second lab target — `node_express`, implementation plan

**Status: planning only — nothing in this document has been executed.** This
plan exists to size and sequence the work before any of it is dispatched,
per this project's own standing discipline of not building through an open
question speculatively (see `docs/LAB_IMPLEMENTATION_PLAN.md`'s own framing).

## 0. Why this exists, and what's already decided

`docs/DECISIONS_AND_ROADMAP.md`'s "Deferred decisions" list has carried
**"Second target app — decide when generalization becomes a goal, after the
core toolkit works"** since early in the project. All ten toolkit phases
are now code-complete offline (only live-infra exit measurements remain,
tracked in `docs/ON_HOST_TASKS.md`), and the reconciliation of this
session's parallel lines of work is done — the project owner judged this
the right point to make that deferred call.

**Decided (this session, by the project owner, in order):**

1. The second target is **a second manifest-generated app**, not an
   external independently-built lab (Juice Shop/WAVSEP were the
   alternative, per D10's own naming of them for the "realism"/
   "scanner-benchmark" validation tiers respectively) — cheaper, reuses the
   existing generator/module/conformance machinery, and is what the
   already-built-but-unused `fuzzlab/harness/multitarget.py`/`TargetSpec`
   plumbing was built to consume.
2. The stack is **`node_express`**, chosen over `python_fastapi` (the other
   existing shallow "Tier-A" stack) specifically for generalization value:
   Node/Express has a much larger real-world security-research footprint
   (most of this session's own corpus examples under
   `docs/research/corpus-examples/` drawing on real Node CVEs are Express
   apps), and fewer built-in framework guardrails than FastAPI+Pydantic's
   default type coercion, which tends to map vulnerability shapes more
   directly/idiomatically rather than requiring the shape to route around
   the framework's own validation first.

3. **Phase C's page-content question is decided (2026-09-22): corpus-
   grounded**, not original content. See §4a below for what this expands
   into and §0b for the open questions this creates that need an answer
   before any of §4a is dispatched.

## 0a. Scope expansion (2026-09-22, per direct instruction)

The project owner's instruction, recorded here in full rather than
paraphrased down to a decision line, because several parts of it are new
requirements this plan did not previously scope:

> The answer to phase C's question is corpus grounded pages. We have
> research on a few different categories of websites, their architectures,
> and tech stacks. There may or may not be research on features and
> functionalities of each website. This was supposed to be done but may
> have been overlooked, in which case you will need to do the research. We
> are going to generate 2 new manifest generated web applications per
> website category in the research. The generated applications should be
> based on actual tech stack and functionality of the websites in the
> category. Each new application will use corpus grounded pages. CWEs based
> on the researched tech stacks and architectures were specifically
> researched to facilitate implementation in these applications. The goal
> is applications that reflect what would be observed in real life with
> vulnerabilities placed realistically. If more research is required to
> achieve this, feel free to do so. https://cwe.mitre.org/top25/ is a good
> resource. When designing the pages and deciding on vulnerabilities take
> into account that we are also trying to expand categories of
> vulnerabilities and expand the type of vulnerabilities.

**What this means, broken into concrete requirements:**

1. **Scope: 12 new apps, not 1.** `docs/research/site-architecture-survey.md`
   (Steps 1-2 of `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md`)
   currently documents **6 categories** (E-commerce/marketplaces, Social/
   UGC platforms, SaaS/productivity/collaboration, Media/streaming/content
   platforms, Travel/booking/marketplaces, Fintech/payments), each with 5
   real, cited sites and real, sourced architecture write-ups. **Two new
   manifest-generated apps per category** — 12 total — each based on the
   *actual* tech stack and functionality of (some subset of) that
   category's real researched sites.
2. **Verified finding: the functionality-research gap is real, not
   hypothetical.** I checked `docs/research/site-architecture-survey.md` in
   full against this instruction before writing this section. Every
   category's write-up is genuinely thorough on **architecture** (backend
   language/framework, database, hosting, confidence-rated, multi-sourced)
   but contains **no equivalent per-site feature/functionality research** —
   no breakdown of what a real Amazon/Shopify/Etsy/Walmart/WooCommerce page
   actually *does* (checkout flow shape, review system, seller-dashboard
   permissions, search/filter behavior, etc.), the way
   `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s own base-plan Phase 1 did for the
   *abstract* feature catalog. This confirms the project owner's suspicion:
   **this research was not done and must be done** before Phase C-per-app
   page design can proceed on real grounding rather than invention. This is
   new work, not a re-read of something already there.
3. **CWE research must be tied to each app's actual tech stack/
   architecture, not just its abstract vulnerability class.** The existing
   corpus's own CWE-research discipline (`docs/VULN_CORPUS_SITE_ARCHITECTURE_
   EXPANSION_PLAN.md` Step 6 — MITRE CWE index lookups, `cwe_shared`/
   `cwe_unique` floor, per-entry rationale grounded in the entry's own code)
   is the right *mechanism* and should be reused, not redesigned — but it
   was applied to individual collected code snippets, not to "what would a
   real `<stack>` app in `<category>` realistically have wrong with it."
   This instruction asks for the latter, additionally: given a chosen
   real site's actual stack + a real feature it has, research which CWEs
   are realistically introduced by *that combination specifically*
   (framework-specific footguns, stack-specific default-insecure
   configurations, version-specific known-CVE-shaped patterns), not only
   "this code sample happens to have CWE-X." **`https://cwe.mitre.org/
   top25/` is named explicitly as a resource** — used as one input among
   others (the corpus's existing MITRE-index-lookup discipline, the
   architecture survey's own sourcing standard), not the sole source.
4. **Deliberate vulnerability-class breadth is a design constraint, not a
   side effect.** When choosing which vulnerabilities go on which pages,
   actively check candidate CWEs against what `lab/safety_matrix.yaml`
   and the existing corpus (`docs/research/corpus-examples/`) already
   cover, and against the CWE Top 25, and prefer classes that **expand**
   real coverage over classes that duplicate it — mirroring the reasoning
   `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`'s own §4 recommendation
   already used for the single-app version of this plan (prefer SSRF/SSTI/
   header-injection/insecure-deserialization/webhook-signature-shaped
   classes the current `php_laravel` lab doesn't model at all, over a
   fourth SQLi variant).
5. **"Reflect what would be observed in real life, placed realistically"**
   is the standing bar for every page: a vulnerability should exist because
   the real site's real stack/feature combination would plausibly produce
   it (a known framework footgun, a realistic developer mistake for that
   exact stack), not because it was the easiest shape to template.

## 0b. Open questions this scope expansion creates — need an answer before §4a is dispatched

These are genuine ambiguities the instruction above doesn't resolve, laid
out rather than guessed at, per this project's own standing discipline
(`docs/MULTI_AGENT_ORCHESTRATION.md` §5 — flag genuine risk/ambiguity
rather than silently pick an interpretation for a decision this size):

1. **Does "actual tech stack ... of the websites in the category" override
   or coexist with the already-made "stack = `node_express`" decision
   (§0.2)?** The six categories' real architecture research names Ruby on
   Rails (Shopify), legacy-PHP (Etsy, WooCommerce), Node.js/Java
   microservices (Walmart), and AWS-service-oriented (Amazon) for
   e-commerce alone — none of which is uniformly `node_express`. Three
   readings are all plausible from the instruction as given:
   - **(a) Stack-mapped:** for each of the 12 apps, use whichever of the
     project's existing emitters (`php_current`/`php_laravel`,
     `python_fastapi`, `node_express`) most closely matches that app's
     real-site stack, and pick which 2 sites per category to model
     specifically so their real stacks land on emitters that already
     exist — i.e., let existing-emitter coverage help choose *which* 2
     of each category's 5 sites become the 2 apps.
   - **(b) New-emitters-as-needed:** take stack fidelity literally and
     build new emitters for stacks the project doesn't have yet (Ruby/
     Rails, Java, etc.) where a category's real leading sites need one —
     a substantially larger effort than anything in this plan's Phases
     A-B, and its own multi-week-scale undertaking per new stack.
   - **(c) `node_express`-only:** keep the earlier decision as the
     universal implementation stack for all 12 apps regardless of a given
     category's real dominant stack, and satisfy "based on actual tech
     stack" at the level of *functionality/behavior* (the app behaves like
     a real Shopify-style storefront) rather than *language/framework*
     identity.
   **This plan does not pick one — it needs the project owner's call**,
   since (b) in particular changes this plan's total scope by roughly an
   order of magnitude versus (a)/(c).
2. **Which 2 of each category's 5 already-researched sites become the 2
   apps?** (E.g. for e-commerce: Amazon-style marketplace vs. WooCommerce-
   style single-store are architecturally the most distinct pairing among
   the 5 researched — but this is an example, not a proposal to treat as
   decided.) Should site selection be driven by (i) architectural
   distinctness within the category (maximize what's learned), (ii)
   real-world popularity/representativeness, or (iii) which 2 stacks
   happen to map to emitters that already exist (only relevant if question
   1 resolves to reading (a))?
3. **Does this 12-app initiative fold in and supersede the single-
   `node_express`-app plan (§§1-7 above), or run alongside it as a
   separate, additional effort?** If question 1 resolves to (a) or (c) and
   one of the 12 new apps ends up being `node_express`-based and serves the
   same generalization purpose §§1-7 describe, that single app may *be*
   one of the 12 rather than a 13th, separate build — but this plan
   currently treats §§1-7 as their own, already-scoped unit and should not
   silently absorb or duplicate effort with §4a without an explicit call.
4. **Sequencing/sizing.** 12 apps × (functionality research + CWE research
   + page design + module-inventory depth + Tier 0-3 conformance +
   bookkeeping) is a substantially larger undertaking than anything else
   built this session, closer in scale to the entire `php_laravel`
   migration's history than to any single lane. Should this be piloted on
   one category first (prove the full research → CWE → pages → conformance
   pipeline once, end to end) before committing to all 6, mirroring how
   the base vulnerability-corpus plan itself phased into waves rather than
   dispatching all categories simultaneously?

## 1. Current state of `node_express` (verified against the code, not assumed)

- `fuzzlab/labgen/emitters/node_express/__init__.py` (242 lines),
  `modules.py` (267 lines), `stack_env.py` (88 lines) — comparable in size
  to `python_fastapi`'s equivalents, both meaningfully shallower than
  `php_laravel`'s full-depth build.
- One manifest currently targets it (`grep -l node_express lab/manifests/
  *.yaml` — 1 hit), vs. 11 for `php_laravel`.
- **No checked-in bootable skeleton.** `php_laravel/stack/skeleton/` (a
  real, trimmed `composer create-project laravel/laravel` output) has no
  Node equivalent. `node_express/stack_env.py` exists (88 lines) but this
  has not been read in detail as part of this plan — Phase A's first task
  is to determine exactly how much of the "real assembled app" mechanism
  it already provides before writing anything new.
- **No live-boot conformance harness.** `LiveBootHarness`
  (`fuzzlab/labgen/conformance/live_boot.py`) is `php_laravel`-specific;
  there is no `NodeLiveBootHarness` or equivalent. Tier 1/2 conformance for
  `node_express` is `[design]`-only, per the last full architecture audit.
- **Environment check (this sandbox, done for this plan):** `node` v22.22.2
  and `npm` v10.9.7 are both on `PATH`. A local Node boot-and-serve
  conformance harness is buildable and testable in this sandbox today —
  no container/Docker daemon needed for this part, exactly the same
  situation `php_laravel`'s `LiveBootHarness` was in with `composer`/`php`.

## 2. Phase A — real bootable skeleton + boot harness

**Goal:** the Node equivalent of `php_laravel`'s
`LiveBootHarness`/`SKELETON_DIR` — a real, checked-in, trimmed Express app
skeleton, and a harness that assembles a manifest's rendered output onto
it, runs a real `npm install`, boots the app for real, and lets a caller
make real HTTP requests against it.

Tasks:

1. Read `node_express/stack_env.py` in full first — do not assume it's
   empty or equivalent to what's needed; it may already provide part of
   this.
2. Produce a real, minimal Express skeleton (analogous to `php_laravel`'s
   trimmed `composer create-project` output) — a real `npm init`/`express-
   generator` output with dev-only tooling stripped, checked in under
   `fuzzlab/labgen/emitters/node_express/stack/skeleton/` (mirroring
   `php_laravel`'s own directory shape) with a README recording exact
   provenance and the trim list, per that directory's own convention.
3. Build `NodeLiveBootHarness` (or fold into a renamed shared module if the
   overlap with `LiveBootHarness` turns out large enough to warrant a
   shared base — a judgment call to make once both are visible side by
   side, not decided here) with:
   - A real capability probe, `node_boot_available()` — built correctly
     the first time per `PA-0035`'s rule (a probe must exercise the actual
     operation path: a real, bounded `npm` operation against the actual
     registry a real `npm install` would use, respecting any configured
     proxy — never a bare socket/DNS check standing in for it). This is
     the exact class of mistake `BUG-0033` was; do not repeat it for a new
     package manager.
   - Real assembly: copy the skeleton, overlay a manifest's rendered
     `EmittedFiles`, accumulate routes (whatever `node_express`'s own
     route-registration convention is — read `route_fragment_for` in the
     existing emitter before assuming Express's own `Router` shape maps
     directly onto `php_laravel`'s route-accumulator design).
   - Real `npm install`, real process boot (`node server.js` or
     equivalent), real HTTP requests via the same `urllib.request`-based
     client pattern `LiveBootHarness` already uses (no new HTTP client
     abstraction needed).
   - A real per-run database. SQLite via a Node driver (`better-sqlite3` or
     `node:sqlite` if the pinned Node version ships it — v22 does carry an
     experimental `node:sqlite` built in, worth checking before adding a
     dependency) to mirror `LiveBootHarness`'s own SQLite-for-testing /
     MariaDB-for-production split, rather than inventing a different
     persistence story for this stack.
   - Bounded timeouts on every real subprocess step (install, boot,
     request), enforced at the shared runner, not left to each call site —
     `PA-0035`'s second half, applied from day one instead of retrofitted.
4. One minimal, real, executed test: assemble+boot+serve a single
   illustrative cell, prove a real payload differential end to end (the
   same bar `php_laravel`'s very first live-boot test set).

**Bookkeeping owed:** `CC-LAB-NNNN`/`FR-LAB-N` (verify next-free at dispatch
time), a `CHANGELOG.md` line, and the full bug protocol for any genuine
defect surfaced building this (a new capability probe and a new
package-manager integration are exactly the kind of code most likely to
hide one, per this project's own recent history with `BUG-0029`/`0033`).

## 3. Phase B — deepen the module inventory to full depth

**Goal:** bring `node_express`'s op/sink/source registry up to parity with
the shared vocabulary already accumulated in `lab/safety_matrix.yaml` —
redoing, for Node, what `L-P3.3b` did for `php_laravel`.

Tasks:

1. Diff `node_express`'s current `_MODULE_SET_BY_SHAPE` (or equivalent)
   against the full `lab/safety_matrix.yaml` vocabulary to get an exact
   gap list — do not estimate this, compute it.
2. For each missing `(vuln_class, sink_family)` shape already proven on
   `php_current`/`php_laravel`, write the Node/Express-idiomatic module
   (source/transform/sink) — reusing the shared minimal-pair vocabulary
   convention (register in the shared registry even where only one stack
   renders a given shape, exactly as `L-P3.3c-DOM`'s `dom_url_source` was
   registered in `php_current`'s registry despite being render-only there).
3. Cover, at minimum, the shape classes every other full-depth stack has:
   SQLi (value and identifier position), XSS (body, attribute, DOM), and
   the two newest classes this session added (mass-assignment,
   `orm_entity_bulk_assign`'s ORM-equivalent for whatever Node ORM/query
   builder the skeleton uses — Sequelize/Knex/raw `pg`/`sqlite3`, a choice
   Phase A's skeleton decision determines).
4. Tier 0 (lint — Node's own syntax-check equivalent, e.g. `node --check`)
   and Tier 3 (whole-manifest regenerate-and-diff, byte-deterministic) for
   every new cell, exactly like every other emitter's own build gate.

**Sequencing note:** this phase can start once Phase A's skeleton/harness
shape is settled (module templates need to target real file paths/route
conventions Phase A defines), but the module-writing work itself doesn't
need Phase A's harness *running* — Tier 0/3 conformance doesn't require a
real boot. Phase A's live-boot proof and Phase B's module breadth can
proceed as two concurrent lanes once Phase A's skeleton structure (not its
full harness) is fixed, mirroring this project's own multi-lane
parallelization discipline (`docs/MULTI_AGENT_ORCHESTRATION.md`) — flagged
here rather than assumed serial, but not committed to a lane map until
Phase A's skeleton decisions actually land (a lane map drawn now would be
speculating on an interface that hasn't been designed yet).

## 4. Phase C — its own identity and ground truth (page-content question now decided; scope expanded — see §0a/§0b/§4a)

**Goal:** a genuinely separate app — its own name, its own coherent page
set, its own `labels.json`/`injection-points.json` ground truth, never
reusing `puppy-fort-factory`'s (or its successor generated lab's) case IDs
or identity. Generalization evidence means nothing if the "second" target
is secretly the first one's cases relabeled.

**Decided (2026-09-22): corpus-grounded, not original content** — see §0a
item 1. This applies to the single-app version of Phase C described below
*and* is the same rule §4a's 12-app expansion uses; §4a does not restate
the reasoning, only the added scope.

Reasoning recorded for why corpus-grounded won (kept for context, not a
live decision anymore):

- **Corpus-grounded** gives the new app the same "modeled on real code
  shapes, not invented from memory" grounding this project's whole
  generator philosophy already rests on (see `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s
  own "Why" section) — and reuses research already done and reviewed this
  session, rather than inventing a second, parallel justification story.
- **Corpus-grounded** also means the new app(s) can exercise vulnerability
  classes the current `php_laravel` lab doesn't have at all yet (SSRF,
  SSTI, header injection, insecure deserialization, webhook signature
  bypass) — a genuinely different attack-surface profile, which is exactly
  what makes a transfer-generalization measurement meaningful rather than
  a repeat of the same classes on a different templating syntax.

**Note on scope:** this section (§4) was originally scoped to one app on
one stack (`node_express`, §0.2). §0a/§4a expand "corpus-grounded" into 12
apps across 6 researched categories, each requiring its own functionality
research (§0a item 2) and stack-specific CWE research (§0a item 3) *before*
the steps below can run per app. §0b's open questions (especially #1, the
stack-fidelity question) must be answered before treating any of the 12
apps as dispatchable — the steps below remain correct as a *template* per
app, just not yet sized or stack-assigned for all 12.

Steps, per app, once §0b is answered:

1. Pick a coherent page/route set spanning the chosen vulnerability classes
   (a small, self-consistent app identity matching a real researched
   site's actual functionality — not a loose bag of unrelated illustrative
   cells).
2. Author `labels.json`/`injection-points.json` for this app from scratch,
   with its own opaque case-ID scheme (never `PFF-*`), following
   `docs/DECISIONS_AND_ROADMAP.md` D9's existing out-of-band ground-truth
   contract.
3. Author the manifest(s) (vulnerable/secure twin pairs, one per chosen
   class) using Phase B's module inventory (or the corresponding module
   inventory for whichever stack §0b's question 1 resolves to for this
   app).

## 5. Phase D — Tier 1/2 conformance

Same standard `php_laravel` was held to: real boot, real HTTP, a real
payload differential proven for every cell in the new app's manifest(s),
using Phase A's harness. This phase is mostly mechanical once Phases A-C
land — it is "run the proof," not "design the proof."

## 6. Phase E — wire it into `multitarget.py`

1. Construct the new app's `TargetSpec` (`name`, `base_url` pointing at a
   locally-booted instance via Phase A's harness, `ground_truth` from
   Phase C's labels).
2. Run `fuzzlab/harness/multitarget.py` against **both** targets (the
   `php_laravel` lab and this new one) and confirm it actually produces
   per-target + macro metrics and a `generalizes` verdict — this is
   genuinely testable in this sandbox (both targets can be locally booted;
   no live/external infra needed for this proof).
3. This closes the *toolkit-side* half of Phase 10's `T10.6` exit
   criterion. The *other* half — the real, on-host measurement against a
   live production deployment — stays exactly as blocked as before; this
   plan does not change that.

## 7. What this plan does not do

- Does not build an external target (Juice Shop/WAVSEP) — that option was
  explicitly not chosen (§0).
- Does not attempt the live/on-host `T10.6` measurement itself — only the
  toolkit-side proof that a second target can be run and compared, which
  is the part actually blocked on nothing but being built.
- Does not resolve §0b's open questions (stack-fidelity approach for the
  12-app expansion, which 2 sites per category, whether the 12 apps
  subsume §§1-7's single app, sequencing/piloting) — flagged, not decided.
- Does not yet do the functionality-per-site research §0a item 2 found
  missing, or the stack-specific CWE research §0a item 3 asks for — both
  are real, sized work items for whenever §0b is answered and this plan
  moves from planning to execution.

## 8. Bookkeeping conventions for whoever executes this plan

Every phase above owes this repository's standard checklist per `CLAUDE.md`
— a `CHANGELOG.md` line, a `CC-LAB-NNNN` change-control entry (verify
next-free at dispatch time, not from this document, since other work may
land between now and execution), a `requirements.md` update, and the full
bug protocol for any genuine code defect surfaced along the way. If this
plan is executed via concurrent build lanes, pre-assign each lane's
bookkeeping numbers before dispatch per `docs/MULTI_AGENT_ORCHESTRATION.md`
§3/`PA-0031`, rather than letting each lane claim "the next free" one.

## 9. §0b answered — the 12-app expansion is now the plan (2026-09-22)

The project owner answered every §0b question directly:

1. **Stack fidelity is literal.** New emitters get built as needed for
   whatever a chosen site's real stack actually is — not mapped onto the
   three existing emitters as an approximation, and not kept universally
   on `node_express`. This is explicitly the larger-scope reading; treat
   it as authorized, not as something to re-confirm per category.
2. **Site-pair selection is driven by architectural distinctness** — for
   each category, pick the 2 of its 5 researched sites whose real stacks
   are most different from each other (and, where possible, from stacks
   already built for other categories — see the reuse note in §9.2).
3. **This 12-app initiative subsumes §§1-7.** The single-`node_express`-app
   plan above is not a separate, 13th build — §§1-7 remain useful as a
   worked template (the phase breakdown, the "verify the probe correctly
   the first time" discipline, the bookkeeping conventions) but
   `node_express` is no longer pre-selected as *the* second target; it is
   simply whichever category's distinctness pick happens to name it (or
   doesn't).
4. **Commit to all 6 categories, pilot one at a time, document
   continuously** so other Claude Code sessions can be assigned to the
   remaining categories concurrently. This is the operative instruction
   for how this section is structured below — §9.3 is the coordination
   contract every category (this session's pilot and every future
   session's category) must follow, precisely because concurrent sessions
   on this exact repository have already caused a real, costly bookkeeping-
   collision incident this session (three independently-diverged branches,
   reconciled at real effort cost — see the `reconcile-all-lines` work
   earlier this session). Do not repeat that failure mode here.

### 9.1 Site-pair/stack-selection methodology (apply this per category, don't re-derive it)

For each category, from its 5 researched sites in
`docs/research/site-architecture-survey.md`:

1. **Filter out sites whose real architecture isn't a sensible generator
   target.** This generator models request/response HTTP applications
   (`Cell`/`Route`/`Pipeline` IR — a page, a parameter, a sink). A site
   whose documented architecture is fundamentally a realtime/protocol
   system (e.g. Discord's WebSocket/Elixir presence layer) or an
   infrastructure-only case study with no confirmed application-language
   claim (e.g. Disney+, Trip.com — both explicitly marked "unconfirmed at
   the application-code level" in the survey) is not a good candidate;
   note the exclusion and its reason rather than silently skipping it.
2. **Group the remaining sites by (language, architectural paradigm)** —
   paradigm meaning things like "traditional synchronous MVC monolith"
   vs. "async/microservice API" vs. "service-oriented with a BFF layer."
   Two sites in the same language *and* the same paradigm are not
   architecturally distinct for this purpose even if their companies
   differ (e.g. Etsy's legacy PHP monolith and WooCommerce's PHP/WordPress
   plugin model are both "PHP, synchronous, template-rendering" — picking
   both would not add distinctness).
3. **Pick the 2 groups that are most different from each other**, then
   pick one representative site from each.
4. **Reuse-vs-new check, in this order of preference (distinctness still
   wins if it conflicts):** if two groups are comparably distinct and one
   of them matches a stack this project has *already built* (currently:
   PHP via `php_current`/`php_laravel`, Node/Express via `node_express`),
   prefer the group that reuses an existing stack for one of the category's
   two picks — this keeps total new-emitter count down without sacrificing
   the distinctness goal, since the *other* pick still has to be genuinely
   different from it. Do not let this override reason 3 outright: a
   category with no site landing anywhere near an existing stack should
   still get its two most-distinct real picks, new emitters and all.
5. **Record the pick and the reasoning in that category's own tracker
   entry (§9.4)** — which sites, which stacks, which groups were
   considered and rejected, and why. This is what lets a cold session
   verify a prior category's choice rather than re-deriving it, and lets
   `docs/PREVENTIVE_ACTIONS.md`-style review catch a bad pick before a lot
   of build effort follows it.

### 9.2 Stack-reuse ledger — check this before starting any category's Phase A

Every category's site-pair selection can create or reuse a stack. Whoever
picks up a category **must** check this ledger first (last-decided-first
order) and update it immediately after their own pick, so a later category
doesn't duplicate a stack another category already justified building —
two categories both wanting, say, "a Ruby on Rails emitter" should share
one, not build two.

| Stack (language + paradigm) | Status | Built for / by | Notes |
|---|---|---|---|
| PHP, synchronous MVC (Laravel) | Built | Original lab, `php_laravel` | Full depth. |
| PHP, synchronous procedural | Built | Original lab, `php_current` | Foundation-tier depth. |
| Node/Express, synchronous API | Deepened (prototype pollution + ReDoS/M1-timing-oracle cells landed alongside Tier-A depth) | §§1-6 above (pre-expansion plan); category 1 (Walmart pick) | A category picking Node/Express as one of its two should coordinate with category 1 rather than starting a second effort. |
| Python, async API (FastAPI/Pydantic) | Shallow (Tier-A) | Original Phase 3 lane | Exists; available to reuse if a category's pick lands here specifically (not just "Python" generically — see §9.1 step 2's paradigm distinction, e.g. this is NOT the same stack as Django). |
| Ruby on Rails, synchronous MVC | Phase A + Phase B done (skeleton, live-boot harness, XSS cell, plus webhook-signature/CWE-915/CWE-502) | Category 1 (E-commerce, Shopify pick), `claude/second-target-cat1-ecommerce`, `fuzzlab/labgen/emitters/ruby_rails/` | Not merged to `main` yet. Rails 8.1.3.1 (verified live against rubygems.org, not guessed), `--minimal` skeleton, SQLite dev/test DB. A category wanting "Ruby" (e.g. category 6's Stripe) should check whether Rails specifically fits before building a second Ruby stack — see §9.1 step 2's paradigm-distinction rule. |
| Python, synchronous MVC (Django) | Phase A + Phase B done (SQLi login lookup + stored XSS shapes, route-method-gated `@csrf_exempt`) | Category 2 (Social/UGC, Instagram pick), `claude/category-2-build-bomomg` | Distinct from `python_fastapi` (async API paradigm). `fuzzlab/labgen/emitters/django/` + `DjangoLiveBootHarness`, both real and passing. Any later Python-Django-shaped pick should reuse this, not start a second Django emitter. |
| PHP/Hack, synchronous MVC (HHVM) | Reused (mapped onto `php_laravel`'s paradigm group — company/runtime differ, paradigm doesn't); Huddle Hub's own first cell (webhook-signature "magic hash" bypass) landed on `php_laravel` | Category 3 (Slack pick, "Huddle Hub"), `claude/category-3-build-iuu5k9` | Not a distinct emitter — an app identity built on the existing `php_laravel` emitter. |
| Java/Kotlin, Spring Boot microservice | **Consolidation done 2026-09-23** — `spring_boot` (originally category 3's package, TrackerNest's 3 cells + Huddle Hub's own use of `php_laravel`) is now the sole Java/Spring Boot stack in this project: category 4's `java_spring_boot` package has been deleted, and Netflix's one CWE-502 Jackson-deserialization cell was ported into `spring_boot` (`CC-LAB-0173`, real Jackson-2-vs-3 API break found and resolved during the port — see §9.2a for the full record, kept for history). Category 5's Expedia pick must reuse `spring_boot`, not build anything new. | Any category researching a Java/Spring Boot pick (Wise, PayPal's historical Java tier, Cash App) **must** reuse `spring_boot` — do not build a second package. |
| Go, synchronous HTTP API (`net/http`, post-monolith-migration paradigm) | Phase A + Phase B first increment done (CWE-347 webhook-signature, CWE-918 SSRF via `net.LookupIP`/private-range allowlist) | Category 4 (Media/streaming, Twitch pick), `claude/category-4-build-t9uz3y` | Not merged to `main` yet. |
| *(add a row per new stack the moment a category picks it — before building it, not after)* | — | — | — |

**Cross-branch sync note (2026-09-23, by the category 1 pilot session):**
this file was found to have diverged across all five active category
branches — every one of categories 2, 3, 4, and 5 had independently
claimed `CC-LAB-0090`/`0091` and `FR-LAB-64`/`65` for their own Phase A
work (all forked before seeing each other's usage), and this section's
own ledger table had grown five different, partially-stale copies. Each
branch's colliding IDs were renumbered into a distinct, non-overlapping
block (see each category's own `docs/components/01-target-lab/change-
control.md` for the corrected IDs; the §9.4 tracker row above for each
category is now this section's own authoritative summary), and this
exact file (§9.2's ledger and §9.4's tracker) was then pushed identically
to all five branches so no session works from a stale copy. If you are
reading this on a branch where these tables look different from what's
described above, **that branch has since diverged again — check `git log`
for what changed and reconcile before trusting either copy.**

### 9.2a Java/Spring Boot consolidation — decision and implementation plan (2026-09-23)

**Decided, by the project owner, after the category 1 pilot session's
side-by-side comparison of both existing implementations, and now
**DONE** as of 2026-09-23:**
**`spring_boot`** (category 3's package, `claude/category-3-build-iuu5k9`,
TrackerNest) is the one canonical Java/Spring Boot stack going forward.
Category 4's separately-built `java_spring_boot` package has been
**deleted** (package, conformance harness, manifest, and its 4 test
files) after category 4 itself ported its one cell (Netflix's insecure
Jackson deserialization) into `spring_boot` as `CC-LAB-0173`. The port
required extending `SpringBootEmitter`'s source dispatch with a new
`_SOURCE_OVERRIDE_BY_OP` map to resolve the genuine minimal-pair
vocabulary overlap on `(insecure_deserialization, object_deserialization)`
this section flagged below, and separately required reconciling
`spring_boot`'s Spring Boot 4.1.1 / Jackson 3 dependency against
`java_spring_boot`'s Spring Boot 3.4.1 / Jackson 2 code: Jackson 3 moved
`activateDefaultTyping` from an `ObjectMapper` instance method to
`JsonMapper.builder()...build()`, and made `LaissezFaireSubTypeValidator`
package-private, requiring a local `PolymorphicTypeValidator.Base`
subclass override in the ported sink. Verified via a full test-suite
rerun on category 4's branch (1843 passed, 8 skipped) and direct code
review of both the dispatch extension and the Jackson 3 sink rewrite; no
bookkeeping issues found. Category 5's Expedia pick reuses `spring_boot`
— its Maven-access blocker resolved, and its own build did not need to
touch this package.

**Why `spring_boot`, not `java_spring_boot`, and not a from-scratch
merge:**
- `spring_boot` is materially deeper: 3 real, live-boot-proven cells
  (SSTI/OGNL, XXE, insecure deserialization via raw
  `ObjectInputStream.readObject()`) vs. `java_spring_boot`'s 1 cell
  (insecure deserialization via Jackson polymorphic typing).
- Porting `java_spring_boot`'s one cell into `spring_boot` is
  substantially less work than the reverse (porting three cells into the
  thinner package).
- Both are architecturally identical otherwise (same module-composition
  pattern — source/transform/sink/complexity registries — and both
  correctly forgo a route accumulator in favor of Spring's own
  `@RestController` component scanning), so nothing about the
  consolidation direction is forced by architecture; it's forced by
  which package is more built-out.

**Status: COMPLETE (2026-09-23), executed in full by category 4's own
session.** The numbered items below are retained as the record of what
the port actually required — each one was verified true and handled, not
skipped:

1. **Version reconciliation.** `spring_boot`'s skeleton pins
   `spring-boot-starter-parent` **4.1.1**; `java_spring_boot`'s pins
   **3.4.1**. Standardize on `spring_boot`'s 4.1.1 (the canonical
   package's own version) — do not attempt to run both versions
   side by side. Re-verify Netflix's ported cell actually compiles and
   boots against 4.1.1 before considering the port done; Jackson's
   `activateDefaultTyping`/`PolymorphicTypeValidator` API has moved
   across Jackson major versions before, and Spring Boot 4.1.1 may pull
   in a different Jackson version than 3.4.1 did — check this explicitly,
   don't assume API compatibility.
2. **A real minimal-pair vocabulary collision, not just a naming
   collision.** Both cells target the exact same shape,
   `(vuln_class="insecure_deserialization",
   sink_context.family="object_deserialization")`, via genuinely
   different mechanisms. `spring_boot`'s own `SpringBootEmitter`
   currently dispatches its **sink** module by `cell.transform.ops`
   (already separate from the source+complexity choice, which is keyed
   purely by `(vuln_class, sink_context.family)` in
   `_MODULE_SET_BY_SHAPE`) — see that class's own docstring. Absorbing
   Netflix's cell means **the source dispatch needs extending to also
   consider `cell.transform.ops` (or the route path), not just the
   shape tuple**, since the Jackson-based cell needs a different source
   module (`java_spring_boot`'s own JSON-body-reading source, likely
   renamed) than the existing `request_stream` (raw byte stream) source
   TrackerNest's own cell uses. This is a real, bounded refactor of
   `_MODULE_SET_BY_SHAPE`'s shape (e.g. keying on
   `(vuln_class, sink_context.family, op_family)` or a similar
   discriminator) — plan for it, don't try to route around it.
3. **Safety-matrix ops already coexist without collision** — verified:
   `spring_boot`'s existing `function_executing_deserialize`/
   `handler_registry_lookup` and `java_spring_boot`'s
   `jackson_default_typing_deserialize`/`jackson_typed_allowlist_deserialize`
   are four distinct op names already registered under the same
   `object_deserialization` sink_family with no clash. No new
   safety-matrix entries needed for the port itself.
4. **Package/route identity.** `spring_boot`'s skeleton hardcodes
   `com.fuzzlab.trackernest` as its scanned root package (TrackerNest's
   own app identity); `java_spring_boot`'s cell currently renders to
   `com.fuzzlab.lab.cells`. Per this project's own precedent
   (`node_express`/`php_laravel` already host multiple categories' cells
   under one shared skeleton and package root without issue — see
   Walmart's cells on `node_express`), Netflix's ported cell should
   render under `com.fuzzlab.trackernest.cells` (or wherever
   `spring_boot`'s existing cells live) rather than inventing a second
   package root inside the same skeleton. The literal package name is
   cosmetic (app "identity" for this project lives in the manifest/page
   design, not the Java package string) — don't block the port on
   renaming it to something Netflix-flavored.
5. **Bookkeeping — done.** Category 4 recorded the port as `CC-LAB-0173`
   from its own reserved block, marked `java_spring_boot`'s superseded
   `FR-LAB-77` as `**SUPERSEDED**` in its own `requirements.md` (rather
   than deleting it), and this file's own §9.2/§9.4 have been updated to
   record the consolidation as done. This section's prior "pending"
   framing is removed as of this 2026-09-23 canonical sync — the updated
   file has been re-synced to all five branches (see the sync note
   above), closing out this consolidation's own five-way-divergence risk.
6. **Test suite — confirmed.** `java_spring_boot`'s own package,
   conformance harness, manifest, and 4 test files were deleted outright
   (not left dangling). Category 4's full non-slow suite reran green at
   1843 passed / 8 skipped after the port, including `spring_boot`'s
   live-boot suite grown by Netflix's new cell (real `mvn package`/boot/
   HTTP round trip, not simulated).

### 9.3 Multi-session coordination contract (read this before touching any code)

Binding on every session working any category of this plan, including this
one's own pilot:

1. **One git branch per category**, named
   `claude/second-target-cat<N>-<short-slug>` (e.g.
   `claude/second-target-cat1-ecommerce`). Never work a category's build
   directly on `main` or on another category's branch.
2. **Pre-assigned bookkeeping number BLOCKS per category, reserved in this
   document before that category's build starts** — not "claim the next
   free number," which is exactly the failure mode `PA-0031` already
   exists to prevent and which this session's own branch-reconciliation
   cost real effort to fix. §9.4's tracker table is where each category's
   block gets recorded. A session starting a category must add its row
   (with its reserved block) to §9.4 in the *same commit* that starts any
   other work, so a concurrently-starting session sees it.
3. **Check `docs/research/site-architecture-survey.md`, §9.2's stack-reuse
   ledger, and §9.4's tracker for updates from other sessions before
   assuming any of them are stale** — these are the shared coordination
   surface; a session that hasn't fetched `main` recently before reading
   them is reading stale state.
4. **Full bookkeeping per this project's standard convention** — same as
   every other change in this repository (`CHANGELOG.md`, `CC-LAB-NNNN`,
   `requirements.md`, the full bug protocol for genuine defects) — applies
   per category, not once for the whole 12-app effort.
5. **Progress reporting, continuously, not just at completion:** update
   this document's §9.4 tracker row for your category at every phase
   transition (research done, stack decided, emitter skeleton built,
   module inventory depth reached, conformance proven, wired into
   `multitarget.py`) — not just when the whole category is finished. This
   is what lets the project owner (and other sessions) see live status
   without asking.
6. **Merge discipline:** when a category's branch is ready, open a PR into
   `main` (this repo's own established convention this session, per
   `alpuglisi/fuzzer#1`/`#2`) rather than pushing directly, given the
   proven risk of concurrent-branch collisions on this exact repository.
   Before opening it, rebase/merge `main` in and resolve against
   whatever other categories have already landed — do not assume `main`
   is where you left it.

### 9.4 Category tracker (update this table, don't let it go stale)

| # | Category | Status | Sites picked (stack) | New stack(s) needed | Branch | Bookkeeping block reserved | Notes |
|---|---|---|---|---|---|---|---|
| 1 | E-commerce/marketplaces | **Both apps' full Phase A-E now done — this category's toolkit-side second-target proof is complete for both picks.** Walmart/Node: both cells landed, plus Phase C (MeadowMart BFF app identity + ground truth, CC-LAB-0077), Phase D (whole-app live-boot conformance, CC-LAB-0078), and Phase E (own `TargetSpec` wired into `multitarget.py`, CC-LAB-0079). Rails/Shopify: Phase A+B done, plus Phase C (ForgeCart app identity + ground truth, CC-LAB-0080 — note: renumbered up from the dispatch brief's originally-assigned `CC-LAB-0077`/`FR-LAB-81` after finding, at start-of-work, that the concurrent Walmart/Node lane had already landed those exact numbers first on this same branch — see this row's own bookkeeping column), Phase D (whole-app live-boot conformance across all 12 cells, plus a real dependency-pinning defect found and fixed along the way, CC-LAB-0081/BUG-0035/PA-0037), and Phase E (own `TargetSpec` wired into `multitarget.py`, with a real, scored `ScoreReport` genuinely confirming the app's real `/search` reflected-XSS case, CC-LAB-0082). §6 step 2 (combining both `TargetSpec`s in one `run_targets` call) is now also done (`CC-LAB-0083`/`FR-LAB-87`, `tests/test_multitarget_category1_combined.py`) — both real targets boot and score together in one call; `generalizes` is correctly `False` (MeadowMart's two vuln classes still need `_VULN_TO_CATEGORY`/audit-rule follow-on wiring, flagged not attempted). **Category 1's full Phase A-E build is now complete for both apps — ready for a PR into `main` per §9.3 point 6.** | Shopify (Ruby on Rails); Walmart (Node/Express — reuses existing) | Ruby on Rails | `claude/second-target-cat1-ecommerce` | `CC-LAB-0070`-`0082` used (`0072`-`0075` Rails Phase B; `0077`-`0079` Walmart/Node Phase C/D/E; `0080`-`0082` Rails/Shopify Phase C/D/E — **renumbered from the dispatch brief's stale `0077`-`0079`/`FR-LAB-81`-`83` after checking this file's own CHANGELOG.md/change-control.md at start-of-work and finding the Node lane had already claimed those exact numbers**, exactly the PA-0031 failure mode this section's own coordination contract warns about, caught and corrected before landing rather than colliding on merge; `0083`-`0089` still free for any further increment); `FR-LAB-84`-`86` used for Rails/Shopify Phase C/D/E (renumbered up from the stale `81`-`83` for the same reason); `CC-FUZZ-0025`/`FR-FUZZ-12` used in the FUZZ component for the ReDoS oracle mechanism | See §9.4a for full detail (site-pair rationale, functionality findings, CWE shortlists, breadth ranking). |
| 2 | Social / UGC platforms | **Piloting** | Instagram (Python/Django — new stack); Facebook (PHP/Hack — approximated via existing `php_current`/`php_laravel`, reuses) | Python/Django (synchronous MVC) | `claude/category-2-build-bomomg` | `CC-LAB-0090`-`0119` (reserved, `CC-LAB-0090`/`0091` used) | YouTube excluded (Google-internal infra, no portable app-language claim — §9.1 step 1). Discord excluded (Elixir realtime/WebSocket, not a request/response fit — §9.1 step 1). Reddit excluded as redundant with Instagram: both are (Python, synchronous monolith) per §9.1 step 2, so picking both adds no distinctness; Instagram preferred as the far better-documented, larger production Django deployment. Facebook's real backend is PHP/**Hack**-on-HHVM specifically, not vanilla PHP — approximated via the existing PHP stack rather than building a literal HHVM/Hack runtime emitter (disproportionate for the vulnerability-shape fidelity it would buy); distinctness and corpus-grounding come from Facebook's real feature set and Meta-documented graph/storage model, not the runtime. Full reasoning: `docs/research/category2-social-ugc-functionality-and-cwe-research.md` §1. Functionality research (Instagram + Facebook) and Django/PHP-Hack-specific CWE research: **done** — see that doc §§2-5. Django emitter Phase A: **done** (`CC-LAB-0090`). Django emitter Phase B: **done** (`CC-LAB-0091`, 2026-09-23) — widened to `node_express`'s own three-shape Tier-A bar (`sqli`/`sql_string_literal`, `xss`/`html_body`), real live-boot proof for both including a `PA-0034` adversarial test that found and fixed a real code defect (`BUG-0034`/`PA-0036` — a cross-language `str()`-cast gap). See `docs/components/01-target-lab/change-control.md`'s `CC-LAB-0090`/`CC-LAB-0091` entries for the full record. (The earlier `FR-LAB-64`/`65` cross-branch collision with `claude/second-target-cat1-ecommerce`, flagged 2026-09-22, was resolved by renumbering to `FR-LAB-72`/`73`; see `requirements.md`'s own correction note for the full history — a later fix commit's warning text had briefly, self-contradictorily re-asserted the collision due to a blind find/replace bug, itself corrected 2026-09-23.) Next: either Phase B's remaining depth (full `php_laravel`-parity module inventory, not attempted) or Phase C (corpus-grounded page design for both the Instagram/Django and Facebook/PHP apps, per §0a, including the deferred Django-specific XSS footgun from the research doc's §4) — not yet started. |
| 3 | SaaS / productivity / collaboration | **Piloting** | Slack (PHP/Hack web tier — reuses `php_laravel`); Atlassian (Java/Kotlin+Spring Boot — new emitter) | Java/Kotlin, Spring Boot | `claude/category-3-build-iuu5k9` | `CC-LAB-0130`-`0169` (reserved, not yet all used) | Google Workspace excluded per §9.1 step 1: OT algorithm + Spanner/Bigtable is confirmed at the algorithm/storage level only, no named portable app-framework/language claim, same exclusion class as Disney+/Trip.com. Notion excluded for the same reason: Postgres/Redis/Kafka are infra/data-model detail, not an app-framework/language claim the survey names — re-checked, still not found; would need dedicated research to unblock and two other candidates already give a stronger distinctness pair. Remaining three (Slack, Atlassian, MS365/Teams) grouped per §9.1 step 2: Slack = PHP/Hack, synchronous web-app tier (Java realtime-messaging tier excluded — not the app-logic tier, a WebSocket fan-out layer, poor fit for this generator's request/response IR); Atlassian = Java/Kotlin+Spring Boot microservice (picked over Atlassian's own Node+Express/Python options as the most distinct from stacks already built); MS365/Teams = Node.js+Apollo GraphQL BFF (same language family as the already-built/being-deepened `node_express`, so not the most distinct choice available). Slack vs. Atlassian is the most distinct pair (different language, different runtime, different paradigm) of the three viable candidates. Reuse-vs-new (§9.1 step 4): Slack's PHP/Hack web tier groups with `php_laravel`'s paradigm (synchronous MVC/template-rendering) — reused rather than built as a separate Hack/HHVM emitter (see §9.2 ledger note); Atlassian's Java/Kotlin+Spring Boot is genuinely new and doesn't overlap any built or reused stack, satisfying step 4's "other pick still distinct" requirement. Functionality + stack-specific CWE research + Phase C page design: **done**, see `docs/research/category3-saas-functionality-and-cwe-research.md` (apps: "Huddle Hub" for Slack, "TrackerNest" for Atlassian). Phase A, TrackerNest cell 1 (SSTI/OGNL at `/wiki/pages/render`): **done and verified**, `CC-LAB-0130` (13 tests). Phase A, TrackerNest cell 2 (XXE at `/issues/import`, route simplified from the design doc's `/issues/{id}/render` for the same `Route`-has-no-path-parameter reason `CC-LAB-0130` found — reflected back into the research doc's sec 6b; also added a new additive `xml_external_entities_disabled` entry to `lab/safety_matrix.yaml`, that family's first secure counterpart): **done and verified**, `CC-LAB-0131` (13 more tests, 26 total for this stack — real `mvn package` + `java -jar` boot + real HTTP POST proving a real external-entity file-read on the vulnerable twin vs. a real HTTP 400 DOCTYPE rejection on the secure twin). TrackerNest's third and final designed cell (insecure deserialization at `/integrations/webhook-payload`): **done and verified**, `CC-LAB-0132` — built despite the 2026-09-22 scoping note above flagging it as harder (it needed a real Java-side `SerializeFixtureTool` helper to produce real Java-serialization-protocol bytes, plus a new public `SpringBootLiveBootHarness.app_dir` accessor and a `pom.xml` `<mainClass>` fix — none of that was a judgment call requiring a human decision, so it was built rather than deferred). Real `mvn package` + `java -jar` boot + real HTTP POST proves the differential: the vulnerable twin constructs and reports an unexpected `Serializable` type's name; the secure twin's `resolveClass()` allowlist rejects it with a real HTTP 400 while still accepting the expected type. **TrackerNest's full three-cell set (SSTI, XXE, insecure deserialization) is now done and live-boot-verified — 38 tests, all passing.** Huddle Hub's first designed cell (webhook-signature-verification bypass at `/webhooks/events`, served illustratively at `/cell/<slug>`): **done and verified**, `CC-LAB-0133` — built on the existing `php_laravel` emitter (no new emitter), using the real `loose_equality_compare`/`constant_time_compare` PHP "magic hash" ops per the research doc's own design (corrected during pre-change review from a first draft that had picked a non-matching total-bypass op). Found and fixed two real implementation-time gaps rather than routing around them: `LiveBootHarness` had no way to send a custom request header at all (added an additive `headers` param), and this stack's own shared-minimal-pair-vocabulary convention required matching module registrations in `fuzzlab.labgen.modules` (`php_current`'s package) too, mirroring the existing `dom_url_source`/L-P3.3c-DOM precedent (`php_current` gets classifiable names/templates only, not a working cell). Proof is honestly split in two: a real live-boot HTTP test for ordinary functional correctness (3 tests) plus a separate real-`php`-executed test proving the actual "magic hash" comparison-operator differential itself (6 tests), since a live HTTP test cannot force a real SHA-256 HMAC output to be magic-hash-shaped. `HHB` cell-id prefix checked against every other active branch's own `php_laravel` cell-ids before use (none collide). Next for this category: Huddle Hub's other two designed cells (SSRF via link unfurling, header injection in outgoing-webhook delivery, follow-on `CC-LAB-013x`), then Phase D (fuller conformance)/Phase E (`multitarget.py` wiring) for both apps — **in progress**. |
| 4 | Media / streaming / content platforms | **Piloting — Go/Twitch Phase A+B increment 1 done; Java/Netflix's cell ported into `spring_boot` and `java_spring_boot` retired per §9.2a (`CC-LAB-0173`); Phase C (corpus-grounded pages) not yet started** | Netflix (Java/Spring Boot, DGS Federated GraphQL); Twitch (Go, post-monolith API edge) | Java/Spring Boot; Go | `claude/category-4-build-t9uz3y` | `CC-LAB-0170`-`0209` (reserved; `0170`-`0173` used) | Applied §9.1 in full: Amazon Prime Video excluded (AWS-service-oriented, no single confirmed app-language, same exclusion reasoning as category 1's Amazon-retail exclusion); Disney+ excluded per the survey's own "partially unconfirmed at the application-code level" note (§9.1 step 1). Remaining three group as {Netflix, Spotify} = Java/Spring-Boot microservices (same language and paradigm — both fit §9.1 step 2's "not architecturally distinct from each other" bar) vs. {Twitch} = Go, a genuinely distinct language and paradigm (compiled, minimalist stdlib, post-Rails-monolith migration). Picked the two most-distinct groups (step 3) and, within the Java/Spring group, picked Netflix over Spotify for its documented Federated-GraphQL-gateway pattern (a distinct architectural surface — a BFF-shaped federation boundary — beyond plain REST, and confirmed at the same two-independent-source confidence level as Spotify). No reuse-preference applied (step 4): neither Java nor Go maps to any already-built stack, so distinctness alone decided both picks. Functionality research (real pages/flows) and stack-specific CWE research done and recorded: `docs/research/site-architecture-survey-functionality-netflix.md` (pick: CWE-502, Jackson polymorphic deserialization in a DGS mutation resolver; CWE-862 GraphQL field-authorization flagged for Phase B) and `-twitch.md` (pick: CWE-347, naive/skipped HMAC comparison in an EventSub webhook receiver; CWE-918 SSRF flagged for Phase B). Both picks are new-stack instances of classes `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4 already names as project-preferred (insecure-deserialization, webhook-signature) and both currently have zero Java/Go instances in the corpus. **Go/Twitch Phase A: done** (`CC-LAB-0170`/`FR-LAB-76`, reviewed pre-implementation per the component's pre-change review gate) — real skeleton, `GoEmitter` (one shape: CWE-347 webhook-signature-verification), `GoLiveBootHarness` (real `go build`/boot/HTTP), Tier 0/3 + a real live-boot test all pass; see `CC-LAB-0170` for the two real defects found and fixed during the build. **Java/Netflix Phase A: done** (`CC-LAB-0171`/`FR-LAB-77`, reviewed pre-implementation per the component's pre-change review gate) — real Maven/Spring Boot skeleton (no GraphQL/DGS dependency in this Phase A — that's Phase B, see the entry's scope call), `JavaEmitter` (one shape: CWE-502 `object_deserialization`, two new safety-matrix ops), `JavaLiveBootHarness` (real `mvn package`/boot/HTTP), Tier 0 (`mvn -q compile`)/3 + a real live-boot test all pass; architecturally needs no route accumulator (Spring Boot component-scans); see `CC-LAB-0171` for the route-collision bug found and fixed during the build. **Both of this pilot's Phase-A builds are done.** **Go/Twitch Phase B, first increment: done** (`CC-LAB-0172`/`FR-LAB-78`, reviewed pre-implementation, numbered against this category's `0170`-`0209` block after the cross-branch collision fix above) — a second shape, CWE-918/SSRF (clip-thumbnail-fetch proxy: `unchecked_url_fetch` vulnerable vs. `scheme_and_resolved_ip_allowlist` secure), reusing the existing `server_side_http_fetch` safety-matrix family; a genuine module-composition divergence (the op selects a sink directly, not a transform) required moving import bookkeeping from per-shape to per-module, found during implementation; Tier 0/3 + a real live-boot test (two throwaway loopback listeners isolating the scheme check from the resolved-IP-allowlist check) all pass; see `CC-LAB-0172`. Still deferred for Go: a per-run database and the richer EventSub message-ID/timestamp/replay-window checks. **Java/Netflix Phase B is superseded by the §9.2a consolidation decision, now landed.** `CC-LAB-0173`/`FR-LAB-79` ported the one Netflix cell (CWE-502, Jackson polymorphic deserialization) into category 3's `spring_boot` package (a real Jackson 2-to-3 major-version API break found and resolved during the port, plus a new `_SOURCE_OVERRIDE_BY_OP` dispatch extension `SpringBootEmitter` needed to host a second mechanism for the same shape tuple), re-verified with two real live-boot tests, and `java_spring_boot` was deleted from this branch entirely (package, harness, manifest, 4 test files) — full non-slow suite re-run afterward, no regression. GraphQL/DGS federation + CWE-862 (the richer, Netflix-architecture-specific Phase B work) remain out of scope, same as before the consolidation. Next: Phase C (corpus-grounded pages for Netflix and Twitch, per §0a/§4), then Phases D-E (conformance, `multitarget.py` wiring) per §9.5. |
| 5 | Travel / booking / marketplaces | **Piloting** | Booking.com (PHP — reuses existing `php_laravel`/`php_current`); Expedia (Java/Spring Boot — new stack) | Java/Spring Boot | `claude/category-5-build-6boejs` (harness-assigned branch name for this session; does not follow §9.3's `claude/second-target-cat5-<slug>` suggested convention, but is this category's dedicated branch — do not build another category on it) | `CC-LAB-0210`-`0249` (reserved, not yet all used) | Step 1 filter: Trip.com excluded (unconfirmed at the application-language level, per the survey's own caveat). TripAdvisor excluded (event-driven microservices + GraphQL BFF — no single portable application-language claim as clearly named as Booking.com/Airbnb/Expedia's). Step 2 groups among the remaining three: Booking.com = PHP, service-oriented/microservices behind an API gateway; Airbnb = Ruby on Rails (historical backbone) + Java/Dropwizard (newer services); Expedia = Java/Spring Boot (later Kotlin) microservices. All three pairings (PHP+Ruby, PHP+Java, Ruby+Java) read as comparably cross-language-distinct from the research alone, so step 4's reuse tiebreak decided it: Airbnb/Ruby-on-Rails was **not** picked specifically because category 1 (this same pilot wave) already committed to building a Ruby on Rails emitter for Shopify — picking Airbnb here would duplicate that in-progress new-stack effort rather than add distinctness (exactly the collision §9.2/§9.3 exist to prevent). Booking.com/PHP was picked over Airbnb/Ruby because PHP is already a built stack (`php_laravel`/`php_current`), satisfying step 4's reuse preference outright. Expedia/Java+Spring Boot is the new stack: genuinely distinct from every stack built or already committed elsewhere (PHP, Node/Express, Python/FastAPI, Ruby on Rails). Functionality research and stack-specific CWE research for this pair: **done** — see `docs/research/category5-travel-functionality-and-cwe-research.md`. Shortlisted CWEs for page design: CWE-601 open redirect (affiliate/partner links, genuinely new class for this project), CWE-502 Jackson polymorphic deserialization (Java-specific flavor, first Java entry), Spring Data JPA/MongoDB SpEL injection via `@Query` (framework-specific trigger path), CWE-1236 CSV/report export injection (Extranet-style admin exports, contingent on confirming `search-export` doesn't already cover it), Booking.com rate-plan-selection price integrity (lowest novelty, kept for real-site grounding). **Expedia/Java-Spring-Boot Phase A (real bootable skeleton) was environment-blocked in this sandbox** (Maven Central/Spring Initializr unreachable through the egress proxy, `ERROR_LOG.md`'s 2026-09-22 "Maven Central unreachable" entry) **but per §9.2a's cross-category consolidation decision, Expedia now reuses category 3's `spring_boot` package (TrackerNest) once Maven access is reconfirmed, rather than needing its own from-scratch Phase A** — re-check Maven reachability at the start of any session resuming this half of the pilot before assuming the old blocker still applies verbatim. Booking.com/PHP is unaffected (reuses the already-built `php_laravel` skeleton/harness) and proceeds unblocked. **Booking.com module-inventory depth: 2 of 5 shortlisted shapes landed** — `open_redirect` (CWE-601, `CC-LAB-0210`/`FR-LAB-78`/`FR-LAB-79`) and `csv_formula_injection` (CWE-1236, `CC-LAB-0211`/`FR-LAB-90`/`FR-LAB-91`), both through this repo's pre-change review gate (draft → 2 independent reviews → revised → real live-boot proof); the second increment's review gate caught the same *class* of under-specified-neutralization-check gap the first one did, plus drove a real refactor (the `redirect_response` complexity module, found already sink-agnostic, renamed `terminal_response` and reused rather than duplicated). Page/route count: 2 (`/booking/continue`, `/extranet/export`), own ground truth: 2 cases (`BKNG-0001`/`BKNG-0002` in `lab/ground-truth-booking-clone/`). Bookkeeping-ID note: this app's first increment was renumbered from the originally-contested `CC-LAB-0090`/`FR-LAB-64`/`FR-LAB-65` to `CC-LAB-0210`/`FR-LAB-78`/`FR-LAB-79` by the category 1 pilot session's cross-branch review (2026-09-22) after a real collision with categories 2/3/4's own independently-claimed IDs — this category's block is now exclusively `CC-LAB-0210`-`0249`; the second increment was numbered directly within it (`CC-LAB-0211`/`FR-LAB-90`/`FR-LAB-91`, next-free at merge time, not independently re-verified against categories 2-4's latest state — re-check for a fresh collision before trusting these numbers in a later session). Remaining for this app: the price-integrity duplicate (Booking.com/PHP, unblocked, not yet started, lowest novelty), then Spring Data SpEL injection + CWE-502 Jackson deserialization (both Expedia/Java, pending the `spring_boot` reuse above), then Phase C's "coherent page/route set" bar (search, listing, checkout, Extranet — not yet begun), Tier 1/2 conformance beyond each shape's own live-boot proof, and wiring into `multitarget.py`. |
| 6 | Fintech / payments | Not started | — | Candidates: PayPal (historically Java, now diversifying to Node.js for high-traffic pages — itself two stacks, and Node may already be built, check §9.2), Stripe (Ruby — same caveat as Rails re: §9.2 if category 1 or 5 already built a Ruby stack; Stripe is Ruby generically, not Rails specifically, worth checking if that's a meaningfully different stack for this purpose or the same group), Wise (Java-based microservice fleet), Cash App (Kotlin + Java, state-machine payment lifecycle — a genuinely distinctive *functional* pattern worth preserving in page design even if the stack overlaps another Java/Kotlin pick), Venmo (Python on Kubernetes + DynamoDB + Celery — check against category 2's Python pick before assuming this is the same group). | — | — | Open. This category has the most cross-category stack-reuse-checking to do before picking (Node, Ruby, Java/Kotlin, and Python all plausibly already exist elsewhere by the time this category starts) — the picking session should read §9.2 particularly carefully. |

**Bookkeeping-block allocation note:** `CC-LAB-0070`-`0089` is reserved for
category 1 (the pilot) as a generous block (Ruby on Rails is a full new
emitter — skeleton, live-boot harness, module inventory, conformance — a
comparable scope to `php_laravel`'s own history, which used far more than
20 entries across its full build; this block may need extending, and if so
extend it in this table rather than letting the next category's block
overlap it). Categories 2-6 should each reserve their own block **in this
table, in the same commit that starts their work** — suggested size 20-30
per category given category 1's own scope, but the picking session should
size it based on how many new stacks its own picks actually require (a
category needing 2 new emitters needs a bigger block than one reusing an
existing stack for one of its two picks).

### 9.5 What's actually next (this session's pilot)

Category 1 (E-commerce) is now **piloting**, per §9.4's row. The concrete
next steps, in order, per §9.1-§9.3's discipline:

1. Create `claude/second-target-cat1-ecommerce` and do all pilot work there
   (not on `main`).
2. Functionality/feature research for Shopify (Rails) and Walmart
   (Node/Express) specifically — what real pages/flows each actually has
   (checkout, cart, seller/admin dashboard, search/catalog, reviews if
   any), cited, not invented — closing the gap §0a item 2 identified.
3. Stack-specific CWE research for each: what vulnerability classes are
   realistically introduced by *Rails-the-framework* specifically (mass
   assignment via unguarded `strong_parameters`, ERB/`raw`-bypassed
   auto-escaping, YAML deserialization via `Marshal`/`Psych` defaults,
   etc. — researched against the real Rails CWE landscape and
   `cwe.mitre.org/top25`, not assumed from general Ruby knowledge) and by
   *Express-the-framework* specifically, cross-checked against what
   `lab/safety_matrix.yaml`/the corpus already cover so the picks add
   breadth (§0a items 3-4) rather than repeat SQLi/XSS a third and fourth
   time.
4. Only then: build the Rails skeleton/live-boot harness (this category's
   version of §2's Phase A, for a stack that doesn't exist in this project
   at all yet — the biggest single piece of new work in this pilot),
   deepen `node_express` per §3's Phase B (already-scoped, reusable
   as-is), design and build the pages (§4's Phase C, now corpus-grounded
   per real Shopify/Walmart research instead of the generic corpus
   examples), prove conformance (§5), wire into `multitarget.py` (§6).
5. Update §9.4's tracker row at every step above — do not wait until the
   category is fully done to report progress.
