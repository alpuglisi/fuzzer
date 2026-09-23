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
| 2 | Social / UGC platforms | **Piloting** | Instagram (Python/Django — new stack); Facebook (PHP/Hack — approximated via existing `php_current`/`php_laravel`, reuses) | Python/Django (synchronous MVC) | `claude/category-2-build-bomomg` | `CC-LAB-0090`-`0119` (reserved, `CC-LAB-0090`/`0091`/`0092`/`0093`/`0094`/`0094a` used) | YouTube excluded (Google-internal infra, no portable app-language claim — §9.1 step 1). Discord excluded (Elixir realtime/WebSocket, not a request/response fit — §9.1 step 1). Reddit excluded as redundant with Instagram: both are (Python, synchronous monolith) per §9.1 step 2, so picking both adds no distinctness; Instagram preferred as the far better-documented, larger production Django deployment. Facebook's real backend is PHP/**Hack**-on-HHVM specifically, not vanilla PHP — approximated via the existing PHP stack rather than building a literal HHVM/Hack runtime emitter (disproportionate for the vulnerability-shape fidelity it would buy); distinctness and corpus-grounding come from Facebook's real feature set and Meta-documented graph/storage model, not the runtime. Full reasoning: `docs/research/category2-social-ugc-functionality-and-cwe-research.md` §1. Functionality research (Instagram + Facebook) and Django/PHP-Hack-specific CWE research: **done** — see that doc §§2-5. Django emitter Phase A: **done** (`CC-LAB-0090`). Django emitter Phase B: **done** (`CC-LAB-0091`, 2026-09-23) — widened to `node_express`'s own three-shape Tier-A bar (`sqli`/`sql_string_literal`, `xss`/`html_body`), real live-boot proof for both including a `PA-0034` adversarial test that found and fixed a real code defect (`BUG-0037`/`PA-0039` — a cross-language `str()`-cast gap). See `docs/components/01-target-lab/change-control.md`'s `CC-LAB-0090`/`CC-LAB-0091` entries for the full record. (Two cross-branch FR-LAB collisions have hit this category's numbers so far — `64`/`65` with cat1, then `74`/`75` with category 3's `spring_boot` — each found and fixed by the cat1 pilot session's cross-branch review; see `requirements.md`'s own correction notes for the full history. Current landed numbers: `FR-LAB-88`/`89` for Phase B, `FR-LAB-95`/`96` for Phase C's first page.) Phase C: **started** (`CC-LAB-0092`, 2026-09-23) — established the **PicTrail** (Instagram-style) app identity and landed its first real, ground-truth-bearing page (`GET /post?id=`, reusing Phase A's proven SQLi module verbatim; page-set design for both PicTrail and **CircleFeed**, the Facebook-style PHP app, recorded in the research doc's §6). A new `_REAL_PAGE_CELL_IDS` URL-pinning mechanism and this project's first-ever second, independent ground-truth directory (`lab/ground-truth-picktrail-django/`) both landed and are real-live-boot-proven, including a `PA-0034` adversarial test (citing `BUG-0031` as precedent) whose real result differed from what was predicted — caught and corrected in the record. See `docs/components/01-target-lab/change-control.md`'s `CC-LAB-0092` entry for the full record. PicTrail's second real page landed (`CC-LAB-0093`, 2026-09-23): `/post/comments`, Django's real `mark_safe()`-defeats-template-autoescaping footgun (deliberately simplified from the fuller researched `@mention`/`#hashtag` auto-linking shape, stated explicitly) — this emitter's first two-file-per-cell render (view + a real `.html` template) and first real Django template-engine round trip. A new `lab/safety_matrix.yaml` sink family (`html_body_template`) models Django's inverted "safe by default" semantics. The pre-change review caught a real Jinja2/Django `{{ }}` delimiter collision before it was built (this project's own Jinja2 generation pass shares Django's template-variable syntax) — resolved by emitting the template as a fixed Python string constant, never a `.j2` file, verified by a real generation-time test. Real live-boot proof covers both directions of the differential through the real template engine, plus a `PT-0002` ground-truth extension. Current landed numbers: `FR-LAB-88`/`89` (Phase B), `FR-LAB-95`/`96` (Phase C page 1), `FR-LAB-102`/`103` (Phase C page 2), `FR-LAB-105`/`106` (Phase C page 3) — the numbering gaps reflect near-collisions caught by pre-landing checks against all other active category branches (see `requirements.md`'s own correction notes). See `docs/components/01-target-lab/change-control.md`'s `CC-LAB-0093` entry for the full record. PicTrail's third real page landed (`CC-LAB-0094`, 2026-09-23): `/upload/link-preview`, a real SSRF (CWE-918) via `requests.get()` with no scheme/resolved-IP check — this emitter's first outbound-HTTP-fetch sink category, reusing `lab/safety_matrix.yaml`'s existing `server_side_http_fetch` sink family unchanged (no new safety-matrix design needed) and porting the already-reviewed Python corpus example almost verbatim. A new, real, stdlib-only `InternalServiceFixture` (port-`0`-bound, thread-join teardown) proves the differential live in both directions; a `PA-0034`/`PA-0035`-disciplined adversarial test (a dedicated `external_http_probe()`, not a PyPI-reachability stand-in) proves the allowlist still admits a legitimate public URL, correctly skip-guarding given this build environment's own restricted network egress. The shared `labels.schema.json` needed widening for this page's ground truth (`vuln_class`/`sink_context` gaining `ssrf`/`network`) — landed as its own standalone, pre-requisite entry (`CC-LAB-0094a`), adopting category 3's own already-reviewed widening (`fa8207d` on `claude/category-3-build-iuu5k9`) byte-identically to avoid cross-branch schema drift. Two real defects were caught and corrected during implementation itself, before landing: the sink module's own name (the reviewed draft had conflated a transform op's name with a sink name) and its complexity module (`single_statement`'s fixed DB-row epilogue would have appended real, unreachable dead code after this shape's own early `return` — caught by `py_compile`, fixed by using `render_only`). See `docs/components/01-target-lab/change-control.md`'s `CC-LAB-0094`/`CC-LAB-0094a` entries for the full record. Next: PicTrail's remaining planned pages (mass-assignment settings, identifier-SQLi search, session deserialization, the full auto-linking-specific XSS shape) or CircleFeed's page set (per the research doc's §6) — each its own future, separately-gated increment; not yet started. |
| 3 | SaaS / productivity / collaboration | **Both apps' full Phase A-E now done — this category's toolkit-side second-target proof is complete for both picks.** | Slack (PHP/Hack web tier — reuses `php_laravel`); Atlassian (Java/Kotlin+Spring Boot — new emitter) | Java/Kotlin, Spring Boot | `claude/category-3-build-iuu5k9` | `CC-LAB-0130`-`0169` (reserved, not yet all used) | Google Workspace excluded per §9.1 step 1: OT algorithm + Spanner/Bigtable is confirmed at the algorithm/storage level only, no named portable app-framework/language claim, same exclusion class as Disney+/Trip.com. Notion excluded for the same reason: Postgres/Redis/Kafka are infra/data-model detail, not an app-framework/language claim the survey names — re-checked, still not found; would need dedicated research to unblock and two other candidates already give a stronger distinctness pair. Remaining three (Slack, Atlassian, MS365/Teams) grouped per §9.1 step 2: Slack = PHP/Hack, synchronous web-app tier (Java realtime-messaging tier excluded — not the app-logic tier, a WebSocket fan-out layer, poor fit for this generator's request/response IR); Atlassian = Java/Kotlin+Spring Boot microservice (picked over Atlassian's own Node+Express/Python options as the most distinct from stacks already built); MS365/Teams = Node.js+Apollo GraphQL BFF (same language family as the already-built/being-deepened `node_express`, so not the most distinct choice available). Slack vs. Atlassian is the most distinct pair (different language, different runtime, different paradigm) of the three viable candidates. Reuse-vs-new (§9.1 step 4): Slack's PHP/Hack web tier groups with `php_laravel`'s paradigm (synchronous MVC/template-rendering) — reused rather than built as a separate Hack/HHVM emitter (see §9.2 ledger note); Atlassian's Java/Kotlin+Spring Boot is genuinely new and doesn't overlap any built or reused stack, satisfying step 4's "other pick still distinct" requirement. Functionality + stack-specific CWE research + Phase C page design: **done**, see `docs/research/category3-saas-functionality-and-cwe-research.md` (apps: "Huddle Hub" for Slack, "TrackerNest" for Atlassian). Phase A, TrackerNest cell 1 (SSTI/OGNL at `/wiki/pages/render`): **done and verified**, `CC-LAB-0130` (13 tests). Phase A, TrackerNest cell 2 (XXE at `/issues/import`, route simplified from the design doc's `/issues/{id}/render` for the same `Route`-has-no-path-parameter reason `CC-LAB-0130` found — reflected back into the research doc's sec 6b; also added a new additive `xml_external_entities_disabled` entry to `lab/safety_matrix.yaml`, that family's first secure counterpart): **done and verified**, `CC-LAB-0131` (13 more tests, 26 total for this stack — real `mvn package` + `java -jar` boot + real HTTP POST proving a real external-entity file-read on the vulnerable twin vs. a real HTTP 400 DOCTYPE rejection on the secure twin). TrackerNest's third and final designed cell (insecure deserialization at `/integrations/webhook-payload`): **done and verified**, `CC-LAB-0132` — built despite the 2026-09-22 scoping note above flagging it as harder (it needed a real Java-side `SerializeFixtureTool` helper to produce real Java-serialization-protocol bytes, plus a new public `SpringBootLiveBootHarness.app_dir` accessor and a `pom.xml` `<mainClass>` fix — none of that was a judgment call requiring a human decision, so it was built rather than deferred). Real `mvn package` + `java -jar` boot + real HTTP POST proves the differential: the vulnerable twin constructs and reports an unexpected `Serializable` type's name; the secure twin's `resolveClass()` allowlist rejects it with a real HTTP 400 while still accepting the expected type. **TrackerNest's full three-cell set (SSTI, XXE, insecure deserialization) is now done and live-boot-verified — 38 tests, all passing.** Huddle Hub's first designed cell (webhook-signature-verification bypass at `/webhooks/events`, served illustratively at `/cell/<slug>`): **done and verified**, `CC-LAB-0133` — built on the existing `php_laravel` emitter (no new emitter), using the real `loose_equality_compare`/`constant_time_compare` PHP "magic hash" ops per the research doc's own design (corrected during pre-change review from a first draft that had picked a non-matching total-bypass op). Found and fixed two real implementation-time gaps rather than routing around them: `LiveBootHarness` had no way to send a custom request header at all (added an additive `headers` param), and this stack's own shared-minimal-pair-vocabulary convention required matching module registrations in `fuzzlab.labgen.modules` (`php_current`'s package) too, mirroring the existing `dom_url_source`/L-P3.3c-DOM precedent (`php_current` gets classifiable names/templates only, not a working cell). Proof is honestly split in two: a real live-boot HTTP test for ordinary functional correctness (3 tests) plus a separate real-`php`-executed test proving the actual "magic hash" comparison-operator differential itself (6 tests), since a live HTTP test cannot force a real SHA-256 HMAC output to be magic-hash-shaped. `HHB` cell-id prefix checked against every other active branch's own `php_laravel` cell-ids before use (none collide). Huddle Hub's second designed cell (SSRF via link unfurling at `/messages/unfurl`): **done and verified**, `CC-LAB-0134` — reuses the existing `unchecked_url_fetch`/`scheme_and_resolved_ip_allowlist` ops, both twins bounded with an explicit fetch timeout (PA-0035 spirit, a real gap the pre-change review caught). Live-boot-proven against a real local marker HTTP server this test owns and controls: the vulnerable twin reaches it via both a bare IP literal and a resolved hostname (`localhost`) — the hostname form specifically needed to actually exercise the secure twin's `gethostbyname()` resolution path, another real gap the review caught (an IP-literal-only test would never distinguish the secure op from a naive string check) — while the secure twin rejects both forms with a real HTTP 400, confirmed via the marker server's own hit counter staying at zero, and still correctly accepts a real public URL. 9 new tests, all passing. Huddle Hub's third and final designed cell (header injection in outgoing-webhook delivery at `/integrations/outgoing-webhook`): **done and verified**, `CC-LAB-0135`/`FR-LAB-107` — new `outbound_http_request_header_value` sink_family/concern in `lab/safety_matrix.yaml` (additive), `raw_header_concat` (vulnerable) vs. `structured_http_client_headers` (secure, Laravel's Guzzle-backed `Http` facade rejects a CRLF-bearing header value with a real `InvalidArgumentException`) ops, both twins bounded with an explicit timeout and reading the destination URL from an env var with an RFC-2606 `.invalid`-TLD fail-closed fallback. Live-boot-proven against a real local marker HTTP server: the vulnerable twin's crafted trigger word (`innocuous\r\nX-Injected: proof`) genuinely splices a real, separate `X-Injected: proof` header the marker server actually parses (verified by inspecting its own parsed headers, not assumed), alongside the intact original header; the secure twin rejects the identical value with a real HTTP 400 and never reaches the marker server, while still accepting an ordinary trigger word. 6 unit tests + 3 live-boot tests, all passing. **Huddle Hub's full three-cell designed set (webhook-signature, SSRF, header injection) is now done and live-boot-verified.** **Both TrackerNest and Huddle Hub now have their full designed cell sets complete and live-boot-verified for category 3's pilot scope.** Phase C ground truth: **done**, `CC-LAB-0136`/`FR-LAB-108` (TrackerNest, `lab/ground-truth-trackernest/`, 3 cases describing the app with its three vulnerable twins deployed together -- the only combination that is simultaneously real-bootable, since its twins share a literal route) and `CC-LAB-0137`/`FR-LAB-109` (Huddle Hub, `lab/ground-truth-huddlehub/`, 3 cases at each vulnerable cell's own per-cell URL, matching category 5/Booking.com's own convention) -- split into two entries after the pre-change review's adequacy pass flagged bundling both apps as the same over-scoping `CC-LAB-0090` was originally caught on. Phase E (`multitarget.py` wiring): **done**, `CC-LAB-0138`/`FR-LAB-110` (TrackerNest's own `TargetSpec`, a hand-rolled multi-cell Spring Boot boot fixture since its conformance harness is deliberately single-cell-only) and `CC-LAB-0139`/`FR-LAB-111` (Huddle Hub's own `TargetSpec`, via the existing multi-cell-capable `LiveBootHarness`), then `CC-LAB-0140`/`FR-LAB-104` runs both together in one `run_targets` call (mirroring category 1's own combined-run precedent) -- a real, distinct `run_id` per target, a real combined `transfer_summary`. Recall was initially 0 for every case (this category's 6 vuln classes were all unmapped in `fuzzlab.core.runmode._VULN_TO_CATEGORY`) and `generalizes` was correctly `False` -- both stated plainly rather than glossed over. **First real detection wiring landed**, `CC-CORE-0020`/`FR-CORE-10`: `ssti` mapped to the pre-existing, independently-verified `server-side-template-injection` category (real rule `R-SSTI` + real confirmation strategy `SstiStrategy`, both already built and already correctly scoped -- verified live against both of TrackerNest's own twins before landing: 2 of the strategy's 5 existing payloads genuinely evaluate under OGNL with zero code changes needed). TrackerNest's own recall is now 1/3 (`tp=1`, its `ssti` case confirms for real); the other 5 of this category's 6 new classes remain deliberately unmapped (no verified confirmer built for any of them yet, scoped explicitly rather than left as an oversight); `generalizes` is still correctly `False` (needs both scored targets above zero recall, not just one). `CC-LAB-0138`'s/`CC-LAB-0140`'s own Phase E tests updated and re-verified for the new numbers. A second, narrower gap flagged and tracked (`requirements.md` §8 Open Questions), not fixed: `points_from_ground_truth` mislabels Huddle Hub's one `location="header"` point's skip reason. All Phase E tests run for real (real `mvn package`/`java -jar` + real `composer install`/`artisan serve` + real HTTP) and pass; full non-slow suite re-run post-merge (categories 1/2/4/5 now consolidated onto this branch): 1838 passed, only the same pre-existing gitleaks/scikit-learn environment gap failing, no regressions. Process note: `CC-LAB-0138`-`0140`'s own pre-change review gate was run *after* implementation rather than before (an acknowledged deviation, recorded in each entry); `CC-CORE-0020` went through the gate in full, before implementation, per this project's normal discipline. **This closes category 3's own toolkit-side Phase 10 T10.6-style proof, with one real, verified, non-zero detection result now demonstrated end-to-end (not just wiring).** Remaining, out of this pilot's own scope: the `points_from_ground_truth`/header-capable-prober follow-on above, and confirmers for the remaining 5 of this category's 6 vuln classes. |
| 4 | Media / streaming / content platforms | **Piloting — Go/Twitch Phase A+B increment 1 done; Java/Netflix's cell ported into `spring_boot` and `java_spring_boot` retired per §9.2a (`CC-LAB-0173`); Phase C ground truth landed for both apps' currently-built cells (`CC-LAB-0174`/`FR-LAB-97`) — page/route count: 1 (`/api/playback/resume`, Netflix), 2 (`/generated/labgen-go-0001`, `/generated/labgen-go-0003`, Twitch); own ground truth: 1 case (`NFLX-0001` in `lab/ground-truth-netflix-clone/`), 2 cases (`TWCH-0001`/`TWCH-0002` in `lab/ground-truth-twitch-clone/`); Phase C's "coherent page/route set" bar not yet begun for either app, same still-open gap category 5 records for its own apps; Phase D: real Tier 1/2 conformance landed for 2 of 3 cells (SSRF, Jackson deserialization; `CC-LAB-0175`/`FR-LAB-98`) — the webhook-signature cell's CWE-347 timing side-channel is not Tier-1/2-confirmable and is recorded as an open question, not attempted; Phase E: both apps wired into `multitarget.py` for real (`CC-LAB-0176`/`FR-LAB-99`); the SSRF cell now has real, confirmed detection (`R-SSRF`/`SsrfInBandMarkerStrategy`/`SsrfOobStrategy`, `CC-AUD-0016`/`CC-FUZZ-0027`/`CC-LAB-0177`) — the point/sender-model gaps for the other two vuln classes are now closed too (header points real, whole-body sender content-type-aware) -- only their audit-rule/oracle-strategy detection capability remains open, tracked with concrete follow-on sketches; the "coherent page/route set" depth work has since landed a run of cheap, zero-new-generator-code second-instance increments on both apps' already-built shapes, each verified live to generalize with zero new detection code: Twitch's own JWT `alg:none` (`CC-LAB-0180`/`FR-LAB-120`), predictable-session-token (`CC-LAB-0181`/`FR-LAB-121`), channel-profile mass-assignment (`CC-LAB-0182`/`FR-LAB-122`, detection landed separately as `CC-AUD-0022`/`CC-FUZZ-0035`), a second `access_control`/`db_row_by_id_lookup` instance at `/channels/subscribers` (`TWCH-0007`, `CC-LAB-0183`/`FR-LAB-123`), and a second `ssrf`/`server_side_http_fetch` instance at `/clips/download` (`TWCH-0008`, `CC-LAB-0185`/`FR-LAB-125`); Netflix's own second `insecure_deserialization` instance at `/api/profiles/switch` (`NFLX-0003`, `CC-LAB-0184`/`FR-LAB-124`) — Twitch now has eight real pages/`TWCH-0001`..`TWCH-0008` ground-truth cases (real, scored recall 7/8 via `fuzzlab.harness.multitarget.run_targets`) and Netflix has three (`NFLX-0001`..`NFLX-0003`, real, scored recall 3/3 in the hand-rolled multi-cell boot; 1/3 in the single-cell `test_both_apps_run_through_multitarget_for_real` test, which only boots `LABGEN-JV-0001`) — see `docs/components/01-target-lab/change-control.md` for each entry's own full record** | Netflix (Java/Spring Boot, DGS Federated GraphQL); Twitch (Go, post-monolith API edge) | Java/Spring Boot; Go | `claude/category-4-build-t9uz3y` | `CC-LAB-0170`-`0209` (reserved; `0170`-`0186` used) | Applied §9.1 in full: Amazon Prime Video excluded (AWS-service-oriented, no single confirmed app-language, same exclusion reasoning as category 1's Amazon-retail exclusion); Disney+ excluded per the survey's own "partially unconfirmed at the application-code level" note (§9.1 step 1). Remaining three group as {Netflix, Spotify} = Java/Spring-Boot microservices (same language and paradigm — both fit §9.1 step 2's "not architecturally distinct from each other" bar) vs. {Twitch} = Go, a genuinely distinct language and paradigm (compiled, minimalist stdlib, post-Rails-monolith migration). Picked the two most-distinct groups (step 3) and, within the Java/Spring group, picked Netflix over Spotify for its documented Federated-GraphQL-gateway pattern (a distinct architectural surface — a BFF-shaped federation boundary — beyond plain REST, and confirmed at the same two-independent-source confidence level as Spotify). No reuse-preference applied (step 4): neither Java nor Go maps to any already-built stack, so distinctness alone decided both picks. Functionality research (real pages/flows) and stack-specific CWE research done and recorded: `docs/research/site-architecture-survey-functionality-netflix.md` (pick: CWE-502, Jackson polymorphic deserialization in a DGS mutation resolver; CWE-862 GraphQL field-authorization flagged for Phase B) and `-twitch.md` (pick: CWE-347, naive/skipped HMAC comparison in an EventSub webhook receiver; CWE-918 SSRF flagged for Phase B). Both picks are new-stack instances of classes `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4 already names as project-preferred (insecure-deserialization, webhook-signature) and both currently have zero Java/Go instances in the corpus. **Go/Twitch Phase A: done** (`CC-LAB-0170`/`FR-LAB-76`, reviewed pre-implementation per the component's pre-change review gate) — real skeleton, `GoEmitter` (one shape: CWE-347 webhook-signature-verification), `GoLiveBootHarness` (real `go build`/boot/HTTP), Tier 0/3 + a real live-boot test all pass; see `CC-LAB-0170` for the two real defects found and fixed during the build. **Java/Netflix Phase A: done** (`CC-LAB-0171`/`FR-LAB-77`, reviewed pre-implementation per the component's pre-change review gate) — real Maven/Spring Boot skeleton (no GraphQL/DGS dependency in this Phase A — that's Phase B, see the entry's scope call), `JavaEmitter` (one shape: CWE-502 `object_deserialization`, two new safety-matrix ops), `JavaLiveBootHarness` (real `mvn package`/boot/HTTP), Tier 0 (`mvn -q compile`)/3 + a real live-boot test all pass; architecturally needs no route accumulator (Spring Boot component-scans); see `CC-LAB-0171` for the route-collision bug found and fixed during the build. **Both of this pilot's Phase-A builds are done.** **Go/Twitch Phase B, first increment: done** (`CC-LAB-0172`/`FR-LAB-92`, reviewed pre-implementation, numbered against this category's `0170`-`0209` block after the cross-branch collision fix above) — a second shape, CWE-918/SSRF (clip-thumbnail-fetch proxy: `unchecked_url_fetch` vulnerable vs. `scheme_and_resolved_ip_allowlist` secure), reusing the existing `server_side_http_fetch` safety-matrix family; a genuine module-composition divergence (the op selects a sink directly, not a transform) required moving import bookkeeping from per-shape to per-module, found during implementation; Tier 0/3 + a real live-boot test (two throwaway loopback listeners isolating the scheme check from the resolved-IP-allowlist check) all pass; see `CC-LAB-0172`. Still deferred for Go: a per-run database and the richer EventSub message-ID/timestamp/replay-window checks. **Java/Netflix Phase B is superseded by the §9.2a consolidation decision, now landed.** `CC-LAB-0173`/`FR-LAB-93` ported the one Netflix cell (CWE-502, Jackson polymorphic deserialization) into category 3's `spring_boot` package (a real Jackson 2-to-3 major-version API break found and resolved during the port, plus a new `_SOURCE_OVERRIDE_BY_OP` dispatch extension `SpringBootEmitter` needed to host a second mechanism for the same shape tuple), re-verified with two real live-boot tests, and `java_spring_boot` was deleted from this branch entirely (package, harness, manifest, 4 test files) — full non-slow suite re-run afterward, no regression. GraphQL/DGS federation + CWE-862 (the richer, Netflix-architecture-specific Phase B work) remain out of scope, same as before the consolidation. **Phase C ground truth: done** (`CC-LAB-0174`/`FR-LAB-97`, reviewed pre-implementation per the component's pre-change review gate) — real, out-of-band ground truth for every vulnerable cell currently built (`lab/ground-truth-netflix-clone/`: 1 case, `NFLX-0001`; `lab/ground-truth-twitch-clone/`: 2 cases, `TWCH-0001`/`TWCH-0002`), plus an additive widening of `fuzzlab/labels/schemas/labels.schema.json` (`webhook_signature`/`ssrf`/`insecure_deserialization` vuln classes; `webhook`/`network`/`deserialization` sink contexts) mirroring category 5's own precedent; two judgment calls recorded (a whole-body-JSON `param` convention for Netflix, a header-carried-value `param` convention for Twitch's webhook case). Full non-slow suite re-verified green (1605 passed, same 15 pre-existing unrelated failures). Explicitly deferred, not silently skipped: Phase C's own "coherent page/route set" design bar (a small, self-consistent set of pages per app spanning its vulnerability classes, not ground truth over the single illustrative route(s) Phase A/B happened to build) remains open, larger, not-yet-started work for both apps — the same still-open gap category 5's own tracker row records for Booking.com/Expedia. **Phase D: 2 of 3 cells done** (`CC-LAB-0175`/`FR-LAB-98`) — real, executed Tier 1/2 conformance (`fuzzlab.labgen.conformance.tier1`/`tier2`, unmodified) for the SSRF cell and the Jackson-deserialization cell, via small local adapter classes over Phase A/B's own live-boot harnesses. The webhook-signature cell's CWE-347 timing side-channel is explicitly not Tier-1/2-confirmable (both twins behave identically for any single request; the divergence is comparison timing, which this module's marker-differential model cannot observe) — recorded as an open question (`FR-LAB-98` §8), not attempted. **Phase E: done** (`CC-LAB-0176`/`FR-LAB-99`) — both apps wired into `fuzzlab.harness.multitarget` for real: `TargetSpec`s pointing at real live-booted instances, run through `run_targets`/`transfer_summary` in one call with the project's existing real HTTP `RequestsProbeSender`. Detection was a documented, structural zero at landing (no audit rule yet for these three vuln classes; the header-located and whole-body-JSON ground-truth points don't fit the generic point/sender model) — recorded as real, sized follow-on work, not silently accepted, matching category 1's own precedent for its own new vuln classes. **One of those three gaps closed for real**: `CC-AUD-0016`/`FR-AUD-7` (a new `R-SSRF` audit rule) + `CC-FUZZ-0027`/`FR-FUZZ-14` (`SsrfInBandMarkerStrategy`/`SsrfOobStrategy`, cheapest-first, modeled on the existing `CommandInjectionOobStrategy` OOB pattern) + `CC-LAB-0177`/`FR-LAB-117` (`run_targets()`'s own missing `oob` passthrough, found while wiring this) together make the Twitch SSRF cell (`LABGEN-GO-0003`) a real, confirmed finding — `tp=1`, `recall=0.5` on that target's own 2 positives, verified against a real live-booted Go app. Reviewed pre-implementation per the component's pre-change review gate; the adequacy pass's finding (an OOB-only strategy would leave the common "target echoes the fetched body back" case — this project's own SSRF cells' actual shape — unconfirmed) drove building the cheap in-band layer first rather than deferring it. **All five phases (A-E) now have a first real increment landed for this category**, and one of the three vuln classes (`ssrf`) now has real, end-to-end, live-boot-proven detection. Two of the three remaining structural gaps are also now closed for real: `CC-FUZZ-0028`/`FR-FUZZ-15` gives header points real audited status (Twitch's own `TWCH-0001` is now sent as a real header probe, not skipped) and a content-type-aware whole-body sender (Netflix's own `NFLX-0001` is now sent as real raw JSON, not form-encoded) -- corrected mid-review to avoid a real overfit risk (forcing JSON on TrackerNest's own XML/binary-serialized body points), and catching a real `_CountingSender` passthrough bug before it could ever fire. Remaining work: the deferred page/route-set design work, a timing-differential oracle for the webhook-signature cell (concrete sketch tracked, `requirements.md` §8), and real audit-rule/oracle-strategy support for `webhook_signature`/`insecure_deserialization` (a URLDNS-style OOB sketch tracked for the latter, also §8) -- detection-capability gaps, not point/sender gaps, which are now closed. **Twitch's own page/route-set depth now moved forward for real**: `CC-LAB-0178`/`FR-LAB-118` landed a third real page, access-control/IDOR (`GET /channels/analytics?channel_id=`, reusing category 3's own `no_ownership_check`/`identity_match_before_fetch` mechanism, `CC-LAB-0063` -- the first lab-generator instance of it on any stack), real live-boot-proven (3 assertions), ground truth extended (`TWCH-0003`), a real Go compile gap found and fixed before landing. Twitch now has 3 real pages reading as one coherent API-edge app identity (webhook receiver, clip-thumbnail proxy, channel-analytics lookup); **Netflix's own page count now 2, not 1**: `CC-LAB-0179`/`FR-LAB-119` reused TrackerNest's already-built XXE shape (zero new generator code) at a new route, `POST /api/content/import` (partner content-metadata ingestion, grounded in confirmed facts -- DDEX ERN is XSD-validated XML, Netflix is a confirmed EIDR participant -- with the endpoint design itself labeled as illustrative inference, not a confirmed implementation detail), real live-boot proven, the shared-template risk with TrackerNest stated explicitly and covered by a new joint regression test. The GraphQL/DGS federation CWE-862 pick remains the harder, explicitly-deferred half of this gap (needs new infra, not just a reused mechanism). **A second detection-capability gap now closed for real**: `CC-AUD-0017`/`FR-AUD-8` (a new `R-ACCESS-CONTROL` audit rule, narrower in scope than `R-SSRF`'s own bare-`name_regex` shape per the pre-change review's adequacy pass) + `CC-FUZZ-0029`/`FR-FUZZ-16` (`AccessControlIdorStrategy`, plus a real `fuzzlab.core.runmode._VULN_TO_CATEGORY` fix without which the rule/strategy pair would never actually run) together make the Twitch access-control/IDOR cell (`TWCH-0003`) a real, confirmed finding, verified live against a real booted Go app — Twitch's own real, scored `multitarget` recall moves from 1/3 to 2/3 (`tp=2, fp=0`). Two of the three vuln classes (`ssrf`, `access_control`) now have real, end-to-end, live-boot-proven detection; only `webhook_signature` still has none (the CWE-347 timing side-channel this project's single-request oracle model cannot observe, tracked as its own open question). **A third detection-capability gap now closed for real, on the Netflix side**: `CC-AUD-0018`/`FR-AUD-9` (a new `R-INSECURE-DESERIALIZATION` audit rule, the project's first use of the `sink_context_in` predicate) + `CC-FUZZ-0030`/`FR-FUZZ-17` (`InsecureDeserializationTypeConfusionStrategy`, a two-probe differential over Jackson's `WRAPPER_ARRAY` polymorphic-type format, deliberately no real gadget-chain/RCE payload -- a materially simpler mechanism than the URLDNS path shelved earlier, needing no new DNS-listener infra) together make the Netflix insecure-deserialization cell (`NFLX-0001`) a real, confirmed finding. Along the way, a real, previously dormant defect was found and fixed: `fuzzlab.harness.auto.points_from_ground_truth` never propagated `sink_context` onto a ground-truth-sourced point at all (harmless until this was the first rule ever keyed on it) -- caught by the real, executed Phase E run showing `tp=0` despite a working rule+strategy pair, not assumed correct from unit tests alone. Netflix's own real, scored `multitarget` recall moves from 0 to 1/2, and the project's own cross-target `generalizes` definition (recall > 0 on >= 2 scored targets) is met for the first time across this whole project. Also fixed the second instance of a recurring `_VULN_TO_CATEGORY`/`_CATEGORY_TO_CLASS` pairing gap (the first was `access_control`, minutes earlier) with a real structural guard test this time, scoped to only categories with a real audit rule so it does not disturb the MeadowMart app's own deliberately-deferred `redos`/`prototype_pollution` gap (category 2's own tracked follow-on, not this category's). **A fourth and final detection-capability gap now closed for real**: `CC-AUD-0019`/`FR-AUD-10` (a new `R-XXE` audit rule) + `CC-FUZZ-0031`/`FR-FUZZ-18` (`XxeInBandMarkerStrategy`/`XxeOobStrategy`, modeled directly on the SSRF pair, an explicit docstring-stated safety scope limiting the entity value to `OobListener`'s own loopback URL) together make TrackerNest's XXE cell (`TNEST-0002`, category 3's own app sharing the same XXE templates Netflix's `NFLX-0002` reuses) a real, confirmed finding, verified live against a real booted Spring Boot app. Wiring this surfaced that two pre-existing multitarget tests (Huddle Hub's own solo test and category 3's combined test) never actually exercised the already-landed SSRF detection either, since neither passed a real `OobListener` to `run_targets` -- fixed and re-verified, not a production defect (the tests simply predated the capability). All four of category 4's own vuln classes now have real, end-to-end, live-boot-proven detection except `webhook_signature` (needs a genuinely new timing-statistics oracle, out of scope for a single-request model, tracked as its own open question) -- `ssrf`/`access_control`/`insecure_deserialization` all confirm for real against Twitch/Netflix, and `xxe`'s own detection capability is proven against TrackerNest's real boot; `CC-FUZZ-0032` then closed the remaining follow-on with a hand-rolled multi-cell Netflix boot (mirroring TrackerNest's own established pattern) proving both of Netflix's own positives (`NFLX-0001`/`NFLX-0002`) confirm together in one real boot -- `tp=2, fp=0, recall=1.0`. Also empirically confirmed (not just assumed) that a real webhook-signature timing oracle is genuinely infeasible with this project's current wall-clock-HTTP measurement -- booted the real vulnerable twin, computed the true HMAC against its own fixed demo secret, and measured 400 randomly-interleaved real requests per prefix-match length: no detectable timing relationship at all, HTTP/goroutine-scheduling jitter (hundreds of microseconds) swamps Go's real but nanosecond-scale per-byte comparison timing even same-machine over loopback. **Twitch's own page/route-set depth moved forward again**: `CC-LAB-0180`/`FR-LAB-120` landed a 4th real page, JWT `alg:none` signature confusion (`GET /channels/settings`, a hand-rolled Go-stdlib-only JWT parser/verifier modeling the real auth0/node-jsonwebtoken GHSA-8cf7-32gw-wr33 vulnerability), real live-boot-proven (3 assertions, including a real Go compile bug found and fixed before landing), ground truth extended (`TWCH-0004`). Twitch now has 4 real pages; the pre-change review gate's adequacy pass deliberately split this page from its own detection capability (a real, buildable single-request differential, not attempted) into a separately-scoped follow-on, matching this session's own established lab-then-detection pattern. That follow-on landed immediately after (`CC-AUD-0020`/`FR-AUD-11`, `CC-FUZZ-0033`/`FR-FUZZ-19`, `JwtAlgNoneConfusionStrategy`) -- a two-probe differential (an alg:none token with an injected marker must be accepted and echoed; a garbage-signature HS256-claimed control probe with the same marker must be rejected with a real 401/403, not merely "not 200") that closed a real defect the accuracy-review pass caught before implementation (the marker had to travel in the sink's own `channel_id` field, not an arbitrary one). **A 5th Twitch page followed**: `CC-LAB-0181`/`FR-LAB-121` landed a predictable-session-token mechanism (CWE-330, `POST /sessions/refresh`) -- genuinely no tainted request input at all, a real, third module-composition convention for this stack (documented explicitly as new, not conflated with SSRF's own Convention 2), real live-boot proof (observed vulnerable-twin tokens are literal nanosecond timestamps tracking real elapsed time; secure-twin tokens are 64-hex-char crypto/rand output). Detection deliberately not bundled (same split as `CC-LAB-0180`), tracked as its own follow-on. **That follow-on landed**: `CC-AUD-0021`/`FR-AUD-12` (a new `R-WEAK-TOKEN-ENTROPY` audit rule, genuinely less-constrained than every prior rule shape — no `location_in` at all, since this class has no tainted location to key off) + `CC-FUZZ-0034`/`FR-FUZZ-20` (`PredictableTokenSourceStrategy`, a two-probe differential keyed on the hex-vs-decimal parse gate as its primary false-positive defense, not delta-window tightness — `(10/16)^64 ≈ 8.6e-14`; corrected pre-implementation by the review gate's accuracy pass, which caught a ~5x error in that same math, and by its adequacy pass, which required dropping an unused mid-probe timestamp and switching the probe body from `""` to `"{}"` to survive a real JSON-parsing target) closed `TWCH-0005` for real, verified live against Twitch's real booted twins. `Verdict.evidence` deliberately redacts to an 8-character prefix of each token plus the computed delta, never the full raw value, since these are the target's own issued tokens. Twitch's own real, scored recall is now 4/5 (only `webhook_signature` remains permanently undetected, by the same deliberate timing-infeasibility finding above). **A 6th Twitch page followed**: `CC-LAB-0182`/`FR-LAB-122` landed a channel-profile-update mass-assignment mechanism (CWE-915, `POST /channels/profile` -- `PATCH` was this task's own suggested method, but `labels.schema.json`'s `method` enum is closed to `GET`/`POST`, so `POST` is used instead, a documented departure), reusing `lab/safety_matrix.yaml`'s existing `orm_entity_bulk_assign` family and `unfiltered_object_assign`/`typed_schema_allowlist` ops verbatim (already instantiated on `php_current`/`ruby_rails`/`php_laravel`, never before on `go_net_http`) -- Go has no ORM bulk-assign call to misuse, so this stack's own Convention 2 (the manifest's op names a sink directly, like SSRF) models it idiomatically: the vulnerable sink `json.Unmarshal`s the raw body directly onto a channel struct that already declares every persisted field (including `is_partner`); the secure sink unmarshals into a narrow DTO struct with only `display_name`/`bio`, then copies exactly those. Real live-boot proof: the vulnerable twin's response reflects `is_partner: true` when the request sets it; the secure twin's response never does. Ground truth extended (`TWCH-0006`); no schema widening needed (`mass_assignment` was already a valid `vuln_class`/`sink_context` enum value from other stacks' prior ground truth). Twitch now has 6 real pages; detection deliberately not bundled (same split as every prior page), tracked as its own follow-on -- Twitch's own real, scored recall is 4/6 until that follow-on lands. **That follow-on landed**: `CC-AUD-0022`/`FR-AUD-13` (a new `R-MASS-ASSIGNMENT` audit rule, `location_in=["body"]` + `sink_context_in=["mass_assignment"]`, the same shape as `R-INSECURE-DESERIALIZATION`/`R-XXE`) + `CC-FUZZ-0035`/`FR-FUZZ-21` (`MassAssignmentPrivilegedFieldStrategy`, a two-probe differential over the hardcoded, known `is_partner` field: probe A sets only the intended fields and requires it to read back `false`; probe B additionally sets it and requires it to read back `true` -- confirms only on that specific transition, never a bare "is it true" check) -- this project's first-ever rule/strategy pair for the `mass_assignment` class, closing `TWCH-0006` for real, verified live against Twitch's real booted twins. A real defect was found and fixed before this landed: the lab-page commit's own first-draft ground truth used `param="is_partner"` (the privileged field name), but `fuzzlab.harness.auto.points_from_ground_truth` only marks a body point's content type as JSON when `param=="body"` exactly -- caught by running the real `run_targets` pipeline, not assumed correct from unit tests alone, and fixed to the `param="body"` whole-body-point convention (matching `weak_token_entropy`'s own `TWCH-0005`) before either commit landed. Twitch's own real, scored recall is now 5/6. **A 7th Twitch page followed, a cheap depth increment reusing already-built detection**: `CC-LAB-0183`/`FR-LAB-123` landed a second access-control/IDOR instance, `GET /channels/subscribers?channel_id=` (a subscriber-roster lookup, the same BOLA surface as `/channels/analytics` reused at a genuinely different real Twitch feature), reusing `CC-LAB-0178`'s already-built module set verbatim — zero new generator code (one new manifest + one `_ROUTE_PARAMS` entry only), real live-boot proof (`TWCH-0007`). The point of this increment: `AccessControlIdorStrategy` (keyed on `vuln_class`+sink shape, not per-route) confirmed this new vulnerable twin and failed closed on its new secure twin with zero new detection code, verified both via a dedicated live-boot strategy test and a real, executed `run_targets` pipeline run — Twitch's own real, scored recall is now 6/7 (`tp=6, fp=0`), proving the project's existing `access_control` detection genuinely generalizes across distinct routes of the same shape. **A 3rd Netflix page followed, the same cheap depth-increment pattern applied to the other app**: `CC-LAB-0184`/`FR-LAB-124` landed a second `insecure_deserialization` instance, `POST /api/profiles/switch` (a multi-profile-switch payload, a real, documented Netflix account feature — up to 5 profiles per account, each with its own maturity-rating/autoplay/subtitle preferences), reusing `LABGEN-JV-0001`/`0002`'s already-built Jackson-polymorphic-typing module set verbatim — zero new generator code (one new manifest + one `_PAGE_PARAMS` entry only), real live-boot proof (`NFLX-0003`). `InsecureDeserializationTypeConfusionStrategy` (keyed on `vuln_class`+sink shape, not per-route) confirmed the new vulnerable twin and failed closed on its new secure twin with zero new detection code, verified both via a dedicated live-boot strategy test and a hand-rolled 3-cell `run_targets` boot assembling all three of Netflix's own positives together — Netflix's own real, scored recall in that boot is now 3/3 (`tp=3, fp=0`), the second detection-generalization proof this session has made (after `CC-LAB-0183`'s own, on a different stack). Netflix now has 3 real pages. **A 9th Twitch page followed, genuinely new breadth this time, not another cheap depth reuse**: `CC-LAB-0186`/`FR-LAB-126` landed this project's FIRST instance, on any stack, of `lab/safety_matrix.yaml`'s existing `fs_web_root_write` sink family / `unrestricted_file_upload` concern (`CC-LAB-0063`, confirmed absent by grep before starting) -- a channel-emote upload endpoint (`POST /channels/emotes/upload`). Since Go has no PHP-style "the web server executes an uploaded script" footgun, the vulnerable twin (a new `no_extension_check` sink, fed by a new `ReadUploadedFileSource` that is this stack's first real `multipart/form-data` parser) models the real, well-documented CWE-434-to-XSS chain instead: it writes the upload under the caller's own filename into a web-served directory and serves it back with a Content-Type derived from that same filename's extension (falling back to the caller's own multipart Content-Type header), so an uploaded `.html` file is served back same-origin as `text/html`. The secure twin (`extension_allowlist_mime_check`) allowlists real image extensions AND sniffs the real bytes via `http.DetectContentType`, writes under a fully server-chosen filename, and always serves the sniffed content type. A real Go "declared and not used" compile bug was found and fixed before landing (the same defect class `CC-LAB-0178`'s/`CC-LAB-0180`'s own bugs were), and `GoLiveBootHarness.HttpResponse` additively gained a `headers` field (this stack's first shape whose differential is only observable in a response header). Real live-boot proof: 4 assertions covering the vulnerable twin's Content-Type-chaining, the secure twin's extension rejection, its content-sniffing rejection of a spoofed upload, and its correct acceptance of a real image -- every write lands under `GoLiveBootHarness`'s own throwaway temp directory, and the probe payload is inert (a marker string, never an executing `<script>`). Ground truth extended (`TWCH-0009`); `labels.schema.json` additively widened (`unrestricted_file_upload`/`fs_web_root_write`). Twitch's own real, scored recall is now 7/9 (was 7/8) -- a real missed positive, not a false one, since **detection is deliberately not bundled into this commit**, tracked as its own separately-scoped follow-on (the same lab-then-detection split `CC-LAB-0180`/`CC-LAB-0181` established). Twitch now has 9 real pages. **This 9th page's own deliberately-deferred detection follow-on has now landed** (`CC-AUD-0023`/`FR-AUD-14`, `CC-FUZZ-0036`/`FR-FUZZ-22`): a new `R-UNRESTRICTED-FILE-UPLOAD` audit rule (`location_in=["body"]`+`sink_context_in=["fs_web_root_write"]`, the same shape as `R-MASS-ASSIGNMENT`/`R-INSECURE-DESERIALIZATION`/`R-XXE`) plus a new `UnrestrictedFileUploadContentTypeTrustStrategy` oracle strategy -- this project's first-ever rule/strategy pair for `unrestricted_file_upload` and its first real `multipart/form-data` probe of any kind. A real two-probe differential: an inert-marker `probe.svg` upload (a plausible extension, but bytes that are NOT a real image) must be accepted and served back with a script-executable `Content-Type` derived from the extension; a real-PNG `control.png` upload must independently be accepted and correctly served as `image/png` -- the false-positive defense ruling out both a legitimate SVG-accepting endpoint and a generically-permissive/broken target. Verified live against the real booted `LABGEN-GO-0017`/`0018` twins and through the real `run_targets` pipeline: Twitch's own real, scored recall moves from 7/9 to 8/9 (only `webhook_signature`'s permanently-infeasible timing side channel remains undetected). A real, narrowly-scoped `Sender` extension was needed along the way (`fuzzlab/tools/probesender.py`: a whole-body value is now encoded latin-1 instead of utf-8 specifically for a `multipart/` content type, so real binary probe content round-trips losslessly), and the seventh instance of this session's own recurring `_VULN_TO_CATEGORY`/`_CATEGORY_TO_CLASS` underscore/hyphen naming gap was found and fixed proactively this time, before landing. **A 4th Netflix page followed, genuinely new breadth, not another cheap depth reuse**: `CC-LAB-0187`/`FR-LAB-127` landed this stack's FIRST instance of `lab/safety_matrix.yaml`'s existing `db_row_by_id_lookup` sink family / `access_control` (IDOR) concern (`CC-LAB-0063`) -- Netflix never had this mechanism before, though Twitch already did (`CC-LAB-0178`/`CC-LAB-0183`). An account-billing-details lookup (`GET /api/account/billing?account_id=`), requiring a fixed demo `X-Account-Id` caller-identity header (this project's own design call, mirroring `go_net_http`'s own `X-Broadcaster-Id`) to match the requested `account_id`. Since `spring_boot`'s module shape has no separate transform stage, the op selects the sink directly (a new source, `ReadAccountIdAndCallerHeaderSource`, plus two new sinks, `no_ownership_check`/`identity_match_before_fetch`) rather than `go_net_http`'s source+transform+sink triad. `R-ACCESS-CONTROL`'s own `name_regex` was widened additively to also match `account_id` (`CC-AUD-0024`, confirmed to affect zero pre-existing cases by grep first). `SpringBootLiveBootHarness.request()`/`get()` additively gained a `headers` parameter -- this stack's first cell needing a caller-identity header sent by a test. Real live-boot proof: the vulnerable twin returns distinct, id-echoing billing data for two unrelated `account_id` values; the secure twin rejects a mismatched or missing `X-Account-Id` and accepts a matching one. **Detection generalized for free, verified live**: `AccessControlIdorStrategy` (`CC-FUZZ-0029`, built for Twitch's `go_net_http` cells) needed zero new code to confirm the new Spring Boot vulnerable twin and correctly fail closed on its new secure twin -- the first proof this strategy generalizes across stacks (`go_net_http` -> `spring_boot`), not just across routes on one stack. Ground truth extended (`NFLX-0004`, reusing Twitch's own pre-existing `access_control`/`object_lookup` enum values, no schema widening needed). Netflix's own real, scored recall in the hand-rolled multi-cell live-boot test moves from 3/3 to 4/4. Netflix now has 4 real pages. || 5 | Travel / booking / marketplaces | **Piloting** | Booking.com (PHP — reuses existing `php_laravel`/`php_current`); Expedia (Java/Spring Boot — new stack) | Java/Spring Boot | `claude/category-5-build-6boejs` (harness-assigned branch name for this session; does not follow §9.3's `claude/second-target-cat5-<slug>` suggested convention, but is this category's dedicated branch — do not build another category on it) | `CC-LAB-0210`-`0249` (reserved, not yet all used) | Step 1 filter: Trip.com excluded (unconfirmed at the application-language level, per the survey's own caveat). TripAdvisor excluded (event-driven microservices + GraphQL BFF — no single portable application-language claim as clearly named as Booking.com/Airbnb/Expedia's). Step 2 groups among the remaining three: Booking.com = PHP, service-oriented/microservices behind an API gateway; Airbnb = Ruby on Rails (historical backbone) + Java/Dropwizard (newer services); Expedia = Java/Spring Boot (later Kotlin) microservices. All three pairings (PHP+Ruby, PHP+Java, Ruby+Java) read as comparably cross-language-distinct from the research alone, so step 4's reuse tiebreak decided it: Airbnb/Ruby-on-Rails was **not** picked specifically because category 1 (this same pilot wave) already committed to building a Ruby on Rails emitter for Shopify — picking Airbnb here would duplicate that in-progress new-stack effort rather than add distinctness (exactly the collision §9.2/§9.3 exist to prevent). Booking.com/PHP was picked over Airbnb/Ruby because PHP is already a built stack (`php_laravel`/`php_current`), satisfying step 4's reuse preference outright. Expedia/Java+Spring Boot is the new stack: genuinely distinct from every stack built or already committed elsewhere (PHP, Node/Express, Python/FastAPI, Ruby on Rails). Functionality research and stack-specific CWE research for this pair: **done** — see `docs/research/category5-travel-functionality-and-cwe-research.md`. Shortlisted CWEs for page design: CWE-601 open redirect (affiliate/partner links, genuinely new class for this project), CWE-502 Jackson polymorphic deserialization (Java-specific flavor, first Java entry), Spring Data JPA/MongoDB SpEL injection via `@Query` (framework-specific trigger path), CWE-1236 CSV/report export injection (Extranet-style admin exports, contingent on confirming `search-export` doesn't already cover it), Booking.com rate-plan-selection price integrity (lowest novelty, kept for real-site grounding). **Expedia/Java-Spring-Boot Phase A (real bootable skeleton) was environment-blocked in this sandbox** (Maven Central/Spring Initializr unreachable through the egress proxy, `ERROR_LOG.md`'s 2026-09-22 "Maven Central unreachable" entry) **but per §9.2a's cross-category consolidation decision, Expedia now reuses category 3's `spring_boot` package (TrackerNest) once Maven access is reconfirmed, rather than needing its own from-scratch Phase A** — re-check Maven reachability at the start of any session resuming this half of the pilot before assuming the old blocker still applies verbatim. Booking.com/PHP is unaffected (reuses the already-built `php_laravel` skeleton/harness) and proceeds unblocked. **Booking.com module-inventory depth: 3 of 3 unblocked shapes landed (PHP shape roster now complete)** — `open_redirect` (CWE-601, `CC-LAB-0210`/`FR-LAB-78`/`FR-LAB-79`), `csv_formula_injection` (CWE-1236, `CC-LAB-0211`/`FR-LAB-90`/`FR-LAB-91`), and `price_integrity_bypass` (client-trusted payment amount, reusing `CC-LAB-0063`'s pre-existing concern, `CC-LAB-0212`/`FR-LAB-100`/`FR-LAB-101`), all through this repo's pre-change review gate (draft → 2 independent reviews → revised → real live-boot proof); each increment's review gate caught a real, blocking gap before implementation (under-specified neutralization checks on increments 1-2; a secure-twin design that didn't actually "recompute" plus a missing `bookings` DB table on increment 3), and increment 2 additionally drove a real refactor (the `redirect_response` complexity module, found already sink-agnostic, renamed `terminal_response` and reused rather than duplicated). Page/route count: 3 (`/booking/continue`, `/extranet/export`, `/booking/checkout`), own ground truth: 3 cases (`BKNG-0001`/`BKNG-0002`/`BKNG-0003` in `lab/ground-truth-booking-clone/`). Bookkeeping-ID note: this app's first increment was renumbered from the originally-contested `CC-LAB-0090`/`FR-LAB-64`/`FR-LAB-65` to `CC-LAB-0210`/`FR-LAB-78`/`FR-LAB-79` by the category 1 pilot session's cross-branch review (2026-09-22) after a real collision with categories 2/3/4's own independently-claimed IDs — this category's block is now exclusively `CC-LAB-0210`-`0249`; increments 2 and 3 were numbered directly within it (`CC-LAB-0211`/`FR-LAB-90`/`FR-LAB-91`, `CC-LAB-0212`/`FR-LAB-100`/`FR-LAB-101`, next-free at each merge time, not independently re-verified against categories 2-4's latest state each time — re-check for a fresh collision before trusting these numbers in a later session). **Expedia/Java-Spring-Boot: unblocked.** The `spring_boot` package (built by category 3 for TrackerNest, `CC-LAB-0130`-`0132`, already hosting category 4's ported Netflix Jackson-deserialization cell `CC-LAB-0173`) was mechanically ported onto this branch from `origin/claude/category-4-build-t9uz3y` (`CC-LAB-0213`/`FR-LAB-94`) — Maven Central reconfirmed reachable, and per §9.2a Expedia reuses this package rather than a from-scratch build. Running the ported test suite (not just trusting it) surfaced two small, real `lab/safety_matrix.yaml` gaps (the XXE secure-counterpart row, the Jackson-deserialization op pair) present on the source branches but not synced here — fixed additively. All 41 ported tests (33 non-live-boot + 8 real live-boot, a genuine `mvn package`/`java -jar` boot + HTTP round trip) pass. This closes CWE-502 Jackson deserialization for free (the ported cell already models Expedia's exact shortlisted idiom, `activateDefaultTyping()`) — no Expedia-specific work needed beyond a page profile/manifest reusing the existing ops. **Expedia's first own shape (not ported/reused): `spel_injection`** (CWE-917, `CC-LAB-0214`/`FR-LAB-113`/`FR-LAB-114`) — a hotel-search `sortBy` parameter evaluated as a Spring Expression Language (SpEL) expression, grounded in real CVE-2018-1273/CVE-2022-22980/CVE-2026-41717, modeling Spring's own documented fix (`SimpleEvaluationContext` vs. `StandardEvaluationContext`) directly. Went through the full pre-change review gate: accuracy clean (10/10 claims independently verified, including a real `mvn dependency:tree` run), adequacy INADEQUATE — caught a real, blocking classification error in the draft's own reasoning (a false SSTI-shape analogy; correct `static_precheck` classification is UNINFORMATIVE, the opposite of what the draft's analogy suggested) plus a schema-widening omission, both fixed pre-implementation. Also corrected a pre-existing CWE-89→CWE-917 mislabeling in this category's own CWE research doc, caught during drafting. Real live-boot proof: a safe `T(java.lang.Math).abs(-99)` type-reference canary evaluates for real on the vulnerable twin (HTTP 200, `99` in the body), is rejected for real on the secure twin (HTTP 400), with a benign expression proving the fix doesn't break legitimate use. Establishes Expedia's own cell-ID prefix (`LABGEN-EXP-`) and its own dedicated ground-truth directory (`lab/ground-truth-expedia-clone/`, `EXPD-` case prefix, matching Booking/Netflix/Twitch's per-app-identity precedent — TrackerNest's own spring_boot cells have no ground-truth cross-check at all, so there was no "shared dir" precedent to follow instead). Remaining for this app: Spring Data JPA `@Query`'s narrower SQL/JPQL-outcome flavor (CVE-2016-6652-style, CWE-89, genuinely distinct from the CWE-917 mechanism `spel_injection` already covers — optional, lowest novelty, not yet started) is no longer a blocking gap in the shortlist; then Phase C's "coherent page/route set" bar (search, listing, checkout-flow completion, Extranet browsing for Booking.com; Expedia's own real page/flow set, not yet designed), Tier 1/2 conformance beyond each shape's own live-boot proof, and wiring into `multitarget.py`. Netflix's fifth real page landed: `price_integrity_bypass`'s first instantiation on `spring_boot` (this concern's second real implementation project-wide, after `php_laravel`'s Booking.com checkout charge, `CC-LAB-0212`), a subscription plan-upgrade/downgrade endpoint (`POST /api/subscription/change-plan`) whose vulnerable twin trusts a client-supplied `monthly_charge` and whose secure twin recomputes it server-side from a fixed plan-tier price map (`CC-LAB-0188`/`FR-LAB-128`) -- real live-boot proof of the differential; detection deliberately not built yet (no audit-rule/oracle-strategy exists for this concern anywhere in the project), tracked as a separate follow-on. Detection follow-on landed: `PriceIntegrityBypassStrategy`/`R-PRICE-INTEGRITY` (`CC-FUZZ-0037`/`CC-AUD-0025`) -- a two-probe differential needing no prior knowledge of the target's real price, confirming only when the server's own reported charge tracks two different, deliberately implausible client-submitted amounts. Also fixed a real ground-truth defect (a per-field `param` that silently failed the harness's whole-body-JSON gate) found and corrected during this follow-on's own real end-to-end pipeline verification, which had also broken two of `test_multitarget_category4.py`'s own slow tests -- both fixed in the same commit. Netflix's real, scored recall in the multi-cell live-boot test now moves from 4/4 to 5/5. |
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

### 9.4a Category 1 (E-commerce) detail — functionality + CWE research (done)

**Site-pair rationale:** Shopify (Ruby on Rails) + Walmart (Node/Express).
Amazon excluded (AWS-microservices, no single app-language claim
confirmed — not a sensible single-stack target). Etsy/WooCommerce excluded:
both are PHP, landing in the same (PHP, synchronous, template-rendering)
group as each other per §9.1 step 2, and PHP is already a built stack
(§9.2) — Walmart's Node/Express pick was preferred over a second PHP pick
per §9.1 step 4's reuse preference.

**Shopify functionality + Rails-CWE research** — full detail in
`docs/research/site-architecture-survey-functionality-shopify.md`.
Headline findings:
- Real, concrete grounding: Shopify's `X-Shopify-Hmac-SHA256` webhook-
  verification mechanism maps directly onto the existing `webhook-
  signature` corpus class — a strong candidate page (Rails'
  `ActiveSupport::SecurityUtils.secure_compare` vs. a naive `==` compare).
  Checkout is a separate PCI-scoped subsystem with a serverless
  customization layer ("Shopify Functions") for discount/shipping logic.
- Top CWE picks for genuine breadth: **CWE-915** (mass assignment via
  Rails `permit!` — the ID exists elsewhere in the corpus but never as a
  Rails idiom) and **CWE-502** (insecure deserialization via
  `Psych.load`/`YAML.load` — exists elsewhere only as a Python/pickle
  idiom). Third pick: the `order`/`pluck` identifier-position SQLi
  variant, Rails' analogue of the identifier-position shapes this
  corpus's PHP entries already value.
- Sourcing caveat: `shopify.dev` direct fetch was blocked by this
  sandbox's egress proxy; those claims are WebSearch-relayed, not
  directly fetched. CVE numbers not independently re-verified against
  NVD. Both flagged for follow-up before formal citation.

**Walmart functionality + Node-CWE research** — full detail in
`docs/research/site-architecture-survey-functionality-walmart.md`.
Headline findings:
- Real, primary-sourced grounding (Walmart's own Global Tech Blog): Node
  was adopted specifically as an orchestration/BFF layer aggregating
  legacy Java services; order management is a BPM-orchestrated state
  machine (payment auth → inventory reservation → routing → pick/pack →
  ship). A BFF aggregation endpoint mishandling one aggregated service's
  error differently than another (fail-open on an inventory timeout,
  correctly hard-failing on a pricing error) is a plausible, architecture-
  motivated logic-flaw placement — flagged as design synthesis, not a
  sourced fact.
- Top CWE pick for genuine breadth: **CWE-1333 (ReDoS)** — genuinely
  absent from the corpus, tied to a real, current Express-ecosystem CVE
  (`path-to-regexp`, CVE-2024-45296), and the project's own
  `docs/architecture/oracle-confirmation.md` already flags ReDoS as a
  deferred class needing a timing-differential (M1) oracle rather than a
  single-request one — a different confirmation shape than every other
  class this session has built so far, worth planning for explicitly.
- Second pick, **corrected from the dispatch brief's assumption**:
  **CWE-1321 (Prototype Pollution)** is not fully absent — the ID appears
  once incidentally and is already named as a first-wave sourcing class
  in `lab/patterns/sourcing/crosswalk.yaml`. What's actually missing is a
  **dedicated vulnerable/secure pair demonstrating the real pollution
  mechanism** (a live deep-merge, not an incidental side-effect) — still
  worth building, described accurately.
- **Flagged, not decided:** CWE-943 (NoSQL injection) would require
  giving this one app a second, non-relational persistence layer
  (`node_express`'s module inventory is committed to `mysql2`/relational)
  — the research explicitly declines to recommend this without an
  explicit scope call, rather than silently picking it.

**Decided (2026-09-22, project owner authorized proceeding on whatever this
session would have recommended given unavailability for further
questions):**

- **CWE-943 (NoSQL injection): declined**, per the research's own
  recommendation — `node_express`'s module inventory is committed to
  `mysql2`/relational persistence; giving one app a second, non-relational
  datastore for a single page is a bigger architectural change than this
  pilot's scope justifies. Not picked up by any category unless a future
  category's own site-pair genuinely needs MongoDB as its primary store.
- **Shopify (Rails) cells — 3, matching this project's established
  per-app cell count:**
  1. **Webhook-signature verification** (extends the existing
     `webhook-signature` corpus class with a Rails idiom) — vulnerable:
     naive `==` string compare of the recomputed HMAC; secure: Rails'
     own `ActiveSupport::SecurityUtils.secure_compare`. Strongest
     grounding of the three (a real, specific Shopify mechanism).
  2. **CWE-915, mass assignment** via unguarded `permit!` vs. an explicit
     `.permit(:field, :field2)` allowlist, on a product/admin update
     endpoint.
  3. **CWE-502, insecure deserialization** via `YAML.load`/`Psych.load`
     vs. `YAML.safe_load`, on an admin bulk-import feature (e.g.
     importing product data with embedded metadata).
  The `order`/`pluck` identifier-position SQLi variant (§9.4a) is
  deferred, not dropped — a good candidate for a follow-up increment
  once the base 3 are proven, not blocking this pilot's first pass.
- **Walmart (Node/Express) cells — 2 for this pass, both genuinely new
  CWE IDs to the corpus:**
  1. **CWE-1321, prototype pollution** — vulnerable: an unguarded deep-merge
     (e.g. lodash `merge`/a hand-rolled recursive merge) of a user-supplied
     JSON body into a live settings/config object, letting a
     `__proto__`/`constructor.prototype` key pollute `Object.prototype`;
     secure: a merge that rejects those keys (or builds onto an
     `Object.create(null)` base). Placed on a BFF-style "update account/
     cart preferences" endpoint, matching the real functionality research.
  2. **CWE-1333, ReDoS** — vulnerable: a user-supplied search term used
     directly to construct a `RegExp` with no escaping/bounding (e.g. a
     "highlight my search term in results" feature); secure: escape regex
     metacharacters before constructing the pattern (treat the term as a
     literal). **Needs a genuinely different oracle mechanism** (a
     timing-differential confirmation, not a single-request one) —
     sequence this second, after prototype pollution is proven, since it's
     the harder of the two to get right; do not let it block landing
     prototype pollution first if it runs long.
- **Page/app identity:** given the research's own synthesis (§9.4a), the
  two apps are NOT merged into one — they stay two separate generated
  apps (matching "2 new apps per category," not one combined app), each
  with its own coherent identity: a Shopify-style merchant storefront +
  admin app (webhook config, product management, checkout-adjacent
  discount handling) for the Rails pick, and a Walmart-style BFF-fronted
  storefront (account/cart preferences, search) for the Node pick.

### 9.5 What's actually next (this session's pilot)

Category 1 (E-commerce) is now **piloting**, per §9.4's row. The concrete
next steps, in order, per §9.1-§9.3's discipline:

1. ~~Create `claude/second-target-cat1-ecommerce` and do all pilot work
   there (not on `main`).~~ **Done.**
2. ~~Functionality/feature research for Shopify (Rails) and Walmart
   (Node/Express) specifically.~~ **Done — see §9.4a and the two research
   docs it links.**
3. ~~Stack-specific CWE research for each.~~ **Done — see §9.4a.**
4. ~~Finalize which CWEs become this app's actual manifest cells.~~ **Done
   — see §9.4a's "Decided" block: 3 Rails cells (webhook-signature idiom,
   CWE-915, CWE-502), 2 Node cells (CWE-1321, CWE-1333). CWE-943 declined.**
5. ~~Build the Rails skeleton/live-boot harness (this category's version
   of §2's Phase A, for a stack that didn't exist in this project at all
   before).~~ **Phase A done (`CC-LAB-0071`/`FR-LAB-65`, 2026-09-22): a
   real, trimmed, checked-in Rails 8.1.3.1 skeleton
   (`fuzzlab/labgen/emitters/ruby_rails/stack/skeleton/`), a `RailsEmitter`
   rendering one illustrative reflected-XSS-shaped cell, and
   `RailsLiveBootHarness` (`fuzzlab/labgen/conformance/rails_live_boot.py`)
   proven end to end by a real, executed, passing test
   (`tests/test_labgen_ruby_rails_live_boot.py`, 1 passed, ~4.9s real
   `bundle install` + migrate + boot + HTTP round trip). **Phase B is now
   also done** (`CC-LAB-0072`-`0075`/`FR-LAB-66`-`68`, 2026-09-22, see the
   progress update below) — the actual Rails-idiom vulnerability modules
   this section's own "Decided" block names (webhook-signature idiom,
   CWE-915, CWE-502), widening `RailsEmitter._MODULE_SET_BY_SHAPE` from the
   one Phase A shape to four. In parallel: deepen `node_express`'s module inventory with the
   two new Node cells (§3's Phase B, extended with the specific
   CWE-1321/1333 modules §9.4a names — these are additive to what §3
   originally scoped generically; CWE-1321 already done, see
   `CC-LAB-0070`/`FR-LAB-64`). Then: design and build the pages (§4's
   Phase C, now corpus-grounded per the real Shopify/Walmart research),
   prove conformance (§5), wire into `multitarget.py` (§6).
5. Update §9.4/§9.4a at every step above — do not wait until the category
   is fully done to report progress.

**Progress update (2026-09-22):** the CWE-1321 (prototype pollution) half of
step 5's Node cells is **done** — `CC-LAB-0070`/`FR-LAB-64`, a real
`unguarded_deep_merge`/`proto_key_filtered_merge` pair at a BFF-style
`/api/preferences` endpoint, proved with a real, executed `node` subprocess
adversarial test (see `docs/components/01-target-lab/change-control.md`'s
`CC-LAB-0070` entry for full detail).

**Progress update (2026-09-22, ReDoS lane):** the CWE-1333 (ReDoS) half of
step 5's Node cells is now also **done** — `CC-LAB-0076`/`FR-LAB-69`, a real
`unescaped_regex_construct`/`regex_escape_construct` pair at a search/
highlight `/api/search` endpoint, proved with a real, executed `node`
subprocess timing test (measured ~55-70ms vulnerable vs. <1ms secure on a
calibrated payload/content pair, 5x flakiness check, no variance observed --
see `docs/components/01-target-lab/change-control.md`'s `CC-LAB-0076` entry).
This also required, and built, the timing-differential (M1) oracle mechanism
this shape's own §9.4a decision flagged as needed:
`RegexDosStrategy` (`fuzzlab/oracle/strategies.py`, `CC-FUZZ-0025`/
`FR-FUZZ-12`) -- a genuinely new M1 *variant* (escalating independent
evil-regex shapes rather than a requested delay), fitted into the existing
`ConfirmationStrategy` taxonomy and documented in
`docs/architecture/oracle-confirmation.md`, which no longer lists ReDoS as
deferred. Both Walmart/Node cells §9.4a's "Decided" block named were
therefore now built. Not done here (explicitly out of this lane's scope):
wiring `node_express`/the new oracle strategy into `multitarget.py`, and
running the oracle mechanism against a live target. The Rails skeleton
(Phase A, `CC-LAB-0071`, done by a concurrent lane on this same branch) and
Phase C page design remain the next work.

**Progress update (2026-09-22, Rails Phase B lane):** all 3 Shopify/Rails
cells §9.4a's "Decided" block names are now **done**, built against the
Phase A skeleton/harness by a concurrent lane on this same branch --
`RailsEmitter._MODULE_SET_BY_SHAPE` widened from the one Phase A shape to
four:

- Webhook-signature verification (`CC-LAB-0072`/`FR-LAB-66`): a real
  naive-`==`-vs-`ActiveSupport::SecurityUtils.secure_compare` pair over a
  recomputed HMAC-SHA256, the first implementation of the existing
  `webhook_signature_verification` sink family in any stack. Proved two
  ways: a real HTTP round trip against both booted twins with a real
  forged valid/tampered signature (both twins correctly accept/reject --
  the vulnerability is a timing side channel, not a functional bypass, per
  D20's own `partial` framing), and a real, isolated Ruby timing
  microbenchmark (`RailsLiveBootHarness.run_ruby`) showing plain `==`'s
  early-vs-late mismatch timing ratio at ~4.8x vs. `secure_compare`'s own
  ~1.02x, executed against the real `activesupport` gem this app's own
  `Gemfile.lock` resolved.
- CWE-915 mass assignment (`CC-LAB-0073`/`FR-LAB-67`): Rails' own
  unrestricted `permit!` vs. an explicit `permit(:username, :bio)`
  strong-parameters allowlist, against the checked-in `users` table (a new
  migration adds the one privilege-relevant `role` column the pair needs).
  Proved with a real HTTP PATCH against each booted twin: the vulnerable
  twin's real ActiveRecord write lets an attacker also set `role`; the
  secure twin's real write silently drops it.
- CWE-502 insecure deserialization (`CC-LAB-0074`/`FR-LAB-68`):
  `YAML.unsafe_load` vs. `YAML.safe_load`, the first implementation of the
  existing `object_deserialization` sink family in any stack. Proved with
  a real HTTP POST carrying a `!ruby/object:OpenStruct` YAML payload: the
  vulnerable twin's real response reports a real `OpenStruct` was
  constructed server-side; the secure twin's real response reports
  `Psych::DisallowedClass` instead.

Shared harness/tooling this required (`RailsLiveBootHarness`
`raw_body`/`headers`/`run_ruby`, `tier0.lint_ruby`, `application_controller
.rb`'s `skip_forgery_protection`) tracked under `CC-LAB-0075`/`FR-LAB-66`-
`68` (cross-referenced). All three pairs derive their expected verdict,
`ruby -c` lint clean, regenerate byte-identically (Tier 3), and pass their
real live-boot proofs with no observed flakiness across repeated runs --
see `docs/components/01-target-lab/change-control.md`'s `CC-LAB-0072`-
`0075` entries for full detail. Both Shopify/Rails and Walmart/Node app
cell lists §9.4a's "Decided" block named are therefore now fully built.
**Not done here** (explicitly out of this lane's scope, per its own
dispatch instructions): wiring `ruby_rails`/`node_express`/the ReDoS
oracle strategy into `multitarget.py`; Phase C page design/identity for
either app; the deferred `order`/`pluck` identifier-position SQLi variant
§9.4a flags as a follow-up increment, not part of this pilot's first pass.

**Progress update (2026-09-23, Walmart/Node Phase C/D/E lane):** the
Walmart/Node half of the two items the previous update flagged as not done
is now **done**, built concurrently with the Rails/Shopify lane's own
Phase C/D/E work on this same branch (each lane's own half only, per
`docs/MULTI_AGENT_ORCHESTRATION.md`'s coordination contract).

- **Phase C (app identity + ground truth), `CC-LAB-0077`/`FR-LAB-81`:** the
  two existing real Node cells (prototype pollution at `/api/preferences`,
  ReDoS at `/api/search`) are now assembled into one small, coherent app
  identity, the **MeadowMart BFF** (a fictitious brand; its shape -- a
  Node/Express layer aggregating legacy services rather than owning its
  own domain logic -- is grounded in the real Walmart Global Tech Blog
  research this category's §9.4a research already did). Each real page's
  canonical (vulnerable) cell is now served at its actual, coherent BFF
  URL (`/api/preferences`, `/api/search` -- previously both cells of both
  pairs landed at a synthetic, identity-free `/generated/<cell-id>` URL);
  its secure twin at a deterministic `-twin-<cell-id>` variant of that same
  URL (the same canonical/twin-URL mechanism `php_laravel` already uses,
  for the identical "twins must coexist as distinct live routes in one
  process" reason). Three new, always-included, genuinely inert
  surrounding routes (`/api/products`, `/api/orders/:orderId`, `/api/cart`)
  make the assembled app read as a small BFF storefront rather than two
  isolated endpoints -- none reads or reflects any request input, and none
  carries a manifest cell or ground-truth case of its own. New
  `lab/ground-truth-meadowmart/` (opaque `MMART-NNNN` case IDs, distinct
  from `PFF-*` and the concurrent Rails lane's `FCART-*`; `target:
  "node_express_meadowmart_bff"`) follows D9's out-of-band contract exactly
  and loads/validates for real via `fuzzlab.labels.contract.load`. This
  required an additive `labels.schema.json` enum widening
  (`vuln_class`/`sink_context` gain `prototype_pollution`/`redos` and
  `object_property`/`regex` respectively -- neither class could be
  expressed in the ground-truth contract before this).
- **Phase D (whole-app live-boot conformance), `CC-LAB-0078`/`FR-LAB-82`:**
  closed the real gap every prior `node_express` proof left open --
  isolated `require()`-and-fake-`req`/`res` per cell, never the whole
  assembled app (every cell's route, `render_route_accumulator`'s real
  cardinality) booted together and driven over real HTTP. New
  `tests/test_labgen_node_bff_app.py`: a real, network-reachable `npm
  install`, a real `node app.js` boot on `127.0.0.1`, and real HTTP
  (`urllib.request`) against every route -- the three inert pages, both
  real pages' canonical URLs, both twins' URLs, and (directly observable
  over real HTTP, unlike prototype pollution's own in-band-invisible
  finding) the ReDoS cell's real timing differential, all proven against
  the fully assembled app, not a single isolated handler.
- **Phase E (`multitarget.py` wiring), `CC-LAB-0079`/`FR-LAB-83`:** this
  app's own real `TargetSpec` (`base_url` from the same real live-booted
  app Phase D assembles; `ground_truth` from Phase C's
  `lab/ground-truth-meadowmart`), run for real through
  `fuzzlab.harness.multitarget.run_targets`/`transfer_summary` using the
  existing, unmodified `fuzzlab.tools.probesender.RequestsProbeSender` (a
  real HTTP sender, not a hand-written fake). New
  `tests/test_labgen_node_bff_multitarget.py` proves a real, scored
  `ScoreReport` comes back (tp=0, fn=2, precision=recall=0.0 --
  **honestly 0, not a bug**: neither `prototype_pollution`'s nor
  `redos`'s raw vuln_class name is mapped by
  `fuzzlab.core.runmode._VULN_TO_CATEGORY` nor known to
  `fuzzlab.audit.rules.known_categories()`, so the audit stage nominates
  zero candidates for either before any oracle confirmer is even reached;
  `redos` already has a downstream confirmer, `RegexDosStrategy`, but under
  a *different* category string, `regular-expression`, that nothing
  upstream currently routes a candidate to) and `transfer_summary`
  correctly reports `generalizes=False` for the single target. Wiring the
  category mapping/an audit rule so these two classes can actually be
  nominated and confirmed is real, sized follow-on work, flagged here, not
  attempted by this lane. Combining this `TargetSpec` with the concurrent
  Rails/Shopify lane's own one in a single `run_targets` call (§6 step 2)
  is also left for a follow-on step, once both exist on a merged branch.

Full test suite re-run clean after this lane's changes (1891 passed, 8
skipped, 0 failed, `not slow`-marked tests deselected) -- see
`docs/components/01-target-lab/change-control.md`'s `CC-LAB-0077`-`0079`
entries for full detail.

**Progress update (2026-09-23, Rails/Shopify Phase C/D/E lane):** the
Rails/Shopify half is now also **done**, built concurrently with the
Walmart/Node lane's own Phase C/D/E work above on this same branch (each
lane's own half only). **Bookkeeping note, read before trusting any ID
below:** this lane's dispatch brief pre-assigned `CC-LAB-0077`-`0079`/
`FR-LAB-81`-`83` for this work -- but at start-of-work this lane checked
this file's own CHANGELOG.md/`docs/components/01-target-lab/change-
control.md` (per §9.3 point 3's own instruction to check for updates from
other sessions before assuming any are stale) and found the concurrent
Walmart/Node lane had already landed those exact numbers first (see the
progress update immediately above). Renumbered to the next actually-free
block, `CC-LAB-0080`-`0082`/`FR-LAB-84`-`86`, before writing anything --
exactly the coordination check §9.3/`PA-0031` exist to require, applied
successfully rather than colliding on merge.

- **Phase C (app identity + ground truth), `CC-LAB-0080`/`FR-LAB-84`:** the
  four existing real Rails shapes (Phase A's illustrative reflected XSS;
  Phase B's webhook-signature, CWE-915 mass assignment, CWE-502 insecure
  deserialization) are now assembled into one small, coherent app
  identity, the **ForgeCart storefront + admin** (a fictitious brand; its
  shape -- a Shopify-style merchant storefront + admin -- is grounded in
  this category's own `docs/research/site-architecture-survey-functionality-shopify.md`).
  Five new real-page cells (`LABGEN-RR-RP-0001`..`0005`) get real,
  coherent URLs (`_REAL_PAGE_URL_BY_CELL_ID`, checked first by
  `url_path_for`): the storefront search box (`/search`, reflected XSS);
  two real, distinct Shopify webhook topics (`/webhooks/orders/create`
  vulnerable -- naive `==`; `/webhooks/customers/update` secure --
  `secure_compare`, giving this app's own ground truth a genuine negative
  real-page case, not an all-positive set); the merchant-admin
  customer-account update (`/admin/customers/update`, CWE-915) and
  product bulk-import (`/admin/products/import`, CWE-502). Every
  pre-existing cell (`LABGEN-RR-0001`..`0007`) is untouched and keeps its
  prior `/cell/<slug>` URL and passing tests unchanged. Five new,
  always-included, genuinely inert surrounding routes/controllers
  (storefront home/products/cart, admin dashboard/orders --
  `route_accumulator._STATIC_APP_ROUTES` plus their own checked-in
  `StorefrontController`/`AdminController`) make the assembled app read
  as a small Shopify-style storefront+admin rather than four isolated
  endpoints. New `lab/ground-truth-forgecart/` (opaque `FCART-NNNN` case
  IDs, distinct from `PFF-*` and the concurrent Node lane's `MMART-*`;
  `target: "ruby_rails_forgecart"`; 4 positive/1 negative case) follows
  D9's out-of-band contract exactly and loads/validates for real via
  `fuzzlab.labels.contract.load`. Required an additive
  `labels.schema.json` enum widening (`vuln_class` gains
  `webhook_signature`/`mass_assignment`/`insecure_deserialization`,
  `sink_context` gains matching values -- none of the three classes could
  be expressed in the ground-truth contract before this).
- **Phase D (whole-app live-boot conformance), `CC-LAB-0081`/`FR-LAB-85`:**
  closed the real gap every prior `ruby_rails` proof left open -- one or
  two cells booted in isolation, never the whole assembled app. New
  `tests/test_labgen_ruby_rails_whole_app_live_boot.py`: all 12 cells this
  stack has ever built (1 Phase A + 6 Phase B + 5 Phase C), one real
  `bin/rails server` boot, real HTTP against every route, no route
  collision. **Found and fixed a real, 100%-reproducible defect while
  building this** (full bug protocol run, not just a code fix):
  `BUG-0035`/`PA-0037` -- the checked-in skeleton's `Gemfile` never pinned
  the `json` gem, so an unconstrained `bundle install` resolved `json
  3.0.2` (`activesupport` 8.1.3.1's own gemspec declares only `json >=
  0`), whose keyword-only `JSON.parse` broke `ActiveSupport::JSON.decode`'s
  own positional call on the read path of every encrypted session-cookie
  read -- 500'ing every second request of any session, invisible to two
  full build phases' worth of single-request-per-test coverage. Fixed by
  pinning `gem "json", "~> 2.7"` and regenerating `Gemfile.lock` for real
  (resolves `json 2.21.2`); full RCA in `docs/bugs/BUG-0035-rails-skeleton-
  json-gem-arity-breaks-second-request-in-a-session.md`, preventive action
  `PA-0037` in `docs/PREVENTIVE_ACTIONS.md`.
- **Phase E (`multitarget.py` wiring), `CC-LAB-0082`/`FR-LAB-86`:** this
  app's own real `TargetSpec` (`base_url` from the same real live-booted
  app Phase D assembles; `ground_truth` from Phase C's
  `lab/ground-truth-forgecart`), run for real through
  `fuzzlab.harness.multitarget.run_targets`/`transfer_summary` using the
  existing, unmodified `fuzzlab.tools.probesender.RequestsProbeSender`.
  New `tests/test_multitarget_ruby_rails_forgecart.py` proves a real,
  scored `ScoreReport` with **`tp>=1`** -- the real `/search`
  reflected-XSS case is genuinely confirmed by `run_auto`'s existing,
  unmodified detection machinery (`xss` is a category it already knows how
  to confirm on `php_laravel`/`php_current`; this proves that same
  mechanism transfers to a brand-new Rails target it has never seen
  before), unlike this app's three brand-new vuln classes
  (`webhook_signature`/`mass_assignment`/`insecure_deserialization`),
  which score 0 recall for the same documented-gap reason the Node lane's
  own two brand-new classes do above. A second run against a fresh boot of
  the same app gets its own distinct `run_id`. Combining this `TargetSpec`
  with the Walmart/Node lane's own one in a single `run_targets` call (§6
  step 2) is left for a follow-on step, once both exist on a merged
  branch -- same note the Node lane's own update above already makes.

Full `ruby_rails`-scoped test suite re-run clean after this lane's changes
(12 slow tests passed, 2 skipped, 0 failed) and the shared
`contract`/`schema` suite re-run clean too (57 passed, 2 skipped) -- see
`docs/components/01-target-lab/change-control.md`'s `CC-LAB-0080`-`0082`
entries for full detail. **Both apps' full Phase A-E are now done** --
category 1's remaining work is combining both `TargetSpec`s in one
`run_targets` call (§6 step 2) and, per §9.3 point 6, opening a PR into
`main` once this branch is otherwise ready.
