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
| Node/Express, synchronous API | Shallow (Tier-A), being deepened | §§1-6 above (pre-expansion plan) | Not yet full depth; whichever category picks Node/Express as one of its two should coordinate with whoever is deepening it rather than starting a second effort. |
| Python, async API (FastAPI/Pydantic) | Shallow (Tier-A) | Original Phase 3 lane | Exists; available to reuse if a category's pick lands here specifically (not just "Python" generically — see §9.1 step 2's paradigm distinction, e.g. this is NOT the same stack as Django). |
| *(add a row per new stack the moment a category picks it — before building it, not after)* | — | — | — |

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
| 1 | E-commerce/marketplaces | **Piloting** | Shopify (Ruby on Rails); Walmart (Node/Express — reuses existing) | Ruby on Rails | `claude/second-target-cat1-ecommerce` | `CC-LAB-0070`-`0089` (reserved, not yet all used) | Amazon excluded (AWS-microservices, no single app-language claim confirmed — not a sensible single-stack target); Etsy/WooCommerce excluded as redundant with Shopify's PHP-adjacent... no — Etsy/WooCommerce are PHP, genuinely distinct from Rails, but both landed in the same (PHP, synchronous, template-rendering) group as each other per §9.1 step 2, and PHP is already a built stack (§9.2) — Walmart's Node/Express pick was preferred over a second PHP pick specifically per §9.1 step 4's reuse preference. Functionality research and CWE research for this pair: **not started yet** — next step. |
| 2 | Social / UGC platforms | Not started | — | Likely Python/Django (Instagram) is the strongest new-stack candidate; Facebook (PHP/Hack+HHVM) may or may not warrant a *new* stack vs. reusing `php_laravel`/`php_current` as an approximation — this is exactly the kind of call §9.1 asks the picking session to make and record, not this table to pre-decide. Discord flagged in §9.1 step 1 as likely excluded (realtime/Elixir, not a request/response fit). YouTube likely excluded (Google-internal infra, no portable app-language claim). | — | — | Open for another session to pick up. |
| 3 | SaaS / productivity / collaboration | Not started | — | Candidates per the survey: Slack (PHP/Hack web tier + Java realtime — itself two stacks), Notion (sharded Postgres + Kafka, but no named app-framework/language beyond "engineering blog doesn't name one" — check before committing), Atlassian (Java/Kotlin+Spring, Node+Express, or Python — Atlassian itself uses 3 stacks, pick the one most distinct from what's already built), Microsoft 365/Teams (Node.js backend + React/TS front end), Google Workspace (OT + Spanner/Bigtable — confirmed at the algorithm/storage level, not at a portable app-framework level; may not be a sensible single-stack pick without further research). | — | — | Open. Flag: Google Workspace's confirmed detail is algorithmic/storage, not framework-level — whoever picks this category should research further (per the standing instruction to do more research if needed) before treating it as buildable, or should pick two of the other four sites instead. |
| 4 | Media / streaming / content platforms | Not started | — | Candidates: Netflix (Java/Spring Boot + a Federated GraphQL gateway), Spotify (Java/Spring + Kafka), Twitch (Go, post-monolith-migration — genuinely distinct paradigm from the others), Disney+ (excluded per §9.1 step 1 — infrastructure-only, unconfirmed at application-code level). | — | — | Open. Twitch/Go vs. Netflix-or-Spotify/Java+Spring reads as the most architecturally distinct pair from the current research, but the picking session should verify against §9.1's full procedure rather than take this as decided. |
| 5 | Travel / booking / marketplaces | Not started | — | Candidates: Booking.com (PHP+MariaDB — same language-family caveat as category 1/2's PHP sites, check §9.2 before assuming reuse), Airbnb (Ruby on Rails + Java/Dropwizard — Rails may already be built by the time this category starts, per §9.2's ledger; check it), Expedia (Java/Spring Boot, later Kotlin), TripAdvisor (event-driven microservices + GraphQL BFF — no single portable app-language claim as clearly named as the others), Trip.com (excluded per §9.1 step 1 — unconfirmed at the application-language level). | — | — | Open. |
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
