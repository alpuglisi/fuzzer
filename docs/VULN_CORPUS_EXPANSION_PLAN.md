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

**Taxonomy granularity.** There's no single canonical "correct" size for a
catalog like this — taxonomy design generally trades off a small number of
broad buckets (easy to keep mutually exclusive, but each hides real
variation) against a large number of narrow ones (precise, but harder to
keep non-overlapping and quickly unwieldy). For this catalog, use a
single-tier list of **user-facing, sink-bearing capabilities** — each entry
should be something a user or admin *does* that causes the app to touch a
sink (a query, a file write, a shell call, a template render), not an
implementation concern. Concretely:

- Target **15-25 top-level features** for the first pass — enough to cover
  the obviously common categories (the list already sketched above is a
  reasonable start) without fragmenting into near-duplicates.
- **Boundary rule:** if two candidate features would collect examples from
  the same code shape and the same sink family (e.g. "search" and
  "reporting/exports" both usually reduce to "user-supplied filter/sort
  params reach a DB query"), merge them into one feature and note the
  variants in its description rather than splitting them.
- **Cross-cutting concerns are not features.** Something like "input
  validation," "logging," or "error handling" isn't a standalone feature
  in this catalog — it's a property that shows up *inside* many features'
  examples. Don't give it its own row; instead note it as a recurring
  pattern when it appears while collecting a real feature's examples.
- "APIs/webhooks" is broad enough to risk swallowing other rows (an API
  endpoint can front almost anything). Keep it scoped to what's distinct
  about *that* shape — auth/signature verification on inbound webhooks,
  mass-assignment/param-binding on API endpoints — and let feature-specific
  rows (checkout, messaging, etc.) own their own sinks even when they
  happen to be exposed over an API.
2. **Which of those features are disproportionately associated with real
   exploitation?** Cross-referenced against OWASP Top 10 / OWASP WSTG
   categories, CWE prevalence data, and documented real-world breach/bug-
   bounty patterns — not just theoretical risk.

**Merging the two angles into one prioritized list:** OWASP's own Top 10
methodology is the model to follow here — it merges a "how common is this
CWE" signal with a "how many tested apps had it" prevalence signal into a
single ranked list, rather than publishing two separate lists side by side
(OWASP 2021/2025 data-collection methodology). Concretely, for each
candidate feature from angle 1:

1. **Commonality score (1-3):** how often the feature shows up across
   typical web apps/sites (1 = niche/optional, 2 = common in a given
   app category, 3 = near-ubiquitous — e.g. auth, search).
2. **Exploitability score (1-3):** how strongly angle 2's sources associate
   the feature with real exploitation — OWASP Top 10/WSTG category hit,
   CWE prevalence data, or a documented breach/bug-bounty pattern. Score 3
   only if at least two independent source types agree (e.g. an OWASP
   category *and* a bug-bounty writeup, not just one blog post).
3. **Priority = commonality x exploitability** (max 9). Rank the merged
   list by this product, not by either angle alone, and record which
   sources justified each score inline next to the feature (so the number
   is auditable, not vibes).
4. A feature scoring 3x3 belongs near the top of Phase 2's collection
   queue; a 1x1 is a candidate to skip or defer.

This keeps the two research angles procedurally separate (so each stays
easy to run/verify independently) while producing one ranked table as the
actual Phase 1 output, instead of two disconnected lists.

**Output:** a single documented, ranked list (this file, "Candidate feature/
vulnerability list" section below, filled in once research lands) of
feature areas worth targeting, each annotated with its commonality score,
exploitability score, the vulnerability class(es) it's known to be
susceptible to, and why (with source citations).

## Phase 2 — real source-code collection (not started)

For each feature on the Phase 1 list: search GitHub for real, published
example implementations of that feature — vulnerable and/or idiomatic
implementations both count as reference material. This is a reference
corpus for humans/agents designing module templates, not an ML training
set, so target counts stay small and deliberate rather than exhaustive:

**Pairing vulnerable and idiomatic examples.** `safety_matrix.yaml` rows
are inherently contrastive — each `(op, sink_family)` pair carries an
`effect` (e.g. `no_effect` for a vulnerable shape like `raw_concat` vs. a
neutralizing transform for a parameterized/escaped equivalent at the same
sink). Established vulnerability benchmarks lean on exactly this contrast:
the NIST SARD/Juliet Test Suite pairs a `bad()` (vulnerable) and `good()`
(patched) function for the same CWE in the same file specifically so a
tool/human can compare the two directly, and OWASP Benchmark similarly
labels each test case's vulnerability status against a matched shape. This
plan should follow that precedent rather than leave "vulnerable and/or
idiomatic... both count" as loosely interchangeable:

- **Require a matched pair per feature+language cell where feasible:** at
  least one vulnerable-shape example and one idiomatic/safe-shape example
  of the *same* sink (e.g. file-upload's PHP cell wants both a
  no-extension-check `move_uploaded_file()` call and a
  denylist/allowlist-checked equivalent), not just whichever shape happens
  to turn up first.
- If only one side of the pair can be found within the collection effort
  for a cell (e.g. real vulnerable code is easy to find but a clean
  idiomatic counterpart isn't, or vice versa), record the cell as
  **half-populated** and say so explicitly in that directory's
  `manifest.yaml` — don't pad with an unrelated shape just to check both
  boxes, and don't quietly drop the cell either.
- Note in each example whether it's the vulnerable or idiomatic side of
  its pair (a `role: vulnerable|idiomatic` field alongside the metadata
  already specified), since that's exactly the axis Phase 3's `effect`
  field will need.
- This mirrors the caveat noted in the benchmark research: paired
  `good()`/`bad()` cases are clean for illustrating a contrast, but can be
  simpler than real app complexity — real GitHub examples (vs. synthetic
  Juliet-style cases) are still preferred here specifically because they
  keep that real-world messiness, so don't over-simplify a pair just to
  make it match cleanly.

- **Per feature-per-language cell: 3-5 examples**, floor of 2 (below that,
  don't bother recording the cell — note the gap instead and move on).
  Stop early, below 5, once additional candidates are just re-showing the
  same implementation shape already captured (e.g. three more copies of
  the same tutorial-style raw-SQL search box add nothing). Push toward the
  upper end (up to 8) only when a feature genuinely has multiple
  meaningfully different shapes worth keeping distinct (e.g. search
  implemented as raw SQL concat vs. an ORM query-builder vs. a
  full-text-search service call are different enough to keep separately).
- Where a feature appears in multiple languages/stacks, collect examples
  per language separately (same 3-5 target per language), prioritizing the
  languages/stacks `fuzzlab` already models (see `lab/safety_matrix.yaml`'s
  existing per-stack module templates) before adding new ones.

**Source quality bar.** Not every GitHub hit is worth collecting from.
Apply this triage before adding an example to the corpus:

- **Skip:** repos with no LICENSE file and no license declared in the
  GitHub UI (undeclared license = "all rights reserved" by default —
  don't copy from these at all, see the license note below); forks with
  no changes of their own; repos that are clearly disk/backup dumps
  (default README, no commits beyond initial import); auto-generated or
  vendored code (the actual upstream, not a mirror, is the source to cite).
- **Prefer:** repos with a real README and more than a handful of
  commits (shows it's actually maintained/used, not a one-off scratch
  file); recent activity (pushed within the last ~2-3 years) *unless* the
  example is deliberately historical (e.g. a known-vulnerable legacy
  pattern still relevant to the class being documented); a declared
  OSI-approved license; for "idiomatic"/secure examples, some community
  signal (stars/forks) as a weak proxy that the pattern is actually used,
  not just written once. None of these is individually disqualifying on
  its own if the code shape itself is a good, clear illustration of the
  feature/vulnerability — the bar is "not obviously junk or unlicensed,"
  not "must be a popular project."
- Tutorial/course-project code is fine to include (and often the
  *clearest* illustration of an unsafe idiomatic shape) but must be
  labeled as such in that example's `manifest.yaml` entry, so Phase 3
  doesn't mistake it for production-derived evidence of real-world
  prevalence.

**Scope cap.** Deriving the estimate directly from Phase 1's stated target
(15-25 features) rather than restating a separate number: 15-25 features x
2-3 languages/stacks each x 3-5 examples (2 minimum per cell to satisfy the
vulnerable/idiomatic pairing above) puts the corpus in the rough range of
**90-375 examples total** — treat that as the expected order of magnitude,
not a hard ceiling. If collection is trending past **~400 examples**, stop
and check with a human before continuing (a sign the feature list itself
was scoped too broadly, or the quality bar above isn't being applied).
Track running totals in this file's Status section (or a short tally in
`docs/research/corpus-examples/README.md` once that directory exists) so
scope creep is visible as it happens rather than discovered after the fact.

**Organization and metadata:** one `manifest.yaml` per feature+language
directory is the single canonical place all of a cell's example metadata
lives — every other reference in this plan to "the note," "the metadata,"
or "the per-example note" means an entry in this file, not a separate
NOTES.md or inline comment:

```
docs/research/corpus-examples/
  file-upload/
    php/
      manifest.yaml
      vulnerable-1.php
      idiomatic-1.php
    node/
      manifest.yaml
      ...
  search/
    php/
      manifest.yaml
      ...
  ...
```

Source files are named `<role>-<n>.<ext>` (`role` is `vulnerable` or
`idiomatic`, per the pairing requirement above) so the pairing is visible
from the directory listing alone, without opening the manifest. Each
`manifest.yaml` is a list with one entry per example in that directory:

```yaml
- file: vulnerable-1.php
  role: vulnerable
  repo: owner/name
  commit_sha: 3f9a1c2e8b7d4560a1b2c3d4e5f6a7b8c9d0e1f2   # full 40-char SHA,
                                                          # not a branch/tag
  license: MIT
  pattern: "unchecked extension, moved into web-root"
  notes: "mirrors puppy-fort-factory's own unrestricted-upload shape"
  validated: false   # every entry defaults to this the moment it's created,
                      # Phase 2 or Phase 3 -- see Phase 3's "Validated data
                      # only reaches lab-generation-facing files"
  validated_by: []   # populated only once validated: true is set
```

The full 40-character commit SHA (never a branch/tag — branches move and
tags can be re-pointed; a SHA is the only reference that's actually
immutable) is what makes the citation reproducible later (a reader can
`git clone` and check out that exact commit to verify the claim) and
protects against the source repo being deleted, force-pushed, or
relicensed after collection — if the license changes upstream after the
SHA was pinned, the corpus entry still correctly reflects the terms that
applied when the snippet was taken. Phase 3 later appends `cwe`,
`suggested_op`, and `suggested_sink_family` fields to each existing entry
in place (see Phase 3 below) rather than creating a second metadata file.

**Secrets/PII scrubbing.** This project treats "never commit secrets" as
non-negotiable (`docs/DECISIONS_AND_ROADMAP.md` D12: credentials live in
the OS keyring, never committed) — and Phase 2 is copying real,
third-party example code into this repo, which routinely contains
hardcoded demo credentials, API keys, or incidental PII (a tutorial's
`sk_live_...`-shaped placeholder, a hardcoded DB password, a real email
address left in a comment). Before a snippet is committed:

1. Run a lightweight secret scanner over each new file before it's added —
   **gitleaks** (regex/rule-based, fast, works well as a one-off local
   scan: `gitleaks detect --source <file>`) is sufficient for this corpus's
   scale; reach for something like TruffleHog's verification-first
   checking only if gitleaks flags something ambiguous and it's worth
   confirming whether a credential is live.
2. Any match gets the credential redacted (replace with an obvious
   placeholder like `REDACTED_API_KEY`) in the copied snippet, noted in
   that example's `manifest.yaml` entry (a `redacted: true` field) that a
   redaction was made, and the file is *not* pulled in unredacted at any
   point in git history (scrub before first commit, not after).
3. Skim for obvious PII (real names/emails/phone numbers left in
   comments or fixture data) even if the scanner doesn't flag it — a quick
   manual read is proportionate here; this is a handful of files per
   feature, not a full CI pipeline.
4. When in doubt about a snippet (looks like it might contain a live
   secret, or its provenance is unclear), skip that example rather than
   spend time verifying it — there are other candidates for the same cell.

**License handling for collected snippets.** This corpus copies real
third-party source into this repo, so license terms apply per example, not
just as a blanket note:

- **Permissive (MIT, BSD-2/3-Clause, Apache-2.0, ISC):** safe to copy a
  small excerpt for this internal, non-distributed research purpose.
  Still record the license and reproduce the upstream copyright line in
  that example's `manifest.yaml` entry (attribution cost is near zero and
  keeps the provenance trail honest) — Apache-2.0 in particular expects a
  copy of the license notice to travel with copied code.
- **Copyleft (GPL/AGPL/LGPL family, MPL):** avoid wholesale file copies;
  if a snippet is worth keeping, keep the smallest illustrative fragment
  necessary and note the copyleft license prominently, since these
  licenses require derivative works to carry the same license — don't let
  a GPL snippet quietly become the seed of an emitter template later
  without that flag surviving into Phase 3's handoff.
- **No LICENSE file / no license declared:** treat as "all rights
  reserved" under default copyright law — **do not copy code from these.**
  It's fine to *cite* the repo/URL and describe the pattern in prose
  (a description of a shape isn't a copy of the expression), but the
  actual source text does not get pasted into this repo.
- Every example's `manifest.yaml` entry records the license verbatim
  (SPDX identifier where known) alongside its `repo`/`commit_sha`/`file`
  fields, so a later pass can audit or filter the corpus by license
  without re-fetching every source.

**Output:** an organized reference corpus of real code, per feature, per
language — input to Phase 3.

## Phase 3 — CWE mapping (deferred, not started)

Once Phase 2's corpus exists: identify the CWE(s) each collected example is
associated with, to ground the eventual `safety_matrix.yaml` vocabulary
(new `op`/`sink_family`/concern-ID rows) in a recognized taxonomy rather than
ad hoc naming. **Explicitly deferred** — do not start this until Phase 2's
corpus is in hand.

**Handoff into `safety_matrix.yaml` and module templates.** The existing
SQLi/XSS rows were derived manually from `puppy-fort-factory/
VULNERABILITIES.md` (cited by line number in the matrix's header) plus a
targeted spot-check (L-P1.2a's sqlmap run) before being hand-written as
`op`/`sink_family`/`effect` entries and their informative `concern-ID`
vocabulary. Phase 3 should follow that same precedent rather than invent a
new mechanical pipeline: this stays a human/agent-curated step, not an
auto-generated one, but it needs a structured intermediate so the curation
has something concrete to work from. That intermediate is the same
per-feature-per-language `manifest.yaml` Phase 2 already produces (see
Phase 2's "Organization and metadata" above) — Phase 3 appends three
fields to each existing entry rather than creating a second file:

```yaml
- file: vulnerable-1.php
  role: vulnerable
  repo: owner/name
  commit_sha: 3f9a1c2e8b7d4560a1b2c3d4e5f6a7b8c9d0e1f2
  license: MIT
  pattern: "unchecked extension, moved into web-root"
  notes: "mirrors puppy-fort-factory's own unrestricted-upload shape"
  validated: false   # already set by Phase 2 -- see Phase 2's
  validated_by: []   # "Organization and metadata" for these two fields
  # --- appended during Phase 3 ---
  cwe: [CWE-434]
  suggested_op: extension_denylist_check   # Phase 3's best guess at a
                                            # safety_matrix.yaml `op` name
  suggested_sink_family: fs_web_root_write # ditto for `sink_family`
```

Before proposing a *new* `suggested_op`/`suggested_sink_family` name,
check it against `lab/safety_matrix.yaml`'s existing entries (its current
vocabulary includes ops like `raw_concat`, `param_bind`,
`html_entity_escape`, `identifier_allowlist`, `url_scheme_allowlist`, and
sink families like `sql_string_literal`, `html_body`, `sql_identifier`,
`url_javascript_scheme`) — a shape that's really the same op/sink_family
pair under a new name (e.g. another `raw_concat` into a string-literal
sink, just in a new language) should reuse the existing name, not mint a
near-duplicate. Only genuinely new sink shapes or transforms get a new
name. Phase 3 then walks the manifests (not the raw source a second time)
to: (a) assign the CWE(s), (b) propose new `op`/`sink_family` rows
following the matrix's existing append-only convention (bump `version`
only for a breaking change to an *existing* pair, per the matrix's own
header) — checked against `lab/schemas/safety_matrix.schema.json` before
being treated as final — and (c) flag which examples justify a new
per-stack module template vs. which are redundant with a class the matrix
already covers. The `suggested_op`/`suggested_sink_family` fields are
proposals for the human/agent doing that later change to accept, rename,
or merge — not a guarantee the exact name survives into the matrix.

**Pair generation: alter collected code to manufacture a matched pair.**
A CWE assignment on its own doesn't guarantee the collected example is
paired the way `safety_matrix.yaml` needs (an `(op, sink_family)` row is
inherently a vulnerable-shape/neutralized-shape contrast, and Phase 2's
"pairing where feasible" requirement can still leave a cell half-populated
if the wild didn't offer both sides). Once a CWE is assigned to a
feature+language cell's collected example(s), close that gap deliberately
rather than continuing to search for a naturally-occurring match:

1. Take the collected source for that cell (whichever role — vulnerable or
   idiomatic — is on hand) and **produce an altered variant that is
   deliberately made vulnerable to the matched CWE**, using the collected
   code's own real structure/idiom as the base rather than a synthetic
   stand-in. If the collected example was already the idiomatic/safe side,
   the alteration introduces the flaw (e.g. removes the parameter binding,
   swaps an allowlist for raw concatenation); if it was already the
   vulnerable side, the alteration produces the corresponding fixed
   counterpart. Either direction is fine — what matters is that the
   resulting two files differ *only* in the specific mechanism the CWE
   describes, the same minimal-pair discipline `fuzzlab.labgen.minimal_pair`
   already enforces for generator output (see that module and its `pair_by`/
   content-confinement fix from this session for the actual invariant being
   mirrored here, even though this corpus predates and feeds the generator
   rather than being generator output itself).
2. **Generate more than one such pair per CWE — floor scaled to available
   source material, not a fixed count.** A single pair proves the
   alteration is *possible*, not that it's *representative*. Research into
   established benchmark/dataset conventions (Juliet, OWASP Benchmark,
   CVEfixes/BigVul/D2A) found no universal fixed minimum — purpose-built
   suites like Juliet go big (dozens of flow-pattern variants per CWE) for
   a stated reason (stress-testing static analyzers across control/data-flow
   shapes) that doesn't apply at this corpus's scale, while mined corpora
   (CVEfixes/BigVul) are naturally imbalanced with no target at all.
   Borrowing an arbitrary fixed number from neither precedent would be
   unmoored, so instead scale the floor to what Phase 2 actually collected
   for that CWE's feature+language cell: **generate pairs for at least half
   of that cell's available source examples, minimum 2** (a cell with only
   2 source examples uses both; a cell with 4-5 uses at least 2-3). This
   keeps the proof-burden proportional to what's actually on hand rather
   than either overclaiming variety from a thin cell or leaving usable
   source material idle in a well-stocked one. A naturally-collected pair
   that already satisfies the same CWE contrast (the wild genuinely offered
   both a vulnerable and a fixed real-world example of it) **counts toward
   this floor** — manufacturing is how gaps get closed, not a mandate to
   re-derive evidence Phase 2 already collected for free. Only the shortfall
   between what's naturally paired and the floor needs deliberate alteration.
3. Store the altered pair alongside (never overwriting) the original
   collected file: add `vulnerable-<n>-altered.<ext>` /
   `idiomatic-<n>-altered.<ext>` naming for a manufactured pair, distinct
   from the `<role>-<n>.<ext>` naming Phase 2 uses for as-collected source,
   so it's visible from the directory listing alone which files are
   real-as-found vs. deliberately modified. Each manufactured file gets its
   own `manifest.yaml` entry with a `derived_from` field pointing at the
   original collected file's own entry, plus the `cwe` field already
   established above — never a bare copy with no traceable origin.

**Validation: every pair must be confirmed before it's trusted.** An
altered pair is a claim ("this side is vulnerable to the matched CWE, this
side isn't") until it's actually checked — mirroring why this session built
a real live-boot harness for the generator itself rather than trusting a
rendered file's syntax validity alone (`fuzzlab/labgen/conformance/
live_boot.py`). Before a pair counts as validated:

**Validation execution sandbox (required before any DYNAMIC/execution
check — not required for the static-analysis tools below, which only
parse/scan source text and never run it).** Actually executing
deliberately-vulnerabilized third-party code is a distinct, real risk
surface, separate from and in addition to this project's existing lab
safety doctrine (`CLAUDE.md`'s loopback-only/`--authorized`-gated posture
governs the *generated lab*; this governs *running arbitrary altered
source during corpus validation*, which the lab doctrine doesn't cover).
Research into how established benchmarks handle this found a useful
negative data point: CVEfixes/BigVul/D2A never execute their vulnerable
examples at all (purely static mining), and OWASP Benchmark/Juliet/
WebGoat/DVWA's own guidance is "never expose to a network, run in an
isolated VM/container" without prescribing execution containment beyond
that — so this goes further than established precedent and needs its own
explicit rule, not an inherited one:

- **Network: zero outbound by default, no exceptions via allow-listing.**
  Command-injection and SSRF payloads are specifically designed to make
  the target reach out; an egress filter or allow-list is not reliable
  containment (DNS exfiltration and IP-literal SSRF both defeat naive
  filtering). Run every dynamic check with no network namespace/bridge at
  all. If a specific CWE's proof genuinely requires an external-looking
  endpoint (confirming an SSRF fired), the target is a mock server inside
  the *same* isolated network namespace — never the real internet, never a
  route back to the host.
- **Filesystem: ephemeral, scoped to the one fixture, destroyed per run.**
  Mount only the specific pair under test, read-only where the runtime
  allows it, a small tmpfs for scratch output. No reuse across runs and no
  persistent volume, so a path-traversal payload that manages to write
  somewhere can't contaminate the next validation.
- **Resource/time limits per run:** a memory cap, a `pids-limit` (blocks
  fork bombs), a wall-clock timeout (kill the run rather than let it hang),
  non-root user, all capabilities dropped, `no-new-privileges`.
- **Runtime: gVisor (`runsc`), not plain Docker/`runc`.** A dynamic check
  deliberately triggers real command execution (command-injection payloads
  are host-kernel-facing arbitrary code execution, not merely file/network
  misuse) across three language runtimes — a bigger threat than typical
  container isolation is built for. gVisor is a drop-in Docker runtime
  swap (`--runtime=runsc`, no architecture change, no VM images) that
  intercepts syscalls in userspace specifically for running third-party/
  untrusted code, and is the proportionate choice for a small research
  project (Firecracker/microVMs are the stronger option, worth it only at
  a scale — large-volume or multi-tenant — this project isn't at).
- **Explicit opt-in, audited per run** — mirroring the lab's own
  `--authorized` flag pattern rather than inventing a separate convention:
  a dynamic-check run requires an explicit flag, and every run is logged
  (which payload, which CWE, which fixture, pass/fail), so running a
  validation batch is always a visible, reviewable action, never an
  implicit side effect of some other command.

A concrete example invocation shape (illustrative, not a final CLI spec):
`docker run --runtime=runsc --network none --read-only --tmpfs /tmp
--cap-drop ALL --security-opt no-new-privileges --pids-limit 64
--memory 256m --user nobody <validation-image> <fixture-path>`, with a
wall-clock timeout wrapping the whole invocation and the container
destroyed immediately after. The static-analysis tools in step 2 below
(Semgrep, Bandit, Psalm, eslint-plugin-security) run directly, unsandboxed
— they read and pattern-match source text, they never execute it, so none
of the above applies to them.

1. **Structural check:** confirm the vulnerable and safe sides of a pair
   differ only in the mechanism the CWE describes — the same confinement
   check `minimal_pair.py` performs on generator output, applied here to
   arbitrary collected-language source. Use **difftastic**
   (github.com/Wilfred/difftastic) as the one structural-diff CLI across
   all three stacks this corpus targets (PHP, JS/TS, Python) — it's
   tree-sitter-based, ignores whitespace/formatting-only differences, and
   needs no per-language setup (`difft <vulnerable-file> <safe-file>`).
   Fall back to a language-native AST dump only when a claim needs
   programmatic (not just visual) confirmation that exactly one
   node/call-expression differs: `nikic/PHP-Parser` or the `php-ast`
   extension for PHP, `@babel/parser` for JS/TS, the stdlib `ast` module
   (`ast.dump(node, indent=...)`) for Python.
2. **Behavioral check, where the language/stack allows it:** actually
   exercise the vulnerable side, inside the sandbox above, and confirm
   it's exploitable (a real payload triggers the described effect) and the
   safe side isn't — the same standard this session's live-boot work
   applied to the `php_laravel` emitter's own output. Where standing the
   collected code up to actually run it isn't practical (a fragment with
   no runnable harness around it, a language/framework this project has no
   runtime for), fall back to a static-analysis tool as the next-best
   evidence (no sandbox needed for this path). **Semgrep** (semgrep.dev)
   is the primary cross-language tool for this — run `semgrep --config
   p/cwe-top-25 --config p/security-audit` (plus a per-language pack:
   `p/python`, `p/javascript`/`p/typescript`, `p/php`) across the pair,
   since one tool covering all three stacks for these CWE classes (SQLi,
   path traversal, command injection, SSRF, insecure deserialization, XSS)
   beats needing a different tool per language for the common cases. Layer
   a language-native tool only for classes Semgrep's generic rules tend to
   miss: **Bandit** (Python — pickle/deserialization, `subprocess`
   shell=True), **Psalm** with `--taint-analysis` (PHP — native
   taint-flow tracking, stronger than a rule-based scanner for multi-step
   SQLi/command-injection/XSS chains), **eslint-plugin-security** (Node —
   `child_process`/`eval`/unsafe-regex patterns Semgrep's generic JS rules
   don't always catch). Record in the `manifest.yaml` entry which
   validation method(s) were actually used, as a **list** since a check
   can legitimately layer more than one tool — `validated_by: [dynamic]`
   or `validated_by: [semgrep, bandit]`, etc. (values drawn from
   `dynamic|semgrep|bandit|psalm-taint|eslint-security|manual-review`) —
   never silently treat a weaker check as equivalent to a stronger one
   without saying so, and never collapse a layered check into a single
   value that hides what was actually run.
3. **No silent pass.** A pair that fails validation (the alteration didn't
   actually introduce/fix the described flaw, or the two sides differ in
   more than the declared mechanism) is not corrected quietly and re-marked
   valid — log what was wrong, fix it, and re-run the validation from step 1
   before it counts.

**Validated data only reaches lab-generation-facing files.** The corpus
collected and altered in Phases 2-3 (everything under
`docs/research/corpus-examples/`) is reference/staging material — it must
**never** be read directly by anything that builds the actual generated lab.
A pair is only eligible to inform a real `lab/safety_matrix.yaml` row, a new
per-stack module template, or a new manifest cell once its `manifest.yaml`
entry carries `validated: true` (set only after step 2 above passes, not
step 1 alone). Concretely:
- Every example's `manifest.yaml` entry defaults to `validated: false`
  the moment it's created (collected, altered, or otherwise) — this is a
  gate a human/agent has to explicitly flip, not an implicit "assume good."
- The handoff into `safety_matrix.yaml`/module templates described above
  (`suggested_op`/`suggested_sink_family`) only ever gets acted on for
  entries where `validated: true` — an unvalidated entry can be *read* for
  planning purposes (deciding what to validate next) but must never be the
  direct source of a new matrix row or module template.
- If a check-in or status update needs to report progress before every
  pair is validated, report it as "N of M pairs validated" — do not round
  up, and do not let an in-progress corpus look complete by omitting the
  distinction.

## Candidate feature/vulnerability list

Merged per the Phase 1 methodology (commonality x exploitability, 1-3 each,
priority = product, max 9). Angle 1 (feature catalog) research used a
qualitative Ubiquitous/Common/Frequent/Niche scale; mapped here to 1-3
(Ubiquitous->3, Common->3 when the feature is standard within its own app
category, Common/Frequent->2, Niche->1) per Phase 1's own scoring rubric.
Angle 2 (exploitability) already used the 1-3 scale directly, with scores
capped at 2 wherever fewer than 2 independent source types could be found
(the plan's own hard requirement for a 3) — see the full per-feature source
citations in this session's research record; abbreviated here to keep the
table scannable.

**Boundary-rule merges applied** (angle 2 flagged these as sharing the same
code shape/sink family as another row): "Social features" folded into
"Authorization/access control" (both are IDOR/BOLA on object references —
a literal duplicate, not just a related class). "Billing/invoicing" folded
into "E-commerce" (same business-logic/price-manipulation shape). Angle 2
also flagged "Referral/loyalty" and "Calendar/scheduling" as sharing
e-commerce's race-condition *pattern* — kept as separate rows here rather
than merged, since they're genuinely different real-world code (a booking
table vs. a coupon-redemption counter are different sink families for
Phase 2's actual collection purposes) even though the abstract vulnerability
class rhymes; noted in each row.

| # | Feature | Commonality | Exploitability | Priority | Vuln class(es) | Notes |
|---|---|---|---|---|---|---|
| 1 | Authorization / access control (incl. social features: follow/friend, sharing, profile visibility — merged, same IDOR/BOLA shape) | 3 | 3 | **9** | IDOR/BOLA, vertical/horizontal privilege escalation, forced browsing (CWE-639/862/863) | OWASP A01:2021 (#1 category, ~94% of tested apps); arXiv HackerOne BOLA study (78.5% confirmed). Two independent source types. |
| 2 | Authentication / session management | 3 | 3 | **9** | Broken auth, session fixation, JWT `alg:none`, weak reset tokens (CWE-287/384/640) | OWASP A07:2021; dedicated WSTG-ATHN+WSTG-SESS categories; documented JWT `alg:none` CVEs/HackerOne pattern. |
| 3 | User-generated content (comments/reviews/forums/messaging/chat) | 3 | 3 | **9** | Stored/reflected XSS, HTML injection (CWE-79) | CWE Top 25 2024 ranks XSS **#1** overall; dedicated WSTG-CLNT category; historically the single most common HackerOne report type. |
| 4 | File handling (upload/download/preview/storage) | 3 | 3 | **9** | Unrestricted upload -> RCE, path traversal, XXE via uploaded docs, SSRF via remote-fetch preview (CWE-434/22/611) | Dedicated WSTG upload/traversal tests; CWE-22 and CWE-434 both recurring Top-25 entries; real CVE (Drupal REST upload->RCE, CVE-2019-6340). |
| 5 | Search / filtering (merged with reporting/exports/dashboards per angle 2 — same "user filter param reaches a query/template" shape) | 3 | 3 | **9** | SQL/NoSQL injection, SSTI/XXE in export templates, IDOR via report IDs (CWE-89/943/611/1336) | CWE Top 25 2024 ranks SQLi **#3**; dedicated WSTG/PortSwigger SQLi+XXE+SSTI topics; real CVEs in report/export template engines. |
| 6 | E-commerce (cart/checkout/payment/coupons; incl. billing/invoicing/subscriptions — merged, same business-logic shape) | 3 | 3 | **9** | Business logic (price/quantity tampering, coupon-stacking), race conditions on single-use resources (CWE-841/362/840) | Dedicated WSTG-BUSL category names price manipulation/workflow bypass as test cases; two independently documented real disclosed race-condition cases (Stripe coupon, Starbucks gift card). |
| 7 | Configuration / settings / admin panels | 3 | 2 | 6 | Security misconfiguration — default creds, exposed debug endpoints, verbose errors (CWE-16 family, CWE-209) | OWASP A05:2021 + dedicated WSTG-CONF category, but both OWASP-authored (treated as one source family, not two independent types) — capped at 2 per the plan's own rule. |
| 8 | Notifications (email/SMS/push, template-driven) | 3 | 2 | 6 | Header/email injection (CWE-93), SSRF via link-preview, HTML injection in templated emails | WSTG-INPV email-header-injection test case + recognized CWE, but only one independent source type found — capped at 2. |
| 9 | Background / async processing (job queues, scheduled tasks) | 2 | 3 | 6 | Insecure deserialization of queued payloads -> RCE (CWE-502), SSRF from worker outbound calls | OWASP A08:2021; CWE-502 in Top 25 2024; landmark real breach (CVE-2017-5638 Struts OGNL, used in the Equifax breach). |
| 10 | Content management (CMS pages, themeable templates, media library) | 2 | 3 | 6 | SSTI (CWE-1336), stored XSS in WYSIWYG content, unrestricted media upload | OWASP A03:2021 injection (SSTI subtype); CWE-94 (parent class) in Top 25 2024; dedicated PortSwigger SSTI topic; real CMS theme-editor SSTI/RCE CVEs. |
| 11 | APIs / integrations (inbound webhook signature verification, mass-assignment on API param binding — scoped narrowly per Phase 1's own boundary note) | 2 | 3 | 6 | Mass assignment (CWE-915), missing webhook signature verification -> forged events, SSRF via callback URLs | CWE-915 recurring Top-25-adjacent; dedicated WSTG-APIT category; real historical incident (GitHub 2012 mass-assignment breach). |
| 12 | Onboarding / registration (email verification, invite flows) | 2 | 2 | 4 | Account takeover via predictable verification tokens, host-header password-reset-link poisoning, open redirect in invites (CWE-640/601) | OWASP A07:2021 + dedicated WSTG-IDNT category; overlaps heavily with row 2 (auth/session) — candidate for a future merge if Phase 2 finds the same code shape. |
| 13 | Support / helpdesk (ticketing, live chat, attachments) | 2 | 2 | 4 | Stored XSS via agent-facing ticket rendering, IDOR across tickets/orgs, unrestricted attachment upload | Shares CWE-79/434 with rows 3/4 but no independently-documented helpdesk-specific pattern found — held at 2. |
| 14 | Localization / i18n (locale-driven template/resource selection) | 2 | 2 | 4 | Path/local-file-inclusion via locale param (CWE-22/98) | CWE-22 Top-25-adjacent + WSTG-INPV LFI test cases; known but narrower pattern (older PHP CMS locale-LFI CVEs), one independently confirmed source type in this pass. |
| 15 | Calendar / scheduling (bookings, appointments) | 2 | 2 | 4 | Business logic (double-booking race condition), IDOR on other users' events (CWE-362/639) | Shares e-commerce's race-condition *pattern*, different sink family (booking-availability flag, not a redemption counter) — kept separate. |
| 16 | Referral / loyalty / rewards programs | 2 | 2 | 4 | Business logic / race conditions (double-crediting via parallel requests) | Same pattern as e-commerce coupon races; kept separate for Phase 2's collection purposes since the actual code (referral crediting) differs from checkout code. |
| 17 | Surveys / feedback / form builders / custom fields | 2 | 2 | 4 | Stored XSS via free-text answers, NoSQL/SQL injection via dynamic custom-field queries (CWE-79/89/943) | Shares CWE-79/89 with rows 3/5 but no independently-distinct survey/form-builder pattern found — held at 2 to avoid double-counting those rows' evidence. |
| 18 | Workflow automation (rules engines, "if this then that" triggers) | 2 | 2 | 4 | SSRF via user-configured outbound action URLs, SSTI/expression-language injection in rule conditions (CWE-918/1336) | OWASP A10:2021 SSRF is a dedicated category, but PortSwigger's SSRF content is treated as the same source family — no independently distinct workflow-automation CVE/writeup found, held at 2. |
| 19 | Chatbots / AI assistants (LLM-backed features, RAG, agentic tool use) | 2 | **1 (evidence-scope-limited, not a claim of low real-world risk)** | 2 | Prompt injection -> tool-call abuse/data exfiltration, SSRF via LLM-driven URL fetch tools | Governed by OWASP's separate *LLM* Top 10, outside this pass's stated source scope (OWASP Top 10 2021/2025, CWE Top 25, classic WSTG/PortSwigger/CVE corpus) — flagged explicitly for a dedicated follow-up pass against LLM-specific sources before this score is trusted for prioritization. |

**Reading this for Phase 2 dispatch:** rows 1-6 (priority 9) are the
strongest, best-evidenced candidates and should be Phase 2's first wave.
Rows 7-11 (priority 6) are solid second-wave candidates. Rows 12-18
(priority 4) are legitimate but thinner-evidenced — fine to collect, lower
urgency. Row 19 (chatbots/AI) should not be treated as "deprioritized on
the merits" — its low score is a source-scope artifact, not a risk
judgment, and deserves its own follow-up research pass using LLM-specific
sources (OWASP LLM Top 10) before Phase 2 either includes or skips it.

## Status

- [x] Phase 1 dispatched (in progress — see Phase 1 heading above)
- [x] Phase 1 complete, list documented above (19 features scored and
      ranked; row 19's score is flagged as evidence-scope-limited, not a
      risk judgment — see the list's own closing note)
- [x] Phase 2 dispatched (wave 1: the six priority-9 rows)
- [ ] Phase 2 complete, corpus collected — **wave 1 done** (rows 1-6:
      access-control, auth-session, ugc-xss, file-handling, search-export,
      ecommerce-logic; ~65 real, license-triaged, gitleaks-scanned,
      commit-pinned files under `docs/research/corpus-examples/`, verified
      independently). **Wave 2 (rows 7-11, priority 6) not yet dispatched.**
- [x] Phase 3: CWEs assigned to collected examples (all 12 wave-1 feature
      cells now carry a flat `cwe: [...]` field per entry, plus
      `suggested_op`/`suggested_sink_family`; a real cross-cell CWE-
      uniqueness defect found during this pass — several entries in
      unrelated cells had independently claimed the same "unique" CWE ID —
      was fixed by re-researching each duplicate against its actual source
      and assigning a genuinely specific, non-colliding MITRE ID)
- [x] Phase 3: manufactured pairs generated (floor met per CWE — see
      "Pair generation") — all 33 (cell, CWE) groups / 39 manufactured
      pairs in `docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md`'s gap-analysis
      table are done, across 4 batches: `CC-LAB-0226` (5 worst-gap groups),
      `CC-LAB-0227` (7 `auth-session` groups), `CC-LAB-0228` (10
      `ecommerce-logic`/`file-handling`/`header-injection` groups), and
      `CC-LAB-0229` (final 10 groups: `insecure-deserialization/python`,
      `search-export/{node,php,python}`, `ssrf/python`, `ssti/python`,
      `ugc-xss/{node,php,python}`, `webhook-signature/python`) — see that
      plan's own "Not yet done" section for the full per-batch record.
- [x] Phase 3: validation execution sandbox actually built/tested (not just
      specified) — `fuzzlab/tools/corpus_validation_sandbox.py`
      (`CC-LAB-0084`/`FR-LAB-112`, 2026-09-23): real gVisor (`runsc run`),
      zero network namespace, `-overlay2=all:memory` ephemeral writes,
      real cgroup v1 memory/pids limits, non-root, wall-clock timeout,
      explicit `authorized=True` opt-in, mandatory audit log. Every
      containment property verified for real in
      `tests/test_corpus_validation_sandbox.py` (12 tests, all passing),
      not asserted from the mechanism's existence alone. Two documented
      deviations from this section's literal spec, both forced by this
      environment's egress policy blocking every container registry's
      blob CDN (no base image is pullable at all): reuses the host's own
      interpreters as the OCI root rather than a purpose-built minimal
      image, and drives `runsc` directly rather than via `docker run
      --runtime=runsc` — see `CC-LAB-0084`'s change-control entry for the
      full reasoning. This sandbox does not itself validate any real
      corpus entry (see the still-unchecked "all pairs validated" item
      below) — it only makes that step possible.
- [x] Phase 3: all pairs validated (report as "N of M", per "Validated data
      only reaches lab-generation-facing files" — never rounded up) —
      195 of 195 manifest entries across all 18 real-collected-plus-
      manufactured manifest files (`access-control`, `auth-session`,
      `ecommerce-logic`, `file-handling`, `header-injection`,
      `insecure-deserialization`, `mass-assignment`, `search-export`,
      `ssrf`, `ssti`, `ugc-xss`, `webhook-signature`, each `node`/`php`/
      `python` where applicable) now carry `validated: true`. The final
      63 (the real, Phase-2-collected entries that were still `false`
      going into this pass — `access-control`/`auth-session`/
      `ecommerce-logic`/`file-handling`/`search-export`/`ugc-xss`) were
      closed out in `CC-LAB-0230` (2026-09-24): semgrep (local custom
      rule files, since the registry and semgrep.dev are unreachable
      from this environment) plus bandit for static confirmation, and
      gVisor-sandboxed dynamic execution for 15 of the 63 where a real
      harness was buildable without fabricating the mechanism under
      test; `psalm-taint`/`eslint-security` recorded as genuinely
      unavailable (network-blocked installs) rather than claimed. All 63
      claims were confirmed accurate against the actual source; none
      needed correction. Two pre-existing, out-of-scope gaps surfaced by
      this pass and deliberately left unfixed (per direct instruction —
      not this task's job): `access-control/php`'s 4 entries still carry
      the legacy flat `cwe:` field (a Phase-3-CWE-mapping gap, not a
      validation gap), and `check-corpus-cwe-coverage.sh` surfaces
      dozens of pre-existing cross-file `cwe_unique` collisions across
      manifests this pass happened to touch (touching a manifest makes
      the hook re-check every entry in it against the whole corpus).
- [x] Phase 3: `suggested_op`/`suggested_sink_family` proposals acted on
      (accepted/renamed/merged into `lab/safety_matrix.yaml`) — audited
      2026-09-23 against the now-CWE-complete corpus (all 12 wave-1
      cells): every single `(suggested_op, suggested_sink_family)` pair
      across all 32 manifest files already has an exact matching row in
      `lab/safety_matrix.yaml`, applied earlier by `CC-LAB-0063`. Zero new
      rows needed, zero op/sink_family naming collisions found. One open
      gap noted for a future pass (not a missed proposal): `search-export`/
      `node`'s manifest flags a still-uncollected secure-twin op for
      `template_render_pipeline` that was never formally proposed via
      `suggested_op` in the first place.
