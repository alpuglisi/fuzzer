# Seed authoring playbook — from a vulnerability report to a generated cell

**Status: consolidation of already-decided rules, not a new decision.**
Everything below is already settled across `CR-LAB-0001` Addenda B/C/D/E
and `LAB_PHASE_0_PLAN.md`; this document exists because those rules were
never written down as one executable sequence, and answers the question
"how, concretely, do we turn a real disclosure into a generated lab cell."
**This playbook has never been exercised on a real seed.** Its own
recommended first action ("Recommended next action" below) is to fix that
before trusting anything else in it.

**Revision note (Addendum E):** the original version of this playbook
required a human to hand-author the security oracle assertion for every
seed. That's no longer the default. For most classes, the security
assertion is now **a mature, independently-authored exploitation tool**
(sqlmap, commix, SSTImap, Nuclei) invoked headlessly — genuinely
independent of whatever drafted the code, since these tools predate this
project and use their own detection logic. **A hand-authored assertion is
now the exception**, reserved for the three classes with no mature
automated oracle: IDOR/BOLA, business-logic flaws, and race conditions —
and even there, the recommended source is a one-off paid expert
consultation, not the project owner personally developing exploit-writing
skill.

## The pipeline, end to end

```
OSV/GHSA disclosure
      │  (human triage, LAB_PATTERN_CORPUS_SOURCING_PLAN.md)
      ▼
pattern card (2-4 sentences, original words, provenance ONLY)
      │  informs the SCENARIO, never the code
      ▼
scenario brief (human-written; must NOT name the vulnerability
                or the required mitigation — SecCodePLT rule, Addendum D)
      │
      ▼
check: does a permissive seed app already have this shape? (Addendum E #5 —
       Juice Shop/MIT, crAPI/Apache-2.0, vAPI/PHP-Laravel, NodeGoat,
       AutoBaxBench/SecCodePLT/MIT) — reference its idiom, never copy verbatim
      │
      ▼
SEED  — one (class, sink_context) pair, on stack 1, human-authored:
   • safety-matrix entry: (op, sink_context) -> effect
   • vulnerable module fragment(s), by file_role
   • secure twin (identical identifiers, differs ONLY in the transform)
   • ONE functional assertion (human- or LLM-drafted, low stakes)
   • ONE security assertion: an INDEPENDENT TOOL-ORACLE where one exists
     (sqlmap/commix/SSTImap/Nuclei — Addendum E #1); hand-authored (ideally
     by a paid one-off expert, not the project owner) only for the three
     gap classes with no mature tool (IDOR/BOLA, business logic, race
     conditions — Addendum E #2)
   • TWO Semgrep "shape" rules: sink present, transform present
      │
      ├──► PORT / VARIANT (LLM may draft; never the seed itself):
      │       - port the seed's shape to another stack's idiom
      │       - vary the sink context within the same class
      │       - vary nuisance-axis surface detail
      │     Input: the structured tuple + framework docs.
      │     NEVER the pattern card. NEVER writes the oracle or matrix entry.
      │
      ▼
GATES (tiered, LAB_PHASE_0_PLAN T-LAB0.7):
   Tier 0  lint + minimal-pair diff (whole file set) + Semgrep shape rules
   Tier 1  in-process functional + security test (where valid — never for
           SQLi/race cells; app in-process, DB in a long-lived container)
   Tier 2  full container oracle — the ONLY tier that confirms a label
   Tier 3  whole-lab regeneration + determinism + leakage probe + name-leak
      │
      ▼
provenance.yaml: cell_id -> [card_id]     (never inside the manifest —
                                            Addendum A's structural separation)
      │
      ▼
labels.json / expectedresults.csv / injection-points.json
```

## Step by step: adding one `(class, sink_context)` to the lab

1. **Identify the gap.** Pick a `(class, sink_context)` from the first-wave
   scope (`CR-LAB-0001` §5 / `LAB_PATTERN_CORPUS_SOURCING_PLAN.md` §5) not
   yet covered on the target stack.
2. **Pull the relevant pattern card(s).** Read the card's `root_cause` for
   the mechanism shape and its `source_url` for context. **Do not open the
   advisory's linked patch diff or PoC while authoring** — the card's
   paraphrase is what's licensed for this use; the diff is not.
3. **Write the scenario brief**, deriving it from the card the way
   SecCodePLT derives seeds from CVE analysis: describe the *coding
   scenario* (e.g. "a listing endpoint accepts a sort column from the
   client"), never the *vulnerability* (never "this is missing an
   allowlist on the sort column"). If the brief would give away the answer,
   rewrite it.
4. **Write the safety-matrix entry.** For every `(op, sink_context)` pair
   this seed touches, declare its effect: `neutralises | partial |
   no_effect | introduces` (`lab/safety_matrix.yaml`, T-LAB0.2). This is
   what makes `verdict()` derive the label — never write `vulnerable: true`
   anywhere.
5. **Author the secure twin first**, then produce the vulnerable variant as
   a *minimal removal* of one transform step — closer to how real flaws
   arise than adding a flaw to a blank page, and it's what keeps the
   minimal-pair diff small and mechanically checkable. Assign each module a
   `file_role` (`source | transform | sink | view | route`, Addendum D) and
   route it through the stack's `StackEnv.file_roles` map.
6. **Enforce identifier discipline.** Per-cell identifiers derive from the
   cell ID; the vulnerable and secure twins must emit **identical**
   identifiers. (Juliet's own documented defect: generic helper names made
   false positives unattributable to the right variant — don't repeat it.)
7. **Confirm the cell with an independent oracle, not a hand-written
   assertion, wherever one exists (Addendum E).** Write one functional
   assertion ("the route works and returns the expected shape" — this one
   is low-stakes and fine to draft with LLM help). For the security
   assertion, wire the class-appropriate independent tool instead of
   writing exploit logic yourself: sqlmap for SQL injection, commix for OS
   command injection, SSTImap for SSTI (never tplmap — unmaintained), a
   hand-authored Nuclei template for path traversal/XXE/open redirect/
   known-CVE classes, ZAP as a whole-app safety net. Run it against both
   twins: a positive result on the vulnerable variant and a negative result
   on the secure twin, from the **same tool**, is the confirmation — never
   an LLM's opinion about its own code. **Never use an oracle tool from the
   same family as any system-under-test this project's own tools will
   later be evaluated against** (Addendum E #3) — that biases the corpus
   toward exactly what that tool family can find. Only for the three gap
   classes with no mature tool — IDOR/BOLA, business-logic flaws, race
   conditions — does this step fall back to a hand-authored assertion, and
   the recommended source for that is a one-off paid security consultation,
   not the project owner personally writing exploit code (Addendum E §8's
   "Recommended next action" starts here for a reason).
8. **Write two Semgrep shape rules.** One asserting the vulnerable module
   contains the intended sink pattern, one asserting the secure module
   contains the intended transform. Mark the pair's
   `static_precheck: informative` unless the class is one a taint tool is
   structurally blind to (identifier/alias/connector-position injection,
   escaping-context mismatch, mass assignment, header-trust bypass — mark
   those `uninformative` and skip the check rather than trusting a clean
   scan, per `CR-LAB-0001` Addendum C §4).
9. **Record provenance**, never inline. Add `cell_id -> [card_id]` to
   `lab/patterns/provenance.yaml`. The manifest cell itself carries no
   reference to the card.
10. **Run the gates in order** (Tier 0 → 1 → 2). Fix and re-run on any
    failure; a Tier-1 pass is never recorded as label confirmation. Only a
    Tier-2 pass makes the cell real.
11. **To port to another stack:** hand the LLM the structured tuple +
    pinned framework version + a relevant doc excerpt — not the pattern
    card, not the seed's oracle or matrix entry as something to imitate
    unsupervised. Run the same gates. A human reviews anything that fails a
    gate twice, or that belongs to a Tier-B (deliberately hard) class.
12. **Log the hours spent** against (class tier × stack × seed-vs-port),
    tagged in the same place effort is tracked for §8 below. This is how
    the current ±40% effort estimate (`CR-LAB-0001` Addendum C §4) gets
    replaced with a real number instead of staying a guess forever.

## Non-negotiable rules (consolidated)

- The pattern card informs the *scenario*; it never appears in code, in an
  LLM's code-drafting context, or inside the manifest.
- A human authors every seed's safety-matrix entry. Security *assertions*
  come from an independent tool-oracle wherever one exists (Addendum E);
  only the three gap classes still need a hand-authored one. An LLM may
  draft/port *modules* and low-stakes functional assertions, never a
  security assertion or a safety-matrix entry.
- An oracle tool is never drawn from the same family as a system-under-test
  this project's own tools are evaluated against (Addendum E #3).
- Patch-inversion vulnerability-injection tools (LAVA, EvilCoder, VulGen,
  VGX) are rejected outright, not just deprioritized — their output risks
  being a derivative work of the real patches they mine (Addendum E #4).
- The scenario brief never names the vulnerability class or its required
  mitigation.
- Vulnerable and secure twins differ *only* in the transform, are diffed
  across their whole file set (not one file), and emit identical
  identifiers.
- A clean static-analysis scan is never treated as confirmation for a class
  marked `static_precheck: uninformative`.
- Only a Tier-2 (full container) oracle pass confirms a label. Nothing
  earlier in the pipeline is allowed to be recorded as confirmation.
- Never substitute an in-memory database for the real engine when
  fast-testing a SQL-related cell — dialect differences produce false
  passes that look like flaky tests, not methodology errors.

## What this playbook does not yet resolve

- **It has never been run.** No seed exists yet on any stack.
- **The module schema's `view`/`route`/`StackEnv` additions (Addendum D)
  are unvalidated** on a real framework — Phase 0's PHP reproduction target
  doesn't exercise them (filesystem-routed, no accumulator needed).
- **The 5–20% expected LLM-draft error rate** (Addendum C §2.2) has no
  measurement yet specific to framework-idiomatic web code, only adjacent
  analogues from other artifact types.
- **sqlmap-as-oracle and commix-as-oracle are both validated**
  (`docs/spikes/SPIKE-001-sqlmap-vs-vapi.md`,
  `docs/spikes/SPIKE-002-commix-vs-dvwa.md`, 2026-09-21): headless `sqlmap
  --batch` and `commix --batch` each correctly confirmed a real vulnerable
  endpoint (SQLi, OS command injection respectively) and correctly cleared
  its paired secure twin, with zero original exploit code written by
  anyone. **Two concrete corrections the spikes surfaced, both the same
  underlying lesson:** sqlmap treats a `401`/`403` "no vulnerability"
  response as an auth failure and refuses to test past it
  (`--ignore-code` needed); commix gets stuck against a target whose secure
  twin has an unrelated rotating anti-CSRF token, because the token is
  stale by the second request; commix separately got stuck in a runaway
  false-positive-verification loop after also sweeping the target's
  irrelevant static `Submit` field, not just the parameter actually under
  test. **General rule for the oracle wrapper, two parts: (1) it must
  handle a target's ambient defenses that aren't the class under test**
  (auth-style status codes, CSRF tokens, rate limiting) — either by
  scoping each security assertion to just the one transform under test, or
  by giving the wrapper session/token-refresh awareness; **(2) it must
  scope the tool invocation to the one parameter the cell declares as the
  injection point** (e.g. sqlmap's/commix's own parameter-selection flags),
  never a blind sweep of every form field, both for correctness and to
  bound runtime — or it will
  silently under-test rather than fail loudly.
- **SSTImap-as-oracle is now validated too**
  (`docs/spikes/SPIKE-003-sstimap-vs-ssti-flask-hacking-playground.md`,
  2026-09-21), extending the validated set from {SQL injection, OS command
  injection} to {SQL injection, OS command injection, server-side template
  injection}: headless `sstimap.py` (no separate batch flag needed — its
  default, non-interactive mode already is one) correctly confirmed a real
  Jinja2 SSTI in `filipkarc/ssti-flask-hacking-playground` and correctly
  cleared a secure twin authored for the spike (passing `user` as a Jinja2
  context variable instead of `.format()`-ing it into the template source).
  Two findings distinct from sqlmap/commix: **SSTImap has no `-p`-style
  parameter selector** — the equivalent scoping mechanism is its own
  *marker* (default `*`) substituted at the declared parameter's exact
  value, combined with restricting its `-P` injection-point flag to the one
  location category (query/body/header) that parameter lives in, never its
  default un-marked, all-locations sweep; and **SSTImap has no sqlmap-style
  401/403 auth-abort behavior** (confirmed by reading `core/matcher.py`
  directly — status code is only ever one of several boolean-blind matching
  signals, never a hard gate), so its request type carries no
  `--ignore-code`-equivalent field. **SSTImap/Nuclei/ZAP remain
  unintegrated** narrows to: **SSTImap integrated; Nuclei/ZAP remain
  unintegrated**, and (below) further to **SSTImap and ZAP integrated;
  Nuclei remains unintegrated** (Nuclei is a separate, concurrent lane's
  work — Spike 004, not documented in this playbook by this lane).
- **ZAP-as-a-whole-app-safety-net-oracle is now validated too**
  (`docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md`,
  2026-09-21), per `CR-LAB-0001`'s "Whole-app safety net → OWASP ZAP daemon
  mode / Automation Framework — Supplementary" mapping: ZAP's own headless
  "Automation Framework" (`zap.sh -cmd -autorun <plan.yaml>`, a single
  bounded subprocess call — no daemon/API-polling loop needed) correctly
  raised a dedicated **"Server Side Template Injection"** active-scan alert
  (High risk/confidence) plus a **"Cross Site Scripting (Reflected)"** alert
  against the Spike 003 vulnerable endpoint reused as the target, and raised
  neither against its secure twin — incidentally also validating
  `CR-LAB-0001`'s separate "ZAP active scan ... for reflected/stored XSS"
  path for free. Unlike sqlmap/commix/SSTImap, **ZAP is a whole-app scanner
  with no single declared parameter** — it crawls a target and attacks
  everything it finds with its whole active-scan rule set at once, so
  scoping means restricting the *verdict* to one declared alert-name pattern
  (e.g. `r"Server Side Template Injection"`), not one parameter. The secure
  twin still raised five unrelated, routine alert types (missing security
  headers, version disclosure, etc.) — a real finding that an *unscoped*
  "any ZAP alert at all" verdict would flag every target, secure ones
  included, on noise unrelated to the class under test; the default,
  recommended usage is always scoped to the class being confirmed, with an
  explicit unscoped "whole-app safety-net" mode available for genuinely
  supplementary spot-checks. Also: **ZAP's own process exit code is not
  trusted for the verdict** (same "the tool's opaque exit status isn't the
  signal; its detailed output is" lesson already applied to sqlmap/commix,
  generalized to a fourth tool) — the wrapper always parses the Automation
  Framework's structured JSON report instead.
- **AutoBaxBuilder's self-bias question is contested** (paper vs. project
  site) and unresolved — don't attribute full independence to its exploits
  until arXiv:2512.21132 §4.4 has been read and its verdicts cross-checked
  against a class-specific tool-oracle (Addendum E #6).
- **The paid-expert-engagement path for the three gap classes (IDOR/BOLA,
  business logic, race conditions) has not been decided or budgeted** —
  this needs your call, not a default assumption.

## Recommended next action (revised again, post-Spike-005)

The sqlmap, commix, SSTImap, and ZAP validations from the original "wrap
sqlmap and commix, validate against a known-vulnerable seed app" action
(later extended to a third and fourth tool) are **done** — see
`docs/spikes/SPIKE-001-sqlmap-vs-vapi.md`,
`docs/spikes/SPIKE-002-commix-vs-dvwa.md`,
`docs/spikes/SPIKE-003-sstimap-vs-ssti-flask-hacking-playground.md`, and
`docs/spikes/SPIKE-005-zap-vs-ssti-flask-hacking-playground.md` (Nuclei is a
separate, concurrent lane's Spike 004, not covered here). What's left before
attempting an original seed:

1. **Done (2026-09-21; extended to SSTImap 2026-09-21; extended to ZAP
   2026-09-21).** The reusable per-parameter oracle wrapper — not ad-hoc CLI
   invocations — lives at `fuzzlab/labgen/oracle_wrapper.py`
   (`fuzzlab.labgen.oracle_wrapper`, re-exported from `fuzzlab.labgen`). Call
   `run_sql_injection_oracle(SqlInjectionOracleRequest(...))`,
   `run_command_injection_oracle(CommandInjectionOracleRequest(...))`, or
   `run_server_side_template_injection_oracle(ServerSideTemplateInjectionOracleRequest(...))`
   (or the type-dispatching `run_oracle(request)`) with plain, explicit
   parameters — target URL, method, the injection parameter's name and
   location, (for SQLi) the expected "secure" HTTP status code(s), and an
   optional `refresh_session` callback — never a manifest/cell object (that
   schema is a separate, concurrently-developed concern; this wrapper takes
   no dependency on it). It encodes all three per-parameter spikes' lessons:
   a given `secure_status_codes` list is translated into sqlmap's
   `--ignore-code` automatically (Spike 001); every invocation is scoped to
   the one declared parameter — via `-p` for sqlmap/commix, via SSTImap's own
   marker mechanism plus its `-P` location restriction for SSTImap, which has
   no `-p` flag — never a blind sweep (Spike 002 part 1, Spike 003); and a
   bounded per-attempt timeout × bounded `max_attempts` loop (refreshing the
   session on each attempt when a `refresh_session` callback is given)
   guarantees a hung tool can never block the caller indefinitely, regardless
   of cause (Spike 002 part 2) — see
   `docs/components/01-target-lab/change-control.md`
   `CC-LAB-0016`/`CC-LAB-0017` for why a bounded timeout/retry was chosen as
   the safety valve over building generic per-request session-refresh
   machinery into each tool's own request loop. The loopback-only constraint
   from Addendum E is enforced before every invocation (`assert_loopback`, no
   bypass). Returns a fail-closed `confirmed_vulnerable | confirmed_secure |
   inconclusive` verdict — a tool crash, timeout, or missing binary is always
   `inconclusive`, never guessed as secure. 45 offline tests (every branch,
   injected fake runner) + 3 skip-guarded tests against the real cloned
   `sqlmap`/`commix`/`sstimap` binaries (`tests/test_labgen_oracle_wrapper.py`,
   `tests/test_labgen_oracle_wrapper_integration.py`).
   **Separately, the whole-app safety-net oracle** lives at
   `fuzzlab/labgen/zap_oracle.py` (`ZapWholeAppScanRequest` /
   `run_zap_whole_app_scan`, kept out of `oracle_wrapper.py` since ZAP has no
   single declared parameter to scope by — see `CC-LAB-0019`): scope a scan
   to one declared alert-name pattern (or opt into an unscoped whole-app
   "safety net" mode) and it invokes ZAP's Automation Framework as one
   bounded subprocess call, parsing its own structured JSON report — never
   its opaque exit code — for the same three-outcome fail-closed verdict. 22
   offline tests + 1 skip-guarded real-ZAP integration test
   (`tests/test_labgen_zap_oracle.py`,
   `tests/test_labgen_zap_oracle_integration.py`). **Nuclei remains
   unintegrated** — a separate, concurrent lane's work.
2. Only after that wrapper exists does it make sense to attempt an original
   Tier-A seed on this project's own (eventual) generated code — the
   security assertion for it is now a call to that wrapper, not hand-written
   exploit logic.
4. **Decided (2026-09-21, `CR-LAB-0001`):** the three gap classes (IDOR/BOLA,
   business logic, race conditions) are deferred indefinitely — no paid
   consultation for now. The generator ships without them.

None of this requires Phase 0 to be finished first, and steps 1–2 are cheap
enough to run in parallel with Phase 0's implementation.
