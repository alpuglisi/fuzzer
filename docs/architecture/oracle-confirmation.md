# Secondary architecture: oracle confirmation strategies

Referenced from `ARCHITECTURE.md` #7 (fuzzing harness and oracle). This document
owns the depth for **how the deterministic oracle confirms many attack vectors**,
so the primary map stays high-level (splitting rule).

The project's intent is to cover as many web-application attack vectors as
possible. The oracle is therefore **not** a time-based-only SQLi checker: it is a
**class-pluggable deterministic confirmer** — the sole writer of `finding` labels —
and each injection class registers the confirmation mechanism(s) that prove it.

## The oracle is a set of mechanisms, not one check

There are a handful of deterministic **confirmation mechanisms**; every injection
class maps to one or more. Building the mechanisms once and mapping classes onto
them (a `ConfirmationStrategy` per class, selecting mechanisms) is what makes broad
coverage tractable.

| # | Mechanism | Signal it keys on | Needs |
| --- | --- | --- | --- |
| M1 | **Differential timing** | latency rises monotonically with a requested delay (rising-delay, median/MAD) | black-box |
| M2 | **Error signature** | a class-specific error fingerprint appears (DB/template/parser/stack) | black-box |
| M3 | **Boolean / response differential** | a `true` condition renders, a `false` one does not (stable diff) | black-box |
| M4 | **Evaluation marker** | the sink *computes* an injected expression to a value we predict (e.g. `7*7`→`49`) | black-box |
| M5 | **Reflected canary in executable context** | a unique canary lands unescaped in a sink whose context would execute/inject | black-box |
| M6 | **Browser execution** | the payload actually executes in a headless browser (JS hook / DOM change / dialog) | Playwright (have it) |
| M7 | **File-content marker** | a known file's signature (or a planted lab canary file) appears in the response | black-box |
| M8 | **Out-of-band (OOB) callback** | a loopback canary service receives a request/DNS the target made | OOB listener (lab loopback only) |
| M9 | **Redirect-target control** | a parameter controls the `Location`/redirect host | black-box |
| M10 | **Grey-box** (Phase 3) | line coverage hit / DB-fault / sink reached — augments any of the above | instrumented lab |

Every confirmation records the mechanism, the evidence, and is reproducible.
Where two mechanisms are cheap, the oracle prefers the strongest (e.g. error
signature or evaluation marker over timing).

## Injection classes → confirmation (web-app-pertinent, from `references/`)

Grouped by the sequencing tier that governs when the confirmer is built. "Ref"
is the `references/` folder holding that class's payloads.

### Tier 1 — black-box, no extra infrastructure (Phase 2)

| Class (ref) | Mechanism(s) | Confirmation detail |
| --- | --- | --- |
| `sql-injection` | M1, M2, M3 | rising-delay SLEEP; DB error fingerprint; boolean `1=1`/`1=2` diff |
| `nosql-injection` | M3, M2, M1 | operator injection (`[$ne]`, `[$gt]`) boolean diff; driver error; JS `sleep` timing |
| `ldap-injection` | M3, M2 | `*)(uid=*` boolean diff; LDAP filter error |
| `xpath-injection` | M3, M2 | boolean node-count diff; XPath error |
| `server-side-template-injection` | M4, M2 | `{{7*7}}`/`${7*7}`/`#{7*7}`→`49`; template engine error |
| `server-side-include-injection` | M4 | `<!--#echo var=...-->` / directive evaluates in output |
| `xslt-injection` | M4, M2 | `system-property('xsl:version')` value; XSLT error |
| `latex-injection` | M4, M2 | server-side LaTeX computes/leaks; compile error |
| `crlf-injection` | M5 | injected `\r\n` creates a controlled response header |
| `open-redirect` | M9 | the param sets `Location:` to an off-site/attacker host |
| `http-parameter-pollution` | M3 | duplicate params change which value the app honors (diff) |
| `file-inclusion` / `directory-traversal` / `client-side-path-traversal` / `zip-slip` | M7 | traversal returns a known file signature or a **planted lab canary file** |
| `type-juggling` | M3 | loose-comparison payload flips an auth/branch outcome |
| `csv-injection` | M4 (stored) | a formula payload (`=1+1`) is stored and served unescaped for a spreadsheet sink |
| `xxe-injection` | M2, M7 (M8 for blind) | parser error; local-file entity read marker; OOB when blind |
| `xss` (reflected) | M5 | canary reflected unescaped in an executable HTML/JS/attr context |
| `css-injection` | M5 | attacker CSS injected into a style context |
| `graphql-injection` | M2, M3 | introspection enabled / injected arg changes result or errors |

### Tier 2 — browser execution (uses Playwright; Phase 2 late / next)

| Class (ref) | Mechanism | Confirmation detail |
| --- | --- | --- |
| `xss` (stored, DOM) | M6 | payload executes in the headless browser (hook `alert`/`onerror`/DOM sink) |
| `prototype-pollution` | M6 | `__proto__` payload mutates a base-object property observed in the page |
| `dom-clobbering` | M6 | injected named element clobbers a global the page reads |

### Tier 3 — out-of-band listener (lab loopback canary only)

| Class (ref) | Mechanism | Confirmation detail |
| --- | --- | --- |
| `server-side-request-forgery` | M8 | the target fetches a loopback canary URL we control |
| `command-injection` (blind) | M1, M8 | `sleep` rising-delay; or OOB callback from `curl`/`nslookup` canary |
| `insecure-deserialization` (blind) | M8, M2 | OOB callback from a gadget; or deserialization error/stack |
| `xxe-injection` (blind/OOB) | M8 | external-entity fetch of a loopback canary |

Command injection with visible output also uses **M4/M5** (a marker in the
response); only the blind case needs OOB.

### `regular-expression` (ReDoS, CWE-1333) — M1, timing-differential (built, CC-LAB-0076)

| Class (ref) | Mechanism | Confirmation detail |
| --- | --- | --- |
| `regular-expression` | M1 (escalating-shape variant) | independent classic catastrophic-backtracking shapes each measured far above baseline (`RegexDosStrategy`, `fuzzlab/oracle/strategies.py`) |

Previously listed only in "Out of scope" below ("`regular-expression` (ReDoS
— could use M1 timing later)"). Built for real by the `node_express`
CWE-1333 lab lane (`CC-LAB-0076`/`FR-LAB-69`-`70`), because M1 as it existed
(`ConfirmationStrategy._confirm_timing`, used by `SqliTimingStrategy`/
`CommandInjectionStrategy`) does not fit ReDoS unchanged, and this is worth
recording precisely rather than glossing over:

- **`_confirm_timing`'s shape.** Its templates each embed an explicit,
  attacker-*requested* delay (`SLEEP({d})`/`sleep {d}`) that a vulnerable
  target is expected to honor almost exactly. Confirmation checks two
  things across two escalating delays: latency clears a robust baseline
  threshold (`Baseline.exceeds`, `k`/`floor`), AND latency tracks the
  requested duration (`elapsed >= d - tolerance`).
- **Why ReDoS cannot reuse that unchanged.** A ReDoS payload requests no
  duration at all -- how long a pathological regex pattern takes to
  (fail to) match is an emergent property of the regex engine's own
  backtracking over the *target's own content*, which the oracle does not
  see or control (only the pattern, sent as the probe value, is
  attacker-controlled in this shape). There is nothing to compare the
  measured latency *against* the way `_confirm_timing` compares it to `d`.
- **The built mechanism (`RegexDosStrategy`).** Still M1 in spirit --
  "latency rises far above baseline across multiple escalating probes,
  never one slow response" -- but escalates a different axis: several
  independent, single-nesting-level classic catastrophic-backtracking
  shapes (`_REDOS_TEMPLATES`: `(a+)+$`, `(a|a)*$`, `(a|aa)+$`,
  `([a-zA-Z]+)*$`, `(\d+)+$`), each targeting a different common "run of a
  repeated character class" a target's real content might contain.
  Confirmation requires **at least two** independent templates to each
  clear a robust-baseline threshold — substituting "two independent evil
  shapes" for `_confirm_timing`'s "two requested durations," since no
  requested duration exists here. `floor`/`k` are overridden per-strategy
  (`floor=0.02s`, `k=4.0`) to fit this mechanism's own, deliberately
  bounded probe magnitude (tens-to-low-hundreds of milliseconds), never
  `_confirm_timing`'s multi-second-tuned `floor=1.5`.
- **Nesting depth was tried and rejected.** Deepening a single evil shape
  by even one level (`(a+)+$` -> `((a+)+)+$`) was calibrated as an
  alternative escalation axis (so a fixed content run-length could still
  produce a "rising trend" the way `_confirm_timing`'s two delays do) and
  found to compound the already-exponential blowup so violently that even
  depth 2 hung well past any CI-safe bound against ordinary lab content
  (tens of seconds, trending toward unbounded) -- rejected as unsafe for
  this project's own use, let alone for probing a live target. This is why
  the built mechanism escalates *which* evil shape, never how deeply
  nested one is.
- **Stated limitation.** This can only detect ReDoS when the target's own
  content already contains a run of the character class a template
  targets -- a black-box confirmer has no way to know that shape in
  advance. Multiple templates targeting different common runs raise the
  odds without needing that knowledge, but coverage here is inherently
  probabilistic, unlike every other M1 use (each of which can supply its
  own exact requested delay). Flagged here, not silently treated as
  equivalent-confidence to the SQLi/command-injection M1 uses.
- **Proof status.** `RegexDosStrategy`'s decision logic is unit-tested
  against a deterministic fake sender (`tests/test_oracle_redos.py`, same
  convention `test_oracle_vectors.py` uses for `_confirm_timing`'s other
  callers). The underlying mechanism itself -- that a real regex engine
  really does blow up on these templates against realistic content, and
  that escaping really does prevent it -- is proven separately, with real
  Node.js execution and real measured wall-clock timing (not a Python
  simulation), against this project's own `node_express` ReDoS lab cells:
  `tests/test_labgen_redos.py`. It has not yet been run against an
  arbitrary external target or wired into `fuzzlab/harness/multitarget.py`
  -- both explicitly out of this lane's scope.

### Tier 4 — grey-box augmentation (Phase 3)

M10 layers onto every tier: a confirmed finding that also shows the vulnerable sink
was reached (coverage) or faulted (DB error hook) is higher-confidence, and
grey-box gives dense reward for the bandit. Never the *sole* signal for a label.

### Protocol / infrastructure classes (separate track, Phase 9+)

`request-smuggling`, `web-cache-deception`, `virtual-hosts` / host-header,
`reverse-proxy-misconfigurations`, `web-sockets`, `dns-rebinding` — these are not
parameter-injection into one endpoint; they need protocol-level differential tests
and are sequenced with the protocol-depth work, not the injection oracle.

## Out of scope for the oracle (handled elsewhere or later)

These `references/` categories are real and stay in the payload catalogs, but they
are **not deterministic injection confirmations**, so the oracle does not own them
(authorization/logic/config/disclosure/DoS/auth-token/client-bait/AI):
`account-takeover`, `api-key-leaks`, `brute-force-rate-limit`,
`business-logic-errors`, `clickjacking`, `cors-misconfiguration`, `cve-exploits`,
`denial-of-service`, `dependency-confusion`, `external-variable-modification`,
`google-web-toolkit`, `headless-browser`, `hidden-parameters`,
`insecure-direct-object-references` (IDOR/BOLA — an authorization check, later),
`insecure-management-interface`, `insecure-randomness`,
`insecure-source-code-management`, `java-rmi`, `json-web-token` /
`saml-injection` / `oauth-misconfiguration` (auth-token tampering — a distinct
check family), `mass-assignment`, `orm-leak`, `prompt-injection`, `race-condition`
(a scheduling test, not a single-request oracle), `tabnabbing`, `xs-leak`. Several
of these become their own checks in later phases; this document tracks only
oracle confirmation. (`regular-expression` — ReDoS — is no longer in this list:
it is now built, via a timing-differential M1 variant; see its own section
above.)

## Category selection by run mode (D14)

Which classes' strategies actually run is chosen by the launcher run mode (D11),
not always all of them:

- **Automatic** (benchmark against our lab): the set of active categories is
  **auto-derived from the lab's ground truth** (the distinct `vuln_class` values in
  `labels.json` / `injection-points.json`). The oracle runs exactly the strategies
  for the classes the lab is known to contain.
- **Manual** (hand-driven): the user **selects the categories** (launcher selector
  / `--categories` flag); only the selected classes' strategies run.

The selection scopes three things together: the auditor's active rules (which
candidates are emitted), the payload sources drawn from `references/`, and which
`ConfirmationStrategy` classes the oracle runs.

**No-ground-truth fail-safe (D15).** A target without ground truth (external lab /
arbitrary target) cannot auto-derive. An automatic run against it therefore
**requires an explicit category selection** — it never guesses and never runs all
categories by default — **fails loudly** if none is given, runs **unscored** (the
harness reports findings but no TP/FP/FN, since there is nothing to score against),
and keeps every safety gate on (destructive off, scope-enforced, authorized).

## Design notes

- **`ConfirmationStrategy` interface.** One per class: `applies(candidate)`,
  `confirm(candidate, http) -> Verdict|None`, declaring the mechanism(s) it uses.
  Registered in a built-in registry now; exposed via the plugin system's
  `register_oracle` hook (component #13) later.
- **Selection by `(vuln_class, sink_context)`.** The auditor's canary + context
  typing (Phase 2 T2.4) tells the oracle which context a candidate is in, so it
  picks the right mechanism (e.g. HTML-attribute XSS vs JS-string XSS).
- **Fail-closed labeling.** A strategy returns a `finding` only on a positive,
  reproducible signal; ambiguity is "not confirmed," never a guess. ML never writes
  labels (oracle/advisory split).
- **Safety.** Destructive confirmations stay behind the default-off gate; OOB uses
  a loopback canary only; everything lab-only.
