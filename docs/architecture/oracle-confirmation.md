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
(a scheduling test, not a single-request oracle), `regular-expression` (ReDoS —
could use M1 timing later), `tabnabbing`, `xs-leak`. Several of these become their
own checks in later phases; this document tracks only oracle confirmation.

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
