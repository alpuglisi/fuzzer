You are a senior security-tooling architect and applied-ML researcher. I need a
rigorous, up-to-date research report to inform the design of a personal,
open-source security-testing toolkit. Use web search extensively. Prefer
authoritative, recent sources (roughly the last 18–24 months for anything
labeled "cutting edge"), cite every non-obvious claim with a URL and its
publication date, and clearly separate established practice from experimental
ideas. Where evidence conflicts or is thin, say so.

## Context (read before researching)

I am building a modular offensive-security testing toolkit in Python. It runs
entirely on my own machine against a self-hosted, deliberately vulnerable web
application in an isolated local lab (same spirit as DVWA/Mutillidae). This is
authorized, educational security research on infrastructure I own. Keep the
report architecture- and defense-research-oriented: focus on how to build robust
tooling and how these techniques work, not on operational instructions for
attacking third parties.

Already built (all Python, all storing results in SQLite):
- A deliberately vulnerable PHP/MySQL target app (30 pages, ~10 JavaScript-
  rendered, with documented SQL injection, reflected/stored XSS, and DOM XSS).
- spider.py: a crawler with a headless-browser (Playwright) engine that renders
  JavaScript, follows links, and captures fetch/XHR endpoints.
- fetcher.py: an auditor that renders each page and flags injection-point
  candidates via a 28-rule registry mapped to a payload-category taxonomy.
- build_sql_db.py: builds the indicator/rule database.
- blind_sqli_fuzzer.py: a time-based blind SQL injection detector that measures
  response latency against a per-target baseline and emits a labeled CSV dataset
  (features: latency, latency delta, response-size delta, status, repeat count,
  error-signature hits; labels available because the lab has ground truth).
- references/: payload catalogs organized by vulnerability class
  (PayloadsAllTheThings-style taxonomy).

Planned next:
- An intercepting proxy (Burp/ZAP-like) built FROM SCRATCH in Python (not
  mitmproxy): inspect and modify requests/responses, searchable history,
  repeater/replay, match-and-replace, scope rules, TLS interception via a local
  certificate authority, HTTP/1.1 plus ideally HTTP/2 and WebSockets, and
  deliberate byte-level control of non-compliant traffic (for studying request
  smuggling, HTTP desync, CRLF injection). It should integrate with the other
  tools and share the SQLite store.
- A session manager: handle authenticated sessions across tools (login flows,
  cookies, CSRF/anti-forgery tokens, bearer/JWT tokens, session reuse, detecting
  logout/expiry and re-authenticating).
- Machine learning woven across the pipeline (detailed below).

Design constraints to respect throughout: Python; single local machine; small
and class-imbalanced but ground-truth-labeled data; HTTP request budget matters
(each request costs time and perturbs timing measurements); tools must be
modular and independently usable yet composable; ML should be advisory, with a
deterministic oracle confirming any "hit."

## Part A — Machine learning research

For EACH item below, research: optimal implementation approaches, concrete
algorithms/model families and Python libraries, feature engineering and data
requirements, pitfalls to avoid, architectural considerations, optimizations,
and how to maximize robustness. Also rate maturity (established / experimental /
likely overkill for a solo local project) and explain integration with the
tools above.

1. Detection classifier: supervised tabular model that decides "vulnerable vs
   not" from response features, replacing fixed thresholds (e.g. the fuzzer's
   timing cutoff). Cover model choice, calibration, handling timing noise and
   class imbalance, avoiding label leakage, and evaluation methodology.
2. Injection-point candidate ranker: model that ranks the auditor's flagged
   parameters/forms by exploitability to cut false positives. Cover useful
   features (parameter-name tokens, reflection, field type, page context) and
   text/embedding representations.
3. Payload prioritization as a contextual bandit (Thompson sampling / UCB) over
   the payload catalogs, minimizing wasted requests. Cover reward design,
   context features, cold start, and non-stationarity.
4. Payload generation: compare evolutionary/genetic and grammar-based mutation
   versus neural/LLM-based generation for producing filter/WAF-bypass variants.
   Cover fitness/feedback signals, coverage-guided approaches, and when neural
   generation is or isn't worth it.
5. Unsupervised anomaly detection (isolation forest, one-class SVM, autoencoders,
   and newer methods) on response features for when labels are absent. Cover
   feature design, drift, and thresholding.

Then, separately, scan for NEW or cutting-edge ML that could benefit this kind of
project even if I didn't list it: for example reinforcement-learning-guided
fuzzing, LLM agents for web-app security testing, transformers/sequence models
for payloads and protocol grammars, request/response embeddings and similarity,
active learning to minimize labeling and requests, and coverage- or
feedback-guided learning. For each, note maturity, what it would take to adopt,
and whether it's justified at this scale.

## Part B — Tools and features research

For EACH tool below, research both how to build it well AND how existing/prior-art
tools solve the same problem, so I can learn from their architectures and known
pitfalls. Apply this lens to each: optimal implementation approaches, pitfalls to
avoid, architectural considerations, optimizations, and maximizing robustness,
scalability, and modularity.

1. From-scratch intercepting proxy in Python. Research: async I/O and
   concurrency models; the CONNECT tunnel and TLS interception with a local CA
   and on-the-fly per-host certificate generation; correct HTTP/1.1 parsing
   (chunked transfer, keep-alive, compression) and the tradeoffs of adding
   HTTP/2 and WebSockets; how to preserve byte-exact/malformed traffic for
   smuggling/desync/CRLF study when most stacks normalize it; interception and
   edit workflow; history storage and search at scale; repeater/replay;
   match-and-replace and scope enforcement; and UI options (local web app vs
   TUI). Compare prior art: mitmproxy, Burp Suite, OWASP ZAP, hetty, proxify,
   and relevant Python HTTP libraries.
2. Session manager. Research: how Burp and ZAP model sessions, macros, and login
   sequences; cookie jars; detecting and refreshing expired sessions; CSRF/anti-
   forgery token extraction and replay; bearer/JWT handling; multi-identity
   testing; and a clean API so the crawler, auditor, fuzzer, and proxy all share
   one authenticated session. Note pitfalls and security-of-stored-credentials
   concerns.
3. The already-built tools (JS-rendering crawler, injection-point auditor, blind
   SQLi fuzzer, indicator/rules database, payload-catalog taxonomy). Research
   best practices and prior art for each (e.g. crawlers like katana/hakrawler,
   fuzzers like sqlmap/ffuf/wfuzz/Ghauri) and how to harden and scale them.
4. Overall architecture that ties everything together: how to make the tools
   modular and independently runnable yet composable through a shared data
   store and/or the proxy as a central request bus; schema/versioning of the
   SQLite stores; plugin/extension patterns; configuration; logging; testing
   strategy; and how the ML components plug in cleanly.

## Output format

Produce a structured report with a short executive summary, then Part A and
Part B with one clearly headed subsection per item above. Within each subsection
give: the recommended approach and 1–2 alternatives with tradeoffs; concrete
libraries/algorithms/patterns; specific pitfalls; optimizations; robustness (and,
for tools, scalability and modularity) notes; integration guidance; and a
maturity rating. Include a comparison of the prior-art tools where relevant. End
with (a) a prioritized, phased build roadmap for the whole project and (b) a list
of open questions and decisions I still need to make. Cite sources inline with
URLs and dates, and add a final reference list. Flag anything that is hype or not
worth the effort at solo/local scale.
