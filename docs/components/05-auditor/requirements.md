# Auditor / Fetcher — Requirement Specification

Component code: **AUD** · Status: `[built; to harden]` · Last updated: 2026-09-23

Related: `ARCHITECTURE.md` #5; `DECISIONS_AND_ROADMAP.md` (D5, D6, D9, Phase 2);
`./change-control.md`.

## 1. Purpose
Turn discovered surface (pages, endpoints, parameters) into ranked **injection
candidates** with recorded rule evidence, so the fuzzer and oracle spend their
budget where a vulnerability is plausible.

## 2. Scope
- **In:** per-parameter rule evaluation, canary reflection probing with context
  typing, target fingerprinting, candidate emission with evidence and features.
- **Out:** confirming a vulnerability (fuzzer + oracle) and ordering candidates by
  a learned model (the ranker reads what the auditor writes).

## 3. Functional requirements
- **FR-AUD-1** Evaluate each injection point against the rule set and record a
  full per-rule evaluation log (which rules fired, which did not, and why), not
  only the rules that matched.
- **FR-AUD-2** Move rules from code toward data (rules-as-data) so the rule set is
  editable and versioned without code changes.
- **FR-AUD-3** Probe reflection with a unique canary and classify the **sink
  context** of each reflection (HTML body, attribute, JS string, URL, etc.).
- **FR-AUD-4** Fingerprint the target (DBMS, framework, WAF) and record it for
  the scheduler and fuzzer to condition on.
- **FR-AUD-5** Emit `candidate` rows carrying rule evidence and an extracted,
  versioned feature vector; never emit a vulnerability label.
- **FR-AUD-6** Read discovered surface from the shared store and write candidates
  back to it (no direct tool-to-tool calls). (D5)
- **FR-AUD-7** *(`CC-AUD-0016`, 2026-09-23).* A candidate is generated for the
  `ssrf` category: `R-SSRF` (`fuzzlab/audit/rules_data/default_rules.json`)
  matches a parameter name against a common SSRF-fetch vocabulary (`url`,
  `src`, `target`, `webhook`, `thumbnail`, etc.), the same bare
  `name_regex`-only shape `R-OPEN-REDIRECT`/`R-FILE-INCLUSION`/
  `R-COMMAND-INJECTION` already use. Rule-generation only — confirmation is
  `fuzzlab.oracle`'s job (`FR-FUZZ-18`).
- **FR-AUD-8** *(`CC-AUD-0017`, 2026-09-23; regex widened by
  `CC-AUD-0024`, 2026-09-23).* A candidate is generated for the
  `access-control` category: `R-ACCESS-CONTROL`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `GET`/`query`
  parameter whose name looks like an object identifier (`channel_id`,
  `resource_id`, `object_id`, `item_id`, `record_id`, `owner_id`,
  `account_id` — the last added by `CC-AUD-0024` for Netflix's first
  `access_control` page, `CC-LAB-0187`) —
  narrower than `R-SSRF`'s bare-`name_regex` shape (adds `method_in`/
  `location_in`) to bound the false-positive risk a broader match would
  carry for this category (see `CC-AUD-0017`). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-20`).
- **FR-AUD-9** *(`CC-AUD-0018`, 2026-09-23).* A candidate is generated for
  the `insecure-deserialization` category: `R-INSECURE-DESERIALIZATION`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `body`-location
  point whose `sink_context` is `"deserialization"` — this project's first
  use of the `sink_context_in` predicate, since this class has no
  informative parameter name to key off (every whole-body point shares the
  literal `param="body"`). **Scope limit, stated explicitly**:
  `sink_context` is currently populated only from ground truth
  (`fuzzlab.harness.auto.points_from_ground_truth` looks it up from the
  matching scoring `Case`); the auditor does not yet infer `sink_context`
  generically for an arbitrary crawled target, so this rule is reachable
  only in the project's own ground-truth-scored detection-benchmark mode
  today, not yet a general crawl-driven capability. Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-21`).
- **FR-AUD-10** *(`CC-AUD-0019`, 2026-09-23).* A candidate is generated for
  the `xxe` category: `R-XXE` (`fuzzlab/audit/rules_data/
  default_rules.json`) matches a `body`-location point whose `sink_context`
  is `"xml"` — the second use of `sink_context_in` (after `R-INSECURE-
  DESERIALIZATION`), same necessary shape and same scope limit (reachable
  only from ground-truth-sourced points today). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-22`).
- **FR-AUD-11** *(`CC-AUD-0020`, 2026-09-23).* A candidate is generated for
  the `jwt-algorithm-confusion` category: `R-JWT-ALG-NONE`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `header`-
  location point whose name looks like a JWT-carrying header
  (`authorization|jwt`) — scoped to header points only, mirroring
  `R-ACCESS-CONTROL`'s own location-narrowed shape. Rule-generation only
  — confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-23`).
- **FR-AUD-12** *(`CC-AUD-0021`, 2026-09-23).* A candidate is generated for
  the `weak-token-entropy` category: `R-WEAK-TOKEN-ENTROPY`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `POST` point
  whose `sink_context` is `"session_token"` — genuinely a new,
  less-constrained rule shape (no `location_in`, since this class has no
  real tainted location to key off at all; `method_in` substitutes as
  the available constraint). Rule-generation only — confirmation is
  `fuzzlab.oracle`'s job (`FR-FUZZ-24`).
- **FR-AUD-13** *(`CC-AUD-0022`, 2026-09-23).* A candidate is generated for
  the `mass-assignment` category: `R-MASS-ASSIGNMENT`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a body point
  whose `sink_context` is `"mass_assignment"` — the same
  `location_in`+`sink_context_in` shape as `R-INSECURE-DESERIALIZATION`/
  `R-XXE`. The project's first-ever candidate-generation rule for this
  vuln class (already built on three other stacks' lab pages, but with
  no rule anywhere before this entry). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-25`).
- **FR-AUD-14** *(`CC-AUD-0023`, 2026-09-23).* A candidate is generated for
  the `unrestricted-file-upload` category: `R-UNRESTRICTED-FILE-UPLOAD`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a body point
  whose `sink_context` is `"fs_web_root_write"` — the same
  `location_in`+`sink_context_in` shape as `R-MASS-ASSIGNMENT`/
  `R-INSECURE-DESERIALIZATION`/`R-XXE`. This project's first-ever
  candidate-generation rule for this vuln class, closing `CC-LAB-0186`'s
  own deliberately-deferred detection follow-on for Twitch's
  unrestricted-file-upload cell (`TWCH-0009`). Rule-generation only —
  confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-26`).
- **FR-AUD-15** *(`CC-AUD-0025`, 2026-09-23).* A candidate is generated for
  the `price-integrity-bypass` category: `R-PRICE-TRUST-DIFFERENTIAL`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a body point
  whose `sink_context` is `"payment_charge"` — the same
  `location_in`+`sink_context_in` shape as `R-MASS-ASSIGNMENT`/
  `R-UNRESTRICTED-FILE-UPLOAD`. Deliberately scoped to `"payment_charge"`
  only, not also `"sql"` (Booking.com's own `BKNG-0003` ground truth uses
  `sink_context="sql"`, since its sink is a real DB insert): `"sql"` is
  already used as the `sink_context` for a large number of unrelated
  SQL-injection candidates project-wide, and widening this rule's own
  `sink_context_in` to include it would have generated a
  `price-integrity-bypass` candidate for essentially every SQL-sink point
  in the project, a real false-candidate-explosion risk caught during
  this rule's own pre-change review, not discovered after the fact. This
  project's first-ever candidate-generation rule for this vuln class,
  closing `CC-LAB-0188`'s own deliberately-deferred detection follow-on
  for Netflix's price-integrity-bypass cell (`NFLX-0005`). Rule-generation
  only — confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-27`).
  **Cross-stack generalization, verified live (`CC-LAB-0189`,
  2026-09-23, updated in place)**: this rule's own `location_in`/
  `sink_context_in` gate was never stack-specific, so it needed **zero**
  changes to also generate a candidate for `go_net_http`'s new
  `price_integrity_bypass` cell (`TWCH-0010`, Twitch's channel-
  subscription-purchase endpoint) — verified directly, not merely
  assumed from the rule's shape.
- **FR-AUD-16** *(`CC-AUD-0026`, 2026-09-23).* A candidate is generated
  for the `http-header-injection` category: `R-HEADER-INJECTION`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `query`/`body`
  point whose `sink_context` is `"header"` — the same `location_in`+
  `sink_context_in` shape as `R-INSECURE-DESERIALIZATION`/
  `R-UNRESTRICTED-FILE-UPLOAD`/`R-PRICE-TRUST-DIFFERENTIAL`. Closes `CC-LAB-0198`'s
  own deliberately-deferred detection follow-on for Twitch's
  `http_header_injection` cell (`TWCH-0013`). Checked directly (not
  assumed) that the one other real user of `sink_context="header"`
  (php_laravel's HuddleHub `outbound_header_injection` case, a genuinely
  distinct concern) cannot false-positive through this rule: the
  companion oracle strategy fails closed on that page, and that app's own
  `vuln_class` has no category mapping that would ever include this
  category in a real automatic run's `plan.categories`. Rule-generation
  only — confirmation is `fuzzlab.oracle`'s job (`FR-FUZZ-29`).
- **FR-AUD-17** *(`CC-AUD-0027`, 2026-09-23).* A candidate is generated
  for the `path-traversal` category: `R-PATH-TRAVERSAL`
  (`fuzzlab/audit/rules_data/default_rules.json`) matches a `query`/`body`
  point whose `sink_context` is `"fs_path_read"` — the same
  `location_in`+`sink_context_in` shape as `R-HEADER-INJECTION`/
  `R-INSECURE-DESERIALIZATION`/`R-UNRESTRICTED-FILE-UPLOAD`/
  `R-PRICE-TRUST-DIFFERENTIAL`. Closes `CC-LAB-0190`'s own deliberately-deferred
  detection follow-on for Twitch's `path_traversal` cell (`TWCH-0011`) —
  this project's own last known real, TRACKED category-4 detection gap.
  Checked directly (not assumed) that `sink_context="fs_path_read"` has
  no other current user in any ground truth, so there is no cross-target
  overlap to reason about. The pre-existing `R-FILE-INCLUSION` rule's
  broader `name_regex` also matches `filename`, generating a second,
  independent candidate under a genuinely distinct category
  (`file-inclusion`, matching no current ground truth) — by design, not
  a duplicate: that category has no confirming path in a scored
  automatic run today. Rule-generation only — confirmation is
  `fuzzlab.oracle`'s job (`FR-FUZZ-30`).

- **FR-AUD-18** *(`CC-AUD-0028`, 2026-10-13, BUG-0110).* The passive auditor
  (`tools/fetcher.py`) reports each field's default value as a browser holds it
  (`core.forms.default_value`): a select's selected or first option, a textarea's
  text, a checkbox's value or `on`. These values feed the value-based indicator
  rules.
  *(CC-AUD-0042, BUG-0136 review:)* each URL's rendered result (its DOM and its XHR
  list) comes from that URL's page only. When the browser cannot load a URL (a refused
  navigation, a timeout), `ContentFetcher.fetch` sends its one page to `about:blank`
  before the static fallback -- *(CC-AUD-0053, BUG-0522:)* through
  `navguard.end_failed_load`: when the failure settled on the browser's own error
  page (SP-01 waits for it before raising), that page has replaced it and nothing
  more is navigated, else `about:blank`. The page shown before, which ERR_ABORTED leaves alive,
  stops, and its requests are never listed under a later URL. *(CC-AUD-0043,
  BUG-0138:)* the rendered fetch navigates through `navguard.navigate` and waits for
  `networkidle` only after a completed load. A page whose load did not complete is
  returned without waiting out the timeout and without a second request (review Q2):
  - superseded, or replaced by another document, the HTML the browser received for it;
  - merely slow, its live DOM.
  - Enforced by (a failed load ends the previous document; CC-AUD-0042): `ContentFetcher.fetch` — `tests/test_navigation_aborts.py::test_the_auditors_failed_load_ends_the_previous_document`
  - Enforced by (the fetch after failed loads is rendered; CC-AUD-0053, BUG-0522): `ContentFetcher.fetch` → `navguard.navigate` / `end_failed_load` — `tests/test_navigation_aborts.py::test_the_auditors_load_after_failed_loads_is_rendered`
  - Enforced by (no wait for a load a refused navigation cancelled; CC-AUD-0043, BUG-0138): `ContentFetcher.fetch` → `navguard.navigate` — `tests/test_guarded_navigation.py::test_the_auditor_reads_the_page_without_waiting_it_out`

- **FR-AUD-19** *(`CC-AUD-0031`, 2026-10-13).* A form point's candidate evidence
  carries its entry list (`"entries"`, secrets blank), so the oracle probes it with its
  sibling fields.
- **FR-AUD-20** *(forms phase 2; `CC-AUD-0032`, 2026-10-14).*
  - **Value shapes.** `audit/value_shape.value_shape` is the one classifier of an
    example value: `url`, `ip`, `filename` (a closed extension set), `path`, `hostname`
    (RFC 1123 labels; the last a two-letter or listed generic TLD), or none. It is
    total, bounded (2048 characters) and linear, with no regular expression.
    Accepted false positive: a dotted name ending in two letters (`user.id`,
    `order.by`) is a host name.
  - **Predicates.** `value_shape_in` (the point's `value_shapes`) and `origin_in`
    (`crawl` / `ground-truth`). `load_rules` validates every rule: unknown keys, values
    outside a closed set, or a regex that does not compile raise `RuleError`. An invalid
    plugin rule is left out and counted (`invalid_plugin_rules`).
  - **Rules.** `R-COMMAND-INJECTION-VALUE` (ip, hostname) and `R-FILE-INCLUSION-VALUE`
    (filename, path) fire whatever the parameter is called; `R-SQLI-HEADER` and
    `R-XSS-HEADER` fire on crawl-sourced header points only. None fires on a
    ground-truth point.
  - **Examples.** Crawl points carry their example's shapes; a field whose own example
    is empty or our filler takes the shapes its name has elsewhere in the run (one
    pass).
  - **Neutral base values.** A point whose example is ip- or hostname-shaped is probed
    from `127.0.0.1` (the command-injection base value and payload prefix, built under
    CC-FUZZ-0063). `value_shape.neutral_value` errs toward loopback for siblings and
    header-point queries: any value with `://` (any scheme, any length) or starting
    with `//` → `http://127.0.0.1/`; an ip or host name, also with a port →
    `127.0.0.1`, and with a path after it → `http://127.0.0.1/`. Our own fillers (exact
    match, `store_adapter.is_filler`; since CC-AUD-0039 also the crawler's
    constraint-aware ladder values, `store_adapter.is_ladder_value`: repeated or
    ascending digits of at most 15 digits, `fuzzlab` padded with `x` or cut to a
    prefix of 3 or more, `Fuzzlab`, `FUZZLAB`, `2000`, FR-CRAWL-15) are sent as they
    are. The fuzzer never sends a host name taken from the app's
    own defaults. *(Amended by FR-FUZZ-67, `CC-AUD-0056`, 2026-10-21:)* a sibling's default naming
    loopback (the lab itself, D11) is sent as given; one naming any other host is
    never sent and never replaced by a stand-in -- its request cannot be rebuilt, so
    its point carries a `replay_refusal` and is inconclusive
    (`value_shape.names_outside_lab`, the one predicate). A point's own value and the
    command-injection base value are the payload's slot and keep loopback. *(Review
    rounds 1 to 3, BUG-0544: the predicate fails closed, on the authority and on the
    tail; the tail rule is an allow-list, the owner's decision of 2026-10-21. Amended by
    `CC-AUD-0058`, BUG-0555, 2026-10-22: the predicate is an allow-list from its entry;
    no recogniser decides which values it proves. Amended by its review round 1, the
    same day: an authority mark anywhere, an unbracketed IPv6 literal and a JSON number
    are judged, and a bare token is outside only when it names an IP literal or a name
    under a TLD delegated in the DNS root, FR-AUD-32. Amended by its review round 2, the
    owner's final round, the same day: a special scheme and `:` after any character
    that cannot be part of a scheme is an authority mark, an IPv6 literal ends at any
    character outside its alphabet and the raw value is judged, and a JSON number is
    judged only when it is an integer.)* `names_outside_lab` judges a string as it is
    and a JSON integer (never a bool; a float with an integral value as that integer:
    JavaScript reads `134744072.0` as 134744072) by its JSON text (`134744072` is the
    text `134744072`, 8.8.8.8 to WHATWG); any other JSON float (a decimal: `2.5`), a
    bool, null or empty object or list names nothing. It reads every text a reader
    parses from the value -- the raw value (an address parser, `ping6`, a shell or an
    application that splits the value keeps the tab, LF and CR that WHATWG removes),
    WHATWG's tab and newline removal and C0-or-space trim, an application's Unicode
    trim, a C reader's cut at the first NUL, and the value as an application that
    percent-decodes it reads it, decoded until stable, at most eight times -- and never
    asks whether `neutral_value` or `value_shape` would change it. A value is of a **URL
    or authority shape** when, in any of those texts:
    - it starts with a scheme and `:` (any scheme: `https:evil.example`, `mailto:`,
      `sort:asc`) or with `//`, `\` or `/\`, or holds `://`, `:\` or `:/\` **anywhere**
      (`?next=http://evil.top`, `see http://evil.top`, `url=http:\\evil.top`,
      `/login?next=https://evil.example/`, and `http%3A%2F%2Fevil.top` decoded);
    - it holds a **special scheme and `:`** (`http`, `https`, `ws`, `wss`, `ftp`, `file`,
      in any case) at its start or **after any character that cannot be part of a
      scheme** (anything but an ASCII letter, digit, `+`, `-` or `.`), whatever follows
      the `:` (review round 2: WHATWG reads `https:evil.top` and `https:/evil.top` as
      https://evil.top/ and `ws:evil.top` as ws://evil.top/, node 22):
      `?next=https:evil.top`, `go=https:/evil.top/x`, `see https:evil.top`,
      `(https:evil.top)`, `url=ws:evil.top`, `next=Http:8.8.8.8`, `?next=https%3Aevil.top`
      decoded, `go to\thttps:evil.top` (a tab) raw. Not `?next=xhttps:evil.example`,
      `?next=web+https:evil.example` (another scheme, no host to WHATWG) or
      `?q=1https:evil.example` (no scheme);
    - it holds an **unbracketed IPv6 literal**: a run of hex digits, `:` and `.`, ended
      at either side by **any other character** (a zone's `%`, `/ ? # \ ;`, whitespace
      with tab, LF and CR, `=`, `,`, a quote, a parenthesis, `|`, `&`, `@`, a letter past
      `f`; review round 2), holding `::` or at least six `:` (`2001:4860:4860::8888`,
      `::ffff:8.8.8.8`, `64:ff9b::808:808`, `fe80::1%eth0`, `::1`,
      `dns=2001:4860:4860::8888`, `2001:4860:4860::8888,2001:4860:4860::8844`,
      `"2001:4860:4860::8888"`, `2001:4860:4860::8888|id`, `2001:db8::1\tis the server`,
      a tab), so any `::` is one. WHATWG reads none of them after `http://`;
      `getaddrinfo(AI_NUMERICHOST)` reads each literal as that address, and `inet_pton`
      each without a zone, and Python's `str.split`, a shell's word splitting, a
      `key=value` reader, a list split at `,` and `json.loads` each hand that literal on
      (measured), and `value_shape` calls each bare literal `ip`. A time of day
      (`12:00:00`), a date-time (`2020-01-01T00:00:00`) and a MAC address (five `:`) are
      not one;
    - it holds a path, query or fragment (a `/`, `?`, `#` or `\`), and its leading token
      (up to the first `/ ? # : @ ; \`) or the host a reader that puts `http://` before
      the value takes (leading slashes skipped, userinfo cut at its last `@`:
      `/evil.top` → evil.top) is a host to a reader: WHATWG reads it (no space or control
      after percent-decoding and its mapping) and it holds a dot or an IDNA full stop, is
      a bracketed literal, is `localhost`, or is a dotless number WHATWG reads as
      0.0.0.0 or as an address of at least 2^24 (`robots.txt/x`, `/evil.top`);
    - it is a **bare token** (none of `/ ? # \`), and the same leading token or reader
      host is an **IP literal** in any form -- bracketed, dotted with a last label that
      is a number in any radix (`8.8.2056`, `1.2.3`, `19.99`, `127.1`), or a dotless
      number read as 0.0.0.0 or from 2^24 to 2^32 - 1 (`134744072`, `00:30`; a whole
      value that is a dotless number below 2^24, `0` included, is not: nothing follows
      the host) -- or `localhost`,
      or a dotted name whose **last label is a TLD delegated in the DNS root**
      (FR-AUD-32; the label read up to its first character outside letters, digits and
      `-`, and a non-ASCII last label taken for an internationalised TLD): `evil.top`,
      `evil.zip`, `user@gmail.com`, `a;b.top`, `com.`, `evil.рф`. A bare token whose host
      is a reserved or undelegated name names no host a public resolver answers, and is
      not of this shape: `robots.txt`, `lang_en.php`, `user@lab.test`, `a@b.example`,
      `evil.example`, `intranet.corp`, `x.localhost`, `printer.local`, `Hello.`,
      `localhost.`.

    A value of a URL or authority shape is the lab only when its authority, up to the
    first `/`, `?` or `#` after `http://`, `https://`, `//` or nothing, is one of the
    **explicit loopback spellings**: `localhost` in any case, `[::1]`, or `127.a.b.c` in
    canonical dotted decimal (four decimal parts, no leading zero: every reader reads
    that spelling alike, 127.0.0.0/8 never leaves the host, and the lab's multi-origin
    setups bind 127.0.0.2 and 127.0.0.3), with at most a port of one to five digits;
    `urlsplit` reads the same host and port; no `@`, `\`, `%`, control, space or
    non-ASCII character is anywhere; and its path, query and fragment are wholly in the
    **safe tail grammar** (`value_shape._tail_in_grammar`): the separators `/`, `?`,
    `#`, `&`, `=` (never `/` twice in a row) between words of ASCII letters, digits,
    `_`, `-`, `~` whose first character is not a digit. So no tail token holds a `.` or
    a `:` (or any other character), and none is a number in any radix or of any length;
    the tail rule never asks whether a token reads as a host. Not admitted as an
    authority, so outside wherever the value is of a URL or authority shape:
    `localhost.` (WHATWG keeps it as another host, and a resolver may send a rooted name
    to DNS) and every other spelling of a loopback address (`127.1`, `2130706433`,
    `0x7f000001`, `0177.0.0.1`, `127.0.0.1.`, `[0:0:0:0:0:0:0:1]`, `[::ffff:127.0.0.1]`,
    a bare `::1`: readers disagree on them). A value of no such shape names no host to
    any reader but a single-label or an undelegated one (a pure word, a small number,
    free text with a space, a reference to the page's own path, a file name, a lab's
    e-mail address) and is the lab.

    Outside, for example: `127.0.0.1:80@evil.example/`, `localhost:1@evil.example`,
    `http://evil.example\@127.0.0.1/`, `http://127.0.0.1/r?next=http://evil.example/`,
    `?next=evil.example:8080`, `?next=8.8.8.8:53`, `?next=https:evil.example`,
    `#evil.example:8080`, `?next=evil.top`, `#evil.zip`, `?next=134744072` after a
    loopback authority; BUG-0544's residual N-R3-1, fixed: `127.0.0.1?next=evil.top`,
    `localhost?u=134744072`, `LOCALHOST?next=8.8.8.8:53`, and `127.0.0.1./`,
    `localhost./`, `127.1/`, `2130706433/`, `0x7f000001/` before `?next=evil.top`; a bare
    `evil.top`, `evil.shop:8080`, `evil.zip`, `user@gmail.com`, `134744072`,
    `0x8080808`, `8.8.2056`, a fullwidth or percent-encoded `evil.top`, `/evil.top`,
    `/8.8.8.8:53/x`; and (review round 1) `?next=http://evil.top`, `url=http://evil.top`,
    `see http://evil.top`, `x=http:/\evil.top`, a percent-encoded URL,
    `2001:4860:4860::8888`, `::ffff:8.8.8.8`, `64:ff9b::808:808`, `user@2001:db8::1`,
    and the JSON integers `134744072`, `134744072.0` and `3232235777` (192.168.1.1); and
    (review round 2) `?next=https:evil.top`, `?next=https:/evil.top`, `url=ws:evil.top`,
    `see https:evil.top`, `{"u":"https:/evil.top"}`, `?next=https%3Aevil.top`,
    `dns=2001:4860:4860::8888`, `2001:4860:4860::8888,2001:4860:4860::8844`,
    `(2001:4860:4860::8888)`, `2001:4860:4860::8888|id` and `2001:db8::1\tis the server`.
    The same predicate gates a fresh value the binder reads from a page (FR-FUZZ-67),
    and `neutral_value` stands loopback in for every value it puts outside
    (`127.0.0.1` for a JSON integer). Accepted false positives (the owner's decision for
    the tail; BUG-0555 for the rest): a loopback value whose tail holds a number, a
    dotted or colon-separated token or any other character outside the grammar
    (`?page=2`, `/app.js?v=1.2.3`, `?at=10:30`, `?q=a+b`, `/2fa`); before a path, query
    or fragment, any dotted token (`robots.txt/x`, `lang_en.php?x=1`, `/index.php`,
    `../x`); in a bare token, a file name or word under a delegated TLD (`archive.zip`,
    `readme.md`, `script.py`) and a decimal or version WHATWG reads as an IPv4 address
    (`2.5`, `1.2.3`, `0.00`, `19.99`, as a string; a JSON float leaf is not judged, a
    stated residual below); an e-mail address whose
    domain is under a delegated TLD (`user@mail.example.com`; this supersedes the earlier
    stated e-mail residual for such an address); a dotless number from 2^24 to 2^32 - 1
    (an 8- to 10-digit id or timestamp, string or JSON number) and one read as 0.0.0.0
    before a port or path (`00:30`, `0/x`); text starting with a word and `:` (a scheme
    to WHATWG: `Note: x`, `intranet:8080/x`); text naming a special scheme and `:` after
    a character that cannot be part of a scheme (`Upload a file: x.pdf`, `see http:
    below`; review round 2); any `::` and any run of hex digits, `:` and `.` with six
    `:` (a colon-separated fingerprint, a scope operator `use std::string`, a CSS
    `a::before`; review round 2); and every loopback spelling outside the explicit set.
    Wherever a stand-in is sent, plain loopback stands in for such a value, and a
    request needing it as a sibling or a fresh value is unbound (FR-FUZZ-67).
    **Measured cost, per point** (BUG-0555 review LA-6, re-measured in review round 2;
    `scratchpad/lanes/LABAUTH/r2/measure_points_r2.py`, `point_cost.txt`, 2026-10-22):
    over 13,684 parameter rows with sibling entries in 4,216 recorded stores on the
    test host (form, link-set and JSON-leaf points; mostly the test suite's and the
    lanes' runs), 1,104 points are unbound now against 992 at 7393c90 (126 more, beside
    percent-encoded URLs naming `host.example`; 14 fewer: `db.lab.example`) and 1,300 at
    d3cb339 (196 fewer, every one beside the JSON float leaf `2.5`: the float residual's
    gain, all from one test fixture's runs; none more: the special-scheme mark and the
    IPv6 rule of review round 2 cost no recorded point). Review round 1 measured the
    same at 1338d7a (705 of 9,562 then: it had dropped the `://`-anywhere coverage).
    Over every lab answer key (22 keys, 352 points with writes on and off), no point is
    refused (at 1338d7a four were, two of them Mongection's expected-vulnerable
    SDLMG-0002), and a test keeps it so
    (`tests/test_replay_bindings.py::test_no_expected_vulnerable_answer_key_point_is_unbound_by_the_lab_predicate`).
    In the external labs' sources (`lab/external/*/.cache`), no form-field point (123)
    is unbound, and 62 of 2,095 URL-query points are (as at 1338d7a and d3cb339, none at
    7393c90): third-party Google Maps and Fonts URLs (`28.659344,-81.187888`,
    `Roboto:300,400,500`). Stated residuals: a JSON float leaf that is not an integer
    (`2.5`, `8.8`, `19.99`: an app that puts `http://` before it reads `8.8` as 8.0.0.8,
    node 22) is the lab (review round 2, the owner's decision; measured gain above); a
    pure dotless word and a dotless number of 2^32 or more (`intranet`,
    `?next=intranet`) are single-label names, a host only to a resolver that completes
    them from a search list or a hosts file, whatever follows them
    (`intranet/?next=evil.top`); a non-zero dotless number below 2^24 (`42` is 0.0.0.42
    to WHATWG) is in 0.0.0.0/8 (RFC 6890: not forwardable; on the test host Linux routes
    it to the default route and 0.0.0.0 to loopback, measured); free text with
    whitespace is the lab unless a rule above holds (an IPv6 literal, an authority or
    special-scheme mark), though a reader that splits it may take an IPv4 address or a
    name from it (`8.8.8.8 is the server`, `8.8.8.8\tx`, `evil.top foo`: the IPv6 rule
    of review round 2 is stricter, the owner's scope); a value naming no host of its own whose
    path, query or fragment does (`/?next=evil.top`, `/go/evil.top`, `?next=evil.top`,
    `#evil.zip`) is the lab: holding every such value to the tail grammar would put
    99.9% of ASP.NET view states (`/wE...`) and 21.5% of standard base64 tokens outside
    (measured, BUG-0555); a bare dotted name whose last label is not delegated at the
    snapshot's date (`intranet.corp`, `printer.local`, `db.lab.example`) is the lab, a
    host only to a private resolver, a hosts file or mDNS, and a TLD delegated after the
    snapshot's date is the lab until the snapshot is refreshed (FR-AUD-32); a value
    percent-encoded more than eight times is read only that far. Pinned neighbour (owner
    FUZZ): the access-control replay reads a point's own stand-in as the object key and
    records a negative
    (`tests/test_replay_bindings.py::test_an_access_control_replay_never_reads_a_stand_in_for_its_own_value`).
    **Stated exception (FR-AUD-21, BUG-0124,
    operator-approved 2026-10-14):** the open-redirect retry probe.
  - *(Stated gaps, pinned at the gaps merge.)* A '+' before a special scheme in a form-encoded value, or a JSON-escaped colon, and a Unicode spelling of an IPv6 address that getaddrinfo's nameprep reads as the ASCII address, are still the lab: strict xfails in `tests/test_lab_predicate_pins.py` (BUG-0555's final residuals).
- **FR-AUD-21** *(open redirect and SSRF by value; `CC-AUD-0034`, 2026-10-14,
  BUG-0124).*
  - **Shape → categories.** `audit/value_shape.SHAPE_CATEGORIES` is the one table of
    the categories each shape implies (ip, hostname → command-injection; filename,
    path → file-inclusion; url → open-redirect, ssrf). The default rules carry exactly
    one `R-*-VALUE` rule per pair (`R-OPEN-REDIRECT-VALUE`, `R-SSRF-VALUE` new), and
    `SHAPE_EXCLUSIONS` records the pairs left out with a reason (url → file-inclusion).
  - **The redirect seed.** `value_shape.redirect_seed(example)` is an `http`/`https`
    crawled example sliced from its original text up to its query or fragment, userinfo
    cut out; `None` for any other scheme and for a host or path with an identifier-like piece.
    `harness/auto` sets it on crawl points; `audit/engine.evaluate` writes it to an
    **open-redirect** candidate's evidence only. An AST guard limits where
    `redirect_seed` is set, carried and read.
  - **The FR-AUD-20 exception and its reach.** The open-redirect confirmer may send the
    seed, after its plain canary failed, as text in the query of a reserved `.example`
    canary (FR-FUZZ-46). fuzzlab never sends a request to the seed's host (it is never
    a request host) and never follows the redirect. **A target that extracts and
    fetches URLs embedded in a parameter could contact the seed's host** (a third
    party): the operator accepted this residual explicitly. Every other category keeps
    FR-AUD-20 as written.
  - **Stated gaps:** a protocol-relative example (`//host/x`, shape `path`) gets no
    rule and no seed; an allowlist keyed on a query string is not matched (the seed
    drops the query).
- **FR-AUD-22** *(captured requests and JSON leaves; `CC-AUD-0035`, 2026-10-14, forms
  phase 3, lane J).*
  - **Source.** `store_adapter.import_spider` reads the spider table
    `discovered_requests` (`id, page_url, method, url, content_type, body_json, source,
    signature`; FR-CRAWL-13). A spider DB without it imports exactly as before.
  - **Never imported** (counted `request_refused`, nothing stored): a method outside
    GET/POST/PUT/PATCH (DELETE included); PUT/PATCH unless `fuzzlab auto
    --fuzz-json-writes` is given (and the URL passes the next rules); a URL
    `destructive_reason` or `transaction_reason` flags; a URL on another origin than
    the page that sent it; a content type other than JSON (`application/json`,
    `application/*+json`) or form-encoded; a body that is malformed, not an object,
    empty, over 64 leaves or 16 levels; a body with a field name or string value
    holding a lone surrogate (a JSON `\udXXX` escape with no partner, which the spider
    stores losslessly since FR-CRAWL-42 and disco's capture keeps as sent): no store row
    can hold it, and before BUG-0554 the import failed on it (both importers, through
    `captured_request`); a **credential-change body**
    (`store_adapter.credential_change_rule`, the one rule crawled forms use: two or
    more password fields, a password field named with a change word — new, confirm,
    repeat, current, old …, or an account-management token in the URL path); a body
    with a settings word (`formnav.settings_word`) on any key; a destructive name or
    value (`entries_refusal`, run with `credential_names=True` over the non-password
    leaves — every credential-named leaf is a password field, so that half is a second
    check; each name and value is judged as a text, `core.urls.text_destructive_reason`,
    so a `#` in it hides nothing — CC-AUD-0039, BUG-0131).
  - **Stored.** A JSON body is a `form` row (`enctype` `application/json`, entries as
    FR-CORE-36). A form-encoded body is a `form` row (`enctype`
    `application/x-www-form-urlencoded`) and imports as today's form points (`body`).
    The endpoint is the request's path plus its (redacted) query, at its method. Every
    stored value passes `redact_leaf` (a sensitive key on the path or an
    identifier-like value: `""` for a string, `null` otherwise; PA-0100).
  - **Points.** Each string, number or bool leaf is a `json` parameter named by its
    display name, with its value as the example (non-strings as JSON text), except:
    - a **password field** — a credential name (`is_credential_name`) on any key of
      its path: never a point, stored and sent `""`, listed in `form.password_fields`,
      so `isolated_paths_from_store` isolates the path (FR-FUZZ-44);
    - a sensitive or identifier-like leaf (pinned, sent blank);
    - an **object selector** (`_object_selector` on the last key: `UserId`,
      `BasketId`, `username`, `owner` …; pinned, sent as captured).

    ~~When two captured requests share an endpoint, the first one's leaf wins a
    name.~~ *(Superseded by FR-AUD-31: each captured body is its own context.)* A
    pinned sensitive or identifier-like leaf is a placeholder named in the row's replay
    recipe; a captured JSON body has no page holding it, so a point needing it is
    inconclusive (FR-FUZZ-67).
  - **Rules on JSON leaves.** `name_regex` matches the path's last object key
    (`rules.rule_name`); credential and sensitive checks run on every key; value shapes
    apply to the leaf's example, and a url leaf's `redirect_seed` keeps FR-AUD-21's host
    and path identifier checks. `R-SQLI-PARAM` and `R-SSTI` include `json`.
    `R-XSS-REFLECT` does not: a JSON response is not rendered as HTML, and the
    reflected-XSS check does not read the response's content type, so a JSON echo would
    read as a break-out (stated gap: reflected and stored XSS through JSON bodies).
  - **SPA route queries.** A crawled URL whose fragment is a hash route with a query
    (`/#/search?q=x`) gives `fragment` parameters on the endpoint `/#/search`
    (`core.urls.to_route_path`), never `query` ones; lane A's link sets and header
    queries read only `urlsplit(url).query`. A `fragment` crawl point is built only with
    a browser (`--browser`, M6), else reported as ground truth's DOM points are; a
    destructive route (`/#/logout`) is never a point. A crawled SPA query seed whose
    load blocked a write (`discovered_pages.source = 'spa-query-writes'`, FR-CRAWL-17) is
    imported as a page only: no endpoint, parameter or link set comes from it (counted
    `write_seed_skipped`; `CC-AUD-0041`), so M6 never replays that write outside a
    window.
  - **Client-side categories only on fragment points.** A `fragment` payload never
    reaches the server, so every server-side rule carries `location_not_in:
    ["fragment"]` (a closed predicate beside `location_in`) or a `location_in` without
    it: a fragment point draws only xss candidates (reviewer B). *(Integration,
    CC-AUD-0036:)* both open-redirect rules carry `location_not_in: ["fragment"]` too:
    the only confirmer is the HTTP `OpenRedirectStrategy`, so a fragment candidate could
    never be decided. `location_in` / `location_not_in` values are a closed set
    (`audit.rules.LOCATIONS`); an unknown location is a `RuleError`.
  - **Stated gaps:** points are only as good as lane I's capture (no captured request,
    no points; API calls only seen in a bundle are not imported); an object-selector
    user field (`username`, `login`) of a JSON login is pinned, so it is not fuzzed;
    an identifier-like value blanked by the crawler before import reads as an empty
    example; other query parameters of an SPA route are not sent with a fragment probe.
- **FR-AUD-27** *(a crawled URL keeps its origin; `CC-AUD-0048`, 2026-10-19).*
  `import_spider` and `import_disco` take the run's `base_url` (`fuzzlab auto`,
  `greybox-run` and the crawler pass theirs); its origin, else the first crawled URL's,
  is the run's **main origin**. Every page, endpoint and path-template row is stored
  with `core.urls.store_url` (FR-CORE-504): a path on the main origin, as before; an
  absolute URL on another origin. So a page's API on another port keeps it, and one
  path on two origins is two endpoints (the `UNIQUE(run_id, url, method)` keys
  differ). Existing stores read unchanged (their rows are paths).
  - **Stated gaps:** the web site tree places only rows that start with `/`, so a row on
    another origin shows as unplaced; `import_audit` keeps paths (the auditor's own
    findings).
- **FR-AUD-28** *(discovery observations as trace events; `CC-AUD-0050`, 2026-10-19;
  spider time and initiator `CC-AUD-0051`).*
  `import_spider` and `import_disco` first record what the crawl observed
  (`tools.observe`, with the active `core.trace` recorder; none, nothing):
  - each spider page (`observe.page`, or `observe.exchange` for an `xhr` row; `by`
    `crawler`: the spider's own load, never browser traffic; a stored status 0 is no
    status, "no response recorded" (BUG-0515); its
    `found_from` page as the initiator, `referer`, path only) and each captured request
    (`observe.exchange`, its `page_url` as the initiator, a `dry-submit` /
    `reveal-blocked` row marked "blocked by the tool's write window: never reached the
    server"). Their time is the row's `seen_at` (FR-CRAWL-29: when the page's load
    began, when the request was captured). A spider DB from before FR-CRAWL-29 leaves
    both unknown (no time, no initiator); a page the crawl queued itself (the start
    URL, a well-known file) has no initiator. Neither is ever guessed from row order or
    another row's time.
  - each disco capture record (`observe.exchange`, scope its action id or `capture`):
    method, URL, status or "no response (error)", a redirect's `Location`, the
    WebSocket direction, the `Referer` path, the auth profile name, the time.
  - each explorer action (`observe.action`, scope `workflow:<its action id>`: the
    `action_id` the explorer logs (`act-`, `nav-`, `harvest-`; one counter), or, in a
    log from before it, the id a capture record with the same number carries;
    BUG-0512; for an old log no record matches, the explorer's own `act-`/`harvest-`
    naming, kept and documented) and each host refused, with its count
    (`observe.external`): by the capture proxy (its stats, key `<tag>:external:<host>`,
    `src` `capture`) and by the browser's own guard (`explore.json`
    `explore.out_of_scope`, key `<tag>:guard:<host>`, `src` `browser-guard`; BUG-0524,
    `CC-AUD-0054`). Both layers count by hostname (another port of an in-scope host
    is drawn as that host), and a host refused by both carries both counts as a set,
    never their sum. A capture that crashed writes no `explore.json`: its guard
    refusals are not traced.

  Only parameter **names** and locations are kept (query, form, top-level JSON keys),
  never a value or a header. Keys are `<source tag>:<table>:<row>` (the tag a digest of
  the source's resolved path; an action's `<tag>:action:line<n>`, its line in the
  append-only log), so importing the same crawl twice into a run adds nothing.
- **FR-AUD-29** *(one builder of disco observation events; `CC-AUD-0054`, 2026-10-19).*
  The events FR-AUD-28 records for a disco run are built only by `tools/observe.py`:
  `emit_capture_record` and `emit_disco_action` (with `disco_tag`), and the refused
  hosts inside `observe_disco`. Both the import (`observe_disco`) and the live trace
  of a capture (FR-CRAWL-30) call them. A record's index is its position among the
  well-formed records of `capture.jsonl` (`disco.capture.CaptureTail`; `read_capture`
  is the same reader read to the end). An action's number is its physical line in
  `actions.jsonl` (`observe.DiscoActionLines`): lines are split on `\n` bytes only,
  never by universal newlines or `splitlines` (a raw `\r`, U+2028 and U+0085 stay
  inside their line), and each complete line is decoded alone, never a partial read.
  A line that is not UTF-8 or not JSON is skipped and still numbered. For one run
  directory both paths give identical `(key, kind, scope, t, body)` and the same model.
- **FR-AUD-31** *(the importer keeps every request context; the engine writes it;
  `CC-AUD-0056`, 2026-10-21, BUG-0530, BUG-0544).* It supersedes FR-AUD-22's "the first
  one's leaf wins a name" and FR-FUZZ-43's link binding.
  - `import_spider` and `import_disco` write one `parameter` row per (endpoint, name,
    location, sibling set) (`store_adapter._get_parameter`).
  - A crawled link query with two or more names is its own sibling set with its own
    rows; identical sets after redaction are one. A one-name or refused set gives lone
    rows, as before. A form's fields are that form's rows, never merged into a link's.
    Each captured body is its own context; identical stored bodies are one. A disco form
    body keeps a repeated name in order.
  - Every sibling set records its replay recipe (`form.source_page`, `form.fresh`,
    migration 25; FR-FUZZ-67): the page it came from (a form's page, a link's
    `found_from`, a captured request's page or Referer, with its query) and the names
    of the entries redaction blanked (never a password). Names and a page only (D12).
    *(Review round 1:)* the page is stored only when `core.redaction.page_url_is_clean`
    holds (the strongest URL redactor leaves it unchanged; no placeholder; no empty query
    value); otherwise none (PA-0100, PA-0514(1)).
  - *(Amended by `CC-AUD-0059`, 2026-10-22, BUG-0556:)* **every stored value passes the
    owner's rule** (`core.redaction.stored_value`, FR-CORE-537): a link set's entries
    (`redact_sibling`), the `parameter.example` of a link set's names, of a lone query
    point and of an SPA route's `fragment` parameter, and a crawled form's entries and
    examples are `""` when the name is sensitive or the value holds a secret anywhere
    (an identifier, or a token nested in a URL, a query string or a `;` pair, raw or
    percent-encoded); a form entry blanked so is named in `form.fresh` (never a
    password). A POST form's action query and a captured request's URL query are stored
    as `redact_url_identifiers` leaves them; a stored path keeps no path parameter that
    holds a secret (`store_url`). This closes the reserved BUG-0120 (raw crawled
    examples). Stated, pinned: a captured body's leaf holding a nested token keeps the
    flat leaf rule (body redaction paused; BUG-0556 R1), and an endpoint query that
    redaction changed is sent so by its points (BUG-0556 R2, PA-0544's scope).
    *(Review round 1, BUG-0556:)* a POST form's action query and a captured request's
    URL query record a value redaction replaced as `PLACEHOLDER` (by name; never a
    blank: `redact_url_identifiers(..., placeholder=True)`), and the point builder
    refuses such a point (FR-FUZZ-67: `UNBOUND`, never sent); R2 remains only for the
    spider capture writer's blank (owner CRAWL, pinned). `import_audit` stores a
    finding's endpoint as `store_url` stores the page (another origin kept) and passes its
    `target_identifier` and `html_context` through the owner (`_audit_text`: the page
    URL, the page path and every query value `stored_value` would not store).
    *(Review round 2, `CC-AUD-0059`:)* a query value is judged **whole** and replaced
    wherever the text repeats it whole or any run of it 8 characters or longer, never by
    the rules' cut lengths (a rule quotes a substring: `rule_serialized_tokens`); the
    endpoint is the form this run's spider rows already hold the same page in (the
    spider's absolute form for a page off its main origin, its path for one on it), else
    `store_url(page, main)` with `base_url`'s origin or the first finding page's, so an
    off-origin first finding no longer splits the main origin's pages.
    *(r6, `CC-AUD-0059`; corrected by the r6 review, D1 and R4, and at the merge,
    BUG-0556 "At the merge", R4 and D1(b):)* the owner's URL redactors run the pushed
    tree's redactor first, which raises `ValueError` on a URL `urlsplit` rejects that
    holds a `?` and returns one without a `?` unread (FR-CORE-537). **`import_audit`
    stores nothing the pushed tree's import redacted and fails on no finding page the
    pushed tree's import read**; on the pages below, where 7393c90's import failed or
    stored the text raw:
    - a target identifier the owner rejects is stored as
      `store_adapter.AUDIT_TEXT_WITHHELD` (`(unparseable URL withheld)`, as
      `core.trace.safe_ref` withholds), never raw (7393c90 stored it raw);
    - a finding **page** no origin can be read from -- `canonical_origin` raises, as it
      does on a page that is not an absolute URL and holds `[` or `]` in its first
      segment (`x[y/app/p.php`, `h]/…`, `[h/…`) or after a leading Unicode space
      (`\u3000http://[h/…`), to which it prefixes `http://` -- is not used for the run's
      main origin (`_readable_origin`) and is stored by its path, as `store_url` stores a
      URL whose origin is unknown and as 7393c90's `to_path` stored every finding page (a
      `;` path parameter holding a secret dropped; nothing else of the path is judged, so
      the endpoint can keep a userinfo or a JWT segment, as on 7393c90:
      `\u3000http://u:<pw>@[h/app/p.php` is stored `/\u3000http://u:<pw>@[h/app/p.php`);
      its texts pass `_audit_text` as any other's. r6 (3615cfb) failed the whole import
      there, where 7393c90 imported it;
    - a finding **page** `urlsplit` rejects as written **and that holds a `?`**
      (`http://[h/…?…`, `//[h/…?…`: `to_path` rejects it too, and 7393c90's import
      raised) gets no endpoint (the candidate's `parameter_id` is NULL), and its target
      and context are `AUDIT_TEXT_WITHHELD` whole (`_audit_text`: they may quote the
      page URL the owner cannot read); every other finding is imported. r6's record that
      such a text was withheld was not true on 3615cfb: `_main_origin` raised before
      `_audit_text` ran;
    - *(at the merge, R4, pinned; fixed in the merge's follow-up)* a finding **page**
      `urlsplit` rejects as written **without a `?`** (`http://[h/app/p.php`,
      `//[h/app/p.php`, `http://x＃y/app/p.php`, `//user:pw@x[y/app/p.php`) is handled
      as one with a `?`: no endpoint, every non-NULL text withheld, the import goes on.
      The floor returns such a URL unread, so `_audit_text` judges the page by
      `urlparse` as well; until the follow-up its `urlparse` raised and the whole
      import failed, as 7393c90's fails the same pages (in `to_path`)
      (`tests/test_redaction_residual_pins.py::test_import_audit_imports_a_finding_page_urlsplit_rejects_without_a_query`,
      an ordinary test now;
      `tests/test_redaction_nested.py::test_merge_followup_every_text_of_a_page_urlsplit_rejects_is_withheld`);
    - *(at the merge, D1(b))* a finding page stored as a BLOB is read by `to_path` as
      7393c90 read it: one with an empty path (`b"http://h"`, `b"x://"`) is stored `/`,
      its texts judged against nothing of the page (as on 7393c90, which judged no
      text); one with a path (`TypeError`) or one `urlsplit` rejects (`ValueError`)
      fails the import, as on 7393c90. The batch's import (3615cfb, 08eb900) raised
      `TypeError` in `canonical_origin` on every BLOB page but `b""` -- a regression
      against 7393c90 for the empty-path ones, fixed at the merge
      (`tests/test_redaction_nested.py::test_merge_d1b_import_audit_imports_a_blob_page_with_no_path_as_the_pushed_tree_did`);
      the rest is pinned, owner AUD
      (`tests/test_redaction_residual_pins.py::test_import_audit_imports_a_blob_finding_page_and_judges_its_texts`).
      Unreachable from the auditor itself (`fetcher.log_finding` writes the crawler's
      str URL).
    - *(The merge's check, 2026-10-22; the follow-up's.)* A page `urlsplit` rejects (with
      or without a `?`) made 7393c90's whole import raise, so it stored nothing; it is imported now, and
      every non-NULL text of that finding is `AUDIT_TEXT_WITHHELD` whatever its type (a
      BLOB `html_context` was stored verbatim before this fix:
      `tests/test_redaction_nested.py::test_merge_p2_a_blob_text_of_a_page_its_floor_rejects_is_withheld`).
      The other findings of the same DB, and the finding's rule metadata (`category`,
      `transaction_type`, `reference`), are stored as both trees store them in a run
      without such a page -- neither redacts them; 7393c90 kept them out only by
      failing the import. A BLOB page `urlsplit` rejects (`b"http://[h/x"`) fails the
      import on both trees (pinned, the BLOB pin's fourth case).
  - `audit.engine.evaluate` writes each candidate's request fields through
    `core.reqctx.point_evidence` and stamps `identity_scope` and `context_id` (SP-57,
    FR-FUZZ-66). `InjectionPoint` carries `bindings` and `replay_refusal`.
  - Stated gap: the crawler's own form signature merges contexts before the store sees
    them (CRAWL, pinned by a strict xfail). Its request signature keeps operations apart
    since SPIDER9 (BUG-0546, FR-CRAWL-37); that pin passes and was removed.
- **FR-AUD-32** *(the delegated-TLD snapshot; `CC-AUD-0058` review round 1, 2026-10-22,
  BUG-0555).* FR-AUD-20's bare-token rule reads which top-level domains are delegated in
  the DNS root from one source: IANA's list
  (https://data.iana.org/TLD/tlds-alpha-by-domain.txt), bundled verbatim as package data
  (`fuzzlab/audit/tld_data/tlds-alpha-by-domain.txt`, read by
  `value_shape._delegated_tlds`), never a hand-written list or a classifier's closed
  list (`GENERIC_TLDS`, `FILE_EXTENSIONS`).
  - The snapshot is dated: its first line holds IANA's version (2026102100, last
    updated 2026-10-21 07:07:01 UTC; 1,437 TLDs), and `value_shape` records it
    (`DELEGATED_TLDS_SOURCE`, `DELEGATED_TLDS_VERSION`, `DELEGATED_TLDS_FETCHED`:
    downloaded 2026-10-22).
  - A test checks that the file is that download byte for byte (its SHA-256), and that
    the predicate's decision is the file's, label for label: every listed TLD, every
    two-letter label, and reserved names and file extensions (`test`, `example`,
    `invalid`, `localhost`, `local`, `corp`, `txt`, `php`, ...).
  - Without the data (an unreadable package), every label counts as delegated: every
    bare dotted name is outside (fail closed).
  - Refresh: download the list again, replace the file byte for byte, update the
    version, date and digest in `value_shape` and in the test, and measure the change
    per point (FR-AUD-20).
  - Stated residual: a TLD delegated after the snapshot's date is the lab in a bare
    token until the refresh.
  - Enforced by: `tests/test_replay_bindings.py::test_the_bare_token_rule_reads_ianas_root_zone_and_nothing_else`
- **FR-AUD-30** *(a point's deciding mechanism, scoped to its category; `CC-AUD-0055`,
  2026-10-19, BUG-0523).* An `InjectionPoint` may name the one mechanism that decides
  it: `decided_by`, a `(category, arm)` pair, written by the point builder, never by
  the auditor (`harness.auto.STORED_DECIDER` on a stored case's observe point,
  `DOM_DECIDER` on a ground-truth DOM point; `harness.auto.DECIDERS`). `evaluate`
  copies the arm into a fired rule's evidence as `decided_by` **only when the rule's
  category is the pair's category**, as `redirect_seed` reaches open-redirect
  evidence only (FR-AUD-21): a SQLi, command-injection or SSTI candidate on the same
  point carries none. The key reaches `plugins.on_candidate` with the evidence. A row
  without it (every older run) is confirmed as before (FR-FUZZ-47).
- **FR-AUD-26** *(path parameters from crawls; `CC-AUD-0047`, 2026-10-19).*
  `import_spider` and `import_disco` each pass the run's answered URLs (status below
  400 or unknown; a spider's write seeds excluded; a disco run's API GETs included,
  JSON answers without a query too) once to `_import_path_templates`: every
  `core.pathtemplate` template (FR-CORE-503) is a GET endpoint at its template path
  with one `path` parameter, its example the crawled value, blanked when it looks like
  an identifier (PA-0100) *(since `CC-AUD-0059`, BUG-0556: when it holds a secret
  anywhere, `core.redaction.stored_value`; the template path keeps no path parameter
  that holds one)*. `R-SQLI-PARAM` now includes `path`; `R-ACCESS-CONTROL-PATH`
  (FR-AUD-25) and the location-agnostic rules apply as to any point.
  - **Stated gaps:** ~~a template on another origin than the run's base is stored as a
    path, so it is probed at the base's origin~~ *(fixed by FR-AUD-27: it keeps its
    origin)*; ~~variation can template sibling pages (`/docs/intro`,
    `/docs/setup` -> `/docs/{docs}`), which costs probes, not safety~~ *(narrowed by
    CC-AUD-0049, BUG-0507: a value the app's scripts name is a route, not a value;
    with no recorded code segments, an older crawl, it still can)*; path parameters
    of POST requests are not discovered.
  - *CC-AUD-0049:* each importer passes the crawl's code segments to
    `_import_path_templates` (`code=`): the spider DB's `script_segments` table, a disco
    run's `script_segments.json` (FR-CRAWL-28). Neither present: no code evidence.
- **FR-AUD-25** *(an id-shaped path segment; `CC-AUD-0046`, 2026-10-19, FR-FUZZ-57).*
  `R-ACCESS-CONTROL-PATH` fires on a GET `path` point whose name is `id`, `uuid` or
  `guid`, ends in `_id`/`-id` (or `_uuid`/`-guid`…), or is camelCase `…Id`/`…Uuid`
  (matched case-sensitively, so `paid` and `userid` do not).
- **FR-AUD-24** *(the store request on a stored-XSS candidate; `CC-AUD-0045`,
  2026-10-19, FR-FUZZ-56).* An `InjectionPoint` with a `store_url` also carries
  `store_method` (default `POST`), `store_location` (`body`, `query` or `json`) and,
  for a JSON store, `store_entries` (the body's other leaves); a fired rule's candidate
  evidence records all three (`store_entries` as lists) so the oracle plants through
  the request the ground truth enumerates.
- **FR-AUD-23** *(a disco run as crawl points; `CC-AUD-0044`, 2026-10-18, D70).*
  `store_adapter.import_disco(run_dir, store, run_id, fuzz_json_writes=)` imports a
  `fuzzlab disco capture` run directory as `import_spider` imports a crawl, through
  the same code (`fuzzlab auto --disco-run DIR`, FR-FUZZ-53):
  - **Pages and queries.** Each captured GET with a query string or an HTML answer goes
    through `_import_page_url` (the per-URL step of `import_spider`): a `page` row, its
    query as `query` parameters and a link set (source `disco`). An asset GET (script,
    style, image, JSON without a query) is not a page.
  - **Captured requests.** Every other HTTP exchange with a response is judged by
    `captured_request` and stored by `_store_request`, so every FR-AUD-22 refusal,
    redaction and pinning applies unchanged. A form-encoded body is read from the wire
    into the object form the spider stores. A truncated body (`req_truncated`) is
    refused. The `Referer` header stands for the sending page in the other-origin rule.
    WebSocket messages and exchanges without a response are skipped.
  - **Fragments.** Each page URL of `actions.jsonl` (`url`, redacted by the explorer)
    goes through `_import_page_url`, so an SPA hash route's query is a `fragment` point:
    the browser never sends a fragment, so only the explorer's log holds it.
  - **Fields a user saw.** A form step in `actions.jsonl` lists its controls' names and
    types (`fields`); joined to the capture by action id (`act-<seq>`), the names of
    its non-hidden controls are `visible` to `_store_request`. An object selector
    among them (a visible `username` input) is a point, as a crawled form's visible
    field is (`_import_forms`); a hidden or unseen one stays pinned (FR-AUD-22).
  - Malformed `actions.jsonl` lines are counted `quarantined`, with the capture's own.

## 4. Non-functional requirements
- **NFR-AUD-explainable** Every candidate is traceable to the rule evidence that
  produced it; a candidate with no evidence is a bug.
- **NFR-AUD-idempotent** Re-auditing the same surface produces stable candidate
  identities (no duplicate churn).
- **NFR-AUD-safe** Probing uses non-destructive canaries only; destructive checks
  are gated off by default.
  - Clause (scope; CC-AUD-0033, BUG-0123): the auditor's scope is one origin, fixed
    once (the auth base's, else the first fetched URL's); a URL outside it is never
    fetched, and the rendered fetcher's browser reaches nothing else (a context-wide
    route, redirect chains walked, plus launch arguments for Chromium's own traffic).
    Stated consequence: with `--base-url` on a separate auth origin (a login hosted
    elsewhere), every page fetch is refused and logged ("outside the audit scope"),
    so the audit finds nothing; audit with a base URL on the pages' own origin.
  - Enforced by (scope): `ContentFetcher.fetch` / `_start_browser`, `navguard` — `tests/test_browser_scope.py::test_the_auditors_browser_never_leaves_the_target_origin`, `tests/test_browser_scope.py::test_the_auditors_scope_is_fixed_and_never_moves`, `tests/test_browser_scope.py::test_the_static_auditor_refuses_another_origin_too`, `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped`
  - Enforced by: the auditor sends only GETs of crawled URLs, now deny-listed and redirect-checked — `tests/test_destructive_urls.py::test_the_auditor_never_refetches_a_destructive_url_from_an_old_spider_db`, `tests/test_destructive_urls.py::test_the_auditors_static_fetch_does_not_follow_a_redirect_to_one`
  - Enforced by (session headers; CC-AUD-0038, FR-CRAWL-14's mechanism): the rendered fetcher ensures the session before its context opens and hands its headers to the guarded route only (in scope, the session's host, its transport), never `set_extra_http_headers` — `tests/test_browser_scope.py::test_no_browser_context_gets_session_headers_outside_the_route`, `tests/test_browser_scope.py::test_session_headers_are_added_by_the_route_only_in_scope`, `tests/test_browserauth.py::test_an_https_sessions_headers_never_go_over_http`
  - Enforced by (a browser login's state adopted in scope only, through the one helper; CC-AUD-0040): `ContentFetcher._start_browser` → `browserauth.context_options` — `tests/test_session_browser_login.py::test_the_auditors_browser_adopts_a_browser_logins_local_storage`, `tests/test_session_browser_login.py::test_the_auditors_browser_renders_the_app_logged_in`, `tests/test_session_browser_login.py::test_storage_state_adoption_keeps_in_scope_origins_only`
  - Clause (where the session's cookies reach; CC-AUD-0060, BUG-0559, SP-74, FR-CRAWL-43): the rendered fetcher's context passes the session's credential cookies, as it holds them, to its guard, which refuses every request, redirect hop and socket to a host they do not reach (a loopback alias of a host-only cookie's host is in the audit's origin scope). A page on such a host, or whose own redirect hop went there, is never fetched and gives no page (`(0, "", "", [])`, as an out-of-scope URL; no static fallback); a jump the page makes itself is refused and the page is audited with its own content. *(Review round 1, BA-3; round 2, BB-3:)* the browser never preloads anything past the guard: what Chromium sends itself goes to the enforcer every launch names and is refused (round 2: a rule set in a closed shadow root with a character-referenced type still went to the alias and to `/logout` past round 1's page layers -- `navguard.PRELOAD_OFF_JS`, which remain as defence in depth; round 3: over `https` too -- a prefetch rode the tunnel admitted for a redirect landing, which now carries its one exchange -- and an `https` target's redirected page loads with a self-signed certificate under `ignore_https_errors`; after the owner's final round, a known gap pinned in FR-CRAWL-43: a ticket whose own connection never comes is taken by the next `CONNECT` to its host and port, and a prefetch of `/logout` inserted into a closed root then reaches the target with the session -- `tests/test_browser_session_reach.py::test_a_ticket_its_own_connection_never_uses_admits_no_prefetch`, strict xfail, owner navguard SP-04), and a load whose main frame is found committed on such a host when it settles (a navigation the route never saw) gives no page either (`navguard.committed_session_refusal`, counted as `committed`), never that document's content nor the load's own HTML. Each refusal is counted by host (`ContentFetcher.session_host_unreached`). The static path is the seam's (the session manager's `prepare`), unchanged here.
  - Enforced by (the session's cookies reach): `ContentFetcher.fetch` / `_start_browser`, `navguard.session_host_refusal` — `tests/test_browser_session_reach.py::test_the_auditors_browser_fetcher_never_audits_an_unreached_host_as_the_identity`, `tests/test_browser_session_reach.py::test_every_context_that_adopts_a_session_hands_its_cookies_to_the_guard`
  - Enforced by (no preload past the guard, and no committed document off the session's hosts; review round 1, BA-3): `navguard.guard_page` / `PRELOAD_OFF_JS`, `ContentFetcher.fetch` / `navguard.committed_session_refusal` — `tests/test_browser_session_reach.py::test_the_auditors_fetcher_and_the_spider_never_preload_the_alias`, `tests/test_browser_session_reach.py::test_a_preload_past_the_guard_is_never_read_as_the_identitys_page`, `tests/test_browser_session_reach.py::test_no_speculation_rules_preload_leaves_a_guarded_context`, `tests/test_browser_session_reach.py::test_no_preload_a_page_hides_from_the_guard_leaves_the_browser` (round 2, the enforcer), `tests/test_browser_session_reach.py::test_no_request_rides_an_https_landings_tunnel_after_its_exchange` (round 3, an https landing's tunnel)
  - Not yet enforced: there is no destructive-check gate in `fuzzlab/audit` (it has no destructive checks today), and the FR-AUD-3 reflection canary is not wired into production code. (BUG-0111 sweep.)
- **NFR-AUD-no-leak** Candidate identifiers carry no vulnerability class name (D9).
- **NFR-AUD-dry-run** `fuzzlab audit` accepts `--dry-run`: plans and prints the
  exact argv/command it would run and sends nothing (no probe is made), for
  headless use outside the web UI. Reuses the web launcher's dry-run plan/report
  logic (`fuzzlab/web/commandspec.py` + `fuzzlab/web/runner.py`) via the shared
  `fuzzlab/cli_dryrun.py` helper.
  - Enforced by: `cli_dryrun` — `tests/test_cli_dry_run.py::test_audit_has_dry_run_flag`, `tests/test_cli_dry_run.py::test_audit_dry_run_reports_plan_and_sends_nothing`
  - Not yet enforced (exact argv display; BUG-0400, open, the UI lane's fix): the shared display `web/runner.build_flags` mis-serialises `nargs='*'` lists, a bare `const=""` flag and dash-leading values, so for those the printed plan is not the exact argv. Pinned by strict xfails in `tests/test_cli_argv_roundtrip.py`.

## 5. Interfaces and data contracts
Reads `page`, `endpoint`, `parameter` (and, for crawl points, `form` sibling entries;
the importer writes them from the spider's `discovered_forms` and, since forms phase 3,
`discovered_requests`, FR-AUD-22) from the store; writes `candidate` rows
(rule evidence, `features_json` + `feature_version`) and `target` fingerprint
data. Reads indicators/rules from the indicator DB & catalogs, and IANA's root-zone TLD
list bundled as package data (`fuzzlab/audit/tld_data`, FR-AUD-32). Authenticates via
the session manager: the static path through the `core/` seam; the rendered path's
browser context adopts the session the crawl's way (`browserauth.browser_session`,
then `browserauth.context_options`: a browser login's `storage_state`, cookies and
localStorage, filtered to in-scope origins; its cookies; its headers through the guarded
route only; CC-AUD-0038, CC-AUD-0040), and nothing it sends goes to a host the session's
cookies do not reach (SP-74, CC-AUD-0060). Runs standalone or in the discovery pipeline.

## 6. Dependencies (components)
`core/`, session manager, crawler, indicator DB & catalogs.

## 7. Acceptance criteria
- Produces candidates with complete per-rule evidence on the lab's known
  injection points.
- Correctly types reflection contexts on the lab's reflected-input pages.
- Fingerprints the lab's DBMS/framework; candidates carry a versioned feature
  vector consumable by the ranker.

## 8. Open questions
- Rules-as-data schema and how rule versions bind to a run.
- Confidence weighting of overlapping rules for the same parameter.
