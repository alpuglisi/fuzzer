# core/ Shared Library — Requirement Specification

Component code: **CORE** · Status: `[planned]` (Phase 0) · Last updated: 2026-09-22

Related: `ARCHITECTURE.md` #2; `DECISIONS_AND_ROADMAP.md` (D5, D6); the store
contract; `./change-control.md`.

## 1. Purpose
Provide the shared foundation every tool imports: the project store, config,
logging, the request budget, feature extraction, an HTTP send seam, and the
plugin registry. It is the layer that makes the store the integration bus.

## 2. Scope
- **In:** store access and migrations; config; logging; budget and concurrency;
  versioned features; HTTP send seam; plugin registry.
- **Out:** any tool-specific logic; network protocols beyond a basic send seam
  (the proxy owns those).

## 3. Functional requirements
- **FR-CORE-1** Manage a single SQLite project store: schema, PRAGMAs (WAL,
  `synchronous=NORMAL`, `busy_timeout`, foreign keys), content-addressed bodies,
  and a numbered, forward-only migration runner.
- **FR-CORE-2** Provide versioned feature extraction (`extract_vN`) writing
  `features_json` + `feature_version`.
- **FR-CORE-3** Provide layered config (defaults → file → env → CLI), validated,
  and hashed onto the `run` row.
- **FR-CORE-4** Provide structured logging carrying `run_id`, `tool`, `identity`,
  and `flow_id` where applicable, plus an audit log of every request.
- **FR-CORE-5** Provide a request-budget manager with per-component caps and a
  per-host mutex that serializes timing-sensitive traffic to concurrency 1.
- **FR-CORE-6** Provide an HTTP send helper that requires a session context.
  *(Amended CC-CORE-0036, BUG-0099.)* It records flows **redacted**, through the
  `core.redaction` storage boundary (URL query and both bodies; the content type is
  matched case-insensitively). The wire request stays exact. This resolves the former
  conflict between "records raw bytes" and NFR-CORE-secrets. *(CC-CORE-0054,
  FR-SESS-20:)* `Request.session_decision: str | None = None` is a declared field: the
  session addon's `prepare` sets it (`"anonymous (out of origin)"` when it withheld the
  identity's session) and the sender that built the request reads it after the send.
  The seam itself never reads or changes it.
- **FR-CORE-7** Provide a plugin registry (entry points plus hooks).
- **FR-CORE-8** Provide a generic cross-run scalar time-series sink,
  `metric_series(run_id, source, key, step, ts, value)`, for per-step
  emitters from any subsystem (training curves, bandit posterior/regret,
  coverage-frontier growth, mutation-search reward/novelty, stage
  wall-clock/throughput) to write through, plus the write API:
  `log_scalar(store, run_id, source, key, step, value, ts=None)` and a
  buffered `MetricLogger(store, run_id, source, flush_every=200)` context
  manager. Non-finite values (NaN/inf) are rejected at emit (dropped, with a
  warning) — never stored. `key` values are bounded/slash-delimited paths;
  distributions are pre-binned by the writer, never stored per-example.
  Indexed for both a single series within a run and a cross-run overlay of
  the same series. (Added by CC-CORE-0018; per-component emitters that write
  through this API are separate components' scope, not CORE's.)
- **FR-CORE-9** Provide `saved_views(id, table_key, name, spec_json, is_pinned,
  created_at, updated_at)`: a durable store for named filter/sort/column specs
  a faceted UI workbench saves, keyed by `table_key` (the logical dataset the
  view is over, e.g. `"finding"`) so more than one workbench can share the
  table. `spec_json` is opaque to CORE — owned and shaped entirely by its
  caller (`fuzzlab.web.savedviews`); CORE only provides the table and index.
  (Added by CC-CORE-0019, for the Findings workbench, `CC-UI-0029`.)

- **FR-CORE-10** `_VULN_TO_CATEGORY` (in `fuzzlab.core.runmode`) maps a ground-truth
  `vuln_class` to the audit-rule/oracle category it corresponds to, when one with a
  real, working confirmer exists — an unmapped class falls through
  `to_category()`'s own fallback unchanged and is never nominated by
  `evaluate()`, so it always scores as an honest false negative rather than a
  mis-wired one. Currently maps `sqli`→`sql-injection`, `xss-reflected`/
  `xss-stored`/`xss-dom`→`xss`, and `ssti`→`server-side-template-injection`
  (added by `CC-CORE-0020`, verified live against TrackerNest's real vulnerable
  and secure `ssti` twins before landing). A class is added here only once it has
  a real, independently-verified rule+confirmation-strategy pairing — adding an
  entry for a class with no confirmer would only relabel a false negative as a
  mis-wired candidate, not improve detection, so category 3's other 5 new classes
  (`xxe`/`insecure_deserialization`/`webhook_signature_bypass`/`ssrf`/
  `outbound_header_injection`) stay unmapped until each has one.

- **FR-CORE-11** *(`open_redirect`→`open-redirect` mapping; `CC-CORE-0021`,
  2026-09-23).* Extends `FR-CORE-10`'s map with `open_redirect`→
  `open-redirect` (category 5, Booking.com's real vulnerable cell,
  `CC-LAB-0210`), verified live end to end through
  `fuzzlab.harness.multitarget.run_targets`'s own real scoring (`PA-0042`),
  not just `ConfirmationStrategy.confirm()` in isolation — that stricter
  verification bar caught two real, distinct pre-existing defects
  (`BUG-0039`: `RequestsProbeSender` followed redirects into an attacker-
  controlled canary host; `BUG-0040`: `OpenRedirectStrategy.vuln_class`'s
  spelling didn't match ground truth's own convention), both fixed before
  this mapping was considered complete — see `CC-CORE-0021`'s own entry for
  the full record and `CC-FUZZ-0027` for the fixes' own component-owner
  entry. Real, verified result: `tp=1, fn=2, fp=0` against Booking.com's
  real, locally-booted deployment. Scoped to `open_redirect` only — category
  5's other three built classes have no verified confirmer yet.

- **FR-CORE-12** *(`price_integrity_bypass`→`price-integrity-bypass`
  mapping; `CC-CORE-0022`, 2026-09-23).* Extends `FR-CORE-10`'s map with
  `price_integrity_bypass`→`price-integrity-bypass` (category 5,
  Booking.com's real vulnerable cell `LABGEN-BC-0005`, `CC-LAB-0212`),
  paired with a genuinely new rule+strategy (`R-PRICE-INTEGRITY`/
  `PriceIntegrityBypassStrategy`, `CC-FUZZ-0029`, this component's own
  FUZZ counterpart — see `FR-FUZZ-16`). Verified live end to end through
  `fuzzlab.harness.multitarget.run_targets`'s own real scoring (`PA-0042`),
  not just `ConfirmationStrategy.confirm()` in isolation. Real, verified
  result: `tp=2, fn=1, fp=0` against Booking.com's real, locally-booted
  deployment (recall `1/3 -> 2/3`). Scoped to `price_integrity_bypass`
  only — `csv_formula_injection` (Booking.com) and
  `insecure_deserialization` (Expedia) still have no verified confirmer.

- **FR-CORE-13** *(`csv_formula_injection`→`csv-formula-injection`
  mapping; `CC-CORE-0023`, 2026-09-23).* Extends `FR-CORE-10`'s map with
  `csv_formula_injection`→`csv-formula-injection` (category 5,
  Booking.com's real vulnerable cell `LABGEN-BC-0003`, `CC-LAB-0211`),
  paired with a genuinely new rule+strategy (`R-CSV-FORMULA-INJECTION`/
  `CsvFormulaInjectionStrategy`, `CC-FUZZ-0030`, this component's own FUZZ
  counterpart — see `FR-FUZZ-17`). Verified live end to end through
  `fuzzlab.harness.multitarget.run_targets`'s own real scoring (`PA-0042`).
  Real, verified result: `tp=3, fn=0, fp=0` against Booking.com's real,
  locally-booted deployment (recall `2/3 -> 1.0`) — this app's own full
  ground truth, zero false negatives, closing Booking.com's toolkit-side
  detection coverage entirely. This is category 5's fourth real detection
  and the last of Booking.com's own classes; only Expedia's own
  `insecure_deserialization` remains unmapped in this category.

- **FR-CORE-14** *(migration 13; `CC-CORE-0026`, 2026-10-13).* `candidate` carries:
  - `oracle_status`:
    - `checked`: the oracle confirmed or rejected it;
    - `skipped_budget`: not sent to the oracle because `fuzzlab auto --confirm-budget`
      ran out. This is **not** a negative label;
    - `no_confirmer`: its category has no oracle confirmer;
    - `pending` *(CC-CORE-0033, BUG-0071)*: written before the oracle loop and
      overwritten as the oracle reaches the row. It survives only when a run crashed
      mid-loop, and is unlabelled (in `UNLABELLED`);
    - `inconclusive` *(CC-CORE-0043)*: a confirmer started a check but its cost cap
      stopped it before a decision. Unlabelled (in `UNLABELLED`);
    - NULL: written before migration 13 or by a writer outside the pipeline, with the
      old meaning (treated as oracle-labelled).
  - `anomaly_score` / `anomaly_flag`: the ECOD tripwire's advisory output.
  - Only the pipeline writes `oracle_status`, and only
    `fuzzlab.ml.anomaly.detect_anomalies` writes the anomaly columns. None of them is a
    `finding` label.

- **FR-CORE-15** *(migration 14; `CC-CORE-0027`, 2026-10-13).* `model` carries
  `params` (canonical JSON of the trained model) and `params_sha256` (sha256 of that
  exact text). Only the ML trainers write them, through `fuzzlab.ml.persist`; rows
  from before migration 14 read NULL and are not reloadable.
- **FR-CORE-17** *(`CC-CORE-0029`, 2026-10-13).* The `candidate.oracle_status`
  vocabulary (`checked`, `skipped_budget`, `no_confirmer`, `pending`, `inconclusive`,
  and the `UNLABELLED` set) is defined once in `core/oracle_status.py`.
- **FR-CORE-33** *(`CC-CORE-0043`, 2026-10-14).*
  - `inconclusive` means the candidate **could not be decided: a cost cap stopped it,
    or no mechanism could place the point** (the second since CC-CORE-0046,
    FR-FUZZ-47: every applicable mechanism raised `UnplaceableLocation`, mechanism
    `unplaceable`). It is a member of `UNLABELLED`, so it is never a negative label.
  - The pipeline writes it for every row of a key whose confirmation returned an
    inconclusive verdict and nothing confirmed (FR-FUZZ-45). Which meaning applies is
    the verdict's mechanism, carried in the run's `inconclusive` detail and shown by
    `fuzzlab auto` and the web run page (`unplaceable` vs the capped mechanism, e.g.
    `boolean-differential`).
- **FR-CORE-24** *(atomic migrations; `CC-CORE-0034`, 2026-10-13, BUG-0087).*
  - **Each migration is atomic.** It runs in one `BEGIN IMMEDIATE` transaction,
    statement by statement (`split_statements`), with its version row: `COMMIT`, or
    `ROLLBACK` on any error. A failed migration leaves nothing behind.
  - **The version is re-read inside the write lock,** so concurrent first opens never
    double-apply.
  - **`open_store`** sets `busy_timeout` before the WAL switch and retries the switch
    for up to 10 s.
- **FR-CORE-25** *(shared safety helpers; `CC-CORE-0034`, 2026-10-13, BUG-0079/0080/0084).*
  - `core.net.is_loopback_host` / `require_loopback`: the one listener gate (D11),
    accepting `localhost`, 127/8, `::1` and IPv4-mapped loopback;
  - `core.redaction.is_sensitive_name`: the one secret-name predicate (by name token),
    used by obs and proxy redaction. *(CC-CORE-0035, BUG-0090:)* a trailing plural `s`
    is folded only when the folded form is sensitive (`passwords`, `secrets`,
    `apiKeys`; never `passes`, and never `pass` → `pas`). The whole names `codes` /
    `pins` are accepted false redactions. *(CC-CORE-0052, forms phase 4:)* a payment
    card's security code (`cvv`, `cvc`, `cvn`, `csc`) is sensitive too;
  - `core.secretfile`: secret files are created 0600 with `O_NOFOLLOW`. *(CC-CORE-0035,
    BUG-0096:)* every write is complete or raises (a loop over short writes, then
    `fsync`):
    - `write_secret` writes in place;
    - `create_secret` refuses an existing file (`O_EXCL`), for a trust root;
    - `replace_secret` is atomic (unique temp file, fsync, rename, directory fsync; on
      failure the original is intact and no temp is left).

    The encrypted keyring saves through `replace_secret`.
  - *(CC-CORE-0036, BUG-0105)* The directory fsync is skipped only where the platform
    cannot do it (no `O_DIRECTORY`; `EINVAL` / `ENOTSUP` / `EOPNOTSUPP`). Any other
    error after the rename raises `DurabilityUnknown`: the new content is visible,
    durability is not established, and a retry is safe.
  - *(CC-CORE-0036, BUG-0100/0099)* **`core.redaction` is the one storage-redaction
    boundary** (`redact_url`, `redact_body`) for every producer of persisted traffic,
    and it **fails closed**:
    - a body over `MAX_REDACT_BYTES` (8 MiB) is omitted;
    - unparseable JSON, or JSON deeper than `MAX_JSON_DEPTH` (64), is omitted when any
      identifier-like token or quoted string in it is a sensitive name, and kept
      otherwise;
    - untyped and `text/plain` bodies are sniffed (JSON if it parses, form if it has
      the urlencoded shape).

    An AST guard enumerates the producers.
  - *(CC-CORE-0036, BUG-0108/0109)* The encrypted keyring serialises load → save with a
    thread lock plus `flock` on `<keyring>.lock`. Non-POSIX gets threads only, and
    `flock` is advisory and unreliable on NFS (both stated). `CredentialStore.delete`
    verifies the entry is gone, or raises `CredentialError`.
  - *(CC-CORE-0036, BUG-0107)* `core.evidence.parse_evidence` is the one parser of
    candidate evidence: an object with string `url` / `param` / `category`, and
    `method` absent or a string; anything else is `None`. `display_evidence` is the
    display-only, never-raising variant.
- **FR-CORE-26** *(migration 19; `CC-CORE-0036`, 2026-10-13, BUG-0104).*
  - `holdout_seal` (`origin`, `record`, `version`, `fraction`, `model_id`,
    `created_at`; append-only) holds every blind-holdout seal, apart from the mutable
    model calibration JSON.
  - `holdout_seal_meta` holds the backfill watermark (the highest model id at
    migration time).
  - `migrations.POST_STEPS = {19: _backfill_holdout_seal}` copies every present legacy
    `holdout` record (valid or malformed) **inside the migration's own
    `BEGIN IMMEDIATE` transaction**, so no reader ever writes.
  - The tables hold membership facts only, and stay browsable.
- **FR-CORE-23** *(aborted runs; `CC-CORE-0033`, 2026-10-13, BUG-0078).*
  `Store.mark_aborted(run_id, exc)` records on a run that failed after it started
  `run.notes = "aborted: <Type>: <message>"`, or `"aborted: exit N"` for `SystemExit`,
  truncated to 500 characters, after rolling back any half-written statement. It is best
  effort and never masks the error being handled. The run-starting entry points
  (`fuzzlab auto`, `greybox-run`, `run_targets`) call it from a `BaseException` guard,
  so no failed run reads as an empty finished one.
- **FR-CORE-22** *(packaging; `CC-CORE-0032`, 2026-10-13, BUG-0068).* Every tracked
  non-Python file under `fuzzlab/` ships in the built package (wheel, sdist,
  `build_py`), except the declared exclusions (`exclude-package-data "*"`: caches,
  credentials/keys, SQLite side files, OS/editor junk); executable bits are kept. The
  deny-list never matches a tracked file; release builds come from a clean checkout
  (stray `*.db` / `.env` variants cannot all be denied). Verified on the built artefact
  by `tests/test_packaging.py` (PA-0070).
- **FR-CORE-20** *(migration 18; `CC-CORE-0031`, 2026-10-13).* `flow.anomaly_score REAL`
  and `flow.anomaly_flag INTEGER` (FR-ML-23); existing rows read NULL (never scored).
- **FR-CORE-21** *(candidate features; `CC-CORE-0031`, 2026-10-13).* `core/features.py`
  holds the candidate vector: `CANDIDATE_FEATURE_NAMES`, `CANDIDATE_FEATURE_VERSION = 1`
  and `extract_candidate_v1(evidence, sink_context, rules_fired)`, moved verbatim from
  `ml/dataset` (which aliases them, so saved models are unaffected) and pinned by
  `tests/data/candidate_features/v1_golden.json`, captured before the move. Its version
  counter is separate from the response extractor's `FEATURE_VERSION`. It imports no ML.
- **FR-CORE-19** *(migration 17; `CC-CORE-0030`, 2026-10-13).*
  - **Migration 17** adds `holdout_metric(id, run_id, model_id, holdout_version, key,
    value)` and `holdout_reveal(id, run_id, holdout_version, revealed_at)` (FR-ML-19).
  - **`core/sealed.py`:** `SEALED_TABLES` (no generic store view lists or browses them),
    `write_metrics` (the trainers, under the advisory guard) and `reveal(store, run_id)`
    — the one reader, which records a `holdout_reveal` row and returns the store-wide
    reveal count for the version (none recorded when there is nothing to reveal). No ML
    import, so a reveal works without the ML package.
- **FR-CORE-18** *(migration 16; `CC-CORE-0029`, 2026-10-13).*
  - **Canonical origin.** `core/urls.canonical_origin(url)` is the canonical
    `scheme://host:port` used to compare targets (loopback aliases → `127.0.0.1`;
    explicit default port). It is `None` (never matches) for no usable host or port.
  - **Migration 16** adds `candidate.score_oof` / `rank_score_oof` (FR-ML-16).
- **FR-CORE-16** *(migration 15; `CC-CORE-0028`, 2026-10-13).* `run_plugin` carries
  `config` (canonical JSON of the plugin's options), `status` (`attached`, then `ok` /
  `failed`) and `error`. They are written by `PluginManager.record` / `finalize`
  (FR-PLUG-7) and read per run by `fuzzlab report`. Legacy rows read NULL.
- **FR-CORE-27** *(form serialisation; `CC-CORE-0037`, 2026-10-13, BUG-0110).*
  - `core/forms.form_entries(form)` is the one way a scraped HTML form is serialised:
    - the result is the browser's entry list (HTML §4.10.21.4) as ordered
      `(name, value)` pairs, duplicates included;
    - `core/forms.RULES` lists every implemented rule with its spec step;
    - a guard test requires one fixture per rule (PA-0111).
  - **Stated deviations:**
    - the submitter is the first *enabled* submit control;
    - `dirname` and script-set state are not modelled;
    - the submitter's `formaction` / `formmethod` / `formenctype` are reported by
      `submitter_overrides`, never applied.
  - `default_value(el)` is the value a control holds before input, for reporting.

- **FR-CORE-28** *(destructive URLs; `CC-CORE-0038`, 2026-10-13, BUG-0111/0112).*
  - **The rule.** `core/urls.destructive_reason(url)` is the one rule for "this URL
    performs a destructive or session-ending action". It decodes the path and query
    (up to 3 rounds), splits camelCase, tokenises, and matches `DESTRUCTIVE_TOKENS`
    or `DESTRUCTIVE_PAIRS`. `format` is deliberately absent, since it is the export
    selector. Accepted false positives include `password_reset` pages.
  - **Texts** *(`CC-CORE-0052`, 2026-10-14, BUG-0131).* `text_destructive_reason(text)`
    applies the same tokens and pairs to a whole **text** -- a button label, a control
    name, an entry value, an option -- decoded the same way (up to 3 rounds of `%xx` and
    `+`) but never parsed as a URL, so a `#` or `?` in it hides nothing. A text is never
    judged by embedding it in a URL (`destructive_reason("/?x=" + text)`): enforced by
    an AST guard over `fuzzlab/` (PA-0131).
  - **Helpers.** `url_key(url)` (canonical origin plus path) names an explicit
    allowance. `check_send_url(url, explicit)` raises `DestructiveUrlRefused`.
  - **Users:** the crawler and auditor (NFR-CRAWL-safe), every probe sender
    (FR-FUZZ-40), and login discovery's hop check (FR-SESS-13).

- **FR-CORE-29** *(forms; `CC-CORE-0039`, 2026-10-13).*
  - `core/forms.form_record` describes a scraped form: action, method, enctype,
    controls, the browser-default entry list with password and sensitive values
    blanked, and selector options.
  - **Migration 20** stores a crawled form's entries in `form`, and links its fields
    through `parameter.form_id`.

- **FR-CORE-30** *(forms phase 2; `CC-CORE-0040`, 2026-10-14).*
  - `core/redaction.looks_like_identifier(value)` is the single test for "this value
    looks like a secret identifier" (a session id, a one-time or capability token, an
    API key).
  - **How it decides:** the value is split on `. : @` and whitespace, and on `/` when
    it is a URL or an absolute path. It is identifier-like when a piece drawn from
    `[A-Za-z0-9_-+/=]` either:
    - has at least 16 characters with a digit or with both cases; or
    - has 8–15 characters with a letter, a digit and at least 32 Shannon bits;

    and the piece is neither word-shaped (every `_`/`-`/`/`/`+` part a word with at most
    four trailing digits, or a short number) nor a date.
  - **Accepted false negatives:** about 0.3% of random tokens, and 0.6% of
    16-character standard base64.
  - **Callers pass the raw value:** percent-decoded, not form-decoded.
  - **Total and linear:** it never raises, and runs in time linear in the value.
  - **No second definition:** nothing else in `fuzzlab/` defines its own entropy or
    identifier test.

- **FR-CORE-31** *(forms phase 2, lane B; `CC-CORE-0041`, 2026-10-14).*
  - **Migration 21** adds `form.password_fields` (`TEXT NOT NULL DEFAULT '[]'`): the
    names of the form's password controls, as a JSON list, written by the importer from
    the control kinds. A form with any is an in-app login form (FR-FUZZ-44).
  - Rows from migration 20 read `[]`. The one reader (`harness.auto._password_fields`)
    treats a malformed value as unknown and fails closed.
- **FR-CORE-32** *(forms phase 2, lane A; `CC-CORE-0042`, 2026-10-14; no schema change).*
  - **The `form` table** is a request's default sibling entry list: a crawled form's
    (`enctype` set, possibly `""`) or a crawled link's query (`enctype` NULL). Only
    `core.forms.is_link_set` tells them apart, and `core.forms.first_link_set` is the
    one store reader of `form.enctype` (a guard test keeps it so).
  - **Header-point names:** `core.http.header_point_refusal` is the one rule
    (framing, routing, method-override and credential headers, and any name
    `is_sensitive_name` flags; whole names, case-insensitive). `check_send_header`
    applies it at send, except for explicitly enumerated (ground-truth) URLs.
  - **Credential names:** `core.redaction.is_credential_name` is the one predicate for
    the importer and the point builder.
  - **`oracle_status`:** `pending` also covers rows a safety breaker stopped before
    the oracle reached them; the reason is in the run's metrics.
- **FR-CORE-34** *(origin scope; `CC-CORE-0044`, 2026-10-14, BUG-0123).*
  `core/urls.origin_scope(*urls)` and `in_origin_scope(url, origins)` are the one
  predicate for "may a browser or API-request client reach this URL": canonical
  scheme, host and port (`canonical_origin`; loopback aliases on one port are one
  origin, other 127/8 addresses distinct), `ws`/`wss` compared as `http`/`https`, and a
  URL without `://` never in scope. **Users:** the spider, the auditor's fetcher, the
  M6 browser executor and `tools/navguard`.
- **FR-CORE-35** *(transactions; `CC-CORE-0045`, 2026-10-14, forms phase 3).*
  `core/urls.transaction_reason(text)` is the one rule for "submitting this spends,
  buys, moves or subscribes": `TRANSACTION_TOKENS` / `TRANSACTION_PAIRS` over a URL's
  path, query and SPA fragment, a route path or a button label (tokenised like
  `destructive_reason`, plural folded). Such a page may be visited; its form is never
  submitted by the crawler and a captured request to it is never imported for fuzzing.
- **FR-CORE-36** *(the `json` point location; `CC-CORE-0046`, 2026-10-14, forms phase
  3; no schema change).*
  - **The location.** `parameter.location = "json"` (`core.jsonbody.LOCATION`) is a
    point whose payload goes into **one leaf** of a JSON body sent as
    `Content-Type: application/json`. Its `form` row has `enctype = "application/json"`
    (`jsonbody.ENCTYPE`) and `entries` `[[path segments], typed value]`, a path being
    string keys and integer list indexes. A send rebuilds the whole body from the
    entries (types kept: numbers, bools, null, empty containers) with the leaf set to
    the payload **as a string**. A sender that cannot place it raises
    `UnplaceableLocation` (PA-0115). A leaf the captured entries do not have is never
    added to the body (`replace_leaf` refuses); only a send with no entries sends
    `{leaf: payload}` alone.
  - **Names.** `jsonbody.display_name` joins keys with `.` and writes indexes as
    `[n]`, escaping `\`, `.`, `[` and `]` inside a key with `\`; `parse_name` is its
    exact inverse (byte for byte) and is None for any other text. The parameter name
    is the display name.
  - **Bounds and parsing.** A body over 64 leaves or 16 levels is not a point source.
    `jsonbody.decode_entries` is the one reader of a stored entry list; a malformed
    list (bad shape or type, a non-finite number, a repeated path, a path through
    another leaf) is None, and the caller drops the point.
  - **SPA routes.** `core.urls.spa_route` reads a hash route (`#/x?q=1`, `#!/x`) and
    `to_route_path` stores a `fragment` point's endpoint as `/#/x` (the route's query
    dropped), so a browser can load the route.
  - **DELETE at send.** `check_send_url(url, explicit, method=)` refuses a `DELETE`
    whose URL was not explicitly enumerated (`REFUSED_SEND_METHODS`).
  - **Candidate feature.** `loc_body` counts `json` as a body location (CC-ML-0030; the
    feature version is unchanged).
- **FR-CORE-37** *(captured requests; `CC-CORE-0047`, 2026-10-14, forms phase 3).*
  `core/redaction` is the one boundary for what the crawler stores of the app's own
  requests (FR-CRAWL-13) and of a SPA route's URL (FR-CRAWL-12):
  - `redact_captured_body(body, content_type)` returns `(value, None)` or `(None,
    reason)`. Only a JSON object or array, or a form-encoded body (an object, the last
    value of a repeated name winning), at most `CAPTURE_MAX_BYTES` (64 KiB) and
    `CAPTURE_MAX_DEPTH` (8) deep, is recorded, and only if `redact_body` (fail closed)
    would not omit it. A sensitively named key's value (`is_sensitive_name`) is blanked
    whatever its shape, and an identifier-like value too -- a string (a form value
    judged raw) or a number judged as its text: a string becomes `""`, a number or
    boolean `null`, a container empty. An identifier-like key or form name is replaced
    by `REDACTED_KEY` (`__REDACTED_KEY_<n>__`) and its value blanked. The result never
    depends on whether the body was JSON or form-encoded. Total (never raises).
  - `is_sensitive_name` also treats the adjacent token pairs `SENSITIVE_PAIRS`
    (`security answer`, `secret answer`, `recovery answer`, plural folded) as secrets;
    a bare `answer` is not one.
  - `redact_url_identifiers(url)`: `redact_url`, then identifier-like query values
    blanked to `name=`, and a SPA-route fragment's query redacted the same way.
  - `redact_spa_fragment(url)`: only that fragment step (`#/x?token=…`; a fragment that
    is not a route is left alone), for the crawler's stored route URLs.

- **FR-CORE-41** *(a started server is up only when it owns its port; `CC-CORE-0057`,
  2026-10-15, BUG-0143).*
  - `procutil.start_server_on_free_port` picks a loopback port, starts the server, and
    returns only once the server's own process tree listens on that port
    (`port_owner(h, port) == "ours"`).
  - A port another process answers on raises `PortTaken` and is retried on a fresh port
    (3 attempts). A server that exits first, or misses its timeout, raises
    `ServerDidNotListen` with its output.
  - A bare connect is never a boot check: it also reaches another process holding the
    port.
  - Enforced by: `tests/test_server_port_ownership.py` (ownership, retry, exit, the
    real-Go reproduction, and an AST guard over every port-picking server start).
- **FR-CORE-40** *(which document a URL loads; `CC-CORE-0055`, 2026-10-15, BUG-0138
  review).* `core.urls.document_key(url)` is the canonical origin, path and query of a URL,
  fragment dropped: two URLs load the same document exactly when their keys are equal
  (`/p?a=1` and `/p?a=2` differ; `url_key`, origin and path only, does not tell them
  apart). It is the one definition for the crawler's own-reload key (`spider._nav_key`)
  and for the browser guard's "the page still shows the document I loaded" and received-HTML
  lookups (`tools.navguard`), PA-0003. Enforced by:
  `tests/test_guarded_navigation.py` (the `/p?a=1` → `/p?a=2` case).
- **FR-CORE-39** *(the open-redirect name set; `CC-CORE-0053`, 2026-10-14, FR-CRAWL-17
  review).* `core.urls.REDIRECT_PARAMS` (a frozenset) is the one set of parameter names
  that control the next location. The auditor's redirect rule
  (`tools.fetcher.rule_redirect_parameters`, exact lower-cased names; `tools.fetcher`
  re-exports the same object) and the crawler's seeds and probes
  (`tools.spa.redirect_name`, whole tokens or the whole name) both read it (PA-0003).
  Moved unchanged from `tools/fetcher.py`. Stated tension: the rules-data
  `R-OPEN-REDIRECT` `name_regex` is a second, regex-shaped list; changing detection is
  out of this requirement's scope.
- **FR-CORE-38** *(process trees; `CC-CORE-0048`, 2026-10-14, BUG-0125).*
  `fuzzlab/procutil.py` is the one way the toolkit and its tests start a long-lived
  child process or a forking tool. It is a **stdlib-only leaf** (imports nothing from
  `fuzzlab`), so `fuzzlab.labgen` may use it. Contract:
  - `start_server(argv, *, cwd, env, stdin, stdout, stderr, text, grace, allow_thread,
    ready_timeout) -> ServerHandle` starts a supervisor (this file run by
    `sys.executable -I -S`) in a new session; the supervisor sets
    `PR_SET_PDEATHSIG(SIGTERM)` and `PR_SET_CHILD_SUBREAPER` on itself, exits if its
    parent is not the owner pid, starts `argv` in a new process group (server
    `PDEATHSIG(SIGKILL)`, `oom_score_adj` raised by 500, capped at 1000), and on a stop
    request, an unrequested SIGTERM (handled once), the owner's death or the server's
    exit stops the group and every re-parented descendant (SIGTERM, grace, SIGKILL),
    reaps, and exits with the server's exit code. `handle.proc` is the supervisor's
    `Popen`; its stdout/stderr carry the server's. Exec failure raises the real
    `OSError`; a missing `prctl` raises `SupervisorUnavailable` (never a silent
    downgrade). Off the main thread it raises unless `allow_thread=True`, with which the
    server dies when the forking thread ends -- loudly (`ServerLost`, a stderr line).
  - `stop_server(handle, *, timeout)` requests a stop (control pipe + pidfd SIGTERM),
    waits for the supervisor to exit **without reaping it** (`waitid(WNOWAIT)`), and if
    it is wedged kills, inside its still-held session, the server's group and the
    supervisor's other descendants, then the supervisor; then sweeps the supervisor's
    session while its pid is held, and only then reaps it. Idempotent; returns the exit
    reason (`stop`, `child`, `owner`, `killed`); raises `ServerLost` for `signal`.
    `finish(handle)` collects an exited one. The supervisor likewise reaps its server
    only after its last `killpg`. *(BUG-0125 review, CC-CORE-0050.)*
  - `run_bounded(argv, *, timeout, cwd, env, input, text)` behaves like
    `subprocess.run(capture_output=True, timeout=)` but stops the tool's whole tree on
    timeout and on its exit. `astart_server` / `astop_server` / `arun_bounded` are the
    asyncio forms (their process view never lets asyncio reap the supervisor before the
    sweep); `request_stop` is the non-blocking stop.
  - Identity: every signal goes through a pidfd (where available) after the target's
    `/proc/<pid>/stat` start time (field 22) matches the recorded one. A group or
    session id is trusted only while its leader pid is held (alive or an unreaped
    zombie, matching start time); a group whose leader is gone only inside a held
    supervisor's session (`anchor`). A start time of 0 means "identity unknown":
    nothing is signalled, `start_server` refuses such a server, and the safety net
    reports such a record. Nothing is killed by name or pattern (`kill_process_group`,
    `group_members`, `session_members`, `read_stat`).
  - Listening sockets *(BUG-0130, CC-CORE-0051)*: `listeners(handle)` returns every TCP
    LISTEN socket held by the server's tree (`/proc/<pid>/fd` inodes mapped to
    `/proc/<pid>/net/tcp{,6}` LISTEN rows), only while the supervisor pid is held;
    `exposed_listeners` / `assert_loopback_only` (raises `NonLoopbackListener`). Every
    stop (`stop_server`, `astop_server`, the safety net) checks them while the server is
    still up and, after stopping the tree, raises `NonLoopbackListener` on exposure.
    *(BUG-0130 follow-up, CC-CORE-0051.)* Each `Listener` carries its `netns`.
    `listeners()` reads one table per distinct `/proc/<pid>/ns/net`, from that
    process's own `/proc/<pid>/net/tcp{,6}`, and skips unparseable rows.
    A listener is **exposed** only if it is non-loopback *and* in the host's network
    namespace. The host's namespace is this process's own; `host_netns=` overrides it
    for tests. A wildcard listener in a private namespace (`unshare -n`) is listed but
    not exposed.
    The rule is "checked after boot, and at stop while live", and the stop's check is
    total. Anything the check raises is recorded, and the stop, sweep and collect
    always run. Afterwards the stop raises `ListenerCheckFailed`. An exposed server
    that had also been stopped without a request raises `ExposedAndLost`, which is
    both a `NonLoopbackListener` and a `ServerLost`. This runtime check is
    authoritative; the source rules are lints.
  - A registry of what this process started (`registered()`); `reap_registered()` stops
    every live entry and returns `Leak(argv, pid, age_s, note)` records, dropping a
    record whose pid now names another process.
  - Stated residual (BUG-0130 confirmation, reviewer A): "exposed" is judged against the
    owner's own (host) network namespace. A listener in some other pre-existing namespace
    (a container's, joined with nsenter) would not count as exposed, even though that
    namespace may be bridged with published ports. Nothing launches servers that way
    today.
- **FR-CORE-300** *(host LISTEN table; `CC-CORE-0300`, 2026-10-15).*
  `procutil.host_listen_sockets()` returns a `Listener` (pid 0: the owner is not looked
  up) for every LISTEN socket in the calling process's network namespace, through the same
  `/proc/net/tcp{,6}` parser as `listeners()` (PA-0087); `netns_of(pid)` and
  `host_netns()` name a process's and this process's network namespace. Consumer: the
  external lab
  fixtures' exposure check (FR-LAB-301), which judges a container engine's published
  ports -- sockets this process did not start. The spawn guard
  (`tests/test_procutil_guard.py`) treats `bash`, `sh`, `docker`, `podman`,
  `docker-compose` and `podman-compose` as forking tools: a `subprocess.run`-family call
  of them with a `timeout=` must go through `run_bounded` (an unbounded call is held to it
  by review, not by the guard).

- **FR-CORE-400** *(store resolution; `CC-CORE-0400`, 2026-10-15).* `--store` is not required
  by the commands that resolve it (`report`, `train run`,
  `train models`, `train reveal-holdout`/`reveal-holdout`, `train flow-anomaly`/
  `flow-anomaly`, `train mutate`/`mutate-run`, and `proxy --record`). For those
  commands, and for the web UI's `load_config()["store_path"]`,
  `core/storepath.resolve` is the one resolution (PA-0003).
  - **Exceptions in Phase 1:** `auto` and `greybox-run` still require `--store` (their
    files were locked). They gain the default in Phase 2.
  - **Opt-in only:** `crawl`, `audit` and `fuzz` keep `--store` as opt-in
    consolidation, with no default.
  - **Order:** `--store PATH`, then `$FUZZLAB_STORE`, then `$FUZZLAB_STORE_PATH`, then
    `DEFAULT_STORE` (`fuzzlab.db` in the current directory, the shared project store).
  - **Environment values:** an empty variable is unset, and `~` is expanded.
    `from_environ` (the only reader of the two variables) never raises.
  - **Explicit empty flag:** an explicit empty `--store` is a usage error.
  - **Side effects:** resolution writes nothing.
    - Writers create the store file on first use (`Store`). Its mode comes from the
      umask, as for any explicit path; a private mode is part of the §8 per-user
      follow-up.
    - Non-creating commands (`report`, `train models`, `reveal-holdout`,
      `flow-anomaly`) refuse a missing store. They do migrate an existing older store
      when they open it.
  - **Typed refusals:** a missing directory, or a path that is a directory or another
    non-regular file, is refused with the typed `StorePathError` (a `ValueError`), which
    each CLI prints as a usage error.
  - **The printed line:** these commands' run summaries and read-only output name the
    resolved store and its source (`describe`). A wrapper that forwards to an engine
    passes the resolved store, so what it prints is what is opened (BUG-0401, PA-0401).
  - **Help text:** the default rule is stated from `DEFAULT_STORE` (`DEFAULT_RULE`,
    `store_help`), never restated.
  - **Config hash:** with neither variable set, the config value and its hash are
    unchanged.
  - **Test isolation:** tests run with both variables cleared (from `pytest_configure`).
    The session fails on any new or written `fuzzlab.db` in the repository tree (minus
    pytest's temp base) or in an outside cwd's own files (`tests/_store_guard.py`, never
    walking an unowned directory: BUG-0402, PA-0402).
  - **Shared model facts:** `core/modelinfo.trained_on` is the one reading of what a
    model row was trained on (absent = `run`; `run`/`earlier`/`saved` as recorded; any other value is `None`, PA-0108).
    `report` (which shows it as `unknown`) and `train models` both use it, and it works
    in a no-ML build.

- **FR-CORE-450** *(project files; `CC-CORE-0450`, 2026-10-15; migration 22).* A store
  is a project. Migration 22 adds `project` (one metadata row: name, created_at — the
  store's own creation time, `MIN(schema_version.applied_at)` — opened_at, notes,
  targets, the fuzzlab versions that created and last opened it, the schema version it
  was created at), `launch` (FR-CORE-451) and `run.launch_id`, and stamps the fuzzlab
  SQLite `application_id` (`migrations.APPLICATION_ID`). The migration writes no
  metadata row; `core.project.ensure_metadata` creates it on the first UI open (one
  `BEGIN IMMEDIATE`, re-checked) and marks orphaned `running` launches `unknown`.
  `core.project` is the one writer and parser of both tables; `inspect` reads a file
  without writing its main file and refuses (typed `ProjectError`, from a named list of
  errors) anything that is not a fuzzlab store, fails the allowlist below, or fails
  `quick_check`; `create` makes a file 0600 / `O_EXCL` / `O_NOFOLLOW`; `copy_to` copies
  with the SQLite backup API into a private temporary file (rollback journal), checks no
  side file holds data, `quick_check`s, fsyncs and hard-links it into place;
  `migrate_with_backup` writes a verified backup before migrating.
  `Store(path, create=False)` / `open_store(..., create=False)` open an existing file
  only (a `mode=rw` URI); every connection sets `trusted_schema=OFF`.
  *(Code review round 2, BUG-0451:)* the untrusted-file check is an **allowlist**:
  `reference_schema(version)` (fuzzlab's migrations run in memory) and `_foreign_objects`
  refuse any `sqlite_master` row whose exact `(type, name, tbl_name)` is not fuzzlab's at
  the file's version, or — *(code review round 3, BUG-0453; round 4, BUG-0456)* — whose
  **definition** differs from the reference's **byte for byte** (no normalisation), **for every object including tables**
  (`trusted_schema=OFF` stops application functions only, so an added generated column,
  `CHECK` or `DEFAULT` would run SQLite's own functions); `sqlite_stat1`/`sqlite_stat4`
  must carry SQLite's own definitions. `schema_version`'s definition is checked from
  `sqlite_master` before any of its rows is read, and a file newer than this build is
  returned as `newer` before anything else of it is read. A non-integer or < 1 schema
  version, a foreign `application_id`, or a missing `run` table is refused too. The
  inspecting and summarising connections cap string/blob length (4 MiB, 1 MiB). Every
  value `core.project` reads back from such a file is typed before use (`_text`, `_int`,
  `RecursionError` among the JSON errors; BUG-0454).
- **FR-CORE-453** *(project identity; `CC-CORE-0450`, migration 23).* `project` gains
  `uuid` (the file's own id, 32 hex — **display only**: nothing matches, dedupes or trusts
  on it, since a file can claim any value), `origin_uuid`, `copied_at`, `copy_kind`
  (`snapshot` | `save-as`); the post-step backfills `uuid` for an existing row.
  `core.project.mark_copy` (one transaction) records a published copy: a new `uuid` plus
  its origin, or — a saved temporary project — the same `uuid`. `file_facts` (size, last
  write) and `summary` (bounded read-only counts for listings) serve the UI's lists.
- **FR-CORE-451** *(launch provenance; `CC-CORE-0450`).* A job the web UI starts is a
  `launch` row with a random 32-hex `token`; the UI gives the child
  `FUZZLAB_LAUNCH_TOKEN`, and `Store.start_run` links each run it creates
  (`launch_id`) only when that token names a `launch` row of the same store — anything
  else links nothing. Every recorded value passes `core.redaction.redact_for_record`.
  `store.is_aborted` is the one reader of `mark_aborted`'s `aborted: ` note.
- **FR-CORE-452** *(newer schemas; `CC-CORE-0450`).* `migrations.migrate` raises
  `SchemaTooNew` (before any write) when a store's schema is above this build's
  `head_version()`; `Store` closes its connection on that or any migration error. Each
  migration remains its own transaction, so a failed multi-version upgrade leaves the
  store at the last version that completed (`migrate_with_backup` names it and the
  backup).

- **FR-CORE-501** *(URL placement: a path segment or a query value; `CC-CORE-0059`,
  2026-10-19; `CC-CORE-0068`, 2026-10-20, BUG-0531).*
  `core.urls.place_path_param(url, param, value)` replaces the URL path's one segment
  equal to `{param}` with `value` percent-encoded as one segment (`/` and quotes
  encoded), keeping the query; a path without that segment exactly once raises
  `PathPlacementError`.
  - `core.urls.QueryEntries` is the ordered list of a query's raw parts: split on `&`
    only from `urlsplit`'s query (`;` is data), an empty query having none, empty parts
    and the absence of `=` kept, each name decoded with `errors="surrogateescape"` for
    matching only.
  - `place_query_param(url, name, value)` puts `encode_query_value(value)`
    (`quote_plus`, `safe=""`) into the first part named `name` (its raw name text kept),
    or appends one encoded pair, and keeps every other part's text and the rest of the
    URL.
  - `with_query(url, entries)` sets the query to the urlencoded entries;
    `bind_query(url, entries, name, value)` is `with_query(url,
    FormEntries(entries).replace(name, value))` (every occurrence: the binder's rule).
  - `place_route_query_pairs(url, pairs, encode=encode_route_value)` places each pair,
    in order, by the same first-occurrence rule into the URL's route query: the
    fragment's own query when the URL has a fragment (hash mode), else its own query
    (history mode); `encode_route_value` is `quote` with `safe=""` (a space is `%20`).
    `place_route_query_param(url, name, value)` places one pair inside an SPA hash
    route's query through it; a non-route fragment is replaced by the pair.
  - These are the one placement (SP-42). Outside this module a query is built only at a
    site on an exact, reasoned allow-list; a known defect among those sites is pinned by
    a strict xfail naming its owner
    (`tests/test_query_placement.py::test_every_query_builder_goes_through_the_one_owner`).
- **FR-CORE-502** *(account values; `CC-CORE-0059`, 2026-10-19).*
  `CredentialStore.set_attributes(host, identity, {name: value})` stores an account's
  own values (lowercase names, non-empty strings) in its credential's keyring entry
  (refused when there is no credential); `attributes(host, identity)` reads them
  (empty when none). A new `set` of the credential drops them (SP-43).

- **FR-CORE-503** *(path templates from crawled URLs; `CC-CORE-0060`, 2026-10-19).*
  `core.pathtemplate.path_templates(urls)` returns, in first-seen order, one
  `PathTemplate(origin, path, param, example)` per (origin, template path), each path
  with one placeholder segment: a segment that is `id_shaped` (digits, a UUID, mixed
  hex of 8+ characters, or `looks_like_identifier`) even when seen once, named `id`;
  and, among URLs of one origin with as many segments that agree on all but one
  position (never the first), a position with two or more values, named after the
  segment before it. A URL whose last segment is a static asset (`ASSET_EXTENSIONS`)
  gives none; a file name (`FILE_EXTENSIONS`) or a placeholder is never a value. A URL
  with two parameters gives two templates, the other segment concrete (SP-45). Pure.
  *Amended `CC-CORE-0062` (BUG-0507):* `path_templates(urls, code=...)`:
  - a segment in `JS_PLACEHOLDERS` (`undefined`, `null`, `NaN`, `Infinity`,
    `[object Object]`) is shape evidence, named `id`;
  - a varying position is a parameter only through `varying_is_parameter(values,
    code=, data=None, min_distinct=2)`, the one decision `disco.synth` also uses: at
    least `min_distinct` values not among `code` (the segments the app's scripts hold,
    `code_segments`), and, with response `data`, every such value seen as data;
  - only a data value is a variation template's example;
  - one template per (origin, position), the first evidence naming it;
  - `FILE_EXTENSIONS` covers documents, data, configuration, backups and archives.

  `code_segments(text)` is each run of URL characters after a `/` ending at `/`, a
  quote, `?` or `#`, identifier-like ones dropped, at most `MAX_CODE_SEGMENTS`
  (5000), in one linear scan.

- **FR-CORE-504** *(a crawled URL's stored form; `CC-CORE-0061`, 2026-10-19).*
  `core.urls.store_url(url, main_origin, route=False)` is how an importer stores a
  crawled URL: its path (`to_route_path` with `route`) when it is on `main_origin` or
  either origin is unknown, else its canonical origin plus that path.
  `stored_absolute(stored, base_origin)` reads one back: a stored `http(s)://` URL as it
  is, else the path under `base_origin` (a path always starts with `/`, so one holding
  `://` stays a path). `is_loopback_origin` holds for 127.0.0.0/8, `localhost` and `::1`
  (SP-46).

- **FR-CORE-505** *(the trace: the evidence model behind the diagrams; `CC-CORE-0063`,
  2026-10-19).* `core.trace` (SP-48). **Events:** `trace_event` (migration 24) is
  append-only, one row per event: `run_id`, `key` (`UNIQUE(run_id, key)`: a repeated
  delivery or replay is ignored), `v` (the body schema, `EVENT_VERSION` 1), `kind`,
  `scope` (`test:<id>`, `workflow:<action>`, `capture`, `spider`, `proxy`, `run`), `seq` (the
  producer's order), `t` (when it happened; NULL when the source records no time --
  never replaced by "now") and a JSON `body`. Kinds: `run.start` / `run.end`,
  `observe.exchange` / `observe.page` / `observe.action` / `observe.external`,
  `test.start` / `test.strategy` / `test.end`, `exchange`, `finding`, and (FR-FUZZ-62,
  `CC-CORE-0065`) `browser.step` / `oob.wait`, the M6 and M8 confirmations' steps.
  - **Model:** `dg_entity` (actors, the application, origins, interfaces, external
    hosts), `dg_flow` (`view` `app` or `test`) and `dg_evidence` (each entity or flow's
    supporting event keys) are derived by `reduce`, idempotently and independently of
    order and batching (tested with permutations and batch sizes, BUG-0516): first/last
    seen min/max; attributes set unions keeping the `MAX_ATTR_VALUES` smallest values
    in a fixed order, with `<key>_more: true` when there were more; an entity's kind
    the strongest any event gives it (`interface` over `page`); knowledge only
    strengthens (`unknown` < `inferred` < `observed`); observation counts are counted
    from `dg_evidence`. `rebuild` replays a run's events into fresh rows and equals the
    incremental model. An origin always carries "internals unknown"; nothing
    server-side is created.
  - **What is drawn as what (BUG-0515):** an interface whose path holds a template
    segment (`{id}`, a crawled `{x}`) is `inferred` (a grouping; the requests to it are
    observed). The spider's own page loads come from a "Spider (crawler, tool)" actor,
    never the browser. A request learnt in the browser and blocked before sending
    (`delivery` not `sent`) is a separate `blocked` flow with `refused`, never traffic.
    A status of 0 is no status. A `browser.step` `store` or `navigate` that was sent is
    a `test`-view flow from `M6_BROWSER` ("Browser driven by the tool (M6)",
    `CC-CORE-0065`), never merged with the tool's exchange flow to the same interface;
    `oob.wait` adds nothing to the model.
  - **Interface identity** (SP-49): `interface_id(origin, method, url)` -- the origin,
    the method and the path with crawled placeholders kept and id-shaped or
    JavaScript-placeholder segments grouped as `{id}` (the grouping recorded as
    inferred), as is a segment `safe_ref` withheld; never the query, the fragment or a
    segment's `;name=value` parameters; words are never merged.
  - **`safe_ref`** (BUG-0514): sensitive and identifier-like query values blanked (a
    SPA route's too), userinfo, sensitive `;name=value` parameters and a query-shaped
    fragment's sensitive values replaced by the record boundary
    (`redaction.redact_for_record`), other identifier-like matrix and fragment values
    blanked, and an identifier-like path segment (a JWT, a reset token, a UUID), or an
    identifier-like run inside a segment (a URL embedded in a payload, BUG-0521),
    replaced by `{redacted}`.
  - **The writer:** `TraceRecorder(store, run_id, max_buffer=512, flush_seconds=0.25)`,
    one per producer, used only on the thread that owns its `Store` (a `Store` is one
    connection): a bounded buffer, a batch written with its reduction in one
    transaction, every body through `scrub_event` (PA-0100: strings with `://`, and any
    string with a `/` under a URL key (`url`, `location`, `redirect`, `referer`,
    `route`, ...), through `safe_ref`; values under sensitive key names blanked except
    the schema's own keys, whose values are names, labels or the tool's own words
    (`auth`, `session`, `identity`, `profile`: an account's name; `error`: a class);
    strings capped at `MAX_TEXT`); a full buffer flushes synchronously (counted
    `forced_flushes`); a batch that cannot be written is counted `dropped` and logged.
    The counters reach `run_metrics` (`trace_*`) while the run is live: at the first
    flush, at most every `METRICS_SECONDS` (1 s) after, at once after a drop, and at
    `close` (BUG-0516). Execution points call
    `trace.emit` (a no-op without an active recorder, `trace.recording`) and read the
    context (`test_scope`, `strategy_scope`, `role`, `collected`). A confirmation step
    is emitted with `emit_step`, which also adds its key to the strategy run's
    `collected_steps` (reset by `strategy_scope`; `CC-CORE-0065`).
- **FR-CORE-507** *(one classification of an HTTP answer; `CC-CORE-0069`, 2026-10-20,
  BUG-0528, BUG-0529; SP-56).* `core.comparability.response_class(status, headers=None,
  *, complete, credentialed, credential_submission, redirect_to_login) -> (class,
  reason)` names an answer, first match wins:
  - **incomplete:** no status, a status of 0 or below or not an integer, or `complete`
    false;
  - **throttle-or-unavailable:** 429; 503 with or without `Retry-After` -- by policy
    (RFC 9110 §15.6.4; nginx's documented `limit_req_status` default), not by
    measurement;
  - **gateway:** 502, 504;
  - **auth-failure:** 407; a 401 or a 3xx redirect to a login page when `credentialed`
    and not `credential_submission`;
  - **policy-block:** 403, 451;
  - **application:** anything else, an uncredentialed request's or a credential
    submission's 401 or login redirect included.

  The facts are required keyword inputs (FR-SESS-22 supplies the login facts; the
  sender the credential). It is total (odd input is `incomplete`, never an exception);
  its reason names a class and a status, never a URL, header value or body; it imports
  nothing from `fuzzlab.session` or `fuzzlab.oracle`. Whether a class is admitted is the
  consumer's decision (FR-FUZZ-52, FR-FUZZ-63, FR-MUT-401). No other module compares a
  status against these classes' statuses except the reviewed allowance list in
  `tests/test_core_comparability.py::ALLOWED` (the session manager's own checks until
  defect 6's item, JWT's rejection control, the blind-SQLi payload's 504).
  - Enforced by: `tests/test_core_comparability.py` (the rule table, totality, the
    import guard and the status guard, each guard proven on a synthetic offender).
- **FR-CORE-508** *(one read-only opener; a SQLite file is touched only through
  SQLite; `CC-CORE-0071`, 2026-10-20, BUG-0535).*
  - `core.store.open_read_only(path, *, timeout, fold_on_close=False, any_thread=False)`
    is the one read-only open of a SQLite file in `fuzzlab/`: an existing file only (a
    missing one raises `sqlite3.OperationalError`; nothing is created), `cache=private`,
    `PRAGMA query_only=1`, `trusted_schema=OFF`, never a journal-mode change, a migration
    or a write; `mode=ro` by default (the main file is never written; `-wal`/`-shm` may
    be left), `mode=rw` when its last close should fold the WAL like any reader's
    (`fold_on_close`); `check_same_thread=False` only with `any_thread` (its caller then
    serialises every use). The connection is closed if its set-up fails. No other module
    builds a read-only SQLite open (`mode=ro`, `mode=rw`, `query_only`).
  - `core.store.is_sqlite(conn)` answers whether the file is SQLite, asked of SQLite
    (`PRAGMA schema_version`: `False` on `SQLITE_NOTADB`, any other error propagates); a
    0-byte file is an empty database to SQLite, so callers that refuse one check its size
    first.
  - A process that holds, or may hold, SQLite connections never opens, reads, writes or
    copies a database's main file, `-wal` or `-shm` outside SQLite: on POSIX the close of
    any descriptor of a file releases every lock the process holds on it, SQLite's WAL
    protection included (BUG-0535). `core.project.inspect` and `summary` ask SQLite
    (the refusal still reads "is not an SQLite database"); `copy_to` reads its source
    through the opener (SQLite's backup API); `harness.auto.header_point_estimate` reads
    the spider DB through it.
  - `core.project.summary` never serves a cached summary older than `SUMMARY_MAX_AGE_S`
    (2 s, `_summary_clock`): its stat key can miss a commit inside the WAL's old extent
    within one coarse mtime tick.
  - Enforced by: `tests/test_core_store_read_only.py::test_the_read_only_opener_never_creates_writes_or_migrates`, `tests/test_core_store_read_only.py::test_the_read_only_opener_pins_a_private_cache`, `tests/test_core_store_read_only.py::test_whether_a_file_is_sqlite_is_asked_of_sqlite_never_read_raw`, `tests/test_core_store_read_only.py::test_every_read_only_open_goes_through_the_opener`, `tests/test_core_store_read_only.py::test_the_read_only_open_guard_catches_synthetic_offenders`, `tests/test_web_store_locks.py::test_no_web_process_module_opens_a_store_file_except_through_sqlite`, `tests/test_web_store_locks.py::test_the_store_file_guard_catches_synthetic_offenders`, `tests/test_web_store_locks.py::test_the_store_open_audit_catches_synthetic_offenders`, `tests/test_web_store_locks.py::test_a_projects_listing_never_drops_the_in_process_proxys_store_locks`, `tests/test_web_store_locks.py::test_a_projects_listing_never_drops_a_request_readers_locks`, `tests/test_web_store_locks.py::test_opening_a_project_never_drops_a_held_connections_locks`, `tests/test_web_sitetree.py::test_the_project_listing_never_serves_a_summary_older_than_its_bound`
- **FR-CORE-500** *(one reader for a run's target; one method key; `CC-CORE-0500`,
  2026-10-15).*
  - `fuzzlab/core/runtarget.py` is the one reader of the `target` table (PA-0063(1)): a
    run's target is its **first** `target` row by id (`run_target_rows`, `run_target`),
    and its origin is that row's `base_url` through `core.urls.canonical_origin`
    (`run_origins`; `None` when the URL has no usable host or port). Every stored
    `base_url` is canonicalised through `runtarget.origin_of`, which is total: a
    malformed authority that makes `canonical_origin` raise reads `None` (BUG-0500,
    CC-CORE-0501). A run without a
    target row has no recorded target; nothing is inferred from `run.config_hash` or a
    hostname (PA-0075). Every production writer writes at most one row per run, so the
    "first row" rule changes no current output.
  - Readers: `ml/dataset.target_of` / `target_runs`, `ml/holdout._run_origins`,
    `report/report.build_report`, `web/results.run_detail` / `finding_detail`,
    `web/proxycontrol.create_from_finding`, `web/sitetree`. Enforced by
    `tests/test_core_runtarget.py::test_no_module_reads_target_rows_outside_runtarget`
    (a lint over `fuzzlab/` for upper-case `FROM target` / `JOIN target`; the shipped
    migration-19 post-step is allowlisted; proven on a synthetic offender).
  - `core.evidence.method_key(method)`: upper-case, `GET` when missing -- the one
    method normalisation for joins (PA-0076(2)), moved from `ml.dataset` (which
    re-exports it) so the web UI shares it without the ML package.

## 4. Non-functional requirements
- **NFR-CORE-single-writer** All store writes go through one writer path; readers
  never block the writer (WAL).
- **NFR-CORE-central-connection** Every process and test that opens the store
  connection directly (not via `Store`) routes through the single central
  `open_store()` constructor (WAL, `busy_timeout=10000`, `synchronous=NORMAL`,
  `foreign_keys=ON`, `trusted_schema=OFF`, connect-time `timeout=10.0`), so the
  WAL/concurrency design lives in one place. `connect()` is a backward-compatible alias
  for it. One stated exception (CC-CORE-0450): `core.project.copy_to` opens its private
  copy destination with a plain rollback-journal connection, because a WAL destination
  could leave data in a `-wal` that the hard link publishing the copy does not carry.
- **NFR-CORE-deterministic** Feature extraction is a pure function of
  (request, response, baseline); recomputable over history.
- **NFR-CORE-secrets** Secrets are referenced, never stored in the store or
  config; redaction on write.
  - Enforced by: the credential store and the storage-redaction boundary — `tests/test_credentials.py::test_set_get_delete_per_host`, `tests/test_storage_redaction.py::test_the_http_client_records_no_secret`, `tests/test_storage_redaction.py::test_every_traffic_producer_goes_through_the_redaction_boundary`, `tests/test_proxy_redaction.py::test_no_secret_reaches_any_persisted_copy`, `tests/test_session_persistence.py::test_login_persists_non_secret_state_only`, `tests/test_proxy_redaction.py::test_logs_use_the_same_predicate`
  - Enforced by (captured request bodies, forms phase 3; CC-AUD-0035): the importer's JSON producer stores every leaf through `store_adapter.redact_leaf` and passwords as `""` — `tests/test_json_points.py::test_the_json_producer_goes_through_redaction`, `tests/test_json_points.py::test_object_selectors_sensitive_and_identifier_leaves_are_pinned`, `tests/test_json_points.py::test_a_password_leaf_on_any_segment_is_isolated_sent_empty_and_never_a_point`
  - Enforced by (the crawler's captured requests and SPA route URLs, CC-CORE-0047): `redact_captured_body` / `redact_url_identifiers` / `redact_spa_fragment`, called at the spider's one write site — `tests/test_storage_redaction.py::test_the_guard_catches_a_synthetic_capture_producer`, `tests/test_storage_redaction.py::test_the_spiders_capture_writer_is_seen_by_the_guard`, `tests/test_spa_capture.py::test_a_sensitive_name_blanks_its_whole_value_keeping_the_type`, `tests/test_spa_capture.py::test_record_request_stores_no_secret_and_no_identifier`, `tests/test_spa_capture.py::test_a_spa_fragments_query_passes_the_boundary_too`, `tests/test_spa_capture.py::test_a_password_form_is_submitted_only_in_a_fresh_unauthenticated_context`
  - Not yet enforced: config accepts secret values unchecked; `repeater_tab.raw_request` and `run_plugin.config` are stored unredacted; `session_state.login_url` is not passed through `redact_url`. (BUG-0111 sweep; reported to the operator.)
- **NFR-CORE-no-bypass** No tool constructs HTTP or session state outside core.
  - Not yet enforced: the spider, the auditor, the standalone fuzzer, `RequestsProbeSender`, the greybox sender and the login fetcher build their own `requests.Session`, and the proxy uses sockets; there is no guard test. The destructive-URL gate (BUG-0111/0112) is enforced at each of them instead. (BUG-0111 sweep; reported to the operator.)

- **NFR-CORE-trace-overhead** *(CC-CORE-0063)* The trace never blocks a send on more
  than one batched SQLite transaction, and its cost is measured, not assumed
  (`scripts/measure_diagrams.py`; the figures are in CC-CORE-0063's effectiveness).
## 5. Interfaces and data contracts
Owns the store schema and migrations. Writes `run`, `schema_version`,
`request_budget`, `model`, `metric_series`, `saved_views`, (CC-CORE-0450) `project`
and `launch`, and (CC-CORE-0063, `core.trace` only) `trace_event`, `dg_entity`,
`dg_flow`, `dg_evidence`. Exposes Python APIs
consumed by every tool and ML component.

## 6. Dependencies (components)
None (foundational layer; it manages the project store).

## 7. Acceptance criteria
- A fresh database is created by the migration runner; re-running is idempotent.
- A run records its config hash; budget checkouts and the timing mutex are
  enforced.
- Golden-file feature tests pass; a feature change bumps `feature_version`.

## 8. Open questions
- Package name.
- Per-project database files plus a small global config database, versus one
  global database. *(Answered 2026-10-15, FR-CORE-400: per project directory
  (`./fuzzlab.db`, shared by the CLI and the web UI); a per-user location
  (`$XDG_DATA_HOME/fuzzlab/default.db`) is pending the owner's decision with its listed
  preconditions -- `docs/CLI_WORKING_VS_TRAINING_DESIGN.md` §4.8.)*
