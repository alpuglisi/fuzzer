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
  conflict between "records raw bytes" and NFR-CORE-secrets.
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

## 4. Non-functional requirements
- **NFR-CORE-single-writer** All store writes go through one writer path; readers
  never block the writer (WAL).
- **NFR-CORE-central-connection** Every process and test that opens the store
  connection directly (not via `Store`) routes through the single central
  `open_store()` constructor (WAL, `busy_timeout=10000`, `synchronous=NORMAL`,
  `foreign_keys=ON`, connect-time `timeout=10.0`), so the WAL/concurrency
  design lives in one place. `connect()` is a backward-compatible alias for it.
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

## 5. Interfaces and data contracts
Owns the store schema and migrations. Writes `run`, `schema_version`,
`request_budget`, `model`, `metric_series`, `saved_views`. Exposes Python APIs
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
