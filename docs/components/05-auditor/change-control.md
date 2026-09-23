# Auditor / Fetcher — Change Control Log

Component code: **AUD**. Entry format and required fields: see `../README.md`.
Newest first.

### CC-AUD-0027 — `R-PATH-TRAVERSAL` audit rule closes category 4's last known real, tracked detection gap (2026-09-23)

- Change: adds `R-PATH-TRAVERSAL`, category `path-traversal`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["query", "body"], "sink_context_in": ["fs_path_read"]}`, the same
  `location_in`+`sink_context_in` shape as `R-HEADER-INJECTION`/
  `R-INSECURE-DESERIALIZATION`/`R-UNRESTRICTED-FILE-UPLOAD`/
  `R-PRICE-INTEGRITY`. `reference` is `"directory-traversal"` — an
  existing `references/directory-traversal` catalog directory names this
  exact concern, unlike `R-HEADER-INJECTION`'s own deliberate departure
  (checked before choosing this reference, not assumed). Gated on
  `sink_context_in: ["fs_path_read"]` rather than the pre-existing
  `R-FILE-INCLUSION` rule's `name_regex` (`file|path|page|include|
  template|doc|folder|dir|load`) deliberately: `sink_context=
  "fs_path_read"` is this project's own ground-truth-schema label for
  exactly this concern (`TWCH-0011`'s own `labels.json` entry), and this
  rule's own category (`path-traversal`) and `vuln_class`
  (`path_traversal`, underscored) are both genuinely distinct from
  `R-FILE-INCLUSION`'s own category/vuln_class (`file-inclusion`, which
  matches no current ground truth and is left untouched) — the two rules
  legitimately both fire on `filename` (the `name_regex` matches
  "file" too), generating two independent candidates under two
  independent categories for the same point; this is by design, not a
  duplicate, since `PathTraversalStrategy`'s own `"file-inclusion"`
  strategy fails closed on this page (no candidate reaches it, since
  `file-inclusion` has no `_VULN_TO_CATEGORY`/ground-truth path into a
  scored automatic run today), while the new `R-PATH-TRAVERSAL`/
  `PathTraversalFsPathReadStrategy` pair is the one that actually scores.
  Checked before landing: `sink_context="fs_path_read"` is used nowhere
  else in the project (`grep -rl '"sink_context": "fs_path_read"'
  lab/ground-truth-*/labels.json` returns only Twitch's own file), so
  there is no cross-target overlap to reason about, unlike
  `R-HEADER-INJECTION`'s own `outbound_header_injection` case.
- Impact (other components / project): `AUD` primarily
  (`default_rules.json`). `FUZZ`'s `CC-FUZZ-0042` (this rule's own
  companion oracle strategy, `PathTraversalFsPathReadStrategy`) depends
  on this rule to ever receive a candidate to confirm. Closes
  `CC-LAB-0190`'s own deliberately-deferred detection follow-on for
  Twitch's `TWCH-0011` — this project's own last known real, TRACKED
  category-4 detection gap.
- Risk (level; mitigation or accepted-risk justification): Low.
  Additive-only (one new rule entry, no existing rule changed). The
  `sink_context_in` gate means this rule only ever fires for a point
  whose `sink_context` was positively typed as `"fs_path_read"` — never
  for a crawled/untyped real point with no `sink_context` at all — so it
  cannot spuriously widen candidate generation on an untyped black-box
  target. No cross-target `sink_context` overlap exists today (checked
  directly).
- Deliverables:
  - [x] `R-PATH-TRAVERSAL` rule added — done
  - [x] Cross-checked `sink_context="fs_path_read"` against every other
        `labels.json` file for an unintended overlap — none found — done
  - [x] Verified live via the real, scored multitarget pipeline
        (`tests/test_multitarget_category4.py`) — done
- Effectiveness (assessed 2026-09-23): achieved. `evaluate()` now
  nominates a real candidate for `TWCH-0011`'s `filename` param under
  category `path-traversal`, which `PathTraversalFsPathReadStrategy`
  confirms — verified against a live-booted app through the real
  `run_targets` pipeline (Twitch's own `tp` moves from 13 to 14, `fp`
  stays 0).

### CC-AUD-0026 — `R-HEADER-INJECTION` audit rule (2026-09-23)

- Change: adds `R-HEADER-INJECTION`, category `http-header-injection`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["query", "body"], "sink_context_in": ["header"]}`, the same
  `location_in`+`sink_context_in` shape as `R-INSECURE-DESERIALIZATION`/
  `R-UNRESTRICTED-FILE-UPLOAD`/`R-PRICE-INTEGRITY`. `reference` is
  `"http-response-splitting"` (no existing `references/` catalog
  directory names this concern under that exact slug — the same kind of
  deliberate departure from the "reference matches an existing catalog
  dir" default `R-PRICE-INTEGRITY`'s own entry already took, for the same
  reason: no catalog entry exists yet for this concern). Gated on
  `sink_context_in: ["header"]` rather than a `name_regex` (the shape
  `R-OPEN-REDIRECT` uses) deliberately: `sink_context="header"` is this
  project's own ground-truth-schema label for exactly this concern
  (`TWCH-0013`'s own `labels.json` entry), and a name-based regex would
  either miss this shape (a redirect-style `destination` param, already
  claimed by `R-OPEN-REDIRECT`'s own broader regex) or risk over-matching
  unrelated params project-wide for a concern that is currently
  single-instance — checked before choosing this gate: `sink_context=
  "header"` is also used by `outbound_header_injection`
  (php_laravel's HuddleHub `triggerWord`, `CC-LAB-0135`, a genuinely
  distinct OUTBOUND-request-header concern, not this one), so this rule
  DOES generate a second candidate there too under this rule's own
  category — verified this cannot cause a false positive:
  `HttpHeaderInjectionCrlfStrategy` (`CC-FUZZ-0041`) fails closed on that
  page (no response-header splice is observable for an outbound-only
  injection), and `outbound_header_injection`'s own `vuln_class` has no
  `_VULN_TO_CATEGORY` entry mapping it to `http-header-injection`, so no
  currently-automatic, ground-truth-driven run against HuddleHub ever
  includes this category in `plan.categories` to generate the candidate
  in the first place.
- Impact (other components / project): `AUD` primarily
  (`default_rules.json`). `FUZZ`'s `CC-FUZZ-0041` (this rule's own
  companion oracle strategy, `HttpHeaderInjectionCrlfStrategy`) depends on
  this rule to ever receive a candidate to confirm. Closes `CC-LAB-0198`'s
  own deliberately-deferred detection follow-on for Twitch's
  `TWCH-0013`.
- Risk (level; mitigation or accepted-risk justification): Low.
  Additive-only (one new rule entry, no existing rule changed). The
  `sink_context_in` gate means this rule only ever fires for a point whose
  `sink_context` was positively typed as `"header"` — never for a
  crawled/untyped real point with no `sink_context` at all — so it cannot
  spuriously widen candidate generation on an untyped black-box target.
  The one cross-concern overlap found during review (`outbound_header_
  injection`'s shared `sink_context` value) was checked directly, not
  assumed, and shown structurally unable to produce a false positive
  through either the strategy's own fail-closed confirm logic or the
  category's own current unreachability from that app's ground truth.
- Deliverables:
  - [x] `R-HEADER-INJECTION` rule added — done
  - [x] Cross-checked `sink_context="header"` against every other
        `labels.json` file for an unintended overlap, and verified the
        one found (`outbound_header_injection`) cannot false-positive —
        done
  - [x] Verified live via the real, scored multitarget pipeline
        (`tests/test_multitarget_category4.py`) — done
- Effectiveness (assessed 2026-09-23): achieved. `evaluate()` now
  nominates a real candidate for `TWCH-0013`'s `destination` param under
  category `http-header-injection`, which `HttpHeaderInjectionCrlfStrategy`
  confirms — verified against a live-booted app through the real
  `run_targets` pipeline (Twitch's own `tp` moves from 12 to 13, `fp`
  stays 0).

### CC-AUD-0025 — `R-PRICE-INTEGRITY` audit rule (2026-09-23)

- Change: adds `R-PRICE-INTEGRITY`, category `price-integrity-bypass`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["body"], "sink_context_in": ["payment_charge"]}`, the same
  `location_in`+`sink_context_in` shape as `R-MASS-ASSIGNMENT`/
  `R-UNRESTRICTED-FILE-UPLOAD`. `reference` is
  `"business-logic-price-manipulation"` (no existing `references/`
  catalog directory names this concern -- the same kind of deliberate
  departure from the "reference matches an existing catalog dir" default
  `CC-AUD-0023` already recorded and explained for
  `"upload-insecure-files"`, not silently assumed to exist). The
  project's first-ever candidate-generation rule for
  `price_integrity_bypass` (CWE-807) -- this vuln class now exists on two
  lab pages (`php_laravel`'s Booking.com checkout, `CC-LAB-0212`, and
  `spring_boot`'s Netflix plan-change endpoint, `CC-LAB-0188`), and had no
  rule at all before this entry, closing Netflix's own deliberately-
  deferred `NFLX-0005` structural detection zero. Paired with
  `CC-FUZZ-0037`'s new `PriceIntegrityBypassStrategy` oracle confirmation.
  **Deliberately scoped to `sink_context_in: ["payment_charge"]` only,
  not also `"sql"`** (Booking.com's own `BKNG-0003` ground truth uses
  `sink_context="sql"` there, since its own sink is a real DB insert) --
  checked and rejected during this rule's own drafting, not discovered
  after the fact: `"sql"` is already the `sink_context` for a large
  number of unrelated SQL-injection ground-truth points project-wide
  (confirmed by grep across every `lab/ground-truth-*/labels.json`), so
  including it here would have generated a spurious
  `price-integrity-bypass` candidate for essentially every SQL-sink point
  in the project -- a real false-candidate-explosion risk this narrower
  scoping avoids entirely. `R-SQLI-PARAM`'s own `when` clause has no
  `sink_context_in` filter at all, so it is unaffected either way; this
  rule simply does not attempt to also cover Booking.com's own
  `php_laravel` cell, which remains a real, deliberately-scoped, one-page
  detection gap tracked here rather than silently claimed as covered.
  Reviewed via the mandatory pre-change review gate: the `Agent` tool for
  a two-independent-reviewer pass was checked for and found unavailable
  in this session's toolset (via `ToolSearch`) -- the same substitution
  precedent `CC-LAB-0182`-`0188`/`CC-AUD-0023`/`CC-AUD-0024` already used,
  documented here rather than silently skipped. **(1) Accuracy** --
  checked by direct source inspection: confirmed `NFLX-0005`'s real
  ground-truth `sink_context` value (`"payment_charge"`) directly from
  `lab/ground-truth-netflix-clone/labels.json`, and confirmed
  `fuzzlab.harness.auto.points_from_ground_truth` genuinely propagates it
  onto the real audited `InjectionPoint` (verified by reading that
  function's own code, not assumed, the same discipline `CC-AUD-0023`
  used) -- and, in the course of that check, actually found the point
  was NOT reaching the strategy as JSON at all (see `CC-FUZZ-0037`'s own
  entry for the `param="body"` ground-truth correction this uncovered).
  **(2) Adequacy** -- checked this rule does not collide with or
  duplicate `R-MASS-ASSIGNMENT`/`R-UNRESTRICTED-FILE-UPLOAD`/any SQLi
  rule (each keys on a disjoint `sink_context_in` value, or no
  `sink_context_in` filter at all for `R-SQLI-PARAM`, so no two rules
  with a `sink_context_in` filter can ever both fire for the same
  `payment_charge` point); confirmed via a real, executed `run_targets`
  pipeline run
  (`tests/test_multitarget_category4.py::test_netflix_multi_cell_boot_confirms_all_positives`)
  that this rule actually fires for the real ground-truth point and the
  paired strategy actually confirms it, moving Netflix's own real, scored
  recall from 4/4 to 5/5 -- not assumed correct from unit tests alone.
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-15`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-UNRESTRICTED-FILE-UPLOAD`). Only
  Netflix's own ground truth currently uses `sink_context="payment_charge"`
  (Booking.com's own price-integrity cell uses `"sql"` instead, per this
  entry's own explicit, recorded scoping decision), so no other target's
  scoring changes. Paired with `CC-FUZZ-0037` (oracle) — see that entry
  for the full strategy record and the ground-truth correction it made.

### CC-AUD-0024 — `R-ACCESS-CONTROL` widened to also match `account_id` (2026-09-23)

- Change: widens `R-ACCESS-CONTROL`'s `name_regex` in `fuzzlab/audit/
  rules_data/default_rules.json` from `channel_id|resource_id|object_id|
  item_id|record_id|owner_id` to `channel_id|resource_id|object_id|
  item_id|record_id|owner_id|account_id` — one new alternative, additive
  only, nothing else about the rule changes (`method_in: ["GET"]`,
  `location_in: ["query"]`, `reference: "access-control"` all unchanged).
  Needed because `CC-LAB-0187` (Netflix's `/api/account/billing`, this
  project's first `access_control`/IDOR page on `spring_boot`) uses
  `account_id` as its query-param name — the idiomatically correct name
  for a real account-billing feature — and that name did not already
  match the rule (read and confirmed directly before widening, not
  assumed). Reviewed via the mandatory pre-change review gate: the
  `Agent` tool for a two-independent-reviewer pass was checked for and
  found unavailable in this session's toolset (via `ToolSearch`) — the
  same substitution precedent `CC-LAB-0182`-`0186`/`CC-AUD-0023` already
  used, documented here rather than silently skipped. **(1) Accuracy** —
  confirmed by direct source inspection: the pre-existing regex, read
  verbatim from the file before editing, genuinely lacked `account_id`;
  grepped every existing manifest and every ground-truth `labels.json`
  in the project for `account_id` first and found none, so this widening
  cannot silently start matching (and therefore rescoring) any
  pre-existing case. **(2) Adequacy** — checked this widening does not
  make the rule dangerously broad: `account_id` is exactly as
  specific as the six names already present (a `_id`-suffixed
  object-identifier name, not a generic token like `id` alone), and the
  rule's own `method_in`/`location_in` scoping (GET query params only)
  is unchanged, so the same bounded false-positive risk
  `AccessControlIdorStrategy`'s own docstring already documents and
  accepts is not widened in kind, only in the set of param names that
  can reach it; confirmed via a real, executed `run_targets` pipeline
  run (`tests/test_multitarget_category4.py::
  test_netflix_multi_cell_boot_confirms_all_positives`) that the widened
  rule actually fires for `NFLX-0004`'s real ground-truth point and the
  paired, already-existing `AccessControlIdorStrategy` actually confirms
  it, moving Netflix's own real, scored recall from 3/3 to 4/4 — not
  assumed correct from unit tests alone.
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/01-target-lab/requirements.md` (`FR-LAB-127`, paired
    lab-side entry)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — additive
  only (one new regex alternative on an existing rule). No other ground
  truth in the project currently uses `account_id` (grepped and
  confirmed before landing), so no other target's scoring changes.
  Paired with `CC-LAB-0187` (target lab) — see that entry for the full
  new-page record.
- Risk (level; mitigation or accepted-risk justification): **low**.
  A single-alternative regex widening on an already-scoped rule
  (`method_in`/`location_in` unchanged); confirmed to affect zero
  pre-existing cases by grep before landing, and to correctly fire for
  the one new case it targets by a real, executed pipeline run.
- Deliverables:
  - [x] Regex widened, additive-only, confirmed to affect no pre-existing
    case
  - [x] Verified live against a real booted app via
    `test_netflix_multi_cell_boot_confirms_all_positives` — recall
    `3/3` -> `4/4`
  - [x] Full non-slow suite re-verified green
  - [x] Pre-change review gate's `Agent`-tool absence flagged explicitly,
    substituted with a documented self-review (accuracy + adequacy)
- Effectiveness (assessed 2026-09-23): met — `R-ACCESS-CONTROL` now fires
  for Netflix's own `account_id`-keyed page with no other case affected,
  verified live, not assumed.

### CC-AUD-0023 — `R-UNRESTRICTED-FILE-UPLOAD` audit rule (2026-09-23)

- Change: adds `R-UNRESTRICTED-FILE-UPLOAD`, category
  `unrestricted-file-upload`, to `fuzzlab/audit/rules_data/
  default_rules.json` — `{"location_in": ["body"], "sink_context_in":
  ["fs_web_root_write"]}`, the same `location_in`+`sink_context_in` shape
  as `R-MASS-ASSIGNMENT`/`R-INSECURE-DESERIALIZATION`/`R-XXE`. `reference`
  is `"upload-insecure-files"` (the matching `references/` catalog
  directory name — `unrestricted-file-upload` itself has no catalog dir,
  so this is a genuine, deliberate departure from the "reference matches
  the category slug" convention every prior rule in this file happened to
  follow, recorded here rather than left implicit). The project's
  first-ever candidate-generation rule for `unrestricted_file_upload`
  (CWE-434) — this vuln class exists on only one lab page so far
  (Twitch's `/channels/emotes/upload`, `CC-LAB-0186`), and had no rule at
  all before this entry, closing that page's own deliberately-deferred
  `TWCH-0009` structural detection zero. Paired with `CC-FUZZ-0036`'s new
  `UnrestrictedFileUploadContentTypeTrustStrategy` oracle confirmation.
  Reviewed via the mandatory pre-change review gate: the `Agent` tool for
  a two-independent-reviewer pass was checked for and found unavailable
  in this session's toolset (via `ToolSearch`, several queries) — the
  same substitution precedent `CC-LAB-0182`-`0186` already used,
  documented here rather than silently skipped. **(1) Accuracy** —
  checked by direct source inspection of both real Go sink templates
  (`no_extension_check.go.j2`/`extension_allowlist_mime_check.go.j2`)
  before designing the rule/strategy pair, not assumed from the
  `CC-LAB-0186` change-control entry's own prose alone: confirmed both
  twins write-and-serve in the same POST response (no separate GET
  round trip exists to key detection off), confirmed `TWCH-0009`'s real
  ground-truth `param`/`location`/`sink_context` values
  (`file`/`body`/`fs_web_root_write`) directly from `lab/
  ground-truth-twitch-clone/labels.json` and confirmed
  `fuzzlab.harness.auto.points_from_ground_truth` genuinely propagates
  `sink_context` onto the real audited `InjectionPoint` (verified by
  reading that function's own code, not assumed). **(2) Adequacy** —
  checked this rule does not collide with or duplicate `R-MASS-
  ASSIGNMENT`/`R-INSECURE-DESERIALIZATION`/`R-XXE` (each keys on a
  disjoint `sink_context_in` value: `mass_assignment`/`deserialization`/
  `xml` vs. this rule's own `fs_web_root_write`, so no two rules can ever
  both fire for the same point); confirmed via a real, executed
  `run_targets` pipeline run (`tests/test_multitarget_category4.py::
  test_both_apps_run_through_multitarget_for_real`) that this rule
  actually fires for the real ground-truth point and the paired strategy
  actually confirms it, moving Twitch's own real, scored recall from 7/9
  to 8/9 — not assumed correct from unit tests alone, the same discipline
  `CC-AUD-0018`'s own `sink_context` propagation defect was originally
  caught by.
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-14`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-MASS-ASSIGNMENT`). No other
  ground truth in the project currently uses `fs_web_root_write`, so no
  other target's scoring changes. Paired with `CC-FUZZ-0036` (oracle) —
  see that entry for the full strategy record.

### CC-AUD-0022 — `R-MASS-ASSIGNMENT` audit rule (2026-09-23)

- Change: adds `R-MASS-ASSIGNMENT`, category `mass-assignment`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["body"], "sink_context_in": ["mass_assignment"]}`, the same rule
  shape as `R-INSECURE-DESERIALIZATION`/`R-XXE`. The project's first-ever
  candidate-generation rule for the `mass-assignment` category —
  `mass_assignment` lab pages already exist on three other stacks
  (`php_current`/`ruby_rails`/`php_laravel`), but none had ever had a
  rule or strategy at all before this entry, and this Twitch page
  (`CC-LAB-0182`) closes its own `TWCH-0006` structural detection zero.
  Paired with `CC-FUZZ-0035`'s new `MassAssignmentPrivilegedFieldStrategy`
  oracle confirmation. Reviewed pre-implementation per the component's
  pre-change review gate (accuracy + adequacy passes — see `CC-FUZZ-0035`
  for the full review record and the real ground-truth `param`
  convention defect the accuracy pass's real `run_targets` re-run
  caught before landing).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-13`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-WEAK-TOKEN-ENTROPY`). Also the
  first rule to ever fire for the pre-existing `php_current`/
  `ruby_rails`/`php_laravel` mass-assignment ground-truth cases
  (`FCART-0004` et al.) if/when their own targets are next run through
  the generic pipeline — those cases use a differently-shaped
  form-encoded/nested-param convention this rule still nominates
  (`location_in`/`sink_context_in` alone, no `param`-shape assumption),
  but `MassAssignmentPrivilegedFieldStrategy` itself fails closed on them
  (see that strategy's own docstring) — a candidate nominated but not yet
  confirmable elsewhere, the same honest state every other rule's
  cross-target reach already carries.
- Risk (level; mitigation or accepted-risk justification): Low. A rule
  only nominates a candidate; it cannot itself produce a false
  "confirmed" finding (that risk lives in the paired strategy, assessed
  in `CC-FUZZ-0035`).
- Deliverables:
  - [x] `R-MASS-ASSIGNMENT` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_mass_assignment_rule_matches_a_body_mass_
        assignment_point`, `test_r_mass_assignment_rule_does_not_match_a_
        query_point`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `MassAssignmentPrivilegedFieldStrategy`, the rule correctly nominates
  Twitch's real `TWCH-0006` point and is proven end-to-end against a
  real booted app — see `CC-FUZZ-0035`'s Effectiveness note.

### CC-AUD-0021 — `R-WEAK-TOKEN-ENTROPY` audit rule (2026-09-23)

- Change: adds `R-WEAK-TOKEN-ENTROPY`, category `weak-token-entropy`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"method_in":
  ["POST"], "sink_context_in": ["session_token"]}`. The project's first
  candidate-generation rule for the `weak-token-entropy` category,
  closing Twitch's `TWCH-0005` structural detection zero. Genuinely a
  new, less-constrained rule shape (no `location_in`, unlike
  `R-INSECURE-DESERIALIZATION`/`R-XXE`'s own `sink_context_in`+
  `location_in` pairing) — this class has no real tainted location to
  key off at all, so `method_in` substitutes as the available
  constraint, confirmed by the accuracy-review pass as a deliberate,
  documented departure from the established pattern, not an oversight.
  Paired with `CC-FUZZ-0034`'s new `PredictableTokenSourceStrategy`
  oracle confirmation. Reviewed pre-implementation per the component's
  pre-change review gate (accuracy + adequacy passes — see `CC-FUZZ-0034`
  for the full review record).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-12`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-JWT-ALG-NONE`).
- Risk (level; mitigation or accepted-risk justification): Low. A rule
  only nominates a candidate; it cannot itself produce a false
  "confirmed" finding (that risk lives in the paired strategy, assessed
  in `CC-FUZZ-0034`).
- Deliverables:
  - [x] `R-WEAK-TOKEN-ENTROPY` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_weak_token_entropy_rule_matches_a_post_
        session_token_point`, `test_r_weak_token_entropy_rule_does_not_
        match_a_get_point`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `PredictableTokenSourceStrategy`, the rule correctly nominates Twitch's
  real `TWCH-0005` point and is proven end-to-end against a real booted
  app — see `CC-FUZZ-0034`'s Effectiveness note.

### CC-AUD-0020 — `R-JWT-ALG-NONE` audit rule (2026-09-23)

- Change: adds `R-JWT-ALG-NONE`, category `jwt-algorithm-confusion`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"location_in":
  ["header"], "name_regex": "authorization|jwt"}`. The project's first
  candidate-generation rule for the `jwt-algorithm-confusion` category,
  closing Twitch's `TWCH-0004` structural detection zero. Scoped to
  header-location points only, mirroring `R-ACCESS-CONTROL`'s own
  location-narrowed shape — this class's own attack surface is
  inherently header-carried. `"bearer"` deliberately dropped from the
  `name_regex` during review (a header *value* prefix, not a header
  name — would have added dead/misleading weight). Paired with
  `CC-FUZZ-0033`'s new `JwtAlgNoneConfusionStrategy` oracle
  confirmation. Reviewed pre-implementation per the component's
  pre-change review gate (accuracy + adequacy passes — see `CC-FUZZ-0033`
  for the full review record, since both passes covered the rule and the
  strategy together).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-11`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-XXE`).
- Risk (level; mitigation or accepted-risk justification): Low. A rule
  only nominates a candidate; it cannot itself produce a false
  "confirmed" finding (that risk lives in the paired strategy, assessed
  in `CC-FUZZ-0033`).
- Deliverables:
  - [x] `R-JWT-ALG-NONE` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_jwt_alg_none_rule_matches_an_authorization_
        header_point`, `test_r_jwt_alg_none_rule_does_not_match_an_
        unrelated_header`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `JwtAlgNoneConfusionStrategy`, the rule correctly nominates Twitch's
  real `TWCH-0004` point and is proven end-to-end against a real booted
  app — see `CC-FUZZ-0033`'s Effectiveness note.

### CC-AUD-0019 — `R-XXE` audit rule (2026-09-23)

- Change: adds `R-XXE`, category `xxe`, to `fuzzlab/audit/rules_data/
  default_rules.json` — `{"location_in": ["body"], "sink_context_in":
  ["xml"]}`. The project's first candidate-generation rule for the `xxe`
  category, closing TrackerNest's and Netflix's shared structural
  detection zero. Second use of `sink_context_in` (after
  `R-INSECURE-DESERIALIZATION`) — same necessary shape: this class has no
  informative parameter name to key off, every whole-body point sharing
  the literal `param="body"`. Paired with `CC-FUZZ-0031`'s new
  `XxeInBandMarkerStrategy`/`XxeOobStrategy` oracle confirmation. Reviewed
  pre-implementation per the component's pre-change review gate (accuracy
  + adequacy passes — see `CC-FUZZ-0031` for the full review record).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-10`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-INSECURE-DESERIALIZATION`).
- Risk (level; mitigation or accepted-risk justification): Low-medium.
  Same explicit scope limit as `R-INSECURE-DESERIALIZATION`
  (`FR-AUD-9`): `sink_context` is currently populated only from ground
  truth (`BUG-0039`'s fix), not inferred generically by the auditor for
  an arbitrary crawled target — reachable only in the project's own
  ground-truth-scored detection-benchmark mode today.
- Deliverables:
  - [x] `R-XXE` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_xxe_rule_matches_a_body_xml_point`,
        `test_r_xxe_rule_does_not_match_an_unrelated_sink_context`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `XxeInBandMarkerStrategy`, the rule correctly nominates TrackerNest's
  real `TNEST-0002` point and is proven end-to-end against a real booted
  app, through both a dedicated live-boot test and the real generic
  ground-truth-driven multitarget pipeline — see `CC-FUZZ-0031`'s
  Effectiveness note.

### CC-AUD-0018 — `R-INSECURE-DESERIALIZATION` audit rule (2026-09-23)

- Change: adds `R-INSECURE-DESERIALIZATION`, category
  `insecure-deserialization`, to `fuzzlab/audit/rules_data/
  default_rules.json` — `{"location_in": ["body"], "sink_context_in":
  ["deserialization"]}`. The project's first rule to use the
  `sink_context_in` `when` predicate (`fuzzlab/audit/rules.py`'s own
  docstring has always listed it as supported; no prior rule exercised
  it). Necessary shape: this vulnerability class has no informative
  *parameter name* to key off (`param="body"` for a whole-body point,
  the same literal string every whole-body point of any class uses), so
  `sink_context` (what kind of sink the point actually is) is the only
  available signal, unlike every previous rule in this file. Paired with
  `CC-FUZZ-0030`'s new `InsecureDeserializationTypeConfusionStrategy`
  oracle confirmation. Reviewed pre-implementation per the component's
  pre-change review gate (accuracy + adequacy passes — see `CC-FUZZ-0030`
  for the full review record, since both passes covered the rule and the
  strategy together).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-9`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-ACCESS-CONTROL`). Being the
  first `sink_context_in` rule, it also exposed a real, previously
  dormant defect in `fuzzlab.harness.auto.points_from_ground_truth`
  (`sink_context` was never propagated onto a ground-truth-sourced
  `InjectionPoint` at all) — recorded and fixed in `CC-FUZZ-0030`, not
  duplicated here, since this rule alone cannot itself cause a false
  finding (that risk lives in the paired strategy).
- Risk (level; mitigation or accepted-risk justification): Low-medium.
  `sink_context` is currently populated only from ground truth, not
  inferred generically by the auditor for an arbitrary crawled target
  (`FR-AUD-9` states this explicitly) — this rule is reachable only in
  the project's own detection-benchmark (ground-truth-scored) mode today,
  not yet a general crawl-driven capability. Documented as a real,
  explicit scope limit rather than silently assumed to generalize.
- Deliverables:
  - [x] `R-INSECURE-DESERIALIZATION` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_insecure_deserialization_rule_matches_a_body_
        deserialization_point`,
        `test_r_insecure_deserialization_rule_does_not_match_an_
        unrelated_sink_context`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `InsecureDeserializationTypeConfusionStrategy`, the rule correctly
  nominates Netflix's real `NFLX-0001` point and is proven end-to-end
  against a real booted app, including through the real generic
  ground-truth-driven pipeline (not just a dedicated Tier1/2 test) — see
  `CC-FUZZ-0030`'s Effectiveness note.

### CC-AUD-0017 — `R-ACCESS-CONTROL` audit rule (2026-09-23)

- Change: adds `R-ACCESS-CONTROL`, category `access-control`, to
  `fuzzlab/audit/rules_data/default_rules.json` — `{"method_in": ["GET"],
  "location_in": ["query"], "name_regex": "channel_id|resource_id|
  object_id|item_id|record_id|owner_id"}`. The project's first
  candidate-generation rule for the `access_control` (IDOR/BOLA) category,
  closing the `CC-LAB-0178` open question. Narrower than `R-SSRF`'s own
  bare-`name_regex` shape by design — the adequacy pass of the paired
  `CC-FUZZ-0029` pre-change review gate flagged the originally-drafted
  bare `name_regex` (which also matched `account_id`) as a realistic
  false-positive source against a legitimate multi-account search
  feature; `method_in`/`location_in` were added and `account_id` dropped
  from the term list in response. Paired with `CC-FUZZ-0029`'s new
  `AccessControlIdorStrategy` oracle confirmation (this rule alone only
  generates a candidate; that strategy confirms it).
  Reviewed pre-implementation per the component's pre-change review gate
  (accuracy + adequacy passes — see `CC-FUZZ-0029` for the full review
  record, since both passes covered the rule and the strategy together).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-8`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (a new rule appended after `R-SSRF`, nothing else changed), so
  no existing rule's behavior is affected. Requires the paired
  `fuzzlab.core.runmode._VULN_TO_CATEGORY` fix (`CC-FUZZ-0029`) to
  actually be reachable from a ground-truth-driven run — recorded there,
  not duplicated here.
- Risk (level; mitigation or accepted-risk justification): Low. A rule
  only nominates a candidate for confirmation; it cannot itself produce a
  false "confirmed" finding (that risk lives in the paired strategy,
  assessed in `CC-FUZZ-0029`). The narrowed `method_in`/`location_in`
  scope reduces how often the rule fires on an unrelated GET/query param
  that happens to share a common id-shaped name.
- Deliverables:
  - [x] `R-ACCESS-CONTROL` added to `default_rules.json` — done
  - [x] Unit tests confirming the rule's `when` predicate matches/excludes
        as scoped (`test_r_access_control_rule_matches_a_channel_id_query_
        get_point`, `test_r_access_control_rule_does_not_match_a_body_or_
        post_point`) — done
- Effectiveness (assessed 2026-09-23): achieved. Paired with
  `AccessControlIdorStrategy`, the rule correctly nominates Twitch's real
  `TWCH-0003` point and is proven end-to-end against a real booted app
  (see `CC-FUZZ-0029`'s Effectiveness note).

### CC-AUD-0016 — `R-SSRF` audit rule (2026-09-23)

- Change: adds `R-SSRF`, category `ssrf`, to
  `fuzzlab/audit/rules_data/default_rules.json` — a bare `name_regex`-only
  rule (`url|uri|link|src|source|target|endpoint|fetch|proxy|webhook|
  image|thumbnail|avatar`), the same shape `R-OPEN-REDIRECT`/
  `R-FILE-INCLUSION`/`R-COMMAND-INJECTION` already use. The project's first
  candidate-generation rule for the `ssrf` category, closing one of the
  three "no audit rule yet" gaps `CC-LAB-0176`/`FR-LAB-99` (category 4's
  Phase E) flagged as real follow-on work. Paired with
  `CC-FUZZ-0027`'s new `SsrfInBandMarkerStrategy`/`SsrfOobStrategy`
  oracle confirmation (this rule alone only generates a candidate; those
  strategies confirm it). Overlaps `R-OPEN-REDIRECT`'s `target` term
  deliberately — `fuzzlab.audit.rules.matches()` is non-exclusive (a
  parameter can match more than one rule, each producing its own
  candidate/category), so the overlap is harmless, not a bug.
  Reviewed pre-implementation per the component's pre-change review gate
  (accuracy + adequacy passes; the adequacy pass's one addition — a cheap
  in-band confirmation layer alongside the OOB one — is reflected in the
  paired FUZZ change, not this rule itself).
  New/changed files:
  - `fuzzlab/audit/rules_data/default_rules.json`
  - `docs/components/05-auditor/requirements.md` (`FR-AUD-7`, new)
- Impact (other components / project): `default_rules.json` is shared
  across every category and every existing target's own run — purely
  additive (one new rule appended; no existing rule changed). No existing
  target's scoring changes (no existing ground truth uses the `ssrf`
  category with this rule absent, so nothing regresses).
- Risk (level; mitigation or accepted-risk justification): **low**.
  Additive-only; verified by re-running the full non-slow suite (no new
  failures) plus category 4's own real live-boot Phase E test, which now
  shows a real, confirmed SSRF finding.
- Deliverables:
  - [x] `R-SSRF` rule added, additive
  - [x] Full non-slow suite re-verified green
- Effectiveness (assessed 2026-09-23): met — `evaluate()` now emits a
  real `ssrf`-category candidate for category 4's real SSRF cell
  (`LABGEN-GO-0003`), confirmed end to end by `CC-FUZZ-0027`.

### CC-AUD-0015 — `--dry-run` CLI flag (lane D0a) (2026-09-22)
- Change: `fuzzlab/tools/fetcher.py::build_parser()` gained `--dry-run` (via the
  shared `fuzzlab/cli_dryrun.add_dry_run_flag()`). The module's `__main__` block
  checks `args.dry_run` first: if set, it calls `fuzzlab/cli_dryrun.report("audit",
  args)` — reusing the web launcher's existing dry-run plan/report logic
  (`fuzzlab/web/commandspec.spec()` + `fuzzlab/web/runner.build_argv()`/
  `display_command()`, CC-UI-0013/0015) — and exits 0 before `load_urls`/
  `load_indicators`/`ContentFetcher` run. No probe is sent. Unchanged when
  `--dry-run` is absent.
- Impact (other components / project): AUD only, plus an incidental UI effect — see
  CC-UI-0027 (the introspected `build_parser()` surfaces the new checkbox in the web
  launcher automatically; `fuzzlab/web/app.py` untouched). No schema/store change.
- Risk (level; mitigation): low — additive flag, short-circuits before any side
  effect. Mitigated by `tests/test_cli_dry_run.py` (audit cases: flag present, report
  printed, `load_urls`/`load_indicators` patched to raise if called) and the
  unchanged full suite otherwise.
- Deliverables:
  - [x] `--dry-run` on `audit`'s parser — done.
  - [x] Short-circuit in `__main__` calling the shared `cli_dryrun.report()` — done.
  - [x] Tests confirming the plan is reported and nothing runs — done.
- Effectiveness (assessed 2026-09-22): effective — `fuzzlab audit --dry-run` prints
  the planned argv/command and exits 0 without loading any DB or fetching anything;
  verified directly and via the new tests.

### CC-AUD-0014 — Expose `build_parser()` for the command-spec registry (2026-09-21)
- Change: `fuzzlab/tools/fetcher.py` now factors its argparse setup into `build_parser()`;
  `parse_args()` delegates to it. Added `prog="fuzzlab audit"` for accurate usage.
  Behavior-preserving — same flags, defaults, and parsing.
- Impact: lets the web launcher introspect the auditor's flags (CC-UI-0011). No CLI
  behavior change; no traffic; no schema change.
- Risk (level; mitigation): low — a pure refactor. Mitigated by the unchanged suite
  (433 passed / 6 skipped) and the command-spec tests.
- Deliverables:
  - [x] `build_parser()`; `parse_args()` delegates — done.
- Effectiveness (assessed 2026-09-21): effective — the registry builds the auditor's spec
  from this parser.

### CC-AUD-0013 — InjectionPoint carries stored-XSS store endpoint (2026-09-21)
- Change: `audit.InjectionPoint` gained optional `store_url`/`store_param`, and the
  engine writes them into the candidate evidence when set, so a stored-XSS observe
  point can carry the endpoint where its payload is planted (supports CC-FUZZ-0014).
- Impact (other components / project): lets the pipeline build a stored-XSS
  `Candidate`; no schema change (evidence is JSON), GET/query behavior unchanged.
- Risk (level; mitigation): low — additive fields. Covered by the auto stored-XSS
  tests. Suite 162 passed / 2 skipped.
- Deliverables:
  - [x] `store_url`/`store_param` on InjectionPoint + evidence — done.
- Effectiveness (assessed 2026-09-21): effective — the pipeline reconstructs the store
  endpoint and the oracle plants there.

### CC-AUD-0012 — R-XSS-REFLECT also nominates on `fragment` (DOM XSS) (2026-09-21)
- Change: added `fragment` to `R-XSS-REFLECT`'s `location_in`, so URL-fragment
  parameters (client-side DOM sinks, e.g. `reviews.php#author`) get an XSS candidate
  the M6 browser strategy can confirm (CC-FUZZ-0013). SQLi stays query/body (a fragment
  never reaches the server).
- Impact (other components / project): enables DOM-XSS confirmation for fragment
  points under `auto --browser`; no effect without a browser (the points aren't
  audited) or on non-fragment behavior.
- Risk (level; mitigation): low — data-only rule edit; oracle fail-closed. Covered by
  the auto browser-path test. Suite 154 passed / 2 skipped.
- Deliverables:
  - [x] `fragment` added to R-XSS-REFLECT — done.
- Effectiveness (assessed 2026-09-21): effective — fragment DOM points are nominated
  and confirmed via M6 in tests.

### CC-AUD-0011 — R-SSTI nominates on location (parity with XSS) (2026-09-21)
- Change: `R-SSTI`'s `when` changed from `sink_context_in [html]` to
  `location_in [query, body]`, so it nominates a candidate on what discovery knows
  (like `R-XSS-REFLECT`, CC-AUD-0009); the oracle's SSTI strategy (evaluation-marker)
  confirms precisely. Without this the rule was dead in automatic mode (sink_context is
  never set pre-detection — the BUG-0006 class).
- Impact (other components / project): SSTI candidates are now nominated when the SSTI
  category is active (scoped by the run plan, D14), enabling CC-FUZZ-0012's SSTI
  confirmer. No effect on the SQLi/XSS lab benchmark.
- Risk (level; mitigation): low — data-only rule edit; oracle fail-closed (no FP).
  Covered by updated `test_audit_rules`. Suite 145 passed / 2 skipped.
- Deliverables:
  - [x] R-SSTI location-based nomination — done.
- Effectiveness (assessed 2026-09-21): effective — SSTI is nominated when selected;
  the oracle confirms by evaluation marker.

### CC-AUD-0010 — Candidate evidence carries method/location (POST support) (2026-09-21)
- Change: the rules engine now records `method` and `location` in each `candidate`
  row's evidence JSON (previously only `url`/`param`), so the pipeline can reconstruct
  a POST/body candidate and the oracle can probe it over the right transport
  (supports CC-FUZZ-0011).
- Impact (other components / project): enables POST-body injection end to end; no
  schema change (evidence is JSON). GET/query behavior unchanged.
- Risk (level; mitigation): low — an additive evidence field. Covered by the existing
  audit-rules tests and the auto/pipeline POST tests. Suite 135 passed / 2 skipped.
- Deliverables:
  - [x] `method`/`location` added to candidate evidence — done.
- Effectiveness (assessed 2026-09-21): effective — the pipeline builds POST candidates
  from the evidence and the oracle probes them over POST.

### CC-AUD-0009 — R-XSS-REFLECT nominates on location, oracle confirms context (BUG-0006) (2026-09-21)
- Change: changed the `R-XSS-REFLECT` rule's `when` from `sink_context_in [...]` to
  `location_in [query, body]` (symmetric with `R-SQLI-PARAM`). `sink_context` is a
  post-detection label the pipeline's discovery upstream never sets, so the old rule
  never fired in automatic mode and no XSS candidate was ever nominated. The oracle's
  M5 strategy already types the reflection context from the response and is
  fail-closed, so nomination-on-location + oracle-confirmation is the correct division
  of labor (rules nominate on what discovery knows; the oracle decides precisely).
- Impact (other components / project): fixes BUG-0006 — automatic mode can now detect
  reflected XSS (e.g. `search.php?q`) with no false positives on escaped params
  (oracle rejects them). Broader nomination shifts negatives from non-firing rules to
  oracle-rejected candidates (see CC-FUZZ-0010). `R-SSTI` still keys on `sink_context`
  (a spec placeholder; no oracle strategy yet).
- Risk (level; mitigation): low — a data-only rule edit; the oracle remains the sole,
  fail-closed finding-writer so no FP is introduced. Mitigated by updated
  `test_audit_rules` (nomination model) and the auto/pipeline scored tests. Suite 132
  passed / 2 skipped.
- Deliverables:
  - [x] Rule predicate changed to location-based nomination — done.
  - [x] `test_audit_rules` updated to the model; no fixture hand-sets a post-detection
    label to fire a rule (PA-0006) — done.
- Effectiveness (assessed 2026-09-21): effective — XSS candidates are now nominated and
  the oracle confirms the reflected case; live tp for `search.php?q` XSS expected on
  the host run.

### CC-AUD-0008 — `known_categories()` for run-mode selection (2026-09-21)
- Change: added `audit.known_categories()` returning the sorted set of injection
  categories the rule set can test, so the run-mode resolver (CC-CORE-0007,
  D14/T2.9) can offer/validate a category selection.
- Impact (other components / project): consumed by the launcher/harness when
  building a run plan; no behavior change to the engine itself.
- Risk (level; mitigation): low — a read-only helper over the loaded rules; covered
  by the run-mode tests.
- Deliverables:
  - [x] `known_categories()` + export — done.
- Effectiveness (assessed 2026-09-21): effective — returns the rule categories used
  by the selection tests (105/105).

### CC-AUD-0007 — Rules-as-data engine + full evaluation logging (T2.3) (2026-09-21)
- Change: built `fuzzlab/audit/` — a rules-as-data engine. Rules live as JSON
  (`rules_data/default_rules.json`) with a declarative `when` predicate
  (always/location_in/method_in/sink_context_in/name_regex), loaded by `rules.py`;
  `engine.evaluate` runs every rule against every injection point and writes an
  `evaluation` row for **each** evaluation (fired and not-fired), emitting a
  `candidate` row for fired ones. Recording negatives gives a trainable dataset
  (Phase 2 exit half). An optional `categories` filter scopes active rules — the
  hook for D14/T2.9 category selection. Resolves the plan's to-confirm toward a
  dedicated `evaluation` table (negatives there; `candidate` stays the fired subset).
- Impact (other components / project): the store now holds negatives (via CORE
  migration 4, CC-CORE-0006). The rule set is editable data, not code. Wiring the
  fetcher to feed real discovered injection points (with sink-context from T2.4)
  into the engine is the next step (needs the live crawl/lab).
- Risk (level; mitigation): low–medium — a data rule language is new surface; the
  predicate set is small, safe (no code eval), and ANDed with a "no conditions =>
  never fires" guard. 4 unit tests (rules load as data; predicate matching; engine
  logs negatives + candidates with correct counts; category filter scopes rules).
- Deliverables:
  - [x] Rule schema + JSON rule set + loader (rules-as-data) — done.
  - [x] Engine: full evaluation logging (negatives) + candidate emission — done.
  - [x] Category filter hook (D14/T2.9) + 4 tests — done.
  - [ ] Wire the fetcher to feed real injection points into the engine — todo (live).
  - [ ] Port the existing 28 in-code reflection rules to data incrementally — todo.
- Effectiveness (assessed 2026-09-21): effective in unit tests — every (point, rule)
  pair is logged; negatives are present (fired=0) and candidates match fired=1;
  category filter restricts the active rules. Live fetcher wiring pending.

### CC-AUD-0006 — Target fingerprinting (algorithm) (2026-09-21)
- Change: built `core/fingerprint.py` (T2.5) — a pure, accumulative fingerprinter
  that identifies server / framework / DBMS / WAF from response headers, cookies,
  and error text (`Fingerprint.merge` accumulates over responses). Fingerprint-
  before-fuzz lets the scheduler/oracle scope payloads to the target.
- Impact (other components / project): the auditor will accumulate a fingerprint
  over its fetches and write the `target` row (dbms/framework/waf), which the
  scheduler (#8) and oracle (#7) read. The module is in `core/` (shared). Wiring it
  into the auditor's fetch loop + `target` write is the next step (needs live
  responses to validate end-to-end).
- Risk (level; mitigation): low (pure function, tested). Mis-fingerprint is
  non-fatal (payloads just aren't scoped); mitigated by first-observation-wins merge
  and signature specificity. 3 unit tests (PHP/MySQL from headers+error; framework
  from cookie; WAF + merge).
- Deliverables:
  - [x] `fingerprint.py` + tests (T2.5) — done.
  - [ ] Accumulate in the auditor loop and write the `target` row — todo (with T2.8).
- Effectiveness (assessed 2026-09-21): effective in unit tests — server/framework/
  DBMS/WAF identified from representative responses. Live wiring pending.

### CC-AUD-0005 — Authenticated Playwright audit (cookie injection) (2026-09-21)
- Change: the auditor's Playwright engine now authenticates too — `ContentFetcher`
  gained `session_manager`/`auth_base_url`, and `__enter__` injects the session
  (cookies / bearer header) into the browser context via `browserauth`. `main`
  builds the manager + seam client together (`make_auth`) and passes both. With
  this, both auditor paths (static via the seam, browser via injection) audit
  authenticated. Completes the auditor side of Option A.
- Impact (other components / project): JS-rendered pages are audited as an identity;
  depends on the session manager (#3) and credential store. No rule/output change.
- Risk (level; mitigation): low–medium — injection runs once at browser start;
  failed login fails loud. Covered by the `browserauth` unit tests; live browser
  wiring validated on a host with a browser + lab.
- Deliverables:
  - [x] `session_manager`/`auth_base_url` on ContentFetcher; `__enter__` injection — done.
  - [x] `main` builds manager + client via `make_auth` — done.
  - [ ] Live authenticated audit (browser) against the lab (T1.10) — todo.
- Effectiveness (assessed 2026-09-21): effective in unit tests (shared with the
  crawler's browser-auth path); live browser audit pending.

### CC-AUD-0004 — Auditor static fetch migrated onto the auth seam (2026-09-21)
- Change: `ContentFetcher` gained `identity`/`seam_client`; its static
  (non-browser) fetch now routes through the `core/` HTTP seam + session manager
  when an identity is given (via `fuzzlab/tools/authhttp.py`), so pages are audited
  authenticated. Added `--identity` and `--base-url` flags. The Playwright (browser)
  path is unchanged — cookie injection into the browser context is the separate,
  later sub-step. Standalone behavior is unchanged when no identity is given.
  Realizes the requests-tool half of Phase 1 T1.10 for the auditor.
- Impact (other components / project): the auditor can now reach and audit
  authenticated pages as an identity; depends on the session manager (#3) and
  credential store. No rule or output-format change; browser-rendered auditing is
  still unauthenticated until the Playwright sub-step.
- Risk (level; mitigation): low–medium — only the static path changed; standalone
  raw-requests path preserved. Mitigated by isolating the change to `_static_fetch`
  and 2 tests (authenticated static fetch attaches the cookie; standalone uses raw
  requests). Note the mixed state: static = authenticated, browser = not yet.
- Deliverables:
  - [x] `identity`/`seam_client` on ContentFetcher; `_static_fetch`; flags — done.
  - [x] Tests (authenticated static + standalone) — done.
  - [ ] Playwright path cookie injection (browser auth) — todo (next A sub-step).
  - [ ] Live authenticated audit run against the lab (T1.10) — todo.
- Effectiveness (assessed 2026-09-21): effective in tests — the static fetch is
  authenticated and returns the protected page; standalone unchanged. Browser-path
  auth and the live run pending.

### CC-AUD-0003 — Consolidates candidates into the unified store (2026-09-21)
- Change: added `--store PATH` to the auditor; after an audit it consolidates its
  native `findings` into the unified store via `store_adapter.import_audit`,
  writing `candidate` rows (rule = transaction type, evidence JSON incl. category/
  reference/occurrences, sink_context from the HTML context) and linking to a
  discovered `parameter` when one matches. It first imports the spider DB so
  candidates can link to parameters. Native output unchanged without `--store`.
  Phase 0 T0.8.
- Impact (other components / project): candidates now land on the integration bus
  for the scheduler/fuzzer/ranker; depends on the crawler having populated
  parameters (CC-CRAWL-0003) for linkage.
- Risk (level; mitigation): low — opt-in, additive; covered by the consolidation
  test (synthetic audit DB → candidate rows).
- Deliverables:
  - [x] `--store` + `import_audit` (candidate rows, param linkage) (T0.8) — done.
  - [ ] Full per-rule evaluation evidence + versioned features (Phase 2) — todo.
- Effectiveness (assessed 2026-09-21): effective — synthetic findings become
  candidate rows in the unified store (test green).

### CC-AUD-0002 — Moved into the `fuzzlab` package (2026-09-21)
- Change: `fetcher.py` moved to `fuzzlab/tools/fetcher.py`; imports `core/`
  (`get_logger`, structured startup line) and now defaults `--indicator-db` to the
  packaged `php_indicators.db` (via `fuzzlab.tools.paths`) so it runs from
  anywhere. Still writes its own SQLite file (T0.8 migrates it). Phase 0 T0.1.
- Impact (other components / project): the auditor is now a package module and
  resolves its indicator DB from the package rather than the working directory;
  depends on the IND component's packaged data path (CC-IND-0002). No rule or
  output-format change.
- Risk (level; mitigation): low — move + path default + one import; verified the
  module imports, `--help` shows the packaged default, and the indicator DB loads.
- Deliverables:
  - [x] Move into package; import `core/`; packaged indicator-db default (T0.1) — done.
  - [ ] Write candidates to the shared store (T0.8) — todo.
- Effectiveness (assessed 2026-09-21): effective — runs as a package module with
  the packaged indicator DB resolved automatically.

### CC-AUD-0001 — Baseline (2026-09-21)
- Change: record the component at its current state — `fetcher.py` renders dynamic
  content, evaluates 28 injection-point rules against discovered parameters, probes
  canary reflection, and emits candidates. Standalone; not yet on the shared store,
  session manager, or ranker.
- Impact (other components / project): produces the candidate queue the scheduler
  and fuzzer consume; depends on the indicator DB for its rule/indicator data.
  Currently writes its own output rather than the shared `candidate` table, and
  rules are in code rather than data.
- Risk (level; mitigation): low–medium. Rules-in-code and no shared store limit
  reuse and explainability; mitigated by the Phase 0 store migration and the
  Phase 2 move to rules-as-data with full per-rule evaluation logging. No current
  risk to other components beyond output format.
- Deliverables:
  - [x] 28-rule evaluation over dynamic + static content — done.
  - [x] Canary reflection probing — done.
  - [ ] Full per-rule evaluation logging (fired + not-fired) — todo (Phase 2).
  - [ ] Rules-as-data registry — todo (Phase 2).
  - [ ] Sink-context typing of reflections — todo (Phase 2).
  - [ ] Target fingerprinting (DBMS/framework/WAF) — todo (Phase 2).
  - [ ] Migrate to the shared store + versioned features — todo (Phase 0 T0.8).
  - [ ] Session-manager integration — todo (Phase 1).
- Effectiveness (assessed or pending): effective at emitting candidates from the
  lab's injection points with the 28 rules active; explainability and store
  integration pending.
