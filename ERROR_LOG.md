# Error log

A record of identified errors (bugs, deployment failures, environment issues) and
**how they were remediated**. Newest entries at the top. Add an entry whenever
something breaks and is fixed, so the same problem is easy to recognize and
resolve next time.

A **code** defect also needs a full bug report (`docs/bugs/BUG-NNNN-*.md`) and one or
more preventive-action rules (`docs/PREVENTIVE_ACTIONS.md`) — this log alone is not
enough. See `CLAUDE.md` for the full change process.

Format per entry:
- **Date / component**
- **Symptom:** what was observed
- **Root cause:** why it happened
- **Remediation:** what fixed it
- **Status:** Fixed / Open / Environment (fixed outside the repo)

---

## 2026-09-25 — LAB: `spring_boot` (ReelQueue) POST routes crashed on a bare POST — PA-0054's GET-only sweep never exercised them (fixed, BUG-0054/PA-0056)

- **Symptom:** a bare `POST` (no multipart part / no query string) of
  `/api/profiles/avatar` answered 500 on both twins; `/api/content/thumbnail-import`
  answered 502 on the vulnerable twin -- reproduced live against the
  pre-change emitter; ReelQueue's new nav/client pages would have led
  straight to them.
- **Root cause:** neither route's source guarded against its required input
  (a multipart part, a query parameter) being absent, so the servlet API
  (`getPart`) or the SSRF sink ran anyway; `PA-0054`'s only mechanical
  enforcement is a bare-`GET` sweep, and Spring answers a bare `GET` on a
  POST-only route with its own framework-level 405 before the handler ever
  runs, so the sweep never reached the crash path.
- **Remediation:** every `spring_boot` route now declares one of 7
  absent-input kinds (`required_multipart`/`required_param`/etc.), rendered
  before any sink; a new own-method bare-request sweep
  (`tests/test_labgen_spring_boot_absent_input_live_boot.py`) sends each
  route's own declared method, not only `GET`.
- **Status:** Fixed (16/16 routes declared and passing on both twins). See
  `docs/bugs/BUG-0054-*.md` and `PA-0056`.

## 2026-09-25 — LAB: `django` (PicTrail) routes 500'd on a bare GET — absent query parameter reached the sink as None (fixed, BUG-0052/PA-0054)

- **Symptom:** a bare `GET` (no query string) of `/post`, `/explore`,
  `/upload/link-preview` (both twins) and the illustrative
  `/generated/labgen_dj_0001/` returned HTTP 500 -- reproduced live against
  the pre-change emitter; the new PicTrail nav/catalog would have linked
  straight to them.
- **Root cause:** the `django` `get_param` source had no default or
  required-parameter guard, so `None` reached the sink (`str(None)` -> `WHERE
  id = None` / `ORDER BY None`; `requests.get(None)`); PA-0053's only
  enforcement is a link-reachability crawl, which never ran on the unlinked
  `django` build (BUG-0051's sweep deferred it).
- **Remediation:** `CC-LAB-0242`: `default_value` (`/post`, `/api/products`
  = `"1"`, `/explore` = `"id"`) and `required_param` (`/upload/link-preview`
  -> handled 400) route-profile keys; `/settings`/`/inbox` render their form
  on GET; an offline declaration check and a live bare-GET sweep of every
  served route (`docs/bugs/BUG-0052-...md`, `PA-0054`).
- **Status:** Fixed.

## 2026-09-25 — LAB: `php_laravel` nav/catalog links 500'd on a bare GET — absent query parameter reached the sink as null (fixed, BUG-0051/PA-0053)

- **Symptom:** clicking the Puppy Fort Factory nav's "Product"/"Blog" links
  (`/product.php`, `/blog_post.php`, no `?id=`) returned HTTP 500; the new
  navigability crawl also found `/booking/continue` 500ing and
  `/comments/share` sending an empty `Location:` redirect when reached bare
  from `/catalog`.
- **Root cause:** `get_param.php.j2` rendered `$request->query('<param>')`
  with no default and page profiles had no way to declare one, so `null` hit
  sinks only correct for a present value (`... WHERE id = ` invalid SQL;
  `redirect(null)`); no test ever requested a generated page bare. Recurrence
  of `BUG-0037`'s class, which `PA-0039` scoped too narrowly (cross-language
  ports, type cast only).
- **Remediation:** `CC-LAB-0241` — per-profile `default_value` key (`'1'` on
  product/blog_post, the real pages' own `?? '1'`; `'/'` on the two redirect
  pages), bare-URL live-boot assertions (SQLite + MariaDB), and the
  navigability crawl as the standing check (PA-0053). Huddle Hub's
  `/messages/unfurl` bare-GET 500 and the illustrative `/cell/labgen-pl-*`
  bare-GET 500s are flagged follow-ups (BUG-0051's sweep section).
- **Status:** Fixed (4 instances); 1 ground-truth instance open as a flagged
  follow-up, pinned by a strict xfail.

## 2026-09-24 — CRAWL: crawler followed only loopback links; grabbed nothing on authorized external hosts (fixed, BUG-0050/PA-0052)

- **Symptom:** operator pointed `fuzzlab crawl` (via the web UI) at authorized
  live hosts; it fetched the start page but followed no links ("Crawled 1
  page(s)"), on any real site.
- **Root cause:** `LocalSpider._is_local` hardcoded the follow filter to
  `hostname in {localhost, 127.0.0.1}`, so every link on a non-loopback target
  was dropped. The lab-only guard was expressed as a fixed loopback allowlist
  instead of "the operator-configured target's host."
- **Remediation:** replaced it with `_in_scope`, scoped to the start URL's host
  (loopback aliases + `www.` normalised; third-party/other-subdomain links still
  not followed). Added `tests/test_spider_scope.py`; verified end-to-end on both
  engines. BUG-0050, PA-0052, CC-CRAWL-0008, FR-CRAWL-7.
- **Status:** Fixed.

## 2026-09-24 — host lab image would not build: btrfs ENOSPC + missing `composer:2` image (Environment)

- **Symptom:** first on-host `lab/labctl.sh up` failed with podman "no space
  left on device" (even a metadata rename failed) though `df` showed ~8 GB free;
  after freeing space, the build failed `COPY --from=composer:2 ... no stage or
  image found with that name`.
- **Root cause:** (a) the host root fs is **btrfs** with **0 unallocated space**
  (all 242 GiB allocated into block groups), so no new metadata chunk could be
  allocated — the "free" space was inside a full data block group; (b) the
  `composer:2` image the Dockerfile's `COPY --from` references was not present
  locally and podman-compose/buildah did not auto-pull it. Environment/infra, not
  a fuzzlab code defect.
- **Remediation:** `btrfs balance start -dusage=…,limit=…` to return ~4 GiB of
  partially-empty data chunks to unallocated (so metadata could grow), plus a
  narrow `podman image prune -f` (dangling layers only — the user's 234 GB of
  personal data was left untouched); then `podman pull docker.io/library/
  composer:2` so `COPY --from` resolves locally.
- **Status:** Environment (fixed outside the repo).

## 2026-09-24 — LAB: from-scratch lab image build failed — skeleton `composer.lock` locked PHP-8.4-only Symfony 8.1 on a `php:8.3` base (fixed, BUG-0047/PA-0049)

- **Symptom:** `composer install` in `web.Dockerfile` failed with ~17
  "requires php >=8.4.1 -> your php version (8.3.33) does not satisfy" errors.
- **Root cause:** the skeleton `composer.json` had no `config.platform.php` pin
  (its sibling `stack/composer.json` did), so its `composer.lock` had been
  regenerated on a PHP-8.4 host and resolved to Symfony 8.1 (PHP ≥ 8.4.1),
  incompatible with the D7-pinned `php:8.3` runtime.
- **Remediation:** added `"platform": {"php": "8.3.33"}` to the skeleton
  `composer.json` and regenerated `composer.lock` against it (Symfony → 7.4.19).
  Lab now builds + serves. BUG-0047, PA-0049, CC-LAB-0234.
- **Status:** Fixed.

## 2026-09-24 — LAB: on-host e2e scripts declared a healthy lab "not reachable" (fixed, BUG-0048/PA-0050)

- **Symptom:** `greybox_e2e.sh` (and latently `proxy_e2e.sh`,
  `waf_evasion_e2e.sh`) aborted at their readiness gate — "lab did not become
  reachable at http://127.0.0.1:8080/" — though the lab was serving.
- **Root cause:** the readiness probe `curl -fs "${BASE}/"` treats the generated
  Laravel app's (correct) 404 on `/` as failure; the app has no homepage route
  since the `L-P3.3c-CUT` cutover.
- **Remediation:** probe `"${BASE}/product.php?id=1"` (a served endpoint, also
  confirms DB) in all three scripts; swept `scripts/` for other bare-`/` probes.
  BUG-0048, PA-0050, CC-LAB-0235.
- **Status:** Fixed.

## 2026-09-24 — LAB: grey-box `db_fault` never fired; Laravel routing pipeline swallowed the controller `QueryException` (fixed, BUG-0049/PA-0051)

- **Symptom:** error-based SQLi on `login.php` returned 500 with a real SQL
  error, but the `FzlCoverage` side-channel file always had `db_fault=false`;
  `greybox_e2e.sh`'s self-test failed. Phase 3 T3.7 exit unmeetable.
- **Root cause:** `FzlCoverage` caught a `QueryException` *propagating out of
  `$next()`*, but Laravel's `Illuminate\Routing\Pipeline` catches+renders a
  controller exception at the router-dispatch boundary, so it never propagates
  back to the middleware's `catch` — a mechanism ported from raw-PHP semantics
  that Laravel does not share.
- **Remediation:** capture the `QueryException` via a
  `withExceptions(...)->report(...)` hook into a request-scoped static the
  middleware reads after `$next()`; kept a belt-and-suspenders catch. Verified
  live (fault ⇒ db_fault=1, benign ⇒ 0); Part E passes T3.7. BUG-0049, PA-0051,
  CC-LAB-0236.
- **Status:** Fixed.

## 2026-09-24 — `cwe.mitre.org` unreachable through this environment's egress proxy during PA-0033 CWE-migration research (Environment)

- **Symptom:** while migrating `docs/research/corpus-examples/*/manifest.yaml`
  entries to the `cwe_shared`/`cwe_unique`/`cwe_rationale` schema
  (`docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` Step 6, enforced by
  `.claude/hooks/check-corpus-cwe-coverage.sh`), both `curl` and `WebFetch`
  against `https://cwe.mitre.org/data/index.html` returned a block
  (EGRESS_BLOCKED/403) rather than the MITRE CWE index content the standard
  calls for looking up live.
- **Root cause:** this sandbox's outbound-egress proxy does not allow
  `cwe.mitre.org` — an environment/network restriction, not a defect in any
  fuzzlab code path. Not a code defect, so the full `docs/bugs/` RCA protocol
  does not apply (per CLAUDE.md's own scoping: that protocol is for code
  defects); this entry exists because it is exactly the "deploy/env failure"
  class this log is for.
- **Remediation:** CWE research for the affected entries was done from
  trained knowledge instead of a live MITRE lookup, with that fact recorded
  plainly in each touched entry's own note/comment (per this corpus's
  existing "not silently" honesty convention) rather than fabricating a
  citation or silently treating trained-knowledge recall as equivalent to a
  verified lookup. Every migrated entry's `cwe_rationale` should be
  spot-checked against the real MITRE index by a session with that access
  before being treated as fully authoritative — flagged here so that
  follow-up isn't lost.
- **Status:** Environment (fixed outside the repo — a session with working
  egress to `cwe.mitre.org` can re-verify; no code change possible or needed
  here).

## 2026-09-23 — `RequestsProbeSender` followed redirects into an attacker-controlled canary host (fixed, BUG-0039/PA-0041)

- **Symptom:** live-verifying category 5's `open_redirect` → `_VULN_TO_CATEGORY`
  mapping before landing it, a real `OpenRedirectStrategy.confirm()` call
  against Booking.com's real vulnerable twin raised an uncaught
  `requests.exceptions.ProxyError` instead of returning a confirmed `Verdict`.
- **Root cause:** `RequestsProbeSender.send()` never set `allow_redirects=False`
  (unlike `fuzzlab.core.http`'s own authenticated client, which already does),
  so `requests` tried to follow the strategy's own canary redirect target —
  an attacker-controlled host this sandbox's egress proxy correctly refuses.
  No prior category's ground truth included a redirect-based sink, so no
  real confirmation run had ever exercised this path before.
- **Remediation:** added `allow_redirects=False` to `RequestsProbeSender.send()`,
  matching `fuzzlab.core.http`'s own client. `tests/test_probesender.py`
  updated to assert it.
- **Status:** Fixed. See `docs/bugs/BUG-0039-*.md`.

## 2026-09-23 — `OpenRedirectStrategy.vuln_class` was hyphenated, mismatching ground truth's underscored spelling (fixed, BUG-0040/PA-0042)

- **Symptom:** after fixing `BUG-0039`, the same real confirmation now
  returned a correct `Verdict`, but `fuzzlab.harness.multitarget.run_targets`'s
  own scoring against real `lab/ground-truth-booking-clone/` ground truth
  recorded the confirmed finding as a false positive (`tp=0, fp=1`), not a hit.
- **Root cause:** `OpenRedirectStrategy.vuln_class = "open-redirect"`
  (hyphenated, matching this strategy's own `category` attribute) never
  matched ground truth's `"open_redirect"` (underscored, this project's
  established `vuln_class` convention for this class, which every sibling
  strategy already follows correctly) — `fuzzlab.harness.scoring.score()`'s
  exact-key match therefore never linked the two. Latent since this
  strategy was first authored; no `open_redirect` ground truth existed
  anywhere in this project to catch the mismatch until now.
- **Remediation:** `OpenRedirectStrategy.vuln_class` corrected to
  `"open_redirect"` (`category` left unchanged, a separate, correctly-
  hyphenated namespace). Re-verified live: `tp=1, fn=2, fp=0`.
- **Status:** Fixed. See `docs/bugs/BUG-0040-*.md`.

---

## 2026-09-23 — FUZZ: `points_from_ground_truth` collapsed two cases sharing a point's `sink_context` (fixed, BUG-0046/PA-0048)

- **Symptom:** building `CC-FUZZ-0045`'s `R-HEADER-INJECTION`/
  `HttpHeaderInjectionCrlfStrategy` (closing category 4's last known real
  detection gap, `http_header_injection` at Twitch's `TWCH-0013`) showed
  the case still scoring as a missed (false negative) finding in a real
  `run_targets` pipeline run, despite the strategy confirming the
  identical candidate directly via a hand-built `Candidate`.
- **Root cause:** `fuzzlab/harness/auto.py::points_from_ground_truth`'s
  `sink_context_by_point` dict comprehension kept only the LAST
  ground-truth case's `sink_context` for a given `(url, method, param)`
  key — `TWCH-0015` (`sink_context="redirect"`, added by `BUG-0045`'s own
  fix) silently overwrote `TWCH-0013`'s own `sink_context="header"` at
  their shared sink, so `R-HEADER-INJECTION`'s `sink_context_in:
  ["header"]` gate never matched that point.
- **Remediation:** `sink_context_by_point` now collects every DISTINCT
  `sink_context` value per point (a `set`) and emits one audited
  `InjectionPoint` per distinct value, verified harmless against
  `fuzzlab.harness.scoring.score`'s own set-based, vuln_class-keyed
  dedup. `tp` for Twitch's real, scored pipeline run moves from 12 to 13
  (recall `12/15` -> `13/15`).
- **Status:** Fixed.

## 2026-09-23 — `open_redirect` silently unreachable in a scored pipeline: missing category mapping, then a wrongly-hyphenated strategy `vuln_class` (fixed, BUG-0045/PA-0047)

- **Symptom:** wiring `CC-LAB-0199`'s new `open_redirect` Twitch cell
  (`/auth/login-redirect?next=`) into `tests/test_multitarget_
  category4.py`'s real, full `run_targets` pipeline showed the new case,
  `TWCH-0014`, as a missed (false negative) finding, despite
  `fuzzlab.oracle.strategies.OpenRedirectStrategy` (already built)
  confirming the identical URL/param directly via a hand-built
  `Candidate` moments earlier. After fixing the reachability gap, the
  same case then scored as a false-positive/false-negative pair instead
  of a true positive.
- **Root cause:** two independent, pre-existing defects. (1)
  `fuzzlab.core.runmode._VULN_TO_CATEGORY` had no `"open_redirect":
  "open-redirect"` entry, so `to_category("open_redirect")` returned it
  unchanged and the real `R-OPEN-REDIRECT` rule's category
  (`"open-redirect"`) never entered `plan.categories` — the underscore/
  hyphen category-mismatch class this project has hit repeatedly, this
  time NOT caught by the existing generic guard test
  (`test_every_ruled_strategy_category_is_reachable_from_its_vuln_class`),
  because that guard only checks the oracle's own internal
  `_CATEGORY_TO_CLASS` dict for self-consistency, not real ground truth.
  (2) `OpenRedirectStrategy.vuln_class` was itself wrongly hyphenated
  (`"open-redirect"`, copied from its own `category` field) instead of
  underscored like every other strategy's `vuln_class` in the file —
  `fuzzlab.harness.scoring.score`'s exact `(url, method, param,
  vuln_class)` key match never matched ground truth's own underscored
  `"open_redirect"`, even once (1) was fixed. Fixing (2) also surfaced a
  third, genuine (not a bug) finding: `CC-LAB-0198`'s own existing page
  is independently, honestly open-redirect-vulnerable too (verified
  live), closed by adding a second, honest ground-truth case (`TWCH-0015`)
  at that same url/param rather than routed around.
- **Remediation:** added the missing `_VULN_TO_CATEGORY` entry; corrected
  `OpenRedirectStrategy.vuln_class` to `"open_redirect"` (and
  `_CATEGORY_TO_CLASS` to match); added a second, stronger guard test
  (`tests/test_oracle.py::
  test_ground_truth_vuln_classes_with_a_ruled_hyphenated_twin_are_mapped`)
  that checks every real `lab/ground-truth*/labels.json` file directly
  instead of the oracle's own internal dict; added `TWCH-0015`. Re-
  verified against real booted apps: `test_both_apps_run_through_
  multitarget_for_real` now scores Twitch `tp=12, fp=0` (was `tp=10` with
  both new cases missed before either fix, then `tp=10, fp=2` after fix 1
  alone).
- **Status:** Fixed (BUG-0045/PA-0047 — see `docs/bugs/BUG-0045-open-
  redirect-category-mapping-and-strategy-vuln-class-spelling.md`; this is
  the same underscore/hyphen mismatch class `runmode.py`'s own comment
  already documents finding repeatedly, but the FIRST instance the
  existing generic guard test failed to catch, since it checks internal
  consistency rather than real ground truth).

## 2026-09-23 — the oracle's own `RequestsProbeSender`/`RequestsCorrelatingSender` silently followed HTTP redirects (fixed, BUG-0044/PA-0046)

- **Symptom:** wiring `CC-LAB-0198`'s new `http_header_injection` Twitch
  cell (`/channels/redirect`, echoes a caller-supplied `destination` query
  param into a real `Location:` response header) into
  `tests/test_multitarget_category4.py`'s real, full `run_targets`
  pipeline crashed with `requests.exceptions.TooManyRedirects: Exceeded 30
  redirects.` The generic `SstiStrategy`'s own `#{a*b}` payload, echoed
  into `Location: #{a*b}`, resolves (as a URL *fragment*, never sent to
  the server) to the SAME url on every redirect hop — an infinite
  self-redirect loop `requests` followed by default.
- **Root cause:** `fuzzlab.tools.probesender.RequestsProbeSender.send()`
  (and, found by the same sweep, `fuzzlab.greybox.run.
  RequestsCorrelatingSender.send_correlated()` and `fuzzlab.tools.
  blind_sqli_fuzzer.RequestsSender.get()`) called `requests`' own
  `.request()`/`.get()` with no `allow_redirects` override, so `requests`'
  library default (`True`) silently applied — following any redirect
  a real target issues and reporting the FOLLOWED chain's final response
  to a `ConfirmationStrategy` that needs the ORIGINAL, un-followed
  response (`OpenRedirectStrategy` reads `Location:` off exactly that
  first response). `fuzzlab.core.http`'s own authenticated path already
  set `allow_redirects=False` for this reason — the unauthenticated
  senders never received the same fix.
- **Remediation:** added `allow_redirects=False` to all three senders;
  updated their fake-session test doubles
  (`tests/test_probesender.py`/`tests/test_fuzzer_seam.py`) to accept and
  record the kwarg, and added a regression test asserting it is actually
  passed. Re-verified against a real booted app:
  `test_both_apps_run_through_multitarget_for_real` reproducibly crashed
  before the fix and reproducibly passes after it.
- **Status:** Fixed (BUG-0044/PA-0046 — see `docs/bugs/BUG-0044-oracle-
  probe-senders-silently-followed-redirects.md`; strengthens `PA-0030`
  from `BUG-0028`, which named the same root-cause class but scoped it to
  conformance harnesses only, not every sender feeding the oracle).

---

## 2026-09-23 — PA-0042's own fix missed a second hardcoded recall assertion in the same test file (fixed, BUG-0043/PA-0045)

- **Symptom:** `CC-LAB-0197` (Netflix's 11th real page, an `ssti` instance)
  added `NFLX-0011` to `lab/ground-truth-netflix-clone/` and, per `PA-0042`,
  re-derived and re-ran `tests/test_multitarget_category4.py`'s hardcoded
  recall assertions before committing and pushing. An independent
  re-verification pass afterward found
  `test_both_apps_run_through_multitarget_for_real`'s own hardcoded
  `netflix_report.recall == round(1/10, 4)` assertion still stale
  (`1/11` was correct) — a second, separate hardcoded fraction for the
  same target in the *same file* `CC-LAB-0197`'s own PA-0042 pass had
  just run, sitting in a different test function
  (`test_netflix_multi_cell_boot_confirms_all_positives`'s own sibling
  assertion, in the same file, was correctly updated).
- **Root cause:** `PA-0042` instructs re-running every FILE a grep for
  hardcoded fractions surfaces, but does not say a file can contain more
  than one independent hardcoded fraction for the same target (a
  single-cell test and a multi-cell test each keep their own separate
  assertion) — an agent that finds and fixes one occurrence in a file,
  then re-runs that file and sees it pass, can reasonably (but wrongly)
  conclude the file is "handled," when a second occurrence elsewhere in
  the same file was never located because the grep or manual scan
  stopped at the first match rather than confirming every match.
- **Remediation:** corrected the stale `1/10` -> `1/11` assertion (and
  its own paired `macro_recall` assertion) in the same commit-adjacent
  fix, re-verified by re-running `test_multitarget_category4.py`,
  `test_auto.py`, and `test_labels_contract_category4.py` together (21
  passed). See
  `docs/bugs/BUG-0043-pa-0042-fix-missed-a-second-hardcoded-assertion-in-the-same-file.md`.
- **Status:** Fixed.

## 2026-09-23 — Adding a ground-truth case silently broke two already-pushed, slow-marked recall assertions (fixed, BUG-0040/PA-0042)

- **Symptom:** `CC-LAB-0188` (Netflix's `price_integrity_bypass` lab page)
  added `NFLX-0005` to `lab/ground-truth-netflix-clone/` and was committed
  and pushed after a green `pytest -q -m "not slow"` run. Building that
  page's detection follow-on (`CC-FUZZ-0041`) then found two pre-existing
  tests in `tests/test_multitarget_category4.py` — both under a
  module-level `pytestmark = [pytest.mark.slow, ...]`, so excluded from
  every "not slow" run this whole session used as its own completion
  bar — now failing: `test_both_apps_run_through_multitarget_for_real`'s
  hardcoded `1/4` Netflix recall assertion and
  `test_netflix_multi_cell_boot_confirms_all_positives`'s hardcoded `4/4`
  assertion, both stale the moment Netflix's own total ground-truth case
  count grew from 4 to 5.
- **Root cause:** adding a ground-truth case changes the denominator/count
  two pre-existing, unrelated-looking test files' hardcoded recall
  assertions depend on, but those two tests live in a file marked
  `pytest.mark.slow` at module level, so this session's routine
  `pytest -q -m "not slow"` pre-push check — treated as sufficient
  throughout this entire build — structurally cannot see them break.
  `CC-LAB-0188`'s own commit touched only the lab page and ground truth,
  never `test_multitarget_category4.py` itself, so nothing in that
  commit's own diff would have prompted running it either.
- **Remediation:** corrected `NFLX-0005`'s own ground-truth `param` to the
  project's real whole-body-JSON convention (`"body"`, not the per-field
  `"monthly_charge"` `CC-LAB-0188` originally shipped — itself found the
  same way, via a real end-to-end `points_from_ground_truth` check) and
  updated both stale assertions (`1/4`→`1/5`, `4/4`→`5/5` before the new
  cell's own detection, then →`5/5` again including it) in the same
  `CC-FUZZ-0041` commit that also closed the detection gap. See
  `docs/bugs/BUG-0040-slow-marked-recall-assertions-silently-broken-by-a-ground-truth-only-change.md`.
- **Status:** Fixed.

## 2026-09-23 — `points_from_ground_truth` never propagated `sink_context`, silently defeating the first rule ever keyed on it (fixed, BUG-0039/PA-0041)

- **Symptom:** building real detection for `insecure_deserialization`
  (`R-INSECURE-DESERIALIZATION`, keyed on `sink_context_in=
  ["deserialization"]` — the project's first rule to use that predicate),
  `test_multitarget_category4.py`'s real, executed live-boot run against
  Netflix kept showing `netflix_report.tp == 0` despite a real, unit-tested
  working rule+strategy pair. Unit tests (which hand-construct a
  `Candidate`/`InjectionPoint` with `sink_context` set directly) all
  passed; only the real end-to-end run through
  `fuzzlab.harness.auto.points_from_ground_truth` exposed the gap.
- **Root cause:** `points_from_ground_truth` builds a
  `fuzzlab.audit.InjectionPoint` from each of the ground truth's
  enumerated *points* (`injection-points.json`,
  `fuzzlab.labels.contract.InjectionPoint`) — a deliberately slim shape
  that carries no `sink_context` field at all. `sink_context` instead
  lives on the ground truth's scoring `Case` (`labels.json`), and nothing
  in `points_from_ground_truth` ever bridged the two: the constructed
  audit `InjectionPoint` simply never set `sink_context`, defaulting to
  `None`, for every ground-truth-sourced point, project-wide, since this
  function was first written. This caused no observed wrong behavior
  until now because no rule had ever used the `sink_context_in` predicate
  before `R-INSECURE-DESERIALIZATION` — a real, silent, already-shipped
  gap that simply had no consumer to expose it.
- **Remediation:** `points_from_ground_truth` now builds a
  `(url, method, param) -> sink_context` lookup from `ground_truth.cases`
  and threads the matching case's `sink_context` onto each constructed
  `InjectionPoint`. Pinned by
  `tests/test_auto.py::test_points_from_ground_truth_carries_sink_context_from_the_matching_case`.
  Re-verified end to end: `test_multitarget_category4.py`'s real run now
  shows `netflix_report.tp == 1`.
- **Status:** Fixed.

## 2026-09-23 — `ruby_rails` skeleton's unpinned `json` gem 500'd every second request in a session (fixed, BUG-0035/PA-0037)

- **Symptom:** building the Phase D whole-app conformance test and the Phase
  E `multitarget.py` wiring test for category 1's "ForgeCart" (Shopify/
  `ruby_rails`) app, the real `/search` reflected-XSS page's second HTTP
  probe (the ordinary marker-then-breakout round trip
  `fuzzlab.oracle.strategies.ReflectedXssStrategy.confirm` performs) 500'd —
  `ActionView::Template::Error` wrapping `ArgumentError: wrong number of
  arguments (given 2, expected 1)`. Reproducible on the *second* real
  request of *any* session, against *any* route, including the app's own
  inert static pages — not specific to `/search` or to this app's own new
  code.
- **Root cause:** the checked-in skeleton's `Gemfile` never pinned the
  `json` gem; `activesupport` 8.1.3.1's own gemspec declares only `json >=
  0`, so an unconstrained `bundle install` resolved `json 3.0.2`, whose 3.x
  line made `JSON.parse`'s options parameter keyword-only — but
  `ActiveSupport::JSON.decode` still calls `::JSON.parse(json, options)`
  positionally, which every encrypted session-cookie read goes through.
  Every prior `ruby_rails` live-boot test (Phase A/B) sent exactly one
  request per booted instance, so this 100%-reproducible defect (it only
  fires on a request that *presents* an already-set session cookie, never
  the request that creates one) shipped latent through two full build
  phases.
- **Remediation:** pinned `gem "json", "~> 2.7"` in
  `fuzzlab/labgen/emitters/ruby_rails/stack/skeleton/Gemfile`, regenerated
  `Gemfile.lock` for real (resolves `json 2.21.2`), and verified the exact
  two-request session sequence that 500'd before the fix now returns
  200/200 after it. Full RCA: `docs/bugs/BUG-0035-rails-skeleton-json-gem-
  arity-breaks-second-request-in-a-session.md`; preventive action:
  `docs/PREVENTIVE_ACTIONS.md` `PA-0037`.
- **Status:** Fixed.

---

## 2026-09-22 — `ruby_rails` emitter's generated controller 500'd: Rails' inflector does not round-trip a class name with digits abutting a letter (fixed, BUG-0034/PA-0036)

- **Symptom:** the first real live-boot test of the new `ruby_rails` emitter
  (`tests/test_labgen_ruby_rails_live_boot.py`) got a real HTTP `500`
  (`ActionView::MissingTemplate` for `cell_labgen_rr0001/show`) even though
  the emitter had written the view file to the correctly-underscored
  `app/views/cell_labgen_rr_0001/show.html.erb`.
- **Root cause:** the generated controller used Rails' bare `render :show`
  symbol form, which resolves the view directory from
  `self.class.controller_path` — derived from the *class name* via
  `ActiveSupport::Inflector#underscore` at runtime, not from any path string
  the emitter itself wrote. That inflector does not insert an underscore
  before a digit run directly following a letter (`"Rr0001".underscore` =>
  `"rr0001"`, not `"rr_0001"`), so the emitter's own camelized class name and
  Rails' own runtime reconstruction of a view path from it silently
  disagreed — for exactly the letter-then-digits shape this project's own
  `LABGEN-...-NNNN` cell-ID convention always produces. See
  `docs/bugs/BUG-0034-*.md` for the full Five Whys.
- **Remediation:** the generated controller now renders via an explicit
  `render template: "<controller_name>/<view_name>"` path literal computed
  directly from the same string the emitter used to write the view file,
  never through Rails' inflector-derived `controller_path`. Verified for
  real: the live-boot test now returns a real `200` with the expected
  unescaped payload. New preventive action: **PA-0036**.
- **Status:** Fixed.
## 2026-09-23 — django `sql_string_literal` sink crashes (500, not 404) on a missing POST param, found by its own PA-0034 adversarial test (fixed, BUG-0037/PA-0039)

- **Symptom:** `CC-LAB-0091`'s own required `PA-0034` adversarial test (a
  mismatched-method `GET` request against the newly `@csrf_exempt`-decorated
  `/api/login` view) returned a real `500` instead of the expected `404`.
- **Root cause:** the vulnerable `sql_string_literal_lookup.py.j2` sink
  template's unbound branch concatenated the tainted `value_expr` directly
  (`"...'" + {{ value_expr }} + "'..."`) instead of casting it with `str()`
  first, unlike its sibling `sql_numeric_lookup.py.j2` sink (which already
  wraps in `str(...)`). `request.POST.get("username")` returns `None` on a
  `GET` request, and Python's `+` operator raises `TypeError` concatenating
  `str` and `NoneType` -- a crash the PHP/JS analogs of this same shape
  don't have (PHP's `.` operator and JS's `+` on a string both coerce
  `null`/`undefined` to text rather than raising).
- **Remediation:** added the missing `str(...)` cast
  (`fuzzlab/labgen/emitters/django/templates/sinks/
  sql_string_literal_lookup.py.j2`), landed with `CC-LAB-0091`. Swept every
  other `django` template for the same `+`-concatenation-without-`str()`
  shape (`grep` over `fuzzlab/labgen/emitters/django/templates/`) -- no
  other instance found; `html_body_echo.py.j2` and `sql_numeric_lookup.py.j2`
  already cast correctly.
- **Status:** Fixed (`BUG-0037`/`PA-0039`).
## 2026-09-23 — Category 5 pilot (Expedia, spel_injection shape): ground-truth directory shipped without expectedresults.csv (Fixed, BUG-0036/PA-0038)

- **Symptom:** `CC-LAB-0214`'s new `lab/ground-truth-expedia-clone/`
  directory had `labels.json` and `injection-points.json` but not
  `expectedresults.csv`, which `fuzzlab.labels.contract.load()` requires
  unconditionally. Found during a whole-repo `pytest -m "not slow"` run
  performed as part of an unrelated cross-branch bookkeeping-ID collision
  fix on this same branch — two tests in
  `tests/test_labgen_spel_injection.py` failed with `FileNotFoundError`,
  despite the shape's own authoring commit claiming a clean whole-repo
  pass.
- **Root cause:** an authoring omission when the new ground-truth
  directory was created — every sibling second-target ground-truth
  directory in this corpus ships all three files as one atomic unit, and
  this one didn't; compounded by `.gitignore` never having gained the
  per-directory `!lab/ground-truth-expedia-clone/*.csv` negation its
  blanket `*.csv` rule requires, so the file could not have been
  committed even if authored. See BUG-0036 for the full five-whys
  (including why the authoring commit's own claimed whole-repo pass is
  inconsistent with this file having been exercised against what was
  actually committed).
- **Remediation:** authored the missing `expectedresults.csv` (one row,
  `EXPD-0001`, matching `labels.json`'s existing case and the established
  column convention from `lab/ground-truth-booking-clone/
  expectedresults.csv`) and added the missing `.gitignore` negation.
  `pytest tests/test_labgen_spel_injection.py`:
  9 passed (up from 7 passed/2 failed). Whole-repo re-run: 1865 passed, 8
  skipped — no regression.
- **Status:** Fixed.

## 2026-09-22 — Category 5 pilot (open_redirect shape): shared-vocabulary modules added without their determinism-fixture entries (Fixed, BUG-0038/PA-0040)

- **Symptom:** `CC-LAB-0210`'s three new shared-vocabulary-only module
  registrations (`redirect_target_allowlist`/`http_redirect_return`/
  `redirect_response` in `fuzzlab/labgen/modules/__init__.py`) were pushed
  in a commit that had only been verified with `tests/
  test_labgen_open_redirect.py` and `tests/test_labgen_php_laravel_harder_
  shapes.py` run directly — not the whole-repo `pytest tests/` suite. A
  first whole-repo run (done as this same change's own closing
  verification, before declaring it complete) failed two tests:
  `tests/test_labgen_modules.py::test_every_module_renders_
  deterministically_twice` and `::test_every_registered_module_has_a_
  determinism_ctx_fixture`.
- **Root cause:** `_DETERMINISM_CTX_BY_MODULE` (a hand-kept, per-module
  fixture table in `tests/test_labgen_modules.py`, guarded by its own
  completeness assertion) had no entries for the three new module names —
  an authoring omission in the same commit that registered them, not a gap
  in the guard test itself, which is exactly `PA-0001`/`PA-0027`'s "a
  hand-maintained completeness table must be kept in sync, and a guard test
  must fail loud when it isn't" pattern working as designed.
- **Remediation:** added the three missing `_DETERMINISM_CTX_BY_MODULE`
  entries (matching the file's own `L-P3.3c-DOM` precedent's comment
  convention), verified with a second whole-repo `pytest tests/` run:
  1618 passed, 30 skipped, 0 failed.
- **Status:** Fixed. See `docs/bugs/BUG-0038-*.md` for the full RCA and
  recurrence review: `PA-0001`/`PA-0027` already cover the registry/
  guard-test discipline itself (and their guard test worked correctly here
  — it failed loud on the very first run against the new code), so this is
  not a recurrence of that root cause. The actual gap was this session's
  own pre-push verification being scoped to "directly relevant test
  files" rather than the whole suite; `PA-0040` (new) closes that
  sequencing gap.

## 2026-09-22 — Category 5 pilot (Expedia/Java-Spring-Boot): Maven Central unreachable through this sandbox's egress proxy (Open, Environment)

- **Symptom:** building `node_express`/`php_laravel`'s equivalent of a real,
  checked-in bootable skeleton for the new Java/Spring Boot emitter (this
  category's Expedia pick, `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md`
  §9.4 category 5) requires a real dependency resolution against Maven
  Central, the same way `php_laravel`'s skeleton required a real
  `composer create-project`/`composer update` against Packagist. Every
  attempt (`curl` against `repo.maven.apache.org/maven2/.../maven-metadata.xml`,
  four tries spaced ~15s apart) returned `HTTP 429` from Maven Central
  itself (via Cloudflare, `server: cloudflare` header present — not a local
  timeout or DNS failure). `start.spring.io` (Spring Initializr, the
  standard way to generate a real trimmed Spring Boot project) returned
  `403 Forbidden` at the proxy's own CONNECT tunnel step, before even
  reaching the origin.
- **Root cause:** this sandbox's outbound-HTTPS proxy explicitly allowlists
  `registry.npmjs.org`, `pypi.org`/`files.pythonhosted.org`, `index.crates.io`,
  and `proxy.golang.org` as direct-bypass (`noProxy`) hosts (confirmed via
  `curl "$HTTPS_PROXY/__agentproxy/status"`), but **not** `repo.maven.apache.org`
  or `start.spring.io` — Maven/Java package resolution is not one of this
  environment's supported registries. `repo.maven.apache.org` traffic still
  routes through the general proxy and is rate-limited/blocked upstream
  (429) rather than reaching Maven Central cleanly; `start.spring.io` is
  blocked outright at the proxy (403 on CONNECT).
- **Remediation:** none available inside this sandbox — this is an
  environment capability gap, not a code defect (no bug report/preventive
  action owed; `CLAUDE.md`'s bug protocol is scoped to code defects). Per
  this project's own `PA-0035` discipline (a capability probe must exercise
  the real operation, never assume/stub it), Phase A's real-boot skeleton
  work for the Java/Spring Boot emitter is **paused, not faked**, pending
  either a sandbox with Maven Central/Spring Initializr egress allowed, or
  an on-host environment (mirroring how `docs/ON_HOST_TASKS.md` already
  tracks other real-infra-only work this project can't complete in-sandbox).
  Category 5's other pick (Booking.com, PHP) has no such blocker — it reuses
  the already-built, already-network-proven `php_laravel` skeleton/harness,
  so that half of the pilot proceeds unblocked in this session.
- **Status:** Open (Environment) — tracked in
  `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4's category 5 row;
  re-check Maven Central/Spring Initializr reachability at the start of any
  future session resuming this category's Java/Spring Boot Phase A before
  assuming it's still blocked.

## 2026-09-22 — Mass-assignment codegen: smuggled SQLi, broken POST routing, and a nullable dereference, found by PR review (fixed, BUG-0031/PA-0034)

- **Symptom:** PR #1's external review found the `orm_entity_bulk_assign`
  code-generation increment (`CC-LAB-0064`/`FR-LAB-59`), which had passed its
  own 21-test suite and a 4-round change-control review, had three real
  defects: the php_current sink spliced an unvalidated `$_POST` array key
  into a SQL identifier position (a real SQL injection, CWE-89, smuggled
  into a cell classified mass-assignment-only); `php_laravel`'s
  `_served_route_for()` hardcoded `GET` for illustrative pages, so the new
  illustrative POST cells were served at the wrong HTTP method and could
  never be exercised; and the php_laravel sink dereferenced
  `$request->user()->id` unguarded, fatal on any unauthenticated request.
- **Root cause:** the feature's own tests and its change-control review both
  verified the code against the *design it was written to satisfy* (mass
  assignment via a valid key; correct registry wiring; correct Eloquent
  semantics), never against adversarial inputs orthogonal to that design (a
  malformed identifier; a method-mismatched request; a null auth context) —
  see `docs/bugs/BUG-0031-*.md` for the full Five Whys.
- **Remediation:** identifier-charset guard on the SQL column name
  (php_current); `_served_route_for()` now serves an illustrative page at
  its cell's own declared method (verified backward-compatible against every
  pre-existing illustrative cell, all of which are `GET`); PHP 8 nullsafe
  `?->id` on the Laravel sink. New preventive action: **PA-0034**.
- **Status:** Fixed.

## 2026-09-22 — `check-corpus-cwe-coverage.sh` silently passed unannotated and unpaired corpus entries (fixed, BUG-0032/PA-0034)

- **Symptom:** the same PR review found two gaps in the `Stop` hook built
  specifically to mechanically enforce the corpus's CWE-coverage and
  pairs-per-class floors (`PA-0033`): an entry with neither `cwe_unique:`
  nor the legacy `cwe:` field at all fell through a bare `continue` with no
  problem ever recorded; and the pairs-per-class floor only counted
  `role: vulnerable` entries, so a cell with 5 orphaned vulnerable entries
  and zero idiomatic counterparts satisfied the floor and passed.
- **Root cause:** the hook was validated only by confirming it caught the
  specific problems already present in the real, self-authored corpus at
  build time — never against synthetic fixtures shaped like the exact
  failure modes it claims to catch, which the author's own habits never
  happened to produce. Same root-cause class as `BUG-0030` (`PA-0033`'s own
  origin), recurring one layer up in the enforcement mechanism `BUG-0030`'s
  fix built — see `docs/bugs/BUG-0032-*.md`'s prior-preventive-action
  failure analysis.
- **Remediation:** both gaps closed; verified against three synthetic
  fixtures (missing-CWE-field entry; 5-vulnerable/3-idiomatic cell;
  genuine 5/5 paired cell) since the real corpus never exercised these
  shapes. Also fixed a related nit: the no-upstream diff fallback now uses
  the merge-base with the default branch, so a manifest edit already
  committed on a fresh, unpushed branch is still checked. Strengthens
  **PA-0033** via the shared **PA-0034**.
- **Status:** Fixed.

## 2026-09-22 — Corpus expansion: CWE research under-delivered the plan's explicit "more is better" instruction, recurring right after a related correction (fixed)

- **Symptom:** every one of the 6 manufactured vulnerable/idiomatic pairs
  added to `docs/research/corpus-examples/*/manifest.yaml` in waves 1-2 of
  `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` carried only 1-2
  CWE IDs (several `cwe: []`), despite the plan's own Step 6 explicitly
  stating "the more CWEs that are able to be implemented, the better" — and
  the same shortfall recurred in wave 2 immediately after the user had
  already corrected a different under-delivery (deferred category scope)
  in the same conversation.
- **Root cause:** CWE assignment was done by recall (the first plausible
  CWE ID from memory) rather than by actually researching the MITRE CWE
  index's class/parent/child/related-weakness structure for each entry's
  mechanism; a written "more is better" instruction was treated as
  satisfied once any CWE field was populated, with no mechanical check
  forcing a real ceiling search. Same root-cause class as PA-0020 ("my own
  missed self-check needs mechanical enforcement, not a clearer written
  rule"), but PA-0020's existing enforcement (`check-error-log-bookkeeping.sh`)
  is scoped only to `ERROR_LOG.md` bookkeeping, not to this deliverable —
  see `docs/bugs/BUG-0030-*.md`'s "Prior-preventive-action failure
  analysis" for the full account.
- **Remediation:** re-researched and expanded all 6 existing entries' `cwe:`
  lists against the MITRE index; added
  `.claude/hooks/check-corpus-cwe-coverage.sh` (a new `Stop` hook) that
  mechanically blocks the session from ending if a touched
  `docs/research/corpus-examples/*/*/manifest.yaml` entry has fewer than 2
  CWEs and no explicit rationale for the cap; rewrote
  `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md` from scratch with
  a Step 6 that names the actual research procedure and its enforcement
  mechanism instead of repeating unenforced prose. New preventive action:
  PA-0033 (`docs/PREVENTIVE_ACTIONS.md`).
- **Status:** Fixed.

## 2026-09-22 — Research tooling: Semgrep installs but panics at import in this remote execution environment (Environment)

- **Symptom:** following `docs/VULN_CORPUS_EXPANSION_PLAN.md`'s Phase 3
  validation tooling (Semgrep as the primary cross-stack static-analysis
  check) while executing wave 1 of
  `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md`, `pip install
  semgrep` succeeded but every invocation (`semgrep --version` and later)
  crashed: `pyo3_runtime.PanicException: Python API call failed` inside
  `cryptography`'s Rust bindings (`_cffi_backend`/`cryptography.hazmat._rust`
  failing to load), reached via `semgrep -> pyjwt -> cryptography`.
- **Root cause:** an environment-level native-dependency mismatch in this
  remote execution container (the installed `cryptography` wheel's compiled
  Rust extension does not load correctly against this container's Python/
  system libraries) — not a bug in this repo's own code, and not something a
  code change in `fuzzlab` can fix.
- **Remediation:** none attempted beyond the standard `pip install` (rebuilding
  `cryptography`/`cffi` from source, or switching container base images, is
  outside this session's scope). Worked around by using Bandit (functional,
  Python-only) plus manual/structural review for the PHP and HTML/template
  entries collected in that wave, and recording each affected corpus
  `manifest.yaml` entry's `validated_by` as `[manual-review]` rather than
  implying a Semgrep pass that didn't happen. See
  `docs/VULN_CORPUS_SITE_ARCHITECTURE_EXPANSION_PLAN.md`'s "Tooling
  constraints in this execution environment" section for the full list of
  validation-tooling gaps found (gVisor and difftastic also unavailable).
- **Status:** Environment (fixed outside the repo — no `fuzzlab` code defect,
  so no `docs/bugs/BUG-NNNN-*.md`/preventive-action entry applies; this is
  purely a note for whoever next tries to run Semgrep in a similar container).
## 2026-09-22 — Session process: agent paused to ask for continuation after explicit "work until tasks run out" instruction (fixed, BUG-0029/PA-0032)

- **Symptom:** the user instructed the session to keep executing the approved
  `docs/PARALLEL_LANE_BUILD_PLAN.md` build lanes "until you ran out of tasks." After
  Wave 1a completed (7 lanes merged, verified, pushed), the session ended its turn with
  a summary that included "say the word if you want me to continue" — an implicit
  request for confirmation before dispatching Wave 1b/Wave 2, despite the user having
  already given that authorization up front.
- **Root cause:** default end-of-turn habit (offering a next-step choice) was applied
  even though the user's standing instruction for this task explicitly pre-authorized
  continuing without a check-in; the session treated "keep working" as applying only to
  the current wave rather than to the whole remaining backlog.
- **Remediation:** the user called it out directly; the session proceeded immediately
  with Wave 1b (B0's 4 emitter sub-lanes) and Wave 2 (5 UI lanes + D0b) without asking
  again, and will continue dispatching remaining waves/lanes from
  `docs/PARALLEL_LANE_BUILD_PLAN.md` without pausing for confirmation until the backlog
  is actually exhausted or a genuine blocker (not just "more work exists") comes up.
- **Status:** Fixed. Not a fuzzlab code defect, so `CLAUDE.md`'s bug protocol does not
  strictly require it — but per the user's explicit request, given the full treatment
  anyway: `docs/bugs/BUG-0029-session-paused-for-confirmation-despite-explicit-continue-instruction.md`
  (root-cause analysis, recurrence review against `BUG-0018`'s related-but-distinct
  agent-conduct failure) and `docs/PREVENTIVE_ACTIONS.md`'s **PA-0032**.

## 2026-09-22 — LAB: `live_boot_available()`'s network probe tested a raw socket connect, not the real proxied composer-install path, letting a live-boot test hang instead of skip/pass (fixed)

- **Symptom:** a background lane's incidental plain `pytest -q` run observed
  `tests/test_labgen_conformance_live_boot.py::test_live_boot_forms_manifest_serves_real_pages`
  hang indefinitely instead of completing or skipping (could not be reproduced on demand
  in this session's own sandbox; investigated via code reading).
- **Root cause:** `live_boot_available()`'s `_network_reachable()` probed a bare
  `socket.create_connection((host, 443))` -- a different, easier operation than the real
  one it gates (`composer install`'s real, proxy-aware HTTPS round trip through composer's
  own HTTP client). In a sandbox where outbound HTTPS only actually completes through a
  configured proxy, a raw TCP connect can report "reachable" without saying anything about
  whether the real, proxied operation will complete in bounded time.
- **Remediation:** replaced the raw-socket probe with `_composer_network_probe()`, which
  runs a real, bounded (`timeout=`-enforced) `composer show -a psr/log` -- the actual
  client and code path `composer install` itself uses -- and reports unavailable
  (never hangs, never raises) on timeout/failure. `_run()` (every real subprocess step of
  the pipeline) now wraps `subprocess.TimeoutExpired` in a clear `LiveBootError` instead of
  letting it propagate uncaught. See `docs/bugs/BUG-0033-*.md` for the full RCA.
- **Status:** Fixed (`CC-LAB-0068`/`FR-LAB-60`, `PA-0035`).

## 2026-09-22 — LAB: `LiveBootHarness` silently followed real redirects and its seeded schema lacked Eloquent timestamp columns (fixed)

- **Symptom:** extending `LiveBootHarness` coverage to the auth/G4 real-page manifests
  (`CC-LAB-0056`/`FR-LAB-54`), a real correct-credentials `POST /login.php` reported a
  `404` (a successful login's own real `302` to `/profile.php` was silently chased to a
  `GET` on a URL the auth manifest alone never registers), and every G4 write
  (`edit_profile.php`) reported an unconditional real `500`.
- **Root cause:** `LiveBootHarness.request()` used `urllib.request.urlopen()` directly,
  which auto-follows a `POST`'s `301`/`302`/`303` per the stdlib's own documented
  default; and the harness's seeded SQLite `users` table had no `created_at`/
  `updated_at` columns, which `App\Models\User`'s default Eloquent `$timestamps = true`
  needs on every `->save()` (a code path only G4's write endpoint exercises — neither
  original `CC-LAB-0054` manifest touches Eloquent at all).
- **Remediation:** `request()` now opens through a custom `urllib` opener
  (`_NoRedirectHttpErrorProcessor`) that hands back every response unmodified instead of
  chasing a redirect; `_SCHEMA_SQL`'s `users` table gained nullable `created_at`/
  `updated_at` columns. See `docs/bugs/BUG-0028-*.md` for the full RCA.
- **Status:** Fixed (`CC-LAB-0056`/`FR-LAB-54`, `PA-0030`).

## 2026-09-22 — LAB: `check_minimal_pair`'s content-confinement check silently disabled whenever the two variants' compositions differ by name (fixed)

- **Symptom:** `fuzzlab.labgen.minimal_pair.check_minimal_pair()` returned `None` (no
  violation) for a hand-constructed "secure twin" that both (a) legitimately renamed its
  transform (`identity` -> `param_bind`, a real declared difference) and (b) rewrote an
  unrelated line (its source, `$_GET` -> `$_POST`) with nothing to do with the declared
  difference — exactly the failure mode the checker's own docstring says it exists to
  catch. Demonstrated by the new
  `tests/test_labgen_minimal_pair.py::test_unrelated_rewrite_before_the_transform_region_now_caught`.
  Separately, the checker paired vulnerable/secure files strictly by literal path, so two
  independently-authored cells rendering to two different paths (lane L-P3.3c-G3's
  `login.php`/its secure twin, `CC-LAB-0048`) could not be compared directly at all.
- **Root cause:** `_check_file_pair()` only validated the empirical content-diff band
  (requiring it be empty) inside the `if not any_declared_difference:` branch — the branch
  taken when the two compositions are name-identical. Whenever any composition position
  legitimately differed by name (`any_declared_difference = True` — the case for
  essentially every real vulnerable/secure pair, since their transform names differ), no
  code path validated the band at all; the function fell straight through, regardless of
  the band's size or location. Full RCA: `docs/bugs/BUG-0027-*.md`. The pairing limitation
  was simply that `check_minimal_pair()` had no non-path way to match two `EmittedFile`s.
- **Remediation:** added `pair_by` (an optional `EmittedFile -> Hashable` key function) to
  `check_minimal_pair()`, defaulting to `None` (literal path pairing, unchanged for every
  existing caller). Added a new, unconditional content-confinement check derived from each
  side's *own* composition metadata independently (never from name-matching between the two
  sides): a `transform` module's self-identifying comment line (`// {name} transform: ...`,
  a convention every template in `fuzzlab.labgen.modules.transforms` already follows) marks
  where the fixed source/depth fragments end and the transform/sink region begins; content
  found to differ before that line, on either side, is now a `MinimalPairViolation`
  regardless of whether the two sides' composition names match. New tests:
  `test_default_pairing_still_rejects_two_differently_pathed_cells`,
  `test_pair_by_lets_two_differently_pathed_cells_be_compared`,
  `test_pair_by_still_reports_a_real_violation`,
  `test_pair_by_ambiguous_mapping_raises_setup_error`,
  `test_a_real_transform_rename_alone_still_passes`,
  `test_unrelated_rewrite_before_the_transform_region_now_caught`,
  `test_content_confinement_runs_even_when_variable_categories_is_narrowed`. Full suite:
  1521 passed, 8 skipped (see `CC-LAB-0055`).
- **Status:** Fixed (see `docs/bugs/BUG-0027-minimal-pair-confinement-check-disabled-when-composition-differs.md`,
  `docs/PREVENTIVE_ACTIONS.md` PA-0029, `docs/components/01-target-lab/change-control.md`
  CC-LAB-0055, `FR-LAB-53`).

---

## 2026-09-22 — MUT: `SemanticsValidator` fail-open on untrusted SQL comment-append (fixed)

- **Symptom:** `tests/test_mutation_operators.py::test_every_surface_variant_preserves_semantics`
  and `::test_sql_equivalent_needs_trusted_provenance` failed. The second is the
  security-relevant one: `SemanticsValidator.preserves("1 or 1=1", "1 or 1=1 -- x",
  "sql-injection")` (untrusted) returned `True` — an untrusted `--` comment-append was
  accepted as semantics-preserving. First recorded as "found, not fixed" by lane
  L-P3.4 (see the entry immediately below/prior in this log) and re-confirmed by
  several subsequent `pytest` runs without being fixed until now.
- **Root cause:** (1) the AST-equivalence path returned a decisive verdict from
  `sqlglot` ASTs that discard comments as non-semantic trivia, so a `--`-appended
  fragment parsed identically to the original and was accepted before any
  provenance check — `canonicalize()`'s comment-stripping only covers `/* */` block
  comments, the shape the surface operators actually emit, so it never even ran.
  (2) Separately, `_ast_equiv()` compared AST nodes with case-sensitive `==`,
  rejecting a genuinely meaning-preserving `case-toggle` variant.
- **Remediation:** added `introduces_line_comment()` and made `preserves()` refuse
  (fail-closed) any untrusted mutation that introduces a `--` marker, before the
  AST/canonical checks run; made `_ast_equiv()` compare lowercased re-rendered SQL
  text instead of raw node equality. New regression tests derive the checked
  operator set from `default_operators()` (PA-0027 discipline) rather than hardcoding
  operator ids. Full suite: 1494 passed, 8 skipped.
- **Status:** Fixed (see `docs/bugs/BUG-0026-semantics-validator-fail-open-on-untrusted-sql-comment.md`,
  `docs/PREVENTIVE_ACTIONS.md` PA-0028, `docs/components/09-mutation-engine/change-control.md`
  CC-MUT-0008).

---

## 2026-09-22 — LAB: `php_laravel`'s stack-local module names would have failed every minimal-pair gate (found during L-P3.3b, fixed in the same lane)

- **Symptom:** while wiring the Laravel emitter into `fuzzlab lab-generate --check` (§4.3
  step 3's requirement, lane L-P3.3b), the minimal-pair gate would have reported a
  `MinimalPairError` **setup** failure — "composition names module `get_query_param` …
  which is not registered in any of `fuzzlab.labgen.modules`' SOURCES/TRANSFORMS/SINKS/
  COMPLEXITIES" — for every generated Laravel cell, i.e. a gate that cannot evaluate its
  invariant rather than one reporting a real finding. Caught by reading
  `minimal_pair._parse_composition` before wiring, not by a failing build.
- **Root cause:** `fuzzlab.labgen.minimal_pair` classifies each position of a generated
  file's `// Module composition: …` provenance line by looking the name up in
  `fuzzlab.labgen.modules`' registries — `php_current`'s — which is the only category map
  it has. L-P3.3a's foundation emitter used two stack-local names (`get_query_param`,
  `db_select_raw`) that no shared registry knows. The gap was invisible until this lane,
  because that foundation was never run through `--check` (the emitter was not registered
  in the CLI).
- **Remediation:** `php_laravel`'s module registry keys are the project's shared
  composition vocabulary (`get_param`, `sql_numeric_lookup`, …) with Laravel-idiom
  implementations behind them; the two stack-local names were renamed. A test now asserts
  every key of every `php_laravel` registry is classifiable by `minimal_pair`'s own map, so
  a future stack-local name fails at unit level rather than as an unevaluable gate. The
  general fix — a pluggable category map on `minimal_pair`, so a stack may keep its own
  names — is recorded as an open question in
  `docs/components/01-target-lab/requirements.md` §8; it is a sibling lane's shared file
  and no second stack needs it yet. Not a code defect in shipped behavior (no released
  path produced a wrong result), so no `BUG-NNNN`/`PA-NNNN` is claimed; see `CC-LAB-0044`.
- **Status:** Fixed.

## 2026-09-21 — MUT: two `tests/test_mutation_operators.py` failures pre-existing on the branch tip (found, not fixed)

- **Symptom:** the full suite run for lane L-P3.4 (§4.4, `CC-LAB-0040`) ended
  `2 failed, 1170 passed, 8 skipped`. The two failures are
  `test_every_surface_variant_preserves_semantics` and
  `test_sql_equivalent_needs_trusted_provenance`: `SemanticsValidator.preserves()`
  returns `False` for a surface-only case-toggle variant of a SQLi payload that it
  should accept, and `True` for an unvetted `-- x` comment append that it should refuse
  (a fail-*open* direction, so the more serious of the two).
- **Root cause:** not yet diagnosed here — outside this lane's component (MUT,
  `fuzzlab/mutation/semantics.py`) and outside its scope. Recorded because it was
  observed, per `ERROR_LOG.md`'s own scope line and PA-0019: both failures reproduce on
  a **pristine detached worktree of this branch's tip (`HEAD`, no L-P3.4 changes
  applied)**, so they are pre-existing on `claude/trusting-noether-heon0n` and not
  caused by this lane's change — verified explicitly rather than assumed.
- **Remediation:** none by this lane (deliberately: fixing another in-flight lane's
  component mid-merge would collide). Flagged to the orchestrating session in this
  lane's hand-off report so it can be routed to whoever owns MUT; a code defect, so it
  needs the full `docs/bugs/BUG-NNNN` + `PA-NNNN` protocol from that owner, not just
  this line.
- **Status:** Open (not caused by, and not remediated by, `CC-LAB-0040`).

## 2026-09-21 — `lab-generate --check` gate tests stopped exercising their gate when an emitter's supported shapes were widened

- **Symptom:** while landing lane L-P1.2b (the harder SQLi/XSS shapes, which widen
  `php_current`'s supported shapes by four and therefore make the example manifest's
  long-skipped `LABGEN-EX-0003` renderable),
  `tests/test_labgen_cli.py::test_check_fails_loud_on_nondeterministic_render` failed:
  `--check` still exited 1, but the *determinism* gate it exists to exercise no longer
  tripped at all.
- **Root cause:** that test (and its minimal-pair sibling) injected its fault on the
  parity of a **global** counter incremented once per rendered cell, so which parity a
  given cell's render lands on depends on how many *other* supported cells precede it —
  at an even supported-cell count the corruption applied to both whole-tree renders
  identically and the regenerate-and-diff comparison saw no difference. The same file
  also hardcoded the supported-cell set that `PhpCurrentEmitter.supports()` computes.
- **Remediation:** both fault injections now count renders per `cell_id` (invariant under
  cell count), and `SUPPORTED_CELL_IDS` is derived from `supports()`. PA-0002 sweep done
  across `tests/`: the whole-tree counters in `test_labgen_gates.py` /
  `test_labgen_conformance_tier3.py` are at the correct granularity and left as-is. Full
  RCA: `docs/bugs/BUG-0025-check-gate-fault-injection-coupled-to-supported-cell-count.md`;
  rule: PA-0027.
- **Status:** Fixed (`CC-LAB-0043`).

## 2026-09-21 — Covering-array resolver silently returns zero cells when `strength` exceeds the factor count

- **Symptom:** while wiring `fuzzlab.labgen.resolver.expand()` into manifest loading
  (T-LAB2.1), an `axis_ranges` block with a single-axis `factors` mapping and the
  default `strength: 2` validated cleanly and expanded to an **empty** cell list — no
  error, no cells, nothing to catch it short of noticing the count.
- **Root cause:** `covertable.make()` does not raise when `strength` exceeds the number
  of factors (or a `sub_models` entry's own `strength` exceeds its own field count) — it
  silently returns `[]`, a t-way covering array being undefined for fewer than t factors.
  `fuzzlab.labgen.resolver.validate_covering_array_config()` already defends against two
  other silent-covertable-failure shapes (an unrecognized kwarg, an unpinned sorter
  default — both PA-0010) but had no check for this third shape.
- **Remediation:** `validate_covering_array_config()` now rejects `strength >
  len(factors)` and, per `sub_models` entry, `strength > len(fields)`, both before ever
  calling `covertable.make()`. Full RCA: `docs/bugs/BUG-0024-covering-array-strength-exceeds-factor-count.md`.
- **Status:** Fixed (`CC-LAB-0029`).

## 2026-09-21 — Nuclei oracle draft would misclassify an unreachable target as `confirmed_secure`

- **Symptom:** while validating `nuclei` as a tool-oracle (Spike 004), a first-draft
  classifier for `fuzzlab.labgen.nuclei_oracle` treated "exit 0, zero JSONL matches" as
  `confirmed_secure` — but `nuclei` also exits 0 with zero matches when it never reached
  the target at all (a closed port), so a torn-down/misconfigured secure twin would be
  recorded as confirmed secure.
- **Root cause:** unlike sqlmap/commix, Nuclei has no dedicated "not vulnerable" textual
  marker; a clean scan and an unreachable-target scan are both silent on stdout with exit
  code 0, distinguishable only via a stderr health-check line Nuclei prints unless
  `-silent` is passed.
- **Remediation:** `_classify()` checks `stderr` for Nuclei's own host-unreachable
  signal before ever returning `confirmed_secure`, downgrading to `inconclusive`
  instead; the wrapper never passes `-silent`. Caught and fixed during development,
  before shipping. Full RCA:
  `docs/bugs/BUG-0023-nuclei-oracle-unreachable-target-false-secure.md`; preventive
  action `PA-0025`.
- **Status:** Fixed.

## 2026-09-21 — `php_current.supports()` accepted a shape whose illustrative-manifest cell had no page profile

- **Symptom:** `PhpCurrentEmitter.render()` raised `ValueError` for
  `lab/manifests/example_phase0_scaffold.yaml`'s `LABGEN-EX-0004` cell
  (`xss`/`html_body`, route `/example/profile.php`), even though
  `PhpCurrentEmitter.supports()` returned `True` for that shape — violating
  the `Emitter` interface's own documented supports-then-render contract.
- **Root cause:** `CC-LAB-0022`'s real-page extension widened
  `PhpCurrentEmitter._MODULE_SET_BY_SHAPE` to accept `(xss, html_body)` (for
  the real `/profile.php` page) without adding a matching `_PAGE_PARAMS`
  entry for the pre-existing illustrative manifest's cell of the same shape
  — no test exercised a whole manifest's cell list through the now-widened
  `supports()`/`render()` pair, only individually hand-picked cells.
- **Remediation:** added the missing `_PAGE_PARAMS["/example/profile.php"]`
  entry; new whole-manifest Tier-3 regeneration tests
  (`tests/test_labgen_conformance_tier3.py`) now render every cell of both
  existing Phase-0 manifests, not a hand-picked subset. Full RCA:
  `docs/bugs/BUG-0022-php-current-supports-true-render-crashes-missing-page-profile.md`;
  preventive action `PA-0024`.
- **Status:** Fixed.

## 2026-09-21 — LAB lane worktree created from a stale/unrelated branch lineage

- **Symptom:** on session start for the T-LAB0.6 (Gitleaks secret-scanner) lane,
  `git log --oneline -5` showed only unrelated UI-redesign commits (a master-detail
  Launch view rebuild, app-shell/design tokens, Proxy Scope/Match-Replace) with no
  mention of "LAB"/"CC-LAB-00"/"labgen"/"D20", and `fuzzlab/labgen/` did not exist
  anywhere in the checkout at all (no `denylist.py`, `gates.py`, `resolver.py`, etc.).
  A sibling lane (`CC-LAB-0019`) hit the identical symptom independently.
- **Root cause:** a worktree-creation quirk in this session's harness — the worktree
  was materialized from a stale/unrelated branch lineage instead of the actual current
  trunk, even though the correct branch (holding the merged Phase 0 LAB lanes) was
  fully present in the shared git object store the whole time. Not a missing-history
  problem and not something either lane did wrong.
- **Remediation:** stopped and reported the discrepancy instead of working around it
  (e.g. manually re-importing files), per this project's explicit guidance for this
  exact failure mode. Confirmed via a fresh worktree that `claude/trusting-noether-heon0n`
  was reachable as a local branch and `git reset --hard claude/trusting-noether-heon0n`
  (working tree was clean, so no destructive-command safeguard was overridden) recovered
  the correct tree in one step — `git log` then showed the expected LAB merge-lane
  history and `fuzzlab/labgen/` existed with all expected modules.
- **Status:** Environment (fixed outside the repo — no repo-level change needed; the
  underlying worktree-provisioning quirk is a harness/session-infrastructure issue, not
  a defect in this codebase). See `docs/components/01-target-lab/change-control.md`
  `CC-LAB-0019`'s and `CC-LAB-0020`'s notes for the per-lane detail.

## 2026-09-21 — `test_web_repeater.py` flakes with a cross-thread SQLite error

- **Symptom:** found incidentally while verifying an unrelated lab-generator lane's full-suite
  run: `tests/test_web_repeater.py::test_routes_list_create_and_send_gate` and
  `::test_route_send_reaches_upstream_when_authorized` intermittently fail with
  `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same
  thread` (a different one of the two failing each time). Reproduced twice independently
  (each time with different specific test(s) failing, consistent with a genuine race rather
  than one bad test); not reliably reproducible on demand afterward — order/timing-dependent.
- **Root cause:** `fuzzlab/web/proxycontrol.py::RepeaterController` (not `Repeater`/
  `SocketSender` themselves) cached one persistent `Store`/`sqlite3` connection as shared
  instance state (`self._store`/`self._rep`) and reused it for every request regardless of
  which OS thread was calling. `fastapi.testclient.TestClient`, when not used as a context
  manager, spins up a fresh `anyio` portal thread per top-level `client.get()`/`client.post()`
  call; whether the bug fires depends on whether Linux happens to reuse the same low-level
  thread id for the next ephemeral thread, which is why it was order/timing-dependent rather
  than deterministic. Full RCA in `docs/bugs/BUG-0021-repeater-controller-cross-thread-sqlite.md`.
- **Remediation:** `RepeaterController` now keeps its `Store`/`Repeater` per calling thread
  (`threading.local()`) instead of as one shared attribute, while still sharing a single
  `repeater` run row across threads (`self._run_id` under a lock). See `CC-PROXY-0016`.
  Reproduced reliably under thread-churn stress testing (100s of failures per few hundred
  iterations) before the fix, 0 failures across 600+ iterations after; full suite green
  (642 passed / 5 skipped; the 2 `test_mutation_operators.py` failures are pre-existing and
  unrelated).
- **Status:** Fixed.

## 2026-09-21 — sqlmap/commix exit non-zero on a legitimate negative finding, not only on a crash

- **Symptom:** while building `fuzzlab/labgen/oracle_wrapper.py` (`CC-LAB-0015`), an initial
  draft gated a verdict on the tool's subprocess exit code being `0` before trusting its
  textual output — the two skip-guarded integration tests against real cloned `sqlmap`/
  `commix` binaries failed immediately, because both tools exit non-zero on a clean "not
  injectable" finding, not only on a crash.
- **Root cause:** an untested assumption about a third-party tool's exit-code contract,
  carried over from a more typical CLI convention (0 = success/negative, non-zero = error)
  that doesn't hold for these two tools.
- **Remediation:** verdicts are now derived from the tool's own textual output via
  configurable regex markers, tuned against real tool output; a non-zero exit code is only
  consulted to add detail when neither marker matched (never as the primary signal). Caught
  by the real-binary integration test before the assumption ever shipped in a commit — no
  `docs/bugs/BUG-NNNN` opened, matching this project's own precedent (`docs/bugs/BUG-0018`'s
  scope note): this is a fact caught and fixed within the same session's authoring work,
  never landed as a defect in committed code, same as the two prior sqlmap/commix
  tool-behavior findings below.
- **Status:** Fixed (this commit). See CC-LAB-0015.

## 2026-09-21 — ERROR_LOG hook's keyword regex false-positives on "change" (BUG-0020)

- **Symptom:** the first real use of `.claude/hooks/check-error-log-bookkeeping.sh` (added
  in BUG-0019) after an incident-free, decision-only commit (D20/`CR-LAB-0001` approval)
  fired a false positive, blocking the stop.
- **Root cause:** the keyword regex matched `hang` as an unanchored substring, and `hang`
  is a substring of `change`/`changed`/`changes` — words this changelog-heavy project's
  own conventions use in nearly every commit. Full RCA in `docs/bugs/BUG-0020-*`.
- **Remediation:** anchored every keyword with `\b` word boundaries and explicit inflection
  groups; verified the real false-positive diff now passes, a synthetic true positive still
  blocks, and a synthetic change/changed/changes-only diff no longer matches on keywords.
  Rule PA-0022 (check a keyword heuristic against the project's own routine vocabulary
  before trusting it unattended).
- **Status:** Fixed (this commit).

## 2026-09-21 — PA-0019 was advisory-only, not mechanically enforced (BUG-0019)

- **Symptom:** asked to make PA-0019 (BUG-0018's fix) actually prevent recurrence rather
  than just document the expectation, inspection showed PA-0019 has no enforcement path
  other than my own end-of-turn recall of `docs/PREVENTIVE_ACTIONS.md` — the same recall
  step BUG-0018 showed already fails silently.
- **Root cause:** a preventive action whose root cause is my own missed/inconsistent
  self-check cannot be fixed by a written rule addressed to that same self-check; it needs
  an enforcement path independent of my remembering to apply it. Full RCA in
  `docs/bugs/BUG-0019-*`.
- **Remediation:** added `.claude/hooks/check-error-log-bookkeeping.sh`, wired as a Stop
  hook in `.claude/settings.json`. It inspects this turn's not-yet-pushed changes (working
  tree + unpushed commits) and blocks the session from stopping (once per stop cycle, via
  the same `stop_hook_active` recursion guard as `~/.claude/stop-hook-git-check.sh`) when
  they look incident-shaped (a new/modified `docs/spikes/`/`docs/bugs/` doc, or `fail`/
  `hang`/`workaround`/`killed`/`timed out`/`crash`/`broken`/`regress` added to the diff) but
  this log wasn't touched. Pipe-tested against four synthetic scenarios; committed to the
  repo so it applies in future sessions/clones, not just this container. Added PA-0020
  (strengthens/supersedes PA-0019).
- **Status:** Fixed

## 2026-09-21 — oracle-spike break/fix findings not logged to ERROR_LOG until prompted (BUG-0018)

- **Symptom:** the sqlmap 401/403-handling finding (Spike 001) and the commix ambient-
  defense/field-sweep hang (Spike 002) were each fully written up inside their spike
  documents and folded into `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`, but neither was added to
  this log at the time. Both were only logged after the user explicitly asked, in a
  following turn, to "record those both in a bug log."
- **Root cause:** reliance on a finding's narrative framing/salience to decide whether the
  `CLAUDE.md` bookkeeping checklist applied, rather than mechanically checking new findings
  against this log's own stated scope ("anything that broke and was fixed") regardless of
  how the finding was phrased or where else it was written up. Full RCA in
  `docs/bugs/BUG-0018-*`.
- **Remediation:** added the two findings to this log (previous entries below) with
  cross-references to their spike docs; added PA-0019 (re-check a turn's findings against
  each bookkeeping artifact's literal scope before ending the turn, not by how bug-shaped
  the finding feels); swept this session's own conduct per PA-0002 and found one more
  un-logged instance (the Docker Hub egress-policy block during Spike 001 — logged below).
- **Status:** Fixed (this commit).

## 2026-09-21 — Docker Hub image pulls blocked by egress policy during Spike 001 (found via BUG-0018's PA-0002 sweep)

- **Symptom:** `docker compose up -d --build` against a cloned `vAPI` repo (Spike 001)
  failed pulling `mysql:8.0`/`phpmyadmin/phpmyadmin` with a 403 from
  `production.cloudfront.docker.com`, reported by this session's agent proxy as a policy
  denial, not a transient failure.
- **Root cause:** this execution environment's egress policy blocks Docker Hub image pulls
  outright; per this environment's own guidance, a policy denial is reported, not retried
  or routed around.
- **Remediation:** ran the spike's target application natively instead (PHP built-in
  server + a local MariaDB install via `apt`), loopback-only, rather than in containers.
  Fully described in `docs/spikes/SPIKE-001-sqlmap-vs-vapi.md`, but not given its own log
  line until the BUG-0018 sweep found it. **Forward-looking implication:** Phase 3's
  containerized per-stack emitters (`CR-LAB-0001` Addendum D's `StackEnv.base_image`)
  should not assume Docker Hub is reachable in every execution context this project might
  run in; worth a documented fallback when that work actually starts.
- **Status:** Environment (worked around outside the repo; no repo change needed unless
  Phase 3 implementation later needs a documented fallback).

## 2026-09-21 — commix oracle hangs on ambient defenses and non-target form fields (Spike 002)

- **Symptom:** during `docs/spikes/SPIKE-002-commix-vs-dvwa.md` (validating commix as an
  independent security-assertion oracle for the lab generator, per `CR-LAB-0001` Addendum
  E), a headless `commix --batch` run against a properly-secured target (DVWA's
  `impossible.php`) first hung indefinitely against the real `ip` parameter because its
  anti-CSRF token rotates every page load and a captured token was stale by the second
  request; after that was worked around, commix moved on to sweep the irrelevant static
  `Submit` form field and entered a runaway false-positive-verification retry loop that
  never concluded on its own and had to be killed manually.
- **Root cause:** no fuzzlab code exists yet for this — this is a design gap, not a code
  defect. Nothing in the (not-yet-built) oracle wrapper scopes a tool invocation to the
  cell's declared injection parameter, and nothing accounts for a target's ambient defenses
  (rotating CSRF tokens, rate limiting) that are unrelated to the vulnerability class
  actually under test.
- **Remediation:** for the spike itself, the CSRF check was disabled in a local, reverted
  copy of `impossible.php` to isolate the command-injection defense from the unrelated CSRF
  defense, and the runaway `Submit`-field sweep was stopped by killing the process once the
  real parameter's clean result was already captured. The actual fix — scoping oracle
  invocations to the cell's declared parameter and giving the wrapper session/token-refresh
  awareness (or scoping each security assertion to just the transform under test) — is
  recorded as a requirement in `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`, not yet implemented.
- **Status:** Open (design requirement recorded; no oracle-wrapper code exists yet to fix).

## 2026-09-21 — sqlmap oracle refuses to test past a 401/403 "secure" response (Spike 001)

- **Symptom:** during `docs/spikes/SPIKE-001-sqlmap-vs-vapi.md` (validating sqlmap as an
  independent security-assertion oracle for the lab generator, per `CR-LAB-0001` Addendum
  E), a headless `sqlmap --batch` run against vAPI's properly-parameterized secure endpoint
  aborted immediately with `[CRITICAL] not authorized` instead of testing and reporting a
  clean negative, because the endpoint's "wrong credentials" response is `HTTP 401`, which
  sqlmap treats as an authentication failure by default.
- **Root cause:** no fuzzlab code exists yet for this — this is a design gap, not a code
  defect. The generator's planned oracle wrapper (`CR-LAB-0001` Addendum E) does not yet
  exist, so nothing reads a cell's declared "secure" HTTP status and passes it to sqlmap as
  `--ignore-code`.
- **Remediation:** re-ran manually with `--ignore-code=401`, which let sqlmap test both
  parameters and correctly report "does not seem to be injectable" with no false positive.
  The actual fix — the oracle wrapper reading the cell's expected secure-response status
  from the manifest and passing the matching `--ignore-code` automatically — is recorded as
  a requirement in `docs/LAB_SEED_AUTHORING_PLAYBOOK.md`, not yet implemented.
- **Status:** Open (design requirement recorded; no oracle-wrapper code exists yet to fix).

---

## 2026-09-21 — `labctl.sh reset` not self-healing under podman-compose (BUG-0017, recurrence of BUG-0013)

- **Symptom:** `scripts/greybox_e2e.sh` step 1 (`labctl.sh reset`) failed on the host with
  `executing /usr/bin/podman-compose up -d --build: exit status 125` and "cannot remove
  container … as it is running" / "container state improper" — the stack was wedged and
  Part E could not start.
- **Root cause:** `reset` recreated containers with a bare `compose down -v` + `up` and no
  force-clean fallback. podman-compose cannot remove/recreate a running/wedged stack — the
  exact limitation fixed in BUG-0013, but that fix (CC-LAB-0011) was applied only to the
  `up` subcommand. A **recurrence of BUG-0013**: PA-0014 was scoped to the *trigger*
  (env/profile change) not the *mechanism*, the PA-0002 sweep inherited that narrow framing
  and missed the sibling recreate path, and the self-heal was inlined in `up` instead of a
  shared helper (PA-0003 not applied).
- **Remediation:** factored the force-clean sequence into one shared `_force_clean()` helper
  and routed **both** `up` (keep-volume, on failure) and `reset` (drop-volume, before +
  after with retry) through it. Full RCA incl. recurrence + prior-PA-failure analysis in
  `docs/bugs/BUG-0017-*`; new rule PA-0018 (re-keys the self-heal to the mechanism and to
  all container-recreate paths). See CC-LAB-0013.
- **Status:** Fixed (this commit). labctl `up`/`reset` exit-code paths verified statically
  (mocked podman/compose, both success and fallback branches exit 0); suite 416 passed /
  6 skipped.

## 2026-09-21 — Grey-box "new-code reward" starved by the global frontier (BUG-0016)

- **Symptom:** `greybox-run` step 5 reported `new-code max: 0.000` + a NOTE "is the cov.php
  shim installed?" while step 6 said PASS and 338 novel lines were captured — a
  self-contradiction. The coverage-reward property (T3.7) wasn't actually demonstrated
  (payloads scored higher only via db_fault).
- **Root cause:** novelty was measured against a single **global** frontier and the benign
  baseline ran first per point, consuming that point's coverage — so every attack showed
  `novel=0`, `newcode_reward` was ~always 0, the baseline earned a novelty-only reward, and
  the NOTE inferred "shim broken" from that artifact.
- **Recurrence:** same class as the Part F metric (`requests_per_finding` can't show the
  bandit's oracle-probe savings) and BUG-0014 — a metric/self-test that passes/fires
  without measuring the capability. PA-0015 didn't prevent it (a self-test can pass while
  measuring the wrong thing).
- **Remediation:** `run_greybox` now uses a **per-point differential** (attack coverage vs
  its own baseline) for the reward novelty and `newcode_reward`; the global frontier is kept
  only for the run-wide exploration total; the NOTE fires only when `coverage_lines_seen==0`.
  Part F's runbook exit reframed to verify via posteriors with a metric caveat. Full RCA +
  recurrence/prior-PA analysis in `docs/bugs/BUG-0016-*`; rule PA-0017. See CC-FUZZ-0017.
- **Status:** Fixed (this commit). Suite 416 passed / 6 skipped.

## 2026-09-21 — `labctl.sh up` exits non-zero on success without a profile (BUG-0015)

- **Symptom:** `scripts/waf_evasion_e2e.sh` printed step 1 "lab up" then exited silently
  with no steps 2–5 (its EXIT trap quietly turned the WAF back off). `h2_desync_e2e.sh`
  (which sets `PFF_PROFILE=desync`) was unaffected.
- **Root cause:** the `up)` case ended with `[ -n "${PFF_PROFILE:-}" ] && echo ...`; with no
  profile, `[ -n "" ]` returns 1 and — being the last command — `labctl.sh up` exits 1
  despite success, so the caller under `set -e` aborts. A shell trailing-`A && B` exit-status
  pitfall introduced by the profile support (CC-LAB-0010). It shipped because the on-host
  scripts can't be executed in the build sandbox (recurrence of BUG-0014's root cause), and a
  fail-loud self-test can't catch an abort that precedes it.
- **Remediation:** the profile notice now uses an `if` (returns 0 with or without a profile);
  verified `up`'s no-profile tail exits 0. Swept the other `&&` sites (safe). Full RCA +
  recurrence + prior-PA-failure analysis in `docs/bugs/BUG-0015-*`; rule PA-0016. See
  CC-LAB-0012.
- **Status:** Fixed (this commit). Parts I and K passed on-host; Part J unblocked.

## 2026-09-21 — ON_HOST_RUNBOOK documented unbuilt/unverified steps as followable (BUG-0014)

- **Symptom:** the initial runbook's `[build+run]` parts (E, I, J, K) could not be followed —
  they referenced last-mile code that didn't exist and commands/outputs never run, and
  contained concrete errors (a second `auto_prepend_file` line that would silently disable
  the WAF; per-request DB fault via log-tailing; `up --profile desync` that didn't work; a
  duplicate-*identical* Content-Length "exit" that is valid HTTP).
- **Root cause:** operational docs were authored from design intent and never executed/
  verified against the real host, and the format didn't distinguish verified-runnable from
  unbuilt/aspirational steps (`[build+run]` conflated "needs building" with "runnable").
- **Recurrence:** the same root cause recurred across Parts E/I/J/K and produced BUG-0009
  (double auto_prepend), BUG-0012 (dup-CL), BUG-0013 (up --profile) + the "no Compose
  provider" incident; each was fixed piecemeal with no PA about documentation adequacy, so
  the class stayed unguarded (same failure mode as BUG-0013).
- **Remediation:** Parts E/I/J/K rebuilt into verified one-command `[run]` flows backed by
  tested code + self-testing scripts; the concrete errors fixed (BUG-0009/0012/0013); the
  runbook Legend corrected (all parts `[run]`; a `[design]` tag now marks any unbuilt/
  unverified step, which must not be written as followable). Full RCA + recurrence/prior-PA
  analysis in `docs/bugs/BUG-0014-*`; rule PA-0015.
- **Status:** Fixed (this commit). Suite 415 passed / 6 skipped.

## 2026-09-21 — On-host script defects: proxy self-test premise (BUG-0012) + compose recreate (BUG-0013)

- **Symptom (1):** `scripts/proxy_e2e.sh` step 5 reported `FAIL: the parsed path did not
  reject the duplicate Content-Length`, even though the proxy forwarded byte-exact correctly.
- **Root cause (1):** the self-test used two *identical* `Content-Length: 0` headers;
  duplicate-identical CL is valid per RFC 7230 (h11 accepts it) — only *conflicting* values
  are rejected. The script diverged from the offline unit test, which used 5/6.
- **Remediation (1):** the script now sends conflicting values (0 and 5); runbook Part I.4
  clarified. RCA `docs/bugs/BUG-0012-*`; rule PA-0013.
- **Symptom (2):** `scripts/waf_evasion_e2e.sh` / `h2_desync_e2e.sh` step 1 failed under
  podman-compose (`container name ... already in use ... use --replace`; dependent-container
  errors) and left the stack wedged.
- **Root cause (2):** the orchestration assumed `compose up` recreates a running stack in
  place on an env/profile change (a docker-compose behavior); podman-compose cannot. Same
  *class* as the earlier "no Compose provider" entry (assuming a compose capability podman
  lacks) — which was fixed in place and never captured as a PA, so the class recurred.
- **Remediation (2):** `lab/labctl.sh up` is now self-healing — on failure it `down`s (keeps
  the DB volume), force-clears wedged podman containers/pod/network, and retries `up`. Full
  RCA + recurrence/prior-PA-failure analysis in `docs/bugs/BUG-0013-*`; rule PA-0014.
- **Status:** Fixed (this commit). See CC-PROXY-0013, CC-LAB-0011. Suite 415 passed / 6 skipped.

## 2026-09-21 — Proxy on-host: leaf cert rejected (BUG-0010) + shutdown hang (BUG-0011)

- **Symptom (1):** on the host, `pytest ...test_connect_tls_tunnel_forwards_byte_exact`
  failed the TLS handshake with `ssl.SSLCertVerificationError: ... Missing Authority Key
  Identifier`. **Symptom (2):** `scripts/proxy_e2e.sh` hung at 5/6 (stopping the proxy).
- **Root cause (1):** `LocalCA` minted CA/leaf certs without SKI/AKI (and KeyUsage/EKU, and
  a DNSName SAN for IP hosts); strict OpenSSL (Fedora, Py 3.13) rejects a leaf with no AKI.
  **Root cause (2):** `AsyncProxyServer.stop()` awaited `Server.wait_closed()` unbounded,
  which on Python 3.12+ waits for active connections — a lingering connection blocked
  shutdown forever, so the proxy never exited and the script's `wait` hung.
- **Remediation (1):** `_mint_ca` adds SKI + keyCertSign KeyUsage; `_mint_leaf` adds SKI, an
  AKI from the CA public key, serverAuth EKU, a leaf KeyUsage, and an IPAddress SAN for IP
  hosts; dropped deprecated `utcnow()`. Added a skip-guarded extension-assertion test.
  **Remediation (2):** `AsyncProxyServer` tracks + cancels connection tasks and bounds
  `wait_closed()` with a 3s timeout; the proxy CLI persists flow history per-record
  (`batch_size=1`, WAL); `proxy_e2e.sh` bounds its `kill -INT` wait with a `-KILL` fallback.
- **Status:** Fixed (this commit). Full RCAs in `docs/bugs/BUG-0010-*` and `BUG-0011-*`;
  rules PA-0011, PA-0012. See CC-PROXY-0012. Suite 415 passed / 6 skipped.

## 2026-09-21 — Grey-box self-test: coverage file written but empty (pcov not collecting)

- **Symptom:** `scripts/greybox_e2e.sh` step 3 failed with "benign request recorded no
  covered lines — is pcov installed/enabled?" The side-channel file *was* written (the
  shim ran and the host↔container mount worked), but its `files` map was empty.
- **Root cause:** three independent causes, each producing empty coverage, fixed in
  sequence (the step-3 self-test caught each). (1) The `cov.php` shim gated pcov on
  `function_exists('\pcov\start')`, whose leading-backslash string form is unreliable —
  it can be false even when pcov is loaded, so the shim never called `\pcov\start()`/
  `collect()`. (2) `lab/web.Dockerfile` ran `pecl install pcov` without `$PHPIZE_DEPS`
  (autoconf/gcc/make); on a rebuild the PECL build can no-op/fail so pcov never loads,
  and a stale cached layer hid it. (3) **Decisive:** even with pcov loaded, the shim
  called `\pcov\collect(\pcov\inclusive, ['/var/www/html'])` — but pcov's inclusive
  filter is a list of *files*, not directories, so a directory matched nothing and
  `collect()` returned empty.
- **Remediation:** the shim now gates on `extension_loaded('pcov')` (unambiguous) and
  calls `\pcov\collect()` (no directory filter), keeping app files by path prefix; the
  Dockerfile installs `$PHPIZE_DEPS` before `pecl install pcov` and asserts
  `php -m | grep -qi pcov` at build time so a broken layer fails the build (and the
  changed RUN line invalidates the suspect cache). `labctl.sh exec` was added and the
  script now checks pcov is loaded in the container before the curl self-test, printing
  the exact `build --no-cache web` command if not. (cov.php is bind-mounted, so this last
  fix needs no image rebuild — just re-run the script.)
- **Remediation (sweep, PA-0002):** the `mysqli` install now carries the same build-time
  load check; no other fragile `function_exists('\ns\fn')` guards or unverified extension
  installs remain.
- **Status:** Fixed (this commit); live re-run on the host to confirm. Full RCA in
  `docs/bugs/BUG-0009-greybox-coverage-empty-fragile-pcov-guard.md`; rules PA-0008,
  PA-0009. See CC-LAB-0009 update.

## 2026-09-21 — Any credentials "authenticated" (BUG-0008): login success inferred from an anonymous cookie

- **Symptom:** `fuzzlab session print`/`crawl --identity admin` reported a `PHPSESSID`
  cookie and "authenticated as admin (1 cookie(s))" for *any* username/password —
  including a nonexistent user and mismatched identities (`broken_auth.txt`).
- **Root cause:** `SessionManager._login` treated the presence of a session cookie as
  proof of login. PHP's `session_start()` sets an anonymous `PHPSESSID` on the first
  GET (before login), so the jar was non-empty even on a *failed* login; and
  `_verify_authenticated` only checked that `base_url` (the public homepage) was "not a
  login page", which is always true. So auth success was inferred from an *ambient*
  credential the server hands to anonymous users too — a toolkit false-positive, **not**
  the lab's intended (SQLi-based) auth bypass, which plain wrong creds do not trigger.
- **Remediation:** `_login` now fails loud when the login POST response is still a login
  page (`is_login_page`) or is `401/403`, before inspecting cookies — a positive
  differential signal is required. On the lab, wrong creds now error (form re-rendered)
  and correct creds still succeed (redirect to `profile.php`). Regression tests model
  `session_start()`'s pre-login cookie (`AnonCookieLoginFetcher`). Full RCA in
  `docs/bugs/BUG-0008-login-success-inferred-from-anonymous-cookie.md`; rule PA-0007.
- **Status:** Fixed (this commit). See CC-SESS-0008. Suite 394 passed / 4 skipped.

## 2026-09-21 — Credential host-key mismatch (BUG-0007) + ground-truth path traceback

- **Symptom (1):** `fuzzlab crawl --identity admin` failed with `CredentialError: no
  credentials for identity 'admin' on host '127.0.0.1'`, even though the runbook's
  `set-credential --host 127.0.0.1:8080` had been (or would be) used.
- **Root cause (1):** the credential store keyed by the exact `--host` string
  (`127.0.0.1:8080`), but the session/browser-auth path looks credentials up by
  `urlparse(base_url).hostname` (`127.0.0.1`, no port) — the two never matched.
- **Remediation (1):** `credentials.py` normalizes the host to its bare hostname
  (`_norm_host`) on set/get/require/delete, so `127.0.0.1`, `127.0.0.1:8080`, and a full
  URL all key the same; the `require` error now prints the exact `set-credential` command.
  Runbook Part C corrected to `--host 127.0.0.1`.
- **Symptom (2):** `fuzzlab auto --ground-truth lab/ground-truth` (run from inside `lab/`)
  raised a raw `FileNotFoundError` for `lab/ground-truth/labels.json`.
- **Root cause (2):** cwd was `lab/`, so the relative path resolved to `lab/lab/...`; the
  toolkit commands assume the repo root.
- **Remediation (2):** `contract.load` raises an actionable `ContractError` (naming the
  expected path and the repo-root/absolute-path options) and `fuzzlab auto` exits cleanly
  on it; the runbook now states to run `fuzzlab` from the repo root.
- **Status:** Fixed. Full RCA (backfilled during a bookkeeping reconciliation pass — this
  entry and CC-CORE-0017 existed but the investigation doc and PA did not) in
  `docs/bugs/BUG-0007-credential-host-key-mismatch-and-ground-truth-path-traceback.md`;
  rule PA-0021 (recurrence of the BUG-0003/PA-0003 class on a different field). See
  CC-CORE-0017.

## 2026-09-21 — Automatic mode never nominated XSS (rule keyed on a post-detection label)

- **Symptom:** the live `fuzzlab auto` scored run missed every reflected/DOM XSS case
  (e.g. `search.php?q`) as a false negative, though the oracle can confirm reflected XSS.
- **Root cause:** `R-XSS-REFLECT` fired only when `sink_context` was set, but that is a
  label discovery never sets on a fresh point, so no XSS candidate was ever nominated
  for the oracle. `test_pipeline` masked it by hand-setting `sink_context="html"`.
- **Remediation:** `R-XSS-REFLECT` now nominates on location (query/body); the oracle's
  M5 types the reflection context itself and confirms (fail-closed → no FP). Pipeline
  now counts oracle-rejected candidates as negatives. Full RCA in
  `docs/bugs/BUG-0006-xss-never-nominated-in-automatic-mode.md`; rule PA-0006.
- **Status:** Fixed (this commit). See CC-AUD-0009, CC-FUZZ-0010.

## 2026-09-21 — Headless credential store crashed (`No module named 'Crypto'`)

- **Symptom:** `fuzzlab session set-credential` with `FUZZLAB_KEYRING_PATH`/
  `FUZZLAB_KEYRING_PASSPHRASE` set crashed with
  `ModuleNotFoundError: No module named 'Crypto'` (after trying `Cryptodome`).
- **Root cause:** the encrypted-file backend used `keyrings.alt`'s `EncryptedKeyring`,
  which needs PyCrypto/pycryptodome — an undeclared, uninstalled dependency. The
  intended library, `cryptography` (already installed), was never actually wired up;
  the store's tests inject a fake backend, so the real path was never exercised.
- **Remediation:** reimplemented the backend on `cryptography` (Fernet + PBKDF2),
  declared `cryptography` as a dependency, added real round-trip tests (skip when the
  native lib is broken). Full RCA in
  `docs/bugs/BUG-0005-headless-keyring-depended-on-pycrypto.md`; rule PA-0005.
- **Status:** Fixed (this commit; verified on the host after `pip install -e .`).

## 2026-09-21 — `labctl.sh up` failed: no Compose provider

- **Symptom:** on a Fedora host, `./labctl.sh up` dumped
  `Error: looking up compose provider failed / 7 errors occurred: ... docker-compose
  ... podman-compose ... executable file not found`.
- **Root cause:** the host had the `docker`/`podman` CLI (podman-docker) but no
  Compose provider package installed; `labctl.sh` assumed `docker` existing implied
  `docker compose` worked, so it invoked a provider that was not present.
- **Remediation (environment):** install a provider —
  `sudo dnf install -y podman-compose` (or `docker-compose-plugin`).
- **Remediation (repo hardening, PA-0004):** `labctl.sh` now probes each candidate
  (`docker compose`, `podman compose`, `docker-compose`, `podman-compose`) and uses
  the first that runs, and prints an install hint if none is found instead of the raw
  provider dump. Lab README + on-host runbook note the prerequisite.
- **Status:** Environment (install a provider); repo hardened. See CC-LAB-0005.

## 2026-09-21 — App DB config defaulted to `root` (repo default fixed)

- **Symptom:** `config.php` defaulted the DB user to `root`/empty; with no PFF_DB_*
  env, `mysqli_connect` died with `Access denied for user 'root'@'localhost'`. Same
  failure as the 2026-09-18 "Environment" entry below, but this is the repo default.
- **Root cause:** the committed default selected `root`, which modern MariaDB
  authenticates over the unix socket (TCP login refused), and which also disagreed
  with the lab's own dedicated `pff` user (compose/.env). The earlier incident was
  worked around only in the environment, so the repo default stayed broken.
- **Remediation:** defaulted `config.php` to the `pff` app user (never root); updated
  the app README manual setup to create `pff` and the schema import note. Full RCA in
  `docs/bugs/BUG-0004-config-defaults-to-db-root.md`; rule PA-0004.
- **Status:** Fixed (this commit; live DB connect to be confirmed on the host).

## 2026-09-21 — Oracle stored findings with full URLs (path-form mismatch)

- **Symptom:** the T2.8 scored pipeline reported `tp=0, fp=3` — every genuine,
  oracle-confirmed vulnerability counted as a false alarm.
- **Root cause:** `Oracle._write_finding` stored `candidate.url` verbatim
  (`http://localhost/product.php`) while ground truth and every other stored URL
  use path form (`/product.php`); the normalization convention lived only as a
  private helper in `store_adapter`, invisible to the oracle.
- **Remediation:** added `fuzzlab/core/urls.py::to_path` as the single home of the
  convention; the oracle and `store_adapter` both call it. Full RCA in
  `docs/bugs/BUG-0003-oracle-stored-full-urls-not-path-form.md`; rule PA-0003.
- **Status:** Fixed (this commit).

## 2026-09-21 — Schema-version assertion hardcoded, recurrence (BUG-0002)

- **Symptom:** `tests/test_harness.py::test_score_from_store_and_metrics` failed
  (`assert 3 == 2`) after adding migration 3 (T1.7) — a correct, intended schema change
  turned green tests red.
- **Root cause:** another test hardcoded the schema head version instead of deriving it
  from the migration registry — the same class BUG-0001 fixed, but BUG-0001's fix only
  touched the tests failing at the time and never swept for other instances, leaving this
  one latent until migration 3 tripped it.
- **Remediation:** derived the assertion from `migrations.MIGRATIONS`
  (`max(v for v, _ in migrations.MIGRATIONS)`); swept `tests/` for other hardcoded
  schema-version literals (none remained). Full RCA in
  `docs/bugs/BUG-0002-schema-version-hardcoded-recurrence.md`; rule PA-0002 (sweep the
  codebase for a bug class's other instances whenever a preventive action is added).
- **Status:** Fixed (commit `30ea97d`+ range). Suite 71/71 passed.

## 2026-09-21 — Schema-version assertions hardcoded in tests (BUG-0001)

- **Symptom:** `tests/test_core_foundations.py::test_migrations_are_idempotent` and
  `test_store_run_and_body_roundtrip` failed (`assert 2 == 1`) after adding migration 2
  (self-describing findings, T0.7) — a correct, intended schema change turned green tests
  red.
- **Root cause:** both tests asserted the schema head version as the literal `1` instead of
  deriving it from the `MIGRATIONS` registry, the value's actual source of truth.
- **Remediation:** both assertions now derive the head from the registry. Full RCA in
  `docs/bugs/BUG-0001-schema-version-hardcoded-in-tests.md`; rule PA-0001 (don't hardcode a
  value a source-of-truth constant/registry already defines).
- **Status:** Fixed (commit `30ea97d`, CC-CORE-0003). Suite 30/30 passed.

## 2026-09-18 — `build_sql_db.py` / auditor coverage

- **Symptom:** the auditor implemented 28 rules but only ever ran 7; all findings
  were grouped as `references/(unmapped)/`.
- **Root cause:** the indicator database defined only the original 7 indicator
  types and had no `reference` column, so 21 rules had no matching row and never
  executed.
- **Remediation:** updated `build_sql_db.py` to define all 28 indicator types
  (matching the rule registry one-to-one) and a `reference` column mapping each to
  its `references/` folder; regenerated `php_indicators.db`. Verified every rule
  runs with no unhandled or failed rules.
- **Status:** Fixed (commit `bc096b4`).

## 2026-09-18 — `spider.py` / `fetcher.py` browser navigation

- **Symptom:** navigating a headless-browser page to an error-status or
  non-navigable endpoint (e.g. `api/products.php` returning 500) raised
  `ERR_HTTP_RESPONSE_CODE_FAILURE` and the URL was dropped.
- **Root cause:** Chromium refuses to render some responses; the code treated any
  `goto` failure as a lost page.
- **Remediation:** wrapped the render in a try/except that falls back to a plain
  HTTP request, so the URL is still recorded and audited.
- **Status:** Fixed.

## 2026-09-18 — `spider.py` local-scope check

- **Symptom:** the crawler recorded only the start page and never followed any
  links when crawling a site on a non-default port (e.g. `:8080`).
- **Root cause:** `_is_local` compared `urlparse(url).netloc`, which includes the
  port, against bare hostnames, so every link was judged non-local and skipped.
- **Remediation:** compare `urlparse(url).hostname` instead, which excludes the
  port.
- **Status:** Fixed.

## 2026-09-18 — Playwright install (dev environment)

- **Symptom:** `pip install playwright` failed to find any distribution; later the
  browser launch failed with "Executable doesn't exist" for a build the managed
  version expected.
- **Root cause:** the package index host was excluded from the proxy, so pip could
  not reach it; and the installed Playwright version expected a browser build that
  did not match the one already present.
- **Remediation:** forced pip through the agent proxy to install the package, then
  either ran `playwright install chromium` or pointed the launcher at an existing
  browser via a `PLAYWRIGHT_CHROMIUM_EXECUTABLE` override.
- **Status:** Environment.

## 2026-09-18 — Live site returned HTTP 500 (Fedora deployment)

- **Symptom:** `http://localhost/puppy-fort-factory/` returned "500 Internal
  Server Error"; the Apache error log did not show the cause.
- **Root cause:** on Fedora, PHP runs under PHP-FPM, so the fatal error was logged
  in the PHP-FPM log, not the Apache log. The underlying failure was the database
  connection (see the two entries below), not a PHP parse error.
- **Remediation:** read the PHP-FPM log to get the real error, then fixed the
  database connection issues below.
- **Status:** Environment.

## 2026-09-18 — Database connection "Permission denied" (SELinux)

- **Symptom:** PHP-FPM logged `mysqli_sql_exception: Permission denied` when the
  app tried to connect to the database.
- **Root cause:** SELinux (enforcing on Fedora) blocks the web server from opening
  a network connection to the database by default.
- **Remediation:** enabled the boolean with
  `sudo setsebool -P httpd_can_network_connect_db on`.
- **Status:** Environment.

## 2026-09-18 — Database connection "Access denied for user 'root'"

- **Symptom:** after the SELinux fix, PHP-FPM logged
  `Access denied for user 'root'@'localhost'`.
- **Root cause:** on Fedora, MariaDB's `root` account uses socket authentication,
  so it cannot be reached over TCP with a password regardless of the value set.
- **Remediation:** created a dedicated application user
  (`CREATE USER 'pff'@'127.0.0.1' ... GRANT ALL ON puppy_fort.*`) and pointed the
  app's `config/config.php` at it; imported the schema.
- **Status:** Environment.

## 2026-09-18 — Web root returned a 403 (directory index)

- **Symptom:** browsing `http://localhost/` returned an Apache autoindex 403
  (`AH01276: ... No matching DirectoryIndex`).
- **Root cause:** the web root had no index page and directory listing is
  disabled; the app was in a subdirectory.
- **Remediation:** changed `deploy.sh` to deploy the app to the web root by
  default, so `index.php` sits at `/`. (Harmless before that, since the app was
  reached via its subdirectory URL.)
- **Status:** Fixed (commit `5f87d80`).

## 2026-09-17 — `blind_sqli_fuzzer.py` circular labeling

- **Symptom:** the generated training label was not an independent signal; it was
  effectively derived from the payload's own class.
- **Root cause:** the original draft set the "vulnerable" label from the
  is-malicious flag plus timing, so the label leaked the feature it was meant to
  predict.
- **Remediation:** detection is now computed from measured timing alone (median of
  repeats vs baseline), and the payload label is recorded as a separate column, so
  features and ground truth stay independent.
- **Status:** Fixed (commit `814cdd7`).

## 2026-09-17 — `blind_sqli_fuzzer.py` missing import

- **Symptom:** the original draft would crash immediately with a `NameError`.
- **Root cause:** it used the `requests` library throughout but never imported it.
- **Remediation:** added `import requests` with a friendly guard if the package is
  missing, and required an explicit target plus an `--authorized` flag.
- **Status:** Fixed (commit `814cdd7`).

---

## Open / low priority

- `fetcher.py` `--append` occurrence counter: repeated `--append` runs recompute
  `occurrences` as the current row count (1 after de-duplication) before the new
  audit bumps it, so cumulative counts across runs are not preserved. The default
  (fresh) run is unaffected. **Status:** Open (low priority).
