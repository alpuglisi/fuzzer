# BUG-0148 — the browser login found a login page only by an exact path word

- Date: 2026-10-15
- Status: fixed (CC-SESS-0025; FR-SESS-21)
- Severity: high. An authenticated crawl cannot start when the login is not found, so
  everything behind the login is never reached. On the first held-out lab it reached
  0 endpoints. The same defect blocked the default login pages of Rails, Devise, ASP.NET
  Identity and Django admin, and any login opened by a "Log in" button or menu.

## Description
The browser login (FR-SESS-19) looked for a login form on the base page and then only
on routes whose **last path segment is exactly** a login word (`login`, `signin`,
`sign_in`, `sign-in`, `log_in`, `log-in`, `logon`). It never used the page's own "Log
in" / "Sign in" link or button, the signal every web stack shares. When it did reach a
framework's default login page, its form gates refused several of them for a word on
the route or action. The requests-side discovery tried four fixed paths only.

## Where encountered
The blind held-out lab, 2026-10-15 (HOLDOUT-SPA). `fuzzlab crawl --identity ...`
failed with:

> no login form was found in the browser (no rendered form with a password control on
> the base page or a login route)

The authenticated crawl never started. That message is the only lab fact this fix
uses; the lab's routes, labels and source were not read. The first version's tests did
contain one route and label pair that mirrors that lab (found in review B, B1); it was
removed in ef477f0, and no fixture now copies the lab's shape (PA-0154(4)).

## What it caused to fail
- No authenticated discovery or fuzzing on any app whose login route has no exact
  login segment, or whose login opens in place (modal, drawer, menu, a button that
  pushes a route).
- Standard framework login pages refused even when reached (measured before the fix,
  below): Django admin (`admin`), Rails `session/new` (`new`), Devise `users/sign_in`
  (`users`, then its `user[remember_me]` hidden field), ASP.NET Identity
  `Identity/Account/Login` (`account`).
- A pre-rendered hidden login modal ended the whole login with a Playwright
  `TimeoutError` instead of a refusal (measured, section 0).
- The failure did not say what was tried.

## What the bug was identified to be
1. `browserlogin._login_routes` kept a route only when its last segment was in
   `detect._LOGIN_SEGMENTS`, a third copy of login vocabulary with a narrower rule than
   `detect.looks_like_login_url` (which also has the final-token and
   `session(s)/new` rules). It imported the private name `_LOGIN_SEGMENTS`.
2. No affordance signal: links and buttons labelled "Log in" / "Sign in" were never
   read, so a login on a path with no login word, or one opened in place, was missed.
3. The form gates (`account_word_reason`, `store_adapter.credential_change_reason`
   via the route standing in for the action, `formnav.settings_word` in
   `spa.form_refusal`) refused framework defaults: `new`, `users`, `account`, `admin`
   on the route or action, and Rails' checkbox companion `user[remember_me]` as a
   "hidden object selector".
4. `_pick_form` asked `page.is_enabled` of a hidden form's password control. Measured:
   `spa.FORMS_JS` re-marks a hidden form's controls for an enclosing container, so the
   first form's selector no longer exists and `is_enabled` waited out its timeout and
   raised out of the login.
5. `SessionManager._discover_login_form` tried the base page and four fixed paths
   (`login`, `login.php`, `signin`, `users/login`), never what the page links to.
6. Before the login window, `LoginGate.request_refusal` refused nothing, so clicking
   an affordance could have sent a write (the gap reviewer B found in design v1).

## Measurements (CLAUDE.md item 8; design section 0)
Real Chromium (Playwright 1.63, the pinned build), synthetic pages on a loopback port,
the project's own guard (`navguard.guard_page`) and `spa` scripts. Script:
`b148-lane/measure.py` in the session scratchpad; output `measure.out`.

| # | Question | Result | Design consequence |
|---|---|---|---|
| 1 | `FORMS_JS` and `page.is_enabled` on a `display:none` pre-rendered modal form | `FORMS_JS` returns the hidden form (fi 0) **and** the `<body>` as a second container whose one shown button is the modal's "Log in" opener (fi 1); the body container re-marks the same controls, so fi 0's ids no longer exist. `is_enabled` on fi 0's password: **raised `TimeoutError`** (waits for the missing mark). On fi 1's: `True` (a hidden control is enabled). `is_visible`: `False` for both. After the opener is clicked: one form, button "Sign in", visible and enabled. | Section 4 holds: refuse on `is_visible` (checked first, it never waits). The re-marking is pinned by a strict xfail (spa.py is another lane's file). |
| 2 | `LABELS_JS` / `innerText` on hidden menu items and `aria-hidden` icons | `display:none` and `visibility:hidden` items: labels and `href` read (`["Log in","",""]`). An `aria-hidden` icon span: text "Sign in". An icon-only link with `aria-label`: `["", "Sign in", ""]`. A Font Awesome private-use glyph stays in the text (`"Log in"`), and `name_tokens` drops it (`log`, `in`). An icon-only account button with no label: `["","",""]`. | Section 3 holds: links are read visible or not; the label rule works on icon-decorated labels; "empty with an icon" needs an icon flag (added to the marking script). |
| 3 | `click_vetted` on a hidden and on a covered control | Hidden: `TimeoutError` after the trial probe. Covered by an overlay: Escape, still covered, dispatched (`el.click()`), result `"dispatched"`. | Section 3 holds: per-candidate errors are caught; a hidden click candidate is refused before the click (no probe wait). |
| 4 | Does `request_refusal` see a write fired on page load, and one fired by a click, before the window? | Both seen (`POST /api/onload`, `POST /api/clicked`); refusing them aborted both; the server received **no** POST. | Section 5 holds. |
| 5 | What the `window` hook sees for click-triggered navigations | A link click and a `location.href` button: a GET with `navigation=True`, aborted, the page stays put, nothing reaches the server. A `pushState` button: no request; the URL changes and the rendered form is there. A form POST: a POST navigation, aborted. | Section 3 holds: capture, don't follow; a `pushState` login is read in place. |

No measurement contradicts the design.

**Before and after, the framework matrix** (`b148-lane/matrix_before_after.py`, the
same fixtures run against the base tree `13b1cff` and against the fix):

| Shape | Browser before | Browser after | Requests side before | after |
|---|---|---|---|---|
| Django `LoginView` (`/accounts/login/`) | ok (exact segment) | ok | not found | found |
| Django admin (`/admin/` -> `/admin/login/`) | refused (`admin`) | ok | found | found |
| Rails 8 generator (`/session/new` -> `/session`) | not found | ok | not found | found |
| Devise (`/users/sign_in`) | refused (`users`) | ok | not found | found |
| ASP.NET Identity (`/Identity/Account/Login`) | refused (`account`) | ok | not found | found |
| Spring Security (`/` -> `/login`) | ok | ok | found | found |
| Laravel Breeze (`/login`) | ok | ok | found | found |
| Vue hash link (`#/sign-in`) | ok | ok | - | - |
| `routerLink` button, `pushState` to a route with no login word | not found | ok | - | - |
| Account menu rendered on open | not found | ok | - | - |
| Bootstrap hidden modal | **`TimeoutError`** | ok | - | - |
| Decoy `xss_login` linked before `/login` | ok | ok (decoy never filled) | - | - |

## Root cause analysis
**Method: Five Whys**, from the symptom.

1. *Why was no login form found?* The candidate rule accepted only an exact login
   segment, and the page's own "Log in" control was never read.
2. *Why only an exact segment?* `_login_routes` reimplemented a login-word rule beside
   the SP-16 owner, narrower than it, with its own copy of the vocabulary (a private
   import), so widening or fixing one never reached the other.
3. *Why was the path the only signal?* Discovery was designed as a property of URL
   vocabulary, and checked only on labs whose login route happened to be `login` (the
   development lab's `#/login`, bWAPP's `login.php`). The checks that existed (PA-0122(4),
   PA-0301(1)) test a rule against vocabulary; none tests a rule end to end against
   other technologies' defaults.
4. *Why did the gates refuse standard login pages?* Each gate's word list was written
   to refuse account-management forms and was checked for missed account forms, never
   for false refusals of real login pages. `_CHANGE_TOKENS` even listed its accepted
   false positives (`/sessions/new`, `/users/sign_in`, `/admin/login`,
   `/account/login`) as "a missed finding, never a safety risk", a judgement made for
   the import side and then inherited by the login path, where the cost is the login
   itself.
5. *Why did no review catch it?* No rule requires a "find" rule to have a primary
   signal every technology shares, nor every keyword rule to be tested through every
   downstream gate against a table of framework defaults. The design for this very fix
   (v1) repeated the pattern: it fitted its first fixture to the failing lab and missed
   the gate refusals (F-052).

**Root cause:** rules that *find* something (here a login page) were built on a word
list fitted to the labs at hand, not on the signal every technology shares (the page's
own login affordance); and keyword rules (find, allow, deny) were never tested end to
end through their downstream gates against other frameworks' defaults. The vocabulary
was also copied rather than owned.

## Corrective action
CC-SESS-0025, per design v2 sections 1-8. Commits on branch `bug-0148`: 223518b (the fix), c169a06 (two guard findings of the first harness run), 2aef9ee (bookkeeping), ef477f0 (combined reviews A and B; see "Combined review" below).
- **SP-16, one owner** (`detect.login_path_match`, modes `logout` and `candidate`):
  `looks_like_login_url` is its thin wrapper, unchanged for its callers; rank 1 (whole
  segment, `session(s)/new`) and rank 2 (final token, final login pair; own-case
  tokens, so `UserLogin`); no prefix or suffix rule. Public vocabulary
  (`LOGIN_WORDS`, `LOGIN_PAIRS`, `LOGIN_ENDPOINT_TOKENS`, `USERNAME_HINT`);
  `browserlogin.LOGIN_PATH_TOKENS` / `LOGIN_PATH_PAIRS` are those sets.
- **Discovery by affordance** (`browserlogin._Discovery`): affordances read with
  `spa.LABELS_JS`, form submitters excluded, `detect.login_affordance` then
  `spa.submitter_glyph` / `spa.label_refusal`; links visited with `navguard.navigate`;
  other controls clicked with `spa.click_vetted` under the reveal window
  (`guard_page(window=LoginGate.window_refusal, ws_hold=LoginGate.ws_hold)`, over
  `spa.window_request_refusal`), navigations captured and visited next; restore
  before each later click; one level of an account menu; per-candidate errors caught.
- **Order and cap:** base page, affordances, rank 1, rank 2; at most 5 distinct.
- **Hidden forms refused** (`is_visible` first, errors caught).
- **Gates:** route/action overrides for `new`, `users`, `account`, `admin` when that
  location is a login page's own name (review A, A1); hidden fields are framework tokens on the login path (review B, B2(b)).
- **Pre-window writes aborted**, counted and named (host and path).
- **Requests side:** `detect.login_links` (affordance links, then rank-1 links) before
  the fixed paths.
- **Diagnosis** lists candidates, refusals, aborted writes, an off-scope affordance
  (`--auth-origin`), identifier-first, and "no login affordance found (English labels
  only)".

Tests: `tests/test_login_discovery.py` (pure ranks and invariant, affordance rule,
gate overrides and what they keep, pre-window gate, the private-vocabulary AST guard
and its synthetic offenders, the framework matrix through the browser and the requests
side, negatives, strict-xfail residuals); fixtures `tests/_framework_login_fixture.py`
from framework documentation defaults only.

**Deviations from design v2** (each narrower or required by the design's own matrix):
1. Section 2's override is judged **per location**: the route's words are dropped only
   when the route names a login, the action's only when the action does. The design's
   "route or action" wording would have accepted a login-route form posting to
   `/users/new`, which an existing test refuses.
2. Section 2 gained one rule the matrix found: a hidden control that has the name of a
   checkbox in the same form is that checkbox's unchecked value (Rails `check_box`,
   ASP.NET), not an object selector. Without it Devise's default page is refused. *(Replaced in ef477f0 by review B's general rule, B2(b).)*
3. Section 5 reverses two assertions of `tests/test_session_browser_login.py` that
   pinned "nothing is refused before the window"
   (`test_the_request_side_gate_needs_the_window`,
   `test_every_write_to_an_account_endpoint_is_refused_in_the_window`); they now pin
   the new rule. Every other test of that file is unchanged and green.
4. A pre-window write that happens after the login has landed (inside the window) is
   not aborted: the window's own rule (account endpoints only) is unchanged, as the
   design says.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for the same bug or the same
root cause (a rule fitted to the labs at hand; a keyword rule not tested across
technologies; a mechanism re-derived instead of shared):
- **BUG-0122 / PA-0122** (logout read from any redirect containing "login"): same
  vocabulary, same owner (SP-16). PA-0122 made rules anchored and its item (4) checks
  each rule "against the lab's own vocabulary".
- **BUG-0301 / PA-0301** (the destructive rule missed Juice Shop's `dataerasure` and a
  verb-object pair): a keyword rule validated only against the spellings it was
  written for.
- **BUG-0124 / PA-0124** (an open redirect missed because the candidate rule keyed on a
  parameter-name list): a *finding* rule built on names.
- **BUG-0110 / PA-0111** (a login form serialised unlike a browser, checked only
  against our own lab): behaviour fitted to our own lab; PA-0111(3) asks for one
  captured third-party fixture.
- PA-0003 / SP-16 (one implementation per convention): `_login_routes` was a second,
  narrower implementation with a copied vocabulary.

Result: a recurrence of the same root cause, four times over.

## Prior-preventive-action failure analysis
- **PA-0122 (BUG-0122) — wrong target, and item (4) fits to the lab.** PA-0122 governs
  rules that *decide* session or auth state from a URL, and its guard looks for
  substring tests. A rule that *finds* a page by an exact segment is anchored and
  passes it; nothing asked whether path vocabulary was the right signal. Item (4)
  ("checked against the lab's own vocabulary") made the lab the reference, the very
  fit this bug is. **Superseded in part by PA-0154(b).**
- **PA-0301 (BUG-0301) — too narrow.** It checks deny rules against unforeseen
  spellings (false negatives) of lab routes. This bug is the mirror: allow and find
  rules, and deny rules that refuse a real login page (false positives), against other
  frameworks. A per-rule spelling scan cannot see a gate downstream refusing what the
  rule found.
- **PA-0124 (BUG-0124) — fixed per mechanism, not generalised.** It replaced one
  name-keyed classifier with a value-shape table, but stated no rule that a finding
  rule needs a technology-shared primary signal, so the next finding rule (login
  discovery) was free to be name-only.
- **PA-0111 (BUG-0110) — one third-party fixture is not a matrix.** Its item (3)
  requires at least one captured third-party shape; login discovery had Juice Shop's
  shape, the lab it was fitted to. One fixture proves fit to that one.
- **PA-0003 / SP-16 — not enforced against copies of vocabulary.** The defined-once
  guard checks function names; a module re-implementing the rule under another name
  over a privately imported constant passed it.

## Preventive action
**PA-0154** (`docs/PREVENTIVE_ACTIONS.md`): supersedes PA-0122(4); strengthens
PA-0301(1), PA-0003 and SP-16.
- (a) A rule that **finds** something (a login page, a parameter, a route) has a
  primary signal every technology shares (a UI affordance, an observed request). A
  word list may only rank or add candidates.
- (b) Every keyword rule (allow, deny or discovery) is tested end to end, through every
  downstream gate, against a table of framework defaults from framework documentation,
  never from a lab.
- (c) No module imports another module's private vocabulary (AST guard, with a reasoned
  allowlist of the known instances in files this change may not edit; the login
  vocabulary has no entry).
- (d) No fixture copies the shape of the lab that failed.

### PA-0002 sweep (by mechanism: keyword rules that find, allow or deny a login, and private vocabulary imports)
| Site | Class | Disposition |
|---|---|---|
| `browserlogin._login_routes` (exact segment) | find by word list | **fixed**: affordance first, then `login_path_match` ranks |
| `browserlogin.LOGIN_PATH_TOKENS` / `LOGIN_PATH_PAIRS` (a copy) | copied vocabulary | **fixed**: derived from `detect` |
| `browserlogin` imports `_LOGIN_SEGMENTS`, `_USERNAME_HINT` | private vocabulary import | **fixed**: public names; AST guard |
| `login_form_refusal` (via `account_word_reason`, `credential_change_reason`, `form_refusal`'s `settings_word`) refusing `new` / `users` / `account` / `admin` | deny rule refusing framework defaults | **fixed** for a location that names a login; framework matrix test |
| `store_adapter._object_selector` on a checkbox companion (`user[remember_me]`) | deny rule refusing a framework default | **fixed** in the login path: after the login-shape and account-word gates, hidden fields are not judged as object selectors (review B, B2(b); replaces the first version's checkbox-companion rule); the import-side rule is unchanged |
| `_pick_form` waiting on a stale mark of a hidden form | a hidden login stops the search | **fixed**: `is_visible` first, errors caught |
| `manager._discover_login_form` fixed paths only | find by word list | **fixed**: `detect.login_links` first; fixed paths kept as the fallback |
| `store_adapter._CHANGE_TOKENS` (`admin`, `account`, `users`, ...) on the import side | deny rule | **not changed** (design section 2: the import-side rule is unchanged); its stated accepted false positives remain an import-side choice |
| `spa.FORMS_JS` re-marks a hidden form's controls for an enclosing container | stale marks | **not fixed**: `spa.py` belongs to a concurrent lane. Pinned by `tests/test_login_discovery.py::test_residual_forms_js_marks_stay_unique_for_a_hidden_form` (strict xfail) |
| `spa.FORMS_JS` does not read shadow roots | find | residual, strict xfail `test_residual_a_shadow_dom_login_form` |
| `spa._LABELS_FN` icons are Angular Material only (`mat-icon`, `.material-icons`) | fitted to one component library (F-014) | **listed**: measured that a Font Awesome glyph stays in the text and `name_tokens` drops it; other icon fonts whose glyph is a word would be read as text. `spa.py` is another lane's file |
| `spa.REVEAL_JS` toggle words and Material selectors | fitted to one component library (F-014) | **listed** for the spa.py owner |
| `spa.scan_routes` / `scan_query_params` on by default | reading the app's code (F-014) | **listed**: follow-on "retire script route scanning" |
| `spa.py` imports `store_adapter._FILLERS`, `_TEXT_FILLER`; `harness/auto.py` imports `strategies._TIMING_TEMPLATES`; `labgen/.../django_live_boot.py` imports `live_boot._NO_REDIRECT_OPENER` | private vocabulary import | **listed** in the guard's allowlist with reasons (files owned by another lane or out of scope); a stale entry fails |
| `spa.label_refusal` imports `browserlogin._account_hit` (a private function) | private import | **debt** (review B, B5): a function, not vocabulary; the guard (`tests/test_private_vocabulary.py`) judges constants |
| `detect._USERNAME_HINT` (a substring regex) | ranks controls already found | **kept**: it picks among the one login-shaped form's controls, never finds a page (BUG-0121 owns it) |
| `detect.find_login_form` (requests side) applies no `login_form_refusal` | gate-less path | **listed**: unchanged behaviour; it now also sees affordance and rank-1 pages |
| `manager` assumes `urljoin(base, "logout")` as the logout URL | fitted path | **listed**: follow-on below |
| `store_adapter._CHANGE_TOKENS`, `formnav.SETTINGS_WORDS`, `browserlogin.ACCOUNT_WORDS` on the import side | existing keyword rules never run through a framework matrix | **debt** under PA-0154(2) (it binds new or changed rules); not changed here |
| `account_endpoint_reason` (the in-window write gate) treats `auth`, `session` or `token` in a path as a login token, so a POST to `/auth/users/` (a Djoser-style registration API) is not refused in the window (review A, A1) | endpoint vocabulary too wide for a deny exception | **listed**: unchanged behaviour since CC-SESS-0021; the form gates no longer accept such a form (A1), which closes the path this fix opened. Follow-on |
| `harness/auto.py` reads `strategies.SqliBooleanStrategy._FAMILIES` | private class constant | **listed** in the guard's allowlist (another lane's file) |
| `probesender.py` `redirect_is_logout` | SP-16 caller | **unchanged** (logout mode identical; tested over a corpus) |

### Named follow-ons
- A login found only through a protected page's 401 or 302.
- OIDC code-flow login, and tokens kept in `sessionStorage`.
- Identifier-first (two-step) login.
- Login vocabulary by language.
- Shadow DOM, and clickable `div`s with no role.
- The assumed `logout` path (`manager.py`: `urljoin(base_url, "logout")` in `_login`,
  `_browser_login_state` and the persisted state).
- Retiring script route scanning (F-014).
- `spa.FORMS_JS`'s re-marking of a hidden form (pinned above).

## Combined review (reviews A and B of the build; fixed in ef477f0)
| Item | Finding | Disposition |
|---|---|---|
| A1 | The override used the endpoint vocabulary: `/auth/users/`, `/auth/account`, `/auth/admin/users`, `auth/users/new` were accepted | **fixed**: `names_login_page` (rank 1 on that location only); the four are negatives in `test_the_override_keeps_every_other_refusal`; the matrix still passes |
| A2 | The requests side took the first password form of a linked page | **fixed**: `login_form_core_refusal` is the one gate both paths call; `detect.login_forms` offers every form; `test_the_requests_side_never_fills_a_registration_form_before_the_login` |
| A3 | A menu's `href="#"` was visited as a link | **fixed**: the same-page check at both levels; `account-menu-hash-link` shape |
| A4 | The logout-parity test compared the function with itself | **fixed**: against a frozen copy of the 13b1cff rule over a corpus |
| A5 | WebSocket messages held only during clicks | **fixed**: held for the whole pre-window phase |
| A6 | `OPTIONS` (and `HEAD`) aborted before the window | **fixed**: they pass; the GraphQL-POST cost is stated in FR-SESS-21 and the diagnosis |
| A7 | A failed return to the base page ended the login | **fixed**: caught; path candidates and the diagnosis follow |
| A8 | `input[type=button]` was not an affordance | **fixed**; `input-button-opener` shape |
| A9 | A rank-2 app page is filled when nothing better is found | **residual**, pinned: `test_residual_a_rank_2_decoy_alone_is_never_filled` (strict xfail) |
| A10 | No discovery time budget | **fixed**: `DISCOVERY_BUDGET_S` (60 s); `test_the_search_stops_at_its_time_budget_with_a_diagnosis` |
| A11 | The guard missed attribute access | **fixed** (with B5) |
| A12 | The `FORMS_JS` re-marking needs its own number | **done**: BUG-0151 / PA-0157; the strict xfail stays |
| B1 | A lab-mirroring route and label pair in the tests | **fixed**: neutral compounds (`memberlogin`, `customerlogin`), the decoy renamed (`exercise_login`), the corpus's lab page names replaced; line 26 corrected |
| B2(a) | Exact-label affordances missed "User Login", "Login / Register", ... | **fixed**: a label containing a login word or pair, no logout word; account words waived in the label gate. **Deviation:** a label that only *contains* one ranks after the rank-1 path candidates (an exact one before them). Without it the decoy test failed: "Exercise: login form" became an affordance, and its login-shaped form got the credentials before `/login`, which the form gates cannot stop |
| B2(b) | Drupal and Keycloak refused on hidden fields | **fixed**: hidden fields are not judged as object selectors on the login path (they are still judged for account and destructive words); replaces the checkbox-companion rule |
| B2(c) | Drupal, Keycloak and WordPress in the matrix | **done**, from their documented default forms |
| B2(d) | Redirect variants, an absolute action, Moodle | **done**: Rails `require_authentication` and Devise `authenticate_user!` redirects, Laravel's absolute action, Moodle `login/index.php` (rank 1) |
| B2(e) | What still fails | strict xfails and FR-SESS-21 residuals |
| B3 | Reads sent as POST are aborted before the window | **residual**: `test_residual_a_graphql_query_before_the_login` (strict xfail); `TODO(SP-37)` at the rule for the integration |
| B4 | The guard ran with the Chromium matrix | **fixed**: `tests/test_private_vocabulary.py` |
| B5 | Attribute access and relative imports | **fixed**, each with a synthetic offender; class constants read across modules too (`SqliBooleanStrategy._FAMILIES` listed); private rule functions recorded as debt |
| B6 | Icon-ligature words in `DISCLOSURE_WORDS` | **fixed**: `LABEL_FILLER` plus user, profile, me, menu; the `aria-haspopup` / `aria-expanded` signal decides |
| B7 | PA-0154 wording | **fixed**: PA-0124 and PA-0111 named; item 2 scoped to new or changed rules, existing ones listed as debt; items 1 and 4 stated as review rules |
| B8 | Bookkeeping | **done**: CC-SESS-0025's counts; the measurement output quoted below; commit hashes above |
| B9 | `[role=tab]`, `<summary>`, same-origin iframes | **residuals**, strict xfails |
| B10 | Do not edit `docs/claude_juicelab_failures.md` | not edited |

### Measurement output (section 0, condensed; ports replaced)
```
{"1_hidden_modal": {"forms_found": 2, "marked_ids_now": ["r1f1b", "r1f1c0", "r1f1c1"],
 "is_enabled_hidden_form0": "raised TimeoutError: Page.is_enabled: Timeout 2000ms exceeded.",
 "is_visible_hidden_form0": false, "is_enabled_hidden_form1": true,
 "is_visible_hidden_form1": false, "is_visible_after_open": true,
 "after_open_visible_enabled": [true, true]},
 "2_labels": {"li": [["Log in", "", ""], false], "vis": [["Sign in", "", ""], false],
  "icon": [["Sign in", "", ""], true], "icononly": [["", "Sign in", ""], true],
  "srtext": [["Log in", "", ""], true], "acct": [["", "", ""], true]},
 "3_click_vetted": {"hidden": {"raised": "TimeoutError",
  "first_line": "Page.click: Timeout 3000ms exceeded."},
  "covered": {"result": "dispatched", "clicked": "covered"}},
 "4_prewindow_writes": {"request_refusal_saw": [["POST", "/api/onload"],
  ["POST", "/api/clicked"]], "server_received_posts": []},
 "5_click_navigations": {
  "link": {"window_saw": [["GET", "/accounts/login/", true]], "url_after": "/nav",
   "server_received": [], "password_forms_after": 0},
  "go": {"window_saw": [["GET", "/users/sign_in", true]], "url_after": "/nav",
   "server_received": [], "password_forms_after": 0},
  "push": {"window_saw": [], "url_after": "/signin", "server_received": [],
   "password_forms_after": 1},
  "post": {"window_saw": [["POST", "/do", true]], "url_after": "/nav",
   "server_received": [], "password_forms_after": 0}}}
```
