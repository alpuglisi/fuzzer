# BUG-0301 — The destructive rule missed Juice Shop's GET password change and data erasure

- Date: 2026-10-15
- Status: open — recorded and pinned; the corrective action is deferred to the owner of
  the locked `fuzzlab/core/urls.py` (CC-CORE-0301). Pinned by strict xfails
  (PA-0054(3)) in `tests/test_destructive_routes_external_labs.py`.
- Severity: medium (latent). Neither route is captured by a crawl today (see the
  compensating controls below), but an imported change-password URL, or the
  server-rendered erasure form once crawled, would be fuzzed: every probe of the first
  changes the session user's password, and every probe of the second files an erasure
  request and clears the session's token cookie.

## Description
`core.urls.destructive_reason` (and `transaction_reason`) return None for two Juice Shop
routes that rewrite account state:
1. **`GET /rest/user/change-password?current=a&new=b&repeat=b`**
   (`routes/changePassword.ts`, wired at `server.ts:625`). It changes the bearer's
   password. `current` is optional server-side (`if (currentPassword && …)`), so a
   replayed or fuzzed URL changes the password without it. The rule tokenises the path
   to `rest user change password` and the query names `current new repeat`: no token is
   in `DESTRUCTIVE_TOKENS`, and no `DESTRUCTIVE_PAIRS` entry is `(change, password)`.
2. **`/dataerasure`, GET and POST** (`routes/dataErasure.ts`, `server.ts:684`). The GET
   renders `views/dataErasureForm.hbs`; its POST inserts a `PrivacyRequest` with
   `deletionRequested: true` and clears the `token` cookie. The path is one token,
   `dataerasure`, and `erasure` is not `erase`. The form (two text fields, an
   unnamed "Delete User Data" button) passes `store_adapter.form_skip_reason`, so a
   crawl that reached the page would import the POST and fuzz `email` and
   `securityAnswer`.

## Where encountered
The PA-0114 enumeration of Juice Shop's destructive and state-rewriting routes from its
source, done before adopting it as a permanent lab fixture (design rev 2 §5.6,
`juice-catalogue-notes.md`), with the rule functions run in-process. Re-verified on
`cdde39f` in this lane:
`destructive_reason(...)` and `transaction_reason(...)` are None for both URLs,
`check_send_url(url, method="GET")` does not raise, and `form_skip_reason` of the real
`dataErasureForm.hbs` form (fetched from the juice-shop repository) is None.

## What it caused to fail
- **NFR-CRAWL-safe** (deny-list destructive actions): the crawler's link gate would
  visit `/dataerasure`, and its form gate would import the erasure form.
- **NFR-FUZZ-safe** (destructive actions never fuzzed): the send gate
  (`check_send_url`) lets both URLs through.
- **PA-0114(1)**'s table for Juice Shop: two of its endpoints are not refused.
Latent: no run has sent either (the live crawl never reached them; Lane A's live pass
asserts that, design §5.6).

## What the bug was identified to be
The rule matches **whole tokens and listed adjacent pairs** only. An app that spells an
action as a compound (`dataerasure`), as a noun form of a listed verb (`erasure` for
`erase`), or as a verb-object pair the pair list does not name (`change` + `password`)
passes it.

## Root cause analysis
Five Whys:
1. *Why was `/dataerasure` not refused?* Its only token is `dataerasure`; the rule
   compares whole tokens, and neither `dataerasure` nor `erasure` is in
   `DESTRUCTIVE_TOKENS`.
2. *Why was the change-password URL not refused?* `change` and `password` are each
   harmless alone, and the pair list holds only the BUG-0114 `update`/`upgrade` shapes
   and sign-out spellings.
3. *Why did the lists not have them?* Each list entry was added for one app's spelling
   when that app was adopted (BUG-0111: common verbs; BUG-0114: bWAPP's `update.php`,
   `insert`). PA-0114 enumerates the new app's endpoints and checks each against the
   rule, but the rule itself never generalises past the spellings seen.
4. *Why was the gap not caught by a check?* No check runs the rule over spellings it
   was not written for: no test feeds it compound tokens or verb-object pairs, and
   PA-0022's "check a keyword heuristic against the project's vocabulary" was applied
   to false positives (collisions), never to false negatives (spellings missed).
5. *Why is that the weak layer?* The rule is a keyword deny-list, and a deny-list is
   only as complete as the spellings its authors thought of. PA-0114 worked (it found
   these two), but it is a per-adoption manual enumeration, so it finds the gap only
   after the rule has already shipped without it.

**Root cause:** the destructive rule is validated only against the spellings it was
written for. Nothing checks it against compound or concatenated spellings, noun forms or
verb-object pairs, so each newly adopted app's spelling is a new miss.

## Corrective action
**Deferred to the owner of the locked `fuzzlab/core/urls.py`** (CC-CORE-0301 records
this). This lane makes no code change to the rule. It adds:
- **Strict xfails** (PA-0054(3)) in `tests/test_destructive_routes_external_labs.py`:
  - `test_juice_change_password_url_is_refused` and
    `test_juice_change_password_url_is_refused_at_the_send_gate`;
  - `test_juice_dataerasure_url_is_refused`;
  - `test_juice_dataerasure_form_is_never_imported` (the real form, as a POST action).
  `test_bug_0301_is_what_the_xfails_claim` pins that they fail for the stated reason.
- **The Juice Shop PA-0114 table** (`JUICE_ROUTES`): every destructive or
  state-rewriting route, each with its gate's computed verdict, or a stated residual.
- **The bWAPP table** (`BWAPP_ROUTES`): the catalogue's whole destructive list (the
  existing `BWAPP_DESTRUCTIVE_GETS` is a subset, checked).
- **The PA-0301 spelling scan** over every lab's routes, proven on synthetic offenders.

Suggested fix, for the owner to weigh (each must pass the existing `HARMLESS` list in
`tests/test_destructive_urls.py`, which includes `/password_change.php`,
`/clearance.php`, `/dropdown.php` and `/exitpoll.php`, and the PA-0022 vocabulary
check):
- add `erasure` (and its compound in `dataerasure`) — e.g. treat a token that **ends**
  with a listed word of five or more letters as that word, which catches `dataerasure`
  and `accountdelete` but not `clearance` or `dropdown`; `preset` would then read as
  `reset`, so check the project's vocabulary first;
- add the ordered pair `(change, password)`; `password_change.php` is bWAPP's form page
  (a GET visit only renders the form; its POST is already refused by
  `credential_change_rule`), so the reversed order should stay out.
When the fix lands, the owner deletes the strict-xfail markers in the same merge
(MULTI_AGENT §6) and moves the two routes into `SPELLING_DISPOSITIONS`' refused set
(the stale-disposition check will say so).

**Compensating controls meanwhile** (computed in
`test_bug_0301_compensating_controls_hold_meanwhile`):
- the crawler never submits the SPA's change-password form (`spa.form_refusal`: a
  settings-like route, `privacy`; three password controls), so its XHR is never
  captured;
- a captured GET XHR has no body and is never imported (`captured_request`);
- a captured form-encoded erasure POST is refused for its `securityAnswer` field
  (`settings_word`: `security`).
The **server-rendered erasure form remains uncovered**: a crawl that reaches
`/dataerasure` would import it. Lane A's live crawl pass asserts that neither path is
in the store (design §5.6).

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a deny-list missing an app's
spelling, and for keyword heuristics:
- **BUG-0114 / PA-0114** — the same bug: the destructive rule missed bWAPP's `update`
  and `insert`. A recurrence.
- **BUG-0111 / PA-0112** — the rule's origin (common verbs only).
- **BUG-0020 / PA-0022** — the same root-cause family: a keyword heuristic trusted
  without checking it against real vocabulary.
- **BUG-0122 / PA-0122** — a URL rule must compare whole segments and tokens, never
  substrings. Related: it fixed false positives; this bug is the false-negative side.
- **BUG-0131 / PA-0131** — the rule's input was truncated before matching (`#`); a
  different mechanism (lossy input), not a recurrence.

## Prior-preventive-action failure analysis
- **PA-0114 (from BUG-0114)** did its job: its from-source enumeration is how these two
  routes were found. But it is **the wrong layer** for prevention. It checks each new
  lab's endpoints after the rule exists, so it finds a gap only when the rule already
  has one. It also asks only "is each endpoint flagged?", not "why would the rule miss
  a spelling like this one?". So the rule was extended by one spelling per adoption,
  and the next app's spelling recurs.
- **PA-0022 (from BUG-0020)** asked for a keyword heuristic to be checked against the
  project's vocabulary for collisions. It was applied to false positives only. No
  wording asks for the reverse check, for spellings the list misses (compounds, noun
  forms, verb-object pairs). It was too narrow, and not enforced by a test for this
  rule.

## Preventive action
**PA-0301** (strengthens PA-0114 and PA-0022):
1. A deny rule is **checked against compound and concatenated spellings**
   (`dataerasure`, `accountdelete`), noun forms of its verbs (`erasure`), and
   verb-object pairs in a path, in either order (`change-password`,
   `password_change`). This is a test, not a review step:
   `tests/test_destructive_routes_external_labs.py::test_no_lab_route_hides_a_destructive_word_in_a_compound`
   scans every lab route, and each hit the rule does not refuse needs a written
   disposition. It is proven on synthetic offenders
   (`test_the_spelling_scan_catches_synthetic_offenders`).
2. A **PA-0002 sweep** runs the rule over **every lab's enumerated state-changing
   routes**: the generated labs' manifests and ground truth, bWAPP, and Juice Shop. Each
   route the rule does not refuse is listed with its compensating control, or as a
   stated residual.
3. Each table row records its gate's **computed** verdict (PA-0001). A residual is
   pinned to None, so it is revisited when a rule starts refusing it.

**Sweep (this change):**
- **Juice Shop:** 36 routes; 25 refused by a gate. The residuals are row creation on
  the session user's own data, two ground-truth cells, and one egress-only route.
  BUG-0301's two routes are the strict xfails.
- **bWAPP:** 39 routes; 21 refused. The residuals are each the page's own
  demonstration, or row creation on a ground-truth cell, the session user's own secret,
  or RCE demo pages (bounded by payloads and the container). The spelling scan found no
  compound miss beyond the two forms already refused (`password_change.php`,
  `secret_change.php`).
- **Generated labs:** every non-GET route in `lab/manifests/*.yaml` and
  `lab/ground-truth*/`. Each is a scored cell, sent as an explicit point in a
  ground-truth run, or a transaction refused by the rule. No generated lab serves a
  logout, delete or reset route. The scan's only other hit is `/channels/subscribers`
  (a plural noun on a read-only GET).
- **No further bug** was found (BUG-0302..0305 unused).
