# BUG-0552 — Behavioural discovery missed a lost session and re-installed stale credentials

- Date: 2026-10-21
- Status: fixed
- Severity: high

## Description
`fuzzlab disco capture`'s explorer (`fuzzlab/disco/explore.py`) decided that an
authenticated run's session was lost by one predicate -- the page's URL is a login URL
(`session.detect.looks_like_login_url(page.url)`) -- and "recovered" by building a new
browser context from the storage state the run had started with, without closing the
context it replaced. Audit defect 4 (CRITICAL, 2026-10-19, at 6552276).

## Where encountered
- The audit, defect 4: `explore.py` lines 531-551 (`_new_context`), 573-575
  (`_on_response`, which read no answer) and 1326-1336 (`_process`'s loss branch) at
  6552276; on the base c483dc1 the same code in `Explorer._new_context`,
  `Explorer._on_response` and `Explorer._process` (`if authenticated and
  looks_like_login_url(page.url): ... navguard.release(ctx); ctx = self._ctx =
  self._new_context(browser, pw)`).
- Reproduced by `tests/test_disco_session_loss.py`: a real, guarded Chromium through the
  real capture proxy (mitmdump) against a loopback board whose server-side session dies
  after a set number of API answers, then shows an error line and keeps its route
  (`stay`), renders its login form in place (`form`: the API answers 200
  `{"login": true}`), or goes to `/login` (`redirect`).

## What it caused to fail
- **A session lost without a URL change went unseen.** With the board's route still
  `/dashboard` and its APIs answering 401 (`stay`), or its login form rendered in place
  (`form`), the explorer went on clicking: `report.session_lost` stayed 0, and every
  state and answer after the loss was recorded as the identity's coverage (the base
  fails `test_without_a_provider_a_lost_session_ends_authenticated_exploration[stay]`
  and `[form]` on `session_lost == 1`).
- **A server-invalidated session was re-installed as if it were fresh.** On a landing
  at `/login` (`redirect`) the new context adopted the same storage state, so the dead
  session id was sent again: the restore landed on `/login` again and the run went
  round the same loss.
- **Each loss left a context open** until the browser closed: `navguard.release` closes
  the pages and leaves a refusing route, but the context itself was never closed (the
  base fails `[redirect]` on `open_contexts == [1]`: it held two).
- **Answers on the dead session were evidence.** The capture proxy stamped them with the
  run's profile; nothing marked them, so `disco synth` takes a 401 or a login page as
  the identity's answer to the endpoint (D′ broken for captures).
- **A login page on a live session was a "loss".** A step that merely showed a login URL
  had its action denied and the context rebuilt, with no check of the session.

## What the bug was identified to be
Three defects at one site, all in the explorer's handling of the session it holds:
1. **Detection.** The only loss signal was the page's URL. No answer was read: a
   credentialed 401 or login redirect on an XHR, a login form rendered in place and a
   200 login shell were invisible; and the URL decided alone, with no check of the
   session.
2. **Replacement.** `_new_context` always built from `self.storage_state`: the snapshot
   of the session that had just been lost. There was no session provider to ask for a
   fresh one, and nothing revalidated what was installed.
3. **Lifecycle.** The replaced context was released (SP-38) but not closed.

## Root cause analysis
Five Whys, from the observed failure (a 401 on `/api/items/3` while the route stays
`/dashboard` is not seen):
1. *Why was the 401 not seen?* The explorer's only loss signal was the page's URL; it
   classified no answer.
2. *Why was the URL the only signal?* The explorer (CC-CRAWL-0031, D70) was built with a
   copy of the oldest rule of the session layer ("a landing on a login URL is a
   logout"), before the session layer had a classification of answers (SP-56,
   BUG-0528/0529) or a health check for a generation (SP-61, BUG-0533). Nobody
   re-derived the explorer's rule when those owners arrived.
3. *Why was it not re-derived then?* BUG-0533's sweep (PA-0002 by primitive) enumerated
   the consumers **of the session manager**: `observe`'s callers, `verify_live`'s
   callers, the writers of `valid`, `detect_logout`'s callers. Disco holds a session (a
   storage state) but no manager, so the sweep's row listed it as "not a consumer (R9)"
   and left its loss decision to "defect 4". The sweep's criterion was *who calls the
   owner*, not *who holds a session and decides its loss*.
4. *Why did the recovery re-install the stale snapshot?* The explorer had no session
   provider: the only session it knew was the snapshot, so "rebuild" could only mean
   "the snapshot again". No rule said that a lost session is replaced only by a fresh,
   revalidated one.
5. *Why was the old context left open?* `navguard.release` (SP-38) owns how a guarded
   context's pages are frozen, drained and closed "before closing a guarded context";
   the spider pairs it with `context.close()`, the explorer's loss branch copied the
   release only. PA-0128 and PA-0504 govern a teardown's order and its pages; their
   guards check that pages close through the owner, and no test counted contexts across
   repeated replacements.

**Root cause:** a component that holds a session outside the session manager decided
that session's loss by its own predicate and replaced it by its own means. The session
layer's owners (SP-56's classes, SP-16's login form, SP-61's check for a generation) and
the sweep that applied them covered only the session manager's callers, so a session
held elsewhere had no owner for its loss, its replacement or its context's lifecycle.

## Corrective action
CC-CRAWL-0060 (`docs/components/04-crawler/change-control.md`), FR-CRAWL-41; commit on
`lane/DISCO4`. In `fuzzlab/disco/explore.py`, new functions only, the loop calling them:
- **A session provider:** `ExploreSession(manager, identity, base_url)`, the new
  `Explorer(session=)` keyword (one session source: a storage state or a provider). The
  context adopts the provider's session through `browserauth.browser_session` (the one
  adoption helper); a header-only session is refused loudly (`SessionUnavailable`).
- **One generation per run** (`_Shared.auth`, `_SessionMaterial`): every worker's
  context carries the current one (`_new_context`, `_session_current`).
- **Suspicion through the owners** (`_loss_signal`, `_answer_class`, `_shows_login`):
  every answer an authenticated context gets that finished whole
  (``requestfinished``) on the session's origins is classed by SP-56 with SP-16's
  `login_facts` and `request_entry_names` (a credential submission's refusal and an
  intermediary's 407 are no sign); the page at a login URL, or showing this session's
  login form (`shows_login_form`; with no known form, any password form only where it
  replaced the page in place), is one; a login page the step asked for is not.
- **Decision by SP-61** (`_confirm_loss`): `check_health` for the context's generation
  (``policy`` for a 403, ``signal_url`` the answer's). Live: an authorization denial
  (`authorization_denials`), or, for a login page after an action, a context that lost
  its copy of a live session (re-given it, `session_reinstalled`). Without a provider:
  a loss shape is an unconfirmed loss and a policy block never is one (PA-0533(1)).
- **Recovery** (`_recover_session`, single flight under `auth_lock`): a fresh session
  from the provider (`ensure`, another generation), revalidated by its own protected
  check, at most `max_session_recoveries` (3) a run; anything unresolved ends the
  authenticated exploration with its reason (`auth_ended`).
- **Lifecycle** (`_replace_context`): the old context released and **closed** before
  the new one is made; its in-flight tracking dropped with it.
- **D′ for captures:** the action ids whose requests went out since the last clean
  checkpoint (`_note_window_tag`) are marked on a loss: a `session` line in
  `actions.jsonl` and `ExploreReport.session_lost_actions`; the action is denied (unless
  the window was stale) and logged with no new state and no URL.
- Checkpoints after every action, restore (`_restore_checked`: a restore on a lost
  session is tried once more on the recovered one), harvest load and the seed
  (`_seed_session`).

## Recurrence review
Checked `docs/bugs/` -- BUG-0113 (the coarse password-field logout), BUG-0122 (a
substring login redirect read as a logout), BUG-0128 and BUG-0504 (browser teardown),
BUG-0132 (the browser login's JS-set cookie), BUG-0134 (a session sent to another port),
BUG-0529 (a submission's refusal read as a loss) and BUG-0533 (a 403 logged the session
in again) -- and `docs/PREVENTIVE_ACTIONS.md` (PA-0113, PA-0122, PA-0128, PA-0134,
PA-0504, PA-0529, PA-0533):
- **BUG-0533 / PA-0533:** the same root cause. A session's loss decided from evidence
  that is not about that session (there: one 403; here: a URL decides and the answers
  are ignored), with no owner deciding it. Its sweep table names disco explicitly ("not
  consumers (R9); disco's defect 4 may build on the public `health_verdict`").
- **BUG-0122 / PA-0122:** the explorer's URL test already compared whole segments
  (compliant); the defect is that a URL was the evidence at all.
- **BUG-0113:** the coarse "any password field" rule; the explorer now reads this
  session's login form when the provider knows it.
- **BUG-0128 / PA-0128, BUG-0504 / PA-0504:** a teardown that stopped short. There it
  let a refused request out; here it left the context open. The same family (a
  teardown's completeness), another failure.
- **Result:** a recurrence of BUG-0533's root cause (PA-0533), and of PA-0128/PA-0504's
  family for the context's lifecycle.

## Prior-preventive-action failure analysis
- **PA-0533 (BUG-0533): too narrow, by its scope and its sweep.**
  1. Its rule 1 ("an identity's state changes only on evidence about that session ...
     SP-56 classifies first ... the resource's answer decides") reads as a rule about the
     session manager's state. A browser context that keeps its own copy of a session (a
     storage state) and decides its loss without the manager is outside its words.
  2. Its enforcement (rule 4) is an AST guard over writes of `valid` and calls of
     `detect_logout`. A component that decides a loss without writing `valid` or calling
     `detect_logout` -- `looks_like_login_url(page.url)` followed by a rebuild -- is
     invisible to it.
  3. Its sweep was by primitive (the callers of the owner), so it listed exactly the
     components that decide a loss *without* the owner as "not consumers".
  4. Its rule 5 (D′) named its consumers by the session layer's mark
     (`Request.session_lost`); a capture has no such mark, so nothing applied to the
     answers a browser recorded on a dead session.
- **PA-0128 / PA-0504: not enforced for contexts.** PA-0504(2)'s guard checks that a
  guarded page is closed only through `navguard.close_pages`; PA-0128's test checks
  `release`'s order. Neither checks that a released context is closed, so the
  explorer's replacement path leaked one context per loss.
- **PA-0122:** not applicable to the failure (it governs how a URL is compared).

## Preventive action
**PA-0552**, strengthening PA-0533 (rules 1, 4 and 5 and its sweep) and PA-0128 /
PA-0504 (a replaced context): a component that holds a session outside the session
manager is a session consumer; it decides that session's loss only through the session
layer's owners (SP-56 for each answer, SP-16 for a page, SP-61 for the generation it
holds, PA-0533(1)'s unconfirmed loss without a check); a lost session is replaced only
by a fresh one from the provider, revalidated before use, never by its starting
snapshot, and an unresolved loss ends the work with a reported reason; a replaced
context is released and closed before its replacement exists, counted by a test; the
answers of a known-lost window are marked where they are recorded and read by every
consumer that takes answers as evidence, or that consumer is pinned by a strict xfail
naming its owner; and a sweep for a session rule enumerates the holders of a session,
not only the owner's callers. Text and enforcement in `docs/PREVENTIVE_ACTIONS.md`
(this lane's text in its `doc_texts.md`).

## The sweep (PA-0002), by holder of a session
| Site | Holds | Before | Disposition |
|---|---|---|---|
| `disco/explore.py` (`Explorer`) | a storage state, now or a provider | URL predicate, snapshot rebuild, context left open | **fixed** (this change) |
| `tools/spider.py` (`_session_intact`, `_reveal_session_check`, `_readopt_session`; deprecated, FR-CRAWL-21) | a manager's browser session | client-side check of its own cookies and storage, then `verify_live` (SP-61) | compliant: the server half is the owner's; a re-adoption is revalidated by `verify_live` before reveals go on, and a second loss stops them -- never trusted as fresh; its main context is never replaced, and its extra contexts are released and closed (`release(context); context.close()`) |
| `tools/fetcher.py` (the auditor's browser, CC-AUD-0040) | a manager's browser session | no loss decision at all | no own predicate and no replacement: not this bug. Its pages after a server-side loss are a degraded discovery window, as BUG-0533's sweep stated (discovery, not evidence); residual, owner AUD |
| `disco/runner.py` (the contract runner) | a profile's credential | classifies each answer by SP-56 (an auth failure is never a pass) | no loss decision, no replacement: compliant |
| `disco/ede.py` | no session (an anonymous context) | -- | not a holder; **but a consumer of a capture's answers** (row below; corrected in review round 1) |
| `proxy/session_capture.py` | a captured session, adopted into the manager | -- | the owner's path (`adopt`): compliant |
| consumers of a capture's answers: `disco/synth.py` (`fuzzlab disco synth`) | -- | takes every answer as the endpoint's under the run's profile | **pinned** by a strict xfail naming its owner (`test_an_answer_in_a_lost_window_is_never_in_the_inventory`), PA-0531(4); residual |
| consumers of a capture's answers: `disco/ede.py` (`fuzzlab disco ede`; review round 1, B2) | -- | replays the last 2xx JSON answer per URL and tests every 2xx HTML document: a lost window's answer replaced the identity's | **fixed** (review round 1): `ede.replayable`, `ede.page_urls` and `EdeRunner` skip marked action ids; the CLI passes `capture.lost_action_ids(run)` |
| consumers of a capture's answers: `tools/store_adapter.import_disco` (`fuzzlab auto`; review round 1, B2) | -- | a GET's status is the page row's (a 2xx page row gives header injection points) and path-template evidence (`_answered`), its HTML media type makes it a page | **pinned** by a strict xfail naming its owner, AUD (`test_import_disco_never_takes_a_lost_windows_answer_as_evidence`); residual. *(Corrected: this row first read "reads requests and their URLs, not answers"; lines 259-266 read the answer's status and media type.)* |
| `tools/observe` / `disco/livetrace` | -- | the trace of what was exchanged (FR-AUD-28/29) | not an evidence consumer: the trace shows what happened; listed with its reason in `tests/test_lost_window_mark.py` |

## Review round 1 (2026-10-21, on a1a93b1; DISCO4-B1, B2, R1, R2, R3)

Five confirmed findings on the lane's commit, each reproduced by a test that fails on
a1a93b1 and passes after (CC-CRAWL-0060's "Review round 1"; branch `lane/DISCO4-r1`).

### What each was
- **B1, a lost generation was the run's only once replaced.** The run recorded that a
  generation was gone only by moving `_Shared.auth` after a fresh session was installed.
  Until then -- the whole recovery, or for ever after `_end_authenticated` -- another
  worker whose context carried the lost generation saw no generation change and no sign
  in its own (anonymous-200) answers: its checkpoint cleared its window, its action was
  logged with a new state and URL, and what it found was pushed and gathered as the
  identity's coverage. `_session_current` dropped a pending window unmarked when it
  replaced a context.
- **B2, two consumers of a capture's answers did not read the mark.** `ede.replayable`
  served the last 2xx JSON answer per URL (a lost window's `{"login": true}` over the
  identity's), and `store_adapter.import_disco` took a lost window's status and media
  type as page, header-point and path-template evidence. The sweep had listed `ede`
  only as "not a holder" and `import_disco` as reading "requests, not answers".
- **R1, the in-place rule held only right after an action.** Without a known login form
  (every storage-state run), a password form counted only when the page's URL equalled
  the URL before an action. A loss that landed on a restore, at the seed or on a harvest
  load was unseen: measured on a1a93b1 with `form`, budget 1 -- the sid died on the root
  state's restore, `session_lost` 0, the run harvested on the dead session and ended
  with no loss reported.
- **R2, an answer sign hid the page sign.** `_loss_signal` returned the first auth
  failure before reading the page, so a 401 whose script then went to `/login` (the
  usual SPA interceptor) was checked as an answer: live, an authorization denial, and
  the context explored on without its session.
- **R3, nothing confirmed a suspicion on the CLI's path.** Without a provider every
  loss shape was an unconfirmed loss that ended the run, so a role-gated 401 or a login
  redirect for a live session's role ended every `fuzzlab disco capture`.

### Root cause analysis (Five Whys, across the five)
1. *Why did these reach review?* The lane's tests drove one worker, one loss per run,
   at the moment its fixture chose (after a click), and a provider for every
   confirmation; each finding lives outside that envelope (a second worker, a loss on a
   restore or at the seed, a 401 and a page together, no provider).
2. *Why was the envelope that narrow?* The design was derived from the provider path
   (SP-61's `check_health` and its generation), and the storage-state path -- the only
   one the CLI reaches -- was treated as its degenerate case (PA-0533(1)'s unconfirmed
   loss), not as the production path with its own needs (an in-place reference and a
   protected check of its own).
3. *Why was the loss of a generation not shared at once?* The explorer took the
   manager's model (the state object moves on install) without the manager's other half:
   the manager marks a generation lost at the verdict (`_mark_lost`) before any
   re-login, so every holder of it sees the loss at once. The explorer had no such
   record, so "lost" became visible only as "replaced".
4. *Why did the sweep miss two consumers?* PA-0552(4)'s consumer list was written from
   reading descriptions (what each module is for), not from the call graph (who reads a
   capture's answers), and nothing enforced the list.
5. *Why did the page sign depend on the answers?* The suspicion was one first-match
   value, so whichever sign came first decided the kind of check, and the "reinstall"
   decision (which needs the page sign) was keyed on that kind.

**Root cause:** the session-loss decision was built and tested for one worker on the
provider path; the state a decision changes (a generation's loss) was published only
through the side effect of its recovery, and the rule that every consumer reads the mark
had no mechanical check.

### Corrective action
CC-CRAWL-0060 "Review round 1": `_Shared.lost_generations` recorded at the verdict under
the recovery lock, checked before every action, restore and load, with every gone
window marked (B1); `disco.capture.lost_action_ids` read by `fuzzlab disco ede`, the
importer pinned (owner AUD), and a guard over every capture reader (B2); a password form
in place at the restored state's URL or the start page, `State.login_shown`, weak signs
only where a check decides them (R1); the page sign read whatever the answers, a live
verdict after an action with a strong page sign a reinstall (R2); the start page as a
storage-state run's protected resource, judged by SP-61's `health_verdict` (R3).

### Recurrence review and prior-preventive-action failure analysis
- **Same root cause as BUG-0533 (PA-0533(2)):** "evidence is bound ... to its
  generation ... every write compare-and-sets ... atomic with every install". The
  manager meets it by marking a generation lost at the verdict; the explorer, a second
  holder of a generation (PA-0552(1) made it a session consumer), re-implemented the
  generation without that rule. **PA-0533(2) was too narrow for this holder**: it is
  written about the manager's writes; PA-0552(1) routed the explorer's *decision*
  through the owners but said nothing about *publishing* it to every holder of the
  generation.
- **PA-0552(4) not enforced:** it required every consumer to read the mark or be
  pinned, and the lane's own sweep (its first application) missed two consumers. A
  rule with a list and no guard: the list was wrong on day one.
- **PA-0533(1) applied without its precondition:** its unconfirmed loss is for an
  identity "without a resource"; the lane never tried to find one for a storage-state
  run, so the fallback became the rule.
- **PA-0113 (BUG-0113) and the in-place rule:** the coarse "any password form" rule was
  narrowed to "after an action, at the same URL" to avoid its false positives; the
  narrowing dropped the other places a page is known without a form (a restore, the
  seed), which is R1.

### Preventive action
PA-0552 (text in the lane's `doc_texts.md`) gains rules 6-8: a holder of a session
generation publishes its loss to every other holder at the verdict, before any recovery,
and no holder acts, restores or loads on a generation known gone (checked before each
step, not at state boundaries); every consumer of a capture's answers reads the mark,
enforced by a whole-package guard over the capture readers (`tests/test_lost_window_mark.py`,
proven on synthetic offenders), not by a hand-written list; a session holder without a
manager establishes a protected resource of its own before falling back to PA-0533(1)'s
unconfirmed loss, and its suspicions are decided by SP-61's public `health_verdict`.

### Sweep (PA-0002) for the review round
- *Every reader of a capture's records* (the guard's enumeration): `disco/cli.py::_ede`
  (fixed), `disco/cli.py::_synth` (pinned), `tools/store_adapter.py::import_disco`
  (pinned, AUD), `disco/livetrace.py::LiveTrace.__init__` / `finish` (the trace: not
  evidence). No other.
- *Every holder of a session generation shared across threads*: the explorer's workers
  (fixed); the session manager (`_mark_lost` at the verdict, under its lock: compliant).
  The deprecated spider's workers (FR-CRAWL-21) each check their own context after a
  reveal (client-side, then `verify_live`); whether one worker's loss reaches the
  others was **not examined** in this round -- flagged, not cleared (owner CRAWL, the
  spider's own item).
- *Every first-match suspicion*: `session.manager.observe` reads one answer per call
  (no page); `detect_logout` decides one answer: no other first-match over mixed signs.

## Merge integration with BUG-0539 (AU-DISCO) and BUG-0551 (DISCO13), 2026-10-21
Merged after both, as planned. CC-CRAWL-0060's merge-integration note lists the
resolution. What changed in this bug's mechanism at the merge:
- The check before a step lives in AU-DISCO's `_bring_to` (the contract and the
  session together; DISCO4's `_ready` folded in); every restore goes through
  `_restore_checked`.
- A known-lost window's action finishes its work item (BUG-0539's ledger: its effect
  was a lost session); a replaced context's states are read in the execution key's
  next generation (`_replace_context`).
- Evidence BUG-0539 and BUG-0551 add is taken only from a live window: the first-visit
  and dismissal reloads are session-checked before a declaration, and a delegated
  trial's inert verdict from a lost window is reopened.
- **Residual (merge):** `_shows_login` reads `page.content()`, the top document's light
  tree, so a login form a component renders inside a shadow root or a frame is no page
  sign (BUG-0551 R5's read); an answer sign (SP-56) still reaches the check.

