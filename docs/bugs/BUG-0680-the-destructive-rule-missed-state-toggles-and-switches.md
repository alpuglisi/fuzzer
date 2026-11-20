# BUG-0680 — The destructive rule missed state toggles and switches

- Date: 2026-11-20
- Status: fixed for the shapes two independent sources show (CC-CORE-0650); DVGA's
  `/difficulty/<level>` and `/start_over` are stated residuals (see Corrective action).
- Severity: high (safety). A crawl changed the lab's global state and, on Mutillidae,
  collapsed itself.

## Description
`core.urls.destructive_reason` (SP-09), the rule every crawl, audit and probe gate uses
to refuse a state-changing URL, returned None for links that **switch** application
state rather than delete it:
- Mutillidae's header links `index.php?do=toggle-security`, `?do=toggle-enforce-ssl`,
  `?do=toggle-hints` (tokens `do toggle security`: no listed token, and the action-slot
  pairs held only `update`/`upgrade`);
- DVGA's `/difficulty/hard`, `/difficulty/easy` and `/start_over`.
The rule listed `disable` and `deactivate` but not their opposites `enable` and
`activate`, had no `toggle`, and its action-slot pairs (`?action=`, `?do=`, `?op=`)
knew only two verbs.

## Where encountered
The lab-expansion lanes' discovery crawls (2026-11-20): on Mutillidae the spider fetched
the three toggles; after `toggle-enforce-ssl` the app redirected the session to https and
the crawl collapsed with 121 pages unresolved. On DVGA the crawler followed
`/difficulty/hard` and `/start_over`, flipping the server's global mode and resetting its
state. Re-measured in this lane, live (CC-CRAWL-0650) and against a cited corpus
(CC-CORE-0650).

## What it caused to fail
- **NFR-CRAWL-safe** (a crawl changes no lab state): violated on both labs.
- The crawl itself (Mutillidae): every page after the toggle was unresolved.
- Every measurement taken from those crawls (another lane's pages and findings counts)
  ran against a lab in a state the answer key does not describe.
- Latent, **NFR-FUZZ-safe**: `check_send_url` would let a probe go to such a URL.

## What the bug was identified to be
The rule's vocabulary named **destruction and session end**; it had no notion of a
**state switch**. The project already had one for forms (`formnav.SETTINGS_WORDS`
refuses a select named `level`, `security`, `enable`, `mode`), but a GET link that does
the same thing reached only the URL rule, which never learned the class.

## Root cause analysis
Five Whys:
1. *Why did the spider fetch `?do=toggle-hints`?* `destructive_reason` returned None: no
   token is listed and `(do, toggle)` is not a pair.
2. *Why was `toggle` (or `enable`) not listed when `disable` was?* Each word was added
   from one bug's spelling (BUG-0111: logout/delete; BUG-0114: update/insert; BUG-0301:
   compounds, open). Nobody asked what class of action the list stands for, so a
   word's opposite or sibling was never added with it.
3. *Why did no check find the gap before a crawl did?* Every check of the rule runs it
   over the **labs we already have** (PA-0114's per-lab tables, PA-0301's spelling scan
   of lab routes). None measures it against state-changing links from apps we do not
   host, so a class absent from our labs is absent from the checks.
4. *Why were Mutillidae and DVGA crawled before their state switches were enumerated?*
   PA-0114(1) requires that enumeration "before any crawl of a newly adopted lab", but
   it is a process step with no gate; the lanes crawled first to measure.
5. *Why does a settings link escape when a settings form does not?* The settings class
   lives in `formnav` (forms only); SP-09 (links) and SP-10 (texts) never read it.

**Root cause:** the destructive rule was grown one lab spelling at a time and checked
only against our own labs, with no independent corpus of real state-changing links to
measure it against, so a whole class (state switches) was missing.

## Corrective action
CC-CORE-0650 (`fuzzlab/core/urls.py`, the owner; no caller changes needed, see the
sweep below):
- `enable`, `activate`, `toggle` join `DESTRUCTIVE_TOKENS` (GET evidence: WordPress
  `plugins.php?action=activate`, WebGoat `service/enable-security.mvc`, Gitea
  `/user/activate?code=`, Jenkins `toggleLogKeep`, Security Shepherd `enableCheats`).
- The action-slot pairs (`ACTION_SLOTS` x `SLOT_VERBS`) gain `toggle`, `enable`,
  `activate`, `resume`, `stop`, `switch` (WordPress `action=resume`, bWAPP
  `sqli_9.php?action=stop`): verbs too common to list alone are refused in a slot.
- A destructive verb fused with its object in one token (`COMPOUND_STEMS`, token prefix,
  inflections excluded) is refused: Gruyere `/resetbutton/<id>`, `/<id>/deletesnippet`,
  WebGoat `restartlesson.mvc`.

Measured on the corpus (`tests/data/state_change_corpus/`, 68 positives, 202
negatives; built and cited by this lane): cited state-changing GET links outside the
labs refused 8/33 → 18/33; the bug's lab links 1/7 → 4/7 (all three Mutillidae toggles
plus `set-up-database`); benign cited/illustrative links falsely refused 8/55 → 13/55
(documentation and how-to pages, one render-only page); SecLists paths 2/147 → 13/147;
generated-lab cells and ground-truth points 0/505 → 0/505.

Live (CC-CRAWL-0650, baseline d492b9d → fixed 2ca7cc8): Mutillidae toggle requests
received by the target 100 → 0 (spider) and 91 → 0 (disco); crawl sessions whose state
the crawl changed 7/8 → 0/5 and 2/3 → 0/3; spider pages 271 → 345 (the https redirects
gone). DVGA and bWAPP unchanged (residual; bWAPP's switch is a POST form).

**Stated residuals** (each pinned in `tests/test_state_switch_urls.py`):
DVGA `/difficulty/<level>` and `/start_over` (no second independent source; the
noun-plus-value shape refused wapiti's own `form.php?level=1` fixture and other benign
links), flag values (`phpids=on`, `admin=1`; a flag rule refused 58 ordinary URLs),
per-session `lang`/`locale`/`theme` switches, Drupal `run-cron`, Grafana
`switch-org`, Juice `saveLoginIp`, and BUG-0301's change-password (open). DVGA's two
links therefore still need a non-word control; see the CC-CRAWL-0650 open gap.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md`:
- **BUG-0114 / PA-0114** — the same bug (the rule missed bWAPP's `update`/`insert`).
- **BUG-0301 / PA-0301** — the same bug (missed Juice's compound and verb-object
  spellings); still open for change-password.
- **BUG-0111 / PA-0112** — the rule's origin.
- **BUG-0020 / PA-0022** — the keyword-heuristic family.
A recurrence: the third time the rule missed a lab's state-changing endpoint.

## Prior-preventive-action failure analysis
- **PA-0114 (BUG-0114)** — *not followed and not enforced*: its enumeration-before-crawl
  step has no gate, and the Mutillidae/DVGA lanes crawled first. It is also the wrong
  layer: a per-lab table finds a gap only after the lab exists.
- **PA-0301 (BUG-0301)** — *too narrow*: its scan looks for the rule's **own** words
  hidden in compounds of **our** lab routes. It cannot find a word the rule never had,
  or a class our labs do not contain.
- **PA-0022 (BUG-0020)** — vocabulary checked for collisions, never for coverage of
  a class.
The common failure: every check is anchored on our own labs and our own word list.
Nothing compared the rule with real state-changing links from apps we do not host.

## Preventive action
**PA-0680** (strengthens PA-0114 and PA-0301): the rule is measured against a committed,
cited, independent corpus; every cited positive is refused or a stated residual; the
benign links it refuses are pinned; and every word added to the rule needs two
independent corpus apps, one of them not the lab it was found on (the black-box rule,
mechanised). **PA-0681** (strengthens PA-0114(1)): a newly adopted lab's state switches
are enumerated and judged before its first crawl.

**Sweep (PA-0002, by primitive):** every caller of SP-09/SP-10 calls the owner on the
full URL or text (CC-CORE-0650's sweep table), so the owner fix reaches the spider's
static and browser engines, the redirect hops, navguard's route, disco's explorer, the
store importer (proxy captures), the probe senders, greybox, the oracle, the login
discovery and the form/label gates. No parallel word list for links was found;
`formnav.SETTINGS_WORDS` (forms) is a separate, wider mechanism for selects and keeps
its role. The PA-0301 compound scan is unaffected (no new stem missed).
