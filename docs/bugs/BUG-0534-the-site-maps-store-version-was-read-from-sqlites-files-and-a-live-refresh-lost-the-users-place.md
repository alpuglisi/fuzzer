# BUG-0534 — The site map's store version was read from SQLite's files, and a live refresh lost the user's place

- Date: 2026-10-20
- Status: fixed (AU-SITETREE; CC-UI-0068, with CC-CORE-0071 and CC-FUZZ-0108)
- Severity: medium. No data was wrong in the store. The site map and the Diagrams page
  refreshed with no write, missed most commits of a running scan (lagging it by up to 230
  commits, M4), and dropped a keyboard user's focus to the page body on six control
  kinds; a page the user asked for was dropped silently.

## Description
Two layers of one live view.

**Layer 1, the version.** `fuzzlab/web/sitetree.py::store_version` fingerprinted the
store from its files: the main file's `os.stat` (device, inode, size, mtime) and the
`-wal`'s size and 32-byte header. The pages poll it (`/api/sitetree/version`) and the
child-list cache is keyed on it (G11).
- **E1, a change with no write.** A reader's or a writer's last close folds the WAL
  (rewriting the main file, deleting `-wal`), and a passive checkpoint rewrites the main
  file: the fingerprint changed and the page refreshed although no content changed.
- **E2, a write not seen.** After a WAL restart a commit lands inside the WAL's old
  extent: the WAL keeps its size and header, the main file is untouched. 2782 of 3000
  held-writer commits were unseen in process (M1), 2783 of 3000 with the writer in
  another process; polls and the G11 cache served the old state.

**Layer 2, the refresh.** `static/js/sitetree.js` and `diagrams.js` re-rendered on a
version change:
- **E3** a refresh replaced a focused "Show more": focus went to `<body>` and Enter loaded
  nothing (200 of 250);
- **E4** a refresh dropped a "Show more" page the user had asked for, in either order of
  the two fetches;
- **E5** a refresh dropped focus from a row's control (the findings count, the open
  link) and from an Issues link, and reset Issues to its first page (60 rows to 50);
- **E6** the Diagrams refresh dropped focus from 4 of 6 control kinds (an interface row,
  an origin group, a sequence step, an export link);
- **E8** (found by the confirming review) the poll recorded a new version *before* its
  refresh, and a refresh whose group fetch failed returned early: the failed part was
  never re-read, because the next poll saw no change.

## Where encountered
- `tests/test_web_sitetree_browser.py::test_show_more_from_the_keyboard_keeps_focus_in_the_tree`
  failed once in a full harness run (200 of 250 items): E3 met an E1 refresh caused by an
  earlier test's writer frames folded by a reader's close (DRAFT-AU-SITETREE §1.6).
- The AU-SESS403 lane reproduced it; the AU-SITETREE lane measured E1-E6 (DRAFT §1.2-§1.6,
  probes M1-M7 and the browser probes p1-p7).
- E8: the confirming review of revision 2, after
  `test_a_refresh_keeps_focus_selection_and_loaded_pages` failed once on `7ebf48a` plus
  the counters-only patch ("/wide/w999" not shown within 10 s; DRAFT §5.6).

## What it caused to fail
- A harness run failed (one browser test, above), and another test failed once (E8 or
  E2, above).
- An operator watching a scan saw a site map and a Diagrams page up to 230 commits
  behind (M4), with stale child lists from the cache, and refreshes with no write.
- A keyboard or screen-reader user lost their place on every refresh (focus to
  `<body>`), lost a requested page silently, and Issues lost its loaded pages.

## What the bug was identified to be
- `store_version` (entered `6a996de`, CC-UI-0500; review fix A1 `1d02cd0`, CC-UI-0503,
  turned E1's open half off and made E2 frequent) inferred "the store changed" from
  storage side effects that SQLite does not tie to commits.
- `setTail`, `refreshGroup`, `showNode`, `renderIssues` (`1d02cd0`, `830a98f`) and
  `diagrams.js::renderFlow`, `renderIfaceTable`, `renderSeq`, `exportLinks` (`ede72b9`,
  CC-UI-0058) re-created focused nodes without restoring focus, except for a removed tree
  item (`cab3cea`); the "Show more" click and the refresh each treated the other's fetch
  as stale; `poll` set `state.version` before `refresh()`.

## Root cause analysis
Five Whys, per layer.

**Layer 1.**
1. *Why did the page refresh with no write, and miss a scan's commits?* The version was
   the main file's stat and the WAL's size and header. A last close or a passive
   checkpoint rewrites the main file (a change with no write); a commit after a WAL
   restart rewrites frames inside the WAL's old extent (a write with no change in size,
   header or main file).
2. *Why was a change signal derived from the files?* CC-UI-0500 wanted a version "with
   no SQLite at all", so that polling held no connection, and assumed that every commit
   grows the WAL or rewrites the store, and that reads never touch the files.
3. *Why did no test catch either?* Its claims were tested only on the engine states the
   author pictured: one short writer, in the test's own process. No test ran a held
   writer across autocheckpoints (WAL restarts), a reader's last close after a writer's
   commit, a passive checkpoint, or a writer in another process.
4. *Why did review fix A1 make E2 frequent?* A1 fixed "a reader's open changes it" by
   ignoring a WAL shorter than its header and the WAL's inode and mtime, which removed the
   signals that had made restarts visible. The fix re-ran only the case it fixed; the
   "never" claim and the "always" claim were not re-run together.
5. *Why were the claims not re-run against every operation?* No rule asked for it: a
   change signal over state another engine manages was treated as the module's own
   design, not as a claim about that engine's behaviour.

**Root cause (layer 1):** a change signal over storage another engine manages was
inferred from that engine's storage side effects (sizes, mtimes, journal headers), and
its never/always claims were tested only on the engine states the author pictured, never
against every engine operation that touches what it reads, nor with the writer in another
process. SQLite documents its own change counter for this (`PRAGMA data_version`).

**Layer 2.**
1. *Why did focus fall to `<body>`?* Each refresh re-created the focused element (the
   "Show more" button, a row, the Issues rows, the Diagrams regions), and nothing put
   focus back except for a removed tree item.
2. *Why only that case?* FR-UI-505's "keeping focus" was implemented (`cab3cea`) and
   tested for the one element kind the author pictured, a tree item; the Diagrams refresh
   (CC-UI-0058) was never considered for focus at all.
3. *Why was a requested page dropped?* The refresh re-read "as many items as it shows"
   and treated a page in flight as stale, while the page's own load gave way to the
   refresh's generation. Each side was right alone; no test held one side's fetch while
   the other ran.
4. *Why was a failed refresh never retried (E8)?* The poll recorded the version before
   the refresh ran, so "seen" meant "asked for", not "shown"; the browser tests slept
   (900 ms) instead of observing the refresh, so a refresh that did not happen surfaced
   only as a timeout.
5. *Why did PA-0518(1) not prevent it?* See the prior-preventive-action failure analysis
   below: it was not swept to FR-UI-505 or FR-UI-510's live behaviour, and only two
   Diagrams tests enforced it.

**Root cause (layer 2):** a requirement about every control across a refresh was
implemented and tested for one element kind in one order of events, with no mechanism
that makes each live view enumerate its focusable controls, key them by identity and test
each kind across a change in both orders, and no rule that a version is seen only once
shown. This is BUG-0518's root cause recurring (a UI requirement for "every" element or
"a change" tested on one).

## Corrective action
CC-UI-0068 (this item's implementation commit on branch `worktree-agent-a60c0b76d37a91dd4`;
design record `docs/components/12-diagnostics-and-ui/DRAFT-AU-SITETREE.md`):
- **Layer 1:** `store_version` is `PRAGMA data_version` on one held `core.store.open_read_only`
  connection (query-only, private cache) on the open store, hashed with the process
  nonce, the store's identity, a reopen epoch and the count (SP-58). Measured with every
  writer in another process: 3000 of 3000 commits seen across 17 WAL restarts, 26 of 26
  facts. One watch, released before a project's files are removed, idle-released by a
  reaper, closed outside its lock, never replaced while its predecessor closes; a watch
  whose store moved truncates its WAL into it first (DRAFT §1.10). Safe only with
  CC-CORE-0071 (BUG-0535).
- **Layer 2:** `static/js/livefocus.js`, the one helper (focus keys, verified landing,
  visible fallbacks ending at the region's pane, `preventScroll`, in-place patching of a
  focused row); keys on every focusable control of both pages; one ordering rule for a
  user's page load against a refresh; Issues kept on refresh; a version marked seen only
  once its refresh succeeded; page counters, and every live-view test synchronised on
  them.
- Tests: the L1, K, B and G tests listed in CC-UI-0068 (each failing on `7ebf48a` for its
  stated reason, DRAFT §5.5; each named revert re-proved against the implementation,
  DRAFT §11.4).

## Recurrence review
Searched `docs/bugs/` for fingerprint, `store_version`, `data_version`, refresh, focus,
poll, WAL, checkpoint, site tree, sleep and wait; read `docs/PREVENTIVE_ACTIONS.md` in full.
- **BUG-0146** (`store_version` with no project open): the same function, another cause
  (a merged contract). Not a recurrence.
- **CC-UI-0503's review finding A1**: the same layer-1 defect, partly fixed, with no
  BUG record. Its fix is where E2 entered; recorded here.
- **BUG-0518 / PA-0518(1)**: a UI requirement stated for every element or a change,
  tested on one kind. **Layer 2 recurs its root cause.**
- **BUG-0021 / PA-0023** (a SQLite handle shared across threads): not a recurrence; the
  watch is one shared handle by necessity, PA-0023's third pattern (PA-0534(4)).
- **BUG-0135, BUG-0511, BUG-0526 / PA-0150, PA-0511, PA-0526** (judging a concurrent
  actor by wall time): the browser tests' 900 ms "the poll has its baseline" sleeps are
  that class; the one failure on `7ebf48a` surfaced as a 10 s timeout behind such a sleep.
  Those PAs cover timing bounds, arrival order and exact counts, not a sleep standing in
  for an event; PA-0534(3) adds the page counters and a guard.
- **BUG-0087, BUG-0452** (store contracts, applied: the watch never creates or migrates).
- **PA-0311(2)** (a premise asserted, not assumed): landed 13 minutes after `1d02cd0`, on
  another branch; the new tests assert their premises (a WAL restart happened, frames
  were left, the parent is out of view).
- **PA-0083(2)** (never/always claims backed by a test): written for safety claims; the
  layer-1 docstring's "reads never change the fingerprint" was such a claim, untested
  against a reader's close. PA-0534(2) extends it to correctness claims over an engine.
- `docs/MULTI_AGENT_ORCHESTRATION.md` §7 (measure before design): covered targets and
  the browser, not the store engine.

## Prior-preventive-action failure analysis
**BUG-0518 / PA-0518(1)** ("a UI requirement stated for every element or for a change is
tested on each kind of element and on a change after the first load") did not prevent
layer 2:
- **Not swept.** BUG-0518 recorded no PA-0002 sweep, so FR-UI-505 ("keeping focus") and
  FR-UI-510 ("a change reloads the run") were never re-checked against it.
- **Not enforced.** Its enforcement line names two Diagrams tests; nothing discovers a
  live view, its controls or its focus tests, so a new or existing live view could stay
  untested.
- **Too narrow even on its own page.** FR-UI-510's live reload was never tested for the
  user's place: the Diagrams page lost focus on 4 of 6 kinds.
- **Wrong oracle shape.** Tests that did exist slept for a poll and wrote only rows that
  sort after the focused control, so a positional restore would have passed them.

Layer 1 had no prior PA that failed (A1 was a review finding without a PA).

## Preventive action
**PA-0534** (text for `docs/PREVENTIVE_ACTIONS.md`; the coordinator applies it). It
strengthens PA-0083(2), PA-0311(2) and MULTI_AGENT_ORCHESTRATION §7 for engine-managed
state; strengthens and supersedes PA-0518(1) for live views (made mechanical and swept:
G1-G4 discover every polling or streaming script and require its registered real-browser
tests, a key on each control, counters instead of sleeps); amends PA-0023 with a third
pattern; and adds the rule that a version is seen only once shown. The PA-0002 sweep:
DRAFT §4 (every consumer of `store_version`, every raw open and "has the store changed"
detector, every live-refresh view: `proxy.js`, `lab.js`, `launcher.js`, `common.js`
exempt with reasons).
