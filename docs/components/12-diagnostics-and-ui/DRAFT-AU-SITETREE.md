# DRAFT AU-SITETREE (revision 2): the store version is SQLite's change counter, the web process never drops SQLite's locks, and a live refresh keeps the user's place

- Item: `AU-SITETREE` (owner-approved; found and reproduced by the AU-SESS403 lane).
- Base: `7ebf48a` (tip of `ccr-602fc4d9-vyovmz`, with the host pytest lock).
- Numbers (pre-assigned): CC-UI-0068, CC-CORE-0071; FR-UI-514 (new), FR-UI-505 and
  FR-UI-510 (amended), FR-CORE-508 (new); BUG-0534 / PA-0534 (the version and the focus
  defect), BUG-0535 / PA-0535 (the lock drop); SP-58.
- Status: **phase 1, revision 2, for one confirming review** (`docs/components/README.md`).
  Nothing in `fuzzlab/` is changed. The failing tests are committed with this draft
  (§5): each was run on `7ebf48a` and fails for its stated reason (§5.5). The probes are
  scratch files (§1.9).

## R. Revision 2 at a glance

Both reviewers of revision 1 found, and measured, that on POSIX the close of **any** file
descriptor releases every `fcntl` lock the process holds on that file. The web process
reads the store's magic bytes with a plain `open()` (`core/project.py:132` `inspect`,
`:663` `summary`), so one Projects view plus one short writer in another process deleted
`-wal`/`-shm` under revision 1's held watch: it then missed 200 of 200 (B) and 300 of
300 (A) commits, web reads were wrong or "malformed", and a project file was corrupt.
Revision 2 measures the same hazard on today's code (§1.7: it reproduces, with on-disk
corruption under `--with-proxy`) and takes the coordinator's decisions:

| Decision | What changed | Where |
|---|---|---|
| D1 | Keep the held `query_only` watch; make the web process safe for it. No raw open of a store file in the web process: the magic is asked of SQLite through a new public read-only opener (`core.store.open_read_only`, `cache=private`, FR-CORE-508, CC-CORE-0071), with a disposition for every read-only open; a computed whole-package guard; the watch re-checks the identity of the main file, `-wal` and `-shm` on every call (a defence, measured as insufficient alone). | §1.4, §3.1, §3.2, §4.2, §5.2 |
| D2 | The pre-existing hazard is BUG-0535 / PA-0535, measured on `7ebf48a` for `--with-proxy` and for an overlapping request; D1 fixes it; cross-process regression tests. | §1.7, §2, §5.2, §9.2 |
| D3 | One watch, for the current `store_path()` only; `_leave`, `_switch` and discard release it before files go; released watches close outside the lock; a fd test; the unsupported platforms and cases stated. | §3.1 (lifecycle), §5.1, §7 |
| D4 | Every measurement and layer-1 test has its writer in another process; M2 re-run with the planned opener; X1 in §1.4. | §1.4, §1.5, §5.1 |
| D5 | Focus keys unique per live region and never positional; a step's key is derived beyond its evidence key; B8 asserts uniqueness; B7 focuses a response step. | §3.3 |
| D6 | One ordering rule for a user's page load against a refresh, in both orders; `renderIssues` deduplicates; tests hold the refresh's fetch, click, release. | §3.3, §5.3 |
| D7 | `restoreFocus` verifies focus landed, walks fallbacks to a visible target ending at the pane (never `<body>`, the empty tree included), `preventScroll`. | §3.3 |
| D8 | Page counters (`data-baseline`, `data-polls`, `data-refreshes`); tests wait on them, B2 holds with `page.route` and `expect_request`, every B test asserts its refresh, L1-B counts polls. | §3.3, §5.3 |
| D9 | Numbers as above; PA-0534 amends PA-0023 (a third pattern); L1-12 unconditional: `_stat_key` fixed in the same CORE change (an age bound). | header, §3.2, §9 |
| D10 | WAL disk use measured (§1.8) and stated (R4, NFR-UI-live): `journal_size_limit` bounds it but is not needed for correctness; the Diagrams poll respects visibility; an autouse fixture releases watches; `sitetree_poll_ms` / `diagram_poll_ms` clamped below the idle release, `time.monotonic`; R5 says two refreshes; focused controls updated in place where possible; `aria-activedescendant`; the lost-click residual. | §1.8, §3, §6, §7 |

Revision 1 called the six defects D1-D6; they are **E1-E6** here so that D1-D10 name the
coordinator's decisions. E7 is the lock drop (BUG-0535).

## 0. Summary

Three problems, two bugs:

- **BUG-0535, the lock drop (pre-existing, E7).** A plain `open()`/`close()` of a store's
  main file in the web process drops the POSIX locks of every SQLite connection the
  process holds on it. Another process's later close then believes it is the last, folds
  the WAL and deletes `-wal` and `-shm` under the web process's connections. Measured on
  `7ebf48a` (§1.7): under `fuzzlab web --with-proxy`, one Projects view and one short
  writer left the project file corrupt on disk (`vtable constructor failed: flow_fts`,
  after every connection closed); with a request's reader held across a listing, 100 of
  100 reads were wrong, the reader read "malformed" and 4 of 5 UI commits were lost.
  Realistic overlapping requests deleted the side files under an open reader 11 to 17
  times in 8 s (no damage seen in that short run).
- **BUG-0534, layer 1, the version fingerprint** (`web/sitetree.py::store_version`, read
  from SQLite's files):
  - **E1, spurious changes:** a reader's or a writer's last close, and a passive
    checkpoint, change it with no write (its docstring and FR-UI-505 say "reads never
    change it").
  - **E2, missed writes:** after a WAL restart a commit lands inside the WAL's old extent
    and is not seen: 2782 of 3000 held-writer commits in process (M1), 2783 of 3000 with
    the writer in another process (§5.5); polls and the G11 child-list cache then serve
    the old state.
- **BUG-0534, layer 2, the live refresh** (`sitetree.js`, `diagrams.js`): **E3** a refresh
  replaces a focused "Show more" (focus to `<body>`, Enter loads nothing); **E4** it drops
  a "Show more" page the user asked for, in either order; **E5** it drops focus from a
  row's control and an Issues link and resets Issues to page 1; **E6** the Diagrams
  refresh drops focus from 4 of 6 control kinds.

**Design.**
- (a) No module of the web process opens a store file except through SQLite: the magic
  check is SQLite's own (`SQLITE_NOTADB`), through one read-only opener in core
  (FR-CORE-508). This fixes BUG-0535 and is what makes (b) safe.
- (b) The version is `PRAGMA data_version` on **one** held, `query_only`, private-cache
  connection on the open project's store, hashed with the store's identity, a reopen
  epoch and a process nonce (SP-58). Measured with every writer in another process: it
  sees every commit (3000 of 3000 across 17 WAL restarts, rollback mode 50 of 50) and
  ignores reads, closes, empty transactions and passive checkpoints (§1.4, 26 of 26 facts).
- (c) One helper, `static/js/livefocus.js`, remembers the focused control by a focus key,
  restores it after a re-render with a verified fallback chain, and patches a focused
  row in place; one ordering rule delivers a page the user asked for whichever of the
  two comes first.

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7)

### 1.1 Platform

- Python 3.13.16, SQLite 3.45.1, Linux 6.18.44, an ext-family filesystem with
  nanosecond mtimes; Chromium 1194 (`/opt/pw-browsers`), `FUZZLAB_REQUIRE_BROWSER=1`.
- `core.store.Store`: WAL, `busy_timeout=10000`, `synchronous=NORMAL`. No module of
  `fuzzlab/` runs `wal_checkpoint`, sets `journal_size_limit` or changes
  `wal_autocheckpoint` (default 1000 pages).
- The web server is one process: uvicorn's threads serve sync routes; `--with-proxy` runs
  the proxy in the same process. A launched scan is another process.

### 1.2 What changes the current `store_version` (rev 1, M1: `m1_fingerprint_facts.py`; writer in process)

| Case | Content changed? | Fingerprint changed? | |
|---|---|---|---|
| 1. A writer commits with a reader open; the reader closes last (WAL folded, deleted) | no | **yes** | E1 |
| 2. A writer's own last close after its commit | no | **yes** | E1 |
| 3. A passive checkpoint by another connection, the writer open | no | **yes** | E1 |
| 4a/4b. An UPDATE / an INSERT after a WAL restart (WAL stays 2 006 472 B) | yes | **no** | E2 |
| 5. A held writer's 3000 one-row commits | yes | unchanged on **2782** | E2 |
| 6. A reader opens and closes on a quiet store | no | no | |

M4 (`m4_longest_unseen_run.py`): 5000 held-writer commits, rows of ~40 B / ~400 B / ~2 KB:
4719 / 4758 / 4792 unseen, longest unseen runs 230 / 178 / 126 commits. M6: the stated
rollback-mode residual does not reproduce here (0 of 500; fine-grained mtimes), so the
test emulates a coarse tick with `os.utime`. The cross-process re-runs (§5.5) give the same
shapes: case 1, 2 and 3 change it; 2783 of 3000 unseen.

### 1.3 When each defect entered (rev 1, M7: `m7_history.py`; git blame for E7)

| Code at | A reader's open changes it | A reader's last close changes it | Held-writer commits unseen |
|---|---|---|---|
| `6a996de` (CC-UI-0500) | yes | yes | 0 of 3000 |
| `1d02cd0` (CC-UI-0503, review fix A1) | no | yes | **2782 of 3000** |
| `7ebf48a` (now) | no | yes | 2782 of 3000 |

E7: the magic reads entered with project files, `inspect` at `9f1536e` and `summary` at
`8569187` (CC-CORE-0450, 2026-10-15); the proxy's held `Store` predates them (it is already in
`4c4f18c`, the oldest commit of this shallow clone). The hazard exists since `9f1536e`.

### 1.4 The watch, measured across processes (M2x: `rev2/m2x_crossproc.py` with the planned opener `rev2/proto.py`; the reviewers' X1/X3)

Every writer is `rev2/agent.py` in another process. The watch is the planned body
(`proto.open_read_only(fold_on_close=True)`: `mode=rw`, `cache=private`, `query_only`,
`trusted_schema=OFF`). **26 of 26 facts as expected** (`rev2/m2x_crossproc.out`):

| Fact | Result |
|---|---|
| A. A fresh connection's value is comparable to a held one's | **no** (held 2 → 3 after 6 commits; a fresh one reads 2). A watch's baseline is its first read, which the watch takes at open. |
| B / **X1**. A held writer in another process, 3000 commits | **0 unseen**; the WAL stayed 4 152 992 B (restarts). Reviewer A: 0 of 3000, 17 distinct WAL salts; reviewer B: 0 of 3000. |
| B2. An UPDATE-only commit after a WAL restart; B3. a schema change | changes it; changes it |
| C1. A passive checkpoint by the other process | no change |
| C2. A web reader in this process opens, reads, closes | no change |
| C3. An empty write transaction; C4. an UPDATE matching no row | no change; no change |
| C5. The other process's writer closes while watched | no change; `-wal` and `-shm` stay |
| C6. A TRUNCATE checkpoint by another process | **changes it** (R1) |
| C7. The first commit after it | changes it |
| C8. A commit by another connection **of this process** (a UI write) | seen, with a private and with a shared cache |
| C9. A read while a same-process connection holds a write transaction | private cache: reads; **shared cache: `SQLITE_LOCKED_SHAREDCACHE` at once** (no busy wait). Why the opener pins `cache=private`. |
| D. Idle watch: the other process's passive checkpoint backfills every frame; no transaction held between reads | yes; yes |
| E. Watched: the other process's close and a web reader's close leave the store file and the WAL; the watch's own last close folds and removes the side files | yes; yes; yes |
| F. A store replaced at its path (`os.replace`) under the watch | `data_version` does not see it (the identity check does); the old watch's close leaves the new store's WAL |
| G. The store deleted under the watch, then the watch closed | nothing recreated |
| H. Rollback-journal mode, 50 UPDATEs by another process | 50 of 50 seen |
| I. `core.project._stat_key` over 3000 cross-process commits | unchanged on 0 (fine-grained mtimes; see §3.2 for the coarse tick) |
| **X3** (both reviewers, and here). A raw `open()`/`close()` of the main file in the watch's process, then a short writer's close in another process | `-wal`/`-shm` **deleted**; the watch then missed **200 of 200** (here, and B) / **300 of 300** (A); per-request web reads wrong on 186 and "malformed" on 114 of 300 (A); a later web-process write left the file "malformed" on disk (A); a fresh process saw **0 of 50** committed rows (B). |
| X3, with the magic checked through the opener instead | side files kept; **0 of 200** missed |
| N. The magic through SQLite (`PRAGMA schema_version` on the opener) | text, a 16-byte magic alone, random bytes, JSON: all `SQLITE_NOTADB`, no side file created; a 0-byte file is an empty database to SQLite (the callers keep their `st_size == 0` branch) |
| SQLite's backup API from an opener connection (`copy_to`'s source) | works (`rev2/backup_ro.out`) |

**X3b, how far the identity re-check defends** (`rev2/x3_identity_defence.out`; side files
deleted under a watch by an injected raw open, then a held writer in another process):

| Replacement watch | Missed of 200 |
|---|---|
| (a) opened before the stale one is closed, its first read after the close | 0 |
| (a2) its **first read while the stale one is still open** | **200** |
| (b) the stale one closed first, no other connection of the process open | 0 |
| (c) closed first, but a per-request reader of the process stayed open across the deletion | **200** |

SQLite shares one shared-memory node per inode inside a process; a connection that
attaches while any connection still holds the stale node inherits it. So the identity
re-check recovers only when nothing else of the process holds the store: a defence, never
the fix. The fix is that nothing drops the locks (D1).

### 1.5 How often each fingerprint misbehaves (M3x: `rev2/m3x_frequency.py`, writer in another process)

Readers are threads of the web process (`open_reader`, one read transaction, close); the
writer process takes a shared lock around each commit and its counter; the poller samples
under that lock every 20 ms for 4 s. *Spurious*: changed with no commit; *missed*: commits
and no change.

| Scenario | Today: changes / spurious / missed | Planned watch: changes / spurious / missed |
|---|---|---|
| 1 or 4 readers, no writer | 0 / 0 / 0 | 0 / 0 / 0 |
| 1 reader, short writes (open, commit, close; 16) | 15 / 0 / 0 | 15 / 0 / 0 |
| 4 readers, short writes (16) | 16 / **1** / 0 | 14 / 0 / 0 |
| 1 / 4 readers, a scan that ends (201 commits) | 43 / 0 / 0; 44 / 0 / 0 | 43 / 0 / 0; 44 / 0 / 0 |
| 1 reader, a held writer (786 commits) | 47 / 0 / **149 of 196 samples** | 197 / 0 / 0 |
| 4 readers, a held writer (791 commits) | 47 / 0 / **150 of 197 samples** | 196 / 0 / 0 |

Revision 1's in-process M3 (`m3_frequency.out`) had the same shape (140 and 137 missed).

### 1.6 What the live refresh does to the user (rev 1 probes, real Chromium: `test_zz_au_sitetree_probe.py`, `browser_probe_run1.log`, `browser_probe_run2_diagrams.log`)

| Probe | Today |
|---|---|
| p1 control: focus "Show more", Enter | `BUTTON`, 250 items |
| p2 a refresh between focus and Enter | focus **`BODY`**, Enter loads nothing: **200** (E3) |
| p3 a refresh while a "Show more" page loads | **200**, focus `BODY` (E4) |
| p4 a focused findings-count button | **`BODY`** (E5) |
| p5 Issues, 60 rows, a link focused | **50** rows, **`BODY`** (E5) |
| p6 control: a focused tree item | kept |
| p7 a checkpoint and no write after the baseline | one root re-fetch (E1 in the app) |
| Diagrams: interface row, origin group, sequence step, export link | **`BODY`** (E6) |
| Diagrams: run and scope `<select>` | kept |

The committed tests reproduce each of these on `7ebf48a` (§5.5). The original harness
failure (one full run, 200 of 250) is p2 meeting an E1 refresh caused by an earlier test's
writer frames folded by a reader's close.

### 1.7 BUG-0535 on today's code (D2: `rev2/d2_today.py`, `rev2/d2_today.out`)

`7ebf48a`, no watch anywhere. Every writer is another process. "Projects view" is the
real `ProjectManager.list_files()` reading the file (`core.project.summary`'s magic read);
each case has a control without it.

| Case | Control | With one Projects view |
|---|---|---|
| **P**, `fuzzlab web --with-proxy`: the real `ProxyController` holds its `Store` and records flows (`HistoryWriter`, batch 1); a short writer, then a 50-commit scan, then 5 more flows | side files kept; 76 of 76 flows, 50 endpoints, `integrity_check` ok | `-wal`/`-shm` **deleted** after the short writer; a web reader: `disk I/O error`; another process: **`vtable constructor failed: flow_fts`**, and still after every connection closed (**the project file is corrupt**) |
| **R**, a site-map request's reader held across the listing; a 100-commit scan; per-request readers; 5 UI writes | 0 wrong reads; 5 of 5 UI runs kept | side files **deleted**; **100 of 100** per-request reads wrong; the held reader: **"database disk image is malformed"**; UI writes reported ok 5/5, **1 of 5** in the file afterwards (4 lost silently); integrity ok after all closed |
| **T**, realistic: 2 threads loop open/read/close (30 ms read transactions), the listing every 150 ms, short writes every ~100 ms in another process, 8 s | no deletion under an open reader | `-wal` deleted **while a reader's transaction was open 11 (and, in an earlier run, 17) times**; no wrong read or loss detected in 8 s |

The hazard is real today. `--with-proxy` is the dangerous configuration: its `Store` lives
as long as the server, so one Projects view leaves the process unprotected until it stops.

### 1.8 Resources while a store is watched (D10)

**WAL disk use** (`rev2/w_walsize.out`; another process makes one ~40 MB transaction, 2000
small commits, then closes):

| | `-wal` after the big transaction | after 2000 small commits | after the writer's close | after the watch's release |
|---|---|---|---|---|
| not watched | 135 337 912 B | 135 337 912 B | deleted | |
| watched | 135 337 912 B | 135 337 912 B | **135 337 912 B** | deleted |
| watched, writer's `journal_size_limit` = 4 MiB | 135 337 912 B | **4 194 304 B** | 4 194 304 B | deleted |
| watched, `journal_size_limit` = 64 MiB | 135 337 912 B | 67 108 864 B | 67 108 864 B | deleted |

A watch does not grow the WAL; it keeps the writer's high-water mark on disk after the
writer closes, until the watch's release (an idle page: 60 s). An unwatched running scan
holds the same size for its whole life. `journal_size_limit` on writers (`core.store`)
would bound it at the next restart. It is **not needed for correctness**, it changes every
writer, so it is proposed as a CORE follow-up (Q1), and the size is a stated residual (R4).

**File descriptors** (`rev2/f_fds.out`): the watch holds 3 (main, `-wal`, `-shm`). While it
is held, SQLite defers a per-request reader's close (its inode has locks) and reuses
deferred descriptors: after 1, 4, 8, 16 concurrent reader threads the store's descriptors
were 4, 7, 11, 19, then stayed at 19 for 4 and 1 threads; 0 after the release. Bounded by
the peak concurrency (uvicorn's thread pool: 40), released with the watch (R10).

### 1.9 Probe files

Revision 1: `/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au-sitetree/`
(`m1`..`m7`, the browser probe and logs). Revision 2: `…/au-sitetree/rev2/`: `agent.py`
(the writer process), `proto.py` (the planned opener and watch, scratch), `d2_today.py`,
`m2x_crossproc.py`, `x3_identity_defence.py`, `m3x_frequency.py`, `w_walsize.py`,
`f_fds.py`, each with its `.out`; `proof7ebf/` and `counters_only.diff` (§5.5). The
reviewers' probes: `…/reviewA_sitetree/`, `…/review-b-au-sitetree/`. Never committed; the
tests in §5 replace them.

## 2. The defects, and when they entered

| | Defect | Where | Entered |
|---|---|---|---|
| E1 | The version changes with no write | `sitetree.py::store_version` | `6a996de` (CC-UI-0500); `1d02cd0` fixed only the open half |
| E2 | Commits after a WAL restart are not seen; polls and the G11 cache serve old state | same | `1d02cd0` (CC-UI-0503, A1) |
| E3 | A refresh replaces a focused "Show more"; focus to `<body>` | `sitetree.js::setTail` | `1d02cd0`; `cab3cea` handled removed items only |
| E4 | A refresh drops a "Show more" page the user asked for (either order) | click handler, `refreshGroup` | `1d02cd0` |
| E5 | A refresh drops focus from a row's control and an Issues link; Issues reset to page 1 | `refreshGroup`, `showNode`, `renderIssues` | `830a98f` (Issues), `1d02cd0` (rows) |
| E6 | The Diagrams refresh drops focus from 4 kinds of control | `diagrams.js::renderFlow`, `renderIfaceTable`, `renderSeq`, `exportLinks` | `ede72b9` (CC-UI-0058) |
| E7 | A raw open/close of the store in the web process drops SQLite's locks (BUG-0535) | `core/project.py::inspect` (`:132`), `::summary` (`:663`); exposed: the proxy's held `Store` (`web/proxycontrol.py:72`), per-request readers | `9f1536e`, `8569187` (CC-CORE-0450) |

The AU-SESS403 lane caused none of these (its diff touches no web or core file).

## 3. Design

### 3.1 Layer 1: the store version (SP-58; `fuzzlab/web/sitetree.py`)

**Chosen: one held watch connection, read with `PRAGMA data_version`.** The web layer
holds no connection today (every request opens its own `Store`), so the watch is a new held
resource owned by `sitetree.py`. It is safe only together with §3.2 (no raw open of a store
file anywhere in the web process): X3 and §1.7 show what a dropped lock does to it.

```
WATCH_IDLE_S = 60.0                     # a watch unused this long is released at the next call
WATCH_TIMEOUT_S = 1.0                   # the watch's busy wait; a busy read gives no version
MAX_POLL_MS = 30_000                    # half the idle release: pages are clamped to it
_clock = time.monotonic                 # injectable; tests never wait on wall time
_NONCE = secrets.token_hex(8)           # a server restart never repeats a version
_watch_lock = threading.Lock()          # every use of the watch and of _closing
_watch: _Watch | None                   # path, conn, ident (main, -wal, -shm), epoch, used
_closing: Counter[str]                  # paths whose released watch is still closing
_epoch = 0                              # process-wide reopen counter

def store_version(path) -> str | None   # path: str | PathLike | None | () -> str | None
def release_watches() -> None           # closes before it returns
```

`store_version(path)`. Under `_watch_lock`:
1. If `path` is callable (the routes pass `store_path`), call it **under the lock**, so a
   transition that cleared the open project and then released the watch can never be
   followed by a poll that read the old path earlier (D3).
2. `None` (no project open): release the watch; return `None`.
3. Release the watch if idle (`_clock() - used > WATCH_IDLE_S`) or on another path (one
   watch, for the current store only: D3).
4. `ident = (st_dev, st_ino)` of the main file, `-wal` and `-shm` (`os.stat`: never an
   open). A missing main file: release; return `None`.
5. A held watch whose recorded `ident` differs (a replace, a switch, or side files
   deleted under it): release; return `None`. The next call opens a fresh watch only
   after the old one is closed (step 6), so the fresh one never attaches to a stale
   shared-memory node of its own predecessor (X3b a2). Stated: if another connection of
   the process holds the store across such a deletion, the fresh watch inherits the stale
   node (X3b c); the defence is that no lock is dropped (§3.2).
6. No watch: if `_closing[path] > 0` (a released watch on this path is still closing),
   return `None`. Else open `core.store.open_read_only(path, timeout=WATCH_TIMEOUT_S,
   fold_on_close=True, any_thread=True)`, bump `_epoch`, read `PRAGMA data_version` (the
   baseline, fact A), record `ident` **after** that read (it creates the side files) and
   compare its main identity with step 4's: different (replaced during the open):
   release; return `None`.
7. Read `PRAGMA data_version`; `used = _clock()`; return
   `sha256(f"{_NONCE}:{dev}:{ino}:{epoch}:{dv}")[:32]`.
8. A failed read is swallowed only for `sqlite3.OperationalError` and exactly
   `sqlite3.DatabaseError` (PA-0106): release; return `None`. Anything else propagates
   (`ProgrammingError`, `InterfaceError`: exact-type check).

A release moves the connection out of `_watch` and increments `_closing[path]` under the
lock; the close runs **outside** the lock (it may fold the WAL), then `_closing[path]` is
decremented under the lock. `release_watches()` returns after its close.

**Why it catches every write a reader must see:** an UPDATE-only commit, a commit after a
WAL restart, every commit of a held writer across autocheckpoints, a rollback-mode commit,
a schema change, a same-process UI write (B, B2, B3, H, C8): `data_version` counts commits.
A switch, replace or removal: another path, another identity, or `None` (F). What never
changes it: a read, any connection's close, a passive checkpoint, an empty transaction
(C1-C5, E). While the watch is held nobody else's close is the last, so E1's fold does not
happen while a page watches the store.

**G11 still holds.** The children route takes the version (a fresh read on the watch)
before its snapshot; `test_fingerprint_is_taken_before_the_snapshot` keeps the order (its
monkeypatch passes the callable through).

**Threads: PA-0023's third pattern (D9).** `data_version` is per connection (fact A), so
the watch is one shared handle by necessity: opened `check_same_thread=False`
(`any_thread=True`), every use under `_watch_lock`, stated in the docstring, pinned by an
AST guard over `sitetree.py` and a many-thread test (§5.1, at implementation). PA-0534(4)
records this as PA-0023's third allowed pattern.

**Lifecycle (D3).** Releases: `store_version(None)`; another path; idle 60 s; an identity
change; a failed read; `ProjectManager._leave` (so `_switch`, close, discard, save as and
every transition) **after** `current = None` and **before** `_remove_project_files`;
`web/app.py::_lifespan` at shutdown; the tests' autouse fixture. Other removal sites
(a failed new, save-as or snapshot target, `_discard_leftover`) never hold the watch: it
follows the open project only.

**Pages (D10).** `web/app.py` passes `min(cfg value, sitetree.MAX_POLL_MS)` for
`sitetree_poll_ms` and `diagram_poll_ms`: a page polling slower than the idle release
would reopen the watch, and refresh, on every poll. `diagrams.js::poll` skips while the
page is hidden (as `sitetree.js` does), so a hidden tab lets the watch idle out.

**Unsupported (D3).** Windows (no POSIX lock-drop, but other file semantics: not
measured), network filesystems (SQLite's WAL needs shared memory on one host), and
replacing a store at its path without its side files while the UI watches it (F covers a
replace with its side files; a bare `cp` over a live WAL store corrupts it whatever the
UI does).

**Options rejected (unchanged from revision 1, with their measurements):** a file stat
plus a content counter (the WAL header and size are what miss E2; a trigger counter is a
schema change); `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` (fixes only the readers' fold, needs
Python 3.12); `data_version` on a fresh connection per poll (fact A); a `mode=ro` watch
(it leaves `-wal`/`-shm` on its own close, M5).

### 3.2 No raw open of a store file in the web process (BUG-0535; FR-CORE-508, CC-CORE-0071)

**The opener, `fuzzlab/core/store.py`** (+~35 lines):

```
def open_read_only(path, *, timeout: float, fold_on_close: bool = False,
                   any_thread: bool = False) -> sqlite3.Connection
    # file: URI of the resolved path, mode=ro (default: never writes the main file) or
    # mode=rw (its last close folds the WAL like any reader's), always cache=private;
    # check_same_thread=not any_thread; then PRAGMA query_only=1, trusted_schema=OFF;
    # closed on any failure. A missing file raises (nothing is created). Never runs
    # journal_mode, migrate or any write.
def is_sqlite(conn) -> bool
    # PRAGMA schema_version: False on SQLITE_NOTADB; any other error propagates.
```

**Every read-only open goes through it (disposition):**

| Site | Today | Revision 2 |
|---|---|---|
| `core/project.py:132` `inspect` magic | `open(p, "rb")` | removed: `is_sqlite` on the opener (the message stays "is not an SQLite database") |
| `:136` `inspect` | `sqlite3.connect(_ro_uri(p))` | `open_read_only(p, timeout=10.0)` |
| `:663` `summary` magic | `open(p, "rb")` | removed: `is_sqlite` (NOTADB is a `DatabaseError`: unreadable) |
| `:666` `summary` | `sqlite3.connect(_ro_uri(p), timeout=0.05)` | `open_read_only(p, timeout=0.05)` |
| `:718` `copy_to` source | `sqlite3.connect(_ro_uri(src))` | `open_read_only(src, timeout=timeout)` (backup API measured) |
| `core/project.py::_ro_uri` | the URI builder | removed |
| `harness/auto.py:528` `header_point_estimate` (the spider DB, the CLI's process) | `mode=ro` URI | `open_read_only(path, timeout=…)`: one owner of read-only opens |
| `web/sitetree.py:851` `store_version` `-wal` header | `open(base + "-wal")` | removed with the old body |
| `core/store.py:30` `_no_create_uri` (`open_store(create=False)`, a writer) | `mode=rw` | unchanged: the owner module |

`tests/test_query_placement.py::ALLOWED` follows: the `core/project.py::_ro_uri` and
`harness/auto.py::header_point_estimate` entries go, an entry for the opener's URI
builder in `core/store.py` comes (it is a SQLite `file:` URI, not HTTP).

**The listing's cache key (`core.project._stat_key`, D9, L1-12).** A summary is recomputed
when it is older than `SUMMARY_MAX_AGE_S` (2 s, `_summary_clock = time.monotonic`),
whatever its stat key: a commit inside the WAL's old extent within one coarse mtime tick
is then shown at most 2 s late, instead of never (measured only under emulation here:
fine-grained mtimes, fact I). About 10 lines in `summary`.

**The guard (PA-0535, `tests/test_web_store_locks.py`).** The scope is **computed**: every
module of `fuzzlab/web/`, plus every module the web package imports (AST, function-level
imports included, transitively) that opens SQLite (`sqlite3.connect`, `open_store`,
`Store`, `open_read_only`). In it, every `open()`, `io.open`, `os.open`, `os.fdopen`,
`.open()`, `.read_bytes()`, `.read_text()`, `.write_bytes()`, `.write_text()` and
`shutil.copy/copy2/copyfile/move` is flagged unless allowed by `(module, function, shape)`
with its exact count and its reason; a stale allowance fails. Today: 19 allowances (22 sites), each
"never a store's main file, `-wal` or `-shm`" or "a new inode created `O_EXCL`" (`create`,
`copy_to`), and exactly 3 offenders: `inspect`, `summary`, `store_version`. Proven on
synthetic offenders: every shape, a lazily imported SQLite module (in scope) and a non-SQLite
one (out), a grown count, a stale entry. Stated limits: a module handed a `Store` (not a
path) that raw-opens `store.path`, and a raw open through another name (`getattr(os,
"open")`), are not seen; the cross-process tests are the proof.

**The PA-0002 sweep** of every SQLite-opening module outside that scope (disco CLI and
live trace, the labgen live boots, the diagram CLI): each raw open is of a capture, JSON,
env, vendor or export file, never a store's (§4.2).

### 3.3 Layer 2: the user's place across a refresh (FR-UI-514)

**One helper, `fuzzlab/web/static/js/livefocus.js`** (an ES module, ~70 lines):

```
export function focusKeyIn(root)                       // data-focus-key of the focused control inside root, else null
export function restoreFocus(root, key, ...fallbacks)  // D7, below
export function rerender(root, draw, ...fallbacks)     // key = focusKeyIn(root); draw(); restoreFocus(...): synchronous
export function patchInPlace(oldEl, newEl)             // D10: keeps the focused node, below
```

**`restoreFocus` (D7).** It acts only when `key` is not null (focus was inside `root`
before the re-render) and focus is no longer on a connected element inside `root`: it never
steals focus. Candidates in order: `[data-focus-key=key]` inside `root`, then each fallback
(an element, or a function returning one). A candidate is taken only if it is connected,
not inside `[hidden]` and rendered (`getClientRects().length > 0`); it gets
`focus({preventScroll: true})`, and is accepted only if `document.activeElement` is then
that element; otherwise the next candidate is tried. **The chain always ends at the
region's pane**, a container with `tabindex="-1"` that is always rendered, the empty tree
included: never `<body>`. It returns the element focused (or `null` if even the pane
refused, which a test catches).

**`patchInPlace` (D10, screen readers).** When a re-rendered row contains the focused
control, the row is not replaced: the focused node stays in the document, its text and
attributes are copied from its counterpart (same key) in the new row, and the other
children are replaced around it. Nothing is removed under focus, so nothing is announced
again. Used for a tree item's row; "Show more" is reused in place by `setTail` (its cursor
lives on the element). A re-rendered Issues link or Diagrams control is restored by key
(a new node: announced again, R7).

**Focus keys (D5): identity, unique per live region, never position.**
- Site map, region `#st-tree`: a tree item `item:<group key or root>><data-id>`; a keyless
  node (too deep to key) has `kind:label:<label>`, and only identical siblings get
  `#2`, `#3` (the one positional tie-break, stated R7); "Show more" `more:<group key or
  root>`; the count button `count:<item key>`; the open link `open:<item key>`.
- Site map, region `#st-issues`: a finding link `issue:<finding id>`; "Show more findings"
  `issues-more`.
- Diagrams: an origin group `origin:<id>`; an interface row `iface:<id>`; an export link
  `export:json|flow|seq`; a sequence step `step:<first evidence key or ->:<type>:<kind>:
  <src>><dst>`, plus `#n` among identical steps. A capture record's request, forward and
  two response steps share one evidence key (`report/diagram.py:717-727`) and differ in
  kind, source and target; a tool exchange's request and response likewise (`:471-479`).
- B6 and B8 assert every focusable control in each live region has a key, unique there.

**Fallback chains.** Site map: a gone "Show more" → its group's last item → `#st-tree`; a
row's control → its item → the parent item → `#st-tree`; a gone item → the parent item
(today's `dropNode`) → `#st-tree`; an Issues link → `#st-issues`. Diagrams: each region's
own container. Templates add `tabindex="-1"` to `#st-tree`, `#dg-flow`, `#dg-ifaces`,
`#dg-seq`, `#dg-exports` (`#st-issues` has it).

**One ordering rule for a user's page load against a refresh (D6).**
1. The user's load registers a token on its container **before** its fetch:
   `container._more = {before, hadFocus}` for "Show more", `state.issuesMore` for "Show more
   findings".
2. A refresh of that container reads the token and the loaded count **before and after**
   its own fetch. Before: it fetches `loaded + PAGE` when a token is set. After: if the
   token or the count changed while it was in flight, it fetches once more with the new
   values. It then reconciles, delivers the page, consumes the token and places focus
   (item `before` when the button had focus).
3. The user's load, when its fetch returns: token consumed → it does nothing (the refresh
   delivered); token live and its generation current → it appends, de-duplicated by
   identity (tree: `data-id`; Issues: `renderIssues` skips a finding id already shown),
   and consumes the token; token live but a refresh in flight → it leaves the token to that
   refresh (step 2's "after" read); the container gone or collapsed → the token dies with
   it, and a still-attached button is re-enabled: nothing is lost silently.
4. Both orders are tested by holding a fetch: the user's page held while a refresh runs
   (B2), and the refresh's group or Issues fetch held while the user asks (B2b, B5b).
   Generations stay as they are: an old cursor's page is never appended after a refresh,
   which could skip an item a write inserted before the cursor.

**Issues (E5).** On a refresh, `showNode` runs with `{keep: true}`: it fetches as many
findings as are shown (pages of 200, following `next`) plus a page when `issuesMore` is
set, and renders them through `rerender(#st-issues, …, #st-issues)`. `refresh()` awaits
it, so "refresh done" includes the selection.

**Page counters (D8).** `#sitetree-root` and `#diagrams-root` carry `data-baseline="1"`
once the first poll has its version, `data-polls` (completed polls) and `data-refreshes`
(completed refreshes, the selection's Issues and the Diagrams sequence included). Tests
wait on them and never sleep; a poll that skips (hidden page, failed fetch) is not counted.

**`aria-activedescendant` (D10).** No view uses it today. FR-UI-514 states the rule for one
that does: it re-points `aria-activedescendant` at the element with the same key.

**Content Security Policy.** No inline script, no HTML parsing; the banned-sink guard
follows imports, so it scans `livefocus.js`; `test_web_pages_browser.py` smokes both pages.

### 3.4 Unchanged on purpose

- `/api/sitetree/version`'s shape (`{"version": str | null}`), the rate limit of one
  refresh per poll interval, the generations, the routes' read-only contract, the schema.
- `web/projects.py` changes by one call in `_leave` (D3); its transitions are otherwise as
  they are. `core/` changes only as §3.2 says. The session package is AU-SESS403's.

## 4. The sweep (PA-0002; PA-0138(3); SHARED_PRIMITIVES rule 2; PA-0152)

### 4.1 Every consumer of `store_version` (`grep -rn store_version fuzzlab/ tests/`)

| Consumer | Reads | Disposition |
|---|---|---|
| `web/sitetree_routes.py::sitetree_version` | the version | passes the `store_path` callable |
| ↳ `static/js/sitetree.js::poll` | baseline, then refresh | counters; E3-E5 fixed |
| ↳ `static/js/diagrams.js::poll` and its baseline | refresh (`loadRuns`) | counters; visibility; E6 fixed |
| `web/sitetree_routes.py::sitetree_children` | the cache key (G11) | passes the callable; order kept |
| `web/diagram_routes.py` (docstring) | prose | "the store version (FR-UI-505)" |
| `web/projects.py::ProjectManager._leave` (new) | releases | D3 |
| `web/app.py::_lifespan` (new) | releases | at shutdown |
| `tests/test_web_sitetree.py`, `tests/test_web_sitetree_scale.py:202`, `tests/test_web_store_locks.py`, `tests/test_web_projects.py` | the value | §4.4 |

### 4.2 Raw opens and other "has the store changed" detectors

| Site | What it is | Disposition |
|---|---|---|
| `core/project.py::inspect`, `::summary` | raw magic reads (E7) | removed (§3.2) |
| `web/sitetree.py::store_version` | raw `-wal` header read; a fingerprint from files | replaced (§3.1) |
| `core/project.py::_stat_key` → `summary` cache | `(dev, ino, size, mtime_ns)` of the store and `-wal` | kept as the key; bounded by `SUMMARY_MAX_AGE_S` (L1-12); allowance in the fingerprint guard |
| `core/project.py::file_facts` | a display of size and last write | allowance: not a change signal |
| `core/project.py::copy_to` (`getsize` of `-wal`) | a disk-space estimate | allowance |
| `core/project.py::create`, `::copy_to` (`os.open`) | a new `O_EXCL` inode; the copy's fsync after its connections closed | allowed raw opens |
| `web/projects.py` (`_acquire_owner`, `_parse_recent`, `_remove_*`, `_copy_sidecars`'s CSV), `web/labcontrol.py`, `web/projectroutes.py` (a method named `open`) | not store files | allowed raw opens, with reasons |
| the CLI modules the web imports for their parsers (`greybox_cli`, `auto_cli`, `authhttp`, `blind_sqli_fuzzer`, `observe`, `store_adapter`) | cookie, account, body-part, CSV, JSONL, JSON files | allowed raw opens, with reasons |
| outside the web scope: `disco/cli.py`, `disco/livetrace.py`, `labgen/conformance/*live_boot.py`, `report/diagram_cli.py` | capture, actions, JSON, env, vendor, export files | swept: no store file |
| `web/projects.py` identity checks, `web/proxycontrol.py:273` | `(dev, ino)` for remove and copy | identity, not change detection |
| `tests/conftest.py::_default_store_state`, `tests/_store_guard.py` | `stat` of the default store's files | a test guard; `stat` never opens |

### 4.3 Every live-refresh view (`grep -n "setInterval\|setTimeout(poll\|EventSource\|subscribe(\|sitetree/version" static/js/*.js`)

| Script | Live mechanism | Re-renders focusable controls? | Disposition |
|---|---|---|---|
| `sitetree.js` | version poll | yes (E3-E5) | fixed; registered (G1) |
| `diagrams.js` | version poll | yes, 4 kinds (E6) | fixed; registered |
| `proxy.js` | 1.2 s pending poll | no: its rows hold no tabindex, link or button | exempt, with that reason |
| `lab.js`, `launcher.js` | SSE output | no: text appended to one `<pre>` | exempt |
| `common.js` | the `subscribe` helper | no DOM | exempt |

Observations outside this item (PA-0143, opened by this session, waiting for the user):
keyboard activation of the Diagrams page's `role=button` groups, rows and steps (no
keydown handler); the Diagrams selection highlight across a refresh; keyboard access to
`proxy.js`'s pending rows.

### 4.4 Existing tests whose expectation could change (phase 2's harness run confirms)

- `test_web_sitetree.py`: `test_version_changes_on_an_update_only_commit` (a same-process
  commit: C8), `test_a_cached_child_list_is_never_served_for_a_newer_store`,
  `test_reads_never_change_the_version_fingerprint`, `test_fingerprint_is_taken_before_the_snapshot`
  (its lambda passes the callable through), `test_site_tree_routes_are_read_only`: all
  expected to pass unchanged.
- `test_web_sitetree_scale.py`: the watch's PRAGMA is its own connection; it never enters
  the request's VM counters.
- `test_web_projects.py`: the BUG-0146 trio and the discard test (a watch is released
  before the files go).
- `test_query_placement.py`: `ALLOWED` edited (§3.2).
- `test_core_project.py`: the magic refusal's message is kept; the 0-byte branch kept.
- Every web test: the autouse fixture `tests/conftest.py::_release_store_watches` releases
  watches after each test (it lands with the implementation: on `7ebf48a` the function it
  calls does not exist).

### 4.5 `docs/SHARED_PRIMITIVES.md`: proposed row (text for the coordinator)

> | SP-58 | Whether the open store changed since a page last looked: the store version (SQLite's `PRAGMA data_version` on one held, `query_only`, private-cache connection on the open project's store, through `core.store.open_read_only`, with the identity of the store, its `-wal` and `-shm`, a reopen epoch and a process nonce; every commit changes it, no read, close or passive checkpoint does; safe only because the web process never opens a store file except through SQLite, PA-0535) | `fuzzlab/web/sitetree.py::store_version` (with `release_watches`; read by `/api/sitetree/version` for the site map and Diagrams pages and as the child-list cache key, G11; released by `ProjectManager._leave` and the lifespan) | `tests/test_web_sitetree.py::test_every_commit_of_a_held_writer_in_another_process_changes_the_version`, `tests/test_web_sitetree.py::test_no_read_close_or_checkpoint_changes_the_version`, `tests/test_web_sitetree.py::test_no_module_fingerprints_the_store_from_its_files`, `tests/test_web_sitetree.py::test_the_store_fingerprint_guard_catches_synthetic_offenders`, `tests/test_web_store_locks.py::test_no_web_process_module_opens_a_store_file_except_through_sqlite`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | PA-0534, PA-0535 (CC-UI-0068, CC-CORE-0071) |

The table accepts Python owners only, so `livefocus.js` is held by its own guard (G1-G3).
The opener is a CORE primitive used by the SP-58 owner; it gets no row of its own unless the
coordinator prefers one (Q3).

## 5. Tests

"Fails on `7ebf48a`" was run and recorded (§5.5). "Design guard" passes on `7ebf48a` by
construction (today holds nothing) and is proven at implementation against the named
mutant (PA-0034(2)).

### 5.1 Layer 1 and the watch (`tests/test_web_sitetree.py`, `tests/test_web_projects.py`; writers via `tests/_xproc.py`, another process)

| # | Test | On `7ebf48a` | Must also fail on |
|---|---|---|---|
| L1-1 | `test_a_readers_last_close_never_changes_the_version` | **fails**: the fold changed it | a watch released between polls |
| L1-2 | `test_every_commit_of_a_held_writer_in_another_process_changes_the_version` (asserts a WAL restart: the writer's own header, checkpoint sequence > 0) | **fails**: 2783 of 3000 unseen | a stat-based body |
| L1-3 | `test_no_read_close_or_checkpoint_changes_the_version[…]`, 5 cases | **fails** for "the writer process closes with frames in the WAL" and "a passive checkpoint"; the reader, empty-transaction and no-row cases pass (controls) | a watch that reopens per call |
| L1-4 | `test_a_commit_hidden_by_a_wal_restart_is_never_served_from_the_cache` (through the route) | **fails**: `['a']` served for `['a', 'b']` | a key taken after the snapshot |
| L1-5 | `test_a_replaced_or_removed_store_changes_the_version` | design guard | a watch without the identity check (F) |
| L1-6 | `test_a_reopened_watch_never_repeats_a_version` (epoch, nonce) | at implementation (needs `release_watches`) | a watch without its epoch or nonce |
| L1-7 | `test_rollback_journal_commits_are_seen_under_a_coarse_clock` (`os.utime`) | **fails**: 20 of 20 unseen | |
| L1-8 | `test_a_failed_read_is_no_version_and_any_other_error_propagates` | at implementation (injects into the watch) | a broad `except`; "return the last version" |
| L1-9 | `test_the_store_watch_is_used_only_under_its_lock` (AST) + synthetic offender; `test_concurrent_polls_from_many_threads_agree` (8 threads, a writer process) | at implementation (names the lock) | a use outside the lock; no `check_same_thread=False` |
| L1-10 | `test_the_store_version_never_creates_or_migrates_a_store` | design guard | a watch through `open_store`/`Store` |
| L1-11 | `test_no_module_fingerprints_the_store_from_its_files` + `test_the_store_fingerprint_guard_catches_synthetic_offenders` (the owner is **not** exempt; allowances `_stat_key`, `file_facts`, `copy_to`) | **fails**: `fuzzlab/web/sitetree.py::store_version`; the self-test passes | re-adding the old body anywhere |
| L1-12 | `test_the_project_listing_never_serves_a_summary_older_than_its_bound` (`_summary_clock`, `os.utime`) | **fails**: 2 runs shown for 3 | `summary` without the age bound |
| L1-13 | `test_leaving_a_temporary_project_leaves_no_descriptor_on_its_files[close with discard / save as]` (`/proc/self/fd`) | design guard | `_leave` without the release |
| L1-14 | `test_only_the_open_projects_store_is_watched` | design guard | a watch registry over several paths |
| L1-15 | `test_a_released_watch_is_closed_outside_the_lock`; `test_a_replacement_watch_never_reads_before_its_predecessor_closed` (X3b a2) | at implementation | a close under the lock; no `_closing` |

### 5.2 BUG-0535 and the opener (`tests/test_web_store_locks.py`, `tests/test_core_store_read_only.py`)

| # | Test | On `7ebf48a` |
|---|---|---|
| K1 | `test_a_projects_listing_never_drops_the_in_process_proxys_store_locks` (the real `ProxyController`, a writer process; then 10 flows and a fresh process's `integrity_check` and counts) | **fails**: the side files deleted under the proxy's `Store` |
| K2 | `test_a_projects_listing_never_drops_a_request_readers_locks` (a 20-commit scan in another process, per-request readers, a UI write) | **fails**: deleted under a request's reader |
| K3 | `test_opening_a_project_never_drops_a_held_connections_locks` (`inspect`) | **fails**: deleted under a held `Store` |
| K4 | `test_a_projects_listing_never_drops_the_store_watchs_locks` (the watch sees 50 of 50 after a listing and a short writer) | design guard (the reviewers' X3) |
| K5 | `test_no_web_process_module_opens_a_store_file_except_through_sqlite` | **fails**: `inspect`, `summary`, `store_version` |
| K6 | `test_the_store_file_guard_catches_synthetic_offenders` | passes (the guard's own proof) |
| C1 | `test_the_read_only_opener_never_creates_writes_or_migrates` (both modes; missing, write refused, an older schema neither migrated nor switched to WAL) | **fails**: no opener |
| C2 | `test_the_read_only_opener_pins_a_private_cache` (C9) | **fails**: no opener |
| C3 | `test_whether_a_file_is_sqlite_is_asked_of_sqlite_never_read_raw` (`builtins.open` and `os.open` refuse the files) | **fails**: "a raw open of …/junk.fuzzlab" |
| C4 | `test_every_read_only_open_goes_through_the_opener` + `test_the_read_only_open_guard_catches_synthetic_offenders` | **fails**: `core/project.py::_ro_uri`, `harness/auto.py::header_point_estimate`; the self-test passes |

### 5.3 Layer 2, real Chromium, `FUZZLAB_REQUIRE_BROWSER=1` (synchronised on the page counters)

| # | Test | On `7ebf48a` + counters only (§5.5) |
|---|---|---|
| B1 | `test_web_sitetree_browser.py::test_a_refresh_keeps_focus_on_show_more_and_enter_still_loads_the_page` | **fails**: "Show more" not focused |
| B2 | `::test_a_refresh_during_a_show_more_load_still_delivers_that_page` (the user's page held with `page.route`, seen with `expect_request`) | **fails**: 200 items for 250 |
| B2b | `::test_show_more_pressed_while_a_refresh_loads_its_group_is_kept` (the refresh's group fetch held, Enter, release) | **fails**: 250 → 200 when the refresh lands |
| B3 | `::test_a_refresh_that_ends_a_groups_paging_keeps_focus_in_the_tree` | **fails**: the last item not focused |
| B4 | `::test_a_refresh_keeps_focus_on_a_control_inside_a_row[findings count / open link]` (the **same node** keeps focus: in place) | **fails**: `BODY`, both |
| B5 | `::test_a_refresh_keeps_the_issues_pages_and_the_focused_finding` | **fails**: 50 rows for 60 |
| B5b | `::test_show_more_findings_pressed_while_a_refresh_loads_issues_is_kept` (the refresh's Issues fetch held, click, release) | **fails**: 60 → 50 |
| B6 | `::test_every_focusable_control_in_the_site_maps_live_regions_has_a_focus_key` (every kind present; keyed; unique) | **fails**: no keys |
| L1-B | `::test_a_checkpoint_with_no_write_never_refreshes_the_page` (three counted polls after the fold) | **fails**: 1 refresh with no write |
| B7 | `test_web_diagrams.py::test_a_live_refresh_keeps_focus_on_every_kind_of_control[interface row / origin group / response step / export link / run select / scope select]` | **fails**: `BODY` for the 4 rendered kinds; the two selects pass (controls) |
| B8 | `::test_every_focusable_control_in_the_diagrams_live_regions_has_a_focus_key` (all four regions present; keyed; unique) | **fails**: no keys |
| B9 | `restoreFocus` on an empty tree ends at `#st-tree`; a candidate that refuses focus is skipped | at implementation |
| (kept) | `test_a_refresh_keeps_focus_selection_and_loaded_pages`, `test_show_more_from_the_keyboard_keeps_focus_in_the_tree` | pass |

Every B test asserts its refresh happened (`data-refreshes` grew and the written node is
shown). Existing tests keep their waits (D8: only the tests touched change).

### 5.4 Guard (`tests/test_web_live_focus.py`, `package_guard`)

| # | Test | On `7ebf48a` |
|---|---|---|
| G1 | `test_every_live_view_is_registered_with_its_focus_test` (discovery by text; registry of tests checked by AST, or a reasoned exemption; stale fails) | passes (the registry is written; the views are known) |
| G2 | `test_the_live_view_registry_catches_synthetic_offenders` | passes (the guard's own proof) |
| G3 | `test_every_live_view_restores_focus_through_the_one_helper` + `test_the_one_helper_guard_tells_a_definition_from_a_use` | **fails**: `livefocus.js` is missing; the self-test passes |

### 5.5 The proof runs on `7ebf48a`

- Offline (`tests/test_web_store_locks.py`, `tests/test_core_store_read_only.py`,
  `tests/test_web_live_focus.py`, the new tests of `test_web_sitetree.py` and
  `test_web_projects.py`) ran on the worktree at `7ebf48a` itself (no `fuzzlab/` change):
  **17 failed, 19 passed**; every failure is the one named in §5.1-§5.4 and every pass is a
  control, a design guard or a guard's self-test. The two modified offline files in full:
  8 failed (the new tests), 232 passed, 2 xfailed: no existing test changed outcome.
- Browser: `7ebf48a` has no page counters, so the B tests would only time out at their
  first counter wait there. They were run on a scratch copy of `7ebf48a` plus a
  **counters-only** patch (`rev2/counters_only.diff`, 35 lines: the three counters, and
  `refresh()` awaiting its `showNode` so "refresh done" includes the selection; no other
  change): **15 failed, 25 passed** over both browser files; the 15 are the B tests above,
  each for its stated reason; the 25 are the existing tests and the two select controls.
- The whole-package guards that scan `tests/` stay green with the new files (463 passed,
  8 xfailed: `test_no_wall_clock_ratio`, `test_no_startup_timing`,
  `test_no_arrival_order_oracle`, `test_procutil_guard`, `test_loopback_listeners`,
  `test_server_port_ownership`, `test_pytest_lock_wiring`, `test_browser_scope`,
  `test_guarded_navigation`, `test_pa_enforcement`, `test_requirements_traceability`,
  `test_query_placement`, `test_shared_primitives`).
- At implementation: `scripts/verify_change.py --base 7ebf48a`, then `--full` before merge,
  the file count and pass, fail and skip counts quoted, the browser files' pass counts
  quoted separately (PA-0065(2)), and each "must also fail on" mutant run and recorded.

## 6. Requirement text

**FR-UI-505, edited in place:**

> - **FR-UI-505** *(added CC-UI-0500; the version and the refresh's guarantees CC-UI-0068)* **Site tree: live.** The page polls `GET /api/sitetree/version` while visible, at most every `sitetree_poll_ms` (clamped to `sitetree.MAX_POLL_MS`). The version (`sitetree.store_version`, SP-58) is SQLite's own change counter (`PRAGMA data_version`) read through **one** connection the server holds on the open project's store (`core.store.open_read_only`: `query_only`, private cache; it never creates, migrates or writes the store), with the identity of the store, its `-wal` and `-shm`, a reopen epoch and a per-process nonce:
>   - every commit by any other connection, of any process, changes it -- an UPDATE-only one, one after a WAL restart, each commit of a long held-writer burst, one in rollback-journal mode, a schema change -- and so do the store being replaced at its path, removed, or switched for another;
>   - a read, any connection's close, an empty transaction and a passive checkpoint never change it;
>   - a reopened watch (another store, 60 s unused, a failed read, a changed identity, a server restart) always gives a new version; a failed read or a changed identity gives none (`null`), never the previous one.
>
>   The watch is released when the project is left (before any of its files is removed), when unused for 60 s, and at shutdown. It is safe only because the web process never opens a store's file except through SQLite (FR-CORE-508, PA-0535). When the version changes the page refreshes in place -- the root, every expanded group (as many items as it shows, plus a page the user asked for), the selection (its Issues pages as loaded) -- at most once per poll interval; a node that is gone is removed; the user's place is kept (FR-UI-514). Stated residuals: an explicit RESTART or TRUNCATE checkpoint by another program, and a reopened watch, each cause one refresh with no write; a failed read or a changed identity causes two (to `null`, then to the new version); a byte-for-byte overwrite of the live store file in place (same inode) is seen only at the next commit; Windows and network filesystems are unsupported. SSE is not used: a long-lived stream holds uvicorn's graceful shutdown, and with it the lifespan shutdown that stops launched jobs (BUG-0125).
>   - Enforced by: `tests/test_web_sitetree.py::test_every_commit_of_a_held_writer_in_another_process_changes_the_version`, `::test_no_read_close_or_checkpoint_changes_the_version`, `::test_a_readers_last_close_never_changes_the_version`, `::test_a_commit_hidden_by_a_wal_restart_is_never_served_from_the_cache`, `::test_a_replaced_or_removed_store_changes_the_version`, `::test_a_reopened_watch_never_repeats_a_version`, `::test_rollback_journal_commits_are_seen_under_a_coarse_clock`, `tests/test_web_projects.py::test_leaving_a_temporary_project_leaves_no_descriptor_on_its_files`, `tests/test_web_store_locks.py::test_a_projects_listing_never_drops_the_store_watchs_locks`, `tests/test_web_sitetree_browser.py::test_a_checkpoint_with_no_write_never_refreshes_the_page`

**FR-UI-510, its "live" bullet edited in place:**

> - live: the store version (FR-UI-505) is taken before the first read and polled every `diagram_poll_ms` (3000, clamped to `sitetree.MAX_POLL_MS`) while the page is visible; a change reloads the run, keeping the user's place (FR-UI-514).

**FR-UI-514, new:**

> - **FR-UI-514** *(added CC-UI-0068, BUG-0534)* **A live refresh keeps the user's place.** Every page that refreshes itself while open (the site map, FR-UI-505; the Diagrams page, FR-UI-510; any later one) keeps the focused control focused across a refresh: the same element where it is updated in place (a focused row is patched around it), else the control with the same focus key (`data-focus-key`, naming its identity, unique in its region, never its position); else its nearest visible equivalent -- a removed tree item's parent, a gone "Show more"'s group's last item, a row control's tree item -- ending at the region's pane, never the page body; focus is accepted only where it actually landed, and restoring never scrolls (`preventScroll`). A view using `aria-activedescendant` re-points it at the element with the same key. Work the user started that a refresh overlaps (a "Show more" page, a page of Issues) is delivered exactly once, whichever comes first, and never dropped silently. One helper remembers and restores (`static/js/livefocus.js`). Each live page exposes `data-baseline`, `data-polls` and `data-refreshes` on its root. Every page script that polls or streams is registered with its real-browser focus tests or a reasoned exemption; each focusable control a live region re-renders carries a focus key, and each kind is tested across a change after the first load (PA-0518(1), PA-0534). Stated residuals: a control re-created by key (an Issues link, a Diagrams control) is announced again by a screen reader; a click whose row is replaced between mousedown and mouseup is lost; scroll position is not restored.
>   - Enforced by: `tests/test_web_live_focus.py::test_every_live_view_is_registered_with_its_focus_test`, `::test_the_live_view_registry_catches_synthetic_offenders`, `::test_every_live_view_restores_focus_through_the_one_helper`, `tests/test_web_sitetree_browser.py::test_a_refresh_keeps_focus_on_show_more_and_enter_still_loads_the_page`, `::test_a_refresh_during_a_show_more_load_still_delivers_that_page`, `::test_show_more_pressed_while_a_refresh_loads_its_group_is_kept`, `::test_a_refresh_that_ends_a_groups_paging_keeps_focus_in_the_tree`, `::test_a_refresh_keeps_focus_on_a_control_inside_a_row`, `::test_a_refresh_keeps_the_issues_pages_and_the_focused_finding`, `::test_show_more_findings_pressed_while_a_refresh_loads_issues_is_kept`, `::test_every_focusable_control_in_the_site_maps_live_regions_has_a_focus_key`, `tests/test_web_diagrams.py::test_a_live_refresh_keeps_focus_on_every_kind_of_control`, `::test_every_focusable_control_in_the_diagrams_live_regions_has_a_focus_key`

**NFR-UI-live, amended:**

> *(CC-UI-0500:)* the site tree polls the store version (FR-UI-505) and holds no long-lived HTTP connection. *(CC-UI-0068:)* the server holds one SQLite connection, on the open project's store, while a live page polls it (released 60 s after the last poll, when the project is left, and at shutdown); it never holds a transaction between reads -- a writer's checkpoint completes -- and never writes (`query_only`). While it is held: no other connection's close folds the WAL, so `-wal` keeps its high-water mark (the largest transaction's WAL; 135 MB measured for one ~40 MB insert) until a writer's restart or the release; a hand copy of the bare `.db` lacks recent commits (as with any writer open); SQLite defers per-request readers' descriptor closes, bounded by the peak concurrency and freed with the release.

**NFR-UI-read-only (SAFETY), its Enforced-by list gains:**
`tests/test_web_sitetree.py::test_the_store_version_never_creates_or_migrates_a_store`,
`tests/test_core_store_read_only.py::test_the_read_only_opener_never_creates_writes_or_migrates`.

**FR-CORE-508, new (`docs/components/02-core-library/requirements.md`):**

> - **FR-CORE-508** *(one read-only opener; a SQLite file is touched only through SQLite; `CC-CORE-0071`, 2026-10-20, BUG-0535)* `core.store.open_read_only(path, *, timeout, fold_on_close=False, any_thread=False)` is the one read-only open of a SQLite file in `fuzzlab/`: an existing file only (a missing one raises; nothing is created), `cache=private`, `query_only`, `trusted_schema=OFF`, never a journal-mode change, a migration or a write; `mode=ro` by default (the main file is never written; `-wal`/`-shm` may be left), `mode=rw` when its last close should fold the WAL like any reader's. `core.store.is_sqlite(conn)` answers whether the file is SQLite (`SQLITE_NOTADB`). A process that holds, or may hold, SQLite connections never opens, reads, writes or copies a database's main file, `-wal` or `-shm` outside SQLite: on POSIX the close of any descriptor of a file releases every lock the process holds on it, SQLite's WAL protection included (BUG-0535). `core.project.summary` never serves a summary older than `SUMMARY_MAX_AGE_S` (2 s).
>   - Enforced by: `tests/test_core_store_read_only.py::test_the_read_only_opener_never_creates_writes_or_migrates`, `::test_the_read_only_opener_pins_a_private_cache`, `::test_whether_a_file_is_sqlite_is_asked_of_sqlite_never_read_raw`, `::test_every_read_only_open_goes_through_the_opener`, `tests/test_web_store_locks.py::test_no_web_process_module_opens_a_store_file_except_through_sqlite`, `tests/test_web_sitetree.py::test_the_project_listing_never_serves_a_summary_older_than_its_bound`

## 7. Residuals (stated; each fails toward a refresh, never toward stale state, except R2)

- **R1.** An explicit RESTART or TRUNCATE checkpoint by another program changes
  `data_version` (C6): one refresh with no write. Nothing in `fuzzlab/` runs one.
- **R2.** A byte-for-byte overwrite of the live store in place (same inode) is seen only at
  the next commit. Unsupported: it corrupts a live WAL store.
- **R3.** A reopened watch (a switch, 60 s idle, a server restart): one refresh, by design.
- **R4.** While watched, `-wal` keeps the writer's high-water mark until a restart or the
  release (135 MB for one ~40 MB transaction, §1.8); a hand copy of the bare `.db` lacks
  recent commits. `journal_size_limit` (Q1) would bound it.
- **R5.** One watch, polls serialised on one lock. A busy read waits at most 1 s and gives
  `null`; a failed read or a changed identity gives `null` and then a new version: **two
  refreshes**, the cache bypassed for the `null` one.
- **R6.** SQLite's moved-file check (F) and the shared-memory behaviour (X3b) are measured
  on 3.45.1, Linux. Windows and network filesystems are unsupported (§3.1).
- **R7.** Focus keys match identity; identical keyless siblings are told apart by
  occurrence (the one positional tie-break). A control re-created by key is announced
  again by a screen reader. Scroll position is not part of this item.
- **R8.** G1's discovery is by text: a script polling through another spelling is not
  discovered; its real-browser test, once written, is the proof. K5's limits are in §3.2.
- **R9.** A click is lost if its row is replaced between mousedown and mouseup (the browser
  fires no click on a replaced target). Rows holding focus are patched in place, so a
  keyboard user is not affected.
- **R10.** While a watch is held, SQLite defers per-request readers' descriptor closes:
  up to the peak number of concurrent readers (19 with 16 threads, §1.8), all freed with
  the release.
- **R11.** If any other connection of the web process holds a store across a deletion of
  its side files, a fresh watch inherits the stale node (X3b c). With no raw open left
  (K5) nothing in the web process can cause such a deletion.

## 8. Change-control entries (drafts)

### CC-UI-0068 — The store version is SQLite's change counter on one held read-only connection; a live refresh keeps the user's place (FR-UI-505, FR-UI-510, FR-UI-514, BUG-0534, BUG-0535) (2026-10-20)
- Change:
  - **`fuzzlab/web/sitetree.py`** (+~140/−26): `store_version(path)` as §3.1 (one watch
    for the current store, `_watch_lock`, `_closing`, identity of main/`-wal`/`-shm`,
    epoch, nonce, idle release on `time.monotonic`, named swallows); `release_watches()`;
    `MAX_POLL_MS`; the docstring states the measured contract.
  - **`fuzzlab/web/sitetree_routes.py`** (+2/−2): the version and children routes pass the
    `store_path` callable.
  - **`fuzzlab/web/projects.py`** (+3): `_leave` releases the watch after `current = None`,
    before any file is removed.
  - **`fuzzlab/web/app.py`** (+4): the lifespan releases watches at shutdown; both poll
    intervals clamped to `sitetree.MAX_POLL_MS`.
  - **`fuzzlab/web/static/js/livefocus.js`** (new, ~70): `focusKeyIn`, `restoreFocus`,
    `rerender`, `patchInPlace`.
  - **`fuzzlab/web/static/js/sitetree.js`** (+~120/−20): focus keys; `setTail` reuses
    "Show more" in place and falls back to the group's last item; the ordering rule (§3.3)
    for "Show more" and "Show more findings"; rows holding focus patched in place;
    `showNode({keep})` awaited by `refresh()`; `renderIssues` de-duplicates; counters.
  - **`fuzzlab/web/static/js/diagrams.js`** (+~50/−12): focus keys (steps derived beyond
    their evidence key); every re-render through `rerender`; the poll skips a hidden page;
    counters.
  - **`templates/sections/sitetree.html`**, **`diagrams.html`** (+5): `tabindex="-1"` panes.
  - **`web/diagram_routes.py`**: docstring only.
  - **Tests** (committed with the draft, failing on `7ebf48a`, §5): `tests/_xproc.py`
    (new), `tests/test_web_sitetree.py`, `tests/test_web_projects.py`,
    `tests/test_web_store_locks.py` (new), `tests/test_web_sitetree_browser.py`,
    `tests/test_web_diagrams.py`, `tests/test_web_live_focus.py` (new); at implementation
    L1-6, L1-8, L1-9, L1-15, B9 and the autouse fixture in `tests/conftest.py`.
- Impact:
  - The web UI, plus CORE's opener (CC-CORE-0071). No schema or API-shape change:
    `{"version": str | null}` stays opaque.
  - Consumers, from the code (PA-0152): §4.1.
  - The server holds one read-only connection while a page watches the store
    (NFR-UI-live amended; R4, R10). It reverses CC-UI-0500's "a fingerprint with no SQLite
    at all"; it removes the harness failure's cause.
  - BUG-0535's fix is CC-CORE-0071's; this entry depends on it (the watch is unsafe
    without it, X3).
- Risk: **medium-high**: a held resource in a multi-threaded server whose correctness
  depends on a process-wide invariant (no raw open). Mitigated by the computed guard (K5),
  the cross-process regression tests (K1-K4), the identity re-check (a stated partial
  defence, X3b), one watch only, release before removal, named swallows (PA-0106),
  `query_only` and no-create (PA-0452), the lock with its AST guard and a many-thread
  test (PA-0023's third pattern), and real-browser tests under
  `FUZZLAB_REQUIRE_BROWSER=1`. Rollback: the old function body and the JS files.
- Deliverables:
  - [x] measurements: rev 1 (M1-M7, browser probes) and rev 2 (§1.4-§1.8) — done
  - [x] failing tests committed and run on `7ebf48a` (§5.5) — done
  - [ ] draft confirmed by one review — todo
  - [ ] `store_version`, `release_watches`, the routes, `_leave`, the lifespan, the clamps — todo
  - [ ] `livefocus.js`; `sitetree.js`; `diagrams.js`; templates — todo
  - [ ] the implementation-time tests (L1-6, L1-8, L1-9, L1-15, B9, the autouse fixture); every "must also fail on" mutant run — todo
  - [ ] FR-UI-505, FR-UI-510 edited; FR-UI-514 added; NFR-UI-live, NFR-UI-read-only amended — todo
  - [ ] BUG-0534; PA-0534; the SP-58 row; ERROR_LOG, CHANGELOG, ARCHITECTURE, F-entry text to the coordinator — todo
  - [ ] `scripts/verify_change.py --base 7ebf48a`, then `--full`; counts quoted — todo
- Effectiveness: pending.

### CC-CORE-0071 — One read-only opener; a SQLite file is touched only through SQLite; the listing's summary has an age bound (FR-CORE-508, BUG-0535) (2026-10-20)
- Change:
  - **`fuzzlab/core/store.py`** (+~35): `open_read_only`, `is_sqlite` (§3.2).
  - **`fuzzlab/core/project.py`** (+~15/−12): `inspect` and `summary` ask SQLite whether a
    file is SQLite (no raw open), open through `open_read_only`; `copy_to`'s source too;
    `_ro_uri` removed; `summary` recomputes a cached summary older than
    `SUMMARY_MAX_AGE_S` (2 s, `_summary_clock`).
  - **`fuzzlab/harness/auto.py`** (+1/−1): `header_point_estimate` opens the spider DB
    through `open_read_only`.
  - **Tests**: `tests/test_core_store_read_only.py` (new), `tests/test_web_store_locks.py`
    (new), `tests/test_web_sitetree.py` (L1-12), `tests/test_query_placement.py`
    (`ALLOWED` edited).
- Impact:
  - Every caller of `inspect`, `summary` and `copy_to` (the web UI's projects pages,
    open, save as, snapshot, migration, `fuzzlab project` CLI if any): same results, same
    refusal message; a cached listing is at most 2 s old.
  - It fixes BUG-0535 for the web process today (the proxy's held `Store`, overlapping
    requests) and makes CC-UI-0068's watch safe.
  - The FUZZ CLI's spider-DB estimate: same result.
- Risk: low-medium. The magic check moves from bytes to SQLite: measured on text, a bare
  magic, random bytes, JSON and an empty file (N); the refusal text is kept. Mitigated by
  C1-C4, K1-K6 and the existing `test_core_project.py` suite. Rollback: the two magic
  reads (which re-open BUG-0535).
- Deliverables:
  - [x] measurements (§1.4 N, backup; §1.7) and failing tests (§5.2, L1-12) — done
  - [ ] the opener, `is_sqlite`, the `inspect`/`summary`/`copy_to`/`auto.py` changes, the age bound — todo
  - [ ] FR-CORE-508 added; BUG-0535; PA-0535; text for ERROR_LOG and CHANGELOG to the coordinator — todo
  - [ ] verified with CC-UI-0068 (one harness run) — todo
- Effectiveness: pending.

## 9. Bug protocol (drafts)

### 9.1 BUG-0534 (the version and the focus defect) and PA-0534

**Root cause (Five Whys, summarised; revision 1's analysis stands).**
- Layer 1: a change signal over storage another engine manages was derived from that
  storage's side effects (file sizes, mtimes, journal headers), and its never and always
  claims were tested only on the engine states the author pictured (a review fix for one
  case opened the other).
- Layer 2: FR-UI-505's "keeping focus" was implemented and tested for the one element kind
  that came to mind, on one order of events: BUG-0518's root cause recurring.

**Recurrence review.** `docs/bugs/` searched for fingerprint, `store_version`, refresh,
focus, poll, WAL, checkpoint, site tree; `docs/PREVENTIVE_ACTIONS.md` read in full.
BUG-0146 (same function, different cause); CC-UI-0503's review finding A1 (the same defect,
partly fixed, no BUG record); **BUG-0518 / PA-0518(1): layer 2 recurs its root cause**;
BUG-0021 / PA-0023 (a shared SQLite handle across threads: the design is its third
pattern); BUG-0087, BUG-0452 (applied); PA-0311(2) (landed 13 minutes after `1d02cd0`, on
another branch); PA-0083(2) (safety claims only); §7 (targets and browser only).

**Prior-preventive-action failure analysis.** PA-0518(1) did not prevent layer 2: not swept
(BUG-0518 recorded no PA-0002 sweep, so FR-UI-505 was never re-checked), not enforced (two
Diagrams tests for the requirements that failed), and too narrow even on its own page
(FR-UI-510's "a change reloads the run" was never tested for the user's place). Layer 1 has
no prior PA that failed.

**PA-0534 (proposed text).** Strengthens PA-0083(2), PA-0311(2) and §7; strengthens and
supersedes PA-0518(1) for live views; amends PA-0023.

> - **PA-0534** — After BUG-0534: the store version was read from SQLite's file side effects, so a reader's close refreshed the page and a running scan's commits went unseen (a review fix for one case opened the other); and a live refresh dropped focus from every control kind but the one tested, in either order of a user's page load and a refresh (a recurrence of BUG-0518's root cause; PA-0518 not swept or enforced).
>   1. **A change signal over state another engine manages is that engine's own documented change counter** (SQLite: `PRAGMA data_version` on one held connection) plus the identity of what it watches -- never inferred from the engine's storage side effects (file sizes, mtimes, journal headers). One owner: `web/sitetree.py::store_version` (SP-58).
>   2. **Its never / always claims, correctness ones included, are tested against every engine operation that touches what it reads, with the writer in another process**: a commit (UPDATE-only, after a WAL restart, a held writer's burst, rollback mode), each checkpoint kind, a reader's and a writer's last close, a replace, a delete. A fix for one case re-runs all of them.
>   3. **A live view keeps the user's place across every refresh**: each focusable control it re-renders carries a focus key unique in its region and is restored through the one helper (`static/js/livefocus.js`), verified where focus landed, falling back to a visible equivalent and ending at the pane, never the page body; work the user started that a refresh overlaps is delivered once, in either order, tested by holding each side's fetch. Every polling or streaming page script is registered with its real-browser focus tests, synchronised on the page's own counters (never a sleep), or a reasoned exemption -- PA-0518(1) made mechanical and swept.
>   4. **Amends PA-0023 with a third pattern**: a handle whose value is meaningful only on one connection (here `data_version`) may be one shared instance if every use is under one lock, it is opened for any thread, the invariant is in its docstring, and an AST guard plus a many-thread test pin it.
>   - Enforced by: tests/test_web_sitetree.py::test_every_commit_of_a_held_writer_in_another_process_changes_the_version, tests/test_web_sitetree.py::test_no_read_close_or_checkpoint_changes_the_version, tests/test_web_sitetree.py::test_no_module_fingerprints_the_store_from_its_files, tests/test_web_sitetree.py::test_the_store_fingerprint_guard_catches_synthetic_offenders, tests/test_web_sitetree.py::test_the_store_watch_is_used_only_under_its_lock, tests/test_web_store_locks.py::test_a_projects_listing_never_drops_the_store_watchs_locks, tests/test_web_live_focus.py::test_every_live_view_is_registered_with_its_focus_test, tests/test_web_live_focus.py::test_the_live_view_registry_catches_synthetic_offenders, tests/test_web_live_focus.py::test_every_live_view_restores_focus_through_the_one_helper, tests/test_web_sitetree_browser.py::test_a_refresh_during_a_show_more_load_still_delivers_that_page, tests/test_web_sitetree_browser.py::test_every_focusable_control_in_the_site_maps_live_regions_has_a_focus_key, tests/test_web_diagrams.py::test_every_focusable_control_in_the_diagrams_live_regions_has_a_focus_key

### 9.2 BUG-0535 (the lock drop) and PA-0535

- **Description.** A plain `open()`/`close()` of a store's main file in the web process
  released the POSIX locks of every SQLite connection the process held on it; another
  process's next close then folded the WAL and deleted `-wal`/`-shm` under them.
- **Where encountered.** Both reviewers of AU-SITETREE revision 1 (against the planned
  watch); measured on `7ebf48a` by this lane (§1.7).
- **What it caused to fail.** Under `fuzzlab web --with-proxy`: a corrupt project file
  (`vtable constructor failed: flow_fts`) after one Projects view and one short writer.
  With a request's reader across a listing: wrong reads (100 of 100), "malformed", 4 of 5
  UI commits lost silently.
- **The defect.** `core/project.py::inspect` (`:132`) and `::summary` (`:663`) read the
  SQLite magic with `open()`; they run in the web process (`web/projects.py:513-517, 564,
  617`, via `projectroutes.py:53`).
- **Root cause (Five Whys).**
  1. Why were the side files deleted under open connections? Another process's close got
     the exclusive lock it needs to fold the WAL: no other process held a shared lock.
  2. Why not, with the web process's connections open? A `close()` of any descriptor of a
     file releases every `fcntl` lock the process holds on it (POSIX), and the magic read
     closed one.
  3. Why read the magic outside SQLite? The untrusted-file check (CC-CORE-0450) wanted a
     cheap "is it SQLite" before opening; SQLite answers that itself (`SQLITE_NOTADB`).
  4. Why did no test catch it? Every store test ran its writers as connections of the test
     process (one process: its locks are per process), and no test combined a held
     connection, a raw open and another process's close.
  5. **Root cause: a SQLite database's files were treated as plain files by code running in
     a process that holds SQLite connections to them; SQLite's locking is per process and
     is silently undone by any raw descriptor's close, and no rule or guard kept raw file
     access to a database out of such a process, nor tested store code across processes.**
- **Corrective action.** CC-CORE-0071 (no raw open; the opener; `is_sqlite`), with the
  guard K5 and the regression tests K1-K3.
- **Recurrence review.** `docs/bugs/` searched for fcntl, flock, lock, WAL, shm, checkpoint,
  `SQLITE_BUSY`, "database is locked", journal mode, shared cache, `sqlite3.connect`:
  BUG-0011 (a shutdown hang), BUG-0021 (a SQLite handle across threads), BUG-0087 (a WAL
  switch's immediate BUSY; check-then-act), BUG-0108 (a file read-modify-write with no
  lock), BUG-0402 and BUG-0452 (store guards), BUG-0532 (a process rule as a lock). **None
  is a raw access to a database file in a process holding connections: no recurrence.**
  Related: PA-0088(3) (a store-contract rule is backed by a concurrency test: it named
  threads and first opens, not processes); PA-0023 (thread affinity, not process locks);
  BUG-0534 layer 1 (found in the same item: a sibling, "SQLite's files read as plain
  files", which PA-0535 and PA-0534(1) state from two sides).
- **PA-0535 (proposed text).**

> - **PA-0535** — After BUG-0535: the Projects listing read the store's magic bytes with `open()` in the web process, whose close released the POSIX locks of every SQLite connection the process held; another process's close then deleted `-wal`/`-shm` under them (a corrupt project under `--with-proxy`, lost commits, wrong reads).
>   1. **A process that holds, or may hold, SQLite connections never opens, reads, writes or copies a database's main file, `-wal` or `-shm` outside SQLite.** Whether a file is SQLite is asked of SQLite (`core.store.is_sqlite`); a read-only open goes through `core.store.open_read_only` (FR-CORE-508); a copy uses the backup API.
>   2. **Enforced by a computed scope, not a list**: every module of `fuzzlab/web/` and every module the web package imports that opens SQLite; each raw open there is a reviewed allowance with its count and its reason, and a stale one fails.
>   3. **Store behaviour across connections is tested with the other connection in another process** (`tests/_xproc.py`): SQLite's locks, shared memory and WAL fold are per process, so a second connection of the test's own process cannot show a cross-process failure.
>   - Enforced by: tests/test_web_store_locks.py::test_no_web_process_module_opens_a_store_file_except_through_sqlite, tests/test_web_store_locks.py::test_the_store_file_guard_catches_synthetic_offenders, tests/test_web_store_locks.py::test_a_projects_listing_never_drops_the_in_process_proxys_store_locks, tests/test_web_store_locks.py::test_a_projects_listing_never_drops_a_request_readers_locks, tests/test_web_store_locks.py::test_opening_a_project_never_drops_a_held_connections_locks, tests/test_core_store_read_only.py::test_whether_a_file_is_sqlite_is_asked_of_sqlite_never_read_raw, tests/test_core_store_read_only.py::test_every_read_only_open_goes_through_the_opener

### 9.3 Text for the coordinator (files this lane must not edit)

- **ERROR_LOG.md** (two lines):
  > 2026-10-20 — `test_web_sitetree_browser.py::test_show_more_from_the_keyboard_keeps_focus_in_the_tree` failed once in a full harness run (200 of 250). Root cause: the site map's store version changed with no write (a reader's last close folds the WAL) and, since review fix A1, missed most commits of a running scan (2783 of 3000, after WAL restarts); a live refresh then dropped focus from "Show more". Remediation: the version is `PRAGMA data_version` on one held, query-only connection; live views keep the user's place through one helper (CC-UI-0068, BUG-0534, PA-0534). Status: fix drafted.
  > 2026-10-20 — A Projects view under `fuzzlab web --with-proxy` let another process's close delete the store's `-wal`/`-shm` under the proxy's open Store, corrupting the project file (measured on 7ebf48a). Root cause: `core.project.inspect`/`summary` read the SQLite magic with `open()`, whose close released the web process's SQLite locks (POSIX). Remediation: a SQLite file is touched only through SQLite (CC-CORE-0071, FR-CORE-508, BUG-0535, PA-0535). Status: fix drafted.
- **CHANGELOG.md:**
  > 2026-10-20 — The web process never drops SQLite's locks (a Projects view could corrupt the project under `--with-proxy`, BUG-0535, CC-CORE-0071); the site map and Diagrams read the store version from SQLite's own change counter on one held, query-only connection, so a read or checkpoint no longer refreshes the page and a running scan's commits are no longer missed (2783 of 3000 were); a live refresh keeps the focused control and delivers a page the user asked for (BUG-0534, CC-UI-0068).
- **docs/ARCHITECTURE.md** (the Site map paragraph): "polling refresh on an `os.stat` store
  fingerprint (no SSE: …)" becomes "polling refresh on the store version (SQLite's
  `PRAGMA data_version` through one held, query-only connection on the open store, SP-58;
  the web process touches a store's files only through SQLite, FR-CORE-508; a refresh keeps
  the user's place, FR-UI-514; no SSE: …)".
- **docs/SHARED_PRIMITIVES.md**: the SP-58 row (§4.5).
- **docs/PREVENTIVE_ACTIONS.md**: PA-0534, PA-0535 (§9.1, §9.2).
- **docs/claude_juicelab_failures.md** (F-number from the coordinator):
  > F-NNN — The agent built the site tree's store fingerprint (CC-UI-0500) from SQLite's file side effects without measuring them; review fix A1 (`1d02cd0`) claimed "reads never change the fingerprint" while a reader's last close still changed it and hid 2782 of 3000 commits of a running scan. FR-UI-505's "keeping focus" was tested on one element kind. Project files (CC-CORE-0450) read the SQLite magic with `open()` in the web process, which drops SQLite's locks: a Projects view under `--with-proxy` could corrupt the project (measured on 7ebf48a). AU-SITETREE revision 1 then proposed a held connection without measuring across processes; both reviewers found the lock drop. Evidence: DRAFT-AU-SITETREE §1.2, §1.3, §1.4 (X3), §1.6, §1.7. Impact: one harness failure; a site map and Diagrams page lagging a scan by up to 230 commits; focus lost to the page body on 6 control kinds; a corruption and data-loss path in the web UI since 2026-10-15. Status: fix drafted (CC-UI-0068, CC-CORE-0071), failing tests committed, pending the confirming review.

## 10. Questions for the coordinator

- **Q1. `journal_size_limit`.** Measured (§1.8): it bounds the watched WAL (4 MiB, 64 MiB)
  at the next restart; not needed for correctness; it changes every writer. Proposed: a
  separate CORE item (PA-0143), with R4 stated meanwhile. Agree?
- **Q2. `test_query_placement.py`.** Its `ALLOWED` table changes with the opener (§3.2). It
  is a CRAWL/CORE guard file; editing it in CC-CORE-0071 is the proposal. Agree?
- **Q3. An SP row for the opener.** SP-58 names the watch; the opener is CORE's and is
  guarded by C4. A separate row is possible if wanted.
- **Q4. Opened by this session (PA-0143, waiting for the user):** Diagrams keyboard
  activation, the selection highlight across a refresh, `proxy.js`'s pending rows; and
  Q1's CORE item.
