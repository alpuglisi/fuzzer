# BUG-0535 — A raw open of a store in the web process dropped SQLite's locks (a Projects view could corrupt the project under `--with-proxy`)

- Date: 2026-10-20
- Status: fixed (AU-SITETREE; CC-CORE-0071, with CC-UI-0068 and CC-FUZZ-0108)
- Severity: high. A data-loss and corruption path in the web UI since 2026-10-15
  (`9f1536e`, `8569187`, CC-CORE-0450).

## Description
On POSIX, closing **any** file descriptor of a file releases every `fcntl` lock the
process holds on that file. SQLite's WAL protection is such a lock: while any connection
of a process holds its shared lock, no other process's close can believe it is the last,
fold the WAL and delete `-wal` and `-shm`. `core.project.inspect` (`:132`) and
`core.project.summary` (`:663`) read a store's 16-byte SQLite magic with `open()` before
opening it. They run in the web process (the Projects listing, opening, re-checking and
migrating a project). Each `open()`/`close()` silently dropped the locks of every SQLite
connection the web process held on that store; the next close by another process (a CLI
tool, a scan ending) then folded the WAL and deleted the side files under the web
process's open connections.

## Where encountered
Both reviewers of AU-SITETREE revision 1, against its planned held watch (the watch then
missed 200 of 200 and 300 of 300 commits, X3). Measured on today's code (`7ebf48a`, no
watch anywhere) by the AU-SITETREE lane (DRAFT-AU-SITETREE §1.7, `rev2/d2_today.py`).

## What it caused to fail
Measured on `7ebf48a`, every writer in another process:
- **`fuzzlab web --with-proxy`** (the in-process proxy holds its `Store` for the server's
  life): after one Projects view and one short writer, `-wal`/`-shm` were deleted under
  the proxy's `Store`; a web reader got `disk I/O error`; another process got
  `vtable constructor failed: flow_fts`, and still after every connection closed: **the
  project file was corrupt on disk**.
- **A request's reader held across a listing** (a site-map request in flight): 100 of
  100 per-request reads during a scan were wrong; the held reader read "database disk
  image is malformed"; 5 UI commits were reported ok and **4 of them were lost**.
- **Realistic overlap** (two reader threads, the listing every 150 ms, short writes every
  ~100 ms in another process, 8 s): `-wal` was deleted while a reader's transaction was
  open 11 times (17 in an earlier run); no damage was detected in that short run.

## What the bug was identified to be
`core/project.py::inspect` and `::summary` treated a SQLite database's main file as a
plain file (`open(p, "rb").read(16)`) in a process that holds SQLite connections to it.
Exposed through: the proxy's held `Store` (`web/proxycontrol.py:72`), per-request readers
(`web/projects.open_reader`), and, by design, CC-UI-0068's held watch.

## Root cause analysis
Five Whys.
1. *Why were the side files deleted under open connections?* Another process's close
   obtained the exclusive lock it needs to fold the WAL: no other process held a shared
   lock on the store.
2. *Why not, with the web process's connections open?* A `close()` of any descriptor of a
   file releases every `fcntl` lock the process holds on it (POSIX), and the magic read
   closed one.
3. *Why read the magic outside SQLite?* The untrusted-file check (CC-CORE-0450) wanted a
   cheap "is it SQLite" before opening; SQLite answers that itself (`SQLITE_NOTADB`).
4. *Why did no test catch it?* Every store test ran its other connections in the test's
   own process (SQLite's locks are per process), and no test combined a held connection,
   a raw open and another process's close.
5. *Why was nothing in place to keep raw opens out?* No rule or guard said that a
   database's files belong to SQLite in a process that holds connections, and no store
   behaviour was tested across processes.

**Root cause:** a SQLite database's files were treated as plain files by code running in
a process that holds SQLite connections to them; SQLite's locking is per process and is
silently undone by any raw descriptor's close; no rule or guard kept raw file access to a
database out of such a process, and no test exercised store behaviour across processes.

## Corrective action
CC-CORE-0071 (this item's implementation commit on branch
`worktree-agent-a60c0b76d37a91dd4`):
- `core.store.open_read_only` (the one read-only opener: existing file only, private
  cache, query-only) and `core.store.is_sqlite` (SQLite's own answer); `inspect`,
  `summary` and `copy_to` go through them; no raw open of a store file remains in the
  web process. CC-FUZZ-0108 routes `harness.auto.header_point_estimate` through the
  opener too (the sweep).
- **Static guard** (`tests/test_web_store_locks.py::test_no_web_process_module_opens_a_store_file_except_through_sqlite`):
  the scope is the whole import closure of `fuzzlab/web` (184 modules: lazy imports and
  literal `import_module` included), not only modules that open SQLite. Revision 2's
  SQLite-only scope missed 21 reachable modules with 41 raw-open sites, e.g.
  `core/secretfile.py:72,:84`, reached from `web/projects.py:845` (the confirming
  review). Every raw open (`open`, `io.open`, `os.open`, `os.fdopen`, `Path.open/read_*/
  write_*`, `shutil.copy*/move/copytree/...`, `filecmp`, `tempfile`, `ZipFile`/`.write`,
  `tarfile`/`.add`, `FileResponse`, `StaticFiles`) is a reviewed allowance with its count
  and reason: 60 allowances covering 64 sites in 32 modules, none a store's file.
- **Run-time audit hook** (`tests/_store_audit.py`, armed for every `test_web_*`,
  `test_core_project` and `test_core_store_read_only` test by `tests/conftest.py`): fails
  a test during which production code opened a store's main file, `-wal` or `-shm`
  outside SQLite, whatever the call path. Proven on synthetic offenders (BUG-0535's own
  read, a helper a route hands the path to, `os.open`, `shutil`, `zipfile`).
- Regression tests K1-K4 (the proxy's `Store`, a request's reader, a held connection
  across `inspect`, the watch), each with a writer in another process (`tests/_xproc.py`).
- What neither guard sees (stated): code outside the import graph -- an entry-point
  plugin the web process loads (`web/app.py:444`), a module imported by a computed name
  -- unless a web test runs it; opens by C code that raise no audit event; opens in
  another process.

## Recurrence review
Searched `docs/bugs/` for fcntl, flock, lock, WAL, `-wal`, shm, checkpoint, raw open,
magic, `SQLITE_BUSY`, "database is locked", journal mode, shared cache and
`sqlite3.connect`; read `docs/PREVENTIVE_ACTIONS.md` in full.
- BUG-0011 (a shutdown hang), BUG-0021 (a SQLite handle across threads), BUG-0087 (a WAL
  switch's immediate BUSY; check-then-act), BUG-0108 (a file read-modify-write with no
  interprocess lock), BUG-0402 and BUG-0452 (store guards walking or writing too much),
  BUG-0532 (a process rule enforced as a lock): none is a raw access to a database file
  in a process that holds connections to it. **No recurrence.**
- Related: PA-0088(3) (a store-contract rule is backed by a concurrency test) named
  threads and first opens, not processes; PA-0023 (thread affinity) is not about process
  locks; PA-0109 (an interprocess lock for files) is the opposite direction. BUG-0534
  layer 1, found in the same item, is a sibling ("SQLite's files read as plain files"),
  which PA-0535 and PA-0534(1) state from two sides.

## Preventive action
**PA-0535** (text for `docs/PREVENTIVE_ACTIONS.md`; the coordinator applies it):
1. a process that holds, or may hold, SQLite connections never opens, reads, writes or
   copies a database's main file, `-wal` or `-shm` outside SQLite (FR-CORE-508);
2. enforced by a computed scope -- the web package's whole import closure, whatever a
   module opens -- with library openers, reviewed allowances that fail when stale, and a
   run-time audit hook over the web tests; both proven on synthetic offenders;
3. store behaviour across connections is tested with the other connection in another
   process (`tests/_xproc.py`).

The PA-0002 sweep: DRAFT-AU-SITETREE §4.2 (every raw open and "has the store changed"
detector, with a disposition), §3.2 (every read-only open), and the guard's allowance list (60 entries, 64 sites) (every raw open in the web process's code, each never a store's file).
Outside the web process's code: `disco/cli.py`, `disco/livetrace.py`, the labgen live
boots and `report/diagram_cli.py` open capture, actions, JSON, env, vendor and export
files, never a store's.
