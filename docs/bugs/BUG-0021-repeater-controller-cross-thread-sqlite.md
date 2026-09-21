# BUG-0021 — `RepeaterController` reused a cached SQLite connection across threads

- Date: 2026-09-21
- Status: fixed
- Severity: medium (intermittent test failures; the same mechanism can affect any
  future multi-threaded serving of the web app, not just tests)

## Description
`RepeaterController` (`fuzzlab/web/proxycontrol.py`) is a single long-lived object
created once per app (`fuzzlab/web/app.py`) and shared across every request. On first
write (`create_tab`/`send`) it lazily opened a persistent `Store` (a `sqlite3`
connection) and cached it on `self._store`/`self._rep`, reusing that same cached
connection object for every later call, from any request, for the app's lifetime.
`sqlite3` connections are thread-affine by default (`check_same_thread=True`): the
connection object may only be used from the OS thread that created it. Nothing in
`RepeaterController` accounted for the calling thread changing between requests.

## Where encountered
`tests/test_web_repeater.py::test_routes_list_create_and_send_gate` and
`::test_route_send_reaches_upstream_when_authorized`, intermittently, both through
`fastapi.testclient.TestClient` driving `fuzzlab.web.app.create_app(...)`.

## What it caused to fail
Intermittent `sqlite3.ProgrammingError: SQLite objects created in a thread can only be
used in that same thread` — a different one of the two tests failing on different runs,
consistent with a genuine race rather than a deterministically-broken test. Not
reliably reproducible with a single ad hoc run of the test file.

## What the bug was identified to be
`RepeaterController._writer()` created `self._store = Store(path)` once (on the thread
handling whichever request happened to write first) and cached it on the instance.
`list_tabs()`/`create_from_flow()` then read `self._store.conn` (or opened+closed a
throwaway connection only when `self._store` was still `None`). Once the cached
connection existed, every subsequent call — from `list_tabs`, `create_from_flow`,
`create_tab`, or `send` — reused that same physical `sqlite3.Connection`, regardless of
which OS thread the current request happened to be running on.

Starlette's `TestClient`, when not used as a context manager (`with TestClient(...) as
client:`), does not keep one persistent event loop: each top-level `client.get()` /
`client.post()` call spins up its own `anyio.from_thread.start_blocking_portal()` — a
**freshly spawned OS thread** — runs the request's `async def` route handler on it, and
tears the thread down again before returning
(`starlette/testclient.py::TestClient._portal_factory`, `self.portal` stays `None`
outside the `with` form). `tests/test_web_repeater.py`'s route tests call
`client.get(...)`/`client.post(...)` directly, without a `with` block, so each call in
a test potentially runs on a different, brand-new thread.

Whether the bug actually fires on a given run depends on whether the OS happens to
reuse the same low-level thread id (TID) for the next ephemeral portal thread — Linux
recycles exited threads' TIDs, and `sqlite3`'s same-thread check compares the raw TID
captured at connection-open time. When the TID is reused, the check passes by
coincidence; when a still-different TID lands (e.g. under any extra thread churn from
GC, other fixtures, or the rest of the suite running in the same process), the check
fails — exactly the "intermittent, not reliably reproducible on demand" symptom
reported.

## Root cause analysis
Five Whys:
1. Why did the test fail? `sqlite3.ProgrammingError` — a connection used from a
   different thread than it was created on.
2. Why was it used from a different thread? `RepeaterController` cached one `Store`
   connection on the instance and reused it for every request, but the ASGI test
   client does not guarantee the same thread handles every request.
3. Why didn't `RepeaterController` account for that? Its lazy-init pattern
   (`if self._rep is None: create it`) was written assuming "shared instance = shared
   connection is fine", the same assumption that already holds safely for the
   *engine*-side `ProxyController` (which really is single-threaded: it runs entirely
   inside one `asyncio` event loop bound to one OS thread). `RepeaterController` copied
   that shape without the assumption that justified it actually holding for its own
   caller.
4. Why wasn't this caught before? Every existing repeater test up to this point issued
   at most one or two chained calls in a pattern that, empirically, usually landed on a
   reused/coincidentally-matching TID for the ephemeral test-client portal threads (or
   used the non-route `RepeaterController` directly with no ASGI portal in play at
   all), so the race window was rarely hit.
5. Why did the race window exist at all in a "single-threaded" web app? Because
   `TestClient` used without a `with` block does not pin one event loop to one thread
   for the client's lifetime — a detail specific to that test-harness idiom, not to how
   the app is served in production (a real ASGI server pins one event-loop thread) —
   but the shared, thread-oblivious `RepeaterController` state made the *test harness's*
   threading detail into a *correctness* bug rather than a harmless implementation
   detail.

**Root cause:** `RepeaterController` cached a single `sqlite3` connection as shared
instance state and reused it across calls without regard for which OS thread was
calling — an assumption that happens to hold for the proxy engine's single-event-loop
controller it was modeled after, but does not hold for a controller invoked through
route handlers whose calling thread can change between requests (as `TestClient`
without a `with` block demonstrates, and as any other multi-threaded dispatch of sync
work would too).

## Corrective action
`fuzzlab/web/proxycontrol.py::RepeaterController` now keeps its persistent `Store` +
`Repeater` **per calling thread** (`threading.local()`) instead of as one shared
instance attribute:
- `_writer()` looks up/creates the calling thread's own `Store`/`Repeater` in
  `self._local`; a lock (`self._run_lock`) still guarantees only **one** `repeater` run
  row is ever created (`self._run_id`), shared by every thread's `Repeater`, so tabs
  created from different threads still show up together.
- `list_tabs()`/`create_from_flow()` use a new `_thread_store()` helper (this thread's
  cached store, or `None`) in place of the old shared `self._store`, preserving the
  existing "open a throwaway connection and close it again" behavior for a thread that
  has not written yet.
- Every SQL statement continues to go through whichever connection is valid for the
  calling thread; since all connections point at the same on-disk WAL-mode file and
  writes are never concurrent across threads in practice (one request in flight at a
  time in this controller's call pattern), this does not introduce a new consistency
  hazard — it removes the connection-reuse hazard that was actually present.

See `docs/components/11-intercepting-proxy/change-control.md` `CC-PROXY-0016`.

## Recurrence review
Checked every entry in `docs/bugs/` and every rule in `docs/PREVENTIVE_ACTIONS.md` for
a prior occurrence of the same bug (a cached `sqlite3`/DB-handle reused across threads)
or a different bug with the same root cause:
- `grep -il "sqlite\|thread" docs/bugs/*.md` found only `BUG-0009` (an unrelated
  incidental mention of "thread" inside a pcov discussion) and this bug's own doc.
- `BUG-0011` ("async-proxy-shutdown-hang", PA-0012) is the project's other
  concurrency-adjacent proxy bug, but its root cause is distinct: `asyncio.Server`
  teardown assuming `wait_closed()` returns once the listener closes, when Python 3.12+
  also waits on live connection tasks. That is a lifecycle/bounding problem in
  `asyncio` task management, not a thread-affinity problem in a synchronous DB handle,
  and it lives in the async proxy engine (single-threaded by construction), not in a
  controller invoked from multiple threads. No shared root cause; not a recurrence.
- No other bug or preventive action addresses connection/handle affinity across
  threads, or a shared-instance-state assumption borrowed from one component (a
  genuinely single-threaded controller) that does not hold for a sibling component with
  a different calling pattern.

**Result: none found.** This is a new bug class for the project; no
prior-preventive-action failure analysis applies.

## Preventive action
New rule **PA-0023** (`docs/PREVENTIVE_ACTIONS.md`): any object wrapping a `sqlite3`
connection (or another thread-affine OS handle) that is held as shared state on an
object reachable from more than one call path must not assume its calls always land on
the same OS thread — either confine it to a component that is provably single-threaded
by construction (state the invariant in the docstring, as `ProxyController` already
is), or make the cached handle per-thread (`threading.local()`), never a single shared
instance attribute reused blindly. Do not copy a "cache one connection on `self`"
pattern from one component into a new one without re-checking whether that
single-thread assumption still holds for the new component's actual callers — e.g. an
ASGI test client used without its context-manager form spins up a fresh thread per
top-level call, which is enough to break it. Also, per PA-0002, the codebase was swept
for the same pattern (a `Store`/connection cached on `self` in a shared controller): the
only other instance is `ProxyController._store`, which is safe because it is created
and used exclusively inside one `asyncio` event loop pinned to one OS thread
(`AsyncProxyServer`/`ProxyEngine`, per `BUG-0011`'s corrective action) — documented as
an explicit invariant, not re-derived per read.
