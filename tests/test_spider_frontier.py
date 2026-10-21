"""The legacy spider's frontier, its transient failures and its page writer (audit
defects 11, 12 and 25; BUG-0545; FR-CRAWL-35, FR-CRAWL-36).

- **Defect 11 (FR-CRAWL-35).** The queue was an unbounded list: producers checked
  visited pages but reserved nothing, so many parents queued one destination many
  times; ``pop(0)`` and deletion near the head shifted the rest; nothing bounded
  fan-out (a page of calendar cells, facets, nonce links). Now a frontier admits each
  scheduling key once and admits nothing past its budgets (total, pending, per origin,
  per route shape, URL length), counting and reporting every refusal as partial
  coverage.
- **Defect 12 (FR-CRAWL-36).** A timeout, a reset, an incomplete body (SP-60's
  `BodyIncomplete`) or a 503 was filed as a visited page (status 0, or the 503), and a
  resume skipped it like a crawled one. Now such a load is retried with backoff, and
  one that keeps failing is recorded unresolved -- never visited -- reported, and
  retried by a resumed crawl.
- **Defect 25, the spider's part (FR-CRAWL-36).** Each page row was committed on its
  own under the store's one lock, so a crawl thread waited on every commit. Now page
  rows go to a writer thread that commits by count, bytes and age; recording a page
  never waits on the store; everything is flushed at close.

Every site here is a loopback server the test starts."""

from __future__ import annotations

import socket
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

from fuzzlab.tools import spider as sp


class _Site:
    """A loopback site whose answers the test scripts: ``routes`` maps a path to a
    function ``(handler, n)`` (``n``: how many times that path was requested, from 1)
    returning ``(status, html, headers)``, or None after writing to the socket itself.
    Every GET's path (with its query) is recorded."""

    def __init__(self, routes):
        self.routes = routes
        self.hits: list[str] = []
        self.counts: dict[str, int] = {}
        self._lock = threading.Lock()
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                with site._lock:
                    site.hits.append(self.path)
                    n = site.counts[path] = site.counts.get(path, 0) + 1
                route = site.routes.get(path)
                answer = route(self, n) if route else (404, "no", {})
                if answer is None:
                    return
                status, html, headers = answer
                body = html.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def gets(self, path: str) -> int:
        with self._lock:
            return sum(1 for h in self.hits if h.split("?", 1)[0] == path)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _page(*links, text="page"):
    return (200, f"<html><body><p>{text}</p>"
                 + "".join(f"<a href='{u}'>x</a>" for u in links) + "</body></html>", {})


def _db_pages(db) -> dict[str, tuple]:
    """``path -> (status, outcome)``; outcome None in a DB without the column."""
    con = sqlite3.connect(db)
    try:
        cols = {r[1] for r in con.execute("PRAGMA table_info(discovered_pages)")}
        outcome = "outcome" if "outcome" in cols else "NULL"
        return {urlsplit(u).path: (status, out) for u, status, out in con.execute(
            f"SELECT url, status_code, {outcome} FROM discovered_pages")}
    finally:
        con.close()


def _stats(db) -> dict[str, int]:
    con = sqlite3.connect(db)
    try:
        return dict(con.execute("SELECT name, value FROM crawl_stats"))
    finally:
        con.close()


@pytest.fixture
def fast_retries(monkeypatch):
    """Backoff short enough for a test (the rule, not its timing, is under test)."""
    monkeypatch.setattr(sp, "RETRY_BASE_S", 0.01, raising=False)
    monkeypatch.setattr(sp, "RETRY_MAX_S", 0.05, raising=False)


# --- defect 11: the frontier -------------------------------------------------------------
HUBS, LEAVES = 40, 40


def test_a_destination_many_parents_link_is_queued_once(tmp_path):
    """``/`` links 40 hubs; each hub links the same 40 leaves. The old queue held every
    (hub, leaf) pair at once (1600+ entries); the frontier reserves a leaf when it is
    first admitted, so what is pending never exceeds the distinct URLs."""
    hub_links = [f"/leaf/{i}" for i in range(LEAVES)]
    routes = {"/": lambda h, n: _page(*[f"/hub/{i}" for i in range(HUBS)])}
    for i in range(HUBS):
        routes[f"/hub/{i}"] = lambda h, n: _page(*hub_links)
    for i in range(LEAVES):
        routes[f"/leaf/{i}"] = lambda h, n: _page()
    site = _Site(routes)
    peak = [0]
    original = sp.LocalSpider._visit

    def visit(self, url, depth, source, queue, *a, **k):
        peak[0] = max(peak[0], len(queue))
        return original(self, url, depth, source, queue, *a, **k)
    try:
        spider = sp.LocalSpider(site.base, max_depth=2, db_name=str(tmp_path / "s.db"),
                                engine="requests")
        spider._visit = visit.__get__(spider)
        spider.crawl()
    finally:
        site.close()
    distinct = 1 + HUBS + LEAVES + 2                  # + robots.txt, sitemap.xml
    assert peak[0] <= distinct, peak[0]
    assert all(site.gets(f"/leaf/{i}") == 1 for i in range(LEAVES))


FANOUT = 30


def test_a_fan_out_trap_is_bounded_by_the_route_budget_and_reported(tmp_path, caplog):
    """A calendar-like trap: every ``/cal?d=N`` links 30 new days. Depth alone let 931
    loads through at depth 2; the per-route-shape budget (query variants of one route)
    admits at most `FrontierLimits.max_route_variants`, and every refusal is counted in
    ``crawl_stats`` and logged as partial coverage. An over-long URL is refused too."""
    def cal(h, n):
        d = int(dict(parse_qsl(urlsplit(h.path).query)).get("d", "0"))
        return _page(*[f"/cal?d={d * FANOUT + k + 1}" for k in range(FANOUT)])
    long_url = "/long?x=" + "a" * 8192
    site = _Site({"/": lambda h, n: _page("/cal?d=0", long_url), "/cal": cal})
    db = str(tmp_path / "s.db")
    try:
        with caplog.at_level("WARNING"):
            sp.LocalSpider(site.base, max_depth=3, db_name=db, engine="requests").crawl()
    finally:
        site.close()
    assert site.gets("/long") == 0
    assert site.gets("/cal") < 1 + FANOUT + FANOUT ** 2, site.gets("/cal")   # depth alone
    limits = sp.FrontierLimits()
    assert len(site.base) + len(long_url) > limits.max_url_length     # the input is over
    assert site.gets("/cal") <= limits.max_route_variants, site.gets("/cal")
    stats = _stats(db)
    assert stats["frontier_rejected[route_shape]"] > 0
    assert stats["frontier_rejected[url_length]"] == 1
    assert "partial coverage" in caplog.text


def test_the_frontier_admits_each_key_once_and_counts_every_budget():
    """The frontier's own rules, budget by budget (small limits)."""
    lock = threading.Condition(threading.RLock())
    limits = sp.FrontierLimits(max_pages=6, max_pending=3, max_per_origin=4,
                               max_route_variants=2, max_url_length=60)
    f = sp._Frontier(lock, limits, is_visited=lambda u: u.endswith("/seen"))
    f.extend([("http://h/a", 0, "link", None), ("http://h:80/a", 1, "link", None),
              ("http://h/seen", 1, "link", None)])          # an alias, a visited page
    assert len(f) == 1 and f.report()["duplicates"] == 2
    f.extend([("http://h/x?id=1", 1, "link", None), ("http://h/x?id=2", 1, "link", None),
              ("http://h/x?id=3", 1, "link", None)])         # third variant of one shape
    assert f.report()["rejected"] == {"route_shape": 1}
    f.append(("http://h/" + "z" * 80, 1, "link", None))
    f.append(("http://h/b", 1, "link", None))                  # the pending budget (3)
    assert f.report()["rejected"] == {"route_shape": 1, "url_length": 1, "pending": 1}
    assert f.take(True)[:4] == ("http://h/a", 0, "link", None)   # FIFO, from the head
    f.append(("http://h/b", 1, "link", None))                  # refused before: admitted
    assert f.take(True)[0] == "http://h/x?id=1"
    f.append(("http://h/c", 1, "link", None))                  # the per-origin budget (4)
    assert f.report()["rejected"]["origin"] == 1
    assert [f.take(True)[0] for _ in range(2)] == ["http://h/x?id=2", "http://h/b"]
    f.extend([("http://k/a", 1, "link", None), ("http://k/b", 1, "link", None),
              ("http://k/c", 1, "link", None)])              # the total budget (6)
    assert f.report()["rejected"]["total"] == 1 and f.report()["admitted"] == 6
    assert f.take(True) == ("http://k/a", 1, "link", None, 1)  # its attempt number
    f.retry(("http://k/a", 1, "link", None), 2, 0.0)            # due now: taken first
    assert f.take(True) == ("http://k/a", 1, "link", None, 2)
    assert f.report()["admitted"] == 6                          # a retry is no admission


# --- defect 12: transient failures ----------------------------------------------------
def test_a_transient_failure_is_retried_and_never_recorded_visited(tmp_path, fast_retries):
    """``/flaky`` answers 503 twice, then the page (which links ``/child``); ``/hangup``
    drops its connection once. Each is loaded again after a backoff, recorded once as
    visited with its real answer, and what it links is crawled. Before: the 503 and the
    reset were filed as visited pages and ``/child`` was never found."""
    def flaky(h, n):
        return (503, "busy", {"Retry-After": "0"}) if n <= 2 else _page("/child")

    def hangup(h, n):
        if n == 1:
            h.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                    b"\x01\x00\x00\x00\x00\x00\x00\x00")
            h.close_connection = True
            return None
        return _page(text="hangup-ok")
    site = _Site({"/": lambda h, n: _page("/flaky", "/hangup"), "/flaky": flaky,
                  "/hangup": hangup, "/child": lambda h, n: _page(text="child")})
    db = str(tmp_path / "s.db")
    try:
        sp.LocalSpider(site.base, max_depth=2, db_name=db, engine="requests").crawl()
    finally:
        site.close()
    pages = _db_pages(db)
    assert pages["/flaky"] == (200, "visited") and pages["/hangup"] == (200, "visited")
    assert pages["/child"] == (200, "visited")
    assert site.gets("/flaky") == 3 and site.gets("/hangup") == 2
    assert _stats(db)["pages_retried"] == 3 and _stats(db)["pages_failed"] == 0


def test_an_incomplete_body_is_retried_never_taken_for_a_page(tmp_path, fast_retries):
    """A body dripped past its deadline (SP-60's `BodyIncomplete`) is no page: retried,
    then recorded with the complete answer."""
    def drip(h, n):
        if n > 1:
            return _page(text="whole")
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.send_header("Content-Length", "40")
        h.end_headers()
        for _ in range(40):
            try:
                h.wfile.write(b"x")
                h.wfile.flush()
                time.sleep(0.05)
            except OSError:
                break
        return None
    site = _Site({"/": lambda h, n: _page("/drip"), "/drip": drip})
    db = str(tmp_path / "s.db")
    try:
        sp.LocalSpider(site.base, max_depth=1, db_name=db, engine="requests",
                       timeout_ms=200).crawl()
    finally:
        site.close()
    assert _db_pages(db)["/drip"] == (200, "visited")
    assert site.gets("/drip") == 2


def test_a_page_that_keeps_failing_is_unresolved_reported_and_resumed(tmp_path,
                                                                     fast_retries,
                                                                     caplog):
    """``/down`` answers 503 on every attempt: after `FETCH_ATTEMPTS` loads it is
    recorded unresolved (outcome ``failed``, its status kept), never visited; the crawl
    reports it. A resumed crawl loads it again, finds it up, and crawls what it links.
    Before: filed as a visited 503, and the resume skipped it."""
    up = [False]

    def down(h, n):
        return _page("/below") if up[0] else (503, "down", {})
    site = _Site({"/": lambda h, n: _page("/down"), "/down": down,
                  "/below": lambda h, n: _page(text="below")})
    db = str(tmp_path / "s.db")
    try:
        with caplog.at_level("WARNING"):
            first = sp.LocalSpider(site.base, max_depth=2, db_name=db, engine="requests")
            first.crawl()
        assert _db_pages(db)["/down"] == (503, "failed")
        assert site.gets("/down") == sp.FETCH_ATTEMPTS
        assert "/below" not in _db_pages(db)
        assert _stats(db)["pages_failed"] == 1
        assert list(first.failed_pages) == [site.base + "down"]
        assert "unresolved" in caplog.text
        reopened = sp.StorageManager(db)
        try:
            assert not reopened.is_visited(site.base + "down")
        finally:
            reopened.close()
        up[0] = True
        sp.LocalSpider(site.base, max_depth=2, db_name=db, engine="requests",
                       resume=True).crawl()
    finally:
        site.close()
    pages = _db_pages(db)
    assert pages["/down"] == (200, "visited") and pages["/below"] == (200, "visited")


def test_a_resumed_crawl_never_loads_a_stored_row_out_of_its_scope_or_destructive(
        tmp_path, fast_retries):
    """BUG-0545 review (B1): a resumed crawl loads the stored unresolved rows again, and
    each load passes the crawl's scope and destructive rules first, as every other one
    does. One DB (the CLI's default is one file for every run) gets ``A/logout`` left
    failed by a crawl that started there (the start URL is the operator's own, so the
    destructive rule let it through), then ``B/down`` left failed by a resumed crawl of
    B, another loopback port: another service (BUG-0123), so A is out of its scope. A
    last crawl resumes from ``A/``: B is out of its scope and ``A/logout`` is destructive.
    Neither target receives a request from a crawl that may not load it; each refusal
    is counted; both rows stay unresolved for a crawl that may load them. Before
    (9071440): B's resumed crawl loaded ``A/logout`` (3 GETs), and A's loaded ``B/down``
    and ``A/logout`` again."""
    a = _Site({"/": lambda h, n: _page(text="a"),
               "/logout": lambda h, n: (503, "down", {})})
    b = _Site({"/": lambda h, n: _page("/down"), "/down": lambda h, n: (503, "down", {})})
    db = str(tmp_path / "s.db")
    try:
        sp.LocalSpider(a.base + "logout", max_depth=1, db_name=db,
                       engine="requests").crawl()
        assert a.gets("/logout") == sp.FETCH_ATTEMPTS        # its own start: loaded
        crawl_b = sp.LocalSpider(b.base, max_depth=1, db_name=db, engine="requests",
                                 resume=True)
        crawl_b.crawl()
        assert a.gets("/logout") == sp.FETCH_ATTEMPTS, "B's crawl loaded A's row"
        assert b.gets("/down") == sp.FETCH_ATTEMPTS
        crawl_a = sp.LocalSpider(a.base, max_depth=1, db_name=db, engine="requests",
                                 resume=True)
        crawl_a.crawl()
        assert b.gets("/down") == sp.FETCH_ATTEMPTS, "A's crawl loaded B's row"
        assert a.gets("/logout") == sp.FETCH_ATTEMPTS, "a destructive row was loaded"
        assert a.gets("/") >= 1                    # the resumed crawl itself ran
    finally:
        a.close()
        b.close()
    assert crawl_b.crawl_counts()["loads_refused[out_of_scope]"] == 1
    counts = crawl_a.crawl_counts()
    assert counts["loads_refused[out_of_scope]"] == 1
    assert counts["loads_refused[destructive]"] == 1
    assert crawl_a.skipped_destructive == {a.base + "logout": "logout"}
    reopened = sp.StorageManager(db)
    try:
        assert sorted(u for u, *_rest in reopened.unresolved()) == sorted(
            [a.base + "logout", b.base + "down"])
    finally:
        reopened.close()


# --- defect 25: the page writer -------------------------------------------------------
def test_recording_a_page_never_waits_for_the_stores_lock(tmp_path):
    """A crawl thread records a page while another thread holds the store's lock (a
    slow commit): it returns at once. Before: it waited for the lock."""
    storage = sp.StorageManager(str(tmp_path / "s.db"))
    held, release = threading.Event(), threading.Event()

    def hold():
        with storage.lock:
            held.set()
            release.wait(10)
    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    held.wait(5)
    done = threading.Event()
    recorder = threading.Thread(target=lambda: (storage.mark_visited(
        "http://127.0.0.1:9/a", 200, 0, "t", "c"), done.set()), daemon=True)
    recorder.start()
    try:
        assert done.wait(2), "mark_visited waited for the store's lock"
        assert storage.is_visited("http://127.0.0.1:9/a")
    finally:
        release.set()
        holder.join(5)
        recorder.join(5)
        storage.close()
    con = sqlite3.connect(tmp_path / "s.db")
    assert con.execute("SELECT COUNT(*) FROM discovered_pages").fetchone()[0] == 1
    con.close()


def test_page_rows_are_committed_by_count_bytes_and_age_and_flushed_at_close(
        tmp_path, monkeypatch):
    monkeypatch.setattr(sp, "WRITE_BATCH_SECONDS", 0.2, raising=False)
    db = str(tmp_path / "s.db")
    storage = sp.StorageManager(db)
    commits = []
    storage.conn.set_trace_callback(lambda sql: commits.append(sql) if sql == "COMMIT"
                                    else None)
    rows = 200
    try:
        for i in range(rows):                           # by count
            storage.mark_visited(f"http://127.0.0.1:9/p{i}", 200, 1, "t", "c")
        assert len(commits) < rows // 4, len(commits)   # before: one per page
        storage.flush()
        assert len(commits) <= rows // sp.WRITE_BATCH_ROWS + 2, len(commits)
        big = "x" * (sp.WRITE_BATCH_BYTES // 4 + 1)
        commits.clear()
        for i in range(4):                              # by bytes: 4 rows pass the cap
            storage.mark_visited(f"http://127.0.0.1:9/big{i}", 200, 1, "t", big)
        deadline = time.monotonic() + 5
        while not commits and time.monotonic() < deadline:
            time.sleep(0.01)
        assert commits, "a batch over its byte cap was never written"
        storage.mark_visited("http://127.0.0.1:9/late", 200, 1)       # by age
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            con = sqlite3.connect(db)
            got = con.execute("SELECT COUNT(*) FROM discovered_pages WHERE url LIKE "
                              "'%/late'").fetchone()[0]
            con.close()
            if got:
                break
            time.sleep(0.05)
        assert got == 1, "a lone row was never written by age"
        storage.mark_visited("http://127.0.0.1:9/last", 200, 1)
    finally:
        storage.close()                                  # flushed at close
    con = sqlite3.connect(db)
    assert con.execute("SELECT COUNT(*) FROM discovered_pages").fetchone()[0] == rows + 6
    con.close()
