"""Crawl workers in the legacy spider (``--workers N``, CC-CRAWL-0037).

A local link tree (every page links to its children; each answer is delayed so loads
can overlap) is crawled with one worker and with several. What is checked: the same
pages are visited, each once; loads really overlap; whatever can write
(`LocalSpider._after_fetch`: reveals, submissions, selector forms) never runs on two
workers at once; the worker count is bounded; one real-browser run with two workers."""

from __future__ import annotations

import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fuzzlab.tools import spider as sp

FANOUT, DEPTH, DELAY = 3, 3, 0.05


class _Tree:
    """``/`` and ``/n/<path>`` pages, each linking to its ``FANOUT`` children down to
    ``DEPTH``; records every GET and the most requests it served at once.

    With `gate` set, the first child page is held until a second child is requested
    at the same time (or 30 s pass), once: overlap is then observed whatever the
    machine's load -- a second worker's browser may take seconds to launch, and the
    tree must not be crawled out before it does."""

    def __init__(self):
        self.hits: list[str] = []
        self.active = 0
        self.max_active = 0
        self.gate: threading.Barrier | None = None
        lock = threading.Lock()
        tree = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                with lock:
                    tree.hits.append(self.path)
                    tree.active += 1
                    tree.max_active = max(tree.max_active, tree.active)
                try:
                    time.sleep(DELAY)
                    path = self.path.split("?", 1)[0].rstrip("/")
                    level = 0 if path in ("", "/") else path.count("/") - 1
                    gate = tree.gate
                    if gate is not None and level == 1:
                        try:
                            gate.wait(timeout=30)
                        except threading.BrokenBarrierError:
                            pass
                        tree.gate = None
                    base = "/n" if path in ("", "/") else path
                    links = "".join(f'<a href="{base}/{i}">{i}</a>' for i in range(FANOUT)) \
                        if level < DEPTH else ""
                    body = f"<!doctype html><html><body>{links}</body></html>".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    with lock:
                        tree.active -= 1

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


EXPECTED = sum(FANOUT ** d for d in range(DEPTH + 1))        # 1 + 3 + 9 + 27


@pytest.fixture
def tree():
    t = _Tree()
    yield t
    t.close()


def _visited(db) -> list[str]:
    conn = sqlite3.connect(db)
    try:
        return [r[0] for r in conn.execute("SELECT url FROM discovered_pages")]
    finally:
        conn.close()


def _crawl(tree, tmp_path, name, **kw):
    db = tmp_path / f"{name}.db"
    s = sp.LocalSpider(tree.url, max_depth=DEPTH, db_name=str(db), engine="requests", **kw)
    s.crawl()
    return _visited(db)


def test_workers_visit_the_same_pages_once_and_overlap_their_loads(tree, tmp_path):
    one = _crawl(tree, tmp_path, "one")
    assert len(one) == EXPECTED
    tree.hits.clear()
    tree.max_active = 0
    tree.gate = threading.Barrier(2)
    four = _crawl(tree, tmp_path, "four", workers=4)
    assert sorted(four) == sorted(one)
    pages = [h for h in tree.hits if h.startswith("/n") or h == "/"]
    assert len(pages) == len(set(pages)) == EXPECTED        # each page fetched once
    assert tree.max_active >= 2                               # loads overlapped


def test_the_write_capable_phase_runs_one_worker_at_a_time(tree, tmp_path, monkeypatch):
    inside, peak = [0], [0]
    lock = threading.Lock()
    original = sp.LocalSpider._after_fetch

    def after_fetch(self, *a, **k):
        with lock:
            inside[0] += 1
            peak[0] = max(peak[0], inside[0])
        try:
            time.sleep(0.01)
            return original(self, *a, **k)
        finally:
            with lock:
                inside[0] -= 1

    monkeypatch.setattr(sp.LocalSpider, "_after_fetch", after_fetch)
    tree.gate = threading.Barrier(2)
    pages = _crawl(tree, tmp_path, "w", workers=4)
    assert len(pages) == EXPECTED and peak[0] == 1
    assert tree.max_active >= 2                    # while loads still overlapped


def test_a_failing_worker_stops_the_crawl_and_the_error_is_raised(tree, tmp_path,
                                                                     monkeypatch):
    original = sp.LocalSpider._fetch_static

    def fetch(self, url):
        if url.rstrip("/").endswith("/n/1/2"):
            raise KeyboardInterrupt                  # escapes the per-page handler
        return original(self, url)

    monkeypatch.setattr(sp.LocalSpider, "_fetch_static", fetch)
    s = sp.LocalSpider(tree.url, max_depth=DEPTH, db_name=str(tmp_path / "f.db"),
                       engine="requests", workers=3)
    done = threading.Event()

    def run():
        s.crawl()                                     # crawl() reports the interrupt
        done.set()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(30)
    assert done.is_set(), "the crawl did not end after a worker failed"


def test_shared_flags_and_counts_are_one_value_across_workers(tmp_path):
    s = sp.LocalSpider("http://127.0.0.1:9/", db_name=str(tmp_path / "x.db"),
                       engine="requests", workers=2)
    other = s._clone()
    other.spa_submit_stopped = "session lost"
    assert s.spa_submit_stopped == "session lost"
    other._bump_shared("session_out_of_origin")
    assert s.session_out_of_origin == 1
    assert other.storage is s.storage and other._submitted_sigs is s._submitted_sigs
    assert other.session is not s.session and other._xhr_urls is not s._xhr_urls
    s.storage.close()


@pytest.mark.parametrize("n", [0, sp.MAX_WORKERS + 1])
def test_the_worker_count_is_bounded(n, tmp_path):
    with pytest.raises(ValueError, match="workers"):
        sp.LocalSpider("http://127.0.0.1:9/", db_name=str(tmp_path / "b.db"),
                       engine="requests", workers=n)
    with pytest.raises(SystemExit):
        sp.parse_args(["--start", "http://127.0.0.1:9/", "--workers", str(n)])


def test_two_browser_workers_crawl_the_tree(tree, tmp_path, monkeypatch):
    """Real browsers: each worker starts its own guarded Chromium."""
    from tests._spa_fixture import chromium_or_skip
    chromium_or_skip(monkeypatch)
    db = tmp_path / "pw.db"
    tree.gate = threading.Barrier(2)
    s = sp.LocalSpider(tree.url, max_depth=2, db_name=str(db), engine="playwright",
                       workers=2, reveal=False)
    s.crawl()
    visited = _visited(db)
    assert len(visited) == 1 + FANOUT + FANOUT ** 2
    assert tree.max_active >= 2
