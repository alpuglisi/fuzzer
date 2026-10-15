"""The site tree stays bounded on a large store (FR-UI-502; design F6/G1/G7).

Synthetic stores of >= 50 000 endpoints, every shape the writers produce (pages,
parameters, pipeline and FK candidates, findings, several runs and origins, a 50 000-wide
flat directory, an SPA index with routes). Every bound is an **operation count** --
statements executed, rows read into Python, registered-function calls, SQLite VM steps --
never wall-clock time (PA-0095(2)):

(a) statements per request are a constant: equal on a small and a large store, and for a
    10-child and a 50 000-child node (no N+1);
(b) rows read into Python are bounded by the node's width;
(c) a deep node costs the same when another origin's runs grow by 50 000 endpoints
    (ranges and run sets narrow every source);
(d) walking every page of the 50 000-wide node costs at most 3 x N child-key calls (the
    whole child list is built once and cached), and without the cache it costs more --
    so the test can fail.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.core.store import Store
from fuzzlab.web import sitetree as st

A = "http://127.0.0.1:8080"
B = "http://127.0.0.1:9090"
WIDE = 50_000


def _build(path, *, wide: int, grow_b: int) -> dict:
    s = Store(path)
    c = s.conn
    runs = {}
    for name, base in (("a1", A), ("a2", "http://localhost:8080"), ("b", B)):
        rid = s.start_run("auto", "h")
        c.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)", (rid, base))
        runs[name] = rid
    a1, a2, b = runs["a1"], runs["a2"], runs["b"]
    # origin A: a structured area, a wide flat directory, an SPA index with routes
    eps = [(a1, f"/d{i % 10}/s{(i // 10) % 10}/item{i // 100}.php", "GET")
           for i in range(2000)]
    eps += [(a1, f"/w/i{i:06d}", "GET") for i in range(wide)]
    eps += [(a2, f"/#/route{i}", "GET") for i in range(20)] + [(a2, "/", "GET")]
    eps += [(b, f"/g/x{i:06d}/y", "GET") for i in range(grow_b)]
    c.executemany("INSERT INTO endpoint (run_id, url, method) VALUES (?,?,?)", eps)
    c.executemany("INSERT INTO page (run_id, url, method) VALUES (?,?, 'GET')",
                  [(r, u) for r, u, _m in eps[:500]] + [(b, u) for _r, u, _m in eps[-500:]])
    ids = [r[0] for r in c.execute("SELECT id FROM endpoint WHERE run_id IN (?,?) "
                                   "ORDER BY id LIMIT 3000", (a1, b))]
    c.executemany("INSERT INTO parameter (run_id, endpoint_id, name, location) "
                  "VALUES (?,?,?,?)", [(a1, e, n, loc) for e in ids
                                       for n, loc in (("id", "query"), ("t", "body"),
                                                      ("h", "header"))])
    pids = [r[0] for r in c.execute("SELECT id FROM parameter LIMIT 2000")]
    c.executemany("INSERT INTO candidate (run_id, parameter_id, evidence, oracle_status) "
                  "VALUES (?,?,?, 'checked')",
                  [(a1, p, json.dumps({"category": "URL Parameters (GET)"})) for p in pids])

    def ev(base, path, cat="sql-injection"):
        return json.dumps({"rule_id": "R", "category": cat, "url": base + path,
                           "param": "id", "method": "GET", "location": "query"})
    cands = [(a1, ev(A, f"/d{i % 10}/s{(i // 10) % 10}/item{i // 100}.php"), "checked")
             for i in range(2000)]
    cands += [(a1, ev(A, f"/w/i{i:06d}"), "inconclusive") for i in range(0, wide, 10)]
    cands += [(b, ev(B, f"/g/x{i:06d}/y"), "checked") for i in range(grow_b)]
    c.executemany("INSERT INTO candidate (run_id, evidence, oracle_status) VALUES (?,?,?)",
                  cands)
    finds = [(a1, f"/d{i % 10}/s{(i // 10) % 10}/item{i // 100}.php") for i in range(0, 2000, 7)]
    finds += [(b, f"/g/x{i:06d}/y") for i in range(0, grow_b, 50)]
    c.executemany("INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, "
                  "url, method, param) VALUES (?, 'sqli', 1, 'm', '{}', ?, 'GET', 'id')",
                  finds)
    c.commit()
    s.close()
    return runs


class Probe:
    """Counts what one request does: statements, rows read into Python, child-key and
    projection calls, and SQLite VM steps (a progress-handler tick per 1000)."""

    def __init__(self, monkeypatch):
        self.statements = self.child_calls = self.projections = self.ticks = 0
        self.counters = st.Counters()
        real_child, real_view = st._child_function, st._evidence_view_uncached

        def counting_child(segs):
            fn = real_child(segs)

            def wrapped(*a):
                self.child_calls += 1
                return fn(*a)
            return wrapped

        def counting_view(ev):
            self.projections += 1
            return real_view(ev)
        monkeypatch.setattr(st, "_child_function", counting_child)
        monkeypatch.setattr(st, "_evidence_view_uncached", counting_view)

    def attach(self, conn):
        conn.set_trace_callback(self._stmt)
        conn.set_progress_handler(self._tick, 1000)
        st.counting(self.counters)

    def _stmt(self, sql):
        if sql.lstrip().upper().startswith(("SELECT", "WITH")):
            self.statements += 1

    def _tick(self):
        self.ticks += 1
        return 0

    def reset(self):
        self.statements = self.child_calls = self.projections = self.ticks = 0
        self.counters.fetched = 0


@pytest.fixture
def probe(monkeypatch):
    p = Probe(monkeypatch)
    st.child_cache.clear()
    st._proj_cache.clear()
    yield p
    st.counting(None)
    st.child_cache.clear()


def _measure(probe, path, key, *, filters=st.Filters(), limit=200, warm=True):
    with Store(path) as s:
        probe.attach(s.conn)
        if warm:                                    # projections cached, as in use
            st.children(s.conn, key, filters, limit=limit)
            st.child_cache.clear()
        probe.reset()
        page = st.children(s.conn, key, filters, limit=limit)
        return page, (probe.statements, probe.counters.fetched, probe.child_calls,
                      probe.ticks)


def _key(d) -> st.NodeKey:
    return st.parse_key(json.dumps(d))


@pytest.fixture(scope="module")
def stores(tmp_path_factory):
    d = tmp_path_factory.mktemp("scale")
    small, large = d / "small.db", d / "large.db"
    _build(small, wide=200, grow_b=0)
    _build(large, wide=WIDE, grow_b=WIDE)
    with Store(large) as s:
        n = s.conn.execute("SELECT COUNT(*) FROM endpoint").fetchone()[0]
    assert n >= 100_000                        # >= 50k on origin A alone, 50k more on B
    return small, large


def test_a_statement_count_is_constant_and_python_reads_are_bounded(stores, probe):
    small, large = stores
    keys = [st.ROOT, _key({"o": A}), _key({"o": A, "s": ["d3"]}),
            _key({"o": A, "s": ["d3", "s4"]}), _key({"o": A, "s": ["w"]}),
            _key({"o": A, "s": [""]}), _key({"o": A, "s": ["d3", "s4", "item0.php"],
                                             "m": "GET"})]
    for key in keys:
        _p, (st_small, _f, _c, _t) = _measure(probe, small, key)
        page, (st_large, fetched, _c, _t) = _measure(probe, large, key)
        assert st_small == st_large, key            # (a) no per-row or per-child query
        width = len(st.children(Store(large).conn, key, st.Filters(),
                                limit=st.PAGE_MAX)["children"]) if key.level != "dir" \
            or key.segs != ("w",) else WIDE
        assert fetched <= 8 * width + 3 * 3 + 64, (key, fetched, width)   # (b)
    # the 10-child node and the 50 000-child node run the same statements
    _p, (narrow, *_r) = _measure(probe, large, _key({"o": A, "s": ["d3"]}))
    _p, (wide, *_r) = _measure(probe, large, _key({"o": A, "s": ["w"]}))
    assert narrow == wide


def test_c_a_deep_node_costs_the_same_when_another_origin_grows(tmp_path, probe):
    small, grown = tmp_path / "a.db", tmp_path / "b.db"
    _build(small, wide=200, grow_b=0)
    _build(grown, wide=200, grow_b=WIDE)
    key = _key({"o": A, "s": ["d3", "s4"]})
    p1, (s1, f1, c1, t1) = _measure(probe, small, key)
    p2, (s2, f2, c2, t2) = _measure(probe, grown, key)
    assert p1["children"] == p2["children"]
    assert (s1, f1, c1) == (s2, f2, c2)
    assert t2 <= t1 * 1.05 + 2, (t1, t2)          # VM steps: independent of the growth


def test_d_walking_a_wide_node_is_linear_and_the_cache_is_what_makes_it_so(stores, probe,
                                                                           monkeypatch):
    _small, large = stores
    key = _key({"o": A, "s": ["w"]})

    def walk(limit):
        with Store(large) as s:
            probe.attach(s.conn)
            probe.reset()
            seen, after, pages = 0, None, 0
            version = st.store_version(large)        # as the route passes it (G11)
            while True:
                page = st.children(s.conn, key, st.Filters(), after=after, limit=limit,
                                   version=version)
                seen += len(page["children"])
                pages += 1
                after = page["next"]
                if after is None:
                    return seen, pages, probe.child_calls
    st.child_cache.clear()
    seen, pages, calls = walk(1000)
    assert seen == WIDE and pages == -(-WIDE // 1000)
    rows_under = WIDE + WIDE // 10 + 1000        # endpoints + candidates + pages there
    assert calls <= 3 * rows_under, calls
    st.child_cache.clear()
    monkeypatch.setattr(st.child_cache, "enabled", False)
    _seen, _pages, uncached = walk(1000)
    assert uncached > 3 * rows_under, uncached    # the bound above can fail


def test_c2_range_narrowing_holds_within_the_nodes_own_runs(tmp_path, probe):
    """Endpoints and pages added to the node's **own** run outside its prefix cost
    nothing: the stored-path ranges (not only the run set) narrow them."""
    base, grown = tmp_path / "a.db", tmp_path / "b.db"
    _build(base, wide=200, grow_b=0)
    runs = _build(grown, wide=200, grow_b=0)
    with Store(grown) as s:
        s.conn.executemany("INSERT INTO endpoint (run_id, url, method) VALUES (?,?,'GET')",
                           [(runs["a1"], f"/z/n{i:06d}") for i in range(WIDE)])
        s.conn.commit()
    key = _key({"o": A, "s": ["d3", "s4"]})
    p1, (s1, f1, c1, t1) = _measure(probe, base, key)
    p2, (s2, f2, c2, t2) = _measure(probe, grown, key)
    assert p1["children"] == p2["children"] and (s1, f1, c1) == (s2, f2, c2)
    assert t2 <= t1 * 1.05 + 2, (t1, t2)


def test_e_finding_location_resolution_is_linear(tmp_path, monkeypatch):
    """Code review B1 (design F6(e), PA-0095): resolving every finding's location at an
    endpoint, and listing a parameter's items, costs operations linear in the rows read
    -- it was a scan of every candidate and parameter row per finding."""
    made = []
    real = st._Locations

    class Counting(real):
        def __init__(self, *a):
            super().__init__(*a)
            made.append(self)
    monkeypatch.setattr(st, "_Locations", Counting)

    def cost(n):
        path = tmp_path / f"loc{n}.db"
        s = Store(path)
        rid = s.start_run("auto", "h")
        s.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)", (rid, A))
        ep = s.conn.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?, '/p', "
                            "'GET')", (rid,)).lastrowid
        s.conn.executemany("INSERT INTO parameter (run_id, endpoint_id, name, location) "
                           "VALUES (?,?,?, 'query')", [(rid, ep, f"x{i}") for i in range(n)])
        s.conn.executemany(
            "INSERT INTO candidate (run_id, evidence, oracle_status) VALUES (?,?, 'checked')",
            [(rid, json.dumps({"rule_id": "R", "category": "sql-injection",
                               "url": A + "/p", "param": f"x{i}", "method": "GET",
                               "location": "query"})) for i in range(n)])
        s.conn.executemany(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, url, "
            "method, param) VALUES (?, 'sqli', 1, 'm', '{}', '/p', 'GET', ?)",
            [(rid, f"x{i}") for i in range(n) for _ in range(3)])
        s.conn.commit()
        made.clear()
        st.child_cache.clear()
        key = _key({"o": A, "s": ["p"], "m": "GET"})
        kids = st.children(s.conn, key, st.Filters(), limit=st.PAGE_MAX)["children"]
        assert len(kids) == n
        steps = sum(m.steps for m in made)
        made.clear()
        st.children(s.conn, st.parse_key(kids[0]["key"]), st.Filters(), limit=50)
        steps += sum(m.steps for m in made)
        s.close()
        return steps
    small, large = cost(300), cost(900)                  # one page each (<= PAGE_MAX)
    assert large <= 3 * small * 1.1, (small, large)      # linear: 3x rows -> ~3x steps
    assert large <= 3 * 900 * 3                          # a small constant per row
