"""The site tree's data layer and API (CC-UI-0500, FR-UI-500..505).

Data-layer tests drive `fuzzlab.web.sitetree` over seeded stores shaped like what the
real writers produce (PA-0006): pipeline candidates (`audit/engine.py`, absolute evidence
URLs), crawl-imported endpoints/parameters (`tools/store_adapter.py`, including the raw
``?query`` a POST form action or captured request keeps), auditor candidates with and
without a parameter row, oracle findings (`oracle._write_finding`, ``finding_url``) and
target rows (`harness/pipeline.py`). API tests go through the app's routes.
"""

from __future__ import annotations

import inspect
import json
import re

import pytest

from fuzzlab.core.store import Store
from fuzzlab.web import sitetree as st
from fuzzlab.web.findingsview import derive_severity

pytest.importorskip("fastapi")

ORIGIN = "http://127.0.0.1:8080"


# --- seeding helpers ----------------------------------------------------------------

class Seed:
    def __init__(self, path):
        self.path = path
        self.store = Store(path)
        self.conn = self.store.conn

    def run(self, tool="auto", base_url: str | None = ORIGIN) -> int:
        rid = self.store.start_run(tool, "h")
        if base_url is not None:
            self.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)",
                              (rid, base_url))
        self.conn.commit()
        return rid

    def endpoint(self, rid, url, method="GET") -> int:
        cur = self.conn.execute("INSERT INTO endpoint (run_id, url, method) VALUES (?,?,?)",
                                (rid, url, method))
        self.conn.commit()
        return int(cur.lastrowid)

    def page(self, rid, url):
        self.conn.execute("INSERT INTO page (run_id, url, method) VALUES (?,?,'GET')",
                          (rid, url))
        self.conn.commit()

    def param(self, rid, ep, name, location="query", example="") -> int:
        cur = self.conn.execute(
            "INSERT INTO parameter (run_id, endpoint_id, name, location, example) "
            "VALUES (?,?,?,?,?)", (rid, ep, name, location, example))
        self.conn.commit()
        return int(cur.lastrowid)

    def cand(self, rid, path, param, category="sql-injection", method="GET",
             location="query", status="checked", base=ORIGIN, **extra) -> int:
        ev = {"rule_id": "R", "category": category, "url": base + path, "param": param,
              "method": method, "location": location, **extra}
        return self.raw_cand(rid, json.dumps(ev), status)

    def raw_cand(self, rid, evidence, status="checked", parameter_id=None) -> int:
        cur = self.conn.execute(
            "INSERT INTO candidate (run_id, parameter_id, evidence, oracle_status) "
            "VALUES (?,?,?,?)", (rid, parameter_id, evidence, status))
        self.conn.commit()
        return int(cur.lastrowid)

    def finding(self, rid, path, param, vuln_class="sqli", method="GET",
                evidence="{}") -> int:
        cur = self.conn.execute(
            "INSERT INTO finding (run_id, vuln_class, label, confidence, evidence, url, "
            "method, param) VALUES (?,?,1,'error-signature',?,?,?,?)",
            (rid, vuln_class, evidence, path, method, param))
        self.conn.commit()
        return int(cur.lastrowid)

    def close(self):
        self.store.close()


@pytest.fixture
def seed(tmp_path):
    s = Seed(tmp_path / "s.db")
    st.child_cache.clear()
    yield s
    s.close()


def kids(conn, key=st.ROOT, filters=st.Filters(), **kw) -> list[dict]:
    """Every child of ``key`` across all pages."""
    out, after = [], None
    while True:
        page = st.children(conn, key, filters, after=after, **kw)
        out += page["children"]
        after = page["next"]
        if after is None:
            return out


def node(text) -> st.NodeKey:
    return st.parse_key(text if isinstance(text, str) else json.dumps(text))


def walk(conn, filters=st.Filters(), key=st.ROOT, depth=0, out=None) -> list:
    """``[(depth, label or item, child dict)]`` for the whole tree."""
    out = [] if out is None else out
    for c in kids(conn, key, filters):
        out.append((depth, c.get("label") or f"{c['kind']}#{c['id']}", c))
        if c.get("expandable"):
            walk(conn, filters, node(c["key"]), depth + 1, out)
    return out


def labels(conn, key, filters=st.Filters(), **kw) -> list[str]:
    return [c.get("label") or f"{c['kind']}#{c['id']}"
            for c in kids(conn, key, filters, **kw)]


# --- the path convention ------------------------------------------------------------

@pytest.mark.parametrize("path,segs", [
    ("/", [""]), ("/a", ["a"]), ("/a/", ["a", ""]), ("/a/b.php", ["a", "b.php"]),
    ("/a//b", ["a", "", "b"]), ("//", ["", ""]), ("/#/search", ["", "#/search"]),
    ("/app/#/x", ["app", "", "#/x"]), ("/app#/x/y", ["app", "#/x/y"]),
    ("/#!/hash", ["", "#!/hash"]),
])
def test_segments(path, segs):
    assert st.segments(path) == segs


@pytest.mark.parametrize("stored,path", [
    ("/x.php?csrf=abc&next=/a/b", "/x.php"), ("/x", "/x"), ("/#/search", "/#/search"),
    ("//x/y", "//x/y"), ("x/y", None), ("", None), (None, None), (5, None),
])
def test_path_key_is_a_textual_split_and_never_reroots(stored, path):
    assert st.path_key(stored) == path


# --- node keys and filters ----------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "{", "[]", '{"o":"http://127.0.0.1:8080","r":1}', "{}", '{"x":1,"o":"a"}',
    '{"o":"http://localhost:8080"}',               # not canonical
    '{"r":true}', '{"r":0}', '{"r":"1"}',
    '{"o":"http://127.0.0.1:8080","s":["#/r","a"]}',     # a route is last
    '{"o":"http://127.0.0.1:8080","m":"GET"}',            # endpoint without a path
    '{"o":"http://127.0.0.1:8080","s":["a"],"m":"get"}',
    '{"o":"http://127.0.0.1:8080","s":["a"],"p":"id"}',   # param without endpoint
    '{"o":"http://127.0.0.1:8080","s":["a"],"l":"query"}',
    '{"o":"http://127.0.0.1:8080","s":[1]}',
    json.dumps({"r": 1, "s": ["a" * 5000]}),
])
def test_malformed_node_keys_are_refused(bad):
    with pytest.raises(st.SiteTreeError):
        st.parse_key(bad)


def test_node_keys_round_trip():
    for k in (st.NodeKey(origin=ORIGIN, segs=()),
              st.NodeKey(run=3, segs=("a", "", "#/x")),
              st.NodeKey(origin=ORIGIN, segs=("a",), method=""),
              st.NodeKey(origin=ORIGIN, segs=("a",), method="POST", param="id",
                         has_param=True, loc=None)):
        assert st.parse_key(k.dump()) == k


@pytest.mark.parametrize("kw", [
    {"run": ["x"]}, {"run": ["0"]}, {"severity": ["urgent"]}, {"status": ["done"]},
    {"q": "x" * 600}, {"category": ["c"] * 65},
])
def test_malformed_filters_are_refused(kw):
    with pytest.raises(st.SiteTreeError):
        st.parse_filters(**kw)


# --- hosts ----------------------------------------------------------------------------

def test_loopback_aliases_are_one_host_other_ports_and_addresses_are_not(seed):
    for base in ("http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080",
                 "http://127.0.0.2:8080", "http://localhost:8081"):
        rid = seed.run(base_url=base)
        seed.endpoint(rid, "/p")
    hosts = kids(seed.conn)
    assert [h["label"] for h in hosts] == [
        "http://127.0.0.1:8080", "http://127.0.0.1:8081", "http://127.0.0.2:8080"]
    assert hosts[0]["rollup"]["endpoints"] == 3


def test_runs_without_a_recorded_origin_are_their_own_hosts(seed):
    crawl = seed.run("crawler", base_url=None)
    broken = seed.run("auto", base_url="http://example.test:99999")
    seed.endpoint(crawl, "/a")
    seed.endpoint(broken, "/b")
    got = {h["label"]: h for h in kids(seed.conn)}
    assert set(got) == {f"run #{crawl} · crawler — origin not recorded",
                        f"run #{broken} · auto — origin unreadable"}
    assert json.loads(got[f"run #{crawl} · crawler — origin not recorded"]["key"]) == {
        "r": crawl}


def test_host_labels_never_show_the_raw_base_url(seed):
    rid = seed.run(base_url="http://user:hunter2@LOCALHOST:8080/app/")
    seed.endpoint(rid, "/a")
    text = json.dumps(kids(seed.conn))
    assert "hunter2" not in text and "user" not in text and "/app/" not in text


# --- paths, routes and depth ----------------------------------------------------------

def test_spa_hash_routes_are_route_children_of_their_document(seed):
    rid = seed.run()
    seed.endpoint(rid, "/#/search")
    seed.endpoint(rid, "/#/track-result")
    seed.endpoint(rid, "/")
    seed.endpoint(rid, "/app/#/x")
    host = node({"o": ORIGIN})
    assert labels(seed.conn, host) == ["/", "app"]
    index = kids(seed.conn, host)[0]
    sub = kids(seed.conn, node(index["key"]))
    assert [(c["kind"], c["label"]) for c in sub] == [
        ("endpoint", "GET /"), ("route", "#/search"), ("route", "#/track-result")]
    assert labels(seed.conn, node(sub[1]["key"])) == ["GET /#/search"]
    app = node({"o": ORIGIN, "s": ["app", ""]})
    assert [(c["kind"], c["label"]) for c in kids(seed.conn, app)] == [("route", "#/x")]


def test_a_route_finding_and_candidate_sit_under_their_route(seed):
    rid = seed.run()
    seed.cand(rid, "/#/search", "q", category="xss", location="fragment")
    seed.finding(rid, "/#/search", "q", vuln_class="xss-dom")
    ep = node({"o": ORIGIN, "s": ["", "#/search"], "m": "GET"})
    params = kids(seed.conn, ep)
    assert [p["label"] for p in params] == ["q · fragment"]
    assert params[0]["rollup"]["findings"] == 1 and params[0]["rollup"]["candidates"] == 1


def test_deep_paths(seed):
    rid = seed.run()
    deep = "/" + "/".join(f"d{i}" for i in range(40)) + "/leaf.php"
    seed.endpoint(rid, deep)
    seed.finding(rid, deep, "id")
    key = node({"o": ORIGIN})
    for i in range(40):
        (child,) = kids(seed.conn, key)
        assert child["label"] == f"d{i}" and child["rollup"]["findings"] == 1
        key = node(child["key"])
    (leaf,) = kids(seed.conn, key)
    (ep,) = kids(seed.conn, node(leaf["key"]))
    assert ep["label"] == f"GET {deep}"


def test_trailing_slash_index_and_double_slash_are_distinct(seed):
    rid = seed.run()
    for p in ("/a", "/a/", "/a//b"):
        seed.endpoint(rid, p)
    a = node({"o": ORIGIN, "s": ["a"]})
    assert labels(seed.conn, a) == ["GET /a", "/"]
    idx = node({"o": ORIGIN, "s": ["a", ""]})
    assert labels(seed.conn, idx) == ["GET /a/", "b"]


# --- endpoints carrying a raw query (design blocker F1) ------------------------------

def test_a_stored_query_is_never_shown_searched_or_split_into_nodes(seed):
    rid = seed.run()
    form = seed.endpoint(rid, "/save.php?csrf=QSECRET1&next=/a/b", "POST")
    seed.param(rid, form, "title", "body")
    captured = seed.endpoint(rid, "/api/cart?api_key=QSECRET2", "POST")
    seed.param(rid, captured, "qty", "json")
    seed.finding(rid, "/save.php", "title", vuln_class="xss-stored", method="POST")
    tree = walk(seed.conn)
    text = json.dumps([c for _d, _l, c in tree])
    assert "QSECRET" not in text and "next=" not in text
    host = node({"o": ORIGIN})
    assert labels(seed.conn, host) == ["api", "save.php"]
    (ep,) = kids(seed.conn, node({"o": ORIGIN, "s": ["save.php"]}))
    assert ep["label"] == "POST /save.php"
    (title,) = kids(seed.conn, node(ep["key"]))
    assert title["label"] == "title · body" and title["rollup"]["findings"] == 1
    for q in ("QSECRET1", "api_key", "csrf"):
        assert kids(seed.conn, filters=st.parse_filters(q=q)) == []


# --- parameters and finding locations -------------------------------------------------

def test_parameters_in_several_locations(seed):
    rid = seed.run()
    ep = seed.endpoint(rid, "/api/item", "POST")
    for name, loc in (("id", "query"), ("title", "body"), ("item.price", "json"),
                      ("X-Token", "header"), ("q", "fragment"), ("session", "cookie")):
        seed.param(rid, ep, name, loc)
    seed.cand(rid, "/api/item", "item.price", method="POST", location="json")
    got = labels(seed.conn, node({"o": ORIGIN, "s": ["api", "item"], "m": "POST"}))
    assert got == ["X-Token · header", "id · query", "item.price · json", "q · fragment",
                   "session · cookie", "title · body"]


def test_finding_location_is_resolved_on_every_shared_field(seed):
    rid = seed.run()
    # one candidate per location for `id`, with different categories
    seed.cand(rid, "/p", "id", category="sql-injection", location="query")
    seed.cand(rid, "/p", "id", category="xss", location="body")
    sqli = seed.finding(rid, "/p", "id", vuln_class="sqli")           # -> query
    xss = seed.finding(rid, "/p", "id", vuln_class="xss-reflected")   # -> body
    other = seed.finding(rid, "/p", "id", vuln_class="ssrf")          # ambiguous -> null
    ep = node({"o": ORIGIN, "s": ["p"], "m": "GET"})
    by_label = {p["label"]: p for p in kids(seed.conn, ep)}
    assert set(by_label) == {"id · query", "id · body", "id · location not recorded"}

    def ids(label):
        return [i["id"] for i in kids(seed.conn, node(by_label[label]["key"]))
                if i["kind"] == "finding"]
    assert ids("id · query") == [sqli] and ids("id · body") == [xss]
    assert ids("id · location not recorded") == [other]


def test_a_finding_falls_back_to_a_parameter_row_without_category(seed):
    rid = seed.run()
    ep = seed.endpoint(rid, "/p?x=1", "POST")
    seed.param(rid, ep, "name", "body")
    f = seed.finding(rid, "/p", "name", vuln_class="ssti", method="POST")
    (param,) = kids(seed.conn, node({"o": ORIGIN, "s": ["p"], "m": "POST"}))
    assert param["label"] == "name · body"
    assert [i["id"] for i in kids(seed.conn, node(param["key"]))] == [f]


def test_location_resolution_is_per_run(seed):
    a, b = seed.run(), seed.run()
    seed.cand(a, "/p", "id", location="query")
    seed.cand(b, "/p", "id", location="body")
    fa = seed.finding(a, "/p", "id")
    fb = seed.finding(b, "/p", "id")
    ep = node({"o": ORIGIN, "s": ["p"], "m": "GET"})
    by = {p["label"]: [i["id"] for i in kids(seed.conn, node(p["key"]))
                       if i["kind"] == "finding"] for p in kids(seed.conn, ep)}
    assert by == {"id · query": [fa], "id · body": [fb]}


def test_a_finding_without_a_method_is_not_defaulted_to_get(seed):
    rid = seed.run()
    seed.cand(rid, "/p", "id", method="POST", location="body")
    f = seed.finding(rid, "/p", "id", method=None)
    eps = kids(seed.conn, node({"o": ORIGIN, "s": ["p"]}))
    assert [e["label"] for e in eps] == ["(method not recorded) /p", "POST /p"]
    (param,) = kids(seed.conn, node(eps[0]["key"]))
    assert param["label"] == "id · body"                 # any-method resolution (G8)
    assert [i["id"] for i in kids(seed.conn, node(param["key"]))] == [f]


def test_findings_with_no_parameter_group_under_no_parameter(seed):
    rid = seed.run()
    f1 = seed.finding(rid, "/p", None)
    f2 = seed.finding(rid, "/p", "")
    (param,) = kids(seed.conn, node({"o": ORIGIN, "s": ["p"], "m": "GET"}))
    assert param["label"] == "(no parameter) · location not recorded"
    assert sorted(i["id"] for i in kids(seed.conn, node(param["key"]))) == [f1, f2]


# --- candidate shapes (G3) and problem counts ----------------------------------------

def test_every_candidate_shape_is_placed_or_counted(seed):
    rid = seed.run()
    ep = seed.endpoint(rid, "/fk.php")
    pid = seed.param(rid, ep, "id", "query")
    seed.raw_cand(rid, json.dumps({"category": "URL Parameters (GET)",
                                   "target_identifier": "id"}), parameter_id=pid)  # FK
    seed.cand(rid, "/pipe.php", "q")                                    # pipeline
    seed.raw_cand(rid, json.dumps({"category": "Unprotected Forms",
                                   "target_identifier": "form1"}))      # no_path
    # dangling: foreign keys hold, but `parameter.endpoint_id` may be NULL
    orphan = seed.conn.execute("INSERT INTO parameter (run_id, name, location) "
                               "VALUES (?, 'o', 'query')", (rid,)).lastrowid
    seed.raw_cand(rid, json.dumps({"category": "x"}), parameter_id=orphan)
    seed.raw_cand(rid, "not json")                                      # unreadable
    seed.raw_cand(rid, json.dumps({"url": "/u", "param": 3, "category": "x"}))  # unreadable
    seed.raw_cand(rid, json.dumps({"url": "http://[bad/p", "param": "x",
                                   "category": "xss"}))                 # error (urlsplit)
    seed.finding(rid, None, "id")                                       # unplaced finding
    seed.endpoint(rid, "relative/no-slash")                             # unplaced endpoint
    (host,) = kids(seed.conn)
    assert host["rollup"]["problems"] == {"unplaced": 3, "no_path": 1, "unreadable": 2,
                                          "error": 1}
    assert labels(seed.conn, node(host["key"])) == ["fk.php", "pipe.php"]
    summary = st.summary(seed.conn, node(host["key"]), st.Filters())
    assert summary["rollup"]["problems"] == host["rollup"]["problems"]
    (fk,) = kids(seed.conn, node({"o": ORIGIN, "s": ["fk.php"], "m": "GET"}))
    assert fk["label"] == "id · query" and fk["rollup"]["candidates"] == 1


def test_an_unexpected_error_in_a_sql_function_propagates(seed, monkeypatch):
    """PA-0106(2): a named error is swallowed and counted (above); any other one is a
    failure, never silently missing data."""
    rid = seed.run()
    seed.cand(rid, "/p", "id")
    st._proj_cache.clear()

    def boom(evidence):
        raise RuntimeError("bug")
    monkeypatch.setattr(st, "_evidence_view_uncached", boom)
    with pytest.raises(Exception, match="bug|user-defined function raised exception"):
        kids(seed.conn)


def test_severity_shown_equals_the_finding_pages_band_for_every_oracle_class(seed):
    from fuzzlab.oracle import strategies
    classes = sorted({c.vuln_class for _n, c in inspect.getmembers(strategies,
                                                                   inspect.isclass)
                      if isinstance(getattr(c, "vuln_class", None), str)
                      and c.vuln_class})
    assert len(classes) > 10
    rid = seed.run()
    for i, vc in enumerate(classes):
        seed.finding(rid, f"/c{i}", "p", vuln_class=vc)
    for i, vc in enumerate(classes):
        s = st.summary(seed.conn, node({"o": ORIGIN, "s": [f"c{i}"]}), st.Filters())
        (f,) = s["findings"]
        assert f["severity"] == derive_severity(vc), vc


# --- filters ---------------------------------------------------------------------------

@pytest.fixture
def mixed(seed):
    a, b = seed.run(), seed.run()
    seed.endpoint(a, "/static/only")                               # structure only
    seed.cand(a, "/s.php", "id", category="sql-injection", status="checked")
    seed.cand(a, "/s.php", "id", category="sql-injection", status="inconclusive")
    seed.cand(b, "/t.php", "q", category="server-side-template-injection",
              status="pending")
    seed.cand(b, "/n.php", "q", category="xss", status=None)
    seed.finding(a, "/s.php", "id", vuln_class="sqli")
    seed.finding(b, "/t.php", "q", vuln_class="ssti")
    return seed, a, b


def tops(conn, **kw) -> list[str]:
    return labels(conn, node({"o": ORIGIN}), st.parse_filters(**kw))


def test_no_item_filter_shows_every_recorded_endpoint(mixed):
    seed, _a, _b = mixed
    assert tops(seed.conn) == ["n.php", "s.php", "static", "t.php"]


def test_run_filter(mixed):
    seed, a, b = mixed
    assert tops(seed.conn, run=[str(a)]) == ["s.php", "static"]
    assert tops(seed.conn, run=[str(b)]) == ["n.php", "t.php"]


def test_status_filter_and_null_is_never_checked(mixed):
    seed, _a, _b = mixed
    assert tops(seed.conn, status=["confirmed"]) == ["s.php", "t.php"]
    assert tops(seed.conn, status=["inconclusive"]) == ["s.php"]
    assert tops(seed.conn, status=["checked"]) == ["s.php"]
    assert tops(seed.conn, status=["unrecorded"]) == ["n.php"]
    assert tops(seed.conn, status=["pending", "unrecorded"]) == ["n.php", "t.php"]


def test_category_filter_maps_findings_through_to_category(mixed):
    seed, _a, _b = mixed
    assert tops(seed.conn, category=["server-side-template-injection"]) == ["t.php"]
    assert tops(seed.conn, category=["xss"]) == ["n.php"]


def test_severity_filter_applies_to_findings_only(mixed):
    seed, _a, _b = mixed
    # ssti's finding band is `info` (the finding page's band); its candidate is never
    # banded, so `critical` does not show the SSTI candidate (F3)
    assert tops(seed.conn, severity=["critical"]) == ["s.php"]
    assert tops(seed.conn, severity=["info"]) == ["t.php"]
    s = st.summary(seed.conn, node({"o": ORIGIN}), st.parse_filters(severity=["critical"]))
    assert s["rollup"]["candidates"] == 0 and s["rollup"]["findings"] == 1


def test_text_search_on_path(mixed):
    seed, _a, _b = mixed
    assert tops(seed.conn, q="S.PHP") == ["s.php"]
    assert tops(seed.conn, q="nothing") == []


def test_rollups_follow_the_filters(mixed):
    seed, _a, _b = mixed
    (host,) = kids(seed.conn)
    r = host["rollup"]
    assert r["findings"] == 2 and r["candidates"] == 4 and r["endpoints"] == 1
    assert r["by_status"]["checked"] == 1 and r["by_status"]["inconclusive"] == 1
    assert r["by_status"]["pending"] == 1 and r["by_status"]["unrecorded"] == 1
    assert r["by_severity"]["critical"] == 1 and r["by_severity"]["info"] == 1
    assert r["by_category"] == {"sql-injection": 1, "server-side-template-injection": 1}
    (host,) = kids(seed.conn, filters=st.parse_filters(status=["inconclusive"]))
    assert host["rollup"]["candidates"] == 1 and host["rollup"]["findings"] == 0


def test_last_seen_run(mixed):
    seed, a, b = mixed
    got = {c["label"]: c["rollup"]["last_run"] for c in kids(seed.conn, node({"o": ORIGIN}))}
    assert got == {"n.php": b, "s.php": a, "static": a, "t.php": b}


# --- multi-run merge (PA-0066(2)) -----------------------------------------------------

def test_merged_host_equals_the_sum_of_its_runs(seed):
    a, b = seed.run(base_url="http://localhost:8080"), seed.run()
    c = seed.run(base_url="http://other.test:80")
    for rid in (a, b, c):
        seed.endpoint(rid, "/shared.php")
        seed.cand(rid, "/shared.php", "id", location="query" if rid != b else "body",
                  base="http://x")
        seed.finding(rid, "/shared.php", "id")
    host = node({"o": ORIGIN})

    def flat(filters):
        return {lab: c["rollup"] for _d, lab, c in walk(seed.conn, filters, host)
                if "rollup" in c}
    merged = flat(st.Filters())
    per = [flat(st.parse_filters(run=[str(r)])) for r in (a, b)]
    for lab, roll in merged.items():
        for k in ("findings", "candidates", "endpoints"):
            assert roll[k] == sum(p.get(lab, {}).get(k, 0) for p in per), (lab, k)
    assert {"id · query", "id · body"} <= set(merged)


# --- pagination ------------------------------------------------------------------------

def _wide(seed, n=450):
    rid = seed.run()
    names = [f"i{i:04d}" for i in range(n)] + ["", "!bang", "seg", "seg-a", "seg.b"]
    for nm in names:
        seed.endpoint(rid, f"/w/{nm}/x")
    seed.endpoint(rid, "/w#/route")
    seed.endpoint(rid, "/w")
    return node({"o": ORIGIN, "s": ["w"]})


@pytest.mark.parametrize("cache", [True, False])
def test_paging_returns_the_unpaged_child_set_exactly(seed, cache, monkeypatch):
    key = _wide(seed)
    monkeypatch.setattr(st.child_cache, "enabled", cache)
    full = st.children(seed.conn, key, st.Filters(), limit=st.PAGE_MAX)
    paged = kids(seed.conn, key, limit=200)
    assert [c["label"] for c in paged] == [c["label"] for c in full["children"]]
    assert paged[0]["label"] == "GET /w" and "#/route" in [c["label"] for c in paged]
    assert {"seg", "seg-a", "seg.b", "/", "!bang"} <= {c["label"] for c in paged}
    assert len(paged) == 450 + 5 + 2


def test_cursor_narrowing_never_skips_a_sibling_the_cursor_is_a_prefix_of(seed,
                                                                          monkeypatch):
    """Every page boundary, uncached (so the cursor narrows the range): a segment that
    is a prefix of its siblings (``seg`` < ``seg-a`` < ``seg.b`` < ``seg0``, whose stored
    paths sort *before* ``/w/seg/``) is never skipped."""
    rid = seed.run()
    names = ["", "!x", "seg", "seg-a", "seg.b", "seg0", "segz", "t"]
    for nm in names:
        seed.endpoint(rid, f"/w/{nm}/x")
    seed.endpoint(rid, "/w#/r")
    monkeypatch.setattr(st.child_cache, "enabled", False)
    key = node({"o": ORIGIN, "s": ["w"]})
    want = [c["label"] for c in st.children(seed.conn, key, st.Filters(),
                                            limit=50)["children"]]
    assert [c["label"] for c in kids(seed.conn, key, limit=1)] == want
    assert len(want) == len(names) + 1


def test_limits_are_validated(seed):
    with pytest.raises(st.SiteTreeError):
        st.children(seed.conn, st.ROOT, st.Filters(), limit=0)
    with pytest.raises(st.SiteTreeError):
        st.children(seed.conn, st.ROOT, st.Filters(), limit=st.PAGE_MAX + 1)


def test_parameter_items_page_across_both_id_spaces(seed):
    rid = seed.run()
    for _ in range(7):
        seed.cand(rid, "/p", "id")
        seed.finding(rid, "/p", "id")
    (param,) = kids(seed.conn, node({"o": ORIGIN, "s": ["p"], "m": "GET"}))
    got, after = [], None
    while True:
        page = st.children(seed.conn, node(param["key"]), st.Filters(), after=after,
                           limit=3)
        got += [(i["kind"], i["id"]) for i in page["children"]]
        after = page["next"]
        if after is None:
            break
    assert len(got) == 14 and len(set(got)) == 14
    assert got == sorted(got, key=lambda t: (-t[1], t[0]))


# --- the cache and the version fingerprint (G1, G6, G11) --------------------------------

def test_version_changes_on_an_update_only_commit(seed):
    rid = seed.run()
    cid = seed.cand(rid, "/p", "id", status="pending")
    v1 = st.store_version(seed.path)
    seed.conn.execute("UPDATE candidate SET oracle_status='checked' WHERE id=?", (cid,))
    seed.conn.commit()
    assert st.store_version(seed.path) != v1
    assert st.store_version(seed.path.with_name("missing.db")) is None


def test_a_cached_child_list_is_never_served_for_a_newer_store(seed):
    rid = seed.run()
    seed.endpoint(rid, "/a")
    host = node({"o": ORIGIN})
    v1 = st.store_version(seed.path)
    assert labels(seed.conn, host, version=v1) == ["a"]
    seed.endpoint(rid, "/b")
    v2 = st.store_version(seed.path)
    assert v2 != v1
    assert labels(seed.conn, host, version=v2) == ["a", "b"]


# --- SQLite feature fallbacks (G5, F14) --------------------------------------------------

def test_results_are_identical_without_json1_or_materialized(mixed, monkeypatch):
    seed, _a, _b = mixed
    want = walk(seed.conn)
    st.child_cache.clear()
    monkeypatch.setitem(st._features, "json1", False)
    monkeypatch.setitem(st._features, "materialized", False)
    assert walk(seed.conn) == want


# --- API ---------------------------------------------------------------------------------

def _client(path, **cfg):
    from fuzzlab.core.config import load_config
    from fuzzlab.web.app import create_app
    from tests._webclient import web_client
    return web_client(create_app(load_config(overrides={"store_path": str(path), **cfg},
                                             environ={})))


def test_api_walk_matches_the_data_layer(mixed):
    seed, _a, _b = mixed
    client = _client(seed.path)
    r = client.get("/api/sitetree/children").json()
    assert [c["label"] for c in r["children"]] == ["http://127.0.0.1:8080"]
    r = client.get("/api/sitetree/children", params={"node": r["children"][0]["key"],
                                                     "status": ["confirmed"]}).json()
    assert [c["label"] for c in r["children"]] == ["s.php", "t.php"]
    n = client.get("/api/sitetree/node", params={"node": json.dumps({"o": ORIGIN})}).json()
    assert [f["href"] for f in n["findings"]] == ["/findings/2", "/findings/1"]
    facets = client.get("/api/sitetree/facets").json()
    assert {r["id"] for r in facets["runs"]} == {1, 2}
    assert "sql-injection" in facets["categories"]
    assert facets["statuses"] == list(st.STATUSES)
    assert client.get("/api/sitetree/version").json()["version"]


def test_api_refuses_malformed_requests_and_reports_gone_nodes(mixed):
    seed, a, _b = mixed
    client = _client(seed.path)
    assert client.get("/api/sitetree/children", params={"node": "{"}).status_code == 400
    assert client.get("/api/sitetree/children",
                      params={"status": ["bogus"]}).status_code == 400
    gone = client.get("/api/sitetree/children", params={"node": json.dumps(
        {"o": "http://127.0.0.9:1"})})
    assert gone.status_code == 404 and gone.json()["error"] == "gone"


def test_a_run_that_gets_its_origin_mid_run_re_keys_its_host(seed):
    rid = seed.run(base_url=None)
    seed.endpoint(rid, "/a")
    client = _client(seed.path)
    key = json.dumps({"r": rid})
    assert client.get("/api/sitetree/children", params={"node": key}).status_code == 200
    seed.conn.execute("INSERT INTO target (run_id, base_url) VALUES (?,?)", (rid, ORIGIN))
    seed.conn.commit()
    assert client.get("/api/sitetree/children", params={"node": key}).status_code == 404
    top = client.get("/api/sitetree/children").json()["children"]
    assert [c["label"] for c in top] == [ORIGIN]


def test_missing_store_is_an_empty_tree_and_is_never_created(tmp_path):
    path = tmp_path / "missing.db"
    client = _client(path)
    assert client.get("/api/sitetree/children").json() == {"children": [], "next": None}
    assert client.get("/api/sitetree/version").json() == {"version": None}
    assert client.get("/api/sitetree/facets").json()["runs"] == []
    assert client.get("/sitetree").status_code == 200
    assert not path.exists()


def test_fingerprint_is_taken_before_the_snapshot(mixed, monkeypatch):
    """G11: the route computes the version before its store access, so a write landing
    in between can only make a cached list newer than its key, never older."""
    seed, _a, _b = mixed
    calls = []
    real_version, real_read = st.store_version, st._read
    monkeypatch.setattr(st, "store_version",
                        lambda p: calls.append("version") or real_version(p))
    monkeypatch.setattr(st, "_read",
                        lambda conn, fn: calls.append("snapshot") or real_read(conn, fn))
    _client(seed.path).get("/api/sitetree/children")
    assert calls == ["version", "snapshot"]


def _table_state(path) -> str:
    """The store's logical content (a checkpoint may rewrite files without a write)."""
    with Store(path) as s:
        return "\n".join(s.conn.iterdump())


def test_site_tree_routes_are_read_only(mixed):
    """NFR-UI-read-only: walking the whole tree through the API writes no row."""
    seed, _a, _b = mixed
    before = _table_state(seed.path)
    client = _client(seed.path)
    stack = [""]
    while stack:
        key = stack.pop()
        r = client.get("/api/sitetree/children", params={"node": key})
        assert r.status_code == 200
        for c in r.json()["children"]:
            if c.get("expandable"):
                stack.append(c["key"])
            if c.get("key"):
                assert client.get("/api/sitetree/node",
                                  params={"node": c["key"]}).status_code == 200
    client.get("/api/sitetree/facets")
    client.get("/sitetree")
    assert _table_state(seed.path) == before


# --- planted secrets (FR-UI-504, NFR-UI-redacted; PA-0085(2), PA-0091(1)) ---------------

_NAME_FORMS = ("token", "tokens", "api_token")
_SHAPES = ("scalar", "list", "object", "nested", "list_of_objects")


def _shaped(marker: str, shape: str):
    return {"scalar": marker, "list": [marker], "object": {"v": marker},
            "nested": {"a": {"b": [marker]}}, "list_of_objects": [{"v": marker}]}[shape]


def _plant(seed) -> list[str]:
    """Plant a unique marker in every value column the tree must never show."""
    markers = []

    def m(tag):
        markers.append(f"PLANTED{len(markers):03d}{tag}")
        return markers[-1]
    rid = seed.run(base_url=f"http://{m('userinfo')}:pw@localhost:8080")
    seed.conn.execute("UPDATE run SET config_hash=?, notes=? WHERE id=?",
                      (m("config"), m("notes"), rid))
    seed.conn.execute("UPDATE target SET fingerprint=? WHERE run_id=?", (m("fp"), rid))
    ep = seed.endpoint(rid, f"/form.php?csrf={m('epquery')}", "POST")
    pid = seed.param(rid, ep, "title", "body", example=m("example"))
    seed.conn.execute("INSERT INTO form (run_id, endpoint_id, enctype, entries) "
                      "VALUES (?,?,?,?)", (rid, ep, "application/json",
                                           json.dumps([["title", m("formentry")]])))
    seed.raw_cand(rid, json.dumps({"category": "x", "target_identifier": m("ti")}),
                  parameter_id=pid)
    for name in _NAME_FORMS:
        for shape in _SHAPES:
            seed.cand(rid, f"/c/{name}", "id", base=f"http://h?leak={m('evurlq')}",
                      entries=[["sib", m("entry")], [name, _shaped(m(name), shape)]],
                      base_value=m("base"), redirect_seed=m("seed"),
                      store_url=f"/s?x={m('store')}")
            seed.finding(rid, f"/c/{name}", "id",
                         evidence=json.dumps({"payload": m("payload"),
                                              name: _shaped(m(name), shape)}))
    seed.conn.commit()
    return markers


def test_no_planted_secret_reaches_any_sitetree_response(seed):
    markers = _plant(seed)
    # positive control: every marker really is in the store
    dump = "\n".join(seed.conn.iterdump())
    assert all(mk in dump for mk in markers)
    client = _client(seed.path)
    seen = []
    stack = [""]
    filter_sets = [{}, {"status": ["confirmed"]}, {"q": "c"}, {"category": ["x"]}]
    while stack:
        key = stack.pop()
        for f in filter_sets:
            after = None
            while True:
                r = client.get("/api/sitetree/children",
                               params={"node": key, **f, **({"after": after} if after
                                                            else {})})
                seen.append(r.text)
                body = r.json()
                for c in body.get("children", []):
                    if f == {} and c.get("expandable"):
                        stack.append(c["key"])
                    if c.get("key"):
                        seen.append(client.get("/api/sitetree/node",
                                               params={"node": c["key"], **f}).text)
                after = body.get("next")
                if not after:
                    break
    seen += [client.get("/api/sitetree/facets").text,
             client.get("/api/sitetree/version").text, client.get("/sitetree").text]
    text = "\n".join(seen)
    assert len(seen) > 20
    leaked = [mk for mk in markers if mk in text]
    assert leaked == []
    assert "/c/token" in text and "title · body" in text       # the tree did render
